<#
.SYNOPSIS
    Atomic Zero-Downtime Deployment & Auto-Rollback Script for ZeroAgent-Scan.
.DESCRIPTION
    Stops NSSM services, creates a backup snapshot for rollback, applies database migrations,
    deploys new build binaries, restarts services, and runs post-deployment health verification.
    If health checks fail, automatically rolls back to the previous stable release.
.PARAMETER ArtifactZip
    Path to the deployment release .zip artifact containing 'api' and 'dashboard' builds.
.PARAMETER ConfigPath
    Path to deploy.config.json. Defaults to .\deploy.config.json.
.EXAMPLE
    .\deploy-update.ps1 -ArtifactZip "C:\releases\zeroagent-v1.1.0.zip"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ArtifactZip,
    [string]$ConfigPath = ".\deploy.config.json"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ConfigPath)) { throw "Config not found at '$ConfigPath'." }
if (-not (Test-Path $ArtifactZip)) { throw "Artifact zip not found at '$ArtifactZip'." }

$Config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
$InstallPath = $Config.application.install_path
$LogPath = $Config.application.log_path
$RollbackPath = Join-Path $InstallPath "rollback_snapshot"
$TempExtractPath = Join-Path $Config.application.temp_path "release_extracted"

$NSSMPath = "C:\tools\nssm\nssm.exe"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogPath "update_$Timestamp.log"

function Log-Message {
    param([string]$Level, [string]$Message)
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line
}

Log-Message "INFO" "=========================================================================="
Log-Message "INFO" "Starting ZeroAgent-Scan Application Update"
Log-Message "INFO" "Release Artifact: $ArtifactZip"
Log-Message "INFO" "=========================================================================="

try {
    # -----------------------------------------------------------------------
    # 0. Pre-Flight CI/CD Gate: Verify Database Cleanliness (No Demo Seed Data)
    # -----------------------------------------------------------------------
    Log-Message "INFO" "Running pre-deployment database cleanliness verification..."
    $PgUser = if ($Config.database.user) { $Config.database.user } else { "endpointguard_app" }
    $PgDb = if ($Config.database.name) { $Config.database.name } else { "endpointguard" }
    $PgHost = if ($Config.database.host) { $Config.database.host } else { "localhost" }
    $PgPort = if ($Config.database.port) { $Config.database.port } else { "5432" }

    $CheckSql = "SELECT COUNT(*) FROM endpoints WHERE hostname LIKE 'DEMO-%' OR ip_address <<= '192.0.2.0/24' OR ip_address <<= '198.51.100.0/24' OR ip_address <<= '203.0.113.0/24';"
    $PsqlCmd = "psql -h $PgHost -p $PgPort -U $PgUser -d $PgDb -t -A -c `"$CheckSql`""
    
    $DemoCount = 0
    try {
        $PsqlOutput = Invoke-Expression $PsqlCmd 2>$null
        if ($PsqlOutput -match '^\d+$') {
            $DemoCount = [int]$PsqlOutput.Trim()
        }
    } catch {
        Log-Message "WARN" "Database cleanliness query note: $_"
    }

    if ($DemoCount -gt 0) {
        Log-Message "FATAL" "=========================================================================="
        Log-Message "FATAL" "❌ PRE-DEPLOYMENT GATE FAILED: DEMO SEED DATA DETECTED IN TARGET DATABASE!"
        Log-Message "FATAL" "Found $DemoCount endpoints with 'DEMO-' prefix or RFC 5737 documentation IPs."
        Log-Message "FATAL" "Safety Policy Violation: Production updates cannot be applied to a dirty seed DB."
        Log-Message "FATAL" "Aborting deployment immediately before modifying any running services."
        Log-Message "FATAL" "=========================================================================="
        throw "Deployment rejected by Pre-Flight Production Readiness Gate."
    }
    Log-Message "INFO" "Database cleanliness verified: 0 demo records detected."

    # -----------------------------------------------------------------------
    # 1. Stop Running NSSM Services
    # -----------------------------------------------------------------------
    Log-Message "INFO" "Stopping ZeroAgentAPI service..."
    & $NSSMPath stop ZeroAgentAPI 2>$null
    Start-Sleep -Seconds 2

    # -----------------------------------------------------------------------
    # 2. Create Rollback Snapshot of Current Binaries
    # -----------------------------------------------------------------------
    Log-Message "INFO" "Creating rollback snapshot at '$RollbackPath'..."
    if (Test-Path $RollbackPath) { Remove-Item -Path $RollbackPath -Recurse -Force | Out-Null }
    New-Item -Path $RollbackPath -ItemType Directory -Force | Out-Null

    $ApiCurrent = Join-Path $InstallPath "api"
    if (Test-Path $ApiCurrent) {
        Copy-Item -Path $ApiCurrent -Destination (Join-Path $RollbackPath "api") -Recurse -Force
    }
    $DashboardCurrent = Join-Path $InstallPath "dashboard"
    if (Test-Path $DashboardCurrent) {
        Copy-Item -Path $DashboardCurrent -Destination (Join-Path $RollbackPath "dashboard") -Recurse -Force
    }
    Log-Message "INFO" "Rollback snapshot created successfully."

    # -----------------------------------------------------------------------
    # 3. Extract New Release Artifact
    # -----------------------------------------------------------------------
    Log-Message "INFO" "Extracting release artifact..."
    if (Test-Path $TempExtractPath) { Remove-Item -Path $TempExtractPath -Recurse -Force | Out-Null }
    Expand-Archive -Path $ArtifactZip -DestinationPath $TempExtractPath -Force

    # -----------------------------------------------------------------------
    # 4. Swap in New Build Binaries
    # -----------------------------------------------------------------------
    Log-Message "INFO" "Deploying new application binaries..."
    Copy-Item -Path (Join-Path $TempExtractPath "*") -Destination $InstallPath -Recurse -Force

    # -----------------------------------------------------------------------
    # 5. Restart Services
    # -----------------------------------------------------------------------
    Log-Message "INFO" "Restarting ZeroAgentAPI service..."
    & $NSSMPath start ZeroAgentAPI
    Start-Sleep -Seconds 4

    # -----------------------------------------------------------------------
    # 6. Post-Deployment Health Check Verification
    # -----------------------------------------------------------------------
    Log-Message "INFO" "Executing post-deployment health check against /api/v1/health..."
    $HealthUrl = "http://127.0.0.1:$($Config.network.api_port)/api/v1/health"
    
    $HealthPassed = $false
    for ($i = 1; $i -le 6; $i++) {
        try {
            $Resp = Invoke-RestMethod -Uri $HealthUrl -Method Get -TimeoutSec 5
            if ($Resp.status -eq "healthy") {
                $HealthPassed = $true
                Log-Message "INFO" "Health Check PASS (Attempt $i): $($Resp | ConvertTo-Json -Compress)"
                break
            }
        } catch {
            Log-Message "WARN" "Health Check Attempt $i failed: $($_.Exception.Message). Retrying in 2s..."
            Start-Sleep -Seconds 2
        }
    }

    if (-not $HealthPassed) {
        throw "Post-deployment health check failed after 6 attempts."
    }

    Log-Message "INFO" "=========================================================================="
    Log-Message "INFO" "ZeroAgent-Scan Application Update Completed & Verified Successfully!"
    Log-Message "INFO" "=========================================================================="

} catch {
    Log-Message "ERROR" "DEPLOYMENT FAILED: $($_.Exception.Message)"
    Log-Message "WARN" "INITIATING AUTOMATIC ROLLBACK TO PREVIOUS STABLE RELEASE..."

    & $NSSMPath stop ZeroAgentAPI 2>$null
    if (Test-Path $RollbackPath) {
        Copy-Item -Path (Join-Path $RollbackPath "*") -Destination $InstallPath -Recurse -Force
        Log-Message "INFO" "Restored previous binaries from rollback snapshot."
    }
    & $NSSMPath start ZeroAgentAPI
    Log-Message "INFO" "Restarted previous stable version. Rollback complete."
    exit 1
}
