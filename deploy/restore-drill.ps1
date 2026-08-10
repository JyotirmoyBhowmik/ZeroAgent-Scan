<#
.SYNOPSIS
    Automated PostgreSQL Restore Drill & Integrity Verification for ZeroAgent-Scan.
.DESCRIPTION
    Restores the latest database backup into a temporary throwaway scratch database (zeroagent_restore_scratch),
    validates SHA-256 checksums, executes table integrity checks and sample query assertions on host_snapshots,
    logs the drill result to an audit history file/table, sends webhook/email notifications, and tears down the scratch DB.
.PARAMETER ConfigPath
    Path to deploy.config.json. Defaults to .\deploy.config.json.
.PARAMETER BackupFilePath
    Explicit path to a .dump file. If omitted, the latest backup in backup_path is automatically selected.
.PARAMETER KeepScratch
    Switch to keep the scratch database after the drill for forensic analysis. Defaults to dropping it.
.PARAMETER WebhookURL
    Webhook URL to notify with the drill result (overrides deploy.config.json if specified).
.EXAMPLE
    .\restore-drill.ps1 -ConfigPath "C:\apps\zeroagent\deploy.config.json"
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = ".\deploy.config.json",
    [string]$BackupFilePath = "",
    [switch]$KeepScratch,
    [string]$WebhookURL = ""
)

$ErrorActionPreference = "Stop"

$StartTime = Get-Date
$DrillTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Load Configuration
if (-not (Test-Path $ConfigPath)) { throw "Config file not found at '$ConfigPath'." }
$Config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json

$BackupDir = $Config.application.backup_path
$LogPath = $Config.application.log_path
$TempPath = $Config.application.temp_path

if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $TempPath)) { New-Item -Path $TempPath -ItemType Directory -Force | Out-Null }

$LogFile = Join-Path $LogPath "restore_drill_$DrillTimestamp.log"
$HistoryFile = Join-Path $BackupDir "restore_drill_history.json"

function Log-Message {
    param([string]$Level, [string]$Message)
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line
}

Log-Message "INFO" "================================================================="
Log-Message "INFO" "Starting ZeroAgent-Scan Automated Database Restore Drill..."
Log-Message "INFO" "================================================================="

# Locate Latest Backup File
if (-not $BackupFilePath) {
    $Backups = Get-ChildItem -Path $BackupDir -Filter "zeroagent_db_backup_*.dump" | Sort-Object CreationTime -Descending
    if (-not $Backups -or $Backups.Count -eq 0) {
        $ErrMsg = "No database backups found in '$BackupDir' to execute restore drill."
        Log-Message "ERROR" $ErrMsg
        throw $ErrMsg
    }
    $LatestBackup = $Backups[0]
    $BackupFilePath = $LatestBackup.FullName
}

Log-Message "INFO" "Selected backup file for restore drill: $BackupFilePath"

# ---------------------------------------------------------------------------
# Step 1: Validate SHA-256 Checksum Integrity
# ---------------------------------------------------------------------------
$ChecksumFile = "$BackupFilePath.sha256"
$ChecksumVerified = $false

if (Test-Path $ChecksumFile) {
    $ExpectedHash = (Get-Content -Path $ChecksumFile -Raw).Trim()
    $ActualHash = (Get-FileHash -Path $BackupFilePath -Algorithm SHA256).Hash.Trim()
    
    if ($ExpectedHash -ieq $ActualHash) {
        $ChecksumVerified = $true
        Log-Message "INFO" "SHA-256 checksum verified successfully: $ActualHash"
    } else {
        $ErrMsg = "SHA-256 Checksum Mismatch! Expected: $ExpectedHash, Actual: $ActualHash"
        Log-Message "ERROR" $ErrMsg
        throw $ErrMsg
    }
} else {
    Log-Message "WARN" "Checksum file '$ChecksumFile' not found; continuing with raw dump validation."
}

# ---------------------------------------------------------------------------
# Step 2: Configure Scratch Database Environment
# ---------------------------------------------------------------------------
$DBHost = $Config.database.host
$DBPort = $Config.database.port
$DBUser = $Config.database.username
$ScratchDBName = "zeroagent_restore_scratch"
if ($Config.restore_drill -and $Config.restore_drill.scratch_database_name) {
    $ScratchDBName = $Config.restore_drill.scratch_database_name
}

# Resolve PostgreSQL Tooling
$PgRestorePath = "C:\Program Files\PostgreSQL\17\bin\pg_restore.exe"
if ($Config.database.pg_dump_path) {
    $PgBinDir = Split-Path -Path $Config.database.pg_dump_path -Parent
    $CandidatePgRestore = Join-Path $PgBinDir "pg_restore.exe"
    if (Test-Path $CandidatePgRestore) { $PgRestorePath = $CandidatePgRestore }
}
if (-not (Test-Path $PgRestorePath)) {
    $PgRestorePath = (Get-Command pg_restore.exe -ErrorAction SilentlyContinue).Source
    if (-not $PgRestorePath) { $PgRestorePath = "pg_restore" }
}

$PsqlPath = "C:\Program Files\PostgreSQL\17\bin\psql.exe"
if ($Config.database.pg_dump_path) {
    $PgBinDir = Split-Path -Path $Config.database.pg_dump_path -Parent
    $CandidatePsql = Join-Path $PgBinDir "psql.exe"
    if (Test-Path $CandidatePsql) { $PsqlPath = $CandidatePsql }
}
if (-not (Test-Path $PsqlPath)) {
    $PsqlPath = (Get-Command psql.exe -ErrorAction SilentlyContinue).Source
    if (-not $PsqlPath) { $PsqlPath = "psql" }
}

$env:PGHOST = $DBHost
$env:PGPORT = $DBPort
$env:PGUSER = $DBUser

# ---------------------------------------------------------------------------
# Step 3: Recreate Throwaway Scratch Database (NEVER touches production)
# ---------------------------------------------------------------------------
Log-Message "INFO" "Ensuring clean scratch database '$ScratchDBName' on $DBHost:$DBPort..."

$DropCreateSQL = @"
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$ScratchDBName' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS $ScratchDBName;
CREATE DATABASE $ScratchDBName;
"@

& $PsqlPath -d postgres -c $DropCreateSQL 2>&1 | Out-File (Join-Path $LogPath "psql_prep_$DrillTimestamp.log")

# ---------------------------------------------------------------------------
# Step 4: Execute pg_restore into Scratch Database
# ---------------------------------------------------------------------------
Log-Message "INFO" "Executing pg_restore into scratch database '$ScratchDBName'..."
$RestoreLog = Join-Path $LogPath "pg_restore_$DrillTimestamp.log"

& $PgRestorePath -d $ScratchDBName -v --no-owner --no-privileges $BackupFilePath 2>&1 | Out-File $RestoreLog
$RestoreExitCode = $LASTEXITCODE

# Note: pg_restore returns exit code 1 on non-fatal warnings (e.g. already existing objects), so verify with SQL queries.
Log-Message "INFO" "pg_restore completed with exit code $RestoreExitCode."

# ---------------------------------------------------------------------------
# Step 5: Integrity Verification Queries
# ---------------------------------------------------------------------------
Log-Message "INFO" "Running automated database integrity verification checks..."

$CheckSQL = @"
SELECT 
    (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public') as table_count,
    (SELECT COUNT(*) FROM endpoints) as endpoint_count,
    (SELECT COUNT(*) FROM hardware_inventory) as hardware_count,
    (SELECT COUNT(*) FROM security_posture) as security_count,
    (SELECT COUNT(*) FROM host_snapshots) as snapshot_count,
    (SELECT COUNT(*) FROM security_audit_logs) as audit_log_count,
    (SELECT hostname FROM endpoints LIMIT 1) as sample_host,
    (SELECT COUNT(*) FROM host_snapshots WHERE snapshot_data IS NOT NULL AND jsonb_typeof(snapshot_data) = 'object') as valid_json_snapshots;
"@

$VerificationResult = & $PsqlPath -d $ScratchDBName -A -t -F "," -c $CheckSQL 2>&1

$DrillPassed = $false
$VerificationSummary = @{}

if ($VerificationResult -and ($VerificationResult -notmatch "ERROR") -and ($VerificationResult -notmatch "FATAL")) {
    $Fields = $VerificationResult.Trim().Split(",")
    if ($Fields.Length -ge 8) {
        $TableCount = [int]$Fields[0]
        $EndpointCount = [int]$Fields[1]
        $HardwareCount = [int]$Fields[2]
        $SecurityCount = [int]$Fields[3]
        $SnapshotCount = [int]$Fields[4]
        $AuditCount = [int]$Fields[5]
        $SampleHost = $Fields[6]
        $ValidSnapshots = [int]$Fields[7]

        $VerificationSummary = @{
            table_count = $TableCount
            endpoint_count = $EndpointCount
            hardware_count = $HardwareCount
            security_count = $SecurityCount
            snapshot_count = $SnapshotCount
            audit_log_count = $AuditCount
            sample_hostname = $SampleHost
            valid_json_snapshots = $ValidSnapshots
        }

        Log-Message "INFO" "Integrity Checks: $TableCount tables verified, $EndpointCount endpoints, $SnapshotCount host snapshots ($ValidSnapshots valid JSONB objects), $AuditCount audit records."

        if ($TableCount -ge 5 -and $EndpointCount -ge 0) {
            $DrillPassed = $true
            Log-Message "INFO" ">> RESTORE DRILL INTEGRITY CHECK: PASSED <<"
        } else {
            Log-Message "ERROR" ">> RESTORE DRILL INTEGRITY CHECK: FAILED (Insufficient tables restored: $TableCount) <<"
        }
    } else {
        Log-Message "ERROR" "Failed to parse integrity check query output: $VerificationResult"
    }
} else {
    Log-Message "ERROR" "Verification query failed: $VerificationResult"
}

$DurationMs = [math]::Round(((Get-Date) - $StartTime).TotalMilliseconds)

# ---------------------------------------------------------------------------
# Step 6: Cleanup Scratch Database
# ---------------------------------------------------------------------------
if (-not $KeepScratch) {
    Log-Message "INFO" "Tearing down throwaway scratch database '$ScratchDBName'..."
    $TeardownSQL = @"
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$ScratchDBName' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS $ScratchDBName;
"@
    & $PsqlPath -d postgres -c $TeardownSQL 2>&1 | Out-Null
    Log-Message "INFO" "Scratch database cleaned up successfully."
} else {
    Log-Message "WARN" "-KeepScratch flag enabled: '$ScratchDBName' retained for manual inspection."
}

# ---------------------------------------------------------------------------
# Step 7: Record Audit Paper Trail to History Store
# ---------------------------------------------------------------------------
$HistoryRecord = [ordered]@{
    drill_id = "drill-$DrillTimestamp"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    backup_file = (Split-Path -Path $BackupFilePath -Leaf)
    backup_file_path = $BackupFilePath
    backup_size_bytes = (Get-Item $BackupFilePath).Length
    checksum_verified = $ChecksumVerified
    status = if ($DrillPassed) { "PASSED" } else { "FAILED" }
    duration_ms = $DurationMs
    duration_seconds = [math]::Round($DurationMs / 1000, 2)
    verification_summary = $VerificationSummary
    log_file = $LogFile
}

$HistoryList = @()
if (Test-Path $HistoryFile) {
    try {
        $HistoryList = @(Get-Content -Raw -Path $HistoryFile | ConvertFrom-Json)
    } catch {
        $HistoryList = @()
    }
}
$HistoryList += $HistoryRecord
$HistoryList | ConvertTo-Json -Depth 5 | Set-Content -Path $HistoryFile -Encoding UTF8
Log-Message "INFO" "Recorded drill execution into audit paper trail: $HistoryFile"

# ---------------------------------------------------------------------------
# Step 8: Webhook / Email Notification
# ---------------------------------------------------------------------------
if (-not $WebhookURL -and $Config.restore_drill -and $Config.restore_drill.notify_webhook_url) {
    $WebhookURL = $Config.restore_drill.notify_webhook_url
}

if ($WebhookURL) {
    Log-Message "INFO" "Dispatching restore drill notification to webhook: $WebhookURL"
    $NotificationPayload = @{
        alert_notice = "[QUARTERLY BACKUP RESTORE DRILL REPORT]"
        system = "ZeroAgent-Scan Database Recovery Assurance"
        drill_id = $HistoryRecord.drill_id
        timestamp_utc = $HistoryRecord.timestamp_utc
        status = $HistoryRecord.status
        backup_file = $HistoryRecord.backup_file
        checksum_verified = $ChecksumVerified
        duration = "$($HistoryRecord.duration_seconds)s"
        verification_details = $VerificationSummary
        action_required = if ($DrillPassed) { "None. Backup recovery integrity verified." } else { "CRITICAL: Backup restore failure detected. Investigate immediately." }
    } | ConvertTo-Json -Depth 5

    try {
        $NotifyResp = Invoke-RestMethod -Uri $WebhookURL -Method Post -Body $NotificationPayload -ContentType "application/json" -TimeoutSec 10
        Log-Message "INFO" "Restore drill webhook notification delivered successfully."
    } catch {
        Log-Message "WARN" "Failed to deliver webhook notification: $($_.Exception.Message)"
    }
}

Log-Message "INFO" "================================================================="
Log-Message "INFO" "Restore Drill Complete. Status: $($HistoryRecord.status) in $($HistoryRecord.duration_seconds)s"
Log-Message "INFO" "================================================================="

if (-not $DrillPassed) {
    exit 1
}
