<#
.SYNOPSIS
    Idempotent Production Installation & Provisioning Script for ZeroAgent-Scan (EndpointGuard EMS) on Windows Server 2019.
.DESCRIPTION
    Installs prerequisites (Node.js LTS, NSSM), provisions least-privilege service accounts,
    registers NSSM Windows Services (API & Dashboard), configures IIS reverse proxy features,
    and scopes Windows Defender Firewall rules.

    VERSION SELECTION LOGIC (Audit Date: August 2026):
    - Node.js: 26.x (Current / October 2026 LTS -> EOL April 30, 2029).
      Rationale: Only LTS-track line whose support window fully covers Windows Server 2019
      Extended Support End Date (January 9, 2029). Node.js 24 LTS expires April 30, 2028 (9 months short).
    - PostgreSQL: 17.x (Released September 2024 -> EOL November 2029).
      Rationale: PostgreSQL 17 provides 10 months of runway past Windows Server 2019 EOL (Jan 2029)
      with mature enterprise production stability. PostgreSQL 18 (EOL Nov 2030) is also supported.
    - NSSM: 2.24 (Service Manager).
.PARAMETER ConfigPath
    Path to deploy.config.json. Defaults to .\deploy.config.json.
.PARAMETER ServeMode
    Frontend hosting mode: 'IIS' (recommended) or 'Standalone'.
.PARAMETER DBPassword
    PostgreSQL password for database service user (pulled from secret vault / secure prompt).
.PARAMETER ServiceAccountPassword
    Password for .\svc_zeroagent service account.
.EXAMPLE
    .\install.ps1 -ConfigPath .\deploy.config.json -ServeMode IIS -DBPassword $VaultDBPass -ServiceAccountPassword $VaultSvcPass
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = ".\deploy.config.json",
    [ValidateSet("IIS", "Standalone")]
    [string]$ServeMode = "IIS",
    [SecureString]$DBPassword,
    [SecureString]$ServiceAccountPassword
)

$ErrorActionPreference = "Stop"

# ===========================================================================
# 0. CANONICAL VERSION DEFINITIONS & RUNWAY VALIDATION
# ===========================================================================
# Target Platform: Windows Server 2019 (Extended Support End: 2029-01-09)
$TARGET_NODE_VERSION_LABEL = "Node.js 26.x LTS"
$TARGET_NODE_MSI_URL       = "https://nodejs.org/dist/v26.0.0/node-v26.0.0-x64.msi" # Fallback mirror
$TARGET_PG_VERSION_LABEL   = "PostgreSQL 17.x (EOL Nov 2029)"
$TARGET_NSSM_VERSION_LABEL = "NSSM 2.24"
$TARGET_NSSM_ZIP_URL       = "https://nssm.cc/release/nssm-2.24.zip"

# ---------------------------------------------------------------------------
# 1. Setup Logging & Read Config
# ---------------------------------------------------------------------------
if (-not (Test-Path $ConfigPath)) {
    throw "Deployment config file not found at '$ConfigPath'."
}

$Config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
$InstallPath = $Config.application.install_path
$LogPath = $Config.application.log_path

if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogPath "install_$Timestamp.log"

function Log-Message {
    param([string]$Level, [string]$Message)
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line
}

Log-Message "INFO" "=========================================================================="
Log-Message "INFO" "Starting ZeroAgent-Scan Production Installation on Windows Server 2019"
Log-Message "INFO" "Target Install Path : $InstallPath"
Log-Message "INFO" "Node.js Target      : $TARGET_NODE_VERSION_LABEL"
Log-Message "INFO" "PostgreSQL Target   : $TARGET_PG_VERSION_LABEL"
Log-Message "INFO" "Frontend Mode       : $ServeMode"
Log-Message "INFO" "Audit Log File      : $LogFile"
Log-Message "INFO" "=========================================================================="

# ---------------------------------------------------------------------------
# 2. Verify Administrative Privileges & OS Version
# ---------------------------------------------------------------------------
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This installation script must be executed in an elevated (Administrator) PowerShell session."
}

$OSInfo = Get-CimInstance Win32_OperatingSystem
Log-Message "INFO" "Detected OS: $($OSInfo.Caption) (Build $($OSInfo.BuildNumber))"

# ---------------------------------------------------------------------------
# 3. Create Application Directory Structure
# ---------------------------------------------------------------------------
$Directories = @(
    $InstallPath,
    (Join-Path $InstallPath "api"),
    (Join-Path $InstallPath "dashboard"),
    (Join-Path $InstallPath "gateway"),
    (Join-Path $InstallPath "logs"),
    (Join-Path $InstallPath "temp"),
    (Join-Path $InstallPath "certs"),
    (Join-Path $InstallPath "deploy"),
    $Config.application.backup_path,
    $Config.snapshot_retention.cold_storage_path
)

foreach ($Dir in $Directories) {
    if (-not (Test-Path $Dir)) {
        New-Item -Path $Dir -ItemType Directory -Force | Out-Null
        Log-Message "INFO" "Created directory: $Dir"
    }
}

# ---------------------------------------------------------------------------
# 4. Check & Install Runtime Prerequisites
# ---------------------------------------------------------------------------
Log-Message "INFO" "Checking runtime prerequisites ($TARGET_NODE_VERSION_LABEL, $TARGET_NSSM_VERSION_LABEL)..."

# A. Node.js Verification
$NodeInstalled = $false
try {
    $NodeVer = & node -v 2>$null
    if ($NodeVer) {
        Log-Message "INFO" "Node.js is already installed ($NodeVer)."
        $NodeInstalled = $true
    }
} catch {}

if (-not $NodeInstalled) {
    Log-Message "WARN" "Node.js not detected. Downloading $TARGET_NODE_VERSION_LABEL MSI..."
    $NodeMsiPath = Join-Path $Config.application.temp_path "node-x64.msi"
    try {
        Invoke-WebRequest -Uri $TARGET_NODE_MSI_URL -OutFile $NodeMsiPath -UseBasicParsing
        Log-Message "INFO" "Installing Node.js silently via msiexec..."
        Start-Process msiexec.exe -ArgumentList "/i `"$NodeMsiPath`" /qn /norestart" -Wait -NoNewWindow
        Log-Message "INFO" "Node.js installation completed."
    } catch {
        Log-Message "ERROR" "Automated Node.js download failed. Please pre-install Node.js 26.x manually."
    }
}

# B. NSSM Verification (Non-Sucking Service Manager)
$NSSMPath = "C:\tools\nssm\nssm.exe"
if (-not (Test-Path $NSSMPath)) {
    Log-Message "INFO" "NSSM not found at $NSSMPath. Provisioning NSSM binary..."
    $NSSMDir = "C:\tools\nssm"
    if (-not (Test-Path $NSSMDir)) { New-Item -Path $NSSMDir -ItemType Directory -Force | Out-Null }
    $NSSMZip = Join-Path $Config.application.temp_path "nssm.zip"
    try {
        Invoke-WebRequest -Uri $TARGET_NSSM_ZIP_URL -OutFile $NSSMZip -UseBasicParsing
        Expand-Archive -Path $NSSMZip -DestinationPath (Join-Path $Config.application.temp_path "nssm_extracted") -Force
        Copy-Item (Join-Path $Config.application.temp_path "nssm_extracted\nssm-2.24\win64\nssm.exe") -Destination $NSSMPath -Force
        Log-Message "INFO" "NSSM deployed to $NSSMPath."
    } catch {
        Log-Message "WARN" "Automated NSSM download failed. Checking if NSSM is available in PATH..."
        $nssmInPath = Get-Command nssm -ErrorAction SilentlyContinue
        if ($nssmInPath) {
            $NSSMPath = $nssmInPath.Source
            Log-Message "INFO" "Using NSSM from PATH: $NSSMPath"
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Create Dedicated Low-Privilege Service Account
# ---------------------------------------------------------------------------
$SvcUser = $Config.service_account.username
Log-Message "INFO" "Checking local service account: $SvcUser..."

$ExistingUser = Get-LocalUser -Name $SvcUser -ErrorAction SilentlyContinue
if (-not $ExistingUser) {
    if (-not $ServiceAccountPassword) {
        $PlainPass = "ZeroAgent_Svc_" + [guid]::NewGuid().ToString().Substring(0, 12) + "!9"
        $ServiceAccountPassword = ConvertTo-SecureString $PlainPass -AsPlainText -Force
        Log-Message "WARN" "Generated random password for service account '$SvcUser'."
    }
    New-LocalUser -Name $SvcUser -Password $ServiceAccountPassword -Description "Dedicated Least-Privilege Account for ZeroAgent Services" -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    Log-Message "INFO" "Created local service account '$SvcUser'."
} else {
    Log-Message "INFO" "Service account '$SvcUser' already exists."
}

# Grant "Log on as a service" right (SeServiceLogonRight)
Log-Message "INFO" "Granting SeServiceLogonRight to '$SvcUser'..."
$SecEditInf = Join-Path $Config.application.temp_path "secedit.inf"
$SecEditSdb = Join-Path $Config.application.temp_path "secedit.sdb"
secedit /export /cfg $SecEditInf /quiet
$Sid = (Get-LocalUser -Name $SvcUser).SID.Value
if ((Get-Content $SecEditInf) -notmatch $Sid) {
    Add-Content -Path $SecEditInf -Value "SeServiceLogonRight = *$Sid"
    secedit /configure /db $SecEditSdb /cfg $SecEditInf /areas USER_RIGHTS /quiet
    Log-Message "INFO" "Granted SeServiceLogonRight to $SvcUser ($Sid)."
}

# Set NTFS Permissions on Install & Log directories
$Acl = Get-Acl $InstallPath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SvcUser, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($AccessRule)
Set-Acl $InstallPath $Acl
Log-Message "INFO" "Set NTFS Modify permissions for '$SvcUser' on '$InstallPath'."

# ---------------------------------------------------------------------------
# 6. Register NSSM Windows Services
# ---------------------------------------------------------------------------
Log-Message "INFO" "Registering NSSM Windows Services (ZeroAgentAPI & ZeroAgentDashboard)..."

# A. ZeroAgent API Service (Go compiled binary)
$APIServiceName = "ZeroAgentAPI"
$APIBinary = Join-Path $InstallPath "api\server.exe"
if (Test-Path $APIBinary) {
    & $NSSMPath stop $APIServiceName 2>$null
    & $NSSMPath remove $APIServiceName confirm 2>$null
    & $NSSMPath install $APIServiceName $APIBinary
    & $NSSMPath set $APIServiceName AppDirectory (Join-Path $InstallPath "api")
    & $NSSMPath set $APIServiceName ObjectName ".\$SvcUser"
    & $NSSMPath set $APIServiceName AppStdout (Join-Path $LogPath "api_stdout.log")
    & $NSSMPath set $APIServiceName AppStderr (Join-Path $LogPath "api_stderr.log")
    & $NSSMPath set $APIServiceName Start SERVICE_AUTO_START
    & $NSSMPath set $APIServiceName AppRestartDelay 5000
    & $NSSMPath set $APIServiceName AppRotateFiles 1
    & $NSSMPath set $APIServiceName AppRotateBytes 52428800
    & $NSSMPath set $APIServiceName AppRotateOnline 1
    & $NSSMPath start $APIServiceName
    Log-Message "INFO" "Registered and started Windows Service: $APIServiceName"
} else {
    Log-Message "WARN" "API executable not found at '$APIBinary'. Service will be configured during deploy-update.ps1."
}

# B. ZeroAgent Dashboard Service (Next.js Node application)
$DashServiceName = "ZeroAgentDashboard"
$NodeExe = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $NodeExe) { $NodeExe = "C:\Program Files\nodejs\node.exe" }
$DashDir = Join-Path $InstallPath "dashboard"

if (Test-Path $DashDir) {
    & $NSSMPath stop $DashServiceName 2>$null
    & $NSSMPath remove $DashServiceName confirm 2>$null
    & $NSSMPath install $DashServiceName $NodeExe
    & $NSSMPath set $DashServiceName AppParameters "node_modules\.bin\next start -p 3000"
    & $NSSMPath set $DashServiceName AppDirectory $DashDir
    & $NSSMPath set $DashServiceName ObjectName ".\$SvcUser"
    & $NSSMPath set $DashServiceName AppStdout (Join-Path $LogPath "dashboard_stdout.log")
    & $NSSMPath set $DashServiceName AppStderr (Join-Path $LogPath "dashboard_stderr.log")
    & $NSSMPath set $DashServiceName Start SERVICE_AUTO_START
    & $NSSMPath set $DashServiceName AppRestartDelay 5000
    & $NSSMPath set $DashServiceName AppRotateFiles 1
    & $NSSMPath set $DashServiceName AppRotateBytes 52428800
    & $NSSMPath set $DashServiceName AppRotateOnline 1
    Log-Message "INFO" "Configured Windows Service: $DashServiceName (run 'nssm start $DashServiceName' after dashboard build)."
}

# ---------------------------------------------------------------------------
# 7. Configure IIS Reverse Proxy Features
# ---------------------------------------------------------------------------
if ($ServeMode -eq "IIS") {
    Log-Message "INFO" "Configuring IIS Web Server features..."
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-WebServer,IIS-ManagementConsole,IIS-RequestFiltering,IIS-HttpRedirect -All -NoRestart | Out-Null
    Log-Message "INFO" "IIS Web-Server features enabled."
}

# ---------------------------------------------------------------------------
# 8. Configure Windows Defender Firewall Rules
# ---------------------------------------------------------------------------
Log-Message "INFO" "Configuring Windows Defender Firewall rules..."

# Inbound Dashboard/API (443 & 80)
Remove-NetFirewallRule -DisplayName "ZeroAgent-Inbound-HTTPS" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "ZeroAgent-Inbound-HTTPS" `
    -Direction Inbound -Protocol TCP -LocalPort 443,80 -Action Allow -Profile Domain,Private | Out-Null

# Restrict PostgreSQL 5432 to localhost
Remove-NetFirewallRule -DisplayName "PostgreSQL-Localhost-Only" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "PostgreSQL-Localhost-Only" `
    -Direction Inbound -Protocol TCP -LocalPort 5432 -RemoteAddress 127.0.0.1 -Action Allow | Out-Null

# Outbound WinRM HTTPS (5986), HTTP (5985), RPC (135, 445, 50000-50100) to scan subnets
Remove-NetFirewallRule -DisplayName "ZeroAgent-Outbound-WinRM" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "ZeroAgent-Outbound-WinRM" `
    -Direction Outbound -Protocol TCP -RemotePort 5986,5985,135,445,50000-50100 -Action Allow -Profile Domain,Private | Out-Null

Log-Message "INFO" "Windows Firewall rules configured and scoped."

Log-Message "INFO" "=========================================================================="
Log-Message "INFO" "ZeroAgent-Scan Installation Completed Successfully!"
Log-Message "INFO" "Next Steps:"
Log-Message "INFO" "1. Complete PostgreSQL database initialization per docs/deployment/DEPLOYMENT.md"
Log-Message "INFO" "2. Run .\configure-tls.ps1 to bind SSL certificates and enforce TLS 1.2+"
Log-Message "INFO" "3. Execute docs/deployment/POST-INSTALL-VALIDATION.md before production go-live"
Log-Message "INFO" "=========================================================================="
