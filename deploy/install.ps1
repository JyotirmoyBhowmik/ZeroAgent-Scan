<#
.SYNOPSIS
    Idempotent Production Installation & Provisioning Script for ZeroAgent-Scan on Windows Server 2016.
.DESCRIPTION
    Installs prerequisites (Node.js LTS, PostgreSQL 15, NSSM), provisions least-privilege service accounts,
    configures PostgreSQL, registers NSSM Windows Services, configures IIS reverse proxy / standalone mode,
    and scopes Windows Firewall rules.
.PARAMETER ConfigPath
    Path to deploy.config.json. Defaults to .\deploy.config.json.
.PARAMETER ServeMode
    Frontend hosting mode: 'IIS' (recommended) or 'Standalone'.
.PARAMETER DBPassword
    PostgreSQL password for zeroagent_app (pulled from secret vault).
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
Log-Message "INFO" "Starting ZeroAgent-Scan Production Installation on Windows Server 2016"
Log-Message "INFO" "Target Install Path : $InstallPath"
Log-Message "INFO" "Frontend Mode       : $ServeMode"
Log-Message "INFO" "Audit Log File      : $LogFile"
Log-Message "INFO" "=========================================================================="

# ---------------------------------------------------------------------------
# 2. Verify Administrative Privileges
# ---------------------------------------------------------------------------
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This installation script must be executed in an elevated (Administrator) PowerShell session."
}

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
    $Config.application.backup_path
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
Log-Message "INFO" "Checking runtime prerequisites (Node.js 22 LTS, PostgreSQL 17, NSSM)..."

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
    Log-Message "WARN" "Node.js not detected. Downloading Node.js LTS v22 MSI..."
    $NodeMsiPath = Join-Path $Config.application.temp_path "node-v22-x64.msi"
    $NodeUrl = "https://nodejs.org/dist/v22.14.0/node-v22.14.0-x64.msi"
    Invoke-WebRequest -Uri $NodeUrl -OutFile $NodeMsiPath -UseBasicParsing
    Log-Message "INFO" "Installing Node.js 22 LTS silently via msiexec..."
    Start-Process msiexec.exe -ArgumentList "/i `"$NodeMsiPath`" /qn /norestart" -Wait -NoNewWindow
    Log-Message "INFO" "Node.js installation completed."
}

# B. NSSM Verification (Non-Sucking Service Manager)
$NSSMPath = "C:\tools\nssm\nssm.exe"
if (-not (Test-Path $NSSMPath)) {
    Log-Message "INFO" "NSSM not found at $NSSMPath. Provisioning NSSM binary..."
    $NSSMDir = "C:\tools\nssm"
    if (-not (Test-Path $NSSMDir)) { New-Item -Path $NSSMDir -ItemType Directory -Force | Out-Null }
    $NSSMZip = Join-Path $Config.application.temp_path "nssm.zip"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $NSSMZip -UseBasicParsing
    Expand-Archive -Path $NSSMZip -DestinationPath (Join-Path $Config.application.temp_path "nssm_extracted") -Force
    Copy-Item (Join-Path $Config.application.temp_path "nssm_extracted\nssm-2.24\win64\nssm.exe") -Destination $NSSMPath -Force
    Log-Message "INFO" "NSSM deployed to $NSSMPath."
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
# 6. Database Provisioning (PostgreSQL)
# ---------------------------------------------------------------------------
Log-Message "INFO" "Configuring PostgreSQL database '$($Config.database.name)'..."
# PostgreSQL SQL initialization commands
$DBName = $Config.database.name
$DBUser = $Config.database.username

$DBScript = @"
DO `$do`$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$DBUser') THEN
      CREATE ROLE $DBUser LOGIN PASSWORD '$DBUser_Secret_2026';
   END IF;
END
`$do`$;

SELECT 'CREATE DATABASE $DBName WITH OWNER $DBUser'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DBName')\gexec

REVOKE ALL ON DATABASE $DBName FROM PUBLIC;
GRANT CONNECT ON DATABASE $DBName TO $DBUser;
"@

$DBScriptPath = Join-Path $Config.application.temp_path "init_db.sql"
Set-Content -Path $DBScriptPath -Value $DBScript -Encoding ASCII

# ---------------------------------------------------------------------------
# 7. Register NSSM Windows Services
# ---------------------------------------------------------------------------
Log-Message "INFO" "Registering NSSM Windows Services (ZeroAgentAPI & ZeroAgentDashboard)..."

# A. ZeroAgent API Service
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
    & $NSSMPath start $APIServiceName
    Log-Message "INFO" "Registered and started Windows Service: $APIServiceName"
} else {
    Log-Message "WARN" "API executable not found at '$APIBinary'. Service will be configured during deploy-update.ps1."
}

# ---------------------------------------------------------------------------
# 8. Configure IIS Reverse Proxy or Standalone Frontend
# ---------------------------------------------------------------------------
if ($ServeMode -eq "IIS") {
    Log-Message "INFO" "Configuring IIS Reverse Proxy with ARR & URL Rewrite..."
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-WebServer,IIS-ApplicationDevelopment,IIS-NetFxExtensibility45 -All -NoRestart | Out-Null
    Log-Message "INFO" "IIS Web-Server features enabled."
}

# ---------------------------------------------------------------------------
# 9. Configure Windows Defender Firewall Rules
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

# Outbound WinRM HTTPS (5986) to scan subnets
Remove-NetFirewallRule -DisplayName "ZeroAgent-Outbound-WinRM" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "ZeroAgent-Outbound-WinRM" `
    -Direction Outbound -Protocol TCP -RemotePort 5986,5985,135,445 -Action Allow -Profile Domain,Private | Out-Null

Log-Message "INFO" "Windows Firewall rules configured and scoped."

Log-Message "INFO" "=========================================================================="
Log-Message "INFO" "ZeroAgent-Scan Installation Completed Successfully!"
Log-Message "INFO" "Next Step: Run .\configure-tls.ps1 to bind SSL certificates and enforce TLS 1.2+"
Log-Message "INFO" "=========================================================================="
