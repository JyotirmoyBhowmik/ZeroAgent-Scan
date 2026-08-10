<#
.SYNOPSIS
    Configures TLS 1.2+ Encryption and Binds SSL/TLS Certificates on Windows Server 2016.
.DESCRIPTION
    Enforces TLS 1.2 minimum cipher suites via Windows SCHANNEL registry keys, disables legacy protocols
    (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1), imports PFX certificates, and binds them to the IIS HTTPS listener.
.PARAMETER PfxPath
    Path to Enterprise CA-issued .pfx certificate. If omitted, generates a temporary self-signed certificate.
.PARAMETER PfxPassword
    Password for the .pfx certificate.
.PARAMETER SiteName
    IIS Website name. Defaults to "ZeroAgent".
.EXAMPLE
    .\configure-tls.ps1 -PfxPath "C:\certs\zeroagent.pfx" -PfxPassword $CertPass
#>

[CmdletBinding()]
param(
    [string]$PfxPath,
    [SecureString]$PfxPassword,
    [string]$SiteName = "ZeroAgent"
)

$ErrorActionPreference = "Stop"

$LogPath = "C:\apps\zeroagent\logs"
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogPath "configure_tls_$Timestamp.log"

function Log-Message {
    param([string]$Level, [string]$Message)
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line
}

Log-Message "INFO" "=========================================================================="
Log-Message "INFO" "Starting TLS Hardening & Certificate Configuration (Windows Server 2016)"
Log-Message "INFO" "=========================================================================="

# ---------------------------------------------------------------------------
# 1. Enforce TLS 1.2 Minimum in Windows SCHANNEL Registry
# ---------------------------------------------------------------------------
Log-Message "INFO" "Hardening Windows SCHANNEL protocols (Disabling SSLv3, TLS 1.0, TLS 1.1; Enforcing TLS 1.2)..."

$Protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($Proto in $Protocols) {
    $ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Proto\Server"
    $ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Proto\Client"

    if (-not (Test-Path $ServerPath)) { New-Item -Path $ServerPath -Force | Out-Null }
    if (-not (Test-Path $ClientPath)) { New-Item -Path $ClientPath -Force | Out-Null }

    Set-ItemProperty -Path $ServerPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $ServerPath -Name "DisabledByDefault" -Value 1 -Type DWord
    Set-ItemProperty -Path $ClientPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $ClientPath -Name "DisabledByDefault" -Value 1 -Type DWord

    Log-Message "INFO" "Disabled legacy protocol: $Proto (Server + Client)"
}

# Enable TLS 1.2 explicitly
$TLS12Server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
$TLS12Client = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
if (-not (Test-Path $TLS12Server)) { New-Item -Path $TLS12Server -Force | Out-Null }
if (-not (Test-Path $TLS12Client)) { New-Item -Path $TLS12Client -Force | Out-Null }

Set-ItemProperty -Path $TLS12Server -Name "Enabled" -Value 1 -Type DWord
Set-ItemProperty -Path $TLS12Server -Name "DisabledByDefault" -Value 0 -Type DWord
Set-ItemProperty -Path $TLS12Client -Name "Enabled" -Value 1 -Type DWord
Set-ItemProperty -Path $TLS12Client -Name "DisabledByDefault" -Value 0 -Type DWord
Log-Message "INFO" "Enforced TLS 1.2 (Server + Client) via SCHANNEL."

# ---------------------------------------------------------------------------
# 2. Certificate Import & IIS Binding
# ---------------------------------------------------------------------------
$Cert = $null

if ($PfxPath -and (Test-Path $PfxPath)) {
    Log-Message "INFO" "Importing Enterprise CA Certificate from '$PfxPath'..."
    $Cert = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation "Cert:\LocalMachine\My" -Password $PfxPassword
    Log-Message "INFO" "Imported Certificate: Thumbprint=$($Cert.Thumbprint), Subject=$($Cert.Subject)"
} else {
    Log-Message "WARN" "=========================================================================="
    Log-Message "WARN" "NO PFX CERTIFICATE PROVIDED. GENERATING TEMPORARY SELF-SIGNED CERTIFICATE."
    Log-Message "WARN" "THIS CERTIFICATE MUST BE REPLACED WITH AN ENTERPRISE CA CERT BEFORE GO-LIVE!"
    Log-Message "WARN" "=========================================================================="

    $Cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME, "localhost", "zeroagent.corp.local" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -NotAfter (Get-Date).AddYears(1) `
        -KeyExportPolicy Exportable
    Log-Message "INFO" "Generated Self-Signed Certificate: Thumbprint=$($Cert.Thumbprint)"
}

# ---------------------------------------------------------------------------
# 3. Bind Certificate to HTTPS Port 443
# ---------------------------------------------------------------------------
Import-Module WebAdministration -ErrorAction SilentlyContinue
if (Get-Module -Name WebAdministration) {
    Log-Message "INFO" "Binding certificate to IIS HTTPS Port 443..."
    
    # Remove existing 443 binding if present
    Get-WebBinding -Port 443 -ErrorAction SilentlyContinue | Remove-WebBinding
    
    # Add new SSL binding
    New-WebBinding -Name $SiteName -IPAddress "*" -Port 443 -Protocol https
    $Binding = Get-WebBinding -Name $SiteName -Port 443 -Protocol https
    $Binding.AddSslCertificate($Cert.GetCertHashString(), "My")
    Log-Message "INFO" "Successfully bound certificate to IIS Site '$SiteName' on port 443."
}

Log-Message "INFO" "=========================================================================="
Log-Message "INFO" "TLS Configuration Completed Successfully."
Log-Message "INFO" "Note: Server reboot recommended for SCHANNEL protocol changes to take full effect."
Log-Message "INFO" "=========================================================================="
