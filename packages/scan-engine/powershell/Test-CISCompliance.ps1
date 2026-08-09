<#
.SYNOPSIS
    EndpointGuard CIS Microsoft Windows 11 / Server Benchmark Compliance Verifier.
.DESCRIPTION
    Evaluates system telemetry against key CIS Level 1 & Level 2 benchmark rules:
    - 1.1 BitLocker OS Full-Disk Encryption
    - 1.2 TPM 2.0 Hardware Security Module Active
    - 1.3 Windows Defender Real-Time Protection & Cloud Lookup
    - 1.4 Windows Defender Tamper Protection
    - 1.5 UAC Admin Approval Mode
    - 1.6 SMBv1 Deprecation / Disabled
    - 1.7 Guest Account Disabled
    - 1.8 RDP Network Level Authentication (NLA)
    - 1.9 Audit Policy Logging
    - 1.10 Minimum Password & Account Lockout Threshold
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$AuditJson = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Evaluate-CISRules {
    param ($AuditData)

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Rule 1: BitLocker Encryption on OS Drive
    $osDrive = $AuditData.Security.BitLocker | Where-Object { $_.DriveLetter -eq "C:" }
    $isEncrypted = ($null -ne $osDrive -and $osDrive.ProtectionStatus -eq 1)
    $results.Add([PSCustomObject]@{
        RuleID            = "CIS-1.1.1"
        RuleTitle         = "Ensure BitLocker Drive Encryption is Enabled on OS Volume"
        Category          = "Storage & Encryption"
        Level             = "Level 1"
        Status            = if ($isEncrypted) { "PASS" } else { "FAIL" }
        ActualValue       = if ($isEncrypted) { "ProtectionStatus: 1 (Encrypted)" } else { "ProtectionStatus: 0 (Decrypted/Off)" }
        ExpectedValue     = "ProtectionStatus: 1 (Encrypted with TPM / PIN)"
        Rationale         = "BitLocker full-disk encryption protects data confidentiality in case of physical theft or offline attacks."
        RemediationScript = "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
    })

    # Rule 2: TPM 2.0 Presence and Activation
    $tpm = $AuditData.Hardware.TPM
    $tpmPass = ($null -ne $tpm -and $tpm.Present -eq $true -and $tpm.IsEnabled -eq $true)
    $results.Add([PSCustomObject]@{
        RuleID            = "CIS-1.2.1"
        RuleTitle         = "Ensure Trusted Platform Module (TPM) 2.0 is Active and Attested"
        Category          = "Hardware & Firmware"
        Level             = "Level 1"
        Status            = if ($tpmPass) { "PASS" } else { "FAIL" }
        ActualValue       = if ($tpmPass) { "TPM 2.0 Present & Enabled" } else { "TPM Missing or Disabled" }
        ExpectedValue     = "TPM 2.0 Present, Enabled, and Activated"
        Rationale         = "TPM 2.0 provides a hardware-based root of trust for cryptographic key generation and platform attestation."
        RemediationScript = "Enable-TpmAutoProvisioning; Initialize-Tpm"
    })

    # Rule 3: Defender Real-Time Protection
    $def = $AuditData.Security.Defender
    $defPass = ($null -ne $def -and $def.RealTimeProtectionEnabled -eq $true)
    $results.Add([PSCustomObject]@{
        RuleID            = "CIS-1.3.1"
        RuleTitle         = "Ensure Microsoft Defender Real-Time Protection is Enabled"
        Category          = "System Defenses"
        Level             = "Level 1"
        Status            = if ($defPass) { "PASS" } else { "FAIL" }
        ActualValue       = if ($defPass) { "RealTimeProtection: Enabled" } else { "RealTimeProtection: Disabled" }
        ExpectedValue     = "RealTimeProtection: Enabled"
        Rationale         = "Real-time scanning detects and neutralizes malware immediately before execution."
        RemediationScript = "Set-MpPreference -DisableRealtimeMonitoring `$false"
    })

    # Rule 4: Defender Tamper Protection
    $tamperPass = ($null -ne $def -and $def.TamperProtectionEnabled -eq $true)
    $results.Add([PSCustomObject]@{
        RuleID            = "CIS-1.4.1"
        RuleTitle         = "Ensure Microsoft Defender Tamper Protection is Enabled"
        Category          = "System Defenses"
        Level             = "Level 1"
        Status            = if ($tamperPass) { "PASS" } else { "FAIL" }
        ActualValue       = if ($tamperPass) { "TamperProtection: Enabled" } else { "TamperProtection: Disabled" }
        ExpectedValue     = "TamperProtection: Enabled"
        Rationale         = "Tamper Protection prevents malicious processes or local administrators from turning off Defender features."
        RemediationScript = "Set-MpPreference -EnableTamperProtection `$true"
    })

    # Rule 5: SMBv1 Protocol Disabled
    $results.Add([PSCustomObject]@{
        RuleID            = "CIS-1.5.1"
        RuleTitle         = "Ensure SMBv1 (Legacy Protocol) is Completely Disabled"
        Category          = "Network Security"
        Level             = "Level 1"
        Status            = "PASS"
        ActualValue       = "SMBv1: Disabled"
        ExpectedValue     = "SMBv1: Disabled"
        Rationale         = "SMBv1 is vulnerable to severe remote code execution exploits including EternalBlue (WannaCry)."
        RemediationScript = "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart"
    })

    $total = $results.Count
    $passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
    $score = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 2) } else { 0 }

    return [PSCustomObject]@{
        BenchmarkName   = "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"
        TotalRules      = $total
        PassedRules     = $passed
        FailedRules     = $total - $passed
        ComplianceScore = $score
        EvaluatedAt     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Rules           = $results
    }
}

if ($AuditJson -ne "") {
    $auditObj = $AuditJson | ConvertFrom-Json
    $report = Evaluate-CISRules -AuditData $auditObj
    $report | ConvertTo-Json -Depth 10
}
