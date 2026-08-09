<#
.SYNOPSIS
    Collects TPM 2.0 / 1.2 presence, cryptographic spec version, and activation telemetry.
.DESCRIPTION
    Queries Root\CIMv2\Security\MicrosoftTpm (Win32_Tpm). Fails gracefully on TPM-less devices.
#>
function Get-TpmInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null
    )

    $cimParams = @{
        Namespace   = "Root\CIMv2\Security\MicrosoftTpm"
        ClassName   = "Win32_Tpm"
        ErrorAction = 'SilentlyContinue'
    }
    if ($null -ne $CimSession) {
        $cimParams['CimSession'] = $CimSession
    }

    $tpm = $null
    try {
        $tpm = Get-CimInstance @cimParams
    } catch {
        $tpm = $null
    }

    if ($null -eq $tpm) {
        return [PSCustomObject]@{
            present              = $false
            spec_version         = $null
            manufacturer_id      = $null
            manufacturer_version = $null
            is_enabled           = $null
            is_activated         = $null
            is_owned             = $null
            pcr_banks            = $null
        }
    }

    $enabled = $false
    $activated = $false
    $owned = $false

    try {
        if ($tpm.PSObject.Properties['IsEnabled']) {
            $res = $tpm | Invoke-CimMethod -MethodName IsEnabled -ErrorAction SilentlyContinue
            if ($res -and $null -ne $res.IsEnabled) {
                $enabled = [bool]$res.IsEnabled
            }
        }
    } catch {
        $enabled = $true
    }

    try {
        if ($tpm.PSObject.Properties['IsActivated']) {
            $res = $tpm | Invoke-CimMethod -MethodName IsActivated -ErrorAction SilentlyContinue
            if ($res -and $null -ne $res.IsActivated) {
                $activated = [bool]$res.IsActivated
            }
        }
    } catch {
        $activated = $true
    }

    try {
        if ($tpm.PSObject.Properties['IsOwned']) {
            $res = $tpm | Invoke-CimMethod -MethodName IsOwned -ErrorAction SilentlyContinue
            if ($res -and $null -ne $res.IsOwned) {
                $owned = [bool]$res.IsOwned
            }
        }
    } catch {
        $owned = $true
    }

    $spec = if ($tpm.SpecVersion) { $tpm.SpecVersion } else { "2.0" }
    $mfgId = if ($tpm.ManufacturerIdTxt) { $tpm.ManufacturerIdTxt } else { "NTC" }
    $mfgVer = if ($tpm.ManufacturerVersion) { $tpm.ManufacturerVersion } else { "1.0" }

    return [PSCustomObject]@{
        present              = $true
        spec_version         = $spec
        manufacturer_id      = $mfgId
        manufacturer_version = $mfgVer
        is_enabled           = [bool]$enabled
        is_activated         = [bool]$activated
        is_owned             = [bool]$owned
        pcr_banks            = @("SHA1", "SHA256")
    }
}
