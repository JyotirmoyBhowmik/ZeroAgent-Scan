<#
.SYNOPSIS
    Collects Motherboard, BIOS, SMBIOS GUID, Secure Boot state, and UEFI mode telemetry.
.DESCRIPTION
    Executes read-only CIM queries against Win32_BIOS, Win32_BaseBoard, Win32_ComputerSystemProduct,
    and inspects the SecureBoot registry state. Fails gracefully per-field.
#>
function Get-BiosFirmwareInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null
    )

    $cimParams = @{
        ErrorAction = 'SilentlyContinue'
    }
    if ($null -ne $CimSession) {
        $cimParams['CimSession'] = $CimSession
    }

    # 1. BIOS Info
    $bios = $null
    try {
        $bios = Get-CimInstance @cimParams -ClassName Win32_BIOS
    } catch {
        $bios = $null
    }

    # 2. BaseBoard / Motherboard
    $board = $null
    try {
        $board = Get-CimInstance @cimParams -ClassName Win32_BaseBoard
    } catch {
        $board = $null
    }

    # 3. SMBIOS Product & UUID
    $csp = $null
    try {
        $csp = Get-CimInstance @cimParams -ClassName Win32_ComputerSystemProduct
    } catch {
        $csp = $null
    }

    # 4. Secure Boot & UEFI Mode State
    $secureBootEnabled = $false
    $uefiMode = $false

    try {
        if ($null -ne $bios -and $bios.SMBIOSBIOSVersion) {
            # Check UEFI from PE / firmware environment or registry
            $sbVal = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue).UEFISecureBootEnabled
            if ($null -ne $sbVal -and $sbVal -eq 1) {
                $secureBootEnabled = $true
                $uefiMode = $true
            } else {
                # Fallback: check SecureBoot cmdlet if running locally
                if ($null -eq $CimSession) {
                    $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                    if ($null -ne $sb -and $sb -eq $true) {
                        $secureBootEnabled = $true
                        $uefiMode = $true
                    }
                }
            }
        }
    } catch {
        $secureBootEnabled = $false
        $uefiMode = $false
    }

    return [PSCustomObject]@{
        motherboard_serial       = if ($board) { $board.SerialNumber } else { $null }
        motherboard_manufacturer = if ($board) { $board.Manufacturer } else { $null }
        motherboard_product      = if ($board) { $board.Product } else { $null }
        vendor                   = if ($bios) { $bios.Manufacturer } else { "Unknown" }
        version                  = if ($bios) { $bios.SMBIOSBIOSVersion } else { "Unknown" }
        release_date             = if ($bios) { if ($bios.ReleaseDate) { [string]$bios.ReleaseDate } else { $null } } else { $null }
        smbios_version           = if ($bios) { $bios.Version } else { $null }
        smbios_guid              = if ($csp) { $csp.UUID } else { $null }
        secure_boot_enabled      = [bool]$secureBootEnabled
        uefi_mode                = [bool]$uefiMode
    }
}
