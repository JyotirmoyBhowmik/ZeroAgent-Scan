<#
.SYNOPSIS
    Collects USB devices, GPU video controllers, and monitor EDID telemetry.
.DESCRIPTION
    Queries Win32_PnPEntity (USB), Win32_VideoController, and Root\WMI (WmiMonitorID).
#>
function Get-PeripheralInventory {
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

    # 1. Video Controllers (GPUs)
    $videoRaw = @()
    try {
        $videoRaw = @(Get-CimInstance @cimParams -ClassName Win32_VideoController)
    } catch {
        $videoRaw = @()
    }

    $videoList = @()
    foreach ($v in $videoRaw) {
        $videoList += [PSCustomObject]@{
            name              = if ($v.Name) { [string]$v.Name.Trim() } else { "Generic Display Adapter" }
            driver_version    = if ($v.DriverVersion) { [string]$v.DriverVersion } else { $null }
            adapter_ram_bytes = if ($v.AdapterRAM) { [int64]$v.AdapterRAM } else { $null }
            video_processor   = if ($v.VideoProcessor) { [string]$v.VideoProcessor } else { $null }
        }
    }

    # 2. USB Devices
    $usbRaw = @()
    try {
        $usbRaw = @(Get-CimInstance @cimParams -ClassName Win32_PnPEntity -Filter "PNPClass = 'USB' or DeviceID like 'USB%'")
    } catch {
        $usbRaw = @()
    }

    $usbList = @()
    foreach ($u in $usbRaw) {
        $usbList += [PSCustomObject]@{
            device_id    = if ($u.DeviceID) { $u.DeviceID } else { "USB\UNKNOWN" }
            name         = if ($u.Name) { [string]$u.Name.Trim() } else { "USB Device" }
            manufacturer = if ($u.Manufacturer) { [string]$u.Manufacturer.Trim() } else { $null }
            status       = if ($u.Status) { $u.Status } else { "OK" }
        }
    }

    # 3. Monitors (EDID from WMI)
    $monitorList = @()
    try {
        $monitors = Get-CimInstance @cimParams -Namespace "Root\WMI" -ClassName WmiMonitorID
        foreach ($m in $monitors) {
            $mfg = if ($m.ManufacturerName) { -join ($m.ManufacturerName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) } else { $null }
            $prod = if ($m.ProductCodeID) { -join ($m.ProductCodeID | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) } else { $null }
            $serial = if ($m.SerialNumberID) { -join ($m.SerialNumberID | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) } else { $null }
            $year = if ($m.YearOfManufacture) { [int]$m.YearOfManufacture } else { $null }

            $monitorList += [PSCustomObject]@{
                manufacturer        = $mfg
                product_code        = $prod
                serial_number       = $serial
                year_of_manufacture = $year
            }
        }
    } catch {
        $monitorList = @()
    }

    return [PSCustomObject]@{
        video_controllers = $videoList
        usb_devices       = $usbList
        monitors          = $monitorList
    }
}
