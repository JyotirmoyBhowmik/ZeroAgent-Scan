<#
.SYNOPSIS
    Collects detailed physical memory topology and per-DIMM slot telemetry.
.DESCRIPTION
    Queries Win32_PhysicalMemory and Win32_PhysicalMemoryArray.
#>
function Get-MemoryInventory {
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

    # 1. Physical Memory DIMMs
    $dimmsRaw = @()
    try {
        $dimmsRaw = @(Get-CimInstance @cimParams -ClassName Win32_PhysicalMemory)
    } catch {
        $dimmsRaw = @()
    }

    # 2. Memory Array (Total slots)
    $arrayRaw = @()
    try {
        $arrayRaw = @(Get-CimInstance @cimParams -ClassName Win32_PhysicalMemoryArray)
    } catch {
        $arrayRaw = @()
    }

    $totalCapacity = [int64]0
    $dimmList = @()

    foreach ($d in $dimmsRaw) {
        $cap = if ($d.Capacity) { [int64]$d.Capacity } else { [int64]0 }
        $totalCapacity += $cap

        $slotLabel = if ($d.BankLabel) { $d.BankLabel } elseif ($d.DeviceLocator) { $d.DeviceLocator } else { "DIMM Slot" }

        $dimmList += [PSCustomObject]@{
            slot           = $slotLabel
            capacity_bytes = $cap
            speed_mhz      = if ($d.Speed) { [int]$d.Speed } else { $null }
            manufacturer   = if ($d.Manufacturer) { [string]$d.Manufacturer.Trim() } else { $null }
            part_number    = if ($d.PartNumber) { [string]$d.PartNumber.Trim() } else { $null }
            serial_number  = if ($d.SerialNumber) { [string]$d.SerialNumber.Trim() } else { $null }
            form_factor    = switch ($d.FormFactor) {
                8 { "DIMM" }
                12 { "SODIMM" }
                Default { "DIMM" }
            }
        }
    }

    $totalSlots = 0
    foreach ($a in $arrayRaw) {
        if ($a.MemoryDevices) {
            $totalSlots += [int]$a.MemoryDevices
        }
    }
    if ($totalSlots -eq 0) {
        $totalSlots = if ($dimmList.Count -gt 0) { $dimmList.Count } else { 2 }
    }

    return [PSCustomObject]@{
        total_capacity_bytes = [int64]$totalCapacity
        slots_used           = [int]$dimmList.Count
        total_slots          = [int]$totalSlots
        dimms                = $dimmList
    }
}
