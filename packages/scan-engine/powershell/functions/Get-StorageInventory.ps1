<#
.SYNOPSIS
    Collects physical storage drive details, SMART health status, and partitions.
.DESCRIPTION
    Queries Win32_DiskDrive and Win32_DiskPartition.
#>
function Get-StorageInventory {
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

    # 1. Physical Disks
    $disksRaw = @()
    try {
        $disksRaw = @(Get-CimInstance @cimParams -ClassName Win32_DiskDrive)
    } catch {
        $disksRaw = @()
    }

    # 2. Disk Partitions
    $partitionsRaw = @()
    try {
        $partitionsRaw = @(Get-CimInstance @cimParams -ClassName Win32_DiskPartition)
    } catch {
        $partitionsRaw = @()
    }

    $diskList = @()
    foreach ($d in $disksRaw) {
        $busType = if ($d.InterfaceType) { $d.InterfaceType } else { "SCSI" }
        $smart = if ($d.Status) { $d.Status } else { "OK" }
        $size = if ($d.Size) { [int64]$d.Size } else { [int64]0 }
        $partCount = if ($d.Partitions) { [int]$d.Partitions } else { 0 }

        $mediaType = "Fixed hard disk media"
        if ($d.MediaType) {
            $mediaType = $d.MediaType
        }

        $diskList += [PSCustomObject]@{
            index         = if ($null -ne $d.Index) { [int]$d.Index } else { 0 }
            model         = if ($d.Model) { [string]$d.Model.Trim() } else { "Unknown Drive" }
            bus_type      = $busType
            size_bytes    = $size
            partitions    = $partCount
            smart_status  = $smart
            serial_number = if ($d.SerialNumber) { [string]$d.SerialNumber.Trim() } else { $null }
            media_type    = $mediaType
        }
    }

    $partitionList = @()
    foreach ($p in $partitionsRaw) {
        $partitionList += [PSCustomObject]@{
            name        = $p.Name
            disk_index  = if ($null -ne $p.DiskIndex) { [int]$p.DiskIndex } else { 0 }
            size_bytes  = if ($p.Size) { [int64]$p.Size } else { [int64]0 }
            bootable    = if ($p.Bootable) { [bool]$p.Bootable } else { $false }
            primary     = if ($p.PrimaryPartition) { [bool]$p.PrimaryPartition } else { $false }
        }
    }

    return [PSCustomObject]@{
        disk_count = [int]$diskList.Count
        disks      = $diskList
        partitions = $partitionList
    }
}
