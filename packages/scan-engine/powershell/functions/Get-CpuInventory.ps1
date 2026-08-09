<#
.SYNOPSIS
    Collects CPU model, core/thread counts, hardware virtualization (VT-x/AMD-V), and VBS/HVCI status.
.DESCRIPTION
    Queries Win32_Processor and Root\Microsoft\Windows\DeviceGuard (Win32_DeviceGuard).
#>
function Get-CpuInventory {
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

    # 1. Processors
    $cpus = @()
    try {
        $cpus = @(Get-CimInstance @cimParams -ClassName Win32_Processor)
    } catch {
        $cpus = @()
    }

    $socketCount = if ($cpus.Count -gt 0) { $cpus.Count } else { 1 }
    $totalCores = 0
    $totalThreads = 0
    $models = @()
    $virtEnabled = $null

    $processorList = @()
    foreach ($cpu in $cpus) {
        $cores = if ($cpu.NumberOfCores) { [int]$cpu.NumberOfCores } else { 1 }
        $threads = if ($cpu.NumberOfLogicalProcessors) { [int]$cpu.NumberOfLogicalProcessors } else { $cores }
        $totalCores += $cores
        $totalThreads += $threads

        if ($cpu.Name -and ($models -notcontains $cpu.Name)) {
            $models += $cpu.Name
        }

        if ($null -ne $cpu.VirtualizationFirmwareEnabled) {
            $virtEnabled = [bool]$cpu.VirtualizationFirmwareEnabled
        }

        $processorList += [PSCustomObject]@{
            device_id     = $cpu.DeviceID
            name          = $cpu.Name
            manufacturer  = $cpu.Manufacturer
            cores         = $cores
            threads       = $threads
            max_clock_mhz = if ($cpu.MaxClockSpeed) { [int]$cpu.MaxClockSpeed } else { 0 }
            architecture  = switch ($cpu.Architecture) {
                0 { "x86" }
                9 { "x64" }
                5 { "ARM" }
                12 { "ARM64" }
                Default { "Unknown" }
            }
            socket        = if ($cpu.SocketDesignation) { $cpu.SocketDesignation } else { "Socket 0" }
        }
    }

    if ($totalCores -eq 0) { $totalCores = 1 }
    if ($totalThreads -eq 0) { $totalThreads = 1 }
    if ($models.Count -eq 0) { $models = @("Unknown CPU") }

    # 2. VBS & HVCI (Device Guard)
    $vbsStatus = $null
    $hvciStatus = $null
    try {
        $dg = Get-CimInstance @cimParams -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard
        if ($null -ne $dg) {
            $vbsStatus = switch ($dg.VirtualizationBasedSecurityStatus) {
                0 { "Disabled" }
                1 { "EnabledButNotRunning" }
                2 { "Running" }
                Default { "Unknown" }
            }
            $hvciStatus = switch ($dg.HypervisorEnforcedCodeIntegrityStatus) {
                0 { "Disabled" }
                1 { "Enabled" }
                Default { "Unknown" }
            }
        }
    } catch {
        $vbsStatus = $null
        $hvciStatus = $null
    }

    return [PSCustomObject]@{
        models                          = $models
        socket_count                    = [int]$socketCount
        total_cores                     = [int]$totalCores
        total_threads                   = [int]$totalThreads
        virtualization_firmware_enabled = $virtEnabled
        vbs_status                      = $vbsStatus
        hvci_status                     = $hvciStatus
        processors                      = $processorList
    }
}
