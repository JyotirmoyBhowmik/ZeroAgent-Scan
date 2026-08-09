<#
.SYNOPSIS
    Collects network adapter configuration, MACs, IPv4/IPv6, gateway, DNS, and link speed telemetry.
.DESCRIPTION
    Queries Win32_NetworkAdapterConfiguration (IPEnabled=True) and Win32_NetworkAdapter.
#>
function Get-NetworkInventory {
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

    # 1. IP-enabled configurations
    $ipConfigs = @()
    try {
        $ipConfigs = @(Get-CimInstance @cimParams -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True")
    } catch {
        $ipConfigs = @()
    }

    # 2. Physical adapters for LinkSpeed
    $adapters = @()
    try {
        $adapters = @(Get-CimInstance @cimParams -ClassName Win32_NetworkAdapter)
    } catch {
        $adapters = @()
    }

    $adapterSpeedMap = @{}
    foreach ($a in $adapters) {
        if ($a.MACAddress) {
            $speedMbps = if ($a.Speed) { [int64]($a.Speed / 1000000) } else { $null }
            $adapterSpeedMap[$a.MACAddress.ToUpper()] = @{
                SpeedMbps = $speedMbps
                Physical  = if ($null -ne $a.PhysicalAdapter) { [bool]$a.PhysicalAdapter } else { $true }
            }
        }
    }

    $adapterList = @()
    foreach ($nic in $ipConfigs) {
        $mac = if ($nic.MACAddress) { $nic.MACAddress.ToUpper() } else { "00:00:00:00:00:00" }
        $speedInfo = $adapterSpeedMap[$mac]

        $speedMbps = if ($speedInfo) { $speedInfo.SpeedMbps } else { $null }
        $isPhysical = if ($speedInfo) { $speedInfo.Physical } else { $true }

        $ipAddrs = @()
        if ($nic.IPAddress) {
            foreach ($ip in $nic.IPAddress) {
                if ($ip) { $ipAddrs += [string]$ip }
            }
        }

        $subnets = @()
        if ($nic.IPSubnet) {
            foreach ($s in $nic.IPSubnet) {
                if ($s) { $subnets += [string]$s }
            }
        }

        $gateways = @()
        if ($nic.DefaultIPGateway) {
            foreach ($g in $nic.DefaultIPGateway) {
                if ($g) { $gateways += [string]$g }
            }
        }

        $dns = @()
        if ($nic.DNSServerSearchOrder) {
            foreach ($d in $nic.DNSServerSearchOrder) {
                if ($d) { $dns += [string]$d }
            }
        }

        $adapterList += [PSCustomObject]@{
            description      = if ($nic.Description) { [string]$nic.Description.Trim() } else { "Network Adapter" }
            mac_address      = $mac
            ip_addresses     = $ipAddrs
            ip_subnets       = $subnets
            default_gateways = $gateways
            dns_servers      = $dns
            dhcp_enabled     = if ($null -ne $nic.DHCPEnabled) { [bool]$nic.DHCPEnabled } else { $false }
            link_speed_mbps  = $speedMbps
            physical_adapter = $isPhysical
        }
    }

    return [PSCustomObject]@{
        adapters = $adapterList
    }
}
