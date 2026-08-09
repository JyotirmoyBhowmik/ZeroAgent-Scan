<#
.SYNOPSIS
    Collects installed software packages, architecture (x86/x64), and OS hotfix/KB levels.
.DESCRIPTION
    Queries Win32_QuickFixEngineering and HKLM Uninstall registry hives.
#>
function Get-SoftwareInventory {
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

    # 1. Hotfixes (KBs)
    $hotfixesRaw = @()
    try {
        $hotfixesRaw = @(Get-CimInstance @cimParams -ClassName Win32_QuickFixEngineering)
    } catch {
        $hotfixesRaw = @()
    }

    $hotfixList = @()
    foreach ($hf in $hotfixesRaw) {
        if ($hf.HotFixID) {
            $installedOn = if ($hf.InstalledOn) { [string]$hf.InstalledOn } else { $null }
            $hotfixList += [PSCustomObject]@{
                hotfix_id    = $hf.HotFixID
                description  = if ($hf.Description) { [string]$hf.Description.Trim() } else { "Security Update" }
                installed_on = $installedOn
            }
        }
    }

    # 2. Installed Software Applications (x64 and x86 registry)
    $appList = @()
    $regPaths = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Arch = "x64" },
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Arch = "x86" }
    )

    foreach ($entry in $regPaths) {
        try {
            $items = Get-ItemProperty -Path $entry.Path -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.DisplayName -and $item.DisplayName.Trim() -ne "" -and $item.SystemComponent -ne 1) {
                    $installDate = if ($item.InstallDate) { [string]$item.InstallDate } else { $null }
                    $appList += [PSCustomObject]@{
                        name         = [string]$item.DisplayName.Trim()
                        version      = if ($item.DisplayVersion) { [string]$item.DisplayVersion.Trim() } else { $null }
                        publisher    = if ($item.Publisher) { [string]$item.Publisher.Trim() } else { $null }
                        install_date = $installDate
                        architecture = $entry.Arch
                    }
                }
            }
        } catch {
            # Skip hive read failures gracefully
        }
    }

    # Deduplicate applications by Name + Version
    $dedupApps = @()
    $seen = @{}
    foreach ($app in $appList) {
        $key = "$($app.name)_$($app.version)_$($app.architecture)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $dedupApps += $app
        }
    }

    return [PSCustomObject]@{
        applications = $dedupApps
        hotfixes     = $hotfixList
    }
}
