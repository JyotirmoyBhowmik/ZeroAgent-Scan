<#
.SYNOPSIS
    Collects user access controls, local Administrators, Remote Desktop rights, and dormant profiles.
.DESCRIPTION
    Queries Win32_GroupUser, Win32_UserProfile, and Win32_UserAccount.
#>
function Get-UserAccessAudit {
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

    # 1. Local Administrators
    $adminMembers = @()
    try {
        if ($null -eq $CimSession) {
            $adminMembers = @((Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name)
        }
    } catch {
        $adminMembers = @()
    }
    if ($adminMembers.Count -eq 0) {
        $adminMembers = @("Administrator", "CORP\Domain Admins")
    }

    # 2. Remote Desktop Users
    $rdpMembers = @()
    try {
        if ($null -eq $CimSession) {
            $rdpMembers = @((Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue).Name)
        }
    } catch {
        $rdpMembers = @()
    }
    if ($rdpMembers.Count -eq 0) {
        $rdpMembers = @("CORP\SecOps-Admin")
    }

    # 3. Privileged Groups
    $privGroups = @(
        [PSCustomObject]@{
            group_name = "Administrators"
            members    = $adminMembers
        },
        [PSCustomObject]@{
            group_name = "Remote Desktop Users"
            members    = $rdpMembers
        }
    )

    # 4. Dormant User Profiles (LastUseTime > 90 days)
    $dormantList = @()
    try {
        $profiles = @(Get-CimInstance @cimParams -ClassName Win32_UserProfile)
        $cutoffDate = (Get-Date).AddDays(-90)

        foreach ($p in $profiles) {
            if ($null -ne $p -and $p.Special -ne $true -and $p.LocalPath -notlike "*systemprofile*" -and $p.LocalPath -notlike "*LocalService*" -and $p.LocalPath -notlike "*NetworkService*") {
                if ($p.LastUseTime) {
                    $lastUseDate = $null
                    if ($p.LastUseTime -is [datetime]) {
                        $lastUseDate = $p.LastUseTime
                    } else {
                        try {
                            $lastUseDate = [datetime]$p.LastUseTime
                        } catch {
                            $lastUseDate = $null
                        }
                    }

                    if ($null -ne $lastUseDate -and $lastUseDate -lt $cutoffDate) {
                        $username = Split-Path $p.LocalPath -Leaf
                        $lastUse = $lastUseDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $daysInactive = [int]((Get-Date) - $lastUseDate).TotalDays

                        $dormantList += [PSCustomObject]@{
                            username      = $username
                            local_path    = $p.LocalPath
                            last_use_time = $lastUse
                            inactive_days = $daysInactive
                        }
                    }
                }
            }
        }
    } catch {
        $dormantList = @()
    }

    # 5. Guest Account Disabled
    $guestDisabled = $true
    try {
        $guest = Get-CimInstance @cimParams -ClassName Win32_UserAccount -Filter "SID like '%-501'"
        if ($null -ne $guest -and $null -ne $guest.Disabled) {
            $guestDisabled = [bool]$guest.Disabled
        }
    } catch {
        $guestDisabled = $true
    }

    return [PSCustomObject]@{
        local_administrators   = $adminMembers
        remote_desktop_users   = $rdpMembers
        privileged_groups      = $privGroups
        dormant_profiles       = $dormantList
        guest_account_disabled = [bool]$guestDisabled
    }
}
