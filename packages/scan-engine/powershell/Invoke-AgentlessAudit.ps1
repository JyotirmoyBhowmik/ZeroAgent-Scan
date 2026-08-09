<#
.SYNOPSIS
    EndpointGuard 100% Agentless Windows 11 & Windows Server Hardware & Security Auditor.
.DESCRIPTION
    Executes over remote WinRM / WS-Man HTTPS (Port 5986) or CIM-XML session.
    Collects full hardware inventory, BitLocker encryption, TPM 2.0, Windows Defender,
    Firewall profiles, Local Administrators, and Hotfix telemetry with zero host agent installation.
    Outputs structured, sanitized JSON.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory = $false)]
    [pscredential]$Credential = $null,

    [Parameter(Mandatory = $false)]
    [switch]$UseSSL = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EndpointAudit {
    param (
        [string]$TargetHost,
        [pscredential]$TargetCred
    )

    $cimParams = @{
        ErrorAction = 'SilentlyContinue'
    }

    if ($TargetHost -ne "localhost" -and $TargetHost -ne "127.0.0.1") {
        $cimOpt = New-CimSessionOption -UseSsl:$UseSSL -SkipCACheck:$false -SkipCNCheck:$false
        $sessionParams = @{
            ComputerName  = $TargetHost
            SessionOption = $cimOpt
        }
        if ($null -ne $TargetCred) {
            $sessionParams['Credential'] = $TargetCred
        }
        $cimSession = New-CimSession @sessionParams
        $cimParams['CimSession'] = $cimSession
    }

    try {
        # 1. Operating System
        $os = Get-CimInstance @cimParams -ClassName Win32_OperatingSystem
        
        # 2. Computer System (Manufacturer, Model, Domain)
        $cs = Get-CimInstance @cimParams -ClassName Win32_ComputerSystem
        
        # 3. Processors (CPUs, Cores, Sockets)
        $cpus = Get-CimInstance @cimParams -ClassName Win32_Processor
        
        # 4. Memory DIMMs
        $ramModules = Get-CimInstance @cimParams -ClassName Win32_PhysicalMemory
        
        # 5. Storage Disks (Physical Disks & Partitions)
        $disks = Get-CimInstance @cimParams -ClassName Win32_DiskDrive
        
        # 6. Network Adapters (Active IP-Enabled NICs)
        $nics = Get-CimInstance @cimParams -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
        
        # 7. BIOS / UEFI
        $bios = Get-CimInstance @cimParams -ClassName Win32_BIOS

        # 8. TPM 2.0 (Security namespace)
        $tpm = Get-CimInstance @cimParams -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm

        # 9. BitLocker Volume Encryption (Security namespace)
        $bitlockerVolumes = Get-CimInstance @cimParams -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume

        # 10. Windows Defender Status
        $defender = $null
        try {
            $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        } catch {
            $defender = $null
        }

        # 11. Firewall Profiles
        $firewallProfiles = @{}
        try {
            $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            foreach ($p in $fw) {
                $firewallProfiles[$p.Name] = @{
                    Enabled             = $p.Enabled
                    DefaultInboundAction  = $p.DefaultInboundAction.ToString()
                    DefaultOutboundAction = $p.DefaultOutboundAction.ToString()
                }
            }
        } catch {
            $firewallProfiles = @{ Status = "Unavailable" }
        }

        # 12. Hotfixes / Patches
        $hotfixes = Get-CimInstance @cimParams -ClassName Win32_QuickFixEngineering | Select-Object -Property HotFixID, Description, InstalledOn

        # 13. Local Administrators
        $localAdmins = @()
        try {
            $localAdmins = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name
        } catch {
            $localAdmins = @("Unavailable")
        }

        # Format Telemetry Object
        $auditReport = [PSCustomObject]@{
            AuditMetadata = [PSCustomObject]@{
                EngineVersion   = "EndpointGuard-1.0.0"
                TimestampUTC    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                ScanProtocol    = if ($UseSSL) { "WinRM-HTTPS-5986" } else { "WinRM-HTTP-5985" }
                Target          = $TargetHost
            }
            System = [PSCustomObject]@{
                Hostname       = $cs.DNSHostName
                Domain         = $cs.Domain
                Manufacturer   = $cs.Manufacturer
                Model          = $cs.Model
                SystemType     = $cs.SystemType
                ChassisType    = if ($cs.PCSystemType -eq 2) { "Laptop" } elseif ($cs.PCSystemType -eq 7) { "Server" } else { "Desktop" }
                OSName         = $os.Caption
                OSVersion      = $os.Version
                OSBuild        = $os.BuildNumber
                OSArchitecture = $os.OSArchitecture
                SerialNumber   = $bios.SerialNumber
                InstallDate    = $os.InstallDate
                LastBootTime   = $os.LastBootUpTime
            }
            Hardware = [PSCustomObject]@{
                Processors = @($cpus | ForEach-Object {
                    [PSCustomObject]@{
                        DeviceID           = $_.DeviceID
                        Name               = $_.Name
                        Manufacturer       = $_.Manufacturer
                        NumberOfCores      = $_.NumberOfCores
                        NumberOfLogical    = $_.NumberOfLogicalProcessors
                        MaxClockSpeedMHz   = $_.MaxClockSpeed
                        Architecture       = $_.Architecture
                        SocketDesignation  = $_.SocketDesignation
                    }
                })
                Memory = [PSCustomObject]@{
                    TotalCapacityBytes = ($ramModules | Measure-Object -Property Capacity -Sum).Sum
                    SlotCount          = ($ramModules | Measure-Object).Count
                    DIMMs              = @($ramModules | ForEach-Object {
                        [PSCustomObject]@{
                            BankLabel    = $_.BankLabel
                            Capacity     = $_.Capacity
                            SpeedMHz     = $_.Speed
                            Manufacturer = $_.Manufacturer
                            PartNumber   = $_.PartNumber
                            SerialNumber = $_.SerialNumber
                        }
                    })
                }
                Disks = @($disks | ForEach-Object {
                    [PSCustomObject]@{
                        Index          = $_.Index
                        Model          = $_.Model
                        InterfaceType  = $_.InterfaceType
                        SizeBytes      = $_.Size
                        Partitions     = $_.Partitions
                        Status         = $_.Status
                        SerialNumber   = $_.SerialNumber
                    }
                })
                NetworkAdapters = @($nics | ForEach-Object {
                    [PSCustomObject]@{
                        Description    = $_.Description
                        MACAddress     = $_.MACAddress
                        IPAddresses    = @($_.IPAddress)
                        IPSubnets      = @($_.IPSubnet)
                        DefaultGateway = @($_.DefaultIPGateway)
                        DNSServers     = @($_.DNSServerSearchOrder)
                        DHCPEnabled    = $_.DHCPEnabled
                    }
                })
                BIOS = [PSCustomObject]@{
                    Manufacturer    = $bios.Manufacturer
                    SMBIOSVersion   = $bios.SMBIOSBIOSVersion
                    ReleaseDate     = $bios.ReleaseDate
                }
                TPM = [PSCustomObject]@{
                    Present         = ($null -ne $tpm)
                    SpecVersion     = if ($tpm) { $tpm.SpecVersion } else { "None" }
                    ManufacturerID  = if ($tpm) { $tpm.ManufacturerIdTxt } else { "None" }
                    IsEnabled       = if ($tpm) { $tpm.IsEnabled().IsEnabled } else { $false }
                    IsActivated     = if ($tpm) { $tpm.IsActivated().IsActivated } else { $false }
                }
            }
            Security = [PSCustomObject]@{
                BitLocker = @($bitlockerVolumes | ForEach-Object {
                    [PSCustomObject]@{
                        DriveLetter        = $_.DriveLetter
                        ProtectionStatus   = $_.ProtectionStatus
                        ConversionStatus   = $_.ConversionStatus
                        EncryptionMethod   = $_.EncryptionMethod
                        LockStatus         = $_.LockStatus
                    }
                })
                Defender = if ($defender) {
                    [PSCustomObject]@{
                        RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
                        AntivirusEnabled          = $defender.AntivirusEnabled
                        AntispywareEnabled        = $defender.AntispywareEnabled
                        BehaviorMonitorEnabled    = $defender.BehaviorMonitorEnabled
                        IoavProtectionEnabled     = $defender.IoavProtectionEnabled
                        TamperProtectionEnabled   = $defender.IsTamperProtected
                        AntivirusSignatureVersion = $defender.AntivirusSignatureVersion
                        QuickScanAge              = $defender.QuickScanAge
                    }
                } else {
                    [PSCustomObject]@{ Status = "DefenderServiceUnreachable" }
                }
                FirewallProfiles = $firewallProfiles
                LocalAdministrators = @($localAdmins)
                Hotfixes = @($hotfixes)
            }
        }

        return ($auditReport | ConvertTo-Json -Depth 10)

    } finally {
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
    }
}

# Entrypoint
Get-EndpointAudit -TargetHost $ComputerName -TargetCred $Credential
