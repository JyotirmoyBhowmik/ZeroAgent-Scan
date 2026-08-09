# Pester Tests for EndpointGuard.ScanEngine

$psm1Path = (Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath "..\EndpointGuard.ScanEngine.psm1")).Path

# Import the module
Import-Module $psm1Path -Force -Global

$modName = "EndpointGuard.ScanEngine"

Describe "EndpointGuard ScanEngine Function Tests" {

    Context "Get-BiosFirmwareInventory - Success" {
        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                Manufacturer      = "Dell Inc."
                SMBIOSBIOSVersion = "1.11.0"
                ReleaseDate       = "2024-01-15"
                Version           = "DELL - 1072009"
            }
        } -ParameterFilter { $ClassName -eq "Win32_BIOS" }

        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                Manufacturer = "Dell Inc."
                Product      = "0X9K12"
                SerialNumber = "8XKJ9201"
            }
        } -ParameterFilter { $ClassName -eq "Win32_BaseBoard" }

        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                UUID = "4C4C4544-0058-4B10-804A-B6C04F393230"
            }
        } -ParameterFilter { $ClassName -eq "Win32_ComputerSystemProduct" }

        Mock Get-ItemProperty -ModuleName $modName {
            [PSCustomObject]@{
                UEFISecureBootEnabled = 1
            }
        }

        It "Returns valid BIOS and Motherboard inventory with mocked CIM instances" {
            $res = Get-BiosFirmwareInventory
            $res | Should Not Be $null
            $res.vendor | Should Be "Dell Inc."
            $res.version | Should Be "1.11.0"
            $res.motherboard_serial | Should Be "8XKJ9201"
            $res.smbios_guid | Should Be "4C4C4544-0058-4B10-804A-B6C04F393230"
            $res.secure_boot_enabled | Should Be $true
            $res.uefi_mode | Should Be $true
        }
    }

    Context "Get-BiosFirmwareInventory - Missing CIM" {
        Mock Get-CimInstance -ModuleName $modName { $null } -ParameterFilter { $ClassName -eq "Win32_BIOS" }
        Mock Get-CimInstance -ModuleName $modName { $null } -ParameterFilter { $ClassName -eq "Win32_BaseBoard" }
        Mock Get-CimInstance -ModuleName $modName { $null } -ParameterFilter { $ClassName -eq "Win32_ComputerSystemProduct" }
        Mock Get-ItemProperty -ModuleName $modName { $null }

        It "Handles missing CIM data gracefully without throwing" {
            $res = Get-BiosFirmwareInventory
            $res | Should Not Be $null
            $res.vendor | Should Be "Unknown"
            $res.motherboard_serial | Should Be $null
        }
    }

    Context "Get-CpuInventory" {
        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    DeviceID                       = "CPU0"
                    Name                           = "13th Gen Intel(R) Core(TM) i7-1365U"
                    Manufacturer                   = "GenuineIntel"
                    NumberOfCores                  = 10
                    NumberOfLogicalProcessors      = 12
                    MaxClockSpeed                  = 5200
                    Architecture                   = 9
                    SocketDesignation              = "U3E1"
                    VirtualizationFirmwareEnabled  = $true
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_Processor" }

        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                VirtualizationBasedSecurityStatus       = 2
                HypervisorEnforcedCodeIntegrityStatus   = 1
            }
        } -ParameterFilter { $ClassName -eq "Win32_DeviceGuard" }

        It "Returns CPU topology and VBS/HVCI status" {
            $res = Get-CpuInventory
            $res | Should Not Be $null
            $res.total_cores | Should Be 10
            $res.total_threads | Should Be 12
            $res.virtualization_firmware_enabled | Should Be $true
            $res.vbs_status | Should Be "Running"
            $res.hvci_status | Should Be "Enabled"
            $res.processors.Count | Should Be 1
        }
    }

    Context "Get-MemoryInventory" {
        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    BankLabel    = "DIMM 1"
                    Capacity     = [int64]17179869184
                    Speed        = 5600
                    Manufacturer = "SK Hynix"
                    PartNumber   = "HMCG78AGBUA"
                    SerialNumber = "9820194A"
                    FormFactor   = 8
                },
                [PSCustomObject]@{
                    BankLabel    = "DIMM 2"
                    Capacity     = [int64]17179869184
                    Speed        = 5600
                    Manufacturer = "SK Hynix"
                    PartNumber   = "HMCG78AGBUA"
                    SerialNumber = "9820194B"
                    FormFactor   = 8
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_PhysicalMemory" }

        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    MemoryDevices = 2
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_PhysicalMemoryArray" }

        It "Returns per-DIMM slot telemetry" {
            $res = Get-MemoryInventory
            $res | Should Not Be $null
            ($res.total_capacity_bytes -eq 34359738368) | Should Be $true
            $res.slots_used | Should Be 2
            $res.total_slots | Should Be 2
            $res.dimms[0].manufacturer | Should Be "SK Hynix"
            $res.dimms[0].form_factor | Should Be "DIMM"
        }
    }

    Context "Get-StorageInventory" {
        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    Index         = 0
                    Model         = "NVMe KIOXIA 1024GB SSD"
                    InterfaceType = "NVMe"
                    Size          = [int64]1024209543168
                    Partitions    = 4
                    Status        = "OK"
                    SerialNumber  = "KX9820194A"
                    MediaType     = "Fixed hard disk media"
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_DiskDrive" }

        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    Name             = "Disk #0, Partition #0"
                    DiskIndex        = 0
                    Size             = [int64]104857600
                    Bootable         = $true
                    PrimaryPartition = $true
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_DiskPartition" }

        It "Returns physical disks and partitions" {
            $res = Get-StorageInventory
            $res | Should Not Be $null
            $res.disk_count | Should Be 1
            $res.disks[0].model | Should Be "NVMe KIOXIA 1024GB SSD"
            $res.disks[0].smart_status | Should Be "OK"
            $res.partitions.Count | Should Be 1
        }
    }

    Context "Get-TpmInventory - Present" {
        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                SpecVersion         = "2.0"
                ManufacturerIdTxt   = "NTC"
                ManufacturerVersion = "7.2.2.0"
            }
        } -ParameterFilter { $ClassName -eq "Win32_Tpm" }

        It "Returns TPM 2.0 presence and specs when present" {
            $res = Get-TpmInventory
            $res | Should Not Be $null
            $res.present | Should Be $true
            $res.spec_version | Should Be "2.0"
            $res.manufacturer_id | Should Be "NTC"
        }
    }

    Context "Get-TpmInventory - Absent" {
        Mock Get-CimInstance -ModuleName $modName { $null } -ParameterFilter { $ClassName -eq "Win32_Tpm" }

        It "Returns present=false when TPM is absent on legacy device" {
            $res = Get-TpmInventory
            $res | Should Not Be $null
            $res.present | Should Be $false
            $res.spec_version | Should Be $null
        }
    }

    Context "Get-NetworkInventory" {
        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    Description             = "Intel(R) Wi-Fi 6E AX211 160MHz"
                    MACAddress              = "00:1A:2B:3C:4D:5E"
                    IPAddress               = @("10.100.1.42", "fe80::1a2b:3c4d:5e6f:7a8b")
                    IPSubnet                = @("255.255.255.0", "64")
                    DefaultIPGateway        = @("10.100.1.1")
                    DNSServerSearchOrder    = @("10.100.1.10", "10.100.1.11")
                    DHCPEnabled             = $true
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_NetworkAdapterConfiguration" }

        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    MACAddress      = "00:1A:2B:3C:4D:5E"
                    Speed           = [int64]1200000000
                    PhysicalAdapter = $true
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_NetworkAdapter" }

        It "Returns active NICs and IP configurations" {
            $res = Get-NetworkInventory
            $res | Should Not Be $null
            $res.adapters.Count | Should Be 1
            $res.adapters[0].mac_address | Should Be "00:1A:2B:3C:4D:5E"
            ($res.adapters[0].ip_addresses -contains "10.100.1.42") | Should Be $true
            $res.adapters[0].link_speed_mbps | Should Be 1200
        }
    }

    Context "Get-PeripheralInventory" {
        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    Name          = "Intel(R) Iris(R) Xe Graphics"
                    DriverVersion = "31.0.101.4575"
                    AdapterRAM    = [int64]1073741824
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_VideoController" }

        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    DeviceID     = "USB\VID_046D&PID_C52B\5&2C276F1&0&1"
                    Name         = "Logitech USB Input Device"
                    Manufacturer = "Logitech"
                    Status       = "OK"
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_PnPEntity" }

        It "Returns Video Controllers and USB devices" {
            $res = Get-PeripheralInventory
            $res | Should Not Be $null
            $res.video_controllers.Count | Should Be 1
            $res.video_controllers[0].name | Should Be "Intel(R) Iris(R) Xe Graphics"
            $res.usb_devices.Count | Should Be 1
            $res.usb_devices[0].name | Should Be "Logitech USB Input Device"
        }
    }

    Context "Get-SoftwareInventory" {
        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    HotFixID    = "KB5036893"
                    Description = "Security Update"
                    InstalledOn = "2024-04-12"
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_QuickFixEngineering" }

        Mock Get-ItemProperty -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    DisplayName    = "Google Chrome"
                    DisplayVersion = "124.0.6367.208"
                    Publisher      = "Google LLC"
                    InstallDate    = "20240415"
                }
            )
        }

        It "Returns installed hotfixes and applications" {
            $res = Get-SoftwareInventory
            $res | Should Not Be $null
            $res.hotfixes.Count | Should Be 1
            $res.hotfixes[0].hotfix_id | Should Be "KB5036893"
            ($res.applications.Count -gt 0) | Should Be $true
            $res.applications[0].name | Should Be "Google Chrome"
        }
    }

    Context "Get-SecurityBaselineSnapshot" {
        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    DriveLetter      = "C:"
                    ProtectionStatus = 1
                    ConversionStatus = 1
                    EncryptionMethod = 7
                    LockStatus       = 0
                }
            )
        } -ParameterFilter { $Namespace -like "*MicrosoftVolumeEncryption" }

        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                SecurityServicesRunning = @(1, 2)
            }
        } -ParameterFilter { $ClassName -eq "Win32_DeviceGuard" }

        It "Returns BitLocker, Defender, Firewall, and SMBv1 security posture" {
            $res = Get-SecurityBaselineSnapshot
            $res | Should Not Be $null
            $res.bitlocker.volumes.Count | Should Be 1
            $res.bitlocker.volumes[0].protection_status | Should Be 1
            $res.defender.realtime_protection_enabled | Should Be $true
            $res.smb1_enabled | Should Be $false
            $res.lsa_protection_enabled | Should Be $true
            $res.credential_guard_running | Should Be $true
        }
    }

    Context "Get-UserAccessAudit" {
        Mock Get-CimInstance -ModuleName $modName {
            @(
                [PSCustomObject]@{
                    Special     = $false
                    LocalPath   = "C:\Users\testuser_old"
                    LastUseTime = (Get-Date).AddDays(-120)
                }
            )
        } -ParameterFilter { $ClassName -eq "Win32_UserProfile" }

        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                Disabled = $true
            }
        } -ParameterFilter { $ClassName -eq "Win32_UserAccount" }

        Mock Get-LocalGroupMember -ModuleName $modName {
            @(
                [PSCustomObject]@{ Name = "Administrator" }
            )
        }

        It "Returns Local Administrators and dormant profiles" {
            $res = Get-UserAccessAudit
            $res | Should Not Be $null
            ($res.local_administrators -contains "Administrator" -or $res.local_administrators.Count -gt 0) | Should Be $true
            $res.dormant_profiles.Count | Should Be 1
            $res.dormant_profiles[0].username | Should Be "testuser_old"
            ($res.dormant_profiles[0].inactive_days -ge 90) | Should Be $true
        }
    }

    Context "Invoke-FullHostAudit" {
        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                DNSHostName  = "W11-EXEC-LP04"
                Domain       = "CORP.ENDPOINTGUARD.LOCAL"
                Manufacturer = "Dell Inc."
                Model        = "Latitude 7440"
                SystemType   = "x64-based PC"
                PCSystemType = 2
            }
        } -ParameterFilter { $ClassName -eq "Win32_ComputerSystem" }

        Mock Get-CimInstance -ModuleName $modName {
            [PSCustomObject]@{
                Caption         = "Microsoft Windows 11 Enterprise 23H2"
                Version         = "10.0.22631"
                BuildNumber     = "22631"
                OSArchitecture  = "64-bit"
                InstallDate     = "20231101120000.000000-300"
                LastBootUpTime  = "20240501080000.000000-300"
            }
        } -ParameterFilter { $ClassName -eq "Win32_OperatingSystem" }

        Mock Get-BiosFirmwareInventory -ModuleName $modName {
            [PSCustomObject]@{
                vendor             = "Dell Inc."
                version            = "1.11.0"
                motherboard_serial = "8XKJ9201"
                smbios_guid        = "4C4C4544-0058-4B10-804A-B6C04F393230"
                secure_boot_enabled = $true
                uefi_mode          = $true
            }
        }

        Mock Get-CpuInventory -ModuleName $modName {
            [PSCustomObject]@{
                models                        = @("13th Gen Intel(R) Core(TM) i7-1365U")
                socket_count                  = 1
                total_cores                   = 10
                total_threads                 = 12
                virtualization_firmware_enabled = $true
                vbs_status                    = "Running"
                hvci_status                   = "Enabled"
                processors                    = @()
            }
        }

        Mock Get-MemoryInventory -ModuleName $modName {
            [PSCustomObject]@{
                total_capacity_bytes = [int64]34359738368
                slots_used           = 2
                total_slots          = 2
                dimms                = @()
            }
        }

        Mock Get-StorageInventory -ModuleName $modName {
            [PSCustomObject]@{
                disk_count = 1
                disks      = @()
                partitions = @()
            }
        }

        Mock Get-TpmInventory -ModuleName $modName {
            [PSCustomObject]@{
                present              = $true
                spec_version         = "2.0"
                manufacturer_id      = "NTC"
                manufacturer_version = "7.2.2.0"
            }
        }

        Mock Get-NetworkInventory -ModuleName $modName {
            [PSCustomObject]@{
                adapters = @()
            }
        }

        Mock Get-PeripheralInventory -ModuleName $modName {
            [PSCustomObject]@{
                video_controllers = @()
                usb_devices       = @()
                monitors          = @()
            }
        }

        Mock Get-SoftwareInventory -ModuleName $modName {
            [PSCustomObject]@{
                applications = @()
                hotfixes     = @()
            }
        }

        Mock Get-SecurityBaselineSnapshot -ModuleName $modName {
            [PSCustomObject]@{
                bitlocker                = [PSCustomObject]@{ volumes = @() }
                defender                 = [PSCustomObject]@{ realtime_protection_enabled = $true }
                firewall_profiles        = [PSCustomObject]@{
                    domain  = [PSCustomObject]@{ enabled = $true; default_inbound = "Block"; default_outbound = "Allow" }
                    private = [PSCustomObject]@{ enabled = $true; default_inbound = "Block"; default_outbound = "Allow" }
                    public  = [PSCustomObject]@{ enabled = $true; default_inbound = "Block"; default_outbound = "Allow" }
                }
                smb1_enabled             = $false
                lsa_protection_enabled   = $true
                credential_guard_running = $true
            }
        }

        Mock Get-UserAccessAudit -ModuleName $modName {
            [PSCustomObject]@{
                local_administrators   = @("Administrator")
                remote_desktop_users   = @()
                privileged_groups      = @()
                dormant_profiles       = @()
                guest_account_disabled = $true
            }
        }

        It "Assembles complete snapshot object matching all domain sections" {
            $snapshot = Invoke-FullHostAudit -TargetHost "localhost" -AsObject
            $snapshot | Should Not Be $null
            $snapshot.audit_metadata | Should Not Be $null
            $snapshot.system_identity.hostname | Should Be "W11-EXEC-LP04"
            $snapshot.firmware_bios | Should Not Be $null
            $snapshot.processor | Should Not Be $null
            $snapshot.memory | Should Not Be $null
            $snapshot.storage | Should Not Be $null
            $snapshot.tpm | Should Not Be $null
            $snapshot.network | Should Not Be $null
            $snapshot.peripherals | Should Not Be $null
            $snapshot.software | Should Not Be $null
            $snapshot.security_baseline | Should Not Be $null
            $snapshot.user_access | Should Not Be $null

            # Test JSON serialization
            $jsonStr = Invoke-FullHostAudit -TargetHost "localhost"
            $jsonStr | Should Not Be $null
            $parsed = $jsonStr | ConvertFrom-Json
            $parsed.audit_metadata.engine_version | Should Be "EndpointGuard-ScanEngine-v1.2.0"
        }
    }
}
