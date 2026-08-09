package models

import (
	"encoding/json"
	"fmt"
)

// HostSnapshotPayload represents the complete payload structure emitted by Invoke-FullHostAudit.
type HostSnapshotPayload struct {
	AuditMetadata    SnapshotAuditMetadata    `json:"audit_metadata"`
	SystemIdentity   SnapshotSystemIdentity   `json:"system_identity"`
	FirmwareBios     SnapshotFirmwareBios     `json:"firmware_bios"`
	Processor        SnapshotProcessor        `json:"processor"`
	Memory           SnapshotMemory           `json:"memory"`
	Storage          SnapshotStorage          `json:"storage"`
	TPM              SnapshotTPM              `json:"tpm"`
	Network          SnapshotNetwork          `json:"network"`
	Peripherals      SnapshotPeripherals      `json:"peripherals"`
	Software         SnapshotSoftware         `json:"software"`
	SecurityBaseline SnapshotSecurityBaseline `json:"security_baseline"`
	UserAccess       SnapshotUserAccess       `json:"user_access"`
}

type SnapshotAuditMetadata struct {
	EngineVersion string `json:"engine_version"`
	TimestampUTC  string `json:"timestamp_utc"`
	ScanProtocol  string `json:"scan_protocol"`
	TargetHost    string `json:"target_host"`
}

type SnapshotSystemIdentity struct {
	Hostname       string  `json:"hostname"`
	Domain         *string `json:"domain,omitempty"`
	Manufacturer   string  `json:"manufacturer"`
	Model          string  `json:"model"`
	SystemType     *string `json:"system_type,omitempty"`
	ChassisType    string  `json:"chassis_type"`
	OSName         string  `json:"os_name"`
	OSVersion      string  `json:"os_version"`
	OSBuild        string  `json:"os_build"`
	OSArchitecture *string `json:"os_architecture,omitempty"`
	SerialNumber   *string `json:"serial_number,omitempty"`
	InstallDate    *string `json:"install_date,omitempty"`
	LastBootTime   *string `json:"last_boot_time,omitempty"`
}

type SnapshotFirmwareBios struct {
	MotherboardSerial       *string `json:"motherboard_serial,omitempty"`
	MotherboardManufacturer *string `json:"motherboard_manufacturer,omitempty"`
	MotherboardProduct      *string `json:"motherboard_product,omitempty"`
	Vendor                  string  `json:"vendor"`
	Version                 string  `json:"version"`
	ReleaseDate             *string `json:"release_date,omitempty"`
	SMBIOSVersion           *string `json:"smbios_version,omitempty"`
	SMBIOSGUID              *string `json:"smbios_guid,omitempty"`
	SecureBootEnabled       bool    `json:"secure_boot_enabled"`
	UEFIMode                bool    `json:"uefi_mode"`
}

type SnapshotProcessor struct {
	Models                        []string            `json:"models"`
	SocketCount                   int                 `json:"socket_count"`
	TotalCores                    int                 `json:"total_cores"`
	TotalThreads                  int                 `json:"total_threads"`
	VirtualizationFirmwareEnabled *bool               `json:"virtualization_firmware_enabled,omitempty"`
	VBSStatus                     *string             `json:"vbs_status,omitempty"`
	HVCIStatus                    *string             `json:"hvci_status,omitempty"`
	Processors                    []SnapshotCPUDetail `json:"processors"`
}

type SnapshotCPUDetail struct {
	DeviceID     string `json:"device_id"`
	Name         string `json:"name"`
	Manufacturer string `json:"manufacturer"`
	Cores        int    `json:"cores"`
	Threads      int    `json:"threads"`
	MaxClockMHz  int    `json:"max_clock_mhz"`
	Architecture string `json:"architecture"`
	Socket       string `json:"socket"`
}

type SnapshotMemory struct {
	TotalCapacityBytes int64               `json:"total_capacity_bytes"`
	SlotsUsed          int                 `json:"slots_used"`
	TotalSlots         int                 `json:"total_slots"`
	DIMMs              []SnapshotDIMMEntry `json:"dimms"`
}

type SnapshotDIMMEntry struct {
	Slot          string  `json:"slot"`
	CapacityBytes int64   `json:"capacity_bytes"`
	SpeedMHz      *int    `json:"speed_mhz,omitempty"`
	Manufacturer  *string `json:"manufacturer,omitempty"`
	PartNumber    *string `json:"part_number,omitempty"`
	SerialNumber  *string `json:"serial_number,omitempty"`
	FormFactor    *string `json:"form_factor,omitempty"`
}

type SnapshotStorage struct {
	DiskCount  int                         `json:"disk_count"`
	Disks      []SnapshotDiskEntry         `json:"disks"`
	Partitions []SnapshotPartitionEntry    `json:"partitions"`
}

type SnapshotDiskEntry struct {
	Index        int     `json:"index"`
	Model        string  `json:"model"`
	BusType      string  `json:"bus_type"`
	SizeBytes    int64   `json:"size_bytes"`
	Partitions   int     `json:"partitions"`
	SMARTStatus  string  `json:"smart_status"`
	SerialNumber *string `json:"serial_number,omitempty"`
	MediaType    *string `json:"media_type,omitempty"`
}

type SnapshotPartitionEntry struct {
	Name      string `json:"name"`
	DiskIndex int    `json:"disk_index"`
	SizeBytes int64  `json:"size_bytes"`
	Bootable  bool   `json:"bootable"`
	Primary   bool   `json:"primary"`
}

type SnapshotTPM struct {
	Present             bool     `json:"present"`
	SpecVersion         *string  `json:"spec_version,omitempty"`
	ManufacturerID      *string  `json:"manufacturer_id,omitempty"`
	ManufacturerVersion *string  `json:"manufacturer_version,omitempty"`
	IsEnabled           *bool    `json:"is_enabled,omitempty"`
	IsActivated         *bool    `json:"is_activated,omitempty"`
	IsOwned             *bool    `json:"is_owned,omitempty"`
	PCRBanks            []string `json:"pcr_banks,omitempty"`
}

type SnapshotNetwork struct {
	Adapters []SnapshotNICEntry `json:"adapters"`
}

type SnapshotNICEntry struct {
	Description     string   `json:"description"`
	MACAddress      string   `json:"mac_address"`
	IPAddresses     []string `json:"ip_addresses"`
	IPSubnets       []string `json:"ip_subnets"`
	DefaultGateways []string `json:"default_gateways"`
	DNSServers      []string `json:"dns_servers"`
	DHCPEnabled     bool     `json:"dhcp_enabled"`
	LinkSpeedMbps   *int     `json:"link_speed_mbps,omitempty"`
	PhysicalAdapter *bool    `json:"physical_adapter,omitempty"`
}

type SnapshotPeripherals struct {
	VideoControllers []SnapshotVideoController `json:"video_controllers"`
	USBDevices       []SnapshotUSBDevice       `json:"usb_devices"`
	Monitors         []SnapshotMonitorEntry    `json:"monitors"`
}

type SnapshotVideoController struct {
	Name            string  `json:"name"`
	DriverVersion   *string `json:"driver_version,omitempty"`
	AdapterRAMBytes *int64  `json:"adapter_ram_bytes,omitempty"`
	VideoProcessor  *string `json:"video_processor,omitempty"`
}

type SnapshotUSBDevice struct {
	DeviceID     string  `json:"device_id"`
	Name         string  `json:"name"`
	Manufacturer *string `json:"manufacturer,omitempty"`
	Status       *string `json:"status,omitempty"`
}

type SnapshotMonitorEntry struct {
	Manufacturer       *string `json:"manufacturer,omitempty"`
	ProductCode        *string `json:"product_code,omitempty"`
	SerialNumber       *string `json:"serial_number,omitempty"`
	YearOfManufacture  *int    `json:"year_of_manufacture,omitempty"`
}

type SnapshotSoftware struct {
	Applications []SnapshotApplicationEntry `json:"applications"`
	Hotfixes     []SnapshotHotfixEntry      `json:"hotfixes"`
}

type SnapshotApplicationEntry struct {
	Name         string  `json:"name"`
	Version      *string `json:"version,omitempty"`
	Publisher    *string `json:"publisher,omitempty"`
	InstallDate  *string `json:"install_date,omitempty"`
	Architecture *string `json:"architecture,omitempty"`
}

type SnapshotHotfixEntry struct {
	HotFixID    string  `json:"hotfix_id"`
	Description *string `json:"description,omitempty"`
	InstalledOn *string `json:"installed_on,omitempty"`
}

type SnapshotSecurityBaseline struct {
	BitLocker              SnapshotBitLockerInfo    `json:"bitlocker"`
	Defender               SnapshotDefenderInfo     `json:"defender"`
	FirewallProfiles       SnapshotFirewallProfiles `json:"firewall_profiles"`
	SMB1Enabled            bool                     `json:"smb1_enabled"`
	LSAProtectionEnabled   bool                     `json:"lsa_protection_enabled"`
	CredentialGuardRunning bool                     `json:"credential_guard_running"`
}

type SnapshotBitLockerInfo struct {
	Volumes []SnapshotBitLockerVolume `json:"volumes"`
}

type SnapshotBitLockerVolume struct {
	DriveLetter      string   `json:"drive_letter"`
	ProtectionStatus int      `json:"protection_status"`
	ConversionStatus int      `json:"conversion_status"`
	EncryptionMethod string   `json:"encryption_method"`
	LockStatus       int      `json:"lock_status"`
	KeyProtectors    []string `json:"key_protectors"`
}

type SnapshotDefenderInfo struct {
	RealTimeProtectionEnabled *bool   `json:"realtime_protection_enabled,omitempty"`
	AntivirusEnabled          *bool   `json:"antivirus_enabled,omitempty"`
	AntispywareEnabled        *bool   `json:"antispyware_enabled,omitempty"`
	BehaviorMonitorEnabled    *bool   `json:"behavior_monitor_enabled,omitempty"`
	IoavProtectionEnabled     *bool   `json:"ioav_protection_enabled,omitempty"`
	TamperProtectionEnabled   *bool   `json:"tamper_protection_enabled,omitempty"`
	AntivirusSignatureVersion *string `json:"antivirus_signature_version,omitempty"`
	AntivirusEngineVersion    *string `json:"antivirus_engine_version,omitempty"`
	QuickScanAgeDays          *int    `json:"quick_scan_age_days,omitempty"`
}

type SnapshotFirewallProfiles struct {
	Domain  SnapshotFirewallProfile `json:"domain"`
	Private SnapshotFirewallProfile `json:"private"`
	Public  SnapshotFirewallProfile `json:"public"`
}

type SnapshotFirewallProfile struct {
	Enabled        bool   `json:"enabled"`
	DefaultInbound string `json:"default_inbound"`
	DefaultOutbound string `json:"default_outbound"`
}

type SnapshotUserAccess struct {
	LocalAdministrators  []string                 `json:"local_administrators"`
	RemoteDesktopUsers   []string                 `json:"remote_desktop_users"`
	PrivilegedGroups     []SnapshotPrivilegedGroup `json:"privileged_groups"`
	DormantProfiles      []SnapshotDormantProfile  `json:"dormant_profiles"`
	GuestAccountDisabled *bool                    `json:"guest_account_disabled,omitempty"`
}

type SnapshotPrivilegedGroup struct {
	GroupName string   `json:"group_name"`
	Members   []string `json:"members"`
}

type SnapshotDormantProfile struct {
	Username     string  `json:"username"`
	LocalPath    string  `json:"local_path"`
	LastUseTime  *string `json:"last_use_time,omitempty"`
	InactiveDays int     `json:"inactive_days"`
}

// ValidateSnapshotPayload verifies boundary constraints and non-null guarantees (Rule 1.1 - 1.3).
func ValidateSnapshotPayload(data []byte) (*HostSnapshotPayload, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("snapshot: payload cannot be empty")
	}

	var payload HostSnapshotPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("snapshot: failed to deserialize snapshot JSON: %w", err)
	}

	if payload.AuditMetadata.EngineVersion == "" {
		return nil, fmt.Errorf("snapshot: missing required audit_metadata.engine_version")
	}
	if payload.SystemIdentity.Hostname == "" {
		return nil, fmt.Errorf("snapshot: missing required system_identity.hostname")
	}
	if payload.Processor.SocketCount <= 0 {
		return nil, fmt.Errorf("snapshot: processor.socket_count must be at least 1")
	}

	return &payload, nil
}
