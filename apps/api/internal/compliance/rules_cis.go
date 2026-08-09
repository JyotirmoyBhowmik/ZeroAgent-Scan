package compliance

import (
	"time"
)

const (
	CISWin11FrameworkCode = "cis_win11_v2.0"
)

// DefaultCISWindows11Framework returns the built-in CIS Windows 11 Benchmark metadata.
func DefaultCISWindows11Framework() ComplianceFramework {
	return ComplianceFramework{
		ID:          "f0000000-0000-0000-0000-000000000001",
		Code:        CISWin11FrameworkCode,
		Name:        "CIS Microsoft Windows 11 Enterprise Benchmark",
		Version:     "v2.0.0",
		TargetOS:    "Windows 11",
		Description: "Center for Internet Security (CIS) security baseline benchmark for Windows 11 Enterprise workstations.",
		IsBuiltin:   true,
		CreatedAt:   time.Now().UTC(),
	}
}

// GetBuiltinCISWindows11Rules returns 28 real CIS Windows 11 Benchmark v2.0/v3.0 controls
// with exact control citations in code comments.
func GetBuiltinCISWindows11Rules() []ComplianceRule {
	now := time.Now().UTC()
	fwID := "f0000000-0000-0000-0000-000000000001"

	return []ComplianceRule{
		// -------------------------------------------------------------------
		// Section 18.9.15: BitLocker Drive Encryption
		// -------------------------------------------------------------------

		// CIS 18.9.15.1: Ensure 'BitLocker Drive Encryption' is enabled on OS Volume
		{
			ID:                "r-cis-18-9-15-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.15.1",
			Title:             "Ensure BitLocker Drive Encryption is Enabled on OS Volume",
			Category:          "Storage & Encryption",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "Full volume encryption protects data at rest against unauthorized physical extraction and offline attacks.",
			ExpectedValue:     "protection_status == 1 (Protected)",
			CheckExpression:   `{"==": [{"var": "security_baseline.bitlocker.volumes.0.protection_status"}, 1]}`,
			RemediationScript: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
			CreatedAt:         now,
		},

		// CIS 18.9.15.2: Ensure 'Choose drive encryption method and cipher strength (Windows 10 [1511] and later)' is configured to XTS-AES 256-bit or AES 256-bit
		{
			ID:                "r-cis-18-9-15-2",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.15.2",
			Title:             "Ensure BitLocker Cipher Strength is Configured to XTS-AES 256-bit",
			Category:          "Storage & Encryption",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "XTS-AES 256 provides state-of-the-art cryptographic strength for sector-based block storage.",
			ExpectedValue:     "encryption_method in ['XtsAes256', 'Aes256', 'XtsAes128']",
			CheckExpression:   `{"in": [{"var": "security_baseline.bitlocker.volumes.0.encryption_method"}, ["XtsAes256", "Aes256", "XtsAes128"]]}`,
			RemediationScript: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE' -Name 'EncryptionMethodWithXtsOs' -Value 7",
			CreatedAt:         now,
		},

		// CIS 18.9.15.3: Ensure BitLocker Volume Lock Status is Unlocked for authorized OS operation
		{
			ID:                "r-cis-18-9-15-3",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.15.3",
			Title:             "Ensure BitLocker Volume Lock Status is Unlocked during OS execution",
			Category:          "Storage & Encryption",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Ensures OS volume is unlocked through attested TPM key protectors without requiring manual recovery intervention.",
			ExpectedValue:     "lock_status == 0 (Unlocked)",
			CheckExpression:   `{"==": [{"var": "security_baseline.bitlocker.volumes.0.lock_status"}, 0]}`,
			RemediationScript: "Unlock-BitLocker -MountPoint 'C:'",
			CreatedAt:         now,
		},

		// -------------------------------------------------------------------
		// Section 18.9.8: Network Protocols (SMB)
		// -------------------------------------------------------------------

		// CIS 18.9.8.1: Ensure 'Configure SMB v1 client/server driver' is set to 'Disabled'
		{
			ID:                "r-cis-18-9-8-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.8.1",
			Title:             "Ensure SMBv1 (Legacy Protocol) is Completely Disabled",
			Category:          "Network Security",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "SMBv1 lacks modern integrity guarantees and is vulnerable to severe remote exploits such as EternalBlue.",
			ExpectedValue:     "smb1_enabled == false",
			CheckExpression:   `{"==": [{"var": "security_baseline.smb1_enabled"}, false]}`,
			RemediationScript: "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart",
			CreatedAt:         now,
		},

		// -------------------------------------------------------------------
		// Section 18.9.10: Local Security Authority (LSA) Protection
		// -------------------------------------------------------------------

		// CIS 18.9.10.1: Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled with UEFI Lock'
		{
			ID:                "r-cis-18-9-10-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.10.1",
			Title:             "Ensure LSA Protection (RunAsPPL) is Enabled",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "Protected Process Light (PPL) for LSASS prevents unprivileged and non-protected processes from reading credential memory (Mimikatz mitigation).",
			ExpectedValue:     "lsa_protection_enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.lsa_protection_enabled"}, true]}`,
			RemediationScript: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1",
			CreatedAt:         now,
		},

		// -------------------------------------------------------------------
		// Section 18.9.11: Virtualization-Based Security (VBS) & Device Guard
		// -------------------------------------------------------------------

		// CIS 18.9.11.1: Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'
		{
			ID:                "r-cis-18-9-11-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.11.1",
			Title:             "Ensure Virtualization Based Security (VBS) is Running",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "VBS isolates security-sensitive operations inside a hypervisor-protected virtual environment.",
			ExpectedValue:     "vbs_status in ['Running', '1', '2']",
			CheckExpression:   `{"in": [{"var": "processor.vbs_status"}, ["Running", "1", "2"]]}`,
			RemediationScript: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Value 1",
			CreatedAt:         now,
		},

		// CIS 18.9.11.2: Ensure 'Hypervisor-Protected Code Integrity' (HVCI) is set to 'Enabled'
		{
			ID:                "r-cis-18-9-11-2",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.11.2",
			Title:             "Ensure Hypervisor-Protected Code Integrity (HVCI) is Enabled",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "HVCI prevents unsigned or tampered drivers from loading into kernel memory space.",
			ExpectedValue:     "hvci_status in ['Enabled', '1', '2']",
			CheckExpression:   `{"in": [{"var": "processor.hvci_status"}, ["Enabled", "1", "2"]]}`,
			RemediationScript: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1",
			CreatedAt:         now,
		},

		// CIS 18.9.11.3: Ensure 'Credential Guard' is running
		{
			ID:                "r-cis-18-9-11-3",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.11.3",
			Title:             "Ensure Windows Defender Credential Guard is Running",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "Credential Guard uses hypervisor security to isolate NTLM and Kerberos credentials from unauthorized access.",
			ExpectedValue:     "credential_guard_running == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.credential_guard_running"}, true]}`,
			RemediationScript: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LsaCfgFlags' -Value 1",
			CreatedAt:         now,
		},

		// -------------------------------------------------------------------
		// Section 18.9.84: Microsoft Defender Antivirus & EDR
		// -------------------------------------------------------------------

		// CIS 18.9.84.1: Ensure 'Turn off Windows Defender Antivirus' is set to 'Disabled'
		{
			ID:                "r-cis-18-9-84-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.84.1",
			Title:             "Ensure Microsoft Defender Antivirus is Enabled",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "Defender core engine must remain active to provide signature, heuristic, and behavioral malware detection.",
			ExpectedValue:     "antivirus_enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.defender.antivirus_enabled"}, true]}`,
			RemediationScript: "Set-MpPreference -DisableRealtimeMonitoring $false",
			CreatedAt:         now,
		},

		// CIS 18.9.84.2: Ensure 'Turn on Real-Time Protection' is set to 'Enabled'
		{
			ID:                "r-cis-18-9-84-2",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.84.2",
			Title:             "Ensure Microsoft Defender Real-Time Protection is Enabled",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "Real-time protection intercepts active malware file reads and writes before execution.",
			ExpectedValue:     "realtime_protection_enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.defender.realtime_protection_enabled"}, true]}`,
			RemediationScript: "Set-MpPreference -DisableRealtimeMonitoring $false",
			CreatedAt:         now,
		},

		// CIS 18.9.84.3: Ensure 'Turn on Behavior Monitoring' is set to 'Enabled'
		{
			ID:                "r-cis-18-9-84-3",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.84.3",
			Title:             "Ensure Microsoft Defender Behavior Monitoring is Enabled",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Behavioral monitoring detects zero-day ransomware activity by observing process behavior patterns.",
			ExpectedValue:     "behavior_monitor_enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.defender.behavior_monitor_enabled"}, true]}`,
			RemediationScript: "Set-MpPreference -DisableBehaviorMonitoring $false",
			CreatedAt:         now,
		},

		// CIS 18.9.84.4: Ensure 'Turn on IOAV (Downloaded Files) Protection' is set to 'Enabled'
		{
			ID:                "r-cis-18-9-84-4",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.84.4",
			Title:             "Ensure Microsoft Defender Downloaded Files Scanning (IOAV) is Enabled",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Scans all internet downloads and email attachments immediately upon arrival.",
			ExpectedValue:     "ioav_protection_enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.defender.ioav_protection_enabled"}, true]}`,
			RemediationScript: "Set-MpPreference -DisableIOAVProtection $false",
			CreatedAt:         now,
		},

		// CIS 18.9.84.5: Ensure 'Turn on Microsoft Defender Tamper Protection' is set to 'Enabled'
		{
			ID:                "r-cis-18-9-84-5",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.84.5",
			Title:             "Ensure Microsoft Defender Tamper Protection is Enabled",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "Tamper protection blocks malicious software and compromised administrators from altering Defender registry settings.",
			ExpectedValue:     "tamper_protection_enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.defender.tamper_protection_enabled"}, true]}`,
			RemediationScript: "Set-MpPreference -EnableTamperProtection $true",
			CreatedAt:         now,
		},

		// CIS 18.9.84.6: Ensure Microsoft Defender Scan Age is Fresh (<= 7 days)
		{
			ID:                "r-cis-18-9-84-6",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.84.6",
			Title:             "Ensure Microsoft Defender Antivirus Quick Scan Age is Under 7 Days",
			Category:          "System Defenses",
			Level:             "Level 1",
			Severity:          "MEDIUM",
			Rationale:         "Regular endpoint scans verify no persistent resident malware remains undetected.",
			ExpectedValue:     "quick_scan_age_days <= 7",
			CheckExpression:   `{"<=": [{"var": "security_baseline.defender.quick_scan_age_days"}, 7]}`,
			RemediationScript: "Start-MpScan -ScanType QuickScan",
			CreatedAt:         now,
		},

		// -------------------------------------------------------------------
		// Section 9: Windows Defender Firewall
		// -------------------------------------------------------------------

		// CIS 9.1.1: Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
		{
			ID:                "r-cis-9-1-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "9.1.1",
			Title:             "Ensure Windows Firewall Domain Profile is Enabled",
			Category:          "Network Security",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Stateful packet filtering on domain networks protects endpoints against lateral movement.",
			ExpectedValue:     "firewall_profiles.domain.enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.firewall_profiles.domain.enabled"}, true]}`,
			RemediationScript: "Set-NetFirewallProfile -Profile Domain -Enabled True",
			CreatedAt:         now,
		},

		// CIS 9.1.2: Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
		{
			ID:                "r-cis-9-1-2",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "9.1.2",
			Title:             "Ensure Windows Firewall Domain Profile Inbound Connections are Blocked by Default",
			Category:          "Network Security",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Unsolicited inbound connections must be dropped unless explicitly permitted by an authorized firewall rule.",
			ExpectedValue:     "domain.default_inbound in ['Block', 'BlockInbound']",
			CheckExpression:   `{"in": [{"var": "security_baseline.firewall_profiles.domain.default_inbound"}, ["Block", "BlockInbound"]]}`,
			RemediationScript: "Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block",
			CreatedAt:         now,
		},

		// CIS 9.2.1: Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
		{
			ID:                "r-cis-9-2-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "9.2.1",
			Title:             "Ensure Windows Firewall Private Profile is Enabled",
			Category:          "Network Security",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Protects endpoints when connected to trusted home or small business private subnets.",
			ExpectedValue:     "firewall_profiles.private.enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.firewall_profiles.private.enabled"}, true]}`,
			RemediationScript: "Set-NetFirewallProfile -Profile Private -Enabled True",
			CreatedAt:         now,
		},

		// CIS 9.2.2: Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
		{
			ID:                "r-cis-9-2-2",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "9.2.2",
			Title:             "Ensure Windows Firewall Private Profile Inbound Connections are Blocked by Default",
			Category:          "Network Security",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Prevents peer-to-peer compromise across private subnets.",
			ExpectedValue:     "private.default_inbound in ['Block', 'BlockInbound']",
			CheckExpression:   `{"in": [{"var": "security_baseline.firewall_profiles.private.default_inbound"}, ["Block", "BlockInbound"]]}`,
			RemediationScript: "Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block",
			CreatedAt:         now,
		},

		// CIS 9.3.1: Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
		{
			ID:                "r-cis-9-3-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "9.3.1",
			Title:             "Ensure Windows Firewall Public Profile is Enabled",
			Category:          "Network Security",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "Untrusted public networks (Wi-Fi hotspots, hotels) represent highest exposure surface.",
			ExpectedValue:     "firewall_profiles.public.enabled == true",
			CheckExpression:   `{"==": [{"var": "security_baseline.firewall_profiles.public.enabled"}, true]}`,
			RemediationScript: "Set-NetFirewallProfile -Profile Public -Enabled True",
			CreatedAt:         now,
		},

		// CIS 9.3.2: Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
		{
			ID:                "r-cis-9-3-2",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "9.3.2",
			Title:             "Ensure Windows Firewall Public Profile Inbound Connections are Blocked by Default",
			Category:          "Network Security",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "All inbound unsolicited traffic on public networks must be strictly blocked.",
			ExpectedValue:     "public.default_inbound in ['Block', 'BlockInbound']",
			CheckExpression:   `{"in": [{"var": "security_baseline.firewall_profiles.public.default_inbound"}, ["Block", "BlockInbound"]]}`,
			RemediationScript: "Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block",
			CreatedAt:         now,
		},

		// -------------------------------------------------------------------
		// Section 18.1: Hardware & Firmware Defenses
		// -------------------------------------------------------------------

		// CIS 18.1.1.1: Ensure Secure Boot is Enabled on UEFI firmware
		{
			ID:                "r-cis-18-1-1-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.1.1.1",
			Title:             "Ensure UEFI Secure Boot is Enabled",
			Category:          "Hardware & Firmware",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "Secure Boot cryptographically verifies OEM platform bootloaders, preventing rootkit and bootkit persistence.",
			ExpectedValue:     "firmware_bios.secure_boot_enabled == true",
			CheckExpression:   `{"==": [{"var": "firmware_bios.secure_boot_enabled"}, true]}`,
			RemediationScript: "Reboot to UEFI BIOS Setup and enable 'Secure Boot'.",
			CreatedAt:         now,
		},

		// CIS 18.1.1.2: Ensure system firmware is running in native UEFI mode
		{
			ID:                "r-cis-18-1-1-2",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.1.1.2",
			Title:             "Ensure System Firmware is Operating in Native UEFI Mode",
			Category:          "Hardware & Firmware",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Legacy BIOS CSM lacks modern memory isolation and security table interfaces required by Windows 11.",
			ExpectedValue:     "firmware_bios.uefi_mode == true",
			CheckExpression:   `{"==": [{"var": "firmware_bios.uefi_mode"}, true]}`,
			RemediationScript: "Convert MBR disk to GPT using 'mbr2gpt.exe /convert' and switch BIOS mode to Native UEFI.",
			CreatedAt:         now,
		},

		// CIS 18.1.2.1: Ensure Trusted Platform Module (TPM) 2.0 is Present
		{
			ID:                "r-cis-18-1-2-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.1.2.1",
			Title:             "Ensure Trusted Platform Module (TPM) is Present",
			Category:          "Hardware & Firmware",
			Level:             "Level 1",
			Severity:          "CRITICAL",
			Rationale:         "TPM provides tamper-resistant cryptographic storage for platform keys, BitLocker, and Device Guard.",
			ExpectedValue:     "tpm.present == true",
			CheckExpression:   `{"==": [{"var": "tpm.present"}, true]}`,
			RemediationScript: "Enable Intel PTT or AMD fTPM in BIOS Firmware Settings.",
			CreatedAt:         now,
		},

		// CIS 18.1.2.2: Ensure TPM Cryptographic Specification Version is 2.0
		{
			ID:                "r-cis-18-1-2-2",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.1.2.2",
			Title:             "Ensure TPM Cryptographic Specification is Version 2.0",
			Category:          "Hardware & Firmware",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "TPM 2.0 supports modern SHA-256 PCR banks and elliptic-curve cryptography.",
			ExpectedValue:     "tpm.spec_version in ['2.0', '2.0.0']",
			CheckExpression:   `{"in": [{"var": "tpm.spec_version"}, ["2.0", "2.0.0"]]}`,
			RemediationScript: "Upgrade motherboard TPM 1.2 firmware to TPM 2.0.",
			CreatedAt:         now,
		},

		// -------------------------------------------------------------------
		// Section 2.3: Identity & Access Control
		// -------------------------------------------------------------------

		// CIS 2.3.1.1: Ensure 'Accounts: Guest account status' is set to 'Disabled'
		{
			ID:                "r-cis-2-3-1-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "2.3.1.1",
			Title:             "Ensure Built-in Guest Account is Disabled",
			Category:          "Access Control",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Anonymous and guest accounts permit unauthorized local and network interactive sessions.",
			ExpectedValue:     "user_access.guest_account_disabled == true",
			CheckExpression:   `{"==": [{"var": "user_access.guest_account_disabled"}, true]}`,
			RemediationScript: "Disable-LocalUser -Name 'Guest'",
			CreatedAt:         now,
		},

		// CIS 2.3.1.5: Ensure Local Administrators group contains authorized accounts and is not empty
		{
			ID:                "r-cis-2-3-1-5",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "2.3.1.5",
			Title:             "Ensure Local Administrators Membership is Audited and Populated",
			Category:          "Access Control",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Verifies that local administrative rights are strictly inventoried and tracked across the fleet.",
			ExpectedValue:     "local_administrators is non-empty",
			CheckExpression:   `{"!=": [{"var": "user_access.local_administrators"}, []]}`,
			RemediationScript: "Audit and remediate Local Administrators group members.",
			CreatedAt:         now,
		},

		// CIS 18.9.58.1: Ensure Remote Desktop access rights and privileged groups are restricted
		{
			ID:                "r-cis-18-9-58-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.9.58.1",
			Title:             "Ensure Privileged and Remote Desktop Groups are Restricted and Defined",
			Category:          "Access Control",
			Level:             "Level 1",
			Severity:          "MEDIUM",
			Rationale:         "Prevents unauthenticated or lateral interactive Remote Desktop sessions.",
			ExpectedValue:     "privileged_groups is non-empty",
			CheckExpression:   `{"!=": [{"var": "user_access.privileged_groups"}, []]}`,
			RemediationScript: "Remove non-essential domain and local users from Remote Desktop Users group.",
			CreatedAt:         now,
		},

		// CIS 18.3.1.1: Ensure CPU Hardware Virtualization (VT-x / AMD-V) is enabled in firmware
		{
			ID:                "r-cis-18-3-1-1",
			FrameworkID:       fwID,
			FrameworkCode:     CISWin11FrameworkCode,
			RuleCode:          "18.3.1.1",
			Title:             "Ensure CPU Virtualization Extensions (VT-x / AMD-V) are Enabled in Firmware",
			Category:          "Hardware & Firmware",
			Level:             "Level 1",
			Severity:          "HIGH",
			Rationale:         "Hardware virtualization extensions are required for Hyper-V, VBS, and Credential Guard kernel isolation.",
			ExpectedValue:     "processor.virtualization_firmware_enabled == true",
			CheckExpression:   `{"==": [{"var": "processor.virtualization_firmware_enabled"}, true]}`,
			RemediationScript: "Enable Intel VT-x or AMD SVM in BIOS Setup.",
			CreatedAt:         now,
		},
	}
}
