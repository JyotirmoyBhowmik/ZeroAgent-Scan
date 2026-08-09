package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/google/uuid"
)

// PayloadDiffer compares consecutive host snapshots and emits classified drift events.
type PayloadDiffer struct{}

// NewPayloadDiffer creates a snapshot differ.
func NewPayloadDiffer() *PayloadDiffer {
	return &PayloadDiffer{}
}

// ComputePayloadHash generates a deterministic SHA-256 hash of a snapshot payload.
func ComputePayloadHash(snapshot *models.HostSnapshotPayload) (string, error) {
	if snapshot == nil {
		return "", fmt.Errorf("differ: snapshot is nil")
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}

// DiffSnapshots performs field-by-field diffing between previous and new snapshots.
// Fast short-circuits if payload hashes match.
func (d *PayloadDiffer) DiffSnapshots(
	tenantID, hostID, hostname string,
	newSnapshot, prevSnapshot *models.HostSnapshotPayload,
) ([]DriftEvent, error) {
	if newSnapshot == nil {
		return nil, fmt.Errorf("differ: newSnapshot cannot be nil")
	}
	if prevSnapshot == nil {
		// First baseline scan: no drift
		return nil, nil
	}

	// 1. FAST SHORT-CIRCUIT: Compare Payload Hashes
	newHash, err := ComputePayloadHash(newSnapshot)
	if err == nil {
		prevHash, errPrev := ComputePayloadHash(prevSnapshot)
		if errPrev == nil && newHash == prevHash {
			// Identical payload: short-circuit immediately
			return nil, nil
		}
	}

	now := time.Now().UTC()
	var events []DriftEvent

	addEvent := func(category, prop, baseline, current string, severity DriftSeverity) {
		events = append(events, DriftEvent{
			ID:             uuid.New().String(),
			TenantID:       tenantID,
			HostID:         hostID,
			Hostname:       hostname,
			DriftCategory:  category,
			PropertyName:   prop,
			BaselineValue:  baseline,
			CurrentValue:   current,
			Severity:       severity,
			IsAcknowledged: false,
			DetectedAt:     now,
			CreatedAt:      now,
		})
	}

	// -----------------------------------------------------------------------
	// 2. Security Baseline Diff
	// -----------------------------------------------------------------------
	nSec := newSnapshot.SecurityBaseline
	pSec := prevSnapshot.SecurityBaseline

	// BitLocker Protection Status
	nBLProt := getBitLockerStatus(nSec.BitLocker)
	pBLProt := getBitLockerStatus(pSec.BitLocker)
	if nBLProt != pBLProt {
		sev := SeverityInfo
		if pBLProt == 1 && nBLProt != 1 {
			sev = SeverityCritical // BitLocker turned OFF
		}
		addEvent("SecurityBaseline", "security_baseline.bitlocker.protection_status",
			fmt.Sprintf("%d", pBLProt), fmt.Sprintf("%d", nBLProt), sev)
	}

	// BitLocker Encryption Method
	nBLMeth := getBitLockerMethod(nSec.BitLocker)
	pBLMeth := getBitLockerMethod(pSec.BitLocker)
	if nBLMeth != pBLMeth && pBLMeth != "" {
		sev := SeverityWarning
		if strings.Contains(strings.ToLower(nBLMeth), "none") {
			sev = SeverityCritical
		}
		addEvent("SecurityBaseline", "security_baseline.bitlocker.encryption_method", pBLMeth, nBLMeth, sev)
	}

	// Defender Antivirus
	nAV := boolVal(nSec.Defender.AntivirusEnabled, true)
	pAV := boolVal(pSec.Defender.AntivirusEnabled, true)
	if nAV != pAV {
		sev := SeverityInfo
		if pAV && !nAV {
			sev = SeverityCritical // Defender disabled
		}
		addEvent("SecurityBaseline", "security_baseline.defender.antivirus_enabled",
			fmt.Sprintf("%v", pAV), fmt.Sprintf("%v", nAV), sev)
	}

	// Defender Real-Time Protection
	nRTP := boolVal(nSec.Defender.RealTimeProtectionEnabled, true)
	pRTP := boolVal(pSec.Defender.RealTimeProtectionEnabled, true)
	if nRTP != pRTP {
		sev := SeverityInfo
		if pRTP && !nRTP {
			sev = SeverityCritical // Real-time protection disabled
		}
		addEvent("SecurityBaseline", "security_baseline.defender.realtime_protection_enabled",
			fmt.Sprintf("%v", pRTP), fmt.Sprintf("%v", nRTP), sev)
	}

	// Defender Tamper Protection
	nTP := boolVal(nSec.Defender.TamperProtectionEnabled, true)
	pTP := boolVal(pSec.Defender.TamperProtectionEnabled, true)
	if nTP != pTP {
		sev := SeverityInfo
		if pTP && !nTP {
			sev = SeverityCritical
		}
		addEvent("SecurityBaseline", "security_baseline.defender.tamper_protection_enabled",
			fmt.Sprintf("%v", pTP), fmt.Sprintf("%v", nTP), sev)
	}

	// Defender Behavior Monitor
	nBM := boolVal(nSec.Defender.BehaviorMonitorEnabled, true)
	pBM := boolVal(pSec.Defender.BehaviorMonitorEnabled, true)
	if nBM != pBM {
		sev := SeverityInfo
		if pBM && !nBM {
			sev = SeverityCritical
		}
		addEvent("SecurityBaseline", "security_baseline.defender.behavior_monitor_enabled",
			fmt.Sprintf("%v", pBM), fmt.Sprintf("%v", nBM), sev)
	}

	// SMBv1 Protocol
	if nSec.SMB1Enabled != pSec.SMB1Enabled {
		sev := SeverityInfo
		if !pSec.SMB1Enabled && nSec.SMB1Enabled {
			sev = SeverityCritical // SMBv1 re-enabled!
		}
		addEvent("SecurityBaseline", "security_baseline.smb1_enabled",
			fmt.Sprintf("%v", pSec.SMB1Enabled), fmt.Sprintf("%v", nSec.SMB1Enabled), sev)
	}

	// LSA Protection (RunAsPPL)
	if nSec.LSAProtectionEnabled != pSec.LSAProtectionEnabled {
		sev := SeverityInfo
		if pSec.LSAProtectionEnabled && !nSec.LSAProtectionEnabled {
			sev = SeverityCritical // LSA Protection disabled!
		}
		addEvent("SecurityBaseline", "security_baseline.lsa_protection_enabled",
			fmt.Sprintf("%v", pSec.LSAProtectionEnabled), fmt.Sprintf("%v", nSec.LSAProtectionEnabled), sev)
	}

	// Credential Guard
	if nSec.CredentialGuardRunning != pSec.CredentialGuardRunning {
		sev := SeverityInfo
		if pSec.CredentialGuardRunning && !nSec.CredentialGuardRunning {
			sev = SeverityCritical // Credential Guard stopped!
		}
		addEvent("SecurityBaseline", "security_baseline.credential_guard_running",
			fmt.Sprintf("%v", pSec.CredentialGuardRunning), fmt.Sprintf("%v", nSec.CredentialGuardRunning), sev)
	}

	// Firewall Profiles
	diffFirewallProfile("Domain", pSec.FirewallProfiles.Domain, nSec.FirewallProfiles.Domain, addEvent)
	diffFirewallProfile("Private", pSec.FirewallProfiles.Private, nSec.FirewallProfiles.Private, addEvent)
	diffFirewallProfile("Public", pSec.FirewallProfiles.Public, nSec.FirewallProfiles.Public, addEvent)

	// -----------------------------------------------------------------------
	// 3. Firmware & BIOS Diff
	// -----------------------------------------------------------------------
	nFW := newSnapshot.FirmwareBios
	pFW := prevSnapshot.FirmwareBios

	if nFW.SecureBootEnabled != pFW.SecureBootEnabled {
		sev := SeverityInfo
		if pFW.SecureBootEnabled && !nFW.SecureBootEnabled {
			sev = SeverityCritical // Secure Boot disabled!
		}
		addEvent("Firmware", "firmware_bios.secure_boot_enabled",
			fmt.Sprintf("%v", pFW.SecureBootEnabled), fmt.Sprintf("%v", nFW.SecureBootEnabled), sev)
	}

	if nFW.UEFIMode != pFW.UEFIMode {
		sev := SeverityInfo
		if pFW.UEFIMode && !nFW.UEFIMode {
			sev = SeverityCritical // Downgraded to Legacy BIOS
		}
		addEvent("Firmware", "firmware_bios.uefi_mode",
			fmt.Sprintf("%v", pFW.UEFIMode), fmt.Sprintf("%v", nFW.UEFIMode), sev)
	}

	if nFW.Version != pFW.Version && pFW.Version != "" {
		addEvent("Firmware", "firmware_bios.version", pFW.Version, nFW.Version, SeverityWarning)
	}

	// -----------------------------------------------------------------------
	// 4. TPM Diff
	// -----------------------------------------------------------------------
	nTPM := newSnapshot.TPM
	pTPM := prevSnapshot.TPM

	if nTPM.Present != pTPM.Present {
		sev := SeverityInfo
		if pTPM.Present && !nTPM.Present {
			sev = SeverityCritical // TPM removed/disabled!
		}
		addEvent("TPM", "tpm.present",
			fmt.Sprintf("%v", pTPM.Present), fmt.Sprintf("%v", nTPM.Present), sev)
	}

	nTPMEn := boolVal(nTPM.IsEnabled, true)
	pTPMEn := boolVal(pTPM.IsEnabled, true)
	if nTPMEn != pTPMEn {
		sev := SeverityInfo
		if pTPMEn && !nTPMEn {
			sev = SeverityCritical
		}
		addEvent("TPM", "tpm.is_enabled",
			fmt.Sprintf("%v", pTPMEn), fmt.Sprintf("%v", nTPMEn), sev)
	}

	// -----------------------------------------------------------------------
	// 5. Processor & Hypervisor Isolation Diff
	// -----------------------------------------------------------------------
	nCPU := newSnapshot.Processor
	pCPU := prevSnapshot.Processor

	nVBS := strVal(nCPU.VBSStatus, "Running")
	pVBS := strVal(pCPU.VBSStatus, "Running")
	if nVBS != pVBS {
		sev := SeverityWarning
		if (pVBS == "Running" || pVBS == "1" || pVBS == "2") && (nVBS == "Disabled" || nVBS == "0") {
			sev = SeverityCritical
		}
		addEvent("Processor", "processor.vbs_status", pVBS, nVBS, sev)
	}

	nHVCI := strVal(nCPU.HVCIStatus, "Enabled")
	pHVCI := strVal(pCPU.HVCIStatus, "Enabled")
	if nHVCI != pHVCI {
		sev := SeverityWarning
		if (pHVCI == "Enabled" || pHVCI == "1" || pHVCI == "2") && (nHVCI == "Disabled" || nHVCI == "0") {
			sev = SeverityCritical
		}
		addEvent("Processor", "processor.hvci_status", pHVCI, nHVCI, sev)
	}

	// -----------------------------------------------------------------------
	// 6. User Access & Local Administrators Diff
	// -----------------------------------------------------------------------
	nUA := newSnapshot.UserAccess
	pUA := prevSnapshot.UserAccess

	// Check for newly added Local Administrators (CRITICAL)
	addedAdmins, removedAdmins := diffStringSlices(pUA.LocalAdministrators, nUA.LocalAdministrators)
	if len(addedAdmins) > 0 {
		addEvent("UserAccess", "user_access.local_administrators.added",
			strings.Join(pUA.LocalAdministrators, ", "),
			strings.Join(nUA.LocalAdministrators, ", "),
			SeverityCritical) // New local admin is a critical security event!
	} else if len(removedAdmins) > 0 {
		addEvent("UserAccess", "user_access.local_administrators.removed",
			strings.Join(pUA.LocalAdministrators, ", "),
			strings.Join(nUA.LocalAdministrators, ", "),
			SeverityInfo)
	}

	// Guest account status
	nGuest := boolVal(nUA.GuestAccountDisabled, true)
	pGuest := boolVal(pUA.GuestAccountDisabled, true)
	if nGuest != pGuest {
		sev := SeverityInfo
		if pGuest && !nGuest {
			sev = SeverityWarning // Guest account re-enabled
		}
		addEvent("UserAccess", "user_access.guest_account_disabled",
			fmt.Sprintf("%v", pGuest), fmt.Sprintf("%v", nGuest), sev)
	}

	// -----------------------------------------------------------------------
	// 7. Hardware, Memory & Storage Diff (WARNING)
	// -----------------------------------------------------------------------
	nMem := newSnapshot.Memory
	pMem := prevSnapshot.Memory
	if nMem.TotalCapacityBytes != pMem.TotalCapacityBytes && pMem.TotalCapacityBytes > 0 {
		addEvent("Hardware", "memory.total_capacity_bytes",
			fmt.Sprintf("%d", pMem.TotalCapacityBytes),
			fmt.Sprintf("%d", nMem.TotalCapacityBytes),
			SeverityWarning)
	}

	nStor := newSnapshot.Storage
	pStor := prevSnapshot.Storage
	if nStor.DiskCount != pStor.DiskCount && pStor.DiskCount > 0 {
		addEvent("Hardware", "storage.disk_count",
			fmt.Sprintf("%d", pStor.DiskCount),
			fmt.Sprintf("%d", nStor.DiskCount),
			SeverityWarning)
	}

	// -----------------------------------------------------------------------
	// 8. Network Adapters Diff (WARNING)
	// -----------------------------------------------------------------------
	nNICs := extractNICDescriptions(newSnapshot.Network.Adapters)
	pNICs := extractNICDescriptions(prevSnapshot.Network.Adapters)
	addedNICs, _ := diffStringSlices(pNICs, nNICs)
	if len(addedNICs) > 0 {
		addEvent("Hardware", "network.adapters",
			strings.Join(pNICs, "; "),
			strings.Join(nNICs, "; "),
			SeverityWarning) // New physical/virtual network adapter added
	}

	// -----------------------------------------------------------------------
	// 9. Installed Software Diff (INFO)
	// -----------------------------------------------------------------------
	nApps := extractAppNames(newSnapshot.Software.Applications)
	pApps := extractAppNames(prevSnapshot.Software.Applications)
	addedApps, removedApps := diffStringSlices(pApps, nApps)
	if len(addedApps) > 0 {
		addEvent("Software", "software.applications.installed",
			"", strings.Join(addedApps, ", "), SeverityInfo)
	}
	if len(removedApps) > 0 {
		addEvent("Software", "software.applications.uninstalled",
			strings.Join(removedApps, ", "), "", SeverityInfo)
	}

	return events, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func diffFirewallProfile(name string, prev, next models.SnapshotFirewallProfile, addEvent func(string, string, string, string, DriftSeverity)) {
	propEnabled := fmt.Sprintf("security_baseline.firewall_profiles.%s.enabled", strings.ToLower(name))
	if prev.Enabled != next.Enabled {
		sev := SeverityInfo
		if prev.Enabled && !next.Enabled {
			sev = SeverityCritical // Firewall turned off!
		}
		addEvent("SecurityBaseline", propEnabled, fmt.Sprintf("%v", prev.Enabled), fmt.Sprintf("%v", next.Enabled), sev)
	}

	propInbound := fmt.Sprintf("security_baseline.firewall_profiles.%s.default_inbound", strings.ToLower(name))
	if prev.DefaultInbound != next.DefaultInbound && prev.DefaultInbound != "" {
		sev := SeverityInfo
		if strings.EqualFold(prev.DefaultInbound, "Block") && strings.EqualFold(next.DefaultInbound, "Allow") {
			sev = SeverityCritical // Inbound default changed to Allow!
		}
		addEvent("SecurityBaseline", propInbound, prev.DefaultInbound, next.DefaultInbound, sev)
	}
}

func getBitLockerStatus(info models.SnapshotBitLockerInfo) int {
	if len(info.Volumes) > 0 {
		return info.Volumes[0].ProtectionStatus
	}
	return 0
}

func getBitLockerMethod(info models.SnapshotBitLockerInfo) string {
	if len(info.Volumes) > 0 {
		return info.Volumes[0].EncryptionMethod
	}
	return ""
}

func boolVal(p *bool, def bool) bool {
	if p != nil {
		return *p
	}
	return def
}

func strVal(p *string, def string) string {
	if p != nil {
		return *p
	}
	return def
}

func diffStringSlices(oldList, newList []string) (added, removed []string) {
	oldMap := make(map[string]bool, len(oldList))
	for _, item := range oldList {
		oldMap[item] = true
	}

	newMap := make(map[string]bool, len(newList))
	for _, item := range newList {
		newMap[item] = true
		if !oldMap[item] {
			added = append(added, item)
		}
	}

	for _, item := range oldList {
		if !newMap[item] {
			removed = append(removed, item)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func extractNICDescriptions(adapters []models.SnapshotNICEntry) []string {
	var list []string
	for _, a := range adapters {
		if a.Description != "" {
			list = append(list, fmt.Sprintf("%s (%s)", a.Description, a.MACAddress))
		}
	}
	return list
}

func extractAppNames(apps []models.SnapshotApplicationEntry) []string {
	var list []string
	for _, a := range apps {
		v := ""
		if a.Version != nil {
			v = " " + *a.Version
		}
		list = append(list, a.Name+v)
	}
	return list
}
