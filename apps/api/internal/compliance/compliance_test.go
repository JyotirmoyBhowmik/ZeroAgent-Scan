package compliance

import (
	"fmt"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
)

// Helper functions for pointers
func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
func intPtr(i int) *int       { return &i }

// ---------------------------------------------------------------------------
// 1. Golden Compliant Windows 11 Snapshot Payload
// ---------------------------------------------------------------------------

func sampleCompliantWindows11Snapshot() *models.HostSnapshotPayload {
	return &models.HostSnapshotPayload{
		AuditMetadata: models.SnapshotAuditMetadata{
			EngineVersion: "EndpointGuard-v1.2.0",
			TimestampUTC:  time.Now().UTC().Format(time.RFC3339),
			TargetHost:    "10.100.1.50",
		},
		SystemIdentity: models.SnapshotSystemIdentity{
			Hostname:     "W11-EXEC-LP01",
			Domain:       strPtr("CORP.ACME.LOCAL"),
			OSName:       "Microsoft Windows 11 Enterprise 23H2",
			OSVersion:    "10.0.22631.3593",
			OSBuild:      "22631",
			Manufacturer: "Dell Inc.",
			Model:        "Latitude 7440",
			ChassisType:  "Laptop",
		},
		FirmwareBios: models.SnapshotFirmwareBios{
			Vendor:                  "Dell Inc.",
			Version:                 "1.14.0",
			SecureBootEnabled:       true,
			UEFIMode:                true,
			MotherboardManufacturer: strPtr("Dell Inc."),
			MotherboardSerial:       strPtr("8XKJ9201"),
		},
		Processor: models.SnapshotProcessor{
			Models:                        []string{"13th Gen Intel(R) Core(TM) i7-13700H"},
			SocketCount:                   1,
			TotalCores:                    14,
			TotalThreads:                  20,
			VirtualizationFirmwareEnabled: boolPtr(true),
			VBSStatus:                     strPtr("Running"),
			HVCIStatus:                    strPtr("Enabled"),
		},
		TPM: models.SnapshotTPM{
			Present:        true,
			SpecVersion:    strPtr("2.0"),
			ManufacturerID: strPtr("IFX"),
			IsEnabled:      boolPtr(true),
			IsActivated:    boolPtr(true),
			IsOwned:        boolPtr(true),
		},
		SecurityBaseline: models.SnapshotSecurityBaseline{
			BitLocker: models.SnapshotBitLockerInfo{
				Volumes: []models.SnapshotBitLockerVolume{
					{
						DriveLetter:      "C:",
						ProtectionStatus: 1,
						EncryptionMethod: "XtsAes256",
						LockStatus:       0,
						KeyProtectors:    []string{"Tpm", "NumericalPassword"},
					},
				},
			},
			Defender: models.SnapshotDefenderInfo{
				AntivirusEnabled:          boolPtr(true),
				RealTimeProtectionEnabled: boolPtr(true),
				BehaviorMonitorEnabled:    boolPtr(true),
				IoavProtectionEnabled:     boolPtr(true),
				TamperProtectionEnabled:   boolPtr(true),
				AntivirusSignatureVersion: strPtr("1.405.289.0"),
				QuickScanAgeDays:          intPtr(1),
			},
			FirewallProfiles: models.SnapshotFirewallProfiles{
				Domain: models.SnapshotFirewallProfile{
					Enabled:        true,
					DefaultInbound: "Block",
				},
				Private: models.SnapshotFirewallProfile{
					Enabled:        true,
					DefaultInbound: "Block",
				},
				Public: models.SnapshotFirewallProfile{
					Enabled:        true,
					DefaultInbound: "Block",
				},
			},
			SMB1Enabled:            false,
			LSAProtectionEnabled:   true,
			CredentialGuardRunning: true,
		},
		UserAccess: models.SnapshotUserAccess{
			GuestAccountDisabled: boolPtr(true),
			LocalAdministrators:  []string{"Administrator", "CORP\\Domain Admins"},
			RemoteDesktopUsers:   []string{"CORP\\AuthorizedRdpUsers"},
			PrivilegedGroups: []models.SnapshotPrivilegedGroup{
				{
					GroupName: "Remote Desktop Users",
					Members:   []string{"CORP\\AuthorizedRdpUsers"},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// 2. Unit Tests for JSONLogic Evaluator Operators
// ---------------------------------------------------------------------------

func TestJSONLogic_BasicOperators(t *testing.T) {
	data := map[string]interface{}{
		"host": map[string]interface{}{
			"os":        "Windows 11",
			"build":     22631,
			"encrypted": true,
			"ciphers":   []interface{}{"XtsAes256", "Aes256"},
		},
		"score": 95.5,
	}

	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		{"var equality boolean", `{"==": [{"var": "host.encrypted"}, true]}`, true},
		{"var equality string", `{"==": [{"var": "host.os"}, "Windows 11"]}`, true},
		{"var numeric comparison >=", `{">=": [{"var": "host.build"}, 22000]}`, true},
		{"var numeric comparison <", `{"<": [{"var": "score"}, 100.0]}`, true},
		{"in array", `{"in": ["XtsAes256", {"var": "host.ciphers"}]}`, true},
		{"and logic true", `{"and": [{"==": [{"var": "host.encrypted"}, true]}, {">=": [{"var": "host.build"}, 20000]}]}`, true},
		{"and logic false", `{"and": [{"==": [{"var": "host.encrypted"}, true]}, {"==": [{"var": "host.os"}, "Linux"]}]}`, false},
		{"or logic", `{"or": [{"==": [{"var": "host.os"}, "Linux"]}, {"==": [{"var": "host.os"}, "Windows 11"]}]}`, true},
		{"not logic", `{"!": [{"==": [{"var": "host.os"}, "Linux"]}]}`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := EvaluateExpression(tc.expr, data)
			if err != nil {
				t.Fatalf("EvaluateExpression failed: %v", err)
			}
			if res != tc.expected {
				t.Errorf("Expected %v, got %v for expr: %s", tc.expected, res, tc.expr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Parametric Tests for ALL 28 Shipped CIS Rules (Pass & Fail Proofs)
// ---------------------------------------------------------------------------

func TestAll28ShippedCISRules_PassAndFailCases(t *testing.T) {
	rules := GetBuiltinCISWindows11Rules()
	if len(rules) < 25 {
		t.Fatalf("Expected at least 25 CIS rules, found %d", len(rules))
	}

	for _, rule := range rules {
		t.Run(fmt.Sprintf("CIS_%s_%s", rule.RuleCode, rule.Title), func(t *testing.T) {
			// 1. MUST PASS on fully compliant baseline
			compliantSnapshot := sampleCompliantWindows11Snapshot()
			passResult, err := EvaluateExpression(rule.CheckExpression, compliantSnapshot)
			if err != nil {
				t.Fatalf("Rule %s evaluation error on compliant snapshot: %v", rule.RuleCode, err)
			}
			if !passResult {
				t.Errorf("Rule %s (%s) FAILED on compliant snapshot! CheckExpression: %s", rule.RuleCode, rule.Title, rule.CheckExpression)
			}

			// 2. MUST FAIL when its specific setting is violated
			failingSnapshot := sampleCompliantWindows11Snapshot()
			mutateSnapshotForFailure(rule.RuleCode, failingSnapshot)

			failResult, err := EvaluateExpression(rule.CheckExpression, failingSnapshot)
			if err != nil {
				t.Fatalf("Rule %s evaluation error on failing snapshot: %v", rule.RuleCode, err)
			}
			if failResult {
				t.Errorf("Rule %s (%s) PASSED on deliberately non-compliant snapshot! CheckExpression: %s", rule.RuleCode, rule.Title, rule.CheckExpression)
			}
		})
	}
}

// mutateSnapshotForFailure modifies exactly the specific field tested by each rule code
func mutateSnapshotForFailure(ruleCode string, s *models.HostSnapshotPayload) {
	switch ruleCode {
	case "18.9.15.1": // BitLocker Protection Status
		s.SecurityBaseline.BitLocker.Volumes[0].ProtectionStatus = 0 // Unprotected
	case "18.9.15.2": // BitLocker Cipher Strength
		s.SecurityBaseline.BitLocker.Volumes[0].EncryptionMethod = "None"
	case "18.9.15.3": // BitLocker Lock Status
		s.SecurityBaseline.BitLocker.Volumes[0].LockStatus = 1 // Locked
	case "18.9.8.1": // SMBv1
		s.SecurityBaseline.SMB1Enabled = true // SMBv1 enabled
	case "18.9.10.1": // LSA Protection
		s.SecurityBaseline.LSAProtectionEnabled = false
	case "18.9.11.1": // VBS Status
		s.Processor.VBSStatus = strPtr("Disabled")
	case "18.9.11.2": // HVCI Status
		s.Processor.HVCIStatus = strPtr("Disabled")
	case "18.9.11.3": // Credential Guard
		s.SecurityBaseline.CredentialGuardRunning = false
	case "18.9.84.1": // Defender Antivirus
		s.SecurityBaseline.Defender.AntivirusEnabled = boolPtr(false)
	case "18.9.84.2": // Defender Realtime
		s.SecurityBaseline.Defender.RealTimeProtectionEnabled = boolPtr(false)
	case "18.9.84.3": // Defender Behavior Monitor
		s.SecurityBaseline.Defender.BehaviorMonitorEnabled = boolPtr(false)
	case "18.9.84.4": // Defender IOAV
		s.SecurityBaseline.Defender.IoavProtectionEnabled = boolPtr(false)
	case "18.9.84.5": // Defender Tamper Protection
		s.SecurityBaseline.Defender.TamperProtectionEnabled = boolPtr(false)
	case "18.9.84.6": // Defender Scan Age
		s.SecurityBaseline.Defender.QuickScanAgeDays = intPtr(45) // 45 days stale
	case "9.1.1": // Domain Firewall State
		s.SecurityBaseline.FirewallProfiles.Domain.Enabled = false
	case "9.1.2": // Domain Inbound Action
		s.SecurityBaseline.FirewallProfiles.Domain.DefaultInbound = "Allow"
	case "9.2.1": // Private Firewall State
		s.SecurityBaseline.FirewallProfiles.Private.Enabled = false
	case "9.2.2": // Private Inbound Action
		s.SecurityBaseline.FirewallProfiles.Private.DefaultInbound = "Allow"
	case "9.3.1": // Public Firewall State
		s.SecurityBaseline.FirewallProfiles.Public.Enabled = false
	case "9.3.2": // Public Inbound Action
		s.SecurityBaseline.FirewallProfiles.Public.DefaultInbound = "Allow"
	case "18.1.1.1": // Secure Boot
		s.FirmwareBios.SecureBootEnabled = false
	case "18.1.1.2": // UEFI Mode
		s.FirmwareBios.UEFIMode = false // Legacy BIOS
	case "18.1.2.1": // TPM Present
		s.TPM.Present = false
	case "18.1.2.2": // TPM Spec Version
		s.TPM.SpecVersion = strPtr("1.2") // Obsolete TPM 1.2
	case "2.3.1.1": // Guest Account
		s.UserAccess.GuestAccountDisabled = boolPtr(false) // Guest account active
	case "2.3.1.5": // Local Admins
		s.UserAccess.LocalAdministrators = []string{} // Empty
	case "18.9.58.1": // Remote Desktop Users
		s.UserAccess.PrivilegedGroups = []models.SnapshotPrivilegedGroup{} // Empty
	case "18.3.1.1": // CPU Virtualization
		s.Processor.VirtualizationFirmwareEnabled = boolPtr(false)
	}
}

// ---------------------------------------------------------------------------
// 4. Test Pluggability: Ingesting Custom Framework (DISA STIG) Without Code Changes
// ---------------------------------------------------------------------------

func TestComplianceEngine_PluggableFramework_DISASTIG(t *testing.T) {
	repo := NewMemoryComplianceRepository()
	engine := NewComplianceEngine(repo)

	// 1. Register new DISA STIG Framework dynamically
	stigFramework := ComplianceFramework{
		ID:          "f-disa-stig-win11",
		Code:        "disa_stig_win11",
		Name:        "DoD Windows 11 Security Technical Implementation Guide (STIG)",
		Version:     "V1R3",
		TargetOS:    "Windows 11",
		Description: "Defense Information Systems Agency STIG controls for DoD Windows 11 endpoints.",
		IsBuiltin:   false,
		CreatedAt:   time.Now().UTC(),
	}
	if err := repo.SaveFramework(stigFramework); err != nil {
		t.Fatalf("Failed to save DISA STIG framework: %v", err)
	}

	// 2. Add custom STIG rule: WN11-CC-000010 (Audit Credential Guard Running)
	stigRule := ComplianceRule{
		ID:                "r-stig-wn11-000010",
		FrameworkID:       stigFramework.ID,
		FrameworkCode:     stigFramework.Code,
		RuleCode:          "WN11-CC-000010",
		Title:             "Windows 11 must have Credential Guard enabled and running.",
		Category:          "Device Security",
		Level:             "CAT I",
		Severity:          "CRITICAL",
		Rationale:         "Credential Guard isolates credentials in a Virtualization-based security enclave.",
		ExpectedValue:     "credential_guard_running == true",
		CheckExpression:   `{"==": [{"var": "security_baseline.credential_guard_running"}, true]}`,
		RemediationScript: "Enable-WindowsOptionalFeature -Online -FeatureName IsolatedUserMode",
		CreatedAt:         time.Now().UTC(),
	}
	if err := repo.SaveRule(stigRule); err != nil {
		t.Fatalf("Failed to save custom STIG rule: %v", err)
	}

	// 3. Evaluate against compliant snapshot
	snapshot := sampleCompliantWindows11Snapshot()
	evals, score, err := engine.EvaluateHost("tenant-dod", "host-dod-01", "DOD-SEC-LP01", snapshot, "disa_stig_win11")
	if err != nil {
		t.Fatalf("EvaluateHost failed for custom framework: %v", err)
	}

	if len(evals) != 1 {
		t.Fatalf("Expected 1 STIG evaluation, got %d", len(evals))
	}
	if evals[0].Status != "PASS" {
		t.Errorf("Expected STIG evaluation to PASS, got %s", evals[0].Status)
	}
	if score.Score != 100.0 {
		t.Errorf("Expected 100.0 score, got %f", score.Score)
	}

	// 4. Evaluate against failing snapshot
	snapshot.SecurityBaseline.CredentialGuardRunning = false
	evalsFail, scoreFail, err := engine.EvaluateHost("tenant-dod", "host-dod-01", "DOD-SEC-LP01", snapshot, "disa_stig_win11")
	if err != nil {
		t.Fatalf("EvaluateHost failed on failing snapshot: %v", err)
	}
	if evalsFail[0].Status != "FAIL" {
		t.Errorf("Expected STIG evaluation to FAIL, got %s", evalsFail[0].Status)
	}
	if scoreFail.Score != 0.0 {
		t.Errorf("Expected 0.0 score, got %f", scoreFail.Score)
	}
}

// ---------------------------------------------------------------------------
// 5. Test Aggregate Host & Tenant Compliance Scoring
// ---------------------------------------------------------------------------

func TestComplianceEngine_HostAndTenantScoring(t *testing.T) {
	repo := NewMemoryComplianceRepository()
	engine := NewComplianceEngine(repo)
	tenantID := "tenant-acme-finance"

	// Host 1: 100% Compliant (All 28 rules pass)
	h1Snapshot := sampleCompliantWindows11Snapshot()
	_, score1, err := engine.EvaluateHost(tenantID, "host-01", "NY-EXEC-01", h1Snapshot, CISWin11FrameworkCode)
	if err != nil {
		t.Fatalf("Host 1 evaluation failed: %v", err)
	}
	if score1.Score != 100.0 || score1.Status != "COMPLIANT" {
		t.Errorf("Host 1 expected 100%% COMPLIANT, got %f (%s)", score1.Score, score1.Status)
	}

	// Host 2: Degraded (Disable BitLocker, SMBv1, LSA Protection, Realtime Protection -> 24/28 pass = 85.71%)
	h2Snapshot := sampleCompliantWindows11Snapshot()
	h2Snapshot.SecurityBaseline.BitLocker.Volumes[0].ProtectionStatus = 0
	h2Snapshot.SecurityBaseline.SMB1Enabled = true
	h2Snapshot.SecurityBaseline.LSAProtectionEnabled = false
	h2Snapshot.SecurityBaseline.Defender.RealTimeProtectionEnabled = boolPtr(false)

	_, score2, err := engine.EvaluateHost(tenantID, "host-02", "NY-TRADE-02", h2Snapshot, CISWin11FrameworkCode)
	if err != nil {
		t.Fatalf("Host 2 evaluation failed: %v", err)
	}
	if score2.Score < 80.0 || score2.Score > 90.0 || score2.Status != "DEGRADED" {
		t.Errorf("Host 2 expected DEGRADED (~85.71%%), got %f (%s)", score2.Score, score2.Status)
	}

	// Host 3: Non-Compliant (Violate 15 rules)
	h3Snapshot := sampleCompliantWindows11Snapshot()
	for _, code := range []string{"18.9.15.1", "18.9.15.2", "18.9.15.3", "18.9.8.1", "18.9.10.1", "18.9.11.1", "18.9.11.2", "18.9.11.3", "18.9.84.1", "18.9.84.2", "9.1.1", "9.2.1", "9.3.1", "18.1.1.1", "18.1.2.1"} {
		mutateSnapshotForFailure(code, h3Snapshot)
	}

	_, score3, err := engine.EvaluateHost(tenantID, "host-03", "NY-LAB-03", h3Snapshot, CISWin11FrameworkCode)
	if err != nil {
		t.Fatalf("Host 3 evaluation failed: %v", err)
	}
	if score3.Score > 70.0 || score3.Status != "NON_COMPLIANT" {
		t.Errorf("Host 3 expected NON_COMPLIANT (<70%%), got %f (%s)", score3.Score, score3.Status)
	}

	// Tenant Summary Aggregate Verification
	summary, err := repo.GetTenantSummary(tenantID, CISWin11FrameworkCode)
	if err != nil {
		t.Fatalf("GetTenantSummary failed: %v", err)
	}

	if summary.TotalHosts != 3 {
		t.Errorf("Expected 3 total hosts, got %d", summary.TotalHosts)
	}
	if summary.CompliantHosts != 1 {
		t.Errorf("Expected 1 compliant host, got %d", summary.CompliantHosts)
	}
	if summary.DegradedHosts != 1 {
		t.Errorf("Expected 1 degraded host, got %d", summary.DegradedHosts)
	}
	if summary.NonCompliantHosts != 1 {
		t.Errorf("Expected 1 non-compliant host, got %d", summary.NonCompliantHosts)
	}

	expectedAvg := (score1.Score + score2.Score + score3.Score) / 3.0
	if summary.AverageScore < expectedAvg-0.1 || summary.AverageScore > expectedAvg+0.1 {
		t.Errorf("Expected average score ~%f, got %f", expectedAvg, summary.AverageScore)
	}
}
