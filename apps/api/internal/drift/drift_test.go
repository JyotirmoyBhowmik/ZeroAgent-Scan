package drift

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
)

// Helper functions for pointers
func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
func intPtr(i int) *int       { return &i }

func baseSnapshot() *models.HostSnapshotPayload {
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
			Vendor:            "Dell Inc.",
			Version:           "1.14.0",
			SecureBootEnabled: true,
			UEFIMode:          true,
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
			Present:     true,
			SpecVersion: strPtr("2.0"),
			IsEnabled:   boolPtr(true),
		},
		Memory: models.SnapshotMemory{
			TotalCapacityBytes: 34359738368, // 32 GB
		},
		Storage: models.SnapshotStorage{
			DiskCount: 1,
		},
		Network: models.SnapshotNetwork{
			Adapters: []models.SnapshotNICEntry{
				{Description: "Intel Wi-Fi 6E AX211", MACAddress: "00:1A:2B:3C:4D:5E"},
			},
		},
		Software: models.SnapshotSoftware{
			Applications: []models.SnapshotApplicationEntry{
				{Name: "Google Chrome", Version: strPtr("115.0.0.0")},
			},
		},
		SecurityBaseline: models.SnapshotSecurityBaseline{
			BitLocker: models.SnapshotBitLockerInfo{
				Volumes: []models.SnapshotBitLockerVolume{
					{
						DriveLetter:      "C:",
						ProtectionStatus: 1,
						EncryptionMethod: "XtsAes256",
						LockStatus:       0,
					},
				},
			},
			Defender: models.SnapshotDefenderInfo{
				AntivirusEnabled:          boolPtr(true),
				RealTimeProtectionEnabled: boolPtr(true),
				TamperProtectionEnabled:   boolPtr(true),
			},
			SMB1Enabled:            false,
			LSAProtectionEnabled:   true,
			CredentialGuardRunning: true,
		},
		UserAccess: models.SnapshotUserAccess{
			LocalAdministrators:  []string{"Administrator", "CORP\\Domain Admins"},
			GuestAccountDisabled: boolPtr(true),
		},
	}
}

// ---------------------------------------------------------------------------
// 1. Short-Circuit & Severity Classification Tests
// ---------------------------------------------------------------------------

func TestPayloadDiffer_ShortCircuitOnIdentical(t *testing.T) {
	differ := NewPayloadDiffer()
	s1 := baseSnapshot()
	s2 := baseSnapshot()

	events, err := differ.DiffSnapshots("t1", "h1", "W11-01", s1, s2)
	if err != nil {
		t.Fatalf("DiffSnapshots failed: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("Expected 0 events on identical snapshots (short-circuit), got %d", len(events))
	}
}

func TestPayloadDiffer_SeverityClassification(t *testing.T) {
	differ := NewPayloadDiffer()

	// 1. CRITICAL: BitLocker Disabled + New Local Admin Added + Secure Boot Disabled + TPM Disabled
	prev := baseSnapshot()
	next := baseSnapshot()
	next.SecurityBaseline.BitLocker.Volumes[0].ProtectionStatus = 0
	next.UserAccess.LocalAdministrators = []string{"Administrator", "CORP\\Domain Admins", "BackdoorAdmin"}
	next.FirmwareBios.SecureBootEnabled = false
	next.TPM.Present = false

	// 2. WARNING: RAM upgrade + New NIC
	next.Memory.TotalCapacityBytes = 68719476736 // 64 GB
	next.Network.Adapters = append(next.Network.Adapters, models.SnapshotNICEntry{
		Description: "USB Ethernet Adapter",
		MACAddress:  "AA:BB:CC:DD:EE:FF",
	})

	// 3. INFO: New application installed
	next.Software.Applications = append(next.Software.Applications, models.SnapshotApplicationEntry{
		Name: "Wireshark",
	})

	events, err := differ.DiffSnapshots("t1", "h1", "W11-01", next, prev)
	if err != nil {
		t.Fatalf("DiffSnapshots failed: %v", err)
	}

	criticalCount := 0
	warningCount := 0
	infoCount := 0

	for _, ev := range events {
		switch ev.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityWarning:
			warningCount++
		case SeverityInfo:
			infoCount++
		}
	}

	if criticalCount != 4 {
		t.Errorf("Expected 4 CRITICAL drift events (BitLocker, Admin, SecureBoot, TPM), got %d", criticalCount)
	}
	if warningCount != 2 {
		t.Errorf("Expected 2 WARNING drift events (RAM, NIC), got %d", warningCount)
	}
	if infoCount != 1 {
		t.Errorf("Expected 1 INFO drift event (Software app), got %d", infoCount)
	}
}

// ---------------------------------------------------------------------------
// 2. Rule-Based Alert Matching & Suppression Window Tests
// ---------------------------------------------------------------------------

func TestAlertEngine_RuleMatchingAndSuppression(t *testing.T) {
	alertEng := NewAlertEngine()
	tenantID := "tenant-acme"
	hostID := "host-laptop-01"

	rules := []AlertRule{
		{
			ID:                     "rule-crit-laptop",
			TenantID:               tenantID,
			Name:                   "Critical Laptop Security Alert",
			SeverityFilter:         SeverityCritical,
			AssetClassFilter:       "Laptop",
			SuppressionWindowHours: 4,
			IsActive:               true,
		},
		{
			ID:                     "rule-server-all",
			TenantID:               tenantID,
			Name:                   "Server Alert",
			SeverityFilter:         SeverityCritical,
			AssetClassFilter:       "Server",
			SuppressionWindowHours: 4,
			IsActive:               true,
		},
	}

	eventCrit := DriftEvent{
		ID:            "ev-01",
		TenantID:      tenantID,
		HostID:        hostID,
		PropertyName:  "security_baseline.bitlocker.protection_status",
		Severity:      SeverityCritical,
		DriftCategory: "SecurityBaseline",
	}

	// 1. Laptop matches Laptop rule (not Server rule)
	matched := alertEng.EvaluateRules(eventCrit, "Laptop", rules)
	if len(matched) != 1 || matched[0].ID != "rule-crit-laptop" {
		t.Fatalf("Expected 1 match for Laptop rule, got %d", len(matched))
	}

	// 2. Mark dispatched -> subsequent evaluation within suppression window is SILENCED
	alertEng.MarkAlertDispatched(tenantID, hostID, eventCrit.PropertyName, time.Now().UTC())

	matchedSuppressed := alertEng.EvaluateRules(eventCrit, "Laptop", rules)
	if len(matchedSuppressed) != 0 {
		t.Errorf("Expected alert to be suppressed within 4h window, got %d matches", len(matchedSuppressed))
	}

	// 3. Different host with same property is NOT suppressed
	eventDifferentHost := eventCrit
	eventDifferentHost.HostID = "host-laptop-02"
	matchedOtherHost := alertEng.EvaluateRules(eventDifferentHost, "Laptop", rules)
	if len(matchedOtherHost) != 1 {
		t.Errorf("Different host should NOT be suppressed, got %d matches", len(matchedOtherHost))
	}

	// 4. Same host with different property (e.g. TPM) is NOT suppressed
	eventDifferentProp := eventCrit
	eventDifferentProp.PropertyName = "tpm.present"
	matchedOtherProp := alertEng.EvaluateRules(eventDifferentProp, "Laptop", rules)
	if len(matchedOtherProp) != 1 {
		t.Errorf("Different property should NOT be suppressed, got %d matches", len(matchedOtherProp))
	}
}

// ---------------------------------------------------------------------------
// 3. HMAC Webhook Dispatch & Verification Tests
// ---------------------------------------------------------------------------

func TestWebhookDispatcher_HMACSignatureAndVerification(t *testing.T) {
	secretKey := "super-secret-hmac-key-256-bits!"
	var capturedSignature string
	var capturedTimestamp string
	var capturedDeliveryID string
	var capturedBody []byte

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSignature = r.Header.Get("X-EndpointGuard-Signature")
		capturedTimestamp = r.Header.Get("X-EndpointGuard-Timestamp")
		capturedDeliveryID = r.Header.Get("X-EndpointGuard-Delivery-ID")
		capturedBody, _ = io.ReadAll(r.Body)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received": true}`))
	}))
	defer mockServer.Close()

	dispatcher := NewWebhookDispatcher(mockServer.Client(), 3)
	rule := AlertRule{
		ID:         "rule-01",
		Name:       "Test Webhook Rule",
		WebhookURL: mockServer.URL,
		SecretKey:  secretKey,
	}
	event := DriftEvent{
		ID:            "drift-01",
		TenantID:      "tenant-01",
		HostID:        "host-01",
		Hostname:      "W11-LP01",
		DriftCategory: "SecurityBaseline",
		PropertyName:  "security_baseline.bitlocker.protection_status",
		Severity:      SeverityCritical,
		DetectedAt:    time.Now().UTC(),
	}

	log, err := dispatcher.Dispatch(context.Background(), rule, event, "Laptop")
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if log.Status != "SUCCESS" || log.StatusCode != 200 {
		t.Fatalf("Expected delivery SUCCESS 200, got %s (%d)", log.Status, log.StatusCode)
	}
	if capturedDeliveryID == "" || capturedTimestamp == "" {
		t.Errorf("Missing delivery headers: ID='%s', TS='%s'", capturedDeliveryID, capturedTimestamp)
	}

	// Verify cryptographic authenticity via VerifyWebhookSignature
	if !VerifyWebhookSignature(secretKey, capturedBody, capturedSignature) {
		t.Errorf("HMAC signature verification failed! Body: %s, Sig: %s", string(capturedBody), capturedSignature)
	}

	// Verify tampering fails
	tamperedBody := append(capturedBody, []byte("tamper")...)
	if VerifyWebhookSignature(secretKey, tamperedBody, capturedSignature) {
		t.Errorf("Tampered body must fail HMAC verification!")
	}
}

// ---------------------------------------------------------------------------
// 4. Webhook Retry with Exponential Backoff & Delivery Log Tests
// ---------------------------------------------------------------------------

func TestWebhookDispatcher_RetryAndFailureLogging(t *testing.T) {
	var attempts int32

	// Server that fails first 2 attempts with 500, succeeds on 3rd attempt
	mockRetryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		curr := atomic.AddInt32(&attempts, 1)
		if curr < 3 {
			http.Error(w, "Temporary Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success": true}`))
	}))
	defer mockRetryServer.Close()

	dispatcher := NewWebhookDispatcher(mockRetryServer.Client(), 3)
	rule := AlertRule{
		ID:         "rule-retry",
		Name:       "Retry Test Rule",
		WebhookURL: mockRetryServer.URL,
		SecretKey:  "secret-key",
	}
	event := DriftEvent{
		ID:            "drift-retry",
		TenantID:      "tenant-01",
		HostID:        "host-01",
		PropertyName:  "tpm.present",
		Severity:      SeverityCritical,
		DetectedAt:    time.Now().UTC(),
	}

	log, err := dispatcher.Dispatch(context.Background(), rule, event, "Laptop")
	if err != nil {
		t.Fatalf("Dispatch retry expected success on 3rd attempt, got error: %v", err)
	}

	if log.Attempts != 3 || log.Status != "SUCCESS" {
		t.Errorf("Expected 3 attempts and SUCCESS, got %d attempts and status %s", log.Attempts, log.Status)
	}
}

func TestDriftWorker_EndToEndSnapshotProcessing(t *testing.T) {
	repo := NewMemoryDriftRepository()
	var webhookReceived bool

	mockReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookReceived = true
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReceiver.Close()

	dispatcher := NewWebhookDispatcher(mockReceiver.Client(), 3)
	worker := NewDriftWorker(repo, dispatcher)
	tenantID := "tenant-e2e"

	// Register alert rule
	_ = repo.SaveAlertRule(AlertRule{
		ID:                     "rule-e2e",
		TenantID:               tenantID,
		Name:                   "E2E Critical Alert",
		SeverityFilter:         SeverityCritical,
		AssetClassFilter:       "Laptop",
		WebhookURL:             mockReceiver.URL,
		SecretKey:              "secret-123",
		SuppressionWindowHours: 4,
		IsActive:               true,
	})

	prev := baseSnapshot()
	next := baseSnapshot()
	next.SecurityBaseline.BitLocker.Volumes[0].ProtectionStatus = 0 // Critical drift

	events, deliveryLogs, err := worker.ProcessSnapshot(context.Background(), tenantID, "host-01", "W11-01", "Laptop", next, prev)
	if err != nil {
		t.Fatalf("ProcessSnapshot failed: %v", err)
	}

	if len(events) == 0 {
		t.Fatalf("Expected drift events, got 0")
	}
	if !webhookReceived {
		t.Errorf("Expected webhook to be received by mock receiver")
	}
	if len(deliveryLogs) != 1 || deliveryLogs[0].Status != "SUCCESS" {
		t.Errorf("Expected 1 successful delivery log, got: %+v", deliveryLogs)
	}
}
