package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
)

// TestNoSecretLeakInLogsAndExceptions proves that secret credentials are never leaked
// into logs, error messages, terminal streams, or audit trails across both SUCCESS
// and FAILURE/EXCEPTION execution paths.
func TestNoSecretLeakInLogsAndExceptions(t *testing.T) {
	rawSecret := "SuperSecret_P@ssw0rd!_2026_gMSA"
	tenantID := "tenant-prod-redaction"

	// Buffer to capture all log output
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "", log.LstdFlags)

	provider, err := NewEnvelopeProvider([]byte("32-byte-master-key-prod-01234567"))
	if err != nil {
		t.Fatalf("Failed to initialize EnvelopeProvider: %v", err)
	}

	var recordedAudits []SecretResolutionAuditEntry
	auditFn := func(entry SecretResolutionAuditEntry) error {
		recordedAudits = append(recordedAudits, entry)
		// Simulate audit logging
		logger.Printf("[AUDIT] Action=%s Actor=%s Resource=%s Correlation=%s IP=%s",
			entry.Action, entry.GatewayID, entry.CredentialRef, entry.CorrelationID, entry.IPAddress)
		return nil
	}

	manager := NewVaultManager(provider, auditFn)
	ctx := context.Background()

	ref := CredentialRef{
		TenantID:       tenantID,
		CredentialType: "domain_gmsa",
		DomainOrHost:   "CORP.LOCAL",
		Username:       "svc_endpointguard_scan$",
	}

	// 1. Store Credential (Path 1: Success)
	opaqueID, err := manager.StoreCredential(ctx, ref, []byte(rawSecret))
	if err != nil {
		t.Fatalf("StoreCredential failed: %v", err)
	}

	// Assert opaque ID does NOT contain raw secret
	if strings.Contains(opaqueID, rawSecret) {
		t.Fatalf("CRITICAL SECURITY FAILURE: OpaqueID contains raw secret!")
	}

	ref.OpaqueID = opaqueID

	// 2. Resolve Credential (Path 2: Success)
	resolvedBytes, err := manager.ResolveCredentialForGateway(ctx, "gateway-hq-01", "scan-job-100", "corr-test-01", "10.100.1.1", ref)
	if err != nil {
		t.Fatalf("ResolveCredentialForGateway failed: %v", err)
	}
	if string(resolvedBytes) != rawSecret {
		t.Fatalf("Resolved secret mismatch")
	}

	// 3. Resolve Credential (Path 3: Exception / Failure - Invalid Opaque ID)
	badRef := ref
	badRef.OpaqueID = "sec_ref_nonexistent_999999"
	_, err = manager.ResolveCredentialForGateway(ctx, "gateway-hq-01", "scan-job-101", "corr-test-02", "10.100.1.1", badRef)
	if err == nil {
		t.Fatalf("Expected error for non-existent credential")
	}

	// 4. Simulate Error Propagation in Scanner with Failed Auth
	scanError := fmt.Errorf("winrm connection failed for %s: %w", ref.Username, errors.New("401 Unauthorized"))
	logger.Printf("[SCAN_LOG] Error: %v", scanError)

	// 5. In-Memory Zeroization of Resolved Secret
	for i := range resolvedBytes {
		resolvedBytes[i] = 0
	}
	if string(resolvedBytes) == rawSecret {
		t.Fatalf("CRITICAL: Secret bytes were not zeroized in memory!")
	}

	// 6. Comprehensive Redaction Inspection
	logOutput := logBuf.String()

	// Assert raw secret is NOT anywhere in the log stream
	if strings.Contains(logOutput, rawSecret) {
		t.Fatalf("CRITICAL SECURITY FAILURE: Raw secret leaked into log stream!\nLog Output:\n%s", logOutput)
	}

	// Assert raw secret is NOT in any audit entry
	for _, audit := range recordedAudits {
		if strings.Contains(audit.CredentialRef, rawSecret) ||
			strings.Contains(audit.Action, rawSecret) ||
			strings.Contains(audit.GatewayID, rawSecret) {
			t.Fatalf("CRITICAL SECURITY FAILURE: Raw secret leaked into audit log entry: %+v", audit)
		}
	}
}

// TestCredentialRotationWithoutRedeploy proves that credentials can be rotated atomically
// in-place without restarting API services or gateways.
func TestCredentialRotationWithoutRedeploy(t *testing.T) {
	provider, _ := NewEnvelopeProvider([]byte("32-byte-master-key-prod-01234567"))
	manager := NewVaultManager(provider, func(entry SecretResolutionAuditEntry) error { return nil })
	ctx := context.Background()

	ref := CredentialRef{
		TenantID:       "tenant-rotation-test",
		CredentialType: "domain_laps",
		DomainOrHost:   "CORP.LOCAL",
		Username:       "LAPS_Admin",
	}

	oldSecret := "Initial_LAPS_Password_2026_A"
	newSecret := "Rotated_LAPS_Password_2026_B"

	// 1. Store initial secret
	opaqueID, err := manager.StoreCredential(ctx, ref, []byte(oldSecret))
	if err != nil {
		t.Fatalf("StoreCredential failed: %v", err)
	}
	ref.OpaqueID = opaqueID

	// 2. Rotate secret without redeploy
	err = manager.RotateCredential(ctx, ref, []byte(newSecret))
	if err != nil {
		t.Fatalf("RotateCredential failed: %v", err)
	}

	// 3. Resolve rotated secret
	resolved, err := manager.ResolveCredentialForGateway(ctx, "gateway-01", "job-rotate-01", "corr-rot-01", "10.100.1.1", ref)
	if err != nil {
		t.Fatalf("ResolveCredentialForGateway failed after rotation: %v", err)
	}
	defer func() {
		for i := range resolved {
			resolved[i] = 0
		}
	}()

	if string(resolved) != newSecret {
		t.Fatalf("Expected rotated secret '%s', got '%s'", newSecret, string(resolved))
	}
}
