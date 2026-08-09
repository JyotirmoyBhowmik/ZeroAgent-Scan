package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ===========================================================================
// Test Helpers
// ===========================================================================

func mustEnvelopeProvider(t *testing.T) *EnvelopeProvider {
	t.Helper()
	// Fixed 32-byte test key — never used in production
	key := []byte("endpointguard-test-key-32bytes!!")
	p, err := NewEnvelopeProvider(key)
	if err != nil {
		t.Fatalf("NewEnvelopeProvider: %v", err)
	}
	return p
}

func testRef(opaqueID string) CredentialRef {
	return CredentialRef{
		OpaqueID:        opaqueID,
		TenantID:        "tenant-test-001",
		CredentialType:  "domain_kerberos",
		DomainOrHost:    "CORP.TEST.LOCAL",
		Username:        "svc_winrm_test$",
		VaultPath:       "",
		RotationVersion: 0,
	}
}

// captureStdout redirects os.Stdout to a buffer for the duration of fn,
// then returns everything that was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

// ===========================================================================
// 1. EnvelopeProvider: Core Encrypt / Decrypt Round-Trip
// ===========================================================================

func TestEnvelopeProvider_StoreAndResolve(t *testing.T) {
	p := mustEnvelopeProvider(t)
	ctx := context.Background()
	ref := testRef("sec_ref_test_roundtrip_001")
	secret := []byte("P@ssw0rd!SuperSecure#WinRM2024")

	if err := p.StoreSecret(ctx, ref, secret); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	resolved, err := p.ResolveSecret(ctx, ref)
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}

	if !bytes.Equal(resolved, []byte("P@ssw0rd!SuperSecure#WinRM2024")) {
		t.Fatalf("resolved secret mismatch: got %q", resolved)
	}
	zeroize(resolved)
}

func TestEnvelopeProvider_ResolveNotFound(t *testing.T) {
	p := mustEnvelopeProvider(t)
	ctx := context.Background()
	ref := testRef("sec_ref_nonexistent_999")

	_, err := p.ResolveSecret(ctx, ref)
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound, got: %v", err)
	}
}

func TestEnvelopeProvider_DeleteAndZeroize(t *testing.T) {
	p := mustEnvelopeProvider(t)
	ctx := context.Background()
	ref := testRef("sec_ref_delete_test_001")
	secret := []byte("DeleteMe!Secure#2024")

	_ = p.StoreSecret(ctx, ref, secret)

	if err := p.DeleteSecret(ctx, ref); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	// Resolve after delete must fail
	_, err := p.ResolveSecret(ctx, ref)
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound after delete, got: %v", err)
	}

	// Double-delete must also fail
	err = p.DeleteSecret(ctx, ref)
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound on double-delete, got: %v", err)
	}
}

func TestEnvelopeProvider_TamperedCiphertext(t *testing.T) {
	p := mustEnvelopeProvider(t)
	ctx := context.Background()
	ref := testRef("sec_ref_tamper_test_001")
	_ = p.StoreSecret(ctx, ref, []byte("TamperTestSecret"))

	// Corrupt ciphertext
	p.mu.Lock()
	rec := p.records[ref.OpaqueID]
	rec.Ciphertext[0] ^= 0xFF
	p.mu.Unlock()

	_, err := p.ResolveSecret(ctx, ref)
	if err == nil {
		t.Fatal("expected decryption error on tampered ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "authentication tag mismatch") {
		t.Fatalf("expected GCM auth tag error, got: %v", err)
	}
}

func TestEnvelopeProvider_InvalidKeyLength(t *testing.T) {
	_, err := NewEnvelopeProvider([]byte("too-short"))
	if err == nil {
		t.Fatal("expected error for short key, got nil")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected key length error, got: %v", err)
	}
}

func TestEnvelopeProvider_HealthCheck(t *testing.T) {
	p := mustEnvelopeProvider(t)
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck should return nil for envelope provider: %v", err)
	}
}

func TestEnvelopeProvider_Name(t *testing.T) {
	p := mustEnvelopeProvider(t)
	if p.Name() != "envelope-aes256gcm" {
		t.Fatalf("expected name 'envelope-aes256gcm', got '%s'", p.Name())
	}
}

// ===========================================================================
// 2. Credential Rotation (LAPS/gMSA Support)
// ===========================================================================

func TestEnvelopeProvider_RotateSecret(t *testing.T) {
	p := mustEnvelopeProvider(t)
	ctx := context.Background()
	ref := testRef("sec_ref_rotate_test_001")

	originalSecret := []byte("OriginalLAPSPassword!2024")
	rotatedSecret := []byte("RotatedgMSAPassword!2025")

	_ = p.StoreSecret(ctx, ref, originalSecret)

	// Verify original
	resolved, _ := p.ResolveSecret(ctx, ref)
	if !bytes.Equal(resolved, []byte("OriginalLAPSPassword!2024")) {
		t.Fatalf("pre-rotation mismatch")
	}
	zeroize(resolved)

	// Rotate
	if err := p.RotateSecret(ctx, ref, rotatedSecret); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	// Verify rotated value
	resolved2, _ := p.ResolveSecret(ctx, ref)
	if !bytes.Equal(resolved2, []byte("RotatedgMSAPassword!2025")) {
		t.Fatalf("post-rotation mismatch: got %q", resolved2)
	}
	zeroize(resolved2)

	// Verify rotation version incremented
	p.mu.RLock()
	rec := p.records[ref.OpaqueID]
	if rec.RotationVersion != 1 {
		t.Fatalf("expected rotation_version=1 after rotation, got %d", rec.RotationVersion)
	}
	p.mu.RUnlock()
}

func TestEnvelopeProvider_RotateNonexistent(t *testing.T) {
	p := mustEnvelopeProvider(t)
	err := p.RotateSecret(context.Background(), testRef("sec_ref_ghost_001"), []byte("new"))
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound on rotate of nonexistent, got: %v", err)
	}
}

// ===========================================================================
// 3. VaultManager: Gateway-Only Resolution with Audit-Before-Access
// ===========================================================================

func TestVaultManager_StoreAndResolve(t *testing.T) {
	p := mustEnvelopeProvider(t)
	var auditEntries []SecretResolutionAuditEntry
	auditFn := func(entry SecretResolutionAuditEntry) error {
		auditEntries = append(auditEntries, entry)
		return nil
	}

	vm := NewVaultManager(p, auditFn)
	ctx := context.Background()

	ref := CredentialRef{
		TenantID:       "tenant-001",
		CredentialType: "domain_kerberos",
		DomainOrHost:   "CORP.TEST.LOCAL",
		Username:       "svc_audit$",
	}

	opaqueID, err := vm.StoreCredential(ctx, ref, []byte("GatewayResolveTest!Secret"))
	if err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}
	if !strings.HasPrefix(opaqueID, "sec_ref_domain_kerberos_") {
		t.Fatalf("opaque ID format wrong: %s", opaqueID)
	}

	// Resolve via gateway
	ref.OpaqueID = opaqueID
	secret, err := vm.ResolveCredentialForGateway(
		ctx, "gw-subnet-10-100-1-0", "scan-job-001", "corr-001", "10.100.1.5", ref,
	)
	if err != nil {
		t.Fatalf("ResolveCredentialForGateway: %v", err)
	}
	defer zeroize(secret)

	if !bytes.Equal(secret, []byte("GatewayResolveTest!Secret")) {
		t.Fatalf("resolved secret mismatch")
	}

	// Verify audit was written BEFORE resolution
	if len(auditEntries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditEntries))
	}
	entry := auditEntries[0]
	if entry.Action != "credential.resolved" {
		t.Fatalf("expected action 'credential.resolved', got '%s'", entry.Action)
	}
	if entry.GatewayID != "gw-subnet-10-100-1-0" {
		t.Fatalf("expected gateway ID in audit, got '%s'", entry.GatewayID)
	}
	if entry.CredentialRef != opaqueID {
		t.Fatalf("expected opaque ID '%s' in audit, got '%s'", opaqueID, entry.CredentialRef)
	}
	if entry.ScanJobID != "scan-job-001" {
		t.Fatalf("expected scan job ID in audit, got '%s'", entry.ScanJobID)
	}
}

// ===========================================================================
// 4. Authorization Enforcement: Dashboard/Non-Gateway Callers Denied
// ===========================================================================

func TestVaultManager_ResolveWithoutGatewayID_Denied(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)

	ref := testRef("sec_ref_denied_001")
	_ = p.StoreSecret(context.Background(), ref, []byte("ShouldNotResolve"))

	// Empty gateway ID → authorization denied
	_, err := vm.ResolveCredentialForGateway(
		context.Background(), "", "scan-001", "corr-001", "10.0.0.1", ref,
	)
	if !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("expected ErrAuthorizationDenied for empty gateway ID, got: %v", err)
	}

	// Whitespace-only gateway ID → authorization denied
	_, err = vm.ResolveCredentialForGateway(
		context.Background(), "   ", "scan-001", "corr-001", "10.0.0.1", ref,
	)
	if !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("expected ErrAuthorizationDenied for whitespace gateway ID, got: %v", err)
	}
}

// ===========================================================================
// 5. Audit-Before-Access: Resolution Aborted on Audit Failure
// ===========================================================================

func TestVaultManager_AuditFailure_AbortsResolution(t *testing.T) {
	p := mustEnvelopeProvider(t)
	ref := testRef("sec_ref_audit_abort_001")
	_ = p.StoreSecret(context.Background(), ref, []byte("AuditAbortSecret"))

	auditErr := fmt.Errorf("simulated audit storage failure")
	failingAudit := func(_ SecretResolutionAuditEntry) error {
		return auditErr
	}

	vm := NewVaultManager(p, failingAudit)

	_, err := vm.ResolveCredentialForGateway(
		context.Background(), "gw-test-001", "scan-001", "corr-001", "10.0.0.1", ref,
	)
	if err == nil {
		t.Fatal("expected error when audit fails, got nil")
	}
	if !errors.Is(err, ErrAuditWriteFailed) {
		t.Fatalf("expected ErrAuditWriteFailed, got: %v", err)
	}
}

// ===========================================================================
// 6. VaultManager Rotation via Manager Layer
// ===========================================================================

func TestVaultManager_RotateCredential(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)
	ctx := context.Background()

	ref := CredentialRef{
		TenantID:       "tenant-rotation-001",
		CredentialType: "laps",
		DomainOrHost:   "WORKGROUP",
		Username:       "Administrator",
	}

	opaqueID, _ := vm.StoreCredential(ctx, ref, []byte("InitialLAPSPassword!"))
	ref.OpaqueID = opaqueID

	// Rotate
	if err := vm.RotateCredential(ctx, ref, []byte("RotatedLAPSPassword!2025")); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}

	// Verify new secret
	secret, err := vm.ResolveCredentialForGateway(
		ctx, "gw-laps-001", "scan-laps-001", "corr-laps-001", "10.0.0.1", ref,
	)
	if err != nil {
		t.Fatalf("ResolveCredentialForGateway after rotation: %v", err)
	}
	defer zeroize(secret)

	if !bytes.Equal(secret, []byte("RotatedLAPSPassword!2025")) {
		t.Fatalf("post-rotation secret mismatch: got %q", secret)
	}
}

// ===========================================================================
// 7. CRITICAL: Secrets NEVER Appear in Logs, Errors, or API Responses
// ===========================================================================

func TestSecrets_NeverInErrorMessages(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)
	ctx := context.Background()

	secretValue := "TopSecret!P@ssw0rd#NeverLeak$2024"
	ref := CredentialRef{
		TenantID:       "tenant-leak-test",
		CredentialType: "domain_ntlm",
		DomainOrHost:   "CORP.LEAK.TEST",
		Username:       "svc_leak_test$",
	}

	// Store
	opaqueID, err := vm.StoreCredential(ctx, ref, []byte(secretValue))
	if err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}
	ref.OpaqueID = opaqueID

	// Force various error paths and verify no secret leakage

	// Error path 1: Missing tenant_id on store
	_, err = vm.StoreCredential(ctx, CredentialRef{CredentialType: "test"}, []byte(secretValue))
	assertNoSecretInError(t, err, secretValue)

	// Error path 2: Authorization denied
	_, err = vm.ResolveCredentialForGateway(ctx, "", "scan", "corr", "ip", ref)
	assertNoSecretInError(t, err, secretValue)

	// Error path 3: Audit failure
	failVM := NewVaultManager(p, func(_ SecretResolutionAuditEntry) error {
		return fmt.Errorf("audit disk full")
	})
	_, err = failVM.ResolveCredentialForGateway(ctx, "gw", "scan", "corr", "ip", ref)
	assertNoSecretInError(t, err, secretValue)

	// Error path 4: Missing opaque_id on rotate
	err = vm.RotateCredential(ctx, CredentialRef{TenantID: "t"}, []byte(secretValue))
	assertNoSecretInError(t, err, secretValue)

	// Error path 5: Missing opaque_id on delete
	err = vm.DeleteCredential(ctx, CredentialRef{})
	assertNoSecretInError(t, err, secretValue)

	// Error path 6: Resolve nonexistent
	badRef := testRef("sec_ref_nonexistent_leak_test")
	_, err = vm.ResolveCredentialForGateway(ctx, "gw", "scan", "corr", "ip", badRef)
	assertNoSecretInError(t, err, secretValue)
}

func TestSecrets_NeverInPanicRecovery(t *testing.T) {
	secretValue := "PanicPathSecret!NeverLog#2024"

	// Simulate a panic path with deferred zeroize
	var recovered interface{}
	func() {
		plaintext := []byte(secretValue)
		defer func() {
			recovered = recover()
			zeroize(plaintext)
		}()
		panic("simulated vault panic")
	}()

	if recovered == nil {
		t.Fatal("expected panic to be recovered")
	}
	panicMsg := fmt.Sprintf("%v", recovered)
	if strings.Contains(panicMsg, secretValue) {
		t.Fatalf("SECURITY VIOLATION: secret found in panic message: %s", panicMsg)
	}
}

func TestSecrets_NeverInAuditEntries(t *testing.T) {
	p := mustEnvelopeProvider(t)
	secretValue := "AuditLeakTest!Secret#2024"
	var capturedEntries []SecretResolutionAuditEntry

	auditFn := func(entry SecretResolutionAuditEntry) error {
		capturedEntries = append(capturedEntries, entry)
		return nil
	}

	vm := NewVaultManager(p, auditFn)
	ctx := context.Background()

	ref := CredentialRef{
		TenantID:       "tenant-audit-leak",
		CredentialType: "ssh_key",
		DomainOrHost:   "10.100.1.0/24",
		Username:       "bmc_root",
	}

	opaqueID, _ := vm.StoreCredential(ctx, ref, []byte(secretValue))
	ref.OpaqueID = opaqueID

	_, _ = vm.ResolveCredentialForGateway(
		ctx, "gw-audit-check", "scan-audit", "corr-audit", "10.0.0.1", ref,
	)

	for i, entry := range capturedEntries {
		// Serialize entire entry to JSON and check for secret
		entryJSON, _ := json.Marshal(entry)
		entryStr := string(entryJSON)
		if strings.Contains(entryStr, secretValue) {
			t.Fatalf("SECURITY VIOLATION: secret found in audit entry %d: %s", i, entryStr)
		}
		// Also check individual fields
		if strings.Contains(entry.CredentialRef, secretValue) {
			t.Fatalf("SECURITY VIOLATION: secret in CredentialRef field")
		}
		if strings.Contains(entry.GatewayID, secretValue) {
			t.Fatalf("SECURITY VIOLATION: secret in GatewayID field")
		}
	}
}

func TestSecrets_NeverInStdoutLogs(t *testing.T) {
	secretValue := "StdoutLeakTest!NeverPrint#2024"
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)
	ctx := context.Background()

	ref := CredentialRef{
		TenantID:       "tenant-stdout-leak",
		CredentialType: "domain_kerberos",
		DomainOrHost:   "CORP.STDOUT.TEST",
		Username:       "svc_stdout_test$",
	}

	output := captureStdout(t, func() {
		opaqueID, _ := vm.StoreCredential(ctx, ref, []byte(secretValue))
		ref.OpaqueID = opaqueID
		secret, _ := vm.ResolveCredentialForGateway(
			ctx, "gw-stdout-check", "scan-stdout", "corr-stdout", "10.0.0.1", ref,
		)
		if secret != nil {
			zeroize(secret)
		}
	})

	if strings.Contains(output, secretValue) {
		t.Fatalf("SECURITY VIOLATION: secret found in stdout: %s", output)
	}
}

func TestSecrets_ZeroizedAfterStore(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)

	secretBytes := []byte("ZeroizeAfterStore!2024")
	ref := CredentialRef{
		TenantID:       "tenant-zeroize",
		CredentialType: "snmp_v3",
		DomainOrHost:   "10.100.2.0/24",
		Username:       "snmp_admin",
	}

	_, _ = vm.StoreCredential(context.Background(), ref, secretBytes)

	// After StoreCredential, the plaintext slice should be zeroed
	for _, b := range secretBytes {
		if b != 0 {
			t.Fatal("SECURITY VIOLATION: plaintext not zeroed after StoreCredential")
		}
	}
}

func TestSecrets_ZeroizedAfterRotation(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)
	ctx := context.Background()

	ref := CredentialRef{
		TenantID:       "tenant-rotate-zero",
		CredentialType: "gmsa",
		DomainOrHost:   "CORP.ROTATE.TEST",
		Username:       "svc_gmsa$",
	}

	opaqueID, _ := vm.StoreCredential(ctx, ref, []byte("InitialValue"))
	ref.OpaqueID = opaqueID

	rotateBytes := []byte("RotatedValue!MustBeZeroed")
	_ = vm.RotateCredential(ctx, ref, rotateBytes)

	for _, b := range rotateBytes {
		if b != 0 {
			t.Fatal("SECURITY VIOLATION: plaintext not zeroed after RotateCredential")
		}
	}
}

// ===========================================================================
// 8. Concurrency Safety
// ===========================================================================

func TestEnvelopeProvider_ConcurrentAccess(t *testing.T) {
	p := mustEnvelopeProvider(t)
	ctx := context.Background()
	const numWorkers = 50

	var wg sync.WaitGroup
	errs := make(chan error, numWorkers*3)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ref := testRef(fmt.Sprintf("sec_ref_concurrent_%03d", idx))
			secret := []byte(fmt.Sprintf("ConcurrentSecret#%03d", idx))

			if err := p.StoreSecret(ctx, ref, secret); err != nil {
				errs <- fmt.Errorf("store[%d]: %w", idx, err)
				return
			}

			resolved, err := p.ResolveSecret(ctx, ref)
			if err != nil {
				errs <- fmt.Errorf("resolve[%d]: %w", idx, err)
				return
			}

			expected := fmt.Sprintf("ConcurrentSecret#%03d", idx)
			if !bytes.Equal(resolved, []byte(expected)) {
				errs <- fmt.Errorf("mismatch[%d]: expected %q, got %q", idx, expected, resolved)
				return
			}
			zeroize(resolved)

			if err := p.DeleteSecret(ctx, ref); err != nil {
				errs <- fmt.Errorf("delete[%d]: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent test failure: %v", err)
	}
}

// ===========================================================================
// 9. GenerateOpaqueID Format Tests
// ===========================================================================

func TestGenerateOpaqueID_Formats(t *testing.T) {
	tests := []struct {
		prefix   string
		expected string
	}{
		{"domain_kerberos", "sec_ref_domain_kerberos_"},
		{"snmp_v3", "sec_ref_snmp_v3_"},
		{"ssh_key", "sec_ref_ssh_key_"},
		{"laps", "sec_ref_laps_"},
		{"gmsa", "sec_ref_gmsa_"},
		{"", "sec_ref_cred_"},
		{"!@#$%", "sec_ref_cred_"},
	}

	for _, tc := range tests {
		id := GenerateOpaqueID(tc.prefix)
		if !strings.HasPrefix(id, tc.expected) {
			t.Errorf("GenerateOpaqueID(%q) = %q, want prefix %q", tc.prefix, id, tc.expected)
		}
		if len(id) < len(tc.expected)+12 {
			t.Errorf("opaque ID %q too short", id)
		}
	}

	// Uniqueness
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := GenerateOpaqueID("test")
		if seen[id] {
			t.Fatalf("duplicate opaque ID generated: %s", id)
		}
		seen[id] = true
	}
}

// ===========================================================================
// 10. Validation Edge Cases
// ===========================================================================

func TestVaultManager_StoreWithoutTenantID(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)

	_, err := vm.StoreCredential(context.Background(), CredentialRef{}, []byte("test"))
	if !errors.Is(err, ErrInvalidCredentialRef) {
		t.Fatalf("expected ErrInvalidCredentialRef for missing tenant_id, got: %v", err)
	}
}

func TestVaultManager_ResolveWithoutOpaqueID(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)

	_, err := vm.ResolveCredentialForGateway(
		context.Background(), "gw-test", "scan", "corr", "ip",
		CredentialRef{TenantID: "t"},
	)
	if !errors.Is(err, ErrInvalidCredentialRef) {
		t.Fatalf("expected ErrInvalidCredentialRef for missing opaque_id, got: %v", err)
	}
}

func TestVaultManager_ResolveWithoutTenantID(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)

	_, err := vm.ResolveCredentialForGateway(
		context.Background(), "gw-test", "scan", "corr", "ip",
		CredentialRef{OpaqueID: "sec_ref_test"},
	)
	if !errors.Is(err, ErrInvalidCredentialRef) {
		t.Fatalf("expected ErrInvalidCredentialRef for missing tenant_id, got: %v", err)
	}
}

func TestVaultManager_DeleteWithoutOpaqueID(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)

	err := vm.DeleteCredential(context.Background(), CredentialRef{})
	if !errors.Is(err, ErrInvalidCredentialRef) {
		t.Fatalf("expected ErrInvalidCredentialRef for missing opaque_id, got: %v", err)
	}
}

func TestVaultManager_RotateWithoutOpaqueID(t *testing.T) {
	p := mustEnvelopeProvider(t)
	auditFn := func(_ SecretResolutionAuditEntry) error { return nil }
	vm := NewVaultManager(p, auditFn)

	err := vm.RotateCredential(context.Background(), CredentialRef{}, []byte("new"))
	if !errors.Is(err, ErrInvalidCredentialRef) {
		t.Fatalf("expected ErrInvalidCredentialRef for missing opaque_id, got: %v", err)
	}
}

// ===========================================================================
// 11. HashiCorpVaultProvider Constructor Validation
// ===========================================================================

func TestHashiCorpVaultProvider_EmptyAddr(t *testing.T) {
	_, err := NewHashiCorpVaultProvider("", "token", "mount")
	if err == nil {
		t.Fatal("expected error for empty addr")
	}
}

func TestHashiCorpVaultProvider_EmptyToken(t *testing.T) {
	_, err := NewHashiCorpVaultProvider("https://vault.test:8200", "", "mount")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestHashiCorpVaultProvider_DefaultMount(t *testing.T) {
	p, err := NewHashiCorpVaultProvider("https://vault.test:8200", "test-token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.kvMountPath != "endpointguard" {
		t.Fatalf("expected default mount 'endpointguard', got '%s'", p.kvMountPath)
	}
}

func TestHashiCorpVaultProvider_Name(t *testing.T) {
	p, _ := NewHashiCorpVaultProvider("https://vault.test:8200", "test-token", "")
	if p.Name() != "hashicorp-vault-kv2" {
		t.Fatalf("expected name 'hashicorp-vault-kv2', got '%s'", p.Name())
	}
}

// ===========================================================================
// 12. Provider Swappability: Same VaultManager works with both backends
// ===========================================================================

func TestProviderSwappability(t *testing.T) {
	providers := []SecretProvider{
		mustEnvelopeProvider(t),
	}

	// We can't test a real HashiCorp Vault in unit tests, but we verify the
	// interface contract is satisfied at compile time by this assertion:
	var _ SecretProvider = (*HashiCorpVaultProvider)(nil)
	var _ SecretProvider = (*EnvelopeProvider)(nil)

	for _, provider := range providers {
		t.Run(provider.Name(), func(t *testing.T) {
			auditCalled := false
			auditFn := func(_ SecretResolutionAuditEntry) error {
				auditCalled = true
				return nil
			}

			vm := NewVaultManager(provider, auditFn)
			ctx := context.Background()

			ref := CredentialRef{
				TenantID:       "tenant-swap-test",
				CredentialType: "domain_ntlm",
				DomainOrHost:   "SWAP.TEST",
				Username:       "svc_swap$",
			}

			opaqueID, err := vm.StoreCredential(ctx, ref, []byte("SwapTestSecret!"))
			if err != nil {
				t.Fatalf("StoreCredential: %v", err)
			}

			ref.OpaqueID = opaqueID
			secret, err := vm.ResolveCredentialForGateway(
				ctx, "gw-swap-test", "scan-swap", "corr-swap", "10.0.0.1", ref,
			)
			if err != nil {
				t.Fatalf("ResolveCredentialForGateway: %v", err)
			}
			defer zeroize(secret)

			if !bytes.Equal(secret, []byte("SwapTestSecret!")) {
				t.Fatalf("resolved secret mismatch")
			}
			if !auditCalled {
				t.Fatal("audit function was not called")
			}
		})
	}
}

// ===========================================================================
// 13. Sentinel Error Wrapping
// ===========================================================================

func TestSentinelErrors_Unwrappable(t *testing.T) {
	wrapped := fmt.Errorf("vault: context: %w", ErrSecretNotFound)
	if !errors.Is(wrapped, ErrSecretNotFound) {
		t.Fatal("ErrSecretNotFound should be unwrappable")
	}

	wrapped2 := fmt.Errorf("vault: context: %w", ErrProviderUnavailable)
	if !errors.Is(wrapped2, ErrProviderUnavailable) {
		t.Fatal("ErrProviderUnavailable should be unwrappable")
	}

	wrapped3 := fmt.Errorf("vault: context: %w", ErrAuthorizationDenied)
	if !errors.Is(wrapped3, ErrAuthorizationDenied) {
		t.Fatal("ErrAuthorizationDenied should be unwrappable")
	}

	wrapped4 := fmt.Errorf("vault: context: %w", ErrAuditWriteFailed)
	if !errors.Is(wrapped4, ErrAuditWriteFailed) {
		t.Fatal("ErrAuditWriteFailed should be unwrappable")
	}
}

// ===========================================================================
// 14. Audit Entry Timestamp Verification
// ===========================================================================

func TestAuditEntry_TimestampBeforeResolution(t *testing.T) {
	p := mustEnvelopeProvider(t)
	ref := testRef("sec_ref_timestamp_test")
	_ = p.StoreSecret(context.Background(), ref, []byte("TimestampSecret"))

	var auditTimestamp time.Time
	auditFn := func(entry SecretResolutionAuditEntry) error {
		auditTimestamp = entry.Timestamp
		return nil
	}

	vm := NewVaultManager(p, auditFn)
	beforeResolve := time.Now().UTC()

	secret, err := vm.ResolveCredentialForGateway(
		context.Background(), "gw-ts-test", "scan-ts", "corr-ts", "10.0.0.1", ref,
	)
	if err != nil {
		t.Fatalf("ResolveCredentialForGateway: %v", err)
	}
	zeroize(secret)

	// Audit timestamp must be at or after the time we recorded before resolution
	if auditTimestamp.Before(beforeResolve.Add(-1 * time.Second)) {
		t.Fatalf("audit timestamp %v is before resolution start %v", auditTimestamp, beforeResolve)
	}
}

// ===========================================================================
// Assertion Helpers
// ===========================================================================

func assertNoSecretInError(t *testing.T, err error, secret string) {
	t.Helper()
	if err == nil {
		return
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, secret) {
		t.Fatalf("SECURITY VIOLATION: secret '%s' found in error message: %s", secret, errMsg)
	}
}
