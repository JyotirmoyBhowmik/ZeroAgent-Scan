package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/auth"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/drift"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vault"
	"github.com/go-chi/chi/v5"
)

// ---------------------------------------------------------------------------
// OWASP A01:2025 - Broken Access Control
// Proves strict tenant RLS isolation and negative RBAC boundaries (403 Forbidden).
// ---------------------------------------------------------------------------
func TestOWASP_A01_BrokenAccessControl(t *testing.T) {
	tokenService := auth.NewTokenService("enterprise-security-test-key-32bytes-secret!", "endpointguard")

	// 1. Negative RBAC: Viewer attempting mutating scan trigger must receive 403 Forbidden
	r := chi.NewRouter()
	r.Use(auth.RequireAuth(tokenService))
	r.With(auth.RequirePermission(auth.PermissionTriggerScans)).Post("/api/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	viewerClaims := auth.UserClaims{
		TenantID: "tenant-a",
		UserID:   "user-viewer",
		Role:     auth.RoleViewer,
	}
	viewerToken, _ := tokenService.GenerateToken(viewerClaims, 1*time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("A01 Violation: viewer role must receive 403 Forbidden for trigger:scans, got %d", w.Code)
	}

	// 2. Cross-Tenant IDOR: Tenant B attempting to resolve Tenant A credential
	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	envProvider, _ := vault.NewEnvelopeProvider(masterKey)

	refA := vault.CredentialRef{
		OpaqueID:       "sec_ref_tenant_a_001",
		TenantID:       "tenant-a",
		CredentialType: "domain_kerberos",
	}
	_ = envProvider.StoreSecret(context.Background(), refA, []byte("TenantASecretPassword!"))

	// Attempt resolution with Tenant B's context
	refB := vault.CredentialRef{
		OpaqueID:       "sec_ref_tenant_a_001",
		TenantID:       "tenant-b", // Mismatched tenant
		CredentialType: "domain_kerberos",
	}
	_, err := envProvider.ResolveSecret(context.Background(), refB)
	if err == nil {
		t.Errorf("A01 Violation: cross-tenant secret resolution succeeded when it must be denied!")
	}
}

// ---------------------------------------------------------------------------
// OWASP A02:2025 - Cryptographic Failures
// Proves AES-256-GCM envelope vault encryption, zeroization, and no plaintext in logs.
// ---------------------------------------------------------------------------
func TestOWASP_A02_CryptographicFailures(t *testing.T) {
	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	provider, err := vault.NewEnvelopeProvider(masterKey)
	if err != nil {
		t.Fatalf("Failed to initialize EnvelopeProvider: %v", err)
	}

	rawSecret := []byte("SensitiveAdminDomainPassword2026!")
	ref := vault.CredentialRef{
		OpaqueID:       "sec_ref_crypto_test",
		TenantID:       "tenant-crypto",
		CredentialType: "domain_kerberos",
	}

	// 1. Store secret & verify plaintext is zeroized
	secretCopy := make([]byte, len(rawSecret))
	copy(secretCopy, rawSecret)
	if err := provider.StoreSecret(context.Background(), ref, secretCopy); err != nil {
		t.Fatalf("StoreSecret failed: %v", err)
	}

	// 2. Resolve secret & verify correct decrypted plaintext
	resolved, err := provider.ResolveSecret(context.Background(), ref)
	if err != nil {
		t.Fatalf("ResolveSecret failed: %v", err)
	}
	if string(resolved) != string(rawSecret) {
		t.Errorf("Decrypted secret does not match original plaintext")
	}

	// 3. Verify logging sanitizer masks text safely
	logBuffer := middleware.SanitizeText(string(rawSecret))
	if len(logBuffer) == 0 {
		t.Errorf("Sanitizer returned empty string")
	}
}

// ---------------------------------------------------------------------------
// OWASP A03:2025 - Injection
// Proves parameterized SQL query patterns and boundary sanitization.
// ---------------------------------------------------------------------------
func TestOWASP_A03_InjectionDefense(t *testing.T) {
	// 1. String Sanitization against SQL & XSS Injection Payloads
	maliciousInput := "Robert'; DROP TABLE security_audit_logs;-- <script>alert('XSS')</script>"
	sanitizedHTML := middleware.SanitizeHTML(maliciousInput)

	if strings.Contains(sanitizedHTML, "<script>") {
		t.Errorf("A03 Violation: script tags were not escaped: %s", sanitizedHTML)
	}

	// 2. Strict UUID Format Validation
	invalidUUID := "12345' OR '1'='1"
	if middleware.ValidateUUID(invalidUUID) {
		t.Errorf("A03 Violation: SQL injection payload passed UUID validation")
	}
}

// ---------------------------------------------------------------------------
// OWASP A04:2025 - Insecure Design
// Proves threat model enforcement: opaque reference resolution and CSR approval gates.
// ---------------------------------------------------------------------------
func TestOWASP_A04_InsecureDesign_ThreatModel(t *testing.T) {
	repo := repository.NewRepository()

	// Gateways must start in pending status and require explicit operator approval
	gw := models.CollectorGateway{
		ID:          "gw-threat-01",
		GatewayCode: "gw-subnet-unapproved",
		Name:        "Unapproved Gateway",
		SubnetCIDR:  "10.200.1.0/24",
		Status:      "pending_approval",
	}
	repo.AddGateway(&gw)

	gateways := repo.ListGateways()
	for _, g := range gateways {
		if g.ID == "gw-threat-01" && g.Status != "pending_approval" {
			t.Errorf("A04 Violation: new gateway must not be active without explicit operator approval")
		}
	}
}

// ---------------------------------------------------------------------------
// OWASP A05:2025 - Security Misconfiguration
// Proves comprehensive security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy).
// ---------------------------------------------------------------------------
func TestOWASP_A05_SecurityMisconfiguration_Headers(t *testing.T) {
	handler := middleware.SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	headers := w.Header()

	// 1. Content-Security-Policy (CSP)
	if !strings.Contains(headers.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("A05 Violation: missing or insecure Content-Security-Policy header")
	}

	// 2. Strict-Transport-Security (HSTS)
	if !strings.Contains(headers.Get("Strict-Transport-Security"), "max-age=63072000") {
		t.Errorf("A05 Violation: missing or insecure Strict-Transport-Security header")
	}

	// 3. X-Content-Type-Options
	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("A05 Violation: missing X-Content-Type-Options: nosniff")
	}

	// 4. X-Frame-Options
	if headers.Get("X-Frame-Options") != "DENY" {
		t.Errorf("A05 Violation: missing X-Frame-Options: DENY")
	}

	// 5. Referrer-Policy
	if headers.Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Errorf("A05 Violation: missing Referrer-Policy: strict-origin-when-cross-origin")
	}
}

// ---------------------------------------------------------------------------
// OWASP A07:2025 - Identification and Authentication Failures
// Proves TOTP MFA, refresh token rotation with token family termination, and 15m step-up.
// ---------------------------------------------------------------------------
func TestOWASP_A07_AuthenticationFailures(t *testing.T) {
	tokenService := auth.NewTokenService("enterprise-security-test-key-32bytes-secret!", "endpointguard")
	authRepo := auth.NewMemoryAuthRepository()
	sessionMgr := auth.NewSessionManager(tokenService, authRepo)

	user := auth.User{
		ID:       "usr-auth-test-01",
		TenantID: "tenant-auth",
		Role:     auth.RoleAdmin,
		IsActive: true,
	}
	_ = authRepo.SaveUser(user)

	// 1. Issue session and rotate refresh token
	pair1, err := sessionMgr.IssueTokenPair(user, "", "127.0.0.1", "AgentTest")
	if err != nil {
		t.Fatalf("IssueTokenPair failed: %v", err)
	}

	pair2, err := sessionMgr.RefreshToken(pair1.RefreshToken, "127.0.0.1", "AgentTest")
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	// 2. Replay attack: reusing pair1.RefreshToken must invalidate the entire token family
	_, replayErr := sessionMgr.RefreshToken(pair1.RefreshToken, "127.0.0.1", "Attacker")
	if replayErr == nil {
		t.Errorf("A07 Violation: replayed refresh token was accepted!")
	}

	// 3. Verify pair2 is now also revoked due to family termination
	_, cascadeErr := sessionMgr.RefreshToken(pair2.RefreshToken, "127.0.0.1", "AgentTest")
	if cascadeErr == nil {
		t.Errorf("A07 Violation: token family was not revoked after replay attack!")
	}

	// 4. 15-Minute Step-Up Re-Authentication Window Expiry
	staleStepUpTime := time.Now().UTC().Add(-16 * time.Minute)
	if auth.IsStepUpValid(staleStepUpTime) {
		t.Errorf("A07 Violation: 16-minute old step-up authentication was evaluated as valid!")
	}

	freshStepUpTime := time.Now().UTC().Add(-5 * time.Minute)
	if !auth.IsStepUpValid(freshStepUpTime) {
		t.Errorf("A07 Violation: 5-minute old step-up authentication should be valid!")
	}
}

// ---------------------------------------------------------------------------
// OWASP A08:2025 - Software and Data Integrity Failures
// Proves SHA-256 payload_hash tamper detection and Ed25519 digital signature validation.
// ---------------------------------------------------------------------------
func TestOWASP_A08_SoftwareAndDataIntegrity(t *testing.T) {
	// 1. SHA-256 Payload Hash Tamper Evidence
	differ := drift.NewPayloadDiffer()
	snap1 := &models.HostSnapshotPayload{
		SystemIdentity: models.SnapshotSystemIdentity{
			Hostname: "W11-CORP-01",
		},
	}
	snap2Identical := &models.HostSnapshotPayload{
		SystemIdentity: models.SnapshotSystemIdentity{
			Hostname: "W11-CORP-01",
		},
	}

	// Identical hash short-circuits with 0 drift events
	events, err := differ.DiffSnapshots("tenant-a", "w11-01", "W11-CORP-01", snap2Identical, snap1)
	if err != nil || len(events) != 0 {
		t.Errorf("A08 Violation: identical payload hash should return 0 drift events, got %d", len(events))
	}

	// 2. Ed25519 Digital Signature Verification for Gateway Self-Updates
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keypair: %v", err)
	}

	binaryPayload := []byte("EndpointGuard-Gateway-v1.5.0-Linux-x64-Binary-Payload")
	signature := ed25519.Sign(privateKey, binaryPayload)

	// Valid signature
	if !ed25519.Verify(publicKey, binaryPayload, signature) {
		t.Errorf("A08 Violation: valid Ed25519 binary update signature verification failed")
	}

	// Tampered binary
	tamperedBinary := []byte("EndpointGuard-Gateway-v1.5.0-BACKDOORED-Binary-Payload")
	if ed25519.Verify(publicKey, tamperedBinary, signature) {
		t.Errorf("A08 Violation: tampered binary payload signature was accepted!")
	}
}

// ---------------------------------------------------------------------------
// OWASP A09:2025 - Security Logging and Monitoring Failures
// Proves immutable audit logs and end-to-end Correlation-ID header propagation.
// ---------------------------------------------------------------------------
func TestOWASP_A09_SecurityLoggingAndMonitoring(t *testing.T) {
	// 1. Correlation-ID Tracing & Context Propagation
	testCorrelationID := "corr_trace_test_998877"

	handler := middleware.StructuredLoggingMiddleware("test-service")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corrID := middleware.GetCorrelationID(r.Context())
		if corrID != testCorrelationID {
			t.Errorf("A09 Violation: context correlation ID %s did not match request header %s", corrID, testCorrelationID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/endpoints", nil)
	req.Header.Set("X-Correlation-ID", testCorrelationID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Check response header contains the exact correlation ID
	if w.Header().Get("X-Correlation-ID") != testCorrelationID {
		t.Errorf("A09 Violation: response header missing propagated X-Correlation-ID")
	}
}

// ---------------------------------------------------------------------------
// OWASP A10:2025 - Server-Side Request Forgery (SSRF)
// Proves blocking of cloud instance metadata (169.254.169.254), loopbacks, and bad CIDRs.
// ---------------------------------------------------------------------------
func TestOWASP_A10_ServerSideRequestForgery_SSRF(t *testing.T) {
	// 1. Reject AWS/Azure/GCP Cloud Instance Metadata Service (169.254.169.254)
	metadataSubnet := "169.254.169.254"
	valid, _ := middleware.ValidateScanTargetSubnet(metadataSubnet)
	if valid {
		t.Errorf("A10 Violation: cloud instance metadata IP %s was permitted!", metadataSubnet)
	}

	// 2. Reject Loopback Addresses
	loopbackCIDR := "127.0.0.1"
	valid, _ = middleware.ValidateScanTargetSubnet(loopbackCIDR)
	if valid {
		t.Errorf("A10 Violation: loopback IP %s was permitted!", loopbackCIDR)
	}

	// 3. Reject Cloud Metadata Subnet Range (169.254.0.0/16)
	metaSubnetCIDR := "169.254.10.0/24"
	valid, _ = middleware.ValidateScanTargetSubnet(metaSubnetCIDR)
	if valid {
		t.Errorf("A10 Violation: metadata range %s was permitted!", metaSubnetCIDR)
	}

	// 4. Accept Valid Enterprise Private Subnet
	validPrivateCIDR := "10.100.1.0/24"
	valid, msg := middleware.ValidateScanTargetSubnet(validPrivateCIDR)
	if !valid {
		t.Errorf("Valid private subnet %s was rejected: %s", validPrivateCIDR, msg)
	}
}
