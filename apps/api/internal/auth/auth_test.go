package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// Helper router for RBAC tests
func setupRBACTestRouter(tokenService *TokenService, authRepo AuthRepository) *chi.Mux {
	r := chi.NewRouter()
	r.Use(OptionalAuth(tokenService, "tenant-test"))
	r.Use(CSRFProtectionMiddleware())

	// Read Telemetry (All roles)
	r.With(RequirePermission(PermissionReadTelemetry)).Get("/test/telemetry", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access": "telemetry_granted"}`))
	})

	// Audit Logs (Auditor, Admin, SuperAdmin only)
	r.With(RequirePermission(PermissionReadAuditLogs)).Get("/test/audit-logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access": "audit_logs_granted"}`))
	})

	// Trigger Scan (Operator, Admin, SuperAdmin only)
	r.With(RequirePermission(PermissionTriggerScans)).Post("/test/scans", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"access": "scan_triggered"}`))
	})

	// Manage Credentials with Step-Up (Admin, SuperAdmin only)
	r.With(RequirePermission(PermissionManageCredentials), RequireStepUp()).Post("/test/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"access": "credential_created"}`))
	})

	// Manage Tenants (SuperAdmin only)
	r.With(RequirePermission(PermissionManageTenants)).Post("/test/tenants", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"access": "tenant_created"}`))
	})

	return r
}

// ---------------------------------------------------------------------------
// 1. RBAC Matrix & Negative 403 Forbidden Tests
// ---------------------------------------------------------------------------

func TestRBAC_FiveRolesBoundaryAndNegativeTests(t *testing.T) {
	tokenService := NewTokenService("test-secret-key-32b-long-secret-key!", "test-issuer")
	authRepo := NewMemoryAuthRepository()
	r := setupRBACTestRouter(tokenService, authRepo)

	// Generate tokens for each role
	makeToken := func(role Role, stepUpAge time.Duration) string {
		claims := UserClaims{
			TenantID:     "tenant-test",
			UserID:       "usr-" + string(role),
			Email:        string(role) + "@endpointguard.local",
			Role:         role,
			StepUpAuthAt: time.Now().UTC().Add(-stepUpAge).Unix(),
		}
		tok, _ := tokenService.GenerateToken(claims, 1*time.Hour)
		return "Bearer " + tok
	}

	tokenViewer := makeToken(RoleViewer, 0)
	tokenOperator := makeToken(RoleOperator, 0)
	tokenAuditor := makeToken(RoleAuditor, 0)
	tokenAdmin := makeToken(RoleAdmin, 0)
	tokenSuperAdmin := makeToken(RoleSuperAdmin, 0)

	// 1. VIEWER TESTS
	// Can read telemetry (200)
	req := httptest.NewRequest(http.MethodGet, "/test/telemetry", nil)
	req.Header.Set("Authorization", tokenViewer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("viewer should be able to read telemetry, got %d", w.Code)
	}

	// CANNOT trigger scan (403)
	req = httptest.NewRequest(http.MethodPost, "/test/scans", nil)
	req.Header.Set("Authorization", tokenViewer)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer attempting to trigger scan must receive 403 Forbidden, got %d", w.Code)
	}

	// CANNOT read audit logs (403)
	req = httptest.NewRequest(http.MethodGet, "/test/audit-logs", nil)
	req.Header.Set("Authorization", tokenViewer)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer attempting to read audit logs must receive 403 Forbidden, got %d", w.Code)
	}

	// 2. OPERATOR TESTS
	// Can trigger scan (201)
	req = httptest.NewRequest(http.MethodPost, "/test/scans", nil)
	req.Header.Set("Authorization", tokenOperator)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("operator should be able to trigger scan, got %d", w.Code)
	}

	// CANNOT read audit logs (403)
	req = httptest.NewRequest(http.MethodGet, "/test/audit-logs", nil)
	req.Header.Set("Authorization", tokenOperator)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("operator attempting to read audit logs must receive 403 Forbidden, got %d", w.Code)
	}

	// CANNOT manage credentials (403)
	req = httptest.NewRequest(http.MethodPost, "/test/credentials", nil)
	req.Header.Set("Authorization", tokenOperator)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("operator attempting to create credential must receive 403 Forbidden, got %d", w.Code)
	}

	// 3. AUDITOR TESTS
	// Can read audit logs (200)
	req = httptest.NewRequest(http.MethodGet, "/test/audit-logs", nil)
	req.Header.Set("Authorization", tokenAuditor)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("auditor should be able to read audit logs, got %d", w.Code)
	}

	// CANNOT trigger scan (403)
	req = httptest.NewRequest(http.MethodPost, "/test/scans", nil)
	req.Header.Set("Authorization", tokenAuditor)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("auditor attempting to trigger scan must receive 403 Forbidden, got %d", w.Code)
	}

	// 4. ADMIN TESTS
	// Can create credentials (201)
	req = httptest.NewRequest(http.MethodPost, "/test/credentials", nil)
	req.Header.Set("Authorization", tokenAdmin)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("admin with fresh step-up auth should be able to create credential, got %d", w.Code)
	}

	// CANNOT manage global tenants (403)
	req = httptest.NewRequest(http.MethodPost, "/test/tenants", nil)
	req.Header.Set("Authorization", tokenAdmin)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("admin attempting to manage tenants must receive 403 Forbidden, got %d", w.Code)
	}

	// 5. SUPERADMIN TESTS
	// Can manage tenants (201)
	req = httptest.NewRequest(http.MethodPost, "/test/tenants", nil)
	req.Header.Set("Authorization", tokenSuperAdmin)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("superadmin should be able to manage tenants, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// 2. 15-Minute Step-Up Re-Authentication Tests
// ---------------------------------------------------------------------------

func TestStepUpAuthentication_ValidityAndExpiry(t *testing.T) {
	tokenService := NewTokenService("test-secret-key-32b-long-secret-key!", "test-issuer")
	authRepo := NewMemoryAuthRepository()
	r := setupRBACTestRouter(tokenService, authRepo)

	// 1. Fresh step-up auth (5 mins ago) -> SUCCEEDS (201)
	claimsFresh := UserClaims{
		TenantID:     "tenant-test",
		UserID:       "usr-admin",
		Role:         RoleAdmin,
		StepUpAuthAt: time.Now().UTC().Add(-5 * time.Minute).Unix(),
	}
	tokFresh, _ := tokenService.GenerateToken(claimsFresh, 1*time.Hour)

	reqFresh := httptest.NewRequest(http.MethodPost, "/test/credentials", nil)
	reqFresh.Header.Set("Authorization", "Bearer "+tokFresh)
	wFresh := httptest.NewRecorder()
	r.ServeHTTP(wFresh, reqFresh)
	if wFresh.Code != http.StatusCreated {
		t.Errorf("fresh step-up (<15m) expected 201 Created, got %d", wFresh.Code)
	}

	// 2. Stale step-up auth (20 mins ago) -> FAILS (403 STEP_UP_AUTH_REQUIRED)
	claimsStale := UserClaims{
		TenantID:     "tenant-test",
		UserID:       "usr-admin",
		Role:         RoleAdmin,
		StepUpAuthAt: time.Now().UTC().Add(-20 * time.Minute).Unix(),
	}
	tokStale, _ := tokenService.GenerateToken(claimsStale, 1*time.Hour)

	reqStale := httptest.NewRequest(http.MethodPost, "/test/credentials", nil)
	reqStale.Header.Set("Authorization", "Bearer "+tokStale)
	wStale := httptest.NewRecorder()
	r.ServeHTTP(wStale, reqStale)
	if wStale.Code != http.StatusForbidden {
		t.Errorf("stale step-up (>15m) expected 403 Forbidden, got %d", wStale.Code)
	}
}

// ---------------------------------------------------------------------------
// 3. Break-Glass Password + TOTP MFA Tests
// ---------------------------------------------------------------------------

func TestTOTP_BreakGlassMFALifecycle(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret failed: %v", err)
	}

	now := time.Now().UTC()
	code, err := GenerateTOTPCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateTOTPCode failed: %v", err)
	}

	// 1. Verify valid code
	if !ValidateTOTPCode(secret, code, now, 1) {
		t.Errorf("TOTP validation failed for valid code: %s", code)
	}

	// 2. Verify invalid code fails
	if ValidateTOTPCode(secret, "000000", now, 1) && code != "000000" {
		t.Errorf("TOTP validation must fail for incorrect code")
	}

	// 3. Verify clock skew handling (within ±30s step)
	pastTime := now.Add(25 * time.Second)
	if !ValidateTOTPCode(secret, code, pastTime, 1) {
		t.Errorf("TOTP validation should accept clock skew within step window")
	}
}

// ---------------------------------------------------------------------------
// 4. Refresh Token Rotation & Replay Attack Detection
// ---------------------------------------------------------------------------

func TestSessionManager_RefreshTokenRotationAndReplay(t *testing.T) {
	tokenService := NewTokenService("test-secret-key-32b-long-secret-key!", "test-issuer")
	authRepo := NewMemoryAuthRepository()
	sessionMgr := NewSessionManager(tokenService, authRepo)

	user := User{
		ID:       "usr-rot-01",
		TenantID: "tenant-test",
		Username: "alice",
		Email:    "alice@corp.com",
		Role:     RoleOperator,
		IsActive: true,
	}
	_ = authRepo.SaveUser(user)

	// 1. Issue initial TokenPair
	pair1, err := sessionMgr.IssueTokenPair(user, "", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("IssueTokenPair failed: %v", err)
	}

	// 2. Refresh Token -> returns new pair with rotated token
	pair2, err := sessionMgr.RefreshToken(pair1.RefreshToken, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}
	if pair2.RefreshToken == pair1.RefreshToken {
		t.Errorf("Refresh token must be rotated to a new token string")
	}

	// 3. Replay attack: attempt to reuse pair1.RefreshToken -> must fail and invalidate family
	_, errReplay := sessionMgr.RefreshToken(pair1.RefreshToken, "127.0.0.1", "AttackerAgent")
	if errReplay == nil {
		t.Errorf("Replayed refresh token must be rejected")
	}

	// 4. Verify that pair2 is now also invalidated due to family termination
	_, errPair2 := sessionMgr.RefreshToken(pair2.RefreshToken, "127.0.0.1", "TestAgent")
	if errPair2 == nil {
		t.Errorf("Token family should be terminated after replay attack detection")
	}
}

// ---------------------------------------------------------------------------
// 5. CSRF Protection Middleware Tests
// ---------------------------------------------------------------------------

func TestCSRFProtection_DoubleSubmitCookie(t *testing.T) {
	tokenService := NewTokenService("test-secret-key-32b-long-secret-key!", "test-issuer")
	authRepo := NewMemoryAuthRepository()
	r := setupRBACTestRouter(tokenService, authRepo)

	claims := UserClaims{TenantID: "tenant-test", UserID: "u1", Role: RoleSuperAdmin}
	tok, _ := tokenService.GenerateToken(claims, 1*time.Hour)
	authHeader := "Bearer " + tok
	csrfToken := GenerateCSRFToken()

	// 1. Mutating request with matching CSRF cookie & header -> SUCCEEDS (201)
	reqValid := httptest.NewRequest(http.MethodPost, "/test/tenants", nil)
	reqValid.Header.Set("Authorization", authHeader)
	reqValid.Header.Set("X-CSRF-Token", csrfToken)
	reqValid.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	wValid := httptest.NewRecorder()
	r.ServeHTTP(wValid, reqValid)
	if wValid.Code != http.StatusCreated {
		t.Errorf("valid CSRF token expected 201 Created, got %d", wValid.Code)
	}

	// 2. Mutating request with CSRF cookie but mismatched header -> FAILS (403)
	reqInvalid := httptest.NewRequest(http.MethodPost, "/test/tenants", nil)
	reqInvalid.Header.Set("Authorization", authHeader)
	reqInvalid.Header.Set("X-CSRF-Token", "mismatched-csrf-token")
	reqInvalid.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	wInvalid := httptest.NewRecorder()
	r.ServeHTTP(wInvalid, reqInvalid)
	if wInvalid.Code != http.StatusForbidden {
		t.Errorf("mismatched CSRF token expected 403 Forbidden, got %d", wInvalid.Code)
	}
}

// ---------------------------------------------------------------------------
// 6. OIDC Group Mapping & Auth URL Tests
// ---------------------------------------------------------------------------

func TestOIDC_GroupMappingAndAuthURL(t *testing.T) {
	oidc := NewOIDCService(OIDCConfig{
		IssuerURL:   "https://login.microsoftonline.com/common/v2.0",
		ClientID:    "test-client-id",
		RedirectURI: "https://endpointguard.local/api/v1/auth/oidc/callback",
		GroupRoleMap: map[string]Role{
			"SecOps-Admins":    RoleAdmin,
			"Security-Auditor": RoleAuditor,
		},
	})

	// 1. Test Auth URL contains PKCE and client_id
	authURL, state, verifier, err := oidc.BuildAuthURL()
	if err != nil || authURL == "" || state == "" || verifier == "" {
		t.Fatalf("BuildAuthURL failed: %v", err)
	}

	// 2. Test group-to-role resolution
	role := oidc.MapGroupsToRole([]string{"General-Users", "SecOps-Admins"})
	if role != RoleAdmin {
		t.Errorf("expected RoleAdmin from SecOps-Admins group, got %s", role)
	}

	// 3. Test mock ID token decoding
	mockJSON := `{"sub":"oidc-sub-001","email":"ciso@corp.com","name":"Corporate CISO","groups":["SecOps-Admins"]}`
	user, err := oidc.ProcessMockIDToken(mockJSON)
	if err != nil || user.Role != RoleAdmin || user.Email != "ciso@corp.com" {
		t.Errorf("unexpected ProcessMockIDToken result: %+v, err: %v", user, err)
	}
}

// ---------------------------------------------------------------------------
// 7. SCIM 2.0 User Provisioning & Deprovisioning Tests
// ---------------------------------------------------------------------------

func TestSCIM2_UserProvisioningLifecycle(t *testing.T) {
	authRepo := NewMemoryAuthRepository()
	scimService := NewSCIMService(authRepo)
	tenantID := "tenant-scim-test"

	// 1. Provision User
	scimReq := SCIMUser{
		UserName: "john.doe@corp.local",
		Name:     SCIMName{Formatted: "John Doe"},
		Emails:   []SCIMEmail{{Value: "john.doe@corp.local", Type: "work", Primary: true}},
		Roles:    []SCIMRole{{Value: "operator", Primary: true}},
		Active:   true,
	}

	created, err := scimService.ProvisionUser(tenantID, scimReq)
	if err != nil {
		t.Fatalf("SCIM ProvisionUser failed: %v", err)
	}
	if created.ID == "" || !created.Active {
		t.Errorf("unexpected SCIM created user: %+v", created)
	}

	// 2. Get SCIM User
	retrieved, err := scimService.GetSCIMUser(tenantID, created.ID)
	if err != nil || retrieved.UserName != "john.doe@corp.local" {
		t.Errorf("SCIM GetSCIMUser failed: %v", err)
	}

	// 3. List SCIM Users
	list, err := scimService.ListSCIMUsers(tenantID)
	if err != nil || list.TotalResults != 1 {
		t.Errorf("SCIM ListSCIMUsers failed: %v", err)
	}

	// 4. Deprovision User
	if err := scimService.DeprovisionUser(tenantID, created.ID); err != nil {
		t.Fatalf("SCIM DeprovisionUser failed: %v", err)
	}

	deprovUser, _ := scimService.GetSCIMUser(tenantID, created.ID)
	if deprovUser.Active {
		t.Errorf("deprovisioned SCIM user must have Active = false")
	}
}

