package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/auth"
	"github.com/go-chi/chi/v5"
)

func TestAuthHandlers_LoginMFAAndRefresh(t *testing.T) {
	authRepo := auth.NewMemoryAuthRepository()
	tokenService := auth.NewTokenService("test-secret-key-32b-long-secret-key!", "test-issuer")
	oidcService := auth.NewOIDCService(auth.OIDCConfig{})
	authHandler := NewAuthHandler(authRepo, tokenService, oidcService)

	// 1. Login with Break-Glass Credentials -> MFA challenge issued
	loginBody := bytes.NewBufferString(`{
		"username": "breakglass",
		"password": "EmergencyBreakGlassPass2026!"
	}`)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginBody)
	wLogin := httptest.NewRecorder()
	authHandler.Login(wLogin, reqLogin)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 for breakglass login, got %d: %s", wLogin.Code, wLogin.Body.String())
	}
	var loginResp struct {
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
	}
	_ = json.NewDecoder(wLogin.Body).Decode(&loginResp)
	if !loginResp.MFARequired || loginResp.MFAToken == "" {
		t.Fatalf("expected MFA token challenge, got: %+v", loginResp)
	}

	// 2. Generate valid TOTP code with breakglass secret "JBSWY3DPEHPK3PXP"
	code, _ := auth.GenerateTOTPCode("JBSWY3DPEHPK3PXP", time.Now().UTC())

	mfaBody := bytes.NewBufferString(`{
		"mfa_token": "` + loginResp.MFAToken + `",
		"totp_code": "` + code + `"
	}`)
	reqMFA := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", mfaBody)
	wMFA := httptest.NewRecorder()
	authHandler.VerifyMFA(wMFA, reqMFA)

	if wMFA.Code != http.StatusOK {
		t.Fatalf("expected 200 for MFA verify, got %d: %s", wMFA.Code, wMFA.Body.String())
	}
	var tokenPair auth.TokenPair
	_ = json.NewDecoder(wMFA.Body).Decode(&tokenPair)
	if tokenPair.AccessToken == "" || tokenPair.RefreshToken == "" {
		t.Fatalf("expected access & refresh token pair, got: %+v", tokenPair)
	}

	// 3. Refresh Session
	refreshBody := bytes.NewBufferString(`{"refresh_token": "` + tokenPair.RefreshToken + `"}`)
	reqRef := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", refreshBody)
	wRef := httptest.NewRecorder()
	authHandler.RefreshSession(wRef, reqRef)

	if wRef.Code != http.StatusOK {
		t.Fatalf("expected 200 for refresh, got %d: %s", wRef.Code, wRef.Body.String())
	}

	// 4. Step-Up Re-Authentication
	stepUpBody := bytes.NewBufferString(`{"totp_code": "` + code + `"}`)
	reqStepUp := httptest.NewRequest(http.MethodPost, "/api/v1/auth/step-up", stepUpBody)
	reqStepUp.Header.Set("Authorization", "Bearer "+tokenPair.AccessToken)

	// Wrap in Chi router with RequireAuth to test step-up handler
	r := chi.NewRouter()
	r.Use(auth.RequireAuth(tokenService))
	r.Post("/api/v1/auth/step-up", authHandler.StepUpAuth)

	wStepUp := httptest.NewRecorder()
	r.ServeHTTP(wStepUp, reqStepUp)
	if wStepUp.Code != http.StatusOK {
		t.Fatalf("expected 200 for step-up auth, got %d: %s", wStepUp.Code, wStepUp.Body.String())
	}

	// 5. SCIM 2.0 Provisioning & Deprovisioning
	scimUserBody := bytes.NewBufferString(`{
		"userName": "auditor@corp.local",
		"name": {"formatted": "Auditor User"},
		"emails": [{"value": "auditor@corp.local", "primary": true}],
		"roles": [{"value": "auditor", "primary": true}],
		"active": true
	}`)
	reqSCIM := httptest.NewRequest(http.MethodPost, "/api/v1/scim/v2/Users", scimUserBody)
	wSCIM := httptest.NewRecorder()
	authHandler.SCIMCreateUser(wSCIM, reqSCIM)

	if wSCIM.Code != http.StatusCreated {
		t.Fatalf("expected 201 for SCIM create user, got %d: %s", wSCIM.Code, wSCIM.Body.String())
	}
}
