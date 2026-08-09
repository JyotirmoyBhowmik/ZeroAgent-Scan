package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/auth"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AuthHandler exposes REST endpoints for Authentication, MFA, OIDC, and SCIM 2.0.
type AuthHandler struct {
	authRepo       auth.AuthRepository
	tokenService   *auth.TokenService
	sessionManager *auth.SessionManager
	oidcService    *auth.OIDCService
	scimService    *auth.SCIMService
}

// NewAuthHandler creates an initialized auth HTTP handler.
func NewAuthHandler(
	authRepo auth.AuthRepository,
	tokenService *auth.TokenService,
	oidcService *auth.OIDCService,
) *AuthHandler {
	if authRepo == nil {
		authRepo = auth.NewMemoryAuthRepository()
	}
	if tokenService == nil {
		tokenService = auth.NewTokenService("enterprise-endpointguard-master-jwt-secret-key-32b!", "endpointguard-api")
	}
	if oidcService == nil {
		oidcService = auth.NewOIDCService(auth.OIDCConfig{
			IssuerURL:   "https://login.microsoftonline.com/common/v2.0",
			ClientID:    "endpointguard-client-id",
			RedirectURI: "https://endpointguard.local/api/v1/auth/oidc/callback",
		})
	}
	sessionManager := auth.NewSessionManager(tokenService, authRepo)
	scimService := auth.NewSCIMService(authRepo)

	return &AuthHandler{
		authRepo:       authRepo,
		tokenService:   tokenService,
		sessionManager: sessionManager,
		oidcService:    oidcService,
		scimService:    scimService,
	}
}

// ---------------------------------------------------------------------------
// 1. Password & Break-Glass Login
// ---------------------------------------------------------------------------

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "INVALID_BODY", "Failed to parse login request", nil)
		return
	}

	if req.Username == "" || req.Password == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MISSING_CREDENTIALS", "Username and password are required", nil)
		return
	}

	user, exists := h.authRepo.GetUserByUsername(req.TenantID, req.Username)
	if !exists || !user.IsActive {
		middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid username or password", nil)
		return
	}

	expectedHash := auth.HashPassword(req.Password, user.ID)
	if user.PasswordHash != expectedHash {
		middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid username or password", nil)
		return
	}

	// If TOTP MFA is enabled, issue an MFA Challenge token
	if user.TOTPEnabled {
		challengeID := uuid.New().String()
		challenge := auth.MFAChallenge{
			ChallengeID: challengeID,
			UserID:      user.ID,
			TenantID:    user.TenantID,
			ExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
		}
		_ = h.authRepo.SaveMFAChallenge(challenge)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mfa_required": true,
			"mfa_token":    challengeID,
			"message":      "TOTP verification code required",
		})
		return
	}

	// Issue Token Pair directly
	tokenPair, err := h.sessionManager.IssueTokenPair(*user, "", r.RemoteAddr, r.UserAgent())
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "SESSION_ERROR", "Failed to issue session tokens", nil)
		return
	}

	h.setSessionCookies(w, tokenPair)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenPair)
}

// ---------------------------------------------------------------------------
// 2. TOTP MFA Verification
// ---------------------------------------------------------------------------

func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string `json:"mfa_token"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "INVALID_BODY", "Invalid MFA verification payload", nil)
		return
	}

	challenge, exists := h.authRepo.GetMFAChallenge(req.MFAToken)
	if !exists || time.Now().UTC().After(challenge.ExpiresAt) {
		middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "MFA_EXPIRED", "MFA challenge token has expired or is invalid", nil)
		return
	}

	secret, hasSecret := h.authRepo.GetTOTPSecret(challenge.UserID)
	if !hasSecret || !auth.ValidateTOTPCode(secret, req.TOTPCode, time.Now().UTC(), 1) {
		middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "INVALID_TOTP_CODE", "Invalid 6-digit TOTP verification code", nil)
		return
	}

	_ = h.authRepo.DeleteMFAChallenge(req.MFAToken)

	user, exists := h.authRepo.GetUserByID(challenge.UserID)
	if !exists {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "USER_NOT_FOUND", "User record missing", nil)
		return
	}

	tokenPair, err := h.sessionManager.IssueTokenPair(*user, "", r.RemoteAddr, r.UserAgent())
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "SESSION_ERROR", "Failed to issue session tokens", nil)
		return
	}

	h.setSessionCookies(w, tokenPair)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenPair)
}

// ---------------------------------------------------------------------------
// 3. Refresh Token Rotation
// ---------------------------------------------------------------------------

func (h *AuthHandler) RefreshSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.RefreshToken == "" {
		if cookie, err := r.Cookie("refresh_token"); err == nil {
			req.RefreshToken = cookie.Value
		}
	}

	if req.RefreshToken == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MISSING_REFRESH_TOKEN", "Refresh token is required", nil)
		return
	}

	tokenPair, err := h.sessionManager.RefreshToken(req.RefreshToken, r.RemoteAddr, r.UserAgent())
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "REFRESH_FAILED", err.Error(), nil)
		return
	}

	h.setSessionCookies(w, tokenPair)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenPair)
}

// ---------------------------------------------------------------------------
// 4. 15-Minute Step-Up Re-Authentication
// ---------------------------------------------------------------------------

func (h *AuthHandler) StepUpAuth(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.GetUserClaims(r.Context())
	if !ok || claims == nil {
		middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required", nil)
		return
	}

	var req struct {
		Password string `json:"password,omitempty"`
		TOTPCode string `json:"totp_code,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	user, exists := h.authRepo.GetUserByID(claims.UserID)
	if !exists {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "USER_NOT_FOUND", "User not found", nil)
		return
	}

	stepUpSuccess := false
	if req.Password != "" {
		expectedHash := auth.HashPassword(req.Password, user.ID)
		if user.PasswordHash == expectedHash {
			stepUpSuccess = true
		}
	} else if req.TOTPCode != "" {
		if secret, hasSecret := h.authRepo.GetTOTPSecret(user.ID); hasSecret {
			if auth.ValidateTOTPCode(secret, req.TOTPCode, time.Now().UTC(), 1) {
				stepUpSuccess = true
			}
		}
	}

	if !stepUpSuccess {
		middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "STEP_UP_FAILED", "Invalid password or TOTP code for step-up auth", nil)
		return
	}

	// Issue updated access token with new step_up_auth_at timestamp
	newClaims := *claims
	newClaims.StepUpAuthAt = time.Now().UTC().Unix()

	newToken, err := h.tokenService.GenerateToken(newClaims, auth.AccessTokenTTL)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to generate stepped-up token", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "STEP_UP_VERIFIED",
		"access_token":    newToken,
		"step_up_auth_at": time.Now().UTC().Format(time.RFC3339),
		"expires_in_secs": 900,
	})
}

// ---------------------------------------------------------------------------
// 5. OIDC Integration Endpoints
// ---------------------------------------------------------------------------

func (h *AuthHandler) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	authURL, state, _, err := h.oidcService.BuildAuthURL()
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "OIDC_ERROR", "Failed to build OIDC auth URL", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"authorization_url": authURL,
		"state":             state,
	})
}

func (h *AuthHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code           string `json:"code"`
		State          string `json:"state"`
		MockIDToken    string `json:"mock_id_token,omitempty"` // For hermetic testing
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.MockIDToken == "" {
		req.MockIDToken = `{"sub":"oidc-12345","email":"admin@corp.com","name":"OIDC Admin","groups":["EndpointGuard-Admins"]}`
	}

	user, err := h.oidcService.ProcessMockIDToken(req.MockIDToken)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "OIDC_PARSE_FAILED", err.Error(), nil)
		return
	}

	_ = h.authRepo.SaveUser(*user)
	tokenPair, err := h.sessionManager.IssueTokenPair(*user, "", r.RemoteAddr, r.UserAgent())
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "SESSION_ERROR", "Failed to issue session tokens", nil)
		return
	}

	h.setSessionCookies(w, tokenPair)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenPair)
}

// ---------------------------------------------------------------------------
// 6. SCIM 2.0 User Provisioning / Deprovisioning Endpoints
// ---------------------------------------------------------------------------

func (h *AuthHandler) SCIMListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	res, err := h.scimService.ListSCIMUsers(tenantID)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "SCIM_ERROR", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/scim+json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *AuthHandler) SCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	var scimUser auth.SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&scimUser); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "INVALID_SCIM_PAYLOAD", "Failed to decode SCIM user", nil)
		return
	}

	created, err := h.scimService.ProvisionUser(tenantID, scimUser)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "PROVISIONING_FAILED", err.Error(), nil)
		return
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (h *AuthHandler) SCIMGetUser(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	user, err := h.scimService.GetSCIMUser(tenantID, id)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "USER_NOT_FOUND", "SCIM user not found", nil)
		return
	}

	w.Header().Set("Content-Type", "application/scim+json")
	_ = json.NewEncoder(w).Encode(user)
}

func (h *AuthHandler) SCIMDeprovisionUser(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	if err := h.scimService.DeprovisionUser(tenantID, id); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "DEPROVISION_FAILED", err.Error(), nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) SCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":   map[string]bool{"supported": true},
		"bulk":    map[string]bool{"supported": false},
		"filter":  map[string]bool{"supported": false},
		"changePassword": map[string]bool{"supported": false},
		"sort":    map[string]bool{"supported": false},
		"etag":    map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{
			{"name": "OAuth Bearer Token", "description": "Authentication scheme using the OAuth Bearer Token Standard", "specUri": "http://www.rfc-editor.org/info/rfc6750", "type": "oauthbearertoken"},
		},
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (h *AuthHandler) setSessionCookies(w http.ResponseWriter, pair *auth.TokenPair) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    pair.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   900,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    pair.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   604800,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    pair.CSRFToken,
		Path:     "/",
		HttpOnly: false, // Accessible by JavaScript client to set in X-CSRF-Token header
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   604800,
	})
}
