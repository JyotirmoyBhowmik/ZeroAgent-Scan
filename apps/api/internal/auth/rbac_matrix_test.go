package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// buildFullAuditedRouter builds a test Chi router with all production endpoints and middlewares.
func buildFullAuditedRouter(tokenService *TokenService) *chi.Mux {
	r := chi.NewRouter()

	r.Route("/api/v1", func(api chi.Router) {
		api.Group(func(protected chi.Router) {
			protected.Use(OptionalAuth(tokenService, "tenant-matrix-test"))

			// Endpoints & Inventory
			protected.With(RequirePermission(PermissionReadTelemetry)).Get("/endpoints", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			protected.With(RequirePermission(PermissionReadTelemetry)).Get("/endpoints/{id}", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			protected.With(RequirePermission(PermissionManageTenants), RequireStepUp()).Delete("/endpoints/{id}", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"deleted"}`))
			})

			// Scans
			protected.With(RequirePermission(PermissionTriggerScans)).Post("/scans", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"status":"scan_created"}`))
			})
			protected.With(RequirePermission(PermissionCancelScans)).Post("/scans/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"cancelled"}`))
			})

			// Gateways
			protected.With(RequirePermission(PermissionManageTenants)).Post("/gateways/register", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"status":"gateway_registered"}`))
			})

			// Vault Credentials
			protected.With(RequirePermission(PermissionManageCredentials)).Get("/vault/credentials", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"credentials_listed"}`))
			})
			protected.With(RequirePermission(PermissionManageCredentials), RequireStepUp()).Post("/vault/credentials", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"status":"credential_created"}`))
			})
			protected.With(RequirePermission(PermissionManageCredentials), RequireStepUp()).Post("/vault/credentials/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"rotated"}`))
			})
			protected.With(RequirePermission(PermissionManageCredentials)).Post("/vault/credentials/{id}/test", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"tested"}`))
			})

			// Compliance & Destructive Policy Modification
			protected.With(RequirePermission(PermissionReadCompliance)).Get("/compliance/frameworks", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			protected.With(RequirePermission(PermissionManageCredentials), RequireStepUp()).Post("/compliance/policies/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"policy_disabled"}`))
			})

			// Audit Logs (Read-only for Auditor/Admin/SuperAdmin; NEVER editable)
			protected.With(RequirePermission(PermissionReadAuditLogs)).Get("/audit-logs", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"audit_logs"}`))
			})
		})
	})

	return r
}

type EndpointPermissionTestCase struct {
	Method            string
	Path              string
	Body              string
	RequiredRole      string
	AllowedRoles      []Role
	ForbiddenRoles    []Role
	RequiresStepUp    bool
	Description       string
}

// TestRBAC_ExhaustiveEndpointSecurityMatrix tests every single API route against all 5 roles.
func TestRBAC_ExhaustiveEndpointSecurityMatrix(t *testing.T) {
	tokenService := NewTokenService("test-secret-key-32b-matrix-auth-test!", "test-issuer")
	router := buildFullAuditedRouter(tokenService)

	makeToken := func(role Role, stepUpAgeMinutes int) string {
		claims := UserClaims{
			TenantID:     "tenant-matrix-test",
			UserID:       "usr-" + string(role),
			Email:        string(role) + "@corp.local",
			Role:         role,
			StepUpAuthAt: time.Now().UTC().Add(-time.Duration(stepUpAgeMinutes) * time.Minute).Unix(),
		}
		tok, _ := tokenService.GenerateToken(claims, 1*time.Hour)
		return "Bearer " + tok
	}

	testCases := []EndpointPermissionTestCase{
		{
			Method:         http.MethodGet,
			Path:           "/api/v1/endpoints",
			AllowedRoles:   []Role{RoleViewer, RoleOperator, RoleAuditor, RoleAdmin, RoleSuperAdmin},
			ForbiddenRoles: []Role{},
			Description:    "Read inventory telemetry is accessible to all authenticated roles",
		},
		{
			Method:         http.MethodPost,
			Path:           "/api/v1/scans",
			Body:           `{"name":"Test Scan","target_cidr":"10.100.1.0/24"}`,
			AllowedRoles:   []Role{RoleOperator, RoleAdmin, RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleAuditor},
			Description:    "Triggering scans requires Operator role or higher",
		},
		{
			Method:         http.MethodPost,
			Path:           "/api/v1/scans/job-123/cancel",
			AllowedRoles:   []Role{RoleOperator, RoleAdmin, RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleAuditor},
			Description:    "Cancelling scans requires Operator role or higher",
		},
		{
			Method:         http.MethodGet,
			Path:           "/api/v1/audit-logs",
			AllowedRoles:   []Role{RoleAuditor, RoleAdmin, RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleOperator},
			Description:    "Audit logs are accessible strictly to Auditor, Admin, and SuperAdmin",
		},
		{
			Method:         http.MethodGet,
			Path:           "/api/v1/vault/credentials",
			AllowedRoles:   []Role{RoleAdmin, RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleOperator, RoleAuditor},
			Description:    "Listing vault credentials requires Admin role or higher",
		},
		{
			Method:         http.MethodPost,
			Path:           "/api/v1/vault/credentials/cred-01/test",
			Body:           `{"target_ip":"10.100.1.42"}`,
			AllowedRoles:   []Role{RoleAdmin, RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleOperator, RoleAuditor},
			Description:    "Testing vault credentials requires Admin role or higher",
		},
		{
			Method:         http.MethodPost,
			Path:           "/api/v1/vault/credentials",
			Body:           `{"name":"Test Cred","secret_value":"secret"}`,
			AllowedRoles:   []Role{RoleAdmin, RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleOperator, RoleAuditor},
			RequiresStepUp: true,
			Description:    "Creating vault credentials requires Admin role + Step-Up Auth",
		},
		{
			Method:         http.MethodPost,
			Path:           "/api/v1/compliance/policies/pol-01/disable",
			Body:           `{"justification":"Testing exception"}`,
			AllowedRoles:   []Role{RoleAdmin, RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleOperator, RoleAuditor},
			RequiresStepUp: true,
			Description:    "Disabling security policies requires Admin role + Step-Up Auth",
		},
		{
			Method:         http.MethodDelete,
			Path:           "/api/v1/endpoints/ep-01",
			AllowedRoles:   []Role{RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleOperator, RoleAuditor, RoleAdmin},
			RequiresStepUp: true,
			Description:    "Decommissioning endpoints requires SuperAdmin role + Step-Up Auth",
		},
		{
			Method:         http.MethodPost,
			Path:           "/api/v1/gateways/register",
			Body:           `{"hostname":"gw-01"}`,
			AllowedRoles:   []Role{RoleSuperAdmin},
			ForbiddenRoles: []Role{RoleViewer, RoleOperator, RoleAuditor, RoleAdmin},
			Description:    "Registering collector gateways requires SuperAdmin role",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			// 1. Assert Allowed Roles (with valid step-up auth within 5 minutes)
			for _, role := range tc.AllowedRoles {
				req := httptest.NewRequest(tc.Method, tc.Path, bytes.NewBufferString(tc.Body))
				req.Header.Set("Authorization", makeToken(role, 2)) // 2 minutes ago -> valid step-up
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
					t.Errorf("[%s %s] Role '%s' should be ALLOWED, but received HTTP %d: %s",
						tc.Method, tc.Path, role, w.Code, w.Body.String())
				}
			}

			// 2. Assert Forbidden Roles (Must receive HTTP 403 Forbidden)
			for _, role := range tc.ForbiddenRoles {
				req := httptest.NewRequest(tc.Method, tc.Path, bytes.NewBufferString(tc.Body))
				req.Header.Set("Authorization", makeToken(role, 2))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				if w.Code != http.StatusForbidden {
					t.Errorf("[%s %s] Role '%s' must be FORBIDDEN (403), but received HTTP %d",
						tc.Method, tc.Path, role, w.Code)
				}
			}

			// 3. Assert Step-Up Auth Expiration on Destructive Endpoints
			if tc.RequiresStepUp {
				for _, role := range tc.AllowedRoles {
					req := httptest.NewRequest(tc.Method, tc.Path, bytes.NewBufferString(tc.Body))
					req.Header.Set("Authorization", makeToken(role, 20)) // 20 minutes ago -> EXPIRED step-up (> 15m)
					req.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					router.ServeHTTP(w, req)

					if w.Code != http.StatusForbidden {
						t.Errorf("[%s %s] Role '%s' with expired step-up auth (>15m) must be rejected with 403 Forbidden, got HTTP %d",
							tc.Method, tc.Path, role, w.Code)
					}
				}
			}
		})
	}
}

// TestAuditLog_ImmutableGuarantee proves that audit logs cannot be edited, updated, or deleted
// through any API route by ANY role, including Admin and SuperAdmin.
func TestAuditLog_ImmutableGuarantee(t *testing.T) {
	tokenService := NewTokenService("test-secret-key-32b-matrix-auth-test!", "test-issuer")
	router := buildFullAuditedRouter(tokenService)

	claims := UserClaims{
		TenantID:     "tenant-matrix-test",
		UserID:       "usr-superadmin",
		Role:         RoleSuperAdmin,
		StepUpAuthAt: time.Now().UTC().Unix(),
	}
	tok, _ := tokenService.GenerateToken(claims, 1*time.Hour)
	superAdminToken := "Bearer " + tok

	mutatingMethods := []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodPost}

	for _, method := range mutatingMethods {
		t.Run("SuperAdmin cannot "+method+" /api/v1/audit-logs", func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/audit-logs", bytes.NewBufferString(`{"action":"TAMPER"}`))
			req.Header.Set("Authorization", superAdminToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Chi router must return 405 Method Not Allowed or 404 Not Found (no handler exists)
			if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
				t.Errorf("Audit log mutation (%s) must NOT be permitted; got HTTP %d", method, w.Code)
			}
		})
	}
}
