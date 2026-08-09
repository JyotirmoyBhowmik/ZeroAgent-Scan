package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
)

type contextKey string

const (
	tenantContextKey contextKey = "endpointguard.tenant_id"
	claimsContextKey contextKey = "endpointguard.user_claims"
)

// RequireAuth middleware validates the Bearer JWT and injects authenticated tenant context.
func RequireAuth(tokenService *TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "MISSING_AUTHORIZATION",
					"Authorization header with Bearer token is required", nil)
				return
			}

			tokenParts := strings.SplitN(authHeader, " ", 2)
			if len(tokenParts) != 2 || !strings.EqualFold(tokenParts[0], "Bearer") {
				middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "INVALID_AUTH_SCHEME",
					"Authorization format must be 'Bearer <token>'", nil)
				return
			}

			claims, err := tokenService.VerifyToken(tokenParts[1])
			if err != nil {
				middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "INVALID_TOKEN",
					"Supplied JWT token is invalid or expired", nil)
				return
			}

			// Invariant: Never trust client-supplied tenant_id; strictly enforce authenticated JWT claims
			ctx := context.WithValue(r.Context(), tenantContextKey, claims.TenantID)
			ctx = context.WithValue(ctx, claimsContextKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuth middleware parses JWT if present, otherwise injects default tenant for dev/gateway.
func OptionalAuth(tokenService *TokenService, defaultTenant string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				tokenStr := strings.TrimSpace(authHeader[7:])
				claims, err := tokenService.VerifyToken(tokenStr)
				if err == nil {
					ctx := context.WithValue(r.Context(), tenantContextKey, claims.TenantID)
					ctx = context.WithValue(ctx, claimsContextKey, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			tenantID := r.Header.Get("X-Tenant-ID")
			if tenantID == "" {
				tenantID = defaultTenant
			}
			if tenantID == "" {
				tenantID = "tenant-default-01"
			}

			// Default fallback claims with RoleSuperAdmin for unauthenticated dev/gateway endpoints
			claims := &UserClaims{
				TenantID:     tenantID,
				UserID:       "usr-default-admin",
				Email:        "admin@endpointguard.local",
				Role:         RoleSuperAdmin,
				StepUpAuthAt: time.Now().UTC().Unix(),
			}

			ctx := context.WithValue(r.Context(), tenantContextKey, tenantID)
			ctx = context.WithValue(ctx, claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission enforces that the authenticated user has the specified permission.
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetUserClaims(r.Context())
			if !ok || claims == nil {
				middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "UNAUTHENTICATED",
					"Authentication required to perform this action", nil)
				return
			}

			if !HasPermission(claims.Role, perm) {
				middleware.WriteProblemDetails(w, r, http.StatusForbidden, "FORBIDDEN_INSUFFICIENT_PERMISSIONS",
					"Your role ("+string(claims.Role)+") does not have permission: "+string(perm), nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireStepUp enforces that the user has re-authenticated within the last 15 minutes for privilege escalation.
func RequireStepUp() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetUserClaims(r.Context())
			if !ok || claims == nil {
				middleware.WriteProblemDetails(w, r, http.StatusUnauthorized, "UNAUTHENTICATED",
					"Authentication required", nil)
				return
			}

			var lastAuth time.Time
			if claims.StepUpAuthAt > 0 {
				lastAuth = time.Unix(claims.StepUpAuthAt, 0).UTC()
			} else {
				lastAuth = time.Unix(claims.IssuedAt, 0).UTC()
			}

			if !IsStepUpValid(lastAuth) {
				middleware.WriteProblemDetails(w, r, http.StatusForbidden, "STEP_UP_AUTH_REQUIRED",
					"This sensitive operation requires step-up re-authentication within the last 15 minutes", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CSRFProtectionMiddleware validates the double-submit CSRF token on mutating requests.
func CSRFProtectionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only validate on mutating methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// In test or API bearer mode, check X-CSRF-Token if cookie is present
			csrfCookie, err := r.Cookie("csrf_token")
			if err == nil && csrfCookie != nil && csrfCookie.Value != "" {
				csrfHeader := r.Header.Get("X-CSRF-Token")
				if csrfHeader == "" || csrfHeader != csrfCookie.Value {
					middleware.WriteProblemDetails(w, r, http.StatusForbidden, "CSRF_TOKEN_MISMATCH",
						"Missing or invalid X-CSRF-Token header matching csrf_token cookie", nil)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetTenantID extracts the authenticated tenant ID from context.
func GetTenantID(ctx context.Context) string {
	if val, ok := ctx.Value(tenantContextKey).(string); ok && val != "" {
		return val
	}
	return "tenant-default-01"
}

// GetUserClaims extracts the parsed UserClaims from context if available.
func GetUserClaims(ctx context.Context) (*UserClaims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*UserClaims)
	return claims, ok
}
