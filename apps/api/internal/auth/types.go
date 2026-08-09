package auth

import (
	"time"
)

// Role defines the 5 distinct access tiers in EndpointGuard.
type Role string

const (
	RoleViewer     Role = "viewer"     // Read-only access to inventory, telemetry, findings, compliance
	RoleOperator   Role = "operator"   // Can launch/cancel scans, acknowledge drift
	RoleAuditor    Role = "auditor"    // Can read all telemetry, compliance, findings, reports, and audit logs
	RoleAdmin      Role = "admin"      // Tenant administrator (users, alert rules, scans, credential metadata with step-up)
	RoleSuperAdmin Role = "superadmin" // Global administrator across all tenants and gateways
)

// Permission represents an atomic authorization privilege.
type Permission string

const (
	PermissionReadTelemetry     Permission = "read:telemetry"
	PermissionReadCompliance    Permission = "read:compliance"
	PermissionReadFindings      Permission = "read:findings"
	PermissionReadDrift         Permission = "read:drift"
	PermissionReadAuditLogs     Permission = "read:audit_logs"
	PermissionTriggerScans      Permission = "trigger:scans"
	PermissionCancelScans       Permission = "cancel:scans"
	PermissionAcknowledgeDrift  Permission = "ack:drift"
	PermissionManageAlerts      Permission = "manage:alerts"
	PermissionManageCredentials Permission = "manage:credentials"
	PermissionManageUsers       Permission = "manage:users"
	PermissionManageTenants     Permission = "manage:tenants"
	PermissionGenerateReports   Permission = "generate:reports"
)

// User represents an authenticated identity.
type User struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"display_name"`
	Role         Role      `json:"role"`
	IsActive     bool      `json:"is_active"`
	IsBreakGlass bool      `json:"is_break_glass"`
	TOTPEnabled  bool      `json:"totp_enabled"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Session represents an active authenticated session with refresh token family tracking.
type Session struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	TenantID      string    `json:"tenant_id"`
	FamilyID      string    `json:"family_id"`
	RefreshToken  string    `json:"refresh_token"`
	CSRFToken     string    `json:"csrf_token"`
	StepUpAuthAt  time.Time `json:"step_up_auth_at"`
	IsRevoked     bool      `json:"is_revoked"`
	UserAgent     string    `json:"user_agent"`
	IPAddress     string    `json:"ip_address"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
	LastRefreshAt time.Time `json:"last_refresh_at"`
}

// MFAChallenge is issued when password login succeeds but TOTP verification is pending.
type MFAChallenge struct {
	ChallengeID string    `json:"challenge_id"`
	UserID      string    `json:"user_id"`
	TenantID    string    `json:"tenant_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// TokenPair contains the access token, refresh token, and CSRF token returned on login/refresh.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	CSRFToken    string `json:"csrf_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds (900s = 15m)
	User         User   `json:"user"`
}

// OIDCConfig holds settings for enterprise IdP integration (Entra ID, Okta, Keycloak).
type OIDCConfig struct {
	IssuerURL    string            `json:"issuer_url"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	RedirectURI  string            `json:"redirect_uri"`
	GroupRoleMap map[string]Role   `json:"group_role_map"` // e.g. "EndpointGuard-Admins" -> RoleAdmin
}

// SCIMUser represents a SCIM 2.0 User resource.
type SCIMUser struct {
	Schemas    []string          `json:"schemas"`
	ID         string            `json:"id"`
	UserName   string            `json:"userName"`
	Name       SCIMName          `json:"name"`
	Emails     []SCIMEmail       `json:"emails"`
	Roles      []SCIMRole        `json:"roles,omitempty"`
	Active     bool              `json:"active"`
	Meta       SCIMMeta          `json:"meta"`
}

type SCIMName struct {
	Formatted  string `json:"formatted"`
	FamilyName string `json:"familyName"`
	GivenName  string `json:"givenName"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

type SCIMRole struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
}

// SCIMListResponse is the standard RFC 7644 list response.
type SCIMListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []SCIMUser `json:"Resources"`
}
