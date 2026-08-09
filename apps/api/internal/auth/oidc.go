package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// OIDCService manages enterprise OpenID Connect authentication flows.
type OIDCService struct {
	config OIDCConfig
}

// NewOIDCService creates an initialized OIDC provider client.
func NewOIDCService(cfg OIDCConfig) *OIDCService {
	if cfg.GroupRoleMap == nil {
		cfg.GroupRoleMap = map[string]Role{
			"EndpointGuard-SuperAdmins": RoleSuperAdmin,
			"EndpointGuard-Admins":      RoleAdmin,
			"EndpointGuard-Auditors":    RoleAuditor,
			"EndpointGuard-Operators":   RoleOperator,
			"EndpointGuard-Viewers":     RoleViewer,
		}
	}
	return &OIDCService{config: cfg}
}

// BuildAuthURL generates the IdP authorization redirect URL with state and PKCE code challenge.
func (s *OIDCService) BuildAuthURL() (authURL string, state string, codeVerifier string, err error) {
	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state = base64.RawURLEncoding.EncodeToString(stateBytes)

	verifierBytes := make([]byte, 32)
	_, _ = rand.Read(verifierBytes)
	codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	endpoint := strings.TrimSuffix(s.config.IssuerURL, "/") + "/protocol/openid-connect/auth"
	if strings.Contains(s.config.IssuerURL, "login.microsoftonline.com") {
		endpoint = strings.TrimSuffix(s.config.IssuerURL, "/") + "/oauth2/v2.0/authorize"
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", "", err
	}

	q := u.Query()
	q.Set("client_id", s.config.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email groups")
	q.Set("redirect_uri", s.config.RedirectURI)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	return u.String(), state, codeVerifier, nil
}

// OIDCClaims represents identity claims returned in the IdP ID token.
type OIDCClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
	Roles             []string `json:"roles"`
}

// MapGroupsToRole evaluates IdP group memberships and resolves the highest matching EndpointGuard role.
func (s *OIDCService) MapGroupsToRole(groups []string) Role {
	// Role precedence: superadmin > admin > auditor > operator > viewer
	highestRole := RoleViewer

	rolePrecedence := map[Role]int{
		RoleViewer:     1,
		RoleOperator:   2,
		RoleAuditor:    3,
		RoleAdmin:      4,
		RoleSuperAdmin: 5,
	}

	for _, g := range groups {
		if mappedRole, exists := s.config.GroupRoleMap[g]; exists {
			if rolePrecedence[mappedRole] > rolePrecedence[highestRole] {
				highestRole = mappedRole
			}
		}
	}
	return highestRole
}

// ProcessMockIDToken parses and validates an OIDC ID token for tests/mocking.
func (s *OIDCService) ProcessMockIDToken(rawIDTokenJSON string) (*User, error) {
	var claims OIDCClaims
	if err := json.Unmarshal([]byte(rawIDTokenJSON), &claims); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse id_token claims: %w", err)
	}

	allGroups := append(claims.Groups, claims.Roles...)
	resolvedRole := s.MapGroupsToRole(allGroups)

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}

	user := &User{
		ID:           "usr-oidc-" + claims.Subject,
		TenantID:     "tenant-default-01",
		Username:     username,
		Email:        claims.Email,
		DisplayName:  claims.Name,
		Role:         resolvedRole,
		IsActive:     true,
		IsBreakGlass: false,
		TOTPEnabled:  false,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	return user, nil
}
