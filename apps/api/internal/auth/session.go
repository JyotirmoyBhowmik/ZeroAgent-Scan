package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour
)

// SessionManager handles token generation, refresh token rotation, and token family invalidation.
type SessionManager struct {
	tokenService *TokenService
	repo         AuthRepository
}

// NewSessionManager creates an initialized session manager.
func NewSessionManager(tokenService *TokenService, repo AuthRepository) *SessionManager {
	return &SessionManager{
		tokenService: tokenService,
		repo:         repo,
	}
}

// GenerateCSRFToken generates a 256-bit cryptographically random CSRF token.
func GenerateCSRFToken() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// GenerateRefreshToken generates a secure random refresh token string.
func GenerateRefreshToken() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return "rft_" + base64.RawURLEncoding.EncodeToString(bytes)
}

// IssueTokenPair creates a new access token, rotated refresh token, and CSRF token.
func (m *SessionManager) IssueTokenPair(user User, familyID string, ipAddress, userAgent string) (*TokenPair, error) {
	if familyID == "" {
		familyID = uuid.New().String()
	}

	refreshToken := GenerateRefreshToken()
	csrfToken := GenerateCSRFToken()
	now := time.Now().UTC()

	session := Session{
		ID:            uuid.New().String(),
		UserID:        user.ID,
		TenantID:      user.TenantID,
		FamilyID:      familyID,
		RefreshToken:  refreshToken,
		CSRFToken:     csrfToken,
		StepUpAuthAt:  now,
		IsRevoked:     false,
		UserAgent:     userAgent,
		IPAddress:     ipAddress,
		ExpiresAt:     now.Add(RefreshTokenTTL),
		CreatedAt:     now,
		LastRefreshAt: now,
	}

	if err := m.repo.SaveSession(session); err != nil {
		return nil, fmt.Errorf("session: failed to save session: %w", err)
	}

	claims := UserClaims{
		TenantID: user.TenantID,
		UserID:   user.ID,
		Email:    user.Email,
		Role:     user.Role,
	}

	accessToken, err := m.tokenService.GenerateToken(claims, AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("session: failed to generate access token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CSRFToken:    csrfToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
		User:         user,
	}, nil
}

// RefreshToken exchanges an active refresh token for a new TokenPair, rotating the token.
// If an already-rotated/revoked token is used, all tokens in the family are revoked (replay attack protection).
func (m *SessionManager) RefreshToken(oldRefreshToken, ipAddress, userAgent string) (*TokenPair, error) {
	session, exists := m.repo.GetSessionByRefreshToken(oldRefreshToken)
	if !exists {
		return nil, fmt.Errorf("session: invalid refresh token")
	}

	if session.IsRevoked {
		// Replay attack detected! Invalidate the entire token family
		_ = m.repo.RevokeSessionFamily(session.FamilyID)
		return nil, fmt.Errorf("session: revoked token replayed, token family terminated for security")
	}

	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session: refresh token expired")
	}

	// Revoke the old session as part of rotation
	_ = m.repo.RevokeSession(session.ID)

	user, exists := m.repo.GetUserByID(session.UserID)
	if !exists || !user.IsActive {
		return nil, fmt.Errorf("session: user account is deactivated or missing")
	}

	// Issue new token pair preserving the familyID
	return m.IssueTokenPair(*user, session.FamilyID, ipAddress, userAgent)
}
