package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)



// UserClaims contains identity and authorization metadata extracted from JWT.
type UserClaims struct {
	TenantID     string `json:"tenant_id"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Role         Role   `json:"role"`
	StepUpAuthAt int64  `json:"step_up_auth_at,omitempty"`
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	Audience     string `json:"aud"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
}

// TokenService handles HMAC-SHA256 JWT creation and verification.
type TokenService struct {
	secretKey []byte
	issuer    string
}

// NewTokenService creates a token service with an HMAC secret.
func NewTokenService(secretKey string, issuer string) *TokenService {
	if issuer == "" {
		issuer = "endpointguard-auth"
	}
	return &TokenService{
		secretKey: []byte(secretKey),
		issuer:    issuer,
	}
}

// GenerateToken produces a signed JWT string for a user identity.
func (s *TokenService) GenerateToken(claims UserClaims, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims.Issuer = s.issuer
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(ttl).Unix()

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	b64Header := base64.RawURLEncoding.EncodeToString(headerJSON)
	b64Claims := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := b64Header + "." + b64Claims
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsignedToken + "." + signature, nil
}

// VerifyToken validates the JWT signature and expiration, returning the unpacked claims.
func (s *TokenService) VerifyToken(tokenStr string) (*UserClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("auth: invalid token format (must have 3 parts)")
	}

	unsignedToken := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write([]byte(unsignedToken))
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, fmt.Errorf("auth: invalid signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth: failed to decode claims payload: %w", err)
	}

	var claims UserClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("auth: failed to parse claims: %w", err)
	}

	now := time.Now().UTC().Unix()
	if claims.ExpiresAt < now {
		return nil, fmt.Errorf("auth: token has expired")
	}

	return &claims, nil
}
