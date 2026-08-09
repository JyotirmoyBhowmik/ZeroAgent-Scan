package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// HashPassword generates a SHA-256 password hash with salt (for break-glass local accounts).
func HashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(password + salt + "endpointguard-salt-2026"))
	return hex.EncodeToString(hash[:])
}

// AuthRepository manages persistence for users, sessions, MFA secrets, and challenges.
type AuthRepository interface {
	SaveUser(user User) error
	GetUserByID(id string) (*User, bool)
	GetUserByUsername(tenantID, username string) (*User, bool)
	ListUsers(tenantID string) []User

	SaveTOTPSecret(userID, secretBase32 string) error
	GetTOTPSecret(userID string) (string, bool)

	SaveSession(session Session) error
	GetSessionByRefreshToken(refreshToken string) (*Session, bool)
	RevokeSession(sessionID string) error
	RevokeSessionFamily(familyID string) error

	SaveMFAChallenge(challenge MFAChallenge) error
	GetMFAChallenge(challengeID string) (*MFAChallenge, bool)
	DeleteMFAChallenge(challengeID string) error
}

// MemoryAuthRepository is a thread-safe in-memory store for authentication records.
type MemoryAuthRepository struct {
	mu          sync.RWMutex
	users       map[string]*User         // Key: userID
	totpSecrets map[string]string        // Key: userID -> Base32 secret
	sessions    map[string]*Session      // Key: sessionID
	byRefresh   map[string]*Session      // Key: refreshToken -> session
	byFamily    map[string][]*Session    // Key: familyID -> []sessions
	challenges  map[string]*MFAChallenge // Key: challengeID
}

// NewMemoryAuthRepository creates an initialized auth store pre-seeded with a Break-Glass Admin.
func NewMemoryAuthRepository() *MemoryAuthRepository {
	repo := &MemoryAuthRepository{
		users:       make(map[string]*User),
		totpSecrets: make(map[string]string),
		sessions:    make(map[string]*Session),
		byRefresh:   make(map[string]*Session),
		byFamily:    make(map[string][]*Session),
		challenges:  make(map[string]*MFAChallenge),
	}

	// Pre-seed Break-Glass Emergency Administrator
	breakGlassUser := User{
		ID:           "usr-break-glass-01",
		TenantID:     "tenant-default-01",
		Username:     "breakglass",
		Email:        "breakglass@endpointguard.local",
		DisplayName:  "Break-Glass Emergency Admin",
		Role:         RoleSuperAdmin,
		IsActive:     true,
		IsBreakGlass: true,
		TOTPEnabled:  true,
		PasswordHash: HashPassword("EmergencyBreakGlassPass2026!", "usr-break-glass-01"),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	_ = repo.SaveUser(breakGlassUser)
	_ = repo.SaveTOTPSecret("usr-break-glass-01", "JBSWY3DPEHPK3PXP") // standard test TOTP secret

	return repo
}

func (r *MemoryAuthRepository) SaveUser(user User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.ID] = &user
	return nil
}

func (r *MemoryAuthRepository) GetUserByID(id string) (*User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[id]
	return u, ok
}

func (r *MemoryAuthRepository) GetUserByUsername(tenantID, username string) (*User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.Username == username && (tenantID == "" || u.TenantID == tenantID) {
			return u, true
		}
	}
	return nil, false
}

func (r *MemoryAuthRepository) ListUsers(tenantID string) []User {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []User
	for _, u := range r.users {
		if tenantID == "" || u.TenantID == tenantID {
			list = append(list, *u)
		}
	}
	return list
}

func (r *MemoryAuthRepository) SaveTOTPSecret(userID, secretBase32 string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.totpSecrets[userID] = secretBase32
	return nil
}

func (r *MemoryAuthRepository) GetTOTPSecret(userID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.totpSecrets[userID]
	return s, ok
}

func (r *MemoryAuthRepository) SaveSession(session Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[session.ID] = &session
	r.byRefresh[session.RefreshToken] = &session
	r.byFamily[session.FamilyID] = append(r.byFamily[session.FamilyID], &session)
	return nil
}

func (r *MemoryAuthRepository) GetSessionByRefreshToken(refreshToken string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byRefresh[refreshToken]
	return s, ok
}

func (r *MemoryAuthRepository) RevokeSession(sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[sessionID]; ok {
		s.IsRevoked = true
	}
	return nil
}

func (r *MemoryAuthRepository) RevokeSessionFamily(familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if list, ok := r.byFamily[familyID]; ok {
		for _, s := range list {
			s.IsRevoked = true
		}
	}
	return nil
}

func (r *MemoryAuthRepository) SaveMFAChallenge(challenge MFAChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[challenge.ChallengeID] = &challenge
	return nil
}

func (r *MemoryAuthRepository) GetMFAChallenge(challengeID string) (*MFAChallenge, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.challenges[challengeID]
	return c, ok
}

func (r *MemoryAuthRepository) DeleteMFAChallenge(challengeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.challenges, challengeID)
	return nil
}
