package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ---------------------------------------------------------------------------
// EnvelopeProvider: AES-256-GCM self-hosted fallback SecretProvider
// ---------------------------------------------------------------------------

// EnvelopeProvider implements SecretProvider using local AES-256-GCM envelope
// encryption with HKDF-SHA256 key derivation. This is the fallback for teams
// who cannot deploy HashiCorp Vault.
//
// Each record gets a unique derived key via HKDF(masterKey, randomSalt, info).
// The master key itself is wrapped by a KMS-equivalent at rest and loaded
// only into process memory at startup.
type EnvelopeProvider struct {
	masterKey []byte // 32-byte AES-256 key, held only in-memory
	mu        sync.RWMutex
	records   map[string]*envelopeRecord // keyed by opaque_id
}

// envelopeRecord holds the encrypted representation of a single credential.
type envelopeRecord struct {
	TenantID        string
	Ciphertext      []byte
	Nonce           []byte
	Salt            []byte
	RotationVersion int
	CredentialType  string
	Username        string
	DomainOrHost    string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

const hkdfInfo = "endpointguard-vault-envelope-v1"

// NewEnvelopeProvider creates a new envelope encryption provider.
// masterKey must be exactly 32 bytes (256-bit AES key).
func NewEnvelopeProvider(masterKey []byte) (*EnvelopeProvider, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("vault: envelope master key must be exactly 32 bytes (256-bit), got %d", len(masterKey))
	}

	keyCopy := make([]byte, 32)
	copy(keyCopy, masterKey)

	return &EnvelopeProvider{
		masterKey: keyCopy,
		records:   make(map[string]*envelopeRecord),
	}, nil
}

// Name returns the provider identifier for structured logging.
func (e *EnvelopeProvider) Name() string {
	return "envelope-aes256gcm"
}

// deriveKey uses HKDF-SHA256 to derive a per-record 256-bit encryption key.
func (e *EnvelopeProvider) deriveKey(salt []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, e.masterKey, salt, []byte(hkdfInfo))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("vault: HKDF key derivation failed: %w", err)
	}
	return derivedKey, nil
}

// encrypt performs AES-256-GCM encryption with a derived per-record key.
func (e *EnvelopeProvider) encrypt(plaintext []byte) (ciphertext, nonce, salt []byte, retErr error) {
	// Generate random 16-byte salt for HKDF key derivation
	salt = make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, fmt.Errorf("vault: failed to generate salt: %w", err)
	}

	derivedKey, err := e.deriveKey(salt)
	if err != nil {
		return nil, nil, nil, err
	}
	defer zeroize(derivedKey)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: failed to create GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("vault: failed to generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, salt, nil
}

// decrypt performs AES-256-GCM decryption with a derived per-record key.
func (e *EnvelopeProvider) decrypt(ciphertext, nonce, salt []byte) ([]byte, error) {
	derivedKey, err := e.deriveKey(salt)
	if err != nil {
		return nil, err
	}
	defer zeroize(derivedKey)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to create AES cipher for decryption: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to create GCM for decryption: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: decryption failed (GCM authentication tag mismatch): %w", err)
	}

	return plaintext, nil
}

// StoreSecret encrypts and stores a credential in the local envelope store.
func (e *EnvelopeProvider) StoreSecret(_ context.Context, ref CredentialRef, plaintext []byte) error {
	ciphertext, nonce, salt, err := e.encrypt(plaintext)
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	e.mu.Lock()
	defer e.mu.Unlock()

	e.records[ref.OpaqueID] = &envelopeRecord{
		TenantID:        ref.TenantID,
		Ciphertext:      ciphertext,
		Nonce:           nonce,
		Salt:            salt,
		RotationVersion: ref.RotationVersion,
		CredentialType:  ref.CredentialType,
		Username:        ref.Username,
		DomainOrHost:    ref.DomainOrHost,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	return nil
}

// ResolveSecret decrypts and returns the secret for the given credential ref.
// The caller MUST zero the returned byte slice after use.
func (e *EnvelopeProvider) ResolveSecret(_ context.Context, ref CredentialRef) ([]byte, error) {
	e.mu.RLock()
	rec, ok := e.records[ref.OpaqueID]
	if !ok || (rec.TenantID != "" && ref.TenantID != "" && rec.TenantID != ref.TenantID) {
		e.mu.RUnlock()
		return nil, fmt.Errorf("%w: ref=%s", ErrSecretNotFound, ref.OpaqueID)
	}

	// Copy ciphertext material under lock so the record isn't mutated during decrypt
	ct := make([]byte, len(rec.Ciphertext))
	copy(ct, rec.Ciphertext)
	nc := make([]byte, len(rec.Nonce))
	copy(nc, rec.Nonce)
	sl := make([]byte, len(rec.Salt))
	copy(sl, rec.Salt)
	e.mu.RUnlock()

	plaintext, err := e.decrypt(ct, nc, sl)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to resolve secret for ref=%s: %w", ref.OpaqueID, err)
	}

	return plaintext, nil
}

// RotateSecret atomically replaces the encrypted credential with new material.
// The old ciphertext is securely zeroed and replaced in a single locked operation.
func (e *EnvelopeProvider) RotateSecret(_ context.Context, ref CredentialRef, newPlaintext []byte) error {
	// Encrypt new material first (outside the write lock)
	newCiphertext, newNonce, newSalt, err := e.encrypt(newPlaintext)
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	e.mu.Lock()
	defer e.mu.Unlock()

	oldRec, ok := e.records[ref.OpaqueID]
	if !ok || (oldRec.TenantID != "" && ref.TenantID != "" && oldRec.TenantID != ref.TenantID) {
		return fmt.Errorf("%w: ref=%s", ErrSecretNotFound, ref.OpaqueID)
	}

	// Verify old record can be decrypted (integrity check before replacement)
	oldCt := make([]byte, len(oldRec.Ciphertext))
	copy(oldCt, oldRec.Ciphertext)
	oldNc := make([]byte, len(oldRec.Nonce))
	copy(oldNc, oldRec.Nonce)
	oldSl := make([]byte, len(oldRec.Salt))
	copy(oldSl, oldRec.Salt)

	oldPlain, decErr := e.decrypt(oldCt, oldNc, oldSl)
	if decErr != nil {
		return fmt.Errorf("vault: rotation integrity check failed for ref=%s: %w", ref.OpaqueID, decErr)
	}
	zeroize(oldPlain)

	// Securely zero old ciphertext material
	zeroize(oldRec.Ciphertext)
	zeroize(oldRec.Nonce)
	zeroize(oldRec.Salt)

	// Atomic swap
	e.records[ref.OpaqueID] = &envelopeRecord{
		Ciphertext:      newCiphertext,
		Nonce:           newNonce,
		Salt:            newSalt,
		RotationVersion: ref.RotationVersion + 1,
		CredentialType:  ref.CredentialType,
		Username:        ref.Username,
		DomainOrHost:    ref.DomainOrHost,
		CreatedAt:       oldRec.CreatedAt,
		UpdatedAt:       now,
	}

	return nil
}

// DeleteSecret permanently removes the credential and securely zeros all
// associated ciphertext material from memory.
func (e *EnvelopeProvider) DeleteSecret(_ context.Context, ref CredentialRef) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rec, ok := e.records[ref.OpaqueID]
	if !ok {
		return fmt.Errorf("%w: ref=%s", ErrSecretNotFound, ref.OpaqueID)
	}

	// Securely zero all byte slices before deletion
	zeroize(rec.Ciphertext)
	zeroize(rec.Nonce)
	zeroize(rec.Salt)

	delete(e.records, ref.OpaqueID)
	return nil
}

// HealthCheck always returns nil for the local envelope provider.
func (e *EnvelopeProvider) HealthCheck(_ context.Context) error {
	return nil
}

// zeroize securely overwrites a byte slice with zeros to prevent
// secret material from lingering in process memory.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
