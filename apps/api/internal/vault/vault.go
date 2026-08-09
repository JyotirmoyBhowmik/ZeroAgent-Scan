package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

type EncryptedRecord struct {
	OpaqueID        string
	Ciphertext      []byte
	Nonce           []byte
	Salt            []byte
	CredentialType  string
	DomainOrHost    string
	Username        string
}

type VaultService struct {
	masterKey []byte
}

func NewVaultService(masterKey []byte) (*VaultService, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("vault master key must be exactly 32 bytes (256-bit)")
	}
	return &VaultService{masterKey: masterKey}, nil
}

// GenerateOpaqueID creates an unguessable, secure tokenized reference
func GenerateOpaqueID(prefix string) string {
	cleanPrefix := regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(prefix, "")
	cleanPrefix = strings.ToLower(cleanPrefix)
	if cleanPrefix == "" {
		cleanPrefix = "cred"
	}
	return fmt.Sprintf("sec_ref_%s_%s", cleanPrefix, uuid.New().String()[:12])
}

// EncryptSecret encrypts a plaintext secret using AES-256-GCM with a per-record derived key
func (v *VaultService) EncryptSecret(plaintext string) ([]byte, []byte, []byte, error) {
	// Generate random 16-byte salt for HKDF key derivation
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive per-record 256-bit encryption key
	kdf := hkdf.New(sha256.New, v.masterKey, salt, []byte("endpointguard-vault-envelope-v1"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return ciphertext, nonce, salt, nil
}

// DecryptSecret decrypts ciphertext inside an ephemeral memory worker
func (v *VaultService) DecryptSecret(ciphertext, nonce, salt []byte) (string, error) {
	kdf := hkdf.New(sha256.New, v.masterKey, salt, []byte("endpointguard-vault-envelope-v1"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return "", fmt.Errorf("failed to derive key for decryption: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintextBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (authentication tag mismatch): %w", err)
	}

	return string(plaintextBytes), nil
}
