package vault

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestVaultService_EnvelopeEncryption(t *testing.T) {
	masterKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		t.Fatalf("failed to decode master key hex: %v", err)
	}

	vs, err := NewVaultService(masterKey)
	if err != nil {
		t.Fatalf("failed to init vault service: %v", err)
	}

	originalSecret := "P@ssw0rd123!WinRM#SuperSecureKey"

	// Encrypt
	ciphertext, nonce, salt, err := vs.EncryptSecret(originalSecret)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if len(ciphertext) == 0 || len(nonce) == 0 || len(salt) == 0 {
		t.Fatalf("encryption produced empty outputs")
	}

	// Decrypt
	decrypted, err := vs.DecryptSecret(ciphertext, nonce, salt)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if decrypted != originalSecret {
		t.Fatalf("expected decrypted '%s', got '%s'", originalSecret, decrypted)
	}

	// Test Tampered Ciphertext
	corrupted := append([]byte(nil), ciphertext...)
	corrupted[0] ^= 0xFF
	_, err = vs.DecryptSecret(corrupted, nonce, salt)
	if err == nil {
		t.Fatalf("expected error when decrypting tampered ciphertext, got nil")
	}
}

func TestGenerateOpaqueID(t *testing.T) {
	id := GenerateOpaqueID("winrm_domain_prod")
	if !strings.HasPrefix(id, "sec_ref_winrm_domain_prod_") {
		t.Fatalf("opaque ID '%s' does not start with expected prefix", id)
	}
}
