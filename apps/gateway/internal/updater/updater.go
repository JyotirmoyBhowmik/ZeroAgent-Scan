package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrInvalidSignature      = errors.New("updater: binary cryptographic signature is invalid or tampered")
	ErrPublicKeyInvalid       = errors.New("updater: trusted public key is malformed")
	ErrBinaryDownloadFailed   = errors.New("updater: failed to download update binary")
	ErrChecksumMismatch       = errors.New("updater: binary sha256 checksum mismatch")
)

// UpdateManifest describes a new release to be downloaded and verified.
type UpdateManifest struct {
	Version      string `json:"version"`
	DownloadURL  string `json:"download_url"`
	SHA256Hex    string `json:"sha256_hex"`
	SignatureHex string `json:"signature_hex"` // Ed25519 signature over binary bytes or sha256 digest
}

// UpdateEngine manages cryptographic verification and application of self-updates.
type UpdateEngine struct {
	trustedPubKey ed25519.PublicKey
	httpClient    *http.Client
}

// NewUpdateEngine creates a new updater with a trusted Ed25519 public key.
func NewUpdateEngine(trustedPubKeyHex string, httpClient *http.Client) (*UpdateEngine, error) {
	pubBytes, err := hex.DecodeString(trustedPubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d hex bytes, got %d", ErrPublicKeyInvalid, ed25519.PublicKeySize, len(pubBytes))
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}

	return &UpdateEngine{
		trustedPubKey: ed25519.PublicKey(pubBytes),
		httpClient:    httpClient,
	}, nil
}

// VerifyBinary checks if binaryData matches the expected SHA256 and Ed25519 signature.
func (u *UpdateEngine) VerifyBinary(binaryData []byte, expectedSHA256Hex, signatureHex string) error {
	// 1. Verify SHA-256 Checksum
	actualSum := sha256.Sum256(binaryData)
	actualSHA256Hex := hex.EncodeToString(actualSum[:])
	if expectedSHA256Hex != "" && !strings.EqualFold(actualSHA256Hex, expectedSHA256Hex) {
		return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expectedSHA256Hex, actualSHA256Hex)
	}

	// 2. Verify Ed25519 Signature
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid signature encoding or length", ErrInvalidSignature)
	}

	// Verify signature over the raw binary bytes or over the SHA-256 digest
	valid := ed25519.Verify(u.trustedPubKey, binaryData, sigBytes)
	if !valid {
		// Also try signature over digest
		valid = ed25519.Verify(u.trustedPubKey, actualSum[:], sigBytes)
	}

	if !valid {
		return ErrInvalidSignature
	}

	return nil
}

// ApplyUpdate downloads, verifies signature, and writes update to destination path.
func (u *UpdateEngine) ApplyUpdate(ctx context.Context, manifest UpdateManifest, targetPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.DownloadURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBinaryDownloadFailed, err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBinaryDownloadFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: server returned HTTP %d", ErrBinaryDownloadFailed, resp.StatusCode)
	}

	binaryBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100<<20)) // 100MB limit
	if err != nil {
		return fmt.Errorf("updater: failed to read update stream: %w", err)
	}

	// Strictly verify signature BEFORE touching disk
	if err := u.VerifyBinary(binaryBytes, manifest.SHA256Hex, manifest.SignatureHex); err != nil {
		return fmt.Errorf("updater: security verification failed: %w", err)
	}

	// Staging write
	tmpFile := fmt.Sprintf("%s.tmp.%d", targetPath, time.Now().UnixNano())
	_ = os.MkdirAll(filepath.Dir(targetPath), 0755)

	if err := os.WriteFile(tmpFile, binaryBytes, 0755); err != nil {
		return fmt.Errorf("updater: failed to stage update file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpFile, targetPath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("updater: failed to commit update file: %w", err)
	}

	return nil
}
