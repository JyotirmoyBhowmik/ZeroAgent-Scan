package vault

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// VaultManager: orchestrator for credential lifecycle + audit logging
// ---------------------------------------------------------------------------

// AuditFunc is the callback signature for writing audit log entries.
// The VaultManager calls this BEFORE resolving any secret material.
// If it returns an error, the resolution is aborted (no secret without audit trail).
type AuditFunc func(entry SecretResolutionAuditEntry) error

// VaultManager is the central coordinator for credential storage, resolution,
// rotation, and audit logging. It delegates to a SecretProvider backend
// (HashiCorp Vault or envelope encryption) and enforces the security invariant
// that only mTLS-authenticated Collector Gateways can resolve secrets.
type VaultManager struct {
	provider SecretProvider
	auditFn  AuditFunc
	mu       sync.RWMutex
}

// NewVaultManager creates a VaultManager bound to the given SecretProvider backend
// and audit logging callback. The auditFn is mandatory — secret resolution without
// an audit trail is architecturally prohibited.
func NewVaultManager(provider SecretProvider, auditFn AuditFunc) *VaultManager {
	if provider == nil {
		panic("vault: SecretProvider must not be nil")
	}
	if auditFn == nil {
		panic("vault: audit function must not be nil — resolution without audit trail is prohibited")
	}
	return &VaultManager{
		provider: provider,
		auditFn:  auditFn,
	}
}

// ProviderName returns the active backend name for structured logging.
func (vm *VaultManager) ProviderName() string {
	return vm.provider.Name()
}

// ---------------------------------------------------------------------------
// StoreCredential: encrypt and persist a new credential
// ---------------------------------------------------------------------------

// StoreCredential encrypts and stores a credential in the active backend.
// If ref.OpaqueID is empty, a new opaque ID is generated.
// The plaintext slice is securely zeroed after storage completes.
// Returns the opaque ID for the stored credential.
func (vm *VaultManager) StoreCredential(ctx context.Context, ref CredentialRef, plaintext []byte) (string, error) {
	defer zeroize(plaintext)

	if strings.TrimSpace(ref.TenantID) == "" {
		return "", fmt.Errorf("%w: tenant_id is required", ErrInvalidCredentialRef)
	}

	if strings.TrimSpace(ref.OpaqueID) == "" {
		ref.OpaqueID = GenerateOpaqueID(ref.CredentialType)
	}

	if ref.VaultPath == "" {
		ref.VaultPath = buildVaultPath(ref)
	}

	vm.mu.Lock()
	defer vm.mu.Unlock()

	if err := vm.provider.StoreSecret(ctx, ref, plaintext); err != nil {
		// Rule 2.4: Sanitized error — NEVER include plaintext in error messages
		return "", fmt.Errorf("vault: failed to store credential ref=%s: %w", ref.OpaqueID, err)
	}

	return ref.OpaqueID, nil
}

// ---------------------------------------------------------------------------
// ResolveCredentialForGateway: the ONLY method that materializes secrets
// ---------------------------------------------------------------------------

// ResolveCredentialForGateway is the sole code path that resolves a credential_ref
// to actual secret material. It enforces three invariants:
//
//  1. AUTHORIZATION: Only mTLS-authenticated Collector Gateways (identified by
//     gatewayID) may call this method. Dashboard/API consumers never reach here.
//
//  2. AUDIT-BEFORE-ACCESS: An immutable audit log entry is written BEFORE the
//     secret is materialized. If the audit write fails, the resolution is aborted.
//
//  3. ZERO-CACHE: The returned secret bytes are for just-in-time use during a
//     single scan job. The caller MUST zeroize the returned slice after use.
//     The secret is never written to disk or cached.
func (vm *VaultManager) ResolveCredentialForGateway(
	ctx context.Context,
	gatewayID, scanJobID, correlationID, ipAddress string,
	ref CredentialRef,
) ([]byte, error) {
	// Invariant 1: Authorization — only gateways can resolve secrets
	if strings.TrimSpace(gatewayID) == "" {
		return nil, ErrAuthorizationDenied
	}
	if strings.TrimSpace(ref.OpaqueID) == "" {
		return nil, fmt.Errorf("%w: opaque_id is required", ErrInvalidCredentialRef)
	}
	if strings.TrimSpace(ref.TenantID) == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidCredentialRef)
	}

	// Invariant 2: Audit BEFORE access — no secret without an audit trail
	entry := SecretResolutionAuditEntry{
		CorrelationID: correlationID,
		GatewayID:     gatewayID,
		CredentialRef: ref.OpaqueID, // only the opaque ID, never the secret
		TenantID:      ref.TenantID,
		ScanJobID:     scanJobID,
		Action:        "credential.resolved",
		Timestamp:     time.Now().UTC(),
		IPAddress:     ipAddress,
	}

	if err := vm.auditFn(entry); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditWriteFailed, err)
	}

	// Invariant 3: Just-in-time resolution — fetch, return, caller zeros
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	secret, err := vm.provider.ResolveSecret(ctx, ref)
	if err != nil {
		// Rule 2.4: Error messages NEVER contain secret material
		return nil, fmt.Errorf("vault: failed to resolve credential ref=%s for gateway=%s: %w", ref.OpaqueID, gatewayID, err)
	}

	return secret, nil
}

// ---------------------------------------------------------------------------
// RotateCredential: atomic credential rotation for LAPS/gMSA
// ---------------------------------------------------------------------------

// RotateCredential atomically rotates a credential's secret material.
// For LAPS/gMSA credentials, this updates the vault backend's stored data
// without requiring a database schema change — the opaque_id and vault_path
// remain stable; only the encrypted data and rotation_version change.
//
// The newPlaintext slice is securely zeroed after rotation completes.
func (vm *VaultManager) RotateCredential(ctx context.Context, ref CredentialRef, newPlaintext []byte) error {
	defer zeroize(newPlaintext)

	if strings.TrimSpace(ref.OpaqueID) == "" {
		return fmt.Errorf("%w: opaque_id is required for rotation", ErrInvalidCredentialRef)
	}

	vm.mu.Lock()
	defer vm.mu.Unlock()

	if err := vm.provider.RotateSecret(ctx, ref, newPlaintext); err != nil {
		return fmt.Errorf("vault: rotation failed for ref=%s: %w", ref.OpaqueID, err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// DeleteCredential: permanent credential revocation
// ---------------------------------------------------------------------------

// DeleteCredential permanently removes a credential from the backend.
func (vm *VaultManager) DeleteCredential(ctx context.Context, ref CredentialRef) error {
	if strings.TrimSpace(ref.OpaqueID) == "" {
		return fmt.Errorf("%w: opaque_id is required for deletion", ErrInvalidCredentialRef)
	}

	vm.mu.Lock()
	defer vm.mu.Unlock()

	return vm.provider.DeleteSecret(ctx, ref)
}

// ---------------------------------------------------------------------------
// HealthCheck: backend connectivity verification
// ---------------------------------------------------------------------------

// HealthCheck delegates to the active SecretProvider's health check.
func (vm *VaultManager) HealthCheck(ctx context.Context) error {
	return vm.provider.HealthCheck(ctx)
}

// ---------------------------------------------------------------------------
// GenerateOpaqueID: secure tokenized reference generator
// ---------------------------------------------------------------------------

var opaqueIDSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// GenerateOpaqueID creates an unguessable, secure tokenized credential reference.
// The returned ID follows the format: sec_ref_{type}_{uuid12}
func GenerateOpaqueID(prefix string) string {
	cleanPrefix := opaqueIDSanitizer.ReplaceAllString(prefix, "")
	cleanPrefix = strings.ToLower(cleanPrefix)
	if cleanPrefix == "" {
		cleanPrefix = "cred"
	}
	return fmt.Sprintf("sec_ref_%s_%s", cleanPrefix, uuid.New().String()[:12])
}
