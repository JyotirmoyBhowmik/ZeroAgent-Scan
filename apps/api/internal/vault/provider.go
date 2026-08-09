// Package vault implements the EndpointGuard credential vault integration layer.
//
// Architecture:
//   - SecretProvider is the backend abstraction: HashiCorp Vault KV v2 (primary)
//     or AES-256-GCM envelope encryption (self-hosted fallback).
//   - VaultManager orchestrates storage, resolution, rotation, and audit logging.
//   - Secret material is NEVER returned over the REST API. Only opaque sec_ref_*
//     identifiers are exposed to the dashboard frontend.
//   - Only Collector Gateways (authenticated via mTLS) can resolve a credential_ref
//     to actual secret material, and only for the duration of a single scan job.
//   - Every secret resolution writes an audit log entry BEFORE the secret is used.
package vault

import (
	"context"
	"errors"
	"time"
)

// ---------------------------------------------------------------------------
// Sentinel Domain Errors (Rule 2.2: domain-specific exceptions)
// ---------------------------------------------------------------------------

// ErrSecretNotFound indicates the credential_ref does not exist in the backend.
var ErrSecretNotFound = errors.New("vault: secret not found for the given credential reference")

// ErrProviderUnavailable indicates the vault backend is unreachable or unhealthy.
var ErrProviderUnavailable = errors.New("vault: secret provider is unavailable or unreachable")

// ErrAuthorizationDenied indicates the caller is not authorized to resolve secrets.
// Only mTLS-authenticated Collector Gateways may resolve credential_refs.
var ErrAuthorizationDenied = errors.New("vault: authorization denied — only authenticated gateways may resolve secrets")

// ErrAuditWriteFailed indicates the audit log could not be persisted.
// Secret resolution MUST be aborted if the audit trail cannot be guaranteed.
var ErrAuditWriteFailed = errors.New("vault: audit log write failed — aborting secret resolution to preserve audit trail")

// ErrInvalidCredentialRef indicates the credential reference is malformed or incomplete.
var ErrInvalidCredentialRef = errors.New("vault: invalid credential reference — required fields missing")

// ---------------------------------------------------------------------------
// CredentialRef: opaque reference to a stored credential
// ---------------------------------------------------------------------------

// CredentialRef is the metadata envelope for a stored credential. It never
// contains the actual secret material — only the addressing information needed
// to locate and manage the secret inside the chosen SecretProvider backend.
type CredentialRef struct {
	// OpaqueID is the externally-visible tokenized identifier (e.g. "sec_ref_domain_kerberos_a1b2c3d4e5f6").
	// This is the ONLY identifier exposed over the REST API.
	OpaqueID string `json:"opaque_id"`

	// TenantID scopes the credential to a specific tenant for RLS isolation.
	TenantID string `json:"tenant_id"`

	// CredentialType classifies the credential (domain_kerberos, domain_ntlm,
	// local_service, snmp_v3, ssh_key, laps, gmsa).
	CredentialType string `json:"credential_type"`

	// DomainOrHost is the Active Directory domain, host, or subnet this credential targets.
	DomainOrHost string `json:"domain_or_host"`

	// Username is the service account principal (e.g. "svc_winrm_audit$").
	Username string `json:"username"`

	// VaultPath is the backend-specific storage path. For HashiCorp Vault KV v2,
	// this is e.g. "endpointguard/tenants/{tenant_id}/credentials/{opaque_id}".
	// Rotation updates this path's data without requiring a schema migration.
	VaultPath string `json:"vault_path"`

	// RotationVersion is a monotonically increasing counter that tracks how many
	// times this credential has been rotated. Used for LAPS/gMSA rotation auditing.
	RotationVersion int `json:"rotation_version"`
}

// ---------------------------------------------------------------------------
// SecretResolutionAuditEntry: immutable audit record for every resolution
// ---------------------------------------------------------------------------

// SecretResolutionAuditEntry is written to the security audit log BEFORE a secret
// is materialized. If the audit write fails, the resolution is aborted.
type SecretResolutionAuditEntry struct {
	CorrelationID string    `json:"correlation_id"`
	GatewayID     string    `json:"gateway_id"`
	CredentialRef string    `json:"credential_ref"` // opaque ID only, never the secret
	TenantID      string    `json:"tenant_id"`
	ScanJobID     string    `json:"scan_job_id"`
	Action        string    `json:"action"` // always "credential.resolved"
	Timestamp     time.Time `json:"timestamp"`
	IPAddress     string    `json:"ip_address"`
}

// ---------------------------------------------------------------------------
// SecretProvider: backend abstraction interface
// ---------------------------------------------------------------------------

// SecretProvider abstracts the credential storage backend. Two implementations
// are provided:
//
//   - HashiCorpVaultProvider: HashiCorp Vault OSS with KV v2 engine (primary).
//   - EnvelopeProvider: Self-hosted AES-256-GCM with HKDF-SHA256 key derivation
//     (fallback for teams who cannot run HashiCorp Vault).
//
// The interface is intentionally narrow to support future backends (AWS Secrets
// Manager, Azure Key Vault, GCP Secret Manager) without modifying the VaultManager.
type SecretProvider interface {
	// StoreSecret persists encrypted secret material at the location described
	// by ref. The plaintext MUST be zeroed by the caller after this returns.
	StoreSecret(ctx context.Context, ref CredentialRef, plaintext []byte) error

	// ResolveSecret retrieves and decrypts the secret for the given ref.
	// The returned byte slice MUST be zeroed by the caller after use.
	ResolveSecret(ctx context.Context, ref CredentialRef) ([]byte, error)

	// RotateSecret atomically replaces the secret for ref with newPlaintext.
	// For LAPS/gMSA credentials, this updates the vault_path's data without
	// requiring a database schema change. The newPlaintext MUST be zeroed by
	// the caller after this returns.
	RotateSecret(ctx context.Context, ref CredentialRef, newPlaintext []byte) error

	// DeleteSecret permanently removes the secret and all version history
	// for the given ref.
	DeleteSecret(ctx context.Context, ref CredentialRef) error

	// HealthCheck verifies connectivity and authentication to the backend.
	HealthCheck(ctx context.Context) error

	// Name returns a human-readable identifier for this provider, used in
	// structured log entries. Must never contain secret material.
	Name() string
}
