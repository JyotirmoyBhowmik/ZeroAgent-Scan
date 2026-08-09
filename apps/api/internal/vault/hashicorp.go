package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// HashiCorpVaultProvider: HashiCorp Vault OSS KV v2 backend
// ---------------------------------------------------------------------------

// HashiCorpVaultProvider implements SecretProvider using HashiCorp Vault's KV v2
// secrets engine. Secrets are stored at paths scoped by tenant and opaque ID.
//
// Wire format for KV v2 data payloads:
//
//	{"data": {"secret": "<base64-encoded>", "rotation_version": N, "credential_type": "...", "username": "..."}}
type HashiCorpVaultProvider struct {
	client      *http.Client
	addr        string
	token       string // kept only in-memory, never logged or serialized
	kvMountPath string
	mu          sync.RWMutex
}

// vaultKVWriteRequest is the request body for KV v2 PUT operations.
type vaultKVWriteRequest struct {
	Options *vaultKVWriteOptions       `json:"options,omitempty"`
	Data    map[string]interface{} `json:"data"`
}

// vaultKVWriteOptions supports CAS (Check-And-Set) for atomic rotation.
type vaultKVWriteOptions struct {
	CAS *int `json:"cas,omitempty"`
}

// vaultKVReadResponse is the envelope returned by KV v2 GET.
type vaultKVReadResponse struct {
	Data struct {
		Data     map[string]interface{} `json:"data"`
		Metadata struct {
			Version int `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
}

// NewHashiCorpVaultProvider creates a new HashiCorp Vault KV v2 provider.
// addr must be the full base URL (e.g. "https://vault.internal:8200").
// token is the Vault authentication token, held only in-memory.
// kvMountPath is the KV v2 mount point (default: "endpointguard").
func NewHashiCorpVaultProvider(addr, token, kvMountPath string) (*HashiCorpVaultProvider, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, fmt.Errorf("vault: HashiCorp Vault address must not be empty")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("vault: HashiCorp Vault token must not be empty")
	}

	if kvMountPath == "" {
		kvMountPath = "endpointguard"
	}
	kvMountPath = strings.Trim(kvMountPath, "/")

	// Rule 3.1: Explicit connection and read timeouts on every external HTTP request.
	// Rule 5.3: Use managed connection pools, not per-request client instances.
	transport := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	return &HashiCorpVaultProvider{
		client:      client,
		addr:        strings.TrimRight(addr, "/"),
		token:       token,
		kvMountPath: kvMountPath,
	}, nil
}

// Name returns the provider identifier for structured logging.
func (h *HashiCorpVaultProvider) Name() string {
	return "hashicorp-vault-kv2"
}

// buildVaultPath constructs the KV v2 logical path for a credential ref.
// Format: endpointguard/tenants/{tenant_id}/credentials/{opaque_id}
func buildVaultPath(ref CredentialRef) string {
	return fmt.Sprintf("tenants/%s/credentials/%s", ref.TenantID, ref.OpaqueID)
}

// StoreSecret encrypts and persists a secret in HashiCorp Vault KV v2.
func (h *HashiCorpVaultProvider) StoreSecret(ctx context.Context, ref CredentialRef, plaintext []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	path := buildVaultPath(ref)
	payload := vaultKVWriteRequest{
		Data: map[string]interface{}{
			"secret":           base64.StdEncoding.EncodeToString(plaintext),
			"rotation_version": ref.RotationVersion,
			"credential_type":  ref.CredentialType,
			"username":         ref.Username,
			"domain_or_host":   ref.DomainOrHost,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("vault: failed to marshal store request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s/data/%s", h.addr, h.kvMountPath, path)
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPut, url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("vault: failed to build store request: %w", err)
	}
	req.Header.Set("X-Vault-Token", h.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse (Rule 5.1)
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vault: store secret returned status %d for ref %s", resp.StatusCode, ref.OpaqueID)
	}
	return nil
}

// ResolveSecret retrieves and decodes a secret from HashiCorp Vault KV v2.
func (h *HashiCorpVaultProvider) ResolveSecret(ctx context.Context, ref CredentialRef) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	path := buildVaultPath(ref)
	url := fmt.Sprintf("%s/v1/%s/data/%s", h.addr, h.kvMountPath, path)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to build resolve request: %w", err)
	}
	req.Header.Set("X-Vault-Token", h.token)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("%w: ref=%s", ErrSecretNotFound, ref.OpaqueID)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("vault: resolve secret returned status %d for ref %s", resp.StatusCode, ref.OpaqueID)
	}

	// Limit response body to 1 MB (Rule 1.1: boundary validation)
	limitedReader := io.LimitReader(resp.Body, 1<<20)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to read resolve response: %w", err)
	}

	var vaultResp vaultKVReadResponse
	if err := json.Unmarshal(bodyBytes, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: failed to parse resolve response: %w", err)
	}

	secretB64, ok := vaultResp.Data.Data["secret"].(string)
	if !ok || secretB64 == "" {
		return nil, fmt.Errorf("%w: ref=%s (empty secret field)", ErrSecretNotFound, ref.OpaqueID)
	}

	plaintext, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to decode secret from base64: %w", err)
	}

	return plaintext, nil
}

// RotateSecret atomically rotates a credential using KV v2 CAS (Check-And-Set).
// The new secret is stored at a new version; the old version is preserved for
// audit purposes but the latest read always returns the rotated secret.
func (h *HashiCorpVaultProvider) RotateSecret(ctx context.Context, ref CredentialRef, newPlaintext []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	path := buildVaultPath(ref)

	// Step 1: Read current version for CAS
	readURL := fmt.Sprintf("%s/v1/%s/data/%s", h.addr, h.kvMountPath, path)
	readCtx, readCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readCancel()

	readReq, err := http.NewRequestWithContext(readCtx, http.MethodGet, readURL, nil)
	if err != nil {
		return fmt.Errorf("vault: failed to build rotation read request: %w", err)
	}
	readReq.Header.Set("X-Vault-Token", h.token)

	readResp, err := h.client.Do(readReq)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer readResp.Body.Close()

	currentVersion := 0
	if readResp.StatusCode == http.StatusOK {
		limitedReader := io.LimitReader(readResp.Body, 1<<20)
		body, readErr := io.ReadAll(limitedReader)
		if readErr == nil {
			var vaultResp vaultKVReadResponse
			if jsonErr := json.Unmarshal(body, &vaultResp); jsonErr == nil {
				currentVersion = vaultResp.Data.Metadata.Version
			}
		}
	} else {
		_, _ = io.Copy(io.Discard, readResp.Body)
	}

	// Step 2: Write new version with CAS
	casVersion := currentVersion
	payload := vaultKVWriteRequest{
		Options: &vaultKVWriteOptions{CAS: &casVersion},
		Data: map[string]interface{}{
			"secret":           base64.StdEncoding.EncodeToString(newPlaintext),
			"rotation_version": ref.RotationVersion + 1,
			"credential_type":  ref.CredentialType,
			"username":         ref.Username,
			"domain_or_host":   ref.DomainOrHost,
		},
	}

	writeBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("vault: failed to marshal rotation write request: %w", err)
	}

	writeURL := fmt.Sprintf("%s/v1/%s/data/%s", h.addr, h.kvMountPath, path)
	writeCtx, writeCancel := context.WithTimeout(ctx, 10*time.Second)
	defer writeCancel()

	writeReq, err := http.NewRequestWithContext(writeCtx, http.MethodPut, writeURL, strings.NewReader(string(writeBody)))
	if err != nil {
		return fmt.Errorf("vault: failed to build rotation write request: %w", err)
	}
	writeReq.Header.Set("X-Vault-Token", h.token)
	writeReq.Header.Set("Content-Type", "application/json")

	writeResp, err := h.client.Do(writeReq)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer writeResp.Body.Close()
	_, _ = io.Copy(io.Discard, writeResp.Body)

	if writeResp.StatusCode < 200 || writeResp.StatusCode >= 300 {
		return fmt.Errorf("vault: rotation CAS write returned status %d for ref %s", writeResp.StatusCode, ref.OpaqueID)
	}
	return nil
}

// DeleteSecret permanently removes the secret and all version history.
func (h *HashiCorpVaultProvider) DeleteSecret(ctx context.Context, ref CredentialRef) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	path := buildVaultPath(ref)
	url := fmt.Sprintf("%s/v1/%s/metadata/%s", h.addr, h.kvMountPath, path)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("vault: failed to build delete request: %w", err)
	}
	req.Header.Set("X-Vault-Token", h.token)

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: ref=%s", ErrSecretNotFound, ref.OpaqueID)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vault: delete secret returned status %d for ref %s", resp.StatusCode, ref.OpaqueID)
	}
	return nil
}

// HealthCheck verifies connectivity to the HashiCorp Vault cluster.
func (h *HashiCorpVaultProvider) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/v1/sys/health", h.addr)

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to build health check: %v", ErrProviderUnavailable, err)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: health check failed: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Vault returns 200 (initialized, unsealed, active) or 429/472/473/501/503
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: vault health status %d", ErrProviderUnavailable, resp.StatusCode)
	}
	return nil
}
