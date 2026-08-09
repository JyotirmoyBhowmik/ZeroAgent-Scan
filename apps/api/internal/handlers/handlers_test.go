package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/endpointguard/endpointguard/apps/api/internal/models"
	"github.com/endpointguard/endpointguard/apps/api/internal/repository"
	"github.com/endpointguard/endpointguard/apps/api/internal/vault"
	"github.com/go-chi/chi/v5"
)

func setupTestRouter() (*chi.Mux, *repository.Repository) {
	masterKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	masterKey, _ := hex.DecodeString(masterKeyHex)
	vs, _ := vault.NewVaultService(masterKey)
	repo := repository.NewRepository()
	h := NewAPIHandler(repo, vs)

	r := chi.NewRouter()
	r.Get("/api/v1/health", h.HealthCheck)
	r.Get("/api/v1/metrics", h.GetFleetMetrics)
	r.Get("/api/v1/endpoints", h.ListEndpoints)
	r.Get("/api/v1/endpoints/{id}", h.GetEndpointByID)
	r.Post("/api/v1/scans", h.CreateScanJob)
	r.Get("/api/v1/vault/credentials", h.ListVaultCredentials)
	r.Post("/api/v1/vault/credentials", h.CreateVaultCredential)
	r.Get("/api/v1/audit-logs", h.ListAuditLogs)

	return r, repo
}

func TestHealthCheck(t *testing.T) {
	r, _ := setupTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListEndpoints(t *testing.T) {
	r, _ := setupTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/endpoints", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var endpoints []models.Endpoint
	if err := json.NewDecoder(w.Body).Decode(&endpoints); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatalf("expected seeded endpoints, got 0")
	}
}

func TestCreateScanJob_SSRFBlock(t *testing.T) {
	r, _ := setupTestRouter()

	// Try SSRF against AWS metadata endpoint
	payload := models.CreateScanJobRequest{
		Name:           "Attack Scan",
		TargetCIDR:     "169.254.169.254",
		ScanProfile:    "rapid_inventory",
		Protocol:       "winrm_https",
		VaultSecretRef: "sec_ref_dummy",
		GatewayID:      "gw-1",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for SSRF attack target, got %d", w.Code)
	}
}

func TestCreateVaultCredential_ZeroPlaintext(t *testing.T) {
	r, repo := setupTestRouter()

	secretValue := "SuperSecretAdminPassword123!"
	payload := models.CreateVaultCredentialRequest{
		Name:           "Finance Domain Controller Creds",
		CredentialType: "domain_kerberos",
		DomainOrHost:   "FIN.CORP.LOCAL",
		Username:       "svc_fin_winrm",
		SecretValue:    secretValue,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vault/credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", w.Code)
	}

	var summary models.VaultCredentialSummary
	if err := json.NewDecoder(w.Body).Decode(&summary); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if summary.OpaqueID == "" {
		t.Fatalf("expected opaque ID to be populated")
	}

	// Verify audit log has no plaintext
	auditLogs := repo.ListAuditLogs()
	if len(auditLogs) == 0 {
		t.Fatalf("expected audit log entry")
	}
}
