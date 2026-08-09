package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/endpointguard/endpointguard/apps/api/internal/middleware"
	"github.com/endpointguard/endpointguard/apps/api/internal/models"
	"github.com/endpointguard/endpointguard/apps/api/internal/repository"
	"github.com/endpointguard/endpointguard/apps/api/internal/vault"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type APIHandler struct {
	repo         *repository.Repository
	vaultService *vault.VaultService
}

func NewAPIHandler(repo *repository.Repository, vs *vault.VaultService) *APIHandler {
	return &APIHandler{
		repo:         repo,
		vaultService: vs,
	}
}

// ---------------------------------------------------------------------------
// Endpoints & Hardware Inventory
// ---------------------------------------------------------------------------

func (h *APIHandler) ListEndpoints(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	osFilter := r.URL.Query().Get("os")
	statusFilter := r.URL.Query().Get("status")

	endpoints := h.repo.ListEndpoints(search, osFilter, statusFilter)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(endpoints)
}

func (h *APIHandler) GetEndpointByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if strings.TrimSpace(id) == "" {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "INVALID_ENDPOINT_ID", "Endpoint ID must not be empty")
		return
	}

	detail, err := h.repo.GetEndpointDetail(id)
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusNotFound, "ENDPOINT_NOT_FOUND", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(detail)
}

// ---------------------------------------------------------------------------
// Fleet Metrics Overview
// ---------------------------------------------------------------------------

func (h *APIHandler) GetFleetMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := h.repo.GetFleetMetrics()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metrics)
}

// ---------------------------------------------------------------------------
// Agentless Scans Orchestrator
// ---------------------------------------------------------------------------

func (h *APIHandler) CreateScanJob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) // Max 1MB payload

	var req models.CreateScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "MALFORMED_JSON", "Unable to parse scan request payload")
		return
	}

	// Boundary validation
	if strings.TrimSpace(req.Name) == "" {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "MISSING_FIELD", "Scan job name is required")
		return
	}

	// SSRF Subnet validation
	valid, errMsg := middleware.ValidateScanTargetSubnet(req.TargetCIDR)
	if !valid {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "INVALID_TARGET_SUBNET", errMsg)
		return
	}

	if strings.TrimSpace(req.VaultSecretRef) == "" {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "MISSING_SECRET_REF", "A valid vault secret reference (sec_ref_*) is required")
		return
	}

	job := h.repo.CreateScanJob(req)

	// Log audit event
	corrID := middleware.GetCorrelationID(r.Context())
	h.repo.AddAuditLog(models.SecurityAuditLog{
		ID:            uuid.New().String(),
		CorrelationID: corrID,
		Timestamp:     time.Now().UTC(),
		Actor:         "admin_operator",
		Action:        "SCAN_JOB_LAUNCHED",
		ResourceType:  "scan_job",
		ResourceID:    job.ID,
		Status:        "SUCCESS",
		IPAddress:     r.RemoteAddr,
		Details:       map[string]interface{}{"target_cidr": req.TargetCIDR, "profile": req.ScanProfile},
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(job)
}

func (h *APIHandler) ListScanJobs(w http.ResponseWriter, r *http.Request) {
	scans := h.repo.ListScanJobs()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scans)
}

func (h *APIHandler) GetScanJobByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := h.repo.GetScanJob(id)
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusNotFound, "SCAN_JOB_NOT_FOUND", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(job)
}

// ---------------------------------------------------------------------------
// Collector Gateways & mTLS Heartbeat
// ---------------------------------------------------------------------------

func (h *APIHandler) ListGateways(w http.ResponseWriter, r *http.Request) {
	gateways := h.repo.ListGateways()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(gateways)
}

func (h *APIHandler) GatewayHeartbeat(w http.ResponseWriter, r *http.Request) {
	type HeartbeatReq struct {
		GatewayCode string `json:"gateway_code"`
		LatencyMs   int    `json:"latency_ms"`
	}

	var req HeartbeatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "MALFORMED_JSON", "Invalid heartbeat payload")
		return
	}

	h.repo.UpdateGatewayHeartbeat(req.GatewayCode, req.LatencyMs)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged"})
}

// ---------------------------------------------------------------------------
// Credential Vault Management (Zero Plaintext Persistence)
// ---------------------------------------------------------------------------

func (h *APIHandler) ListVaultCredentials(w http.ResponseWriter, r *http.Request) {
	creds := h.repo.ListVaultCredentials()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

func (h *APIHandler) CreateVaultCredential(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req models.CreateVaultCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "MALFORMED_JSON", "Unable to parse credential payload")
		return
	}

	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.SecretValue) == "" {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Name, Username, and SecretValue are strictly required")
		return
	}

	// Encrypt secret with AES-256-GCM envelope
	ciphertext, nonce, salt, err := h.vaultService.EncryptSecret(req.SecretValue)
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusInternalServerError, "VAULT_ENCRYPTION_FAILED", "Failed to encrypt secret into vault envelope")
		return
	}

	// Generate opaque reference identifier
	opaqueID := vault.GenerateOpaqueID(req.CredentialType)
	now := time.Now().UTC()

	summary := &models.VaultCredentialSummary{
		ID:             uuid.New().String(),
		OpaqueID:       opaqueID,
		Name:           req.Name,
		CredentialType: req.CredentialType,
		DomainOrHost:   req.DomainOrHost,
		Username:       req.Username,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	h.repo.AddVaultCredential(summary)

	// Audit log (Secret value is explicitly NEVER logged)
	corrID := middleware.GetCorrelationID(r.Context())
	h.repo.AddAuditLog(models.SecurityAuditLog{
		ID:            uuid.New().String(),
		CorrelationID: corrID,
		Timestamp:     now,
		Actor:         "security_officer",
		Action:        "VAULT_CREDENTIAL_ENCRYPTED_AND_SAVED",
		ResourceType:  "vault_credential",
		ResourceID:    opaqueID,
		Status:        "SUCCESS",
		IPAddress:     r.RemoteAddr,
		Details: map[string]interface{}{
			"opaque_id":       opaqueID,
			"credential_type": req.CredentialType,
			"ciphertext_len":  len(ciphertext),
			"nonce_len":       len(nonce),
			"salt_len":        len(salt),
		},
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(summary)
}

// ---------------------------------------------------------------------------
// Security Audit Logs (OWASP ASVS Level 2)
// ---------------------------------------------------------------------------

func (h *APIHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	logs := h.repo.ListAuditLogs()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

// ---------------------------------------------------------------------------
// Health Check Endpoint
// ---------------------------------------------------------------------------

func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"service":   "endpointguard-api",
		"version":   "1.0.0",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
