package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/compliance"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/drift"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vault"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vulnscan"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type APIHandler struct {
	repo             *repository.Repository
	vaultManager     *vault.VaultManager
	findingRepo      vulnscan.FindingRepository
	complianceRepo   compliance.ComplianceRepository
	complianceEngine *compliance.ComplianceEngine
	driftRepo        drift.DriftRepository
	driftWorker      *drift.DriftWorker
}

func NewAPIHandler(
	repo *repository.Repository,
	vm *vault.VaultManager,
	findingRepo vulnscan.FindingRepository,
	compRepo compliance.ComplianceRepository,
	driftRepo drift.DriftRepository,
) *APIHandler {
	if findingRepo == nil {
		findingRepo = vulnscan.NewMemoryFindingRepository()
	}
	if compRepo == nil {
		compRepo = compliance.NewMemoryComplianceRepository()
	}
	if driftRepo == nil {
		driftRepo = drift.NewMemoryDriftRepository()
	}
	return &APIHandler{
		repo:             repo,
		vaultManager:     vm,
		findingRepo:      findingRepo,
		complianceRepo:   compRepo,
		complianceEngine: compliance.NewComplianceEngine(compRepo),
		driftRepo:        driftRepo,
		driftWorker:      drift.NewDriftWorker(driftRepo, nil),
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

	// Tenant ID: in production this comes from the authenticated JWT/session.
	// For local dev, use a default tenant.
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default-tenant"
	}

	// Store credential via VaultManager (handles encryption, opaque ID generation,
	// and secure plaintext zeroing internally)
	ref := vault.CredentialRef{
		TenantID:       tenantID,
		CredentialType: req.CredentialType,
		DomainOrHost:   req.DomainOrHost,
		Username:       req.Username,
	}

	opaqueID, err := h.vaultManager.StoreCredential(r.Context(), ref, []byte(req.SecretValue))
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusInternalServerError, "VAULT_STORE_FAILED", "Failed to store credential in vault")
		return
	}

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
			"provider":        h.vaultManager.ProviderName(),
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
// Vulnerability Findings (NVD CVE + CISA KEV Prioritized)
// ---------------------------------------------------------------------------

func (h *APIHandler) ListVulnerabilityFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	opts := vulnscan.FindingQueryOptions{
		Severity:   r.URL.Query().Get("severity"),
		Status:     r.URL.Query().Get("status"),
		EndpointID: r.URL.Query().Get("endpoint_id"),
		Search:     r.URL.Query().Get("search"),
	}

	if isKEVStr := r.URL.Query().Get("is_kev"); isKEVStr != "" {
		val := strings.EqualFold(isKEVStr, "true") || isKEVStr == "1"
		opts.IsKEV = &val
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			opts.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			opts.Offset = offset
		}
	}

	res, err := h.findingRepo.QueryFindings(tenantID, opts)
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusInternalServerError, "QUERY_ERROR", "Failed to retrieve vulnerability findings")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *APIHandler) GetVulnerabilityFindingByID(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	id := chi.URLParam(r, "id")
	if strings.TrimSpace(id) == "" {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "INVALID_ID", "Finding ID must not be empty")
		return
	}

	finding, err := h.findingRepo.GetFindingByID(tenantID, id)
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusNotFound, "FINDING_NOT_FOUND", "Vulnerability finding not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(finding)
}

// ---------------------------------------------------------------------------
// Compliance Frameworks, Rules, and Evaluations
// ---------------------------------------------------------------------------

func (h *APIHandler) ListComplianceFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := h.complianceRepo.ListFrameworks()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(frameworks)
}

func (h *APIHandler) ListComplianceRules(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if strings.TrimSpace(code) == "" {
		code = compliance.CISWin11FrameworkCode
	}

	rules := h.complianceRepo.ListRulesByFramework(code)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules)
}

func (h *APIHandler) GetHostComplianceResults(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	hostID := chi.URLParam(r, "host_id")
	if strings.TrimSpace(hostID) == "" {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "INVALID_HOST_ID", "Host ID must not be empty")
		return
	}

	evals, score, err := h.complianceRepo.GetHostEvaluations(tenantID, hostID)
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusNotFound, "EVALUATIONS_NOT_FOUND", "No compliance evaluations found for host")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"host_id":     hostID,
		"score":       score,
		"evaluations": evals,
	})
}

func (h *APIHandler) GetTenantComplianceSummary(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	frameworkCode := r.URL.Query().Get("framework")
	if frameworkCode == "" {
		frameworkCode = compliance.CISWin11FrameworkCode
	}

	summary, err := h.complianceRepo.GetTenantSummary(tenantID, frameworkCode)
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusInternalServerError, "SUMMARY_ERROR", "Failed to compute tenant compliance summary")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

// ---------------------------------------------------------------------------
// Configuration Drift Events & Rule-Based Alerts
// ---------------------------------------------------------------------------

func (h *APIHandler) ListDriftEvents(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	opts := drift.DriftQueryOptions{
		Severity: r.URL.Query().Get("severity"),
		Category: r.URL.Query().Get("category"),
		HostID:   r.URL.Query().Get("host_id"),
	}

	if unackStr := r.URL.Query().Get("unacknowledged"); unackStr != "" {
		isUnack := strings.EqualFold(unackStr, "true") || unackStr == "1"
		val := !isUnack
		opts.IsAcknowledged = &val
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			opts.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			opts.Offset = offset
		}
	}

	res, err := h.driftRepo.QueryDriftEvents(tenantID, opts)
	if err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusInternalServerError, "DRIFT_QUERY_ERROR", "Failed to retrieve drift events")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *APIHandler) AcknowledgeDriftEvent(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	eventID := chi.URLParam(r, "id")
	if strings.TrimSpace(eventID) == "" {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "INVALID_EVENT_ID", "Event ID must not be empty")
		return
	}

	var req struct {
		AcknowledgedBy string `json:"acknowledged_by"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.AcknowledgedBy == "" {
		req.AcknowledgedBy = "SecOps Engineer"
	}

	if err := h.driftRepo.AcknowledgeDriftEvent(tenantID, eventID, req.AcknowledgedBy); err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusNotFound, "DRIFT_NOT_FOUND", "Drift event not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ACKNOWLEDGED",
		"event_id":        eventID,
		"acknowledged_by": req.AcknowledgedBy,
		"acknowledged_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *APIHandler) ListAlertRules(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	rules := h.driftRepo.ListAlertRules(tenantID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules)
}

func (h *APIHandler) CreateAlertRule(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	var rule drift.AlertRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "INVALID_BODY", "Failed to parse alert rule payload")
		return
	}

	if rule.Name == "" || rule.WebhookURL == "" {
		middleware.WriteSanitizedError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "Rule name and webhook_url are required")
		return
	}

	rule.TenantID = tenantID
	if rule.SecretKey == "" {
		rule.SecretKey = uuid.New().String() // Auto-generate HMAC key if not provided
	}
	if rule.SuppressionWindowHours <= 0 {
		rule.SuppressionWindowHours = 4
	}
	rule.IsActive = true

	if err := h.driftRepo.SaveAlertRule(rule); err != nil {
		middleware.WriteSanitizedError(w, r, http.StatusInternalServerError, "SAVE_ERROR", "Failed to save alert rule")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(rule)
}

func (h *APIHandler) ListWebhookDeliveryLogs(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "tenant-default-01"
	}

	logs := h.driftRepo.ListDeliveryLogs(tenantID, 50)
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
