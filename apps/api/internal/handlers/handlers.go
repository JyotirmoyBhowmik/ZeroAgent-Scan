package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/auth"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/compliance"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/drift"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/reports"
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
	reportGen        *reports.ReportGenerator
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
		reportGen:        reports.NewReportGenerator(repo, findingRepo, compRepo, driftRepo),
	}
}

// ---------------------------------------------------------------------------
// 1. Hosts & Hardware Inventory
// ---------------------------------------------------------------------------

func (h *APIHandler) ListEndpoints(w http.ResponseWriter, r *http.Request) {
	search := middleware.SanitizeText(r.URL.Query().Get("search"))
	osFilter := middleware.SanitizeText(r.URL.Query().Get("os"))
	statusFilter := middleware.SanitizeText(r.URL.Query().Get("status"))

	endpoints := h.repo.ListEndpoints(search, osFilter, statusFilter)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(endpoints)
}

func (h *APIHandler) GetEndpointByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if strings.TrimSpace(id) == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "INVALID_ENDPOINT_ID", "Endpoint ID must not be empty", nil)
		return
	}

	detail, err := h.repo.GetEndpointDetail(id)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "ENDPOINT_NOT_FOUND", err.Error(), nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(detail)
}

// ---------------------------------------------------------------------------
// 2. Host Snapshots (Keyset Cursor Pagination)
// ---------------------------------------------------------------------------

func (h *APIHandler) ListSnapshots(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	hostID := r.URL.Query().Get("host_id")
	cursor := r.URL.Query().Get("cursor")

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	req := repository.KeysetPageRequest{
		Cursor: cursor,
		Limit:  limit,
	}

	resp, err := h.repo.ListSnapshotsKeyset(tenantID, hostID, req)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "SNAPSHOT_QUERY_ERROR", "Failed to retrieve snapshots", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *APIHandler) GetSnapshotByID(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	snap, exists := h.repo.GetSnapshotByID(tenantID, id)
	if !exists {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "SNAPSHOT_NOT_FOUND", "Snapshot not found", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

// ---------------------------------------------------------------------------
// 3. Fleet Metrics Overview
// ---------------------------------------------------------------------------

func (h *APIHandler) GetFleetMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := h.repo.GetFleetMetrics()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metrics)
}

// ---------------------------------------------------------------------------
// 4. Agentless Scans Orchestrator
// ---------------------------------------------------------------------------

func (h *APIHandler) CreateScanJob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) // Max 1MB payload

	var req models.CreateScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MALFORMED_JSON", "Unable to parse scan request payload", nil)
		return
	}

	// Boundary validation
	if strings.TrimSpace(req.Name) == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MISSING_FIELD", "Scan job name is required", nil)
		return
	}

	// SSRF Subnet validation
	valid, errMsg := middleware.ValidateScanTargetSubnet(req.TargetCIDR)
	if !valid {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "INVALID_TARGET_SUBNET", errMsg, nil)
		return
	}

	if strings.TrimSpace(req.VaultSecretRef) == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MISSING_SECRET_REF", "A valid vault secret reference (sec_ref_*) is required", nil)
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
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "SCAN_JOB_NOT_FOUND", err.Error(), nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(job)
}

func (h *APIHandler) CancelScanJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := h.repo.GetScanJob(id)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "SCAN_JOB_NOT_FOUND", "Scan job not found", nil)
		return
	}

	job.Status = "cancelled"
	now := time.Now().UTC()
	job.CompletedAt = &now

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "CANCELLED",
		"job_id":  id,
		"message": "Scan job has been aborted",
	})
}

// ---------------------------------------------------------------------------
// 5. Collector Gateways & mTLS Lifecycle
// ---------------------------------------------------------------------------

func (h *APIHandler) ListGateways(w http.ResponseWriter, r *http.Request) {
	gateways := h.repo.ListGateways()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(gateways)
}

func (h *APIHandler) RegisterGateway(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GatewayCode string `json:"gateway_code"`
		Name        string `json:"name"`
		SubnetCIDR  string `json:"subnet_cidr"`
		CSRPEM      string `json:"csr_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MALFORMED_JSON", "Invalid registration payload", nil)
		return
	}

	if req.GatewayCode == "" || req.SubnetCIDR == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MISSING_FIELD", "Gateway code and subnet CIDR are required", nil)
		return
	}

	gw := &models.CollectorGateway{
		ID:                  uuid.New().String(),
		GatewayCode:         req.GatewayCode,
		Name:                req.Name,
		SubnetCIDR:          req.SubnetCIDR,
		MTLSCertFingerprint: "SHA256:PENDING_OPERATOR_APPROVAL",
		Status:              "pending_approval",
		Version:             "v1.2.0",
		LastHeartbeatAt:     time.Now().UTC(),
		CreatedAt:           time.Now().UTC(),
	}
	h.repo.AddGateway(gw)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(gw)
}

func (h *APIHandler) ApproveGateway(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	gateways := h.repo.ListGateways()
	var target *models.CollectorGateway
	for _, gw := range gateways {
		if gw.ID == id || gw.GatewayCode == id {
			target = &gw
			break
		}
	}
	if target == nil {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "GATEWAY_NOT_FOUND", "Gateway not found", nil)
		return
	}

	target.Status = "healthy"
	target.MTLSCertFingerprint = "SHA256:APPROVED_MTLS_CERT_" + uuid.New().String()[:16]

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "APPROVED",
		"gateway_id":  id,
		"fingerprint": target.MTLSCertFingerprint,
	})
}

func (h *APIHandler) GatewayHeartbeat(w http.ResponseWriter, r *http.Request) {
	type HeartbeatReq struct {
		GatewayCode string `json:"gateway_code"`
		LatencyMs   int    `json:"latency_ms"`
	}

	var req HeartbeatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MALFORMED_JSON", "Invalid heartbeat payload", nil)
		return
	}

	h.repo.UpdateGatewayHeartbeat(req.GatewayCode, req.LatencyMs)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged"})
}

// ---------------------------------------------------------------------------
// 6. Credential Vault Management (Zero Plaintext Persistence)
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
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MALFORMED_JSON", "Unable to parse credential payload", nil)
		return
	}

	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.SecretValue) == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Name, Username, and SecretValue are strictly required", nil)
		return
	}

	tenantID := auth.GetTenantID(r.Context())

	ref := vault.CredentialRef{
		TenantID:       tenantID,
		CredentialType: req.CredentialType,
		DomainOrHost:   req.DomainOrHost,
		Username:       req.Username,
	}

	opaqueID, err := h.vaultManager.StoreCredential(r.Context(), ref, []byte(req.SecretValue))
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "VAULT_STORE_FAILED", "Failed to store credential in vault", nil)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(summary)
}

func (h *APIHandler) RotateVaultCredential(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		NewSecretValue string `json:"new_secret_value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewSecretValue == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "INVALID_BODY", "new_secret_value is required", nil)
		return
	}

	tenantID := auth.GetTenantID(r.Context())
	ref := vault.CredentialRef{
		OpaqueID: id,
		TenantID: tenantID,
	}
	if err := h.vaultManager.RotateCredential(r.Context(), ref, []byte(req.NewSecretValue)); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "ROTATION_FAILED", "Failed to rotate credential secret", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ROTATED",
		"opaque_id":   id,
		"rotated_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// 7. Security Audit Logs (Keyset Keyset Pagination)
// ---------------------------------------------------------------------------

func (h *APIHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	cursor := r.URL.Query().Get("cursor")

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	req := repository.KeysetPageRequest{
		Cursor: cursor,
		Limit:  limit,
	}

	resp, err := h.repo.ListAuditLogsKeyset(tenantID, req)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "AUDIT_QUERY_ERROR", "Failed to retrieve audit logs", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// 8. Vulnerability Findings (NVD CVE + CISA KEV Prioritized)
// ---------------------------------------------------------------------------

func (h *APIHandler) ListVulnerabilityFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())

	opts := vulnscan.FindingQueryOptions{
		Severity:   r.URL.Query().Get("severity"),
		EndpointID: r.URL.Query().Get("endpoint_id"),
		Search:     r.URL.Query().Get("cve_id"),
	}

	if kevStr := r.URL.Query().Get("is_kev"); kevStr != "" {
		isKev := strings.EqualFold(kevStr, "true") || kevStr == "1"
		opts.IsKEV = &isKev
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

	findings, err := h.findingRepo.QueryFindings(tenantID, opts)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "FINDINGS_QUERY_ERROR", "Failed to query vulnerability findings", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(findings)
}

func (h *APIHandler) GetVulnerabilityFindingByID(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	findingID := chi.URLParam(r, "id")

	finding, err := h.findingRepo.GetFindingByID(tenantID, findingID)
	if err != nil || finding == nil {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "FINDING_NOT_FOUND", "Vulnerability finding not found", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(finding)
}

// ---------------------------------------------------------------------------
// 9. Compliance Frameworks & CIS Results
// ---------------------------------------------------------------------------

func (h *APIHandler) ListComplianceFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := h.complianceRepo.ListFrameworks()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(frameworks)
}

func (h *APIHandler) ListComplianceRules(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if code == "" {
		code = compliance.CISWin11FrameworkCode
	}

	rules := h.complianceRepo.ListRulesByFramework(code)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules)
}

func (h *APIHandler) GetHostComplianceResults(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	hostID := chi.URLParam(r, "host_id")

	evals, score, err := h.complianceRepo.GetHostEvaluations(tenantID, hostID)
	if err != nil || score == nil {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "EVALUATION_NOT_FOUND", "No compliance evaluations found for host", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"score":       score,
		"evaluations": evals,
	})
}

func (h *APIHandler) GetTenantComplianceSummary(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	frameworkCode := r.URL.Query().Get("framework")
	if frameworkCode == "" {
		frameworkCode = compliance.CISWin11FrameworkCode
	}

	summary, err := h.complianceRepo.GetTenantSummary(tenantID, frameworkCode)
	if err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "SUMMARY_ERROR", "Failed to compute tenant compliance summary", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

// ---------------------------------------------------------------------------
// 10. Configuration Drift Events & Rule-Based Alerts
// ---------------------------------------------------------------------------

func (h *APIHandler) ListDriftEvents(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())

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
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "DRIFT_QUERY_ERROR", "Failed to retrieve drift events", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *APIHandler) AcknowledgeDriftEvent(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	eventID := chi.URLParam(r, "id")

	var req struct {
		AcknowledgedBy string `json:"acknowledged_by"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.AcknowledgedBy == "" {
		req.AcknowledgedBy = "SecOps Engineer"
	}

	if err := h.driftRepo.AcknowledgeDriftEvent(tenantID, eventID, req.AcknowledgedBy); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusNotFound, "DRIFT_NOT_FOUND", "Drift event not found", nil)
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
	tenantID := auth.GetTenantID(r.Context())
	rules := h.driftRepo.ListAlertRules(tenantID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules)
}

func (h *APIHandler) CreateAlertRule(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())

	var rule drift.AlertRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "INVALID_BODY", "Failed to parse alert rule payload", nil)
		return
	}

	if rule.Name == "" || rule.WebhookURL == "" {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "MISSING_FIELDS", "Rule name and webhook_url are required", nil)
		return
	}

	rule.TenantID = tenantID
	if rule.SecretKey == "" {
		rule.SecretKey = uuid.New().String()
	}
	if rule.SuppressionWindowHours <= 0 {
		rule.SuppressionWindowHours = 4
	}
	rule.IsActive = true

	if err := h.driftRepo.SaveAlertRule(rule); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "SAVE_ERROR", "Failed to save alert rule", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(rule)
}

func (h *APIHandler) ListWebhookDeliveryLogs(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())
	logs := h.driftRepo.ListDeliveryLogs(tenantID, 50)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

// ---------------------------------------------------------------------------
// 11. Reports Generation (Executive, Compliance, Vulnerabilities)
// ---------------------------------------------------------------------------

func (h *APIHandler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.GetTenantID(r.Context())

	var req reports.GenerateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Failed to parse report request", nil)
		return
	}

	switch req.Type {
	case reports.ReportExecutiveSummary, "":
		rep, err := h.reportGen.GenerateExecutiveSummary(tenantID)
		if err != nil {
			middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "REPORT_ERROR", err.Error(), nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)

	case reports.ReportComplianceAudit:
		rep, err := h.reportGen.GenerateComplianceAudit(tenantID, req.FrameworkCode)
		if err != nil {
			middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "REPORT_ERROR", err.Error(), nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)

	case reports.ReportVulnerabilityPosture:
		rep, err := h.reportGen.GenerateVulnerabilityPosture(tenantID)
		if err != nil {
			middleware.WriteProblemDetails(w, r, http.StatusInternalServerError, "REPORT_ERROR", err.Error(), nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)

	default:
		middleware.WriteProblemDetails(w, r, http.StatusBadRequest, "UNKNOWN_REPORT_TYPE", "Report type must be EXECUTIVE_SUMMARY, COMPLIANCE_AUDIT, or VULNERABILITY_POSTURE", nil)
	}
}

// ---------------------------------------------------------------------------
// 12. Health Check Endpoint
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
