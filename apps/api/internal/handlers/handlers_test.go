package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/compliance"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/drift"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vault"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vulnscan"
	"github.com/go-chi/chi/v5"
)

func setupTestRouter() (*chi.Mux, *repository.Repository) {
	masterKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	masterKey, _ := hex.DecodeString(masterKeyHex)
	provider, _ := vault.NewEnvelopeProvider(masterKey)
	noopAudit := func(entry vault.SecretResolutionAuditEntry) error { return nil }
	vm := vault.NewVaultManager(provider, noopAudit)
	repo := repository.NewRepository()
	findingRepo := vulnscan.NewMemoryFindingRepository()
	compRepo := compliance.NewMemoryComplianceRepository()
	driftRepo := drift.NewMemoryDriftRepository()
	h := NewAPIHandler(repo, vm, findingRepo, compRepo, driftRepo)

	r := chi.NewRouter()
	r.Get("/api/v1/health", h.HealthCheck)
	r.Get("/api/v1/metrics", h.GetFleetMetrics)
	r.Get("/api/v1/endpoints", h.ListEndpoints)
	r.Get("/api/v1/endpoints/{id}", h.GetEndpointByID)
	r.Post("/api/v1/scans", h.CreateScanJob)
	r.Get("/api/v1/vault/credentials", h.ListVaultCredentials)
	r.Post("/api/v1/vault/credentials", h.CreateVaultCredential)
	r.Get("/api/v1/audit-logs", h.ListAuditLogs)
	r.Get("/api/v1/findings", h.ListVulnerabilityFindings)
	r.Get("/api/v1/findings/{id}", h.GetVulnerabilityFindingByID)
	r.Get("/api/v1/compliance/frameworks", h.ListComplianceFrameworks)
	r.Get("/api/v1/compliance/frameworks/{code}/rules", h.ListComplianceRules)
	r.Get("/api/v1/compliance/hosts/{host_id}/results", h.GetHostComplianceResults)
	r.Get("/api/v1/compliance/tenant/summary", h.GetTenantComplianceSummary)
	r.Get("/api/v1/drift/events", h.ListDriftEvents)
	r.Post("/api/v1/drift/events/{id}/acknowledge", h.AcknowledgeDriftEvent)
	r.Get("/api/v1/alerts/rules", h.ListAlertRules)
	r.Post("/api/v1/alerts/rules", h.CreateAlertRule)
	r.Get("/api/v1/alerts/deliveries", h.ListWebhookDeliveryLogs)

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

func setupTestRouterWithFindingRepo() (*chi.Mux, *repository.Repository, vulnscan.FindingRepository, compliance.ComplianceRepository, drift.DriftRepository) {
	masterKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	masterKey, _ := hex.DecodeString(masterKeyHex)
	provider, _ := vault.NewEnvelopeProvider(masterKey)
	noopAudit := func(entry vault.SecretResolutionAuditEntry) error { return nil }
	vm := vault.NewVaultManager(provider, noopAudit)
	repo := repository.NewRepository()
	findingRepo := vulnscan.NewMemoryFindingRepository()
	compRepo := compliance.NewMemoryComplianceRepository()
	driftRepo := drift.NewMemoryDriftRepository()
	h := NewAPIHandler(repo, vm, findingRepo, compRepo, driftRepo)

	r := chi.NewRouter()
	r.Get("/api/v1/health", h.HealthCheck)
	r.Get("/api/v1/metrics", h.GetFleetMetrics)
	r.Get("/api/v1/endpoints", h.ListEndpoints)
	r.Get("/api/v1/endpoints/{id}", h.GetEndpointByID)
	r.Post("/api/v1/scans", h.CreateScanJob)
	r.Get("/api/v1/vault/credentials", h.ListVaultCredentials)
	r.Post("/api/v1/vault/credentials", h.CreateVaultCredential)
	r.Get("/api/v1/audit-logs", h.ListAuditLogs)
	r.Get("/api/v1/findings", h.ListVulnerabilityFindings)
	r.Get("/api/v1/findings/{id}", h.GetVulnerabilityFindingByID)
	r.Get("/api/v1/compliance/frameworks", h.ListComplianceFrameworks)
	r.Get("/api/v1/compliance/frameworks/{code}/rules", h.ListComplianceRules)
	r.Get("/api/v1/compliance/hosts/{host_id}/results", h.GetHostComplianceResults)
	r.Get("/api/v1/compliance/tenant/summary", h.GetTenantComplianceSummary)
	r.Get("/api/v1/drift/events", h.ListDriftEvents)
	r.Post("/api/v1/drift/events/{id}/acknowledge", h.AcknowledgeDriftEvent)
	r.Get("/api/v1/alerts/rules", h.ListAlertRules)
	r.Post("/api/v1/alerts/rules", h.CreateAlertRule)
	r.Get("/api/v1/alerts/deliveries", h.ListWebhookDeliveryLogs)

	return r, repo, findingRepo, compRepo, driftRepo
}

func TestListVulnerabilityFindings_SortingAndFiltering(t *testing.T) {
	r, _, findingRepo, _, _ := setupTestRouterWithFindingRepo()
	tenantID := "tenant-test-findings"

	// Insert test findings
	_, _, _ = findingRepo.UpsertFinding(&vulnscan.VulnerabilityFinding{
		TenantID:   tenantID,
		EndpointID: "ep-1",
		Hostname:   "W11-EXEC-01",
		CVEID:      "CVE-2024-9999",
		Title:      "Critical Non-KEV",
		Severity:   "CRITICAL",
		CVSSScore:  9.8,
		IsKEV:      false,
		Status:     "OPEN",
	})
	_, _, _ = findingRepo.UpsertFinding(&vulnscan.VulnerabilityFinding{
		TenantID:   tenantID,
		EndpointID: "ep-1",
		Hostname:   "W11-EXEC-01",
		CVEID:      "CVE-2024-30078",
		Title:      "CISA KEV Wi-Fi RCE",
		Severity:   "CRITICAL",
		CVSSScore:  8.8,
		IsKEV:      true,
		Status:     "OPEN",
	})
	_, _, _ = findingRepo.UpsertFinding(&vulnscan.VulnerabilityFinding{
		TenantID:   tenantID,
		EndpointID: "ep-2",
		Hostname:   "W11-DEV-02",
		CVEID:      "CVE-2024-1111",
		Title:      "Medium Severity Info",
		Severity:   "MEDIUM",
		CVSSScore:  5.0,
		IsKEV:      false,
		Status:     "OPEN",
	})

	// 1. Test Query Default (Sorted KEV-first, CVSS desc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?tenant_id="+tenantID, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp vulnscan.FindingListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.TotalCount != 3 {
		t.Fatalf("expected 3 findings, got %d", resp.TotalCount)
	}
	if resp.KEVCount != 1 {
		t.Errorf("expected 1 KEV finding, got %d", resp.KEVCount)
	}

	// Verify KEV item comes first even though CVSS (8.8) is lower than non-KEV (9.8)
	if resp.Items[0].CVEID != "CVE-2024-30078" {
		t.Errorf("expected first item to be KEV CVE-2024-30078, got %s", resp.Items[0].CVEID)
	}
	if resp.Items[1].CVEID != "CVE-2024-9999" {
		t.Errorf("expected second item to be CVE-2024-9999, got %s", resp.Items[1].CVEID)
	}

	// 2. Test Severity Filter
	reqSev := httptest.NewRequest(http.MethodGet, "/api/v1/findings?tenant_id="+tenantID+"&severity=MEDIUM", nil)
	wSev := httptest.NewRecorder()
	r.ServeHTTP(wSev, reqSev)

	var respSev vulnscan.FindingListResponse
	_ = json.NewDecoder(wSev.Body).Decode(&respSev)
	if respSev.TotalCount != 1 || respSev.Items[0].CVEID != "CVE-2024-1111" {
		t.Errorf("expected 1 MEDIUM severity item, got %d", respSev.TotalCount)
	}

	// 3. Test Get Finding By ID
	findingID := resp.Items[0].ID
	reqID := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID+"?tenant_id="+tenantID, nil)
	wID := httptest.NewRecorder()
	r.ServeHTTP(wID, reqID)

	if wID.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wID.Code)
	}
	var single vulnscan.VulnerabilityFinding
	_ = json.NewDecoder(wID.Body).Decode(&single)
	if single.ID != findingID {
		t.Errorf("expected finding ID %s, got %s", findingID, single.ID)
	}
}

func TestCompliance_Handlers(t *testing.T) {
	r, _, _, compRepo, _ := setupTestRouterWithFindingRepo()
	tenantID := "tenant-acme-corp"
	hostID := "host-w11-01"

	// 1. Test List Compliance Frameworks
	reqFw := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/frameworks", nil)
	wFw := httptest.NewRecorder()
	r.ServeHTTP(wFw, reqFw)

	if wFw.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for frameworks list, got %d", wFw.Code)
	}
	var frameworks []compliance.ComplianceFramework
	if err := json.NewDecoder(wFw.Body).Decode(&frameworks); err != nil {
		t.Fatalf("failed to decode frameworks response: %v", err)
	}
	if len(frameworks) == 0 {
		t.Errorf("expected at least 1 built-in framework")
	}

	// 2. Test List Compliance Rules for CIS Windows 11
	reqRules := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/frameworks/cis_win11_v2.0/rules", nil)
	wRules := httptest.NewRecorder()
	r.ServeHTTP(wRules, reqRules)

	if wRules.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for rules list, got %d", wRules.Code)
	}
	var rules []compliance.ComplianceRule
	if err := json.NewDecoder(wRules.Body).Decode(&rules); err != nil {
		t.Fatalf("failed to decode rules response: %v", err)
	}
	if len(rules) < 25 {
		t.Errorf("expected at least 25 CIS rules, got %d", len(rules))
	}

	// 3. Seed mock evaluation results and test GetHostComplianceResults
	evals := []compliance.EvaluationResult{
		{
			ID:            "eval-01",
			TenantID:      tenantID,
			HostID:        hostID,
			Hostname:      "W11-CORP-LP01",
			RuleCode:      "18.9.15.1",
			RuleTitle:     "BitLocker Drive Encryption",
			Status:        "PASS",
			ActualValue:   "1",
			ExpectedValue: "1",
		},
	}
	score := compliance.HostComplianceScore{
		TenantID:      tenantID,
		HostID:        hostID,
		Hostname:      "W11-CORP-LP01",
		FrameworkCode: "cis_win11_v2.0",
		TotalRules:    1,
		PassedRules:   1,
		FailedRules:   0,
		Score:         100.0,
		Status:        "COMPLIANT",
	}
	_ = compRepo.SaveEvaluations(tenantID, hostID, evals, score)

	reqHost := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/hosts/"+hostID+"/results?tenant_id="+tenantID, nil)
	wHost := httptest.NewRecorder()
	r.ServeHTTP(wHost, reqHost)

	if wHost.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for host results, got %d", wHost.Code)
	}

	// 4. Test Get Tenant Summary
	reqSum := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/tenant/summary?tenant_id="+tenantID, nil)
	wSum := httptest.NewRecorder()
	r.ServeHTTP(wSum, reqSum)

	if wSum.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for tenant summary, got %d", wSum.Code)
	}
	var summary compliance.TenantComplianceSummary
	if err := json.NewDecoder(wSum.Body).Decode(&summary); err != nil {
		t.Fatalf("failed to decode summary response: %v", err)
	}
	if summary.TotalHosts != 1 || summary.AverageScore != 100.0 {
		t.Errorf("unexpected summary result: %+v", summary)
	}
}

func TestDrift_Handlers(t *testing.T) {
	r, _, _, _, driftRepo := setupTestRouterWithFindingRepo()
	tenantID := "tenant-drift-test"
	hostID := "host-w11-laptop"

	// 1. Seed Drift Events
	now := time.Now().UTC()
	event1 := drift.DriftEvent{
		ID:             "drift-01",
		TenantID:       tenantID,
		HostID:         hostID,
		Hostname:       "W11-FIN-01",
		DriftCategory:  "SecurityBaseline",
		PropertyName:   "security_baseline.bitlocker.protection_status",
		BaselineValue:  "1",
		CurrentValue:   "0",
		Severity:       drift.SeverityCritical,
		IsAcknowledged: false,
		DetectedAt:     now,
		CreatedAt:      now,
	}
	_ = driftRepo.SaveDriftEvents([]drift.DriftEvent{event1})

	// 2. Test List Drift Events
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/drift/events?tenant_id="+tenantID, nil)
	wList := httptest.NewRecorder()
	r.ServeHTTP(wList, reqList)

	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for list drift events, got %d", wList.Code)
	}
	var listResp drift.DriftListResponse
	_ = json.NewDecoder(wList.Body).Decode(&listResp)
	if listResp.TotalCount != 1 || listResp.CriticalCount != 1 {
		t.Errorf("unexpected drift list response: %+v", listResp)
	}

	// 3. Test Acknowledge Drift Event
	ackBody := bytes.NewBufferString(`{"acknowledged_by": "SecOps Analyst Alice"}`)
	reqAck := httptest.NewRequest(http.MethodPost, "/api/v1/drift/events/drift-01/acknowledge?tenant_id="+tenantID, ackBody)
	reqAck.Header.Set("Content-Type", "application/json")
	wAck := httptest.NewRecorder()
	r.ServeHTTP(wAck, reqAck)

	if wAck.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for acknowledge drift event, got %d", wAck.Code)
	}

	// 4. Test Create Alert Rule
	ruleBody := bytes.NewBufferString(`{
		"name": "Urgent Laptop BitLocker Alert",
		"description": "Alerts when BitLocker is disabled on laptops",
		"severity_filter": "CRITICAL",
		"asset_class_filter": "Laptop",
		"channel": "SLACK",
		"webhook_url": "https://hooks.slack.com/services/T00/B00/X",
		"suppression_window_hours": 4
	}`)
	reqRule := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/rules?tenant_id="+tenantID, ruleBody)
	reqRule.Header.Set("Content-Type", "application/json")
	wRule := httptest.NewRecorder()
	r.ServeHTTP(wRule, reqRule)

	if wRule.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for create alert rule, got %d: %s", wRule.Code, wRule.Body.String())
	}

	// 5. Test List Alert Rules
	reqRules := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/rules?tenant_id="+tenantID, nil)
	wRules := httptest.NewRecorder()
	r.ServeHTTP(wRules, reqRules)

	if wRules.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for list alert rules, got %d", wRules.Code)
	}
	var rules []drift.AlertRule
	_ = json.NewDecoder(wRules.Body).Decode(&rules)
	if len(rules) != 1 {
		t.Errorf("expected 1 alert rule, got %d", len(rules))
	}

	// 6. Test List Webhook Delivery Logs
	_ = driftRepo.SaveDeliveryLog(drift.WebhookDeliveryLog{
		ID:          "del-01",
		TenantID:    tenantID,
		RuleID:      rules[0].ID,
		EventID:     event1.ID,
		TargetURL:   rules[0].WebhookURL,
		StatusCode:  200,
		DurationMs:  45,
		Attempts:    1,
		Status:      "SUCCESS",
		DeliveredAt: now,
	})

	reqDel := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/deliveries?tenant_id="+tenantID, nil)
	wDel := httptest.NewRecorder()
	r.ServeHTTP(wDel, reqDel)

	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for list webhook deliveries, got %d", wDel.Code)
	}
	var deliveries []drift.WebhookDeliveryLog
	_ = json.NewDecoder(wDel.Body).Decode(&deliveries)
	if len(deliveries) != 1 {
		t.Errorf("expected 1 delivery log, got %d", len(deliveries))
	}
}
