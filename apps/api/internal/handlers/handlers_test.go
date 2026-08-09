package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/auth"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/compliance"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/drift"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/openapi"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/reports"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vault"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vulnscan"
	"github.com/go-chi/chi/v5"
)

func setupTestRouter() (*chi.Mux, *repository.Repository, *auth.TokenService) {
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

	tokenService := auth.NewTokenService("test-secret-key-32b-long-secret-key!", "test-issuer")
	rateLimiter := middleware.NewRateLimiter(60, 5) // Low burst of 5 for easy rate limit testing

	r := chi.NewRouter()
	r.Get("/api/v1/health", h.HealthCheck)
	r.Get("/api/v1/metrics", h.GetFleetMetrics)
	r.Get("/api/v1/openapi.json", openapi.ServeOpenAPIJSON)
	r.Get("/api/v1/docs", openapi.ServeSwaggerUI)

	r.Group(func(protected chi.Router) {
		protected.Use(auth.OptionalAuth(tokenService, "tenant-default-01"))
		protected.Use(middleware.RateLimitMutatingMiddleware(rateLimiter))

		protected.Get("/api/v1/endpoints", h.ListEndpoints)
		protected.Get("/api/v1/endpoints/{id}", h.GetEndpointByID)
		protected.Get("/api/v1/snapshots", h.ListSnapshots)
		protected.Get("/api/v1/snapshots/{id}", h.GetSnapshotByID)
		protected.Post("/api/v1/scans", h.CreateScanJob)
		protected.Get("/api/v1/scans", h.ListScanJobs)
		protected.Get("/api/v1/scans/{id}", h.GetScanJobByID)
		protected.Post("/api/v1/scans/{id}/cancel", h.CancelScanJob)
		protected.Get("/api/v1/gateways", h.ListGateways)
		protected.Post("/api/v1/gateways/register", h.RegisterGateway)
		protected.Post("/api/v1/gateways/{id}/approve", h.ApproveGateway)
		protected.Post("/api/v1/gateways/heartbeat", h.GatewayHeartbeat)
		protected.Get("/api/v1/vault/credentials", h.ListVaultCredentials)
		protected.Post("/api/v1/vault/credentials", h.CreateVaultCredential)
		protected.Post("/api/v1/vault/credentials/{id}/rotate", h.RotateVaultCredential)
		protected.Get("/api/v1/audit-logs", h.ListAuditLogs)
		protected.Get("/api/v1/findings", h.ListVulnerabilityFindings)
		protected.Get("/api/v1/findings/{id}", h.GetVulnerabilityFindingByID)
		protected.Get("/api/v1/compliance/frameworks", h.ListComplianceFrameworks)
		protected.Get("/api/v1/compliance/frameworks/{code}/rules", h.ListComplianceRules)
		protected.Get("/api/v1/compliance/hosts/{host_id}/results", h.GetHostComplianceResults)
		protected.Get("/api/v1/compliance/tenant/summary", h.GetTenantComplianceSummary)
		protected.Get("/api/v1/drift/events", h.ListDriftEvents)
		protected.Post("/api/v1/drift/events/{id}/acknowledge", h.AcknowledgeDriftEvent)
		protected.Get("/api/v1/alerts/rules", h.ListAlertRules)
		protected.Post("/api/v1/alerts/rules", h.CreateAlertRule)
		protected.Get("/api/v1/alerts/deliveries", h.ListWebhookDeliveryLogs)
		protected.Post("/api/v1/reports", h.GenerateReport)
	})

	return r, repo, tokenService
}

func setupTestRouterWithFindingRepo() (*chi.Mux, *repository.Repository, vulnscan.FindingRepository, compliance.ComplianceRepository, drift.DriftRepository, *auth.TokenService) {
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

	tokenService := auth.NewTokenService("test-secret-key-32b-long-secret-key!", "test-issuer")
	rateLimiter := middleware.NewRateLimiter(60, 20)

	r := chi.NewRouter()
	r.Get("/api/v1/health", h.HealthCheck)
	r.Get("/api/v1/metrics", h.GetFleetMetrics)
	r.Get("/api/v1/openapi.json", openapi.ServeOpenAPIJSON)
	r.Get("/api/v1/docs", openapi.ServeSwaggerUI)

	r.Group(func(protected chi.Router) {
		protected.Use(auth.OptionalAuth(tokenService, "tenant-default-01"))
		protected.Use(middleware.RateLimitMutatingMiddleware(rateLimiter))

		protected.Get("/api/v1/endpoints", h.ListEndpoints)
		protected.Get("/api/v1/endpoints/{id}", h.GetEndpointByID)
		protected.Get("/api/v1/snapshots", h.ListSnapshots)
		protected.Get("/api/v1/snapshots/{id}", h.GetSnapshotByID)
		protected.Post("/api/v1/scans", h.CreateScanJob)
		protected.Get("/api/v1/scans", h.ListScanJobs)
		protected.Get("/api/v1/scans/{id}", h.GetScanJobByID)
		protected.Post("/api/v1/scans/{id}/cancel", h.CancelScanJob)
		protected.Get("/api/v1/gateways", h.ListGateways)
		protected.Post("/api/v1/gateways/register", h.RegisterGateway)
		protected.Post("/api/v1/gateways/{id}/approve", h.ApproveGateway)
		protected.Post("/api/v1/gateways/heartbeat", h.GatewayHeartbeat)
		protected.Get("/api/v1/vault/credentials", h.ListVaultCredentials)
		protected.Post("/api/v1/vault/credentials", h.CreateVaultCredential)
		protected.Post("/api/v1/vault/credentials/{id}/rotate", h.RotateVaultCredential)
		protected.Get("/api/v1/audit-logs", h.ListAuditLogs)
		protected.Get("/api/v1/findings", h.ListVulnerabilityFindings)
		protected.Get("/api/v1/findings/{id}", h.GetVulnerabilityFindingByID)
		protected.Get("/api/v1/compliance/frameworks", h.ListComplianceFrameworks)
		protected.Get("/api/v1/compliance/frameworks/{code}/rules", h.ListComplianceRules)
		protected.Get("/api/v1/compliance/hosts/{host_id}/results", h.GetHostComplianceResults)
		protected.Get("/api/v1/compliance/tenant/summary", h.GetTenantComplianceSummary)
		protected.Get("/api/v1/drift/events", h.ListDriftEvents)
		protected.Post("/api/v1/drift/events/{id}/acknowledge", h.AcknowledgeDriftEvent)
		protected.Get("/api/v1/alerts/rules", h.ListAlertRules)
		protected.Post("/api/v1/alerts/rules", h.CreateAlertRule)
		protected.Get("/api/v1/alerts/deliveries", h.ListWebhookDeliveryLogs)
		protected.Post("/api/v1/reports", h.GenerateReport)
	})

	return r, repo, findingRepo, compRepo, driftRepo, tokenService
}

func TestOpenAPI_SpecAndDocs(t *testing.T) {
	r, _, _ := setupTestRouter()

	// 1. Test OpenAPI JSON
	reqJSON := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil)
	wJSON := httptest.NewRecorder()
	r.ServeHTTP(wJSON, reqJSON)

	if wJSON.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for openapi.json, got %d", wJSON.Code)
	}
	var spec map[string]interface{}
	if err := json.NewDecoder(wJSON.Body).Decode(&spec); err != nil {
		t.Fatalf("failed to decode OpenAPI JSON: %v", err)
	}
	if spec["openapi"] != "3.1.0" {
		t.Errorf("expected openapi 3.1.0, got %v", spec["openapi"])
	}

	// 2. Test Swagger UI Docs
	reqDocs := httptest.NewRequest(http.MethodGet, "/api/v1/docs", nil)
	wDocs := httptest.NewRecorder()
	r.ServeHTTP(wDocs, reqDocs)

	if wDocs.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /docs, got %d", wDocs.Code)
	}
	if !bytes.Contains(wDocs.Body.Bytes(), []byte("swagger-ui")) {
		t.Errorf("expected swagger-ui in HTML docs")
	}
}

func TestTenantScoping_JWTIsolation(t *testing.T) {
	r, _, _, _, _, tokenService := setupTestRouterWithFindingRepo()

	// Generate JWT for Tenant A
	tokenA, _ := tokenService.GenerateToken(auth.UserClaims{
		TenantID:     "tenant-corp-a",
		UserID:       "user-a",
		Email:        "alice@corp-a.com",
		Role:         auth.RoleAdmin,
		StepUpAuthAt: time.Now().UTC().Unix(),
	}, 1*time.Hour)

	// User from Tenant A creates a credential
	bodyA := bytes.NewBufferString(`{
		"name": "Tenant A Credential",
		"credential_type": "domain_kerberos",
		"username": "svc_corp_a",
		"secret_value": "VerySecretPassword123!"
	}`)
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/vault/credentials", bodyA)
	reqCreate.Header.Set("Authorization", "Bearer "+tokenA)
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	r.ServeHTTP(wCreate, reqCreate)

	if wCreate.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", wCreate.Code, wCreate.Body.String())
	}
	var cred models.VaultCredentialSummary
	_ = json.NewDecoder(wCreate.Body).Decode(&cred)

	// Now try to rotate with Tenant B JWT (must fail or remain isolated)
	tokenB, _ := tokenService.GenerateToken(auth.UserClaims{
		TenantID:     "tenant-corp-b",
		UserID:       "user-b",
		Email:        "bob@corp-b.com",
		Role:         auth.RoleAdmin,
		StepUpAuthAt: time.Now().UTC().Unix(),
	}, 1*time.Hour)

	rotBody := bytes.NewBufferString(`{"new_secret_value": "AttackerOverwrittenPass!"}`)
	reqRot := httptest.NewRequest(http.MethodPost, "/api/v1/vault/credentials/"+cred.OpaqueID+"/rotate", rotBody)
	reqRot.Header.Set("Authorization", "Bearer "+tokenB)
	reqRot.Header.Set("Content-Type", "application/json")
	wRot := httptest.NewRecorder()
	r.ServeHTTP(wRot, reqRot)

	// Must fail because tenant-corp-b does NOT own credential in tenant-corp-a
	if wRot.Code == http.StatusOK {
		t.Fatalf("Cross-tenant IDOR violation: Tenant B was able to rotate Tenant A's secret!")
	}
}

func TestKeysetPagination_SnapshotsAndAuditLogs(t *testing.T) {
	r, repo, _ := setupTestRouter()
	tenantID := "tenant-default-01"
	hostID := "host-w11-exec-01"

	// Seed 5 snapshots
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		_ = repo.SaveSnapshot(models.HostSnapshotEntry{
			ID:          "snap-" + strconv.Itoa(i),
			TenantID:    tenantID,
			HostID:      hostID,
			Hostname:    "W11-EXEC-01",
			PayloadHash: "hash-" + strconv.Itoa(i),
			CreatedAt:   now.Add(time.Duration(i) * time.Minute),
		})
	}

	// 1. Fetch Page 1 (limit 2)
	reqP1 := httptest.NewRequest(http.MethodGet, "/api/v1/snapshots?limit=2", nil)
	wP1 := httptest.NewRecorder()
	r.ServeHTTP(wP1, reqP1)

	if wP1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for snapshots page 1, got %d", wP1.Code)
	}
	var p1 repository.KeysetPageResponse[models.HostSnapshotEntry]
	_ = json.NewDecoder(wP1.Body).Decode(&p1)

	if len(p1.Items) != 2 || !p1.HasMore || p1.NextCursor == "" {
		t.Fatalf("unexpected page 1 result: %+v", p1)
	}

	// 2. Fetch Page 2 using cursor
	reqP2 := httptest.NewRequest(http.MethodGet, "/api/v1/snapshots?limit=2&cursor="+p1.NextCursor, nil)
	wP2 := httptest.NewRecorder()
	r.ServeHTTP(wP2, reqP2)

	if wP2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for snapshots page 2, got %d", wP2.Code)
	}
	var p2 repository.KeysetPageResponse[models.HostSnapshotEntry]
	_ = json.NewDecoder(wP2.Body).Decode(&p2)

	if len(p2.Items) != 2 || p2.Items[0].ID == p1.Items[0].ID {
		t.Errorf("keyset pagination forward navigation failed: page 1 = %s, page 2 = %s", p1.Items[0].ID, p2.Items[0].ID)
	}
}

func TestScanJob_LifecycleAndCancel(t *testing.T) {
	r, _, _ := setupTestRouter()

	// 1. Create Scan Job
	createBody := bytes.NewBufferString(`{
		"name": "Subnet Audit Scan",
		"target_cidr": "10.100.1.0/24",
		"scan_profile": "FULL_CIS_BENCHMARK",
		"protocol": "winrm_https",
		"vault_secret_ref": "sec_ref_winrm_domain_prod_01",
		"gateway_id": "gw-10-100-1-0"
	}`)
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/scans", createBody)
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	r.ServeHTTP(wCreate, reqCreate)

	if wCreate.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", wCreate.Code, wCreate.Body.String())
	}
	var job models.ScanJob
	_ = json.NewDecoder(wCreate.Body).Decode(&job)

	// 2. Cancel Scan Job
	reqCancel := httptest.NewRequest(http.MethodPost, "/api/v1/scans/"+job.ID+"/cancel", nil)
	wCancel := httptest.NewRecorder()
	r.ServeHTTP(wCancel, reqCancel)

	if wCancel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for cancel, got %d", wCancel.Code)
	}
}

func TestGateways_RegistrationAndApproval(t *testing.T) {
	r, _, _ := setupTestRouter()

	// 1. Register Gateway
	regBody := bytes.NewBufferString(`{
		"gateway_code": "gw-subnet-10-200-1-0",
		"name": "Branch Office Collector",
		"subnet_cidr": "10.200.1.0/24",
		"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...-----END CERTIFICATE REQUEST-----"
	}`)
	reqReg := httptest.NewRequest(http.MethodPost, "/api/v1/gateways/register", regBody)
	reqReg.Header.Set("Content-Type", "application/json")
	wReg := httptest.NewRecorder()
	r.ServeHTTP(wReg, reqReg)

	if wReg.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for gateway register, got %d", wReg.Code)
	}
	var gw models.CollectorGateway
	_ = json.NewDecoder(wReg.Body).Decode(&gw)

	// 2. Approve Gateway
	reqApprove := httptest.NewRequest(http.MethodPost, "/api/v1/gateways/"+gw.ID+"/approve", nil)
	wApprove := httptest.NewRecorder()
	r.ServeHTTP(wApprove, reqApprove)

	if wApprove.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for gateway approve, got %d", wApprove.Code)
	}
}

func TestReports_Generation(t *testing.T) {
	r, _, _ := setupTestRouter()

	// 1. Executive Summary Report
	execBody := bytes.NewBufferString(`{"type": "EXECUTIVE_SUMMARY"}`)
	reqExec := httptest.NewRequest(http.MethodPost, "/api/v1/reports", execBody)
	reqExec.Header.Set("Content-Type", "application/json")
	wExec := httptest.NewRecorder()
	r.ServeHTTP(wExec, reqExec)

	if wExec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for executive report, got %d: %s", wExec.Code, wExec.Body.String())
	}
	var execRep reports.ExecutiveSummaryReport
	_ = json.NewDecoder(wExec.Body).Decode(&execRep)
	if execRep.TotalEndpoints == 0 {
		t.Errorf("expected endpoints in executive report")
	}

	// 2. Compliance Audit Report
	compBody := bytes.NewBufferString(`{"type": "COMPLIANCE_AUDIT", "framework_code": "cis_win11_v2.0"}`)
	reqComp := httptest.NewRequest(http.MethodPost, "/api/v1/reports", compBody)
	reqComp.Header.Set("Content-Type", "application/json")
	wComp := httptest.NewRecorder()
	r.ServeHTTP(wComp, reqComp)

	if wComp.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for compliance audit report, got %d", wComp.Code)
	}

	// 3. Vulnerability Posture Report
	vulnBody := bytes.NewBufferString(`{"type": "VULNERABILITY_POSTURE"}`)
	reqVuln := httptest.NewRequest(http.MethodPost, "/api/v1/reports", vulnBody)
	reqVuln.Header.Set("Content-Type", "application/json")
	wVuln := httptest.NewRecorder()
	r.ServeHTTP(wVuln, reqVuln)

	if wVuln.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for vuln posture report, got %d", wVuln.Code)
	}
}

func TestRateLimiter_MutatingEndpoints(t *testing.T) {
	r, _, _ := setupTestRouter()

	// Send burst of 10 requests to trigger rate limit (capacity = 5)
	hitRateLimit := false
	for i := 0; i < 10; i++ {
		body := bytes.NewBufferString(`{"gateway_code": "gw-10-100-1-0", "latency_ms": 5}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/gateways/heartbeat", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			hitRateLimit = true
			if w.Header().Get("Retry-After") == "" {
				t.Errorf("Missing Retry-After header on 429 response")
			}
			break
		}
	}

	if !hitRateLimit {
		t.Errorf("Expected rate limiter to trigger 429 on burst requests")
	}
}

func TestProblemDetails_ErrorFormat(t *testing.T) {
	r, _, _ := setupTestRouter()

	// Trigger 404 endpoint not found
	req := httptest.NewRequest(http.MethodGet, "/api/v1/endpoints/nonexistent-uuid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("expected application/problem+json Content-Type, got %s", w.Header().Get("Content-Type"))
	}

	var prob middleware.ProblemDetails
	if err := json.NewDecoder(w.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem details: %v", err)
	}
	if prob.Status != 404 || prob.CorrelationID == "" || prob.Timestamp == "" {
		t.Errorf("incomplete problem details response: %+v", prob)
	}
}
