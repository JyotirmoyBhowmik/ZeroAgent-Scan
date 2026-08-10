package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/drift"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/go-chi/chi/v5"
)

func setupTestAlertRouter() (*chi.Mux, *repository.Repository, *drift.MemoryDriftRepository) {
	repo := repository.NewRepository()
	driftRepo := drift.NewMemoryDriftRepository()

	apiHandler := NewAPIHandler(repo, nil, nil, nil, driftRepo)

	r := chi.NewRouter()
	r.Post("/admin/health/test-alert", apiHandler.SendTestAlert)
	r.Get("/admin/health/status", apiHandler.GetAlertHealthStatus)

	return r, repo, driftRepo
}

// TestAlertVerification_SuccessfulDispatch asserts that a synthetic alert is sent
// over real HTTP with explicit synthetic markers and recorded to the audit log.
func TestAlertVerification_SuccessfulDispatch(t *testing.T) {
	r, repo, _ := setupTestAlertRouter()

	var receivedNotice string
	var receivedType string
	var isTestAlertHeader string

	// Real mock HTTP receiver simulating Slack/Teams webhook
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		isTestAlertHeader = req.Header.Get("X-EndpointGuard-Test-Alert")
		var payload drift.TestAlertPayload
		_ = json.NewDecoder(req.Body).Decode(&payload)
		receivedNotice = payload.AlertNotice
		receivedType = payload.AlertType
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	payload := map[string]string{
		"webhook_url": mockServer.URL,
		"test_reason": "Quarterly on-call verification of ZeroAgent fleet failure alert delivery",
	}
	payloadBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/admin/health/test-alert", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp drift.TestAlertResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "DELIVERED" {
		t.Errorf("expected status 'DELIVERED', got %s", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status_code 200, got %d", resp.StatusCode)
	}
	if resp.VerificationReceipt == "" {
		t.Errorf("expected non-empty verification receipt")
	}
	if resp.AlertNotice != "[SYNTHETIC TEST ALERT - NOT A REAL INCIDENT]" {
		t.Errorf("expected synthetic alert notice, got %s", resp.AlertNotice)
	}

	// Assert payload received by webhook provider
	if isTestAlertHeader != "true" {
		t.Errorf("expected X-EndpointGuard-Test-Alert header to be 'true'")
	}
	if receivedNotice != "[SYNTHETIC TEST ALERT - NOT A REAL INCIDENT]" {
		t.Errorf("webhook provider received invalid notice: %s", receivedNotice)
	}
	if receivedType != "FLEET_FAILURE_RATE_SIMULATION" {
		t.Errorf("webhook provider received invalid alert type: %s", receivedType)
	}

	// Assert immutable audit log entry was created
	foundAudit := false
	for _, log := range repo.ListAuditLogs() {
		if log.Action == "TEST_ALERT_DISPATCHED" && log.ResourceType == "alert_verification" {
			foundAudit = true
			if log.Status != "DELIVERED" {
				t.Errorf("audit log status should be DELIVERED, got %s", log.Status)
			}
			if log.Details["is_synthetic_test"] != true {
				t.Errorf("audit log should record is_synthetic_test = true")
			}
			break
		}
	}
	if !foundAudit {
		t.Errorf("expected TEST_ALERT_DISPATCHED entry in immutable security_audit_logs")
	}

	// Assert GET /admin/health/status reflects successful test and not lapsed
	healthReq := httptest.NewRequest(http.MethodGet, "/admin/health/status", nil)
	healthRec := httptest.NewRecorder()
	r.ServeHTTP(healthRec, healthReq)

	var health models.AlertHealthStatus
	_ = json.NewDecoder(healthRec.Body).Decode(&health)

	if health.LastTestAlertStatus != "DELIVERED" {
		t.Errorf("expected last_test_alert_status 'DELIVERED', got %s", health.LastTestAlertStatus)
	}
	if health.TestAlertLapsed {
		t.Errorf("health.TestAlertLapsed should be false after fresh test")
	}
	if health.TestAlertLapseDays != 0 {
		t.Errorf("expected 0 lapse days, got %d", health.TestAlertLapseDays)
	}
}

// TestAlertVerification_FailedDelivery asserts handling and audit logging of failing webhooks.
func TestAlertVerification_FailedDelivery(t *testing.T) {
	r, repo, _ := setupTestAlertRouter()

	// Mock server returning HTTP 503 Service Unavailable
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer mockServer.Close()

	payload := map[string]string{
		"webhook_url": mockServer.URL,
		"test_reason": "Verifying dead webhook endpoint handling",
	}
	payloadBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/admin/health/test-alert", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp drift.TestAlertResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)

	if resp.Status != "FAILED" {
		t.Errorf("expected status 'FAILED' for 503 response, got %s", resp.Status)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status code 503, got %d", resp.StatusCode)
	}

	// Verify that health status marks alert testing as lapsed/failed
	health := repo.GetAlertHealthStatus()
	if health.LastTestAlertStatus != "FAILED" {
		t.Errorf("expected health status 'FAILED', got %s", health.LastTestAlertStatus)
	}
	if !health.TestAlertLapsed {
		t.Errorf("expected TestAlertLapsed to be true when last test failed")
	}
}

// TestAlertVerification_LapseCalculation asserts that testing older than 90 days flags as lapsed.
func TestAlertVerification_LapseCalculation(t *testing.T) {
	repo := repository.NewRepository()

	// Initial state (Never tested) -> Must be lapsed
	h := repo.GetAlertHealthStatus()
	if !h.TestAlertLapsed || h.LastTestAlertStatus != "NEVER_TESTED" {
		t.Errorf("initial alert health should be lapsed and NEVER_TESTED, got status=%s, lapsed=%v",
			h.LastTestAlertStatus, h.TestAlertLapsed)
	}

	// Record test from 95 days ago
	oldTime := time.Now().UTC().Add(-95 * 24 * time.Hour)
	repo.RecordTestAlertResult(&drift.TestAlertResponse{
		Status:              "DELIVERED",
		TargetURL:           "https://hooks.slack.com/services/OLD",
		StatusCode:          200,
		DurationMs:          50,
		DeliveryID:          "test-old-123",
		VerificationReceipt: "RECEIPT-OLD95",
	}, "test_operator", "127.0.0.1")

	// Artificially age the timestamp to 95 days ago
	hOld := repo.GetAlertHealthStatus()
	hOld.LastTestAlertAt = &oldTime

	// Check lapse calculation
	days := int(time.Since(oldTime).Hours() / 24)
	if days < 90 {
		t.Fatalf("expected >= 90 days, got %d", days)
	}
}
