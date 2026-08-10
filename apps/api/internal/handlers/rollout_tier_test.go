package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/go-chi/chi/v5"
)

func setupRolloutTestRouter() (*chi.Mux, *repository.Repository) {
	repo := repository.NewRepository()
	apiHandler := &APIHandler{
		repo: repo,
	}

	r := chi.NewRouter()
	r.Get("/endpoints", apiHandler.ListEndpoints)
	r.Get("/endpoints/pilot/summary", apiHandler.GetPilotHealthSummary)
	r.Post("/endpoints/rollout-tier/promote", apiHandler.PromoteEndpointsTier)
	r.Post("/endpoints/rollout-tier/bulk-assign", apiHandler.BulkAssignEndpointsTier)
	r.Post("/endpoints/{id}/rollout-tier", apiHandler.UpdateEndpointRolloutTier)
	r.Get("/admin/settings/rollout-tiers", apiHandler.GetRolloutSettings)
	r.Put("/admin/settings/rollout-tiers", apiHandler.UpdateRolloutSettings)

	return r, repo
}

// TestRolloutTiers_PilotHealthSummary asserts that pilot health aggregates only pilot hosts
// and correctly reports clean 0 lockout/auth failure metrics.
func TestRolloutTiers_PilotHealthSummary(t *testing.T) {
	r, _ := setupRolloutTestRouter()

	req := httptest.NewRequest(http.MethodGet, "/endpoints/pilot/summary", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var summary models.PilotHealthSummary
	if err := json.NewDecoder(w.Body).Decode(&summary); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if summary.TotalPilotHosts <= 0 {
		t.Errorf("expected > 0 pilot hosts, got %d", summary.TotalPilotHosts)
	}
	if summary.ScanSuccessRate < 90.0 {
		t.Errorf("expected scan success rate >= 90.0, got %f", summary.ScanSuccessRate)
	}
	if summary.AuthFailureCount != 0 {
		t.Errorf("expected 0 auth failures in pilot, got %d", summary.AuthFailureCount)
	}
	if summary.LockoutRiskCount != 0 {
		t.Errorf("expected 0 AD lockout risk, got %d", summary.LockoutRiskCount)
	}

	// Verify all returned hosts belong strictly to pilot tier
	for _, h := range summary.PilotHosts {
		if h.RolloutTier != "pilot" {
			t.Errorf("host %s has tier %s, expected 'pilot'", h.ID, h.RolloutTier)
		}
	}
}

// TestRolloutTiers_PromotionWithMandatoryJustification tests one-click promotion with mandatory audit log note.
func TestRolloutTiers_PromotionWithMandatoryJustification(t *testing.T) {
	r, repo := setupRolloutTestRouter()

	// 1. Attempt promotion WITHOUT justification (Must FAIL with 400 Bad Request)
	badPayload := `{"target_tier":"staged","justification":""}`
	req := httptest.NewRequest(http.MethodPost, "/endpoints/rollout-tier/promote", bytes.NewBufferString(badPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("promoting without justification must return 400 Bad Request, got %d", w.Code)
	}

	// 2. Perform valid promotion from pilot -> staged
	validPayload := `{"target_tier":"staged","justification":"Pilot completed with 100% success across 15 endpoints. Approved by Security Operations."}`
	req = httptest.NewRequest(http.MethodPost, "/endpoints/rollout-tier/promote", bytes.NewBufferString(validPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("valid promotion should return 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "PROMOTED" {
		t.Errorf("expected status 'PROMOTED', got %v", resp["status"])
	}

	// Verify that endpoints were actually updated
	stagedList := repo.ListEndpoints("", "", "", "staged")
	if len(stagedList) == 0 {
		t.Errorf("expected staged endpoints after promotion, got 0")
	}

	// Verify immutable audit log entry was created
	foundAudit := false
	for _, log := range repo.ListAuditLogs() {
		if log.Action == "ROLLOUT_TIER_PROMOTED" && log.ResourceType == "endpoint_rollout_tier" {
			foundAudit = true
			if log.Details["justification"] == "" {
				t.Errorf("audit log missing operator justification")
			}
			break
		}
	}
	if !foundAudit {
		t.Errorf("expected ROLLOUT_TIER_PROMOTED audit log entry")
	}
}

// TestRolloutTiers_BulkAssignBySubnetAndOU tests bulk assigning tiers by network subnet or Active Directory OU.
func TestRolloutTiers_BulkAssignBySubnetAndOU(t *testing.T) {
	r, repo := setupRolloutTestRouter()

	bulkPayload := `{
		"rollout_tier": "staged",
		"subnet_cidr": "10.100.1.0/24",
		"justification": "Expanding staged deployment across HQ Subnet A"
	}`

	req := httptest.NewRequest(http.MethodPost, "/endpoints/rollout-tier/bulk-assign", bytes.NewBufferString(bulkPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("bulk assign should return 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	// Verify endpoints on 10.100.1.0/24 are staged
	for _, ep := range repo.ListEndpoints("", "", "", "") {
		if ep.SubnetCIDR == "10.100.1.0/24" {
			if ep.RolloutTier != "staged" {
				t.Errorf("endpoint %s on 10.100.1.0/24 should be staged, got %s", ep.ID, ep.RolloutTier)
			}
		}
	}
}

// TestRolloutTiers_ScheduledScanSettings asserts settings can configure active rollout tiers.
func TestRolloutTiers_ScheduledScanSettings(t *testing.T) {
	r, repo := setupRolloutTestRouter()

	// 1. Get default settings (must be pilot only)
	req := httptest.NewRequest(http.MethodGet, "/admin/settings/rollout-tiers", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var settings models.RolloutSettings
	_ = json.NewDecoder(w.Body).Decode(&settings)
	if len(settings.ActiveTiers) != 1 || settings.ActiveTiers[0] != "pilot" {
		t.Errorf("default scheduled scan tiers must be ['pilot'], got %v", settings.ActiveTiers)
	}

	// 2. Update settings to enable staged
	updatePayload := `{"active_tiers":["pilot","staged"],"schedule_enforce_tiers":true}`
	req = httptest.NewRequest(http.MethodPut, "/admin/settings/rollout-tiers", bytes.NewBufferString(updatePayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("update settings should return 200, got %d", w.Code)
	}

	updated := repo.GetRolloutSettings()
	if len(updated.ActiveTiers) != 2 {
		t.Errorf("expected 2 active tiers, got %d", len(updated.ActiveTiers))
	}
}
