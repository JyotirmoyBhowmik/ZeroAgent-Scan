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

func setupRetentionTestRouter() (*chi.Mux, *repository.Repository) {
	repo := repository.NewRepository()
	apiHandler := NewAPIHandler(repo, nil, nil, nil, nil)

	r := chi.NewRouter()
	r.Get("/admin/snapshots/retention/policy", apiHandler.GetSnapshotRetentionPolicy)
	r.Put("/admin/snapshots/retention/policy", apiHandler.UpdateSnapshotRetentionPolicy)
	r.Post("/admin/snapshots/retention/dry-run", apiHandler.DryRunSnapshotRetention)
	r.Post("/admin/snapshots/retention/execute", apiHandler.ExecuteSnapshotRetention)

	return r, repo
}

// TestRetentionHandlers_PolicyGetAndUpdate asserts policy retrieval and configuration updates.
func TestRetentionHandlers_PolicyGetAndUpdate(t *testing.T) {
	r, repo := setupRetentionTestRouter()

	// 1. Get default policy (must be 90 days and archive strategy)
	req := httptest.NewRequest(http.MethodGet, "/admin/snapshots/retention/policy", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var policy models.SnapshotRetentionPolicy
	if err := json.NewDecoder(w.Body).Decode(&policy); err != nil {
		t.Fatalf("failed to decode policy: %v", err)
	}

	if policy.RetentionDays != 90 {
		t.Errorf("expected default 90 days, got %d", policy.RetentionDays)
	}
	if policy.Strategy != "archive" {
		t.Errorf("expected default strategy 'archive', got %s", policy.Strategy)
	}

	// 2. Update policy to 60 days
	updatePayload := `{"retention_days":60,"strategy":"downsample","cold_storage_path":"D:\\archives\\snapshots","is_enabled":true}`
	req = httptest.NewRequest(http.MethodPut, "/admin/snapshots/retention/policy", bytes.NewBufferString(updatePayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", w.Code, w.Body.String())
	}

	updated := repo.GetSnapshotRetentionPolicy()
	if updated.RetentionDays != 60 {
		t.Errorf("expected updated retention days 60, got %d", updated.RetentionDays)
	}
	if updated.Strategy != "downsample" {
		t.Errorf("expected updated strategy 'downsample', got %s", updated.Strategy)
	}
}

// TestRetentionHandlers_DryRunAndExecuteEndpoints tests the dry-run preview and execution.
func TestRetentionHandlers_DryRunAndExecuteEndpoints(t *testing.T) {
	r, _ := setupRetentionTestRouter()

	// 1. Dry Run Request
	dryRunPayload := `{"retention_days":90,"strategy":"archive","cold_storage_path":"D:\\archives\\snapshots"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/snapshots/retention/dry-run", bytes.NewBufferString(dryRunPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("dry-run expected HTTP 200, got %d: %s", w.Code, w.Body.String())
	}

	var dryRun models.SnapshotRetentionDryRun
	_ = json.NewDecoder(w.Body).Decode(&dryRun)
	if dryRun.SnapshotsToArchive < 3 {
		t.Errorf("expected at least 3 snapshots to archive, got %d", dryRun.SnapshotsToArchive)
	}
	if dryRun.PreservedDerivedRecordsNotice == "" {
		t.Errorf("expected non-empty derived records safety notice")
	}

	// 2. Execute Request
	execPayload := `{"retention_days":90,"strategy":"archive","cold_storage_path":"D:\\archives\\snapshots","justification":"Audit compliance execution"}`
	req = httptest.NewRequest(http.MethodPost, "/admin/snapshots/retention/execute", bytes.NewBufferString(execPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("execute expected HTTP 200, got %d: %s", w.Code, w.Body.String())
	}

	var result models.SnapshotRetentionExecuteResult
	_ = json.NewDecoder(w.Body).Decode(&result)
	if result.Status != "COMPLETED" {
		t.Errorf("expected status 'COMPLETED', got %s", result.Status)
	}
	if result.SnapshotsArchived < 3 {
		t.Errorf("expected at least 3 archived, got %d", result.SnapshotsArchived)
	}
}
