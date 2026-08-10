package retention

import (
	"context"
	"testing"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
)

func setupTestRetentionEngine(t *testing.T) (*Engine, *repository.Repository) {
	repo := repository.NewRepository()
	engine := NewEngine(repo)
	return engine, repo
}

// TestRetentionEngine_DryRun_ArchivalStrategy asserts dry-run accurately calculates archival metrics without modifying DB.
func TestRetentionEngine_DryRun_ArchivalStrategy(t *testing.T) {
	engine, repo := setupTestRetentionEngine(t)

	req := models.SnapshotRetentionExecuteRequest{
		RetentionDays:   90,
		Strategy:        "archive",
		ColdStoragePath: `D:\archives\snapshots`,
		DryRun:          true,
	}

	dryRun, err := engine.DryRun(context.Background(), req, "tenant-default-01")
	if err != nil {
		t.Fatalf("DryRun failed: %v", err)
	}

	if dryRun.RetentionDays != 90 {
		t.Errorf("expected 90 retention days, got %d", dryRun.RetentionDays)
	}
	if dryRun.Strategy != "archive" {
		t.Errorf("expected 'archive' strategy, got %s", dryRun.Strategy)
	}
	// Initial seed has 3 snapshots older than 90 days (100d, 105d, 120d)
	if dryRun.SnapshotsToArchive < 3 {
		t.Errorf("expected at least 3 snapshots eligible for archival, got %d", dryRun.SnapshotsToArchive)
	}
	if dryRun.EstimatedReclaimedBytes <= 0 {
		t.Errorf("expected positive reclaimed bytes, got %d", dryRun.EstimatedReclaimedBytes)
	}
	if dryRun.PreservedDerivedRecordsNotice == "" {
		t.Errorf("expected non-empty derived records safety notice")
	}

	// Verify that dry-run did NOT modify any snapshot records in repository
	for _, snap := range repo.ListAllSnapshotsForTenant("tenant-default-01") {
		if snap.IsArchived {
			t.Errorf("dry-run should not have modified is_archived on snapshot %s", snap.ID)
		}
	}
}

// TestRetentionEngine_DryRun_DownsamplingStrategy asserts weekly grouping and checkpoint retention.
func TestRetentionEngine_DryRun_DownsamplingStrategy(t *testing.T) {
	engine, _ := setupTestRetentionEngine(t)

	req := models.SnapshotRetentionExecuteRequest{
		RetentionDays:   90,
		Strategy:        "downsample",
		ColdStoragePath: `D:\archives\snapshots`,
		DryRun:          true,
	}

	dryRun, err := engine.DryRun(context.Background(), req, "tenant-default-01")
	if err != nil {
		t.Fatalf("DryRun failed: %v", err)
	}

	if dryRun.Strategy != "downsample" {
		t.Errorf("expected 'downsample' strategy, got %s", dryRun.Strategy)
	}
	if dryRun.SnapshotsWeeklyRetained <= 0 {
		t.Errorf("expected weekly retained checkpoints > 0, got %d", dryRun.SnapshotsWeeklyRetained)
	}
}

// TestRetentionEngine_Execute_ArchivalAndChecksum tests gzip compression, SHA-256, and audit logging.
func TestRetentionEngine_Execute_ArchivalAndChecksum(t *testing.T) {
	engine, repo := setupTestRetentionEngine(t)

	tempDir := t.TempDir()

	req := models.SnapshotRetentionExecuteRequest{
		RetentionDays:   90,
		Strategy:        "archive",
		ColdStoragePath: tempDir,
		Justification:   "Quarterly cold-storage archival of historical telemetry payloads",
	}

	result, err := engine.Execute(context.Background(), req, "tenant-default-01", "secops_admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result.Status != "COMPLETED" {
		t.Errorf("expected status 'COMPLETED', got %s", result.Status)
	}
	if result.SnapshotsArchived < 3 {
		t.Errorf("expected at least 3 snapshots archived, got %d", result.SnapshotsArchived)
	}
	if result.ReclaimedBytes <= 0 {
		t.Errorf("expected positive reclaimed bytes, got %d", result.ReclaimedBytes)
	}

	// Verify snapshots in repo now have is_archived = true and non-empty archive checksum
	archivedFound := 0
	for _, snap := range repo.ListAllSnapshotsForTenant("tenant-default-01") {
		if snap.ID == "snap-historical-100d" || snap.ID == "snap-historical-105d" || snap.ID == "snap-historical-120d" {
			if !snap.IsArchived {
				t.Errorf("expected snapshot %s to have is_archived = true", snap.ID)
			}
			if snap.ArchiveChecksum == "" {
				t.Errorf("expected snapshot %s to have non-empty archive checksum", snap.ID)
			}
			archivedFound++
		}
	}
	if archivedFound < 3 {
		t.Errorf("expected 3 verified archived snapshots, found %d", archivedFound)
	}

	// Verify immutable audit log entry was created
	auditLogs := repo.ListAuditLogs()
	foundAudit := false
	for _, log := range auditLogs {
		if log.Action == "SNAPSHOT_RETENTION_EXECUTED" && log.ResourceType == "host_snapshots_retention" {
			foundAudit = true
			if log.Actor != "secops_admin" {
				t.Errorf("expected actor 'secops_admin', got %s", log.Actor)
			}
			break
		}
	}
	if !foundAudit {
		t.Errorf("expected SNAPSHOT_RETENTION_EXECUTED audit log entry")
	}
}

// TestRetentionEngine_CompressionUtility tests gzip compress and decompress fidelity.
func TestRetentionEngine_CompressionUtility(t *testing.T) {
	originalData := []byte(`{"hostname":"W11-EXEC-LP04","os_build":"22631.3296","bitlocker":{"protection_status":1}}`)

	compressed, hashHex, err := CompressAndHash(originalData)
	if err != nil {
		t.Fatalf("CompressAndHash failed: %v", err)
	}
	if len(hashHex) != 64 {
		t.Errorf("expected 64-char hex SHA-256 hash, got %d chars: %s", len(hashHex), hashHex)
	}

	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	if string(decompressed) != string(originalData) {
		t.Errorf("decompressed data does not match original")
	}
}
