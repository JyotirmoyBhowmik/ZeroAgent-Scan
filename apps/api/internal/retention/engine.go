package retention

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/google/uuid"
)

// Engine orchestrates snapshot retention policies, compressed cold-storage archival, and weekly downsampling.
type Engine struct {
	repo *repository.Repository
	mu   sync.RWMutex
}

// NewEngine creates an initialized snapshot retention engine.
func NewEngine(repo *repository.Repository) *Engine {
	return &Engine{
		repo: repo,
	}
}

// DryRun calculates the exact impact of a retention policy without modifying any records.
func (e *Engine) DryRun(
	ctx context.Context,
	req models.SnapshotRetentionExecuteRequest,
	tenantID string,
) (*models.SnapshotRetentionDryRun, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	retentionDays := req.RetentionDays
	if retentionDays <= 0 {
		retentionDays = 90
	}
	strategy := strings.ToLower(strings.TrimSpace(req.Strategy))
	if strategy == "" {
		strategy = "archive"
	}
	if strategy != "archive" && strategy != "downsample" {
		return nil, fmt.Errorf("invalid retention strategy '%s'; must be 'archive' or 'downsample'", strategy)
	}

	cutoffDate := time.Now().UTC().AddDate(0, 0, -retentionDays)
	allSnapshots := e.repo.ListAllSnapshotsForTenant(tenantID)

	var evaluatedCount int
	var eligibleCount int
	var archiveCount int
	var pruneCount int
	var weeklyRetainedCount int
	var totalReclaimedBytes int64
	affectedEndpointsMap := make(map[string]bool)
	var sampleSummaries []models.SnapshotArchiveSummary

	if strategy == "archive" {
		for _, snap := range allSnapshots {
			evaluatedCount++
			if snap.CreatedAt.Before(cutoffDate) && !snap.IsArchived {
				eligibleCount++
				archiveCount++
				affectedEndpointsMap[snap.HostID] = true

				size := snap.PayloadSizeBytes
				if size <= 0 {
					data, _ := json.Marshal(snap.Payload)
					size = int64(len(data))
				}
				totalReclaimedBytes += size

				if len(sampleSummaries) < 15 {
					yearMonth := snap.CreatedAt.Format("2006-01")
					targetLoc := filepath.Join(req.ColdStoragePath, yearMonth, fmt.Sprintf("%s_%s.json.gz", snap.HostID, snap.ID))
					sampleSummaries = append(sampleSummaries, models.SnapshotArchiveSummary{
						SnapshotID:       snap.ID,
						HostID:           snap.HostID,
						Hostname:         snap.Hostname,
						CapturedAt:       snap.CreatedAt,
						PayloadSizeBytes: size,
						Action:           "ARCHIVE_TO_COLD_STORAGE",
						TargetLocation:   targetLoc,
					})
				}
			}
		}
	} else if strategy == "downsample" {
		// Group older snapshots by HostID and Calendar Week
		type hostWeekKey struct {
			HostID string
			Year   int
			Week   int
		}
		hostWeeks := make(map[hostWeekKey][]models.HostSnapshotEntry)

		for _, snap := range allSnapshots {
			evaluatedCount++
			if snap.CreatedAt.Before(cutoffDate) && !snap.IsArchived {
				y, w := snap.CreatedAt.ISOWeek()
				key := hostWeekKey{HostID: snap.HostID, Year: y, Week: w}
				hostWeeks[key] = append(hostWeeks[key], snap)
			}
		}

		for key, snaps := range hostWeeks {
			if len(snaps) == 0 {
				continue
			}
			affectedEndpointsMap[key.HostID] = true

			// Sort by CreatedAt ascending
			sort.Slice(snaps, func(i, j int) bool {
				return snaps[i].CreatedAt.Before(snaps[j].CreatedAt)
			})

			// Keep the latest snapshot in the week bucket as the weekly checkpoint
			checkpointIdx := len(snaps) - 1
			weeklyRetainedCount++

			if len(sampleSummaries) < 15 {
				checkpoint := snaps[checkpointIdx]
				sampleSummaries = append(sampleSummaries, models.SnapshotArchiveSummary{
					SnapshotID:       checkpoint.ID,
					HostID:           checkpoint.HostID,
					Hostname:         checkpoint.Hostname,
					CapturedAt:       checkpoint.CreatedAt,
					PayloadSizeBytes: checkpoint.PayloadSizeBytes,
					Action:           "RETAIN_WEEKLY_CHECKPOINT",
				})
			}

			// Prune/downsample the intermediate daily snapshots in the week bucket
			for i := 0; i < checkpointIdx; i++ {
				pruneSnap := snaps[i]
				eligibleCount++
				pruneCount++

				size := pruneSnap.PayloadSizeBytes
				if size <= 0 {
					data, _ := json.Marshal(pruneSnap.Payload)
					size = int64(len(data))
				}
				totalReclaimedBytes += size

				if len(sampleSummaries) < 15 {
					sampleSummaries = append(sampleSummaries, models.SnapshotArchiveSummary{
						SnapshotID:       pruneSnap.ID,
						HostID:           pruneSnap.HostID,
						Hostname:         pruneSnap.Hostname,
						CapturedAt:       pruneSnap.CreatedAt,
						PayloadSizeBytes: size,
						Action:           "PRUNE_DOWNSAMPLED",
					})
				}
			}
		}
	}

	var affectedEndpoints []string
	for hostID := range affectedEndpointsMap {
		affectedEndpoints = append(affectedEndpoints, hostID)
	}
	sort.Strings(affectedEndpoints)

	savedMB := float64(totalReclaimedBytes) / (1024 * 1024)

	return &models.SnapshotRetentionDryRun{
		RetentionDays:                  retentionDays,
		Strategy:                       strategy,
		CutoffDate:                     cutoffDate,
		TotalSnapshotsEvaluated:        evaluatedCount,
		SnapshotsEligibleForAction:     eligibleCount,
		SnapshotsToArchive:             archiveCount,
		SnapshotsToPrune:               pruneCount,
		SnapshotsWeeklyRetained:        weeklyRetainedCount,
		EstimatedReclaimedBytes:        totalReclaimedBytes,
		EstimatedStorageSavedMB:        savedMB,
		AffectedEndpointsCount:         len(affectedEndpoints),
		AffectedEndpoints:              affectedEndpoints,
		SampleSnapshots:                sampleSummaries,
		PreservedDerivedRecordsNotice: "ZeroAgent-Scan Architectural Invariant: drift_events and compliance_evaluations remain 100% intact and queryable for historical compliance reports.",
		DryRunGeneratedAt:              time.Now().UTC(),
	}, nil
}

// Execute performs the actual compressed archival or downsampling of eligible snapshots.
func (e *Engine) Execute(
	ctx context.Context,
	req models.SnapshotRetentionExecuteRequest,
	tenantID string,
	operatorID string,
	ipAddr string,
) (*models.SnapshotRetentionExecuteResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	start := time.Now()
	executionID := "retention-" + uuid.New().String()

	retentionDays := req.RetentionDays
	if retentionDays <= 0 {
		retentionDays = 90
	}
	strategy := strings.ToLower(strings.TrimSpace(req.Strategy))
	if strategy == "" {
		strategy = "archive"
	}
	if strategy != "archive" && strategy != "downsample" {
		return nil, fmt.Errorf("invalid retention strategy '%s'", strategy)
	}

	coldStoragePath := req.ColdStoragePath
	if coldStoragePath == "" {
		coldStoragePath = `D:\archives\snapshots`
	}

	cutoffDate := time.Now().UTC().AddDate(0, 0, -retentionDays)
	allSnapshots := e.repo.ListAllSnapshotsForTenant(tenantID)

	var processedCount int
	var archivedCount int
	var downsampledCount int
	var weeklyRetainedCount int
	var reclaimedBytes int64

	if strategy == "archive" {
		for _, snap := range allSnapshots {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if snap.CreatedAt.Before(cutoffDate) && !snap.IsArchived {
				processedCount++

				// 1. Serialize payload and compress with gzip
				payloadBytes, err := json.Marshal(snap.Payload)
				if err != nil {
					continue
				}
				rawSize := int64(len(payloadBytes))

				var gzippedBuf bytes.Buffer
				gzWriter := gzip.NewWriter(&gzippedBuf)
				if _, err := gzWriter.Write(payloadBytes); err != nil {
					_ = gzWriter.Close()
					continue
				}
				_ = gzWriter.Close()

				compressedBytes := gzippedBuf.Bytes()
				hash := sha256.Sum256(compressedBytes)
				checksumHex := hex.EncodeToString(hash[:])

				// 2. Write to local cold storage directory if path exists or in dev
				yearMonth := snap.CreatedAt.Format("2006-01")
				targetDir := filepath.Join(coldStoragePath, yearMonth)
				targetFile := filepath.Join(targetDir, fmt.Sprintf("%s_%s.json.gz", snap.HostID, snap.ID))

				// In production or test, attempt file creation if directory is writable
				if err := os.MkdirAll(targetDir, 0750); err == nil {
					_ = os.WriteFile(targetFile, compressedBytes, 0640)
				}

				// 3. Update snapshot metadata in repository: set is_archived = true, clear heavy payload
				now := time.Now().UTC()
				_ = e.repo.ArchiveSnapshotPayload(snap.ID, targetFile, checksumHex, "cold_storage", now, rawSize)

				archivedCount++
				reclaimedBytes += rawSize
			}
		}
	} else if strategy == "downsample" {
		type hostWeekKey struct {
			HostID string
			Year   int
			Week   int
		}
		hostWeeks := make(map[hostWeekKey][]models.HostSnapshotEntry)

		for _, snap := range allSnapshots {
			if snap.CreatedAt.Before(cutoffDate) && !snap.IsArchived {
				y, w := snap.CreatedAt.ISOWeek()
				key := hostWeekKey{HostID: snap.HostID, Year: y, Week: w}
				hostWeeks[key] = append(hostWeeks[key], snap)
			}
		}

		for _, snaps := range hostWeeks {
			if len(snaps) == 0 {
				continue
			}
			sort.Slice(snaps, func(i, j int) bool {
				return snaps[i].CreatedAt.Before(snaps[j].CreatedAt)
			})

			// Retain the latest snapshot in the week as checkpoint
			checkpointIdx := len(snaps) - 1
			checkpoint := snaps[checkpointIdx]
			_ = e.repo.MarkSnapshotWeeklyRetained(checkpoint.ID)
			weeklyRetainedCount++

			// Prune/downsample intermediate daily snapshots
			for i := 0; i < checkpointIdx; i++ {
				pruneSnap := snaps[i]
				processedCount++
				downsampledCount++

				size := pruneSnap.PayloadSizeBytes
				if size <= 0 {
					data, _ := json.Marshal(pruneSnap.Payload)
					size = int64(len(data))
				}
				reclaimedBytes += size

				_ = e.repo.PruneDownsampledSnapshot(pruneSnap.ID)
			}
		}
	}

	duration := time.Since(start).Milliseconds()
	savedMB := float64(reclaimedBytes) / (1024 * 1024)

	// Record immutable audit log
	auditLogID := fmt.Sprintf("audit-retention-%d", time.Now().UnixNano())
	e.repo.AddAuditLog(models.SecurityAuditLog{
		ID:            auditLogID,
		CorrelationID: fmt.Sprintf("corr-%s", executionID),
		Timestamp:     time.Now().UTC(),
		Actor:         operatorID,
		Action:        "SNAPSHOT_RETENTION_EXECUTED",
		ResourceType:  "host_snapshots_retention",
		ResourceID:    executionID,
		IPAddress:     ipAddr,
		Status:        "SUCCESS",
		Details: map[string]interface{}{
			"execution_id":              executionID,
			"strategy":                  strategy,
			"retention_days":            retentionDays,
			"cutoff_date":               cutoffDate.Format(time.RFC3339),
			"snapshots_processed":       processedCount,
			"snapshots_archived":        archivedCount,
			"snapshots_downsampled":     downsampledCount,
			"snapshots_weekly_retained": weeklyRetainedCount,
			"reclaimed_bytes":           reclaimedBytes,
			"storage_saved_mb":          savedMB,
			"cold_storage_path":         coldStoragePath,
			"duration_ms":               duration,
			"justification":             req.Justification,
		},
	})

	// Update retention policy metadata
	e.repo.UpdateRetentionPolicyRunStats(models.SnapshotRetentionPolicy{
		RetentionDays:          retentionDays,
		Strategy:               strategy,
		ColdStoragePath:        coldStoragePath,
		KeepWeeklyIntervalDays: 7,
		IsEnabled:              true,
		LastRunAt:              &time.Time{},
		LastRunStatus:          "COMPLETED",
		LastReclaimedBytes:     reclaimedBytes,
		UpdatedAt:              time.Now().UTC(),
		UpdatedBy:              operatorID,
	})

	return &models.SnapshotRetentionExecuteResult{
		ExecutionID:             executionID,
		Strategy:                strategy,
		RetentionDays:           retentionDays,
		CutoffDate:              cutoffDate,
		SnapshotsProcessed:      processedCount,
		SnapshotsArchived:       archivedCount,
		SnapshotsDownsampled:    downsampledCount,
		SnapshotsWeeklyRetained: weeklyRetainedCount,
		ReclaimedBytes:          reclaimedBytes,
		StorageSavedMB:          savedMB,
		ArchiveDirectory:        coldStoragePath,
		DurationMs:              duration,
		Status:                  "COMPLETED",
		ExecutedAt:              time.Now().UTC(),
		ExecutedBy:              operatorID,
		AuditLogID:              auditLogID,
	}, nil
}

// CompressAndHash utility compresses raw bytes with gzip and returns compressed data and SHA-256 hash.
func CompressAndHash(data []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		_ = gw.Close()
		return nil, "", err
	}
	if err := gw.Close(); err != nil {
		return nil, "", err
	}
	compressed := buf.Bytes()
	hash := sha256.Sum256(compressed)
	return compressed, hex.EncodeToString(hash[:]), nil
}

// Decompress decompresses gzip payload.
func Decompress(compressed []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}
