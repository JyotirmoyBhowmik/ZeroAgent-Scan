package queue

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestPersistentJobQueue_EnqueueAndLease(t *testing.T) {
	q := NewPersistentJobQueue()
	ctx := context.Background()

	// 1. Enqueue 400-host bulk scan job
	var targets []string
	for i := 1; i <= 400; i++ {
		targets = append(targets, fmt.Sprintf("10.100.%d.%d", i/256+1, i%254+1))
	}

	job := JobEntry{
		ID:          "job-bulk-400-test",
		TenantID:    "tenant-prod",
		Name:        "Corporate Fleet Bulk Audit (400 Endpoints)",
		TargetCIDR:  "10.100.0.0/22",
		ScanProfile: "full_audit",
	}

	err := q.EnqueueJob(ctx, job, targets)
	if err != nil {
		t.Fatalf("EnqueueJob failed: %v", err)
	}

	j, err := q.GetJob("job-bulk-400-test")
	if err != nil || j.TotalHosts != 400 {
		t.Fatalf("Expected 400 total hosts in queued job, got %d", j.TotalHosts)
	}

	// 2. Lease in batches of 25 (matching bounded worker pool concurrency)
	leased, err := q.LeaseBatch(ctx, "gateway-worker-01", 25, 30*time.Second)
	if err != nil || len(leased) != 25 {
		t.Fatalf("Expected 25 leased tasks, got %d", len(leased))
	}

	// 3. Complete 20 tasks, fail 5 tasks
	for i := 0; i < 20; i++ {
		_ = q.CompleteTask(ctx, leased[i].ID, true, map[string]interface{}{"compliance": 95.0})
	}
	for i := 20; i < 25; i++ {
		_ = q.FailTask(ctx, leased[i].ID, "timeout connecting to host", true)
	}

	// Verify job progress
	updatedJob, _ := q.GetJob("job-bulk-400-test")
	if updatedJob.ScannedHosts != 20 {
		t.Errorf("Expected 20 scanned hosts, got %d", updatedJob.ScannedHosts)
	}
}

func TestPersistentJobQueue_CrashRecovery_ReclaimLeases(t *testing.T) {
	q := NewPersistentJobQueue()
	ctx := context.Background()

	targets := []string{"10.100.1.10", "10.100.1.11", "10.100.1.12"}
	job := JobEntry{
		ID:       "job-crash-recovery-test",
		TenantID: "tenant-prod",
	}
	_ = q.EnqueueJob(ctx, job, targets)

	// Lease with a very short expiration (1 millisecond) to simulate expired lease
	leased, _ := q.LeaseBatch(ctx, "crashed-worker-99", 3, 1*time.Millisecond)
	if len(leased) != 3 {
		t.Fatalf("Expected 3 leased tasks")
	}

	// Wait for lease to expire
	time.Sleep(10 * time.Millisecond)

	// Reclaim expired leases (Simulates API/Worker restart)
	reclaimed, err := q.ReclaimExpiredLeases(ctx)
	if err != nil {
		t.Fatalf("ReclaimExpiredLeases failed: %v", err)
	}
	if reclaimed != 3 {
		t.Errorf("Expected 3 reclaimed tasks after worker crash, got %d", reclaimed)
	}

	// Verify tasks are now pending and can be re-leased by a healthy worker
	reLeased, _ := q.LeaseBatch(ctx, "healthy-worker-01", 3, 30*time.Second)
	if len(reLeased) != 3 {
		t.Errorf("Expected 3 tasks to be re-leased by healthy worker, got %d", len(reLeased))
	}
}
