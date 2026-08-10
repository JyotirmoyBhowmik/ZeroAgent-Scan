package queue

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// TaskStatus represents the lifecycle state of an individual host scan task.
type TaskStatus string

const (
	StatusPending   TaskStatus = "pending"
	StatusLeased    TaskStatus = "leased"
	StatusCompleted TaskStatus = "completed"
	StatusFailed    TaskStatus = "failed"
)

// JobEntry represents a high-level bulk/CIDR scan job.
type JobEntry struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	Name           string     `json:"name"`
	TargetCIDR     string     `json:"target_cidr"`
	ScanProfile    string     `json:"scan_profile"`
	Status         string     `json:"status"` // queued, in_progress, completed, failed
	TotalHosts     int        `json:"total_hosts"`
	ScannedHosts   int        `json:"scanned_hosts"`
	CompliantHosts int        `json:"compliant_hosts"`
	FailedHosts    int        `json:"failed_hosts"`
	GatewayID      string     `json:"gateway_id"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// HostTask represents an individual host probe unit within a scan job.
type HostTask struct {
	ID              string                 `json:"id"`
	JobID           string                 `json:"job_id"`
	TenantID        string                 `json:"tenant_id"`
	TargetIP        string                 `json:"target_ip"`
	Status          TaskStatus             `json:"status"`
	RetryCount      int                    `json:"retry_count"`
	MaxRetries      int                    `json:"max_retries"`
	LeasedByWorker  string                 `json:"leased_by_worker,omitempty"`
	LeaseExpiresAt  *time.Time             `json:"lease_expires_at,omitempty"`
	LastError       string                 `json:"last_error,omitempty"`
	ResultPayload   map[string]interface{} `json:"result_payload,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
}

// PersistentJobQueue coordinates persistent job queue operations and lease reclamation.
type PersistentJobQueue struct {
	mu    sync.RWMutex
	jobs  map[string]*JobEntry
	tasks map[string]*HostTask
}

// NewPersistentJobQueue creates a new thread-safe persistent job queue.
func NewPersistentJobQueue() *PersistentJobQueue {
	return &PersistentJobQueue{
		jobs:  make(map[string]*JobEntry),
		tasks: make(map[string]*HostTask),
	}
}

// EnqueueJob creates a job and populates all individual host tasks.
func (q *PersistentJobQueue) EnqueueJob(ctx context.Context, job JobEntry, targetIPs []string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	job.TotalHosts = len(targetIPs)
	job.Status = "queued"
	job.CreatedAt = time.Now().UTC()
	job.UpdatedAt = time.Now().UTC()

	q.jobs[job.ID] = &job

	for _, ip := range targetIPs {
		taskID := uuid.New().String()
		task := &HostTask{
			ID:         taskID,
			JobID:      job.ID,
			TenantID:   job.TenantID,
			TargetIP:   ip,
			Status:     StatusPending,
			RetryCount: 0,
			MaxRetries: 2,
			CreatedAt:  time.Now().UTC(),
			UpdatedAt:  time.Now().UTC(),
		}
		q.tasks[taskID] = task
	}

	return nil
}

// LeaseBatch atomically leases up to batchSize pending tasks to a worker.
func (q *PersistentJobQueue) LeaseBatch(ctx context.Context, workerID string, batchSize int, leaseDuration time.Duration) ([]*HostTask, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now().UTC()
	leaseExpires := now.Add(leaseDuration)
	var leased []*HostTask

	for _, task := range q.tasks {
		if task.Status == StatusPending {
			task.Status = StatusLeased
			task.LeasedByWorker = workerID
			task.LeaseExpiresAt = &leaseExpires
			task.UpdatedAt = now

			// Update parent job status to in_progress if queued
			if job, exists := q.jobs[task.JobID]; exists && job.Status == "queued" {
				job.Status = "in_progress"
				job.UpdatedAt = now
			}

			leased = append(leased, task)
			if len(leased) >= batchSize {
				break
			}
		}
	}

	return leased, nil
}

// CompleteTask marks a task completed and updates job statistics.
func (q *PersistentJobQueue) CompleteTask(ctx context.Context, taskID string, isCompliant bool, result map[string]interface{}) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	task, exists := q.tasks[taskID]
	if !exists {
		return fmt.Errorf("queue: task %s not found", taskID)
	}

	now := time.Now().UTC()
	task.Status = StatusCompleted
	task.ResultPayload = result
	task.CompletedAt = &now
	task.UpdatedAt = now

	// Update job counters
	if job, exists := q.jobs[task.JobID]; exists {
		job.ScannedHosts++
		if isCompliant {
			job.CompliantHosts++
		}
		job.UpdatedAt = now

		// If all tasks completed, finalize job
		if job.ScannedHosts+job.FailedHosts >= job.TotalHosts {
			job.Status = "completed"
			job.CompletedAt = &now
		}
	}

	return nil
}

// FailTask records a task failure, increments retry count, or marks failed permanently.
func (q *PersistentJobQueue) FailTask(ctx context.Context, taskID string, errMsg string, retryable bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	task, exists := q.tasks[taskID]
	if !exists {
		return fmt.Errorf("queue: task %s not found", taskID)
	}

	now := time.Now().UTC()
	task.LastError = errMsg
	task.UpdatedAt = now

	if retryable && task.RetryCount < task.MaxRetries {
		task.RetryCount++
		task.Status = StatusPending
		task.LeasedByWorker = ""
		task.LeaseExpiresAt = nil
	} else {
		task.Status = StatusFailed
		task.CompletedAt = &now

		if job, exists := q.jobs[task.JobID]; exists {
			job.FailedHosts++
			job.UpdatedAt = now

			if job.ScannedHosts+job.FailedHosts >= job.TotalHosts {
				job.Status = "completed"
				job.CompletedAt = &now
			}
		}
	}

	return nil
}

// ReclaimExpiredLeases finds all leased tasks whose lease has expired and resets them to pending.
// This guarantees that a scan job survives mid-run worker or API process crashes.
func (q *PersistentJobQueue) ReclaimExpiredLeases(ctx context.Context) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now().UTC()
	reclaimedCount := 0

	for _, task := range q.tasks {
		if task.Status == StatusLeased && task.LeaseExpiresAt != nil && task.LeaseExpiresAt.Before(now) {
			task.Status = StatusPending
			task.LeasedByWorker = ""
			task.LeaseExpiresAt = nil
			task.UpdatedAt = now
			reclaimedCount++
		}
	}

	return reclaimedCount, nil
}

// GetJob returns a job and its current progress metrics.
func (q *PersistentJobQueue) GetJob(jobID string) (*JobEntry, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	job, exists := q.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("queue: job %s not found", jobID)
	}
	return job, nil
}
