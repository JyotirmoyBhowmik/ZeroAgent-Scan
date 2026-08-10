package scanner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanTask represents an individual host to be scanned by a worker.
type ScanTask struct {
	Target       EndpointScanTarget
	AttemptCount int
	LastError    error
}

// WorkerPoolOptions configures worker concurrency and retry policies.
type WorkerPoolOptions struct {
	Concurrency     int           // Number of parallel worker goroutines (default: 25)
	TargetTimeout   time.Duration // Max timeout per individual host probe (default: 15s)
	MaxRetries      int           // Max retries on transient network errors (default: 2)
	BackoffBase     time.Duration // Exponential backoff base duration (default: 300ms)
	MaxBackoffLimit time.Duration // Max backoff ceiling (default: 3s)
}

// DefaultWorkerPoolOptions returns production defaults for 400-endpoint LAN/WAN scale.
func DefaultWorkerPoolOptions() WorkerPoolOptions {
	return WorkerPoolOptions{
		Concurrency:     25,
		TargetTimeout:   15 * time.Second,
		MaxRetries:      2,
		BackoffBase:     300 * time.Millisecond,
		MaxBackoffLimit: 3 * time.Second,
	}
}

// BoundedWorkerPool coordinates fixed worker routines processing a task queue.
type BoundedWorkerPool struct {
	opts       WorkerPoolOptions
	scanFn     func(ctx context.Context, target EndpointScanTarget) (*EndpointScanResult, error)
	tasksCh    chan ScanTask
	resultsCh  chan *EndpointScanResult
	wg         sync.WaitGroup
	activeJobs int64
	completed  int64
	failed     int64
}

// NewBoundedWorkerPool initializes the worker pool.
func NewBoundedWorkerPool(
	opts WorkerPoolOptions,
	scanFn func(ctx context.Context, target EndpointScanTarget) (*EndpointScanResult, error),
) *BoundedWorkerPool {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 25
	}
	if opts.TargetTimeout <= 0 {
		opts.TargetTimeout = 15 * time.Second
	}
	if opts.MaxRetries < 0 {
		opts.MaxRetries = 2
	}
	if opts.BackoffBase <= 0 {
		opts.BackoffBase = 300 * time.Millisecond
	}

	return &BoundedWorkerPool{
		opts:      opts,
		scanFn:    scanFn,
		tasksCh:   make(chan ScanTask, 1024),
		resultsCh: make(chan *EndpointScanResult, 1024),
	}
}

// Execute processes all targets through the bounded worker pool and aggregates results.
func (p *BoundedWorkerPool) Execute(ctx context.Context, targets []EndpointScanTarget) ([]EndpointScanResult, []string) {
	var logs []string
	startTime := time.Now().UTC()
	logs = append(logs, fmt.Sprintf("[%s] [INFO] Starting Bounded Worker Pool: %d workers, %d targets, timeout %s per host",
		startTime.Format(time.RFC3339), p.opts.Concurrency, len(targets), p.opts.TargetTimeout))

	// 1. Launch Fixed Worker Goroutines
	for w := 1; w <= p.opts.Concurrency; w++ {
		p.wg.Add(1)
		go p.workerRoutine(ctx, w)
	}

	// 2. Feed Tasks into Channel
	go func() {
		for _, target := range targets {
			select {
			case p.tasksCh <- ScanTask{Target: target, AttemptCount: 0}:
			case <-ctx.Done():
				return
			}
		}
		close(p.tasksCh)
	}()

	// 3. Collector Goroutine to wait and close results channel
	go func() {
		p.wg.Wait()
		close(p.resultsCh)
	}()

	// 4. Aggregate Results
	var results []EndpointScanResult
	for res := range p.resultsCh {
		if res != nil {
			results = append(results, *res)
		}
	}

	duration := time.Since(startTime)
	logs = append(logs, fmt.Sprintf("[%s] [INFO] Bounded Worker Pool completed %d targets in %s (Completed: %d, Failed: %d)",
		time.Now().UTC().Format(time.RFC3339), len(results), duration.Round(time.Millisecond), p.completed, p.failed))

	return results, logs
}

func (p *BoundedWorkerPool) workerRoutine(ctx context.Context, workerID int) {
	defer p.wg.Done()

	for task := range p.tasksCh {
		select {
		case <-ctx.Done():
			return
		default:
		}

		atomic.AddInt64(&p.activeJobs, 1)
		res, err := p.processTaskWithRetry(ctx, task)
		atomic.AddInt64(&p.activeJobs, -1)

		if err != nil {
			atomic.AddInt64(&p.failed, 1)
		} else {
			atomic.AddInt64(&p.completed, 1)
		}

		if res != nil {
			p.resultsCh <- res
		}
	}
}

func (p *BoundedWorkerPool) processTaskWithRetry(ctx context.Context, task ScanTask) (*EndpointScanResult, error) {
	for attempt := 0; attempt <= p.opts.MaxRetries; attempt++ {
		task.AttemptCount = attempt + 1

		// Enforce strict per-target timeout
		targetCtx, cancel := context.WithTimeout(ctx, p.opts.TargetTimeout)
		res, err := p.scanFn(targetCtx, task.Target)
		cancel()

		if err == nil {
			return res, nil
		}

		// FAST ABORT ON AUTH FAILURES: Never retry 401/403 to prevent Active Directory account lockout
		if isAuthenticationFailure(err) {
			if res == nil {
				res = &EndpointScanResult{
					IPAddress:         task.Target.IPAddress,
					Hostname:          task.Target.Hostname,
					Status:            "auth_error",
					AgentlessProtocol: task.Target.Protocol,
					ErrorMessage:      fmt.Sprintf("Authentication rejected by target host: %v", err),
					ScannedAt:         time.Now().UTC(),
				}
			}
			return res, err
		}

		// If out of retries, return final failure result
		if attempt >= p.opts.MaxRetries {
			if res == nil {
				res = &EndpointScanResult{
					IPAddress:         task.Target.IPAddress,
					Hostname:          task.Target.Hostname,
					Status:            "offline",
					AgentlessProtocol: task.Target.Protocol,
					ErrorMessage:      fmt.Sprintf("Host unreachable after %d attempts: %v", task.AttemptCount, err),
					ScannedAt:         time.Now().UTC(),
				}
			}
			return res, err
		}

		// Calculate Exponential Backoff with Jitter
		backoff := calculateBackoff(attempt, p.opts.BackoffBase, p.opts.MaxBackoffLimit)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, errors.New("workerpool: maximum retries exceeded")
}

func isAuthenticationFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "forbidden") ||
		strings.Contains(msg, "auth failed") ||
		strings.Contains(msg, "invalid credentials") ||
		strings.Contains(msg, "401") ||
		strings.Contains(msg, "403")
}

func calculateBackoff(attempt int, base, limit time.Duration) time.Duration {
	// Exponential backoff: base * 2^attempt
	multiplier := 1 << attempt
	backoff := base * time.Duration(multiplier)
	if backoff > limit {
		backoff = limit
	}

	// Add +/- 20% random jitter to avoid thundering herd on network recovery
	jitterRange := int64(backoff / 5)
	if jitterRange > 0 {
		jitter := time.Duration(rand.Int63n(jitterRange*2) - jitterRange)
		backoff += jitter
	}

	return backoff
}
