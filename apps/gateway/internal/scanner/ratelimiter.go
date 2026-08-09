package scanner

import (
	"context"
	"fmt"
	"sync"
)

// SubnetRateLimiter enforces a maximum number of concurrent active scan probes per subnet.
type SubnetRateLimiter struct {
	maxConcurrency int
	sem            chan struct{}
	mu             sync.Mutex
	activeCount    int
	peakCount      int
}

// NewSubnetRateLimiter creates a rate limiter with a maximum token capacity.
func NewSubnetRateLimiter(maxConcurrency int) *SubnetRateLimiter {
	if maxConcurrency <= 0 {
		maxConcurrency = 20
	}
	return &SubnetRateLimiter{
		maxConcurrency: maxConcurrency,
		sem:            make(chan struct{}, maxConcurrency),
	}
}

// Acquire blocks until a concurrency token is available or the context expires.
func (r *SubnetRateLimiter) Acquire(ctx context.Context) error {
	select {
	case r.sem <- struct{}{}:
		r.mu.Lock()
		r.activeCount++
		if r.activeCount > r.peakCount {
			r.peakCount = r.activeCount
		}
		r.mu.Unlock()
		return nil
	case <-ctx.Done():
		return fmt.Errorf("rate_limiter: acquire cancelled or timed out: %w", ctx.Err())
	}
}

// Release returns an acquired concurrency token to the pool.
func (r *SubnetRateLimiter) Release() {
	select {
	case <-r.sem:
		r.mu.Lock()
		if r.activeCount > 0 {
			r.activeCount--
		}
		r.mu.Unlock()
	default:
		// Semaphore was not held
	}
}

// ActiveSessions returns the current number of active parallel probes.
func (r *SubnetRateLimiter) ActiveSessions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.activeCount
}

// PeakSessions returns the highest concurrent session count observed.
func (r *SubnetRateLimiter) PeakSessions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peakCount
}

// Capacity returns the maximum concurrent session limit.
func (r *SubnetRateLimiter) Capacity() int {
	return r.maxConcurrency
}

// Execute wraps a function execution with automatic token acquire and release.
func (r *SubnetRateLimiter) Execute(ctx context.Context, fn func() error) error {
	if err := r.Acquire(ctx); err != nil {
		return err
	}
	defer r.Release()
	return fn()
}
