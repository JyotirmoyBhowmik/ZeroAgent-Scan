package vulnscan

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// RateLimiter enforces a strict request budget (e.g. for NVD API 2.0).
type RateLimiter struct {
	mu           sync.Mutex
	interval     time.Duration
	lastRequest  time.Time
	maxBurst     int
	tokens       float64
	fillRate     float64 // tokens per second
	apiKeySet    bool
}

// NewNVDRateLimiter creates a rate limiter configured for NVD API 2.0 guidelines.
// With API key: 50 requests / 30 seconds -> 1.66 req/sec (min interval 600ms).
// Without API key: 5 requests / 30 seconds -> 0.166 req/sec (min interval 6000ms).
func NewNVDRateLimiter(hasAPIKey bool) *RateLimiter {
	var fillRate float64
	var minInterval time.Duration

	if hasAPIKey {
		fillRate = 50.0 / 30.0 // ~1.666 tokens/sec
		minInterval = 600 * time.Millisecond
	} else {
		fillRate = 5.0 / 30.0 // ~0.166 tokens/sec
		minInterval = 6000 * time.Millisecond
	}

	return &RateLimiter{
		interval:    minInterval,
		fillRate:    fillRate,
		tokens:      1.0,
		maxBurst:    3,
		apiKeySet:   hasAPIKey,
		lastRequest: time.Time{},
	}
}

// Wait blocks until a token is available or the context is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
	r.mu.Lock()
	now := time.Now()

	// Replenish tokens based on elapsed time
	if !r.lastRequest.IsZero() {
		elapsed := now.Sub(r.lastRequest).Seconds()
		r.tokens += elapsed * r.fillRate
		if r.tokens > float64(r.maxBurst) {
			r.tokens = float64(r.maxBurst)
		}
	}

	// If tokens < 1, calculate required sleep time
	var waitDuration time.Duration
	if r.tokens < 1.0 {
		missing := 1.0 - r.tokens
		waitSec := missing / r.fillRate
		waitDuration = time.Duration(waitSec * float64(time.Second))
	} else {
		// Ensure minimal spacing between requests
		if !r.lastRequest.IsZero() {
			sinceLast := now.Sub(r.lastRequest)
			if sinceLast < r.interval {
				waitDuration = r.interval - sinceLast
			}
		}
	}

	if waitDuration > 0 {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDuration):
		}
		r.mu.Lock()
	}

	r.tokens -= 1.0
	if r.tokens < 0 {
		r.tokens = 0
	}
	r.lastRequest = time.Now()
	r.mu.Unlock()
	return nil
}

// CalculateBackoff returns exponential backoff with full jitter for retry attempts.
func CalculateBackoff(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}

	// 2^(attempt-1) * baseDelay
	multiplier := 1 << (attempt - 1)
	if multiplier > 32 {
		multiplier = 32
	}

	temp := time.Duration(multiplier) * baseDelay
	if temp > maxDelay {
		temp = maxDelay
	}

	// Full randomized jitter: uniform random in [baseDelay/2, temp]
	halfBase := int64(baseDelay / 2)
	maxJitter := int64(temp)
	if maxJitter <= halfBase {
		return baseDelay
	}

	jittered := halfBase + rand.Int63n(maxJitter-halfBase)
	return time.Duration(jittered)
}
