package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rateLimiterEntry struct {
	tokens     float64
	lastUpdate time.Time
}

// RateLimiter implements a token-bucket rate limiter per IP/User.
type RateLimiter struct {
	mu           sync.Mutex
	rate         float64 // tokens per second
	capacity     float64 // max burst capacity
	entries      map[string]*rateLimiterEntry
	cleanupTimer *time.Ticker
}

// NewRateLimiter creates a rate limiter with specified requests per minute and burst limit.
func NewRateLimiter(reqsPerMinute int, burst int) *RateLimiter {
	if reqsPerMinute <= 0 {
		reqsPerMinute = 60
	}
	if burst <= 0 {
		burst = 20
	}
	rl := &RateLimiter{
		rate:         float64(reqsPerMinute) / 60.0,
		capacity:     float64(burst),
		entries:      make(map[string]*rateLimiterEntry),
		cleanupTimer: time.NewTicker(5 * time.Minute),
	}

	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) cleanupLoop() {
	for range rl.cleanupTimer.C {
		rl.mu.Lock()
		now := time.Now()
		for key, entry := range rl.entries {
			if now.Sub(entry.lastUpdate) > 10*time.Minute {
				delete(rl.entries, key)
			}
		}
		rl.mu.Unlock()
	}
}

// Allow checks if a request with the given key is allowed under rate limits.
func (rl *RateLimiter) Allow(key string) (bool, int, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.entries[key]
	if !exists {
		entry = &rateLimiterEntry{
			tokens:     rl.capacity - 1.0,
			lastUpdate: now,
		}
		rl.entries[key] = entry
		return true, int(entry.tokens), 0
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(entry.lastUpdate).Seconds()
	entry.tokens += elapsed * rl.rate
	if entry.tokens > rl.capacity {
		entry.tokens = rl.capacity
	}
	entry.lastUpdate = now

	if entry.tokens >= 1.0 {
		entry.tokens -= 1.0
		return true, int(entry.tokens), 0
	}

	// Rate limit exceeded: calculate reset duration
	missingTokens := 1.0 - entry.tokens
	retryAfter := time.Duration(missingTokens/rl.rate) * time.Second
	return false, 0, retryAfter
}

// RateLimitMutatingMiddleware enforces rate limits on mutating HTTP methods (POST, PUT, DELETE, PATCH).
func RateLimitMutatingMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only rate limit mutating methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Key based on User-ID header / Auth token, or client IP
			clientKey := extractClientKey(r)
			allowed, remaining, retryAfter := rl.Allow(clientKey)

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(int(rl.capacity)))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

			if !allowed {
				retryAfterSecs := int(retryAfter.Seconds())
				if retryAfterSecs < 1 {
					retryAfterSecs = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecs))
				w.Header().Set("X-RateLimit-Reset", strconv.Itoa(retryAfterSecs))

				WriteProblemDetails(w, r, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
					fmt.Sprintf("Rate limit exceeded for mutating operations. Please retry in %d seconds.", retryAfterSecs), nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func extractClientKey(r *http.Request) string {
	// If user is authenticated, use auth identity
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		return "user:" + authHeader
	}
	// Fall back to IP
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		ip = strings.TrimSpace(parts[0])
	}
	return "ip:" + ip
}
