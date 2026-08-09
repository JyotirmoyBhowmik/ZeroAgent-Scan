package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/google/uuid"
)

type contextKey string

const CorrelationIDKey contextKey = "correlation_id"

var secretRegex = regexp.MustCompile(`(?i)(password|secret|token|key|authorization|bearer)\s*[:=]\s*["']?([^"'\s,]+)["']?`)

type LogEntry struct {
	Timestamp     string `json:"timestamp"`
	Level         string `json:"level"`
	CorrelationID string `json:"correlation_id"`
	Service       string `json:"service"`
	Method        string `json:"method,omitempty"`
	Path          string `json:"path,omitempty"`
	StatusCode    int    `json:"status_code,omitempty"`
	DurationMs    int64  `json:"duration_ms,omitempty"`
	ClientIP      string `json:"client_ip,omitempty"`
	Message       string `json:"message"`
}

func MaskSecrets(input string) string {
	return secretRegex.ReplaceAllString(input, "$1=***REDACTED***")
}

func LogJSON(level, correlationID, service, message string) {
	entry := LogEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Level:         level,
		CorrelationID: correlationID,
		Service:       service,
		Message:       MaskSecrets(message),
	}
	bytes, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stdout, string(bytes))
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func StructuredLoggingMiddleware(serviceName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Extract or generate Correlation-ID
			corrID := r.Header.Get("X-Correlation-ID")
			if corrID == "" {
				corrID = r.Header.Get("X-Request-ID")
			}
			if corrID == "" {
				corrID = fmt.Sprintf("req-%s", uuid.New().String()[:8])
			}

			// Propagate down context
			ctx := context.WithValue(r.Context(), CorrelationIDKey, corrID)
			w.Header().Set("X-Correlation-ID", corrID)

			recorder := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(recorder, r.WithContext(ctx))

			duration := time.Since(start).Milliseconds()

			entry := LogEntry{
				Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
				Level:         "info",
				CorrelationID: corrID,
				Service:       serviceName,
				Method:        r.Method,
				Path:          r.URL.Path,
				StatusCode:    recorder.statusCode,
				DurationMs:    duration,
				ClientIP:      r.RemoteAddr,
				Message:       fmt.Sprintf("%s %s -> %d in %dms", r.Method, r.URL.Path, recorder.statusCode, duration),
			}

			if recorder.statusCode >= 500 {
				entry.Level = "error"
			} else if recorder.statusCode >= 400 {
				entry.Level = "warn"
			}

			bytes, _ := json.Marshal(entry)
			fmt.Fprintln(os.Stdout, string(bytes))
		})
	}
}

func GetCorrelationID(ctx context.Context) string {
	if val, ok := ctx.Value(CorrelationIDKey).(string); ok && val != "" {
		return val
	}
	return "unknown"
}
