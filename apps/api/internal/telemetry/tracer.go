package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type contextKey string

const (
	TraceContextKey contextKey = "endpointguard_trace_ctx"
)

// TraceContext represents an immutable distributed trace envelope following W3C Trace Context.
type TraceContext struct {
	TraceID       string            `json:"trace_id"`
	SpanID        string            `json:"span_id"`
	ParentSpanID  string            `json:"parent_span_id,omitempty"`
	CorrelationID string            `json:"correlation_id"`
	TenantID      string            `json:"tenant_id"`
	JobID         string            `json:"job_id,omitempty"`
	Sampled       bool              `json:"sampled"`
	Baggage       map[string]string `json:"baggage"`
}

// Span represents a timed execution step within a distributed scan lifecycle.
type Span struct {
	Name       string                 `json:"name"`
	TraceID    string                 `json:"trace_id"`
	SpanID     string                 `json:"span_id"`
	ParentID   string                 `json:"parent_id,omitempty"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time"`
	DurationMs int64                  `json:"duration_ms"`
	Status     string                 `json:"status"` // OK, ERROR
	Attributes map[string]interface{} `json:"attributes"`
	Events     []SpanEvent            `json:"events"`
	mu         sync.Mutex
}

type SpanEvent struct {
	Name      string                 `json:"name"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload"`
}

// NewTraceContext initializes a new root distributed trace context.
func NewTraceContext(tenantID, correlationID string) TraceContext {
	if correlationID == "" {
		correlationID = fmt.Sprintf("corr_%s", randomHex(8))
	}
	return TraceContext{
		TraceID:       randomHex(16), // 128-bit W3C TraceID
		SpanID:        randomHex(8),  // 64-bit W3C SpanID
		CorrelationID: correlationID,
		TenantID:      tenantID,
		Sampled:       true,
		Baggage:       make(map[string]string),
	}
}

// StartSpan creates a child span with hierarchical linkage.
func (tc TraceContext) StartSpan(name string) (*Span, TraceContext) {
	childSpanID := randomHex(8)
	span := &Span{
		Name:       name,
		TraceID:    tc.TraceID,
		SpanID:     childSpanID,
		ParentID:   tc.SpanID,
		StartTime:  time.Now().UTC(),
		Status:     "OK",
		Attributes: make(map[string]interface{}),
		Events:     make([]SpanEvent, 0),
	}
	span.Attributes["tenant_id"] = tc.TenantID
	span.Attributes["correlation_id"] = tc.CorrelationID
	if tc.JobID != "" {
		span.Attributes["job_id"] = tc.JobID
	}

	childContext := TraceContext{
		TraceID:       tc.TraceID,
		SpanID:        childSpanID,
		ParentSpanID:  tc.SpanID,
		CorrelationID: tc.CorrelationID,
		TenantID:      tc.TenantID,
		JobID:         tc.JobID,
		Sampled:       tc.Sampled,
		Baggage:       tc.Baggage,
	}

	return span, childContext
}

// End finishes the span and calculates duration.
func (s *Span) End(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EndTime = time.Now().UTC()
	s.DurationMs = s.EndTime.Sub(s.StartTime).Milliseconds()
	if err != nil {
		s.Status = "ERROR"
		s.Attributes["error"] = err.Error()
	}
}

// AddEvent records an in-span event.
func (s *Span) AddEvent(name string, payload map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, SpanEvent{
		Name:      name,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	})
}

// InjectHTTP adds W3C traceparent and X-Correlation-ID headers to an outgoing HTTP request.
func (tc TraceContext) InjectHTTP(header http.Header) {
	sampledFlag := "00"
	if tc.Sampled {
		sampledFlag = "01"
	}
	// W3C traceparent: 00-<trace_id>-<span_id>-<flags>
	header.Set("traceparent", fmt.Sprintf("00-%s-%s-%s", tc.TraceID, tc.SpanID, sampledFlag))
	header.Set("X-Correlation-ID", tc.CorrelationID)
	if tc.TenantID != "" {
		header.Set("X-Tenant-ID", tc.TenantID)
	}
}

// ExtractHTTP extracts W3C traceparent and correlation ID from an incoming HTTP request.
func ExtractHTTP(header http.Header) TraceContext {
	corrID := header.Get("X-Correlation-ID")
	if corrID == "" {
		corrID = fmt.Sprintf("corr_%s", randomHex(8))
	}
	tenantID := header.Get("X-Tenant-ID")

	traceparent := header.Get("traceparent")
	if traceparent != "" {
		parts := strings.Split(traceparent, "-")
		if len(parts) == 4 && parts[0] == "00" && len(parts[1]) == 32 && len(parts[2]) == 16 {
			return TraceContext{
				TraceID:       parts[1],
				SpanID:        parts[2],
				CorrelationID: corrID,
				TenantID:      tenantID,
				Sampled:       parts[3] == "01",
				Baggage:       make(map[string]string),
			}
		}
	}

	return NewTraceContext(tenantID, corrID)
}

// WithTraceContext binds a TraceContext to a Go standard context.
func WithTraceContext(ctx context.Context, tc TraceContext) context.Context {
	return context.WithValue(ctx, TraceContextKey, tc)
}

// FromContext extracts TraceContext from a Go context.
func FromContext(ctx context.Context) (TraceContext, bool) {
	if ctx == nil {
		return TraceContext{}, false
	}
	val, ok := ctx.Value(TraceContextKey).(TraceContext)
	return val, ok
}

func randomHex(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
