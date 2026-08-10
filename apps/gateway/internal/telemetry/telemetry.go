package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// GatewayMetrics tracks on-prem collector execution telemetry.
type GatewayMetrics struct {
	scansExecuted uint64
	scansFailed   uint64
	totalLatencyMs uint64
}

var DefaultGatewayMetrics = &GatewayMetrics{}

func (m *GatewayMetrics) RecordScan(duration time.Duration, success bool) {
	atomic.AddUint64(&m.scansExecuted, 1)
	atomic.AddUint64(&m.totalLatencyMs, uint64(duration.Milliseconds()))
	if !success {
		atomic.AddUint64(&m.scansFailed, 1)
	}
}

func (m *GatewayMetrics) Stats() (executed, failed, avgLatencyMs uint64) {
	executed = atomic.LoadUint64(&m.scansExecuted)
	failed = atomic.LoadUint64(&m.scansFailed)
	totalMs := atomic.LoadUint64(&m.totalLatencyMs)
	if executed > 0 {
		avgLatencyMs = totalMs / executed
	}
	return
}

// InjectTraceContext injects W3C traceparent into outbound requests to target or API.
func InjectTraceContext(header http.Header, traceID, spanID, correlationID string) {
	if traceID == "" {
		traceID = randomHex(16)
	}
	if spanID == "" {
		spanID = randomHex(8)
	}
	header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", traceID, spanID))
	if correlationID != "" {
		header.Set("X-Correlation-ID", correlationID)
	}
}

// ExtractTraceContext extracts traceparent & correlation ID from incoming jobs.
func ExtractTraceContext(ctx context.Context, header http.Header) (traceID, spanID, correlationID string) {
	correlationID = header.Get("X-Correlation-ID")
	traceparent := header.Get("traceparent")
	if traceparent != "" {
		parts := strings.Split(traceparent, "-")
		if len(parts) == 4 && parts[0] == "00" {
			traceID = parts[1]
			spanID = parts[2]
			return
		}
	}
	traceID = randomHex(16)
	spanID = randomHex(8)
	return
}

func randomHex(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
