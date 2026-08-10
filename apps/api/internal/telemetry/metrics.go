package telemetry

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Prometheus Metric Registry for EndpointGuard
type MetricsRegistry struct {
	mu                   sync.RWMutex
	scanJobsTotal        map[string]*uint64
	scanDurationBuckets  map[string]map[float64]*uint64
	scanDurationSum      map[string]*float64
	scanDurationCount    map[string]*uint64
	gatewayHeartbeatGaps map[string]*float64
	queueDepths          map[string]*int64
	apiLatencyBuckets    map[string]map[float64]*uint64
	apiLatencySum        map[string]*float64
	apiLatencyCount      map[string]*uint64
	activeEndpoints      map[string]*int64
	complianceAvg        float64
}

var (
	defaultRegistry *MetricsRegistry
	registryOnce    sync.Once

	// Standard latency histogram buckets (in seconds)
	LatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}
	ScanBuckets    = []float64{1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0}
)

// GetRegistry returns the singleton Prometheus metrics registry.
func GetRegistry() *MetricsRegistry {
	registryOnce.Do(func() {
		defaultRegistry = &MetricsRegistry{
			scanJobsTotal:        make(map[string]*uint64),
			scanDurationBuckets:  make(map[string]map[float64]*uint64),
			scanDurationSum:      make(map[string]*float64),
			scanDurationCount:    make(map[string]*uint64),
			gatewayHeartbeatGaps: make(map[string]*float64),
			queueDepths:          make(map[string]*int64),
			apiLatencyBuckets:    make(map[string]map[float64]*uint64),
			apiLatencySum:        make(map[string]*float64),
			apiLatencyCount:      make(map[string]*uint64),
			activeEndpoints:      make(map[string]*int64),
		}
	})
	return defaultRegistry
}

// RecordScanJob increments the scan jobs counter with status and profile labels.
func (r *MetricsRegistry) RecordScanJob(status, profile string) {
	key := fmt.Sprintf(`status="%s",profile="%s"`, status, profile)
	r.mu.Lock()
	counter, exists := r.scanJobsTotal[key]
	if !exists {
		var val uint64
		r.scanJobsTotal[key] = &val
		counter = &val
	}
	r.mu.Unlock()
	atomic.AddUint64(counter, 1)
}

// RecordScanDuration records the duration of a scan job.
func (r *MetricsRegistry) RecordScanDuration(profile string, durationSeconds float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf(`profile="%s"`, profile)
	if _, exists := r.scanDurationBuckets[key]; !exists {
		r.scanDurationBuckets[key] = make(map[float64]*uint64)
		for _, b := range ScanBuckets {
			var val uint64
			r.scanDurationBuckets[key][b] = &val
		}
		var sum float64
		var count uint64
		r.scanDurationSum[key] = &sum
		r.scanDurationCount[key] = &count
	}

	for _, b := range ScanBuckets {
		if durationSeconds <= b {
			atomic.AddUint64(r.scanDurationBuckets[key][b], 1)
		}
	}
	*r.scanDurationSum[key] += durationSeconds
	atomic.AddUint64(r.scanDurationCount[key], 1)
}

// SetGatewayHeartbeatGap sets the seconds since last heartbeat for a gateway.
func (r *MetricsRegistry) SetGatewayHeartbeatGap(gatewayID string, gapSeconds float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gatewayHeartbeatGaps[gatewayID] = &gapSeconds
}

// SetQueueDepth sets the current depth for a specific work queue.
func (r *MetricsRegistry) SetQueueDepth(queueName string, depth int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queueDepths[queueName] = &depth
}

// RecordAPIRequest records latency for an HTTP API request.
func (r *MetricsRegistry) RecordAPIRequest(method, path string, statusCode int, durationSeconds float64) {
	// Normalize path for cardinality control (e.g. /endpoints/123 -> /endpoints/:id)
	normPath := normalizePath(path)
	key := fmt.Sprintf(`method="%s",path="%s",status="%d"`, method, normPath, statusCode)

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.apiLatencyBuckets[key]; !exists {
		r.apiLatencyBuckets[key] = make(map[float64]*uint64)
		for _, b := range LatencyBuckets {
			var val uint64
			r.apiLatencyBuckets[key][b] = &val
		}
		var sum float64
		var count uint64
		r.apiLatencySum[key] = &sum
		r.apiLatencyCount[key] = &count
	}

	for _, b := range LatencyBuckets {
		if durationSeconds <= b {
			atomic.AddUint64(r.apiLatencyBuckets[key][b], 1)
		}
	}
	*r.apiLatencySum[key] += durationSeconds
	atomic.AddUint64(r.apiLatencyCount[key], 1)
}

// SetActiveEndpoints sets count of endpoints by status.
func (r *MetricsRegistry) SetActiveEndpoints(status string, count int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activeEndpoints[status] = &count
}

// SetAverageCompliance sets the fleet-wide average compliance score.
func (r *MetricsRegistry) SetAverageCompliance(score float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.complianceAvg = score
}

// MetricsHandler returns an HTTP handler emitting Prometheus text format.
func (r *MetricsRegistry) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		var out strings.Builder

		// 1. Scan Jobs Total Counter
		out.WriteString("# HELP endpointguard_scan_jobs_total Total count of scan jobs dispatched and executed.\n")
		out.WriteString("# TYPE endpointguard_scan_jobs_total counter\n")
		r.mu.RLock()
		for labels, counter := range r.scanJobsTotal {
			out.WriteString(fmt.Sprintf("endpointguard_scan_jobs_total{%s} %d\n", labels, atomic.LoadUint64(counter)))
		}

		// 2. Scan Job Duration Histogram
		out.WriteString("# HELP endpointguard_scan_job_duration_seconds Histogram of scan job execution duration in seconds.\n")
		out.WriteString("# TYPE endpointguard_scan_job_duration_seconds histogram\n")
		for key, buckets := range r.scanDurationBuckets {
			var cumulative uint64
			for _, b := range ScanBuckets {
				val := atomic.LoadUint64(buckets[b])
				cumulative += val
				out.WriteString(fmt.Sprintf("endpointguard_scan_job_duration_seconds_bucket{%s,le=\"%g\"} %d\n", key, b, val))
			}
			out.WriteString(fmt.Sprintf("endpointguard_scan_job_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", key, atomic.LoadUint64(r.scanDurationCount[key])))
			out.WriteString(fmt.Sprintf("endpointguard_scan_job_duration_seconds_sum{%s} %g\n", key, *r.scanDurationSum[key]))
			out.WriteString(fmt.Sprintf("endpointguard_scan_job_duration_seconds_count{%s} %d\n", key, atomic.LoadUint64(r.scanDurationCount[key])))
		}

		// 3. Gateway Heartbeat Gap Gauge
		out.WriteString("# HELP endpointguard_gateway_heartbeat_gap_seconds Seconds elapsed since last heartbeat per collector gateway.\n")
		out.WriteString("# TYPE endpointguard_gateway_heartbeat_gap_seconds gauge\n")
		for gwID, gap := range r.gatewayHeartbeatGaps {
			out.WriteString(fmt.Sprintf("endpointguard_gateway_heartbeat_gap_seconds{gateway_id=\"%s\"} %g\n", gwID, *gap))
		}

		// 4. Queue Depth Gauge
		out.WriteString("# HELP endpointguard_queue_depth Pending message depth across background work queues.\n")
		out.WriteString("# TYPE endpointguard_queue_depth gauge\n")
		for qName, depth := range r.queueDepths {
			out.WriteString(fmt.Sprintf("endpointguard_queue_depth{queue=\"%s\"} %d\n", qName, *depth))
		}

		// 5. API Request Latency Histogram
		out.WriteString("# HELP endpointguard_api_request_duration_seconds HTTP API request duration in seconds.\n")
		out.WriteString("# TYPE endpointguard_api_request_duration_seconds histogram\n")
		for key, buckets := range r.apiLatencyBuckets {
			for _, b := range LatencyBuckets {
				val := atomic.LoadUint64(buckets[b])
				out.WriteString(fmt.Sprintf("endpointguard_api_request_duration_seconds_bucket{%s,le=\"%g\"} %d\n", key, b, val))
			}
			out.WriteString(fmt.Sprintf("endpointguard_api_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", key, atomic.LoadUint64(r.apiLatencyCount[key])))
			out.WriteString(fmt.Sprintf("endpointguard_api_request_duration_seconds_sum{%s} %g\n", key, *r.apiLatencySum[key]))
			out.WriteString(fmt.Sprintf("endpointguard_api_request_duration_seconds_count{%s} %d\n", key, atomic.LoadUint64(r.apiLatencyCount[key])))
		}

		// 6. Active Endpoints Gauge
		out.WriteString("# HELP endpointguard_active_endpoints Total inventory endpoints grouped by status.\n")
		out.WriteString("# TYPE endpointguard_active_endpoints gauge\n")
		for status, count := range r.activeEndpoints {
			out.WriteString(fmt.Sprintf("endpointguard_active_endpoints{status=\"%s\"} %d\n", status, *count))
		}

		// 7. Average Compliance Gauge
		out.WriteString("# HELP endpointguard_compliance_score_average Fleet-wide average CIS compliance percentage.\n")
		out.WriteString("# TYPE endpointguard_compliance_score_average gauge\n")
		out.WriteString(fmt.Sprintf("endpointguard_compliance_score_average %g\n", r.complianceAvg))

		r.mu.RUnlock()

		_, _ = w.Write([]byte(out.String()))
	}
}

// LatencyMiddleware records HTTP latency into Prometheus metrics.
func LatencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(ww, r)

		duration := time.Since(start).Seconds()
		GetRegistry().RecordAPIRequest(r.Method, r.URL.Path, ww.statusCode, duration)
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (s *statusResponseWriter) WriteHeader(code int) {
	s.statusCode = code
	s.ResponseWriter.WriteHeader(code)
}

func normalizePath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1" {
		// e.g. /api/v1/endpoints/host-123 -> /api/v1/endpoints/:id
		if len(parts) == 4 && parts[2] == "endpoints" {
			return "/api/v1/endpoints/:id"
		}
		if len(parts) == 4 && parts[2] == "gateways" {
			return "/api/v1/gateways/:id"
		}
		if len(parts) == 4 && parts[2] == "scans" {
			return "/api/v1/scans/:id"
		}
	}
	return path
}
