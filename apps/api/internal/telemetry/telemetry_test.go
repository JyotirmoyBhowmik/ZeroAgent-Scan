package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrometheusMetricsRegistry(t *testing.T) {
	reg := GetRegistry()

	// 1. Record metrics
	reg.RecordScanJob("completed", "full_audit")
	reg.RecordScanJob("failed", "fast_inventory")
	reg.RecordScanDuration("full_audit", 14.5)
	reg.SetGatewayHeartbeatGap("gw-10-100-1-0", 12.0)
	reg.SetQueueDepth("scans", 5)
	reg.RecordAPIRequest("GET", "/api/v1/endpoints/host-01", 200, 0.045)
	reg.SetActiveEndpoints("online", 18)
	reg.SetAverageCompliance(94.2)

	// 2. Query /metrics endpoint
	handler := reg.MetricsHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /metrics, got %d", w.Code)
	}

	body := w.Body.String()

	// 3. Verify Prometheus metric lines exist
	expectedMetrics := []string{
		`endpointguard_scan_jobs_total{status="completed",profile="full_audit"} 1`,
		`endpointguard_scan_jobs_total{status="failed",profile="fast_inventory"} 1`,
		`endpointguard_gateway_heartbeat_gap_seconds{gateway_id="gw-10-100-1-0"} 12`,
		`endpointguard_queue_depth{queue="scans"} 5`,
		`endpointguard_active_endpoints{status="online"} 18`,
		`endpointguard_compliance_score_average 94.2`,
		`endpointguard_api_request_duration_seconds_bucket`,
		`endpointguard_scan_job_duration_seconds_bucket`,
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("Missing expected Prometheus metric: %s\nGot output:\n%s", metric, body)
		}
	}
}

func TestEndToEndDistributedTracePropagation(t *testing.T) {
	// Simulate full 6-phase scan lifecycle with W3C Trace Context and Correlation ID
	initialCorrelationID := "corr_scan_lifecycle_test_001"
	tenantID := "tenant-acme-corp"
	jobID := "job-778899"

	// -------------------------------------------------------------------------
	// Phase 1: API Job Creation
	// -------------------------------------------------------------------------
	rootCtx := NewTraceContext(tenantID, initialCorrelationID)
	rootCtx.JobID = jobID

	spanJobCreation, ctxPhase1 := rootCtx.StartSpan("api.create_scan_job")
	spanJobCreation.AddEvent("job_enqueued", map[string]interface{}{"target_cidr": "10.100.1.0/24"})
	spanJobCreation.End(nil)

	if spanJobCreation.TraceID != rootCtx.TraceID {
		t.Errorf("Trace ID mismatch in Phase 1")
	}

	// -------------------------------------------------------------------------
	// Phase 2: Gateway Poll & WS-Man Dispatch (mTLS HTTP Header Injection)
	// -------------------------------------------------------------------------
	httpReq, _ := http.NewRequest(http.MethodPost, "https://gateway-01.corp/scans/execute", nil)
	ctxPhase1.InjectHTTP(httpReq.Header)

	// Gateway extracts W3C traceparent on other side of wire
	gatewayCtx := ExtractHTTP(httpReq.Header)
	if gatewayCtx.TraceID != rootCtx.TraceID {
		t.Errorf("Phase 2: Gateway failed to extract original TraceID. Expected %s, got %s", rootCtx.TraceID, gatewayCtx.TraceID)
	}
	if gatewayCtx.CorrelationID != initialCorrelationID {
		t.Errorf("Phase 2: Correlation ID lost in transit. Expected %s, got %s", initialCorrelationID, gatewayCtx.CorrelationID)
	}

	spanGatewayExec, ctxPhase2 := gatewayCtx.StartSpan("gateway.execute_winrm_cim")
	time.Sleep(2 * time.Millisecond)
	spanGatewayExec.End(nil)

	// -------------------------------------------------------------------------
	// Phase 3: Telemetry Snapshot DB Ingestion
	// -------------------------------------------------------------------------
	spanDBWrite, ctxPhase3 := ctxPhase2.StartSpan("api.save_host_snapshot")
	spanDBWrite.AddEvent("snapshot_saved", map[string]interface{}{"endpoint_id": "host-w11-01"})
	spanDBWrite.End(nil)

	// -------------------------------------------------------------------------
	// Phase 4: Vulnerability Correlation (NVD / CISA KEV)
	// -------------------------------------------------------------------------
	spanVuln, ctxPhase4 := ctxPhase3.StartSpan("worker.vuln_correlation")
	spanVuln.AddEvent("cve_matched", map[string]interface{}{"cve_id": "CVE-2024-38077", "kev": true})
	spanVuln.End(nil)

	// -------------------------------------------------------------------------
	// Phase 5: CIS Compliance Evaluation
	// -------------------------------------------------------------------------
	spanCompliance, ctxPhase5 := ctxPhase4.StartSpan("worker.compliance_evaluation")
	spanCompliance.AddEvent("rules_evaluated", map[string]interface{}{"passed": 26, "failed": 2})
	spanCompliance.End(nil)

	// -------------------------------------------------------------------------
	// Phase 6: Drift Detection & Webhook Alert Dispatch
	// -------------------------------------------------------------------------
	spanDrift, _ := ctxPhase5.StartSpan("worker.drift_alert_webhook")
	spanDrift.AddEvent("webhook_dispatched", map[string]interface{}{"url": "https://hooks.slack.com/services/test"})
	spanDrift.End(nil)

	// -------------------------------------------------------------------------
	// Verify unbroken trace linkage
	// -------------------------------------------------------------------------
	spans := []*Span{spanJobCreation, spanGatewayExec, spanDBWrite, spanVuln, spanCompliance, spanDrift}
	for i, s := range spans {
		if s.TraceID != rootCtx.TraceID {
			t.Errorf("Span %d (%s) lost TraceID: expected %s, got %s", i, s.Name, rootCtx.TraceID, s.TraceID)
		}
		if s.Attributes["correlation_id"] != initialCorrelationID {
			t.Errorf("Span %d (%s) lost CorrelationID: expected %s, got %v", i, s.Name, initialCorrelationID, s.Attributes["correlation_id"])
		}
		if s.DurationMs < 0 {
			t.Errorf("Span %d (%s) has invalid negative duration: %d", i, s.Name, s.DurationMs)
		}
	}
}

func TestContextBinding(t *testing.T) {
	tc := NewTraceContext("tenant-123", "corr-abc")
	ctx := WithTraceContext(context.Background(), tc)

	extracted, ok := FromContext(ctx)
	if !ok {
		t.Fatalf("Failed to extract TraceContext from context.Context")
	}
	if extracted.TraceID != tc.TraceID || extracted.CorrelationID != tc.CorrelationID {
		t.Errorf("Extracted trace context did not match bound context")
	}
}
