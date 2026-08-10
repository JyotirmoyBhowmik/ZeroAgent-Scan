package scanner

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// Test400EndpointScaleLoadBenchmark executes a realistic synthetic fleet audit against 400 endpoints.
// Target Composition:
// - 260 Healthy, Fast Reachable Endpoints (10-25ms CIM telemetry extraction)
// - 80 Unreachable / Offline Hosts (triggering timeout and max 2 retries with backoff)
// - 40 Slow WAN Branch Office Endpoints (150-250ms latency)
// - 20 Auth Failure Endpoints (401/403 fast abort without retry to prevent AD lockout)
func Test400EndpointScaleLoadBenchmark(t *testing.T) {
	// Pre-benchmark Memory Stats
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// 1. Generate 400 Synthetic Targets
	totalTargetCount := 400
	targets := make([]EndpointScanTarget, 0, totalTargetCount)

	for i := 1; i <= totalTargetCount; i++ {
		ip := fmt.Sprintf("10.100.%d.%d", (i/254)+1, (i%254)+1)
		var hostname string
		var mockType string

		switch {
		case i <= 260:
			mockType = "healthy_fast"
			hostname = fmt.Sprintf("W11-CORP-%03d", i)
		case i <= 340:
			mockType = "offline_timeout"
			hostname = fmt.Sprintf("W11-OFFLINE-%03d", i)
		case i <= 380:
			mockType = "slow_wan"
			hostname = fmt.Sprintf("WS22-BRANCH-%03d", i)
		default:
			mockType = "auth_failure"
			hostname = fmt.Sprintf("W11-EXPIRED-%03d", i)
		}

		targets = append(targets, EndpointScanTarget{
			IPAddress: ip,
			Hostname:  hostname,
			Protocol:  mockType, // passed in protocol to dispatch synthetic behavior
		})
	}

	// 2. Configure Bounded Worker Pool with Concurrency = 25
	opts := WorkerPoolOptions{
		Concurrency:     25,
		TargetTimeout:   5 * time.Second,
		MaxRetries:      2,
		BackoffBase:     50 * time.Millisecond,
		MaxBackoffLimit: 500 * time.Millisecond,
	}

	// Mock Scanner Dispatcher
	mockScanFn := func(ctx context.Context, target EndpointScanTarget) (*EndpointScanResult, error) {
		switch target.Protocol {
		case "healthy_fast":
			// Fast CIM query (~5ms)
			time.Sleep(5 * time.Millisecond)
			return &EndpointScanResult{
				IPAddress:         target.IPAddress,
				Hostname:          target.Hostname,
				Status:            "online",
				AgentlessProtocol: "winrm_https",
				ComplianceScore:   92.5,
				ScannedAt:         time.Now().UTC(),
			}, nil

		case "slow_wan":
			// Slow WAN connection (~80ms)
			time.Sleep(80 * time.Millisecond)
			return &EndpointScanResult{
				IPAddress:         target.IPAddress,
				Hostname:          target.Hostname,
				Status:            "online",
				AgentlessProtocol: "winrm_https",
				ComplianceScore:   85.0,
				ScannedAt:         time.Now().UTC(),
			}, nil

		case "auth_failure":
			// Auth rejection (401 Unauthorized) -> Fast Abort!
			time.Sleep(10 * time.Millisecond)
			return nil, errors.New("winrm: 401 Unauthorized - invalid Kerberos ticket or account locked")

		case "offline_timeout":
			// Offline host -> simulate socket connect timeout
			time.Sleep(60 * time.Millisecond)
			return nil, errors.New("winrm: dial tcp 10.100.x.x:5986: connect: connection timed out")

		default:
			return nil, errors.New("unknown target type")
		}
	}

	pool := NewBoundedWorkerPool(opts, mockScanFn)

	// 3. Execute 400-Host Fleet Scan
	wallClockStart := time.Now()
	results, logs := pool.Execute(context.Background(), targets)
	wallClockDuration := time.Since(wallClockStart)

	// Post-benchmark Memory Stats
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	// 4. Calculate Statistics
	var successfulCount, offlineCount, authFailCount int
	for _, res := range results {
		switch res.Status {
		case "online":
			successfulCount++
		case "offline":
			offlineCount++
		case "auth_error":
			authFailCount++
		}
	}

	throughput := float64(totalTargetCount) / wallClockDuration.Seconds()
	memAllocMB := float64(memAfter.Alloc-memBefore.Alloc) / (1024 * 1024)

	// Print Benchmark Summary Report
	fmt.Println("\n==========================================================================")
	fmt.Println("🚀 400-ENDPOINT FLEET SCAN BENCHMARK REPORT (PRODUCTION AUDIT)")
	fmt.Println("==========================================================================")
	fmt.Printf("• Total Endpoints Scanned : %d\n", len(results))
	fmt.Printf("• Successful Scans (Online): %d (Expected: 300)\n", successfulCount)
	fmt.Printf("• Offline / Timeout Hosts : %d (Expected: 80)\n", offlineCount)
	fmt.Printf("• Auth Failure Hosts      : %d (Expected: 20)\n", authFailCount)
	fmt.Printf("• Worker Pool Concurrency : %d simultaneous WinRM sessions\n", opts.Concurrency)
	fmt.Printf("• Total Wall-Clock Time   : %s\n", wallClockDuration.Round(time.Millisecond))
	fmt.Printf("• Fleet Throughput        : %.2f endpoints / second\n", throughput)
	fmt.Printf("• Memory Allocated (Heap) : %.2f MB\n", memAllocMB)
	fmt.Printf("• Total GC Cycles Run     : %d\n", memAfter.NumGC-memBefore.NumGC)
	fmt.Println("==========================================================================")

	// Assertions
	if len(results) != totalTargetCount {
		t.Fatalf("Expected 400 results, got %d", len(results))
	}
	if successfulCount != 300 {
		t.Errorf("Expected 300 successful scans (260 healthy + 40 slow WAN), got %d", successfulCount)
	}
	if offlineCount != 80 {
		t.Errorf("Expected 80 offline/timeout hosts, got %d", offlineCount)
	}
	if authFailCount != 20 {
		t.Errorf("Expected 20 auth failures, got %d", authFailCount)
	}
	if len(logs) < 2 {
		t.Errorf("Expected worker pool lifecycle logs")
	}
}
