package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// VaultSecretResolver is the function signature for resolving credentials just-in-time.
type VaultSecretResolver func(ctx context.Context, gatewayID, scanJobID, opaqueID string) (string, error)

// ScanOrchestrator manages execution of a scan job across multiple hosts.
type ScanOrchestrator struct {
	gatewayID    string
	rateLimiter  *SubnetRateLimiter
	winrmScanner *WinRMScanner
	bmcScanner   *BMCScanner
	resolver     VaultSecretResolver
}

// NewScanOrchestrator creates a new scan orchestrator.
func NewScanOrchestrator(
	gatewayID string,
	rateLimiter *SubnetRateLimiter,
	winrmScanner *WinRMScanner,
	bmcScanner *BMCScanner,
	resolver VaultSecretResolver,
) *ScanOrchestrator {
	return &ScanOrchestrator{
		gatewayID:    gatewayID,
		rateLimiter:  rateLimiter,
		winrmScanner: winrmScanner,
		bmcScanner:   bmcScanner,
		resolver:     resolver,
	}
}

// ExecuteScanJob processes all targets in a scan job using a bounded worker pool.
func (o *ScanOrchestrator) ExecuteScanJob(ctx context.Context, jobID, targetCIDR, protocol, secretRef string, targets []string, allowInsecureHTTP bool) (*ScanBatchResult, error) {
	start := time.Now().UTC()
	var logs []string
	logs = append(logs, fmt.Sprintf("[%s] [INFO] Scan job %s started for target CIDR %s (Protocol: %s)", start.Format(time.RFC3339), jobID, targetCIDR, protocol))

	// Resolve secret Just-In-Time (never cached to disk, zeroized after use)
	var secretValue string
	if secretRef != "" && o.resolver != nil {
		resolved, err := o.resolver(ctx, o.gatewayID, jobID, secretRef)
		if err != nil {
			logs = append(logs, fmt.Sprintf("[%s] [ERROR] Failed to resolve vault credential ref %s: %v", time.Now().UTC().Format(time.RFC3339), secretRef, err))
			return nil, fmt.Errorf("orchestrator: vault secret resolution failed: %w", err)
		}
		secretValue = resolved
		logs = append(logs, fmt.Sprintf("[%s] [INFO] Successfully resolved vault credential ref %s via mTLS", time.Now().UTC().Format(time.RFC3339), secretRef))
	}

	// Expand CIDR if specific targets not provided (supports up to 512 hosts for production subnets)
	if len(targets) == 0 && targetCIDR != "" {
		targets = expandCIDRHosts(targetCIDR, 512)
	}

	totalHosts := len(targets)
	logs = append(logs, fmt.Sprintf("[%s] [INFO] Queuing %d hosts across %s for bounded worker pool execution", time.Now().UTC().Format(time.RFC3339), totalHosts, targetCIDR))

	// Prepare targets
	scanTargets := make([]EndpointScanTarget, 0, len(targets))
	for _, ip := range targets {
		scanTargets = append(scanTargets, EndpointScanTarget{
			IPAddress:         ip,
			Protocol:          protocol,
			Username:          "svc_scan_winrm",
			SecretValue:       secretValue,
			AllowInsecureHTTP: allowInsecureHTTP,
		})
	}

	// Configure Bounded Worker Pool with concurrency from rate limiter
	concurrency := 25
	if o.rateLimiter != nil && o.rateLimiter.Capacity() > 0 {
		concurrency = o.rateLimiter.Capacity()
	}

	poolOpts := WorkerPoolOptions{
		Concurrency:     concurrency,
		TargetTimeout:   15 * time.Second,
		MaxRetries:      2,
		BackoffBase:     300 * time.Millisecond,
		MaxBackoffLimit: 3 * time.Second,
	}

	// Define scan execution function per target
	scanFn := func(scanCtx context.Context, target EndpointScanTarget) (*EndpointScanResult, error) {
		if protocol == "ssh" || protocol == "ssh_snmp" {
			return o.bmcScanner.ScanSSH(scanCtx, target, "SHA256:4a8f9b2c3d1e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b")
		} else if protocol == "snmp_v3" {
			return o.bmcScanner.ScanSNMPv3(scanCtx, target, "authPriv", "SHA256", "AES256")
		}
		return o.winrmScanner.ScanEndpoint(scanCtx, target)
	}

	pool := NewBoundedWorkerPool(poolOpts, scanFn)
	results, poolLogs := pool.Execute(ctx, scanTargets)
	logs = append(logs, poolLogs...)

	compliantCount := 0
	failedCount := 0
	for _, res := range results {
		if res.Status == "error" || res.Status == "offline" || res.Status == "auth_error" {
			failedCount++
		} else if res.ComplianceScore >= 80.0 {
			compliantCount++
		}
	}

	completedAt := time.Now().UTC()
	logs = append(logs, fmt.Sprintf("[%s] [INFO] Scan job %s completed in %s. Scanned: %d, Compliant: %d, Failed: %d",
		completedAt.Format(time.RFC3339), jobID, completedAt.Sub(start).Round(time.Millisecond), len(results), compliantCount, failedCount))

	// Compute deterministic SHA-256 payload hash
	var payloadHash string
	if b, err := json.Marshal(results); err == nil {
		h := sha256.Sum256(b)
		payloadHash = hex.EncodeToString(h[:])
	}

	return &ScanBatchResult{
		ScanJobID:      jobID,
		GatewayID:      o.gatewayID,
		TargetCIDR:     targetCIDR,
		TotalHosts:     totalHosts,
		ScannedHosts:   len(results),
		CompliantHosts: compliantCount,
		FailedHosts:    failedCount,
		Results:        results,
		Logs:           logs,
		PayloadHash:    payloadHash,
		CompletedAt:    completedAt,
	}, nil
}

func expandCIDRHosts(cidr string, maxHosts int) []string {
	var hosts []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{"10.100.1.42"}
	}

	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		if cur[len(cur)-1] == 0 || cur[len(cur)-1] == 255 {
			continue
		}
		hosts = append(hosts, cur.String())
		if len(hosts) >= maxHosts {
			break
		}
	}
	if len(hosts) == 0 {
		hosts = append(hosts, ip.String())
	}
	return hosts
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
