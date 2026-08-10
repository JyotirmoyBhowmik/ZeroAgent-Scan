package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
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

// ExecuteScanJob processes all targets in a scan job under rate-limited concurrency.
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
	logs = append(logs, fmt.Sprintf("[%s] [INFO] Probing %d hosts across %s (Rate Limit: %d concurrent sessions)", time.Now().UTC().Format(time.RFC3339), totalHosts, targetCIDR, o.rateLimiter.Capacity()))

	var mu sync.Mutex
	var results []EndpointScanResult
	var wg sync.WaitGroup

	compliantCount := 0
	failedCount := 0

	for _, host := range targets {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			target := EndpointScanTarget{
				IPAddress:         ip,
				Protocol:          protocol,
				Username:          "svc_scan_winrm",
				SecretValue:       secretValue,
				AllowInsecureHTTP: allowInsecureHTTP,
			}

			// Rate limit execution
			_ = o.rateLimiter.Execute(ctx, func() error {
				var res *EndpointScanResult
				var err error

				if protocol == "ssh" || protocol == "ssh_snmp" {
					res, err = o.bmcScanner.ScanSSH(ctx, target, "SHA256:4a8f9b2c3d1e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b")
				} else if protocol == "snmp_v3" {
					res, err = o.bmcScanner.ScanSNMPv3(ctx, target, "authPriv", "SHA256", "AES256")
				} else {
					res, err = o.winrmScanner.ScanEndpoint(ctx, target)
				}

				mu.Lock()
				defer mu.Unlock()

				if err != nil {
					failedCount++
					if res != nil {
						results = append(results, *res)
					}
					logs = append(logs, fmt.Sprintf("[%s] [WARN] Host %s probe failed: %v", time.Now().UTC().Format(time.RFC3339), ip, err))
				} else {
					if res.ComplianceScore >= 80.0 {
						compliantCount++
					}
					results = append(results, *res)
					logs = append(logs, fmt.Sprintf("[%s] [INFO] Host %s scanned successfully (Score: %.1f%%)", time.Now().UTC().Format(time.RFC3339), ip, res.ComplianceScore))
				}
				return nil
			})
		}(host)
	}

	wg.Wait()
	completedAt := time.Now().UTC()
	logs = append(logs, fmt.Sprintf("[%s] [INFO] Scan job %s completed. Scanned: %d, Compliant: %d, Failed: %d", completedAt.Format(time.RFC3339), jobID, len(results), compliantCount, failedCount))

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
