package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/config"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/heartbeat"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/mtls"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/poller"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/scanner"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/streamer"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] Configuration error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[INFO] Starting EndpointGuard Subnet Collector Gateway\n")
	fmt.Printf("[INFO] Gateway ID: %s | Subnet: %s | Max Concurrency: %d\n", cfg.GatewayID, cfg.SubnetCIDR, cfg.MaxConcurrentSessions)
	fmt.Printf("[INFO] Control Plane URL: %s\n", cfg.ControlPlaneURL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Initialize mTLS Enrollment
	enrollMgr := mtls.NewEnrollmentManager(cfg.GatewayID, cfg.SubnetCIDR, cfg.ControlPlaneURL, cfg.CertDir, nil)
	regResp, err := enrollMgr.RegisterAndEnroll(ctx)
	if err != nil {
		fmt.Printf("[WARN] mTLS enrollment initiation note: %v\n", err)
	} else {
		fmt.Printf("[INFO] Enrollment status: %s (Fingerprint: %s)\n", regResp.Status, regResp.Fingerprint)
	}

	// 2. Build HTTP Client with mTLS transport if enrolled
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if tlsConf, err := enrollMgr.BuildTLSClientConfig(); err == nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConf,
		}
	}

	// 3. Initialize Rate Limiter & Scanners
	rateLimiter := scanner.NewSubnetRateLimiter(cfg.MaxConcurrentSessions)
	winrmScanner := scanner.NewWinRMScanner(cfg.ProbeTimeout, nil, cfg.AllowInsecureHTTP)
	bmcScanner := scanner.NewBMCScanner(cfg.ProbeTimeout, nil)

	// JIT Vault Secret Resolver over mTLS
	vaultResolver := func(reqCtx context.Context, gwID, scanJobID, opaqueID string) (string, error) {
		resolveURL := fmt.Sprintf("%s/api/v1/vault/resolve", cfg.ControlPlaneURL)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, resolveURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("X-Gateway-ID", gwID)
		req.Header.Set("X-Scan-Job-ID", scanJobID)
		req.Header.Set("X-Credential-Ref", opaqueID)

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("vault resolution returned status %d", resp.StatusCode)
		}

		secretBytes, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err != nil {
			return "", err
		}
		return string(secretBytes), nil
	}

	orchestrator := scanner.NewScanOrchestrator(cfg.GatewayID, rateLimiter, winrmScanner, bmcScanner, vaultResolver)
	resultStreamer := streamer.NewResultStreamer(cfg.ControlPlaneURL, cfg.GatewayID, httpClient)

	// 4. Initialize 60s Heartbeat Daemon
	hbDaemon := heartbeat.NewDaemon(
		cfg.GatewayID,
		cfg.SubnetCIDR,
		cfg.ControlPlaneURL,
		cfg.HeartbeatInterval,
		httpClient,
		"v1.2.4",
		rateLimiter.ActiveSessions,
	)
	go hbDaemon.Start(ctx)

	// 5. Initialize Job Poller
	jobPoller := poller.NewPoller(
		cfg.GatewayID,
		cfg.ManagedSubnets,
		cfg.ControlPlaneURL,
		cfg.PollMinInterval,
		cfg.PollMaxInterval,
		httpClient,
	)

	// 6. Poller & Worker Dispatch Loop
	go func() {
		fmt.Printf("[INFO] Subnet worker active. Polling jobs with exponential backoff & jitter...\n")
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			jobs, err := jobPoller.PollOnce(ctx)
			if err != nil {
				// Log transient poll failure
			} else if len(jobs) > 0 {
				for _, job := range jobs {
					fmt.Printf("[INFO] Executing scan job %s (%s) for target %s\n", job.ID, job.Name, job.TargetCIDR)
					batch, scanErr := orchestrator.ExecuteScanJob(ctx, job.ID, job.TargetCIDR, job.Protocol, job.VaultSecretRef, job.TargetHosts, cfg.AllowInsecureHTTP)
					if scanErr != nil {
						fmt.Printf("[ERROR] Job %s failed: %v\n", job.ID, scanErr)
					} else {
						hash, streamErr := resultStreamer.StreamResults(ctx, batch)
						if streamErr != nil {
							fmt.Printf("[ERROR] Streaming results for job %s failed: %v\n", job.ID, streamErr)
						} else {
							fmt.Printf("[INFO] Successfully streamed results for job %s (Payload Hash: %s)\n", job.ID, hash)
						}
					}
				}
			}

			sleepDuration := jobPoller.NextDelay()
			select {
			case <-time.After(sleepDuration):
			case <-ctx.Done():
				return
			}
		}
	}()

	// 7. Graceful Shutdown Management
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	fmt.Printf("[INFO] Subnet Collector Gateway received shutdown signal. Terminating cleanly...\n")
	cancel()
	hbDaemon.Stop()
	time.Sleep(300 * time.Millisecond)
	fmt.Printf("[INFO] Gateway shutdown complete.\n")
}
