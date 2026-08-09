package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type GatewayConfig struct {
	GatewayID            string
	SubnetCIDR           string
	ControlPlaneURL      string
	HeartbeatIntervalSec int
	ProbeTimeoutSec      int
}

type HeartbeatPayload struct {
	GatewayCode string `json:"gateway_code"`
	LatencyMs   int    `json:"latency_ms"`
}

type GatewayDaemon struct {
	cfg        GatewayConfig
	httpClient *http.Client
	stopChan   chan struct{}
}

func NewGatewayDaemon(cfg GatewayConfig) *GatewayDaemon {
	return &GatewayDaemon{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopChan: make(chan struct{}),
	}
}

func (g *GatewayDaemon) SendHeartbeat(ctx context.Context) error {
	start := time.Now()
	url := fmt.Sprintf("%s/api/v1/gateways/heartbeat", g.cfg.ControlPlaneURL)

	payload := HeartbeatPayload{
		GatewayCode: g.cfg.GatewayID,
		LatencyMs:   int(time.Since(start).Milliseconds()),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("EndpointGuard-Gateway/%s", g.cfg.GatewayID))

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat HTTP failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("heartbeat rejected with status: %d", resp.StatusCode)
	}

	return nil
}

func (g *GatewayDaemon) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(g.cfg.HeartbeatIntervalSec) * time.Second)
	defer ticker.Stop()

	// Initial heartbeat immediately
	_ = g.SendHeartbeat(ctx)

	for {
		select {
		case <-ticker.C:
			if err := g.SendHeartbeat(ctx); err != nil {
				fmt.Printf("[WARN] Gateway heartbeat failed: %v\n", err)
			}
		case <-g.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (g *GatewayDaemon) Stop() {
	close(g.stopChan)
}
