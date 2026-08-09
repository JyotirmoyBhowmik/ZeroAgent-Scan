package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HeartbeatPayload is sent periodically to report gateway liveness.
type HeartbeatPayload struct {
	GatewayCode    string    `json:"gateway_code"`
	SubnetCIDR     string    `json:"subnet_cidr"`
	Status         string    `json:"status"` // healthy, degraded
	Version        string    `json:"version"`
	LatencyMs      int       `json:"latency_ms"`
	ActiveSessions int       `json:"active_sessions"`
	Timestamp      time.Time `json:"timestamp"`
}

// Daemon runs the background periodic heartbeat emitter.
type Daemon struct {
	gatewayID       string
	subnetCIDR      string
	controlPlaneURL string
	interval        time.Duration
	httpClient      *http.Client
	version         string
	activeSessionsFn func() int
	stopChan        chan struct{}
	mu              sync.Mutex
	lastLatencyMs   int
}

// NewDaemon creates a configured heartbeat daemon.
func NewDaemon(gatewayID, subnetCIDR, controlPlaneURL string, interval time.Duration, httpClient *http.Client, version string, activeSessionsFn func() int) *Daemon {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if version == "" {
		version = "v1.2.4"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Daemon{
		gatewayID:        gatewayID,
		subnetCIDR:       subnetCIDR,
		controlPlaneURL:  strings.TrimRight(controlPlaneURL, "/"),
		interval:         interval,
		httpClient:       httpClient,
		version:          version,
		activeSessionsFn: activeSessionsFn,
		stopChan:         make(chan struct{}),
	}
}

// SendHeartbeat performs a single heartbeat HTTP transmission and calculates round-trip latency.
func (d *Daemon) SendHeartbeat(ctx context.Context) error {
	start := time.Now()
	url := fmt.Sprintf("%s/api/v1/gateways/heartbeat", d.controlPlaneURL)

	activeSessions := 0
	if d.activeSessionsFn != nil {
		activeSessions = d.activeSessionsFn()
	}

	payload := HeartbeatPayload{
		GatewayCode:    d.gatewayID,
		SubnetCIDR:     d.subnetCIDR,
		Status:         "healthy",
		Version:        d.version,
		LatencyMs:      0, // measured on response
		ActiveSessions: activeSessions,
		Timestamp:      start.UTC(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("heartbeat: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("heartbeat: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("EndpointGuard-Gateway-Heartbeat/%s", d.gatewayID))

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	latency := int(time.Since(start).Milliseconds())
	d.mu.Lock()
	d.lastLatencyMs = latency
	d.mu.Unlock()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("heartbeat: control plane returned status %d", resp.StatusCode)
	}

	return nil
}

// Start runs the periodic 60-second ticker until context is cancelled or Stop is called.
func (d *Daemon) Start(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	// Initial heartbeat immediately on startup
	_ = d.SendHeartbeat(ctx)

	for {
		select {
		case <-ticker.C:
			_ = d.SendHeartbeat(ctx)
		case <-d.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// Stop terminates the heartbeat loop cleanly.
func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.stopChan:
		// already closed
	default:
		close(d.stopChan)
	}
}

// LastLatencyMs returns the latest measured round-trip time.
func (d *Daemon) LastLatencyMs() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastLatencyMs
}
