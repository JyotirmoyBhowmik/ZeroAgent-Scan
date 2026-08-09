package poller

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ScanJobDescriptor represents a job fetched from the control plane queue.
type ScanJobDescriptor struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	TargetCIDR     string   `json:"target_cidr"`
	ScanProfile    string   `json:"scan_profile"`
	Protocol       string   `json:"protocol"` // "winrm_https", "winrm_http", "ssh_snmp"
	VaultSecretRef string   `json:"vault_secret_ref"`
	GatewayID      string   `json:"gateway_id"`
	TargetHosts    []string `json:"target_hosts,omitempty"`
}

// Poller polls the control plane for scan jobs with exponential backoff and jitter.
type Poller struct {
	gatewayID       string
	subnets         []string
	controlPlaneURL string
	httpClient      *http.Client
	minInterval     time.Duration
	maxInterval     time.Duration
	currentInterval time.Duration
	consecutiveZero int
	mu              sync.Mutex
}

// NewPoller creates a new job poller with exponential backoff and jitter.
func NewPoller(gatewayID string, subnets []string, controlPlaneURL string, minInterval, maxInterval time.Duration, httpClient *http.Client) *Poller {
	if minInterval <= 0 {
		minInterval = 2 * time.Second
	}
	if maxInterval <= minInterval {
		maxInterval = 30 * time.Second
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Poller{
		gatewayID:       gatewayID,
		subnets:         subnets,
		controlPlaneURL: strings.TrimRight(controlPlaneURL, "/"),
		httpClient:      httpClient,
		minInterval:     minInterval,
		maxInterval:     maxInterval,
		currentInterval: minInterval,
	}
}

// PollOnce queries the control plane for queued jobs for this gateway and its subnets.
func (p *Poller) PollOnce(ctx context.Context) ([]ScanJobDescriptor, error) {
	u, err := url.Parse(fmt.Sprintf("%s/api/v1/gateways/jobs/poll", p.controlPlaneURL))
	if err != nil {
		return nil, fmt.Errorf("poller: invalid control plane url: %w", err)
	}

	q := u.Query()
	q.Set("gateway_id", p.gatewayID)
	q.Set("subnets", strings.Join(p.subnets, ","))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("poller: failed to create poll request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("EndpointGuard-Gateway-Poller/%s", p.gatewayID))

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poller: HTTP poll request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		p.recordPollResult(0)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		p.recordPollResult(0)
		return nil, fmt.Errorf("poller: server returned status %d: %s", resp.StatusCode, string(body))
	}

	var jobs []ScanJobDescriptor
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jobs); err != nil {
		p.recordPollResult(0)
		return nil, fmt.Errorf("poller: failed to decode job descriptors: %w", err)
	}

	p.recordPollResult(len(jobs))
	return jobs, nil
}

// NextDelay calculates the next sleep duration using exponential backoff with full jitter:
// delay = random_between(0, min(maxInterval, minInterval * 2^consecutiveZero))
func (p *Poller) NextDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Calculate base exponential backoff
	backoffFactor := math.Pow(2, float64(p.consecutiveZero))
	baseDelay := float64(p.minInterval) * backoffFactor
	if baseDelay > float64(p.maxInterval) {
		baseDelay = float64(p.maxInterval)
	}

	// Apply full jitter: random value between [0.5 * base, 1.0 * base] or [minInterval, base]
	jitterFraction := secureRandomFloat() // 0.0 to 1.0
	delayNano := float64(p.minInterval) + jitterFraction*(baseDelay-float64(p.minInterval))
	if delayNano < float64(p.minInterval) {
		delayNano = float64(p.minInterval)
	}

	return time.Duration(delayNano)
}

func (p *Poller) recordPollResult(jobCount int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if jobCount > 0 {
		p.consecutiveZero = 0
		p.currentInterval = p.minInterval
	} else {
		if p.consecutiveZero < 10 {
			p.consecutiveZero++
		}
	}
}

// secureRandomFloat generates a cryptographic float in [0.0, 1.0).
func secureRandomFloat() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	val := binary.BigEndian.Uint64(b[:])
	return float64(val) / (float64(^uint64(0)) + 1.0)
}
