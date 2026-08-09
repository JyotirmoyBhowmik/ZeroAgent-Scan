package streamer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/scanner"
)

// ResultStreamer transmits scan results to the Central API with tamper-evident payload hashing.
type ResultStreamer struct {
	controlPlaneURL string
	gatewayID       string
	httpClient      *http.Client
}

// NewResultStreamer creates a new result streamer.
func NewResultStreamer(controlPlaneURL, gatewayID string, httpClient *http.Client) *ResultStreamer {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &ResultStreamer{
		controlPlaneURL: strings.TrimRight(controlPlaneURL, "/"),
		gatewayID:       gatewayID,
		httpClient:      httpClient,
	}
}

// ComputePayloadHash calculates the SHA-256 digest of raw byte slice.
func ComputePayloadHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// StreamResults serializes results, computes the gateway-side SHA-256 payload_hash,
// and transmits the batch to the Control Plane API.
func (s *ResultStreamer) StreamResults(ctx context.Context, batch *scanner.ScanBatchResult) (string, error) {
	// First serialize without the final hash
	rawJSON, err := json.Marshal(batch)
	if err != nil {
		return "", fmt.Errorf("streamer: failed to marshal results payload: %w", err)
	}

	// Compute SHA-256 hash gateway-side for cryptographic tamper evidence
	payloadHash := ComputePayloadHash(rawJSON)
	batch.PayloadHash = payloadHash

	// Re-marshal with populated payload_hash
	finalPayload, err := json.Marshal(batch)
	if err != nil {
		return "", fmt.Errorf("streamer: failed to marshal final payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/scans/%s/results", s.controlPlaneURL, batch.ScanJobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(finalPayload))
	if err != nil {
		return "", fmt.Errorf("streamer: failed to create stream request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-ID", s.gatewayID)
	req.Header.Set("X-Payload-Hash", payloadHash)
	req.Header.Set("User-Agent", fmt.Sprintf("EndpointGuard-Gateway-Streamer/%s", s.gatewayID))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("streamer: HTTP transmission failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("streamer: API rejected results with status %d: %s", resp.StatusCode, string(body))
	}

	return payloadHash, nil
}
