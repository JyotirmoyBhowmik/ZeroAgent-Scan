package drift

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// WebhookDispatcher sends HMAC-signed alert notifications with exponential backoff retries.
type WebhookDispatcher struct {
	httpClient *http.Client
	maxRetries int
	baseDelay  time.Duration
}

// NewWebhookDispatcher creates an initialized webhook dispatcher.
func NewWebhookDispatcher(client *http.Client, maxRetries int) *WebhookDispatcher {
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
		}
	}
	if maxRetries <= 0 {
		maxRetries = 3
	}
	return &WebhookDispatcher{
		httpClient: client,
		maxRetries: maxRetries,
		baseDelay:  100 * time.Millisecond,
	}
}

// ComputeHMACSignature computes the hex-encoded HMAC-SHA256 signature for a payload.
func ComputeHMACSignature(secretKey string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature verifies that a received signature matches the computed HMAC-SHA256 signature.
func VerifyWebhookSignature(secretKey string, payload []byte, signatureHeader string) bool {
	sig := strings.TrimPrefix(signatureHeader, "sha256=")
	expected := ComputeHMACSignature(secretKey, payload)
	return hmac.Equal([]byte(sig), []byte(expected))
}

// Dispatch sends the webhook notification to the target URL with HMAC-SHA256 signature and retry logic.
func (d *WebhookDispatcher) Dispatch(
	ctx context.Context,
	rule AlertRule,
	event DriftEvent,
	assetClass string,
) (*WebhookDeliveryLog, error) {
	deliveryID := uuid.New().String()
	timestampStr := time.Now().UTC().Format(time.RFC3339)

	payload := WebhookNotificationPayload{
		DeliveryID:   deliveryID,
		TimestampUTC: timestampStr,
		TenantID:     event.TenantID,
		RuleID:       rule.ID,
		RuleName:     rule.Name,
		HostID:       event.HostID,
		Hostname:     event.Hostname,
		AssetClass:   assetClass,
		Event:        event,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("webhook: failed to marshal payload: %w", err)
	}

	signatureHex := ComputeHMACSignature(rule.SecretKey, payloadBytes)
	signatureHeader := fmt.Sprintf("sha256=%s", signatureHex)

	start := time.Now()
	var lastErr error
	var statusCode int

	for attempt := 1; attempt <= d.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rule.WebhookURL, bytes.NewReader(payloadBytes))
		if err != nil {
			return nil, fmt.Errorf("webhook: failed to build request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-EndpointGuard-Signature", signatureHeader)
		req.Header.Set("X-EndpointGuard-Timestamp", timestampStr)
		req.Header.Set("X-EndpointGuard-Delivery-ID", deliveryID)
		req.Header.Set("X-EndpointGuard-Event", "configuration.drift")

		resp, err := d.httpClient.Do(req)
		if err == nil {
			statusCode = resp.StatusCode
			_ = resp.Body.Close()

			if statusCode >= 200 && statusCode < 300 {
				// Delivery Success!
				duration := time.Since(start).Milliseconds()
				return &WebhookDeliveryLog{
					ID:          uuid.New().String(),
					TenantID:    event.TenantID,
					RuleID:      rule.ID,
					EventID:     event.ID,
					TargetURL:   rule.WebhookURL,
					StatusCode:  statusCode,
					DurationMs:  duration,
					Attempts:    attempt,
					Status:      "SUCCESS",
					DeliveredAt: time.Now().UTC(),
				}, nil
			}
			lastErr = fmt.Errorf("webhook server returned status %d", statusCode)
		} else {
			lastErr = err
		}

		// If attempts remaining, backoff with jitter
		if attempt < d.maxRetries {
			delay := d.baseDelay * (1 << (attempt - 1))
			jitter := time.Duration(rand.Int63n(int64(delay / 2)))
			select {
			case <-ctx.Done():
				lastErr = ctx.Err()
				break
			case <-time.After(delay + jitter):
			}
		}
	}

	// Delivery Failed after max retries
	duration := time.Since(start).Milliseconds()
	errStr := ""
	if lastErr != nil {
		errStr = lastErr.Error()
	}

	log := &WebhookDeliveryLog{
		ID:           uuid.New().String(),
		TenantID:     event.TenantID,
		RuleID:       rule.ID,
		EventID:      event.ID,
		TargetURL:    rule.WebhookURL,
		StatusCode:   statusCode,
		DurationMs:   duration,
		Attempts:     d.maxRetries,
		Status:       "FAILED",
		ErrorMessage: &errStr,
		DeliveredAt:  time.Now().UTC(),
	}

	return log, lastErr
}
