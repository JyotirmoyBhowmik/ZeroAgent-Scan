package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultCISAKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultKEVTimeout = 30 * time.Second
)

// KEVClient ingests CISA's Known Exploited Vulnerabilities catalog.
type KEVClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewKEVClient creates a new CISA KEV catalog ingestor.
func NewKEVClient(baseURL string, customHTTP *http.Client) *KEVClient {
	if baseURL == "" {
		baseURL = DefaultCISAKEVURL
	}

	client := customHTTP
	if client == nil {
		client = &http.Client{
			Timeout: DefaultKEVTimeout,
		}
	}

	return &KEVClient{
		baseURL:    baseURL,
		httpClient: client,
	}
}

// FetchCatalog downloads and parses the latest CISA KEV JSON catalog.
func (k *KEVClient) FetchCatalog(ctx context.Context) (*CISAKEVFeed, map[string]CISAKEVItem, error) {
	var lastErr error
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, k.baseURL, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("kev_client: failed to create request: %w", err)
		}

		httpReq.Header.Set("Accept", "application/json")
		httpReq.Header.Set("User-Agent", "ZeroAgent-VulnScan/1.0 (CISA KEV Ingestor)")

		resp, err := k.httpClient.Do(httpReq)
		if err != nil {
			lastErr = err
			backoff := CalculateBackoff(attempt, 500*time.Millisecond, 5*time.Second)
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			lastErr = fmt.Errorf("kev_client: unexpected HTTP status %d: %s", resp.StatusCode, string(body))
			backoff := CalculateBackoff(attempt, 1*time.Second, 5*time.Second)
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}

		var feed CISAKEVFeed
		decErr := json.NewDecoder(resp.Body).Decode(&feed)
		resp.Body.Close()
		if decErr != nil {
			return nil, nil, fmt.Errorf("kev_client: failed to decode JSON feed: %w", decErr)
		}

		lookupMap := make(map[string]CISAKEVItem, len(feed.Vulnerabilities))
		for _, item := range feed.Vulnerabilities {
			cveKey := strings.ToUpper(strings.TrimSpace(item.CVEID))
			if cveKey != "" {
				lookupMap[cveKey] = item
			}
		}

		return &feed, lookupMap, nil
	}

	return nil, nil, fmt.Errorf("kev_client: failed after %d attempts: %w", maxRetries, lastErr)
}
