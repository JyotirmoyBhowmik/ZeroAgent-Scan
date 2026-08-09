package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	DefaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultNVDTimeout = 15 * time.Second
	MaxNVDResultsPerPage = 2000
)

// NVDClient provides an HTTP client for querying the NVD CVE API 2.0.
type NVDClient struct {
	baseURL     string
	apiKey      string
	httpClient  *http.Client
	rateLimiter *RateLimiter
}

// NewNVDClient creates an NVD API 2.0 client with rate budgeting and explicit timeouts.
func NewNVDClient(baseURL, apiKey string, customHTTP *http.Client) *NVDClient {
	if baseURL == "" {
		baseURL = DefaultNVDBaseURL
	}

	client := customHTTP
	if client == nil {
		client = &http.Client{
			Timeout: DefaultNVDTimeout,
		}
	}

	return &NVDClient{
		baseURL:     baseURL,
		apiKey:      apiKey,
		httpClient:  client,
		rateLimiter: NewNVDRateLimiter(apiKey != ""),
	}
}

// FetchCVEsOptions defines query parameters for fetching CVEs from NVD.
type FetchCVEsOptions struct {
	StartIndex         int
	ResultsPerPage     int
	LastModStartDate   *time.Time
	LastModEndDate     *time.Time
	CveID              string
	CpeName            string
	VirtualMatchString string
}

// FetchCVEPage queries a single page of CVEs from NVD API 2.0 with retries and rate limiting.
func (c *NVDClient) FetchCVEPage(ctx context.Context, opts FetchCVEsOptions) (*NVDResponse, error) {
	if opts.ResultsPerPage <= 0 || opts.ResultsPerPage > MaxNVDResultsPerPage {
		opts.ResultsPerPage = 100 // Safe default
	}

	reqURL, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("nvd_client: invalid base URL: %w", err)
	}

	q := reqURL.Query()
	q.Set("startIndex", strconv.Itoa(opts.StartIndex))
	q.Set("resultsPerPage", strconv.Itoa(opts.ResultsPerPage))

	if opts.CveID != "" {
		q.Set("cveId", opts.CveID)
	}
	if opts.CpeName != "" {
		q.Set("cpeName", opts.CpeName)
	}
	if opts.VirtualMatchString != "" {
		q.Set("virtualMatchString", opts.VirtualMatchString)
	}
	if opts.LastModStartDate != nil && opts.LastModEndDate != nil {
		// NVD 2.0 format: 2024-01-01T00:00:00.000Z
		const nvdTimeFormat = "2006-01-02T15:04:05.000"
		q.Set("lastModStartDate", opts.LastModStartDate.UTC().Format(nvdTimeFormat))
		q.Set("lastModEndDate", opts.LastModEndDate.UTC().Format(nvdTimeFormat))
	}

	reqURL.RawQuery = q.Encode()

	var lastErr error
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Wait for rate limiter token
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("nvd_client: rate limiter cancelled: %w", err)
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("nvd_client: failed to create request: %w", err)
		}

		httpReq.Header.Set("Accept", "application/json")
		httpReq.Header.Set("User-Agent", "ZeroAgent-VulnScan/1.0 (Enterprise Security Audit)")
		if c.apiKey != "" {
			httpReq.Header.Set("apiKey", c.apiKey)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = err
			backoff := CalculateBackoff(attempt, 500*time.Millisecond, 5*time.Second)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}

		// Handle 429 Too Many Requests or 5xx Server Errors
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("nvd_client: HTTP status %d received", resp.StatusCode)
			backoff := CalculateBackoff(attempt, 1*time.Second, 10*time.Second)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			return nil, fmt.Errorf("nvd_client: unexpected HTTP status %d: %s", resp.StatusCode, string(body))
		}

		var nvdResp NVDResponse
		decErr := json.NewDecoder(resp.Body).Decode(&nvdResp)
		resp.Body.Close()
		if decErr != nil {
			return nil, fmt.Errorf("nvd_client: failed to decode JSON response: %w", decErr)
		}

		return &nvdResp, nil
	}

	return nil, fmt.Errorf("nvd_client: failed after %d attempts: %w", maxRetries, lastErr)
}

// ConvertNVDItemToCached extracts clean domain fields from an NVD 2.0 CVE item.
func ConvertNVDItemToCached(item NVDCVEItem) *CachedCVE {
	title := item.ID
	desc := ""
	for _, d := range item.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if desc == "" && len(item.Descriptions) > 0 {
		desc = item.Descriptions[0].Value
	}

	cvssScore := 0.0
	cvssVer := "v3.1"
	cvssVector := ""
	severity := "UNKNOWN"

	// Check CVSS v3.1 first
	if len(item.Metrics.CvssMetricV31) > 0 {
		m := item.Metrics.CvssMetricV31[0].CvssData
		cvssScore = m.BaseScore
		cvssVer = "v3.1"
		cvssVector = m.VectorString
		severity = m.BaseSeverity
	} else if len(item.Metrics.CvssMetricV30) > 0 {
		m := item.Metrics.CvssMetricV30[0].CvssData
		cvssScore = m.BaseScore
		cvssVer = "v3.0"
		cvssVector = m.VectorString
		severity = m.BaseSeverity
	} else if len(item.Metrics.CvssMetricV2) > 0 {
		m := item.Metrics.CvssMetricV2[0].CvssData
		cvssScore = m.BaseScore
		cvssVer = "v2.0"
		cvssVector = m.VectorString
		if cvssScore >= 7.0 {
			severity = "HIGH"
		} else if cvssScore >= 4.0 {
			severity = "MEDIUM"
		} else {
			severity = "LOW"
		}
	}

	// Extract CPE matches
	var cpeMatches []NVDCpeMatch
	for _, config := range item.Configurations {
		for _, node := range config.Nodes {
			cpeMatches = append(cpeMatches, node.CpeMatch...)
		}
	}

	// Extract references
	var refs []string
	for _, r := range item.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}

	pubDate, _ := time.Parse(time.RFC3339, item.Published)
	modDate, _ := time.Parse(time.RFC3339, item.LastModified)

	return &CachedCVE{
		CVEID:          item.ID,
		Title:          title,
		Description:    desc,
		Severity:       severity,
		CVSSScore:      cvssScore,
		CVSSVersion:    cvssVer,
		CVSSVector:     cvssVector,
		PublishedAt:    pubDate,
		LastModifiedAt: modDate,
		CpeMatches:     cpeMatches,
		References:     refs,
		CachedAt:       time.Now().UTC(),
	}
}
