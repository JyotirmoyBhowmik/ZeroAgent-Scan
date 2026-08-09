package vulnscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
)

// ---------------------------------------------------------------------------
// Fixture Data Generators
// ---------------------------------------------------------------------------

func sampleNVDCVEFeed() NVDResponse {
	return NVDResponse{
		ResultsPerPage: 3,
		StartIndex:     0,
		TotalResults:   3,
		Format:         "NVD_CVE",
		Version:        "2.0",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Vulnerabilities: []NVDVulnerability{
			{
				CVE: NVDCVEItem{
					ID:           "CVE-2024-30078",
					Published:    "2024-06-11T17:16:00.000",
					LastModified: "2024-06-12T12:00:00.000",
					Descriptions: []NVDDescription{
						{Lang: "en", Value: "Windows Wi-Fi Driver Remote Code Execution Vulnerability."},
					},
					Metrics: NVDMetrics{
						CvssMetricV31: []NVDCvssV31{
							{
								Source: "nvd@nist.gov",
								Type:   "Primary",
								CvssData: NVDCvssV31Data{
									Version:      "3.1",
									VectorString: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									BaseScore:    8.8,
									BaseSeverity: "HIGH",
								},
							},
						},
					},
					Configurations: []NVDConfiguration{
						{
							Nodes: []NVDNode{
								{
									Operator: "OR",
									CpeMatch: []NVDCpeMatch{
										{
											Vulnerable:          true,
											Criteria:            "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*",
											VersionEndExcluding: "10.0.22631.3737",
										},
									},
								},
							},
						},
					},
				},
			},
			{
				CVE: NVDCVEItem{
					ID:           "CVE-2024-21408",
					Published:    "2024-03-12T17:15:00.000",
					LastModified: "2024-03-13T10:00:00.000",
					Descriptions: []NVDDescription{
						{Lang: "en", Value: "Windows Hyper-V Remote Code Execution Vulnerability."},
					},
					Metrics: NVDMetrics{
						CvssMetricV31: []NVDCvssV31{
							{
								Source: "nvd@nist.gov",
								Type:   "Primary",
								CvssData: NVDCvssV31Data{
									Version:      "3.1",
									VectorString: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
									BaseScore:    7.8,
									BaseSeverity: "HIGH",
								},
							},
						},
					},
					Configurations: []NVDConfiguration{
						{
							Nodes: []NVDNode{
								{
									Operator: "OR",
									CpeMatch: []NVDCpeMatch{
										{
											Vulnerable: true,
											Criteria:   "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
										},
									},
								},
							},
						},
					},
				},
			},
			{
				CVE: NVDCVEItem{
					ID:           "CVE-2023-4863",
					Published:    "2023-09-12T15:15:00.000",
					LastModified: "2023-09-13T10:00:00.000",
					Descriptions: []NVDDescription{
						{Lang: "en", Value: "Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187."},
					},
					Metrics: NVDMetrics{
						CvssMetricV31: []NVDCvssV31{
							{
								Source: "nvd@nist.gov",
								Type:   "Primary",
								CvssData: NVDCvssV31Data{
									Version:      "3.1",
									VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
									BaseScore:    8.8,
									BaseSeverity: "HIGH",
								},
							},
						},
					},
					Configurations: []NVDConfiguration{
						{
							Nodes: []NVDNode{
								{
									Operator: "OR",
									CpeMatch: []NVDCpeMatch{
										{
											Vulnerable:          true,
											Criteria:            "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
											VersionEndExcluding: "116.0.5845.187",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func sampleCISAKEVFeed() CISAKEVFeed {
	return CISAKEVFeed{
		Title:          "CISA Known Exploited Vulnerabilities Catalog",
		CatalogVersion: "2024.06.12",
		DateReleased:   "2024-06-12T12:00:00.000Z",
		Count:          2,
		Vulnerabilities: []CISAKEVItem{
			{
				CVEID:                      "CVE-2024-30078",
				VendorProject:              "Microsoft",
				Product:                    "Windows",
				VulnerabilityName:          "Microsoft Windows Wi-Fi Driver Remote Code Execution Vulnerability",
				DateAdded:                  "2024-06-12",
				ShortDescription:           "Microsoft Windows Wi-Fi Driver contains an untrusted pointer dereference vulnerability allowing RCE.",
				RequiredAction:             "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
				DueDate:                    "2024-07-03",
				KnownRansomwareCampaignUse: "Known",
			},
			{
				CVEID:                      "CVE-2023-4863",
				VendorProject:              "Google",
				Product:                    "Chrome",
				VulnerabilityName:          "Google Chrome libwebp Heap Buffer Overflow Vulnerability",
				DateAdded:                  "2023-09-13",
				ShortDescription:           "Google Chrome prior to 116.0.5845.187 contains a heap buffer overflow in WebP.",
				RequiredAction:             "Apply vendor updates.",
				DueDate:                    "2023-10-04",
				KnownRansomwareCampaignUse: "Known",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNVDClient_FetchAndParse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "test-api-key" {
			t.Errorf("Expected apiKey header 'test-api-key', got '%s'", r.Header.Get("apiKey"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sampleNVDCVEFeed())
	}))
	defer mockServer.Close()

	client := NewNVDClient(mockServer.URL, "test-api-key", mockServer.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.FetchCVEPage(ctx, FetchCVEsOptions{ResultsPerPage: 10})
	if err != nil {
		t.Fatalf("FetchCVEPage failed: %v", err)
	}

	if resp.TotalResults != 3 {
		t.Errorf("Expected 3 results, got %d", resp.TotalResults)
	}
	if len(resp.Vulnerabilities) != 3 {
		t.Errorf("Expected 3 vulnerabilities, got %d", len(resp.Vulnerabilities))
	}

	// Verify CVE conversion
	cve1 := ConvertNVDItemToCached(resp.Vulnerabilities[0].CVE)
	if cve1.CVEID != "CVE-2024-30078" {
		t.Errorf("Expected CVE-2024-30078, got %s", cve1.CVEID)
	}
	if cve1.CVSSScore != 8.8 {
		t.Errorf("Expected CVSS score 8.8, got %f", cve1.CVSSScore)
	}
	if len(cve1.CpeMatches) != 1 {
		t.Errorf("Expected 1 CPE match, got %d", len(cve1.CpeMatches))
	}
}

func TestKEVClient_FetchAndIndex(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sampleCISAKEVFeed())
	}))
	defer mockServer.Close()

	client := NewKEVClient(mockServer.URL, mockServer.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	feed, lookupMap, err := client.FetchCatalog(ctx)
	if err != nil {
		t.Fatalf("FetchCatalog failed: %v", err)
	}

	if feed.Count != 2 {
		t.Errorf("Expected 2 catalog entries, got %d", feed.Count)
	}

	item, exists := lookupMap["CVE-2024-30078"]
	if !exists {
		t.Fatalf("Expected CVE-2024-30078 in KEV lookup map")
	}
	if item.KnownRansomwareCampaignUse != "Known" {
		t.Errorf("Expected ransomware use 'Known', got '%s'", item.KnownRansomwareCampaignUse)
	}
	if item.DueDate != "2024-07-03" {
		t.Errorf("Expected due date '2024-07-03', got '%s'", item.DueDate)
	}
}

func TestCPE_BuilderAndNormalization(t *testing.T) {
	// 1. Application CPE
	chromePub := "Google LLC"
	chromeVer := "115.0.5790.170"
	arch := "64-bit"
	app := models.SnapshotApplicationEntry{
		Name:         "Google Chrome",
		Publisher:    &chromePub,
		Version:      &chromeVer,
		Architecture: &arch,
	}

	appCPE := BuildCPEFromApp(app)
	if appCPE.Vendor != "google" {
		t.Errorf("Expected vendor 'google', got '%s'", appCPE.Vendor)
	}
	if appCPE.Product != "chrome" {
		t.Errorf("Expected product 'chrome', got '%s'", appCPE.Product)
	}
	if appCPE.Version != "115.0.5790.170" {
		t.Errorf("Expected version '115.0.5790.170', got '%s'", appCPE.Version)
	}

	cpeStr := appCPE.String()
	expectedPrefix := "cpe:2.3:a:google:chrome:115.0.5790.170"
	if len(cpeStr) < len(expectedPrefix) || cpeStr[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Expected CPE string starting with '%s', got '%s'", expectedPrefix, cpeStr)
	}

	// 2. OS CPE
	osCPE := BuildCPEFromOS("Microsoft Windows 11 Enterprise 23H2", "10.0.22631", "22631")
	if osCPE.Vendor != "microsoft" {
		t.Errorf("Expected OS vendor 'microsoft', got '%s'", osCPE.Vendor)
	}
	if osCPE.Product != "windows_11" {
		t.Errorf("Expected OS product 'windows_11', got '%s'", osCPE.Product)
	}
	if osCPE.Update != "23h2" {
		t.Errorf("Expected OS update '23h2', got '%s'", osCPE.Update)
	}
}

func TestMatcher_VersionRanges(t *testing.T) {
	// Test CompareVersions
	if CompareVersions("116.0.5845.187", "115.0.5790.170") <= 0 {
		t.Errorf("116 should be greater than 115")
	}
	if CompareVersions("10.0.22631.3737", "10.0.22631.3737") != 0 {
		t.Errorf("Identical versions should compare as 0")
	}
	if CompareVersions("10.0.22621.1", "10.0.22631.3737") >= 0 {
		t.Errorf("22621 should be less than 22631")
	}

	// Test MatchesCPE with versionEndExcluding
	hostCPE := CPE23{
		Part:    "a",
		Vendor:  "google",
		Product: "chrome",
		Version: "115.0.5790.170",
	}

	criteria := NVDCpeMatch{
		Vulnerable:          true,
		Criteria:            "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
		VersionEndExcluding: "116.0.5845.187",
	}

	if !MatchesCPE(hostCPE, criteria) {
		t.Errorf("Host Chrome 115.0 should match criteria versionEndExcluding 116.0")
	}

	// Patched version should NOT match
	patchedCPE := CPE23{
		Part:    "a",
		Vendor:  "google",
		Product: "chrome",
		Version: "117.0.5938.62",
	}
	if MatchesCPE(patchedCPE, criteria) {
		t.Errorf("Patched Chrome 117.0 should NOT match criteria versionEndExcluding 116.0")
	}
}

func TestScanEngine_KEVPrioritizationAndMatching(t *testing.T) {
	repo := NewMemoryFindingRepository()

	// 1. Seed cached CVEs
	cves := sampleNVDCVEFeed().Vulnerabilities
	var cachedCVEs []*CachedCVE
	for _, v := range cves {
		cachedCVEs = append(cachedCVEs, ConvertNVDItemToCached(v.CVE))
	}
	_ = repo.SaveCachedCVEs(cachedCVEs)

	// 2. Seed CISA KEV catalog
	_, kevLookup, _ := NewKEVClient("", nil).FetchCatalog(context.Background()) // default or sample
	kevFeed := sampleCISAKEVFeed()
	kevMap := make(map[string]CISAKEVItem)
	for _, item := range kevFeed.Vulnerabilities {
		kevMap[item.CVEID] = item
	}
	_ = repo.SaveKEVCatalog(kevMap)
	_ = kevLookup

	// 3. Create host snapshot with vulnerable Chrome (115.0) and Windows 11
	chromePub := "Google LLC"
	chromeVer := "115.0.5790.170"
	snapshot := &models.HostSnapshotPayload{
		AuditMetadata: models.SnapshotAuditMetadata{
			EngineVersion: "EndpointGuard-v1.2.0",
			TimestampUTC:  time.Now().UTC().Format(time.RFC3339),
			TargetHost:    "10.100.1.42",
		},
		SystemIdentity: models.SnapshotSystemIdentity{
			Hostname:  "W11-FIN-LP01",
			OSName:    "Microsoft Windows 11 Enterprise 23H2",
			OSVersion: "10.0.22631.3500",
			OSBuild:   "22631",
		},
		Software: models.SnapshotSoftware{
			Applications: []models.SnapshotApplicationEntry{
				{
					Name:      "Google Chrome",
					Publisher: &chromePub,
					Version:   &chromeVer,
				},
			},
		},
	}

	engine := NewScanEngine(repo)
	tenantID := "tenant-acme-corp"
	endpointID := "endpoint-w11-01"

	findings, err := engine.ScanSnapshot(tenantID, endpointID, "W11-FIN-LP01", snapshot)
	if err != nil {
		t.Fatalf("ScanSnapshot failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected vulnerability findings, got 0")
	}

	// Verify KEV flags and prioritization
	var foundKEV bool
	for _, f := range findings {
		if f.CVEID == "CVE-2024-30078" || f.CVEID == "CVE-2023-4863" {
			if !f.IsKEV {
				t.Errorf("Expected CVE %s to have is_kev=true", f.CVEID)
			}
			if f.Severity != "CRITICAL" {
				t.Errorf("Expected KEV CVE %s to be elevated to CRITICAL severity, got '%s'", f.CVEID, f.Severity)
			}
			if f.KEVDueDate == nil {
				t.Errorf("Expected KEV CVE %s to have due date", f.CVEID)
			}
			foundKEV = true
		}
	}

	if !foundKEV {
		t.Errorf("Expected at least one KEV finding to be detected")
	}
}

func TestScanEngine_DeduplicationOnRescan(t *testing.T) {
	repo := NewMemoryFindingRepository()

	// Seed cached CVE
	cveItem := sampleNVDCVEFeed().Vulnerabilities[2] // CVE-2023-4863
	_ = repo.SaveCachedCVEs([]*CachedCVE{ConvertNVDItemToCached(cveItem.CVE)})

	// Seed KEV
	_ = repo.SaveKEVCatalog(map[string]CISAKEVItem{
		"CVE-2023-4863": sampleCISAKEVFeed().Vulnerabilities[1],
	})

	chromePub := "Google LLC"
	chromeVer := "115.0.5790.170"
	snapshot := &models.HostSnapshotPayload{
		AuditMetadata: models.SnapshotAuditMetadata{EngineVersion: "v1.0", TargetHost: "10.0.0.1"},
		SystemIdentity: models.SnapshotSystemIdentity{Hostname: "HOST-01", OSName: "Windows 11", OSVersion: "10.0.22631"},
		Software: models.SnapshotSoftware{
			Applications: []models.SnapshotApplicationEntry{
				{Name: "Google Chrome", Publisher: &chromePub, Version: &chromeVer},
			},
		},
	}

	engine := NewScanEngine(repo)
	tenantID := "tenant-test"
	endpointID := "endpoint-01"

	// First scan
	findings1, err := engine.ScanSnapshot(tenantID, endpointID, "HOST-01", snapshot)
	if err != nil || len(findings1) != 1 {
		t.Fatalf("First scan failed: %v, findings: %d", err, len(findings1))
	}
	firstID := findings1[0].ID
	firstSeen := findings1[0].FirstSeen
	firstLastSeen := findings1[0].LastSeen

	// Small pause to allow timestamp drift
	time.Sleep(10 * time.Millisecond)

	// Second scan (re-scan of same host)
	findings2, err := engine.ScanSnapshot(tenantID, endpointID, "HOST-01", snapshot)
	if err != nil || len(findings2) != 1 {
		t.Fatalf("Second scan failed: %v, findings: %d", err, len(findings2))
	}

	// Verify Deduplication: Same ID, same FirstSeen, updated LastSeen
	if findings2[0].ID != firstID {
		t.Errorf("Expected finding ID to remain %s, got %s", firstID, findings2[0].ID)
	}
	if !findings2[0].FirstSeen.Equal(firstSeen) {
		t.Errorf("Expected FirstSeen to remain unchanged")
	}
	if !findings2[0].LastSeen.After(firstLastSeen) && !findings2[0].LastSeen.Equal(firstLastSeen) {
		t.Errorf("Expected LastSeen to be updated")
	}

	// Verify repository query total count is strictly 1
	res, err := repo.QueryFindings(tenantID, FindingQueryOptions{})
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}
	if res.TotalCount != 1 {
		t.Errorf("Expected TotalCount = 1 after deduplicated rescan, got %d", res.TotalCount)
	}
}

func TestFindingRepository_KEVFirstAndCVSSDescSorting(t *testing.T) {
	repo := NewMemoryFindingRepository()
	tenantID := "tenant-sort-test"
	now := time.Now().UTC()

	// 1. High CVSS non-KEV (CVSS 9.8)
	_, _, _ = repo.UpsertFinding(&VulnerabilityFinding{
		TenantID:   tenantID,
		EndpointID: "ep-01",
		Hostname:   "HOST-A",
		CVEID:      "CVE-2024-9999",
		Title:      "Non-KEV Critical RCE",
		Severity:   "CRITICAL",
		CVSSScore:  9.8,
		IsKEV:      false,
		Status:     "OPEN",
		FirstSeen:  now,
		LastSeen:   now,
	})

	// 2. Medium CVSS KEV (CVSS 7.5, is_kev=true)
	_, _, _ = repo.UpsertFinding(&VulnerabilityFinding{
		TenantID:   tenantID,
		EndpointID: "ep-01",
		Hostname:   "HOST-A",
		CVEID:      "CVE-2024-30078",
		Title:      "CISA KEV Wi-Fi RCE",
		Severity:   "CRITICAL",
		CVSSScore:  7.5,
		IsKEV:      true,
		Status:     "OPEN",
		FirstSeen:  now,
		LastSeen:   now,
	})

	// 3. Higher CVSS KEV (CVSS 8.8, is_kev=true)
	_, _, _ = repo.UpsertFinding(&VulnerabilityFinding{
		TenantID:   tenantID,
		EndpointID: "ep-02",
		Hostname:   "HOST-B",
		CVEID:      "CVE-2023-4863",
		Title:      "CISA KEV Chrome Heap Overflow",
		Severity:   "CRITICAL",
		CVSSScore:  8.8,
		IsKEV:      true,
		Status:     "OPEN",
		FirstSeen:  now,
		LastSeen:   now,
	})

	// 4. Low CVSS non-KEV (CVSS 5.3)
	_, _, _ = repo.UpsertFinding(&VulnerabilityFinding{
		TenantID:   tenantID,
		EndpointID: "ep-02",
		Hostname:   "HOST-B",
		CVEID:      "CVE-2024-1111",
		Title:      "Low Severity Info Disclosure",
		Severity:   "MEDIUM",
		CVSSScore:  5.3,
		IsKEV:      false,
		Status:     "OPEN",
		FirstSeen:  now,
		LastSeen:   now,
	})

	res, err := repo.QueryFindings(tenantID, FindingQueryOptions{})
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}

	if res.TotalCount != 4 {
		t.Fatalf("Expected 4 findings, got %d", res.TotalCount)
	}
	if res.KEVCount != 2 {
		t.Errorf("Expected KEVCount = 2, got %d", res.KEVCount)
	}

	// STRICT SORTING ASSERTIONS:
	// Item 0: CVE-2023-4863 (is_kev=true, CVSS 8.8)
	// Item 1: CVE-2024-30078 (is_kev=true, CVSS 7.5)
	// Item 2: CVE-2024-9999 (is_kev=false, CVSS 9.8)
	// Item 3: CVE-2024-1111 (is_kev=false, CVSS 5.3)

	if res.Items[0].CVEID != "CVE-2023-4863" {
		t.Errorf("Expected 1st item CVE-2023-4863 (KEV 8.8), got %s (is_kev=%v, cvss=%f)",
			res.Items[0].CVEID, res.Items[0].IsKEV, res.Items[0].CVSSScore)
	}
	if res.Items[1].CVEID != "CVE-2024-30078" {
		t.Errorf("Expected 2nd item CVE-2024-30078 (KEV 7.5), got %s (is_kev=%v, cvss=%f)",
			res.Items[1].CVEID, res.Items[1].IsKEV, res.Items[1].CVSSScore)
	}
	if res.Items[2].CVEID != "CVE-2024-9999" {
		t.Errorf("Expected 3rd item CVE-2024-9999 (Non-KEV 9.8), got %s (is_kev=%v, cvss=%f)",
			res.Items[2].CVEID, res.Items[2].IsKEV, res.Items[2].CVSSScore)
	}
	if res.Items[3].CVEID != "CVE-2024-1111" {
		t.Errorf("Expected 4th item CVE-2024-1111 (Non-KEV 5.3), got %s (is_kev=%v, cvss=%f)",
			res.Items[3].CVEID, res.Items[3].IsKEV, res.Items[3].CVSSScore)
	}
}

func TestRateLimiter_BudgetCompliance(t *testing.T) {
	limiter := NewNVDRateLimiter(true) // 50 reqs / 30s
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	// Acquire 3 tokens
	for i := 0; i < 3; i++ {
		if err := limiter.Wait(ctx); err != nil {
			t.Fatalf("RateLimiter.Wait failed: %v", err)
		}
	}
	elapsed := time.Since(start)

	// Since maxBurst=3, first 3 tokens should be acquired rapidly (< 1.5s)
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Token bucket burst acquisition took unexpectedly long: %v", elapsed)
	}
}
