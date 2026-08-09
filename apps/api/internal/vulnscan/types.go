package vulnscan

import (
	"time"
)

// VulnerabilityFinding represents a single detected CVE finding for an endpoint.
type VulnerabilityFinding struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	EndpointID         string     `json:"endpoint_id"`
	Hostname           string     `json:"hostname"`
	CVEID              string     `json:"cve_id"`
	Title              string     `json:"title"`
	Description        string     `json:"description"`
	Severity           string     `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	CVSSScore          float64    `json:"cvss_score"`
	CVSSVersion        string     `json:"cvss_version"`
	CVSSVector         string     `json:"cvss_vector,omitempty"`
	IsKEV              bool       `json:"is_kev"`
	KEVDueDate         *time.Time `json:"kev_due_date,omitempty"`
	KEVRansomwareUse   string     `json:"kev_ransomware_use,omitempty"`
	AffectedComponent  string     `json:"affected_component"`
	CPEMatched         string     `json:"cpe_matched"`
	Status             string     `json:"status"` // OPEN, RESOLVED, IGNORED
	Remediation        string     `json:"remediation,omitempty"`
	FirstSeen          time.Time  `json:"first_seen"`
	LastSeen           time.Time  `json:"last_seen"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// FindingQueryOptions specifies filters, search, and pagination for findings.
type FindingQueryOptions struct {
	Severity   string `json:"severity,omitempty"`
	Status     string `json:"status,omitempty"` // Default "OPEN"
	IsKEV      *bool  `json:"is_kev,omitempty"`
	EndpointID string `json:"endpoint_id,omitempty"`
	Search     string `json:"search,omitempty"`
	Limit      int    `json:"limit,omitempty"`  // Default 50, Max 200
	Offset     int    `json:"offset,omitempty"` // Default 0
}

// FindingListResponse represents the paginated REST API response for findings.
type FindingListResponse struct {
	TotalCount    int                    `json:"total_count"`
	OpenCount     int                    `json:"open_count"`
	KEVCount      int                    `json:"kev_count"`
	CriticalCount int                    `json:"critical_count"`
	HighCount     int                    `json:"high_count"`
	MediumCount   int                    `json:"medium_count"`
	LowCount      int                    `json:"low_count"`
	Limit         int                    `json:"limit"`
	Offset        int                    `json:"offset"`
	Items         []VulnerabilityFinding `json:"items"`
}

// ---------------------------------------------------------------------------
// NVD API 2.0 Feed Data Models
// ---------------------------------------------------------------------------

type NVDResponse struct {
	ResultsPerPage  int               `json:"resultsPerPage"`
	StartIndex      int               `json:"startIndex"`
	TotalResults    int               `json:"totalResults"`
	Format          string            `json:"format"`
	Version         string            `json:"version"`
	Timestamp       string            `json:"timestamp"`
	Vulnerabilities []NVDVulnerability `json:"vulnerabilities"`
}

type NVDVulnerability struct {
	CVE NVDCVEItem `json:"cve"`
}

type NVDCVEItem struct {
	ID               string              `json:"id"`
	SourceIdentifier string              `json:"sourceIdentifier,omitempty"`
	Published        string              `json:"published"`
	LastModified     string              `json:"lastModified"`
	VulnStatus       string              `json:"vulnStatus,omitempty"`
	Descriptions     []NVDDescription    `json:"descriptions"`
	Metrics          NVDMetrics          `json:"metrics"`
	Configurations   []NVDConfiguration  `json:"configurations,omitempty"`
	References       []NVDReference      `json:"references,omitempty"`
}

type NVDDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NVDMetrics struct {
	CvssMetricV31 []NVDCvssV31 `json:"cvssMetricV31,omitempty"`
	CvssMetricV30 []NVDCvssV30 `json:"cvssMetricV30,omitempty"`
	CvssMetricV2  []NVDCvssV2  `json:"cvssMetricV2,omitempty"`
}

type NVDCvssV31 struct {
	Source   string         `json:"source"`
	Type     string         `json:"type"`
	CvssData NVDCvssV31Data `json:"cvssData"`
}

type NVDCvssV31Data struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type NVDCvssV30 struct {
	Source   string         `json:"source"`
	Type     string         `json:"type"`
	CvssData NVDCvssV31Data `json:"cvssData"`
}

type NVDCvssV2 struct {
	Source   string        `json:"source"`
	Type     string        `json:"type"`
	CvssData NVDCvssV2Data `json:"cvssData"`
}

type NVDCvssV2Data struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

type NVDConfiguration struct {
	Nodes []NVDNode `json:"nodes"`
}

type NVDNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate,omitempty"`
	CpeMatch []NVDCpeMatch `json:"cpeMatch"`
}

type NVDCpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"` // CPE 2.3 format e.g. "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
	MatchCriteriaID       string `json:"matchCriteriaId,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// ---------------------------------------------------------------------------
// CISA Known Exploited Vulnerabilities (KEV) Catalog Models
// ---------------------------------------------------------------------------

type CISAKEVFeed struct {
	Title           string        `json:"title"`
	CatalogVersion  string        `json:"catalogVersion"`
	DateReleased    string        `json:"dateReleased"`
	Count           int           `json:"count"`
	Vulnerabilities []CISAKEVItem `json:"vulnerabilities"`
}

type CISAKEVItem struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes,omitempty"`
}

// ---------------------------------------------------------------------------
// Internal Cached CVE Item
// ---------------------------------------------------------------------------

type CachedCVE struct {
	CVEID           string            `json:"cve_id"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Severity        string            `json:"severity"`
	CVSSScore       float64           `json:"cvss_score"`
	CVSSVersion     string            `json:"cvss_version"`
	CVSSVector      string            `json:"cvss_vector"`
	PublishedAt     time.Time         `json:"published_at"`
	LastModifiedAt  time.Time         `json:"last_modified_at"`
	CpeMatches      []NVDCpeMatch     `json:"cpe_matches"`
	References      []string          `json:"references"`
	CachedAt        time.Time         `json:"cached_at"`
}
