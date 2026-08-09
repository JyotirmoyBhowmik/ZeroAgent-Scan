package vulnscan

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FindingRepository defines the storage interface for vulnerability findings, CVE cache, and KEV catalog.
type FindingRepository interface {
	SaveCachedCVEs(cves []*CachedCVE) error
	GetCachedCVEs() []*CachedCVE
	GetCachedCVEByID(cveID string) (*CachedCVE, bool)
	SaveKEVCatalog(items map[string]CISAKEVItem) error
	GetKEVItem(cveID string) (CISAKEVItem, bool)
	GetAllKEVItems() map[string]CISAKEVItem
	UpsertFinding(finding *VulnerabilityFinding) (*VulnerabilityFinding, bool, error) // returns (finding, isNew, error)
	QueryFindings(tenantID string, opts FindingQueryOptions) (*FindingListResponse, error)
	GetFindingByID(tenantID, findingID string) (*VulnerabilityFinding, error)
}

// MemoryFindingRepository is a thread-safe in-memory implementation of FindingRepository.
type MemoryFindingRepository struct {
	mu        sync.RWMutex
	cveCache  map[string]*CachedCVE
	kevCache  map[string]CISAKEVItem
	findings  map[string]*VulnerabilityFinding // Key: tenantID + ":" + endpointID + ":" + cveID
	byID      map[string]*VulnerabilityFinding // Key: findingID
}

// NewMemoryFindingRepository creates an initialized in-memory finding repository.
func NewMemoryFindingRepository() *MemoryFindingRepository {
	return &MemoryFindingRepository{
		cveCache: make(map[string]*CachedCVE),
		kevCache: make(map[string]CISAKEVItem),
		findings: make(map[string]*VulnerabilityFinding),
		byID:     make(map[string]*VulnerabilityFinding),
	}
}

// SaveCachedCVEs stores or updates CVE records in the local cache.
func (r *MemoryFindingRepository) SaveCachedCVEs(cves []*CachedCVE) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, cve := range cves {
		if cve != nil && cve.CVEID != "" {
			cve.CVEID = strings.ToUpper(strings.TrimSpace(cve.CVEID))
			r.cveCache[cve.CVEID] = cve
		}
	}
	return nil
}

// GetCachedCVEs returns all cached CVEs.
func (r *MemoryFindingRepository) GetCachedCVEs() []*CachedCVE {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*CachedCVE, 0, len(r.cveCache))
	for _, cve := range r.cveCache {
		result = append(result, cve)
	}
	return result
}

// GetCachedCVEByID retrieves a single cached CVE by its ID.
func (r *MemoryFindingRepository) GetCachedCVEByID(cveID string) (*CachedCVE, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cve, found := r.cveCache[strings.ToUpper(strings.TrimSpace(cveID))]
	return cve, found
}

// SaveKEVCatalog saves the latest CISA KEV catalog lookup map.
func (r *MemoryFindingRepository) SaveKEVCatalog(items map[string]CISAKEVItem) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.kevCache = make(map[string]CISAKEVItem, len(items))
	for k, v := range items {
		r.kevCache[strings.ToUpper(strings.TrimSpace(k))] = v
	}
	return nil
}

// GetKEVItem looks up a CVE in the CISA KEV catalog.
func (r *MemoryFindingRepository) GetKEVItem(cveID string) (CISAKEVItem, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	item, found := r.kevCache[strings.ToUpper(strings.TrimSpace(cveID))]
	return item, found
}

// GetAllKEVItems returns a copy of all cached KEV catalog items.
func (r *MemoryFindingRepository) GetAllKEVItems() map[string]CISAKEVItem {
	r.mu.RLock()
	defer r.mu.RUnlock()

	copied := make(map[string]CISAKEVItem, len(r.kevCache))
	for k, v := range r.kevCache {
		copied[k] = v
	}
	return copied
}

// UpsertFinding inserts a new finding or updates last_seen on existing finding (deduplication).
func (r *MemoryFindingRepository) UpsertFinding(finding *VulnerabilityFinding) (*VulnerabilityFinding, bool, error) {
	if finding == nil {
		return nil, false, fmt.Errorf("repository: finding cannot be nil")
	}
	if finding.TenantID == "" {
		return nil, false, fmt.Errorf("repository: missing tenant_id")
	}
	if finding.EndpointID == "" {
		return nil, false, fmt.Errorf("repository: missing endpoint_id")
	}
	if finding.CVEID == "" {
		return nil, false, fmt.Errorf("repository: missing cve_id")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	cveUpper := strings.ToUpper(strings.TrimSpace(finding.CVEID))
	dedupKey := fmt.Sprintf("%s:%s:%s", finding.TenantID, finding.EndpointID, cveUpper)

	existing, exists := r.findings[dedupKey]
	if exists {
		// Deduplication update: keep original ID and FirstSeen, update LastSeen and posture
		existing.LastSeen = now
		existing.UpdatedAt = now
		existing.Status = "OPEN"
		existing.ResolvedAt = nil
		existing.Severity = finding.Severity
		existing.CVSSScore = finding.CVSSScore
		existing.CVSSVersion = finding.CVSSVersion
		existing.CVSSVector = finding.CVSSVector
		existing.IsKEV = finding.IsKEV
		existing.KEVDueDate = finding.KEVDueDate
		existing.KEVRansomwareUse = finding.KEVRansomwareUse
		existing.Remediation = finding.Remediation
		existing.AffectedComponent = finding.AffectedComponent
		existing.CPEMatched = finding.CPEMatched

		return existing, false, nil
	}

	// New Finding Insert
	if finding.ID == "" {
		finding.ID = uuid.New().String()
	}
	finding.CVEID = cveUpper
	finding.FirstSeen = now
	finding.LastSeen = now
	finding.CreatedAt = now
	finding.UpdatedAt = now
	if finding.Status == "" {
		finding.Status = "OPEN"
	}

	r.findings[dedupKey] = finding
	r.byID[finding.ID] = finding

	return finding, true, nil
}

// QueryFindings retrieves findings for a tenant with filtering and KEV-first + CVSS descending sorting.
func (r *MemoryFindingRepository) QueryFindings(tenantID string, opts FindingQueryOptions) (*FindingListResponse, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("repository: tenant_id must not be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []VulnerabilityFinding
	totalCount := 0
	openCount := 0
	kevCount := 0
	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0

	for _, f := range r.findings {
		if f.TenantID != tenantID {
			continue
		}

		totalCount++
		if f.Status == "OPEN" {
			openCount++
			if f.IsKEV {
				kevCount++
			}
			switch strings.ToUpper(f.Severity) {
			case "CRITICAL":
				critCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				medCount++
			case "LOW":
				lowCount++
			}
		}

		// Apply Status Filter (defaults to "OPEN" if not specified)
		statusFilter := strings.ToUpper(strings.TrimSpace(opts.Status))
		if statusFilter != "" && statusFilter != "ALL" {
			if strings.ToUpper(f.Status) != statusFilter {
				continue
			}
		}

		// Apply Severity Filter
		if opts.Severity != "" && !strings.EqualFold(opts.Severity, "ALL") {
			if !strings.EqualFold(f.Severity, opts.Severity) {
				continue
			}
		}

		// Apply KEV Filter
		if opts.IsKEV != nil {
			if f.IsKEV != *opts.IsKEV {
				continue
			}
		}

		// Apply Endpoint Filter
		if opts.EndpointID != "" {
			if f.EndpointID != opts.EndpointID {
				continue
			}
		}

		// Apply Search Filter (CVE ID, Title, Hostname, Component)
		if opts.Search != "" {
			s := strings.ToLower(strings.TrimSpace(opts.Search))
			cveMatch := strings.Contains(strings.ToLower(f.CVEID), s)
			titleMatch := strings.Contains(strings.ToLower(f.Title), s)
			hostMatch := strings.Contains(strings.ToLower(f.Hostname), s)
			compMatch := strings.Contains(strings.ToLower(f.AffectedComponent), s)
			if !cveMatch && !titleMatch && !hostMatch && !compMatch {
				continue
			}
		}

		filtered = append(filtered, *f)
	}

	// STRICT SORTING: KEV-First (is_kev=true), then CVSS Score descending, then LastSeen descending
	sort.Slice(filtered, func(i, j int) bool {
		// 1. KEV First
		if filtered[i].IsKEV != filtered[j].IsKEV {
			return filtered[i].IsKEV && !filtered[j].IsKEV
		}
		// 2. CVSS Score Descending
		if filtered[i].CVSSScore != filtered[j].CVSSScore {
			return filtered[i].CVSSScore > filtered[j].CVSSScore
		}
		// 3. LastSeen Descending
		return filtered[i].LastSeen.After(filtered[j].LastSeen)
	})

	// Pagination
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 200 {
		limit = 200
	}

	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	var paginated []VulnerabilityFinding
	if offset < len(filtered) {
		end := offset + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		paginated = filtered[offset:end]
	} else {
		paginated = []VulnerabilityFinding{}
	}

	return &FindingListResponse{
		TotalCount:    len(filtered),
		OpenCount:     openCount,
		KEVCount:      kevCount,
		CriticalCount: critCount,
		HighCount:     highCount,
		MediumCount:   medCount,
		LowCount:      lowCount,
		Limit:         limit,
		Offset:        offset,
		Items:         paginated,
	}, nil
}

// GetFindingByID retrieves a specific finding by its ID.
func (r *MemoryFindingRepository) GetFindingByID(tenantID, findingID string) (*VulnerabilityFinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	f, exists := r.byID[findingID]
	if !exists || f.TenantID != tenantID {
		return nil, fmt.Errorf("repository: finding %s not found", findingID)
	}
	return f, nil
}
