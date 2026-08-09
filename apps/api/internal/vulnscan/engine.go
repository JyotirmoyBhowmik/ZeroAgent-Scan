package vulnscan

import (
	"fmt"
	"strings"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
)

// ScanEngine matches host hardware, OS, and software inventories against CVE/CPE data and KEV catalog.
type ScanEngine struct {
	repo FindingRepository
}

// NewScanEngine creates a vulnerability evaluation engine.
func NewScanEngine(repo FindingRepository) *ScanEngine {
	return &ScanEngine{
		repo: repo,
	}
}

// ScanSnapshot evaluates a host snapshot, matches candidate CPEs against cached CVEs,
// cross-references CISA KEV, and upserts findings with deduplication.
func (e *ScanEngine) ScanSnapshot(tenantID, endpointID, hostname string, snapshot *models.HostSnapshotPayload) ([]*VulnerabilityFinding, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("scan_engine: snapshot payload is nil")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("scan_engine: missing tenant_id")
	}
	if endpointID == "" {
		return nil, fmt.Errorf("scan_engine: missing endpoint_id")
	}
	if hostname == "" {
		hostname = snapshot.SystemIdentity.Hostname
	}

	// 1. Extract Candidate Host CPEs
	hostCPEs := ExtractHostCPEs(snapshot)
	if len(hostCPEs) == 0 {
		return nil, nil
	}

	// 2. Retrieve Cached CVEs
	cachedCVEs := e.repo.GetCachedCVEs()
	var detectedFindings []*VulnerabilityFinding

	// Index already matched CVEs for this scan run
	seenThisScan := make(map[string]bool)

	for _, hostCPE := range hostCPEs {
		for _, cve := range cachedCVEs {
			if cve == nil || cve.CVEID == "" {
				continue
			}

			cveIDUpper := strings.ToUpper(cve.CVEID)
			if seenThisScan[cveIDUpper] {
				continue
			}

			// Check all CPE match criteria in this CVE
			matchedCriteria := ""
			for _, match := range cve.CpeMatches {
				if MatchesCPE(hostCPE, match) {
					matchedCriteria = match.Criteria
					if matchedCriteria == "" {
						matchedCriteria = hostCPE.String()
					}
					break
				}
			}

			if matchedCriteria != "" {
				seenThisScan[cveIDUpper] = true

				// 3. Cross-reference CISA KEV Catalog
				isKEV := false
				var kevDueDate *time.Time
				kevRansomware := ""
				severity := cve.Severity

				if kevItem, found := e.repo.GetKEVItem(cveIDUpper); found {
					isKEV = true
					// Requirement: "flag those as highest priority regardless of raw CVSS score"
					severity = "CRITICAL"
					kevRansomware = kevItem.KnownRansomwareCampaignUse
					if kevItem.DueDate != "" {
						if parsedDue, err := time.Parse("2006-01-02", kevItem.DueDate); err == nil {
							kevDueDate = &parsedDue
						}
					}
				}

				remediation := fmt.Sprintf("Upgrade %s to the latest patched version or install vendor security update.", hostCPE.RawApp)
				if isKEV {
					remediation = fmt.Sprintf("CRITICAL CISA KEV ACTION REQUIRED: %s", remediation)
				}

				finding := &VulnerabilityFinding{
					TenantID:          tenantID,
					EndpointID:        endpointID,
					Hostname:          hostname,
					CVEID:             cveIDUpper,
					Title:             cve.Title,
					Description:       cve.Description,
					Severity:          severity,
					CVSSScore:         cve.CVSSScore,
					CVSSVersion:       cve.CVSSVersion,
					CVSSVector:        cve.CVSSVector,
					IsKEV:             isKEV,
					KEVDueDate:        kevDueDate,
					KEVRansomwareUse:  kevRansomware,
					AffectedComponent: hostCPE.RawApp,
					CPEMatched:        matchedCriteria,
					Status:            "OPEN",
					Remediation:       remediation,
				}

				// 4. Upsert with Deduplication (updates last_seen if already present)
				savedFinding, _, err := e.repo.UpsertFinding(finding)
				if err != nil {
					return nil, fmt.Errorf("scan_engine: failed to upsert finding: %w", err)
				}
				detectedFindings = append(detectedFindings, savedFinding)
			}
		}
	}

	return detectedFindings, nil
}
