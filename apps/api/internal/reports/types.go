package reports

import "time"

// ReportType specifies the analytical report being generated.
type ReportType string

const (
	ReportExecutiveSummary   ReportType = "EXECUTIVE_SUMMARY"
	ReportComplianceAudit    ReportType = "COMPLIANCE_AUDIT"
	ReportVulnerabilityPosture ReportType = "VULNERABILITY_POSTURE"
)

// GenerateReportRequest defines user parameters for on-demand report generation.
type GenerateReportRequest struct {
	Type          ReportType `json:"type"`                     // EXECUTIVE_SUMMARY, COMPLIANCE_AUDIT, VULNERABILITY_POSTURE
	FrameworkCode string     `json:"framework_code,omitempty"` // e.g. cis_win11_v2.0
	Title         string     `json:"title,omitempty"`
}

// ExecutiveSummaryReport provides high-level CISO fleet posture metrics.
type ExecutiveSummaryReport struct {
	ReportID            string    `json:"report_id"`
	GeneratedAt         time.Time `json:"generated_at"`
	TenantID            string    `json:"tenant_id"`
	TotalEndpoints      int       `json:"total_endpoints"`
	OnlineEndpoints     int       `json:"online_endpoints"`
	BitLockerCoverage   float64   `json:"bitlocker_coverage_percent"`
	TPMCoverage         float64   `json:"tpm_coverage_percent"`
	DefenderCoverage    float64   `json:"defender_coverage_percent"`
	AverageCompliance   float64   `json:"average_compliance_score"`
	CriticalVulnerabilities int   `json:"critical_vulnerabilities_count"`
	KEVVulnerabilities  int       `json:"cisa_kev_vulnerabilities_count"`
	UnacknowledgedDrifts int      `json:"unacknowledged_drift_events"`
	OverallFleetStatus  string    `json:"overall_fleet_status"` // "HEALTHY", "NEEDS_ATTENTION", "CRITICAL_RISK"
}

// ComplianceAuditReport contains formal audit evidence for regulatory bodies.
type ComplianceAuditReport struct {
	ReportID          string                 `json:"report_id"`
	GeneratedAt       time.Time              `json:"generated_at"`
	TenantID          string                 `json:"tenant_id"`
	FrameworkCode     string                 `json:"framework_code"`
	FrameworkName     string                 `json:"framework_name"`
	TotalControls     int                    `json:"total_controls"`
	PassedControls    int                    `json:"passed_controls"`
	FailedControls    int                    `json:"failed_controls"`
	ComplianceScore   float64                `json:"compliance_score"`
	EvaluatedHosts    int                    `json:"evaluated_hosts"`
	NonCompliantHosts []NonCompliantHostItem `json:"non_compliant_hosts"`
}

// NonCompliantHostItem describes a host failing specific compliance controls.
type NonCompliantHostItem struct {
	HostID       string   `json:"host_id"`
	Hostname     string   `json:"hostname"`
	IPAddress    string   `json:"ip_address"`
	FailedRules  []string `json:"failed_rules"`
	HostScore    float64  `json:"host_score"`
}

// VulnerabilityPostureReport aggregates CVE and CISA KEV exposure across the fleet.
type VulnerabilityPostureReport struct {
	ReportID        string              `json:"report_id"`
	GeneratedAt     time.Time           `json:"generated_at"`
	TenantID        string              `json:"tenant_id"`
	TotalFindings   int                 `json:"total_findings"`
	KEVCount        int                 `json:"cisa_kev_findings_count"`
	CriticalCount   int                 `json:"critical_count"`
	HighCount       int                 `json:"high_count"`
	MediumCount     int                 `json:"medium_count"`
	LowCount        int                 `json:"low_count"`
	TopCVEs         []TopVulnerability  `json:"top_vulnerabilities"`
	AffectedHosts   int                 `json:"affected_hosts_count"`
}

// TopVulnerability summarizes a key CVE affecting fleet hosts.
type TopVulnerability struct {
	CVEID         string  `json:"cve_id"`
	Title         string  `json:"title"`
	CVSSScore     float64 `json:"cvss_score"`
	Severity      string  `json:"severity"`
	IsKEV         bool    `json:"is_kev"`
	AffectedCount int     `json:"affected_hosts_count"`
}
