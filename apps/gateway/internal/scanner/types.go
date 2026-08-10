package scanner

import (
	"time"
)

// EndpointScanTarget represents an individual target to be scanned.
type EndpointScanTarget struct {
	IPAddress         string `json:"ip_address"`
	Hostname          string `json:"hostname,omitempty"`
	Port              int    `json:"port,omitempty"`
	Protocol          string `json:"protocol"` // "winrm_https", "winrm_http", "ssh", "snmp_v3"
	Username          string `json:"username"`
	SecretValue       string `json:"-"` // never serialized or logged, zeroized after use
	AllowInsecureHTTP bool   `json:"allow_insecure_http"`
}

// EndpointScanResult contains full telemetry extracted from an agentless probe.
type EndpointScanResult struct {
	EndpointID        string                 `json:"endpoint_id"`
	Hostname          string                 `json:"hostname"`
	Domain            string                 `json:"domain"`
	IPAddress         string                 `json:"ip_address"`
	MACAddress        string                 `json:"mac_address"`
	OSName            string                 `json:"os_name"`
	OSBuild           string                 `json:"os_build"`
	SerialNumber      string                 `json:"serial_number"`
	Manufacturer      string                 `json:"manufacturer"`
	Model             string                 `json:"model"`
	ChassisType       string                 `json:"chassis_type"`
	Status            string                 `json:"status"` // online, offline, error
	AgentlessProtocol string                 `json:"agentless_protocol"`
	ComplianceScore   float64                `json:"compliance_score"`
	ComplianceExceptions []ComplianceException `json:"compliance_exceptions,omitempty"`
	Hardware          HardwareTelemetry      `json:"hardware"`
	Security          SecurityPostureTelemetry `json:"security"`
	CISResults        []CISBenchmarkResult   `json:"cis_results"`
	ScannedAt         time.Time              `json:"scanned_at"`
	ScanDurationMs    int64                  `json:"scan_duration_ms"`
	ErrorMessage      string                 `json:"error_message,omitempty"`
}

// ComplianceException records any security policy exception (e.g. unencrypted 5985 usage).
type ComplianceException struct {
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"` // CRITICAL, HIGH, MEDIUM
	RuleID      string    `json:"rule_id"`
	Description string    `json:"description"`
	TargetHost  string    `json:"target_host"`
	Actor       string    `json:"actor"`
}

// HardwareTelemetry details collected from WMI/CIM or BMC Redfish/SNMP.
type HardwareTelemetry struct {
	CPUDetails     map[string]interface{}   `json:"cpu_details"`
	MemoryDetails  map[string]interface{}   `json:"memory_details"`
	StorageDetails map[string]interface{}   `json:"storage_details"`
	NetworkDetails map[string]interface{}   `json:"network_details"`
	BIOSDetails    map[string]interface{}   `json:"bios_details"`
	TPMDetails     map[string]interface{}   `json:"tpm_details"`
}

// SecurityPostureTelemetry details collected from BitLocker, Defender, UAC, etc.
type SecurityPostureTelemetry struct {
	BitLockerStatus  map[string]interface{}   `json:"bitlocker_status"`
	DefenderStatus   map[string]interface{}   `json:"defender_status"`
	FirewallStatus   map[string]interface{}   `json:"firewall_status"`
	UACStatus        map[string]interface{}   `json:"uac_status"`
	RebootPending    map[string]interface{}   `json:"reboot_pending,omitempty"`
	CutoverReadiness map[string]interface{}   `json:"cutover_readiness,omitempty"`
	Hotfixes         []map[string]interface{} `json:"hotfixes"`
	LocalAdmins      []string                 `json:"local_admins"`
}

// CISBenchmarkResult reports compliance for a single CIS check.
type CISBenchmarkResult struct {
	RuleID            string    `json:"rule_id"`
	RuleTitle         string    `json:"rule_title"`
	BenchmarkName     string    `json:"benchmark_name"`
	BenchmarkLevel    string    `json:"benchmark_level"`
	Category          string    `json:"category"`
	Status            string    `json:"status"` // PASS, FAIL, WARNING
	ActualValue       string    `json:"actual_value"`
	ExpectedValue     string    `json:"expected_value"`
	Rationale         string    `json:"rationale"`
	RemediationScript string    `json:"remediation_script"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}

// ScanBatchResult represents the completed output of a scan job across all hosts.
type ScanBatchResult struct {
	ScanJobID      string               `json:"scan_job_id"`
	GatewayID      string               `json:"gateway_id"`
	TargetCIDR     string               `json:"target_cidr"`
	TotalHosts     int                  `json:"total_hosts"`
	ScannedHosts   int                  `json:"scanned_hosts"`
	CompliantHosts int                  `json:"compliant_hosts"`
	FailedHosts    int                  `json:"failed_hosts"`
	Results        []EndpointScanResult `json:"results"`
	Logs           []string             `json:"logs"`
	PayloadHash    string               `json:"payload_hash"` // SHA-256 computed gateway-side
	CompletedAt    time.Time            `json:"completed_at"`
}
