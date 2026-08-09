package models

import "time"

type Endpoint struct {
	ID                string    `json:"id"`
	Hostname          string    `json:"hostname"`
	Domain            string    `json:"domain"`
	IPAddress         string    `json:"ip_address"`
	MACAddress        string    `json:"mac_address"`
	OSName            string    `json:"os_name"`
	OSBuild           string    `json:"os_build"`
	SerialNumber      string    `json:"serial_number"`
	Manufacturer      string    `json:"manufacturer"`
	Model             string    `json:"model"`
	ChassisType       string    `json:"chassis_type"`
	Status            string    `json:"status"` // online, offline, scanning, error
	AgentlessProtocol string    `json:"agentless_protocol"`
	ComplianceScore   float64   `json:"compliance_score"`
	LastScannedAt     *time.Time `json:"last_scanned_at,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type HardwareInventory struct {
	ID             string                 `json:"id"`
	EndpointID     string                 `json:"endpoint_id"`
	CPUDetails     map[string]interface{} `json:"cpu_details"`
	MemoryDetails  map[string]interface{} `json:"memory_details"`
	StorageDetails map[string]interface{} `json:"storage_details"`
	NetworkDetails map[string]interface{} `json:"network_details"`
	BIOSDetails    map[string]interface{} `json:"bios_details"`
	TPMDetails     map[string]interface{} `json:"tpm_details"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type SecurityPosture struct {
	ID              string                 `json:"id"`
	EndpointID      string                 `json:"endpoint_id"`
	BitLockerStatus map[string]interface{} `json:"bitlocker_status"`
	DefenderStatus  map[string]interface{} `json:"defender_status"`
	FirewallStatus  map[string]interface{} `json:"firewall_status"`
	UACStatus       map[string]interface{} `json:"uac_status"`
	Hotfixes        []map[string]interface{} `json:"hotfixes"`
	LocalAdmins     []string               `json:"local_admins"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

type EndpointDetail struct {
	Endpoint        Endpoint          `json:"endpoint"`
	Hardware        HardwareInventory `json:"hardware"`
	SecurityPosture SecurityPosture   `json:"security_posture"`
	CISResults      []CISResult       `json:"cis_results"`
}

type ScanJob struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	TargetCIDR     string                 `json:"target_cidr"`
	ScanProfile    string                 `json:"scan_profile"`
	Protocol       string                 `json:"protocol"`
	VaultSecretRef string                 `json:"vault_secret_ref"`
	GatewayID      string                 `json:"gateway_id"`
	Status         string                 `json:"status"` // pending, running, completed, failed
	TotalHosts     int                    `json:"total_hosts"`
	ScannedHosts   int                    `json:"scanned_hosts"`
	CompliantHosts int                    `json:"compliant_hosts"`
	FailedHosts    int                    `json:"failed_hosts"`
	Logs           []string               `json:"logs"`
	StartedAt      *time.Time             `json:"started_at,omitempty"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

type CollectorGateway struct {
	ID                  string    `json:"id"`
	GatewayCode         string    `json:"gateway_code"`
	Name                string    `json:"name"`
	SubnetCIDR          string    `json:"subnet_cidr"`
	MTLSCertFingerprint string    `json:"mtls_cert_fingerprint"`
	Status              string    `json:"status"` // healthy, degraded, offline
	Version             string    `json:"version"`
	LatencyMs           int       `json:"latency_ms"`
	LastHeartbeatAt     time.Time `json:"last_heartbeat_at"`
	CreatedAt           time.Time `json:"created_at"`
}

type VaultCredentialSummary struct {
	ID             string    `json:"id"`
	OpaqueID       string    `json:"opaque_id"`
	Name           string    `json:"name"`
	CredentialType string    `json:"credential_type"`
	DomainOrHost   string    `json:"domain_or_host"`
	Username       string    `json:"username"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type CreateVaultCredentialRequest struct {
	Name           string `json:"name"`
	CredentialType string `json:"credential_type"` // domain_kerberos, domain_ntlm, local_service, snmp_v3, ssh_key
	DomainOrHost   string `json:"domain_or_host"`
	Username       string `json:"username"`
	SecretValue    string `json:"secret_value"` // Password, Passphrase, or Private Key
}

type CreateScanJobRequest struct {
	Name           string `json:"name"`
	TargetCIDR     string `json:"target_cidr"`
	ScanProfile    string `json:"scan_profile"`
	Protocol       string `json:"protocol"`
	VaultSecretRef string `json:"vault_secret_ref"`
	GatewayID      string `json:"gateway_id"`
}

type CISResult struct {
	ID                string    `json:"id"`
	EndpointID        string    `json:"endpoint_id"`
	BenchmarkName     string    `json:"benchmark_name"`
	BenchmarkLevel    string    `json:"benchmark_level"`
	RuleID            string    `json:"rule_id"`
	RuleTitle         string    `json:"rule_title"`
	Category          string    `json:"category"`
	Status            string    `json:"status"` // PASS, FAIL, WARNING
	ActualValue       string    `json:"actual_value"`
	ExpectedValue     string    `json:"expected_value"`
	Rationale         string    `json:"rationale"`
	RemediationScript string    `json:"remediation_script"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}

type SecurityAuditLog struct {
	ID            string                 `json:"id"`
	CorrelationID string                 `json:"correlation_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Actor         string                 `json:"actor"`
	Action        string                 `json:"action"`
	ResourceType  string                 `json:"resource_type"`
	ResourceID    string                 `json:"resource_id"`
	Status        string                 `json:"status"`
	IPAddress     string                 `json:"ip_address"`
	Details       map[string]interface{} `json:"details"`
}

type FleetMetrics struct {
	TotalEndpoints      int     `json:"total_endpoints"`
	OnlineEndpoints     int     `json:"online_endpoints"`
	BitLockerRate       float64 `json:"bitlocker_rate"`
	TPMRate             float64 `json:"tpm_rate"`
	DefenderRate        float64 `json:"defender_rate"`
	AverageCompliance   float64 `json:"average_compliance"`
	ActiveGateways      int     `json:"active_gateways"`
	TotalGateways       int     `json:"total_gateways"`
	CriticalIssuesCount int     `json:"critical_issues_count"`
}

type HostSnapshotEntry struct {
	ID          string              `json:"id"`
	TenantID    string              `json:"tenant_id"`
	HostID      string              `json:"host_id"`
	Hostname    string              `json:"hostname"`
	ScanJobID   string              `json:"scan_job_id,omitempty"`
	PayloadHash string              `json:"payload_hash"`
	Payload     HostSnapshotPayload `json:"payload"`
	CreatedAt   time.Time           `json:"created_at"`
}
