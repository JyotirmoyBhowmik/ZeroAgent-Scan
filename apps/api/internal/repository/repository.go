package repository

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vault"
	"github.com/google/uuid"
)

type Repository struct {
	mu           sync.RWMutex
	endpoints    map[string]*models.Endpoint
	hardware     map[string]*models.HardwareInventory
	security     map[string]*models.SecurityPosture
	scans        map[string]*models.ScanJob
	gateways     map[string]*models.CollectorGateway
	credentials  map[string]*models.VaultCredentialSummary
	cisResults   map[string][]models.CISResult
	auditLogs    []models.SecurityAuditLog
}

func NewRepository() *Repository {
	repo := &Repository{
		endpoints:   make(map[string]*models.Endpoint),
		hardware:    make(map[string]*models.HardwareInventory),
		security:    make(map[string]*models.SecurityPosture),
		scans:       make(map[string]*models.ScanJob),
		gateways:    make(map[string]*models.CollectorGateway),
		credentials: make(map[string]*models.VaultCredentialSummary),
		cisResults:  make(map[string][]models.CISResult),
		auditLogs:   make([]models.SecurityAuditLog, 0),
	}

	repo.seedInitialData()
	return repo
}

func (r *Repository) seedInitialData() {
	now := time.Now().UTC()
	scannedAt := now.Add(-12 * time.Minute)

	// 1. Seed Gateways
	gw1 := &models.CollectorGateway{
		ID:                  "gw-10-100-1-0",
		GatewayCode:         "gw-subnet-10-100-1-0",
		Name:                "On-Prem Corporate HQ (Subnet A)",
		SubnetCIDR:          "10.100.1.0/24",
		MTLSCertFingerprint: "SHA256:4a8f9b2c3d1e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
		Status:              "healthy",
		Version:             "v1.2.4",
		LatencyMs:           4,
		LastHeartbeatAt:     now.Add(-5 * time.Second),
		CreatedAt:           now.Add(-48 * time.Hour),
	}
	gw2 := &models.CollectorGateway{
		ID:                  "gw-10-100-2-0",
		GatewayCode:         "gw-subnet-10-100-2-0",
		Name:                "Datacenter East Racks (Subnet B)",
		SubnetCIDR:          "10.100.2.0/24",
		MTLSCertFingerprint: "SHA256:9b2c3d1e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b4a8f",
		Status:              "healthy",
		Version:             "v1.2.4",
		LatencyMs:           2,
		LastHeartbeatAt:     now.Add(-2 * time.Second),
		CreatedAt:           now.Add(-72 * time.Hour),
	}
	r.gateways[gw1.ID] = gw1
	r.gateways[gw2.ID] = gw2

	// 2. Seed Vault Credentials
	cred1 := &models.VaultCredentialSummary{
		ID:             uuid.New().String(),
		OpaqueID:       "sec_ref_winrm_domain_prod_01",
		Name:           "Active Directory Domain Scan Account (gMSA)",
		CredentialType: "domain_kerberos",
		DomainOrHost:   "CORP.ENDPOINTGUARD.LOCAL",
		Username:       "svc_endpointguard_winrm",
		CreatedAt:      now.Add(-100 * time.Hour),
		UpdatedAt:      now.Add(-100 * time.Hour),
	}
	cred2 := &models.VaultCredentialSummary{
		ID:             uuid.New().String(),
		OpaqueID:       "sec_ref_bmc_snmpv3_dc_01",
		Name:           "Datacenter BMC/iLO SNMPv3 Auth Profile",
		CredentialType: "snmp_v3",
		DomainOrHost:   "10.100.2.0/24",
		Username:       "sec_admin_snmp",
		CreatedAt:      now.Add(-120 * time.Hour),
		UpdatedAt:      now.Add(-120 * time.Hour),
	}
	r.credentials[cred1.OpaqueID] = cred1
	r.credentials[cred2.OpaqueID] = cred2

	// 3. Seed Host 1: Windows 11 Enterprise Laptop
	h1ID := "host-w11-exec-01"
	h1 := &models.Endpoint{
		ID:                h1ID,
		Hostname:          "W11-EXEC-LP04",
		Domain:            "CORP.ENDPOINTGUARD.LOCAL",
		IPAddress:         "10.100.1.42",
		MACAddress:        "00:1A:2B:3C:4D:5E",
		OSName:            "Microsoft Windows 11 Enterprise 23H2",
		OSBuild:           "22631.3296",
		SerialNumber:      "8XKJ9201",
		Manufacturer:      "Dell Inc.",
		Model:             "Latitude 7440",
		ChassisType:       "Laptop",
		Status:            "online",
		AgentlessProtocol: "winrm_https",
		ComplianceScore:   94.5,
		LastScannedAt:     &scannedAt,
		CreatedAt:         now.Add(-24 * time.Hour),
		UpdatedAt:         now,
	}
	r.endpoints[h1ID] = h1

	r.hardware[h1ID] = &models.HardwareInventory{
		ID:         uuid.New().String(),
		EndpointID: h1ID,
		CPUDetails: map[string]interface{}{
			"name":               "13th Gen Intel(R) Core(TM) i7-1365U",
			"architecture":       "x64",
			"sockets":            1,
			"cores":              10,
			"logical_processors": 12,
			"max_clock_mhz":      5200,
		},
		MemoryDetails: map[string]interface{}{
			"total_bytes": 34359738368,
			"slots_used":  2,
			"total_slots": 2,
			"dimms": []map[string]interface{}{
				{"slot": "DIMM 1", "capacity_bytes": 17179869184, "speed_mhz": 5600, "manufacturer": "SK Hynix", "part_number": "HMCG78AGBUA"},
				{"slot": "DIMM 2", "capacity_bytes": 17179869184, "speed_mhz": 5600, "manufacturer": "SK Hynix", "part_number": "HMCG78AGBUA"},
			},
		},
		StorageDetails: map[string]interface{}{
			"disks": []map[string]interface{}{
				{"index": 0, "model": "NVMe KIOXIA 1024GB SSD", "bus_type": "NVMe", "size_bytes": 1024209543168, "partition_count": 4, "smart_status": "Healthy", "serial": "KX9820194A"},
			},
		},
		NetworkDetails: map[string]interface{}{
			"adapters": []map[string]interface{}{
				{"name": "Intel(R) Wi-Fi 6E AX211 160MHz", "mac": "00:1A:2B:3C:4D:5E", "ip_addresses": []string{"10.100.1.42"}, "subnet_mask": "255.255.255.0", "default_gateway": "10.100.1.1", "dhcp_enabled": true, "link_speed_mbps": 1200},
			},
		},
		BIOSDetails: map[string]interface{}{
			"version":         "1.11.0",
			"release_date":    "2024-01-15",
			"smbios_version":  "3.5",
			"manufacturer":    "Dell Inc.",
			"secure_boot":     true,
		},
		TPMDetails: map[string]interface{}{
			"present":         true,
			"spec_version":    "2.0",
			"manufacturer_id": "NTC",
			"enabled":         true,
			"activated":       true,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	r.security[h1ID] = &models.SecurityPosture{
		ID:         uuid.New().String(),
		EndpointID: h1ID,
		BitLockerStatus: map[string]interface{}{
			"volumes": []map[string]interface{}{
				{"drive_letter": "C:", "protection_status": 1, "encryption_method": "XtsAes256", "lock_status": 0, "key_protectors": []string{"TPM", "RecoveryPassword"}},
			},
		},
		DefenderStatus: map[string]interface{}{
			"realtime_enabled":     true,
			"cloud_protection":     true,
			"tamper_protection":    true,
			"antimalware_version":  "4.18.24030.9",
			"signatures_updated":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
		FirewallStatus: map[string]interface{}{
			"domain_profile":  true,
			"private_profile": true,
			"public_profile":  true,
		},
		UACStatus: map[string]interface{}{
			"admin_approval_mode": true,
		},
		Hotfixes: []map[string]interface{}{
			{"hotfix_id": "KB5036893", "description": "Security Update", "installed_on": "2024-04-12"},
			{"hotfix_id": "KB5037771", "description": "Cumulative Update", "installed_on": "2024-05-14"},
		},
		LocalAdmins: []string{"Administrator", "CORP\\Domain Admins"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	r.cisResults[h1ID] = []models.CISResult{
		{
			ID:                uuid.New().String(),
			EndpointID:        h1ID,
			BenchmarkName:     "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
			BenchmarkLevel:    "Level 1",
			RuleID:            "CIS-1.1.1",
			RuleTitle:         "Ensure BitLocker Drive Encryption is Enabled on OS Volume",
			Category:          "Storage & Encryption",
			Status:            "PASS",
			ActualValue:       "ProtectionStatus: 1 (Encrypted with XTS-AES 256)",
			ExpectedValue:     "ProtectionStatus: 1",
			Rationale:         "Protects volume confidentiality if host is misplaced or physically accessed.",
			RemediationScript: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
			EvaluatedAt:       now,
		},
		{
			ID:                uuid.New().String(),
			EndpointID:        h1ID,
			BenchmarkName:     "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
			BenchmarkLevel:    "Level 1",
			RuleID:            "CIS-1.2.1",
			RuleTitle:         "Ensure Trusted Platform Module (TPM) 2.0 is Active and Attested",
			Category:          "Hardware & Firmware",
			Status:            "PASS",
			ActualValue:       "TPM 2.0 Present & Enabled",
			ExpectedValue:     "TPM 2.0 Present, Enabled, and Activated",
			Rationale:         "TPM 2.0 establishes cryptographic root of trust.",
			RemediationScript: "Enable-TpmAutoProvisioning; Initialize-Tpm",
			EvaluatedAt:       now,
		},
		{
			ID:                uuid.New().String(),
			EndpointID:        h1ID,
			BenchmarkName:     "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
			BenchmarkLevel:    "Level 1",
			RuleID:            "CIS-1.3.1",
			RuleTitle:         "Ensure Microsoft Defender Real-Time Protection is Enabled",
			Category:          "System Defenses",
			Status:            "PASS",
			ActualValue:       "RealTimeProtection: Enabled",
			ExpectedValue:     "RealTimeProtection: Enabled",
			Rationale:         "Real-time scanning detects and prevents malicious code execution.",
			RemediationScript: "Set-MpPreference -DisableRealtimeMonitoring $false",
			EvaluatedAt:       now,
		},
		{
			ID:                uuid.New().String(),
			EndpointID:        h1ID,
			BenchmarkName:     "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
			BenchmarkLevel:    "Level 1",
			RuleID:            "CIS-1.4.1",
			RuleTitle:         "Ensure Microsoft Defender Tamper Protection is Enabled",
			Category:          "System Defenses",
			Status:            "PASS",
			ActualValue:       "TamperProtection: Enabled",
			ExpectedValue:     "TamperProtection: Enabled",
			Rationale:         "Tamper protection blocks malicious disabling of security tools.",
			RemediationScript: "Set-MpPreference -EnableTamperProtection $true",
			EvaluatedAt:       now,
		},
		{
			ID:                uuid.New().String(),
			EndpointID:        h1ID,
			BenchmarkName:     "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
			BenchmarkLevel:    "Level 1",
			RuleID:            "CIS-1.5.1",
			RuleTitle:         "Ensure SMBv1 (Legacy Protocol) is Completely Disabled",
			Category:          "Network Security",
			Status:            "PASS",
			ActualValue:       "SMBv1: Disabled",
			ExpectedValue:     "SMBv1: Disabled",
			Rationale:         "SMBv1 is vulnerable to remote code execution attacks.",
			RemediationScript: "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart",
			EvaluatedAt:       now,
		},
	}

	// 4. Seed Host 2: Windows Server 2022 Datacenter Domain Controller
	h2ID := "host-ws22-dc-01"
	h2 := &models.Endpoint{
		ID:                h2ID,
		Hostname:          "DC01-PROD-EAST",
		Domain:            "CORP.ENDPOINTGUARD.LOCAL",
		IPAddress:         "10.100.2.10",
		MACAddress:        "52:54:00:12:34:56",
		OSName:            "Microsoft Windows Server 2022 Datacenter",
		OSBuild:           "20348.2407",
		SerialNumber:      "VMware-56 4d 8a 91",
		Manufacturer:      "VMware, Inc.",
		Model:             "VMware7,1",
		ChassisType:       "Server",
		Status:            "online",
		AgentlessProtocol: "winrm_https",
		ComplianceScore:   98.0,
		LastScannedAt:     &scannedAt,
		CreatedAt:         now.Add(-48 * time.Hour),
		UpdatedAt:         now,
	}
	r.endpoints[h2ID] = h2

	r.hardware[h2ID] = &models.HardwareInventory{
		ID:         uuid.New().String(),
		EndpointID: h2ID,
		CPUDetails: map[string]interface{}{
			"name":               "Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz",
			"architecture":       "x64",
			"sockets":            2,
			"cores":              16,
			"logical_processors": 32,
			"max_clock_mhz":      2800,
		},
		MemoryDetails: map[string]interface{}{
			"total_bytes": 68719476736,
			"slots_used":  4,
			"total_slots": 8,
			"dimms": []map[string]interface{}{
				{"slot": "DIMM 1", "capacity_bytes": 17179869184, "speed_mhz": 3200, "manufacturer": "Micron", "part_number": "MTA36ASF4G72PZ"},
				{"slot": "DIMM 2", "capacity_bytes": 17179869184, "speed_mhz": 3200, "manufacturer": "Micron", "part_number": "MTA36ASF4G72PZ"},
				{"slot": "DIMM 3", "capacity_bytes": 17179869184, "speed_mhz": 3200, "manufacturer": "Micron", "part_number": "MTA36ASF4G72PZ"},
				{"slot": "DIMM 4", "capacity_bytes": 17179869184, "speed_mhz": 3200, "manufacturer": "Micron", "part_number": "MTA36ASF4G72PZ"},
			},
		},
		StorageDetails: map[string]interface{}{
			"disks": []map[string]interface{}{
				{"index": 0, "model": "VMware Virtual disk", "bus_type": "SCSI", "size_bytes": 214748364800, "partition_count": 3, "smart_status": "Healthy", "serial": "6000c291982a"},
			},
		},
		NetworkDetails: map[string]interface{}{
			"adapters": []map[string]interface{}{
				{"name": "vmxnet3 Ethernet Adapter", "mac": "52:54:00:12:34:56", "ip_addresses": []string{"10.100.2.10"}, "subnet_mask": "255.255.255.0", "default_gateway": "10.100.2.1", "dhcp_enabled": false, "link_speed_mbps": 10000},
			},
		},
		BIOSDetails: map[string]interface{}{
			"version":        "VMW71.00V.21100004.B64",
			"release_date":   "2023-11-12",
			"smbios_version": "2.8",
			"manufacturer":   "Phoenix Technologies LTD",
			"secure_boot":    true,
		},
		TPMDetails: map[string]interface{}{
			"present":         true,
			"spec_version":    "2.0",
			"manufacturer_id": "VMW",
			"enabled":         true,
			"activated":       true,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	r.security[h2ID] = &models.SecurityPosture{
		ID:         uuid.New().String(),
		EndpointID: h2ID,
		BitLockerStatus: map[string]interface{}{
			"volumes": []map[string]interface{}{
				{"drive_letter": "C:", "protection_status": 1, "encryption_method": "XtsAes256", "lock_status": 0, "key_protectors": []string{"TPM"}},
			},
		},
		DefenderStatus: map[string]interface{}{
			"realtime_enabled":    true,
			"cloud_protection":    true,
			"tamper_protection":   true,
			"antimalware_version": "4.18.24030.9",
			"signatures_updated":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
		FirewallStatus: map[string]interface{}{
			"domain_profile":  true,
			"private_profile": true,
			"public_profile":  true,
		},
		UACStatus: map[string]interface{}{
			"admin_approval_mode": true,
		},
		Hotfixes: []map[string]interface{}{
			{"hotfix_id": "KB5037782", "description": "Security Update", "installed_on": "2024-05-14"},
		},
		LocalAdmins: []string{"Administrator", "CORP\\Domain Admins"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	r.cisResults[h2ID] = []models.CISResult{
		{
			ID:                uuid.New().String(),
			EndpointID:        h2ID,
			BenchmarkName:     "CIS Microsoft Windows Server 2022 Benchmark v2.0.0",
			BenchmarkLevel:    "Level 1",
			RuleID:            "CIS-1.1.1",
			RuleTitle:         "Ensure BitLocker Drive Encryption is Enabled on OS Volume",
			Category:          "Storage & Encryption",
			Status:            "PASS",
			ActualValue:       "ProtectionStatus: 1 (Encrypted)",
			ExpectedValue:     "ProtectionStatus: 1",
			Rationale:         "Protects volume confidentiality.",
			RemediationScript: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256",
			EvaluatedAt:       now,
		},
	}

	// 5. Seed Recent Scans
	scan1ID := uuid.New().String()
	startedAt := now.Add(-15 * time.Minute)
	completedAt := now.Add(-12 * time.Minute)
	r.scans[scan1ID] = &models.ScanJob{
		ID:             scan1ID,
		Name:           "HQ Subnet A - Full Hardware & CIS Audit",
		TargetCIDR:     "10.100.1.0/24",
		ScanProfile:    "full_hardware_os",
		Protocol:       "winrm_https",
		VaultSecretRef: "sec_ref_winrm_domain_prod_01",
		GatewayID:      "gw-10-100-1-0",
		Status:         "completed",
		TotalHosts:     42,
		ScannedHosts:   42,
		CompliantHosts: 40,
		FailedHosts:    2,
		Logs: []string{
			"[" + startedAt.Format(time.RFC3339) + "] [INFO] Authenticating to Subnet Gateway gw-subnet-10-100-1-0 via mTLS 1.3",
			"[" + startedAt.Add(2*time.Second).Format(time.RFC3339) + "] [INFO] Resolved opaque credential sec_ref_winrm_domain_prod_01 from Vault memory buffer",
			"[" + startedAt.Add(5*time.Second).Format(time.RFC3339) + "] [INFO] Probing 42 target hosts across 10.100.1.0/24 over WinRM HTTPS (Port 5986)",
			"[" + startedAt.Add(30*time.Second).Format(time.RFC3339) + "] [INFO] Batch WQL CIM queries executed successfully for Win32_OperatingSystem, Win32_Processor, Win32_DiskDrive",
			"[" + startedAt.Add(60*time.Second).Format(time.RFC3339) + "] [INFO] Querying Root\\CIMv2\\Security\\MicrosoftVolumeEncryption (BitLocker) and TPM 2.0 classes",
			"[" + startedAt.Add(90*time.Second).Format(time.RFC3339) + "] [INFO] Evaluating telemetry against CIS Windows 11 Benchmark v3.0.0",
			"[" + completedAt.Format(time.RFC3339) + "] [INFO] Scan completed successfully. 40/42 hosts compliant (95.2%).",
		},
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
		CreatedAt:   startedAt,
	}

	// 6. Seed Audit Log
	r.auditLogs = append(r.auditLogs, models.SecurityAuditLog{
		ID:            uuid.New().String(),
		CorrelationID: "req-init-bootstrap",
		Timestamp:     now.Add(-1 * time.Hour),
		Actor:         "system_bootstrap",
		Action:        "VAULT_MASTER_KEY_LOADED",
		ResourceType:  "vault",
		ResourceID:    "master_key",
		Status:        "SUCCESS",
		IPAddress:     "127.0.0.1",
		Details:       map[string]interface{}{"algorithm": "AES-256-GCM", "kdf": "HKDF-SHA256"},
	})
}

// Public repository methods
func (r *Repository) ListEndpoints(search, osFilter, statusFilter string) []models.Endpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []models.Endpoint
	search = strings.ToLower(search)

	for _, ep := range r.endpoints {
		if search != "" {
			hMatch := strings.Contains(strings.ToLower(ep.Hostname), search)
			ipMatch := strings.Contains(ep.IPAddress, search)
			manMatch := strings.Contains(strings.ToLower(ep.Manufacturer), search)
			if !hMatch && !ipMatch && !manMatch {
				continue
			}
		}
		if osFilter != "" && !strings.Contains(strings.ToLower(ep.OSName), strings.ToLower(osFilter)) {
			continue
		}
		if statusFilter != "" && ep.Status != statusFilter {
			continue
		}
		result = append(result, *ep)
	}
	return result
}

func (r *Repository) GetEndpointDetail(id string) (*models.EndpointDetail, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ep, ok := r.endpoints[id]
	if !ok {
		return nil, fmt.Errorf("endpoint not found with ID: %s", id)
	}

	hw := r.hardware[id]
	if hw == nil {
		hw = &models.HardwareInventory{EndpointID: id}
	}

	sec := r.security[id]
	if sec == nil {
		sec = &models.SecurityPosture{EndpointID: id}
	}

	cis := r.cisResults[id]
	if cis == nil {
		cis = []models.CISResult{}
	}

	return &models.EndpointDetail{
		Endpoint:        *ep,
		Hardware:        *hw,
		SecurityPosture: *sec,
		CISResults:      cis,
	}, nil
}

func (r *Repository) CreateScanJob(req models.CreateScanJobRequest) *models.ScanJob {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	id := uuid.New().String()

	job := &models.ScanJob{
		ID:             id,
		Name:           req.Name,
		TargetCIDR:     req.TargetCIDR,
		ScanProfile:    req.ScanProfile,
		Protocol:       req.Protocol,
		VaultSecretRef: req.VaultSecretRef,
		GatewayID:      req.GatewayID,
		Status:         "running",
		TotalHosts:     16,
		ScannedHosts:   0,
		CompliantHosts: 0,
		FailedHosts:    0,
		Logs: []string{
			fmt.Sprintf("[%s] [INFO] Scan initiated for target %s using %s protocol", now.Format(time.RFC3339), req.TargetCIDR, req.Protocol),
			fmt.Sprintf("[%s] [INFO] Dispatching task to Collector Gateway %s", now.Format(time.RFC3339), req.GatewayID),
			fmt.Sprintf("[%s] [INFO] Target hosts WS-Man handshake established. Scanning WMI/CIM classes...", now.Add(1*time.Second).Format(time.RFC3339)),
		},
		StartedAt: &now,
		CreatedAt: now,
	}

	r.scans[id] = job
	return job
}

func (r *Repository) ListScanJobs() []models.ScanJob {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []models.ScanJob
	for _, s := range r.scans {
		result = append(result, *s)
	}
	return result
}

func (r *Repository) GetScanJob(id string) (*models.ScanJob, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	job, ok := r.scans[id]
	if !ok {
		return nil, fmt.Errorf("scan job not found: %s", id)
	}
	return job, nil
}

func (r *Repository) ListGateways() []models.CollectorGateway {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []models.CollectorGateway
	for _, gw := range r.gateways {
		result = append(result, *gw)
	}
	return result
}

func (r *Repository) UpdateGatewayHeartbeat(gatewayCode string, latencyMs int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, gw := range r.gateways {
		if gw.GatewayCode == gatewayCode {
			gw.LastHeartbeatAt = time.Now().UTC()
			gw.LatencyMs = latencyMs
			gw.Status = "healthy"
			return
		}
	}
}

func (r *Repository) ListVaultCredentials() []models.VaultCredentialSummary {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []models.VaultCredentialSummary
	for _, c := range r.credentials {
		result = append(result, *c)
	}
	return result
}

func (r *Repository) AddVaultCredential(summary *models.VaultCredentialSummary) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.credentials[summary.OpaqueID] = summary
}

func (r *Repository) ListAuditLogs() []models.SecurityAuditLog {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.auditLogs
}

func (r *Repository) AddAuditLog(log models.SecurityAuditLog) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.auditLogs = append([]models.SecurityAuditLog{log}, r.auditLogs...)
	if len(r.auditLogs) > 1000 {
		r.auditLogs = r.auditLogs[:1000]
	}
}

func (r *Repository) GetFleetMetrics() models.FleetMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	total := len(r.endpoints)
	online := 0
	totalCompliance := 0.0

	for _, ep := range r.endpoints {
		if ep.Status == "online" {
			online++
		}
		totalCompliance += ep.ComplianceScore
	}

	avgCompliance := 0.0
	if total > 0 {
		avgCompliance = totalCompliance / float64(total)
	}

	activeGW := 0
	for _, gw := range r.gateways {
		if gw.Status == "healthy" {
			activeGW++
		}
	}

	return models.FleetMetrics{
		TotalEndpoints:      total,
		OnlineEndpoints:     online,
		BitLockerRate:       96.2,
		TPMRate:             100.0,
		DefenderRate:        100.0,
		AverageCompliance:   avgCompliance,
		ActiveGateways:      activeGW,
		TotalGateways:       len(r.gateways),
		CriticalIssuesCount: 0,
	}
}

// AuditLogFromVaultEntry converts a vault SecretResolutionAuditEntry into a
// models.SecurityAuditLog for persistence. This bridge function lives in the
// repository package to avoid a circular dependency between vault and models.
func AuditLogFromVaultEntry(entry vault.SecretResolutionAuditEntry) models.SecurityAuditLog {
	return models.SecurityAuditLog{
		ID:            uuid.New().String(),
		CorrelationID: entry.CorrelationID,
		Timestamp:     entry.Timestamp,
		Actor:         entry.GatewayID,
		Action:        entry.Action,
		ResourceType:  "vault_credential",
		ResourceID:    entry.CredentialRef,
		Status:        "SUCCESS",
		IPAddress:     entry.IPAddress,
		Details: map[string]interface{}{
			"scan_job_id": entry.ScanJobID,
			"tenant_id":   entry.TenantID,
		},
	}
}
