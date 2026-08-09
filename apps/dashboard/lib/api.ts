import { Endpoint, EndpointDetail, FleetMetrics, CollectorGateway, VaultCredentialSummary, ScanJob, SecurityAuditLog } from "./types";
import { MOCK_METRICS, MOCK_ENDPOINTS, MOCK_GATEWAYS, MOCK_CREDENTIALS, MOCK_SCANS, MOCK_AUDIT_LOGS } from "./mockData";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

function generateCorrelationID(): string {
  return `fe-${Math.random().toString(36).substring(2, 10)}`;
}

async function fetchAPI<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const correlationId = generateCorrelationID();
  const headers = {
    "Content-Type": "application/json",
    "X-Correlation-ID": correlationId,
    ...(options.headers || {}),
  };

  try {
    const res = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
      next: { revalidate: 0 },
    });

    if (!res.ok) {
      throw new Error(`API error: ${res.status} ${res.statusText}`);
    }

    return await res.json();
  } catch (err) {
    console.warn(`[EndpointGuard UI] API call to ${endpoint} failed, falling back to cached/mock store:`, err);
    throw err;
  }
}

export const api = {
  getMetrics: async (): Promise<FleetMetrics> => {
    try {
      return await fetchAPI<FleetMetrics>("/api/v1/metrics");
    } catch {
      return MOCK_METRICS;
    }
  },

  getEndpoints: async (search = "", os = "", status = ""): Promise<Endpoint[]> => {
    try {
      const params = new URLSearchParams();
      if (search) params.append("search", search);
      if (os) params.append("os", os);
      if (status) params.append("status", status);
      return await fetchAPI<Endpoint[]>(`/api/v1/endpoints?${params.toString()}`);
    } catch {
      let filtered = [...MOCK_ENDPOINTS];
      if (search) {
        filtered = filtered.filter(
          (e) =>
            e.hostname.toLowerCase().includes(search.toLowerCase()) ||
            e.ip_address.includes(search) ||
            e.manufacturer.toLowerCase().includes(search.toLowerCase())
        );
      }
      if (os) {
        filtered = filtered.filter((e) => e.os_name.toLowerCase().includes(os.toLowerCase()));
      }
      if (status) {
        filtered = filtered.filter((e) => e.status === status);
      }
      return filtered;
    }
  },

  getEndpointDetail: async (id: string): Promise<EndpointDetail> => {
    try {
      return await fetchAPI<EndpointDetail>(`/api/v1/endpoints/${id}`);
    } catch {
      const base = MOCK_ENDPOINTS.find((e) => e.id === id) || MOCK_ENDPOINTS[0];
      return {
        endpoint: base,
        hardware: {
          endpoint_id: base.id,
          cpu_details: {
            name: "13th Gen Intel(R) Core(TM) i7-1365U",
            architecture: "x64",
            sockets: 1,
            cores: 10,
            logical_processors: 12,
            max_clock_mhz: 5200,
          },
          memory_details: {
            total_bytes: 34359738368,
            slots_used: 2,
            total_slots: 2,
            dimms: [
              { slot: "DIMM 1", capacity_bytes: 17179869184, speed_mhz: 5600, manufacturer: "SK Hynix", part_number: "HMCG78AGBUA" },
              { slot: "DIMM 2", capacity_bytes: 17179869184, speed_mhz: 5600, manufacturer: "SK Hynix", part_number: "HMCG78AGBUA" },
            ],
          },
          storage_details: {
            disks: [
              { index: 0, model: "NVMe KIOXIA 1024GB SSD", bus_type: "NVMe", size_bytes: 1024209543168, partition_count: 4, smart_status: "Healthy", serial: "KX9820194A" },
            ],
          },
          network_details: {
            adapters: [
              { name: "Intel(R) Wi-Fi 6E AX211 160MHz", mac: base.mac_address, ip_addresses: [base.ip_address], subnet_mask: "255.255.255.0", default_gateway: "10.100.1.1", dhcp_enabled: true, link_speed_mbps: 1200 },
            ],
          },
          bios_details: { version: "1.11.0", release_date: "2024-01-15", smbios_version: "3.5", manufacturer: base.manufacturer, secure_boot: true },
          tpm_details: { present: true, spec_version: "2.0", manufacturer_id: "NTC", enabled: true, activated: true },
        },
        security_posture: {
          endpoint_id: base.id,
          bitlocker_status: {
            volumes: [{ drive_letter: "C:", protection_status: 1, encryption_method: "XtsAes256", lock_status: 0, key_protectors: ["TPM", "RecoveryPassword"] }],
          },
          defender_status: {
            realtime_enabled: true,
            cloud_protection: true,
            tamper_protection: true,
            antimalware_version: "4.18.24030.9",
            signatures_updated: new Date().toISOString(),
          },
          firewall_status: { domain_profile: true, private_profile: true, public_profile: true },
          uac_status: { admin_approval_mode: true },
          hotfixes: [
            { hotfix_id: "KB5036893", description: "Security Update", installed_on: "2024-04-12" },
            { hotfix_id: "KB5037771", description: "Cumulative Update", installed_on: "2024-05-14" },
          ],
          local_admins: ["Administrator", "CORP\\Domain Admins"],
        },
        cis_results: [
          {
            id: "cis-1",
            endpoint_id: base.id,
            benchmark_name: "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
            benchmark_level: "Level 1",
            rule_id: "CIS-1.1.1",
            rule_title: "Ensure BitLocker Drive Encryption is Enabled on OS Volume",
            category: "Storage & Encryption",
            status: "PASS",
            actual_value: "ProtectionStatus: 1 (Encrypted with XTS-AES 256)",
            expected_value: "ProtectionStatus: 1",
            rationale: "Protects volume confidentiality if host is misplaced or physically accessed.",
            remediation_script: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
            evaluated_at: new Date().toISOString(),
          },
          {
            id: "cis-2",
            endpoint_id: base.id,
            benchmark_name: "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
            benchmark_level: "Level 1",
            rule_id: "CIS-1.2.1",
            rule_title: "Ensure Trusted Platform Module (TPM) 2.0 is Active and Attested",
            category: "Hardware & Firmware",
            status: "PASS",
            actual_value: "TPM 2.0 Present & Enabled",
            expected_value: "TPM 2.0 Present, Enabled, and Activated",
            rationale: "TPM 2.0 establishes cryptographic root of trust.",
            remediation_script: "Enable-TpmAutoProvisioning; Initialize-Tpm",
            evaluated_at: new Date().toISOString(),
          },
          {
            id: "cis-3",
            endpoint_id: base.id,
            benchmark_name: "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
            benchmark_level: "Level 1",
            rule_id: "CIS-1.3.1",
            rule_title: "Ensure Microsoft Defender Real-Time Protection is Enabled",
            category: "System Defenses",
            status: "PASS",
            actual_value: "RealTimeProtection: Enabled",
            expected_value: "RealTimeProtection: Enabled",
            rationale: "Real-time scanning detects and prevents malicious code execution.",
            remediation_script: "Set-MpPreference -DisableRealtimeMonitoring $false",
            evaluated_at: new Date().toISOString(),
          },
          {
            id: "cis-4",
            endpoint_id: base.id,
            benchmark_name: "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
            benchmark_level: "Level 1",
            rule_id: "CIS-1.4.1",
            rule_title: "Ensure Microsoft Defender Tamper Protection is Enabled",
            category: "System Defenses",
            status: "PASS",
            actual_value: "TamperProtection: Enabled",
            expected_value: "TamperProtection: Enabled",
            rationale: "Tamper protection blocks malicious disabling of security tools.",
            remediation_script: "Set-MpPreference -EnableTamperProtection $true",
            evaluated_at: new Date().toISOString(),
          },
          {
            id: "cis-5",
            endpoint_id: base.id,
            benchmark_name: "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
            benchmark_level: "Level 1",
            rule_id: "CIS-1.5.1",
            rule_title: "Ensure SMBv1 (Legacy Protocol) is Completely Disabled",
            category: "Network Security",
            status: "PASS",
            actual_value: "SMBv1: Disabled",
            expected_value: "SMBv1: Disabled",
            rationale: "SMBv1 is vulnerable to remote code execution attacks.",
            remediation_script: "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart",
            evaluated_at: new Date().toISOString(),
          },
        ],
      };
    }
  },

  getGateways: async (): Promise<CollectorGateway[]> => {
    try {
      return await fetchAPI<CollectorGateway[]>("/api/v1/gateways");
    } catch {
      return MOCK_GATEWAYS;
    }
  },

  getVaultCredentials: async (): Promise<VaultCredentialSummary[]> => {
    try {
      return await fetchAPI<VaultCredentialSummary[]>("/api/v1/vault/credentials");
    } catch {
      return MOCK_CREDENTIALS;
    }
  },

  createVaultCredential: async (data: {
    name: string;
    credential_type: string;
    domain_or_host: string;
    username: string;
    secret_value: string;
  }): Promise<VaultCredentialSummary> => {
    try {
      return await fetchAPI<VaultCredentialSummary>("/api/v1/vault/credentials", {
        method: "POST",
        body: JSON.stringify(data),
      });
    } catch {
      const newCred: VaultCredentialSummary = {
        id: `cred-${Date.now()}`,
        opaque_id: `sec_ref_${data.credential_type.toLowerCase()}_${Math.random().toString(36).substring(2, 10)}`,
        name: data.name,
        credential_type: data.credential_type,
        domain_or_host: data.domain_or_host,
        username: data.username,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      MOCK_CREDENTIALS.unshift(newCred);
      return newCred;
    }
  },

  getScans: async (): Promise<ScanJob[]> => {
    try {
      return await fetchAPI<ScanJob[]>("/api/v1/scans");
    } catch {
      return MOCK_SCANS;
    }
  },

  createScan: async (data: {
    name: string;
    target_cidr: string;
    scan_profile: string;
    protocol: string;
    vault_secret_ref: string;
    gateway_id: string;
  }): Promise<ScanJob> => {
    try {
      return await fetchAPI<ScanJob>("/api/v1/scans", {
        method: "POST",
        body: JSON.stringify(data),
      });
    } catch {
      const now = new Date().toISOString();
      const newScan: ScanJob = {
        id: `scan-${Date.now()}`,
        name: data.name,
        target_cidr: data.target_cidr,
        scan_profile: data.scan_profile,
        protocol: data.protocol,
        vault_secret_ref: data.vault_secret_ref,
        gateway_id: data.gateway_id,
        status: "running",
        total_hosts: 16,
        scanned_hosts: 0,
        compliant_hosts: 0,
        failed_hosts: 0,
        logs: [
          `[${now}] [INFO] Dispatched agentless scan to Gateway ${data.gateway_id}`,
          `[${now}] [INFO] Authenticating over WinRM HTTPS (Port 5986) using Vault secret ${data.vault_secret_ref}`,
          `[${now}] [INFO] Probing ${data.target_cidr}...`,
        ],
        started_at: now,
        created_at: now,
      };
      MOCK_SCANS.unshift(newScan);
      return newScan;
    }
  },

  getAuditLogs: async (): Promise<SecurityAuditLog[]> => {
    try {
      return await fetchAPI<SecurityAuditLog[]>("/api/v1/audit-logs");
    } catch {
      return MOCK_AUDIT_LOGS;
    }
  },
};
