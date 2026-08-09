export interface Endpoint {
  id: string;
  hostname: string;
  domain: string;
  ip_address: string;
  mac_address: string;
  os_name: string;
  os_build: string;
  serial_number: string;
  manufacturer: string;
  model: string;
  chassis_type: string;
  status: "online" | "offline" | "scanning" | "error";
  agentless_protocol: string;
  compliance_score: number;
  last_scanned_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CPUDetails {
  name?: string;
  architecture?: string;
  sockets?: number;
  cores?: number;
  logical_processors?: number;
  max_clock_mhz?: number;
}

export interface MemoryDIMM {
  slot?: string;
  capacity_bytes?: number;
  speed_mhz?: number;
  manufacturer?: string;
  part_number?: string;
  serial_number?: string;
}

export interface MemoryDetails {
  total_bytes?: number;
  slots_used?: number;
  total_slots?: number;
  dimms?: MemoryDIMM[];
}

export interface StorageDisk {
  index?: number;
  model?: string;
  bus_type?: string;
  size_bytes?: number;
  partition_count?: number;
  smart_status?: string;
  serial?: string;
}

export interface NetworkAdapter {
  name?: string;
  mac?: string;
  ip_addresses?: string[];
  subnet_mask?: string;
  default_gateway?: string;
  dhcp_enabled?: boolean;
  dns_servers?: string[];
  link_speed_mbps?: number;
}

export interface HardwareInventory {
  id?: string;
  endpoint_id: string;
  cpu_details: CPUDetails;
  memory_details: MemoryDetails;
  storage_details: { disks?: StorageDisk[] };
  network_details: { adapters?: NetworkAdapter[] };
  bios_details: { version?: string; release_date?: string; smbios_version?: string; manufacturer?: string; secure_boot?: boolean };
  tpm_details: { present?: boolean; spec_version?: string; manufacturer_id?: string; enabled?: boolean; activated?: boolean };
}

export interface SecurityPosture {
  id?: string;
  endpoint_id: string;
  bitlocker_status: { volumes?: Array<{ drive_letter?: string; protection_status?: number; encryption_method?: string; lock_status?: number; key_protectors?: string[] }> };
  defender_status: { realtime_enabled?: boolean; cloud_protection?: boolean; tamper_protection?: boolean; antimalware_version?: string; signatures_updated?: string };
  firewall_status: { domain_profile?: boolean; private_profile?: boolean; public_profile?: boolean };
  uac_status: { admin_approval_mode?: boolean };
  hotfixes: Array<{ hotfix_id?: string; description?: string; installed_on?: string }>;
  local_admins: string[];
}

export interface CISResult {
  id: string;
  endpoint_id: string;
  benchmark_name: string;
  benchmark_level: string;
  rule_id: string;
  rule_title: string;
  category: string;
  status: "PASS" | "FAIL" | "WARNING" | "NOT_APPLICABLE";
  actual_value: string;
  expected_value: string;
  rationale: string;
  remediation_script: string;
  evaluated_at: string;
}

export interface EndpointDetail {
  endpoint: Endpoint;
  hardware: HardwareInventory;
  security_posture: SecurityPosture;
  cis_results: CISResult[];
}

export interface ScanJob {
  id: string;
  name: string;
  target_cidr: string;
  scan_profile: string;
  protocol: string;
  vault_secret_ref: string;
  gateway_id: string;
  status: "pending" | "running" | "completed" | "failed";
  total_hosts: number;
  scanned_hosts: number;
  compliant_hosts: number;
  failed_hosts: number;
  logs: string[];
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface CollectorGateway {
  id: string;
  gateway_code: string;
  name: string;
  subnet_cidr: string;
  mtls_cert_fingerprint: string;
  status: "healthy" | "degraded" | "offline";
  version: string;
  latency_ms: number;
  last_heartbeat_at: string;
  created_at: string;
}

export interface VaultCredentialSummary {
  id: string;
  opaque_id: string;
  name: string;
  credential_type: string;
  domain_or_host: string;
  username: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityAuditLog {
  id: string;
  correlation_id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string;
  status: string;
  ip_address: string;
  details: Record<string, any>;
}

export interface FleetMetrics {
  total_endpoints: number;
  online_endpoints: number;
  bitlocker_rate: number;
  tpm_rate: number;
  defender_rate: number;
  average_compliance: number;
  active_gateways: number;
  total_gateways: number;
  critical_issues_count: number;
}
