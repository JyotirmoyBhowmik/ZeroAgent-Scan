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
  open_vulns_count?: number;
  critical_vulns_count?: number;
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
  virtualization_firmware?: boolean;
  vbs_status?: string;
  hvci_status?: string;
}

export interface MemoryDIMM {
  slot?: string;
  capacity_bytes?: number;
  speed_mhz?: number;
  manufacturer?: string;
  part_number?: string;
  serial_number?: string;
  form_factor?: string;
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
  media_type?: string;
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
  status?: string;
}

export interface BIOSDetails {
  vendor?: string;
  version?: string;
  release_date?: string;
  smbios_version?: string;
  smbios_guid?: string;
  manufacturer?: string;
  secure_boot?: boolean;
  uefi_mode?: boolean;
}

export interface TPMDetails {
  present?: boolean;
  spec_version?: string;
  manufacturer_id?: string;
  enabled?: boolean;
  activated?: boolean;
  pcr0_hash?: string;
  pcr7_hash?: string;
}

export interface HardwareInventory {
  id?: string;
  endpoint_id: string;
  cpu_details: CPUDetails;
  memory_details: MemoryDetails;
  storage_details: { disks?: StorageDisk[] };
  network_details: { adapters?: NetworkAdapter[] };
  bios_details: BIOSDetails;
  tpm_details: TPMDetails;
}

export interface SoftwarePackage {
  name: string;
  version: string;
  vendor?: string;
  architecture?: string;
  install_date?: string;
  cpe?: string;
}

export interface SecurityPosture {
  id?: string;
  endpoint_id: string;
  bitlocker_status: {
    volumes?: Array<{
      drive_letter?: string;
      protection_status?: number;
      encryption_method?: string;
      lock_status?: number;
      key_protectors?: string[];
    }>;
  };
  defender_status: {
    realtime_enabled?: boolean;
    cloud_protection?: boolean;
    tamper_protection?: boolean;
    antimalware_version?: string;
    signatures_updated?: string;
    pua_protection?: boolean;
  };
  firewall_status: {
    domain_profile?: boolean;
    private_profile?: boolean;
    public_profile?: boolean;
  };
  uac_status: {
    admin_approval_mode?: boolean;
  };
  credential_guard_enabled?: boolean;
  lsa_protection_enabled?: boolean;
  smbv1_disabled?: boolean;
  rdp_nla_required?: boolean;
  reboot_pending?: {
    component_based_servicing?: boolean;
    windows_update?: boolean;
    pending_file_rename?: boolean;
    is_reboot_required?: boolean;
  };
  cutover_readiness?: {
    windows_11_ready?: boolean;
    tpm20_passed?: boolean;
    secure_boot_passed?: boolean;
    ram_passed?: boolean;
    storage_passed?: boolean;
    cpu_passed?: boolean;
  };
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
  cis_control_citation: string;
  evaluated_at: string;
}

export interface EndpointDetail {
  endpoint: Endpoint;
  hardware: HardwareInventory;
  security_posture: SecurityPosture;
  cis_results: CISResult[];
}

export interface HostSnapshot {
  id: string;
  endpoint_id: string;
  hostname: string;
  scan_job_id: string;
  payload_hash: string;
  created_at: string;
  hardware: HardwareInventory;
  software: SoftwarePackage[];
  security_posture: SecurityPosture;
  cis_results: CISResult[];
}

export interface SnapshotDiffItem {
  subsystem: string;
  field_path: string;
  old_value: any;
  new_value: any;
  severity: "CRITICAL" | "WARNING" | "INFO";
  change_type: "MODIFIED" | "ADDED" | "REMOVED";
}

export interface VulnerabilityFinding {
  id: string;
  tenant_id: string;
  endpoint_id: string;
  hostname: string;
  cve_id: string;
  cpe_string: string;
  cvss_score: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  is_kev: boolean;
  kev_due_date?: string;
  short_description: string;
  status: "OPEN" | "MITIGATED" | "ACCEPTED_RISK" | "FALSE_POSITIVE";
  justification_note?: string;
  remediation_guidance: string;
  first_seen: string;
  last_seen: string;
}

export interface DriftEvent {
  id: string;
  tenant_id: string;
  host_id: string;
  hostname: string;
  subsystem: string;
  property_name: string;
  old_value: string;
  new_value: string;
  severity: "CRITICAL" | "WARNING" | "INFO";
  acknowledged: boolean;
  detected_at: string;
}

export interface NetworkSubnet {
  id: string;
  subnet_cidr: string;
  name: string;
  location: string;
  assigned_gateway_code: string;
  gateway_name: string;
  gateway_status: "healthy" | "degraded" | "offline";
  gateway_latency_ms: number;
  host_count: number;
  online_count: number;
  compliant_count: number;
  last_scan_at: string;
}

export interface ReportConfig {
  id: string;
  title: string;
  report_type: "EXECUTIVE_SUMMARY" | "COMPLIANCE_AUDIT" | "VULNERABILITY_POSTURE";
  format: "PDF" | "CSV";
  schedule: "DAILY" | "WEEKLY" | "MONTHLY" | "ON_DEMAND";
  recipients: string[];
  shareable_token?: string;
  shareable_url?: string;
  expires_at?: string;
  created_at: string;
  last_generated_at?: string;
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
  open_critical_vulns: number;
  open_kev_count: number;
  compliance_bands: {
    band_90_100: number;
    band_75_89: number;
    band_50_74: number;
    band_under_50: number;
  };
}
