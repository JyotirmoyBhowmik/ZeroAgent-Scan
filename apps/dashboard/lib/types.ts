export type RolloutTier = "pilot" | "staged" | "full";

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
  rollout_tier: RolloutTier;
  organizational_unit?: string;
  subnet_cidr?: string;
  tier_promoted_at?: string;
  tier_promoted_by?: string;
  tier_promotion_reason?: string;
  open_vulns_count?: number;
  critical_vulns_count?: number;
  last_scanned_at?: string;
  created_at: string;
  updated_at: string;
}

export interface PilotHealthSummary {
  total_pilot_hosts: number;
  online_pilot_hosts: number;
  scan_success_rate: number;
  auth_failure_count: number;
  lockout_risk_count: number;
  edr_alert_correlation_count: number;
  average_scan_duration_ms: number;
  average_compliance_score: number;
  pilot_hosts: Endpoint[];
}

export interface PromoteTierRequest {
  target_tier: "staged" | "full";
  justification: string;
  endpoint_ids?: string[];
  subnet_cidr?: string;
  organizational_unit?: string;
}

export interface BulkAssignTierRequest {
  rollout_tier: RolloutTier;
  justification: string;
  subnet_cidr?: string;
  organizational_unit?: string;
  endpoint_ids?: string[];
}

export interface RolloutSettings {
  active_tiers: RolloutTier[];
  schedule_enforce_tiers: boolean;
  updated_at?: string;
  updated_by?: string;
}

export interface AlertHealthStatus {
  last_test_alert_at?: string;
  last_test_alert_status: "DELIVERED" | "FAILED" | "NEVER_TESTED";
  last_test_alert_operator?: string;
  last_test_alert_target_url?: string;
  last_test_alert_receipt?: string;
  test_alert_lapse_days: number;
  test_alert_lapsed: boolean;
  configured_webhook_count: number;
  active_alert_rules_count: number;
}

export interface TestAlertRequest {
  webhook_url?: string;
  secret_key?: string;
  channel?: "WEBHOOK" | "SLACK" | "TEAMS" | "EMAIL";
  test_reason?: string;
}

export interface TestAlertResponse {
  status: "DELIVERED" | "FAILED" | "TIMEOUT";
  target_url: string;
  status_code: number;
  duration_ms: number;
  delivery_id: string;
  verification_receipt: string;
  error_message?: string;
  tested_at: string;
  tested_by: string;
  alert_notice: string;
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
  allow_insecure_http?: boolean;
  transport_protocol?: "winrm_https" | "winrm_http" | "dcom_rpc";
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

export interface SnapshotRetentionPolicy {
  retention_days: number;
  strategy: 'archive' | 'downsample';
  cold_storage_path: string;
  keep_weekly_interval_days: number;
  is_enabled: boolean;
  last_run_at?: string;
  last_run_status?: string;
  last_reclaimed_bytes?: number;
  updated_at: string;
  updated_by: string;
}

export interface SnapshotArchiveSummary {
  snapshot_id: string;
  host_id: string;
  hostname: string;
  captured_at: string;
  payload_size_bytes: number;
  action: 'ARCHIVE_TO_COLD_STORAGE' | 'RETAIN_WEEKLY_CHECKPOINT' | 'PRUNE_DOWNSAMPLED';
  target_location?: string;
}

export interface SnapshotRetentionDryRun {
  retention_days: number;
  strategy: string;
  cutoff_date: string;
  total_snapshots_evaluated: number;
  snapshots_eligible_for_action: number;
  snapshots_to_archive: number;
  snapshots_to_prune: number;
  snapshots_weekly_retained: number;
  estimated_reclaimed_bytes: number;
  estimated_storage_saved_mb: number;
  affected_endpoints_count: number;
  affected_endpoints: string[];
  sample_snapshots: SnapshotArchiveSummary[];
  preserved_derived_records_notice: string;
  dry_run_generated_at: string;
}

export interface SnapshotRetentionExecuteRequest {
  retention_days?: number;
  strategy?: string;
  cold_storage_path?: string;
  dry_run?: boolean;
  justification?: string;
}

export interface SnapshotRetentionExecuteResult {
  execution_id: string;
  strategy: string;
  retention_days: number;
  cutoff_date: string;
  snapshots_processed: number;
  snapshots_archived: number;
  snapshots_downsampled: number;
  snapshots_weekly_retained: number;
  reclaimed_bytes: number;
  storage_saved_mb: number;
  archive_directory?: string;
  duration_ms: number;
  status: string;
  executed_at: string;
  executed_by: string;
  audit_log_id: string;
}

