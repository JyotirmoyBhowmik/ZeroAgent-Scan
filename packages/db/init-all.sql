-- ===========================================================================
-- EndpointGuard Migration: 000001_create_tenants_and_core_schema.up.sql
-- Multi-Tenant Core Architecture & Target Endpoint Schema
-- ===========================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------
-- 1. Tenants (Organizations / Enterprise Workspaces)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(128) UNIQUE NOT NULL,
    subscription_tier VARCHAR(64) NOT NULL DEFAULT 'enterprise',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

-- ---------------------------------------------------------------------------
-- 2. Tenant Users (RBAC: Admin, SecurityOfficer, Auditor, CollectorService)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(64) NOT NULL DEFAULT 'SecurityOfficer',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenant_user_email UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_tenant_users_tenant ON tenant_users(tenant_id);

-- ---------------------------------------------------------------------------
-- 3. Endpoints (Target Windows 11 & Windows Server Hosts)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL DEFAULT 'WORKGROUP',
    ip_address INET NOT NULL,
    mac_address VARCHAR(32) NOT NULL,
    os_name VARCHAR(255) NOT NULL,
    os_build VARCHAR(64) NOT NULL,
    serial_number VARCHAR(128) NOT NULL,
    manufacturer VARCHAR(128) NOT NULL,
    model VARCHAR(128) NOT NULL,
    chassis_type VARCHAR(64) NOT NULL DEFAULT 'Desktop',
    status VARCHAR(32) NOT NULL DEFAULT 'online', -- online, offline, scanning, error
    agentless_protocol VARCHAR(32) NOT NULL DEFAULT 'winrm_https', -- winrm_https, winrm_http, cim_xml, snmp_v3, ssh_bmc
    compliance_score NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    last_scanned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenant_endpoint_host_ip UNIQUE (tenant_id, hostname, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_tenant ON endpoints(tenant_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_tenant_status ON endpoints(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_endpoints_tenant_hostname ON endpoints(tenant_id, hostname);
CREATE INDEX IF NOT EXISTS idx_endpoints_tenant_ip ON endpoints(tenant_id, ip_address);
CREATE INDEX IF NOT EXISTS idx_endpoints_tenant_compliance ON endpoints(tenant_id, compliance_score);

-- ---------------------------------------------------------------------------
-- 4. Hardware Inventories (Detailed Component Specs)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hardware_inventories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    cpu_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    memory_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    storage_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    network_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    bios_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    tpm_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_hardware_tenant_endpoint UNIQUE (tenant_id, endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_hardware_tenant ON hardware_inventories(tenant_id);
CREATE INDEX IF NOT EXISTS idx_hardware_endpoint ON hardware_inventories(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_hardware_cpu_gin ON hardware_inventories USING GIN (cpu_details);
CREATE INDEX IF NOT EXISTS idx_hardware_storage_gin ON hardware_inventories USING GIN (storage_details);
CREATE INDEX IF NOT EXISTS idx_hardware_network_gin ON hardware_inventories USING GIN (network_details);

-- ---------------------------------------------------------------------------
-- 5. Security Postures (BitLocker, TPM 2.0, Defender, Firewall, UAC)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_postures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    bitlocker_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    defender_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    firewall_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    uac_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    hotfixes JSONB NOT NULL DEFAULT '[]'::jsonb,
    local_admins JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_security_tenant_endpoint UNIQUE (tenant_id, endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_security_tenant ON security_postures(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_endpoint ON security_postures(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_security_bitlocker_gin ON security_postures USING GIN (bitlocker_status);
CREATE INDEX IF NOT EXISTS idx_security_defender_gin ON security_postures USING GIN (defender_status);

-- ---------------------------------------------------------------------------
-- 6. Subnet Collector Gateways (Per-Subnet On-Prem daemons)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS collector_gateways (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    gateway_code VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    subnet_cidr VARCHAR(64) NOT NULL,
    mtls_cert_fingerprint VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'healthy', -- healthy, degraded, offline
    version VARCHAR(32) NOT NULL DEFAULT 'v1.0.0',
    latency_ms INT NOT NULL DEFAULT 0,
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gateway_tenant_code UNIQUE (tenant_id, gateway_code)
);

CREATE INDEX IF NOT EXISTS idx_gateways_tenant ON collector_gateways(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gateways_tenant_status ON collector_gateways(tenant_id, status);

-- ---------------------------------------------------------------------------
-- 7. Dedicated Credential Vault (Zero Plaintext Persistence)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    opaque_id VARCHAR(128) NOT NULL,
    name VARCHAR(255) NOT NULL,
    credential_type VARCHAR(64) NOT NULL, -- domain_kerberos, domain_ntlm, local_service, snmp_v3, ssh_key
    domain_or_host VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    encrypted_secret BYTEA NOT NULL, -- AES-256-GCM ciphertext
    nonce BYTEA NOT NULL,           -- 12-byte GCM nonce
    auth_tag BYTEA NOT NULL,        -- 16-byte GCM authentication tag
    salt BYTEA NOT NULL,            -- 16-byte HKDF salt
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_vault_tenant_opaque UNIQUE (tenant_id, opaque_id)
);

CREATE INDEX IF NOT EXISTS idx_vault_tenant ON vault_credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_vault_tenant_opaque ON vault_credentials(tenant_id, opaque_id);

-- ---------------------------------------------------------------------------
-- 8. Scan Jobs (Agentless Subnet Execution Records)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    target_cidr VARCHAR(64) NOT NULL,
    scan_profile VARCHAR(64) NOT NULL,
    protocol VARCHAR(32) NOT NULL DEFAULT 'winrm_https',
    vault_secret_ref VARCHAR(128) NOT NULL,
    gateway_id VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, running, completed, failed
    total_hosts INT NOT NULL DEFAULT 0,
    scanned_hosts INT NOT NULL DEFAULT 0,
    compliant_hosts INT NOT NULL DEFAULT 0,
    failed_hosts INT NOT NULL DEFAULT 0,
    logs JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scan_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_tenant_status ON scan_jobs(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_scans_tenant_created ON scan_jobs(tenant_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 9. Immutable Security Audit Logs (OWASP ASVS Level 2)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    correlation_id VARCHAR(128) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL, -- SUCCESS, FAILURE, DENIED
    ip_address VARCHAR(64) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON security_audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_correlation ON security_audit_logs(tenant_id, correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_timestamp ON security_audit_logs(tenant_id, timestamp DESC);
-- ===========================================================================
-- EndpointGuard Migration: 000002_create_compliance_and_findings_schema.up.sql
-- Host Snapshots, CVE Vulnerabilities, Drift Events, and CIS Frameworks
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. Host Snapshots (Historical & Latest Versioned Audits)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS host_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    snapshot_type VARCHAR(32) NOT NULL DEFAULT 'full', -- full, rapid, delta
    cpu_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    memory_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    storage_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    network_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    bios_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    tpm_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    security_posture JSONB NOT NULL DEFAULT '{}'::jsonb,
    compliance_score NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    is_latest BOOLEAN NOT NULL DEFAULT true,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- 2. Vulnerabilities & Findings (CVEs, Patch Gaps, Misconfigurations)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    cve_id VARCHAR(64) NOT NULL, -- e.g. CVE-2024-21408, CVE-2024-30078
    title VARCHAR(512) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
    cvss_score NUMERIC(3,1) NOT NULL DEFAULT 0.0,
    affected_component VARCHAR(255) NOT NULL, -- e.g. "Hyper-V", "Windows Wi-Fi Driver", "Win32k"
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN', -- OPEN, RESOLVED, IGNORED
    remediation TEXT NOT NULL, -- e.g. "Install KB5037771 or newer cumulative update"
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_vulnerability_host_cve UNIQUE (tenant_id, host_id, cve_id)
);

-- ---------------------------------------------------------------------------
-- 3. Configuration Drift Events (Posture changes against baseline)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS drift_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    drift_category VARCHAR(64) NOT NULL, -- BitLocker, Defender, Firewall, Services, Registry, LocalAdmins
    property_name VARCHAR(255) NOT NULL, -- e.g. "BitLocker.VolumeC.ProtectionStatus", "Defender.RealTimeProtection"
    baseline_value TEXT NOT NULL,
    current_value TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH', -- CRITICAL, HIGH, MEDIUM, LOW
    is_acknowledged BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMPTZ,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- 4. Compliance Frameworks (CIS, NIST, ISO 27001)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(64) UNIQUE NOT NULL, -- e.g. "cis_win11_enterprise", "cis_winserver_2022", "nist_800_53_r5"
    name VARCHAR(255) NOT NULL,
    version VARCHAR(32) NOT NULL,
    target_os VARCHAR(128) NOT NULL, -- "Windows 11", "Windows Server 2022", "Windows Server 2025"
    description TEXT NOT NULL,
    is_builtin BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- 5. Compliance Rules
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    rule_code VARCHAR(64) NOT NULL, -- e.g. "1.1.1", "1.2.1", "2.3.1.5"
    title VARCHAR(512) NOT NULL,
    category VARCHAR(128) NOT NULL, -- Storage & Encryption, Hardware & Firmware, System Defenses, Network Security
    level VARCHAR(32) NOT NULL DEFAULT 'Level 1', -- Level 1, Level 2
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    rationale TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    remediation_script TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_framework_rule_code UNIQUE (framework_id, rule_code)
);

CREATE INDEX IF NOT EXISTS idx_compliance_rules_framework ON compliance_rules(framework_id);

-- ---------------------------------------------------------------------------
-- 6. Compliance Evaluations (Host-level Rule Test Results)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL, -- PASS, FAIL, WARNING, NOT_APPLICABLE
    actual_value TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenant_host_rule_eval UNIQUE (tenant_id, host_id, rule_id)
);
-- ===========================================================================
-- EndpointGuard Migration: 000003_add_rls_and_performance_indexes.up.sql
-- Row-Level Security (RLS) Policies & High-Performance Dashboard Indexes
-- ===========================================================================

-- ===========================================================================
-- ARCHITECTURAL RATIONALE: WHY ROW-LEVEL SECURITY (RLS) AT THE DATABASE LAYER?
-- ===========================================================================
--
-- 1. DEFENSE-IN-DEPTH AGAINST APPLICATION CODE OMISSIONS:
--    In complex microservice and ORM codebases, developers frequently construct
--    intricate JOINs, subqueries, raw SQL queries, and aggregation pipelines.
--    If an application-level filter (e.g., "WHERE tenant_id = ?") is omitted by
--    mistake, or if an IDOR (Insecure Direct Object Reference) / SQL Injection
--    vulnerability exists in an endpoint, database-level RLS acts as an unbypassable
--    safety net that restricts visibility strictly to the authenticated tenant.
--
-- 2. MULTI-SERVICE CONSISTENCY ACROSS DISTRIBUTED DAEMONS:
--    EndpointGuard comprises multiple distributed services: the Go Control Plane
--    API, Subnet Collector Gateways, Scan Dispatcher workers, CIS evaluators,
--    and offline reporting scripts. Enforcing tenant isolation at the database
--    kernel guarantees identical zero-leak security boundaries regardless of
--    which service, runtime (Go, Python, PowerShell), or query tool connects.
--
-- 3. ELIMINATION OF CROSS-TENANT DATA LEAKS IN REPORTING & ANALYTICS:
--    Aggregations (e.g., COUNT(*), AVG(compliance_score)) executed under a tenant
--    session will automatically and deterministically scope their calculations to
--    that tenant without risk of polluting compliance metrics with another tenant's hosts.
--
-- 4. MECHANISM:
--    Application connections execute `SET LOCAL app.current_tenant_id = '<uuid>'`
--    within their transaction context. The database engine transparently injects
--    the tenant constraint into all execution plans.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. Helper Functions for Setting & Reading Current Tenant Context
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_current_tenant(p_tenant_id UUID)
RETURNS void AS $$
BEGIN
    PERFORM set_config('app.current_tenant_id', p_tenant_id::TEXT, true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION get_current_tenant()
RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant_id', true), '')::UUID;
END;
$$ LANGUAGE plpgsql STABLE;

-- ---------------------------------------------------------------------------
-- 2. Enable & Enforce Row-Level Security on All Tenant-Scoped Tables
-- ---------------------------------------------------------------------------

-- Endpoints
ALTER TABLE endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoints FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS endpoints_tenant_isolation ON endpoints;
CREATE POLICY endpoints_tenant_isolation ON endpoints
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Hardware Inventories
ALTER TABLE hardware_inventories ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardware_inventories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS hardware_tenant_isolation ON hardware_inventories;
CREATE POLICY hardware_tenant_isolation ON hardware_inventories
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Security Postures
ALTER TABLE security_postures ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_postures FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS security_tenant_isolation ON security_postures;
CREATE POLICY security_tenant_isolation ON security_postures
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Host Snapshots
ALTER TABLE host_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS host_snapshots_tenant_isolation ON host_snapshots;
CREATE POLICY host_snapshots_tenant_isolation ON host_snapshots
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Vulnerabilities & Findings
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vulnerabilities_tenant_isolation ON vulnerabilities;
CREATE POLICY vulnerabilities_tenant_isolation ON vulnerabilities
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Configuration Drift Events
ALTER TABLE drift_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE drift_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS drift_events_tenant_isolation ON drift_events;
CREATE POLICY drift_events_tenant_isolation ON drift_events
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Compliance Evaluations
ALTER TABLE compliance_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_evaluations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_evaluations_tenant_isolation ON compliance_evaluations;
CREATE POLICY compliance_evaluations_tenant_isolation ON compliance_evaluations
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Subnet Collector Gateways
ALTER TABLE collector_gateways ENABLE ROW LEVEL SECURITY;
ALTER TABLE collector_gateways FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS collector_gateways_tenant_isolation ON collector_gateways;
CREATE POLICY collector_gateways_tenant_isolation ON collector_gateways
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Credential Vault Records
ALTER TABLE vault_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vault_credentials_tenant_isolation ON vault_credentials;
CREATE POLICY vault_credentials_tenant_isolation ON vault_credentials
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Scan Jobs
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_jobs_tenant_isolation ON scan_jobs;
CREATE POLICY scan_jobs_tenant_isolation ON scan_jobs
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Security Audit Logs
ALTER TABLE security_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_audit_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS security_audit_logs_tenant_isolation ON security_audit_logs;
CREATE POLICY security_audit_logs_tenant_isolation ON security_audit_logs
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- Tenant Users
ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_users_tenant_isolation ON tenant_users;
CREATE POLICY tenant_users_tenant_isolation ON tenant_users
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
        OR current_setting('app.bypass_rls', true) = 'on'
    );

-- ---------------------------------------------------------------------------
-- 3. High-Performance Indexes for Common Dashboard Queries
-- ---------------------------------------------------------------------------

-- Index 1: Latest Snapshot per Host (Instantaneous current state lookups)
-- Partial unique index ensures exactly one active latest snapshot per host
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_snapshots_unique_latest 
    ON host_snapshots (host_id) 
    WHERE is_latest = true;

CREATE INDEX IF NOT EXISTS idx_host_snapshots_tenant_latest 
    ON host_snapshots (tenant_id, host_id) 
    WHERE is_latest = true;

CREATE INDEX IF NOT EXISTS idx_host_snapshots_timeline 
    ON host_snapshots (host_id, captured_at DESC);

-- Index 2: Open Critical & High Vulnerabilities per Tenant
-- Filtered index ensures instant retrieval of open security findings without scanning resolved rows
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_tenant_open_critical 
    ON vulnerabilities (tenant_id, severity, cvss_score DESC, discovered_at DESC) 
    WHERE status = 'OPEN';

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_open 
    ON vulnerabilities (host_id, severity) 
    WHERE status = 'OPEN';

-- Index 3: Unacknowledged Configuration Drift Events per Tenant
-- Filtered index isolates active drift alerts for dashboard notification feeds
CREATE INDEX IF NOT EXISTS idx_drift_events_tenant_unacknowledged 
    ON drift_events (tenant_id, severity, detected_at DESC) 
    WHERE is_acknowledged = false;

CREATE INDEX IF NOT EXISTS idx_drift_events_host_unacknowledged 
    ON drift_events (host_id, detected_at DESC) 
    WHERE is_acknowledged = false;

-- Index 4: Compliance Evaluation Rollup Indexes
CREATE INDEX IF NOT EXISTS idx_compliance_eval_tenant_status 
    ON compliance_evaluations (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_compliance_eval_host_status 
    ON compliance_evaluations (host_id, status);

-- Index 5: Active Scan Jobs per Tenant
CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant_active 
    ON scan_jobs (tenant_id, status, created_at DESC) 
    WHERE status IN ('pending', 'running');
-- ===========================================================================
-- EndpointGuard Migration: 000004_create_vulnerability_findings_and_cve_cache.up.sql
-- NVD CVE Cache, CISA KEV Catalog, and Tenant Vulnerability Findings
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. NVD CVE Local Cache
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(512) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    cvss_score NUMERIC(3,1) NOT NULL DEFAULT 0.0,
    cvss_version VARCHAR(16) NOT NULL DEFAULT 'v3.1',
    cvss_vector VARCHAR(128),
    published_at TIMESTAMPTZ,
    last_modified_at TIMESTAMPTZ,
    cpe_matches JSONB NOT NULL DEFAULT '[]'::jsonb,
    references_list JSONB NOT NULL DEFAULT '[]'::jsonb,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cve_cache_severity ON cve_cache(severity);
CREATE INDEX IF NOT EXISTS idx_cve_cache_cvss ON cve_cache(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_cache_modified ON cve_cache(last_modified_at DESC);

-- ---------------------------------------------------------------------------
-- 2. CISA Known Exploited Vulnerabilities (KEV) Local Cache
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cisa_kev_cache (
    cve_id VARCHAR(64) PRIMARY KEY,
    vendor_project VARCHAR(255) NOT NULL,
    product VARCHAR(255) NOT NULL,
    vulnerability_name VARCHAR(512) NOT NULL,
    date_added TIMESTAMPTZ NOT NULL,
    short_description TEXT NOT NULL,
    required_action TEXT NOT NULL,
    due_date TIMESTAMPTZ,
    known_ransomware_campaign_use VARCHAR(64) NOT NULL DEFAULT 'Unknown',
    notes TEXT,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cisa_kev_due_date ON cisa_kev_cache(due_date);
CREATE INDEX IF NOT EXISTS idx_cisa_kev_ransomware ON cisa_kev_cache(known_ransomware_campaign_use);

-- ---------------------------------------------------------------------------
-- 3. Vulnerability Findings (Host-Matched with KEV Priority & Deduplication)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerability_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    cve_id VARCHAR(64) NOT NULL,
    title VARCHAR(512) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    cvss_score NUMERIC(3,1) NOT NULL DEFAULT 0.0,
    cvss_version VARCHAR(16) NOT NULL DEFAULT 'v3.1',
    cvss_vector VARCHAR(128),
    is_kev BOOLEAN NOT NULL DEFAULT false,
    kev_due_date TIMESTAMPTZ,
    kev_ransomware_use VARCHAR(64),
    affected_component VARCHAR(255) NOT NULL,
    cpe_matched VARCHAR(512) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    remediation TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_finding_tenant_endpoint_cve UNIQUE (tenant_id, endpoint_id, cve_id)
);

-- Primary Dashboard Query Index: KEV-first, CVSS desc, last_seen desc per tenant
CREATE INDEX IF NOT EXISTS idx_findings_tenant_kev_cvss ON vulnerability_findings (tenant_id, is_kev DESC, cvss_score DESC, last_seen DESC) WHERE status = 'OPEN';
CREATE INDEX IF NOT EXISTS idx_findings_endpoint_open ON vulnerability_findings (endpoint_id, is_kev DESC, cvss_score DESC) WHERE status = 'OPEN';
CREATE INDEX IF NOT EXISTS idx_findings_cve ON vulnerability_findings (cve_id);
-- ===========================================================================
-- EndpointGuard Migration: 000005_create_alert_rules_and_webhook_deliveries.up.sql
-- Rule-Based Alert Engine, Webhook Subscriptions, and Delivery Auditing
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. Alert Rules Table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity_filter VARCHAR(32) NOT NULL DEFAULT 'CRITICAL',
    asset_class_filter VARCHAR(64),
    category_filter VARCHAR(64),
    channel VARCHAR(32) NOT NULL DEFAULT 'WEBHOOK',
    webhook_url TEXT NOT NULL,
    secret_key VARCHAR(255) NOT NULL,
    suppression_window_hours INT NOT NULL DEFAULT 4,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant_active ON alert_rules(tenant_id) WHERE is_active = true;

-- ---------------------------------------------------------------------------
-- 2. Webhook Delivery Logs Table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webhook_delivery_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    target_url TEXT NOT NULL,
    status_code INT NOT NULL,
    duration_ms BIGINT NOT NULL,
    attempts INT NOT NULL DEFAULT 1,
    status VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
    error_message TEXT,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant ON webhook_delivery_logs(tenant_id, delivered_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_rule ON webhook_delivery_logs(rule_id, delivered_at DESC);
-- Migration: 000006_enforce_audit_log_append_only.up.sql
-- Purpose: Enforce immutable, append-only security audit log at the database engine level (OWASP A09).
-- Prevents UPDATE and DELETE operations on security_audit_logs even if attempted by the application database user.

-- Create a trigger function that raises an exception on any mutation attempt
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY VIOLATION: security_audit_logs is an immutable append-only ledger. Operation % is strictly prohibited.', TG_OP
        USING ERRCODE = '55000'; -- Object Not In Prerequisite State / Custom Error
END;
$$ LANGUAGE plpgsql;

-- Apply trigger before UPDATE or DELETE on security_audit_logs
DROP TRIGGER IF EXISTS trg_prevent_audit_log_mutation ON security_audit_logs;
CREATE TRIGGER trg_prevent_audit_log_mutation
BEFORE UPDATE OR DELETE ON security_audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_mutation();

-- Revoke UPDATE and DELETE permissions from standard public/application roles
REVOKE UPDATE, DELETE, TRUNCATE ON security_audit_logs FROM PUBLIC;
-- Migration: 000007_create_persistent_scan_job_queue.up.sql
-- Purpose: Persistent scan job and per-host task queue with lease expiration to survive process restarts mid-run.

-- Create persistent scan tasks table
CREATE TABLE IF NOT EXISTS scan_job_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id VARCHAR(64) NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL,
    target_ip VARCHAR(45) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, leased, completed, failed
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 2,
    leased_by_worker VARCHAR(128),
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT,
    result_payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Index for high-throughput worker lease polling and task reclamation
CREATE INDEX IF NOT EXISTS idx_scan_job_tasks_pending ON scan_job_tasks(job_id, status) WHERE status IN ('pending', 'leased');
CREATE INDEX IF NOT EXISTS idx_scan_job_tasks_lease_recovery ON scan_job_tasks(status, lease_expires_at) WHERE status = 'leased';
CREATE INDEX IF NOT EXISTS idx_scan_job_tasks_tenant ON scan_job_tasks(tenant_id);

-- Enable Row-Level Security
ALTER TABLE scan_job_tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY scan_job_tasks_tenant_isolation ON scan_job_tasks
    USING (tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
-- ===========================================================================
-- EndpointGuard Migration: 000008_add_rollout_tiers.up.sql
-- Phased Deployment Rollout Tiers (Pilot, Staged, Full Fleet)
-- ===========================================================================

-- 1. Add rollout_tier and organizational unit to endpoints table
ALTER TABLE endpoints 
ADD COLUMN IF NOT EXISTS rollout_tier VARCHAR(32) NOT NULL DEFAULT 'pilot',
ADD COLUMN IF NOT EXISTS organizational_unit VARCHAR(255) DEFAULT 'OU=Workstations,DC=corp,DC=local',
ADD COLUMN IF NOT EXISTS subnet_cidr VARCHAR(64) DEFAULT '10.100.1.0/24',
ADD COLUMN IF NOT EXISTS tier_promoted_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS tier_promoted_by VARCHAR(255),
ADD COLUMN IF NOT EXISTS tier_promotion_reason TEXT;

-- 2. Enforce valid rollout tiers via check constraint
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_endpoints_rollout_tier'
    ) THEN
        ALTER TABLE endpoints
        ADD CONSTRAINT chk_endpoints_rollout_tier
        CHECK (rollout_tier IN ('pilot', 'staged', 'full'));
    END IF;
END $$;

-- 3. Add performance indexes for rollout tier filtering
CREATE INDEX IF NOT EXISTS idx_endpoints_rollout_tier ON endpoints(tenant_id, rollout_tier);
CREATE INDEX IF NOT EXISTS idx_endpoints_ou ON endpoints(tenant_id, organizational_unit);
CREATE INDEX IF NOT EXISTS idx_endpoints_subnet ON endpoints(tenant_id, subnet_cidr);

-- 4. Add active_rollout_tiers configuration to tenants
ALTER TABLE tenants
ADD COLUMN IF NOT EXISTS active_rollout_tiers JSONB NOT NULL DEFAULT '["pilot"]'::jsonb;
-- ===========================================================================
-- EndpointGuard Migration: 000009_snapshot_retention_and_archival.up.sql
-- Snapshot Retention Policies, Archival Metadata, and Downsampling
-- ===========================================================================

-- 1. Add archival and retention tracking columns to host_snapshots
ALTER TABLE host_snapshots
    ADD COLUMN IF NOT EXISTS is_archived BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS archive_location TEXT,
    ADD COLUMN IF NOT EXISTS archive_checksum VARCHAR(64),
    ADD COLUMN IF NOT EXISTS archive_strategy VARCHAR(32) DEFAULT 'cold_storage',
    ADD COLUMN IF NOT EXISTS is_downsample_retained BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS payload_size_bytes BIGINT NOT NULL DEFAULT 0;

-- 2. Add performance index for retention window pruning and historical timeline queries
CREATE INDEX IF NOT EXISTS idx_host_snapshots_retention 
    ON host_snapshots (tenant_id, is_archived, captured_at);

CREATE INDEX IF NOT EXISTS idx_host_snapshots_archival_status
    ON host_snapshots (is_archived, captured_at);

-- 3. Create snapshot_retention_policies table
CREATE TABLE IF NOT EXISTS snapshot_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    retention_days INT NOT NULL DEFAULT 90,
    strategy VARCHAR(32) NOT NULL DEFAULT 'archive',
    cold_storage_path TEXT NOT NULL DEFAULT 'D:\archives\snapshots',
    keep_weekly_interval_days INT NOT NULL DEFAULT 7,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(32),
    last_reclaimed_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_retention_strategy CHECK (strategy IN ('archive', 'downsample')),
    CONSTRAINT chk_retention_days_positive CHECK (retention_days >= 7),
    CONSTRAINT uq_retention_policy_tenant UNIQUE (tenant_id)
);

-- Enable RLS on snapshot_retention_policies
ALTER TABLE snapshot_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE snapshot_retention_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS retention_policies_tenant_isolation ON snapshot_retention_policies;
CREATE POLICY retention_policies_tenant_isolation ON snapshot_retention_policies
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);
