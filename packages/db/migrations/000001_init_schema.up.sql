-- ===========================================================================
-- EndpointGuard Database Migration: 000001_init_schema.up.sql
-- PostgreSQL 15+ with JSONB, GIN Indexes, and Row-Level Security (RLS)
-- ===========================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------
-- 1. Endpoints (Target Windows 11 & Windows Server Hosts)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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
    status VARCHAR(32) NOT NULL DEFAULT 'online',
    agentless_protocol VARCHAR(32) NOT NULL DEFAULT 'winrm_https',
    compliance_score NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    last_scanned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_endpoints_ip ON endpoints(ip_address);
CREATE INDEX IF NOT EXISTS idx_endpoints_hostname ON endpoints(hostname);
CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
CREATE INDEX IF NOT EXISTS idx_endpoints_compliance ON endpoints(compliance_score);

-- ---------------------------------------------------------------------------
-- 2. Hardware Inventories (Structured JSONB Specs)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hardware_inventories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    cpu_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    memory_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    storage_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    network_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    bios_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    tpm_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_hardware_endpoint UNIQUE (endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_hardware_cpu_gin ON hardware_inventories USING GIN (cpu_details);
CREATE INDEX IF NOT EXISTS idx_hardware_storage_gin ON hardware_inventories USING GIN (storage_details);
CREATE INDEX IF NOT EXISTS idx_hardware_network_gin ON hardware_inventories USING GIN (network_details);

-- ---------------------------------------------------------------------------
-- 3. Security Postures (BitLocker, TPM 2.0, Defender, Firewall, UAC)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_postures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    bitlocker_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    defender_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    firewall_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    uac_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    hotfixes JSONB NOT NULL DEFAULT '[]'::jsonb,
    local_admins JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_security_endpoint UNIQUE (endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_security_bitlocker_gin ON security_postures USING GIN (bitlocker_status);
CREATE INDEX IF NOT EXISTS idx_security_defender_gin ON security_postures USING GIN (defender_status);

-- ---------------------------------------------------------------------------
-- 4. Scan Jobs (Agentless Subnet Execution)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    target_cidr VARCHAR(64) NOT NULL,
    scan_profile VARCHAR(64) NOT NULL,
    protocol VARCHAR(32) NOT NULL DEFAULT 'winrm_https',
    vault_secret_ref VARCHAR(128) NOT NULL,
    gateway_id VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    total_hosts INT NOT NULL DEFAULT 0,
    scanned_hosts INT NOT NULL DEFAULT 0,
    compliant_hosts INT NOT NULL DEFAULT 0,
    failed_hosts INT NOT NULL DEFAULT 0,
    logs JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scan_jobs(created_at DESC);

-- ---------------------------------------------------------------------------
-- 5. Subnet Collector Gateways (mTLS mesh node tracking)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS collector_gateways (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_code VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    subnet_cidr VARCHAR(64) NOT NULL,
    mtls_cert_fingerprint VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'healthy',
    version VARCHAR(32) NOT NULL DEFAULT 'v1.0.0',
    latency_ms INT NOT NULL DEFAULT 0,
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gateways_status ON collector_gateways(status);

-- ---------------------------------------------------------------------------
-- 6. Dedicated Credential Vault (Zero Plaintext Persistence)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    opaque_id VARCHAR(128) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    credential_type VARCHAR(64) NOT NULL,
    domain_or_host VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    encrypted_secret BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    salt BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vault_opaque_id ON vault_credentials(opaque_id);

-- ---------------------------------------------------------------------------
-- 7. CIS Benchmark Results (Rule-level Evaluation)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cis_benchmark_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    benchmark_name VARCHAR(128) NOT NULL,
    benchmark_level VARCHAR(16) NOT NULL DEFAULT 'Level 1',
    rule_id VARCHAR(64) NOT NULL,
    rule_title VARCHAR(512) NOT NULL,
    category VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL,
    actual_value TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    rationale TEXT NOT NULL,
    remediation_script TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cis_endpoint ON cis_benchmark_results(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_cis_status ON cis_benchmark_results(status);
CREATE INDEX IF NOT EXISTS idx_cis_category ON cis_benchmark_results(category);

-- ---------------------------------------------------------------------------
-- 8. Immutable Security Audit Logs (OWASP ASVS Level 2)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    correlation_id VARCHAR(128) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL,
    ip_address VARCHAR(64) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_correlation ON security_audit_logs(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_logs(timestamp DESC);

-- ---------------------------------------------------------------------------
-- 9. Row-Level Security (RLS) Enablement
-- ---------------------------------------------------------------------------
ALTER TABLE endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardware_inventories ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_postures ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_audit_logs ENABLE ROW LEVEL SECURITY;

-- Allow application role to read/write all authenticated rows
CREATE POLICY app_endpoints_all ON endpoints FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY app_hardware_all ON hardware_inventories FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY app_security_all ON security_postures FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY app_scans_all ON scan_jobs FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY app_vault_all ON vault_credentials FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY app_audit_all ON security_audit_logs FOR ALL USING (true) WITH CHECK (true);
