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
