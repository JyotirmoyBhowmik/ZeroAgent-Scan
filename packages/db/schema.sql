-- Copy of active schema for sqlc code generation
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
