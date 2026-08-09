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
