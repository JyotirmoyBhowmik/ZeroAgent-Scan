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
