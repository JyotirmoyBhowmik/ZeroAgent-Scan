-- ===========================================================================
-- EndpointGuard Migration: 000003_add_rls_and_performance_indexes.down.sql
-- Rollback for RLS Policies and Performance Indexes
-- ===========================================================================

-- Drop Performance Indexes
DROP INDEX IF EXISTS idx_scan_jobs_tenant_active;
DROP INDEX IF EXISTS idx_compliance_eval_host_status;
DROP INDEX IF EXISTS idx_compliance_eval_tenant_status;
DROP INDEX IF EXISTS idx_drift_events_host_unacknowledged;
DROP INDEX IF EXISTS idx_drift_events_tenant_unacknowledged;
DROP INDEX IF EXISTS idx_vulnerabilities_host_open;
DROP INDEX IF EXISTS idx_vulnerabilities_tenant_open_critical;
DROP INDEX IF EXISTS idx_host_snapshots_timeline;
DROP INDEX IF EXISTS idx_host_snapshots_tenant_latest;
DROP INDEX IF EXISTS idx_host_snapshots_unique_latest;

-- Drop RLS Policies & Disable RLS
DROP POLICY IF EXISTS tenant_users_tenant_isolation ON tenant_users;
ALTER TABLE tenant_users DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS security_audit_logs_tenant_isolation ON security_audit_logs;
ALTER TABLE security_audit_logs DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scan_jobs_tenant_isolation ON scan_jobs;
ALTER TABLE scan_jobs DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS vault_credentials_tenant_isolation ON vault_credentials;
ALTER TABLE vault_credentials DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS collector_gateways_tenant_isolation ON collector_gateways;
ALTER TABLE collector_gateways DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS compliance_evaluations_tenant_isolation ON compliance_evaluations;
ALTER TABLE compliance_evaluations DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS drift_events_tenant_isolation ON drift_events;
ALTER TABLE drift_events DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS vulnerabilities_tenant_isolation ON vulnerabilities;
ALTER TABLE vulnerabilities DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS host_snapshots_tenant_isolation ON host_snapshots;
ALTER TABLE host_snapshots DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS security_tenant_isolation ON security_postures;
ALTER TABLE security_postures DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS hardware_tenant_isolation ON hardware_inventories;
ALTER TABLE hardware_inventories DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS endpoints_tenant_isolation ON endpoints;
ALTER TABLE endpoints DISABLE ROW LEVEL SECURITY;

-- Drop Helper Functions
DROP FUNCTION IF EXISTS get_current_tenant();
DROP FUNCTION IF EXISTS set_current_tenant(UUID);
