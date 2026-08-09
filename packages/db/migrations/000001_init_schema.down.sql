-- ===========================================================================
-- EndpointGuard Database Migration: 000001_init_schema.down.sql
-- ===========================================================================

DROP TABLE IF EXISTS security_audit_logs CASCADE;
DROP TABLE IF EXISTS cis_benchmark_results CASCADE;
DROP TABLE IF EXISTS vault_credentials CASCADE;
DROP TABLE IF EXISTS collector_gateways CASCADE;
DROP TABLE IF EXISTS scan_jobs CASCADE;
DROP TABLE IF EXISTS security_postures CASCADE;
DROP TABLE IF EXISTS hardware_inventories CASCADE;
DROP TABLE IF EXISTS endpoints CASCADE;
