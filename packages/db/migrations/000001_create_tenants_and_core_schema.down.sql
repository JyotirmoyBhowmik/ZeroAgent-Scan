-- ===========================================================================
-- EndpointGuard Migration: 000001_create_tenants_and_core_schema.down.sql
-- Rollback for Core Schema
-- ===========================================================================

DROP TABLE IF EXISTS security_audit_logs CASCADE;
DROP TABLE IF EXISTS scan_jobs CASCADE;
DROP TABLE IF EXISTS vault_credentials CASCADE;
DROP TABLE IF EXISTS collector_gateways CASCADE;
DROP TABLE IF EXISTS security_postures CASCADE;
DROP TABLE IF EXISTS hardware_inventories CASCADE;
DROP TABLE IF EXISTS endpoints CASCADE;
DROP TABLE IF EXISTS tenant_users CASCADE;
DROP TABLE IF EXISTS tenants CASCADE;
