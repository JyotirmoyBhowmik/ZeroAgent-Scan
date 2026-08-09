-- ===========================================================================
-- EndpointGuard Migration: 000002_create_compliance_and_findings_schema.down.sql
-- Rollback for Compliance & Findings Schema
-- ===========================================================================

DROP TABLE IF EXISTS compliance_evaluations CASCADE;
DROP TABLE IF EXISTS compliance_rules CASCADE;
DROP TABLE IF EXISTS compliance_frameworks CASCADE;
DROP TABLE IF EXISTS drift_events CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS host_snapshots CASCADE;
