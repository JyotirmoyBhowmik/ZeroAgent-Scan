-- Migration: 000006_enforce_audit_log_append_only.down.sql
-- Rollback immutable append-only trigger on security_audit_logs.

DROP TRIGGER IF EXISTS trg_prevent_audit_log_mutation ON security_audit_logs;
DROP FUNCTION IF EXISTS prevent_audit_log_mutation();
