-- Migration: 000006_enforce_audit_log_append_only.up.sql
-- Purpose: Enforce immutable, append-only security audit log at the database engine level (OWASP A09).
-- Prevents UPDATE and DELETE operations on security_audit_logs even if attempted by the application database user.

-- Create a trigger function that raises an exception on any mutation attempt
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY VIOLATION: security_audit_logs is an immutable append-only ledger. Operation % is strictly prohibited.', TG_OP
        USING ERRCODE = '55000'; -- Object Not In Prerequisite State / Custom Error
END;
$$ LANGUAGE plpgsql;

-- Apply trigger before UPDATE or DELETE on security_audit_logs
DROP TRIGGER IF EXISTS trg_prevent_audit_log_mutation ON security_audit_logs;
CREATE TRIGGER trg_prevent_audit_log_mutation
BEFORE UPDATE OR DELETE ON security_audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_mutation();

-- Revoke UPDATE and DELETE permissions from standard public/application roles
REVOKE UPDATE, DELETE, TRUNCATE ON security_audit_logs FROM PUBLIC;
