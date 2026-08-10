-- Migration: 000007_create_persistent_scan_job_queue.up.sql
-- Purpose: Persistent scan job and per-host task queue with lease expiration to survive process restarts mid-run.

-- Create persistent scan tasks table
CREATE TABLE IF NOT EXISTS scan_job_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id VARCHAR(64) NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL,
    target_ip VARCHAR(45) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, leased, completed, failed
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 2,
    leased_by_worker VARCHAR(128),
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT,
    result_payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Index for high-throughput worker lease polling and task reclamation
CREATE INDEX IF NOT EXISTS idx_scan_job_tasks_pending ON scan_job_tasks(job_id, status) WHERE status IN ('pending', 'leased');
CREATE INDEX IF NOT EXISTS idx_scan_job_tasks_lease_recovery ON scan_job_tasks(status, lease_expires_at) WHERE status = 'leased';
CREATE INDEX IF NOT EXISTS idx_scan_job_tasks_tenant ON scan_job_tasks(tenant_id);

-- Enable Row-Level Security
ALTER TABLE scan_job_tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY scan_job_tasks_tenant_isolation ON scan_job_tasks
    USING (tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
