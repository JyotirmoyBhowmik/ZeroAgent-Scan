-- ===========================================================================
-- EndpointGuard Migration: 000009_snapshot_retention_and_archival.up.sql
-- Snapshot Retention Policies, Archival Metadata, and Downsampling
-- ===========================================================================

-- 1. Add archival and retention tracking columns to host_snapshots
ALTER TABLE host_snapshots
    ADD COLUMN IF NOT EXISTS is_archived BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS archive_location TEXT,
    ADD COLUMN IF NOT EXISTS archive_checksum VARCHAR(64),
    ADD COLUMN IF NOT EXISTS archive_strategy VARCHAR(32) DEFAULT 'cold_storage',
    ADD COLUMN IF NOT EXISTS is_downsample_retained BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS payload_size_bytes BIGINT NOT NULL DEFAULT 0;

-- 2. Add performance index for retention window pruning and historical timeline queries
CREATE INDEX IF NOT EXISTS idx_host_snapshots_retention 
    ON host_snapshots (tenant_id, is_archived, captured_at);

CREATE INDEX IF NOT EXISTS idx_host_snapshots_archival_status
    ON host_snapshots (is_archived, captured_at);

-- 3. Create snapshot_retention_policies table
CREATE TABLE IF NOT EXISTS snapshot_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    retention_days INT NOT NULL DEFAULT 90,
    strategy VARCHAR(32) NOT NULL DEFAULT 'archive',
    cold_storage_path TEXT NOT NULL DEFAULT 'D:\archives\snapshots',
    keep_weekly_interval_days INT NOT NULL DEFAULT 7,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(32),
    last_reclaimed_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_retention_strategy CHECK (strategy IN ('archive', 'downsample')),
    CONSTRAINT chk_retention_days_positive CHECK (retention_days >= 7),
    CONSTRAINT uq_retention_policy_tenant UNIQUE (tenant_id)
);

-- Enable RLS on snapshot_retention_policies
ALTER TABLE snapshot_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE snapshot_retention_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS retention_policies_tenant_isolation ON snapshot_retention_policies;
CREATE POLICY retention_policies_tenant_isolation ON snapshot_retention_policies
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);
