-- ===========================================================================
-- EndpointGuard Rollback: 000009_snapshot_retention_and_archival.down.sql
-- ===========================================================================

DROP POLICY IF EXISTS retention_policies_tenant_isolation ON snapshot_retention_policies;
ALTER TABLE snapshot_retention_policies DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS snapshot_retention_policies CASCADE;

DROP INDEX IF EXISTS idx_host_snapshots_archival_status;
DROP INDEX IF EXISTS idx_host_snapshots_retention;

ALTER TABLE host_snapshots
    DROP COLUMN IF EXISTS is_archived,
    DROP COLUMN IF EXISTS archived_at,
    DROP COLUMN IF EXISTS archive_location,
    DROP COLUMN IF EXISTS archive_checksum,
    DROP COLUMN IF EXISTS archive_strategy,
    DROP COLUMN IF EXISTS is_downsample_retained,
    DROP COLUMN IF EXISTS payload_size_bytes;
