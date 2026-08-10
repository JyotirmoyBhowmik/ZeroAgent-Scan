-- ===========================================================================
-- EndpointGuard Migration: 000008_add_rollout_tiers.down.sql
-- Rollback Rollout Tiers
-- ===========================================================================

DROP INDEX IF EXISTS idx_endpoints_subnet;
DROP INDEX IF EXISTS idx_endpoints_ou;
DROP INDEX IF EXISTS idx_endpoints_rollout_tier;

ALTER TABLE endpoints 
DROP CONSTRAINT IF EXISTS chk_endpoints_rollout_tier,
DROP COLUMN IF EXISTS tier_promotion_reason,
DROP COLUMN IF EXISTS tier_promoted_by,
DROP COLUMN IF EXISTS tier_promoted_at,
DROP COLUMN IF EXISTS subnet_cidr,
DROP COLUMN IF EXISTS organizational_unit,
DROP COLUMN IF EXISTS rollout_tier;

ALTER TABLE tenants
DROP COLUMN IF EXISTS active_rollout_tiers;
