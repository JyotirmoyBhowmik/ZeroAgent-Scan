-- ===========================================================================
-- EndpointGuard Migration: 000008_add_rollout_tiers.up.sql
-- Phased Deployment Rollout Tiers (Pilot, Staged, Full Fleet)
-- ===========================================================================

-- 1. Add rollout_tier and organizational unit to endpoints table
ALTER TABLE endpoints 
ADD COLUMN IF NOT EXISTS rollout_tier VARCHAR(32) NOT NULL DEFAULT 'pilot',
ADD COLUMN IF NOT EXISTS organizational_unit VARCHAR(255) DEFAULT 'OU=Workstations,DC=corp,DC=local',
ADD COLUMN IF NOT EXISTS subnet_cidr VARCHAR(64) DEFAULT '10.100.1.0/24',
ADD COLUMN IF NOT EXISTS tier_promoted_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS tier_promoted_by VARCHAR(255),
ADD COLUMN IF NOT EXISTS tier_promotion_reason TEXT;

-- 2. Enforce valid rollout tiers via check constraint
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_endpoints_rollout_tier'
    ) THEN
        ALTER TABLE endpoints
        ADD CONSTRAINT chk_endpoints_rollout_tier
        CHECK (rollout_tier IN ('pilot', 'staged', 'full'));
    END IF;
END $$;

-- 3. Add performance indexes for rollout tier filtering
CREATE INDEX IF NOT EXISTS idx_endpoints_rollout_tier ON endpoints(tenant_id, rollout_tier);
CREATE INDEX IF NOT EXISTS idx_endpoints_ou ON endpoints(tenant_id, organizational_unit);
CREATE INDEX IF NOT EXISTS idx_endpoints_subnet ON endpoints(tenant_id, subnet_cidr);

-- 4. Add active_rollout_tiers configuration to tenants
ALTER TABLE tenants
ADD COLUMN IF NOT EXISTS active_rollout_tiers JSONB NOT NULL DEFAULT '["pilot"]'::jsonb;
