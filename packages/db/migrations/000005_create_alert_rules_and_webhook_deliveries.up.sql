-- ===========================================================================
-- EndpointGuard Migration: 000005_create_alert_rules_and_webhook_deliveries.up.sql
-- Rule-Based Alert Engine, Webhook Subscriptions, and Delivery Auditing
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. Alert Rules Table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity_filter VARCHAR(32) NOT NULL DEFAULT 'CRITICAL',
    asset_class_filter VARCHAR(64),
    category_filter VARCHAR(64),
    channel VARCHAR(32) NOT NULL DEFAULT 'WEBHOOK',
    webhook_url TEXT NOT NULL,
    secret_key VARCHAR(255) NOT NULL,
    suppression_window_hours INT NOT NULL DEFAULT 4,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant_active ON alert_rules(tenant_id) WHERE is_active = true;

-- ---------------------------------------------------------------------------
-- 2. Webhook Delivery Logs Table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webhook_delivery_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    target_url TEXT NOT NULL,
    status_code INT NOT NULL,
    duration_ms BIGINT NOT NULL,
    attempts INT NOT NULL DEFAULT 1,
    status VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
    error_message TEXT,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant ON webhook_delivery_logs(tenant_id, delivered_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_rule ON webhook_delivery_logs(rule_id, delivered_at DESC);
