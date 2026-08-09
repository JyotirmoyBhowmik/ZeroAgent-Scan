-- ===========================================================================
-- EndpointGuard Migration: 000005_create_alert_rules_and_webhook_deliveries.down.sql
-- ===========================================================================

DROP TABLE IF EXISTS webhook_delivery_logs CASCADE;
DROP TABLE IF EXISTS alert_rules CASCADE;
