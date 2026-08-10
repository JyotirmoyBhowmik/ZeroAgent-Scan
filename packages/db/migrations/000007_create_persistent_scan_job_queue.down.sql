-- Migration: 000007_create_persistent_scan_job_queue.down.sql
-- Rollback persistent scan job tasks table.

DROP TABLE IF EXISTS scan_job_tasks CASCADE;
