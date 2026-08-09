-- name: ListEndpoints :many
SELECT * FROM endpoints ORDER BY hostname ASC LIMIT $1 OFFSET $2;

-- name: GetEndpointByID :one
SELECT * FROM endpoints WHERE id = $1 LIMIT 1;

-- name: GetHardwareByEndpointID :one
SELECT * FROM hardware_inventories WHERE endpoint_id = $1 LIMIT 1;

-- name: GetSecurityPostureByEndpointID :one
SELECT * FROM security_postures WHERE endpoint_id = $1 LIMIT 1;

-- name: ListScanJobs :many
SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT $1 OFFSET $2;

-- name: GetScanJobByID :one
SELECT * FROM scan_jobs WHERE id = $1 LIMIT 1;

-- name: CreateScanJob :one
INSERT INTO scan_jobs (
    name, target_cidr, scan_profile, protocol, vault_secret_ref, gateway_id, status, total_hosts
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListCollectorGateways :many
SELECT * FROM collector_gateways ORDER BY gateway_code ASC;

-- name: GetVaultCredentialByOpaqueID :one
SELECT * FROM vault_credentials WHERE opaque_id = $1 LIMIT 1;

-- name: ListVaultCredentialsSummary :many
SELECT id, opaque_id, name, credential_type, domain_or_host, username, created_at, updated_at
FROM vault_credentials ORDER BY name ASC;

-- name: ListCISResultsByEndpointID :many
SELECT * FROM cis_benchmark_results WHERE endpoint_id = $1 ORDER BY rule_id ASC;

-- name: InsertSecurityAuditLog :one
INSERT INTO security_audit_logs (
    correlation_id, actor, action, resource_type, resource_id, status, ip_address, details
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;
