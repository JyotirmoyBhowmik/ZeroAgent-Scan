# EndpointGuard Disaster Recovery & Credential Vault Runbook

> **Critical Standard Operating Procedure (SOP) for PostgreSQL Backup, Point-In-Time-Recovery (PITR), and Emergency Credential Vault Key Reconstruction.**

---

## 🎯 Recovery Objectives (SLA / SLO)

- **Recovery Point Objective (RPO)**: `< 5 minutes` (continuous WAL streaming + encrypted S3/GCS/Azure Blob archive).
- **Recovery Time Objective (RTO)**: `< 30 minutes` for complete database and control plane reconstruction.

---

## 🗄️ 1. PostgreSQL Backup Architecture

```
   [ Active PostgreSQL Primary ]
         │
         ├──► 1. Nightly Base Backup (02:00 UTC) ──► Encrypted Custom Format (`.dump.gpg`)
         │                                            └──► S3 / Blob Storage (30-day retention)
         │
         └──► 2. Continuous WAL Archiving ─────────► WAL-G / pgBackRest
                                                      └──► 5-minute RPO window
```

### A. Automated Nightly Logical Backup Script
```bash
#!/usr/bin/env bash
# /opt/endpointguard/scripts/backup_postgres.sh
set -euo pipefail

BACKUP_DIR="/var/backups/endpointguard"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
BACKUP_FILE="${BACKUP_DIR}/endpointguard_${TIMESTAMP}.dump"
GPG_RECIPIENT="secops-dr@endpointguard.corp"

mkdir -p "${BACKUP_DIR}"

echo "Starting PostgreSQL backup: ${BACKUP_FILE}"
PGPASSWORD="${DB_PASSWORD}" pg_dump \
  -h "${DB_HOST}" \
  -p "${DB_PORT}" \
  -U "${DB_USER}" \
  -d "${DB_NAME}" \
  -F c \
  -b \
  -v \
  -f "${BACKUP_FILE}"

# Encrypt backup with DR GPG Key
gpg --encrypt --recipient "${GPG_RECIPIENT}" --output "${BACKUP_FILE}.gpg" "${BACKUP_FILE}"
rm -f "${BACKUP_FILE}"

# Ship to immutable cloud object storage
aws s3 cp "${BACKUP_FILE}.gpg" "s3://endpointguard-backups-dr/postgres/${TIMESTAMP}.dump.gpg" \
  --sse aws:kms \
  --sse-kms-key-id "alias/endpointguard-backup-key"

echo "Backup and cloud replication complete: ${BACKUP_FILE}.gpg"
```

---

## 🔄 2. PostgreSQL Full Disaster Recovery Procedure

### Scenario: Primary Database Catastrophic Loss
Follow these steps to restore the database cluster from the encrypted cloud backup:

#### Step 1: Provision Clean PostgreSQL 15+ Target Cluster
Ensure the target database has the required extensions (`uuid-ossp`, `pgcrypto`).

#### Step 2: Download and Decrypt Latest Base Backup
```bash
# 1. Download latest dump from S3
aws s3 cp s3://endpointguard-backups-dr/postgres/latest.dump.gpg ./latest.dump.gpg

# 2. Decrypt using SecOps DR Private Key
gpg --decrypt --output ./latest.dump ./latest.dump.gpg
```

#### Step 3: Execute Schema & Data Restore
```bash
# Create fresh database
PGPASSWORD="${DB_PASSWORD}" createdb -h "${NEW_DB_HOST}" -U "${DB_USER}" endpointguard

# Restore schema and data with clean exit verification
PGPASSWORD="${DB_PASSWORD}" pg_restore \
  -h "${NEW_DB_HOST}" \
  -p "${DB_PORT}" \
  -U "${DB_USER}" \
  -d endpointguard \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  -v ./latest.dump

# Re-apply engine-level append-only audit log rules
psql -h "${NEW_DB_HOST}" -U "${DB_USER}" -d endpointguard \
  -f packages/db/migrations/000006_enforce_audit_log_append_only.up.sql
```

#### Step 4: Verify Database Data Integrity
```bash
psql -h "${NEW_DB_HOST}" -U "${DB_USER}" -d endpointguard -c "
  SELECT 
    (SELECT count(*) FROM endpoints) AS total_endpoints,
    (SELECT count(*) FROM host_snapshots) AS total_snapshots,
    (SELECT count(*) FROM security_audit_logs) AS audit_logs_count,
    (SELECT count(*) FROM vault_credentials) AS vault_credentials_count;
"
```

---

## 🔐 3. Credential Vault Disaster Recovery & Key Reconstruction

Because target credentials are encrypted using **Envelope AES-256-GCM**, recovering the database without the master cryptographic key will result in ciphertext that cannot be decrypted by scan workers.

```
   [ Disaster Recovery Vault Protocol ]
   
   KMS / Master Key Compromised / Destroyed
             │
             ├──► 1. Retrieve Shamir's Secret Sharing (3-of-5 M-of-N Key Shards)
             │
             ├──► 2. Reconstruct Master Key in Ephemeral Air-Gapped Session
             │
             ├──► 3. Decrypt existing credentials using reconstructed key
             │
             └──► 4. Re-encrypt all records with New KMS Master Key (Atomic Re-wrap)
```

### Emergency Master Key Re-wrapping Tool

If the master key is rotated or recovered during DR, run the internal re-wrapping utility:

```bash
cd apps/api
go run cmd/vault-rewrap/main.go \
  --old-master-key "${RECONSTRUCTED_OLD_KEY_HEX}" \
  --new-master-key "${NEW_KMS_MASTER_KEY_HEX}" \
  --db-url "${DATABASE_URL}"
```

### Verification Checklist Post-Recovery
- [ ] Verify `api.endpointguard.corp/api/v1/health` returns `{"status":"healthy"}`.
- [ ] Execute test credential resolution for a non-production test endpoint.
- [ ] Confirm no secrets or keys appear in stdout / log streams.
- [ ] Verify collector gateways successfully establish bidirectional mTLS 1.3 tunnels.
