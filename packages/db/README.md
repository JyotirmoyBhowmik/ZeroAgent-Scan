# EndpointGuard Database Package (`/packages/db`)

PostgreSQL 15+ schema migrations, Row-Level Security (RLS) policies, high-performance dashboard indexes, and local development seed data.

---

## 🏗️ Architecture Overview

- **Multi-Tenant Row-Level Security (RLS)**: Enforced at the PostgreSQL kernel level across all 11 tenant-scoped tables (`endpoints`, `hardware_inventories`, `security_postures`, `host_snapshots`, `vulnerabilities`, `drift_events`, `compliance_evaluations`, `collector_gateways`, `vault_credentials`, `scan_jobs`, `security_audit_logs`, and `tenant_users`).
- **Zero-Plaintext Vault**: Dedicated `vault_credentials` table storing AES-256-GCM ciphertexts, GCM nonces, authentication tags, and HKDF salts.
- **Hardware & Security State**: Structured JSONB columns indexed with GIN for fast sub-property queries (`cpu_details`, `storage_details`, `bitlocker_status`, `defender_status`).
- **Compliance & Findings**: CIS Benchmark framework rules, individual host evaluations, CVE vulnerability tracking, and unacknowledged configuration drift tracking.

---

## 🔒 Why Row-Level Security (RLS) is Applied at the DB Layer

1. **Defense-in-Depth Against Application Code Omissions**:
   If an application-level filter (e.g. `WHERE tenant_id = ?`) is accidentally omitted in a complex ORM query, raw SQL query, or aggregation pipeline, the database engine guarantees that records belonging to another tenant can **never** be selected, updated, or deleted.
2. **Cross-Service Uniformity**:
   EndpointGuard consists of multiple distributed components (Go API, Go On-Prem Gateway daemons, background scan workers, Python CIS evaluators, reporting scripts). Kernel-level RLS guarantees uniform tenant isolation regardless of which service or language connects to the database.
3. **Session-Variable Mechanism**:
   Connections set the tenant context at the transaction boundary:
   ```sql
   SET LOCAL app.current_tenant_id = 'a0000000-0000-0000-0000-000000000001';
   ```

---

## ⚡ Key Dashboard Performance Indexes

1. **Latest Snapshot per Host** (Instantaneous single-lookup of active inventory):
   ```sql
   CREATE UNIQUE INDEX idx_host_snapshots_unique_latest ON host_snapshots (host_id) WHERE is_latest = true;
   ```
2. **Open Critical Vulnerabilities per Tenant** (Filtered index avoiding resolved historical rows):
   ```sql
   CREATE INDEX idx_vulnerabilities_tenant_open_critical ON vulnerabilities (tenant_id, severity, cvss_score DESC, discovered_at DESC) WHERE status = 'OPEN';
   ```
3. **Unacknowledged Drift Events per Tenant** (High-priority alert feeds):
   ```sql
   CREATE INDEX idx_drift_events_tenant_unacknowledged ON drift_events (tenant_id, severity, detected_at DESC) WHERE is_acknowledged = false;
   ```

---

## 🚀 Migration & Seeding Commands

### 1. Apply Migrations Up
```bash
# Using golang-migrate CLI
migrate -path ./migrations -database "postgres://postgres:postgres@localhost:5432/endpointguard?sslmode=disable" up

# Or via Docker
docker run -v $(pwd)/migrations:/migrations --network host migrate/migrate -path=/migrations/ -database "postgres://postgres:postgres@localhost:5432/endpointguard?sslmode=disable" up
```

### 2. Rollback Migrations Down
```bash
migrate -path ./migrations -database "postgres://postgres:postgres@localhost:5432/endpointguard?sslmode=disable" down
```

### 3. Load Local Dev Seed Data
```bash
psql "postgres://postgres:postgres@localhost:5432/endpointguard?sslmode=disable" -f ./seeds/01_local_dev_seed.sql
```
This seeds:
- **3 Organizations**: Acme Financial Services, BioHealth Therapeutics, Apex Cyber Defense Labs.
- **20 Realistic Windows Hosts**: Domain Controllers, SQL Clusters, Hyper-V nodes, Laptops, Trading Workstations.
- **CIS Benchmarks & Rules**: Windows 11 Enterprise v3.0.0, Windows Server 2022 v2.0.0 with PowerShell remediations.
- **Findings**: Open Critical CVEs, unacknowledged configuration drift events, and audit logs.
