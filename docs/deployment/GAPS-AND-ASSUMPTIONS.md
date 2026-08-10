# Gaps and Assumptions — Production Deployment Audit

> **Purpose**: This document lists every unresolved gap, silent assumption, and
> open question discovered while preparing the canonical deployment package.
> Each item is a conscious decision for the deployment owner — none have been
> silently patched. Review each one and either accept the risk, schedule the
> fix, or block the deployment.
>
> **Generated**: August 2026  
> **Scope**: ZeroAgent-Scan EMS v1.2.0 on Windows Server 2019

---

## Version Staleness Notice

| Component | Pinned Version | EOL Date | WS2019 Extended Support Ends |
|-----------|---------------|----------|------------------------------|
| Node.js | 26.x LTS | April 30, 2029 | January 9, 2029 |
| PostgreSQL | 17.x | November 2029 | January 9, 2029 |

**If you are reading this after October 2027**, re-check these versions
against the current Node.js release schedule (https://nodejs.org/en/about/releases/)
and PostgreSQL versioning policy (https://www.postgresql.org/support/versioning/).
Newer LTS lines may offer better runway.

---

## Category 1: SSL/TLS Certificate Lifecycle

### GAP-01: No Certificate Renewal Automation

**Status**: 🔴 Unaddressed  
**Risk**: Service outage when certificate expires  

`configure-tls.ps1` binds a certificate to IIS port 443 but has **no
renewal mechanism**. Self-signed certificates expire after 1 year.
Enterprise CA certificates typically expire after 1–3 years. When
the cert expires, HTTPS connections fail immediately with no warning
ahead of time.

**What exists today**: Manual PFX import via `configure-tls.ps1 -PfxPath`.
No scheduled task, no monitoring, no expiry alerting.

**Options to consider**:
1. Add a scheduled task that checks certificate expiry daily and sends an
   alert via the existing webhook when ≤ 30 days remain.
2. If using an ACME-compatible CA (e.g., internal Smallstep, Let's Encrypt
   for public-facing instances), integrate `win-acme` for automatic renewal.
3. If using Enterprise CA with auto-enrollment, configure IIS to use the
   auto-enrolled cert from the machine's personal certificate store.

**Decision needed**: Which renewal strategy fits your PKI? Manual with
alerting, ACME auto-renewal, or AD Certificate Services auto-enrollment?

---

### GAP-02: TLS 1.3 Not Enabled

**Status**: 🟡 Low Risk  
**Risk**: Missing modern cipher suites  

`configure-tls.ps1` enables TLS 1.2 and disables SSLv3/TLS 1.0/TLS 1.1,
but does **not** enable TLS 1.3. Windows Server 2019 supports TLS 1.3 as
of build 17763.3770+ (KB5017315, August 2022 cumulative update). The
script does not check the OS build level or attempt TLS 1.3 enablement.

**Impact**: TLS 1.2 is still fully secure. TLS 1.3 offers 0-RTT and
improved handshake performance, but is not a security requirement today.

**Decision needed**: Add TLS 1.3 registry keys to `configure-tls.ps1`
after confirming the server has the required cumulative update?

---

## Category 2: Windows Update / Reboot Resilience

### GAP-03: Scheduled Scan Behavior During Unplanned Reboots

**Status**: 🔴 Unaddressed  
**Risk**: Missed scan windows or hung scan jobs  

The Go API server handles `SIGINT`/`SIGTERM` with a 10-second graceful
shutdown (see `main.go:266-272`). NSSM is configured with
`SERVICE_AUTO_START` and a 5-second restart delay, so the service
**will restart after a reboot**.

However, there is **no handling** for:
- A scan job that was in-progress when the server rebooted. The `scan_jobs`
  table will have a record with `status = 'running'` that never completes.
  No cleanup or retry logic exists.
- A scheduled scan window (e.g., 01:00–04:00 UTC) that was missed entirely
  because the server was rebooting during that period. There is no
  "catch-up" or "missed window" detection.

**What exists today**: NSSM restarts the service after reboot. The API
starts cleanly. But orphaned `running` scan jobs stay in that state
indefinitely.

**Options to consider**:
1. Add a startup hook that marks any `status = 'running'` scan jobs as
   `failed` with reason `SERVER_RESTART` and logs the event.
2. Add a "missed scan" detector that compares the last scan completion
   timestamp against the expected schedule and triggers a catch-up scan.
3. Configure Windows Update to use WSUS with a maintenance window that
   avoids the 01:00–04:00 scan window.

**Decision needed**: Implement orphan-cleanup on startup? Configure WSUS
reboot windows?

---

### GAP-04: No Coordinated Reboot Draining

**Status**: 🟡 Moderate Risk  
**Risk**: Data loss during mid-write reboot  

If Windows Update forces an immediate reboot (Group Policy can override
user deferral after a deadline), the 10-second SIGTERM grace period may
not be enough for an in-flight `pg_dump` backup or a large batch of
endpoint snapshots being written to the database. PostgreSQL itself
handles crash recovery via WAL, but the Go API's in-memory repositories
(vulnerability findings, compliance results, drift events — all
`*MemoryRepository` types) **lose all data on restart** because they
are not persisted to PostgreSQL.

**What exists today**: `vulnscan.NewMemoryFindingRepository()`,
`compliance.NewMemoryComplianceRepository()`,
`drift.NewMemoryDriftRepository()` — these are in-memory-only stores.

**Impact**: Vulnerability findings from the last NVD/CISA KEV sync,
recent compliance evaluations, and unacknowledged drift events may
vanish on restart. The next sync cycle re-populates NVD/KEV data
(24-hour interval), but any scan results in the memory store are lost.

**Decision needed**: Is the in-memory repository design intentional
(ephemeral cache) or a gap (should persist to PostgreSQL)?

---

## Category 3: Log Rotation and Disk Fill

### GAP-05: No Log Rotation for NSSM Log Files

**Status**: 🔴 Unaddressed  
**Risk**: C:\ drive fills up, service crashes  

NSSM redirects `stdout` and `stderr` to files in
`C:\apps\zeroagent\logs\`:
- `api_stdout.log`
- `api_stderr.log`
- `dashboard_stdout.log`
- `dashboard_stderr.log`

These files grow **unbounded**. NSSM supports built-in log rotation
(`AppRotateFiles=1`, `AppRotateBytes`, `AppRotateOnline=1`) but none
of these settings are configured in `install.ps1`.

Additionally, the deployment scripts generate timestamped log files
(`install_*.log`, `backup_*.log`, `restore_drill_*.log`,
`snapshot_archive_*.log`) that accumulate over time but have no
purge policy.

**What exists today**: Nothing. Logs grow until the disk fills.

**Options to consider**:
1. Add NSSM rotation settings in `install.ps1`:
   ```powershell
   nssm set ZeroAgentAPI AppRotateFiles 1
   nssm set ZeroAgentAPI AppRotateBytes 52428800  # 50 MB
   nssm set ZeroAgentAPI AppRotateOnline 1
   ```
2. Add a scheduled task to purge logs older than 90 days.
3. Configure the Go API to write directly to a rotating log library
   instead of relying on NSSM file capture.

**Decision needed**: NSSM built-in rotation (simplest), a cleanup
scheduled task, or refactored application logging?

---

### GAP-06: PostgreSQL Log Rotation Not Configured

**Status**: 🟡 Moderate Risk  
**Risk**: D:\ drive fills with PostgreSQL logs  

PostgreSQL's `log_destination` defaults to `stderr` captured to files
in `D:\postgres\data\log\`. The default `log_rotation_age` is 24 hours
and `log_rotation_size` is 0 (disabled). Under heavy scan load (~400
endpoints), verbose query logging can produce several GB per day.

**What exists today**: Default PostgreSQL logging config. No explicit
`postgresql.conf` tuning in the deployment scripts.

**Decision needed**: Set `log_rotation_size = 100MB` and
`log_file_mode = 0600` in `postgresql.conf`? Add a purge script for
logs older than 30 days?

---

## Category 4: Database Topology and Localhost Hardcoding

### GAP-07: Several Components Hardcode localhost/127.0.0.1

**Status**: 🟡 Low Risk Now, High Risk Later  
**Risk**: Cannot split DB to a separate server without code changes  

The following locations assume PostgreSQL runs on the same machine as
the API:

| File | Hardcoded Value |
|------|----------------|
| `deploy.config.json` | `"host": "127.0.0.1"` |
| `deploy-update.ps1` (line 55) | Fallback `$DBHost = "127.0.0.1"` |
| `backup-db.ps1` | Sets `PGHOST` from config (127.0.0.1) |
| `restore-drill.ps1` | Same PGHOST pattern |
| `archive-snapshots.ps1` | Calls `http://127.0.0.1:8080/health` |
| `apps/api/.env.production` | `DATABASE_URL=...@localhost:5432/...` |

The `DATABASE_URL` in `.env.production` is the **only** connection string
the Go API actually reads. The `deploy.config.json` `database.host` is
used by PowerShell scripts for `psql`/`pg_dump` calls.

**If you ever split the database to a remote server**:
1. Update `DATABASE_URL` in `.env.production` with the remote host
   and `sslmode=verify-full`.
2. Update `deploy.config.json` `database.host` for the PowerShell scripts.
3. Open firewall port 5432 between the API server and the DB server
   (currently locked to localhost only by `PostgreSQL-Localhost-Only` rule).
4. Ensure `pg_hba.conf` on the DB server allows the API server's IP.

**Decision needed**: Accept localhost-only for now? Document the
migration path for future DB separation?

---

### GAP-08: deploy.config.json Database Names Don't Match Application Code

**Status**: 🔴 Active Bug  
**Risk**: Install script creates wrong database  

| Source | DB Name | DB User |
|--------|---------|---------|
| `deploy.config.json` | `zeroagent_prod` | `zeroagent_app` |
| `apps/api/.env.production` | `endpointguard_prod` | `endpointguard_prod_svc` |
| `deploy-update.ps1` fallback | `endpointguard` | `endpointguard_app` |

The Go API reads **only** from `DATABASE_URL` in `.env.production`, which
uses `endpointguard_prod`. The PowerShell scripts read from
`deploy.config.json`, which says `zeroagent_prod`. If you run `install.ps1`
as-is, it creates the wrong database name.

**The deployment guide (DEPLOYMENT.md) instructs the operator to create
`endpointguard_prod` manually**, bypassing `install.ps1`'s broken DB
provisioning. But `deploy.config.json` should still be corrected.

**Decision needed**: Update `deploy.config.json` to use
`endpointguard_prod` / `endpointguard_prod_svc` for consistency?

---

## Category 5: Time Zone Handling

### GAP-09: Scheduled Tasks Use Server Local Time

**Status**: 🟡 Moderate Risk for Multi-Region  
**Risk**: Scans fire at unexpected times if server clock isn't UTC  

All three Windows Scheduled Tasks (backup at 02:00, restore drill at
03:00, snapshot retention at 03:30) run in the server's local time zone.
The scan scheduling documentation (`docs/production-scan-scheduling.md`)
specifies scan windows in **UTC**. If the server is set to a local time
zone (e.g., EST/PST/IST), the backup at "02:00 local" and the scan
window at "01:00 UTC" may overlap or conflict unpredictably.

**What exists today**: No time zone enforcement. No documentation telling
the operator to set the server to UTC.

**Options to consider**:
1. Document that the server **must** be set to UTC time zone.
2. Modify scheduled task XML files to use UTC triggers.
3. Add a pre-flight check that warns if the server is not set to UTC.

**Decision needed**: Mandate UTC on the server, or convert all schedules
to explicitly account for local time zones?

---

### GAP-10: Report and Audit Log Timestamps May Confuse Multi-Region Operators

**Status**: 🟡 Low Risk  
**Risk**: Operators in different time zones misinterpret event times  

The Go API stores timestamps in UTC (PostgreSQL `TIMESTAMPTZ`), but the
dashboard renders timestamps using `new Date().toLocaleString()` which
uses the **browser's** local time zone. This is generally correct behavior,
but there is no user-facing control to select a preferred display time
zone, and exported CSV reports use UTC without labeling the column as UTC.

**Decision needed**: Add a "Display Time Zone" user preference, or
document that all exports are UTC?

---

## Category 6: Security Gaps

### GAP-11: JWT Signing Secret Hardcoded in Source Code

**Status**: 🔴 Critical  
**Risk**: Token forgery if source code leaks  

`apps/api/cmd/server/main.go` line 101 contains a hardcoded JWT signing
secret:
```go
"enterprise-endpointguard-master-jwt-secret-key-32b!"
```

The `JWT_SIGNING_SECRET` environment variable defined in `.env.production`
is **never read** by `config.go` or `main.go`. Every deployment uses the
same JWT signing key regardless of environment configuration.

**Impact**: Anyone with access to the source code (GitHub, build artifacts)
can forge valid JWT tokens for any user role, including `superadmin`.

**Decision needed**: This should be treated as a P0 security fix. The
signing secret must be loaded from the environment variable or the vault.

---

### GAP-12: mTLS Environment Variable Name Mismatch

**Status**: 🔴 Active Bug  
**Risk**: mTLS client auth silently disabled in production  

`config.go` reads environment variables using camelCase names:
- `MTLSServerCertPath`
- `MTLSServerKeyPath`

But `.env.production` sets them as UPPER_SNAKE_CASE:
- `MTLS_SERVER_CERT_PATH`
- `MTLS_SERVER_KEY_PATH`

These will **not match**. The server will start without mTLS server
certificates, silently falling back to plain HTTP on port 8080
(which is fine behind IIS, but means collector gateways cannot
establish mTLS connections to the API).

**Decision needed**: Fix `config.go` to read `MTLS_SERVER_CERT_PATH`
and `MTLS_SERVER_KEY_PATH`, or rename the `.env.production` variables
to match the camelCase convention?

---

### GAP-13: PGPASSWORD Authentication Not Configured

**Status**: 🔴 Active Bug  
**Risk**: All backup/restore scripts fail silently  

`backup-db.ps1`, `restore-drill.ps1`, and `deploy-update.ps1` invoke
`pg_dump`, `pg_restore`, and `psql` without setting `PGPASSWORD` or
configuring a `.pgpass` file. PostgreSQL will prompt for a password
interactively, which fails when running under a scheduled task
(no interactive session).

**What exists today**: Nothing. The scripts will fail with
"connection to server ... failed: fe_sendauth: no password supplied."

**Fix required**: Create `pgpass.conf` at
`C:\Users\svc_zeroagent\AppData\Roaming\postgresql\pgpass.conf`
with contents:
```
127.0.0.1:5432:endpointguard_prod:endpointguard_prod_svc:YOUR_PASSWORD
```
And ensure `PGPASSFILE` is set or the file is in the default location.

**Decision needed**: Add `.pgpass` creation to install.ps1, or set
`PGPASSWORD` as an environment variable on the service account?

---

### GAP-14: Hardcoded Password in install.ps1

**Status**: 🔴 Active Bug  
**Risk**: Known default password in production database  

`install.ps1` line 179 contains a hardcoded SQL password
`'$DBUser_Secret_2026'` in the database initialization script. The
`$DBPassword` parameter accepted by the script is **never substituted**
into the SQL. If the DB init SQL were actually executed (see GAP-15),
the database user would have a known, hardcoded password.

**Decision needed**: Fix the script to use the `$DBPassword` parameter
in the SQL template. (The current deployment guide bypasses this by
having the operator create the DB manually.)

---

### GAP-15: Database Init SQL Generated But Never Executed

**Status**: 🟡 Low Risk (bypassed by manual step)  
**Risk**: Misleading script behavior  

`install.ps1` writes `init_db.sql` to the temp directory but never
invokes `psql` to execute it. The deployment guide (DEPLOYMENT.md)
instructs the operator to create the database manually, effectively
bypassing this bug. But the script gives the false impression that
it handles DB provisioning.

**Decision needed**: Either complete the DB provisioning in install.ps1
(fix the SQL, add psql invocation) or remove the dead code to avoid
confusion?

---

### GAP-16: Demo User Credentials Hardcoded in Auth Repository

**Status**: 🟡 Development Only  
**Risk**: Low (only active when no real auth backend)  

`apps/api/internal/auth/repository.go` contains hardcoded demo users
with known passwords (e.g., `admin@demo.local` / `AdminDevPass2026!`).
These are used in development mode when no OIDC/database auth backend
is configured.

The production boot guard (`VerifyNoDemoDataInProduction`) checks the
`endpoints` table for demo data but does **not** check for demo users
in the auth layer. If the in-memory auth repository is active in
production (because OIDC configuration is missing), these demo
credentials would work.

**Decision needed**: Add a production guard that refuses to start if
the in-memory auth repository is the active auth backend?

---

## Category 7: Operational Gaps

### GAP-17: Dashboard NSSM Service Not Registered by install.ps1

**Status**: 🔴 Deployment Gap  
**Risk**: Dashboard doesn't auto-start; manual step required  

`install.ps1` registers only `ZeroAgentAPI` as an NSSM service. The
Next.js dashboard (`ZeroAgentDashboard`) is mentioned in a log message
but **never actually registered**. The deployment guide includes manual
NSSM registration commands for the dashboard as a workaround.

**Decision needed**: Add dashboard service registration to install.ps1?

---

### GAP-18: IIS Reverse Proxy Configuration Not Implemented

**Status**: 🔴 Deployment Gap  
**Risk**: IIS enabled but not configured as reverse proxy  

`install.ps1` enables the IIS Windows features but does **not**:
1. Install URL Rewrite Module 2.1
2. Install Application Request Routing (ARR) 3.0
3. Create the IIS website/application
4. Configure reverse proxy rules (API on /api/* → localhost:8080,
   dashboard on /* → localhost:3000)
5. Set up HTTP→HTTPS redirect

These must all be done manually or by a separate script.

**Decision needed**: Extend install.ps1 to handle full IIS configuration,
or create a separate `configure-iis.ps1` script?

---

### GAP-19: Go Binary Distribution Method Undefined

**Status**: 🟡 Moderate Risk  
**Risk**: No documented build-and-ship pipeline for server.exe  

The API is a compiled Go binary (`server.exe`), but the deployment
package does not document:
1. How to build `server.exe` from source (`CGO_ENABLED=0 GOOS=windows
   go build -ldflags="-w -s" -o server.exe ./cmd/server`)
2. Where pre-built release artifacts are published
3. How `deploy-update.ps1` obtains the release `.zip` file
4. Whether the `.zip` includes both `server.exe` and the dashboard build

The Dockerfile builds for Linux (`GOOS=linux`), not Windows.

**Decision needed**: Add a Windows build target to CI? Publish release
zips to GitHub Releases? Document the manual build process?

---

### GAP-20: In-Memory Repositories Lose Data on Restart

**Status**: 🟡 Architecture Question  
**Risk**: Scan results, compliance evaluations, drift events lost  

As noted in GAP-04, several repositories use in-memory storage:
- `vulnscan.NewMemoryFindingRepository()` — vulnerability findings
- `compliance.NewMemoryComplianceRepository()` — compliance results
- `drift.NewMemoryDriftRepository()` — drift events
- `auth.NewMemoryAuthRepository()` — user sessions

These are populated during scan execution and NVD/KEV sync but are
**not persisted to PostgreSQL**. A service restart or server reboot
loses all data in these stores.

The database schema (`packages/db/schema.sql`) defines tables for
`vulnerabilities`, `compliance_evaluations`, `drift_events`, and
`tenant_users` — suggesting the intent is to persist this data, but
the repository implementations use in-memory maps instead.

**Decision needed**: Is this intentional (demo/MVP architecture) or a
gap that needs PostgreSQL-backed repository implementations before
production use?

---

### GAP-21: Backup Timing Conflicts with Scan Window

**Status**: 🟡 Low Risk  
**Risk**: Degraded performance during concurrent backup + scan  

The database backup scheduled task runs at 02:00 AM local time.
`docs/production-scan-scheduling.md` schedules Subnet C (60 server
endpoints) starting at 02:00 UTC. If the server is set to UTC, these
run simultaneously.

During `pg_dump`, PostgreSQL takes a consistent snapshot which increases
I/O load. Concurrent scan writes may experience elevated latency.

**Decision needed**: Stagger the backup to 04:30 (after the scan window
closes) or accept the overlap for a 400-endpoint fleet?

---

### GAP-22: No Disk Space Monitoring or Alerting

**Status**: 🟡 Moderate Risk  
**Risk**: Silent failure when D:\ fills with backups/snapshots  

No monitoring exists for disk space on C:\ or D:\. If D:\ fills (backups
+ PostgreSQL WAL + cold-storage archives), `pg_dump` will fail silently,
PostgreSQL may crash, and snapshot archival will stop.

**Decision needed**: Add a scheduled task that checks disk free space
and sends a webhook alert when below 10%? Integrate with existing
monitoring (SCOM, Nagios, Prometheus)?

---

### GAP-23: Restore Drill Pass Condition Too Weak

**Status**: 🟡 Low Risk  
**Risk**: Corrupt restore falsely reports PASS  

`restore-drill.ps1` passes if `endpoint_count >= 0`, which is always
true (even for an empty database). The condition should likely be
`endpoint_count > 0` to catch an empty or corrupt restore.

**Decision needed**: Tighten the assertion to `endpoint_count > 0`?

---

### GAP-24: archive-snapshots.ps1 Does Nothing in Offline Mode

**Status**: 🟡 Low Risk  
**Risk**: Retention job silently succeeds without archiving  

If the API is unreachable when `archive-snapshots.ps1` runs, the script
logs a warning, sets status to `COMPLETED_OFFLINE`, and exits with
code 0 (success). No actual archival or downsampling occurs. The
scheduled task reports success to Task Scheduler.

**Decision needed**: Change offline mode to exit with code 1 (failure)
so Task Scheduler flags it? Add a retry mechanism?

---

### GAP-25: Email Notifications Not Implemented

**Status**: 🟡 Low Risk  
**Risk**: Operators who don't use Slack/Teams miss alerts  

`deploy.config.json` defines `notify_email` but no script or API
endpoint sends email. Only webhook (Slack/Teams) notifications are
implemented.

**Decision needed**: Implement SMTP email delivery for backup/drill
notifications, or remove the `notify_email` config field to avoid
confusion?

---

### GAP-26: No Disaster Recovery Runbook for Windows

**Status**: 🔴 Documentation Gap  
**Risk**: No recovery procedure for the deployment platform  

`docs/disaster-recovery-runbook.md` uses Linux paths (`/opt/...`,
`/var/...`), bash scripts, and AWS S3/KMS for backup storage. There
is no equivalent Windows Server recovery procedure covering:
1. Full server loss and rebuild
2. PostgreSQL data directory corruption
3. Certificate/vault key loss
4. Restoring from backup to a fresh Windows Server

**Decision needed**: Write a Windows-specific DR runbook?

---

## Category 8: Product Consistency

### GAP-27: Three Different Product Names Used Interchangeably

**Status**: 🟡 Cosmetic  
**Risk**: Operator confusion, incorrect documentation searches  

| Name | Used In |
|------|---------|
| ZeroAgent-Scan | deploy.config.json, deploy scripts, repo name |
| EndpointGuard | README.md, API service name, .env files, database names |
| EMS | deploy.config.json display name |

**Decision needed**: Standardize on one name across all documentation
and configuration?

---

## Summary: Priority Matrix

| Priority | ID | Gap | Category |
|----------|----|-----|----------|
| 🔴 P0 | GAP-11 | JWT signing secret hardcoded | Security |
| 🔴 P0 | GAP-12 | mTLS env var name mismatch | Security |
| 🔴 P1 | GAP-13 | PGPASSWORD not configured | Operations |
| 🔴 P1 | GAP-08 | DB name mismatch config vs code | Operations |
| 🔴 P1 | GAP-14 | Hardcoded password in install.ps1 | Security |
| 🔴 P1 | GAP-05 | No log rotation | Operations |
| 🔴 P1 | GAP-01 | No cert renewal automation | Operations |
| 🔴 P1 | GAP-17 | Dashboard service not registered | Deployment |
| 🔴 P1 | GAP-18 | IIS reverse proxy not configured | Deployment |
| 🔴 P1 | GAP-26 | No Windows DR runbook | Documentation |
| 🟡 P2 | GAP-03 | Orphaned scan jobs on reboot | Resilience |
| 🟡 P2 | GAP-04 | In-memory repos lose data on restart | Architecture |
| 🟡 P2 | GAP-20 | In-memory repos not persisted | Architecture |
| 🟡 P2 | GAP-07 | Localhost hardcoding for DB | Scalability |
| 🟡 P2 | GAP-09 | Time zone handling | Multi-region |
| 🟡 P2 | GAP-19 | Go binary build pipeline undefined | CI/CD |
| 🟡 P2 | GAP-22 | No disk space monitoring | Monitoring |
| 🟡 P2 | GAP-16 | Demo users in auth repository | Security |
| 🟡 P2 | GAP-06 | PostgreSQL log rotation | Operations |
| 🟡 P3 | GAP-02 | TLS 1.3 not enabled | Security |
| 🟡 P3 | GAP-10 | Report timezone display | UX |
| 🟡 P3 | GAP-15 | Dead code in install.ps1 | Code quality |
| 🟡 P3 | GAP-21 | Backup/scan timing overlap | Performance |
| 🟡 P3 | GAP-23 | Weak restore drill assertion | Testing |
| 🟡 P3 | GAP-24 | Silent offline archival success | Operations |
| 🟡 P3 | GAP-25 | Email notifications not implemented | Operations |
| 🟡 P3 | GAP-27 | Product name inconsistency | Documentation |
