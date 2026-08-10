# Deploying ZeroAgent-Scan / EMS on Windows Server 2016 — Production Guide

One heads-up before you start: **Windows Server 2016 exited mainstream support in Jan 2022** and is in Extended Support (security patches only) until **January 2027**. If this box is internet-facing at all, plan its retirement now — but everything below works fine on it for an internal enterprise deployment in the meantime.

This assumes WS2016 hosts the **application itself** (dashboard + API + Postgres), which then reaches out over WinRM/DCOM to scan your ~400 endpoints. If you actually meant WS2016 is one of the *scan targets*, let us know and we will provide target-side WinRM-enablement steps instead — they're different.

---

## Part A — Agent Prompt (generates the deployment automation)

Paste this into your coding agent to produce the actual install scripts, since hand-typing 400 lines of PowerShell is a waste of your time:

```
Generate a production deployment package for ZeroAgent-Scan on Windows
Server 2016, targeting an on-prem enterprise environment. Deliverables:

1. A PowerShell install script (install.ps1) that:
   - Checks for and installs prerequisites: Node.js LTS (via msiexec silent
     install), PostgreSQL 15+ (via silent installer), and NSSM
     (Non-Sucking Service Manager) for running Node as a Windows Service.
   - Creates a dedicated low-privilege local service account (not
     LocalSystem) to run the application service.
   - Creates the application's PostgreSQL database and role with
     least-privilege grants (no SUPERUSER).
   - Registers the API/backend as a Windows Service via NSSM, configured
     to auto-restart on failure and start on boot.
   - Registers the frontend build as a static site served either by IIS
     (with URL Rewrite + Application Request Routing as reverse proxy to
     the Node API) or by the Node service itself, depending on a
     -ServeMode parameter.
   - Configures Windows Firewall rules scoped to only the ports actually
     needed (app port, Postgres port bound to localhost only, WinRM
     outbound to scan subnets).
   - Is idempotent — safe to re-run for updates without duplicating
     services or losing data.

2. A configure-tls.ps1 script that:
   - Binds a provided PFX certificate to the IIS site or Node HTTPS
     listener (support both a real enterprise CA cert and, as a fallback,
     generating a self-signed cert for initial bring-up with a clear
     warning it must be replaced before go-live).
   - Enforces TLS 1.2+ only, disabling older protocols at the OS level via
     registry (SCHANNEL) settings, and documents the registry keys touched
     so this can be reviewed before running on a shared server.

3. A deploy-update.ps1 script for pushing new application versions:
   - Pulls or accepts a build artifact, stops the NSSM service, runs DB
     migrations, swaps in the new build, restarts the service, and runs a
     post-deploy health check against the /health endpoint before
     declaring success — auto-rollback to the previous build if the health
     check fails.

4. A backup-db.ps1 script using pg_dump, scheduled via a Windows Task
   Scheduler XML definition (not cron), writing to a configurable backup
   path with retention (keep last N daily + last N weekly).

5. A README-DEPLOYMENT.md documenting manual prerequisites that can't be
   scripted safely (AD service account creation, firewall change requests
   to the network team, certificate procurement) and the exact order to
   run the scripts in.

Do not hardcode any credentials, connection strings, or paths — everything
configurable goes in a deploy.config.json read by all scripts. Every script
must log its actions to a timestamped log file for audit purposes.
```

---

## Part B — Manual Production Deployment Runbook

Use this alongside the generated scripts, or as a standalone checklist if you're doing it by hand.

### 1. Server Preparation
- Apply all pending Windows Updates and reboot before installing anything.
- Confirm the server has a static IP and is joined to the domain (needed for AD service account auth to endpoints).
- Disable SMBv1 at the OS level if not already (`Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`) — ironic to leave it on a compliance-scanning box.
- Create a dedicated volume/partition for the Postgres data directory if possible, separate from the OS drive.

### 2. Install Runtime Prerequisites
- **Node.js LTS** (matching whatever version the app was built/tested against — check `package.json` engines field).
- **PostgreSQL 15+**, with the data directory placed on the dedicated volume from step 1.
- **NSSM** to wrap the Node process as a proper Windows Service (Node has no native Windows Service support).
- **IIS with URL Rewrite + Application Request Routing (ARR)** if you want IIS as the TLS-terminating reverse proxy in front of Node — recommended for production over exposing Node's HTTP server directly.

### 3. Service Accounts
- Create a dedicated **gMSA or standard AD service account** for the application to run as (never LocalSystem, never a personal admin account).
  - Grant it "Log on as a service" right.
  - Grant it least-privilege on the Postgres database only — not local admin on the box.
- Create a **separate** AD service account (or gMSA) specifically for outbound scanning of the ~400 endpoints — this should have exactly the rights needed for WMI/CIM read access on target hosts and nothing more. Do not reuse the app's own service account for this.

### 4. Database Setup
```powershell
# Run as postgres admin
CREATE ROLE zeroagent_app LOGIN PASSWORD '<from-vault-not-here>';
CREATE DATABASE zeroagent_prod OWNER zeroagent_app;
REVOKE ALL ON DATABASE zeroagent_prod FROM PUBLIC;
```
- Apply migrations via your migration tool, not manual SQL, so this is repeatable.
- Confirm `pg_hba.conf` restricts connections to `127.0.0.1`/localhost only unless the app and DB are on separate boxes — in which case restrict to the specific app server IP, never `0.0.0.0/0`.
- Set `postgresql.conf` `listen_addresses` accordingly, and disable remote superuser login.

### 5. Application Install & Service Registration
```powershell
# Example NSSM registration for the API
nssm install ZeroAgentAPI "C:\Program Files\nodejs\node.exe" "C:\apps\zeroagent\server.js"
nssm set ZeroAgentAPI AppDirectory "C:\apps\zeroagent"
nssm set ZeroAgentAPI ObjectName ".\svc_zeroagent" "<password>"
nssm set ZeroAgentAPI AppStdout "C:\apps\zeroagent\logs\stdout.log"
nssm set ZeroAgentAPI AppStderr "C:\apps\zeroagent\logs\stderr.log"
nssm set ZeroAgentAPI Start SERVICE_AUTO_START
nssm start ZeroAgentAPI
```
- Store the service account password in a secrets manager, not in a script or Task Scheduler credential in plaintext — NSSM supports pulling this from environment variables set on the service object rather than command-line args where possible.
- Point all DB connection strings, vault addresses, and scan concurrency limits at `deploy.config.json` / environment variables — nothing hardcoded.

### 6. Reverse Proxy & TLS
- Terminate TLS at IIS (or a hardware/network load balancer if you have one) rather than in Node directly — easier certificate lifecycle management.
- Use a real internal CA-issued certificate (most enterprises have an internal PKI) rather than a self-signed cert for anything beyond initial smoke testing.
- Enforce TLS 1.2 minimum; disable TLS 1.0/1.1 and SSLv3 via the SCHANNEL registry keys.
- Set HSTS, and confirm the app's own security headers (CSP, X-Content-Type-Options) survive the proxy hop.

### 7. Firewall Rules
| Direction | Port | Purpose |
|---|---|---|
| Inbound | 443 | Dashboard/API access for your users |
| Outbound | 5986 (or 5985 if forced, see prior hardening prompt) | WinRM to scan targets |
| Outbound | 135, 445, dynamic RPC range | DCOM/CIM to scan targets |
| Outbound | 443 | NVD/CISA KEV feed if vuln correlation is enabled |
| Local only | 5432 | Postgres — never expose this outside the box unless DB is separate |

Submit the outbound WinRM/DCOM rule as a formal change request to your network/firewall team — this is the rule most likely to get flagged in a security review if it's not documented as an approved compliance-scanning exception.

### 8. Scheduled Scans
- Use Windows Task Scheduler (not an in-process cron-like library alone) to trigger the nightly/staggered fleet scan via a call to the app's own scan-trigger API, so scan scheduling survives independently of the app process staying up continuously.
- Stagger by subnet as recommended in the earlier scale-hardening prompt — don't fire all 400 at 2:00 AM sharp.

### 9. Backup & Monitoring
- Schedule `pg_dump` nightly via Task Scheduler, retained per your compliance policy (commonly 30 daily + 12 monthly).
- Point Windows Server's built-in Performance Monitor or your existing enterprise monitoring (SCOM, Zabbix, etc.) at the NSSM service and Postgres process, and at the app's `/health` endpoint.
- Confirm Windows Event Log entries from the service are actually useful (not just "Node.exe exited") — this is where the structured logging from the earlier hardening prompt pays off.

### 10. Go-Live Checklist
- [ ] All 10 production-hardening prompts from the previous pack applied and tested
- [ ] Service account is least-privilege, not domain admin
- [ ] TLS 1.2+ enforced, valid internal CA cert installed
- [ ] Firewall change request approved and rules verified with a test scan against 2-3 pilot endpoints before the full ~400
- [ ] Backup job tested with an actual restore, not just "the job ran"
- [ ] Alerting wired to your team's actual notification channel (email/Teams/Slack), tested with a deliberate failure
- [ ] Runbook handed to whoever's on call, including how to restart the NSSM service and where logs live
