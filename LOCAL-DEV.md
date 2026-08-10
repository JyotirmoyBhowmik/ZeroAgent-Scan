# ZeroAgent-Scan / EndpointGuard EMS — Local Development & Testing Guide

This guide describes how to run and explore the complete ZeroAgent-Scan platform on `localhost` with **100% network isolation** from any production environment.

---

## 🚀 Quick Start (Single Command)

### 1. Start the Full Local Stack
From the repository root, start PostgreSQL, the API backend (with `MOCK_SCAN_MODE=true`), the Next.js web dashboard, and the mock Collector Gateway:

```bash
docker compose -f docker-compose.dev.yml up -d
```

*Note: PostgreSQL automatically applies all database migrations (`packages/db/init-all.sql`) and seeds the mock RFC 5737 fleet (`packages/db/seed-dev.sql`) on initial startup.*

---

## 🌐 Local Service Access & URLs

| Component | Local URL / Port | Technology | Purpose |
| :--- | :--- | :--- | :--- |
| **Web Dashboard** | [http://localhost:3000](http://localhost:3000) | Next.js 14 App Router | Main GUI (White & Charcoal Enterprise Theme) |
| **API Control Plane** | [http://localhost:8080](http://localhost:8080) | Go (go-chi/v5) | REST & SSE Telemetry Engine |
| **PostgreSQL Database** | `localhost:5432` | PostgreSQL 15+ | Multi-Tenant Database (`endpointguard`) |
| **Collector Gateway** | `gateway` container | Go Agentless Daemon | Simulates WinRM gateway for `192.0.2.0/24` |

---

## 🔑 Default Seeded Login Credentials

The local database comes pre-seeded with dedicated test accounts for each of the 5 RBAC access tiers:

| Role | Username / Email | Password | Allowed Capabilities |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@demo.local` (or `admin`) | `AdminDevPass2026!` | Full tenant control, user management, alert configuration, credential rotation (step-up auth). |
| **Operator** | `operator@demo.local` (or `operator`) | `OperatorDevPass2026!` | Can trigger/cancel scans, acknowledge drift events, inspect endpoints. |
| **Auditor** | `auditor@demo.local` (or `auditor`) | `AuditorDevPass2026!` | Read-only access to all compliance evaluations, findings, reports, and immutable audit logs. |
| **Viewer** | `viewer@demo.local` (or `viewer`) | `ViewerDevPass2026!` | Read-only access to endpoints and inventory overview (403 on scans and admin settings). |
| **SuperAdmin** | `breakglass@endpointguard.local` | `EmergencyBreakGlassPass2026!` | Break-glass emergency administrator with TOTP MFA (`JBSWY3DPEHPK3PXP`). |

---

## 🛡️ Mock Fleet Data Overview (RFC 5737 Compliant)

All seeded inventory uses **RFC 5737 documentation IP prefixes** and `DEMO-*` naming conventions to guarantee mock data can never be confused with real production hosts:

- **30 Total Mock Hosts**:
  - `DEMO-WKS-001` through `DEMO-WKS-020` (Windows 11 23H2 Workstations)
  - `DEMO-SRV-001` through `DEMO-SRV-010` (Windows Server 2022 Datacenter)
- **Subnet Rings**:
  - `192.0.2.0/24` (TEST-NET-1): Pilot Ring (Canary workstations `DEMO-WKS-001`..`008`)
  - `198.51.100.0/24` (TEST-NET-2): Staged Ring (Departmental endpoints `DEMO-WKS-009`..`015`)
  - `203.0.113.0/24` (TEST-NET-3): Full Fleet Ring (Domain Controllers, SQL servers, core hosts)
- **Compliance Statuses**:
  - 18 Fully Compliant (95–100% score; BitLocker enabled, TPM 2.0 active, Defender real-time protection active)
  - 8 Partially Compliant (70–85% score; non-critical baseline deviations)
  - 4 Failed (35–55% score; BitLocker disabled, Defender outdated, unauthorized local admins)
- **CISA KEV (Known Exploited Vulnerabilities) Seeded**:
  - `CVE-2023-34362` (MOVEit Transfer SQLi / RCE) — **CRITICAL (CVSS 9.8) [KEV]**
  - `CVE-2024-21413` (Microsoft Outlook Moniker Link RCE) — **CRITICAL (CVSS 9.8) [KEV]**
  - `CVE-2023-23397` (Microsoft Outlook NTLM Relay) — **HIGH (CVSS 9.8) [KEV]**
  - `CVE-2024-30051` (Windows DWM Core Library EoP) — **HIGH (CVSS 7.8) [KEV]**
- **Compliance Benchmarks Seeded**:
  - CIS Microsoft Windows 11 Enterprise Benchmark v3.0 (Level 1 & Level 2)
  - CIS Microsoft Windows Server 2022 Benchmark v2.0
  - NIST SP 800-53 Rev. 5, HIPAA Security Rule, PCI-DSS v4.0

---

## ⚡ Mock Scan Engine Walkthrough (`MOCK_SCAN_MODE=true`)

When `MOCK_SCAN_MODE=true` is set, the scan orchestrator runs in **safe simulation mode**. You can launch scans and watch the full 6-stage agentless pipeline execute live without needing real target endpoints:

1. Open [http://localhost:3000/scans](http://localhost:3000/scans)
2. In the **Configure Agentless Scan** card:
   - **Target Subnet CIDR**: `192.0.2.0/24` (RFC 5737 Pilot Ring)
   - **Protocol**: `WinRM over HTTPS (Port 5986)`
   - **Scan Profile**: `Full Hardware & CIS Benchmark Audit`
3. Click **"Launch Agentless Scan"**.
4. Watch the **6-Stage Pipeline Stepper & Live Telemetry Terminal** animate through each stage:
   - **Stage 1: Discovery** — ICMP ping & ARP sweep across `192.0.2.0/24`.
   - **Stage 2: Handshake** — WinRM HTTPS (5986) TLS 1.2+ mutual handshake with vault token.
   - **Stage 3: Hardware Audit** — WMI/CIM queries (`Win32_Processor`, `Win32_PhysicalMemory`, TPM 2.0).
   - **Stage 4: Security Posture** — BitLocker encryption, Defender AV status, Secure Boot UEFI.
   - **Stage 5: Inventory Indexing** — Installed applications and patch hotfix correlation against CVE / KEV feeds.
   - **Stage 6: DB Commit** — Telemetry snapshot stored (SHA-256 verified), drift analysis calculated, compliance benchmark scored.

---

## 🛠️ Developer Commands & Scripts

```bash
# Re-apply seed data manually at any time
npm run seed:dev
# or: go run scripts/seed_dev.go

# Run API unit & integration tests
go test -v ./apps/api/...

# Build dashboard frontend for production validation
cd apps/dashboard && npm run build

# Stop and wipe the local dev environment
docker compose -f docker-compose.dev.yml down -v
```

---

## 🔍 Database Inspection

To connect to the local PostgreSQL database using `psql` or a GUI client (DBeaver, pgAdmin):

- **Host**: `localhost`
- **Port**: `5432`
- **Database**: `endpointguard`
- **User**: `endpointguard_app`
- **Password**: `endpointguard_secure_dev_password_change_in_prod`

```bash
# Connect via Docker CLI:
docker exec -it zeroagent-dev-postgres psql -U endpointguard_app -d endpointguard
```
