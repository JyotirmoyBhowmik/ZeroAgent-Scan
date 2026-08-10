# EndpointGuard Production Scan Window & Subnet Staggering Runbook

> **Recommended Operational Guidelines for Auditing ~400+ Enterprise Windows Endpoints Without Impacting Business-Hours Network Traffic or Triggering EDR/Firewall Alarms.**

---

## 🕒 1. Recommended Scan Window

| Scan Profile | Recommended Schedule | Time Window (Local/UTC) | Concurrency | Target Duration |
| :--- | :--- | :--- | :--- | :--- |
| **Nightly Full CIS Audit** | Mon – Fri (Daily) | **01:00 – 04:00 UTC** | 25 Workers / Subnet | ~3–5 Minutes per /24 Subnet |
| **Weekly Deep Vuln & CPE Scan**| Sunday (Weekly) | **00:00 – 06:00 UTC** | 20 Workers / Subnet | ~8–12 Minutes per Subnet |
| **Fast Ping & Inventory Sweep** | Business Hours (Hourly) | **08:00 – 18:00 Local** | 10 Workers / Subnet | ~45 Seconds per Subnet |
| **Ad-Hoc Single Host Probe** | On-Demand (Security Analyst) | Any Time | 1 Session | ~1.5 Seconds |

---

## 🔀 2. Subnet Staggering Architecture (~400 Hosts Fleet)

To avoid saturating WAN uplinks, Active Directory Domain Controllers (Kerberos TGS request spikes), and core firewall state tables, bulk CIDR scans must be **staggered by subnet** rather than executing all subnets simultaneously.

```
   01:00 UTC ──► Subnet A: Corporate HQ Workstations (10.100.1.0/24 - ~180 Hosts)
                 └── Concurrency: 25 Workers | Gateway: `gw-hq-core-01`
   
   01:30 UTC ──► Subnet B: Finance & Executive Laptops (10.100.2.0/24 - ~120 Hosts)
                 └── Concurrency: 20 Workers | Gateway: `gw-finance-01`
   
   02:00 UTC ──► Subnet C: Datacenter Windows Servers (10.100.3.0/24 - ~60 Hosts)
                 └── Concurrency: 15 Workers | Gateway: `gw-dc-servers-01`
   
   02:30 UTC ──► Subnet D: Remote Branch Office (10.100.4.0/24 - ~40 Hosts via WAN)
                 └── Concurrency: 10 Workers | Gateway: `gw-branch-01` (Adaptive WAN Backoff)
```

---

## ⚙️ 3. Throttling, Rate Limits & EDR Evasion Rules

1. **Bounded Worker Pool Concurrency**:
   - Limit active WinRM sessions to **20–30 per gateway**.
   - Spawning 400 simultaneous TCP connections from a single IP to 400 different hosts within 1 second can trigger EDR port-scan heuristics (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne). The bounded worker pool rate-limits connections to a steady, legitimate administrative stream.
2. **Active Directory Kerberos Protection**:
   - When using Kerberos authentication (`winrm_https` / `winrm_http`), the Collector Gateway caches Kerberos Ticket Granting Service (TGS) tickets in memory.
   - **Auth Failure Fast-Abort**: If an endpoint returns `401 Unauthorized` or `403 Forbidden`, the engine **immediately aborts without retrying**, preventing Active Directory account lockouts caused by bad credentials.
3. **WAN Link Latency & Jitter Handling**:
   - For high-latency branch offices (`ping > 100ms`), configure:
     ```yaml
     gateway:
       scanTimeout: 20s
       maxRetries: 2
       backoffBase: 500ms
       maxBackoffLimit: 5s
     ```

---

## 🤖 4. Automated Cron Scheduling Example (`crontab` / Kubernetes CronJob)

```bash
# /etc/cron.d/endpointguard-scans

# 01:00 UTC: Scan Subnet A (HQ Workstations)
0 1 * * 1-5 endpointguard curl -s -X POST https://api.endpointguard.corp/api/v1/scans \
  -H "Authorization: Bearer $CRON_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"Nightly Subnet A Audit","target_cidr":"10.100.1.0/24","scan_profile":"full_audit"}'

# 01:30 UTC: Scan Subnet B (Finance)
30 1 * * 1-5 endpointguard curl -s -X POST https://api.endpointguard.corp/api/v1/scans \
  -H "Authorization: Bearer $CRON_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"Nightly Subnet B Audit","target_cidr":"10.100.2.0/24","scan_profile":"full_audit"}'

# 02:00 UTC: Scan Subnet C (Servers)
0 2 * * 1-5 endpointguard curl -s -X POST https://api.endpointguard.corp/api/v1/scans \
  -H "Authorization: Bearer $CRON_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"Nightly Subnet C Audit","target_cidr":"10.100.3.0/24","scan_profile":"full_audit"}'
```
