# EndpointGuard

> **100% Agentless, Open-Source Endpoint Audit, Hardware Inventory & CIS Compliance Platform for Windows 11 and Windows Server.**

EndpointGuard audits, inventories, and verifies security compliance for entire enterprise Windows fleets without installing a single byte of software or agent on target hosts. All discovery and telemetry collection operates remotely via **WinRM / CIM over HTTPS (Port 5986 / 5985)** using native WMI/CIM providers, supplemented by **SSH, SNMPv3, and Redfish REST APIs** for embedded server management controllers (Dell iDRAC, HPE iLO, Supermicro BMC).

---

## 🏛️ System Architecture

```mermaid
graph TD
    subgraph Browser ["User Interface"]
        UI["Next.js 14 Dashboard\n(Accessible, Dark/Charcoal Theme)"]
    end

    subgraph ControlPlane ["Control Plane (Core Cloud / Central Infra)"]
        API["EndpointGuard API\n(Go with go-chi/chi/v5)"]
        Vault["Dedicated Credential Vault\n(Envelope AES-256-GCM / HashiCorp Vault)"]
        DB[("PostgreSQL 15+\nJSONB & Row-Level Security")]
        AuditLog["Immutable ASVS Audit Log\n(Correlation-ID Tracing)"]
        VulnWorker["NVD 2.0 & CISA KEV\nVulnerability Worker"]
        DriftWorker["Configuration Drift &\nHMAC Webhook Engine"]
    end

    subgraph SubnetA ["On-Premises Subnet A (e.g. 10.100.1.0/24)"]
        GW1["Collector Gateway Daemon\n(Go Binary, mTLS 1.3)"]
        SE1["Scan Engine\n(PowerShell 7.4+ / CIM Modules)"]
    end

    subgraph SubnetB ["On-Premises Subnet B (e.g. 10.100.2.0/24)"]
        GW2["Collector Gateway Daemon\n(Go Binary, mTLS 1.3)"]
        SE2["Scan Engine\n(PowerShell 7.4+ / CIM Modules)"]
    end

    subgraph TargetFleet ["Target Endpoints (100% Agentless)"]
        W11["Windows 11 Enterprise\n(WinRM HTTPS / CIM)"]
        WS22["Windows Server 2022/2025\n(WinRM HTTPS / CIM)"]
        BMC["iLO / iDRAC / BMC\n(SNMPv3 / Redfish REST)"]
    end

    UI -->|REST / SSE (JSON)| API
    API -->|Opaque Ref sec_ref_*| Vault
    API <-->|SQL Queries / RLS| DB
    API -->|Write Events| AuditLog
    VulnWorker <-->|Query & Deduplicate| DB
    DriftWorker <-->|Diff Snapshots| DB
    
    GW1 <==>|Mutual TLS 1.3 (mTLS)| API
    GW2 <==>|Mutual TLS 1.3 (mTLS)| API
    
    GW1 --> SE1
    GW2 --> SE2
    
    SE1 -.->|WinRM Port 5986 (WQL / CIM Protocol)| W11
    SE1 -.->|WinRM Port 5986 (WQL / CIM Protocol)| WS22
    SE2 -.->|SNMPv3 / Redfish Port 161 / 443| BMC
```

---

## 🏢 Enterprise Production Deployment Guide

### 1. Network Topology & Port Matrix

Collector Gateways are deployed per-subnet or per-VPC/datacenter boundary, establishing outbound-only **mTLS 1.3** tunnels back to the central Control Plane. Target endpoints never initiate outbound connections.

| Flow / Direction | Protocol | Port | Description |
| :--- | :--- | :--- | :--- |
| **Gateway ➔ Target Hosts** | WinRM HTTPS (Default) | `5986` | Encrypted WS-Management & CIM session transport. |
| **Gateway ➔ Target Hosts** | WinRM HTTP (Kerberos) | `5985` | Kerberos-encrypted HTTP transport (internal LAN fallback). |
| **Gateway ➔ Server BMCs** | SNMPv3 / IPMI | `161` / `623` | Out-of-band hardware telemetry (Dell iDRAC, HPE iLO). |
| **Gateway ➔ Server BMCs** | Redfish HTTPS | `443` | Modern RESTful BMC hardware inventory. |
| **Gateway ➔ Control Plane API** | Mutual TLS 1.3 | `443` / `8080` | Bidirectional encrypted telemetry & job dispatch. |
| **Dashboard ➔ Control Plane API** | HTTPS | `443` / `8080` | REST API with JWT claims & double-submit CSRF. |
| **Control Plane ➔ PostgreSQL** | TLS PostgreSQL | `5432` | Managed DB connection pool with Row-Level Security. |

---

### 2. Control Plane Production Setup

#### A. Central Database & Encryption Keys
1. **PostgreSQL 15+ Cluster**: Provision a High-Availability PostgreSQL cluster (e.g. AWS Aurora PostgreSQL, Azure Flexible Server, or Patroni HA).
2. **Master Key Storage (KMS)**: Generate a 256-bit AES master key and store it in your cloud Key Management Service (AWS KMS, Azure Key Vault, or HashiCorp Vault).
   ```bash
   # Generate 32-byte hex master key
   openssl rand -hex 32
   ```

#### B. API Server Deployment (Kubernetes / ECS / Systemd)
Deploy the Go API as a containerized stateless service:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: endpointguard-api
  namespace: endpointguard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: endpointguard-api
  template:
    metadata:
      labels:
        app: endpointguard-api
    spec:
      containers:
        - name: api
          image: ghcr.io/endpointguard/api:latest
          ports:
            - containerPort: 8080
          env:
            - name: PORT
              value: "8080"
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: endpointguard-secrets
                  key: database-url
            - name: VAULT_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: endpointguard-secrets
                  key: vault-master-key
            - name: JWT_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: endpointguard-secrets
                  key: jwt-secret-key
          readinessProbe:
            httpGet:
              path: /api/v1/health
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
```

#### C. Next.js Dashboard Deployment
Deploy the Next.js frontend with standalone Node.js or edge container:
```bash
cd apps/dashboard
npm run build
node .next/standalone/server.js
```

---

### 3. Collector Gateway Subnet Deployment

Collector Gateways execute as lightweight background daemons (Linux or Windows Server) located within target subnets.

#### Step 1: Request Gateway Certificate (CSR)
```bash
# Generate private key & CSR on gateway host
openssl req -new -newkey rsa:4096 -nodes \
  -keyout gateway.key \
  -out gateway.csr \
  -subj "/CN=gw-subnet-10-100-1-0/O=EndpointGuard"
```

#### Step 2: Register & Approve Gateway via API
```bash
curl -X POST https://api.endpointguard.corp/api/v1/gateways/register \
  -H "Authorization: Bearer <ADMIN_JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "gateway_code": "gw-subnet-10-100-1-0",
    "name": "HQ Workstations Gateway",
    "subnet_cidr": "10.100.1.0/24",
    "csr_pem": "'"$(cat gateway.csr | tr '\n' ' ')"'"
  }'
```

#### Step 3: Run Gateway Daemon (Systemd)
```ini
[Unit]
Description=EndpointGuard Subnet Collector Gateway
After=network.target

[Service]
Type=simple
User=endpointguard
WorkingDirectory=/opt/endpointguard/gateway
ExecStart=/opt/endpointguard/gateway/gateway \
  --config /etc/endpointguard/gateway.yaml
Restart=always
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

---

## 🔒 Handling Restricted & Hardened Endpoints (When PowerShell Is Blocked)

In heavily secured enterprise environments, workstations and servers often enforce strict endpoint hardening:
- **PowerShell Script Execution Policy**: `Restricted` or `AllSigned`.
- **PowerShell Constrained Language Mode (CLM)** (enforced via AppLocker or Device Guard).
- **Windows Defender Application Control (WDAC)** blocking `powershell.exe` execution.
- **Endpoint Detection & Response (EDR)** alerting on `powershell.exe` spawning child processes.

### How EndpointGuard Operates 100% Agentlessly in Hardened Environments:

```
┌────────────────────────────────────────────────────────────────────────────┐
│              Collector Gateway Remote Execution Architecture               │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  [ Gateway Daemon ]                                                        │
│         │                                                                  │
│         ▼ (WinRM HTTPS / Port 5986)                                        │
│  [ WS-Management / CIM Session ]                                          │
│         │                                                                  │
│         ├─► Primary: Native CIM/WMI Protocol (Direct Binary WQL)           │
│         │   └─► Targets `WmiPrvSE.exe` Directly                            │
│         │   └─► ZERO `powershell.exe` Process Spawning                     │
│         │   └─► Immune to CLM, AppLocker, and Script Execution Policies   │
│         │                                                                  │
│         ├─► Secondary: Just Enough Administration (JEA) Restricted Runspace│
│         │   └─► Non-interactive compiled CIM commandlets only              │
│         │                                                                  │
│         └─► Out-of-Band: Redfish REST / SNMPv3 / IPMI                      │
│             └─► Hardware BMC inventory (Dell iDRAC, HPE iLO)               │
└────────────────────────────────────────────────────────────────────────────┘
```

### 1. Native CIM / WMI Protocol Queries (Zero `powershell.exe` Spawning)
EndpointGuard's primary transport utilizes the native **CIM over WS-Management protocol (`WS-Man`)**.
- The gateway connects to the target's `WsmSvc` service and talks directly to the WMI provider host (`WmiPrvSE.exe`).
- **No `powershell.exe` process is ever spawned on the target endpoint.**
- Queries are executed as compiled binary WQL commands (`SELECT * FROM Win32_Bios`, `SELECT * FROM Win32_EncryptableVolume`, `SELECT * FROM MSFT_MpComputerStatus`).
- **Result**: Completely bypasses PowerShell Execution Policies, AppLocker script rules, and Constrained Language Mode (CLM) without triggering EDR script-block heuristics.

### 2. Group Policy Object (GPO) Configuration Template

Deploy this single Active Directory Group Policy Object to enable secure, non-admin agentless scanning across your domain:

#### A. Enable WinRM HTTPS Listener & Windows Firewall Rule
1. **Computer Configuration ➔ Policies ➔ Administrative Templates ➔ Windows Components ➔ Windows Remote Management (WinRM) ➔ WinRM Service**:
   - `Allow remote server management through WinRM`: **Enabled**
   - `IPv4 filter`: `*` (or your Gateway subnet `10.100.1.0/24`)
2. **Computer Configuration ➔ Policies ➔ Windows Settings ➔ Security Settings ➔ Windows Firewall with Advanced Security**:
   - Inbound Rule: Allow TCP port `5986` (and `5985` if using Kerberos) from the Gateway IP.

#### B. Configure Non-Admin Scan Service Account (Least Privilege)
EndpointGuard does **not** require Domain Admin privileges. A dedicated service account (e.g. `svc_endpointguard_audit`) can be granted read-only telemetry permissions:

1. **Add Service Account to Built-in Groups**:
   - `Remote Management Users` (grants WinRM access)
   - `Performance Monitor Users` (grants hardware telemetry access)
2. **Grant WMI Namespace Read Security**:
   Execute once per machine (or via GPO Startup Script) to grant Read & Enable Account on root WMI namespaces:
   ```powershell
   # Grant svc_endpointguard_audit Read/Enable on root/cimv2, root/standardcimv2, and root/Microsoft/Windows/Defender
   $Namespaces = @(
       "root\cimv2",
       "root\standardcimv2",
       "root\Microsoft\Windows\Storage",
       "root\Microsoft\Windows\Defender",
       "root\cimv2\Security\MicrosoftTpm"
   )
   $Account = "CORP\svc_endpointguard_audit"

   foreach ($ns in $Namespaces) {
       $acl = Get-Acl -Path "WMI:\localhost\$ns"
       $rule = New-Object System.Security.AccessControl.WmiAccessRule(
           $Account,
           "Enable,ReadSecurity,MethodExecute",
           "ContainerInherit",
           "None",
           "Allow"
       )
       $acl.AddAccessRule($rule)
       Set-Acl -Path "WMI:\localhost\$ns" -AclObject $acl
   }
   ```

### 3. Just Enough Administration (JEA) Configuration (Optional Maximum Hardening)
For ultra-secure defense or financial environments, create a dedicated JEA endpoint on target hosts restricting the session to specific inventory cmdlets:

```powershell
# /etc/endpointguard/jea/EndpointGuardAudit.pssc
New-PSSessionConfigurationFile -Path "C:\ProgramData\EndpointGuard\EndpointGuardAudit.pssc" `
    -SessionType RestrictedRemoteServer `
    -TranscriptDirectory "C:\ProgramData\EndpointGuard\Transcripts" `
    -RoleDefinitions @{ 'CORP\svc_endpointguard_audit' = @{ RoleCapabilities = 'EndpointGuardAuditCapabilities' } }

# Register the restricted JEA endpoint
Register-PSSessionConfiguration -Name "EndpointGuardAudit" `
    -Path "C:\ProgramData\EndpointGuard\EndpointGuardAudit.pssc" `
    -Force
```

---

## 🧪 Testing & Verification

Run the full automated test suite across all subsystems:

```bash
# 1. Test Control Plane API (Auth, RBAC, Vault, VulnScan, Drift, Handlers)
cd apps/api && go test -v -race ./...

# 2. Test Subnet Collector Gateway (mTLS, Scan Workers, Cache Zeroization)
cd apps/gateway && go test -v -race ./...

# 3. Build & Validate Next.js 14 Dashboard
cd apps/dashboard && npm run build
```

---

## 📄 License
EndpointGuard is enterprise open-source software licensed under the [Apache 2.0 License](LICENSE).
