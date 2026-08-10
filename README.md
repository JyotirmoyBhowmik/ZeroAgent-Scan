# EndpointGuard

> **100% Agentless, Open-Source Endpoint Audit, Hardware Inventory & CIS Compliance Platform for Windows 11 and Windows Server.**

EndpointGuard audits, inventories, and verifies security compliance for entire enterprise Windows fleets without installing a single byte of software or agent on target hosts. All discovery and telemetry collection operates remotely via **WinRM / CIM over HTTPS (Port 5986 / 5985)** using native WMI/CIM providers, supplemented by **SSH, SNMPv3, and Redfish REST APIs** for embedded server management controllers (Dell iDRAC, HPE iLO, Supermicro BMC, Lenovo XClarity).

---

## 🏛️ System Architecture

```mermaid
graph TD
    subgraph Browser ["User Interface & Security Operations"]
        UI["Next.js 14 Dashboard\n(Pure White & Charcoal Black Theme / Accessible)"]
    end

    subgraph ControlPlane ["Control Plane (Core Cloud / Central Infra)"]
        API["EndpointGuard API\n(Go with go-chi/chi/v5)"]
        Vault["Dedicated Credential Vault\n(AES-256-GCM Envelope Encryption / HashiCorp Vault)"]
        DB[("PostgreSQL 15+\nJSONB & Row-Level Security")]
        AuditLog["Immutable ASVS Audit Log\n(Correlation-ID Tracing)"]
        VulnWorker["NVD 2.0 & CISA KEV\nVulnerability Worker"]
        DriftWorker["Configuration Drift &\nHMAC-Signed Webhooks"]
        OIDC["Enterprise OIDC & SCIM 2.0\n(Entra ID / Okta / Keycloak)"]
    end

    subgraph SubnetA ["On-Premises Subnet A (e.g. 10.100.1.0/24)"]
        GW1["Collector Gateway Daemon\n(Go Binary, mTLS 1.3)"]
        SE1["Scan Engine\n(PowerShell 7.4+ / Native CIM Modules)"]
    end

    subgraph SubnetB ["On-Premises Subnet B (e.g. 10.100.2.0/24)"]
        GW2["Collector Gateway Daemon\n(Go Binary, mTLS 1.3)"]
        SE2["Scan Engine\n(PowerShell 7.4+ / Native CIM Modules)"]
    end

    subgraph TargetFleet ["Target Fleet (100% Agentless Endpoints)"]
        W11["Windows 11 Enterprise\n(WinRM HTTPS 5986 / CIM)"]
        WS22["Windows Server 2022/2025\n(WinRM HTTPS 5986 / CIM)"]
        BMC["iLO / iDRAC / BMC\n(SNMPv3 / Redfish REST 443)"]
    end

    UI -->|REST / SSE (JSON) + CSRF| API
    API -->|Opaque Ref sec_ref_*| Vault
    API <-->|SQL Queries / RLS| DB
    API -->|Write Events| AuditLog
    API <-->|SSO & SCIM Sync| OIDC
    VulnWorker <-->|Query & Deduplicate| DB
    DriftWorker <-->|Diff Snapshots| DB
    
    GW1 <==>|Mutual TLS 1.3 (Outbound Only)| API
    GW2 <==>|Mutual TLS 1.3 (Outbound Only)| API
    
    GW1 --> SE1
    GW2 --> SE2
    
    SE1 -.->|WinRM Port 5986 (Native CIM Protocol / WQL)| W11
    SE1 -.->|WinRM Port 5986 (Native CIM Protocol / WQL)| WS22
    SE2 -.->|SNMPv3 / Redfish Port 161 / 443| BMC
```

---

## 🏢 Enterprise Production Deployment Architecture

Deploying EndpointGuard in a Fortune 500 or heavily regulated environment (finance, healthcare, defense) follows a multi-tiered, zero-trust network segregation model.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 ENTERPRISE NETWORK TOPOLOGY                            │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   [ Cloud / Management VPC ]                                                           │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │  Application Load Balancer (ALB / F5 BIG-IP)                                   │   │
│   │    │                                                                           │   │
│   │    ├──► Next.js Dashboard Pods (Port 3000)                                     │   │
│   │    └──► Go API Control Plane Cluster (Port 8080)                               │   │
│   │           │                                                                    │   │
│   │           ├──► AWS KMS / Azure Key Vault (Master Key Envelope Encryption)      │   │
│   │           ├──► Multi-AZ PostgreSQL 15+ Cluster (with Read Replicas & RLS)      │   │
│   │           └──► Enterprise IdP (Microsoft Entra ID / Okta via OIDC & SCIM)      │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
│          ▲ (Outbound-only mTLS 1.3 over TCP 443 / 8080)                                │
│          │                                                                             │
│   [ Datacenter / Branch Office Subnets ]                                               │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │  Subnet Collector Gateway Cluster (Active/Passive HA or Per-VLAN Pod)          │   │
│   │    │                                                                           │   │
│   │    ├──► Target Subnet A (10.100.1.0/24): WinRM HTTPS Port 5986 (Direct CIM)    │   │
│   │    ├──► Target Subnet B (10.100.2.0/24): WinRM HTTPS Port 5986 (Direct CIM)    │   │
│   │    └──► Out-of-Band Network (192.168.10.0/24): Redfish REST Port 443 / SNMPv3   │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 1. Enterprise Network Ingress & Egress Port Matrix

Collector Gateways initiate **outbound-only connections** to the Control Plane API. Target hosts never communicate directly with the central API, eliminating cross-segment firewall traversal issues.

| Source | Destination | Protocol | Port | Purpose / Security Context |
| :--- | :--- | :--- | :--- | :--- |
| **Collector Gateway** | **Control Plane API** | Mutual TLS 1.3 | `443` / `8080` | Encrypted scan dispatch, heartbeats, and telemetry streaming. Zero inbound ports on Gateway. |
| **Collector Gateway** | **Windows Endpoints** | WinRM HTTPS (Default) | `5986` | Encrypted WS-Management & CIM session transport. TLS certificate verification. |
| **Collector Gateway** | **Windows Endpoints** | WinRM HTTP (Kerberos) | `5985` | Internal fallback; payloads are encrypted at message layer with Kerberos session keys (GSS-API). |
| **Collector Gateway** | **Server BMCs (iLO/iDRAC)** | Redfish REST / HTTPS | `443` | Modern RESTful hardware inventory for rack/blade servers. |
| **Collector Gateway** | **Server BMCs (iLO/iDRAC)** | SNMPv3 / IPMI | `161` / `623` | Encrypted hardware telemetry (AuthPriv HMAC-SHA256 + AES-128). |
| **Client Browser** | **Next.js Dashboard** | HTTPS | `443` | Web UI access with strict Content Security Policy (CSP). |
| **Control Plane API** | **PostgreSQL Cluster** | TLS PostgreSQL | `5432` | Managed DB connection pool with Row-Level Security tenant isolation. |
| **Control Plane API** | **Enterprise KMS / Vault** | HTTPS | `443` / `8200` | Envelope master key unwrapping & secret resolution. |

---

### 2. High-Availability (HA) Control Plane Setup

#### A. Central Database Cluster (PostgreSQL 15+)
1. Deploy PostgreSQL across multiple Availability Zones with automated failover (e.g. AWS Aurora PostgreSQL, Azure Database for PostgreSQL Flexible Server, or Patroni on Linux VMs).
2. Apply database migrations:
   ```bash
   # Run all database schema migrations
   migrate -path packages/db/migrations -database "postgres://user:pass@pg-cluster.corp:5432/endpointguard?sslmode=verify-full" up
   ```

#### B. Kubernetes Production Deployment (`api-deployment.yaml`)
Deploy stateless Go API pods behind an ingress controller or cloud load balancer:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: endpointguard-api
  namespace: endpointguard
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: endpointguard-api
  template:
    metadata:
      labels:
        app: endpointguard-api
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - endpointguard-api
                topologyKey: "topology.kubernetes.io/zone"
      containers:
        - name: api
          image: ghcr.io/endpointguard/api:v1.0.0
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
              name: http
          env:
            - name: PORT
              value: "8080"
            - name: SERVICE_NAME
              value: "endpointguard-api"
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
          resources:
            requests:
              cpu: "500m"
              memory: "512Mi"
            limits:
              cpu: "2000m"
              memory: "2Gi"
          readinessProbe:
            httpGet:
              path: /api/v1/health
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /api/v1/health
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 20
```

#### C. Next.js Production Frontend Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: endpointguard-dashboard
  namespace: endpointguard
spec:
  replicas: 2
  selector:
    matchLabels:
      app: endpointguard-dashboard
  template:
    metadata:
      labels:
        app: endpointguard-dashboard
    spec:
      containers:
        - name: dashboard
          image: ghcr.io/endpointguard/dashboard:v1.0.0
          ports:
            - containerPort: 3000
          env:
            - name: NEXT_PUBLIC_API_URL
              value: "https://api.endpointguard.corp.local/api/v1"
```

---

### 3. Collector Gateway Subnet Installation (Linux / Windows Service)

Collector Gateways can be deployed on a lightweight Linux VM (Ubuntu 22.04 / RHEL 9) or Windows Server within each target subnet.

#### Step 1: Generate mTLS Private Key & CSR
```bash
# Generate 4096-bit RSA key and CSR
openssl req -new -newkey rsa:4096 -nodes \
  -keyout /etc/endpointguard/gateway.key \
  -out /etc/endpointguard/gateway.csr \
  -subj "/CN=gw-subnet-10-100-1-0/O=EndpointGuard"
```

#### Step 2: Register & Approve Gateway via API
```bash
curl -X POST https://api.endpointguard.corp.local/api/v1/gateways/register \
  -H "Authorization: Bearer <ADMIN_JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "gateway_code": "gw-subnet-10-100-1-0",
    "name": "HQ Corporate Workstations Subnet",
    "subnet_cidr": "10.100.1.0/24",
    "csr_pem": "'"$(cat /etc/endpointguard/gateway.csr | tr '\n' ' ')"'"
  }'
```

#### Step 3: Run as a Systemd Service (`/etc/systemd/system/endpointguard-gateway.service`)
```ini
[Unit]
Description=EndpointGuard Subnet Collector Gateway Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=endpointguard
Group=endpointguard
WorkingDirectory=/opt/endpointguard/gateway
ExecStart=/opt/endpointguard/gateway/gateway \
  --api-url "https://api.endpointguard.corp.local/api/v1" \
  --gateway-code "gw-subnet-10-100-1-0" \
  --cert "/etc/endpointguard/gateway.crt" \
  --key "/etc/endpointguard/gateway.key" \
  --max-concurrent-scans 50
Restart=always
RestartSec=5s
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/endpointguard/gateway/cache

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now endpointguard-gateway
```

---

## 🔒 Handling Restricted & Hardened Endpoints (When PowerShell Is Blocked)

In high-security enterprise environments, workstations and servers frequently enforce stringent endpoint hardening:
1. **PowerShell Script Execution Policy**: Set to `Restricted` or `AllSigned` via GPO.
2. **PowerShell Constrained Language Mode (CLM)**: Enforced via AppLocker or Windows Defender Application Control (WDAC).
3. **`powershell.exe` Process Execution Blocked**: Software Restriction Policies or AppLocker blocking `powershell.exe`, `pwsh.exe`, and `powershell_ise.exe`.
4. **EDR Script-Block Heuristics**: CrowdStrike Falcon, Microsoft Defender for Endpoint, or SentinelOne alerting on interactive `powershell.exe` execution or encoded commands (`-enc`).

---

### How EndpointGuard Bypasses PowerShell Restrictions 100% Agentlessly

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│               EndpointGuard Protocol Decoupling Architecture                           │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   [ Collector Gateway Daemon (Go / WS-Man Client) ]                                    │
│         │                                                                              │
│         ▼ (WinRM HTTPS Port 5986 / 5985)                                               │
│   [ Windows Remote Management Service (`WsmSvc.dll`) on Target Host ]                  │
│         │                                                                              │
│         ├─► [ PRIMARY ] Native CIM / WMI Protocol (Direct Binary WQL)                  │
│         │   │                                                                          │
│         │   ├──► Talk directly to WMI Service Host (`WmiPrvSE.exe`)                    │
│         │   ├──► Executed by native C++ WMI Providers (`cimwin32.dll`, `fveapi.dll`)  │
│         │   ├──► ZERO `powershell.exe` or `cmd.exe` process spawned                   │
│         │   └──► IMMUNE to AppLocker, CLM, and PowerShell Execution Policies           │
│         │                                                                              │
│         ├─► [ SECONDARY ] Just Enough Administration (JEA) Restricted Runspace         │
│         │   │                                                                          │
│         │   ├──► Connects to locked-down endpoint (`EndpointGuardAudit`)               │
│         │   └──► Non-interactive pre-compiled CIM cmdlets only (No language syntax)    │
│         │                                                                              │
│         └─► [ OUT-OF-BAND ] Redfish REST API & SNMPv3 (Hardware BMCs)                  │
│             │                                                                          │
│             └──► Direct HTTPS queries to Dell iDRAC / HPE iLO (Bypasses OS entirely)   │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### Transport 1: Native CIM/WMI Protocol (Zero `powershell.exe` Process Spawning)

EndpointGuard's default engine communicates with target Windows endpoints using the **WS-Management (WS-Man) protocol** to query the native Windows Management Instrumentation (WMI) infrastructure directly:

- The Gateway creates a remote `CimSession` over WinRM port `5986`.
- The target's `WsmSvc` daemon delegates WQL queries directly to the Windows Management Instrumentation host process (`WmiPrvSE.exe`).
- **No interactive shell or `powershell.exe` executable is ever invoked on the target.**
- Queries are executed by native Windows C++ providers loaded inside `WmiPrvSE.exe`:
  - `root\cimv2` ➔ `Win32_Bios`, `Win32_Processor`, `Win32_PhysicalMemory`, `Win32_DiskDrive`
  - `root\Microsoft\Windows\Storage` ➔ `MSFT_Disk`, `MSFT_PhysicalDisk`, `MSFT_Partition`
  - `root\cimv2\Security\MicrosoftVolumeEncryption` ➔ `Win32_EncryptableVolume` (BitLocker)
  - `root\Microsoft\Windows\Defender` ➔ `MSFT_MpComputerStatus` (Defender Antivirus)
  - `root\cimv2\Security\MicrosoftTpm` ➔ `Win32_Tpm` (TPM 2.0 PCR0 & PCR7 Hashes)
- **Result**: Because no PowerShell scripts or executables run on the endpoint, **AppLocker script rules, WDAC policies, Constrained Language Mode (CLM), and `Set-ExecutionPolicy Restricted` are completely bypassed legally without generating suspicious EDR process-spawn alerts.**

---

### Transport 2: Active Directory Group Policy (GPO) Automated Deployment

Apply the following standard Group Policy Object (GPO) across your Active Directory Domain to enable secure, non-admin remote CIM auditing:

#### A. Configure WinRM HTTPS Listener via GPO
1. **Computer Configuration ➔ Policies ➔ Administrative Templates ➔ Windows Components ➔ Windows Remote Management (WinRM) ➔ WinRM Service**:
   - `Allow remote server management through WinRM`: **Enabled**
   - `IPv4 filter`: `*` (or restrict to your Collector Gateway IP: `10.100.1.50`)
2. **Computer Configuration ➔ Policies ➔ Windows Settings ➔ Security Settings ➔ System Services**:
   - `Windows Remote Management (WS-Management)`: **Automatic**

#### B. Configure Windows Defender Firewall Rules via GPO
1. **Computer Configuration ➔ Policies ➔ Windows Settings ➔ Security Settings ➔ Windows Defender Firewall with Advanced Security ➔ Inbound Rules**:
   - **New Rule**: Predefined ➔ `Windows Remote Management`
   - Specific Ports: Allow TCP `5986` (WinRM HTTPS) and TCP `5985` (WinRM HTTP Kerberos) from the Collector Gateway subnet.

#### C. Grant Least-Privilege Non-Admin Service Account Permissions
EndpointGuard does **not** require Domain Admin credentials. You can provision a dedicated service account (e.g. `CORP\svc_endpointguard_audit`) with least-privilege telemetry rights:

1. **Add Service Account to Built-in Groups via GPO (Restricted Groups)**:
   - `Remote Management Users` (grants WinRM connection rights)
   - `Performance Monitor Users` (grants hardware telemetry access)

2. **Automated GPO Startup Script: Grant Root WMI Read & Enable Permissions**:
   Deploy this PowerShell script as a GPO Computer Startup Script to grant namespace permissions automatically across all endpoints:

```powershell
<#
.SYNOPSIS
    Configures least-privilege WMI security permissions for EndpointGuard Agentless Audit.
.DESCRIPTION
    Grants ReadSecurity, Enable, and MethodExecute permissions on required WMI namespaces
    without requiring local Administrator privileges.
#>
[CmdletBinding()]
param(
    [string]$AuditAccount = "CORP\svc_endpointguard_audit"
)

$Namespaces = @(
    "root\cimv2",
    "root\standardcimv2",
    "root\Microsoft\Windows\Storage",
    "root\Microsoft\Windows\Defender",
    "root\cimv2\Security\MicrosoftTpm",
    "root\cimv2\Security\MicrosoftVolumeEncryption"
)

# Translate Account to SID
$objUser = New-Object System.Security.Principal.NTAccount($AuditAccount)
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value

foreach ($ns in $Namespaces) {
    if (Test-Path "WMI:\localhost\$ns") {
        Write-Host "Configuring WMI ACL for namespace: $ns"
        $invPath = "WMI:\localhost\$ns"
        $acl = Get-Acl -Path $invPath
        
        # Access mask: 0x21 (Enable Account | Read Security)
        $wmiRule = New-Object System.Security.AccessControl.WmiAccessRule(
            $objUser,
            "Enable,ReadSecurity,MethodExecute",
            "ContainerInherit",
            "None",
            "Allow"
        )
        
        $acl.AddAccessRule($wmiRule)
        Set-Acl -Path $invPath -AclObject $acl
    }
}
```

---

### Transport 3: Just Enough Administration (JEA) Maximum Hardening

In ultra-hardened environments (DoD, air-gapped networks, financial trading networks), you can enforce Just Enough Administration (JEA). JEA restricts remote connections to a non-interactive virtual account that can only execute pre-approved CIM read cmdlets:

#### Step 1: Create JEA Role Capability File (`EndpointGuardAudit.psrc`)
```powershell
# C:\Program Files\WindowsPowerShell\Modules\EndpointGuardJEA\RoleCapabilities\EndpointGuardAudit.psrc
@{
    Author = "EndpointGuard Security Team"
    Description = "Read-only CIS Benchmark and Hardware Inventory capabilities"
    VisibleCmdlets = @(
        'Get-CimInstance',
        'Get-CimSession',
        'Get-BitLockerVolume',
        'Get-MpComputerStatus',
        'Get-NetFirewallProfile',
        'Get-HotFix',
        'Get-LocalGroupMember'
    )
    VisibleFunctions = @()
    VisibleExternalCommands = @()
    LanguageMode = 'RestrictedLanguage'
}
```

#### Step 2: Register JEA Session Configuration (`Register-JEA.ps1`)
```powershell
New-PSSessionConfigurationFile -Path "C:\ProgramData\EndpointGuard\EndpointGuardAudit.pssc" `
    -SessionType RestrictedRemoteServer `
    -TranscriptDirectory "C:\ProgramData\EndpointGuard\Transcripts" `
    -RoleDefinitions @{
        'CORP\svc_endpointguard_audit' = @{ RoleCapabilities = 'EndpointGuardAudit' }
    }

Register-PSSessionConfiguration -Name "EndpointGuardAudit" `
    -Path "C:\ProgramData\EndpointGuard\EndpointGuardAudit.pssc" `
    -Force
```

---

## 🧪 Triple-Layer Testing & Verification

Validate the entire workspace before staging or production deployments:

```bash
# 1. Test Control Plane API (Auth, RBAC, Vault, VulnScan, Drift, Keyset Pagination, OpenAPI)
cd apps/api && go test -v -race ./...

# 2. Test Subnet Collector Gateway (mTLS, Scan Worker Pool, Credential Zeroization)
cd ../../apps/gateway && go test -v -race ./...

# 3. Test Scan Engine PowerShell Modules
pwsh -Command "Invoke-Pester -Path packages/scan-engine/powershell/tests"

# 4. Build & Typecheck Next.js 14 Dashboard
cd ../../apps/dashboard && npm run build
```

---

## 📄 License
EndpointGuard is open-source software licensed under the [Apache 2.0 License](LICENSE).
