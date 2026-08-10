# ZeroAgent-Scan EMS: Deployment Prerequisites

This document outlines the prerequisites for deploying ZeroAgent-Scan EMS (EndpointGuard) on a fresh Windows Server 2019 system. All requirements, versions, and configurations listed here are canonical and must be strictly followed for a supported production deployment.

## 1. Version Selection Rationale (Verified August 2026)

> [!WARNING]
> **Staleness Check:** If today's date is after October 2027, re-evaluate these versions against the current Node.js and PostgreSQL release cycles.

The following core dependencies were selected to ensure continuous support through the end of Windows Server 2019's extended support lifecycle (January 9, 2029).

| Component | Selected Version | Release Date | EOL Date | WS2019 Extended Support End |
|-----------|------------------|--------------|----------|-----------------------------|
| **Node.js** | 26.x (LTS Track) | April 2026 | April 30, 2029 | January 9, 2029 |
| **PostgreSQL**| 17.x | Sept 26, 2024| November 2029 | January 9, 2029 |

### Why these versions?
*   **Node.js 26.x**: It is the only LTS-track version whose support window completely covers the WS2019 extended support end date. Node.js 24 LTS (EOL April 30, 2028) falls 9 months short. (Note: Node.js 26.x becomes LTS in October 2026).
*   **PostgreSQL 17.x**: Provides coverage past the WS2019 extended support end date with 10 months of runway, while offering 2 full years of production maturity as of mid-2026. (PostgreSQL 18 has more runway but lacks production exposure).

Other essential tooling:
*   **NSSM**: 2.24 (latest stable)
*   **IIS**: Built-in Windows Server role (requires URL Rewrite 2.1 + Application Request Routing 3.0)
*   **Go**: Not required on the server. The API ships as a pre-compiled binary (`server.exe`).

## 2. Hardware Sizing Recommendations

> [!IMPORTANT]
> **ESTIMATE** — Validate with a production load test before scaling beyond 400 endpoints. No formal load-test results currently exist in the repository.

For an estimated load of ~400 concurrently scanned endpoints and standard dashboard usage:

*   **CPU**: 4 vCPU minimum (8 vCPU recommended for concurrent scan + dashboard load)
*   **RAM**: 16 GB minimum (32 GB recommended to support PostgreSQL `shared_buffers`, the Go API, and the Node.js dashboard)
*   **Disk C (OS/App)**: 100 GB SSD (OS + application binaries + logs)
*   **Disk D (Data)**: 200 GB HDD/SSD (PostgreSQL data + backups + cold-storage archives)
*   **Network**: 1 Gbps NIC minimum

## 3. Operating System Prerequisites

*   **OS**: Windows Server 2019 Standard or Datacenter (build 17763+)
*   **Active Directory**: Server must be domain-joined to Active Directory (required for Kerberos authentication to scan targets).
*   **Windows Features** to enable:
    *   `IIS-WebServerRole`, `IIS-WebServer`, `IIS-ManagementConsole`
    *   `IIS-RequestFiltering`, `IIS-HttpRedirect`
    *   `NetFx4Extended-ASPNET45` (required for IIS modules)
*   **Additional Software** to install:
    *   IIS URL Rewrite Module 2.1
    *   IIS Application Request Routing (ARR) 3.0
    *   Visual C++ Redistributable 2015-2022 (required for Node.js native modules)

## 4. Active Directory Service Account Requirements

Create a dedicated service account **before** running the deployment scripts.

*   **Account Name**: `svc_zeroagent`
*   **Account Type**: Domain user (Must **NOT** be a domain admin)
*   **Required Local Rights** (assigned automatically by `install.ps1` via `secedit` and `icacls`):
    *   Log on as a service
    *   NTFS Modify permission on `C:\apps\zeroagent`
    *   NTFS Read permission on `D:\backups\zeroagent`
    *   NTFS Read/Write permission on `D:\postgres\data`
*   **WinRM Scanning Requirements**:
    *   Read access to target endpoints via WinRM (typically achieved by adding the account to the 'Remote Management Users' group on targets via GPO).
    *   Kerberos delegation rights if scanning across multiple domains.

For more details on the least-privilege design rationale, please refer to [SECURITY.md](SECURITY.md).

## 5. Network Firewall Change Request

Submit the following rules to your network security team. 

| Rule ID | Direction | Source | Destination | Port/Protocol | Justification |
|---------|-----------|--------|-------------|---------------|---------------|
| FW-01 | Inbound | Any | ZeroAgent Server | TCP 443 | HTTPS access to dashboard and API |
| FW-02 | Inbound | Any | ZeroAgent Server | TCP 80 | HTTP-to-HTTPS redirect (optional) |
| FW-03 | Outbound | ZeroAgent Server | Endpoint Subnets | TCP 5986 | WinRM HTTPS for agentless scanning |
| FW-04 | Outbound | ZeroAgent Server | Endpoint Subnets | TCP 5985 | WinRM HTTP (legacy exception only) |
| FW-05 | Outbound | ZeroAgent Server | Endpoint Subnets | TCP 135 | RPC Endpoint Mapper (DCOM/WMI fallback) |
| FW-06 | Outbound | ZeroAgent Server | Endpoint Subnets | TCP 445 | SMB/Named Pipes (WMI transport) |
| FW-07 | Outbound | ZeroAgent Server | Endpoint Subnets | TCP 50000-50100 | Dynamic RPC (narrowed from 49152-65535) |
| FW-08 | Outbound | ZeroAgent Server | Endpoint Subnets | ICMP Type 8 | Host discovery ping |
| FW-09 | Outbound | ZeroAgent Server | Domain Controllers | TCP/UDP 88 | Kerberos authentication |
| FW-10 | Outbound | ZeroAgent Server | DNS Servers | TCP/UDP 53 | DNS resolution |
| FW-11 | Localhost | 127.0.0.1 | 127.0.0.1 | TCP 5432 | PostgreSQL (localhost-only) |

> [!TIP]
> **RPC Port Narrowing Command**: To apply the narrowed RPC dynamic port range (FW-07) on the ZeroAgent Server, run:
> ```powershell
> netsh int ipv4 set dynamicport tcp start=50000 num=100
> ```

## 6. Pre-Flight Checklist

The installer must complete this checklist **before** starting `install.ps1`.

- [ ] **Windows Server 2019 build 17763+ confirmed**
  ```powershell
  [System.Environment]::OSVersion.Version
  ```
- [ ] **Server is domain-joined**
  ```powershell
  (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
  ```
- [ ] **D:\ drive exists with at least 200 GB free**
  ```powershell
  Get-Volume -DriveLetter D
  ```
- [ ] **C:\ drive has at least 50 GB free**
  ```powershell
  Get-Volume -DriveLetter C
  ```
- [ ] **`svc_zeroagent` AD account created** (Verified NOT a domain admin)
- [ ] **Firewall change request approved and rules applied**
- [ ] **SSL/TLS certificate obtained** from Enterprise CA (.pfx file ready) — OR explicit decision made to use self-signed for initial testing.
- [ ] **PostgreSQL 17.x installer downloaded** from postgresql.org
- [ ] **Node.js 26.x installer downloaded** from nodejs.org
- [ ] **NSSM 2.24 zip downloaded** from nssm.cc
- [ ] **`deploy.config.json` reviewed and customized** (database name `endpointguard_prod`, backup paths, webhook URL)
- [ ] **Application release artifact (.zip) available**
- [ ] **DNS record created** pointing to this server (e.g., `zeroagent.corp.local` → server IP)
- [ ] **VAULT_MASTER_KEY_HEX generated** (64 hex characters = 256-bit AES key):
  ```powershell
  -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
  ```
- [ ] **Database password generated** and stored securely in a vault.
- [ ] **Outbound connectivity to endpoint subnets verified**
  ```powershell
  Test-NetConnection -ComputerName <endpoint_ip> -Port 5986
  ```
