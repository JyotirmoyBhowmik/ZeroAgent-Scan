# Network Firewall Change Request Specification

> **Official Firewall Change Request (CR) for EndpointGuard Agentless Security Scanners across Enterprise LAN/WAN Networks.**

---

## 📋 1. Change Request Summary

| Field | Value |
| :--- | :--- |
| **Change Request Title** | Open Inbound Firewall Ports for Agentless EndpointGuard Collector Gateways |
| **Service Description** | Agentless Windows 11 & Windows Server introspection via WinRM HTTPS (5986) & DCOM/RPC |
| **Source Assets** | On-Prem Collector Gateways (e.g. `10.100.1.10`, `10.100.2.10`, `10.100.3.10`) |
| **Destination Assets** | Enterprise Corporate Endpoints (`10.100.0.0/16` Workstations & Servers) |
| **Security Standard** | OWASP ASVS Level 2 / CIS Microsoft Windows Benchmark v3.0.0 |
| **Traffic Direction** | Inbound from Gateway to Target Endpoints (Unidirectional Introspection) |

---

## 🛡️ 2. Core Firewall Change Rules Matrix

### Table 1: Scanner-to-Endpoint Introspection Ports

| Rule # | Source (Gateway IP) | Destination (Subnets) | Protocol | Destination Port(s) | Traffic Classification | Justification & Security Control |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FW-01** | `Collector_Gateways_Group` | `Corporate_Endpoints_Group` | **TCP** | **5986** | **WinRM over HTTPS (Mandatory)** | Primary agentless introspection transport. Encrypted via TLS 1.3/1.2+ certificates. |
| **FW-02** | `Collector_Gateways_Group` | `Legacy_Subnets_Exception` | **TCP** | **5985** | **WinRM over HTTP (Exception Only)** | *Strictly restricted to subnets with signed compliance exceptions.* Session-encrypted via Kerberos GSS-API. |
| **FW-03** | `Collector_Gateways_Group` | `Corporate_Servers_Group` | **TCP** | **135** | **RPC Endpoint Mapper** | Required for DCOM/WMI RPC connection initiation on Windows Server targets. |
| **FW-04** | `Collector_Gateways_Group` | `Corporate_Servers_Group` | **TCP** | **445** | **SMB / Named Pipes** | Required for authenticated IPC$ transport in DCOM environments. |
| **FW-05** | `Collector_Gateways_Group` | `Corporate_Servers_Group` | **TCP** | **49152–65535** *(or 50000–50100)* | **Dynamic RPC High Ports** | Dynamic ports allocated by RPC Endpoint Mapper during WMI queries with Packet Privacy encryption. |
| **FW-06** | `Collector_Gateways_Group` | `Corporate_Endpoints_Group` | **ICMP** | **Echo Request (Type 8)** | **ICMP Ping** | Fast discovery & host liveness detection prior to initiating WinRM handshake. |

---

### Table 2: Scanner-to-Infrastructure Auxiliary Ports

| Rule # | Source (Gateway IP) | Destination (Infra) | Protocol | Destination Port(s) | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FW-07** | `Collector_Gateways_Group` | `Active_Directory_DCs` | **TCP/UDP**| **88** | Active Directory Kerberos Authentication (TGT/TGS negotiation) |
| **FW-08** | `Collector_Gateways_Group` | `Internal_DNS_Servers` | **TCP/UDP**| **53** | Hostname forward and reverse PTR resolution |
| **FW-09** | `Collector_Gateways_Group` | `EndpointGuard_API_VPC`| **TCP** | **443** | Upstream mTLS 1.3 telemetry stream & JIT vault resolution |
| **FW-10** | `Collector_Gateways_Group` | `Enterprise_OTel_Collector`| **TCP** | **4317** | OpenTelemetry gRPC trace and metrics stream |

---

## 💻 3. Active Directory GPO & Windows Firewall Configuration

To automatically apply these rules across all ~400 domain workstations and servers via Active Directory Group Policy (GPO):

### PowerShell GPO Configuration Script

```powershell
<#
.SYNOPSIS
    Configures Windows Defender Firewall rules for EndpointGuard Agentless Gateways.
#>

# Define authorized Collector Gateway IP range
$AuthorizedGateways = "10.100.1.10,10.100.2.10,10.100.3.10"

# 1. Allow Inbound WinRM HTTPS (5986) - Encrypted Transport
New-NetFirewallRule -Name "EndpointGuard-WinRM-HTTPS-In" `
    -DisplayName "EndpointGuard Agentless Scanner - WinRM HTTPS (5986)" `
    -Description "Permits encrypted WMI/CIM queries over TLS 1.3/1.2 from authorized collector gateways." `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5986 `
    -RemoteAddress $AuthorizedGateways `
    -Action Allow `
    -Profile Domain,Private `
    -Enabled True

# 2. Allow Inbound RPC Endpoint Mapper (135) for DCOM Fallback
New-NetFirewallRule -Name "EndpointGuard-RPC-Mapper-In" `
    -DisplayName "EndpointGuard Agentless Scanner - RPC Mapper (135)" `
    -Description "Permits DCOM RPC endpoint mapping for legacy servers." `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 135 `
    -RemoteAddress $AuthorizedGateways `
    -Action Allow `
    -Profile Domain `
    -Enabled True

# 3. Allow Inbound Dynamic RPC Ports (49152-65535) with Packet Privacy Enforcement
New-NetFirewallRule -Name "EndpointGuard-Dynamic-RPC-In" `
    -DisplayName "EndpointGuard Agentless Scanner - Dynamic RPC Ports" `
    -Description "Permits dynamic RPC calls for WMI introspection with Packet Privacy." `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 49152-65535 `
    -RemoteAddress $AuthorizedGateways `
    -Action Allow `
    -Profile Domain `
    -Enabled True

# 4. Allow Inbound ICMP Echo (Ping)
New-NetFirewallRule -Name "EndpointGuard-ICMP-In" `
    -DisplayName "EndpointGuard Agentless Scanner - ICMP Ping" `
    -Direction Inbound `
    -Protocol ICMPv4 `
    -IcmpType 8 `
    -RemoteAddress $AuthorizedGateways `
    -Action Allow `
    -Profile Domain,Private `
    -Enabled True
```

---

## 🔒 4. Narrowing Dynamic RPC Ports (Optional Server Hardening)

If corporate security policy prohibits the default dynamic RPC port range (`49152–65535`), Windows RPC can be pinned to a narrower fixed port range (e.g. `50000–50100`):

```powershell
# Restrict RPC dynamic ports to a 100-port range
netsh int ipv4 set dynamicport tcp start=50000 num=100
```
