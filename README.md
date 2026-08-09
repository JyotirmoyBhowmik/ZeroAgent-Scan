# EndpointGuard

> **100% Agentless, Open-Source Endpoint Audit, Hardware Inventory & CIS Compliance Platform for Windows 11 and Windows Server.**

EndpointGuard audits, inventories, and verifies security compliance for entire enterprise Windows fleets without installing a single byte of software or agent on target hosts. All discovery and telemetry collection operates remotely via **WinRM / CIM over HTTPS (Port 5986 / 5985)** using native WMI/CIM providers, supplemented by **SSH and SNMPv3** for embedded server management controllers (Dell iDRAC, HPE iLO, Supermicro BMC).

---

## 🏛️ System Architecture

```mermaid
graph TD
    subgraph Browser ["User Interface"]
        UI["Next.js 14 Dashboard\n(Pure White & Charcoal Black Theme)"]
    end

    subgraph ControlPlane ["Control Plane (Core Cloud / Central Infra)"]
        API["EndpointGuard API\n(Go with go-chi/chi/v5)"]
        Vault["Dedicated Credential Vault\n(AES-256-GCM Envelope Encryption)"]
        DB[("PostgreSQL 15+\nJSONB & Row-Level Security")]
        AuditLog["Immutable ASVS Audit Log\n(Correlation-ID Tracing)"]
    end

    subgraph SubnetA ["On-Premises Subnet (e.g. 10.100.1.0/24)"]
        GW1["Collector Gateway Daemon\n(Go Binary)"]
        SE1["Scan Engine\n(PowerShell / Python Modules)"]
    end

    subgraph SubnetB ["On-Premises Subnet (e.g. 10.100.2.0/24)"]
        GW2["Collector Gateway Daemon\n(Go Binary)"]
        SE2["Scan Engine\n(PowerShell / Python Modules)"]
    end

    subgraph TargetFleet ["Target Endpoints (100% Agentless)"]
        W11["Windows 11 Enterprise\n(WinRM HTTPS / CIM)"]
        WS22["Windows Server 2022/2025\n(WinRM HTTPS / CIM)"]
        BMC["iLO / iDRAC / BMC\n(SNMPv3 / SSH)"]
    end

    UI -->|REST / SSE (JSON)| API
    API -->|Opaque Ref sec_ref_*| Vault
    API <-->|SQL Queries / RLS| DB
    API -->|Write Events| AuditLog
    
    GW1 <==>|Mutual TLS 1.3 (mTLS)| API
    GW2 <==>|Mutual TLS 1.3 (mTLS)| API
    
    GW1 --> SE1
    GW2 --> SE2
    
    SE1 -.->|WinRM Port 5986 (WQL / CIM)| W11
    SE1 -.->|WinRM Port 5986 (WQL / CIM)| WS22
    SE2 -.->|SNMPv3 / IPMI Port 161/22| BMC
```

---

## 📂 Monorepo Structure

```
├── /apps
│   ├── /dashboard          # Next.js 14 (App Router, TypeScript, Crisp White & Charcoal Black Theme)
│   ├── /api                # Go Control Plane API (using go-chi/chi/v5)
│   └── /gateway            # Go On-Prem Subnet Collector Gateway daemon (mTLS to API)
├── /packages
│   ├── /scan-engine        # PowerShell & Python agentless modules (WinRM, CIM, CIS rules, SNMP)
│   └── /db                 # PostgreSQL 15+ schema, RLS policies, golang-migrate SQL migrations
├── /infra
│   ├── docker-compose.yml  # Full local dev stack (Postgres, API, Dashboard, Gateway)
│   └── /terraform          # Production Cloud IaC stubs (AWS/Azure VPC, RDS, ECS/EKS)
├── .github/workflows/ci.yml # GitHub Actions CI: lint, test, gosec, bandit, npm audit
├── CONTRIBUTING.md          # Branch strategy, PR checklist, ASVS Level 2 requirements
└── docker-compose.yml       # Root convenience symlink to /infra/docker-compose.yml
```

---

## ⚖️ Router Selection: Why `go-chi/chi/v5` over Fiber?

For EndpointGuard's Control Plane API, **`go-chi/chi/v5`** was selected over Fiber for the following critical architectural and security reasons:

| Architectural Metric | `go-chi/chi/v5` (Selected) | Fiber (`fasthttp`) | Rationale for EndpointGuard |
| :--- | :--- | :--- | :--- |
| **Standard Library Compatibility** | 100% `net/http.Handler` compliant | Custom `fasthttp` request context | Native integration with Go's `crypto/tls` (crucial for per-subnet mTLS gateway certificate extraction). |
| **Context & Tracing** | Zero-copy `context.Context` propagation | Custom non-standard context lifecycle | Strict OWASP ASVS Rule 4.2 requires propagating `Correlation-ID` seamlessly across DB queries, logger, and async tasks. |
| **Memory Safety & Concurrency** | Idiomatic Go goroutine-safe memory | Unsafe byte buffer pooling | Eliminates race condition hazards and memory corruption when processing large concurrent WMI/CIM scan payloads. |
| **Security Middleware Ecosystem** | Native Go ecosystem (`cors`, `rate`, `csrf`) | Fiber-only adapter middleware | Enables battle-tested standard security filters and zero third-party lock-in. |

---

## 🛡️ OWASP ASVS Level 2 Security Architecture

1. **Zero-Plaintext Vault Service**:
   - Credentials never touch the database or log streams in plaintext.
   - Secrets are envelope-encrypted using **AES-256-GCM** with keys derived via **HKDF-SHA256**.
   - Target scan profiles reference secrets strictly through opaque identifiers (`sec_ref_winrm_finance_01`).
   - Transient scan workers in the Gateway decrypt credentials exclusively in-memory for the duration of the WS-Man session.
2. **mTLS Subnet Gateway Authentication**:
   - Per-subnet Collector Gateways establish bidirectional **Mutual TLS 1.3** tunnels with the Control Plane.
   - Client certificate serials and SANs are verified against the gateway registry on every request.
3. **Defense Against Injection & SSRF**:
   - 100% parameterized SQL queries (strictly no raw string concatenation).
   - Strict subnet and IP boundary validation to prevent SSRF against cloud instance metadata endpoints (`169.254.169.254`).
4. **Structured JSON Logging & Redaction**:
   - Every log entry emits ISO-8601 timestamps, log level, caller, correlation ID, and automatic regex redaction for keys, tokens, and hashes.

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- **Docker** & **Docker Compose** v2+
- **Go** 1.22+ (for local backend development)
- **Node.js** 20+ & **pnpm** (for dashboard development)
- **Python** 3.11+ & **PowerShell Core 7+** (for scan-engine development)

### 1. Launch with Docker Compose
```bash
# Clone the repository
git clone https://github.com/endpointguard/endpointguard.git
cd endpointguard

# Spin up Postgres, API, Dashboard, and Subnet Gateway
docker compose up --build
```

- **Dashboard UI**: [http://localhost:3000](http://localhost:3000)
- **Control Plane API**: [http://localhost:8080](http://localhost:8080)
- **OpenAPI Swagger Docs**: [http://localhost:8080/swagger](http://localhost:8080/swagger)
- **PostgreSQL**: `localhost:5432` (`endpointguard` / `postgres`)

---

### 2. Run Services Individually

#### A. PostgreSQL Database
```bash
docker compose up -d postgres
```

#### B. Control Plane API (`/apps/api`)
```bash
cd apps/api
cp .env.example .env
go run cmd/server/main.go
```

#### C. Subnet Collector Gateway (`/apps/gateway`)
```bash
cd apps/gateway
cp .env.example .env
go run cmd/gateway/main.go
```

#### D. Next.js 14 Dashboard (`/apps/dashboard`)
```bash
cd apps/dashboard
cp .env.example .env.local
pnpm install
pnpm dev
```

---

## 🧪 Testing & Verification

Run the full triple-layer test suite across all workspaces:

```bash
# Test Go API & Gateway
cd apps/api && go test -v -race ./...
cd ../../apps/gateway && go test -v -race ./...

# Test Scan Engine (Python CIS / WinRM parsers)
cd ../../packages/scan-engine/python
pytest tests/ -v

# Test Next.js Dashboard
cd ../../../apps/dashboard
pnpm test
pnpm build
```

---

## 📄 License
EndpointGuard is open-source software licensed under the [Apache 2.0 License](LICENSE).
