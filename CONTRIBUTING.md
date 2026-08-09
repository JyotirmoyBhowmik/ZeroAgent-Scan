# Contributing to EndpointGuard

Thank you for contributing to EndpointGuard! As an enterprise-grade, agentless security and compliance platform, we enforce rigorous standards around security, code quality, resilience, and testing.

---

## 🌳 Branching Strategy

We follow a **Trunk-Based Development** model with short-lived feature branches:

- **`main`**: Always releasable, production-ready branch. Direct pushes to `main` are blocked.
- **`feat/<issue-id>-<short-description>`**: New features, API endpoints, or scan engine modules.
- **`fix/<issue-id>-<short-description>`**: Bug fixes and stability improvements.
- **`sec/<cve-or-advisory>-<description>`**: Security fixes and vulnerability remediations (prioritized review).
- **`refactor/<description>`**: Non-functional code improvements.

### Commit Guidelines
We use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat(api): add CIM Win32_EncryptableVolume parser`
- `fix(gateway): enforce connection timeout on dead WinRM endpoints`
- `sec(vault): enforce HKDF salt rotation on secret envelope`
- `test(dashboard): add unit tests for hardware tree viewer`
- `docs(readme): clarify mTLS gateway handshake requirements`

---

## 📋 Pull Request Review Checklist

Before opening or approving a Pull Request, verify every item below:

### 1. Security & OWASP ASVS Level 2
- [ ] **No Secrets in Code or Logs**: No API keys, passwords, private keys, or credentials committed or emitted in log statements.
- [ ] **Strict Input Validation**: All external parameters (query params, JSON payloads, headers, subnet CIDRs) pass through schema validators (`Zod` for TS, strict DTO structs with regex/range checks for Go/Python).
- [ ] **Parameterized Queries**: All database queries are 100% parameterized via `sqlc` / `pgx` or `sqlalchemy` parameterized statements. No raw SQL string interpolation.
- [ ] **SSRF Protections**: Target scan ranges are validated against banned loopback/metadata addresses (`169.254.169.254`, `127.0.0.0/8`).
- [ ] **Sanitized Error Responses**: API error payloads contain only `{ timestamp, status_code, error_code, correlation_id, message }` without internal file paths or raw DB exceptions.

### 2. Resilience & Resource Safety
- [ ] **Explicit Timeouts**: Every network socket, HTTP call, WinRM session, and DB query has an explicit context deadline/timeout.
- [ ] **Resource Cleanup**: All connections, channels, goroutines, and file handles are explicitly closed via `defer` / `try-finally`.
- [ ] **Pagination Enforced**: Database list queries enforce `LIMIT` and `OFFSET` / cursor pagination.

### 3. Observability
- [ ] **Correlation ID**: Passed through context and logged in every handler and asynchronous task.
- [ ] **Structured Logs**: Logs use structured JSON format (`timestamp`, `level`, `correlation_id`, `service`, `event`).

### 4. Testing & QA
- [ ] **Unit Tests Included**: Business logic and parsing engines have corresponding unit tests.
- [ ] **Edge Cases Covered**: Null payloads, malformed WMI XML, unreachable hosts, and timeout behavior tested.
- [ ] **CI Passing**: All linter, unit test, and security scan steps (`gosec`, `bandit`, `npm audit`) pass without warnings.

---

## 💻 Local Development Workflow

### 1. Set Up Monorepo
```bash
# Clone the repository
git clone https://github.com/endpointguard/endpointguard.git
cd endpointguard

# Start local infrastructure (Postgres)
docker compose up -d postgres
```

### 2. Working on the Go API (`/apps/api`)
```bash
cd apps/api
cp .env.example .env
go mod download
go test -v -race ./...
go run cmd/server/main.go
```

### 3. Working on the Subnet Gateway (`/apps/gateway`)
```bash
cd apps/gateway
cp .env.example .env
go mod download
go test -v -race ./...
go run cmd/gateway/main.go
```

### 4. Working on the Next.js Dashboard (`/apps/dashboard`)
```bash
cd apps/dashboard
cp .env.example .env.local
pnpm install
pnpm dev
```

### 5. Running Security Scanners Locally
```bash
# Run Go security scanner
gosec -quiet ./apps/...

# Run Python security scanner
bandit -r packages/scan-engine/python/

# Run Frontend dependency audit
cd apps/dashboard && pnpm audit
```
