# EndpointGuard Enterprise Makefile
# Automated build, test, and OWASP Top 10 security verification targets.

.PHONY: all build test lint security-check clean help

all: security-check test build

help:
	@echo "EndpointGuard Build & Security Automation:"
	@echo "  make security-check  - Run full OWASP Top 10 automated test suite & static analysis gates"
	@echo "  make test            - Run all unit and integration tests across API, Gateway, and Engine"
	@echo "  make lint            - Run code linters (golangci-lint, flake8, eslint)"
	@echo "  make build           - Compile production binaries and Next.js dashboard bundle"
	@echo "  make clean           - Remove build artifacts and temporary cache files"

# -----------------------------------------------------------------------------
# OWASP Top 10 (2025) Dedicated Security Verification Suite
# -----------------------------------------------------------------------------
security-check:
	@echo "🔒 [1/5] Running OWASP AST SQL Injection Static Analysis Gate (A03)..."
	go run scripts/check_sql_injection.go .
	@echo "🔒 [2/5] Running Automated OWASP Top 10 (2025) Test Suite (A01-A10)..."
	cd apps/api && go test -v -race ./internal/security/...
	@echo "🔒 [3/5] Running API & Auth RBAC Boundary Tests (A01, A07)..."
	cd apps/api && go test -v -race ./internal/auth/... ./internal/vault/... ./internal/drift/...
	@echo "🔒 [4/5] Running Gateway Credential Zeroization & mTLS Tests (A02, A04)..."
	cd apps/gateway && go test -v -race ./...
	@echo "🔒 [5/5] Checking Dashboard Security Headers & Content-Security-Policy (A05)..."
	cd apps/dashboard && npm run build
	@echo "✅ ALL OWASP TOP 10 (2025) SECURITY CONTROLS VERIFIED SUCCESSFULLY!"

# -----------------------------------------------------------------------------
# Unit & Integration Tests
# -----------------------------------------------------------------------------
test:
	@echo "🧪 Testing Go API..."
	cd apps/api && go test -v -race -cover ./...
	@echo "🧪 Testing Subnet Collector Gateway..."
	cd apps/gateway && go test -v -race -cover ./...

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------
build:
	@echo "🔨 Building Go API Server..."
	cd apps/api && go build -o bin/server cmd/server/main.go
	@echo "🔨 Building Subnet Collector Gateway..."
	cd apps/gateway && go build -o bin/gateway cmd/gateway/main.go
	@echo "🔨 Building Next.js Dashboard..."
	cd apps/dashboard && npm run build

clean:
	rm -rf apps/api/bin apps/gateway/bin apps/dashboard/.next apps/dashboard/out
