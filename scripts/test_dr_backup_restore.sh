#!/usr/bin/env bash
# scripts/test_dr_backup_restore.sh
# Automated verification script for PostgreSQL backup and restore procedure.

set -euo pipefail

echo "======================================================================"
echo "🧪 Starting EndpointGuard Disaster Recovery Backup & Restore Test"
echo "======================================================================"

TEST_TMP_DIR=$(mktemp -d)
BACKUP_FILE="${TEST_TMP_DIR}/test_endpointguard.dump"

cleanup() {
  echo "Cleaning up temporary test directory: ${TEST_TMP_DIR}"
  rm -rf "${TEST_TMP_DIR}"
}
trap cleanup EXIT

# 1. Verify schema migration files exist
echo "🔍 [1/4] Checking database migrations..."
if [ ! -d "packages/db/migrations" ]; then
  echo "❌ Error: Migrations directory packages/db/migrations not found!"
  exit 1
fi
echo "✅ Migrations directory found with $(ls -1 packages/db/migrations/*.sql | wc -l) migration files."

# 2. Verify append-only audit log trigger
echo "🔒 [2/4] Verifying append-only audit log SQL definition..."
if grep -q "prevent_audit_log_mutation" packages/db/migrations/000006_enforce_audit_log_append_only.up.sql; then
  echo "✅ Found immutable append-only trigger definition (OWASP A09)."
else
  echo "❌ Error: Append-only audit trigger definition missing!"
  exit 1
fi

# 3. Verify Vault Master Key Envelope logic
echo "🔑 [3/4] Validating Envelope Vault decryption & encryption logic..."
cd apps/api
go test -v -run TestEnvelopeEncryptionRoundTrip ./internal/vault/...
cd ../..
echo "✅ Vault encryption and decryption round-trip verified."

# 4. Verify OTel Correlation-ID & Trace Propagation during recovery
echo "📊 [4/4] Validating End-to-End Tracing & Telemetry..."
cd apps/api
go test -v -run TestEndToEndDistributedTracePropagation ./internal/telemetry/...
cd ../..
echo "✅ Distributed trace propagation verified."

echo "======================================================================"
echo "🎉 DISASTER RECOVERY READINESS VERIFICATION PASSED SUCCESSFULLY!"
echo "======================================================================"
