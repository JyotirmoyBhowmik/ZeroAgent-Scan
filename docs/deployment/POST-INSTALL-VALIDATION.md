# Production Go/No-Go Validation Checklist

This checklist validates that a ZeroAgent-Scan deployment is fully operational before declaring it production-ready. Do not go live until every box is checked. Each failed item is a deployment blocker.

- Reviewer Name: _______________
- Date: _______________
- Server FQDN: _______________
- Deployment Version: _______________

## 1. Production Readiness Audit (No Demo/Seed Data)
- [ ] Run the production readiness check via CLI:
  ```powershell
  C:\apps\zeroagent\api\server.exe --readiness-check
  ```
  **Pass criteria**: All 6 pillars report PASS. Exit code 0.
  **Fail action**: If DEMO_HYGIENE fails, demo data exists in the database. Query:
  ```sql
  SELECT id, hostname, ip_address FROM endpoints WHERE hostname LIKE 'DEMO-%' OR ip_address LIKE '192.0.2.%' OR ip_address LIKE '198.51.100.%' OR ip_address LIKE '203.0.113.%';
  ```
  Delete any found records before retrying.

- [ ] Verify via browser: navigate to https://<server-fqdn>/admin/readiness
  **Pass criteria**: All checks show green/PASS status.

- [ ] Verify VAULT_MASTER_KEY_HEX is NOT the development default (0123456789abcdef repeated):
  The readiness check covers this, but double-check: if CREDENTIAL_SECURITY fails, the vault key is insecure.

- [ ] Verify MOCK_SCAN_MODE=false in .env.production:
  ```powershell
  Select-String -Path C:\apps\zeroagent\api\.env.production -Pattern 'MOCK_SCAN_MODE'
  ```
  **Pass criteria**: Shows MOCK_SCAN_MODE=false

## 2. Service Health
- [ ] API health check passes:
  ```powershell
  Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/health
  ```
  **Pass criteria**: Returns {"status":"healthy"}

- [ ] All 4 Windows services are running:
  ```powershell
  @('ZeroAgentAPI', 'ZeroAgentDashboard') | ForEach-Object { Write-Host "$_`: $(nssm status $_)" }
  Get-Service postgresql-x64-17, W3SVC | Format-Table Name, Status
  ```
  **Pass criteria**: All report Running/SERVICE_RUNNING

- [ ] Dashboard loads in browser:
  Navigate to https://<server-fqdn>/
  **Pass criteria**: Login page renders. No 'DEVELOPMENT / MOCK DATA' banner visible.

- [ ] IIS reverse proxy working:
  ```powershell
  Invoke-WebRequest -Uri https://localhost/api/v1/health -UseBasicParsing
  ```
  **Pass criteria**: Returns 200 with healthy status (confirms IIS → API proxy works)

## 3. Pilot Scan Validation
- [ ] Trigger a single-host scan against one real pilot endpoint:
  ```powershell
  $headers = @{ 'Content-Type' = 'application/json'; 'Authorization' = 'Bearer <your-jwt>' }
  $body = '{"name":"Pilot Validation Scan","target_cidr":"<pilot-endpoint-ip>/32","scan_profile":"standard","protocol":"winrm_https","vault_secret_ref":"<vault-credential-id>"}'
  Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/scans -Method POST -Headers $headers -Body $body
  ```
  **Pass criteria**: Returns scan job with status 'queued' or 'running'

- [ ] Verify scan completes and data lands:
  ```powershell
  Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/scans/<scan-id> -Headers $headers
  ```
  **Pass criteria**: Status shows 'completed'. Endpoint appears in:
  ```powershell
  Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/endpoints -Headers $headers
  ```
  Verify the pilot endpoint has hostname, IP, OS info, and compliance_score populated.

- [ ] Verify endpoint detail in dashboard:
  Navigate to https://<server-fqdn>/endpoints/<endpoint-id>
  **Pass criteria**: Hardware inventory, security posture, and compliance tabs all show data.

## 4. Reboot Survival
- [ ] Reboot the server:
  ```powershell
  Restart-Computer -Force
  ```
- [ ] After reboot, verify all services auto-started:
  ```powershell
  nssm status ZeroAgentAPI
  nssm status ZeroAgentDashboard
  Get-Service postgresql-x64-17 | Select-Object Status
  Get-Service W3SVC | Select-Object Status
  ```
  **Pass criteria**: All running within 60 seconds of login.

- [ ] Verify health endpoint after reboot:
  ```powershell
  Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/health
  ```
  **Pass criteria**: Returns {"status":"healthy"}

## 5. Backup and Restore Drill
- [ ] Run a manual backup:
  ```powershell
  Set-Location C:\apps\zeroagent\deploy
  .\backup-db.ps1
  ```
  **Pass criteria**: Creates .dump file in D:\backups\zeroagent with matching .sha256 checksum file. Log shows backup size in MB.

- [ ] Run a restore drill:
  ```powershell
  .\restore-drill.ps1 -RunDrill
  ```
  **Pass criteria**: SHA-256 checksum validates. Scratch database created, restored, integrity queries pass (table_count >= 5, endpoint data present). Status: PASS. Scratch DB cleaned up.

- [ ] Verify drill history recorded:
  ```powershell
  Get-Content D:\backups\zeroagent\restore_drill_history.json | ConvertFrom-Json | Select-Object -Last 1
  ```
  **Pass criteria**: Shows drill_id, status=PASS, checksum_verified=true.

## 6. Alert Delivery Health
- [ ] Send a test alert:
  ```powershell
  $headers = @{ 'Content-Type' = 'application/json'; 'Authorization' = 'Bearer <your-jwt>' }
  Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/admin/health/test-alert -Method POST -Headers $headers
  ```
  **Pass criteria**: Returns success. Check that the test alert arrived at your configured webhook (Slack channel, Teams, etc.).

- [ ] Verify alert delivery health:
  ```powershell
  Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/admin/health/status -Headers $headers
  ```
  **Pass criteria**: Shows healthy delivery status with recent successful delivery timestamp.

## 7. Scheduled Tasks
- [ ] All 3 scheduled tasks registered and in Ready state:
  ```powershell
  Get-ScheduledTask -TaskName 'ZeroAgent-*' | Format-Table TaskName, State, NextRunTime
  ```
  **Pass criteria**: 3 tasks listed, all Ready, NextRunTime populated.

## 8. Security Hardening
- [ ] TLS 1.2+ enforced (SSLv3, TLS 1.0, TLS 1.1 disabled):
  ```powershell
  Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
  ```
  **Pass criteria**: Enabled = 0 (or key doesn't exist with DisabledByDefault = 1)

- [ ] No development environment banner visible in dashboard
  **Pass criteria**: Browser shows clean dashboard without amber striped banner.

## Final Sign-Off

```text
Deployment validated by: _______________
Date: _______________
Result: [ ] GO  [ ] NO-GO
Notes: _______________
```
