# ZeroAgent-Scan EMS — Production Deployment Guide
## Windows Server 2019 · PostgreSQL 17 · Node.js 26 · IIS Reverse Proxy

> [!IMPORTANT]
> Complete this guide AFTER finishing all items in PREREQUISITES.md

## Part 1: Manual Steps (You Must Do These Yourself)

The following steps are prerequisites that the automated `install.ps1` script does NOT handle. You must complete these manually before proceeding to Part 2.

### Step 1: Install PostgreSQL 17
- Run the PostgreSQL 17.x Windows installer from postgresql.org
- During install:
  - Set superuser (postgres) password → record it securely
  - Data directory: `D:\postgres\data`
  - Port: `5432` (default)
  - Locale: English, United States (or your locale)
- After install, verify:
  ```powershell
  & 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U postgres -c 'SELECT version();'
  ```
  **Expected output:** `PostgreSQL 17.x on x86_64-pc-windows-msvc...`

### Step 2: Create the Application Database
Run the following commands in PowerShell to create the database and user:
```powershell
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U postgres -c "CREATE ROLE endpointguard_prod_svc WITH LOGIN PASSWORD 'YOUR_SECURE_PASSWORD_HERE';"
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U postgres -c "CREATE DATABASE endpointguard_prod OWNER endpointguard_prod_svc;"
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U postgres -d endpointguard_prod -c "CREATE EXTENSION IF NOT EXISTS `"uuid-ossp`"; CREATE EXTENSION IF NOT EXISTS pgcrypto;"
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U postgres -d endpointguard_prod -c "REVOKE ALL ON DATABASE endpointguard_prod FROM PUBLIC;"
```
Verify the connection: 
```powershell
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U endpointguard_prod_svc -d endpointguard_prod -c '\conninfo'
```
**Expected output:** `You are connected to database "endpointguard_prod" as user "endpointguard_prod_svc"...`

### Step 3: Run Database Migrations
Apply the initial schema to the database:
```powershell
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U endpointguard_prod_svc -d endpointguard_prod -f C:\apps\zeroagent\packages\db\schema.sql
```
Verify the tables were created: 
```powershell
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U endpointguard_prod_svc -d endpointguard_prod -c '\dt'
```
**Expected output:** List of 15 tables including `endpoints`, `host_snapshots`, `security_audit_logs`, `vault_credentials`, etc.

### Step 4: Install Node.js 26
- Run the Node.js 26.x MSI installer from nodejs.org
- Accept defaults (installs to `C:\Program Files\nodejs`)
- Verify the installation:
  ```powershell
  node --version
  ```
  **Expected output:** `v26.x.x`

### Step 5: Obtain SSL Certificate
- **Enterprise CA:** Request a certificate for your server's FQDN (e.g., `zeroagent.corp.local`)
- Export as a `.pfx` file with the private key
- Place the file at `C:\apps\zeroagent\certs\server.pfx`
- **OR for initial testing:** the `install.ps1` script's `configure-tls` step will generate a self-signed cert (browser will show warnings).

---

## Part 2: Automated Steps (install.ps1 Does These For You)

### Step 6: Review and Customize deploy.config.json
Review and edit the configuration file with the correct deployment variables:
- `database.name` → `endpointguard_prod`
- `database.username` → `endpointguard_prod_svc`
- `network.api_port` → `8080`
- `restore_drill.notify_webhook_url` → your Slack/Teams webhook

Command to edit: 
```powershell
notepad C:\apps\zeroagent\deploy\deploy.config.json
```

### Step 7: Run install.ps1
Execute the primary deployment script:
```powershell
Set-Location C:\apps\zeroagent\deploy
$dbPwd = Read-Host -AsSecureString 'Enter database password for endpointguard_prod_svc'
$svcPwd = Read-Host -AsSecureString 'Enter password for svc_zeroagent service account'
.\install.ps1 -ServeMode IIS -DBPassword $dbPwd -ServiceAccountPassword $svcPwd
```

**What install.ps1 does (so you don't have to):**
- Creates `svc_zeroagent` local account with "Log On As Service" right
- Downloads and installs NSSM 2.24 to `C:\tools\nssm`
- Creates directory structure under `C:\apps\zeroagent`
- Registers `ZeroAgentAPI` as an NSSM service
- Configures Windows Firewall rules
- Enables IIS features (WebServerRole, URL Rewrite, ARR)

**Expected output:** `install.ps1` logs to `C:\apps\zeroagent\logs\install_YYYYMMDD_HHMMSS.log`. Last line should be: `[INFO] Installation completed successfully.`

### Step 8: Configure the Production Environment File
Open the environment file for editing:
```powershell
notepad C:\apps\zeroagent\api\.env.production
```
Set these values (replacing placeholders with your actual values):
```env
HOST=127.0.0.1
PORT=8080
ENVIRONMENT=production
NODE_ENV=production
DATABASE_URL=postgres://endpointguard_prod_svc:YOUR_DB_PASSWORD@localhost:5432/endpointguard_prod?sslmode=disable
VAULT_MASTER_KEY_HEX=<your 64-hex-char key>
MOCK_SCAN_MODE=false
MTLS_ENFORCE_CLIENT_AUTH=false
SERVICE_NAME=endpointguard-api-prod
LOG_LEVEL=info
ALLOWED_ORIGINS=https://zeroagent.corp.local
```

### Step 9: Configure TLS
Apply TLS settings and harden SCHANNEL using your PFX certificate:
```powershell
.\configure-tls.ps1 -PfxPath C:\apps\zeroagent\certs\server.pfx -PfxPassword (Read-Host -AsSecureString 'PFX password')
```
**OR for self-signed (testing only):**
```powershell
.\configure-tls.ps1
```
**Expected output:** `[INFO] TLS configuration complete. SCHANNEL protocols hardened. Certificate bound to IIS port 443.`
*Note: Requires server reboot for SCHANNEL changes to take effect.*

### Step 10: Start the Services
Start the backend API service:
```powershell
nssm start ZeroAgentAPI
```
Verify the API is running correctly:
```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/health
```
**Expected output:**
```json
{
  "status": "healthy",
  "service": "endpointguard-api",
  "version": "1.0.0",
  "timestamp": "..."
}
```
*If you see 'connection refused', check:*
1. `nssm status ZeroAgentAPI` — should say `SERVICE_RUNNING`
2. Check logs: `Get-Content C:\apps\zeroagent\logs\api_stderr.log -Tail 50`

### Step 11: Build and Start the Dashboard
Build the Next.js production bundle and register it as a service:
```powershell
cd C:\apps\zeroagent\dashboard
npm install --production
npm run build
```
**Expected output:** `✓ Compiled successfully`, `✓ Generating static pages (15/15)`

Install and start the Dashboard service:
```powershell
nssm install ZeroAgentDashboard "C:\Program Files\nodejs\node.exe"
nssm set ZeroAgentDashboard AppParameters "node_modules\.bin\next start -p 3000"
nssm set ZeroAgentDashboard AppDirectory C:\apps\zeroagent\dashboard
nssm set ZeroAgentDashboard ObjectName .\svc_zeroagent <svc_password>
nssm set ZeroAgentDashboard Start SERVICE_AUTO_START
nssm set ZeroAgentDashboard AppStdout C:\apps\zeroagent\logs\dashboard_stdout.log
nssm set ZeroAgentDashboard AppStderr C:\apps\zeroagent\logs\dashboard_stderr.log
nssm start ZeroAgentDashboard
```
Verify the dashboard is responding locally:
```powershell
Invoke-WebRequest -Uri http://127.0.0.1:3000 -UseBasicParsing | Select-Object StatusCode
```
**Expected output:** `200`

### Step 12: Register Scheduled Tasks
Register the background maintenance tasks:
```powershell
Register-ScheduledTask -TaskName 'ZeroAgent-DatabaseBackup' -Xml (Get-Content .\endpointguard-backup-task.xml -Raw) -Force
Register-ScheduledTask -TaskName 'ZeroAgent-DatabaseRestoreDrill' -Xml (Get-Content .\endpointguard-restore-drill-task.xml -Raw) -Force
Register-ScheduledTask -TaskName 'ZeroAgent-SnapshotRetention' -Xml (Get-Content .\endpointguard-snapshot-retention-task.xml -Raw) -Force
```
Verify the tasks are registered:
```powershell
Get-ScheduledTask -TaskName 'ZeroAgent-*' | Format-Table TaskName, State
```
**Expected output:** `3 tasks, all in Ready state.`

### Step 13: Verify Browser Access
Open a browser and navigate to `https://zeroagent.corp.local` (or your configured FQDN).
- If using a self-signed cert: you'll see a certificate warning — click through for testing.
- If using an Enterprise CA cert: page loads cleanly.
- You should see the ZeroAgent-Scan dashboard login page.
- If using development mode: an amber-striped banner reading 'DEVELOPMENT / MOCK DATA — NOT PRODUCTION' appears (this should NOT appear in production).

### Step 14: Reboot and Verify Auto-Start
Reboot the server to apply SCHANNEL updates and test service auto-start:
```powershell
Restart-Computer -Force
```
After the reboot, verify all services started properly:
```powershell
nssm status ZeroAgentAPI
nssm status ZeroAgentDashboard
Get-Service postgresql-x64-17 | Select-Object Status
Get-Service W3SVC | Select-Object Status
```
**Expected output:** All running.
Verify health one last time: `Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/health`

---

## Part 3: Troubleshooting

### 'Connection Refused' on port 8080
- **Check:** `nssm status ZeroAgentAPI` → if `SERVICE_STOPPED`, check stderr log
- **Check:** `Get-Content C:\apps\zeroagent\logs\api_stderr.log -Tail 50`
- **Common cause:** DATABASE_URL wrong or PostgreSQL not running
- **Fix:** Verify `Get-Service postgresql-x64-17` is Running, check DATABASE_URL in `.env.production`

### 'Certificate Warning' in browser
- **Cause:** Self-signed certificate is not trusted by browser
- **Fix:** Import the cert to Trusted Root CA store OR deploy an Enterprise CA cert via `configure-tls.ps1`

### API starts then immediately stops
- **Check stderr log:** `Get-Content C:\apps\zeroagent\logs\api_stderr.log -Tail 50`
- If log shows `FATAL: demo data detected in production database`: the DB contains demo/seed records. Clean them before going to production.
- If log shows `connection refused` to PostgreSQL: verify `pg_hba.conf` allows local connections for the app user

### PostgreSQL rejects connections
- Check `pg_hba.conf` at `D:\postgres\data\pg_hba.conf`
- Ensure this line exists: `host endpointguard_prod endpointguard_prod_svc 127.0.0.1/32 scram-sha-256`
- After editing, restart: `Restart-Service postgresql-x64-17`

### Firewall blocking WinRM scans
- **Verify outbound rule exists:** `Get-NetFirewallRule -DisplayName 'ZeroAgent-Outbound-WinRM'`
- **Test connectivity:** `Test-NetConnection -ComputerName <target-endpoint> -Port 5986`
- **If blocked:** confirm firewall change request was applied on both the ZeroAgent server AND the target subnet's firewall

### Service doesn't start after reboot
- **Check NSSM recovery settings:** `nssm get ZeroAgentAPI AppRestartDelay` (should be 5000)
- **Check service account:** `nssm get ZeroAgentAPI ObjectName` (should be `.\svc_zeroagent`)
- If 'Log on as service' right was removed by GPO refresh: re-apply via `secedit` or GPO

### Dashboard shows 'DEVELOPMENT / MOCK DATA' banner
- The `NEXT_PUBLIC_APP_ENV` variable is not set to 'production'
- Edit `C:\apps\zeroagent\dashboard\.env.production` and ensure `NEXT_PUBLIC_APP_ENV=production`
- Rebuild: `cd C:\apps\zeroagent\dashboard && npm run build`
- Restart: `nssm restart ZeroAgentDashboard`

### Backup script fails with authentication error
- `pg_dump` requires a `.pgpass` file for non-interactive auth
- Create `C:\Users\svc_zeroagent\AppData\Roaming\postgresql\pgpass.conf` with:
  `127.0.0.1:5432:endpointguard_prod:endpointguard_prod_svc:YOUR_DB_PASSWORD`
- Set file permissions so only `svc_zeroagent` can read it
