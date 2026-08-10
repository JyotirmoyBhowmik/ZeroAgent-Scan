# ZeroAgent-Scan / EMS Enterprise Deployment Guide (Windows Server 2016)

This directory contains the production automation suite for deploying and operating ZeroAgent-Scan on Windows Server 2016.

---

## 📁 Package Contents

| File | Purpose |
| :--- | :--- |
| [`deploy.config.json`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/deploy.config.json) | Centralized configuration for paths, service accounts, database ports, and subnets. |
| [`install.ps1`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/install.ps1) | Idempotent system provisioning script (prereqs, service accounts, database, NSSM services, firewall). |
| [`configure-tls.ps1`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/configure-tls.ps1) | Enforces TLS 1.2+ minimum in Windows SCHANNEL registry and binds SSL/TLS certificates. |
| [`deploy-update.ps1`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/deploy-update.ps1) | Zero-downtime deployment script with automatic rollback on health check failure. |
| [`backup-db.ps1`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/backup-db.ps1) | Automated PostgreSQL `pg_dump` backup script with configurable retention policies and `-RunDrill` mode. |
| [`restore-drill.ps1`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/restore-drill.ps1) | Automated database restore drill into scratch DB with SHA-256 validation, table integrity tests, and history tracking. |
| [`archive-snapshots.ps1`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/archive-snapshots.ps1) | Automated JSONB host snapshots retention tool: exports raw payloads to gzip cold storage, enforces weekly downsampling, and includes safe dry-run mode. |
| [`endpointguard-backup-task.xml`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/endpointguard-backup-task.xml) | Windows Task Scheduler XML definition for scheduled nightly backups. |
| [`endpointguard-restore-drill-task.xml`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/endpointguard-restore-drill-task.xml) | Windows Task Scheduler XML definition for quarterly automated restore drills. |
| [`endpointguard-snapshot-retention-task.xml`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/endpointguard-snapshot-retention-task.xml) | Windows Task Scheduler XML definition for nightly snapshot cold-storage retention jobs. |

---

## 🛠️ Step-by-Step Execution Order

### Step 1: Pre-Deployment Server Prep & Manual Prerequisites
1. **Windows Updates**: Apply all pending cumulative updates on Windows Server 2016 and reboot.
2. **Disable SMBv1**:
   ```powershell
   Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
   ```
3. **Dedicated Volumes**: Ensure `D:\postgres\data`, `D:\backups\zeroagent`, and `D:\archives\snapshots` partitions exist on non-OS volumes.

### Step 2: Configure Environment Settings
Review and customize [`deploy.config.json`](file:///C:/Users/TEST/ZeroAgent%20Scan/deploy/deploy.config.json) with your enterprise paths, scan subnets, and database settings.

### Step 3: Run Master Installation Script
In an elevated Administrator PowerShell console:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install.ps1 -ConfigPath .\deploy.config.json -ServeMode IIS
```

### Step 4: Configure TLS & SCHANNEL Protocol Hardening
```powershell
# If using an Enterprise CA PFX Certificate:
.\configure-tls.ps1 -PfxPath "C:\certs\zeroagent_corp.pfx" -PfxPassword (Read-Host -AsSecureString "Enter PFX Password")

# If generating temporary self-signed certificate for staging:
.\configure-tls.ps1
```

### Step 5: Register Scheduled Tasks in Windows Task Scheduler
```powershell
# 1. Nightly Database Backups (02:00 AM Daily)
Register-ScheduledTask -Xml (Get-Content -Raw .\endpointguard-backup-task.xml) -TaskName "ZeroAgent-DatabaseBackup" -Force

# 2. Quarterly Restore Drills & Integrity Checks (03:00 AM on 1st of Jan/Apr/Jul/Oct)
Register-ScheduledTask -Xml (Get-Content -Raw .\endpointguard-restore-drill-task.xml) -TaskName "ZeroAgent-DatabaseRestoreDrill" -Force

# 3. Nightly Snapshot Cold-Storage Archival (03:30 AM Daily)
Register-ScheduledTask -Xml (Get-Content -Raw .\endpointguard-snapshot-retention-task.xml) -TaskName "ZeroAgent-SnapshotRetention" -Force
```

### Step 6: Snapshot Retention & Dry-Run Verification
```powershell
# Preview snapshots eligible for archival without modifying database (Dry-Run mode):
.\archive-snapshots.ps1 -DryRun

# Execute live cold-storage archival (90-day retention window):
.\archive-snapshots.ps1 -RetentionDays 90 -Strategy archive -ColdStoragePath "D:\archives\snapshots"
```

### Step 7: On-Demand Backup & Restore Drill Verification
```powershell
# Take a backup and immediately verify it end-to-end in a scratch database:
.\backup-db.ps1 -RunDrill

# Or execute a standalone restore drill on the latest backup:
.\restore-drill.ps1
```

### Step 8: Deploying Application Updates
When rolling out a new version:
```powershell
.\deploy-update.ps1 -ArtifactZip "C:\releases\zeroagent-v1.2.0.zip"
```

---

## 🔍 Log Files & Auditing
All deployment and maintenance scripts write structured logs to `C:\apps\zeroagent\logs\`:
- `install_YYYYMMDD_HHMMSS.log`: Initial server setup audit trail.
- `configure_tls_YYYYMMDD_HHMMSS.log`: Registry SCHANNEL changes and SSL bindings.
- `update_YYYYMMDD_HHMMSS.log`: Application updates, migration runs, and health checks.
- `backup_YYYYMMDD_HHMMSS.log`: Nightly database dumps and retention purges.
- `restore_drill_YYYYMMDD_HHMMSS.log`: Database restore drill execution and integrity check results.
- `snapshot_archive_YYYYMMDD_HHMMSS.log`: Snapshot retention, gzip compression, and archival execution logs.
- `D:\backups\zeroagent\snapshot_retention_history.json`: Machine-readable audit paper trail of snapshot retention runs.
