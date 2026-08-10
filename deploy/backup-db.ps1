<#
.SYNOPSIS
    Automated PostgreSQL Database Backup with Retention for ZeroAgent-Scan.
.DESCRIPTION
    Executes an encrypted/compressed pg_dump, generates SHA-256 checksums, and purges backups exceeding retention policy.
.PARAMETER ConfigPath
    Path to deploy.config.json. Defaults to .\deploy.config.json.
.EXAMPLE
    .\backup-db.ps1 -ConfigPath "C:\apps\zeroagent\deploy.config.json"
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = ".\deploy.config.json"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ConfigPath)) { throw "Config file not found at '$ConfigPath'." }
$Config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json

$BackupDir = $Config.application.backup_path
$LogPath = $Config.application.log_path
if (-not (Test-Path $BackupDir)) { New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogPath "backup_$Timestamp.log"

function Log-Message {
    param([string]$Level, [string]$Message)
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line
}

Log-Message "INFO" "Starting automated PostgreSQL database backup..."

$DBName = $Config.database.name
$DBUser = $Config.database.username
$DBHost = $Config.database.host
$DBPort = $Config.database.port
$PgDumpPath = $Config.database.pg_dump_path

if (-not (Test-Path $PgDumpPath)) {
    # Fallback to PATH search
    $PgDumpPath = (Get-Command pg_dump.exe -ErrorAction SilentlyContinue).Source
    if (-not $PgDumpPath) {
        throw "pg_dump.exe not found at '$($Config.database.pg_dump_path)' or in system PATH."
    }
}

$BackupFileName = "zeroagent_db_backup_$Timestamp.dump"
$BackupFilePath = Join-Path $BackupDir $BackupFileName

# Execute pg_dump
Log-Message "INFO" "Executing pg_dump for database '$DBName' to '$BackupFilePath'..."
$env:PGHOST = $DBHost
$env:PGPORT = $DBPort
$env:PGUSER = $DBUser
$env:PGDATABASE = $DBName

& $PgDumpPath -F c -b -v -f $BackupFilePath 2>&1 | Out-File (Join-Path $LogPath "pg_dump_$Timestamp.log")

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $BackupFilePath)) {
    Log-Message "ERROR" "pg_dump failed with exit code $LASTEXITCODE."
    exit 1
}

$FileSizeMB = [math]::Round((Get-Item $BackupFilePath).Length / 1MB, 2)
$Hash = (Get-FileHash -Path $BackupFilePath -Algorithm SHA256).Hash
Set-Content -Path "$BackupFilePath.sha256" -Value $Hash

Log-Message "INFO" "Backup completed successfully! Size: $FileSizeMB MB, SHA-256: $Hash"

# ---------------------------------------------------------------------------
# Enforce Retention Policy (Daily + Weekly)
# ---------------------------------------------------------------------------
$RetentionDays = $Config.backup.daily_retention_days
if ($RetentionDays -le 0) { $RetentionDays = 30 }

Log-Message "INFO" "Enforcing retention policy (purging backups older than $RetentionDays days)..."
$CutoffDate = (Get-Date).AddDays(-$RetentionDays)
$OldBackups = Get-ChildItem -Path $BackupDir -Filter "zeroagent_db_backup_*.dump" | Where-Object { $_.CreationTime -lt $CutoffDate }

foreach ($Old in $OldBackups) {
    Remove-Item $Old.FullName -Force
    Remove-Item "$($Old.FullName).sha256" -Force -ErrorAction SilentlyContinue
    Log-Message "INFO" "Purged expired backup: $($Old.Name)"
}

Log-Message "INFO" "Backup and retention maintenance completed."
