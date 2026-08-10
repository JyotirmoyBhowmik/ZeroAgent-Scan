"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  Layers,
  Settings2,
  Save,
  CheckCircle2,
  AlertTriangle,
  FolderTree,
  Network,
  Users,
  Lock,
  RotateCcw,
  BellRing,
  Send,
  Radio,
  Clock,
  ExternalLink,
  ShieldAlert,
  Activity,
  Zap,
  HardDrive,
  Database,
  Archive,
  DownloadCloud,
  Play,
  FileCode,
  FileCheck2,
  RefreshCw,
  ArrowRight,
} from "lucide-react";
import { api } from "@/lib/api";
import {
  RolloutSettings,
  BulkAssignTierRequest,
  AlertHealthStatus,
  TestAlertResponse,
  SnapshotRetentionPolicy,
  SnapshotRetentionDryRun,
  SnapshotRetentionExecuteResult,
} from "@/lib/types";

export default function AdminSettingsPage() {
  const [settings, setSettings] = useState<RolloutSettings>({
    active_tiers: ["pilot"],
    schedule_enforce_tiers: true,
  });
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsSavedMessage, setSettingsSavedMessage] = useState<string | null>(null);

  // Alert Health & Test Alert State
  const [alertHealth, setAlertHealth] = useState<AlertHealthStatus | null>(null);
  const [testWebhookURL, setTestWebhookURL] = useState("https://hooks.slack.com/services/T0000/B000/XXXXX");
  const [testReason, setTestReason] = useState("Quarterly on-call verification of ZeroAgent fleet scan alerts");
  const [sendingTestAlert, setSendingTestAlert] = useState(false);
  const [testAlertResult, setTestAlertResult] = useState<TestAlertResponse | null>(null);

  // Snapshot Retention & Archival State
  const [retentionPolicy, setRetentionPolicy] = useState<SnapshotRetentionPolicy>({
    retention_days: 90,
    strategy: "archive",
    cold_storage_path: "D:\\archives\\snapshots",
    keep_weekly_interval_days: 7,
    is_enabled: true,
    last_run_status: "IDLE",
    updated_at: new Date().toISOString(),
    updated_by: "system",
  });
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policySavedMessage, setPolicySavedMessage] = useState<string | null>(null);
  const [dryRunResult, setDryRunResult] = useState<SnapshotRetentionDryRun | null>(null);
  const [runningDryRun, setRunningDryRun] = useState(false);
  const [showDryRunModal, setShowDryRunModal] = useState(false);
  const [executingRetention, setExecutingRetention] = useState(false);
  const [retentionExecutionResult, setRetentionExecutionResult] = useState<SnapshotRetentionExecuteResult | null>(null);

  // Bulk assignment state
  const [bulkTier, setBulkTier] = useState<"pilot" | "staged" | "full">("pilot");
  const [bulkScope, setBulkScope] = useState<"subnet" | "ou">("subnet");
  const [targetSubnet, setTargetSubnet] = useState("10.100.1.0/24");
  const [targetOU, setTargetOU] = useState("OU=Workstations,DC=corp,DC=local");
  const [bulkJustification, setBulkJustification] = useState("");
  const [bulkAssigning, setBulkAssigning] = useState(false);
  const [bulkMessage, setBulkMessage] = useState<string | null>(null);

  const loadData = async () => {
    try {
      const [rolloutData, healthData, policyData] = await Promise.all([
        api.fetchRolloutSettings(),
        api.fetchAlertHealthStatus(),
        api.fetchSnapshotRetentionPolicy(),
      ]);
      setSettings(rolloutData);
      setAlertHealth(healthData);
      if (policyData) setRetentionPolicy(policyData);
    } catch {}
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleTierToggle = (tier: "pilot" | "staged" | "full") => {
    setSettings((prev) => {
      const exists = prev.active_tiers.includes(tier);
      let updated: ("pilot" | "staged" | "full")[];
      if (exists) {
        if (prev.active_tiers.length === 1) {
          alert("At least one rollout tier must remain enabled for scheduled scans.");
          return prev;
        }
        updated = prev.active_tiers.filter((t) => t !== tier);
      } else {
        updated = [...prev.active_tiers, tier];
      }
      return { ...prev, active_tiers: updated };
    });
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSettings(true);
    try {
      await api.updateRolloutSettings(settings);
      setSettingsSavedMessage("Scheduled scan rollout tier policy updated and audited successfully!");
      setTimeout(() => setSettingsSavedMessage(null), 3000);
    } catch (err: any) {
      alert(err.message || "Failed to update settings");
    } finally {
      setSavingSettings(false);
    }
  };

  const handleSendTestAlert = async (e: React.FormEvent) => {
    e.preventDefault();
    setSendingTestAlert(true);
    setTestAlertResult(null);

    try {
      const res = await api.sendTestAlert({
        webhook_url: testWebhookURL,
        test_reason: testReason,
      });
      setTestAlertResult(res);
      await loadData();
    } catch (err: any) {
      alert(err.message || "Failed to dispatch test alert");
    } finally {
      setSendingTestAlert(false);
    }
  };

  const handleBulkAssign = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bulkJustification.trim()) {
      alert("Mandatory justification note is required for bulk tier assignment.");
      return;
    }

    setBulkAssigning(true);
    try {
      const req: BulkAssignTierRequest = {
        rollout_tier: bulkTier,
        justification: bulkJustification,
        ...(bulkScope === "subnet" ? { subnet_cidr: targetSubnet } : {}),
        ...(bulkScope === "ou" ? { organizational_unit: targetOU } : {}),
      };

      const res = await api.bulkAssignRolloutTier(req);
      setBulkMessage(`Bulk assigned ${res.affected_count} endpoints to '${res.assigned_tier}' successfully.`);
      setBulkJustification("");
      setTimeout(() => setBulkMessage(null), 3500);
    } catch (err: any) {
      alert(err.message || "Failed to bulk assign tiers");
    } finally {
      setBulkAssigning(false);
    }
  };

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingPolicy(true);
    try {
      const res = await api.updateSnapshotRetentionPolicy(retentionPolicy);
      setRetentionPolicy(res.policy);
      setPolicySavedMessage("Snapshot retention policy successfully saved and audited.");
      setTimeout(() => setPolicySavedMessage(null), 3000);
    } catch (err: any) {
      alert(err.message || "Failed to update retention policy");
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleRunDryRun = async () => {
    setRunningDryRun(true);
    setDryRunResult(null);
    try {
      const res = await api.dryRunSnapshotRetention({
        retention_days: retentionPolicy.retention_days,
        strategy: retentionPolicy.strategy,
        cold_storage_path: retentionPolicy.cold_storage_path,
        dry_run: true,
      });
      setDryRunResult(res);
      setShowDryRunModal(true);
    } catch (err: any) {
      alert(err.message || "Failed to run dry-run calculation");
    } finally {
      setRunningDryRun(false);
    }
  };

  const handleExecuteRetention = async () => {
    if (
      !confirm(
        `Are you sure you want to execute snapshot ${retentionPolicy.strategy} for snapshots older than ${retentionPolicy.retention_days} days?`
      )
    ) {
      return;
    }
    setExecutingRetention(true);
    try {
      const res = await api.executeSnapshotRetention({
        retention_days: retentionPolicy.retention_days,
        strategy: retentionPolicy.strategy,
        cold_storage_path: retentionPolicy.cold_storage_path,
        justification: "Manual admin console retention execution",
      });
      setRetentionExecutionResult(res);
      await loadData();
    } catch (err: any) {
      alert(err.message || "Failed to execute snapshot retention");
    } finally {
      setExecutingRetention(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Settings2 className="w-6 h-6 text-charcoal-900" />
            <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">Enterprise Admin & System Health</h1>
          </div>
          <p className="text-sm text-charcoal-600 mt-1">
            Verify human alerting delivery, configure JSONB snapshot cold-storage retention policies, and manage fleet rollout tiers.
          </p>
        </div>

        <Link
          href="/admin/readiness"
          className="inline-flex items-center gap-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-lg shadow-sm transition-all shrink-0"
        >
          <ShieldCheck className="w-4 h-4" />
          <span>Production Readiness Check</span>
          <ArrowRight className="w-3.5 h-3.5 ml-0.5" />
        </Link>
      </div>

      {/* Production Readiness Quick Status Banner */}
      <div className="p-4 rounded-xl border bg-gradient-to-r from-emerald-950 via-charcoal-950 to-charcoal-900 text-white border-charcoal-800 shadow-md flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-sm text-white">Pre-Go-Live Production Safety Gates Active</span>
              <span className="text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30">
                ZERO DEMO DATA INVARIANT
              </span>
            </div>
            <p className="text-xs text-charcoal-300 mt-0.5">
              Automated startup guards, CI/CD database cleanliness verification, and key entropy audits are enforced.
            </p>
          </div>
        </div>

        <Link
          href="/admin/readiness"
          className="text-xs text-emerald-400 hover:text-emerald-300 font-semibold inline-flex items-center gap-1.5 shrink-0 bg-charcoal-900 px-3 py-1.5 rounded-lg border border-charcoal-700 hover:border-emerald-500 transition-colors"
        >
          <span>Run Full Audit</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Alert Verification Status Banner */}
      {alertHealth && (
        <div
          className={`p-4 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
            alertHealth.test_alert_lapsed
              ? "bg-amber-500/10 border-amber-300 text-amber-950"
              : "bg-emerald-500/10 border-emerald-300 text-emerald-950"
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`p-2.5 rounded-lg ${
                alertHealth.test_alert_lapsed ? "bg-amber-100 text-amber-800" : "bg-emerald-100 text-emerald-800"
              }`}
            >
              {alertHealth.test_alert_lapsed ? (
                <AlertTriangle className="w-5 h-5" />
              ) : (
                <CheckCircle2 className="w-5 h-5" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm">
                  {alertHealth.test_alert_lapsed
                    ? "Alerting Pipeline Verification Lapsed (90+ Days / Untested)"
                    : "Alerting Delivery Pipeline Verified"}
                </span>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold uppercase ${
                    alertHealth.test_alert_lapsed
                      ? "bg-amber-200 text-amber-900"
                      : "bg-emerald-200 text-emerald-900"
                  }`}
                >
                  {alertHealth.last_test_alert_status}
                </span>
              </div>
              <p className="text-xs opacity-90 mt-0.5">
                {alertHealth.last_test_alert_at ? (
                  <>
                    Last successful test was {alertHealth.test_alert_lapse_days} day(s) ago (
                    {new Date(alertHealth.last_test_alert_at).toLocaleDateString()}) by{" "}
                    <span className="font-mono font-semibold">{alertHealth.last_test_alert_operator}</span>.
                  </>
                ) : (
                  <>No synthetic test alert has been recorded yet. Fire a test alert to confirm alerts reach human on-call engineers.</>
                )}
              </p>
            </div>
          </div>

          <a
            href="#test-alert-section"
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-charcoal-900 hover:bg-charcoal-950 text-white shrink-0 transition-all"
          >
            Run Test Alert Now
          </a>
        </div>
      )}

      {/* Snapshot Retention & Cold-Storage Archival Module */}
      <div className="bg-white border border-charcoal-200 rounded-xl p-6 shadow-xs space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-charcoal-100 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <Archive className="w-6 h-6 text-purple-700" />
              <h2 className="text-lg font-bold text-charcoal-900">
                JSONB Host Snapshots Retention & Cold-Storage Archival
              </h2>
            </div>
            <p className="text-xs text-charcoal-600 mt-1 max-w-2xl">
              Prevents PostgreSQL database bloat from high-frequency scans across 400 hosts by enforcing an automated retention policy.
              Derived compliance evaluations and drift events remain <strong>100% intact and queryable</strong>.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleRunDryRun}
              disabled={runningDryRun}
              className="px-4 py-2 bg-purple-50 hover:bg-purple-100 text-purple-900 border border-purple-300 rounded-lg text-xs font-bold flex items-center gap-2 shadow-xs transition-colors disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 text-purple-700" />
              {runningDryRun ? "Evaluating..." : "Run Dry-Run Preview"}
            </button>
            <button
              type="button"
              onClick={handleExecuteRetention}
              disabled={executingRetention}
              className="px-4 py-2 bg-purple-900 hover:bg-purple-950 text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow-xs transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${executingRetention ? "animate-spin" : ""}`} />
              {executingRetention ? "Executing..." : "Execute Policy Now"}
            </button>
          </div>
        </div>

        {/* Compliance Guarantee Notice */}
        <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3 flex items-start gap-3 text-xs text-emerald-900">
          <ShieldCheck className="w-5 h-5 text-emerald-700 shrink-0 mt-0.5" />
          <div>
            <p className="font-bold">Compliance History Invariant Guarantee</p>
            <p className="text-emerald-800 mt-0.5">
              ZeroAgent-Scan archives only the raw JSONB system introspection telemetry into compressed <code>.json.gz</code> cold storage.
              All calculated <code>drift_events</code>, CVE vulnerability findings, and <code>compliance_evaluations</code> are preserved in PostgreSQL indefinitely for regulatory reporting.
            </p>
          </div>
        </div>

        <form onSubmit={handleSavePolicy} className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Strategy Selection */}
          <div className="space-y-2">
            <label className="block text-xs font-bold text-charcoal-700 uppercase tracking-wider">
              Retention Strategy
            </label>
            <div className="space-y-2">
              <label
                className={`p-3 border rounded-lg flex items-start gap-3 cursor-pointer transition-colors ${
                  retentionPolicy.strategy === "archive"
                    ? "border-purple-600 bg-purple-50/60"
                    : "border-charcoal-200 bg-charcoal-50"
                }`}
              >
                <input
                  type="radio"
                  name="retention_strategy"
                  value="archive"
                  checked={retentionPolicy.strategy === "archive"}
                  onChange={() => setRetentionPolicy({ ...retentionPolicy, strategy: "archive" })}
                  className="mt-0.5 text-purple-600 focus:ring-purple-500"
                />
                <div>
                  <span className="text-xs font-bold text-charcoal-900 block">
                    Cold-Storage Archival (Recommended)
                  </span>
                  <span className="text-[11px] text-charcoal-600">
                    Exports raw payloads to compressed GZIP files on cold storage volume with SHA-256 validation.
                  </span>
                </div>
              </label>

              <label
                className={`p-3 border rounded-lg flex items-start gap-3 cursor-pointer transition-colors ${
                  retentionPolicy.strategy === "downsample"
                    ? "border-purple-600 bg-purple-50/60"
                    : "border-charcoal-200 bg-charcoal-50"
                }`}
              >
                <input
                  type="radio"
                  name="retention_strategy"
                  value="downsample"
                  checked={retentionPolicy.strategy === "downsample"}
                  onChange={() => setRetentionPolicy({ ...retentionPolicy, strategy: "downsample" })}
                  className="mt-0.5 text-purple-600 focus:ring-purple-500"
                />
                <div>
                  <span className="text-xs font-bold text-charcoal-900 block">
                    Weekly Downsampling
                  </span>
                  <span className="text-[11px] text-charcoal-600">
                    Keeps 1 golden weekly snapshot checkpoint per host and prunes intermediate daily snapshots.
                  </span>
                </div>
              </label>
            </div>
          </div>

          {/* Retention Window & Storage Path */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-charcoal-700 uppercase tracking-wider mb-1">
                Full-Resolution Retention Window
              </label>
              <div className="flex items-center gap-3">
                <input
                  type="number"
                  min={7}
                  max={3650}
                  value={retentionPolicy.retention_days}
                  onChange={(e) =>
                    setRetentionPolicy({
                      ...retentionPolicy,
                      retention_days: parseInt(e.target.value, 10) || 90,
                    })
                  }
                  className="w-28 bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 font-mono text-sm font-bold text-charcoal-900"
                />
                <span className="text-xs font-semibold text-charcoal-600">Days (Default: 90 Days)</span>
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold text-charcoal-700 uppercase tracking-wider mb-1">
                Cold Storage Archive Path
              </label>
              <input
                type="text"
                value={retentionPolicy.cold_storage_path}
                onChange={(e) => setRetentionPolicy({ ...retentionPolicy, cold_storage_path: e.target.value })}
                className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 font-mono text-xs text-charcoal-900"
              />
              <span className="text-[11px] text-charcoal-500 mt-0.5 block">
                Dedicated non-OS volume path (e.g. <code>D:\archives\snapshots</code>)
              </span>
            </div>
          </div>

          {/* Execution & Status Summary */}
          <div className="space-y-3 bg-charcoal-50 border border-charcoal-200 rounded-lg p-4 flex flex-col justify-between">
            <div>
              <span className="text-xs font-bold text-charcoal-700 uppercase tracking-wider block mb-2">
                Operational Status
              </span>
              <div className="space-y-1.5 text-xs">
                <div className="flex justify-between">
                  <span className="text-charcoal-600">Scheduled Automation:</span>
                  <span className="font-semibold text-charcoal-900">Task Scheduler (03:30 Nightly)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-charcoal-600">Last Status:</span>
                  <span className="font-bold text-emerald-700 uppercase">
                    {retentionPolicy.last_run_status || "IDLE"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-charcoal-600">Audit History:</span>
                  <span className="font-mono text-charcoal-800">snapshot_retention_history.json</span>
                </div>
              </div>
            </div>

            {policySavedMessage && (
              <div className="p-2 bg-emerald-100 border border-emerald-300 rounded text-emerald-900 text-xs font-semibold flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                <span>{policySavedMessage}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={savingPolicy}
              className="w-full py-2 bg-charcoal-900 hover:bg-charcoal-950 text-white rounded-lg text-xs font-bold flex items-center justify-center gap-2 shadow-xs disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              {savingPolicy ? "Saving..." : "Save Retention Policy"}
            </button>
          </div>
        </form>

        {/* Live Execution Receipt */}
        {retentionExecutionResult && (
          <div className="p-4 bg-purple-50 border border-purple-200 rounded-lg text-xs space-y-2">
            <div className="flex items-center justify-between font-bold text-purple-900 border-b border-purple-200 pb-2">
              <span className="flex items-center gap-1.5">
                <FileCheck2 className="w-4 h-4 text-purple-700" />
                Snapshot Retention Execution Receipt ({retentionExecutionResult.execution_id})
              </span>
              <span className="px-2 py-0.5 bg-purple-200 text-purple-900 rounded font-mono">
                {retentionExecutionResult.status}
              </span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-purple-900">
              <div>
                <span className="text-purple-600 block text-[11px]">Snapshots Processed:</span>
                <span className="font-bold font-mono">{retentionExecutionResult.snapshots_processed}</span>
              </div>
              <div>
                <span className="text-purple-600 block text-[11px]">Archived to Cold Storage:</span>
                <span className="font-bold font-mono">{retentionExecutionResult.snapshots_archived}</span>
              </div>
              <div>
                <span className="text-purple-600 block text-[11px]">Reclaimed Storage:</span>
                <span className="font-bold font-mono text-emerald-700">
                  {retentionExecutionResult.storage_saved_mb.toFixed(2)} MB
                </span>
              </div>
              <div>
                <span className="text-purple-600 block text-[11px]">Audit Log ID:</span>
                <span className="font-mono text-[11px] truncate block">{retentionExecutionResult.audit_log_id}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Grid: Alert Testing & Policy Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Card 1: Send Synthetic Test Alert to Webhook/Email */}
        <div id="test-alert-section" className="bg-white rounded-xl border border-charcoal-200 p-6 shadow-xs card-border">
          <div className="flex items-center justify-between border-b border-charcoal-100 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <BellRing className="w-5 h-5 text-rose-600" />
              <h2 className="text-sm font-bold text-charcoal-900 uppercase tracking-wider">
                Human Alert Delivery Verification
              </h2>
            </div>
            <span className="text-[11px] font-mono bg-rose-50 text-rose-800 px-2 py-0.5 rounded border border-rose-200 font-semibold">
              Live Webhook Dispatch
            </span>
          </div>

          <form onSubmit={handleSendTestAlert} className="space-y-4 text-xs">
            <p className="text-charcoal-600">
              Dispatches a <strong>real synthetic alert</strong> through the notification pipeline (Slack, Microsoft Teams, PagerDuty, or Email webhook) to confirm human receipt.
            </p>

            <div className="p-3 bg-charcoal-50 rounded-lg border border-charcoal-200 text-charcoal-700 font-mono text-[11px]">
              <span className="text-rose-700 font-bold block mb-1">
                [SYNTHETIC TEST ALERT - NOT A REAL INCIDENT]
              </span>
              <span>
                ZeroAgent-Scan Alert Delivery Verification: Simulated 12.5% scan failure threshold exceeded across pilot ring.
              </span>
            </div>

            <div>
              <label className="block font-semibold text-charcoal-800 mb-1">Target Webhook Endpoint URL</label>
              <input
                type="url"
                required
                value={testWebhookURL}
                onChange={(e) => setTestWebhookURL(e.target.value)}
                placeholder="https://hooks.slack.com/services/..."
                className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 font-mono text-charcoal-900 focus:ring-2 focus:ring-charcoal-950"
              />
            </div>

            <div>
              <label className="block font-semibold text-charcoal-800 mb-1">Test Reason / Operator Note</label>
              <input
                type="text"
                value={testReason}
                onChange={(e) => setTestReason(e.target.value)}
                placeholder="e.g. Quarterly notification pipeline validation"
                className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 text-charcoal-900 focus:ring-2 focus:ring-charcoal-950"
              />
            </div>

            {testAlertResult && (
              <div
                className={`p-3 rounded-lg border text-xs font-mono space-y-1 ${
                  testAlertResult.status === "DELIVERED"
                    ? "bg-emerald-50 border-emerald-200 text-emerald-900"
                    : "bg-rose-50 border-rose-200 text-rose-900"
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span>Delivery Status: {testAlertResult.status}</span>
                  <span>HTTP {testAlertResult.status_code}</span>
                </div>
                <div className="text-[11px] opacity-90">
                  <span>Receipt: <strong>{testAlertResult.verification_receipt}</strong></span> |{" "}
                  <span>Latency: {testAlertResult.duration_ms}ms</span>
                </div>
                {testAlertResult.error_message && (
                  <div className="text-rose-700 text-[11px] font-sans">
                    Error: {testAlertResult.error_message}
                  </div>
                )}
                <div className="text-[10px] text-charcoal-600 font-sans pt-1 border-t border-charcoal-200">
                  Result logged permanently to immutable audit trail with operator ID.
                </div>
              </div>
            )}

            <div className="pt-3 border-t border-charcoal-100 flex items-center justify-between">
              <span className="text-[10px] text-charcoal-500">
                Guaranteed safe: synthetic marker prevents false incident escalation.
              </span>
              <button
                type="submit"
                disabled={sendingTestAlert}
                className="px-4 py-2 bg-rose-700 hover:bg-rose-800 text-white rounded-lg font-semibold shadow-xs flex items-center gap-2 disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{sendingTestAlert ? "Dispatching..." : "Send Test Alert"}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Card 2: Rollout Tier Policy Settings */}
        <div className="bg-white rounded-xl border border-charcoal-200 p-6 shadow-xs card-border">
          <div className="flex items-center justify-between border-b border-charcoal-100 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-emerald-700" />
              <h2 className="text-sm font-bold text-charcoal-900 uppercase tracking-wider">
                Scheduled Fleet Scan Rollout Tiers
              </h2>
            </div>
            <span className="text-[11px] font-mono bg-charcoal-100 text-charcoal-800 px-2 py-0.5 rounded font-semibold">
              Default: Pilot Only
            </span>
          </div>

          <form onSubmit={handleSaveSettings} className="space-y-4 text-xs">
            <p className="text-charcoal-600">
              Only hosts residing in explicitly checked rollout tiers will be targeted by automated scheduled scan jobs.
            </p>

            <div className="space-y-2">
              <label
                onClick={() => handleTierToggle("pilot")}
                className={`p-3 rounded-lg border flex items-center justify-between cursor-pointer transition-colors ${
                  settings.active_tiers.includes("pilot")
                    ? "border-emerald-600 bg-emerald-50/60"
                    : "border-charcoal-200 bg-charcoal-50 opacity-60"
                }`}
              >
                <div>
                  <span className="font-bold text-charcoal-900 block">Pilot Ring (5-10%)</span>
                  <span className="text-[11px] text-charcoal-600">Canary endpoints, test labs, and pilot workstations.</span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.active_tiers.includes("pilot")}
                  onChange={() => {}}
                  className="rounded text-emerald-600 focus:ring-emerald-500"
                />
              </label>

              <label
                onClick={() => handleTierToggle("staged")}
                className={`p-3 rounded-lg border flex items-center justify-between cursor-pointer transition-colors ${
                  settings.active_tiers.includes("staged")
                    ? "border-blue-600 bg-blue-50/60"
                    : "border-charcoal-200 bg-charcoal-50 opacity-60"
                }`}
              >
                <div>
                  <span className="font-bold text-charcoal-900 block">Staged Ring (25-50%)</span>
                  <span className="text-[11px] text-charcoal-600">Secondary wave departmental endpoints and non-critical workloads.</span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.active_tiers.includes("staged")}
                  onChange={() => {}}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
              </label>

              <label
                onClick={() => handleTierToggle("full")}
                className={`p-3 rounded-lg border flex items-center justify-between cursor-pointer transition-colors ${
                  settings.active_tiers.includes("full")
                    ? "border-purple-600 bg-purple-50/60"
                    : "border-charcoal-200 bg-charcoal-50 opacity-60"
                }`}
              >
                <div>
                  <span className="font-bold text-charcoal-900 block">Full Fleet (100%)</span>
                  <span className="text-[11px] text-charcoal-600">Complete fleet of ~400 production endpoints and servers.</span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.active_tiers.includes("full")}
                  onChange={() => {}}
                  className="rounded text-purple-600 focus:ring-purple-500"
                />
              </label>
            </div>

            {settingsSavedMessage && (
              <div className="p-2 bg-emerald-50 border border-emerald-200 rounded text-emerald-800 text-xs font-semibold flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>{settingsSavedMessage}</span>
              </div>
            )}

            <div className="pt-3 border-t border-charcoal-100 flex items-center justify-end">
              <button
                type="submit"
                disabled={savingSettings}
                className="px-4 py-2 bg-charcoal-900 hover:bg-charcoal-950 text-white rounded-lg font-semibold shadow-xs flex items-center gap-2 disabled:opacity-50"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{savingSettings ? "Saving..." : "Save Scan Policy"}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Card 3: Bulk Assign Tiers by Subnet or Active Directory OU */}
        <div className="bg-white rounded-xl border border-charcoal-200 p-6 shadow-xs card-border lg:col-span-2">
          <div className="flex items-center justify-between border-b border-charcoal-100 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <FolderTree className="w-5 h-5 text-blue-700" />
              <h2 className="text-sm font-bold text-charcoal-900 uppercase tracking-wider">
                Bulk Assign Tiers (Subnet / Active Directory OU)
              </h2>
            </div>
            <span className="text-[11px] font-mono bg-blue-50 text-blue-800 px-2 py-0.5 rounded border border-blue-200 font-semibold">
              Admin Action
            </span>
          </div>

          <form onSubmit={handleBulkAssign} className="space-y-4 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block font-semibold text-charcoal-800 mb-1">Target Rollout Tier</label>
                <select
                  value={bulkTier}
                  onChange={(e: any) => setBulkTier(e.target.value)}
                  className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 font-medium"
                >
                  <option value="pilot">Pilot Ring</option>
                  <option value="staged">Staged Ring</option>
                  <option value="full">Full Fleet</option>
                </select>
              </div>

              <div>
                <label className="block font-semibold text-charcoal-800 mb-1">Bulk Scope Type</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setBulkScope("subnet")}
                    className={`p-2 rounded-lg border font-medium text-left ${
                      bulkScope === "subnet" ? "border-blue-600 bg-blue-50 text-blue-900 font-bold" : "border-charcoal-200"
                    }`}
                  >
                    By Subnet CIDR
                  </button>
                  <button
                    type="button"
                    onClick={() => setBulkScope("ou")}
                    className={`p-2 rounded-lg border font-medium text-left ${
                      bulkScope === "ou" ? "border-blue-600 bg-blue-50 text-blue-900 font-bold" : "border-charcoal-200"
                    }`}
                  >
                    By Active Directory OU
                  </button>
                </div>
              </div>
            </div>

            {bulkScope === "subnet" ? (
              <div>
                <label className="block font-semibold text-charcoal-800 mb-1">Target Subnet CIDR</label>
                <input
                  type="text"
                  value={targetSubnet}
                  onChange={(e) => setTargetSubnet(e.target.value)}
                  className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 font-mono text-charcoal-900"
                />
              </div>
            ) : (
              <div>
                <label className="block font-semibold text-charcoal-800 mb-1">Target Active Directory OU</label>
                <input
                  type="text"
                  value={targetOU}
                  onChange={(e) => setTargetOU(e.target.value)}
                  className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 font-mono text-charcoal-900"
                />
              </div>
            )}

            <div>
              <label className="block font-semibold text-charcoal-800 mb-1">
                Operator Justification Note <span className="text-rose-600">*</span>
              </label>
              <textarea
                required
                rows={2}
                placeholder="e.g. Assigning Subnet 10.100.1.0/24 to Pilot tier for pilot onboarding."
                value={bulkJustification}
                onChange={(e) => setBulkJustification(e.target.value)}
                className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 text-charcoal-900 placeholder:text-charcoal-400 focus:ring-2 focus:ring-charcoal-950"
              />
            </div>

            {bulkMessage && (
              <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-blue-800 text-xs font-semibold flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-blue-600" />
                <span>{bulkMessage}</span>
              </div>
            )}

            <div className="pt-3 border-t border-charcoal-100 flex items-center justify-end">
              <button
                type="submit"
                disabled={bulkAssigning || !bulkJustification.trim()}
                className="px-4 py-2 bg-blue-900 hover:bg-blue-950 text-white rounded-lg font-semibold shadow-xs disabled:opacity-50"
              >
                {bulkAssigning ? "Assigning..." : "Execute Bulk Assignment"}
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Dry Run Preview Modal */}
      {showDryRunModal && dryRunResult && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl border border-charcoal-300">
            <div className="p-5 border-b border-charcoal-200 flex items-center justify-between bg-charcoal-50 rounded-t-xl">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-purple-700" />
                <h3 className="font-bold text-charcoal-900 text-base">
                  Snapshot Retention Dry-Run Impact Preview (Safe Mode)
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowDryRunModal(false)}
                className="text-charcoal-500 hover:text-charcoal-800 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-6 text-sm">
              {/* Summary Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-charcoal-50 border border-charcoal-200 rounded-lg p-3">
                  <span className="text-xs text-charcoal-500 block">Evaluated Snapshots</span>
                  <span className="text-lg font-bold font-mono text-charcoal-900">
                    {dryRunResult.total_snapshots_evaluated}
                  </span>
                </div>
                <div className="bg-purple-50 border border-purple-200 rounded-lg p-3">
                  <span className="text-xs text-purple-700 block">Eligible for Action</span>
                  <span className="text-lg font-bold font-mono text-purple-900">
                    {dryRunResult.snapshots_eligible_for_action}
                  </span>
                </div>
                <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                  <span className="text-xs text-emerald-700 block">Estimated Space Saved</span>
                  <span className="text-lg font-bold font-mono text-emerald-900">
                    {dryRunResult.estimated_storage_saved_mb.toFixed(2)} MB
                  </span>
                </div>
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                  <span className="text-xs text-blue-700 block">Affected Endpoints</span>
                  <span className="text-lg font-bold font-mono text-blue-900">
                    {dryRunResult.affected_endpoints_count}
                  </span>
                </div>
              </div>

              {/* Notice */}
              <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900 font-medium">
                {dryRunResult.preserved_derived_records_notice}
              </div>

              {/* Sample Snapshots Table */}
              <div>
                <h4 className="font-bold text-charcoal-900 text-xs uppercase tracking-wider mb-2">
                  Sample Target Snapshots & Planned Actions
                </h4>
                <div className="border border-charcoal-200 rounded-lg overflow-hidden">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-charcoal-100 text-charcoal-700 font-semibold">
                      <tr>
                        <th className="p-2">Snapshot ID</th>
                        <th className="p-2">Hostname</th>
                        <th className="p-2">Captured At</th>
                        <th className="p-2">Payload Size</th>
                        <th className="p-2">Planned Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-charcoal-100">
                      {dryRunResult.sample_snapshots.map((s, idx) => (
                        <tr key={idx} className="hover:bg-charcoal-50">
                          <td className="p-2 font-mono text-charcoal-600">{s.snapshot_id}</td>
                          <td className="p-2 font-bold text-charcoal-900">{s.hostname}</td>
                          <td className="p-2 text-charcoal-600">{new Date(s.captured_at).toLocaleDateString()}</td>
                          <td className="p-2 font-mono text-charcoal-700">{(s.payload_size_bytes / 1024).toFixed(1)} KB</td>
                          <td className="p-2">
                            <span className="px-2 py-0.5 rounded font-bold text-[10px] bg-purple-100 text-purple-900">
                              {s.action}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-charcoal-200 bg-charcoal-50 rounded-b-xl flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setShowDryRunModal(false)}
                className="px-4 py-2 bg-charcoal-200 hover:bg-charcoal-300 text-charcoal-800 rounded-lg text-xs font-semibold"
              >
                Close Preview
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowDryRunModal(false);
                  handleExecuteRetention();
                }}
                className="px-4 py-2 bg-purple-900 hover:bg-purple-950 text-white rounded-lg text-xs font-bold"
              >
                Proceed with Execution
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
