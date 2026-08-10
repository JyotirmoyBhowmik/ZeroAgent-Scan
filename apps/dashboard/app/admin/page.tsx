"use client";

import React, { useEffect, useState } from "react";
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
} from "lucide-react";
import { api } from "@/lib/api";
import { RolloutSettings, BulkAssignTierRequest, AlertHealthStatus, TestAlertResponse } from "@/lib/types";

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
      const [rolloutData, healthData] = await Promise.all([
        api.fetchRolloutSettings(),
        api.fetchAlertHealthStatus(),
      ]);
      setSettings(rolloutData);
      setAlertHealth(healthData);
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <Settings2 className="w-6 h-6 text-charcoal-900" />
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">Enterprise Admin & System Health</h1>
        </div>
        <p className="text-sm text-charcoal-600 mt-1">
          Verify human alerting delivery, configure scheduled scan rollout constraints, and manage Active Directory bulk assignments.
        </p>
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

        {/* Card 2: Scheduled Scan Rollout Tier Enforcement */}
        <div className="bg-white rounded-xl border border-charcoal-200 p-6 shadow-xs card-border">
          <div className="flex items-center justify-between border-b border-charcoal-100 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-purple-700" />
              <h2 className="text-sm font-bold text-charcoal-900 uppercase tracking-wider">
                Scheduled Scan Rollout Policy
              </h2>
            </div>
            <span className="text-[11px] font-mono bg-purple-50 text-purple-800 px-2 py-0.5 rounded border border-purple-200 font-semibold">
              Default: Pilot Only
            </span>
          </div>

          <form onSubmit={handleSaveSettings} className="space-y-4 text-xs">
            <p className="text-charcoal-600">
              Automated fleet scans will <strong>only</strong> target hosts belonging to explicitly enabled rollout tiers.
              Unchecked tiers are strictly skipped during cron executions.
            </p>

            <div className="space-y-2.5">
              {/* Pilot Tier */}
              <label className="flex items-start gap-3 p-3 rounded-lg border border-purple-200 bg-purple-50/50 cursor-pointer hover:bg-purple-50 transition-colors">
                <input
                  type="checkbox"
                  checked={settings.active_tiers.includes("pilot")}
                  onChange={() => handleTierToggle("pilot")}
                  className="mt-0.5 rounded text-purple-900 focus:ring-purple-900"
                />
                <div>
                  <span className="font-bold text-charcoal-900 block">Pilot Ring (Initial Wave)</span>
                  <span className="text-[11px] text-charcoal-600 block mt-0.5">
                    Safe pilot hosts across test subnets. High-frequency validation with 0 AD lockout risk.
                  </span>
                </div>
              </label>

              {/* Staged Tier */}
              <label className="flex items-start gap-3 p-3 rounded-lg border border-blue-200 bg-blue-50/50 cursor-pointer hover:bg-blue-50 transition-colors">
                <input
                  type="checkbox"
                  checked={settings.active_tiers.includes("staged")}
                  onChange={() => handleTierToggle("staged")}
                  className="mt-0.5 rounded text-blue-900 focus:ring-blue-900"
                />
                <div>
                  <span className="font-bold text-charcoal-900 block">Staged Ring (Expanded Validation)</span>
                  <span className="text-[11px] text-charcoal-600 block mt-0.5">
                    Departmental workstations and non-critical servers (e.g. Finance, Engineering).
                  </span>
                </div>
              </label>

              {/* Full Fleet Tier */}
              <label className="flex items-start gap-3 p-3 rounded-lg border border-emerald-200 bg-emerald-50/50 cursor-pointer hover:bg-emerald-50 transition-colors">
                <input
                  type="checkbox"
                  checked={settings.active_tiers.includes("full")}
                  onChange={() => handleTierToggle("full")}
                  className="mt-0.5 rounded text-emerald-900 focus:ring-emerald-900"
                />
                <div>
                  <span className="font-bold text-charcoal-900 block">Full Fleet (100% Production Coverage)</span>
                  <span className="text-[11px] text-charcoal-600 block mt-0.5">
                    All ~400 production endpoints including Domain Controllers and SQL database clusters.
                  </span>
                </div>
              </label>
            </div>

            {settingsSavedMessage && (
              <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-emerald-800 text-xs font-semibold flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>{settingsSavedMessage}</span>
              </div>
            )}

            <div className="pt-3 border-t border-charcoal-100 flex items-center justify-between">
              <span className="text-[11px] text-charcoal-500">Tier promotions are never automated.</span>
              <button
                type="submit"
                disabled={savingSettings}
                className="px-4 py-2 bg-charcoal-950 hover:bg-charcoal-900 text-white rounded-lg font-semibold shadow-xs flex items-center gap-2"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{savingSettings ? "Saving..." : "Save Rollout Policy"}</span>
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
    </div>
  );
}
