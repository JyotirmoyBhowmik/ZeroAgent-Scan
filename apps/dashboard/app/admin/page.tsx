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
} from "lucide-react";
import { api } from "@/lib/api";
import { RolloutSettings, BulkAssignTierRequest } from "@/lib/types";

export default function AdminSettingsPage() {
  const [settings, setSettings] = useState<RolloutSettings>({
    active_tiers: ["pilot"],
    schedule_enforce_tiers: true,
  });
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsSavedMessage, setSettingsSavedMessage] = useState<string | null>(null);

  // Bulk assignment state
  const [bulkTier, setBulkTier] = useState<"pilot" | "staged" | "full">("pilot");
  const [bulkScope, setBulkScope] = useState<"subnet" | "ou">("subnet");
  const [targetSubnet, setTargetSubnet] = useState("10.100.1.0/24");
  const [targetOU, setTargetOU] = useState("OU=Workstations,DC=corp,DC=local");
  const [bulkJustification, setBulkJustification] = useState("");
  const [bulkAssigning, setBulkAssigning] = useState(false);
  const [bulkMessage, setBulkMessage] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      const data = await api.fetchRolloutSettings();
      setSettings(data);
    }
    load();
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
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">Enterprise Admin & Rollout Settings</h1>
        </div>
        <p className="text-sm text-charcoal-600 mt-1">
          Configure controlled pilot rings, scheduled scan tier constraints, and Active Directory OU bulk mappings.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Card 1: Scheduled Scan Rollout Tier Enforcement */}
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
              Automated nightly fleet scans will <strong>only</strong> target hosts belonging to explicitly enabled rollout tiers.
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

        {/* Card 2: Bulk Assign Tiers by Subnet or Active Directory OU */}
        <div className="bg-white rounded-xl border border-charcoal-200 p-6 shadow-xs card-border">
          <div className="flex items-center justify-between border-b border-charcoal-100 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <FolderTree className="w-5 h-5 text-blue-700" />
              <h2 className="text-sm font-bold text-charcoal-900 uppercase tracking-wider">
                Bulk Assign Tiers (Subnet / OU)
              </h2>
            </div>
            <span className="text-[11px] font-mono bg-blue-50 text-blue-800 px-2 py-0.5 rounded border border-blue-200 font-semibold">
              Admin Action
            </span>
          </div>

          <form onSubmit={handleBulkAssign} className="space-y-4 text-xs">
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
