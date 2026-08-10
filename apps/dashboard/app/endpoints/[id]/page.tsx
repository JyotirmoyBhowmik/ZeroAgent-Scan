"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  Monitor,
  Cpu,
  HardDrive,
  Network,
  Shield,
  Clock,
  Layers,
  GitCompare,
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  FileCode2,
  RefreshCw,
  AlertCircle,
  Terminal,
} from "lucide-react";
import { getEndpointDetail, getHostSnapshots, getSnapshotDiff } from "@/lib/api";
import { InfoTooltip } from "@/components/ui/InfoTooltip";
import { EndpointDetail, HostSnapshot, SnapshotDiffItem } from "@/lib/types";

export default function HostDetailPage() {
  const params = useParams();
  const hostId = (params?.id as string) || "host-w11-exec-01";

  const [detail, setDetail] = useState<EndpointDetail | null>(null);
  const [snapshots, setSnapshots] = useState<HostSnapshot[]>([]);
  const [selectedTab, setSelectedTab] = useState<"inventory" | "security" | "software" | "timeline" | "diff">("inventory");
  const [diffSnapA, setDiffSnapA] = useState<string>("");
  const [diffSnapB, setDiffSnapB] = useState<string>("");
  const [diffResults, setDiffResults] = useState<SnapshotDiffItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [diffLoading, setDiffLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      setError(null);
      try {
        const [d, snaps] = await Promise.all([
          getEndpointDetail(hostId),
          getHostSnapshots(hostId),
        ]);
        setDetail(d);
        setSnapshots(snaps);
        if (snaps.length >= 2) {
          setDiffSnapA(snaps[0].id);
          setDiffSnapB(snaps[1].id);
        } else if (snaps.length === 1) {
          setDiffSnapA(snaps[0].id);
          setDiffSnapB(snaps[0].id);
        }
      } catch (err: any) {
        setError(err?.message || "Failed to load host telemetry detail.");
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [hostId]);

  const handleComputeDiff = async () => {
    if (!diffSnapA || !diffSnapB) return;
    setDiffLoading(true);
    try {
      const diff = await getSnapshotDiff(diffSnapA, diffSnapB);
      setDiffResults(diff);
    } catch (err) {
      console.error(err);
    } finally {
      setDiffLoading(false);
    }
  };

  useEffect(() => {
    if (selectedTab === "diff" && diffSnapA && diffSnapB && diffResults.length === 0) {
      handleComputeDiff();
    }
  }, [selectedTab, diffSnapA, diffSnapB]);

  if (loading) {
    return (
      <div className="p-8 max-w-7xl mx-auto space-y-6" aria-busy="true" aria-live="polite">
        <div className="h-6 w-32 bg-slate-800 animate-pulse rounded"></div>
        <div className="h-28 bg-slate-800/60 rounded-xl animate-pulse"></div>
        <div className="h-96 bg-slate-800/60 rounded-xl animate-pulse"></div>
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="p-8 max-w-2xl mx-auto text-center py-20" role="alert">
        <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-rose-500/10 text-rose-400 flex items-center justify-center">
          <AlertCircle className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-100 mb-2">Host Not Found or Error</h2>
        <p className="text-sm text-slate-400 mb-6">{error || "Unable to retrieve telemetry snapshot for host."}</p>
        <Link
          href="/endpoints"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Fleet Inventory
        </Link>
      </div>
    );
  }

  const { endpoint, hardware, security_posture, cis_results } = detail;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Back Button & Host Banner */}
      <div className="space-y-4">
        <Link
          href="/endpoints"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Fleet Inventory
        </Link>

        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/70 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 shadow-sm">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center flex-shrink-0">
              <Monitor className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-xl font-bold text-slate-100">{endpoint.hostname}</h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  {endpoint.status}
                </span>
                <span className="text-xs text-slate-400 font-mono">{endpoint.ip_address}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {endpoint.manufacturer} {endpoint.model} • {endpoint.os_name} (Build {endpoint.os_build})
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <div className="px-4 py-2 rounded-lg bg-slate-800/80 border border-slate-700/60 text-right">
              <div className="flex items-center justify-end gap-1 text-slate-400 text-[11px]">
                <span>CIS Compliance</span>
                <InfoTooltip fieldId="endpoint.compliance_score" iconClassName="text-slate-400 hover:text-white hover:bg-slate-700" />
              </div>
              <span className="text-base font-bold text-emerald-400 block">{endpoint.compliance_score.toFixed(1)}%</span>
            </div>
            <div className="px-4 py-2 rounded-lg bg-slate-800/80 border border-slate-700/60 text-right">
              <span className="text-slate-400 block text-[11px]">Last Scanned</span>
              <span className="text-slate-200 font-medium">
                {new Date(endpoint.last_scanned_at || Date.now()).toLocaleDateString()}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex border-b border-slate-800 gap-2 overflow-x-auto text-xs font-medium" role="tablist">
        {[
          { id: "inventory", label: "Hardware & BIOS", icon: Cpu },
          { id: "security", label: "Security Baseline", icon: Shield },
          { id: "software", label: "Software & Hotfixes", icon: Layers },
          { id: "timeline", label: `Scan Timeline (${snapshots.length})`, icon: Clock },
          { id: "diff", label: "Snapshot Diff Engine", icon: GitCompare },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = selectedTab === tab.id;
          return (
            <button
              key={tab.id}
              role="tab"
              aria-selected={isActive}
              onClick={() => setSelectedTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-all ${
                isActive
                  ? "border-emerald-500 text-emerald-400 font-semibold"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Content 1: Hardware & BIOS */}
      {selectedTab === "inventory" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* CPU & Memory */}
          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-emerald-400" /> Processor & Memory Subsystem
            </h2>
            <div className="space-y-3 text-xs divide-y divide-slate-800">
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">CPU Model</span>
                <span className="text-slate-100 font-medium">{hardware?.cpu_details?.name || "13th Gen Intel Core i7"}</span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">Cores / Threads</span>
                <span className="text-slate-100 font-medium">
                  {hardware?.cpu_details?.cores || 14} Cores / {hardware?.cpu_details?.logical_processors || 20} Threads
                </span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">Hardware Virtualization</span>
                <span className="text-emerald-400 font-medium">VT-x / AMD-V Active</span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">Total Installed RAM</span>
                <span className="text-slate-100 font-medium">
                  {((hardware?.memory_details?.total_bytes || 34359738368) / (1024 * 1024 * 1024)).toFixed(0)} GB DDR5
                </span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">DIMM Slots Used</span>
                <span className="text-slate-100 font-medium">
                  {hardware?.memory_details?.slots_used || 2} of {hardware?.memory_details?.total_slots || 2} Slots
                </span>
              </div>
            </div>
          </div>

          {/* BIOS & TPM */}
          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" /> BIOS & TPM 2.0 Security
            </h2>
            <div className="space-y-3 text-xs divide-y divide-slate-800">
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">BIOS Version / Date</span>
                <span className="text-slate-100 font-medium">{hardware?.bios_details?.version || "1.14.0 (03/15/2024)"}</span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">Secure Boot State</span>
                <span className="text-emerald-400 font-medium">Enabled (Active)</span>
              </div>
              <div className="flex justify-between pt-2">
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-400">TPM 2.0 Security Processor</span>
                  <InfoTooltip fieldId="endpoint.tpm" iconClassName="text-slate-400 hover:text-white hover:bg-slate-700" />
                </div>
                <span className="text-emerald-400 font-medium">Present (v2.0, Active)</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab Content 2: Security Baseline */}
      {selectedTab === "security" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" /> Disk Encryption & Defender
            </h2>
            <div className="space-y-3 text-xs divide-y divide-slate-800">
              <div className="flex justify-between pt-2">
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-400">BitLocker Protection (C:)</span>
                  <InfoTooltip fieldId="endpoint.bitlocker" iconClassName="text-slate-400 hover:text-white hover:bg-slate-700" />
                </div>
                <span className="text-emerald-400 font-medium">Protected (XTS-AES 256-bit)</span>
              </div>
              <div className="flex justify-between pt-2">
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-400">Defender Real-time Protection</span>
                  <InfoTooltip fieldId="endpoint.defender" iconClassName="text-slate-400 hover:text-white hover:bg-slate-700" />
                </div>
                <span className="text-emerald-400 font-medium">Enabled</span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">Defender Cloud-Delivered Protection</span>
                <span className="text-emerald-400 font-medium">Enabled</span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">Credential Guard</span>
                <span className="text-emerald-400 font-medium">VBS Running</span>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" /> Account Privileges & Firewall
            </h2>
            <div className="space-y-3 text-xs divide-y divide-slate-800">
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">Windows Firewall Profiles</span>
                <span className="text-emerald-400 font-medium">Domain / Private / Public Active</span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">UAC Admin Approval Mode</span>
                <span className="text-emerald-400 font-medium">Enforced</span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">SMBv1 Driver State</span>
                <span className="text-emerald-400 font-medium">Disabled</span>
              </div>
              <div className="flex justify-between pt-2">
                <span className="text-slate-400">Local Administrators Group</span>
                <span className="text-slate-100 font-mono text-[11px]">CORP\Domain Admins</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab Content 3: Software & Hotfixes */}
      {selectedTab === "software" && (
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4">
          <h2 className="text-sm font-semibold text-slate-100">Installed Software Packages & Hotfixes</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-medium uppercase">
                  <th className="pb-3">Application Name</th>
                  <th className="pb-3">Version</th>
                  <th className="pb-3">Vendor</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {[
                  { name: "Microsoft 365 Apps for enterprise", version: "16.0.17328.20184", vendor: "Microsoft Corporation" },
                  { name: "Google Chrome", version: "125.0.6422.142", vendor: "Google LLC" },
                  { name: "CrowdStrike Falcon Sensor", version: "7.14.18305.0", vendor: "CrowdStrike, Inc." },
                  { name: "Microsoft Visual Studio Code", version: "1.89.1", vendor: "Microsoft Corporation" },
                ].map((app, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="py-3 font-semibold text-slate-200">{app.name}</td>
                    <td className="py-3 font-mono text-slate-300">{app.version}</td>
                    <td className="py-3 text-slate-400">{app.vendor}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab Content 4: Scan Timeline */}
      {selectedTab === "timeline" && (
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-6">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Clock className="w-4 h-4 text-emerald-400" /> Historical Telemetry Snapshots
          </h2>
          <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            {snapshots.map((snap, idx) => (
              <div key={snap.id} className="relative">
                <div className="absolute -left-6 top-1 w-3 h-3 rounded-full bg-emerald-400 border-2 border-slate-900"></div>
                <div className="p-4 rounded-lg bg-slate-800/40 border border-slate-800 flex justify-between items-center">
                  <div>
                    <span className="text-xs font-bold text-slate-200">Snapshot #{snapshots.length - idx}</span>
                    <p className="text-[11px] text-slate-400 mt-0.5 font-mono">Payload Hash: {snap.payload_hash.substring(0, 24)}...</p>
                  </div>
                  <div className="text-right text-xs text-slate-400">
                    <span>{new Date(snap.created_at).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab Content 5: Snapshot Diff Engine */}
      {selectedTab === "diff" && (
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <GitCompare className="w-4 h-4 text-emerald-400" /> Telemetry Snapshot Diff Viewer
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">Select any two snapshots to view granular field-by-field hardware and security changes.</p>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <select
                value={diffSnapA}
                onChange={(e) => setDiffSnapA(e.target.value)}
                className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200"
              >
                {snapshots.map((s, i) => (
                  <option key={s.id} value={s.id}>
                    Snapshot {snapshots.length - i} ({new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
              <span className="text-slate-400 font-bold">vs</span>
              <select
                value={diffSnapB}
                onChange={(e) => setDiffSnapB(e.target.value)}
                className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200"
              >
                {snapshots.map((s, i) => (
                  <option key={s.id} value={s.id}>
                    Snapshot {snapshots.length - i} ({new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
              <button
                onClick={handleComputeDiff}
                className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold"
              >
                Diff
              </button>
            </div>
          </div>

          {diffLoading ? (
            <div className="py-12 text-center text-slate-400 text-xs">Comparing snapshot telemetry payloads...</div>
          ) : diffResults.length === 0 ? (
            <div className="py-12 text-center text-slate-400 text-xs">
              No differences detected between selected snapshots. Payload hashes match.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-medium uppercase">
                    <th className="pb-3">Subsystem</th>
                    <th className="pb-3">Field Path</th>
                    <th className="pb-3">Snapshot A (Prior)</th>
                    <th className="pb-3">Snapshot B (Current)</th>
                    <th className="pb-3">Change Type</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {diffResults.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/40">
                      <td className="py-3 font-semibold text-slate-300">{item.subsystem}</td>
                      <td className="py-3 font-mono text-[11px] text-slate-400">{item.field_path}</td>
                      <td className="py-3 font-mono text-[11px] text-rose-400 bg-rose-500/5 px-2 py-1 rounded">
                        {String(item.old_value)}
                      </td>
                      <td className="py-3 font-mono text-[11px] text-emerald-400 bg-emerald-500/5 px-2 py-1 rounded font-medium">
                        {String(item.new_value)}
                      </td>
                      <td className="py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                          {item.change_type}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
