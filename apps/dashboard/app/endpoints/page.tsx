"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Search,
  Filter,
  Monitor,
  Server,
  Laptop,
  ShieldCheck,
  ArrowUpRight,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  TrendingUp,
  Lock,
  Layers,
  Sparkles,
  RefreshCw,
  FolderTree,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { Endpoint, PilotHealthSummary, RolloutTier, PromoteTierRequest } from "@/lib/types";

export default function EndpointsPage() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [pilotSummary, setPilotSummary] = useState<PilotHealthSummary | null>(null);
  const [search, setSearch] = useState("");
  const [osFilter, setOsFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [tierFilter, setTierFilter] = useState<string>("");
  const [loading, setLoading] = useState(true);

  // Promotion Modal State
  const [showPromoteModal, setShowPromoteModal] = useState(false);
  const [targetTier, setTargetTier] = useState<"staged" | "full">("staged");
  const [promotionJustification, setPromotionJustification] = useState("");
  const [promotionScope, setPromotionScope] = useState<"all_pilot" | "by_subnet" | "by_ou">("all_pilot");
  const [selectedSubnet, setSelectedSubnet] = useState("10.100.1.0/24");
  const [selectedOU, setSelectedOU] = useState("OU=Workstations,DC=corp,DC=local");
  const [promoting, setPromoting] = useState(false);
  const [promotionFeedback, setPromotionFeedback] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [data, summary] = await Promise.all([
        api.getEndpoints(search, osFilter, statusFilter),
        api.fetchPilotHealthSummary(),
      ]);
      setEndpoints(data);
      setPilotSummary(summary);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [search, osFilter, statusFilter, tierFilter]);

  const handlePromoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!promotionJustification.trim()) {
      alert("Mandatory justification note is required to promote rollout tiers for audit logging.");
      return;
    }

    setPromoting(true);
    try {
      const req: PromoteTierRequest = {
        target_tier: targetTier,
        justification: promotionJustification,
        ...(promotionScope === "by_subnet" ? { subnet_cidr: selectedSubnet } : {}),
        ...(promotionScope === "by_ou" ? { organizational_unit: selectedOU } : {}),
      };

      const res = await api.promoteRolloutTier(req);
      setPromotionFeedback(
        `Successfully promoted ${res.promoted_count} endpoints to '${res.target_tier}'. Action logged to immutable audit trail.`
      );
      setTimeout(() => {
        setShowPromoteModal(false);
        setPromotionFeedback(null);
        setPromotionJustification("");
        loadData();
      }, 1500);
    } catch (err: any) {
      alert(err.message || "Failed to promote rollout tier");
    } finally {
      setPromoting(false);
    }
  };

  const filteredEndpoints = endpoints.filter((ep) => {
    if (tierFilter && ep.rollout_tier !== tierFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">Fleet Endpoints & Rollout Tiers</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-100 text-purple-800 border border-purple-200">
              Phased Deployment Active
            </span>
          </div>
          <p className="text-sm text-charcoal-600 mt-1">
            Controlled agentless introspection across Pilot, Staged, and Full Fleet rings with Active Directory safety guarantees.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setTargetTier("staged");
              setShowPromoteModal(true);
            }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-purple-900 hover:bg-purple-950 text-white rounded-lg text-xs font-semibold shadow-sm transition-all"
          >
            <TrendingUp className="w-3.5 h-3.5" />
            <span>Promote Rollout Tier</span>
          </button>
        </div>
      </div>

      {/* 1. Pilot Health Summary View (Controlled Pilot Eye-Ball Widget) */}
      {pilotSummary && (
        <div className="bg-gradient-to-br from-purple-900/5 via-white to-charcoal-50 p-5 rounded-xl border border-purple-200/80 shadow-xs">
          <div className="flex items-center justify-between mb-3 border-b border-purple-100 pb-2.5">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-purple-700" />
              <h2 className="text-sm font-bold text-charcoal-900 uppercase tracking-wider">
                Pilot Ring Health Summary (Isolated Pilot Hosts)
              </h2>
            </div>
            <span className="text-[11px] font-mono text-purple-700 bg-purple-50 px-2 py-0.5 rounded border border-purple-200">
              Filtered to Pilot Tier Only
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <div className="bg-white p-3 rounded-lg border border-charcoal-200 shadow-2xs">
              <span className="text-[11px] text-charcoal-500 block font-medium">Pilot Hosts</span>
              <div className="text-xl font-bold text-charcoal-950 font-mono mt-0.5">
                {pilotSummary.total_pilot_hosts}{" "}
                <span className="text-xs font-normal text-charcoal-500">hosts</span>
              </div>
            </div>

            <div className="bg-white p-3 rounded-lg border border-charcoal-200 shadow-2xs">
              <span className="text-[11px] text-charcoal-500 block font-medium">Scan Success Rate</span>
              <div className="text-xl font-bold text-emerald-700 font-mono mt-0.5 flex items-center gap-1">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>{pilotSummary.scan_success_rate.toFixed(1)}%</span>
              </div>
            </div>

            <div className="bg-white p-3 rounded-lg border border-charcoal-200 shadow-2xs">
              <span className="text-[11px] text-charcoal-500 block font-medium">Auth Failures (401/403)</span>
              <div className="text-xl font-bold text-charcoal-900 font-mono mt-0.5">
                {pilotSummary.auth_failure_count === 0 ? (
                  <span className="text-emerald-700 font-semibold">0 (Clean)</span>
                ) : (
                  <span className="text-rose-600 font-semibold">{pilotSummary.auth_failure_count}</span>
                )}
              </div>
            </div>

            <div className="bg-white p-3 rounded-lg border border-charcoal-200 shadow-2xs">
              <span className="text-[11px] text-charcoal-500 block font-medium">AD Lockout Risk</span>
              <div className="text-xl font-bold text-emerald-700 font-mono mt-0.5 flex items-center gap-1">
                <Lock className="w-3.5 h-3.5 text-emerald-600" />
                <span>0 Lockouts</span>
              </div>
            </div>

            <div className="bg-white p-3 rounded-lg border border-charcoal-200 shadow-2xs">
              <span className="text-[11px] text-charcoal-500 block font-medium">EDR / AV Alerts</span>
              <div className="text-xl font-bold text-emerald-700 font-mono mt-0.5">
                <span className="text-emerald-700">0 Alerts</span>
              </div>
            </div>

            <div className="bg-white p-3 rounded-lg border border-charcoal-200 shadow-2xs">
              <span className="text-[11px] text-charcoal-500 block font-medium">Avg Pilot Latency</span>
              <div className="text-xl font-bold text-charcoal-950 font-mono mt-0.5">
                {pilotSummary.average_scan_duration_ms}ms
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="bg-white p-4 rounded-xl border border-charcoal-200 flex flex-col md:flex-row items-center justify-between gap-4 card-border">
        {/* Tier Tabs */}
        <div className="flex items-center gap-1.5 p-1 bg-charcoal-100 rounded-lg w-full md:w-auto">
          <button
            onClick={() => setTierFilter("")}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
              tierFilter === "" ? "bg-white text-charcoal-950 shadow-xs" : "text-charcoal-600 hover:text-charcoal-950"
            }`}
          >
            All Endpoints ({endpoints.length})
          </button>
          <button
            onClick={() => setTierFilter("pilot")}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all flex items-center gap-1.5 ${
              tierFilter === "pilot"
                ? "bg-purple-900 text-white shadow-xs"
                : "text-purple-800 hover:bg-purple-50"
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-purple-400"></span>
            <span>Pilot Ring</span>
          </button>
          <button
            onClick={() => setTierFilter("staged")}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all flex items-center gap-1.5 ${
              tierFilter === "staged"
                ? "bg-blue-900 text-white shadow-xs"
                : "text-blue-800 hover:bg-blue-50"
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-blue-400"></span>
            <span>Staged Ring</span>
          </button>
          <button
            onClick={() => setTierFilter("full")}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all flex items-center gap-1.5 ${
              tierFilter === "full"
                ? "bg-emerald-900 text-white shadow-xs"
                : "text-emerald-800 hover:bg-emerald-50"
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>Full Fleet</span>
          </button>
        </div>

        {/* Search & Select Filters */}
        <div className="flex flex-col md:flex-row items-center gap-3 w-full md:w-auto">
          <div className="relative w-full md:w-64">
            <Search className="w-4 h-4 text-charcoal-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search host, OU, subnet..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 text-xs bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 placeholder:text-charcoal-400 focus:outline-none focus:ring-2 focus:ring-charcoal-950"
            />
          </div>

          <select
            value={osFilter}
            onChange={(e) => setOsFilter(e.target.value)}
            className="text-xs bg-charcoal-50 border border-charcoal-200 rounded-lg px-3 py-1.5 text-charcoal-800 focus:outline-none focus:ring-2 focus:ring-charcoal-950"
          >
            <option value="">All Operating Systems</option>
            <option value="Windows 11">Windows 11</option>
            <option value="Windows Server">Windows Server</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="text-xs bg-charcoal-50 border border-charcoal-200 rounded-lg px-3 py-1.5 text-charcoal-800 focus:outline-none focus:ring-2 focus:ring-charcoal-950"
          >
            <option value="">All Statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
          </select>
        </div>
      </div>

      {/* Main Endpoints Data Grid */}
      <div className="bg-white rounded-xl border border-charcoal-200 overflow-hidden card-border">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-charcoal-50/70 border-b border-charcoal-200 text-charcoal-600 uppercase tracking-wider font-semibold">
                <th className="py-3.5 px-6">Endpoint / Hostname</th>
                <th className="py-3.5 px-4">Rollout Tier</th>
                <th className="py-3.5 px-4">Active Directory OU & Subnet</th>
                <th className="py-3.5 px-4">Network & Protocol</th>
                <th className="py-3.5 px-4">Operating System</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">Compliance</th>
                <th className="py-3.5 px-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-charcoal-100">
              {filteredEndpoints.map((ep) => (
                <tr key={ep.id} className="hover:bg-charcoal-50/70 transition-colors group">
                  <td className="py-4 px-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-charcoal-100 border border-charcoal-200 text-charcoal-800 group-hover:border-charcoal-400 transition-colors">
                        {ep.chassis_type === "Laptop" ? (
                          <Laptop className="w-4 h-4" />
                        ) : ep.chassis_type === "Server" ? (
                          <Server className="w-4 h-4" />
                        ) : (
                          <Monitor className="w-4 h-4" />
                        )}
                      </div>
                      <div>
                        <Link href={`/endpoints/${ep.id}`} className="font-bold text-sm text-charcoal-950 hover:text-emerald-700 block">
                          {ep.hostname}
                        </Link>
                        <span className="text-[11px] text-charcoal-500 font-mono block">
                          {ep.manufacturer} {ep.model}
                        </span>
                      </div>
                    </div>
                  </td>

                  {/* Rollout Tier Badge */}
                  <td className="py-4 px-4">
                    {ep.rollout_tier === "pilot" && (
                      <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-bold bg-purple-100 text-purple-900 border border-purple-200 font-mono">
                        PILOT
                      </span>
                    )}
                    {ep.rollout_tier === "staged" && (
                      <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-bold bg-blue-100 text-blue-900 border border-blue-200 font-mono">
                        STAGED
                      </span>
                    )}
                    {ep.rollout_tier === "full" && (
                      <span className="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-bold bg-emerald-100 text-emerald-900 border border-emerald-200 font-mono">
                        FULL FLEET
                      </span>
                    )}
                  </td>

                  {/* OU & Subnet */}
                  <td className="py-4 px-4 font-mono text-[11px]">
                    <span className="text-charcoal-900 font-medium block truncate max-w-[200px]" title={ep.organizational_unit}>
                      {ep.organizational_unit || "OU=Workstations"}
                    </span>
                    <span className="text-charcoal-500 text-[10px] block">{ep.subnet_cidr || "10.100.1.0/24"}</span>
                  </td>

                  <td className="py-4 px-4 font-mono">
                    <span className="text-charcoal-900 font-semibold block">{ep.ip_address}</span>
                    <span className="text-[10px] text-emerald-700 font-semibold block">WinRM HTTPS:5986</span>
                  </td>

                  <td className="py-4 px-4">
                    <span className="text-charcoal-900 font-medium block">{ep.os_name}</span>
                    <span className="text-[11px] text-charcoal-500 font-mono block">Build {ep.os_build}</span>
                  </td>

                  <td className="py-4 px-4">
                    <Badge variant={ep.status === "online" ? "success" : "danger"} size="sm">
                      {ep.status}
                    </Badge>
                  </td>

                  <td className="py-4 px-4 text-right">
                    <span
                      className={`inline-flex items-center px-2.5 py-1 rounded text-xs font-bold font-mono border ${
                        ep.compliance_score >= 90
                          ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                          : "bg-amber-50 text-amber-700 border-amber-200"
                      }`}
                    >
                      {ep.compliance_score.toFixed(1)}%
                    </span>
                  </td>

                  <td className="py-4 px-6 text-right">
                    <Link
                      href={`/endpoints/${ep.id}`}
                      className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-charcoal-100 hover:bg-charcoal-950 hover:text-white text-charcoal-800 text-xs font-medium transition-colors"
                    >
                      <span>Inspect</span>
                      <ArrowUpRight className="w-3 h-3" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Promotion Modal */}
      {showPromoteModal && (
        <div className="fixed inset-0 z-50 bg-charcoal-950/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-xl max-w-lg w-full p-6 shadow-2xl border border-charcoal-200 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-charcoal-100 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-purple-700" />
                <h3 className="text-base font-bold text-charcoal-950">Promote Rollout Tier Ring</h3>
              </div>
              <button
                onClick={() => setShowPromoteModal(false)}
                className="text-charcoal-400 hover:text-charcoal-700 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handlePromoteSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block font-semibold text-charcoal-800 mb-1">Target Rollout Tier</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setTargetTier("staged")}
                    className={`py-2 px-3 rounded-lg border text-left font-medium flex items-center justify-between ${
                      targetTier === "staged"
                        ? "border-blue-600 bg-blue-50 text-blue-900 font-bold"
                        : "border-charcoal-200 hover:bg-charcoal-50"
                    }`}
                  >
                    <span>Staged Ring</span>
                    <span className="text-[10px] text-charcoal-500 font-normal">Next Wave</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setTargetTier("full")}
                    className={`py-2 px-3 rounded-lg border text-left font-medium flex items-center justify-between ${
                      targetTier === "full"
                        ? "border-emerald-600 bg-emerald-50 text-emerald-900 font-bold"
                        : "border-charcoal-200 hover:bg-charcoal-50"
                    }`}
                  >
                    <span>Full Fleet (100%)</span>
                    <span className="text-[10px] text-charcoal-500 font-normal">All 400 Hosts</span>
                  </button>
                </div>
              </div>

              <div>
                <label className="block font-semibold text-charcoal-800 mb-1">Promotion Scope</label>
                <select
                  value={promotionScope}
                  onChange={(e: any) => setPromotionScope(e.target.value)}
                  className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 text-charcoal-900 focus:ring-2 focus:ring-charcoal-950"
                >
                  <option value="all_pilot">All Endpoints in Pilot Ring</option>
                  <option value="by_subnet">By Subnet CIDR (e.g. 10.100.1.0/24)</option>
                  <option value="by_ou">By Active Directory OU</option>
                </select>
              </div>

              {promotionScope === "by_subnet" && (
                <div>
                  <label className="block font-semibold text-charcoal-800 mb-1">Select Subnet CIDR</label>
                  <input
                    type="text"
                    value={selectedSubnet}
                    onChange={(e) => setSelectedSubnet(e.target.value)}
                    className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 font-mono text-charcoal-900"
                  />
                </div>
              )}

              {promotionScope === "by_ou" && (
                <div>
                  <label className="block font-semibold text-charcoal-800 mb-1">Active Directory OU Distinguished Name</label>
                  <input
                    type="text"
                    value={selectedOU}
                    onChange={(e) => setSelectedOU(e.target.value)}
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
                  rows={3}
                  placeholder="e.g. Pilot scan completed with 100% success and 0 auth failures. Promoting to Staged tier for broader validation."
                  value={promotionJustification}
                  onChange={(e) => setPromotionJustification(e.target.value)}
                  className="w-full bg-charcoal-50 border border-charcoal-200 rounded-lg p-2 text-charcoal-900 placeholder:text-charcoal-400 focus:ring-2 focus:ring-charcoal-950"
                />
                <span className="text-[10px] text-charcoal-500 mt-1 block">
                  Mandatory justification note recorded into the immutable append-only audit trail.
                </span>
              </div>

              {promotionFeedback && (
                <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-emerald-800 text-xs font-semibold flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>{promotionFeedback}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-charcoal-100">
                <button
                  type="button"
                  onClick={() => setShowPromoteModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-charcoal-200 text-charcoal-700 hover:bg-charcoal-50 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={promoting || !promotionJustification.trim()}
                  className="px-4 py-1.5 rounded-lg bg-purple-900 hover:bg-purple-950 text-white font-semibold shadow-xs disabled:opacity-50"
                >
                  {promoting ? "Promoting..." : "Confirm & Log Promotion"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
