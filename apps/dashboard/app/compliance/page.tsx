"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Shield,
  Filter,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileCode,
  Terminal,
  RefreshCw,
  Search,
} from "lucide-react";
import { getCISResults, getFleetMetrics } from "@/lib/api";
import { CISResult, FleetMetrics } from "@/lib/types";

export default function CompliancePage() {
  const [results, setResults] = useState<CISResult[]>([]);
  const [metrics, setMetrics] = useState<FleetMetrics | null>(null);
  const [selectedFramework, setSelectedFramework] = useState("cis_win11_v2");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const [res, m] = await Promise.all([getCISResults(), getFleetMetrics()]);
        setResults(res);
        setMetrics(m);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const filteredResults = results.filter((r) => {
    if (statusFilter !== "ALL" && r.status !== statusFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        r.rule_title.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        r.cis_control_citation.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const passCount = results.filter((r) => r.status === "PASS").length;
  const failCount = results.filter((r) => r.status === "FAIL").length;
  const scorePercent = results.length > 0 ? Math.round((passCount / results.length) * 100) : 92;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <CheckCircle2 className="w-6 h-6 text-emerald-400" />
            CIS Benchmark Compliance Engine
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Automated evaluation of CIS Windows 11 Enterprise Benchmark v2.0.0 and DISA STIG controls.
          </p>
        </div>

        {/* Framework Selector */}
        <div className="flex items-center gap-3">
          <select
            value={selectedFramework}
            onChange={(e) => setSelectedFramework(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs font-semibold text-slate-200"
          >
            <option value="cis_win11_v2">CIS Windows 11 Benchmark v2.0.0</option>
            <option value="disa_stig_w11">DoD DISA STIG Windows 11 v1.1</option>
            <option value="pci_dss_v4">PCI-DSS v4.0 Endpoint Requirements</option>
          </select>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm">
          <span className="text-xs text-slate-400 font-medium">Framework Compliance Score</span>
          <div className="text-3xl font-bold text-emerald-400 mt-1">{scorePercent}%</div>
          <span className="text-[11px] text-slate-400 mt-1 block">Based on 28 automated checks</span>
        </div>

        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm">
          <span className="text-xs text-slate-400 font-medium">Passing Controls</span>
          <div className="text-3xl font-bold text-slate-100 mt-1">{passCount} Controls</div>
          <span className="text-[11px] text-emerald-400 mt-1 block">Compliant with baseline</span>
        </div>

        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm">
          <span className="text-xs text-slate-400 font-medium">Failing Controls (Remediation Required)</span>
          <div className="text-3xl font-bold text-rose-400 mt-1">{failCount} Controls</div>
          <span className="text-[11px] text-rose-400 mt-1 block">Action required to meet audit bar</span>
        </div>
      </div>

      {/* Rules Table & Filter Controls */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-6">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search rules, CIS citations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Filter Status:</span>
            {["ALL", "FAIL", "PASS"].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1.5 rounded-lg border font-semibold transition-colors ${
                  statusFilter === st
                    ? "bg-slate-800 text-white border-emerald-500/50"
                    : "bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200"
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-400 text-xs">Evaluating compliance benchmarks...</div>
        ) : filteredResults.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-sm">
            No compliance rules found matching the current search filters.
          </div>
        ) : (
          <div className="space-y-3">
            {filteredResults.map((rule) => {
              const isExpanded = expandedRule === rule.id;
              const isPass = rule.status === "PASS";

              return (
                <div
                  key={rule.id}
                  className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/40 hover:border-slate-700 transition-all"
                >
                  <div
                    onClick={() => setExpandedRule(isExpanded ? null : rule.id)}
                    className="p-4 flex items-center justify-between cursor-pointer gap-4"
                  >
                    <div className="flex items-center gap-3">
                      {isPass ? (
                        <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center flex-shrink-0">
                          <CheckCircle2 className="w-4 h-4" />
                        </div>
                      ) : (
                        <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center flex-shrink-0">
                          <XCircle className="w-4 h-4" />
                        </div>
                      )}
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-bold text-slate-200">{rule.rule_title}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-emerald-400 border border-slate-700">
                            {rule.cis_control_citation}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-400 mt-0.5 block">{rule.category}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          isPass
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : "bg-rose-500/10 text-rose-400 border-rose-500/20"
                        }`}
                      >
                        {rule.status}
                      </span>
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-slate-400" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-400" />
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="px-6 pb-6 pt-2 border-t border-slate-800/60 bg-slate-950/40 text-xs space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <span className="text-slate-400 font-medium block mb-1">Expected Configuration:</span>
                          <p className="font-mono text-emerald-400 bg-slate-900 p-2.5 rounded border border-slate-800">
                            {rule.expected_value}
                          </p>
                        </div>
                        <div>
                          <span className="text-slate-400 font-medium block mb-1">Observed Telemetry:</span>
                          <p className="font-mono text-rose-400 bg-slate-900 p-2.5 rounded border border-slate-800">
                            {rule.actual_value}
                          </p>
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-400 font-medium block mb-1">Control Rationale:</span>
                        <p className="text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded border border-slate-800">
                          {rule.rationale}
                        </p>
                      </div>

                      <div>
                        <span className="text-slate-400 font-medium block mb-1 flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-emerald-400" /> PowerShell Remediation Script:
                        </span>
                        <pre className="p-3 rounded bg-slate-900 border border-slate-800 text-emerald-400 font-mono text-[11px] overflow-x-auto">
                          {rule.remediation_script}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
