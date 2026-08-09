"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Flame,
  AlertTriangle,
  CheckCircle2,
  Filter,
  Shield,
  Search,
  ExternalLink,
  Clock,
  Layers,
  FileCheck,
  X,
  RefreshCw,
} from "lucide-react";
import { getVulnerabilityFindings, updateVulnerabilityStatus } from "@/lib/api";
import { VulnerabilityFinding } from "@/lib/types";

export default function VulnerabilitiesPage() {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);

  // Bulk Status Modal State
  const [modalOpen, setModalOpen] = useState(false);
  const [targetStatus, setTargetStatus] = useState<"MITIGATED" | "ACCEPTED_RISK" | "FALSE_POSITIVE">("MITIGATED");
  const [justificationNote, setJustificationNote] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const data = await getVulnerabilityFindings();
      setFindings(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, []);

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedIds(filteredFindings.map((f) => f.id));
    } else {
      setSelectedIds([]);
    }
  };

  const handleToggleSelect = (id: string) => {
    if (selectedIds.includes(id)) {
      setSelectedIds(selectedIds.filter((i) => i !== id));
    } else {
      setSelectedIds([...selectedIds, id]);
    }
  };

  const handleExecuteBulkUpdate = async () => {
    if (!justificationNote.trim()) {
      alert("Mandatory justification note is required for compliance audit logging.");
      return;
    }

    setSubmitting(true);
    try {
      await updateVulnerabilityStatus(selectedIds, targetStatus, justificationNote);
      // Update local state
      setFindings(
        findings.map((f) =>
          selectedIds.includes(f.id)
            ? { ...f, status: targetStatus, justification_note: justificationNote }
            : f
        )
      );
      setSelectedIds([]);
      setModalOpen(false);
      setJustificationNote("");
    } catch (err) {
      console.error(err);
    } finally {
      setSubmitting(false);
    }
  };

  const filteredFindings = findings
    // Sort KEV first, then CVSS score descending
    .sort((a, b) => {
      if (a.is_kev && !b.is_kev) return -1;
      if (!a.is_kev && b.is_kev) return 1;
      return b.cvss_score - a.cvss_score;
    })
    .filter((f) => {
      if (statusFilter !== "ALL" && f.status !== statusFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          f.cve_id.toLowerCase().includes(q) ||
          f.hostname.toLowerCase().includes(q) ||
          f.short_description.toLowerCase().includes(q)
        );
      }
      return true;
    });

  const kevCount = findings.filter((f) => f.is_kev).length;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <Flame className="w-6 h-6 text-rose-400" />
            Vulnerability Management (CISA KEV Prioritized)
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Correlated NVD CVE feed with CISA Known Exploited Vulnerabilities catalog surfaced highest priority.
          </p>
        </div>

        {selectedIds.length > 0 && (
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-300 font-semibold">{selectedIds.length} findings selected</span>
            <button
              onClick={() => {
                setTargetStatus("MITIGATED");
                setModalOpen(true);
              }}
              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-colors"
            >
              Bulk Status Update
            </button>
          </div>
        )}
      </div>

      {/* CISA KEV Alert Banner */}
      <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-rose-500/20 text-rose-400 flex items-center justify-center flex-shrink-0">
            <Flame className="w-5 h-5" />
          </div>
          <div>
            <span className="text-xs font-bold text-rose-300 uppercase tracking-wider block">
              Active Exploitation Notice
            </span>
            <span className="text-xs text-slate-200">
              {kevCount} CVEs in your fleet appear on the CISA KEV catalog and carry mandatory remediation deadlines.
            </span>
          </div>
        </div>
        <a
          href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs font-semibold text-rose-400 hover:text-rose-300 inline-flex items-center gap-1 flex-shrink-0"
        >
          CISA Catalog <ExternalLink className="w-3 h-3" />
        </a>
      </div>

      {/* Findings Table Card */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-6">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search CVE-ID, host, description..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Status:</span>
            {["ALL", "OPEN", "MITIGATED", "ACCEPTED_RISK"].map((st) => (
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
          <div className="py-12 text-center text-slate-400 text-xs">Loading vulnerability telemetry...</div>
        ) : filteredFindings.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-sm">
            No vulnerability findings matching the current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-medium uppercase">
                  <th className="pb-3 w-8">
                    <input
                      type="checkbox"
                      onChange={handleSelectAll}
                      checked={selectedIds.length === filteredFindings.length && filteredFindings.length > 0}
                      className="rounded border-slate-700 bg-slate-800 text-emerald-500"
                      aria-label="Select all findings"
                    />
                  </th>
                  <th className="pb-3">CVE ID</th>
                  <th className="pb-3">CVSS</th>
                  <th className="pb-3">Affected Host</th>
                  <th className="pb-3">CISA KEV</th>
                  <th className="pb-3">Description & Remediation</th>
                  <th className="pb-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredFindings.map((f) => {
                  const isSelected = selectedIds.includes(f.id);

                  return (
                    <tr
                      key={f.id}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        f.is_kev ? "bg-rose-500/[0.03]" : ""
                      }`}
                    >
                      <td className="py-3">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleSelect(f.id)}
                          className="rounded border-slate-700 bg-slate-800 text-emerald-500"
                          aria-label={`Select ${f.cve_id}`}
                        />
                      </td>
                      <td className="py-3 font-mono font-bold text-slate-100">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="hover:text-emerald-400 underline decoration-slate-700 inline-flex items-center gap-1"
                        >
                          {f.cve_id} <ExternalLink className="w-2.5 h-2.5 text-slate-500" />
                        </a>
                      </td>
                      <td className="py-3 font-bold text-rose-400 font-mono">{f.cvss_score.toFixed(1)}</td>
                      <td className="py-3 text-slate-200">
                        <Link href={`/endpoints/${f.endpoint_id}`} className="hover:text-emerald-400">
                          {f.hostname}
                        </Link>
                      </td>
                      <td className="py-3">
                        {f.is_kev ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            <Flame className="w-3 h-3 text-rose-500" /> KEV Due {f.kev_due_date || "Immediate"}
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-500">Standard</span>
                        )}
                      </td>
                      <td className="py-3 max-w-xs text-slate-300">
                        <p className="font-medium text-slate-200">{f.short_description}</p>
                        <p className="text-[11px] text-slate-400 mt-0.5">{f.remediation_guidance}</p>
                      </td>
                      <td className="py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                            f.status === "OPEN"
                              ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                              : f.status === "MITIGATED"
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                              : "bg-amber-500/10 text-amber-400 border-amber-500/20"
                          }`}
                        >
                          {f.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Mandatory Justification Modal for Bulk Status Update */}
      {modalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="modal-title"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex justify-between items-center">
              <h3 id="modal-title" className="text-base font-bold text-slate-100 flex items-center gap-2">
                <FileCheck className="w-5 h-5 text-emerald-400" />
                Bulk Status Change ({selectedIds.length} findings)
              </h3>
              <button
                onClick={() => setModalOpen(false)}
                className="text-slate-400 hover:text-white"
                aria-label="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1.5">Target Status</label>
              <select
                value={targetStatus}
                onChange={(e) => setTargetStatus(e.target.value as any)}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
              >
                <option value="MITIGATED">MITIGATED (Patch Applied / Compensating Control Active)</option>
                <option value="ACCEPTED_RISK">ACCEPTED RISK (Approved by Security Officer)</option>
                <option value="FALSE_POSITIVE">FALSE POSITIVE (Verified Inapplicable)</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1.5">
                Mandatory Audit Justification Note <span className="text-rose-400">*</span>
              </label>
              <textarea
                rows={3}
                placeholder="Explain the technical basis or ticket number for this status change..."
                value={justificationNote}
                onChange={(e) => setJustificationNote(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-3 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              ></textarea>
              <span className="text-[11px] text-slate-500 mt-1 block">
                This note will be cryptographically written to the immutable security_audit_logs table.
              </span>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setModalOpen(false)}
                className="px-4 py-2 rounded-lg border border-slate-700 text-xs font-semibold text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteBulkUpdate}
                disabled={submitting || !justificationNote.trim()}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold text-white shadow-sm"
              >
                {submitting ? "Updating..." : "Commit Status Change"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
