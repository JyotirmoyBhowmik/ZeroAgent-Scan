"use client";

import React, { useEffect, useState } from "react";
import {
  FileBarChart2,
  FileText,
  Calendar,
  Share2,
  Download,
  Copy,
  Check,
  Plus,
  Clock,
  Shield,
  X,
  RefreshCw,
} from "lucide-react";
import { getReportConfigs, generateShareableReportLink, scheduleRecurringReport } from "@/lib/api";
import { InfoTooltip } from "@/components/ui/InfoTooltip";
import { ReportConfig } from "@/lib/types";

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportConfig[]>([]);
  const [loading, setLoading] = useState(true);

  // Share Link Modal State
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [activeReport, setActiveReport] = useState<ReportConfig | null>(null);
  const [ttlHours, setTtlHours] = useState(24);
  const [generatedLink, setGeneratedLink] = useState<{ shareable_url: string; expires_at: string } | null>(null);
  const [copied, setCopied] = useState(false);

  // New Schedule Modal State
  const [scheduleModalOpen, setScheduleModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newType, setNewType] = useState<"EXECUTIVE_SUMMARY" | "COMPLIANCE_AUDIT" | "VULNERABILITY_POSTURE">("EXECUTIVE_SUMMARY");
  const [newFormat, setNewFormat] = useState<"PDF" | "CSV">("PDF");
  const [newSchedule, setNewSchedule] = useState<"DAILY" | "WEEKLY" | "MONTHLY">("WEEKLY");
  const [newRecipient, setNewRecipient] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const loadReports = async () => {
    setLoading(true);
    try {
      const data = await getReportConfigs();
      setReports(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleGenerateShareLink = async (rep: ReportConfig) => {
    setActiveReport(rep);
    setShareModalOpen(true);
    setCopied(false);
    try {
      const link = await generateShareableReportLink(rep.id, ttlHours);
      setGeneratedLink(link);
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateSchedule = async () => {
    if (!newTitle.trim()) return;
    setSubmitting(true);
    try {
      const created = await scheduleRecurringReport({
        title: newTitle,
        report_type: newType,
        format: newFormat,
        schedule: newSchedule,
        recipients: newRecipient ? [newRecipient] : ["secops@corp.local"],
      });
      setReports([created, ...reports]);
      setScheduleModalOpen(false);
      setNewTitle("");
    } catch (err) {
      console.error(err);
    } finally {
      setSubmitting(false);
    }
  };

  const handleCopyLink = () => {
    if (generatedLink?.shareable_url) {
      navigator.clipboard.writeText(generatedLink.shareable_url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <FileBarChart2 className="w-6 h-6 text-emerald-400" />
            Executive & Compliance Report Builder
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Automated recurring exports (PDF / CSV) and cryptographically signed, expiring read-only links.
          </p>
        </div>

        <button
          onClick={() => setScheduleModalOpen(true)}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-colors"
        >
          <Plus className="w-4 h-4" /> Schedule New Report
        </button>
      </div>

      {/* Reports Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {reports.map((rep) => (
          <div
            key={rep.id}
            className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm space-y-4 hover:border-emerald-500/30 transition-all"
          >
            <div className="flex justify-between items-start">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-slate-100">{rep.title}</h2>
                  <span className="text-[11px] text-slate-400 font-mono">{rep.report_type} • {rep.format}</span>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-emerald-400 border border-slate-700">
                {rep.schedule}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 text-xs space-y-1.5">
              <div className="flex justify-between">
                <span className="text-slate-400">Recipients:</span>
                <span className="text-slate-200 font-mono truncate max-w-[200px]">{rep.recipients.join(", ")}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Last Generated:</span>
                <span className="text-slate-300">
                  {rep.last_generated_at ? new Date(rep.last_generated_at).toLocaleString() : "Pending next run"}
                </span>
              </div>
            </div>

            <div className="pt-2 flex justify-between items-center text-xs">
              <button
                onClick={() => handleGenerateShareLink(rep)}
                className="inline-flex items-center gap-1.5 text-slate-300 hover:text-emerald-400 font-medium transition-colors"
              >
                <Share2 className="w-3.5 h-3.5" /> Share Read-Only Link
              </button>
              <button className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-200 hover:text-white font-medium">
                <Download className="w-3.5 h-3.5" /> Export {rep.format}
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Shareable Link Modal */}
      {shareModalOpen && activeReport && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Share2 className="w-5 h-5 text-emerald-400" />
                Shareable Expiring Link
              </h3>
              <button onClick={() => setShareModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-300">
              Generates a cryptographically signed, time-limited token. The recipient gets a pre-scoped read-only view of{" "}
              <strong>{activeReport.title}</strong> with zero tenant RLS bypass.
            </p>

            <div>
              <div className="flex items-center gap-1.5 mb-1">
                <label className="text-xs text-slate-400">Expiration Window</label>
                <InfoTooltip fieldId="report.ttl_hours" iconClassName="text-slate-400 hover:text-white hover:bg-slate-700" />
              </div>
              <select
                value={ttlHours}
                onChange={(e) => {
                  setTtlHours(Number(e.target.value));
                  handleGenerateShareLink(activeReport);
                }}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
              >
                <option value={1}>1 Hour</option>
                <option value={24}>24 Hours (Standard)</option>
                <option value={72}>3 Days</option>
                <option value={168}>7 Days (Max)</option>
              </select>
            </div>

            {generatedLink && (
              <div className="space-y-2">
                <label className="text-xs text-slate-400 block">Signed URL</label>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    readOnly
                    value={generatedLink.shareable_url}
                    className="flex-1 bg-slate-800 border border-slate-700 rounded-lg p-2 font-mono text-[11px] text-emerald-400"
                  />
                  <button
                    onClick={handleCopyLink}
                    className="p-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white"
                    title="Copy Link"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
                <span className="text-[11px] text-slate-500 flex items-center gap-1">
                  <Clock className="w-3 h-3" /> Token valid until {new Date(generatedLink.expires_at).toLocaleString()}
                </span>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShareModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Schedule Recurring Report Modal */}
      {scheduleModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Calendar className="w-5 h-5 text-emerald-400" />
                Schedule Recurring Report
              </h3>
              <button onClick={() => setScheduleModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1">Report Title</label>
              <input
                type="text"
                placeholder="e.g. Monthly CIS Compliance Board Summary"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="flex items-center gap-1.5 mb-1">
                  <label className="text-xs text-slate-400">Report Type</label>
                  <InfoTooltip fieldId="report.type" iconClassName="text-slate-400 hover:text-white hover:bg-slate-700" />
                </div>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as any)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
                >
                  <option value="EXECUTIVE_SUMMARY">Executive Summary</option>
                  <option value="COMPLIANCE_AUDIT">Compliance Audit (CIS)</option>
                  <option value="VULNERABILITY_POSTURE">Vulnerability Posture (KEV)</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Format</label>
                <select
                  value={newFormat}
                  onChange={(e) => setNewFormat(e.target.value as any)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
                >
                  <option value="PDF">PDF Document</option>
                  <option value="CSV">CSV Data Export</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Schedule Cadence</label>
                <select
                  value={newSchedule}
                  onChange={(e) => setNewSchedule(e.target.value as any)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
                >
                  <option value="DAILY">Daily (06:00 UTC)</option>
                  <option value="WEEKLY">Weekly (Monday 08:00 UTC)</option>
                  <option value="MONTHLY">Monthly (1st of month)</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Email Recipient</label>
                <input
                  type="email"
                  placeholder="ciso@corp.local"
                  value={newRecipient}
                  onChange={(e) => setNewRecipient(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setScheduleModalOpen(false)}
                className="px-4 py-2 rounded-lg border border-slate-700 text-xs font-semibold text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateSchedule}
                disabled={submitting || !newTitle.trim()}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold text-white shadow-sm"
              >
                {submitting ? "Scheduling..." : "Save Schedule"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
