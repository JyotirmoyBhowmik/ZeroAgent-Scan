"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  ArrowLeft,
  Terminal,
  Key,
  Database,
  Sliders,
  FileText,
  Network,
  Copy,
  Check,
  Sparkles,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { ProductionReadinessReport, ReadinessCheckItem } from "@/lib/types";

export default function ProductionReadinessPage() {
  const [report, setReport] = useState<ProductionReadinessReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const loadReport = async () => {
    setLoading(true);
    try {
      const data = await api.fetchProductionReadiness();
      setReport(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReport();
  }, []);

  const copyRemediation = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getPillarIcon = (pillar: string) => {
    switch (pillar) {
      case "DEMO_HYGIENE":
        return Database;
      case "CREDENTIAL_SECURITY":
        return Key;
      case "FEATURE_FLAGS":
        return Sliders;
      case "AUDIT_INTEGRITY":
        return FileText;
      case "NETWORK_MTLS":
        return Network;
      default:
        return ShieldCheck;
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Back Link & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-charcoal-200 pb-4">
        <div>
          <Link
            href="/admin"
            className="inline-flex items-center gap-1.5 text-xs text-charcoal-500 hover:text-charcoal-900 font-medium mb-2 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Admin Panel
          </Link>
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950 flex items-center gap-2.5">
            <ShieldCheck className="w-6 h-6 text-emerald-600" />
            Production Readiness & Go-Live Auditor
          </h1>
          <p className="text-xs text-charcoal-600 mt-1">
            Automated verification verifying complete elimination of demo seed data, hardened cryptographic keys, and production safety flags.
          </p>
        </div>

        <button
          onClick={loadReport}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3.5 py-2 bg-charcoal-950 hover:bg-charcoal-800 text-white text-xs font-semibold rounded-lg shadow-sm transition-all self-start md:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Re-Run Readiness Audit</span>
        </button>
      </div>

      {/* Main Verdict Card */}
      {report && (
        <div
          className={`p-6 rounded-2xl border transition-all ${
            report.overall_verdict === "PASS"
              ? "bg-gradient-to-br from-emerald-50 via-white to-emerald-50/30 border-emerald-300 shadow-sm"
              : "bg-gradient-to-br from-rose-50 via-white to-rose-50/30 border-rose-300 shadow-sm"
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="flex items-start gap-4">
              <div
                className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 shadow-sm ${
                  report.overall_verdict === "PASS"
                    ? "bg-emerald-600 text-white"
                    : "bg-rose-600 text-white"
                }`}
              >
                {report.overall_verdict === "PASS" ? (
                  <CheckCircle2 className="w-7 h-7" />
                ) : (
                  <ShieldAlert className="w-7 h-7" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2.5">
                  <span
                    className={`text-lg font-extrabold tracking-tight ${
                      report.overall_verdict === "PASS" ? "text-emerald-950" : "text-rose-950"
                    }`}
                  >
                    {report.overall_verdict === "PASS"
                      ? "GO-LIVE APPROVED: PRODUCTION READY"
                      : "GO-LIVE BLOCKED: REMEDIATION REQUIRED"}
                  </span>
                  <Badge
                    variant={report.overall_verdict === "PASS" ? "success" : "danger"}
                    size="md"
                  >
                    VERDICT: {report.overall_verdict}
                  </Badge>
                </div>
                <p className="text-xs text-charcoal-700 mt-1 max-w-2xl">
                  {report.overall_verdict === "PASS"
                    ? "All security gates, entropy audits, and zero demo data invariants passed. Safe for enterprise production deployment."
                    : `${report.failed_count} critical safety checks failed. Demo data or default credentials must be remediated prior to go-live.`}
                </p>
              </div>
            </div>

            {/* Quick Stat Pill Grid */}
            <div className="flex items-center gap-3 shrink-0 bg-white/80 backdrop-blur-xs p-3 rounded-xl border border-charcoal-200">
              <div className="text-center px-3 border-r border-charcoal-200">
                <span className="text-xs text-charcoal-500 font-medium block">Passed</span>
                <span className="text-lg font-bold text-emerald-700">
                  {report.passed_count}/{report.total_checks}
                </span>
              </div>
              <div className="text-center px-3 border-r border-charcoal-200">
                <span className="text-xs text-charcoal-500 font-medium block">Failed</span>
                <span className={`text-lg font-bold ${report.failed_count > 0 ? "text-rose-700" : "text-charcoal-400"}`}>
                  {report.failed_count}
                </span>
              </div>
              <div className="text-center px-3">
                <span className="text-xs text-charcoal-500 font-medium block">Warnings</span>
                <span className={`text-lg font-bold ${report.warning_count > 0 ? "text-amber-700" : "text-charcoal-400"}`}>
                  {report.warning_count}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Detailed Check Items List */}
      <div className="space-y-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-charcoal-900 flex items-center gap-2">
          <Sliders className="w-4 h-4 text-charcoal-700" />
          Individual Security Gate Evaluations
        </h2>

        {report && report.checks && report.checks.length > 0 ? (
          report.checks.map((check, idx) => {
            const Icon = getPillarIcon(check.pillar);
            const isPass = check.status === "PASS";
            const isFail = check.status === "FAIL";
            const isWarn = check.status === "WARN";

            return (
              <div
                key={check.id}
                className={`p-5 rounded-xl border transition-all ${
                  isFail
                    ? "bg-rose-50/50 border-rose-300"
                    : isWarn
                    ? "bg-amber-50/50 border-amber-300"
                    : "bg-white border-charcoal-200"
                }`}
              >
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  <div className="flex items-start gap-3.5">
                    <div
                      className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 shadow-xs ${
                        isFail
                          ? "bg-rose-100 text-rose-800"
                          : isWarn
                          ? "bg-amber-100 text-amber-800"
                          : "bg-emerald-100 text-emerald-800"
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                    </div>

                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-sm font-bold text-charcoal-950">{check.name}</h3>
                        <Badge
                          variant={isPass ? "success" : isFail ? "danger" : "warning"}
                          size="sm"
                        >
                          {check.status}
                        </Badge>
                        <span className="text-[10px] font-mono uppercase text-charcoal-500 bg-charcoal-100 px-2 py-0.5 rounded">
                          {check.pillar}
                        </span>
                      </div>

                      <p className="text-xs text-charcoal-700 mt-1 leading-relaxed">
                        {check.message}
                      </p>

                      {/* Violation List if present */}
                      {check.details && check.details.length > 0 && (
                        <div className="mt-2.5 p-3 rounded-lg bg-charcoal-950 text-charcoal-200 font-mono text-[11px] space-y-1 max-h-40 overflow-y-auto">
                          <div className="text-rose-400 font-bold text-[10px] uppercase tracking-wider mb-1">
                            Offending Seed Data Records Detected:
                          </div>
                          {check.details.map((d, dIdx) => (
                            <div key={dIdx} className="text-rose-300">
                              • {d}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Remediation Script / Advice */}
                      {check.remediation && (
                        <div className="mt-3 flex items-center gap-2 p-2.5 bg-charcoal-50 border border-charcoal-200 rounded-lg text-xs">
                          <Terminal className="w-3.5 h-3.5 text-charcoal-600 shrink-0" />
                          <span className="font-semibold text-charcoal-800">Remediation:</span>
                          <span className="font-mono text-[11px] text-charcoal-700 flex-1 truncate">
                            {check.remediation}
                          </span>
                          <button
                            onClick={() => copyRemediation(check.remediation, idx)}
                            className="inline-flex items-center gap-1 text-[11px] text-charcoal-600 hover:text-charcoal-950 font-medium px-2 py-1 bg-white border border-charcoal-200 rounded hover:bg-charcoal-100 transition-colors"
                          >
                            {copiedIndex === idx ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-600" />
                                <span className="text-emerald-700">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        ) : (
          <div className="bg-white p-12 rounded-xl border border-charcoal-200 text-center text-charcoal-500 text-xs">
            Loading production readiness results...
          </div>
        )}
      </div>

      {/* CLI Verification Instruction Card */}
      <div className="bg-charcoal-950 rounded-xl p-5 border border-charcoal-800 text-white shadow-lg space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-mono font-semibold text-charcoal-200 uppercase tracking-wider">
              Pre-Deploy CLI Verification Command
            </span>
          </div>
          <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
            Automated CI/CD Gate
          </span>
        </div>

        <p className="text-xs text-charcoal-400 leading-relaxed">
          You can run this verification directly from PowerShell or CI/CD pipelines before deployment. It returns exit code 0 on pass or 1 on failure:
        </p>

        <div className="bg-charcoal-900 p-3 rounded-lg font-mono text-xs text-emerald-300 border border-charcoal-800 select-all">
          C:\apps\zeroagent\api\server.exe --readiness-check
        </div>
      </div>
    </div>
  );
}
