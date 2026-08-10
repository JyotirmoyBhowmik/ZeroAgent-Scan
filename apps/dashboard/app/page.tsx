"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Shield,
  Monitor,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Server,
  Activity,
  ArrowRight,
  TrendingUp,
  Clock,
  RefreshCw,
  AlertCircle,
} from "lucide-react";
import { getFleetMetrics, getDriftEvents, getEndpoints, getNetworkSubnets, api } from "@/lib/api";
import { FleetMetrics, DriftEvent, Endpoint, NetworkSubnet, AlertHealthStatus } from "@/lib/types";

export default function FleetOverviewPage() {
  const [metrics, setMetrics] = useState<FleetMetrics | null>(null);
  const [driftEvents, setDriftEvents] = useState<DriftEvent[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [subnets, setSubnets] = useState<NetworkSubnet[]>([]);
  const [alertHealth, setAlertHealth] = useState<AlertHealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [m, d, e, s, h] = await Promise.all([
        getFleetMetrics(),
        getDriftEvents(),
        getEndpoints(),
        getNetworkSubnets(),
        api.fetchAlertHealthStatus(),
      ]);
      setMetrics(m);
      setDriftEvents(d);
      setEndpoints(e);
      setSubnets(s);
      setAlertHealth(h);
    } catch (err: any) {
      setError(err?.message || "Failed to load fleet telemetry.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="p-8 max-w-7xl mx-auto space-y-6" aria-busy="true" aria-live="polite">
        <div className="h-8 w-64 bg-slate-800 animate-pulse rounded"></div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-28 bg-slate-800/60 rounded-xl animate-pulse"></div>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 h-72 bg-slate-800/60 rounded-xl animate-pulse"></div>
          <div className="h-72 bg-slate-800/60 rounded-xl animate-pulse"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8 max-w-2xl mx-auto text-center py-20" role="alert">
        <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-rose-500/10 text-rose-400 flex items-center justify-center">
          <AlertCircle className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-100 mb-2">Error Loading Fleet Telemetry</h2>
        <p className="text-sm text-slate-400 mb-6">{error}</p>
        <button
          onClick={loadData}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium transition-colors"
        >
          <RefreshCw className="w-4 h-4" /> Retry
        </button>
      </div>
    );
  }

  const bands = metrics?.compliance_bands || {
    band_90_100: 0,
    band_75_89: 0,
    band_50_74: 0,
    band_under_50: 0,
  };
  const totalInBands = Object.values(bands).reduce((a, b) => a + b, 0) || 1;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-emerald-400" />
            Executive Fleet Overview
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time compliance posture, vulnerability exposure, gateway mesh health, and configuration drift.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            aria-label="Refresh telemetry data"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
          <Link
            href="/scans"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-colors"
          >
            Launch Agentless Scan <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {/* Insecure Transport Warning Banner */}
      {subnets.filter((s) => s.allow_insecure_http).length > 0 && (
        <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl flex items-start gap-3.5 text-amber-200 text-xs">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="font-bold text-amber-300 text-sm">⚠️ Security Notice: Unencrypted WinRM (Port 5985) Override Active</h3>
            <p className="mt-1 text-slate-300 leading-relaxed">
              The following subnets have explicit unencrypted HTTP overrides enabled:{" "}
              <span className="font-mono font-semibold text-amber-300">
                {subnets
                  .filter((s) => s.allow_insecure_http)
                  .map((s) => `${s.subnet_cidr} (${s.name})`)
                  .join(", ")}
              </span>.
              Unencrypted WinRM transmits sensitive CIM telemetry and authentication hashes across the local network segment in cleartext.
              Documented as a compliance exception under Rule ID <code className="font-mono bg-slate-900 px-1 py-0.5 rounded text-amber-300">COMPLIANCE_EXCEPTION_WINRM_UNENCRYPTED_5985</code>.
              Recommend deploying TLS certificates on port 5986 and disabling port 5985 overrides.
            </p>
          </div>
        </div>
      )}

      {/* Alert Delivery Verification Lapse Warning */}
      {alertHealth && alertHealth.test_alert_lapsed && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-center justify-between gap-4 text-rose-200 text-xs">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/20 text-rose-400">
              <AlertCircle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-rose-300 text-sm">
                ⚠️ Action Recommended: Human Alert Delivery Testing Lapsed (90+ Days / Untested)
              </h3>
              <p className="mt-0.5 text-slate-300">
                {alertHealth.last_test_alert_at
                  ? `Last verified alert delivery was ${alertHealth.test_alert_lapse_days} days ago. Synthetic testing must be executed every 90 days.`
                  : "No synthetic alert test has been recorded yet. Verify that critical fleet failure alerts reach on-call personnel."}
              </p>
            </div>
          </div>
          <Link
            href="/admin"
            className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold shrink-0 transition-colors"
          >
            Send Test Alert
          </Link>
        </div>
      )}

      {/* Top 4 KPI Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Compliance Score */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm relative overflow-hidden group hover:border-emerald-500/30 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-medium text-slate-400">Average Compliance</span>
              <div className="text-2xl font-bold text-white mt-1">
                {metrics?.average_compliance.toFixed(1)}%
              </div>
            </div>
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>CIS Benchmark v2.0</span>
          </div>
        </div>

        {/* Open Critical Vulns & KEV */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm relative overflow-hidden group hover:border-rose-500/30 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-medium text-slate-400">Critical Vulnerabilities</span>
              <div className="text-2xl font-bold text-rose-400 mt-1">
                {metrics?.open_critical_vulns || 0}
              </div>
            </div>
            <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center">
              <Flame className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-xs text-rose-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
            <span>{metrics?.open_kev_count || 0} CISA KEV Exploited</span>
          </div>
        </div>

        {/* Total Hosts */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm relative overflow-hidden group hover:border-sky-500/30 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-medium text-slate-400">Scanned Endpoints</span>
              <div className="text-2xl font-bold text-white mt-1">
                {metrics?.online_endpoints || 0} / {metrics?.total_endpoints || 0}
              </div>
            </div>
            <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400 flex items-center justify-center">
              <Monitor className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-slate-400">
            <span>100% Agentless via WinRM / CIM</span>
          </div>
        </div>

        {/* Gateways Health */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm relative overflow-hidden group hover:border-violet-500/30 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-medium text-slate-400">Collector Gateways</span>
              <div className="text-2xl font-bold text-emerald-400 mt-1">
                {metrics?.active_gateways || 0} Healthy
              </div>
            </div>
            <div className="w-10 h-10 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-400 flex items-center justify-center">
              <Server className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-slate-400">
            <span>mTLS 1.3 Certified Subnets</span>
          </div>
        </div>
      </div>

      {/* Row 2: Compliance Score Bands & Security Baseline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Compliance Score Distribution */}
        <div className="lg:col-span-2 p-6 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h2 className="text-base font-semibold text-slate-100">Compliance Distribution Bands</h2>
              <p className="text-xs text-slate-400 mt-0.5">Host count grouped by CIS benchmark compliance score range</p>
            </div>
            <Link
              href="/compliance"
              className="text-xs font-medium text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1"
            >
              View CIS Rules <ArrowRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="space-y-4">
            {/* Band 90-100% */}
            <div>
              <div className="flex justify-between text-xs font-medium mb-1.5">
                <span className="text-slate-300 flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
                  90% - 100% (High Compliance)
                </span>
                <span className="text-slate-100 font-bold">{bands.band_90_100} hosts ({Math.round((bands.band_90_100 / totalInBands) * 100)}%)</span>
              </div>
              <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                  style={{ width: `${(bands.band_90_100 / totalInBands) * 100}%` }}
                ></div>
              </div>
            </div>

            {/* Band 75-89% */}
            <div>
              <div className="flex justify-between text-xs font-medium mb-1.5">
                <span className="text-slate-300 flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-sky-400"></span>
                  75% - 89% (Moderate Compliance)
                </span>
                <span className="text-slate-100 font-bold">{bands.band_75_89} hosts ({Math.round((bands.band_75_89 / totalInBands) * 100)}%)</span>
              </div>
              <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-sky-500 rounded-full transition-all duration-500"
                  style={{ width: `${(bands.band_75_89 / totalInBands) * 100}%` }}
                ></div>
              </div>
            </div>

            {/* Band 50-74% */}
            <div>
              <div className="flex justify-between text-xs font-medium mb-1.5">
                <span className="text-slate-300 flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
                  50% - 74% (Needs Remediation)
                </span>
                <span className="text-slate-100 font-bold">{bands.band_50_74} hosts ({Math.round((bands.band_50_74 / totalInBands) * 100)}%)</span>
              </div>
              <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full transition-all duration-500"
                  style={{ width: `${(bands.band_50_74 / totalInBands) * 100}%` }}
                ></div>
              </div>
            </div>

            {/* Band Under 50% */}
            <div>
              <div className="flex justify-between text-xs font-medium mb-1.5">
                <span className="text-slate-300 flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-400"></span>
                  &lt; 50% (Critical Risk)
                </span>
                <span className="text-slate-100 font-bold">{bands.band_under_50} hosts ({Math.round((bands.band_under_50 / totalInBands) * 100)}%)</span>
              </div>
              <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-rose-500 rounded-full transition-all duration-500"
                  style={{ width: `${(bands.band_under_50 / totalInBands) * 100}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>

        {/* Security Baseline Rates */}
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm space-y-4">
          <h2 className="text-base font-semibold text-slate-100">Security Baseline Status</h2>
          <div className="space-y-3.5 text-xs">
            <div className="flex justify-between items-center p-3 rounded-lg bg-slate-800/40 border border-slate-800">
              <span className="text-slate-300">BitLocker Volume Encryption</span>
              <span className="font-semibold text-emerald-400">{metrics?.bitlocker_rate}%</span>
            </div>
            <div className="flex justify-between items-center p-3 rounded-lg bg-slate-800/40 border border-slate-800">
              <span className="text-slate-300">TPM 2.0 Hardware Active</span>
              <span className="font-semibold text-emerald-400">{metrics?.tpm_rate}%</span>
            </div>
            <div className="flex justify-between items-center p-3 rounded-lg bg-slate-800/40 border border-slate-800">
              <span className="text-slate-300">Defender Cloud & Real-time</span>
              <span className="font-semibold text-emerald-400">{metrics?.defender_rate}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Row 3: Recent Configuration Drift Events Feed */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Recent Configuration Drift Events
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">Field-level state changes detected across consecutive telemetry snapshots</p>
          </div>
          <Link
            href="/endpoints"
            className="text-xs font-medium text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1"
          >
            All Endpoints <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        {driftEvents.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-sm">
            No configuration drift events recorded. Fleet state is fully synchronized.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-medium uppercase tracking-wider">
                  <th className="pb-3">Severity</th>
                  <th className="pb-3">Host</th>
                  <th className="pb-3">Subsystem</th>
                  <th className="pb-3">Property Changed</th>
                  <th className="pb-3">Prior State</th>
                  <th className="pb-3">Current State</th>
                  <th className="pb-3">Detected</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {driftEvents.map((event) => {
                  const severityBadge =
                    event.severity === "CRITICAL"
                      ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                      : event.severity === "WARNING"
                      ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                      : "bg-sky-500/10 text-sky-400 border-sky-500/20";

                  return (
                    <tr key={event.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold border ${severityBadge}`}>
                          {event.severity}
                        </span>
                      </td>
                      <td className="py-3 font-semibold text-slate-200">
                        <Link href={`/endpoints/${event.host_id}`} className="hover:text-emerald-400 underline decoration-slate-700">
                          {event.hostname}
                        </Link>
                      </td>
                      <td className="py-3 text-slate-300">{event.subsystem}</td>
                      <td className="py-3 font-mono text-[11px] text-slate-300">{event.property_name}</td>
                      <td className="py-3 font-mono text-[11px] text-slate-400 line-through truncate max-w-[150px]">
                        {event.old_value}
                      </td>
                      <td className="py-3 font-mono text-[11px] text-emerald-400 font-medium truncate max-w-[150px]">
                        {event.new_value}
                      </td>
                      <td className="py-3 text-slate-400 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(event.detected_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
