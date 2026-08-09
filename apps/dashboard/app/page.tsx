"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Monitor,
  Lock,
  Cpu,
  CheckCircle2,
  Network,
  Radar,
  ArrowUpRight,
  AlertTriangle,
  Server,
  Laptop,
  Layers,
} from "lucide-react";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { FleetMetrics, Endpoint, ScanJob } from "@/lib/types";

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<FleetMetrics | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [m, e, s] = await Promise.all([
          api.getMetrics(),
          api.getEndpoints(),
          api.getScans(),
        ]);
        setMetrics(m);
        setEndpoints(e);
        setScans(s);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">
            Executive Fleet Overview
          </h1>
          <p className="text-sm text-charcoal-600 mt-1">
            Agentless audit, hardware inventory, and CIS benchmark status across Windows 11 & Windows Server.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/scans"
            className="flex items-center gap-2 px-4 py-2 bg-charcoal-950 hover:bg-charcoal-800 text-white text-sm font-medium rounded-lg shadow-sm transition-all"
          >
            <Radar className="w-4 h-4 text-emerald-400" />
            <span>Launch Discovery Scan</span>
          </Link>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Audited Endpoints"
          value={metrics ? metrics.total_endpoints : "24"}
          subtitle={`${metrics ? metrics.online_endpoints : "22"} Online & Responsive`}
          change="100% Agentless"
          changeType="positive"
          icon={Monitor}
          accentColor="charcoal"
        />

        <StatCard
          title="BitLocker Encryption"
          value={metrics ? `${metrics.bitlocker_rate}%` : "95.8%"}
          subtitle="OS Volumes (XTS-AES 256)"
          change="+2.4% this week"
          changeType="positive"
          icon={Lock}
          accentColor="emerald"
        />

        <StatCard
          title="TPM 2.0 Attestation"
          value={metrics ? `${metrics.tpm_rate}%` : "100.0%"}
          subtitle="Hardware Root of Trust Active"
          change="Compliant"
          changeType="positive"
          icon={Cpu}
          accentColor="indigo"
        />

        <StatCard
          title="Avg CIS Compliance"
          value={metrics ? `${metrics.average_compliance.toFixed(1)}%` : "94.2%"}
          subtitle="CIS Microsoft Windows Baseline"
          change="Level 1 & 2"
          changeType="neutral"
          icon={CheckCircle2}
          accentColor="emerald"
        />
      </div>

      {/* Main Grid: Fleet Posture & Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Fleet Endpoints Quick Inspect */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-charcoal-200 p-6 card-border">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h2 className="text-base font-bold text-charcoal-950">Active Fleet Endpoints</h2>
              <p className="text-xs text-charcoal-500 mt-0.5">
                Scanned via WinRM / CIM over HTTPS (Port 5986)
              </p>
            </div>
            <Link
              href="/endpoints"
              className="text-xs font-semibold text-charcoal-900 hover:text-emerald-600 flex items-center gap-1 transition-colors"
            >
              <span>View All Fleet</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-charcoal-200 text-charcoal-500 uppercase tracking-wider font-semibold">
                  <th className="pb-3">Hostname / Domain</th>
                  <th className="pb-3">IP & Protocol</th>
                  <th className="pb-3">OS Edition</th>
                  <th className="pb-3">Chassis</th>
                  <th className="pb-3 text-right">CIS Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-charcoal-100">
                {endpoints.slice(0, 4).map((ep) => (
                  <tr key={ep.id} className="hover:bg-charcoal-50 transition-colors group">
                    <td className="py-3.5">
                      <Link href={`/endpoints/${ep.id}`} className="block">
                        <span className="font-semibold text-charcoal-950 group-hover:text-emerald-700 block">
                          {ep.hostname}
                        </span>
                        <span className="text-[11px] text-charcoal-500 font-mono block">{ep.domain}</span>
                      </Link>
                    </td>
                    <td className="py-3.5">
                      <span className="font-mono text-charcoal-900 font-medium block">{ep.ip_address}</span>
                      <span className="text-[10px] text-charcoal-500 font-mono block">WinRM HTTPS (5986)</span>
                    </td>
                    <td className="py-3.5">
                      <span className="text-charcoal-800 font-medium block truncate max-w-[180px]">
                        {ep.os_name}
                      </span>
                      <span className="text-[10px] text-charcoal-500 font-mono block">Build {ep.os_build}</span>
                    </td>
                    <td className="py-3.5">
                      <div className="flex items-center gap-1.5 text-charcoal-700">
                        {ep.chassis_type === "Laptop" ? (
                          <Laptop className="w-3.5 h-3.5 text-charcoal-500" />
                        ) : (
                          <Server className="w-3.5 h-3.5 text-charcoal-500" />
                        )}
                        <span>{ep.chassis_type}</span>
                      </div>
                    </td>
                    <td className="py-3.5 text-right">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold font-mono border ${
                          ep.compliance_score >= 90
                            ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                            : "bg-amber-50 text-amber-700 border-amber-200"
                        }`}
                      >
                        {ep.compliance_score.toFixed(1)}%
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right 1 Col: Collector Mesh & Recent Scans */}
        <div className="space-y-6">
          {/* Subnet Collector Mesh Card */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold text-charcoal-950">Subnet Collector Mesh</h2>
              <Badge variant="success" size="sm">
                2 Active Gateways
              </Badge>
            </div>
            <p className="text-xs text-charcoal-500 mb-4">
              Per-subnet Go daemons authenticating over mTLS 1.3 tunnels.
            </p>

            <div className="space-y-2.5">
              <div className="p-2.5 rounded-lg bg-charcoal-50 border border-charcoal-200 flex items-center justify-between text-xs">
                <div>
                  <span className="font-semibold text-charcoal-900 block">Subnet 10.100.1.0/24</span>
                  <span className="text-[10px] text-charcoal-500 font-mono">Corporate HQ (Subnet A)</span>
                </div>
                <div className="text-right">
                  <span className="text-[11px] font-mono text-emerald-700 font-semibold block">4ms</span>
                  <span className="text-[10px] text-emerald-600 block">Healthy</span>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-charcoal-50 border border-charcoal-200 flex items-center justify-between text-xs">
                <div>
                  <span className="font-semibold text-charcoal-900 block">Subnet 10.100.2.0/24</span>
                  <span className="text-[10px] text-charcoal-500 font-mono">Datacenter East (Subnet B)</span>
                </div>
                <div className="text-right">
                  <span className="text-[11px] font-mono text-emerald-700 font-semibold block">2ms</span>
                  <span className="text-[10px] text-emerald-600 block">Healthy</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-charcoal-100 flex justify-between items-center text-xs">
              <Link href="/gateways" className="font-semibold text-charcoal-900 hover:text-emerald-700 flex items-center gap-1">
                <span>Manage Gateways</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          {/* Recent Agentless Scans */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold text-charcoal-950">Recent Scan Jobs</h2>
              <Link href="/scans" className="text-xs font-semibold text-charcoal-900 hover:text-emerald-700">
                All Logs
              </Link>
            </div>

            <div className="space-y-3">
              {scans.slice(0, 2).map((s) => (
                <div key={s.id} className="p-3 rounded-lg border border-charcoal-200 bg-charcoal-50/50">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-xs text-charcoal-950 truncate max-w-[170px]">
                      {s.name}
                    </span>
                    <Badge variant={s.status === "completed" ? "success" : "info"} size="sm">
                      {s.status}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-charcoal-500 font-mono">
                    <span>Target: {s.target_cidr}</span>
                    <span>{s.scanned_hosts}/{s.total_hosts} hosts</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
