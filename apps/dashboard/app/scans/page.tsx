"use client";

import React, { useEffect, useState } from "react";
import { Radar, Terminal, Play, CheckCircle2, Clock, AlertTriangle, Shield, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { ScanJob, CollectorGateway, VaultCredentialSummary } from "@/lib/types";

export default function ScansPage() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [gateways, setGateways] = useState<CollectorGateway[]>([]);
  const [credentials, setCredentials] = useState<VaultCredentialSummary[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanJob | null>(null);

  // New Scan Form State
  const [name, setName] = useState("Corporate Subnet A - Daily Audit");
  const [targetCIDR, setTargetCIDR] = useState("10.100.1.0/24");
  const [scanProfile, setScanProfile] = useState("full_hardware_os");
  const [protocol, setProtocol] = useState("winrm_https");
  const [vaultRef, setVaultRef] = useState("sec_ref_winrm_domain_prod_01");
  const [gatewayId, setGatewayId] = useState("gw-10-100-1-0");
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    async function load() {
      const [s, g, c] = await Promise.all([
        api.getScans(),
        api.getGateways(),
        api.getVaultCredentials(),
      ]);
      setScans(s);
      setGateways(g);
      setCredentials(c);
      if (s.length > 0) {
        setSelectedScan(s[0]);
      }
    }
    load();
  }, []);

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const newJob = await api.createScan({
        name,
        target_cidr: targetCIDR,
        scan_profile: scanProfile,
        protocol,
        vault_secret_ref: vaultRef,
        gateway_id: gatewayId,
      });
      setScans([newJob, ...scans]);
      setSelectedScan(newJob);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">Agentless Scan Orchestrator</h1>
        <p className="text-sm text-charcoal-600 mt-1">
          Launch and stream real-time agentless WMI/CIM scans via remote WinRM HTTPS across enterprise subnets.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 1 Col: Scan Launcher Form */}
        <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
          <div className="flex items-center gap-2 mb-4 font-bold text-sm text-charcoal-950">
            <Radar className="w-4 h-4 text-emerald-600" />
            <h2>Configure Agentless Scan</h2>
          </div>

          <form onSubmit={handleLaunchScan} className="space-y-4 text-xs">
            <div>
              <label className="block font-semibold text-charcoal-700 mb-1">Scan Job Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
              />
            </div>

            <div>
              <label className="block font-semibold text-charcoal-700 mb-1">Target Subnet CIDR / Host IP</label>
              <input
                type="text"
                value={targetCIDR}
                onChange={(e) => setTargetCIDR(e.target.value)}
                placeholder="10.100.1.0/24"
                required
                className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg font-mono text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
              />
              <span className="text-[10px] text-charcoal-500 mt-0.5 block">SSRF Protected: Restricted from cloud metadata IP</span>
            </div>

            <div>
              <label className="block font-semibold text-charcoal-700 mb-1">Agentless Protocol</label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none font-mono"
              >
                <option value="winrm_https">WinRM over HTTPS (Port 5986 - Recommended)</option>
                <option value="winrm_http">WinRM over HTTP (Port 5985)</option>
                <option value="wmi_dcom">WMI / DCOM (RPC Port 135)</option>
                <option value="snmp_v3">SNMPv3 Out-of-Band BMC (Port 161)</option>
                <option value="ssh_bmc">SSH for iLO / iDRAC (Port 22)</option>
              </select>
            </div>

            <div>
              <label className="block font-semibold text-charcoal-700 mb-1">Scan Profile</label>
              <select
                value={scanProfile}
                onChange={(e) => setScanProfile(e.target.value)}
                className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
              >
                <option value="full_hardware_os">Full Hardware & CIS Benchmark Audit</option>
                <option value="rapid_inventory">Rapid Hardware Inventory Only</option>
                <option value="cis_level_1">CIS Level 1 Baseline Verification</option>
                <option value="critical_patches">Security Patch & Hotfix Verification</option>
              </select>
            </div>

            <div>
              <label className="block font-semibold text-charcoal-700 mb-1">Credential Vault Reference</label>
              <select
                value={vaultRef}
                onChange={(e) => setVaultRef(e.target.value)}
                className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none font-mono text-[11px]"
              >
                {credentials.map((c) => (
                  <option key={c.id} value={c.opaque_id}>
                    {c.name} ({c.opaque_id})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block font-semibold text-charcoal-700 mb-1">Collector Gateway</label>
              <select
                value={gatewayId}
                onChange={(e) => setGatewayId(e.target.value)}
                className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
              >
                {gateways.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name} ({g.subnet_cidr})
                  </option>
                ))}
              </select>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 bg-charcoal-950 hover:bg-charcoal-800 text-white font-semibold rounded-lg shadow-sm transition-all flex items-center justify-center gap-2 mt-4"
            >
              <Play className="w-3.5 h-3.5 text-emerald-400 fill-emerald-400" />
              <span>{isSubmitting ? "Dispatching..." : "Launch Agentless Scan"}</span>
            </button>
          </form>
        </div>

        {/* Right 2 Cols: Live Telemetry Terminal & Scan History */}
        <div className="lg:col-span-2 space-y-6">
          {/* Live Telemetry Terminal */}
          <div className="bg-charcoal-950 rounded-xl border border-charcoal-800 overflow-hidden shadow-lg">
            <div className="bg-charcoal-900 px-4 py-3 border-b border-charcoal-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-mono text-charcoal-200 font-semibold">
                  {selectedScan ? selectedScan.name : "Agentless WS-Man Telemetry Console"}
                </span>
              </div>
              {selectedScan && (
                <Badge variant={selectedScan.status === "completed" ? "success" : "info"} size="sm">
                  {selectedScan.status.toUpperCase()}
                </Badge>
              )}
            </div>

            <div className="p-4 font-mono text-[11px] leading-relaxed text-charcoal-300 h-72 overflow-y-auto space-y-1 bg-charcoal-950">
              {selectedScan && selectedScan.logs && selectedScan.logs.length > 0 ? (
                selectedScan.logs.map((line, idx) => (
                  <div key={idx} className="flex gap-2">
                    <span className="text-charcoal-600 select-none">{String(idx + 1).padStart(2, "0")}</span>
                    <span className={line.includes("[ERROR]") ? "text-red-400" : line.includes("completed") ? "text-emerald-400 font-semibold" : "text-charcoal-300"}>
                      {line}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-charcoal-600 text-center py-24">No scan job selected or logs available.</div>
              )}
            </div>

            <div className="bg-charcoal-900/60 px-4 py-2 border-t border-charcoal-800 text-[10px] font-mono text-charcoal-400 flex justify-between">
              <span>Target: {selectedScan ? selectedScan.target_cidr : "None"}</span>
              <span>Vault Ref: {selectedScan ? selectedScan.vault_secret_ref : "None"}</span>
            </div>
          </div>

          {/* Scan History Table */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <h2 className="text-sm font-bold text-charcoal-950 mb-3">Scan Job History</h2>
            <div className="space-y-2">
              {scans.map((s) => (
                <div
                  key={s.id}
                  onClick={() => setSelectedScan(s)}
                  className={`p-3 rounded-lg border text-xs cursor-pointer transition-all flex items-center justify-between ${
                    selectedScan?.id === s.id
                      ? "bg-charcoal-100/70 border-charcoal-950 shadow-sm"
                      : "bg-charcoal-50/50 border-charcoal-200 hover:border-charcoal-400"
                  }`}
                >
                  <div>
                    <span className="font-bold text-charcoal-950 block">{s.name}</span>
                    <span className="text-[10px] text-charcoal-500 font-mono">
                      Target: {s.target_cidr} • Profile: {s.scan_profile}
                    </span>
                  </div>
                  <div className="text-right">
                    <Badge variant={s.status === "completed" ? "success" : "info"} size="sm">
                      {s.status}
                    </Badge>
                    <span className="text-[10px] text-charcoal-500 block mt-0.5 font-mono">
                      {s.scanned_hosts}/{s.total_hosts} hosts
                    </span>
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
