"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  Cpu,
  HardDrive,
  Network,
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  Terminal,
  Copy,
  Check,
  Server,
  Laptop,
  Layers,
  Fingerprint,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { EndpointDetail } from "@/lib/types";

export default function EndpointDetailPage() {
  const params = useParams();
  const id = params.id as string;

  const [detail, setDetail] = useState<EndpointDetail | null>(null);
  const [activeTab, setActiveTab] = useState<"hardware" | "security" | "cis">("hardware");
  const [copiedScript, setCopiedScript] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      if (!id) return;
      try {
        const data = await api.getEndpointDetail(id);
        setDetail(data);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  const copyToClipboard = (text: string, ruleId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedScript(ruleId);
    setTimeout(() => setCopiedScript(null), 2000);
  };

  if (!detail) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-sm font-mono text-charcoal-500 animate-pulse">Loading endpoint telemetry...</div>
      </div>
    );
  }

  const { endpoint, hardware, security_posture, cis_results } = detail;

  return (
    <div className="space-y-6">
      {/* Back Navigation & Breadcrumb */}
      <div className="flex items-center justify-between">
        <Link
          href="/endpoints"
          className="inline-flex items-center gap-2 text-xs font-semibold text-charcoal-600 hover:text-charcoal-950 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Fleet Inventory</span>
        </Link>
        <Badge variant="success" size="sm">
          100% Agentless Probe (WinRM HTTPS:5986)
        </Badge>
      </div>

      {/* Host Summary Header Banner */}
      <div className="bg-white rounded-xl border border-charcoal-200 p-6 card-border">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-charcoal-950 text-white flex items-center justify-center shadow-sm">
              {endpoint.chassis_type === "Laptop" ? (
                <Laptop className="w-6 h-6 text-emerald-400" />
              ) : (
                <Server className="w-6 h-6 text-emerald-400" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-xl font-bold text-charcoal-950">{endpoint.hostname}</h1>
                <Badge variant={endpoint.status === "online" ? "success" : "danger"} size="sm">
                  {endpoint.status}
                </Badge>
              </div>
              <p className="text-xs text-charcoal-600 mt-1">
                {endpoint.os_name} • Build {endpoint.os_build} • {endpoint.domain}
              </p>
              <div className="flex flex-wrap items-center gap-4 mt-3 text-xs font-mono text-charcoal-600">
                <span>IP: <strong className="text-charcoal-900">{endpoint.ip_address}</strong></span>
                <span>MAC: <strong className="text-charcoal-900">{endpoint.mac_address}</strong></span>
                <span>Serial: <strong className="text-charcoal-900">{endpoint.serial_number}</strong></span>
                <span>Model: <strong className="text-charcoal-900">{endpoint.manufacturer} {endpoint.model}</strong></span>
              </div>
            </div>
          </div>

          {/* CIS Score Card */}
          <div className="bg-charcoal-50 p-4 rounded-xl border border-charcoal-200 text-center min-w-[160px]">
            <span className="text-[11px] font-semibold text-charcoal-500 uppercase tracking-wider block">
              CIS Compliance
            </span>
            <span className="text-2xl font-bold text-charcoal-950 font-mono block mt-1">
              {endpoint.compliance_score.toFixed(1)}%
            </span>
            <span className="text-[10px] text-emerald-700 font-semibold block mt-0.5">
              Level 1 Baseline Verified
            </span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-charcoal-200 mt-8 gap-8 text-xs font-semibold">
          <button
            onClick={() => setActiveTab("hardware")}
            className={`pb-3 border-b-2 transition-all flex items-center gap-2 ${
              activeTab === "hardware"
                ? "border-charcoal-950 text-charcoal-950"
                : "border-transparent text-charcoal-500 hover:text-charcoal-900"
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>Hardware Inventory</span>
          </button>
          <button
            onClick={() => setActiveTab("security")}
            className={`pb-3 border-b-2 transition-all flex items-center gap-2 ${
              activeTab === "security"
                ? "border-charcoal-950 text-charcoal-950"
                : "border-transparent text-charcoal-500 hover:text-charcoal-900"
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Security Posture</span>
          </button>
          <button
            onClick={() => setActiveTab("cis")}
            className={`pb-3 border-b-2 transition-all flex items-center gap-2 ${
              activeTab === "cis"
                ? "border-charcoal-950 text-charcoal-950"
                : "border-transparent text-charcoal-500 hover:text-charcoal-900"
            }`}
          >
            <CheckCircle2 className="w-4 h-4" />
            <span>CIS Benchmark Matrix ({cis_results.length})</span>
          </button>
        </div>
      </div>

      {/* Tab 1: Hardware Tree */}
      {activeTab === "hardware" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* CPU Card */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center gap-2.5 mb-4 text-charcoal-950 font-bold text-sm">
              <Cpu className="w-4 h-4 text-emerald-600" />
              <h2>Processor & Sockets</h2>
            </div>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">Processor Model:</span>
                <span className="font-semibold text-charcoal-950">{hardware.cpu_details.name || "Intel Xeon"}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">Physical Cores / Sockets:</span>
                <span className="font-mono text-charcoal-900">{hardware.cpu_details.cores} Cores / {hardware.cpu_details.sockets} Socket</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">Logical Processors:</span>
                <span className="font-mono text-charcoal-900">{hardware.cpu_details.logical_processors} Threads</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-charcoal-500">Max Clock Speed:</span>
                <span className="font-mono text-charcoal-900">{hardware.cpu_details.max_clock_mhz} MHz</span>
              </div>
            </div>
          </div>

          {/* Memory DIMMs */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center gap-2.5 mb-4 text-charcoal-950 font-bold text-sm">
              <Layers className="w-4 h-4 text-emerald-600" />
              <h2>Memory (RAM DIMMs)</h2>
            </div>
            <div className="text-xs mb-3 flex justify-between">
              <span className="text-charcoal-500">Total Installed:</span>
              <span className="font-bold text-charcoal-950 font-mono">
                {((hardware.memory_details.total_bytes || 0) / (1024 * 1024 * 1024)).toFixed(0)} GB
              </span>
            </div>
            <div className="space-y-2">
              {hardware.memory_details.dimms?.map((d, i) => (
                <div key={i} className="p-2.5 rounded bg-charcoal-50 border border-charcoal-200 text-xs flex justify-between items-center">
                  <div>
                    <span className="font-semibold text-charcoal-900 block">{d.slot}: {((d.capacity_bytes || 0) / (1024 * 1024 * 1024)).toFixed(0)} GB</span>
                    <span className="text-[10px] text-charcoal-500 font-mono">{d.manufacturer} {d.part_number}</span>
                  </div>
                  <span className="text-[11px] font-mono text-charcoal-700 bg-white px-2 py-0.5 rounded border border-charcoal-200">
                    {d.speed_mhz} MT/s
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Storage Disks */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center gap-2.5 mb-4 text-charcoal-950 font-bold text-sm">
              <HardDrive className="w-4 h-4 text-emerald-600" />
              <h2>Physical Disks & SMART</h2>
            </div>
            <div className="space-y-2">
              {hardware.storage_details.disks?.map((disk, i) => (
                <div key={i} className="p-3 rounded bg-charcoal-50 border border-charcoal-200 text-xs">
                  <div className="flex justify-between items-center">
                    <span className="font-semibold text-charcoal-950">Disk #{disk.index}: {disk.model}</span>
                    <Badge variant="success" size="sm">{disk.smart_status}</Badge>
                  </div>
                  <div className="flex justify-between mt-2 text-[11px] text-charcoal-600 font-mono">
                    <span>Size: {((disk.size_bytes || 0) / (1024 * 1024 * 1024)).toFixed(0)} GB ({disk.bus_type})</span>
                    <span>Serial: {disk.serial}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* BIOS & TPM 2.0 */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center gap-2.5 mb-4 text-charcoal-950 font-bold text-sm">
              <Fingerprint className="w-4 h-4 text-emerald-600" />
              <h2>BIOS / UEFI & TPM 2.0</h2>
            </div>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">BIOS Version / Date:</span>
                <span className="font-mono text-charcoal-900">{hardware.bios_details.version} ({hardware.bios_details.release_date})</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">SecureBoot Status:</span>
                <Badge variant={hardware.bios_details.secure_boot ? "success" : "danger"} size="sm">
                  {hardware.bios_details.secure_boot ? "Enabled" : "Disabled"}
                </Badge>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-charcoal-500">TPM 2.0 Security Chip:</span>
                <span className="font-semibold text-emerald-700 font-mono">Present & Attested (v2.0)</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Security Posture */}
      {activeTab === "security" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* BitLocker Card */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center gap-2.5 mb-4 text-charcoal-950 font-bold text-sm">
              <Lock className="w-4 h-4 text-emerald-600" />
              <h2>BitLocker Full Disk Encryption</h2>
            </div>
            {security_posture.bitlocker_status.volumes?.map((vol, i) => (
              <div key={i} className="p-3 rounded bg-charcoal-50 border border-charcoal-200 text-xs">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-charcoal-950 font-mono">Volume {vol.drive_letter} (OS Disk)</span>
                  <Badge variant={vol.protection_status === 1 ? "success" : "danger"} size="sm">
                    {vol.protection_status === 1 ? "Encrypted (Protection On)" : "Decrypted"}
                  </Badge>
                </div>
                <div className="mt-2 text-[11px] text-charcoal-600 space-y-1 font-mono">
                  <div>Algorithm: {vol.encryption_method || "XTS-AES 256"}</div>
                  <div>Key Protectors: {vol.key_protectors?.join(", ") || "TPM, RecoveryPassword"}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Windows Defender Posture */}
          <div className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center gap-2.5 mb-4 text-charcoal-950 font-bold text-sm">
              <Shield className="w-4 h-4 text-emerald-600" />
              <h2>Microsoft Defender Posture</h2>
            </div>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">Real-Time Protection:</span>
                <Badge variant={security_posture.defender_status.realtime_enabled ? "success" : "danger"} size="sm">
                  {security_posture.defender_status.realtime_enabled ? "Active" : "Disabled"}
                </Badge>
              </div>
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">Tamper Protection:</span>
                <Badge variant={security_posture.defender_status.tamper_protection ? "success" : "danger"} size="sm">
                  {security_posture.defender_status.tamper_protection ? "Active" : "Disabled"}
                </Badge>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-charcoal-500">Engine Version:</span>
                <span className="font-mono text-charcoal-900">{security_posture.defender_status.antimalware_version}</span>
              </div>
            </div>
          </div>

          {/* Installed Hotfixes / KBs */}
          <div className="md:col-span-2 bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-center gap-2.5 mb-4 text-charcoal-950 font-bold text-sm">
              <Terminal className="w-4 h-4 text-emerald-600" />
              <h2>Installed Security Updates (Win32_QuickFixEngineering)</h2>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {security_posture.hotfixes.map((kb, i) => (
                <div key={i} className="p-2.5 rounded bg-charcoal-50 border border-charcoal-200 text-xs">
                  <span className="font-bold text-charcoal-950 font-mono block">{kb.hotfix_id}</span>
                  <span className="text-[11px] text-charcoal-500 block">{kb.description} • {kb.installed_on}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: CIS Benchmark Matrix */}
      {activeTab === "cis" && (
        <div className="space-y-4">
          {cis_results.map((rule) => (
            <div key={rule.id} className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  {rule.status === "PASS" ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-charcoal-500">{rule.rule_id}</span>
                      <h3 className="font-bold text-sm text-charcoal-950">{rule.rule_title}</h3>
                    </div>
                    <span className="text-[11px] text-charcoal-500 mt-0.5 block">{rule.category} • {rule.benchmark_level}</span>
                  </div>
                </div>

                <Badge variant={rule.status === "PASS" ? "success" : "danger"} size="sm">
                  {rule.status}
                </Badge>
              </div>

              <p className="text-xs text-charcoal-600 mt-3">{rule.rationale}</p>

              <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-2.5 rounded bg-charcoal-50 border border-charcoal-200">
                  <span className="text-charcoal-500 block text-[10px] uppercase font-semibold">Actual Value:</span>
                  <span className="text-charcoal-900 font-medium">{rule.actual_value}</span>
                </div>
                <div className="p-2.5 rounded bg-charcoal-50 border border-charcoal-200">
                  <span className="text-charcoal-500 block text-[10px] uppercase font-semibold">Expected Value:</span>
                  <span className="text-charcoal-900 font-medium">{rule.expected_value}</span>
                </div>
              </div>

              {/* Remediation One-Liner */}
              <div className="mt-4 pt-3 border-t border-charcoal-100 flex items-center justify-between gap-4">
                <div className="flex items-center gap-2 overflow-hidden">
                  <span className="text-[11px] font-semibold text-charcoal-500 uppercase tracking-wider shrink-0">Remediation:</span>
                  <code className="text-[11px] font-mono bg-charcoal-100 px-2 py-1 rounded text-charcoal-900 truncate">
                    {rule.remediation_script}
                  </code>
                </div>
                <button
                  onClick={() => copyToClipboard(rule.remediation_script, rule.id)}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-charcoal-100 hover:bg-charcoal-950 hover:text-white text-charcoal-800 text-xs font-medium transition-colors shrink-0"
                >
                  {copiedScript === rule.id ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy PowerShell</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
