"use client";

import React, { useState } from "react";
import { CheckCircle2, XCircle, ShieldCheck, Copy, Check, Terminal, ExternalLink, Filter } from "lucide-react";
import { Badge } from "@/components/ui/Badge";

const CIS_RULES = [
  {
    id: "CIS-1.1.1",
    title: "Ensure BitLocker Drive Encryption is Enabled on OS Volume",
    category: "Storage & Encryption",
    level: "Level 1",
    benchmark: "Windows 11 & Server 2022/2025",
    rationale: "BitLocker full-disk encryption protects data confidentiality against physical theft, lost media, and cold boot extraction attacks.",
    remediation: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
    passedCount: 22,
    failedCount: 2,
  },
  {
    id: "CIS-1.2.1",
    title: "Ensure Trusted Platform Module (TPM) 2.0 is Active and Attested",
    category: "Hardware & Firmware",
    level: "Level 1",
    benchmark: "Windows 11 & Server 2022/2025",
    rationale: "TPM 2.0 provides hardware-based root of trust for cryptographic key storage, platform measurements, and Virtualization-Based Security (VBS).",
    remediation: "Enable-TpmAutoProvisioning; Initialize-Tpm",
    passedCount: 24,
    failedCount: 0,
  },
  {
    id: "CIS-1.3.1",
    title: "Ensure Microsoft Defender Real-Time Protection is Enabled",
    category: "System Defenses",
    level: "Level 1",
    benchmark: "Windows 11 & Server 2022/2025",
    rationale: "Real-time scanning detects and prevents execution of malware, ransomware, and unauthorized binaries.",
    remediation: "Set-MpPreference -DisableRealtimeMonitoring $false",
    passedCount: 24,
    failedCount: 0,
  },
  {
    id: "CIS-1.4.1",
    title: "Ensure Microsoft Defender Tamper Protection is Enabled",
    category: "System Defenses",
    level: "Level 1",
    benchmark: "Windows 11 & Server 2022/2025",
    rationale: "Tamper protection prevents malicious processes, malware, or local administrators from disabling Defender services or security preferences.",
    remediation: "Set-MpPreference -EnableTamperProtection $true",
    passedCount: 24,
    failedCount: 0,
  },
  {
    id: "CIS-1.5.1",
    title: "Ensure SMBv1 (Legacy Protocol) is Completely Disabled",
    category: "Network Security",
    level: "Level 1",
    benchmark: "Windows 11 & Server 2022/2025",
    rationale: "SMBv1 lacks modern cryptographic integrity checks and is vulnerable to severe remote code execution vulnerabilities (e.g. EternalBlue / WannaCry).",
    remediation: "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart",
    passedCount: 24,
    failedCount: 0,
  },
  {
    id: "CIS-1.6.1",
    title: "Ensure User Account Control: Run all administrators in Admin Approval Mode",
    category: "Access Control",
    level: "Level 1",
    benchmark: "Windows 11 & Server 2022/2025",
    rationale: "Admin Approval Mode ensures that administrative tasks require explicit privilege elevation confirmation.",
    remediation: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1",
    passedCount: 23,
    failedCount: 1,
  },
];

export default function CompliancePage() {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState("all");

  const copyScript = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredRules = selectedCategory === "all"
    ? CIS_RULES
    : CIS_RULES.filter((r) => r.category.toLowerCase().includes(selectedCategory.toLowerCase()));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">
            CIS Benchmark Compliance Center
          </h1>
          <p className="text-sm text-charcoal-600 mt-1">
            Microsoft Windows 11 Enterprise & Windows Server 2022/2025 Level 1 & Level 2 Baselines.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Badge variant="success" size="md">
            Average Compliance: 94.2%
          </Badge>
        </div>
      </div>

      {/* Category Filter Pills */}
      <div className="flex flex-wrap gap-2 text-xs">
        {["all", "Storage & Encryption", "Hardware & Firmware", "System Defenses", "Network Security", "Access Control"].map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1.5 rounded-lg font-medium border transition-all ${
              selectedCategory === cat
                ? "bg-charcoal-950 text-white border-charcoal-950 shadow-sm"
                : "bg-white text-charcoal-700 border-charcoal-200 hover:border-charcoal-400"
            }`}
          >
            {cat === "all" ? "All Categories" : cat}
          </button>
        ))}
      </div>

      {/* Rules Breakdown */}
      <div className="space-y-4">
        {filteredRules.map((rule) => (
          <div key={rule.id} className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center shrink-0 mt-0.5">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-charcoal-500">{rule.id}</span>
                    <h2 className="font-bold text-sm text-charcoal-950">{rule.title}</h2>
                  </div>
                  <span className="text-[11px] text-charcoal-500 mt-0.5 block">
                    {rule.category} • {rule.level} • {rule.benchmark}
                  </span>
                </div>
              </div>

              {/* Pass/Fail stats badge */}
              <div className="flex items-center gap-2 shrink-0 text-xs font-mono">
                <span className="px-2 py-1 bg-emerald-50 text-emerald-700 rounded border border-emerald-200 font-semibold">
                  {rule.passedCount} Passed
                </span>
                {rule.failedCount > 0 && (
                  <span className="px-2 py-1 bg-red-50 text-red-700 rounded border border-red-200 font-semibold">
                    {rule.failedCount} Failed
                  </span>
                )}
              </div>
            </div>

            <p className="text-xs text-charcoal-600 mt-3 leading-relaxed">{rule.rationale}</p>

            {/* Remediation Command */}
            <div className="mt-4 pt-3 border-t border-charcoal-100 flex items-center justify-between gap-4">
              <div className="flex items-center gap-2 overflow-hidden">
                <Terminal className="w-3.5 h-3.5 text-charcoal-500 shrink-0" />
                <span className="text-[11px] font-semibold text-charcoal-500 uppercase tracking-wider shrink-0">Remediation:</span>
                <code className="text-[11px] font-mono bg-charcoal-100 px-2 py-1 rounded text-charcoal-900 truncate">
                  {rule.remediation}
                </code>
              </div>
              <button
                onClick={() => copyScript(rule.remediation, rule.id)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-charcoal-100 hover:bg-charcoal-950 hover:text-white text-charcoal-800 text-xs font-medium transition-colors shrink-0"
              >
                {copiedId === rule.id ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy PowerShell Script</span>
                  </>
                )}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
