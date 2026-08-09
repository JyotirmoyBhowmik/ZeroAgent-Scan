"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  Monitor,
  Radar,
  CheckCircle2,
  AlertTriangle,
  Network,
  FileBarChart2,
  KeyRound,
  FileText,
  Activity,
  Server,
} from "lucide-react";

export function Sidebar() {
  const pathname = usePathname();

  const navigation = [
    { name: "Executive Overview", href: "/", icon: Activity },
    { name: "Fleet Inventory", href: "/endpoints", icon: Monitor },
    { name: "CIS Compliance", href: "/compliance", icon: CheckCircle2 },
    { name: "Vulnerability Mgmt", href: "/vulnerabilities", icon: AlertTriangle },
    { name: "Network Topology", href: "/topology", icon: Network },
    { name: "Agentless Scans", href: "/scans", icon: Radar },
    { name: "Report Builder", href: "/reports", icon: FileBarChart2 },
    { name: "Collector Gateways", href: "/gateways", icon: Server },
    { name: "Credential Vault", href: "/vault", icon: KeyRound },
    { name: "ASVS Audit Logs", href: "/audit-logs", icon: FileText },
  ];

  return (
    <aside
      className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen sticky top-0 z-30 select-none text-slate-100"
      aria-label="Sidebar Navigation"
    >
      {/* Brand Header */}
      <div className="h-16 px-6 border-b border-slate-800 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-sm">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <span className="font-bold text-base text-white tracking-tight block">
            Endpoint<span className="text-emerald-400">Guard</span>
          </span>
          <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest block">
            100% Agentless
          </span>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" role="navigation">
        <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          Core Operations
        </div>
        {navigation.map((item) => {
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shadow-sm"
                  : "text-slate-300 hover:bg-slate-800/60 hover:text-white"
              }`}
              aria-current={isActive ? "page" : undefined}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-emerald-400" : "text-slate-400"}`} />
              <span className="truncate">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Protocol Badge Footer */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/60">
        <div className="flex items-center justify-between text-xs mb-1.5">
          <span className="text-slate-400 font-medium">Protocol Mesh</span>
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            mTLS 1.3
          </span>
        </div>
        <div className="text-[11px] text-slate-400 space-y-0.5">
          <div className="flex justify-between">
            <span>WinRM HTTPS:</span>
            <span className="font-mono text-slate-200 font-medium">5986</span>
          </div>
          <div className="flex justify-between">
            <span>CIM / WMI:</span>
            <span className="font-mono text-slate-200 font-medium">WQL</span>
          </div>
          <div className="flex justify-between">
            <span>BMC / iLO:</span>
            <span className="font-mono text-slate-200 font-medium">SNMPv3</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
