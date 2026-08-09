"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  Monitor,
  Radar,
  CheckCircle2,
  Network,
  KeyRound,
  FileText,
  Terminal,
  Activity,
  Server,
} from "lucide-react";

export function Sidebar() {
  const pathname = usePathname();

  const navigation = [
    { name: "Executive Overview", href: "/", icon: Activity },
    { name: "Fleet Inventory", href: "/endpoints", icon: Monitor },
    { name: "Agentless Scans", href: "/scans", icon: Radar },
    { name: "CIS Compliance", href: "/compliance", icon: CheckCircle2 },
    { name: "Collector Gateways", href: "/gateways", icon: Network },
    { name: "Credential Vault", href: "/vault", icon: KeyRound },
    { name: "ASVS Audit Logs", href: "/audit-logs", icon: FileText },
  ];

  return (
    <aside className="w-64 bg-white border-r border-charcoal-200 flex flex-col h-screen sticky top-0 z-30">
      {/* Brand Header */}
      <div className="h-16 px-6 border-b border-charcoal-200 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-charcoal-950 flex items-center justify-center text-white shadow-sm">
          <Shield className="w-5 h-5 text-emerald-400" />
        </div>
        <div>
          <span className="font-bold text-base text-charcoal-950 tracking-tight block">
            Endpoint<span className="text-emerald-600">Guard</span>
          </span>
          <span className="text-[10px] font-semibold text-charcoal-500 uppercase tracking-widest block">
            100% Agentless
          </span>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-charcoal-400">
          Core Platform
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
                  ? "bg-charcoal-950 text-white shadow-sm"
                  : "text-charcoal-700 hover:bg-charcoal-100 hover:text-charcoal-950"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-emerald-400" : "text-charcoal-500"}`} />
              <span className="truncate">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Protocol Badge Footer */}
      <div className="p-4 border-t border-charcoal-200 bg-charcoal-50">
        <div className="flex items-center justify-between text-xs mb-1.5">
          <span className="text-charcoal-500 font-medium">Protocol Mesh</span>
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            mTLS 1.3
          </span>
        </div>
        <div className="text-[11px] text-charcoal-600 space-y-0.5">
          <div className="flex justify-between">
            <span>WinRM HTTPS:</span>
            <span className="font-mono text-charcoal-900 font-medium">5986</span>
          </div>
          <div className="flex justify-between">
            <span>CIM / WMI:</span>
            <span className="font-mono text-charcoal-900 font-medium">WQL</span>
          </div>
          <div className="flex justify-between">
            <span>BMC / iLO:</span>
            <span className="font-mono text-charcoal-900 font-medium">SNMPv3</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
