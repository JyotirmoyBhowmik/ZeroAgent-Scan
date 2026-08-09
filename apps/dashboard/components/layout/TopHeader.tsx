"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Search, Radar, Bell, ShieldCheck, ExternalLink } from "lucide-react";

export function TopHeader() {
  const [searchQuery, setSearchQuery] = useState("");

  return (
    <header className="h-16 bg-white border-b border-charcoal-200 px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Global Search Bar */}
      <div className="flex items-center gap-3 w-96">
        <div className="relative w-full">
          <Search className="w-4 h-4 text-charcoal-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            placeholder="Search hostnames, IPs, domains, serials..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 placeholder:text-charcoal-400 focus:outline-none focus:ring-2 focus:ring-charcoal-950 focus:bg-white transition-all"
          />
        </div>
      </div>

      {/* Action Center & Status Indicators */}
      <div className="flex items-center gap-4">
        {/* Gateway mTLS Status Pill */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-charcoal-50 border border-charcoal-200 text-xs font-medium text-charcoal-700">
          <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
          <span>Control Plane:</span>
          <span className="text-charcoal-950 font-semibold font-mono">mTLS Authenticated</span>
        </div>

        {/* Quick Launch Scan Button */}
        <Link
          href="/scans"
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-charcoal-950 text-white text-xs font-medium hover:bg-charcoal-800 transition-colors shadow-sm"
        >
          <Radar className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
          <span>Launch Agentless Scan</span>
        </Link>

        {/* User Identity / Role */}
        <div className="flex items-center gap-2 pl-2 border-l border-charcoal-200">
          <div className="w-8 h-8 rounded-full bg-charcoal-100 border border-charcoal-300 flex items-center justify-center font-bold text-xs text-charcoal-800">
            EG
          </div>
          <div className="text-left hidden md:block">
            <span className="block text-xs font-semibold text-charcoal-950">Security Officer</span>
            <span className="block text-[10px] text-charcoal-500">ASVS Level 2</span>
          </div>
        </div>
      </div>
    </header>
  );
}
