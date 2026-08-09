"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Network,
  Server,
  Activity,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Clock,
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import { getNetworkSubnets } from "@/lib/api";
import { NetworkSubnet } from "@/lib/types";

export default function NetworkTopologyPage() {
  const [subnets, setSubnets] = useState<NetworkSubnet[]>([]);
  const [loading, setLoading] = useState(true);

  const loadSubnets = async () => {
    setLoading(true);
    try {
      const data = await getNetworkSubnets();
      setSubnets(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSubnets();
  }, []);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <Network className="w-6 h-6 text-emerald-400" />
            Network Topology & Collector Gateway Mesh
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Segmented CIDR network discovery, assigned agentless gateways, and mTLS 1.3 telemetry health.
          </p>
        </div>

        <button
          onClick={loadSubnets}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-xs font-medium text-slate-300 hover:text-white"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh Mesh
        </button>
      </div>

      {/* Subnet Topology Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {subnets.map((sub) => {
          const isHealthy = sub.gateway_status === "healthy";

          return (
            <div
              key={sub.id}
              className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm space-y-6 hover:border-emerald-500/30 transition-all"
            >
              <div className="flex justify-between items-start">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center">
                    <Radio className="w-5 h-5" />
                  </div>
                  <div>
                    <h2 className="text-base font-bold text-slate-100">{sub.name}</h2>
                    <span className="font-mono text-xs text-emerald-400 font-semibold">{sub.subnet_cidr}</span>
                  </div>
                </div>

                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold border ${
                    isHealthy
                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                      : "bg-rose-500/10 text-rose-400 border-rose-500/20"
                  }`}
                >
                  <span className={`w-2 h-2 rounded-full ${isHealthy ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`}></span>
                  {sub.gateway_status.toUpperCase()}
                </span>
              </div>

              {/* Gateway Assignment Telemetry */}
              <div className="p-4 rounded-lg bg-slate-800/40 border border-slate-800 text-xs space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Assigned Collector Gateway:</span>
                  <span className="font-semibold text-slate-200">{sub.gateway_name}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Gateway Code:</span>
                  <span className="font-mono text-slate-300">{sub.assigned_gateway_code}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">mTLS Round-Trip Latency:</span>
                  <span className="font-mono text-emerald-400 font-semibold">{sub.gateway_latency_ms} ms</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Physical / Cloud Location:</span>
                  <span className="text-slate-300">{sub.location}</span>
                </div>
              </div>

              {/* Host Breakdown */}
              <div className="grid grid-cols-3 gap-3 text-center text-xs">
                <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Total Hosts</span>
                  <span className="text-lg font-bold text-slate-100">{sub.host_count}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Online</span>
                  <span className="text-lg font-bold text-emerald-400">{sub.online_count}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Compliant</span>
                  <span className="text-lg font-bold text-sky-400">{sub.compliant_count}</span>
                </div>
              </div>

              <div className="pt-2 flex justify-between items-center text-xs border-t border-slate-800">
                <span className="text-slate-400 flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5" /> Scanned {new Date(sub.last_scan_at).toLocaleTimeString()}
                </span>
                <Link
                  href="/endpoints"
                  className="text-emerald-400 hover:text-emerald-300 font-semibold inline-flex items-center gap-1"
                >
                  View Hosts <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
