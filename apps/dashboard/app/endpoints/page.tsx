"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Search, Filter, Monitor, Server, Laptop, ShieldCheck, ArrowUpRight, Cpu, HardDrive } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { Endpoint } from "@/lib/types";

export default function EndpointsPage() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [search, setSearch] = useState("");
  const [osFilter, setOsFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const data = await api.getEndpoints(search, osFilter, statusFilter);
        setEndpoints(data);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [search, osFilter, statusFilter]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">Fleet Endpoints & Hardware</h1>
          <p className="text-sm text-charcoal-600 mt-1">
            Complete agentless inventory of audited Windows 11 & Windows Server physical and virtual hosts.
          </p>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-white p-4 rounded-xl border border-charcoal-200 flex flex-col md:flex-row items-center justify-between gap-4 card-border">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-charcoal-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter by hostname, IP, serial..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-xs bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 placeholder:text-charcoal-400 focus:outline-none focus:ring-2 focus:ring-charcoal-950"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          {/* OS Filter */}
          <select
            value={osFilter}
            onChange={(e) => setOsFilter(e.target.value)}
            className="text-xs bg-charcoal-50 border border-charcoal-200 rounded-lg px-3 py-2 text-charcoal-800 focus:outline-none focus:ring-2 focus:ring-charcoal-950"
          >
            <option value="">All Operating Systems</option>
            <option value="Windows 11">Windows 11</option>
            <option value="Windows Server">Windows Server</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="text-xs bg-charcoal-50 border border-charcoal-200 rounded-lg px-3 py-2 text-charcoal-800 focus:outline-none focus:ring-2 focus:ring-charcoal-950"
          >
            <option value="">All Statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
          </select>
        </div>
      </div>

      {/* Main Endpoints Data Grid */}
      <div className="bg-white rounded-xl border border-charcoal-200 overflow-hidden card-border">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-charcoal-50/70 border-b border-charcoal-200 text-charcoal-600 uppercase tracking-wider font-semibold">
                <th className="py-3.5 px-6">Endpoint / Hostname</th>
                <th className="py-3.5 px-4">Network & Protocol</th>
                <th className="py-3.5 px-4">Operating System</th>
                <th className="py-3.5 px-4">Hardware Specs</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">CIS Compliance</th>
                <th className="py-3.5 px-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-charcoal-100">
              {endpoints.map((ep) => (
                <tr key={ep.id} className="hover:bg-charcoal-50/70 transition-colors group">
                  <td className="py-4 px-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-charcoal-100 border border-charcoal-200 text-charcoal-800 group-hover:border-charcoal-400 transition-colors">
                        {ep.chassis_type === "Laptop" ? (
                          <Laptop className="w-4 h-4" />
                        ) : ep.chassis_type === "Server" ? (
                          <Server className="w-4 h-4" />
                        ) : (
                          <Monitor className="w-4 h-4" />
                        )}
                      </div>
                      <div>
                        <Link href={`/endpoints/${ep.id}`} className="font-bold text-sm text-charcoal-950 hover:text-emerald-700 block">
                          {ep.hostname}
                        </Link>
                        <span className="text-[11px] text-charcoal-500 font-mono block">
                          {ep.manufacturer} {ep.model}
                        </span>
                      </div>
                    </div>
                  </td>

                  <td className="py-4 px-4 font-mono">
                    <span className="text-charcoal-900 font-semibold block">{ep.ip_address}</span>
                    <span className="text-[10px] text-charcoal-500 block">{ep.mac_address}</span>
                    <span className="text-[10px] text-emerald-700 font-semibold block">WinRM HTTPS:5986</span>
                  </td>

                  <td className="py-4 px-4">
                    <span className="text-charcoal-900 font-medium block">{ep.os_name}</span>
                    <span className="text-[11px] text-charcoal-500 font-mono block">Build {ep.os_build}</span>
                  </td>

                  <td className="py-4 px-4 text-[11px] text-charcoal-600">
                    <span className="block font-mono">Serial: {ep.serial_number}</span>
                    <span className="block text-charcoal-500">{ep.domain}</span>
                  </td>

                  <td className="py-4 px-4">
                    <Badge variant={ep.status === "online" ? "success" : "danger"} size="sm">
                      {ep.status}
                    </Badge>
                  </td>

                  <td className="py-4 px-4 text-right">
                    <span
                      className={`inline-flex items-center px-2.5 py-1 rounded text-xs font-bold font-mono border ${
                        ep.compliance_score >= 90
                          ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                          : "bg-amber-50 text-amber-700 border-amber-200"
                      }`}
                    >
                      {ep.compliance_score.toFixed(1)}%
                    </span>
                  </td>

                  <td className="py-4 px-6 text-right">
                    <Link
                      href={`/endpoints/${ep.id}`}
                      className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-charcoal-100 hover:bg-charcoal-950 hover:text-white text-charcoal-800 text-xs font-medium transition-colors"
                    >
                      <span>Inspect</span>
                      <ArrowUpRight className="w-3 h-3" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
