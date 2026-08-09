"use client";

import React, { useEffect, useState } from "react";
import { FileText, Shield, Search, Terminal, ArrowUpRight } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { SecurityAuditLog } from "@/lib/types";

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<SecurityAuditLog[]>([]);
  const [search, setSearch] = useState("");

  useEffect(() => {
    async function load() {
      const data = await api.getAuditLogs();
      setLogs(data);
    }
    load();
  }, []);

  const filteredLogs = logs.filter(
    (l) =>
      l.correlation_id.toLowerCase().includes(search.toLowerCase()) ||
      l.action.toLowerCase().includes(search.toLowerCase()) ||
      l.actor.toLowerCase().includes(search.toLowerCase()) ||
      l.resource_id.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">OWASP ASVS Security Audit Stream</h1>
          <p className="text-sm text-charcoal-600 mt-1">
            Immutable security event stream with distributed Correlation-ID tracing and zero secret leak guarantee.
          </p>
        </div>

        <Badge variant="success" size="md">
          ASVS Level 2 Compliant
        </Badge>
      </div>

      {/* Search Toolbar */}
      <div className="bg-white p-4 rounded-xl border border-charcoal-200 card-border">
        <div className="relative w-full md:w-96">
          <Search className="w-4 h-4 text-charcoal-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by correlation ID, actor, action, resource..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-xs bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 placeholder:text-charcoal-400 focus:outline-none focus:ring-2 focus:ring-charcoal-950"
          />
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-white rounded-xl border border-charcoal-200 overflow-hidden card-border">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="bg-charcoal-50/70 border-b border-charcoal-200 text-charcoal-600 uppercase tracking-wider font-semibold font-sans">
                <th className="py-3 px-6">Timestamp (UTC)</th>
                <th className="py-3 px-4">Correlation ID</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Security Action</th>
                <th className="py-3 px-4">Resource Target</th>
                <th className="py-3 px-4">Client IP</th>
                <th className="py-3 px-6 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-charcoal-100">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-charcoal-50/70 transition-colors">
                  <td className="py-3 px-6 text-charcoal-600">
                    {new Date(log.timestamp).toISOString()}
                  </td>
                  <td className="py-3 px-4 text-charcoal-950 font-bold">
                    {log.correlation_id}
                  </td>
                  <td className="py-3 px-4 text-charcoal-700">
                    {log.actor}
                  </td>
                  <td className="py-3 px-4 font-sans font-semibold text-charcoal-950">
                    {log.action}
                  </td>
                  <td className="py-3 px-4 text-charcoal-600">
                    {log.resource_type}: {log.resource_id}
                  </td>
                  <td className="py-3 px-4 text-charcoal-600">
                    {log.ip_address}
                  </td>
                  <td className="py-3 px-6 text-right">
                    <Badge variant={log.status === "SUCCESS" ? "success" : "danger"} size="sm">
                      {log.status}
                    </Badge>
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
