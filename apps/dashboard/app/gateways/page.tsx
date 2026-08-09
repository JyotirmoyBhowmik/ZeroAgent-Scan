"use client";

import React, { useEffect, useState } from "react";
import { Network, ShieldCheck, Activity, Copy, Check, Terminal, Plus, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { CollectorGateway } from "@/lib/types";

export default function GatewaysPage() {
  const [gateways, setGateways] = useState<CollectorGateway[]>([]);
  const [copiedCode, setCopiedCode] = useState(false);

  useEffect(() => {
    async function load() {
      const data = await api.getGateways();
      setGateways(data);
    }
    load();
  }, []);

  const dockerCommand = `docker run -d --name endpointguard-gateway \\
  -e GATEWAY_ID=gw-subnet-10-100-3-0 \\
  -e SUBNET_CIDR=10.100.3.0/24 \\
  -e CONTROL_PLANE_URL=https://api.endpointguard.corp.local:8080 \\
  -v /etc/endpointguard/certs:/etc/endpointguard/certs:ro \\
  ghcr.io/endpointguard/gateway:latest`;

  const copyDocker = () => {
    navigator.clipboard.writeText(dockerCommand);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">Subnet Collector Gateways</h1>
          <p className="text-sm text-charcoal-600 mt-1">
            Distributed on-premises Go daemons authenticating to the Central Control Plane via Mutual TLS (mTLS 1.3).
          </p>
        </div>

        <Badge variant="success" size="md">
          {gateways.length} Gateways Operational
        </Badge>
      </div>

      {/* Gateway Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {gateways.map((gw) => (
          <div key={gw.id} className="bg-white rounded-xl border border-charcoal-200 p-6 card-border">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-charcoal-950 text-white flex items-center justify-center shadow-sm">
                  <Network className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <h2 className="font-bold text-sm text-charcoal-950">{gw.name}</h2>
                  <span className="font-mono text-xs text-charcoal-500 font-semibold block">{gw.subnet_cidr}</span>
                </div>
              </div>
              <Badge variant={gw.status === "healthy" ? "success" : "warning"} size="sm">
                {gw.status.toUpperCase()}
              </Badge>
            </div>

            <div className="mt-5 space-y-2 text-xs">
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">Gateway Identifier:</span>
                <span className="font-mono text-charcoal-900 font-medium">{gw.gateway_code}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">Telemetry Latency:</span>
                <span className="font-mono font-bold text-emerald-700">{gw.latency_ms} ms</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-charcoal-100">
                <span className="text-charcoal-500">Daemon Version:</span>
                <span className="font-mono text-charcoal-900">{gw.version}</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-charcoal-500">mTLS Authentication:</span>
                <span className="font-mono text-[11px] text-emerald-700 font-semibold">TLSv1.3 AES-GCM</span>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-charcoal-100">
              <span className="text-[10px] text-charcoal-500 font-mono block truncate">
                Cert Fingerprint: {gw.mtls_cert_fingerprint}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Deployment Wizard */}
      <div className="bg-white rounded-xl border border-charcoal-200 p-6 card-border">
        <div className="flex items-center gap-2 mb-3 text-charcoal-950 font-bold text-sm">
          <Terminal className="w-4 h-4 text-emerald-600" />
          <h2>Deploy a New Subnet Collector Gateway</h2>
        </div>
        <p className="text-xs text-charcoal-600 mb-4">
          Run this single Docker command on any jump-host or lightweight VM in the target subnet:
        </p>

        <div className="bg-charcoal-950 rounded-lg p-4 font-mono text-xs text-emerald-400 relative">
          <pre className="overflow-x-auto whitespace-pre-wrap">{dockerCommand}</pre>
          <button
            onClick={copyDocker}
            className="absolute top-3 right-3 flex items-center gap-1 px-3 py-1.5 bg-charcoal-800 hover:bg-charcoal-700 text-white rounded text-xs transition-colors"
          >
            {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedCode ? "Copied" : "Copy Command"}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
