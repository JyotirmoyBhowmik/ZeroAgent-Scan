"use client";

import React, { useEffect, useState } from "react";
import { AlertTriangle, Database, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";

export function DevEnvironmentBanner() {
  const [isDev, setIsDev] = useState<boolean>(true);
  const [envName, setEnvName] = useState<string>("development");

  useEffect(() => {
    // 1. Check frontend environment variable
    const appEnv = process.env.NEXT_PUBLIC_APP_ENV || process.env.NODE_ENV;
    if (appEnv === "production") {
      setIsDev(false);
      setEnvName("production");
    }

    // 2. Query backend environment configuration for verification
    async function verifyBackendEnv() {
      try {
        const report = await api.fetchProductionReadiness();
        if (report && report.environment === "production" && appEnv === "production") {
          setIsDev(false);
          setEnvName("production");
        } else if (report && report.environment) {
          setIsDev(true);
          setEnvName(report.environment);
        }
      } catch {
        // Default to keeping banner visible in dev/offline
      }
    }
    verifyBackendEnv();
  }, []);

  if (!isDev) {
    return null;
  }

  return (
    <div
      role="banner"
      aria-label="Development Environment Warning"
      className="bg-amber-500 text-amber-950 px-4 py-2 text-xs font-bold uppercase tracking-wider flex flex-col sm:flex-row items-center justify-between border-b-2 border-amber-600 shadow-sm select-none z-50 sticky top-0"
    >
      <div className="flex items-center gap-2.5">
        <span className="flex h-2.5 w-2.5 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-950 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-950"></span>
        </span>
        <AlertTriangle className="w-4 h-4 text-amber-950 shrink-0" />
        <span className="font-extrabold tracking-wide">
          DEVELOPMENT / MOCK DATA — NOT PRODUCTION
        </span>
        <span className="bg-amber-950 text-amber-200 text-[10px] px-2 py-0.5 rounded font-mono hidden sm:inline-block">
          RFC 5737 SIMULATION MODE
        </span>
      </div>

      <div className="flex items-center gap-3 text-[11px] font-mono opacity-90 mt-1 sm:mt-0">
        <span className="hidden md:inline">
          Active DB: <strong>endpointguard_dev</strong>
        </span>
        <span className="hidden lg:inline">•</span>
        <span className="hidden lg:inline">
          Mode: <strong>MOCK_SCAN_MODE=true</strong>
        </span>
        <span className="bg-amber-600/30 px-2 py-0.5 rounded border border-amber-600/40 text-[10px]">
          ENV: {envName.toUpperCase()}
        </span>
      </div>
    </div>
  );
}
