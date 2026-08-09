"use client";

import React, { useEffect, useState } from "react";
import { KeyRound, Shield, Lock, Plus, CheckCircle2, AlertTriangle, Fingerprint, EyeOff } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import { VaultCredentialSummary } from "@/lib/types";

export default function VaultPage() {
  const [credentials, setCredentials] = useState<VaultCredentialSummary[]>([]);
  const [showModal, setShowModal] = useState(false);

  // Form State
  const [name, setName] = useState("");
  const [credentialType, setCredentialType] = useState("domain_kerberos");
  const [domainOrHost, setDomainOrHost] = useState("");
  const [username, setUsername] = useState("");
  const [secretValue, setSecretValue] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    async function load() {
      const data = await api.getVaultCredentials();
      setCredentials(data);
    }
    load();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const newCred = await api.createVaultCredential({
        name,
        credential_type: credentialType,
        domain_or_host: domainOrHost,
        username,
        secret_value: secretValue,
      });
      setCredentials([newCred, ...credentials]);
      // Zeroize secret state immediately
      setSecretValue("");
      setName("");
      setDomainOrHost("");
      setUsername("");
      setShowModal(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-charcoal-950">Dedicated Credential Vault</h1>
          <p className="text-sm text-charcoal-600 mt-1">
            Zero-plaintext secret storage. Credentials never touch the database directly; referenced strictly via opaque IDs.
          </p>
        </div>

        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-charcoal-950 hover:bg-charcoal-800 text-white text-sm font-semibold rounded-lg shadow-sm transition-all"
        >
          <Plus className="w-4 h-4" />
          <span>Register Opaque Credential</span>
        </button>
      </div>

      {/* Security Architecture Info Card */}
      <div className="bg-white rounded-xl border border-charcoal-200 p-5 flex items-start gap-4 card-border">
        <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center shrink-0">
          <Lock className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-sm font-bold text-charcoal-950">OWASP ASVS Level 2 Secret Isolation</h2>
          <p className="text-xs text-charcoal-600 mt-1 leading-relaxed">
            Secrets are encrypted with <strong>AES-256-GCM</strong> using master keys derived via <strong>HKDF-SHA256</strong>.
            Target scan configurations only store opaque reference tokens (e.g. <code className="font-mono text-charcoal-900 bg-charcoal-100 px-1 py-0.5 rounded">sec_ref_...</code>).
            Plaintext secrets are decrypted exclusively in ephemeral memory buffers inside the on-prem Collector Gateway during active WS-Man sessions.
          </p>
        </div>
      </div>

      {/* Tokenized Credentials List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {credentials.map((c) => (
          <div key={c.id} className="bg-white rounded-xl border border-charcoal-200 p-5 card-border">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-charcoal-100 border border-charcoal-200 text-charcoal-800 flex items-center justify-center">
                  <KeyRound className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-bold text-sm text-charcoal-950">{c.name}</h3>
                  <span className="text-[11px] text-charcoal-500 font-mono block">
                    {c.domain_or_host} • {c.username}
                  </span>
                </div>
              </div>
              <Badge variant="info" size="sm">
                {c.credential_type}
              </Badge>
            </div>

            <div className="mt-4 p-3 bg-charcoal-50 rounded-lg border border-charcoal-200 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-charcoal-500 font-semibold text-[10px] uppercase">Opaque Token ID:</span>
                <span className="font-mono font-bold text-charcoal-950">{c.opaque_id}</span>
              </div>
              <div className="flex justify-between items-center mt-2 pt-2 border-t border-charcoal-200 text-[10px] text-charcoal-500 font-mono">
                <span>Encryption: AES-256-GCM</span>
                <span>Secret: Protected (Zeroized)</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Register Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-charcoal-950/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl border border-charcoal-200 max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-bold text-charcoal-950">Register Encrypted Credential</h2>
              <button
                onClick={() => setShowModal(false)}
                className="text-xs font-semibold text-charcoal-500 hover:text-charcoal-900"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreate} className="space-y-3 text-xs">
              <div>
                <label className="block font-semibold text-charcoal-700 mb-1">Profile Name</label>
                <input
                  type="text"
                  placeholder="e.g. Domain Controller Scan Account"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
                />
              </div>

              <div>
                <label className="block font-semibold text-charcoal-700 mb-1">Credential Type</label>
                <select
                  value={credentialType}
                  onChange={(e) => setCredentialType(e.target.value)}
                  className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
                >
                  <option value="domain_kerberos">Active Directory Domain (Kerberos / gMSA)</option>
                  <option value="domain_ntlm">Active Directory Domain (NTLM over HTTPS)</option>
                  <option value="local_service">Local Service Account</option>
                  <option value="snmp_v3">SNMPv3 Auth/Priv Key (for BMC)</option>
                  <option value="ssh_key">SSH Private Key (for iLO/iDRAC)</option>
                </select>
              </div>

              <div>
                <label className="block font-semibold text-charcoal-700 mb-1">Domain or Target Subnet</label>
                <input
                  type="text"
                  placeholder="CORP.ENDPOINTGUARD.LOCAL"
                  value={domainOrHost}
                  onChange={(e) => setDomainOrHost(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg font-mono text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
                />
              </div>

              <div>
                <label className="block font-semibold text-charcoal-700 mb-1">Username / Service Principal</label>
                <input
                  type="text"
                  placeholder="svc_endpointguard_winrm"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg font-mono text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
                />
              </div>

              <div>
                <label className="block font-semibold text-charcoal-700 mb-1">
                  Secret Value (Password, AuthKey, or Private Key)
                </label>
                <input
                  type="password"
                  placeholder="••••••••••••••••"
                  value={secretValue}
                  onChange={(e) => setSecretValue(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-charcoal-50 border border-charcoal-200 rounded-lg font-mono text-charcoal-900 focus:ring-2 focus:ring-charcoal-950 focus:outline-none"
                />
                <span className="text-[10px] text-charcoal-500 mt-1 block">
                  Encrypted immediately via AES-256-GCM. Plaintext is never written to DB or logs.
                </span>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-2.5 bg-charcoal-950 hover:bg-charcoal-800 text-white font-semibold rounded-lg shadow-sm transition-all"
                >
                  {isSubmitting ? "Encrypting..." : "Encrypt & Store into Vault"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
