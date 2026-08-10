# EndpointGuard Enterprise Security Policy & OWASP Top 10 (2025) Mapping

> **Confidentiality, Integrity, and Availability Guarantee for 100% Agentless Enterprise Auditing.**

This document details the complete security architecture, OWASP Top 10 (2025) control mappings, STRIDE threat models, and vulnerability disclosure policy for the EndpointGuard platform.

---

## 🛡️ OWASP Top 10 (2025) Enterprise Control Mapping

| OWASP (2025) Control | Implementation & Technical Architecture | Automated Verification Gate |
| :--- | :--- | :--- |
| **A01: Broken Access Control** | • PostgreSQL Row-Level Security (`RLS`) enforcing tenant boundary per session variable.<br>• 5-Role RBAC Matrix (`viewer`, `operator`, `auditor`, `admin`, `superadmin`).<br>• Negative authorization enforcing 403 Forbidden with RFC 9457 Problem Details.<br>• Cross-tenant IDOR defense on credential resolution and snapshot retrieval. | [`owasp_test.go:TestOWASP_A01_BrokenAccessControl`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go)<br>[`auth_test.go:TestRBACPermissions`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/auth/auth_test.go) |
| **A02: Cryptographic Failures** | • Dedicated Envelope Vault with AES-256-GCM authenticated encryption & HKDF-SHA256 derivation.<br>• TLS 1.3 / 1.2+ minimum on all API endpoints and mTLS gateway tunnels.<br>• Explicit memory zeroization (`memzero`) on decrypted credential byte buffers.<br>• Structured log stream automatic regex redaction of keys, passwords, and tokens. | [`owasp_test.go:TestOWASP_A02_CryptographicFailures`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go)<br>[`envelope_test.go:TestEnvelopeEncryptionRoundTrip`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/vault/envelope_test.go) |
| **A03: Injection** | • 100% parameterized SQL queries (`$1`, `$2`) across all repositories.<br>• Custom Go AST static analysis scanner enforcing zero string concatenation in SQL.<br>• Output sanitization against XSS and HTML injection on user-rendered fields. | [`scripts/check_sql_injection.go`](file:///C:/Users/TEST/ZeroAgent%20Scan/scripts/check_sql_injection.go)<br>[`owasp_test.go:TestOWASP_A03_InjectionDefense`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go) |
| **A04: Insecure Design** | • Comprehensive STRIDE threat models for Credential Vault and Gateway Trust Bootstrap.<br>• Opaque credential identifiers (`sec_ref_*`) preventing secret disclosure.<br>• Two-stage Gateway enrollment requiring administrative approval before scan dispatch. | [`SECURITY.md (Threat Models Section)`](#stride-threat-models)<br>[`owasp_test.go:TestOWASP_A04_InsecureDesign_ThreatModel`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go) |
| **A05: Security Misconfiguration** | • Strict HTTP Security Headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`.<br>• Zero default passwords in codebase, configurations, or container images (fail-closed check). | [`owasp_test.go:TestOWASP_A05_SecurityMisconfiguration_Headers`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go)<br>[`next.config.mjs`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/dashboard/next.config.mjs) |
| **A06: Vulnerable Components** | • Automated dependency scanning via Dependabot for Go modules, NPM/pnpm, and Python pip.<br>• CI security gates enforcing `govulncheck`, `bandit`, `pip-audit`, and `pnpm audit --audit-level=high`. | [`.github/dependabot.yml`](file:///C:/Users/TEST/ZeroAgent%20Scan/.github/dependabot.yml)<br>[`.github/workflows/ci.yml`](file:///C:/Users/TEST/ZeroAgent%20Scan/.github/workflows/ci.yml) |
| **A07: Identification & Auth** | • OIDC authentication with Microsoft Entra ID / Okta / Keycloak + PKCE.<br>• RFC 6238 TOTP MFA break-glass emergency fallback.<br>• Refresh token rotation with automatic token family revocation upon replay attacks.<br>• 15-minute step-up re-authentication guard on privilege escalation. | [`owasp_test.go:TestOWASP_A07_AuthenticationFailures`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go)<br>[`auth_test.go:TestRefreshTokenFamilyRevocation`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/auth/auth_test.go) |
| **A08: Software & Data Integrity** | • SHA-256 `payload_hash` tamper detection on host inventory snapshots.<br>• HMAC-SHA256 signed webhook dispatch for configuration drift alerts.<br>• Ed25519 digital signature validation on Collector Gateway binary self-updates. | [`owasp_test.go:TestOWASP_A08_SoftwareAndDataIntegrity`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go)<br>[`drift_test.go:TestPayloadHashShortCircuit`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/drift/drift_test.go) |
| **A09: Logging & Monitoring** | • Immutable, append-only `security_audit_logs` protected by PostgreSQL database trigger blocking `UPDATE` and `DELETE`.<br>• End-to-end W3C Trace Context and distributed `X-Correlation-ID` header propagation. | [`000006_enforce_audit_log_append_only.up.sql`](file:///C:/Users/TEST/ZeroAgent%20Scan/packages/db/migrations/000006_enforce_audit_log_append_only.up.sql)<br>[`owasp_test.go:TestOWASP_A09_SecurityLoggingAndMonitoring`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go) |
| **A10: Server-Side Request Forgery** | • Subnet CIDR and IP boundary validation rejecting Cloud Instance Metadata Service (`169.254.169.254`), loopback (`127.0.0.0/8`), multicast, and unassigned networks. | [`owasp_test.go:TestOWASP_A10_ServerSideRequestForgery_SSRF`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/security/owasp_test.go)<br>[`security.go:ValidateScanTargetSubnet`](file:///C:/Users/TEST/ZeroAgent%20Scan/apps/api/internal/middleware/security.go) |

---

## 🏛️ STRIDE Threat Models

### 1. Dedicated Credential Vault Threat Model

```
               ┌──────────────────────────────────────────────────────────┐
               │              Credential Vault Trust Boundary             │
               └──────────────────────────────────────────────────────────┘
                                             │
   [ Security Operator / API ]               │              [ PostgreSQL / Storage ]
               │                             │                         │
               ├─► Store Secret (Plaintext) ─┼─► AES-256-GCM Encrypt ──┼─► Stored Ciphertext
               │   (Memory Only)             │   (Key from KMS/HKDF)   │   (Zero Plaintext)
               │                             │                         │
               ├─► Memory Zeroization ───────┼─► Overwrite buffer 0x00 │
               │                             │                         │
               └─► Resolve by Opaque Ref ────┼─► Check Tenant Scoping ─┼─► Decrypt in Ephemeral
                   (`sec_ref_*`)             │   & 15m Step-Up Auth    │   Worker Memory
```

| STRIDE Category | Threat Description | EndpointGuard Architectural Mitigation |
| :--- | :--- | :--- |
| **Spoofing (S)** | Attacker impersonates an authorized scan worker to retrieve target domain credentials. | Authenticated requests require valid mTLS 1.3 client certificates signed by the Control Plane CA, paired with short-lived JWT claims scoped to a specific scan job. |
| **Tampering (T)** | Attacker alters ciphertext or IV in the database to corrupt decrypted credentials. | AES-256-GCM provides authenticated encryption with 128-bit authentication tags (`GMAC`). Any bit manipulation causes decryption to fail closed. |
| **Repudiation (R)** | Rogue administrator creates or accesses credentials and denies doing so. | Synchronous, append-only entries are written to `security_audit_logs` with actor identity, IP, correlation ID, timestamp, and action (`VAULT_SECRET_ACCESS`). |
| **Information Disclosure (I)** | Memory dumps, swap files, or log streams expose administrator passwords. | Plaintext credentials reside exclusively in ephemeral memory and are explicitly zeroized (`memzero`) upon encryption. Logger enforces automatic regex redaction. |
| **Denial of Service (D)** | Attacker floods vault endpoint with rapid encryption/decryption requests. | Per-user and per-IP sliding token-bucket rate limiting rejects excessive mutations with `429 Too Many Requests`. |
| **Elevation of Privilege (E)** | Viewer or Operator role attempts to read or rotate administrative vault credentials. | RBAC permission `PermissionManageCredentials` strictly limits vault mutations to `admin`/`superadmin`, protected by mandatory 15-minute step-up authentication. |

---

### 2. Collector Gateway Trust Bootstrap Threat Model

```
   [ Subnet Collector Gateway ]                               [ Control Plane API ]
                │                                                       │
                ├─────── 1. Generate RSA 4096 / Ed25519 CSR ───────────┤
                │                                                       │
                ├─────── 2. Submit CSR (`POST /gateways/register`) ────►│ (Status: PENDING)
                │                                                       │
                │        [ Operator Step-Up Administrative Approval ]   │
                │                                                       │
                │◄────── 3. Issue Signed mTLS Client Certificate ───────┤ (Status: HEALTHY)
                │                                                       │
                ├====== 4. Bidirectional Mutual TLS 1.3 Tunnel ========┤
```

| STRIDE Category | Threat Description | EndpointGuard Architectural Mitigation |
| :--- | :--- | :--- |
| **Spoofing (S)** | Rogue device on internal LAN registers as a legitimate collector gateway. | Gateways initialize in `pending_approval` state and cannot receive jobs or dispatch telemetry until an administrator explicitly reviews the CSR and approves registration. |
| **Tampering (T)** | Man-in-the-Middle (MitM) alters scan telemetry or job instructions in transit. | Bidirectional Mutual TLS 1.3 with certificate pinning guarantees channel integrity and server/client authentication. |
| **Repudiation (R)** | Compromised gateway submits fake compliance passes to hide vulnerabilities. | Telemetry snapshots include deterministic SHA-256 payload hashes and gateway signature validation. |
| **Information Disclosure (I)** | Unauthenticated network eavesdropper intercepts host inventory snapshots. | All gateway traffic is encapsulated inside mTLS 1.3 sessions using modern AEAD ciphers (`TLS_AES_256_GCM_SHA384` / `TLS_CHACHA20_POLY1305_SHA256`). |
| **Denial of Service (D)** | Disconnected gateway halts scan pipelines across subnets. | 60-second periodic heartbeat telemetry automatically transitions unresponsive gateways to `offline`, alerting operators via configuration drift webhooks. |
| **Elevation of Privilege (E)** | Gateway binary is modified by local malware to execute unauthorized commands. | Gateway self-updates require cryptographically valid Ed25519 digital signatures signed by the EndpointGuard release master key. |

---

## 📋 Vulnerability Disclosure Policy (VDP)

EndpointGuard is committed to the security of our users and enterprise customers. We welcome responsible security researchers and coordinate remediation in accordance with ISO/IEC 29147:2018 guidelines.

### Reporting Channels
- **Security Email**: `security@endpointguard.corp`
- **PGP Encryption Key**:
  ```text
  Key ID: 0x4E9A7B3C
  Fingerprint: 8F2A 4B6C 1D0E 9F8A 7B3C 2E4F 6A8D 0C2E 4E9A 7B3C
  ```

### Response & Remediation Service Level Agreements (SLAs)
| Priority / Severity (CVSS v3.1) | Initial Acknowledgment | Triage Assessment | Target Remediation / Patch Release |
| :--- | :--- | :--- | :--- |
| **Critical** (9.0 - 10.0) | < 12 Hours | < 24 Hours | < 7 Business Days |
| **High** (7.0 - 8.9) | < 24 Hours | < 48 Hours | < 14 Business Days |
| **Medium** (4.0 - 6.9) | < 48 Hours | < 5 Business Days | < 30 Business Days |
| **Low** (0.1 - 3.9) | < 72 Hours | < 7 Business Days | Next Scheduled Minor Release |

### Safe Harbor
EndpointGuard considers security research conducted under this policy to be authorized, and will not pursue legal action against researchers who:
1. Make a good-faith effort to avoid privacy violations, data destruction, and service interruption.
2. Provide a reasonable window for remediation prior to public disclosure.
3. Do not exploit vulnerabilities beyond the minimum necessary to demonstrate proof-of-concept.

---

## 🧪 Automated Verification Suite

Run the full OWASP Top 10 automated test suite and static analysis gates locally:

```bash
make security-check
```
