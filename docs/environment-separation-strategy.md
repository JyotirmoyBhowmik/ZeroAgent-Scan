# EndpointGuard Staging vs. Production Environment Separation Strategy

> **Zero-Trust Environment Isolation, Cryptographic Key Segregation, and Vault Namespace Boundaries.**

---

## 🏛️ Environment Isolation Matrix

To prevent lateral movement, credential leakage, and configuration contamination, EndpointGuard enforces strict cryptographic, network, and IAM separation across development, staging, and production tiers.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              CRYPTOGRAPHIC & NETWORK ISOLATION                         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   [ Staging Tier ]                                [ Production Tier ]                  │
│   ┌────────────────────────────────────────┐      ┌────────────────────────────────┐   │
│   │ • AWS KMS: `alias/endpointguard-stage` │      │ • AWS KMS: `alias/endpointguard-prod`│
│   │ • Vault Namespace: `endpointguard/stage│      │ • Vault Namespace: `endpointguard/prod`
│   │ • Staging CA: `CN=EndpointGuard Stage` │      │ • Prod CA: `CN=EndpointGuard Prod` │
│   │ • VPC: `10.200.0.0/16` (Staging)       │      │ • VPC: `10.100.0.0/16` (Prod)   │
│   │ • DB: `staging-pg-cluster.internal`    │      │ • DB: `prod-aurora-cluster`    │
│   │ • Synthetic / Lab Target Endpoints Only│      │ • Enterprise Production Fleet  │
│   └────────────────────────────────────────┘      └────────────────────────────────┘   │
│                       ▲                                       ▲                        │
│                       │                                       │                        │
│              [ STRICT FIREWALL AIR-GAP: ZERO CROSS-TALK PERMITTED ]                    │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 1. Cryptographic Key & Vault Segregation

| Isolation Layer | Staging Environment | Production Environment | Security Rationale |
| :--- | :--- | :--- | :--- |
| **AWS KMS / Azure Key Vault** | `alias/endpointguard-staging-key` (Dedicated staging AWS Account / Subscription) | `alias/endpointguard-production-key` (Dedicated prod AWS Account with strict Break-Glass IAM) | A breach of staging CI/CD or developer credentials cannot unwrap production database ciphertexts. |
| **HashiCorp Vault Namespace** | `endpointguard/staging/` | `endpointguard/production/` | Complete role and policy boundary isolation; staging tokens have zero read capability in prod namespace. |
| **mTLS Gateway Root CA** | `EndpointGuard Staging Subordinate CA` | `EndpointGuard Production Root CA (HSM-backed)` | A test/staging collector gateway certificate cannot authenticate to production Control Plane APIs. |
| **JWT Signing Keys** | Ephemeral 256-bit secret stored in Staging K8s secret | 512-bit RSA/ECDSA keypair backed by HSM | Staging sessions cannot be used to forge tokens on production endpoints. |

---

## 🌐 2. Network & Subnet Segmentation

1. **Dedicated Cloud Accounts & VPCs**:
   - Production runs inside an isolated AWS Account / Azure Subscription with no VPC Peering to staging or corporate development subnets.
2. **Subnet Gateway CIDR Restrictions**:
   - Staging Collector Gateways are strictly confined to scan lab/staging subnets (e.g. `10.200.1.0/24`).
   - Any attempt by a staging gateway to initiate scans against production CIDRs (`10.100.0.0/16`) is rejected by both API boundary validation and egress firewall rules.

---

## 🚫 3. Data Hygiene & Zero-Leak Rules

- **No Production Telemetry in Staging**: Staging environments must only scan dedicated synthetic Windows test VMs or sanitized sandbox machines.
- **Zero Real Credentials**: Staging vaults must use test accounts with restricted lab rights (`LAB\svc_test_audit`). Production LAPS or Active Directory credentials must never be inputted into staging systems.
- **Automated CI/CD Validation**: The deployment pipeline enforces that production images and configuration manifests strictly reference production KMS aliases and Vault namespaces.
