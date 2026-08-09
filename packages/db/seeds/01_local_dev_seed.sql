-- ===========================================================================
-- EndpointGuard Local Development Seed Script: 01_local_dev_seed.sql
-- 3 Multi-Tenant Workspaces, 20 Agentless Windows Hosts, CIS Frameworks,
-- Open Critical CVEs, Unacknowledged Configuration Drift, and Vault Secrets.
-- ===========================================================================

-- Temporary bypass RLS during seeding
SET app.bypass_rls = 'on';

-- ---------------------------------------------------------------------------
-- 1. Tenants (3 Enterprise Organizations)
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, name, slug, subscription_tier, is_active) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Acme Financial Services', 'acme-finance', 'enterprise_plus', true),
    ('b0000000-0000-0000-0000-000000000002', 'BioHealth Therapeutics', 'biohealth-pharma', 'enterprise', true),
    ('c0000000-0000-0000-0000-000000000003', 'Apex Cyber Defense Labs', 'apex-cyber', 'enterprise_fedramp', true)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Tenant Users
-- ---------------------------------------------------------------------------
INSERT INTO tenant_users (id, tenant_id, email, full_name, role) VALUES
    ('a1111111-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'ciso@acmefinance.com', 'Sarah Jenkins (CISO)', 'Admin'),
    ('a1111111-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'secops@acmefinance.com', 'Alex Rivera (SecOps)', 'SecurityOfficer'),
    ('b1111111-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'compliance@biohealth.org', 'Elena Rostova', 'SecurityOfficer'),
    ('c1111111-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000003', 'lead@apexlabs.mil', 'Col. Marcus Vance', 'Admin')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3. Subnet Collector Gateways (mTLS mesh nodes)
-- ---------------------------------------------------------------------------
INSERT INTO collector_gateways (id, tenant_id, gateway_code, name, subnet_cidr, mtls_cert_fingerprint, status, version, latency_ms, last_heartbeat_at) VALUES
    ('a2222222-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'gw-acme-ny-dc', 'Acme NY HQ - Subnet 10.100.1.0/24', '10.100.1.0/24', 'SHA256:4a8f9b2c3d1e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b', 'healthy', 'v1.2.4', 3, NOW() - INTERVAL '4 seconds'),
    ('a2222222-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'gw-acme-london', 'Acme London DC - Subnet 10.100.2.0/24', '10.100.2.0/24', 'SHA256:9b2c3d1e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b4a8f', 'healthy', 'v1.2.4', 18, NOW() - INTERVAL '8 seconds'),
    ('b2222222-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'gw-bio-lab-boston', 'BioHealth Boston Lab - Subnet 172.16.10.0/24', '172.16.10.0/24', 'SHA256:1e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b4a8f9b2c3d', 'healthy', 'v1.2.4', 5, NOW() - INTERVAL '2 seconds'),
    ('c2222222-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000003', 'gw-apex-secure-range', 'Apex Cyber Range - Subnet 192.168.99.0/24', '192.168.99.0/24', 'SHA256:3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b4a8f9b2c3d1e5a7b8c9d0e1f2a', 'healthy', 'v1.2.4', 1, NOW() - INTERVAL '1 second')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 4. Credential Vault Records (Zero Plaintext - Opaque IDs)
-- ---------------------------------------------------------------------------
INSERT INTO vault_credentials (id, tenant_id, opaque_id, name, credential_type, domain_or_host, username, encrypted_secret, nonce, auth_tag, salt) VALUES
    ('a3333333-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'sec_ref_acme_domain_gmsa', 'Acme Active Directory gMSA WinRM Account', 'domain_kerberos', 'CORP.ACMEFINANCE.LOCAL', 'svc_winrm_audit$', decode('6a9f8b2c1d3e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b', 'hex'), decode('11223344556677889900aabb', 'hex'), decode('aabbccddeeff00112233445566778899', 'hex'), decode('99887766554433221100ffeeddccbbaa', 'hex')),
    ('a3333333-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'sec_ref_acme_bmc_snmpv3', 'Acme Datacenter iLO/iDRAC SNMPv3 Auth', 'snmp_v3', '10.100.2.0/24', 'sec_admin_snmp', decode('3d1e5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b4a8f9b2c', 'hex'), decode('223344556677889900aabb11', 'hex'), decode('bbccddeeff00112233445566778899aa', 'hex'), decode('887766554433221100ffeeddccbbaa99', 'hex')),
    ('b3333333-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'sec_ref_bio_winrm_admin', 'BioHealth Domain WinRM TLS Profile', 'domain_ntlm', 'BIOHEALTH.ORG', 'svc_endpointguard', decode('5a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b4a8f9b2c3d1e', 'hex'), decode('3344556677889900aabb1122', 'hex'), decode('ccddeeff00112233445566778899aabb', 'hex'), decode('7766554433221100ffeeddccbbaa9988', 'hex')),
    ('c3333333-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000003', 'sec_ref_apex_ssh_ilo_keys', 'Apex Range Supermicro BMC SSH Keys', 'ssh_key', '192.168.99.0/24', 'bmc_root', decode('7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b4a8f9b2c3d1e5a', 'hex'), decode('44556677889900aabb112233', 'hex'), decode('ddeeff00112233445566778899aabbcc', 'hex'), decode('66554433221100ffeeddccbbaa998877', 'hex'))
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 5. Compliance Frameworks & Rules (CIS Benchmarks)
-- ---------------------------------------------------------------------------
INSERT INTO compliance_frameworks (id, code, name, version, target_os, description) VALUES
    ('f0000000-0000-0000-0000-000000000001', 'cis_win11_enterprise', 'CIS Microsoft Windows 11 Enterprise Benchmark', 'v3.0.0', 'Windows 11', 'Center for Internet Security benchmark for Windows 11 Enterprise edition.'),
    ('f0000000-0000-0000-0000-000000000002', 'cis_winserver_2022', 'CIS Microsoft Windows Server 2022 Benchmark', 'v2.0.0', 'Windows Server 2022', 'Center for Internet Security benchmark for Windows Server 2022 Domain Controllers and Member Servers.'),
    ('f0000000-0000-0000-0000-000000000003', 'nist_800_53_r5', 'NIST SP 800-53 Rev 5 High Baseline', 'Rev 5', 'Windows 11 & Server', 'National Institute of Standards and Technology security controls.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO compliance_rules (id, framework_id, rule_code, title, category, level, severity, rationale, expected_value, remediation_script) VALUES
    ('r0000000-0000-0000-0000-000000000001', 'f0000000-0000-0000-0000-000000000001', '1.1.1', 'Ensure BitLocker Drive Encryption is Enabled on OS Volume', 'Storage & Encryption', 'Level 1', 'CRITICAL', 'Full-disk encryption protects data confidentiality in case of device theft or physical loss.', 'ProtectionStatus: 1 (Encrypted with XTS-AES 256)', 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector'),
    ('r0000000-0000-0000-0000-000000000002', 'f0000000-0000-0000-0000-000000000001', '1.2.1', 'Ensure Trusted Platform Module (TPM) 2.0 is Active and Attested', 'Hardware & Firmware', 'Level 1', 'HIGH', 'TPM 2.0 provides hardware root of trust for cryptographic key generation and platform attestation.', 'TPM 2.0 Present, Enabled, and Activated', 'Enable-TpmAutoProvisioning; Initialize-Tpm'),
    ('r0000000-0000-0000-0000-000000000003', 'f0000000-0000-0000-0000-000000000001', '1.3.1', 'Ensure Microsoft Defender Real-Time Protection is Enabled', 'System Defenses', 'Level 1', 'HIGH', 'Real-time protection detects and prevents malware execution prior to disk writes.', 'RealTimeProtection: Enabled', 'Set-MpPreference -DisableRealtimeMonitoring $false'),
    ('r0000000-0000-0000-0000-000000000004', 'f0000000-0000-0000-0000-000000000001', '1.4.1', 'Ensure Microsoft Defender Tamper Protection is Enabled', 'System Defenses', 'Level 1', 'HIGH', 'Tamper protection blocks malicious processes from disabling antimalware features.', 'TamperProtection: Enabled', 'Set-MpPreference -EnableTamperProtection $true'),
    ('r0000000-0000-0000-0000-000000000005', 'f0000000-0000-0000-0000-000000000001', '1.5.1', 'Ensure SMBv1 (Legacy Protocol) is Completely Disabled', 'Network Security', 'Level 1', 'CRITICAL', 'SMBv1 lacks modern cryptographic integrity and is vulnerable to severe remote code execution exploits (EternalBlue).', 'SMBv1: Disabled', 'Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart'),
    ('r0000000-0000-0000-0000-000000000006', 'f0000000-0000-0000-0000-000000000001', '1.6.1', 'Ensure User Account Control: Run all administrators in Admin Approval Mode', 'Access Control', 'Level 1', 'HIGH', 'Admin Approval Mode enforces explicit elevation prompts.', 'EnableLUA: 1 (Enabled)', 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1'),
    ('r0000000-0000-0000-0000-000000000007', 'f0000000-0000-0000-0000-000000000002', '2.1.1', 'Ensure BitLocker is Enabled on Server Data and OS Volumes', 'Storage & Encryption', 'Level 1', 'HIGH', 'Protects server volume data at rest.', 'ProtectionStatus: 1', 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256'),
    ('r0000000-0000-0000-0000-000000000008', 'f0000000-0000-0000-0000-000000000002', '2.2.1', 'Ensure Remote Desktop Network Level Authentication (NLA) is Enforced', 'Network Security', 'Level 1', 'HIGH', 'NLA authenticates connecting clients prior to full RDP session establishment, stopping DoS.', 'UserAuthentication: 1 (Required)', 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 6. 20 Realistic Fake Windows 11 & Windows Server Hosts across 3 Tenants
-- ---------------------------------------------------------------------------

-- Tenant 1: Acme Financial Services (10 Hosts: DCs, SQL Clusters, Executive & Trader Workstations)
INSERT INTO endpoints (id, tenant_id, hostname, domain, ip_address, mac_address, os_name, os_build, serial_number, manufacturer, model, chassis_type, status, agentless_protocol, compliance_score, last_scanned_at) VALUES
    ('e1000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'NY-DC01-PROD', 'CORP.ACMEFINANCE.LOCAL', '10.100.1.10', '00:50:56:A1:01:01', 'Microsoft Windows Server 2022 Datacenter', '20348.2407', 'VMware-42 1a 01 01', 'VMware, Inc.', 'VMware7,1', 'Server', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '15 minutes'),
    ('e1000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'NY-DC02-PROD', 'CORP.ACMEFINANCE.LOCAL', '10.100.1.11', '00:50:56:A1:01:02', 'Microsoft Windows Server 2022 Datacenter', '20348.2407', 'VMware-42 1a 01 02', 'VMware, Inc.', 'VMware7,1', 'Server', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '14 minutes'),
    ('e1000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000001', 'NY-SQL01-CLUSTER', 'CORP.ACMEFINANCE.LOCAL', '10.100.1.20', '00:50:56:A1:01:03', 'Microsoft Windows Server 2022 Datacenter', '20348.2407', 'VMware-42 1a 01 03', 'VMware, Inc.', 'VMware7,1', 'Server', 'online', 'winrm_https', 96.5, NOW() - INTERVAL '12 minutes'),
    ('e1000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000001', 'NY-HYPERV-NODE01', 'CORP.ACMEFINANCE.LOCAL', '10.100.1.30', '00:1E:67:D8:11:22', 'Microsoft Windows Server 2025 Datacenter Preview', '26100.1150', 'DELL-R750-98X2', 'Dell Inc.', 'PowerEdge R750', 'Server', 'online', 'winrm_https', 92.0, NOW() - INTERVAL '10 minutes'),
    ('e1000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000001', 'NY-EXEC-LP01', 'CORP.ACMEFINANCE.LOCAL', '10.100.1.101', '00:1A:2B:3C:01:01', 'Microsoft Windows 11 Enterprise 23H2', '22631.3296', '8XKJ9201', 'Dell Inc.', 'Latitude 7440', 'Laptop', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '5 minutes'),
    ('e1000000-0000-0000-0000-000000000006', 'a0000000-0000-0000-0000-000000000001', 'NY-EXEC-LP02', 'CORP.ACMEFINANCE.LOCAL', '10.100.1.102', '00:1A:2B:3C:01:02', 'Microsoft Windows 11 Enterprise 23H2', '22631.3296', '8XKJ9202', 'Dell Inc.', 'Latitude 7440', 'Laptop', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '6 minutes'),
    ('e1000000-0000-0000-0000-000000000007', 'a0000000-0000-0000-0000-000000000001', 'NY-TRADE-WS01', 'CORP.ACMEFINANCE.LOCAL', '10.100.1.150', 'A4:BB:6D:88:01:01', 'Microsoft Windows 11 Enterprise 23H2', '22631.3007', 'PF4982A1', 'Lenovo', 'ThinkStation P620', 'Desktop', 'online', 'winrm_https', 83.3, NOW() - INTERVAL '8 minutes'),
    ('e1000000-0000-0000-0000-000000000008', 'a0000000-0000-0000-0000-000000000001', 'NY-TRADE-WS02', 'CORP.ACMEFINANCE.LOCAL', '10.100.1.151', 'A4:BB:6D:88:01:02', 'Microsoft Windows 11 Enterprise 23H2', '22631.3296', 'PF4982A2', 'Lenovo', 'ThinkStation P620', 'Desktop', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '9 minutes'),
    ('e1000000-0000-0000-0000-000000000009', 'a0000000-0000-0000-0000-000000000001', 'LDN-APP01-PROD', 'CORP.ACMEFINANCE.LOCAL', '10.100.2.15', '00:50:56:A1:02:01', 'Microsoft Windows Server 2022 Standard', '20348.2407', 'VMware-42 1a 02 01', 'VMware, Inc.', 'VMware7,1', 'Server', 'online', 'winrm_https', 95.0, NOW() - INTERVAL '20 minutes'),
    ('e1000000-0000-0000-0000-000000000010', 'a0000000-0000-0000-0000-000000000001', 'LDN-SEC-LP01', 'CORP.ACMEFINANCE.LOCAL', '10.100.2.105', '5C:BA:EF:11:22:33', 'Microsoft Windows 11 Enterprise 23H2', '22631.3296', '5CD3198X01', 'HP', 'EliteBook 840 G10', 'Laptop', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '18 minutes'),

-- Tenant 2: BioHealth Therapeutics (6 Hosts: Lab Controllers, Clinical Trials Desktops, Sequencing Hosts)
    ('e2000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'BOS-GENOME-WS01', 'BIOHEALTH.ORG', '172.16.10.12', '00:1A:2B:44:01:01', 'Microsoft Windows 11 Pro for Workstations', '22631.3296', '9X19208A', 'Dell Inc.', 'Precision 7960', 'Desktop', 'online', 'winrm_https', 87.5, NOW() - INTERVAL '30 minutes'),
    ('e2000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'BOS-CLINICAL-01', 'BIOHEALTH.ORG', '172.16.10.25', '00:1A:2B:44:01:02', 'Microsoft Windows 11 Enterprise 23H2', '22631.3296', '9X19208B', 'Dell Inc.', 'OptiPlex 7090', 'Desktop', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '25 minutes'),
    ('e2000000-0000-0000-0000-000000000003', 'b0000000-0000-0000-0000-000000000002', 'BOS-CLINICAL-02', 'BIOHEALTH.ORG', '172.16.10.26', '00:1A:2B:44:01:03', 'Microsoft Windows 11 Enterprise 23H2', '22631.3296', '9X19208C', 'Dell Inc.', 'OptiPlex 7090', 'Desktop', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '24 minutes'),
    ('e2000000-0000-0000-0000-000000000004', 'b0000000-0000-0000-0000-000000000002', 'BOS-DC01-BIO', 'BIOHEALTH.ORG', '172.16.10.5', '00:50:56:B2:01:01', 'Microsoft Windows Server 2022 Datacenter', '20348.2407', 'VMware-42 2b 01 01', 'VMware, Inc.', 'VMware7,1', 'Server', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '35 minutes'),
    ('e2000000-0000-0000-0000-000000000005', 'b0000000-0000-0000-0000-000000000002', 'BOS-LIMS-DB01', 'BIOHEALTH.ORG', '172.16.10.40', '00:50:56:B2:01:02', 'Microsoft Windows Server 2022 Datacenter', '20348.2407', 'VMware-42 2b 01 02', 'VMware, Inc.', 'VMware7,1', 'Server', 'online', 'winrm_https', 95.0, NOW() - INTERVAL '32 minutes'),
    ('e2000000-0000-0000-0000-000000000006', 'b0000000-0000-0000-0000-000000000002', 'BOS-RESEARCH-LP03', 'BIOHEALTH.ORG', '172.16.10.115', '48:2A:E3:99:88:77', 'Microsoft Windows 11 Enterprise 23H2', '22631.3296', 'PF99201A', 'Lenovo', 'ThinkPad X1 Carbon Gen 11', 'Laptop', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '15 minutes'),

-- Tenant 3: Apex Cyber Defense Labs (4 Hosts: Simulation Servers, Security Analysis Workstations)
    ('e3000000-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000003', 'APEX-RANGE-SIM01', 'APEX.RANGE.LOCAL', '192.168.99.10', '00:25:90:88:01:01', 'Microsoft Windows Server 2025 Datacenter Preview', '26100.1150', 'SM-X11DPH-91A', 'Supermicro', 'SuperServer 2029U-TN8RT', 'Server', 'online', 'winrm_https', 90.0, NOW() - INTERVAL '50 minutes'),
    ('e3000000-0000-0000-0000-000000000002', 'c0000000-0000-0000-0000-000000000003', 'APEX-RANGE-SIM02', 'APEX.RANGE.LOCAL', '192.168.99.11', '00:25:90:88:01:02', 'Microsoft Windows Server 2022 Datacenter', '20348.2407', 'SM-X11DPH-91B', 'Supermicro', 'SuperServer 2029U-TN8RT', 'Server', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '48 minutes'),
    ('e3000000-0000-0000-0000-000000000003', 'c0000000-0000-0000-0000-000000000003', 'APEX-ANALYST-WS01', 'APEX.RANGE.LOCAL', '192.168.99.50', 'B4:2E:99:11:01:01', 'Microsoft Windows 11 Enterprise 23H2', '22631.3296', 'HPE-Z8-G5-01', 'HP', 'Z8 G5 Workstation', 'Desktop', 'online', 'winrm_https', 100.0, NOW() - INTERVAL '40 minutes'),
    ('e3000000-0000-0000-0000-000000000004', 'c0000000-0000-0000-0000-000000000003', 'APEX-ANALYST-WS02', 'APEX.RANGE.LOCAL', '192.168.99.51', 'B4:2E:99:11:01:02', 'Microsoft Windows 11 Enterprise 23H2', '22631.3007', 'HPE-Z8-G5-02', 'HP', 'Z8 G5 Workstation', 'Desktop', 'online', 'winrm_https', 80.0, NOW() - INTERVAL '38 minutes')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 7. Hardware Inventories (Structured Component JSONB)
-- ---------------------------------------------------------------------------
INSERT INTO hardware_inventories (id, tenant_id, endpoint_id, cpu_details, memory_details, storage_details, network_details, bios_details, tpm_details) VALUES
    ('h1000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000005', 
     '{"name": "13th Gen Intel(R) Core(TM) i7-1365U", "architecture": "x64", "sockets": 1, "cores": 10, "logical_processors": 12, "max_clock_mhz": 5200}',
     '{"total_bytes": 34359738368, "slots_used": 2, "total_slots": 2, "dimms": [{"slot": "DIMM 1", "capacity_bytes": 17179869184, "speed_mhz": 5600, "manufacturer": "SK Hynix", "part_number": "HMCG78AGBUA"}, {"slot": "DIMM 2", "capacity_bytes": 17179869184, "speed_mhz": 5600, "manufacturer": "SK Hynix", "part_number": "HMCG78AGBUA"}]}',
     '{"disks": [{"index": 0, "model": "NVMe KIOXIA 1024GB SSD", "bus_type": "NVMe", "size_bytes": 1024209543168, "partition_count": 4, "smart_status": "Healthy", "serial": "KX9820194A"}]}',
     '{"adapters": [{"name": "Intel(R) Wi-Fi 6E AX211 160MHz", "mac": "00:1A:2B:3C:01:01", "ip_addresses": ["10.100.1.101"], "subnet_mask": "255.255.255.0", "default_gateway": "10.100.1.1", "dhcp_enabled": true, "link_speed_mbps": 1200}]}',
     '{"version": "1.11.0", "release_date": "2024-01-15", "smbios_version": "3.5", "manufacturer": "Dell Inc.", "secure_boot": true}',
     '{"present": true, "spec_version": "2.0", "manufacturer_id": "NTC", "enabled": true, "activated": true}'),

    ('h1000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000001',
     '{"name": "Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz", "architecture": "x64", "sockets": 2, "cores": 16, "logical_processors": 32, "max_clock_mhz": 2800}',
     '{"total_bytes": 68719476736, "slots_used": 4, "total_slots": 8, "dimms": [{"slot": "DIMM 1", "capacity_bytes": 17179869184, "speed_mhz": 3200, "manufacturer": "Micron", "part_number": "MTA36ASF4G72PZ"}]}',
     '{"disks": [{"index": 0, "model": "VMware Virtual disk", "bus_type": "SCSI", "size_bytes": 214748364800, "partition_count": 3, "smart_status": "Healthy", "serial": "6000c291982a"}]}',
     '{"adapters": [{"name": "vmxnet3 Ethernet Adapter", "mac": "00:50:56:A1:01:01", "ip_addresses": ["10.100.1.10"], "subnet_mask": "255.255.255.0", "default_gateway": "10.100.1.1", "dhcp_enabled": false, "link_speed_mbps": 10000}]}',
     '{"version": "VMW71.00V.21100004.B64", "release_date": "2023-11-12", "smbios_version": "2.8", "manufacturer": "Phoenix Technologies LTD", "secure_boot": true}',
     '{"present": true, "spec_version": "2.0", "manufacturer_id": "VMW", "enabled": true, "activated": true}')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 8. Security Postures
-- ---------------------------------------------------------------------------
INSERT INTO security_postures (id, tenant_id, endpoint_id, bitlocker_status, defender_status, firewall_status, uac_status, hotfixes, local_admins) VALUES
    ('s1000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000005',
     '{"volumes": [{"drive_letter": "C:", "protection_status": 1, "encryption_method": "XtsAes256", "lock_status": 0, "key_protectors": ["TPM", "RecoveryPassword"]}]}',
     '{"realtime_enabled": true, "cloud_protection": true, "tamper_protection": true, "antimalware_version": "4.18.24030.9", "signatures_updated": "2024-05-14T10:00:00Z"}',
     '{"domain_profile": true, "private_profile": true, "public_profile": true}',
     '{"admin_approval_mode": true}',
     '[{"hotfix_id": "KB5036893", "description": "Security Update", "installed_on": "2024-04-12"}, {"hotfix_id": "KB5037771", "description": "Cumulative Update", "installed_on": "2024-05-14"}]',
     '["Administrator", "CORP\\Domain Admins"]'),

    ('s1000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000007',
     '{"volumes": [{"drive_letter": "C:", "protection_status": 1, "encryption_method": "XtsAes256", "lock_status": 0}, {"drive_letter": "D:", "protection_status": 0, "encryption_method": "None", "lock_status": 0}]}',
     '{"realtime_enabled": true, "cloud_protection": true, "tamper_protection": false, "antimalware_version": "4.18.24030.9"}',
     '{"domain_profile": true, "private_profile": true, "public_profile": false}',
     '{"admin_approval_mode": true}',
     '[{"hotfix_id": "KB5036893", "description": "Security Update", "installed_on": "2024-04-12"}]',
     '["Administrator", "CORP\\TraderAdmins"]')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 9. Host Snapshots (Historical & Latest Snapshots per Host)
-- ---------------------------------------------------------------------------
INSERT INTO host_snapshots (id, tenant_id, host_id, snapshot_type, cpu_details, memory_details, storage_details, network_details, bios_details, tpm_details, security_posture, compliance_score, is_latest, captured_at) VALUES
    ('sn100000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000005', 'full',
     '{"name": "13th Gen Intel Core i7-1365U", "cores": 10}', '{"total_bytes": 34359738368}', '{"disks": [{"model": "KIOXIA 1024GB", "smart": "Healthy"}]}', '{"ip": "10.100.1.101"}', '{"secure_boot": true}', '{"present": true, "version": "2.0"}',
     '{"bitlocker": "Active", "defender": "Active"}', 100.0, true, NOW() - INTERVAL '5 minutes'),

    ('sn100000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000007', 'full',
     '{"name": "AMD Ryzen Threadripper PRO 3995WX", "cores": 64}', '{"total_bytes": 137438953472}', '{"disks": [{"model": "Samsung 990 PRO 2TB"}]}', '{"ip": "10.100.1.150"}', '{"secure_boot": true}', '{"present": true, "version": "2.0"}',
     '{"bitlocker": "Partial", "defender": "TamperDisabled"}', 83.3, true, NOW() - INTERVAL '8 minutes'),

    ('sn100000-0000-0000-0000-000000000003', 'b0000000-0000-0000-0000-000000000002', 'e2000000-0000-0000-0000-000000000001', 'full',
     '{"name": "Intel Xeon w9-3495X", "cores": 56}', '{"total_bytes": 274877906944}', '{"disks": [{"model": "Intel Optane 1.5TB"}]}', '{"ip": "172.16.10.12"}', '{"secure_boot": true}', '{"present": true, "version": "2.0"}',
     '{"bitlocker": "Active", "defender": "Active"}', 87.5, true, NOW() - INTERVAL '30 minutes'),

    ('sn100000-0000-0000-0000-000000000004', 'c0000000-0000-0000-0000-000000000003', 'e3000000-0000-0000-0000-000000000004', 'full',
     '{"name": "Dual Intel Xeon Platinum 8480+", "cores": 112}', '{"total_bytes": 549755813888}', '{"disks": [{"model": "Micron 9400 PRO 7.68TB"}]}', '{"ip": "192.168.99.51"}', '{"secure_boot": true}', '{"present": true, "version": "2.0"}',
     '{"bitlocker": "Unencrypted", "defender": "Active"}', 80.0, true, NOW() - INTERVAL '38 minutes')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 10. Open Critical Vulnerabilities per Tenant
-- ---------------------------------------------------------------------------
INSERT INTO vulnerabilities (id, tenant_id, host_id, cve_id, title, description, severity, cvss_score, affected_component, status, remediation, discovered_at) VALUES
    ('v1000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000004',
     'CVE-2024-21408', 'Windows Hyper-V Remote Code Execution Vulnerability', 'A remote code execution vulnerability in Windows Hyper-V allows a guest OS to execute arbitrary code on the hypervisor host.', 'CRITICAL', 9.8, 'Hyper-V Host', 'OPEN', 'Deploy Cumulative Update KB5037771 immediately and reboot hypervisor node.', NOW() - INTERVAL '2 days'),

    ('v1000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000007',
     'CVE-2024-30078', 'Windows Wi-Fi Driver Remote Code Execution Vulnerability', 'An unauthenticated attacker within physical Wi-Fi radio range can send malicious networking packets to execute remote code on the target.', 'CRITICAL', 8.8, 'Wi-Fi Subsystem (nwifi.sys)', 'OPEN', 'Install Windows Security Update KB5039212.', NOW() - INTERVAL '1 day'),

    ('v2000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'e2000000-0000-0000-0000-000000000001',
     'CVE-2024-21338', 'Windows Kernel Elevation of Privilege Vulnerability', 'An attacker with local non-administrative access can exploit AppLocker driver (appid.sys) to gain SYSTEM-level kernel execution.', 'HIGH', 7.8, 'Windows Kernel (appid.sys)', 'OPEN', 'Install KB5034765 security fix.', NOW() - INTERVAL '4 days'),

    ('v3000000-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000003', 'e3000000-0000-0000-0000-000000000004',
     'CVE-2023-36884', 'Microsoft Office and Windows HTML Remote Code Execution Vulnerability', 'Unauthenticated remote code execution via specially crafted Microsoft Office / Word document exploiting SearchMS protocol.', 'HIGH', 8.3, 'Windows Shell', 'OPEN', 'Set FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION registry key.', NOW() - INTERVAL '6 days')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 11. Unacknowledged Configuration Drift Events
-- ---------------------------------------------------------------------------
INSERT INTO drift_events (id, tenant_id, host_id, drift_category, property_name, baseline_value, current_value, severity, is_acknowledged, detected_at) VALUES
    ('d1000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000007',
     'Defender', 'Defender.TamperProtection', 'Enabled', 'Disabled', 'CRITICAL', false, NOW() - INTERVAL '4 hours'),

    ('d1000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000007',
     'BitLocker', 'BitLocker.VolumeD.ProtectionStatus', '1 (Encrypted)', '0 (Decrypted)', 'HIGH', false, NOW() - INTERVAL '2 hours'),

    ('d2000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'e2000000-0000-0000-0000-000000000001',
     'Network', 'SMBv1.ServerConfiguration', 'Disabled', 'Enabled', 'CRITICAL', false, NOW() - INTERVAL '6 hours'),

    ('d3000000-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000003', 'e3000000-0000-0000-0000-000000000004',
     'Storage', 'BitLocker.VolumeC.ProtectionStatus', '1 (Encrypted)', '0 (Decrypted)', 'CRITICAL', false, NOW() - INTERVAL '1 hour')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 12. Compliance Evaluations (Sample Rule Test Pass/Fails)
-- ---------------------------------------------------------------------------
INSERT INTO compliance_evaluations (id, tenant_id, host_id, rule_id, status, actual_value, evaluated_at) VALUES
    ('ce100000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000005', 'r0000000-0000-0000-0000-000000000001', 'PASS', 'ProtectionStatus: 1 (Encrypted with XTS-AES 256)', NOW() - INTERVAL '5 minutes'),
    ('ce100000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000005', 'r0000000-0000-0000-0000-000000000002', 'PASS', 'TPM 2.0 Present & Enabled', NOW() - INTERVAL '5 minutes'),
    ('ce100000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000005', 'r0000000-0000-0000-0000-000000000003', 'PASS', 'RealTimeProtection: Enabled', NOW() - INTERVAL '5 minutes'),
    ('ce100000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000005', 'r0000000-0000-0000-0000-000000000004', 'PASS', 'TamperProtection: Enabled', NOW() - INTERVAL '5 minutes'),
    ('ce100000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000005', 'r0000000-0000-0000-0000-000000000005', 'PASS', 'SMBv1: Disabled', NOW() - INTERVAL '5 minutes'),
    ('ce100000-0000-0000-0000-000000000006', 'a0000000-0000-0000-0000-000000000001', 'e1000000-0000-0000-0000-000000000007', 'r0000000-0000-0000-0000-000000000004', 'FAIL', 'TamperProtection: Disabled', NOW() - INTERVAL '8 minutes')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 13. Scan Jobs
-- ---------------------------------------------------------------------------
INSERT INTO scan_jobs (id, tenant_id, name, target_cidr, scan_profile, protocol, vault_secret_ref, gateway_id, status, total_hosts, scanned_hosts, compliant_hosts, failed_hosts, logs, started_at, completed_at) VALUES
    ('sj100000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001',
     'Acme NY HQ - Full Hardware & CIS Audit', '10.100.1.0/24', 'full_hardware_os', 'winrm_https', 'sec_ref_acme_domain_gmsa', 'a2222222-0000-0000-0000-000000000001', 'completed', 10, 10, 9, 1,
     '["[INFO] Authenticating to Subnet Gateway gw-acme-ny-dc via mTLS 1.3", "[INFO] Resolved opaque credential sec_ref_acme_domain_gmsa from Vault buffer", "[INFO] Probing 10 target hosts over WinRM HTTPS (5986)", "[INFO] Querying WMI/CIM classes and BitLocker encryption status", "[INFO] Scan completed successfully. 9/10 hosts fully compliant (90.0%)."]',
     NOW() - INTERVAL '20 minutes', NOW() - INTERVAL '15 minutes')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 14. Security Audit Logs (OWASP ASVS Level 2)
-- ---------------------------------------------------------------------------
INSERT INTO security_audit_logs (id, tenant_id, correlation_id, timestamp, actor, action, resource_type, resource_id, status, ip_address, details) VALUES
    ('al100000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'req-audit-seed-01', NOW() - INTERVAL '20 minutes', 'ciso@acmefinance.com', 'SCAN_JOB_LAUNCHED', 'scan_job', 'sj100000-0000-0000-0000-000000000001', 'SUCCESS', '10.100.1.5', '{"target_cidr": "10.100.1.0/24", "profile": "full_hardware_os"}'),
    ('al100000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'req-audit-seed-02', NOW() - INTERVAL '4 hours', 'secops@acmefinance.com', 'DRIFT_DETECTED', 'drift_event', 'd1000000-0000-0000-0000-000000000001', 'ALERT', '127.0.0.1', '{"category": "Defender", "severity": "CRITICAL"}'),
    ('al200000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'req-audit-seed-03', NOW() - INTERVAL '1 day', 'compliance@biohealth.org', 'VAULT_CREDENTIAL_ROTATED', 'vault_credential', 'sec_ref_bio_winrm_admin', 'SUCCESS', '172.16.10.3', '{"algorithm": "AES-256-GCM"}')
ON CONFLICT (id) DO NOTHING;

-- Re-enable RLS session enforcement
RESET app.bypass_rls;
