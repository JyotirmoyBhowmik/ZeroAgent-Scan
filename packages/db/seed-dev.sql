-- ===========================================================================
-- EndpointGuard Dev Environment Seed Data (RFC 5737 Mock Fleet)
-- Populates ~30 realistic mock hosts, KEV vulnerabilities, compliance benchmarks,
-- drift events, immutable audit logs, and users across all 5 roles.
-- ===========================================================================

-- 1. Default Demo Tenant
INSERT INTO tenants (id, name, slug, subscription_tier, is_active, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Demo Financial Corp (RFC 5737 Test Environment)',
    'tenant-default-01',
    'enterprise',
    true,
    NOW(),
    NOW()
) ON CONFLICT (slug) DO NOTHING;

-- 2. Demo Users (RBAC Roles: Admin, Operator, Auditor, Viewer, SuperAdmin)
INSERT INTO tenant_users (id, tenant_id, email, full_name, role, is_active, created_at, updated_at)
VALUES 
    ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', 'admin@demo.local', 'SecOps Lead Administrator', 'admin', true, NOW(), NOW()),
    ('00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000001', 'operator@demo.local', 'Tier 2 Scan Operator', 'operator', true, NOW(), NOW()),
    ('00000000-0000-0000-0000-000000000012', '00000000-0000-0000-0000-000000000001', 'auditor@demo.local', 'SOC Compliance Auditor', 'auditor', true, NOW(), NOW()),
    ('00000000-0000-0000-0000-000000000013', '00000000-0000-0000-0000-000000000001', 'viewer@demo.local', 'Security Dashboard Viewer', 'viewer', true, NOW(), NOW())
ON CONFLICT (tenant_id, email) DO NOTHING;

-- 3. Mock RFC 5737 Subnets
-- TEST-NET-1 (192.0.2.0/24 - Pilot Ring)
-- TEST-NET-2 (198.51.100.0/24 - Staged Ring)
-- TEST-NET-3 (203.0.113.0/24 - Full Fleet Core)

-- 4. Seed 30 Realistic Windows 11 & Windows Server 2022 Endpoints
DO $$
DECLARE
    t_id UUID := '00000000-0000-0000-0000-000000000001';
    ep_id UUID;
    h_name TEXT;
    ip_addr INET;
    mac_addr TEXT;
    os_str TEXT;
    chassis TEXT;
    tier_str TEXT;
    comp_score NUMERIC;
    ep_status TEXT;
    i INT;
BEGIN
    -- Loop 1..20 for Workstations (DEMO-WKS-001 to DEMO-WKS-020)
    FOR i IN 1..20 LOOP
        ep_id := ('00000000-0000-0000-0001-' || LPAD(i::text, 12, '0'))::UUID;
        h_name := 'DEMO-WKS-' || LPAD(i::text, 3, '0');
        
        IF i <= 8 THEN
            ip_addr := ('192.0.2.' || (10 + i))::INET;
            tier_str := 'pilot';
        ELSIF i <= 15 THEN
            ip_addr := ('198.51.100.' || (10 + i))::INET;
            tier_str := 'staged';
        ELSE
            ip_addr := ('203.0.113.' || (10 + i))::INET;
            tier_str := 'full';
        END IF;

        mac_addr := '00:50:56:A1:' || LPAD(TO_HEX(i), 2, '0') || ':FE';
        os_str := 'Windows 11 Enterprise 23H2 (Build 22631.3296)';
        chassis := CASE WHEN i % 3 = 0 THEN 'Laptop' ELSE 'Desktop' END;
        
        -- Compliant / Partial / Failed scores
        IF i = 4 OR i = 12 THEN
            comp_score := 42.50; -- Failed
            ep_status := 'online';
        ELSIF i = 7 OR i = 16 OR i = 19 THEN
            comp_score := 74.00; -- Partial
            ep_status := 'online';
        ELSIF i = 20 THEN
            comp_score := 88.00;
            ep_status := 'offline';
        ELSE
            comp_score := 96.50 + (i % 4); -- Compliant (96.50 - 99.50)
            ep_status := 'online';
        END IF;

        INSERT INTO endpoints (
            id, tenant_id, hostname, domain, ip_address, mac_address,
            os_name, os_build, serial_number, manufacturer, model,
            chassis_type, status, agentless_protocol, compliance_score,
            rollout_tier, tier_promoted_at, last_scanned_at, created_at, updated_at
        ) VALUES (
            ep_id, t_id, h_name, 'DEMO.CORP.LOCAL', ip_addr, mac_addr,
            os_str, '22631.3296', 'VMware-' || LPAD(i::text, 8, '0'), 'Dell Inc.', 'OptiPlex 7090 Micro',
            chassis, ep_status, 'winrm_https', comp_score,
            tier_str, NOW() - INTERVAL '5 days', NOW() - (i || ' hours')::INTERVAL, NOW(), NOW()
        ) ON CONFLICT (id) DO NOTHING;

        -- Hardware Inventory
        INSERT INTO hardware_inventories (
            id, tenant_id, endpoint_id, cpu_details, memory_details, storage_details, network_details, bios_details, tpm_details, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), t_id, ep_id,
            jsonb_build_object('model', '13th Gen Intel(R) Core(TM) i7-13700', 'cores', 16, 'threads', 24, 'clock_mhz', 2100),
            jsonb_build_object('total_gb', 32, 'type', 'DDR5', 'speed_mhz', 4800, 'slots_used', 2, 'slots_total', 4),
            jsonb_build_object('disks', jsonb_build_array(jsonb_build_object('model', 'Samsung SSD 980 PRO 1TB', 'size_gb', 1000, 'bus', 'NVMe', 'health', 'OK'))),
            jsonb_build_object('adapters', jsonb_build_array(jsonb_build_object('name', 'Intel Ethernet Connection I219-LM', 'ip', ip_addr, 'mac', mac_addr, 'speed_mbps', 1000))),
            jsonb_build_object('vendor', 'Dell Inc.', 'version', '1.14.0', 'release_date', '2024-01-15', 'uefi_secure_boot', true),
            jsonb_build_object('present', true, 'spec_version', '2.0', 'manufacturer', 'IFX', 'enabled', true),
            NOW(), NOW()
        ) ON CONFLICT (tenant_id, endpoint_id) DO NOTHING;

        -- Security Posture
        INSERT INTO security_postures (
            id, tenant_id, endpoint_id, bitlocker_status, tpm_version, defender_antivirus_status, secure_boot_enabled, firewall_profiles_active, uac_enabled, credential_guard_enabled, last_security_evaluated_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), t_id, ep_id,
            CASE WHEN comp_score < 60 THEN 'ProtectionOff' ELSE 'FullyEncrypted' END,
            '2.0',
            CASE WHEN comp_score < 60 THEN 'SignaturesOutOfDate' ELSE 'ActiveAndUpdated' END,
            CASE WHEN comp_score < 60 THEN false ELSE true END,
            CASE WHEN comp_score < 60 THEN jsonb_build_array('Domain') ELSE jsonb_build_array('Domain', 'Private', 'Public') END,
            true,
            CASE WHEN comp_score > 90 THEN true ELSE false END,
            NOW() - (i || ' hours')::INTERVAL, NOW(), NOW()
        ) ON CONFLICT (tenant_id, endpoint_id) DO NOTHING;

        -- Host Snapshot (JSONB Telemetry)
        INSERT INTO host_snapshots (
            id, tenant_id, host_id, snapshot_data, is_archived, is_downsample_retained, payload_size_bytes, created_at
        ) VALUES (
            ('00000000-0000-0000-0003-' || LPAD(i::text, 12, '0'))::UUID,
            t_id, ep_id,
            jsonb_build_object(
                'hostname', h_name,
                'ip_address', ip_addr,
                'os_caption', os_str,
                'wmi_classes_scanned', jsonb_build_array('Win32_ComputerSystem', 'Win32_Processor', 'Win32_PhysicalMemory', 'Win32_EncryptableVolume', 'Win32_BIOS', 'Win32_QuickFixEngineering'),
                'installed_hotfixes', jsonb_build_array('KB5034441', 'KB5034123', 'KB5033920'),
                'installed_software', jsonb_build_array(
                    jsonb_build_object('name', 'Google Chrome Enterprise', 'version', '124.0.6367.91'),
                    jsonb_build_object('name', 'Microsoft 365 Apps for enterprise', 'version', '16.0.17425.20176'),
                    jsonb_build_object('name', 'CrowdStrike Falcon Sensor', 'version', '7.12.18104.0')
                )
            ),
            false, true, 8450, NOW() - (i || ' hours')::INTERVAL
        ) ON CONFLICT (id) DO NOTHING;

    END LOOP;

    -- Loop 21..30 for Servers (DEMO-SRV-001 to DEMO-SRV-010)
    FOR i IN 1..10 LOOP
        ep_id := ('00000000-0000-0000-0002-' || LPAD(i::text, 12, '0'))::UUID;
        h_name := 'DEMO-SRV-' || LPAD(i::text, 3, '0');
        ip_addr := ('203.0.113.' || (100 + i))::INET;
        mac_addr := '00:50:56:B2:' || LPAD(TO_HEX(i), 2, '0') || ':AA';
        os_str := 'Windows Server 2022 Datacenter (Build 20348.2340)';
        chassis := 'RackMountServer';
        tier_str := 'full';

        IF i = 3 THEN
            comp_score := 52.00; -- Failed Server
            ep_status := 'online';
        ELSIF i = 8 THEN
            comp_score := 78.50; -- Partial
            ep_status := 'online';
        ELSE
            comp_score := 98.00; -- Compliant
            ep_status := 'online';
        END IF;

        INSERT INTO endpoints (
            id, tenant_id, hostname, domain, ip_address, mac_address,
            os_name, os_build, serial_number, manufacturer, model,
            chassis_type, status, agentless_protocol, compliance_score,
            rollout_tier, tier_promoted_at, last_scanned_at, created_at, updated_at
        ) VALUES (
            ep_id, t_id, h_name, 'DEMO.CORP.LOCAL', ip_addr, mac_addr,
            os_str, '20348.2340', 'PowerEdge-' || LPAD(i::text, 8, '0'), 'Dell Inc.', 'PowerEdge R750',
            chassis, ep_status, 'winrm_https', comp_score,
            tier_str, NOW() - INTERVAL '10 days', NOW() - (i || ' hours')::INTERVAL, NOW(), NOW()
        ) ON CONFLICT (id) DO NOTHING;

        -- Hardware Inventory Server
        INSERT INTO hardware_inventories (
            id, tenant_id, endpoint_id, cpu_details, memory_details, storage_details, network_details, bios_details, tpm_details, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), t_id, ep_id,
            jsonb_build_object('model', 'Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz (Dual Socket)', 'cores', 64, 'threads', 128, 'clock_mhz', 2000),
            jsonb_build_object('total_gb', 256, 'type', 'ECC DDR4', 'speed_mhz', 3200, 'slots_used', 8, 'slots_total', 16),
            jsonb_build_object('disks', jsonb_build_array(jsonb_build_object('model', 'Dell PERC H755 Front SAS RAID10', 'size_gb', 7680, 'bus', 'SAS', 'health', 'OK'))),
            jsonb_build_object('adapters', jsonb_build_array(jsonb_build_object('name', 'Broadcom Adv. Dual 25Gb Ethernet', 'ip', ip_addr, 'mac', mac_addr, 'speed_mbps', 25000))),
            jsonb_build_object('vendor', 'Dell Inc.', 'version', '1.9.2', 'release_date', '2023-11-20', 'uefi_secure_boot', true),
            jsonb_build_object('present', true, 'spec_version', '2.0', 'manufacturer', 'Nuvoton', 'enabled', true),
            NOW(), NOW()
        ) ON CONFLICT (tenant_id, endpoint_id) DO NOTHING;

        -- Security Posture Server
        INSERT INTO security_postures (
            id, tenant_id, endpoint_id, bitlocker_status, tpm_version, defender_antivirus_status, secure_boot_enabled, firewall_profiles_active, uac_enabled, credential_guard_enabled, last_security_evaluated_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), t_id, ep_id,
            'FullyEncrypted', '2.0',
            CASE WHEN i = 3 THEN 'RealtimeProtectionDisabled' ELSE 'ActiveAndUpdated' END,
            true, jsonb_build_array('Domain', 'Private'), true, true,
            NOW() - (i || ' hours')::INTERVAL, NOW(), NOW()
        ) ON CONFLICT (tenant_id, endpoint_id) DO NOTHING;

        -- Host Snapshot Server
        INSERT INTO host_snapshots (
            id, tenant_id, host_id, snapshot_data, is_archived, is_downsample_retained, payload_size_bytes, created_at
        ) VALUES (
            ('00000000-0000-0000-0004-' || LPAD(i::text, 12, '0'))::UUID,
            t_id, ep_id,
            jsonb_build_object(
                'hostname', h_name,
                'ip_address', ip_addr,
                'os_caption', os_str,
                'server_roles', jsonb_build_array('Active Directory Domain Services', 'DNS Server', 'File and Storage Services'),
                'installed_hotfixes', jsonb_build_array('KB5034129', 'KB5033910')
            ),
            false, true, 12200, NOW() - (i || ' hours')::INTERVAL
        ) ON CONFLICT (id) DO NOTHING;

    END LOOP;
END $$;

-- 5. Seed Realistic Vulnerability Findings (Including CISA KEV Flagged CVEs)
INSERT INTO vulnerability_findings (
    id, tenant_id, endpoint_id, cve_id, title, severity, cvss_score, is_kev, description, remediation, status, discovered_at, created_at, updated_at
) VALUES 
    (
        '00000000-0000-0000-0005-000000000001',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0002-000000000003', -- DEMO-SRV-003
        'CVE-2023-34362',
        'Progress MOVEit Transfer SQL Injection Remote Code Execution',
        'critical',
        9.8,
        true, -- CISA KEV
        'SQL injection vulnerability in Progress Software MOVEit Transfer web application leading to unauthenticated remote code execution and data exfiltration.',
        'Apply vendor security hotfix KB5034441 and update MOVEit Transfer to patched build.',
        'open',
        NOW() - INTERVAL '2 days', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0005-000000000002',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000004', -- DEMO-WKS-004
        'CVE-2024-21413',
        'Microsoft Outlook Moniker Link Remote Code Execution (CVE-2024-21413)',
        'critical',
        9.8,
        true, -- CISA KEV
        'Security feature bypass in Microsoft Outlook where clicking a crafted moniker hyperlink bypasses Protected View and executes arbitrary code.',
        'Deploy Microsoft Office Cumulative Security Update February 2024 (KB5002560).',
        'open',
        NOW() - INTERVAL '3 days', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0005-000000000003',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000012', -- DEMO-WKS-012
        'CVE-2023-23397',
        'Microsoft Outlook NTLM Credential Theft & Relay Elevation of Privilege',
        'high',
        9.8,
        true, -- CISA KEV
        'Crafted MAPI reminder task with PidLidReminderFileParameter transmits NTLM hash to attacker server without user interaction.',
        'Install Microsoft Outlook security hotfix and configure EPA / disable NTLM where Kerberos is supported.',
        'open',
        NOW() - INTERVAL '4 days', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0005-000000000004',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000007', -- DEMO-WKS-007
        'CVE-2024-30051',
        'Windows Desktop Window Manager (DWM) Core Library Elevation of Privilege',
        'high',
        7.8,
        true, -- CISA KEV
        'An elevation of privilege vulnerability in DWM allowing an attacker with standard local credentials to obtain SYSTEM privileges.',
        'Deploy Windows Cumulative Update May 2024.',
        'open',
        NOW() - INTERVAL '1 day', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0005-000000000005',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000016', -- DEMO-WKS-016
        'CVE-2023-38146',
        'Windows Theme Remote Code Execution ("ThemeBleed")',
        'high',
        8.8,
        false,
        'Specially crafted .theme file referencing a malicious .msstyles file allows arbitrary code execution upon preview.',
        'Apply Windows September 2023 Security Update.',
        'open',
        NOW() - INTERVAL '5 days', NOW(), NOW()
    )
ON CONFLICT (id) DO NOTHING;

-- 6. Seed Realistic Compliance Evaluations (CIS Benchmarks, NIST 800-53, HIPAA, PCI-DSS)
INSERT INTO compliance_evaluations (
    id, tenant_id, endpoint_id, benchmark_name, benchmark_version, rule_id, rule_title, status, severity, actual_value, expected_value, evaluated_at, created_at, updated_at
) VALUES 
    (
        '00000000-0000-0000-0006-000000000001',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000004', -- DEMO-WKS-004
        'CIS Microsoft Windows 11 Enterprise Benchmark',
        'v3.0.0',
        'CIS-18.9.15.1',
        'Ensure BitLocker Drive Encryption is Enabled on Operating System Volume',
        'failed',
        'critical',
        'ProtectionOff',
        'FullyEncrypted',
        NOW() - INTERVAL '3 hours', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0006-000000000002',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0002-000000000003', -- DEMO-SRV-003
        'CIS Microsoft Windows Server 2022 Benchmark',
        'v2.0.0',
        'CIS-18.9.4.1',
        'Ensure Microsoft Defender Antivirus Real-time Protection is Enabled',
        'failed',
        'high',
        'RealtimeProtectionDisabled',
        'Enabled',
        NOW() - INTERVAL '3 hours', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0006-000000000003',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000001', -- DEMO-WKS-001
        'NIST SP 800-53 Rev. 5',
        'r5',
        'NIST-SC-28',
        'Protection of Information at Rest (Cryptographic Mechanisms)',
        'passed',
        'high',
        'BitLocker AES-XTS-256 Enabled',
        'AES-XTS-256 or AES-CBC-256',
        NOW() - INTERVAL '1 hour', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0006-000000000004',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000001', -- DEMO-WKS-001
        'HIPAA Security Rule',
        'HITECH-2024',
        '164.312(a)(2)(iv)',
        'Automatic Logoff and Session Lock Policy (Max 15 Minutes)',
        'passed',
        'medium',
        '900 seconds',
        '<= 900 seconds',
        NOW() - INTERVAL '1 hour', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0006-000000000005',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000002', -- DEMO-WKS-002
        'PCI-DSS v4.0',
        'v4.0.1',
        'PCI-REQ-8.3.6',
        'Password Length Minimum 12 Alphanumeric and Special Characters',
        'passed',
        'high',
        '14 characters',
        '>= 12 characters',
        NOW() - INTERVAL '2 hours', NOW(), NOW()
    )
ON CONFLICT (id) DO NOTHING;

-- 7. Seed Sample Drift Events
INSERT INTO drift_events (
    id, tenant_id, host_id, drift_type, field_path, old_value, new_value, severity, acknowledged, detected_at, created_at, updated_at
) VALUES 
    (
        '00000000-0000-0000-0007-000000000001',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000004', -- DEMO-WKS-004
        'SECURITY_POSTURE_DEGRADED',
        'security_postures.bitlocker_status',
        'FullyEncrypted',
        'ProtectionOff',
        'critical',
        false,
        NOW() - INTERVAL '1 day', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0007-000000000002',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0001-000000000007', -- DEMO-WKS-007
        'UNAUTHORIZED_SOFTWARE_INSTALLED',
        'installed_software',
        '["Google Chrome", "M365"]',
        '["Google Chrome", "M365", "AnyDesk Remote Support 7.1"]',
        'high',
        false,
        NOW() - INTERVAL '2 days', NOW(), NOW()
    ),
    (
        '00000000-0000-0000-0007-000000000003',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0002-000000000003', -- DEMO-SRV-003
        'DEFENDER_REALTIME_PROTECTION_DISABLED',
        'security_postures.defender_antivirus_status',
        'ActiveAndUpdated',
        'RealtimeProtectionDisabled',
        'critical',
        false,
        NOW() - INTERVAL '12 hours', NOW(), NOW()
    )
ON CONFLICT (id) DO NOTHING;

-- 8. Seed Immutable Security Audit Log Entries
INSERT INTO security_audit_logs (
    id, tenant_id, correlation_id, timestamp, actor, action, resource_type, resource_id, status, ip_address, details
) VALUES 
    (
        '00000000-0000-0000-0008-000000000001',
        '00000000-0000-0000-0000-000000000001',
        'corr-seed-001',
        NOW() - INTERVAL '5 days',
        'admin@demo.local',
        'ROLLOUT_TIER_PROMOTED',
        'endpoint',
        '00000000-0000-0000-0001-000000000001',
        'SUCCESS',
        '192.0.2.1',
        '{"from_tier": "pilot", "to_tier": "staged", "justification": "Pilot scan completed with 0 errors across 48-hour burn-in"}'::jsonb
    ),
    (
        '00000000-0000-0000-0008-000000000002',
        '00000000-0000-0000-0000-000000000001',
        'corr-seed-002',
        NOW() - INTERVAL '3 days',
        'operator@demo.local',
        'SCAN_JOB_LAUNCHED',
        'scan_job',
        'scan-job-seed-01',
        'SUCCESS',
        '192.0.2.1',
        '{"target_cidr": "192.0.2.0/24", "profile": "full_hardware_os", "protocol": "winrm_https"}'::jsonb
    ),
    (
        '00000000-0000-0000-0008-000000000003',
        '00000000-0000-0000-0000-000000000001',
        'corr-seed-003',
        NOW() - INTERVAL '1 day',
        'admin@demo.local',
        'ALERT_TEST_DISPATCHED',
        'alert_delivery',
        'receipt-test-01',
        'DELIVERED',
        '192.0.2.1',
        '{"webhook_url": "https://hooks.slack.com/services/DEMO", "http_status": 200, "duration_ms": 142}'::jsonb
    ),
    (
        '00000000-0000-0000-0008-000000000004',
        '00000000-0000-0000-0000-000000000001',
        'corr-seed-004',
        NOW() - INTERVAL '12 hours',
        'system',
        'SNAPSHOT_RETENTION_EXECUTED',
        'host_snapshots',
        'retention-run-seed-01',
        'SUCCESS',
        '127.0.0.1',
        '{"strategy": "archive", "retention_days": 90, "snapshots_archived": 14, "storage_saved_mb": 11.25}'::jsonb
    )
ON CONFLICT (id) DO NOTHING;

-- 9. Seed Default Rollout Settings & Snapshot Retention Policy
INSERT INTO rollout_settings (id, tenant_id, active_tiers, schedule_enforce_tiers, updated_at, updated_by)
VALUES (
    '00000000-0000-0000-0009-000000000001',
    '00000000-0000-0000-0000-000000000001',
    ARRAY['pilot', 'staged'],
    true,
    NOW(),
    'admin@demo.local'
) ON CONFLICT (tenant_id) DO UPDATE SET active_tiers = EXCLUDED.active_tiers;

INSERT INTO snapshot_retention_policies (id, tenant_id, retention_days, strategy, cold_storage_path, keep_weekly_interval_days, is_enabled, last_run_status, updated_at, updated_by)
VALUES (
    '00000000-0000-0000-0009-000000000002',
    '00000000-0000-0000-0000-000000000001',
    90,
    'archive',
    'D:\archives\snapshots',
    7,
    true,
    'SUCCESS',
    NOW(),
    'admin@demo.local'
) ON CONFLICT (tenant_id) DO NOTHING;
