import pytest
try:
    from cis_benchmarks import evaluate_endpoint_cis
    from agentless_scanner import AgentlessScanner, ScanTarget
    from bmc_collector import collect_bmc_inventory, BMCTarget
except ImportError:
    from packages.scan_engine.python.cis_benchmarks import evaluate_endpoint_cis
    from packages.scan_engine.python.agentless_scanner import AgentlessScanner, ScanTarget
    from packages.scan_engine.python.bmc_collector import collect_bmc_inventory, BMCTarget


@pytest.mark.asyncio
async def test_agentless_scanner_execution():
    target = ScanTarget(
        ip="192.168.1.50",
        hostname="WIN11-DEV-01",
        port=5986,
        use_ssl=True,
        vault_secret_ref="sec_ref_winrm_test",
        timeout_sec=15
    )
    scanner = AgentlessScanner(target=target)
    telemetry = await scanner.execute_audit()

    assert telemetry["System"]["Hostname"] == "WIN11-DEV-01"
    assert telemetry["Hardware"]["TPM"]["Present"] is True
    assert len(telemetry["Hardware"]["Processors"]) > 0


def test_cis_benchmark_evaluation():
    sample_telemetry = {
        "Hardware": {
            "TPM": {"Present": True, "IsEnabled": True}
        },
        "Security": {
            "BitLocker": [{"DriveLetter": "C:", "ProtectionStatus": 1}],
            "Defender": {
                "RealTimeProtectionEnabled": True,
                "TamperProtectionEnabled": True
            }
        }
    }
    report = evaluate_endpoint_cis(sample_telemetry)
    assert report.total_rules >= 6
    assert report.passed_rules >= 5
    assert report.compliance_score > 80.0


def test_bmc_collector():
    target = BMCTarget(ip="10.100.1.200", vault_secret_ref="sec_ref_bmc_test")
    res = collect_bmc_inventory(target)
    assert res["Chassis"]["Manufacturer"] == "Dell Technologies"
    assert res["Chassis"]["PowerSupplyCount"] == 2
