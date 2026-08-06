import json
import subprocess
import sys
from pathlib import Path

from tools.detection_validation.scripts import macos_platform_visibility_gate as gate


ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools" / "detection_validation"
SCRIPT = TOOLS / "scripts" / "macos_platform_visibility_gate.py"
FIXTURE = TOOLS / "fixtures" / "macos_platform_visibility_readiness_v1.json"


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_fixture_maps_required_macos_visibility_scenarios() -> None:
    payload = gate.load_json(FIXTURE)
    categories = {scenario["category"] for scenario in payload["scenarios"]}

    assert categories == {
        "active_enterprise",
        "degraded_app_only",
        "unavailable_no_entitlement",
    }


def test_gate_classifies_fixture_expected_outcomes() -> None:
    report = gate.build_report(FIXTURE)

    assert report["status"] == "pass"
    assert report["checked_scenarios"] == 3
    assert {
        result["scenario_id"]: result["classification"] for result in report["results"]
    } == {
        "enterprise-active-es-ne": "active",
        "app-only-degraded-bpf-dns": "degraded",
        "no-entitlement-unavailable": "unavailable",
    }


def test_gate_rejects_missing_minimum_field_contract(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "missing-minimum.json",
        {
            "scenarios": [
                {
                    "id": "missing-network-extension-field",
                    "category": "contract_gap",
                    "readiness": {
                        "endpoint_security_entitled": True,
                        "sysext_installed": True,
                        "tcc_permissions": {"accessibility": True},
                        "bpf_access": True,
                        "dns_log_visibility": True,
                        "full_disk_access": True,
                    },
                    "expected_classification": "active",
                }
            ]
        },
    )

    report = gate.build_report(fixture)

    assert report["status"] == "fail"
    result = report["results"][0]
    assert result["classification"] == "active"
    assert result["missing_minimum_fields"] == ["network_extension_entitled"]


def test_gate_keeps_sysext_without_entitlement_degraded_not_active(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "sysext-no-es-entitlement.json",
        {
            "scenarios": [
                {
                    "id": "sysext-without-es-entitlement",
                    "category": "misconfigured_enterprise",
                    "readiness": {
                        "endpoint_security_entitled": False,
                        "sysext_installed": True,
                        "tcc_permissions": {
                            "accessibility": True,
                            "input_monitoring": True,
                            "automation": True,
                        },
                        "bpf_access": False,
                        "network_extension_entitled": True,
                        "dns_log_visibility": False,
                        "full_disk_access": True,
                    },
                    "expected_classification": "active",
                }
            ]
        },
    )

    report = gate.build_report(fixture)

    assert report["status"] == "fail"
    result = report["results"][0]
    assert result["classification"] == "degraded"
    assert "endpoint_security_not_fully_ready" in result["degraded_capabilities"]


def test_cli_outputs_json_and_returns_zero_for_fixture() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(FIXTURE)],
        cwd=TOOLS,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["kind"] == "MacosPlatformVisibilityGate"
    assert summary["status"] == "pass"
