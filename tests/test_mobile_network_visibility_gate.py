from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from inprocess_gate_cli import run_cli_in_process
from tools.detection_validation.scripts import mobile_network_visibility_gate as gate


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "mobile_network_visibility_gate.py"
FIXTURE = ROOT / "fixtures" / "mobile_network_visibility_readiness_v1.json"


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def run_gate_subprocess(fixture: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(fixture)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_gate(fixture: Path) -> subprocess.CompletedProcess[str]:
    return run_cli_in_process(SCRIPT, [str(fixture)])


def test_mobile_network_visibility_fixture_passes_gate() -> None:
    completed = run_gate_subprocess(FIXTURE)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["status"] == "pass"
    assert summary["checked_scenarios"] == 4
    assert summary["mode_counts"] == {
        "android_vpnservice": 1,
        "app_guard_only": 2,
        "ios_network_extension": 1,
        "mdm_managed": 0,
        "sdk_embedded": 0,
    }
    assert summary["required_fields"] == sorted(gate.REQUIRED_FIELDS)
    assert "App Guard and embedded SDK modes are application-scoped fallbacks" in summary["claim_boundary"]


def test_fixture_covers_required_android_ios_scenarios() -> None:
    payload = gate.load_json(FIXTURE)
    categories = {scenario["category"] for scenario in payload["scenarios"]}

    assert categories == {
        "android_vpnservice_active",
        "android_app_only_degraded",
        "ios_network_extension_active",
        "ios_app_only_degraded",
    }


def test_gate_classifies_expected_modes_and_visibility() -> None:
    report = gate.build_report(FIXTURE)

    assert {
        result["scenario_id"]: (result["mode"], result["visibility"])
        for result in report["results"]
    } == {
        "android-vpnservice-active": ("android_vpnservice", "phone_wide_metadata"),
        "android-app-only-degraded": ("app_guard_only", "degraded_app_scope"),
        "ios-network-extension-active": ("ios_network_extension", "phone_wide_metadata"),
        "ios-app-only-degraded": ("app_guard_only", "degraded_app_scope"),
    }


def test_gate_rejects_missing_required_field(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    del data["scenarios"][0]["capabilities"]["packet_visibility"]
    fixture = write_json(tmp_path / "missing-field.json", data)

    completed = run_gate(fixture)

    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    result = summary["results"][0]
    assert result["status"] == "fail"
    assert result["missing_fields"] == ["packet_visibility"]
    assert "minimum field contract is incomplete" in result["reasons"]


def test_gate_rejects_android_vpn_without_user_consent(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["scenarios"][0]["capabilities"]["user_consent_required"] = False
    fixture = write_json(tmp_path / "android-vpn-no-consent.json", data)

    completed = run_gate(fixture)

    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    assert "explicit user VPN consent" in " ".join(summary["results"][0]["reasons"])


def test_gate_rejects_app_guard_claiming_phone_wide_network_visibility(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["scenarios"][1]["capabilities"]["flow_visibility"] = "flow_metadata"
    fixture = write_json(tmp_path / "app-only-flow-claim.json", data)

    completed = run_gate(fixture)

    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    assert "phone-wide network visibility" in " ".join(summary["results"][1]["reasons"])


def test_gate_supports_mdm_managed_mode(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "mdm-managed.json",
        {
            "scenarios": [
                {
                    "id": "ios-mdm-per-app-vpn",
                    "capabilities": {
                        "platform": "ios",
                        "app_installed": True,
                        "sdk_embedded": False,
                        "vpnservice_enabled": False,
                        "network_extension_entitled": False,
                        "mdm_profile_installed": True,
                        "per_app_vpn": True,
                        "dns_visibility": "per_app_vpn_metadata",
                        "flow_visibility": "per_app_vpn_metadata",
                        "app_process_attribution": "mdm_per_app_vpn",
                        "packet_visibility": "metadata_only",
                        "user_consent_required": False,
                    },
                    "expected_mode": "mdm_managed",
                }
            ]
        },
    )

    report = gate.build_report(fixture)

    assert report["status"] == "pass"
    assert report["results"][0]["mode"] == "mdm_managed"
    assert report["mode_counts"]["mdm_managed"] == 1
