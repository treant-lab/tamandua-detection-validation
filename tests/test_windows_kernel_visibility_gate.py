import json
import subprocess
import sys
from pathlib import Path

from tools.detection_validation.scripts import windows_kernel_visibility_gate as gate


ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools" / "detection_validation"
SCRIPT = TOOLS / "scripts" / "windows_kernel_visibility_gate.py"
FIXTURE = TOOLS / "fixtures" / "windows_kernel_visibility_readiness_v1.json"


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_fixture_covers_required_windows_kernel_visibility_states() -> None:
    payload = gate.load_json(FIXTURE)

    assert payload["evidence_class"] == "synthetic_parity"
    assert {scenario["expected_classification"] for scenario in payload["scenarios"]} == {
        "active",
        "degraded",
        "unavailable",
    }


def test_gate_classifies_fixture_expected_outcomes() -> None:
    report = gate.build_report(FIXTURE)

    assert report["status"] == "pass"
    assert report["checked_scenarios"] == 3
    assert {
        result["snapshot_id"]: result["classification"] for result in report["results"]
    } == {
        "active-all-aggressive-windows-signals": "active",
        "degraded-etw-without-embedded-driver": "degraded",
        "unavailable-without-etw": "unavailable",
    }
    assert {
        result["snapshot_id"]: result["health_label"] for result in report["results"]
    } == {
        "active-all-aggressive-windows-signals": "windows_kernel_visibility_active",
        "degraded-etw-without-embedded-driver": "windows_kernel_visibility_degraded",
        "unavailable-without-etw": "windows_kernel_visibility_unavailable",
    }


def test_cli_returns_json_report_for_valid_fixture() -> None:
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
    assert summary["kind"] == "WindowsKernelVisibilityGate"
    assert summary["status"] == "pass"


def test_gate_rejects_mismatched_expected_classification(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "mismatch.json",
        {
            "scenarios": [
                {
                    "id": "no-etw",
                    "snapshot": {
                        "etw_enabled": False,
                        "kernel_process": False,
                        "kernel_file": False,
                        "kernel_network": False,
                        "kernel_registry": False,
                        "dns_client": False,
                        "tamper_detection": True,
                        "driver_embedded": True,
                        "wfp_available": True,
                        "signed_driver": True,
                        "admin_or_service": True,
                    },
                    "expected_classification": "degraded",
                }
            ]
        },
    )

    report = gate.build_report(fixture)

    assert report["status"] == "fail"
    assert report["results"][0]["classification"] == "unavailable"
    assert "etw_enabled is not available" in report["results"][0]["reasons"]


def test_gate_marks_etw_without_wfp_as_degraded(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "degraded.json",
        {
            "scenarios": [
                {
                    "id": "no-wfp",
                    "snapshot": {
                        "etw_enabled": True,
                        "kernel_process": True,
                        "kernel_file": True,
                        "kernel_network": True,
                        "kernel_registry": True,
                        "dns_client": True,
                        "tamper_detection": True,
                        "driver_embedded": True,
                        "wfp_available": False,
                        "signed_driver": True,
                        "admin_or_service": True,
                    },
                    "expected_classification": "degraded",
                }
            ]
        },
    )

    report = gate.build_report(fixture)

    assert report["status"] == "pass"
    result = report["results"][0]
    assert result["classification"] == "degraded"
    assert result["false_fields"] == ["wfp_available"]
