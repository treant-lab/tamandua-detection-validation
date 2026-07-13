from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools" / "detection_validation"
SCRIPT = TOOLS / "scripts" / "posture_inventory_compliance_readiness_gate.py"
FIXTURE = TOOLS / "fixtures" / "wazuh_posture_inventory_compliance_gap_v1.json"


def run_gate(fixture: Path):
    """In-process invocation: same exit-code/stdout contract, no process spawn."""
    return run_cli_in_process(SCRIPT, ["--fixture", str(fixture)])


def test_wazuh_posture_inventory_compliance_fixture_passes_gate() -> None:
    # Kept as a true subprocess smoke test: covers the real CLI entrypoint.
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(FIXTURE)],
        cwd=TOOLS,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["vendor_context"] == "Wazuh"
    assert summary["evidence_class"] == "synthetic_contract"
    assert summary["status_label"] == "live missing"
    assert summary["external_claim_allowed"] is False
    assert "software_inventory" in summary["capabilities"]
    assert "compliance_posture" in summary["capabilities"]
    assert "license_inventory" in summary["capabilities"]
    assert summary["future_artifact_refs"] == 6
    assert "multi_agent_fleet_freshness" in summary["future_artifact_types"]
    assert "unsupported_collector_state" in summary["future_artifact_types"]
    assert summary["license_exception_negative_cases"] == 2


def test_wazuh_posture_gate_rejects_replacement_overclaim(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["claim_boundary"] = "Tamandua is Wazuh replacement ready."
    overclaim = tmp_path / "overclaim.json"
    overclaim.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(overclaim)

    assert completed.returncode == 1
    assert "claim_boundary missing phrases" in completed.stdout
    assert "forbidden overclaims" in completed.stdout


def test_wazuh_posture_gate_requires_live_promotion_artifacts(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["promotion_requirements"] = ["live_endpoint_inventory_artifact"]
    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(incomplete)

    assert completed.returncode == 1
    assert "promotion_requirements missing" in completed.stdout
    assert "multi_agent_fleet_freshness_artifact" in completed.stdout


def test_wazuh_posture_gate_rejects_satisfied_future_artifact_ref(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["live_artifact_bridge"]["artifact_refs"][0]["satisfied"] = True
    data["live_artifact_bridge"]["artifact_refs"][0]["status"] = "attached"
    promoted = tmp_path / "promoted.json"
    promoted.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(promoted)

    assert completed.returncode == 1
    assert "status must be one of" in completed.stdout
    assert "satisfied must remain false" in completed.stdout


def test_wazuh_posture_gate_requires_freshness_threshold_order(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["live_artifact_bridge"]["freshness_thresholds"]["stale_after_seconds"] = 60
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(stale)

    assert completed.returncode == 1
    assert "max_inventory_age_seconds must be <= stale_after_seconds" in completed.stdout
    assert "max_fleet_last_seen_age_seconds must be <= stale_after_seconds" in completed.stdout


def test_wazuh_posture_gate_requires_license_exception_negative_cases(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["license_exception_negative_cases"] = []
    missing = tmp_path / "missing-license-negative.json"
    missing.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(missing)

    assert completed.returncode == 1
    assert "license_exception_negative_cases must be a non-empty list" in completed.stdout
