from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rx_restored_page_drift_gate.py"
FIXTURE = ROOT / "fixtures" / "rx_restored_page_drift_contract_v1.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def write_fixture(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "rx-page-drift.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def run_gate(path: Path):
    return run_cli_in_process(SCRIPT, ["--fixture", str(path)])


def test_rx_page_drift_contract_cli_passes() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(FIXTURE)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["evidence_class"] == "synthetic_lab_contract"
    assert summary["execution_scope"] == "local"
    assert summary["external_claim_allowed"] is False
    assert summary["covered_decisions"] == ["alert", "degraded", "suppress", "unsupported"]
    assert summary["covered_platforms"] == ["android", "linux"]
    assert summary["covered_states"] == ["degraded", "supported", "unsupported"]


def test_gate_rejects_external_claim(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["external_claim_allowed"] = True

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "external_claim_allowed must remain false" in completed.stdout


def test_gate_rejects_unallowlisted_drift_without_finding(tmp_path: Path) -> None:
    payload = load_fixture()
    evidence = payload["scenarios"][1]["evidence"]
    evidence["findings"] = []

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "unallowlisted drift must include rx_restored_page_drift" in completed.stdout


def test_gate_rejects_allowlisted_drift_with_finding(tmp_path: Path) -> None:
    payload = load_fixture()
    evidence = payload["scenarios"][2]["evidence"]
    evidence["findings"] = [
        {
            "kind": "rx_restored_page_drift",
            "evidence": "should be suppressed by relocation allowlist",
        }
    ]

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "allowlisted drift must not emit findings" in completed.stdout


def test_gate_rejects_replay_expectation_drift(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["scenarios"][1]["expected_result"]["severity"] = "medium"

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "expected_result is not the replay result" in completed.stdout


def test_gate_rejects_paths_addresses_or_raw_bytes(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["scenarios"][1]["evidence"]["findings"][0]["evidence"] = "patched at 0x7ffdeadbeef"

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "must not contain paths or addresses" in completed.stdout

    payload = load_fixture()
    payload["scenarios"][1]["evidence"]["raw_bytes"] = "9090"

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "raw_bytes is a forbidden privacy field" in completed.stdout
