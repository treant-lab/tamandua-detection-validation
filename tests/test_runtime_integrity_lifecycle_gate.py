from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "runtime_integrity_lifecycle_gate.py"
FIXTURE = ROOT / "fixtures" / "runtime_integrity_lifecycle_contract_v1.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def write_fixture(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "runtime-integrity-lifecycle.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def run_gate(fixture: Path):
    return run_cli_in_process(SCRIPT, ["--fixture", str(fixture)])


def test_runtime_integrity_contract_cli_passes() -> None:
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
    assert summary["evidence_class"] == "synthetic_contract"
    assert summary["execution_scope"] == "local"
    assert summary["external_claim_allowed"] is False
    assert summary["covered_transitions"] == [
        "collector_degraded",
        "finding_changed",
        "finding_detected",
        "recovered",
    ]
    assert summary["duplicate_suppressions"] >= 2
    assert summary["covered_platforms"] == ["linux", "macos", "windows"]
    assert summary["covered_states"] == ["degraded", "supported", "unsupported"]


def test_gate_rejects_external_claim(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["external_claim_allowed"] = True

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "external_claim_allowed must remain false" in completed.stdout


def test_gate_rejects_lifecycle_expectation_drift(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["scenarios"][1]["observations"][0]["expected_event"]["severity"] = "high"

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "replay produced {'transition': 'finding_detected', 'severity': 'medium'}" in completed.stdout


def test_gate_rejects_missing_transition_coverage(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["scenarios"][1]["observations"] = payload["scenarios"][1]["observations"][:2]

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "scenarios do not cover transitions ['finding_changed']" in completed.stdout


def test_gate_rejects_path_or_address_evidence(tmp_path: Path) -> None:
    for evidence in ("module at C:\\temp\\probe.dll", "mapping at 0x7ffdeadbeef"):
        payload = load_fixture()
        payload["scenarios"][1]["observations"][0]["evidence"]["findings"][0][
            "evidence"
        ] = evidence

        completed = run_gate(write_fixture(tmp_path, payload))

        assert completed.returncode == 1
        assert "evidence must not contain paths or addresses" in completed.stdout


def test_gate_rejects_path_in_limitations(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["scenarios"][0]["observations"][0]["evidence"]["limitations"] = [
        "could not inspect /private/process"
    ]

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "limitations[0] must not contain paths or addresses" in completed.stdout


def test_gate_requires_explicit_unsupported_behavior(tmp_path: Path) -> None:
    payload = load_fixture()
    unsupported = payload["scenarios"][-1]["observations"][0]["evidence"]
    unsupported["limitations"] = []

    completed = run_gate(write_fixture(tmp_path, payload))

    assert completed.returncode == 1
    assert "unsupported evidence must state a limitation" in completed.stdout
