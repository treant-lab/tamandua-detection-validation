from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(os.environ.get("TAMANDUA_ROOT", ROOT.parents[1]))
SCRIPT = ROOT / "scripts" / "validate_model_package_scanner_gate.py"
EXAMPLE = REPO_ROOT / "docs" / "benchmarks" / "model_package_scanner_smoke.example.json"


def run_gate(*args: object) -> subprocess.CompletedProcess[str]:
    return run_cli_in_process(SCRIPT, [str(arg) for arg in args])


def write_json(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "model-package-scanner-results.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def smoke_payload() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def test_model_package_scanner_gate_reports_smoke_outcomes_and_blocks_claims() -> None:
    completed = run_gate("--input", EXAMPLE)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["api_version"] == "tamandua.io/model-package-scanner-gate/v1"
    assert report["kind"] == "ModelPackageScannerGateReport"
    assert report["gate_status"] == "blocked_for_production_claim"
    assert report["external_claim_allowed"] is False
    assert report["local_gate_runnable"] is True
    assert report["claim_boundary"] == "model package scanner smoke/regression only"
    assert report["evidence"]["class"] == "smoke"
    assert report["scanner"]["enforcement"] == "decision_only"
    assert report["sample_accounting"]["total_samples"] == 5
    assert report["sample_accounting"]["malicious"] == 4
    assert report["sample_accounting"]["benign"] == 1
    assert report["fixture_coverage"]["missing"] == []
    assert set(report["fixture_coverage"]["present"]) == {
        "benign_package",
        "persistence",
        "remote_code",
        "reverse_shell",
        "sidecar_injection",
    }
    assert report["outcomes"]["tp"] == 4
    assert report["outcomes"]["tn"] == 1
    assert report["outcomes"]["fp"] == 0
    assert report["outcomes"]["fn"] == 0
    assert "evidence_class_below_governed_holdout" in report["promotion_blockers"]
    assert "overall_benign_sample_count_below_300" in report["promotion_blockers"]
    assert "overall_malicious_sample_count_below_150" in report["promotion_blockers"]
    assert any("validate_model_package_scanner_gate.py" in command for command in report["reproducibility"]["commands"])


def test_model_package_scanner_gate_can_write_report(tmp_path: Path) -> None:
    output = tmp_path / "model-package-scanner-gate-report.json"

    completed = run_gate("--input", EXAMPLE, "--output", output)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(completed.stdout)


def test_model_package_scanner_fail_on_blocked_returns_distinct_status() -> None:
    completed = run_gate("--input", EXAMPLE, "--fail-on-blocked")

    assert completed.returncode == 2
    assert json.loads(completed.stdout)["gate_status"] == "blocked_for_production_claim"


def test_model_package_scanner_gate_detects_false_negative(tmp_path: Path) -> None:
    payload = smoke_payload()
    payload["samples"][1]["verdict"] = "clean"
    path = write_json(tmp_path, payload)

    completed = run_gate("--input", path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["outcomes"]["fn"] == 1
    assert "overall_fnr_above_5_percent" in report["promotion_blockers"]
    reverse_shell = next(item for item in report["sample_outcomes"] if item["fixture_class"] == "reverse_shell")
    assert reverse_shell["outcome"] == "fn"


def test_model_package_scanner_gate_detects_false_positive(tmp_path: Path) -> None:
    payload = smoke_payload()
    payload["samples"][0]["verdict"] = "malicious"
    path = write_json(tmp_path, payload)

    completed = run_gate("--input", path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["outcomes"]["fp"] == 1
    assert "overall_fpr_above_2_percent" in report["promotion_blockers"]
    benign = next(item for item in report["sample_outcomes"] if item["fixture_class"] == "benign_package")
    assert benign["outcome"] == "fp"


def test_model_package_scanner_gate_rejects_missing_required_fixture(tmp_path: Path) -> None:
    payload = smoke_payload()
    payload["samples"] = [sample for sample in payload["samples"] if sample["fixture_class"] != "remote_code"]
    path = write_json(tmp_path, payload)

    completed = run_gate("--input", path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["fixture_coverage"]["missing"] == ["remote_code"]
    assert "required_fixture_classes_missing" in report["promotion_blockers"]


def test_model_package_scanner_gate_rejects_invalid_evidence_class(tmp_path: Path) -> None:
    payload = smoke_payload()
    payload["evidence_class"] = "marketing"
    path = write_json(tmp_path, payload)

    completed = run_gate("--input", path)

    assert completed.returncode == 1
    assert "evidence_class must be one of" in completed.stdout


def test_model_package_scanner_gate_can_be_production_ready_when_gates_are_met(tmp_path: Path) -> None:
    base = smoke_payload()["samples"]
    samples = []
    for index in range(300):
        sample = dict(base[0])
        sample["sample_id"] = f"benign-package-{index}"
        samples.append(sample)
    malicious_templates = [sample for sample in base if sample["label"] == "malicious"]
    for index in range(152):
        sample = dict(malicious_templates[index % len(malicious_templates)])
        sample["sample_id"] = f"malicious-package-{index}"
        samples.append(sample)
    path = write_json(
        tmp_path,
        {
            "evidence_class": "governed_holdout",
            "enforcement": "decision_only",
            "scanner": "model_package_scanner",
            "samples": samples,
        },
    )

    completed = run_gate("--input", path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["gate_status"] == "production_claim_ready"
    assert report["external_claim_allowed"] is True
    assert report["promotion_blockers"] == []
