from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "benchmark_claim_maturity_gate.py"
FIXTURE = ROOT / "fixtures" / "benchmark_claim_maturity_matrix_v1.json"


def run_gate_subprocess(fixture: Path) -> subprocess.CompletedProcess[str]:
    """True subprocess smoke: covers the real CLI entrypoint (argv, exit code)."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(fixture)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_gate(fixture: Path) -> subprocess.CompletedProcess[str]:
    """In-process invocation: same exit-code/stdout contract, no process spawn."""
    return run_cli_in_process(SCRIPT, ["--fixture", str(fixture)])


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def write_fixture(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "benchmark-claim-maturity.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def gate_by_id(payload: dict, gate_id: str) -> dict:
    return next(gate for gate in payload["gates"] if gate["id"] == gate_id)


def test_benchmark_claim_maturity_matrix_passes() -> None:
    completed = run_gate_subprocess(FIXTURE)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["status_labels"] == ["live missing", "local", "synthetic"]
    assert summary["gates"]["goodware_fp"]["status"] == "local"
    assert summary["gates"]["goodware_fp"]["evidence_type"] == "smoke_local"
    assert summary["gates"]["malware_fn"]["status"] == "local"
    assert summary["gates"]["malware_fn"]["evidence_type"] == "smoke_local"
    assert summary["gates"]["mobile_shielding_synthetic_vs_physical"]["status"] == "synthetic"
    assert summary["gates"]["mobile_shielding_synthetic_vs_physical"]["evidence_type"] == "synthetic_parity"
    assert summary["gates"]["endpoint_parity"]["status"] == "live missing"
    assert summary["gates"]["endpoint_parity"]["evidence_type"] == "smoke_local"
    assert summary["vendors"] == {
        "Appdome": "synthetic",
        "Elastic": "local",
        "Guardcore": "live missing",
        "Verimatrix": "synthetic",
        "Wazuh": "local",
    }


def test_gate_rejects_goodware_fp_overclaim(tmp_path: Path) -> None:
    payload = load_fixture()
    gate = gate_by_id(payload, "goodware_fp")
    gate["external_claim_allowed"] = True
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "goodware_fp external_claim_allowed must be false" in completed.stdout


def test_gate_rejects_goodware_sample_regression(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "goodware_fp")["metrics"]["goodware_samples"] = 99
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "goodware_fp samples must meet minimum_goodware_samples" in completed.stdout


def test_gate_rejects_malware_fn_regression(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "malware_fn")["metrics"]["false_negatives"] = 1
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "malware_fn false_negatives exceed maximum_false_negatives" in completed.stdout


@pytest.mark.parametrize("invalid_count", [-1, 1.5])
def test_gate_rejects_negative_or_fractional_counts(tmp_path: Path, invalid_count: float) -> None:
    payload = load_fixture()
    gate_by_id(payload, "goodware_fp")["metrics"]["false_positives"] = invalid_count
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "goodware_fp false_positives must be a non-negative integer" in completed.stdout


@pytest.mark.parametrize("field,invalid_value", [("fpr", -0.01), ("threshold", 1.01)])
def test_gate_rejects_rates_and_thresholds_outside_unit_interval(
    tmp_path: Path, field: str, invalid_value: float
) -> None:
    payload = load_fixture()
    gate_by_id(payload, "goodware_fp")["metrics"][field] = invalid_value
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert f"goodware_fp {field} must be a number between 0 and 1" in completed.stdout


def test_gate_rejects_fpr_inconsistent_with_counts(tmp_path: Path) -> None:
    payload = load_fixture()
    metrics = gate_by_id(payload, "goodware_fp")["metrics"]
    metrics["false_positives"] = 1
    metrics["maximum_false_positives"] = 1
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "goodware_fp fpr must equal false_positives / goodware_samples" in completed.stdout


def test_gate_rejects_fnr_inconsistent_with_counts(tmp_path: Path) -> None:
    payload = load_fixture()
    metrics = gate_by_id(payload, "malware_fn")["metrics"]
    metrics["false_negatives"] = 1
    metrics["maximum_false_negatives"] = 1
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "malware_fn fnr must equal false_negatives / malware_samples" in completed.stdout


def test_gate_rejects_missing_source_artifact_after_removing_anchor(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "goodware_fp")["source_artifacts"] = ["docs/benchmarks/not-real.md#measurements"]
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "does not reference an existing repository file: docs/benchmarks/not-real.md" in completed.stdout


def test_gate_rejects_empty_source_artifact_anchor(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "goodware_fp")["source_artifacts"] = ["docs/benchmarks/ALERT_FP_EVIDENCE_AUDIT_20260706.md#"]
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "must contain a non-empty #anchor" in completed.stdout


def test_gate_rejects_missing_markdown_heading_anchor(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "goodware_fp")["source_artifacts"] = [
        "docs/benchmarks/ALERT_FP_EVIDENCE_AUDIT_20260706.md#not-a-real-section"
    ]
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "does not reference an existing markdown heading anchor: #not-a-real-section" in completed.stdout


def test_gate_rejects_mobile_shielding_promotion_without_physical_evidence(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "mobile_shielding_synthetic_vs_physical")["metrics"]["shielding_claim_allowed"] = True
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "mobile_shielding shielding_claim_allowed must be false" in completed.stdout


def test_gate_rejects_mobile_release_evidence_satisfaction_without_physical_evidence(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "mobile_shielding_synthetic_vs_physical")["promotion_evidence"][
        "satisfied_live_artifacts"
    ] = ["live_signed_app_guard_ingestion_and_duplicate_replay_rejection"]
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "mobile_shielding promotion_evidence.satisfied_live_artifacts must remain empty" in completed.stdout


def test_gate_requires_live_promotion_evidence(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "malware_fn").pop("promotion_evidence")
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "malware_fn promotion_evidence must be an object" in completed.stdout


def test_gate_rejects_strong_claim_without_required_evidence_type(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "malware_fn")["external_claim_allowed"] = True
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "malware_fn strong claim requires governed_holdout evidence" in completed.stdout


def test_gate_requires_missing_evidence_while_gate_is_immature(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "goodware_fp")["promotion_evidence"]["missing_evidence"] = []
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "goodware_fp promotion_evidence.missing_evidence must be non-empty while immature" in completed.stdout


def test_gate_requires_all_unsatisfied_promotion_artifacts_to_be_missing(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "goodware_fp")["promotion_evidence"]["missing_evidence"] = [
        "large_clean_goodware_corpus_manifest_with_hashes",
        "24h_multi_agent_fp_soak_with_agent_count_and_observation_window",
    ]
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "goodware_fp promotion_evidence.missing_evidence must include unsatisfied required artifacts" in completed.stdout
    assert "analyst_reviewed_false_positive_dataset_and_reproduction_status" in completed.stdout


def test_gate_requires_next_evidence_step_while_gate_is_immature(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "endpoint_parity")["promotion_evidence"]["next_evidence_step"] = ""
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "endpoint_parity promotion_evidence.next_evidence_step must describe the next evidence step" in completed.stdout


def test_gate_rejects_endpoint_parity_claim(tmp_path: Path) -> None:
    payload = load_fixture()
    gate_by_id(payload, "endpoint_parity")["metrics"]["parity_claim_allowed"] = True
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "endpoint_parity parity_claim_allowed must be false" in completed.stdout


def test_gate_requires_all_comparison_vendors(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["competitor_matrix"] = [
        row for row in payload["competitor_matrix"] if row["vendor"] != "Verimatrix"
    ]
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "competitor_matrix missing vendors ['Verimatrix']" in completed.stdout


def test_gate_rejects_duplicate_gate_ids(tmp_path: Path) -> None:
    payload = load_fixture()
    duplicate = dict(gate_by_id(payload, "goodware_fp"))
    duplicate["metrics"] = dict(duplicate["metrics"])
    duplicate["metrics"]["fpr"] = 0.99
    payload["gates"].insert(0, duplicate)
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "duplicate gate ids ['goodware_fp']" in completed.stdout


def test_gate_rejects_duplicate_competitor_vendors(tmp_path: Path) -> None:
    payload = load_fixture()
    duplicate = dict(payload["competitor_matrix"][0])
    payload["competitor_matrix"].append(duplicate)
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "duplicate competitor vendors ['Elastic']" in completed.stdout


def test_gate_requires_competitor_live_parity_evidence(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["competitor_matrix"][0].pop("live_parity_evidence")
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "competitor_matrix.Elastic.live_parity_evidence must be an object" in completed.stdout


def test_gate_rejects_competitor_strong_claim_without_required_evidence_type(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["competitor_matrix"][0]["external_claim_allowed"] = True
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "competitor_matrix.Elastic strong claim requires production_telemetry evidence" in completed.stdout


def test_gate_requires_competitor_missing_evidence_while_immature(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["competitor_matrix"][2]["live_parity_evidence"]["missing_evidence"] = []
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert (
        "competitor_matrix.Appdome.live_parity_evidence.missing_evidence must be non-empty while immature"
        in completed.stdout
    )


def test_gate_rejects_competitor_artifact_as_both_satisfied_and_missing(tmp_path: Path) -> None:
    payload = load_fixture()
    live_parity = payload["competitor_matrix"][0]["live_parity_evidence"]
    live_parity["satisfied_artifacts"] = ["live_detection_depth_matrix_against_elastic_analog"]
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert (
        "competitor_matrix.Elastic.live_parity_evidence.artifacts cannot be both satisfied and missing"
        in completed.stdout
    )
