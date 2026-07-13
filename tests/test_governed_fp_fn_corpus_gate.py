from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
SCRIPT = ROOT / "scripts" / "governed_fp_fn_corpus_gate.py"
FIXTURE = ROOT / "fixtures" / "governed_fp_fn_corpus_gate_v1.json"
SCHEMA = REPO_ROOT / "schemas" / "governed_fp_fn_corpus_gate_v1.schema.json"


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
    path = tmp_path / "governed-fp-fn-corpus-gate.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_governed_fp_fn_corpus_gate_passes_hold_fixture() -> None:
    completed = run_gate_subprocess(FIXTURE)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["gate_status"] == "hold"
    assert summary["evidence_class"] == "bootstrap_local"
    assert summary["external_claim_allowed"] is False
    assert summary["goodware_samples"] == 100
    assert summary["malware_samples"] == 100
    assert summary["fpr"] == 0.0
    assert summary["fnr"] == 0.0
    assert "malware detection quality" in summary["blocked_claims"]


def test_governed_fp_fn_corpus_fixture_matches_schema() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    errors = sorted(validator.iter_errors(load_fixture()), key=lambda error: list(error.path))

    assert errors == []


def test_gate_rejects_external_claim_promotion(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["external_claim_allowed"] = True
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "external_claim_allowed must be false" in completed.stdout


def test_gate_rejects_bootstrap_status_promotion(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["gate_status"] = "not_claim_ready"
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "non-governed evidence_class must keep gate_status hold" in completed.stdout


def test_gate_rejects_missing_lineage_manifest(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["corpus_lineage"]["malware"]["manifest_refs"] = []
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "corpus_lineage.malware.manifest_refs must be non-empty" in completed.stdout


def test_gate_rejects_missing_dataset_provenance(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["corpus_lineage"]["goodware"]["provenance_status"] = "governed_recorded"
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "corpus_lineage.goodware.provenance_status must remain" in completed.stdout


def test_gate_rejects_label_review_promotion_without_governed_artifact(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["label_review"]["malware"]["review_complete"] = True
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "label_review.malware.review_complete must be false" in completed.stdout


def test_gate_rejects_sample_count_regression(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["sample_accounting"]["goodware_samples"] = 99
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "sample_accounting.goodware_samples must meet minimum_goodware_samples" in completed.stdout


def test_gate_rejects_fractional_sample_count_floor(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["sample_accounting"]["minimum_goodware_samples"] = 99.5
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "sample_accounting.minimum_goodware_samples must be a non-negative integer" in completed.stdout


def test_gate_requires_public_metric_sample_floor(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["sample_accounting"]["promotion_minimum_malware_samples"] = 999
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "promotion_minimum_malware_samples must be a non-negative integer at least 1000" in completed.stdout


def test_gate_rejects_fractional_public_metric_sample_floor(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["sample_accounting"]["promotion_minimum_goodware_samples"] = 1000.5
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "promotion_minimum_goodware_samples must be a non-negative integer at least 1000" in completed.stdout


def test_gate_rejects_dedupe_mismatch(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["dedupe"]["unique_goodware_samples"] = 99
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "dedupe.unique_goodware_samples must match" in completed.stdout


def test_gate_rejects_threshold_orientation_regression(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["thresholds"]["score_orientation"] = "normal"
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "thresholds.score_orientation must preserve" in completed.stdout


def test_gate_rejects_threshold_mutability(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["thresholds"]["mutation_policy"] = "editable"
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "thresholds.mutation_policy must be immutable_requires_new_gate_artifact" in completed.stdout


def test_gate_rejects_threshold_digest_mismatch(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["thresholds"]["threshold_record_sha256"] = "0" * 64
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "thresholds.threshold_record_sha256 must match" in completed.stdout


def test_gate_rejects_fpr_arithmetic_mismatch(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["outcomes"]["false_positives"] = 1
    payload["outcomes"]["maximum_false_positives"] = 1
    payload["outcomes"]["maximum_fpr"] = 0.01
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "outcomes.fpr must equal false_positives / goodware_samples" in completed.stdout


def test_gate_rejects_confidence_interval_claim_placeholder_promotion(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["confidence_intervals"]["fpr"]["lower"] = 0.0
    payload["confidence_intervals"]["fpr"]["upper"] = 0.01
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "confidence_intervals.fpr bounds must remain null" in completed.stdout


def test_gate_rejects_retained_critical_regression(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["retained_critical_scenarios"]["scenario_count"] = 21
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "retained_critical_scenarios.scenario_count must meet" in completed.stdout


def test_gate_requires_blocked_public_claims(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["claim_promotion_requirements"]["blocked_claims"].remove("vendor parity")
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "claim_promotion_requirements.blocked_claims missing ['vendor parity']" in completed.stdout


def test_gate_rejects_unverified_governed_artifact_satisfaction(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["claim_promotion_requirements"]["satisfied_artifacts"].append(
        "governed_malware_holdout_manifest_with_source_lineage_and_label_review"
    )
    path = write_fixture(tmp_path, payload)

    completed = run_gate(path)

    assert completed.returncode == 1
    assert "must not satisfy governed promotion artifacts without live verification" in completed.stdout
