from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import ContractError, validate_benchmark_report  # noqa: E402


def valid_ml2_report() -> dict:
    return {
        "api_version": "tamandua.io/ml-benchmark-report/v1",
        "kind": "MLBenchmarkReport",
        "metadata": {
            "report_id": "test_ml2_report",
            "created_at": "2026-06-04T00:00:00Z",
            "created_by": "tamandua-ml-test",
            "git_commit": "workspace",
        },
        "lane": "ML-2",
        "subject": {
            "type": "onnx_model",
            "name": "malware-smell-onnx-parity",
            "version": "test",
        },
        "dataset": {
            "dataset_id": "test-dataset",
            "manifest_ref": "memory://dataset",
            "sample_counts": {"total": 2, "malware": 1, "goodware": 1, "unknown": 0},
        },
        "environment": {
            "os": "test",
            "python_version": "3.10",
        },
        "metrics": {
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "false_positive_rate": None,
            "false_negative_rate": None,
            "roc_auc": None,
            "verdict_agreement": 1.0,
            "confidence_delta_p95": None,
            "latency_ms_p50": None,
            "latency_ms_p95": None,
            "latency_ms_p99": None,
            "throughput_per_second": None,
            "memory_mb_peak": None,
            "ml_contribution": {
                "ml_only": 0,
                "ml_assisted": 0,
                "deterministic_only": 0,
                "missed": 0,
            },
        },
        "quality_gate": {
            "status": "pass",
            "checks": [{"name": "verdict_agreement", "status": "pass"}],
        },
        "claim_boundary": "ML-2 test report only. Does not claim production detection.",
    }


def test_validate_benchmark_report_accepts_valid_pass_report() -> None:
    validate_benchmark_report(valid_ml2_report(), Path("memory://ml2-report.json"))


def test_validate_benchmark_report_rejects_inflated_sample_total() -> None:
    payload = copy.deepcopy(valid_ml2_report())
    payload["dataset"]["sample_counts"]["total"] = 3

    try:
        validate_benchmark_report(payload, Path("memory://ml2-report.json"))
    except ContractError as exc:
        assert "must equal malware, goodware, and unknown counts" in str(exc)
    else:
        raise AssertionError("expected inflated sample total to fail")


def test_validate_benchmark_report_rejects_pass_without_samples_for_non_ml0_lane() -> None:
    payload = copy.deepcopy(valid_ml2_report())
    payload["dataset"]["sample_counts"] = {"total": 0, "malware": 0, "goodware": 0, "unknown": 0}

    try:
        validate_benchmark_report(payload, Path("memory://ml2-report.json"))
    except ContractError as exc:
        assert "must evaluate at least one sample" in str(exc)
    else:
        raise AssertionError("expected pass report without samples to fail")


def test_validate_benchmark_report_rejects_pass_without_substantive_metrics_for_non_ml0_lane() -> None:
    payload = copy.deepcopy(valid_ml2_report())
    for name in [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "roc_auc",
        "verdict_agreement",
        "confidence_delta_p95",
        "latency_ms_p95",
        "throughput_per_second",
    ]:
        payload["metrics"][name] = None

    try:
        validate_benchmark_report(payload, Path("memory://ml2-report.json"))
    except ContractError as exc:
        assert "must record at least one substantive metric" in str(exc)
    else:
        raise AssertionError("expected pass report without substantive metrics to fail")


def test_validate_benchmark_report_allows_ml0_contract_pass_without_substantive_metric() -> None:
    payload = copy.deepcopy(valid_ml2_report())
    payload["lane"] = "ML-0"
    payload["subject"]["type"] = "training_pipeline"
    for name in [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "roc_auc",
        "verdict_agreement",
        "confidence_delta_p95",
        "latency_ms_p95",
        "throughput_per_second",
    ]:
        payload["metrics"][name] = None

    validate_benchmark_report(payload, Path("memory://ml0-report.json"))


def test_validate_benchmark_report_accepts_local_artifact_sha(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"tamandua-ml-artifact")
    payload = copy.deepcopy(valid_ml2_report())
    payload["artifacts"] = [
        {
            "name": "artifact",
            "path": str(artifact),
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest().upper(),
        }
    ]

    validate_benchmark_report(payload, tmp_path / "ml2-report.json")


def test_validate_benchmark_report_rejects_missing_local_artifact_sha(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_ml2_report())
    payload["artifacts"] = [
        {
            "name": "artifact",
            "path": str(tmp_path / "missing.bin"),
            "sha256": "a" * 64,
        }
    ]

    try:
        validate_benchmark_report(payload, tmp_path / "ml2-report.json")
    except ContractError as exc:
        assert "artifact file does not exist" in str(exc)
    else:
        raise AssertionError("expected missing sha artifact file to fail")


def test_validate_benchmark_report_rejects_uri_artifact_with_sha() -> None:
    payload = copy.deepcopy(valid_ml2_report())
    payload["artifacts"] = [
        {
            "name": "artifact",
            "path": "synthetic://tamandua/artifact",
            "sha256": "a" * 64,
        }
    ]

    try:
        validate_benchmark_report(payload, Path("memory://ml2-report.json"))
    except ContractError as exc:
        assert "must use a local filesystem path" in str(exc)
    else:
        raise AssertionError("expected sha artifact URI to fail")


def test_validate_benchmark_report_rejects_artifact_sha_mismatch(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"tamandua-ml-artifact")
    payload = copy.deepcopy(valid_ml2_report())
    payload["artifacts"] = [
        {
            "name": "artifact",
            "path": str(artifact),
            "sha256": "a" * 64,
        }
    ]

    try:
        validate_benchmark_report(payload, tmp_path / "ml2-report.json")
    except ContractError as exc:
        assert "does not match artifact file" in str(exc)
    else:
        raise AssertionError("expected sha mismatch to fail")
