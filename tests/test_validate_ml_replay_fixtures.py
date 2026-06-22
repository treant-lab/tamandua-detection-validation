from __future__ import annotations

import copy
import json
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

from validate_ml_contracts import (
    ContractError,
    ML5_PIPELINE_FIXTURE_SCHEMA,
    ML6_HOLDOUT_FIXTURE_SCHEMA,
    validate_contract,
    validate_ml5_pipeline_fixture,
    validate_ml6_holdout_fixture,
)


def valid_ml5_fixture() -> dict:
    return {
        "api_version": "tamandua.io/ml5-pipeline-fixture/v1",
        "kind": "ML5PipelineReplayFixture",
        "fixture_id": "ml5-prod-candidate-v1-fixture",
        "dataset_id": "ml-prod-candidate-v1",
        "created_at": "2026-06-04T19:20:00Z",
        "created_by": "tamandua-ml-fixture-builder",
        "raw_samples_in_fixture": False,
        "pipeline_trace_ref": "external://tamandua-lab/ml5/pipeline-traces/20260604",
        "model_report_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
        "ml_service_report_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-ml4.json",
        "agent_parity_report_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-ml3.json",
        "subject": {
            "name": "tamandua-full-detection-pipeline",
            "version": "workspace",
            "build_ref": "workspace",
        },
        "environment": {
            "agent_features": ["onnx", "ml-local"],
            "rust_version": "1.88.0",
            "onnxruntime_version": "1.18.0",
        },
        "samples": [
            {
                "sample_id": "malware-ml-only",
                "label": "unknown_malware",
                "expected_malicious": True,
                "deterministic_detected": False,
                "ml_detected": True,
                "latency_ms": 14.0,
                "alert_created": True,
                "duplicate_suppressed": False,
                "trace_id": "trace-1",
            },
            {
                "sample_id": "malware-deterministic-only",
                "label": "trojan",
                "expected_malicious": True,
                "deterministic_detected": True,
                "ml_detected": False,
                "latency_ms": 12.0,
                "alert_created": True,
                "duplicate_suppressed": False,
                "trace_id": "trace-2",
            },
            {
                "sample_id": "malware-assisted",
                "label": "ransomware",
                "expected_malicious": True,
                "deterministic_detected": True,
                "ml_detected": True,
                "latency_ms": 18.0,
                "alert_created": True,
                "duplicate_suppressed": True,
                "trace_id": "trace-3",
            },
            {
                "sample_id": "goodware-clean",
                "label": "goodware",
                "expected_malicious": False,
                "deterministic_detected": False,
                "ml_detected": False,
                "latency_ms": 9.0,
                "alert_created": False,
                "duplicate_suppressed": False,
                "trace_id": "trace-4",
            },
        ],
        "claim_boundary": "ML-5 replay fixture only. Does not copy raw malware samples and only supports benchmark replay claims.",
    }


def valid_ml6_fixture() -> dict:
    return {
        "api_version": "tamandua.io/ml6-holdout-prediction-fixture/v1",
        "kind": "ML6HoldoutPredictionFixture",
        "fixture_id": "ml6-prod-candidate-v1-holdout",
        "dataset_id": "ml-prod-candidate-v1",
        "created_at": "2026-06-04T19:20:00Z",
        "created_by": "tamandua-ml-fixture-builder",
        "training_cutoff": "2026-06-01T00:00:00Z",
        "raw_samples_in_fixture": False,
        "model_report_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
        "subject": {
            "name": "tamandua-ml-holdout-robustness",
            "version": "workspace",
            "build_ref": "workspace",
        },
        "environment": {
            "agent_features": ["onnx", "ml-local"],
            "rust_version": "1.88.0",
            "onnxruntime_version": "1.18.0",
        },
        "holdout_sources": [
            {
                "source_id": "malwarebazaar-post-cutoff",
                "source_type": "malwarebazaar",
                "role": "holdout",
                "used_in_training": False,
                "claim_boundary": "Post-cutoff MalwareBazaar metadata and predictions only.",
            },
            {
                "source_id": "vx-underground-inthewild",
                "source_type": "vx_underground",
                "role": "holdout_candidate",
                "used_in_training": False,
                "claim_boundary": "VX metadata and predictions only; samples are not used in training.",
            },
        ],
        "samples": [
            {
                "sample_id": "mb-2026-06-a",
                "label": "unknown_malware",
                "expected_malicious": True,
                "source": "malwarebazaar-post-cutoff",
                "collection_month": "2026-06",
                "predicted_malicious": True,
                "latency_ms": 8.0,
            },
            {
                "sample_id": "vx-2026-07-a",
                "label": "trojan",
                "expected_malicious": True,
                "source": "vx-underground-inthewild",
                "collection_month": "2026-07",
                "predicted_malicious": False,
                "latency_ms": 10.0,
            },
            {
                "sample_id": "gw-2026-06-a",
                "label": "goodware",
                "expected_malicious": False,
                "source": "malwarebazaar-post-cutoff",
                "collection_month": "2026-06",
                "predicted_malicious": False,
                "latency_ms": 6.0,
            },
            {
                "sample_id": "gw-2026-07-a",
                "label": "benign",
                "expected_malicious": False,
                "source": "vx-underground-inthewild",
                "collection_month": "2026-07",
                "predicted_malicious": False,
                "latency_ms": 7.0,
            },
        ],
        "claim_boundary": "ML-6 holdout prediction fixture only. Does not copy raw samples or support zero-day claims.",
    }


def test_validate_ml5_pipeline_fixture_accepts_valid_contract() -> None:
    validate_ml5_pipeline_fixture(valid_ml5_fixture(), Path("memory://ml5-fixture.json"))


def test_validate_ml5_pipeline_fixture_accepts_jsonschema_path(tmp_path: Path) -> None:
    fixture_path = tmp_path / "ml5-fixture.json"
    fixture_path.write_text(json.dumps(valid_ml5_fixture()), encoding="utf-8")

    mode = validate_contract(fixture_path, ML5_PIPELINE_FIXTURE_SCHEMA, validate_ml5_pipeline_fixture)

    assert mode == "jsonschema+built-in"


def test_validate_ml5_pipeline_fixture_rejects_benign_expected_malicious() -> None:
    payload = copy.deepcopy(valid_ml5_fixture())
    payload["samples"][3]["expected_malicious"] = True

    try:
        validate_ml5_pipeline_fixture(payload, Path("memory://ml5-fixture.json"))
    except ContractError as exc:
        assert "benign label" in str(exc)
    else:
        raise AssertionError("expected benign sample marked malicious to fail")


def test_validate_ml6_holdout_fixture_accepts_valid_contract() -> None:
    validate_ml6_holdout_fixture(valid_ml6_fixture(), Path("memory://ml6-fixture.json"))


def test_validate_ml6_holdout_fixture_accepts_jsonschema_path(tmp_path: Path) -> None:
    fixture_path = tmp_path / "ml6-fixture.json"
    fixture_path.write_text(json.dumps(valid_ml6_fixture()), encoding="utf-8")

    mode = validate_contract(fixture_path, ML6_HOLDOUT_FIXTURE_SCHEMA, validate_ml6_holdout_fixture)

    assert mode == "jsonschema+built-in"


def test_validate_ml6_holdout_fixture_rejects_vx_training_use() -> None:
    payload = copy.deepcopy(valid_ml6_fixture())
    payload["holdout_sources"][1]["used_in_training"] = True

    try:
        validate_ml6_holdout_fixture(payload, Path("memory://ml6-fixture.json"))
    except ContractError as exc:
        assert "used_in_training" in str(exc)
    else:
        raise AssertionError("expected VX used_in_training=true to fail")


def test_validate_ml6_holdout_fixture_rejects_unknown_source() -> None:
    payload = copy.deepcopy(valid_ml6_fixture())
    payload["samples"][0]["source"] = "unknown-source"

    try:
        validate_ml6_holdout_fixture(payload, Path("memory://ml6-fixture.json"))
    except ContractError as exc:
        assert "unknown holdout source" in str(exc)
    else:
        raise AssertionError("expected unknown holdout source to fail")
