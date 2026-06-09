from __future__ import annotations

import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    ML5_REPLAY_OUTCOMES_SCHEMA,
    ML6_HOLDOUT_PREDICTION_OUTCOMES_SCHEMA,
    validate_contract,
    validate_ml5_replay_outcomes,
    validate_ml6_holdout_prediction_outcomes,
)


def valid_ml5() -> dict:
    return {
        "api_version": "tamandua.io/ml5-replay-outcomes/v1",
        "kind": "ML5ReplayOutcomes",
        "dataset_id": "ml-prod-candidate-v1",
        "produced_at": "2026-06-06T00:00:00Z",
        "created_by": "test",
        "raw_samples_in_artifact": False,
        "pipeline_trace_ref": "external://tamandua-lab/ml5/replay-trace/20260606",
        "model_report_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
        "ml_service_report_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-ml4-api.json",
        "agent_parity_report_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-ml3-agent-parity.json",
        "samples": [
            {
                "sample_id": "mal-1",
                "label": "malware",
                "expected_malicious": True,
                "deterministic_detected": False,
                "ml_detected": True,
            },
            {
                "sample_id": "ben-1",
                "label": "benign",
                "expected_malicious": False,
                "deterministic_detected": False,
                "ml_detected": False,
            },
        ],
        "claim_boundary": "Metadata-only replay outcomes; raw samples are excluded.",
    }


def valid_ml6() -> dict:
    return {
        "api_version": "tamandua.io/ml6-holdout-prediction-outcomes/v1",
        "kind": "ML6HoldoutPredictionOutcomes",
        "dataset_id": "ml-prod-candidate-v1",
        "produced_at": "2026-06-06T00:00:00Z",
        "created_by": "test",
        "training_cutoff": "2026-06-01T00:00:00Z",
        "raw_samples_in_artifact": False,
        "model_report_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
        "holdout_sources": [
            {
                "source_id": "vx-inthewild-2026-06",
                "source_type": "vx_underground",
                "role": "holdout_candidate",
                "used_in_training": False,
                "claim_boundary": "Metadata-only holdout source; raw samples are excluded.",
            },
            {
                "source_id": "goodware-system-2026-06",
                "source_type": "goodware_system",
                "role": "holdout",
                "used_in_training": False,
                "claim_boundary": "Metadata-only holdout source; raw samples are excluded.",
            },
        ],
        "samples": [
            {
                "sample_id": "mal-1",
                "label": "malware",
                "expected_malicious": True,
                "source": "vx-inthewild-2026-06",
                "collection_month": "2026-06",
                "predicted_malicious": True,
            },
            {
                "sample_id": "ben-1",
                "label": "benign",
                "expected_malicious": False,
                "source": "goodware-system-2026-06",
                "collection_month": "2026-06",
                "predicted_malicious": False,
            },
        ],
        "claim_boundary": "Metadata-only holdout prediction outcomes; raw samples are excluded.",
    }


def test_validate_ml5_replay_outcomes_accepts_schema_and_builtin(tmp_path: Path) -> None:
    path = tmp_path / "ml5.json"
    path.write_text(json.dumps(valid_ml5()), encoding="utf-8")

    mode = validate_contract(path, ML5_REPLAY_OUTCOMES_SCHEMA, validate_ml5_replay_outcomes)

    assert mode == "jsonschema+built-in"


def test_validate_ml5_replay_outcomes_rejects_raw_fields() -> None:
    payload = valid_ml5()
    payload["samples"][0]["raw_bytes"] = "00"

    with pytest.raises(ContractError, match="schema validation failed|raw sample fields"):
        validate_ml5_replay_outcomes(payload, Path("memory://ml5.json"))


def test_validate_ml5_replay_outcomes_rejects_placeholder_refs() -> None:
    payload = valid_ml5()
    payload["pipeline_trace_ref"] = "replace-with-platform-trace"

    with pytest.raises(ContractError, match="non-placeholder evidence reference"):
        validate_ml5_replay_outcomes(payload, Path("memory://ml5.json"))


def test_validate_ml5_replay_outcomes_rejects_placeholder_sample_ids() -> None:
    payload = valid_ml5()
    payload["samples"][0]["sample_id"] = "replace-with-malware-sample"

    with pytest.raises(ContractError, match="placeholders are forbidden"):
        validate_ml5_replay_outcomes(payload, Path("memory://ml5.json"))


def test_validate_ml6_holdout_prediction_outcomes_accepts_schema_and_builtin(tmp_path: Path) -> None:
    path = tmp_path / "ml6.json"
    path.write_text(json.dumps(valid_ml6()), encoding="utf-8")

    mode = validate_contract(path, ML6_HOLDOUT_PREDICTION_OUTCOMES_SCHEMA, validate_ml6_holdout_prediction_outcomes)

    assert mode == "jsonschema+built-in"


def test_validate_ml6_holdout_prediction_outcomes_rejects_unknown_sample_source() -> None:
    payload = valid_ml6()
    payload["samples"][0]["source"] = "unknown-source"

    with pytest.raises(ContractError, match="unknown holdout source"):
        validate_ml6_holdout_prediction_outcomes(payload, Path("memory://ml6.json"))


def test_validate_ml6_holdout_prediction_outcomes_rejects_placeholder_sources() -> None:
    payload = valid_ml6()
    payload["holdout_sources"][0]["source_id"] = "vx-inthewild-replace-with-release-id"
    payload["samples"][0]["source"] = "vx-inthewild-replace-with-release-id"

    with pytest.raises(ContractError, match="placeholders are forbidden"):
        validate_ml6_holdout_prediction_outcomes(payload, Path("memory://ml6.json"))
