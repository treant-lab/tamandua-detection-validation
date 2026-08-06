import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "schemas"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validator(name: str) -> jsonschema.Draft202012Validator:
    schema = load_json(SCHEMAS / name)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_current_research_registry_accepts_pinned_and_placeholder_candidates():
    registry = load_json(
        ROOT / "apps" / "tamandua_ml" / "src" / "external_models" / "candidates.json"
    )
    validator("external_malware_model_registry_v1.schema.json").validate(registry)
    assert all(candidate["status"] == "research_hold" for candidate in registry["candidates"])
    assert any(candidate["artifact"]["sha256"] is not None for candidate in registry["candidates"])
    assert any(candidate["artifact"]["sha256"] is None for candidate in registry["candidates"])


def test_registry_rejects_promoted_placeholder_artifact():
    registry = load_json(
        ROOT / "apps" / "tamandua_ml" / "src" / "external_models" / "candidates.json"
    )
    placeholder = next(
        candidate
        for candidate in registry["candidates"]
        if candidate["artifact"]["sha256"] is None
    )
    placeholder["status"] = "shadow"

    errors = list(
        validator("external_malware_model_registry_v1.schema.json").iter_errors(registry)
    )
    assert errors


def test_prediction_evidence_rejects_benign_degraded_result():
    evidence = {
        "api_version": "tamandua.io/external-model-prediction-evidence/v1",
        "candidate_id": "candidate/one",
        "model_contract_id": "contract-v1",
        "artifact_sha256": "a" * 64,
        "runtime_lane": "embedded_onnx",
        "decision_mode": "detect_only",
        "status": "degraded",
        "verdict": "benign",
        "error_code": "runtime_unavailable",
        "latency_ms": 1.2,
        "timestamp": "2026-07-14T20:00:00Z",
    }

    errors = list(
        validator("external_model_prediction_evidence_v1.schema.json").iter_errors(evidence)
    )
    assert errors


def test_prediction_evidence_accepts_unknown_degraded_result():
    evidence = {
        "api_version": "tamandua.io/external-model-prediction-evidence/v1",
        "candidate_id": "candidate/one",
        "model_contract_id": "contract-v1",
        "artifact_sha256": "a" * 64,
        "runtime_lane": "embedded_onnx",
        "decision_mode": "detect_only",
        "status": "degraded",
        "verdict": "unknown",
        "error_code": "runtime_unavailable",
        "latency_ms": 1.2,
        "timestamp": "2026-07-14T20:00:00Z",
    }

    validator("external_model_prediction_evidence_v1.schema.json").validate(evidence)


def test_all_external_governance_schemas_are_valid_draft_2020_12():
    for name in (
        "external_malware_model_registry_v1.schema.json",
        "external_model_intake_attestation_v1.schema.json",
        "external_model_feature_contract_v1.schema.json",
        "external_model_prediction_evidence_v1.schema.json",
    ):
        validator(name)
