import json
import math
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest


LOCAL_ROOT = Path(__file__).resolve().parents[1]
if (
    (LOCAL_ROOT / "scripts").exists()
    and (LOCAL_ROOT / "fixtures").exists()
    and (LOCAL_ROOT / "schemas").exists()
):
    ROOT = LOCAL_ROOT
    SCRIPTS = ROOT / "scripts"
    FIXTURES = ROOT / "fixtures"
else:
    ROOT = Path(os.environ.get("TAMANDUA_ROOT", Path(__file__).resolve().parents[3]))
    SCRIPTS = ROOT / "tools" / "detection_validation" / "scripts"
    FIXTURES = ROOT / "tools" / "detection_validation" / "fixtures"
SCHEMA = ROOT / "schemas" / "detector_observation_consensus_v1.schema.json"
VALID = FIXTURES / "detector_observation_consensus_contract_smoke_valid_v1.json"
INVALID = FIXTURES / "detector_observation_consensus_contract_smoke_invalid_v1.json"
PARITY = FIXTURES / "detector_observation_consensus_synthetic_parity_v1.json"

sys.path.insert(0, str(SCRIPTS))

from validate_detector_observation_consensus import (  # noqa: E402
    MAX_MESSAGE_BYTES,
    build_validator,
    load_json,
    validation_errors,
)


def test_schema_is_valid_draft_2020_12():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)


def test_valid_contract_smoke_fixture_passes_without_effectiveness_claims():
    payload = load_json(VALID)

    assert validation_errors(payload) == []
    assert payload["validation_context"] == {
        "evidence_class": "contract_smoke",
        "claim_scope": "contract_only",
        "effectiveness_metrics": [],
    }
    observation = payload["observations"][0]
    assert observation["runtime_lane"] == "backend"
    assert observation["model_contract_id"]
    assert observation["decision_mode"] == "detect_only"
    assert observation["ensemble_votes"][1] == {
        "detector_id": "tamandua/malware-smell-static",
        "status": "unsupported",
        "score": None,
        "decision": "unknown",
        "confidence": 0,
    }


def test_invalid_fixture_fails_schema_and_cross_observation_checks():
    errors = validation_errors(load_json(INVALID))

    assert errors
    assert any("detector_id values must be unique" in error for error in errors)
    assert any("unknown detector_id" in error for error in errors)
    assert any("contract_only" in error for error in errors)
    assert any("false_positive_rate" in error or "non-empty" in error for error in errors)


def test_synthetic_runtime_parity_fixture_has_no_efficacy_claim():
    payload = load_json(PARITY)

    assert validation_errors(payload) == []
    assert payload["validation_context"] == {
        "evidence_class": "synthetic_parity",
        "claim_scope": "parity_only",
        "effectiveness_metrics": [],
    }
    observation = payload["observations"][0]
    assert observation["runtime_lane"] == "embedded_onnx"
    assert [vote["status"] for vote in observation["ensemble_votes"]] == [
        "completed",
        "degraded",
    ]


def test_degraded_observation_cannot_claim_a_decision_without_an_error():
    payload = load_json(VALID)
    observation = payload["observations"][0]
    observation.update(
        {
            "status": "degraded",
            "degraded": True,
            "score": None,
            "threshold": None,
            "decision": "malicious",
            "confidence": 0,
            "error": None,
        }
    )

    errors = list(build_validator().iter_errors(payload))
    assert errors


def test_degraded_ensemble_vote_cannot_be_serialized_as_benign():
    payload = load_json(VALID)
    vote = payload["observations"][0]["ensemble_votes"][1]
    vote.update({"score": 0.0, "decision": "benign", "confidence": 1})

    errors = list(build_validator().iter_errors(payload))
    assert errors


def test_non_finite_detector_numbers_are_rejected_in_memory():
    for field in ("score", "threshold", "confidence", "latency_ms"):
        payload = load_json(VALID)
        payload["observations"][0][field] = math.nan
        assert any("finite" in error or "not valid" in error for error in validation_errors(payload))


def test_non_finite_json_and_oversized_messages_are_rejected(tmp_path):
    nan_path = tmp_path / "nan.json"
    nan_path.write_text('{"score": Infinity}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite"):
        load_json(nan_path)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b'{"padding":"' + b"a" * MAX_MESSAGE_BYTES + b'"}')
    with pytest.raises(ValueError, match="exceeds 1 MiB"):
        load_json(oversized)


def test_more_than_32_ensemble_votes_is_rejected():
    payload = load_json(VALID)
    vote = payload["observations"][0]["ensemble_votes"][0]
    payload["observations"][0]["ensemble_votes"] = [dict(vote) for _ in range(33)]
    assert validation_errors(payload)


def test_cli_accepts_valid_fixture_and_rejects_invalid_fixture():
    script = SCRIPTS / "validate_detector_observation_consensus.py"

    valid = subprocess.run(
        [sys.executable, str(script), str(VALID)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    invalid = subprocess.run(
        [sys.executable, str(script), str(INVALID)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert valid.returncode == 0, valid.stdout + valid.stderr
    assert "contract_smoke; contract_only; no FP/FN or efficacy claim" in valid.stdout
    assert invalid.returncode == 1
    assert "INVALID" in invalid.stdout
