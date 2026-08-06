import copy
import json
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
    FIXTURE = ROOT / "fixtures" / "local_model_service_contract_synthetic_parity_v1.json"
else:
    ROOT = Path(os.environ.get("TAMANDUA_ROOT", Path(__file__).resolve().parents[3]))
    SCRIPTS = ROOT / "tools" / "detection_validation" / "scripts"
    FIXTURE = (
        ROOT
        / "tools"
        / "detection_validation"
        / "fixtures"
        / "local_model_service_contract_synthetic_parity_v1.json"
    )
SCHEMA = ROOT / "schemas" / "local_model_service_contract_v1.schema.json"

sys.path.insert(0, str(SCRIPTS))

from validate_local_model_service_contract import (  # noqa: E402
    MAX_MESSAGE_BYTES,
    build_validator,
    load_json,
    validation_errors,
)


def valid_response():
    return load_json(FIXTURE)


def test_schema_is_valid_and_synthetic_fixture_passes():
    jsonschema.Draft202012Validator.check_schema(
        json.loads(SCHEMA.read_text(encoding="utf-8"))
    )
    payload = valid_response()
    assert validation_errors(payload) == []
    assert payload["result"]["metadata"] == {
        "evidence_class": "synthetic_parity",
        "claim_scope": "parity_only",
    }


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("result", "risk_score"), float("nan")),
        (("result", "scan_time_ms"), float("inf")),
        (("result", "ensemble_votes", 0, "confidence"), float("-inf")),
        (("result", "ensemble_votes", 0, "score"), float("nan")),
    ],
)
def test_non_finite_numbers_are_rejected_even_when_constructed_in_memory(path, value):
    payload = valid_response()
    target = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    assert any("finite" in error or "not valid" in error for error in validation_errors(payload))


def test_json_nan_constant_is_rejected_during_load(tmp_path):
    path = tmp_path / "nan.json"
    path.write_text('{"risk_score": NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite"):
        load_json(path)


def test_message_larger_than_runtime_one_mib_limit_is_rejected(tmp_path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b'{"padding":"' + (b"a" * MAX_MESSAGE_BYTES) + b'"}')
    with pytest.raises(ValueError, match="exceeds 1 MiB"):
        load_json(path)


def test_more_than_32_votes_and_duplicate_detectors_are_rejected():
    payload = valid_response()
    vote = payload["result"]["ensemble_votes"][0]
    payload["result"]["ensemble_votes"] = [copy.deepcopy(vote) for _ in range(33)]
    errors = validation_errors(payload)
    assert errors
    assert any("too long" in error or "unique" in error for error in errors)


@pytest.mark.parametrize("status", ["degraded", "timeout", "failed", "unsupported"])
def test_non_success_vote_must_be_unknown_zero_confidence_without_score(status):
    payload = valid_response()
    vote = payload["result"]["ensemble_votes"][0]
    vote.update(
        {
            "status": status,
            "score": 0.2,
            "decision": "benign",
            "confidence": 0.9,
        }
    )
    assert validation_errors(payload)


def test_arbitrary_status_lane_mode_and_extra_result_fields_are_rejected():
    mutations = [
        ("ensemble_votes", 0, "status", "pwned"),
        ("runtime_lane", "remote_service"),
        ("decision_mode", "enforced"),
        ("unexpected", "unbounded producer field"),
    ]
    for mutation in mutations:
        payload = valid_response()
        if mutation[0] == "ensemble_votes":
            payload["result"]["ensemble_votes"][mutation[1]][mutation[2]] = mutation[3]
        else:
            payload["result"][mutation[0]] = mutation[1]
        assert validation_errors(payload), mutation


def test_nested_contract_mismatch_and_safe_with_threats_are_rejected():
    mismatch = valid_response()
    mismatch["result"]["model_contract_id"] = "synthetic/other-v1"
    assert any("must match" in error for error in validation_errors(mismatch))

    contradiction = valid_response()
    contradiction["result"]["safe"] = True
    assert any("cannot contain" in error for error in validation_errors(contradiction))


def test_health_and_request_protocol_messages_are_bounded():
    assert validation_errors(
        {
            "status": "ready",
            "protocol_version": "1",
            "model_contract_ids": ["synthetic/ember-like-v1"],
        }
    ) == []
    assert validation_errors(
        {
            "file_sha256": "a" * 64,
            "local_path": "C:/synthetic/model.bin",
            "model_contract_id": "synthetic/ember-like-v1",
        }
    ) == []


def test_cli_labels_evidence_as_synthetic_parity_only():
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "validate_local_model_service_contract.py"), str(FIXTURE)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "synthetic parity; no efficacy claim" in result.stdout
