"""Fail-closed contract tests for Phase 92 handoff and Phase 93 assembly."""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[3]
PHASE92_SCHEMA = ROOT / "schemas/phase92_endpoint_handoff_v1.schema.json"
PHASE92_FIXTURE = (
    ROOT / "tools/detection_validation/fixtures/phase92_endpoint_handoff_deferred_v1.json"
)
PHASE93_SCHEMA = ROOT / "schemas/phase93_full_coverage_matrix_v1.schema.json"
PHASE93_FIXTURE = (
    ROOT / "tools/detection_validation/fixtures/phase93_full_coverage_matrix_deferred_v1.json"
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validator(path: Path) -> Draft202012Validator:
    schema = load(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_deferred_phase92_handoff_is_schema_valid_and_claim_safe():
    value = load(PHASE92_FIXTURE)
    validator(PHASE92_SCHEMA).validate(value)
    assert value["status"] == "deferred"
    assert value["external_claim_allowed"] is False
    assert all(endpoint["state"] == "deferred" for endpoint in value["endpoints"].values())
    assert all(endpoint["agent_id"] is None for endpoint in value["endpoints"].values())
    assert all(not endpoint["stimulus_event_ids"] for endpoint in value["endpoints"].values())


def test_phase92_status_only_promotion_is_rejected():
    promoted = copy.deepcopy(load(PHASE92_FIXTURE))
    promoted["status"] = "ready_for_phase93"
    promoted["evidence_class"] = "live_endpoint"
    promoted["blockers"] = []
    promoted["endpoints"]["windows"]["state"] = "ready"
    promoted["endpoints"]["macos"]["state"] = "ready"
    with pytest.raises(ValidationError):
        validator(PHASE92_SCHEMA).validate(promoted)


def test_deferred_phase93_matrix_is_schema_valid_and_has_no_fabricated_results():
    value = load(PHASE93_FIXTURE)
    validator(PHASE93_SCHEMA).validate(value)
    assert value["status"] == "deferred"
    assert value["external_claim_allowed"] is False
    assert value["combined"]["evaluated_cells"] == 0
    assert value["combined"]["passed_cells"] == 0
    assert all(row["detection_rate_percent"] is None for row in value["meas05"].values())
    assert all(row["artifact"] is None for row in value["meas06"].values())


def test_phase93_status_only_promotion_is_rejected():
    promoted = copy.deepcopy(load(PHASE93_FIXTURE))
    promoted["status"] = "pass"
    promoted["evidence_class"] = "live_endpoint"
    promoted["phase92_handoff"] = "docs/benchmarks/runs/phase92-handoff.json"
    promoted["blockers"] = []
    with pytest.raises(ValidationError):
        validator(PHASE93_SCHEMA).validate(promoted)


def test_contracts_do_not_define_secret_fields():
    forbidden = {"token", "password", "secret", "private_key"}
    for path in (PHASE92_SCHEMA, PHASE92_FIXTURE, PHASE93_SCHEMA, PHASE93_FIXTURE):
        text = path.read_text(encoding="utf-8").lower()
        assert not any(f'"{name}"' in text for name in forbidden)
