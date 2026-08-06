import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_sanction_appeal_gate.py"
FIXTURE = ROOT / "tools/detection_validation/fixtures/anti_cheat_sanction_appeal_synthetic_v1.json"
DECISION_SCHEMA = ROOT / "schemas/anti_cheat_sanction_decision_v1.schema.json"
APPEAL_SCHEMA = ROOT / "schemas/anti_cheat_appeal_case_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("sanction_appeal_gate", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


@pytest.fixture(scope="module")
def authority():
    return gate._source_authority()


def schemas():
    return json.loads(DECISION_SCHEMA.read_text()), json.loads(APPEAL_SCHEMA.read_text())


def decision(variant, state, authority, context=None):
    bindings, scope = authority
    return gate._make_decision(variant, state, bindings, scope, {} if context is None else context)


def apply_decision(document, state, authority):
    bindings, scope = authority
    return gate.apply_decision(document, state, bindings, scope, schemas()[0])


def re_audit(kind, document, state):
    gate._audit(kind, document, state)


def test_tabletop_report_is_deterministic_closed_and_non_enforcing():
    first = gate.evaluate_fixture()
    second = gate.evaluate_fixture()
    assert first == second
    assert first["readiness_state"] == "governance_contract_ready_for_integration"
    assert first["counts"] == {"accepted": 13, "rejected_attacks": 5, "idempotent_duplicates": 1}
    assert first["enforcement_executed"] is False
    assert first["durable_state_written"] is False
    assert first["production_ready"] is False
    assert first["external_claim_allowed"] is False


def test_cli_is_deterministic():
    argv = [sys.executable, str(SCRIPT)]
    first = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
    second = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
    assert first == second
    assert json.loads(first)["enforcement_executed"] is False


def test_materialized_decision_and_appeal_validate_schemas(authority):
    decision_schema, appeal_schema = schemas()
    state = gate.CaseState()
    context = {}
    initial = decision("temporary_mistake", state, authority, context)
    Draft202012Validator(decision_schema).validate(initial)
    apply_decision(initial, state, authority)
    context["last_decision"] = initial
    opened = gate._make_appeal("open", state, context)
    Draft202012Validator(appeal_schema).validate(opened)


def test_action_vocabulary_is_closed():
    schema, _ = schemas()
    assert schema["properties"]["action"]["enum"] == [
        "observe", "step_up", "temporary_restriction", "manual_review",
        "permanent_sanction", "reverse",
    ]


@pytest.mark.parametrize("evidence_class", ["single_local", "inconclusive"])
@pytest.mark.parametrize("variant", ["temporary_mistake", "permanent_abuse"])
def test_no_restriction_from_single_local_or_inconclusive_signal(authority, evidence_class, variant):
    state = gate.CaseState()
    document = decision(variant, state, authority)
    document["evidence_class"] = evidence_class
    document["decision_id"] = gate.expected_decision_id(document)
    re_audit("decision", document, state)
    with pytest.raises(gate.GovernanceError, match="insufficient_evidence_for_restriction"):
        apply_decision(document, state, authority)


def test_permanent_sanction_requires_two_distinct_approvers_and_separation(authority):
    state = gate.CaseState()
    document = decision("permanent_abuse", state, authority)
    document["human_review"]["approver_digests"] = ["b" * 64]
    with pytest.raises(ValidationError):
        Draft202012Validator(schemas()[0]).validate(document)

    compromised = decision("compromised_moderator", gate.CaseState(), authority)
    with pytest.raises(gate.GovernanceError, match="separation_of_duties_failed"):
        apply_decision(compromised, gate.CaseState(), authority)


def test_idempotency_duplicate_and_conflict_are_distinct(authority):
    state = gate.CaseState()
    context = {}
    original = decision("temporary_uphold", state, authority, context)
    assert apply_decision(original, state, authority) == "accepted"
    context["last_decision"] = original
    assert apply_decision(gate._make_decision("repeat_last", state, *authority, context), state, authority) == "idempotent_duplicate"
    with pytest.raises(gate.GovernanceError, match="idempotency_conflict"):
        apply_decision(gate._make_decision("idempotency_conflict", state, *authority, context), state, authority)


def test_optimistic_version_prior_and_audit_fences_replay(authority):
    state = gate.CaseState()
    first = decision("temporary_uphold", state, authority)
    apply_decision(first, state, authority)
    second = decision("temporary_cross_tenant", state, authority)
    second["decision_version"] = 1
    re_audit("decision", second, state)
    with pytest.raises(gate.GovernanceError, match="decision_version_conflict"):
        apply_decision(second, state, authority)

    second["decision_version"] = 2
    second["prior_decision_digest"] = "f" * 64
    re_audit("decision", second, state)
    with pytest.raises(gate.GovernanceError, match="decision_version_conflict"):
        apply_decision(second, state, authority)

    state = gate.CaseState()
    document = decision("temporary_uphold", state, authority)
    document["audit"]["event_digest"] = "f" * 64
    with pytest.raises(gate.GovernanceError, match="audit_digest_mismatch"):
        apply_decision(document, state, authority)


def test_appeal_reviewer_is_independent_and_sla_bounded(authority):
    state = gate.CaseState()
    context = {}
    initial = decision("temporary_mistake", state, authority, context)
    apply_decision(initial, state, authority)
    opened = gate._make_appeal("open", state, context)
    gate.apply_appeal(opened, state, schemas()[1])
    review = gate._make_appeal("review", state, context)
    review["reviewer_digest"] = initial["human_review"]["proposer_digest"]
    re_audit("appeal", review, state)
    with pytest.raises(gate.GovernanceError, match="independent_reviewer_required"):
        gate.apply_appeal(review, state, schemas()[1])

    review["reviewer_digest"] = "e" * 64
    review["updated_at_unix"] = review["sla_due_at_unix"] + 1
    re_audit("appeal", review, state)
    with pytest.raises(gate.GovernanceError, match="appeal_sla_expired"):
        gate.apply_appeal(review, state, schemas()[1])


def test_fixture_covers_reversal_expiry_deletion_cross_tenant_and_compromise():
    report = gate.evaluate_fixture()
    by_scenario = {item["scenario"]: item["results"] for item in report["results"]}
    assert by_scenario["mistaken_clean_mod_accessibility"][-1] == {"outcome": "accepted", "reason": "none"}
    assert [item["reason"] for item in by_scenario["expiry_deletion"][1:]] == ["appeal_entitlement_expired", "appeal_evidence_deleted"]
    assert by_scenario["cross_tenant"][-1]["reason"] == "cross_scope_rejected"
    assert by_scenario["compromised_moderator"][0]["reason"] == "separation_of_duties_failed"


def test_source_bindings_are_exact_game_001_and_game_003(authority):
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["source_bindings"] == authority[0]
    assert fixture["scope"] == authority[1]


def test_unknown_fields_raw_identity_and_free_text_are_closed(authority):
    state = gate.CaseState()
    document = decision("temporary_uphold", state, authority)
    document["raw_player_name"] = "Alice"
    with pytest.raises(gate.GovernanceError, match="decision_schema_invalid"):
        apply_decision(document, state, authority)
    assert gate.privacy_errors({"raw_player_name": "Alice"})


def test_duplicate_json_members_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
    with pytest.raises(gate.GovernanceError, match="duplicate_json_member"):
        gate.load_json(path)


def test_product_sources_have_no_network_runtime_or_true_claims():
    source = SCRIPT.read_text()
    fixture = FIXTURE.read_text()
    for forbidden in ["requests", "socket", "urllib", "boto", "enforcement_executed\": true", "durable_state_written\": true"]:
        assert forbidden not in source
        assert forbidden not in fixture


def test_exact_scopes_are_utf8_without_trailing_whitespace():
    for path in (DECISION_SCHEMA, APPEAL_SCHEMA, FIXTURE, SCRIPT, Path(__file__)):
        raw = path.read_bytes()
        assert raw and b"\0" not in raw
        text = raw.decode("utf-8")
        assert all(line == line.rstrip(" \t") for line in text.splitlines())
