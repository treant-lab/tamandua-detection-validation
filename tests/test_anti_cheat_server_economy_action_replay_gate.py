import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_server_economy_action_replay_gate.py"
FIXTURE = ROOT / "tools/detection_validation/fixtures/anti_cheat_server_economy_action_synthetic_v1.json"
REPLAY_SCHEMA = ROOT / "schemas/anti_cheat_server_economy_action_replay_v1.schema.json"
REPORT_SCHEMA = ROOT / "schemas/anti_cheat_server_economy_action_report_v1.schema.json"
spec = importlib.util.spec_from_file_location("economy_action_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec); assert spec.loader; sys.modules[spec.name] = gate; spec.loader.exec_module(gate)


def fixture(): return json.loads(FIXTURE.read_text(encoding="utf-8"))


def parts(mutation=None):
    value = fixture()
    return value, gate.build_events(value, "unit", 0, mutation, None)


def test_report_counts_exact_cp_and_nonclaim_boundary():
    report = gate.validate_gate()
    assert report["counts"] == {"total": 2054, "within_constraints": 1794, "economy_violation": 80, "action_violation": 120, "inconclusive_gap": 30, "inconclusive_conflict": 30}
    assert [item["samples"] for item in report["clean_strata"]] == [598, 598, 598]
    assert [item["cp_one_sided_95_upper_ppm"] for item in report["clean_strata"]] == [4998, 4998, 4998]
    assert report["cp_upper_bound_contract"]["integer_exact"] is True
    assert report["claims"] == {"production_fpr_claimable": False, "live_server_validated": False, "enforcement_authorized": False, "external_claim_allowed": False}
    assert not list(Draft202012Validator(json.loads(REPORT_SCHEMA.read_text())).iter_errors(report))


def test_report_is_deterministic_across_three_cold_builds_and_one_hundred_evaluations():
    cold_reports = {gate.canonical(gate._build_report(FIXTURE)) for _ in range(3)}
    assert len(cold_reports) == 1

    value, events = parts()
    replay_ids = {
        gate.evaluate_replay(copy.deepcopy(events), value["policy"], value["policy_digest"])["replay_id"]
        for _ in range(100)
    }
    assert len(replay_ids) == 1


@pytest.mark.parametrize("mutation,classification", [("currency","economy_violation"),("inventory","economy_violation"),("cadence","action_violation"),("ammo","action_violation"),("ability","action_violation"),("gap","inconclusive_gap"),("conflict","inconclusive_conflict")])
def test_injected_matrix_is_categorical(mutation, classification):
    value, events = parts(mutation)
    replay = gate.evaluate_replay(events, value["policy"], value["policy_digest"])
    assert replay["classification"] == classification
    assert replay["disposition"] == ("abstain" if classification.startswith("inconclusive") else "emit_observation")
    assert "score" not in replay and "ban" not in replay


def test_clean_purchase_grant_spend_retry_actions_and_extensions_are_neutral():
    value, events = parts()
    clean = gate.evaluate_replay(events, value["policy"], value["policy_digest"])
    assert clean["classification"] == "within_constraints"
    assert {item["detector_family"] for item in clean["observations"]} == {"economy", "action"}
    events[0]["extensions"] = [{"namespace_digest":"e"*64,"approval":"unknown"}]
    unknown = gate.evaluate_replay(events, value["policy"], value["policy_digest"])
    assert unknown["classification"] == "within_constraints"
    assert unknown["extensions_influenced_suspicion"] is False


def test_policy_is_closed_hash_pinned_and_recomputed():
    value, events = parts()
    changed = copy.deepcopy(value["policy"]); changed["initial_currency"] += 1
    with pytest.raises(gate.EconomyActionReplayError, match="digest not recomputable"):
        gate.evaluate_replay(events, changed, value["policy_digest"])
    changed["extra"] = 1
    with pytest.raises(gate.EconomyActionReplayError, match="members not closed"):
        gate.evaluate_replay(events, changed, gate.policy_digest(changed))


def test_duplicates_out_of_order_and_cross_scope_are_rejected():
    value, events = parts()
    duplicate = copy.deepcopy(events); duplicate[1]["event_id_digest"] = duplicate[0]["event_id_digest"]
    with pytest.raises(gate.EconomyActionReplayError, match="duplicate"):
        gate.evaluate_replay(duplicate, value["policy"], value["policy_digest"])
    ordered = copy.deepcopy(events); ordered[1]["server_tick"] = ordered[0]["server_tick"] - 1
    with pytest.raises(gate.EconomyActionReplayError, match="out-of-order"):
        gate.evaluate_replay(ordered, value["policy"], value["policy_digest"])
    scoped = copy.deepcopy(events); scoped[1]["tenant_scope_digest"] = "f"*64
    with pytest.raises(gate.EconomyActionReplayError, match="cross-scope"):
        gate.evaluate_replay(scoped, value["policy"], value["policy_digest"])


def test_conflict_precedes_gap_and_violation_including_initial_snapshot():
    value, events = parts("currency")
    events[-1]["sequence"] += 1
    events[0]["conflict_code"] = "ledger_snapshot_conflict"
    replay = gate.evaluate_replay(events, value["policy"], value["policy_digest"])
    assert replay["classification"] == "inconclusive_conflict"
    assert replay["disposition"] == "abstain"
    assert replay["observations"] == []


def test_initial_snapshot_authorization_is_closed_and_fails_to_conflict():
    value, events = parts()
    events[0]["authorization_digest"] = "f" * 64
    replay = gate.evaluate_replay(events, value["policy"], value["policy_digest"])
    assert replay["classification"] == "inconclusive_conflict"
    assert replay["disposition"] == "abstain"
    assert replay["observations"] == []


def test_gap_precedes_an_earlier_violation_when_no_conflict_exists():
    value, events = parts("currency")
    events[-1]["sequence"] += 1
    replay = gate.evaluate_replay(events, value["policy"], value["policy_digest"])
    assert replay["classification"] == "inconclusive_gap"
    assert replay["disposition"] == "abstain"


def test_idempotency_marker_is_exclusive_and_retry_cannot_reapply_effects():
    value, events = parts()
    marked_grant = copy.deepcopy(events)
    marked_grant[1]["idempotency_of_digest"] = marked_grant[0]["event_id_digest"]
    with pytest.raises(gate.EconomyActionReplayError, match="event members invalid"):
        gate.evaluate_replay(marked_grant, value["policy"], value["policy_digest"])

    missing_marker = copy.deepcopy(events)
    missing_marker[-1]["idempotency_of_digest"] = None
    with pytest.raises(gate.EconomyActionReplayError, match="event members invalid"):
        gate.evaluate_replay(missing_marker, value["policy"], value["policy_digest"])

    retrying_snapshot = copy.deepcopy(events)
    retrying_snapshot[-1]["idempotency_of_digest"] = retrying_snapshot[0]["event_id_digest"]
    assert gate.evaluate_replay(
        retrying_snapshot, value["policy"], value["policy_digest"]
    )["classification"] == "inconclusive_conflict"

    double_effect = copy.deepcopy(events)
    double_effect[-1]["currency"] += 50
    assert gate.evaluate_replay(
        double_effect, value["policy"], value["policy_digest"]
    )["classification"] == "economy_violation"


@pytest.mark.parametrize("key,value", [("player_id","raw"),("accessToken","raw"),("email","a@example.com"),("ip","192.0.2.1")])
def test_raw_identifiers_secrets_and_network_values_are_rejected(key, value):
    fixture_value = fixture(); fixture_value[key] = value
    with pytest.raises(gate.EconomyActionReplayError, match="raw identifier|raw secret|raw IP"):
        gate.validate_fixture(fixture_value)


@pytest.mark.parametrize("literal", ["1.5", "1e3", "NaN", "Infinity"])
def test_loader_rejects_floats_and_nonfinite(tmp_path, literal):
    path=tmp_path/"bad.json"; path.write_text('{"value":'+literal+'}',encoding="utf-8")
    with pytest.raises(gate.EconomyActionReplayError, match="floating-point|non-finite"):
        gate.load_json(path)


def test_loader_rejects_duplicate_members(tmp_path):
    path=tmp_path/"bad.json"; path.write_text('{"a":1,"a":2}',encoding="utf-8")
    with pytest.raises(gate.EconomyActionReplayError, match="duplicate JSON member"):
        gate.load_json(path)


def test_claim_boundary_cannot_be_promoted():
    value=fixture(); value["claim_boundary"]["production_fpr_claimable"] = True
    with pytest.raises(gate.EconomyActionReplayError, match="claim boundary"):
        gate.validate_fixture(value)


def test_schemas_are_closed_and_valid():
    for path in (REPLAY_SCHEMA, REPORT_SCHEMA):
        schema=json.loads(path.read_text()); Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False


def test_report_schema_and_semantics_reject_count_cp_and_strata_tampering():
    schema = json.loads(REPORT_SCHEMA.read_text())
    validator = Draft202012Validator(schema)
    report = gate.validate_gate()
    mutations = []
    changed = copy.deepcopy(report); changed["counts"]["total"] = 1; mutations.append(changed)
    changed = copy.deepcopy(report); changed["clean_strata"][0]["cp_one_sided_95_upper_ppm"] = 1; mutations.append(changed)
    changed = copy.deepcopy(report); changed["clean_strata"][1]["name"] = "vanilla"; mutations.append(changed)
    for changed in mutations:
        assert list(validator.iter_errors(changed))
        with pytest.raises(gate.EconomyActionReplayError):
            gate.validate_report_semantics(changed)


def test_replay_schema_and_semantics_bind_decision_to_observations():
    value, events = parts("conflict")
    replay = gate.evaluate_replay(events, value["policy"], value["policy_digest"])
    replay["disposition"] = "observe"
    replay["observations"] = [{
        "observation_id_digest": "a" * 64, "detector_family": "economy",
        "outcome": "not_corroborated", "reason_code": "server_economy_within_constraints",
        "evidence_digest": "b" * 64, "start_tick": 1, "end_tick": 2,
        "feature_schema": "tamandua.game.economy_features/v1",
    }]
    schema = json.loads(REPLAY_SCHEMA.read_text())
    assert list(Draft202012Validator(schema).iter_errors(replay))
    with pytest.raises(gate.EconomyActionReplayError, match="must abstain"):
        gate.validate_replay_semantics(replay)


def test_source_has_no_server_runtime_network_score_or_enforcement_path():
    source=SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("requests", "urllib", "socket", "subprocess", "automatic_ban", "kill_session", "risk_score"):
        assert forbidden not in source
    assert '"production_fpr_claimable": False' in source
