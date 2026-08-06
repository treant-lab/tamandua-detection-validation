from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_server_movement_replay_gate.py"
SPEC = importlib.util.spec_from_file_location("anti_cheat_server_movement_replay_gate", SCRIPT)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def fixture() -> dict:
    return json.loads(gate.DEFAULT_FIXTURE_PATH.read_text(encoding="utf-8"))


def write_fixture(tmp_path: Path, value: dict) -> Path:
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return path


def assert_rejected(tmp_path: Path, value: dict, message: str) -> None:
    with pytest.raises(gate.MovementReplayGateError, match=message):
        gate.validate_gate(write_fixture(tmp_path, value))


def evaluation_parts(stratum: str = "vanilla"):
    value = fixture()
    policy, digest = gate.validate_fixture(value)
    schema, _raw = gate.load_json(gate.TELEMETRY_SCHEMA_PATH)
    events = next(events for name, events in gate.expand_fixture(value) if name == stratum)
    return value, policy, digest, schema, copy.deepcopy(events)


def test_closed_synthetic_report_has_exact_counts_and_claim_boundary():
    report = gate.validate_gate()
    assert report["counts"] == {
        "total": 1896,
        "within_constraints": 1795,
        "constraint_violation": 100,
        "inconclusive": 1,
    }
    assert [item["name"] for item in report["strata"]] == [
        "vanilla", "approved_mod", "approved_accessibility", "authorized_teleport",
        "speed_violation", "gap_inconclusive",
    ]
    assert [item["synthetic_one_sided_upper_bound_ppm"] for item in report["strata"][:3]] == [4998, 4998, 4998]
    assert report["synthetic_upper_bound_contract"] == {
        "method": "clopper_pearson_one_sided", "confidence_ppm": 950000,
        "zero_failure_sample_count": 598, "upper_bound_ppm": 4998,
        "production_fpr_claimable": False,
    }
    assert report["claims"] == {
        "production_fpr_validated": False,
        "live_server_validated": False,
        "enforcement_authorized": False,
        "external_claim_allowed": False,
    }
    schema = json.loads(gate.REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(report)) == []


def test_report_is_stable_across_one_hundred_runs():
    _value, policy, digest, schema, events = evaluation_parts("speed_violation")
    digests = {
        hashlib.sha256(gate.canonical(gate.evaluate_replay(events, policy, digest, schema))).hexdigest()
        for _ in range(100)
    }
    assert len(digests) == 1


def test_all_generated_events_and_replays_validate_against_closed_schemas():
    value = fixture()
    policy, digest = gate.validate_fixture(value)
    telemetry_schema = json.loads(gate.TELEMETRY_SCHEMA_PATH.read_text(encoding="utf-8"))
    replay_schema = json.loads(gate.REPLAY_SCHEMA_PATH.read_text(encoding="utf-8"))
    event_validator = Draft202012Validator(telemetry_schema)
    replay_validator = Draft202012Validator(replay_schema)
    for _name, events in gate.expand_fixture(value):
        assert all(list(event_validator.iter_errors(event)) == [] for event in events)
        replay = gate.evaluate_replay(events, policy, digest, telemetry_schema)
        assert list(replay_validator.iter_errors(replay)) == []


def test_policy_digest_is_domain_separated_and_recomputed(tmp_path: Path):
    value = fixture()
    assert value["policy_digest"] == gate.policy_digest(value["policy"])
    value["policy"]["max_speed_mm_per_second"] += 1
    assert_rejected(tmp_path, value, "policy digest is not recomputable")


def test_evaluator_rejects_wrong_or_stale_policy_digest_before_evaluation():
    _value, policy, digest, schema, events = evaluation_parts()
    with pytest.raises(gate.MovementReplayGateError, match="policy digest is not recomputable"):
        gate.evaluate_replay(events, policy, "f" * 64, schema)
    mutated = copy.deepcopy(policy)
    mutated["max_speed_mm_per_second"] += 1
    with pytest.raises(gate.MovementReplayGateError, match="policy digest is not recomputable"):
        gate.evaluate_replay(events, mutated, digest, schema)


def test_evaluator_emits_only_the_recomputed_policy_digest():
    _value, policy, digest, schema, events = evaluation_parts()
    replay = gate.evaluate_replay(events, policy, digest, schema)
    assert replay["policy_digest"] == gate.policy_digest(policy) == digest


def test_self_consistent_policy_mutation_is_bound_to_its_new_canonical_digest():
    _value, policy, _digest, schema, events = evaluation_parts()
    mutated = copy.deepcopy(policy)
    mutated["max_speed_mm_per_second"] += 1
    mutated_digest = gate.policy_digest(mutated)
    replay = gate.evaluate_replay(events, mutated, mutated_digest, schema)
    assert replay["policy_digest"] == mutated_digest
    assert replay["policy_digest"] != gate.policy_digest(policy)


@pytest.mark.parametrize("literal", ["1.5", "1e3", "NaN", "Infinity"])
def test_json_loader_rejects_floating_point_and_non_finite_numbers(tmp_path: Path, literal: str):
    path = tmp_path / "bad.json"
    path.write_text('{"value":' + literal + "}", encoding="utf-8")
    with pytest.raises(gate.MovementReplayGateError, match="floating-point|non-finite"):
        gate.load_json(path)


def test_duplicate_json_members_are_rejected(tmp_path: Path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
    with pytest.raises(gate.MovementReplayGateError, match="duplicate JSON member"):
        gate.load_json(path)


@pytest.mark.parametrize("unsafe", [
    "player@example.com", "source=192.0.2.5", "source=[2001:db8::1]:443",
    "https://example.invalid/replay", "Authorization: Bearer abcdefghijklmnop",
    "Authorization: Basic Zm9vOmJhcg==", "Proxy-Authorization: Basic Zm9vOmJhcg==",
    "Authentication: abcdefghijklmnop", "WWW-Authenticate: Basic realm=game",
    "X-Auth: abcdefghijklmnop", "X-Auth-Token: abcdefghijklmnop", "X-Api-Key: abcdefghijklmnop",
    "AWS_SECRET_ACCESS_KEY=abc1234567890123456789012345678901234567",
    "aws-access-key-id: AKIAIOSFODNN7EXAMPLE", "Cookie: sessionid=abcdef1234567890",
    "Set-Cookie: sid=abcdef1234567890", "Session.Token=abcdef1234567890",
])
def test_recursive_privacy_scanner_rejects_raw_network_and_secret_values(tmp_path: Path, unsafe: str):
    value = fixture()
    value["policy"]["policy_id"] = unsafe
    assert_rejected(tmp_path, value, "email-shaped|IP address|URL value|secret-shaped")


@pytest.mark.parametrize("key", [
    "Player-Email", "PLAYER EMAIL", "access.Token", "Tenant-ID", "raw-chat",
    "AwS.SeCrEt-Access Key", "AWS-Session.Token", "Proxy Authorization", "Set.Cookie",
])
def test_mixed_case_separator_forbidden_members_are_normalized(tmp_path: Path, key: str):
    value = fixture()
    value[key] = "opaque"
    assert_rejected(tmp_path, value, "raw identifier or secret member rejected")


def test_nested_mixed_case_secret_member_is_rejected_before_shape_validation(tmp_path: Path):
    value = fixture()
    value["policy"]["authorized_transitions"][0]["metadata"] = {
        "AwS.SeCrEt-Access Key": "opaque"
    }
    assert_rejected(tmp_path, value, "raw identifier or secret member rejected")


def test_cross_tenant_session_and_build_pairs_are_rejected():
    _value, policy, digest, schema, events = evaluation_parts()
    for field in ["tenant_scope_digest", "build_digest", "session_digest"]:
        candidate = copy.deepcopy(events)
        candidate[1][field] = "f" * 64
        with pytest.raises(gate.MovementReplayGateError, match="cross tenant, build, or session"):
            gate.evaluate_replay(candidate, policy, digest, schema)


def test_duplicate_and_out_of_order_sequence_and_ticks_are_rejected():
    _value, policy, digest, schema, events = evaluation_parts()
    events[1]["sequence"] = events[0]["sequence"]
    with pytest.raises(gate.MovementReplayGateError, match="duplicate sequence or tick"):
        gate.evaluate_replay(events, policy, digest, schema)


def test_missing_sequence_is_inconclusive_and_abstains():
    _value, policy, digest, schema, events = evaluation_parts()
    events[1]["sequence"] = 2
    replay = gate.evaluate_replay(events, policy, digest, schema)
    assert replay["classification"] == "inconclusive_gap"
    assert replay["disposition"] == "abstain"
    assert replay["observation"] is None


def test_compact_generator_members_are_closed(tmp_path: Path):
    value = fixture()
    value["clean_strata"][0]["ignored"] = True
    assert_rejected(tmp_path, value, "clean strata members are not closed")
    _value, policy, digest, schema, events = evaluation_parts()
    events[1]["server_tick"] = events[0]["server_tick"] - 1
    with pytest.raises(gate.MovementReplayGateError, match="out-of-order sequence or tick"):
        gate.evaluate_replay(events, policy, digest, schema)


def test_impossible_displacement_emits_game_001a_compatible_observation_without_score():
    _value, policy, digest, schema, events = evaluation_parts("speed_violation")
    replay = gate.evaluate_replay(events, policy, digest, schema)
    assert replay["classification"] == "constraint_violation"
    assert replay["disposition"] == "emit_observation"
    assert replay["observation"]["detector_family"] == "movement"
    assert replay["observation"]["outcome"] == "corroborated"
    assert replay["observation"]["reason_code"] == "server_movement_constraint_violation"
    assert "score" not in replay and "ban" not in replay


def test_authorized_teleport_is_clean_and_digest_bound():
    _value, policy, digest, schema, events = evaluation_parts("authorized_teleport")
    clean = gate.evaluate_replay(events, policy, digest, schema)
    assert clean["classification"] == "within_constraints"
    events[1]["transition"]["authorization_digest"] = "f" * 64
    unknown = gate.evaluate_replay(events, policy, digest, schema)
    assert unknown["classification"] == "inconclusive_transition"
    assert unknown["disposition"] == "abstain"
    assert unknown["observation"] is None


def test_authorized_dash_is_clean_within_bound_and_violates_only_beyond_bound():
    _value, policy, digest, schema, events = evaluation_parts()
    events[1]["transition"] = {
        "kind": "dash",
        "authorization_digest": "d" * 64,
    }
    events[1]["position_mm"]["x"] = 1200
    clean = gate.evaluate_replay(events, policy, digest, schema)
    assert clean["classification"] == "within_constraints"
    events[1]["position_mm"]["x"] = 1201
    violation = gate.evaluate_replay(events, policy, digest, schema)
    assert violation["classification"] == "constraint_violation"
    assert violation["observation"]["reason_code"] == "server_movement_constraint_violation"


def test_excessive_gap_is_inconclusive_and_abstains():
    _value, policy, digest, schema, events = evaluation_parts("gap_inconclusive")
    replay = gate.evaluate_replay(events, policy, digest, schema)
    assert replay["classification"] == "inconclusive_gap"
    assert replay["disposition"] == "abstain"
    assert replay["observation"] is None


def test_approved_and_unknown_extensions_never_add_suspicion():
    _value, policy, digest, schema, events = evaluation_parts("approved_mod")
    approved = gate.evaluate_replay(events, policy, digest, schema)
    for event in events:
        event["extensions"][0]["approval"] = "unknown"
        event["extensions"][0]["namespace"] = "future.extension"
    unknown = gate.evaluate_replay(events, policy, digest, schema)
    assert approved["classification"] == unknown["classification"] == "within_constraints"
    assert approved["extensions_influenced_suspicion"] is False
    assert unknown["extensions_influenced_suspicion"] is False


def test_client_claimed_authority_and_extra_position_fields_fail_schema():
    _value, policy, digest, schema, events = evaluation_parts()
    events[0]["authority"] = "client"
    with pytest.raises(gate.MovementReplayGateError, match="telemetry envelope schema"):
        gate.evaluate_replay(events, policy, digest, schema)


def test_direct_floating_point_position_is_rejected_by_telemetry_schema():
    _value, policy, digest, schema, events = evaluation_parts()
    events[1]["position_mm"]["x"] = 1.5
    with pytest.raises(gate.MovementReplayGateError, match="telemetry envelope schema"):
        gate.evaluate_replay(events, policy, digest, schema)
    _value, policy, digest, schema, events = evaluation_parts()
    events[0]["position_mm"]["client_x"] = 4
    with pytest.raises(gate.MovementReplayGateError, match="telemetry envelope schema"):
        gate.evaluate_replay(events, policy, digest, schema)


def test_fixture_claim_boundary_cannot_be_promoted(tmp_path: Path):
    value = fixture()
    value["claim_boundary"]["production_fpr_claimable"] = True
    assert_rejected(tmp_path, value, "claim boundary")


def test_source_has_no_network_runtime_or_enforcement_path():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ["requests", "urllib", "socket", "subprocess", "boto", "kill_session", "automatic_sanction"]:
        assert forbidden not in source
    assert "production_fpr_validated\": False" in source
