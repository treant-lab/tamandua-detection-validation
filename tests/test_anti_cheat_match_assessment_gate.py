from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_match_assessment_gate.py"
SPEC = importlib.util.spec_from_file_location("anti_cheat_match_assessment_gate", SCRIPT)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def fixture() -> dict:
    return json.loads(gate.DEFAULT_FIXTURE_PATH.read_text(encoding="utf-8"))


def write_fixture(tmp_path: Path, value: dict) -> Path:
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return path


def assessment(value: dict, scenario: str) -> dict:
    return next(item["assessment"] for item in value["assessments"] if item["scenario"] == scenario)


def semantic_errors(value: dict, scenario: str) -> list[str]:
    return gate._semantic_errors(
        assessment(value, scenario), value["policy_manifest"], value["policy_manifest_digest"]
    )


def assert_rejected(tmp_path: Path, value: dict, match: str) -> None:
    with pytest.raises(gate.MatchAssessmentGateError, match=match):
        gate.validate_gate(write_fixture(tmp_path, value))


def test_valid_fixture_emits_closed_deterministic_synthetic_report():
    first = gate.validate_gate()
    second = gate.validate_gate()
    assert first == second
    assert first["counts"] == {"total": 4, "observe": 2, "queue_review": 1, "abstain": 1}
    assert first["scenario_coverage"] == gate.EXPECTED_SCENARIOS
    assert first["gate_source_sha256"] == hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
    assert first["report_schema_sha256"] == hashlib.sha256(gate.REPORT_SCHEMA_PATH.read_bytes()).hexdigest()
    assert first["tenant_scope_digest"] == fixture()["tenant_scope_digest"]
    assert first["policy_manifest_digest"] == fixture()["policy_manifest_digest"]
    assert first["claims"]["server_authority_authenticated"] is False
    assert first["claims"]["live_server_validated"] is False
    assert first["payload_size"]["within_budget"] is True
    assert first["tooling_performance"] == {
        "measurement_class": "local_semantic_evaluator_tooling_smoke", "iterations": 10000,
        "p95_budget_ms": 10.0, "p95_bucket": "le_10ms", "within_budget": True,
        "product_or_engine_performance_claim": False,
    }
    schema = json.loads(gate.REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(first)) == []
    basis = {key: value for key, value in first.items() if key != "report_id"}
    expected = hashlib.sha256(b"tamandua.anti_cheat.match_assessment_report/v1\0" + gate.canonical(basis)).hexdigest()
    assert first["report_id"] == expected


def test_fixture_assessments_validate_against_closed_schema():
    value = fixture()
    schema = json.loads(gate.ASSESSMENT_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for item in value["assessments"]:
        assert list(validator.iter_errors(item["assessment"])) == []
    decision_values = schema["properties"]["decision"]["enum"]
    assert decision_values == ["observe", "queue_review", "abstain"]
    assert set(decision_values).isdisjoint({"allow", "warn", "step_up", "block", "kill_session", "ban", "sanction"})


@pytest.mark.parametrize("decision", ["ban", "block", "kill_session", "sanction"])
def test_schema_rejects_every_destructive_decision(decision: str):
    value = fixture()
    candidate = assessment(value, "server_corroborated")
    candidate["decision"] = decision
    schema = json.loads(gate.ASSESSMENT_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(candidate))


@pytest.mark.parametrize("field", ["enforcement_authorized", "automatic_sanction", "durable_sanction"])
def test_schema_rejects_enforcement_or_sanction_claims(field: str):
    value = fixture()
    candidate = assessment(value, "server_corroborated")
    candidate["review"][field] = True
    schema = json.loads(gate.ASSESSMENT_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(candidate))


def test_score_and_reasons_must_be_recomputable(tmp_path: Path):
    value = fixture()
    assessment(value, "server_corroborated")["score"]["value"] = 79
    assert_rejected(tmp_path, value, "score is not recomputable")
    value = fixture()
    assessment(value, "server_corroborated")["score"]["reasons"] = ["invented_reason"]
    assert_rejected(tmp_path, value, "schema validation failed")


def test_client_contribution_requires_exact_observed_signal(tmp_path: Path):
    value = fixture()
    assessment(value, "local_only")["client_integrity"]["signals"][0]["state"] = "unknown"
    assert_rejected(tmp_path, value, "score contributions are not policy-derived")


def test_server_contribution_requires_exact_corroborated_observation(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "server_corroborated")
    candidate["score"]["contributions"][1]["evidence_digest"] = "0" * 64
    assert_rejected(tmp_path, value, "score contributions are not policy-derived")


def test_local_only_evidence_cannot_queue_review(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "local_only")
    candidate["decision"] = "queue_review"
    candidate["review"]["status"] = "pending"
    assert_rejected(tmp_path, value, "decision is not recomputable")


def test_assessment_threshold_cannot_drift_from_closed_policy(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "server_corroborated")
    candidate["score"]["review_threshold"] = 90
    candidate["decision"] = "observe"
    candidate["review"]["status"] = "not_queued"
    assert_rejected(tmp_path, value, "assessment score is not bound to the policy manifest")


def test_conflicting_server_evidence_must_abstain(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "conflicting")
    candidate["decision"] = "queue_review"
    candidate["review"]["status"] = "pending"
    assert_rejected(tmp_path, value, "decision is not recomputable")


def test_corroboration_state_and_tick_windows_are_recomputed(tmp_path: Path):
    value = fixture()
    assessment(value, "conflicting")["server_authority"]["corroboration_state"] = "corroborated"
    assert_rejected(tmp_path, value, "corroboration state is not recomputable")
    value = fixture()
    assessment(value, "clean")["server_authority"]["window"]["start_tick"] = 1300
    assert_rejected(tmp_path, value, "window is reversed")


def test_privacy_boundary_is_exact_and_global_identifiers_cannot_be_added(tmp_path: Path):
    value = fixture()
    assessment(value, "clean")["privacy"]["excluded_fields"].remove("raw_chat")
    assert_rejected(tmp_path, value, "schema validation failed")


@pytest.mark.parametrize("member,value", [
    ("player_email", "player@example.com"),
    ("global_player_id", "shared-player-1"),
    ("tenant_id", "tenant-raw"),
])
def test_raw_or_global_identifiers_fail_closed_even_outside_assessment_schema(
    tmp_path: Path, member: str, value: str,
):
    candidate = fixture()
    candidate[member] = value
    assert_rejected(tmp_path, candidate, "fixture members are not closed|identifier|email-shaped")


def test_email_shaped_values_are_rejected_recursively(tmp_path: Path):
    value = fixture()
    assessment(value, "clean")["limitations"][0] = "contact_player@example.com"
    assert_rejected(tmp_path, value, "email-shaped value rejected")


@pytest.mark.parametrize(("unsafe", "message"), [
    ("source_ip=192.0.2.9", "IP address value rejected"),
    ("server_ipv6=2001:db8::1", "IP address value rejected"),
    ("server_ipv6=[2001:db8::1]:443", "IP address value rejected"),
    ("link_local=[fe80::1%eth0]:443", "IP address value rejected"),
    ("mapped=::ffff:192.0.2.128", "IP address value rejected"),
    ("expanded=2001:db8:0:0:0:0:2:1", "IP address value rejected"),
    ("evidence=https://example.invalid/a", "URL value rejected"),
    ("global_player_identifier", "global identifier value rejected"),
    ("Authorization: Bearer abcdefghijklmnop", "authorization or secret value rejected"),
])
def test_privacy_scanner_rejects_network_global_and_secret_values(
    tmp_path: Path, unsafe: str, message: str,
):
    value = fixture()
    assessment(value, "clean")["limitations"][0] = unsafe
    assert_rejected(tmp_path, value, message)


def test_privacy_scanner_rejects_secret_members_recursively(tmp_path: Path):
    value = fixture()
    assessment(value, "clean")["client_integrity"]["api-key"] = "abcdef123456"
    assert_rejected(tmp_path, value, "authorization or secret member rejected")


@pytest.mark.parametrize("invalid_version", ["01", "1.02", "1.2.3.4", "v1", "policy-v1", "auth-v1.02", "1/../../", "1_beta"])
def test_authority_versions_use_closed_bounded_grammar(tmp_path: Path, invalid_version: str):
    value = fixture()
    assessment(value, "clean")["server_authority"]["authority_version"] = invalid_version
    assert_rejected(tmp_path, value, "assessment schema validation failed|IP address value rejected")


@pytest.mark.parametrize("invalid_version", ["01", "1.02", "1.2.3.4", "v1", "auth-v1", "policy-v1.02", "1/../../", "1_beta"])
def test_policy_versions_use_closed_bounded_grammar(tmp_path: Path, invalid_version: str):
    value = fixture()
    value["policy_manifest"]["policy_version"] = invalid_version
    assert_rejected(tmp_path, value, "policy version is invalid")


def test_domain_versions_are_shared_bounded_and_never_ip_literals():
    valid = (
        ("auth-v1", "auth"),
        ("auth-v1.2.3-rc.1+build.5", "auth"),
        ("policy-v0", "policy"),
        ("policy-v1.2.3.4-rc.1+build.5", "policy"),
    )
    for version, domain in valid:
        assert gate._version_is_valid(version, domain)
        assert gate._contains_ip_address(version) is False
    assert gate._version_is_valid("policy-v1", "unknown") is False


@pytest.mark.parametrize(
    ("family", "wrong_family"),
    [
        (family, wrong_family)
        for family in gate.FEATURE_SCHEMA_BY_FAMILY
        for wrong_family in gate.FEATURE_SCHEMA_BY_FAMILY
        if family != wrong_family
    ],
)
def test_every_detector_family_rejects_every_cross_family_feature_schema(
    tmp_path: Path, family: str, wrong_family: str,
):
    value = fixture()
    observation = assessment(value, "clean")["server_authority"]["observations"][0]
    observation["detector_family"] = family
    observation["feature_schema"] = gate.FEATURE_SCHEMA_BY_FAMILY[wrong_family]
    assert_rejected(tmp_path, value, "feature schema does not match detector family")


@pytest.mark.parametrize("forbidden_key", ["Tenant_ID", "PLAYER-email", "Match.Id", "GlobalPlayerIdentifier"])
def test_recursive_forbidden_identifier_keys_are_case_and_separator_insensitive(
    tmp_path: Path, forbidden_key: str,
):
    value = fixture()
    assessment(value, "clean")["client_integrity"][forbidden_key] = "raw"
    assert_rejected(tmp_path, value, "raw or global identifier member rejected")


@pytest.mark.parametrize("invalid_schema", [
    "player.private.features/v1",
    "tamandua.game.unknown_features/v1",
    "tamandua.game.movement_features/v0",
    "tamandua.game.movement_features/latest",
])
def test_feature_schema_uses_closed_namespaced_vocabulary(tmp_path: Path, invalid_schema: str):
    value = fixture()
    assessment(value, "clean")["server_authority"]["observations"][0]["feature_schema"] = invalid_schema
    assert_rejected(tmp_path, value, "assessment schema validation failed")


def test_privacy_closed_report_gate_is_derived_from_scan_result():
    value = fixture()
    pairs = [(item["scenario"], item["assessment"]) for item in value["assessments"]]
    report = gate._report(
        b"fixture", b"schema", b"report-schema", pairs, True,
        value["tenant_scope_digest"], value["policy_manifest_digest"], False,
    )
    assert report["gates"]["privacy_closed"] is False


def test_limitations_are_closed_codes_not_free_form(tmp_path: Path):
    value = fixture()
    assessment(value, "clean")["limitations"] = ["arbitrary analyst prose"]
    assert_rejected(tmp_path, value, "schema validation failed")


def test_observation_identity_is_digest_only(tmp_path: Path):
    value = fixture()
    observation = assessment(value, "clean")["server_authority"]["observations"][0]
    observation["observation_id"] = "observation:raw:1"
    assert_rejected(tmp_path, value, "raw or global identifier member rejected|schema validation failed")
    value = fixture()
    assessment(value, "clean")["server_authority"]["observations"][0]["observation_id_digest"] = "A" * 64
    assert_rejected(tmp_path, value, "schema validation failed")


def test_tenant_scope_and_score_policy_binding_are_mandatory(tmp_path: Path):
    value = fixture()
    assessment(value, "clean").pop("tenant_scope_digest")
    assert_rejected(tmp_path, value, "schema validation failed")
    value = fixture()
    assessment(value, "clean")["score"].pop("policy_digest")
    assert_rejected(tmp_path, value, "schema validation failed")
    value = fixture()
    assessment(value, "clean")["session"]["global_player_id"] = "forbidden"
    assert_rejected(tmp_path, value, "raw or global identifier member rejected")


@pytest.mark.parametrize("path", [
    ("protected_target", "game_id_digest"),
    ("protected_target", "build_id_digest"),
    ("session", "match_id_digest"),
    ("session", "player_session_id_digest"),
])
def test_scoped_identifiers_must_be_lowercase_sha256_digests(tmp_path: Path, path: tuple[str, str]):
    value = fixture()
    assessment(value, "clean")[path[0]][path[1]] = "A" * 64
    assert_rejected(tmp_path, value, "schema validation failed")


def test_fixture_tenant_digest_and_single_tenant_scope_are_enforced(tmp_path: Path):
    value = fixture()
    value["tenant_scope_digest"] = "A" * 64
    assert_rejected(tmp_path, value, "fixture tenant scope digest is invalid")
    value = fixture()
    assessment(value, "clean")["tenant_scope_digest"] = "f" * 64
    assert_rejected(tmp_path, value, "mixed tenant scope rejected")


def test_policy_digest_is_recomputed_and_assessment_bindings_are_closed(tmp_path: Path):
    value = fixture()
    value["policy_manifest"]["rules"][1]["points"] = 79
    assert_rejected(tmp_path, value, "policy manifest digest is not recomputable")
    value = fixture()
    value["policy_manifest"]["rules"][1]["points"] = 79
    value["policy_manifest_digest"] = gate.policy_manifest_digest(value["policy_manifest"])
    assert_rejected(tmp_path, value, "assessment score is not bound to the policy manifest")


def test_supplied_points_are_ignored_as_authority_and_must_equal_policy_derivation(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "local_only")
    candidate["score"]["contributions"][0]["points"] = 99
    candidate["score"]["value"] = 99
    assert_rejected(tmp_path, value, "score contributions are not policy-derived")


def test_duplicate_client_signal_fails_before_scoring(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "local_only")
    candidate["client_integrity"]["signals"].append(
        copy.deepcopy(candidate["client_integrity"]["signals"][0])
    )
    assert_rejected(tmp_path, value, "duplicate client integrity signal rejected")


def test_duplicate_server_observation_fails_before_scoring(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "server_corroborated")
    candidate["server_authority"]["observations"].append(
        copy.deepcopy(candidate["server_authority"]["observations"][0])
    )
    assert_rejected(tmp_path, value, "duplicate server observation rejected")


def test_duplicate_supplied_contribution_fails_before_scoring(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "local_only")
    candidate["score"]["contributions"].append(
        copy.deepcopy(candidate["score"]["contributions"][0])
    )
    assert_rejected(tmp_path, value, "duplicate supplied contribution rejected")


def test_any_inconclusive_server_observation_forces_aggregate_abstention(tmp_path: Path):
    value = fixture()
    candidate = assessment(value, "server_corroborated")
    inconclusive = copy.deepcopy(candidate["server_authority"]["observations"][0])
    inconclusive.update(
        observation_id_digest="6f" * 32,
        outcome="inconclusive",
        evidence_digest="7f" * 32,
    )
    candidate["server_authority"]["observations"].append(inconclusive)
    candidate["server_authority"]["corroboration_state"] = "inconclusive"
    candidate["decision"] = "abstain"
    candidate["review"]["status"] = "not_queued"
    assert semantic_errors(value, "server_corroborated") == []
    candidate["decision"] = "queue_review"
    candidate["review"]["status"] = "pending"
    assert_rejected(tmp_path, value, "decision is not recomputable")


def test_policy_manifest_is_closed_and_selectors_are_unique(tmp_path: Path):
    value = fixture()
    value["policy_manifest"]["unexpected"] = True
    assert_rejected(tmp_path, value, "policy manifest members are not closed")
    value = fixture()
    value["policy_manifest"]["rules"].append(copy.deepcopy(value["policy_manifest"]["rules"][0]))
    value["policy_manifest_digest"] = gate.policy_manifest_digest(value["policy_manifest"])
    assert_rejected(tmp_path, value, "policy rule selectors must be unique")


def test_server_authority_is_explicitly_unauthenticated_synthetic(tmp_path: Path):
    value = fixture()
    assessment(value, "clean")["server_authority"]["authentication_state"] = "authenticated"
    assert_rejected(tmp_path, value, "schema validation failed")
    value = fixture()
    value["claim_boundary"]["server_authority_authenticated"] = True
    assert_rejected(tmp_path, value, "claim boundary")


def test_fixture_claims_and_future_fpr_contract_fail_closed(tmp_path: Path):
    value = fixture()
    value["claim_boundary"]["fpr_claimable"] = True
    assert_rejected(tmp_path, value, "claim boundary")
    value = fixture()
    value["future_governed_fpr_gate"]["zero_failure_minimum_per_stratum"] = 597
    assert_rejected(tmp_path, value, "future governed FPR gate")
    assert math.ceil(math.log(0.05) / math.log(0.995)) == 598


def test_scenario_order_and_identity_uniqueness_are_closed(tmp_path: Path):
    value = fixture()
    value["assessments"].reverse()
    assert_rejected(tmp_path, value, "scenario coverage or ordering")
    value = fixture()
    assessment(value, "local_only")["assessment_id"] = assessment(value, "clean")["assessment_id"]
    assert_rejected(tmp_path, value, "identities are duplicated")


def test_duplicate_json_members_are_rejected(tmp_path: Path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
    with pytest.raises(gate.MatchAssessmentGateError, match="duplicate JSON member"):
        gate.load_json(path)


def test_payload_budget_uses_conservative_upper_median():
    value = fixture()
    pairs = [(item["scenario"], copy.deepcopy(item["assessment"])) for item in value["assessments"]]
    for _scenario, candidate in pairs:
        candidate["limitations"] = [f"limitation_{index}_" + "x" * 230 for index in range(16)]
    report = gate._report(
        b"fixture", b"schema", b"report-schema", pairs, True,
        value["tenant_scope_digest"], value["policy_manifest_digest"], True,
    )
    assert report["payload_size"]["median_bytes"] > 4096
    assert report["payload_size"]["within_budget"] is False


def test_source_has_no_engine_server_network_or_enforcement_runtime():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "requests" not in source and "urllib" not in source and "socket" not in source
    assert "boto" not in source and "subprocess" not in source
    assert "unity" not in source.lower() and "unreal" not in source.lower()
    assert "product_or_engine_performance_claim\": False" in source
