from __future__ import annotations

import copy
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "validate_runtime_trust_policy.py"
SPEC = importlib.util.spec_from_file_location("validate_runtime_trust_policy", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CONTRACT_SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "validate_runtime_trust_contract.py"
CONTRACT_SPEC = importlib.util.spec_from_file_location("validate_runtime_trust_contract_for_policy", CONTRACT_SCRIPT)
assert CONTRACT_SPEC and CONTRACT_SPEC.loader
CONTRACT = importlib.util.module_from_spec(CONTRACT_SPEC)
CONTRACT_SPEC.loader.exec_module(CONTRACT)


def fixtures() -> tuple[dict, dict, dict]:
    return (
        MODULE.load_json(MODULE.POLICY_GOLDEN_PATH),
        MODULE.load_json(MODULE.EVALUATION_GOLDEN_PATH),
        MODULE.load_json(MODULE.EVENT_SCHEMA_PATH),
    )


def test_strict_policy_contract_is_synthetic() -> None:
    report = MODULE.validate(strict=True)
    assert report["ok"] is True
    assert report["evidence_class"] == "synthetic_contract"
    assert report["external_claim_allowed"] is False


def test_policy_digest_and_bundle_are_bound_to_evaluation() -> None:
    policy, evaluation, event_schema = fixtures()
    assert MODULE.semantic_errors(policy, evaluation, event_schema) == []
    evaluation["detector_bundle_version"] = "other"
    assert MODULE.semantic_errors(policy, evaluation, event_schema)


def test_non_monotonic_thresholds_are_rejected() -> None:
    policy, evaluation, event_schema = fixtures()
    policy["workflows"][0]["thresholds"] = {"warn": 70, "step_up": 50, "block": 90}
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert any("thresholds must be strictly increasing" in error for error in errors)


def test_duplicate_workflows_are_rejected() -> None:
    policy, evaluation, event_schema = fixtures()
    policy["workflows"].append(copy.deepcopy(policy["workflows"][0]))
    assert "workflow identifiers must be unique" in MODULE.semantic_errors(policy, evaluation, event_schema)


def test_expired_before_issued_is_rejected() -> None:
    policy, evaluation, event_schema = fixtures()
    policy["expires_at"] = policy["issued_at"]
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert "policy expires_at must be after issued_at" in errors


def test_observe_or_unsigned_policy_cannot_enforce() -> None:
    policy, evaluation, event_schema = fixtures()
    evaluation["decision"] = "block"
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert "observe policy cannot produce an enforcing decision" in errors
    assert "unverified policy cannot produce an enforcing decision" in errors


def test_abstention_requires_reason_and_non_allow_decision() -> None:
    schema = MODULE.load_json(MODULE.EVALUATION_SCHEMA_PATH)
    _, evaluation, _ = fixtures()
    evaluation["abstained"] = True
    evaluation["decision"] = "allow"
    evaluation["abstention_reasons"] = []
    assert MODULE.schema_errors(evaluation, schema)


def test_degraded_behavior_cannot_silently_allow() -> None:
    schema = MODULE.load_json(MODULE.POLICY_SCHEMA_PATH)
    policy, _, _ = fixtures()
    policy["capability_behavior"]["on_degraded"] = "allow"
    assert MODULE.schema_errors(policy, schema)


def test_unsigned_enforce_policy_is_rejected_before_decision() -> None:
    policy, evaluation, event_schema = fixtures()
    policy["mode"] = "enforce"
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert "enforce policy requires signed_verified signature status" in errors


def test_observe_policy_cannot_configure_step_up_or_block_fallback() -> None:
    policy, evaluation, event_schema = fixtures()
    policy["capability_behavior"]["on_degraded"] = "block"
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert any("cannot configure enforcing capability behavior" in error for error in errors)


def test_workflow_and_threshold_derive_decision() -> None:
    policy, evaluation, event_schema = fixtures()
    policy["mode"] = "enforce"
    policy["signature_status"] = "signed_verified"
    evaluation["capability_state"] = "supported"
    evaluation["score"] = 95
    evaluation["decision"] = "allow"
    evaluation["policy_digest"] = MODULE.canonical_sha256(policy)
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert any("does not match policy-derived block" in error for error in errors)
    evaluation["workflow"] = "login"
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert "evaluation workflow must resolve to exactly one policy workflow" in errors


def test_unsupported_abstain_behavior_is_applied() -> None:
    policy, evaluation, event_schema = fixtures()
    evaluation["capability_state"] = "unsupported"
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert any("does not match policy-derived abstain" in error for error in errors)
    assert "evaluation abstained flag does not match policy-derived decision" in errors


def test_decision_abstain_is_bidirectionally_bound() -> None:
    schema = MODULE.load_json(MODULE.EVALUATION_SCHEMA_PATH)
    _, evaluation, _ = fixtures()
    evaluation["decision"] = "abstain"
    evaluation["abstained"] = False
    evaluation["abstention_reasons"] = []
    assert MODULE.schema_errors(evaluation, schema)


def test_evaluation_time_and_rollback_must_be_valid() -> None:
    policy, evaluation, event_schema = fixtures()
    evaluation["evaluated_at"] = policy["expires_at"]
    policy["rollback"]["previous_policy_version"] = policy["policy_version"]
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert "evaluation evaluated_at must be within policy validity window" in errors
    assert "rollback previous_policy_version cannot equal current policy_version" in errors


def test_policy_evaluation_requires_capability_and_signal_completeness() -> None:
    schema = MODULE.load_json(MODULE.EVALUATION_SCHEMA_PATH)
    _, evaluation, _ = fixtures()
    del evaluation["capability_state"]
    del evaluation["signal_completeness"]
    del evaluation["missing_signal_ids"]
    assert MODULE.schema_errors(evaluation, schema)


def test_event_capability_state_must_match_evaluation() -> None:
    event = CONTRACT.load_json(CONTRACT.GOLDEN_PATH)
    event["evaluation"]["capability_state"] = "supported"
    errors = CONTRACT.validation_errors(event)
    assert "evaluation.capability_state must match capability_report.state" in errors


def test_observe_policy_rejects_enforcing_workflow_default() -> None:
    policy, evaluation, event_schema = fixtures()
    policy["workflows"][0]["default_decision"] = "block"
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert any("cannot configure enforcing workflow defaults" in error for error in errors)


def test_missing_required_signal_applies_policy_behavior() -> None:
    policy, evaluation, event_schema = fixtures()
    evaluation["signal_completeness"] = "missing_required"
    evaluation["missing_signal_ids"] = ["signature_integrity"]
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert any("does not match policy-derived abstain" in error for error in errors)
    assert "evaluation abstained flag does not match policy-derived decision" in errors


def test_equal_thresholds_are_rejected() -> None:
    policy, evaluation, event_schema = fixtures()
    policy["workflows"][0]["thresholds"] = {"warn": 40, "step_up": 40, "block": 90}
    errors = MODULE.semantic_errors(policy, evaluation, event_schema)
    assert any("strictly increasing" in error for error in errors)
