#!/usr/bin/env python3
"""Validate Runtime Trust evaluation/policy v1 synthetic contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[3]
POLICY_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_policy_v1.schema.json"
EVALUATION_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_evaluation_v1.schema.json"
EVENT_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_event_v1.schema.json"
POLICY_GOLDEN_PATH = ROOT / "schemas" / "examples" / "runtime_trust_policy_v1.json"
EVALUATION_GOLDEN_PATH = ROOT / "schemas" / "examples" / "runtime_trust_evaluation_v1.json"
MAX_JSON_BYTES = 256 * 1024


class RuntimeTrustPolicyError(ValueError):
    pass


def _reject_non_finite(value: str) -> None:
    raise RuntimeTrustPolicyError(f"non-finite JSON constant rejected: {value}")


def load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise RuntimeTrustPolicyError(f"JSON document exceeds {MAX_JSON_BYTES} bytes: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_non_finite)
    if not isinstance(value, dict):
        raise RuntimeTrustPolicyError(f"expected JSON object: {path}")
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def schema_errors(value: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    return [
        f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in errors
    ]


def semantic_errors(policy: dict[str, Any], evaluation: dict[str, Any], event_schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    workflows = policy.get("workflows") or []
    names = [item.get("workflow") for item in workflows if isinstance(item, dict)]
    if len(names) != len(set(names)):
        errors.append("workflow identifiers must be unique")
    for item in workflows:
        if not isinstance(item, dict):
            continue
        thresholds = item.get("thresholds") or {}
        values = [thresholds.get(name) for name in ("warn", "step_up", "block")]
        if all(isinstance(value, int) for value in values) and not values[0] < values[1] < values[2]:
            errors.append(f"workflow {item.get('workflow')} thresholds must be strictly increasing")
    try:
        issued_at = datetime.fromisoformat(policy["issued_at"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(policy["expires_at"].replace("Z", "+00:00"))
        if expires_at <= issued_at:
            errors.append("policy expires_at must be after issued_at")
        evaluated_at = datetime.fromisoformat(evaluation["evaluated_at"].replace("Z", "+00:00"))
        if not issued_at <= evaluated_at < expires_at:
            errors.append("evaluation evaluated_at must be within policy validity window")
    except (KeyError, TypeError, ValueError):
        pass
    if evaluation.get("policy_id") != policy.get("policy_id"):
        errors.append("evaluation policy_id does not match policy")
    if evaluation.get("policy_version") != policy.get("policy_version"):
        errors.append("evaluation policy_version does not match policy")
    if evaluation.get("policy_digest") != canonical_sha256(policy):
        errors.append("evaluation policy_digest does not match canonical policy")
    bundle = policy.get("detector_bundle") or {}
    if evaluation.get("detector_bundle_id") != bundle.get("bundle_id"):
        errors.append("evaluation detector_bundle_id does not match policy")
    if evaluation.get("detector_bundle_version") != bundle.get("bundle_version"):
        errors.append("evaluation detector_bundle_version does not match policy")
    enforcing_decisions = {"step_up", "block", "kill_session"}
    if policy.get("mode") == "enforce" and policy.get("signature_status") != "signed_verified":
        errors.append("enforce policy requires signed_verified signature status")
    if policy.get("mode") == "observe" and evaluation.get("decision") in enforcing_decisions:
        errors.append("observe policy cannot produce an enforcing decision")
    if policy.get("signature_status") != "signed_verified" and evaluation.get("decision") in enforcing_decisions:
        errors.append("unverified policy cannot produce an enforcing decision")
    if policy.get("mode") == "observe":
        behavior = policy.get("capability_behavior") or {}
        unsafe_behaviors = sorted(
            key for key, value in behavior.items() if value in {"step_up", "block"}
        )
        if unsafe_behaviors:
            errors.append(f"observe policy cannot configure enforcing capability behavior: {unsafe_behaviors}")
        unsafe_defaults = sorted(
            item.get("workflow")
            for item in workflows
            if item.get("default_decision") in {"step_up", "block"}
        )
        if unsafe_defaults:
            errors.append(f"observe policy cannot configure enforcing workflow defaults: {unsafe_defaults}")

    workflow_name = evaluation.get("workflow")
    matching_workflows = [item for item in workflows if item.get("workflow") == workflow_name]
    if len(matching_workflows) != 1:
        errors.append("evaluation workflow must resolve to exactly one policy workflow")
    else:
        workflow = matching_workflows[0]
        capability_state = evaluation.get("capability_state")
        signal_completeness = evaluation.get("signal_completeness")
        behavior = policy.get("capability_behavior") or {}
        if signal_completeness in {"missing_required", "unknown"}:
            expected_decision = behavior.get("on_missing_signal")
        elif capability_state == "degraded":
            expected_decision = behavior.get("on_degraded")
        elif capability_state == "unsupported":
            expected_decision = behavior.get("on_unsupported")
        else:
            score = evaluation.get("score")
            thresholds = workflow.get("thresholds") or {}
            if isinstance(score, int) and score >= thresholds.get("block", 101):
                expected_decision = "block"
            elif isinstance(score, int) and score >= thresholds.get("step_up", 101):
                expected_decision = "step_up"
            elif isinstance(score, int) and score >= thresholds.get("warn", 101):
                expected_decision = "warn"
            else:
                expected_decision = workflow.get("default_decision")
        if policy.get("mode") == "observe" and expected_decision in {"step_up", "block"}:
            expected_decision = "observe"
        if evaluation.get("decision") != expected_decision:
            errors.append(
                f"evaluation decision {evaluation.get('decision')} does not match policy-derived {expected_decision}"
            )
        expects_abstention = expected_decision == "abstain"
        if evaluation.get("abstained") is not expects_abstention:
            errors.append("evaluation abstained flag does not match policy-derived decision")
    if policy.get("rollback", {}).get("previous_policy_version") == policy.get("policy_version"):
        errors.append("rollback previous_policy_version cannot equal current policy_version")
    expected_ref = "https://schemas.tamandua.local/runtime_trust_evaluation_v1.schema.json"
    if event_schema.get("properties", {}).get("evaluation", {}).get("$ref") != expected_ref:
        errors.append("event evaluation must reference shared v1 evaluation schema")
    return errors


def validate(strict: bool = False) -> dict[str, Any]:
    policy_schema = load_json(POLICY_SCHEMA_PATH)
    evaluation_schema = load_json(EVALUATION_SCHEMA_PATH)
    event_schema = load_json(EVENT_SCHEMA_PATH)
    policy = load_json(POLICY_GOLDEN_PATH)
    evaluation = load_json(EVALUATION_GOLDEN_PATH)
    errors = schema_errors(policy, policy_schema)
    errors.extend(schema_errors(evaluation, evaluation_schema))
    errors.extend(semantic_errors(policy, evaluation, event_schema))
    if strict and policy.get("mode") != "observe":
        errors.append("strict synthetic policy must remain observe-only")
    if strict and (policy.get("external_claim_allowed") is not False or evaluation.get("external_claim_allowed") is not False):
        errors.append("strict synthetic policy/evaluation must keep external_claim_allowed=false")
    return {
        "schema": "tamandua.runtime_trust.policy_validation/v1",
        "ok": not errors,
        "evidence_class": "synthetic_contract",
        "external_claim_allowed": False,
        "policy_sha256": canonical_sha256(policy),
        "errors": errors,
        "non_claims": [
            "policy_signing_or_distribution",
            "runtime_writer_enabled",
            "server_ingestion",
            "enforcement",
            "physical_efficacy",
            "production_readiness"
        ]
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(strict=args.strict)
    except (OSError, json.JSONDecodeError, RuntimeTrustPolicyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
