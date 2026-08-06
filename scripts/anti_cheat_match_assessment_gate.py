#!/usr/bin/env python3
"""Validate the offline RT-GAME-001A match-assessment contract.

This gate evaluates synthetic metadata fixtures only. It does not connect to a
game server, execute an engine adapter, estimate a production false-positive
rate, or authorize enforcement.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
GATE_SOURCE_PATH = Path(__file__).resolve()
ASSESSMENT_SCHEMA_PATH = ROOT / "schemas/anti_cheat_match_assessment_v1.schema.json"
REPORT_SCHEMA_PATH = ROOT / "schemas/anti_cheat_match_assessment_report_v1.schema.json"
DEFAULT_FIXTURE_PATH = ROOT / "tools/detection_validation/fixtures/anti_cheat_match_assessment_synthetic_v1.json"
MAX_FIXTURE_BYTES = 1_048_576
MEDIAN_PAYLOAD_BUDGET = 4096
MAX_PAYLOAD_BUDGET = 16384
EXPECTED_SCENARIOS = ["clean", "local_only", "server_corroborated", "conflicting"]
EXPECTED_EXCLUDED_FIELDS = {
    "raw_input", "raw_chat", "screen_content", "raw_memory", "ip_address",
    "device_serial", "credentials", "email", "global_player_identifier",
}
FIXTURE_KEYS = {
    "schema", "evidence_class", "claim_boundary", "future_governed_fpr_gate",
    "tooling_performance_budget", "tenant_scope_digest", "policy_manifest",
    "policy_manifest_digest", "assessments",
}
CLAIM_BOUNDARY = {
    "fixture_only": True,
    "fpr_claimable": False,
    "engine_adapter_validated": False,
    "server_authority_authenticated": False,
    "live_server_validated": False,
    "enforcement_authorized": False,
    "external_claim_allowed": False,
}
POLICY_KEYS = {
    "schema", "policy_id", "policy_version", "score_orientation", "max_score",
    "review_threshold", "queue_review_requires_server_authoritative",
    "decision_rules", "rules",
}
DECISION_RULES = {
    "on_conflicting_or_inconclusive": "abstain",
    "on_corroborated_at_or_above_review_threshold": "queue_review",
    "otherwise": "observe",
}
POLICY_DOMAIN = b"tamandua.anti_cheat.scoring_policy/v1\0"
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
VERSION_BODY = (
    r"(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){0,3}"
    r"(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?(?:\+[a-z0-9]+(?:[.-][a-z0-9]+)*)?"
)
AUTHORITY_VERSION_RE = re.compile(rf"^auth-v{VERSION_BODY}$")
POLICY_VERSION_RE = re.compile(rf"^policy-v{VERSION_BODY}$")
MAX_VERSION_LENGTH = 96
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
URL_RE = re.compile(r"(?i)(?:\b(?:https?|ftp)://|\bwww\.)")
AUTH_SECRET_RE = re.compile(
    r"(?i)\b(?:authorization\s*[:=]|bearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[:=])"
)
GLOBAL_ID_RE = re.compile(r"(?i)\bglobal(?:[_ -]?(?:player|user|tenant))?[_ -]?id(?:entifier)?\b")
EXPECTED_REASON_CODES = {
    "client_integrity_anomaly", "server_action_sequence_valid",
    "server_action_sequence_violation", "server_movement_within_constraints",
    "server_movement_constraint_violation",
}
FORBIDDEN_IDENTIFIER_KEYS = {
    "game_id", "build_id", "match_id", "player_session_id", "tenant_id",
    "observation_id", "global_player_id", "global_player_identifier", "player_email", "email",
}
NORMALIZED_FORBIDDEN_IDENTIFIER_KEYS = {
    re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_") for key in FORBIDDEN_IDENTIFIER_KEYS
}
COMPACT_FORBIDDEN_IDENTIFIER_KEYS = {key.replace("_", "") for key in NORMALIZED_FORBIDDEN_IDENTIFIER_KEYS}
FEATURE_SCHEMA_BY_FAMILY = {
    family: f"tamandua.game.{family}_features/v1"
    for family in ("movement", "action", "economy", "temporal", "session_integrity")
}


class MatchAssessmentGateError(ValueError):
    """Raised when a closed contract or semantic invariant is violated."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MatchAssessmentGateError("duplicate JSON member rejected")
        result[key] = value
    return result


def load_json(path: Path, *, max_bytes: int = MAX_FIXTURE_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if not 1 <= len(raw) <= max_bytes or b"\x00" in raw:
        raise MatchAssessmentGateError("JSON document bounds are invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_closed_pairs, parse_constant=lambda _value: (_ for _ in ()).throw(MatchAssessmentGateError("non-finite JSON rejected")))
    except MatchAssessmentGateError:
        raise
    except Exception:
        raise MatchAssessmentGateError("JSON document is invalid") from None
    if type(value) is not dict:
        raise MatchAssessmentGateError("JSON document must be an object")
    return value, raw


def _schema_errors(value: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [error.message for error in sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))]


def _corroboration_state(assessment: dict[str, Any]) -> str:
    outcomes = {item["outcome"] for item in assessment["server_authority"]["observations"]}
    if {"corroborated", "not_corroborated"}.issubset(outcomes):
        return "conflicting"
    if "inconclusive" in outcomes:
        return "inconclusive"
    if "corroborated" in outcomes:
        return "corroborated"
    if "not_corroborated" in outcomes:
        return "not_corroborated"
    return "inconclusive"


def policy_manifest_digest(policy: dict[str, Any]) -> str:
    return sha256(POLICY_DOMAIN + canonical(policy))


def _version_is_valid(value: Any, domain: str) -> bool:
    if domain == "auth":
        pattern = AUTHORITY_VERSION_RE
    elif domain == "policy":
        pattern = POLICY_VERSION_RE
    else:
        return False
    return type(value) is str and len(value) <= MAX_VERSION_LENGTH and pattern.fullmatch(value) is not None


def _policy_errors(policy: Any) -> list[str]:
    if type(policy) is not dict or set(policy) != POLICY_KEYS:
        return ["policy manifest members are not closed"]
    errors: list[str] = []
    if policy.get("schema") != "tamandua.anti_cheat.scoring_policy/v1":
        errors.append("policy manifest schema is invalid")
    if not isinstance(policy.get("policy_id"), str) or re.fullmatch(r"[a-z][a-z0-9_.-]{1,127}", policy["policy_id"]) is None:
        errors.append("policy id is invalid")
    if not _version_is_valid(policy.get("policy_version"), "policy"):
        errors.append("policy version is invalid")
    if policy.get("score_orientation") != "higher_is_more_suspicious" or policy.get("max_score") != 100:
        errors.append("policy score contract is invalid")
    if not isinstance(policy.get("review_threshold"), int) or isinstance(policy.get("review_threshold"), bool) or not 1 <= policy["review_threshold"] <= 100:
        errors.append("policy review threshold is invalid")
    if policy.get("queue_review_requires_server_authoritative") is not True or policy.get("decision_rules") != DECISION_RULES:
        errors.append("policy decision contract is invalid")
    rules = policy.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 32 or any(type(rule) is not dict for rule in rules):
        return errors + ["policy rules are invalid"]
    identities: list[tuple[Any, ...]] = []
    for rule in rules:
        source = rule.get("source")
        if source == "client_integrity":
            if set(rule) != {"reason_code", "source", "client_state", "evidence_strength", "points"}:
                errors.append("client policy rule members are not closed")
                continue
            identity = (source, rule.get("reason_code"), rule.get("client_state"), rule.get("evidence_strength"))
            if rule.get("client_state") != "observed" or rule.get("evidence_strength") not in {"weak", "moderate", "strong", "unknown"}:
                errors.append("client policy rule selector is invalid")
        elif source == "server_authoritative":
            if set(rule) != {"reason_code", "source", "detector_family", "server_outcome", "points"}:
                errors.append("server policy rule members are not closed")
                continue
            identity = (source, rule.get("reason_code"), rule.get("detector_family"), rule.get("server_outcome"))
            if rule.get("server_outcome") != "corroborated" or rule.get("detector_family") not in {"movement", "action", "economy", "temporal", "session_integrity"}:
                errors.append("server policy rule selector is invalid")
        else:
            errors.append("policy rule source is invalid")
            continue
        if not isinstance(rule.get("reason_code"), str) or re.fullmatch(r"[a-z][a-z0-9_]{1,95}", rule["reason_code"]) is None:
            errors.append("policy reason code is invalid")
        elif rule["reason_code"] not in EXPECTED_REASON_CODES:
            errors.append("policy reason code is outside the closed vocabulary")
        if not isinstance(rule.get("points"), int) or isinstance(rule.get("points"), bool) or not 1 <= rule["points"] <= 100:
            errors.append("policy rule points are invalid")
        identities.append(identity)
    if len(identities) != len(set(identities)):
        errors.append("policy rule selectors must be unique")
    return errors


def _derived_contributions(assessment: dict[str, Any], policy: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    rules = policy["rules"]
    derived: list[dict[str, Any]] = []
    errors: list[str] = []
    for signal in assessment["client_integrity"]["signals"]:
        if signal["state"] != "observed":
            continue
        matches = [rule for rule in rules if rule["source"] == "client_integrity" and rule["reason_code"] == signal["reason_code"] and rule["client_state"] == signal["state"] and rule["evidence_strength"] == signal["evidence_strength"]]
        if len(matches) != 1:
            errors.append("observed client signal lacks one policy rule")
            continue
        derived.append({"source": "client_integrity", "reason_code": signal["reason_code"], "points": matches[0]["points"], "evidence_digest": signal["evidence_digest"]})
    for observation in assessment["server_authority"]["observations"]:
        if observation["outcome"] != "corroborated":
            continue
        matches = [rule for rule in rules if rule["source"] == "server_authoritative" and rule["reason_code"] == observation["reason_code"] and rule["detector_family"] == observation["detector_family"] and rule["server_outcome"] == observation["outcome"]]
        if len(matches) != 1:
            errors.append("corroborated server observation lacks one policy rule")
            continue
        derived.append({"source": "server_authoritative", "reason_code": observation["reason_code"], "points": matches[0]["points"], "evidence_digest": observation["evidence_digest"]})
    derived.sort(key=lambda item: (item["source"], item["reason_code"], item["evidence_digest"]))
    return derived, errors


def _duplicate_evidence_errors(assessment: dict[str, Any]) -> list[str]:
    signals = assessment["client_integrity"]["signals"]
    signal_ids = [item["signal_id"] for item in signals]
    signal_identities = [
        (item["reason_code"], item["state"], item["evidence_strength"], item["evidence_digest"])
        for item in signals
    ]
    observations = assessment["server_authority"]["observations"]
    observation_ids = [item["observation_id_digest"] for item in observations]
    observation_identities = [
        (item["detector_family"], item["outcome"], item["reason_code"], item["evidence_digest"])
        for item in observations
    ]
    supplied_contribution_identities = [
        (item["source"], item["reason_code"], item["evidence_digest"])
        for item in assessment["score"]["contributions"]
    ]
    errors: list[str] = []
    if len(signal_ids) != len(set(signal_ids)) or len(signal_identities) != len(set(signal_identities)):
        errors.append("duplicate client integrity signal rejected")
    if len(observation_ids) != len(set(observation_ids)) or len(observation_identities) != len(set(observation_identities)):
        errors.append("duplicate server observation rejected")
    if len(supplied_contribution_identities) != len(set(supplied_contribution_identities)):
        errors.append("duplicate supplied contribution rejected")
    return errors


def _semantic_errors(assessment: dict[str, Any], policy: dict[str, Any], expected_policy_digest: str) -> list[str]:
    errors: list[str] = []
    score = assessment["score"]
    observations = assessment["server_authority"]["observations"]

    if not _version_is_valid(assessment["server_authority"]["authority_version"], "auth"):
        errors.append("authority version is invalid")

    if assessment["server_authority"]["window"]["start_tick"] > assessment["server_authority"]["window"]["end_tick"]:
        errors.append("server authority window is reversed")
    if assessment["server_authority"]["window"]["end_tick"] > assessment["session"]["tick"]:
        errors.append("server authority window exceeds the assessment tick")
    for observation in observations:
        if observation["start_tick"] > observation["end_tick"]:
            errors.append("server observation tick window is reversed")
        if observation["start_tick"] < assessment["server_authority"]["window"]["start_tick"] or observation["end_tick"] > assessment["server_authority"]["window"]["end_tick"]:
            errors.append("server observation falls outside the authority window")
        if observation["feature_schema"] != FEATURE_SCHEMA_BY_FAMILY[observation["detector_family"]]:
            errors.append("server observation feature schema does not match detector family")

    computed_state = _corroboration_state(assessment)
    if assessment["server_authority"]["corroboration_state"] != computed_state:
        errors.append("server corroboration state is not recomputable")

    duplicate_errors = _duplicate_evidence_errors(assessment)
    if duplicate_errors:
        return errors + duplicate_errors

    if (score["policy_id"], score["policy_version"], score["policy_digest"], score["review_threshold"]) != (
        policy["policy_id"], policy["policy_version"], expected_policy_digest, policy["review_threshold"]
    ):
        errors.append("assessment score is not bound to the policy manifest")
    derived, derivation_errors = _derived_contributions(assessment, policy)
    errors.extend(derivation_errors)
    derived_identities = [
        (item["source"], item["reason_code"], item["evidence_digest"]) for item in derived
    ]
    if len(derived_identities) != len(set(derived_identities)):
        errors.append("duplicate derived contribution rejected")
    if score["contributions"] != derived:
        errors.append("score contributions are not policy-derived")
    if score["value"] != min(policy["max_score"], sum(item["points"] for item in derived)):
        errors.append("suspicion score is not recomputable")
    computed_reasons = sorted({item["reason_code"] for item in derived})
    if score["reasons"] != computed_reasons:
        errors.append("score reasons are not recomputable")
    has_server_contribution = any(item["source"] == "server_authoritative" for item in derived)
    if computed_state in {"conflicting", "inconclusive"}:
        expected_decision = "abstain"
    elif computed_state == "corroborated" and has_server_contribution and score["value"] >= policy["review_threshold"]:
        expected_decision = "queue_review"
    else:
        expected_decision = "observe"
    if assessment["decision"] != expected_decision:
        errors.append("decision is not recomputable")
    expected_review_status = "pending" if expected_decision == "queue_review" else "not_queued"
    if assessment["review"]["status"] != expected_review_status:
        errors.append("review status does not match the recomputed decision")
    if assessment["decision"] == "queue_review" and not has_server_contribution:
        errors.append("queue_review requires server-authoritative corroboration")
    if set(assessment["privacy"]["excluded_fields"]) != EXPECTED_EXCLUDED_FIELDS:
        errors.append("privacy exclusions are not the closed required set")
    return errors


def _identifier_privacy_errors(value: Any, path: str = "fixture") -> list[str]:
    errors: list[str] = []
    if type(value) is dict:
        for key, member in value.items():
            member_path = f"{path}.{key}"
            normalized_key = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
            compact_key = normalized_key.replace("_", "")
            if normalized_key in NORMALIZED_FORBIDDEN_IDENTIFIER_KEYS or compact_key in COMPACT_FORBIDDEN_IDENTIFIER_KEYS or (
                "global" in normalized_key and ("id" in normalized_key or "identifier" in normalized_key)
            ):
                errors.append(f"raw or global identifier member rejected at {member_path}")
            if normalized_key in {
                "authorization", "access_token", "refresh_token", "api_key", "password", "secret"
            }:
                errors.append(f"authorization or secret member rejected at {member_path}")
            errors.extend(_identifier_privacy_errors(member, member_path))
    elif type(value) is list:
        if path.endswith(".excluded_fields"):
            return errors
        for index, member in enumerate(value):
            errors.extend(_identifier_privacy_errors(member, f"{path}[{index}]"))
    elif type(value) is str:
        if EMAIL_RE.search(value):
            errors.append(f"email-shaped value rejected at {path}")
        if _contains_ip_address(value):
            errors.append(f"IP address value rejected at {path}")
        if URL_RE.search(value):
            errors.append(f"URL value rejected at {path}")
        if GLOBAL_ID_RE.search(value):
            errors.append(f"global identifier value rejected at {path}")
        if AUTH_SECRET_RE.search(value):
            errors.append(f"authorization or secret value rejected at {path}")
    return errors


def _contains_ip_address(value: str) -> bool:
    """Recognize IPv4/IPv6 literals without treating arbitrary version strings as IPs."""
    tokens = re.split(r"[\s,;(){}<>\[\]\"'=/]+", value)
    for raw_token in tokens:
        token = raw_token.strip().strip(".,")
        if not token:
            continue
        if "%" in token:
            token = token.split("%", 1)[0]
        if token.count(":") == 1 and token.count(".") == 3:
            host, port = token.rsplit(":", 1)
            if port.isdigit():
                token = host
        if ":" not in token and token.count(".") != 3:
            continue
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        return True
    return False


def _validate_fixture_contract(
    fixture: dict[str, Any],
) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, Any], str, str, bool]:
    if set(fixture) != FIXTURE_KEYS:
        raise MatchAssessmentGateError("fixture members are not closed")
    if fixture["schema"] != "tamandua.anti_cheat.match_assessment_fixture/v1" or fixture["evidence_class"] != "synthetic_contract":
        raise MatchAssessmentGateError("fixture identity is invalid")
    if fixture["claim_boundary"] != CLAIM_BOUNDARY:
        raise MatchAssessmentGateError("fixture claim boundary is invalid")
    tenant_scope_digest = fixture["tenant_scope_digest"]
    if type(tenant_scope_digest) is not str or DIGEST_RE.fullmatch(tenant_scope_digest) is None:
        raise MatchAssessmentGateError("fixture tenant scope digest is invalid")
    policy = fixture["policy_manifest"]
    policy_errors = _policy_errors(policy)
    if policy_errors:
        raise MatchAssessmentGateError(policy_errors[0])
    expected_policy_digest = policy_manifest_digest(policy)
    if fixture["policy_manifest_digest"] != expected_policy_digest:
        raise MatchAssessmentGateError("policy manifest digest is not recomputable")
    expected_fpr = {"method": "clopper_pearson", "one_sided_confidence": 0.95, "upper_bound_max": 0.005, "zero_failure_minimum_per_stratum": 598}
    if fixture["future_governed_fpr_gate"] != expected_fpr:
        raise MatchAssessmentGateError("future governed FPR gate is invalid")
    computed_minimum = math.ceil(math.log(1 - expected_fpr["one_sided_confidence"]) / math.log(1 - expected_fpr["upper_bound_max"]))
    if computed_minimum != expected_fpr["zero_failure_minimum_per_stratum"]:
        raise MatchAssessmentGateError("future governed FPR sample floor is invalid")
    if fixture["tooling_performance_budget"] != {"iterations": 10000, "p95_ms": 10.0, "product_or_engine_performance_claim": False}:
        raise MatchAssessmentGateError("tooling performance budget is invalid")
    entries = fixture["assessments"]
    if type(entries) is not list or len(entries) != 4:
        raise MatchAssessmentGateError("fixture must contain exactly four assessments")
    if any(type(item) is not dict or set(item) != {"scenario", "assessment"} for item in entries):
        raise MatchAssessmentGateError("fixture assessment entries are not closed")
    pairs = [(item["scenario"], item["assessment"]) for item in entries]
    if [scenario for scenario, _assessment in pairs] != EXPECTED_SCENARIOS:
        raise MatchAssessmentGateError("fixture scenario coverage or ordering is invalid")
    privacy_errors = _identifier_privacy_errors(fixture)
    privacy_closed = not privacy_errors
    if privacy_errors:
        raise MatchAssessmentGateError(privacy_errors[0])
    return pairs, policy, expected_policy_digest, tenant_scope_digest, privacy_closed


def _tooling_performance(
    assessments: list[dict[str, Any]], policy: dict[str, Any],
    policy_digest: str, iterations: int, budget_ms: float,
) -> bool:
    durations: list[int] = []
    for index in range(iterations):
        assessment = assessments[index % len(assessments)]
        started = time.perf_counter_ns()
        errors = _semantic_errors(assessment, policy, policy_digest)
        elapsed = time.perf_counter_ns() - started
        if errors:
            raise MatchAssessmentGateError("tooling benchmark encountered an invalid assessment")
        durations.append(elapsed)
    durations.sort()
    p95_ns = durations[math.ceil(len(durations) * 0.95) - 1]
    return p95_ns <= budget_ms * 1_000_000


def _report(
    fixture_raw: bytes, schema_raw: bytes, report_schema_raw: bytes,
    pairs: list[tuple[str, dict[str, Any]]],
    tooling_within_budget: bool, tenant_scope_digest: str, policy_manifest_digest_value: str,
    privacy_closed: bool,
) -> dict[str, Any]:
    assessments = [assessment for _scenario, assessment in pairs]
    sizes = sorted(len(canonical(assessment)) for assessment in assessments)
    median_bytes = sizes[len(sizes) // 2]
    maximum = sizes[-1]
    counts = Counter(assessment["decision"] for assessment in assessments)
    basis: dict[str, Any] = {
        "schema": "tamandua.anti_cheat.match_assessment_report/v1",
        "fixture_sha256": sha256(fixture_raw),
        "assessment_schema_sha256": sha256(schema_raw),
        "report_schema_sha256": sha256(report_schema_raw),
        "gate_source_sha256": sha256(GATE_SOURCE_PATH.read_bytes()),
        "tenant_scope_digest": tenant_scope_digest,
        "policy_manifest_digest": policy_manifest_digest_value,
        "evidence_class": "synthetic_contract",
        "counts": {"total": len(assessments), "observe": counts["observe"], "queue_review": counts["queue_review"], "abstain": counts["abstain"]},
        "scenario_coverage": [scenario for scenario, _assessment in pairs],
        "payload_size": {"median_bytes": median_bytes, "max_bytes": maximum, "median_budget_bytes": MEDIAN_PAYLOAD_BUDGET, "max_budget_bytes": MAX_PAYLOAD_BUDGET, "within_budget": median_bytes <= MEDIAN_PAYLOAD_BUDGET and maximum <= MAX_PAYLOAD_BUDGET},
        "tooling_performance": {"measurement_class": "local_semantic_evaluator_tooling_smoke", "iterations": 10000, "p95_budget_ms": 10.0, "p95_bucket": "le_10ms", "within_budget": tooling_within_budget, "product_or_engine_performance_claim": False},
        "fpr": {"claimable": False, "observed_rate": None, "reason": "synthetic_fixture_cannot_estimate_false_positive_rate", "future_governed_method": "clopper_pearson", "future_one_sided_confidence": 0.95, "future_upper_bound_max": 0.005, "zero_failure_minimum_per_stratum": 598},
        "gates": {"schema_valid": True, "score_recomputable": True, "reasons_recomputable": True, "server_required_for_review": True, "conflict_abstains": True, "privacy_closed": privacy_closed, "no_destructive_output": True, "synthetic_no_fpr_claim": True, "deterministic": True},
        "claims": {"enforcement_authorized": False, "durable_sanction": False, "engine_adapter_validated": False, "server_authority_authenticated": False, "live_server_validated": False, "production_fpr_validated": False, "external_claim_allowed": False},
    }
    report_id = sha256(b"tamandua.anti_cheat.match_assessment_report/v1\0" + canonical(basis))
    return {"report_id": report_id, **basis}


def validate_gate(fixture_path: Path = DEFAULT_FIXTURE_PATH) -> dict[str, Any]:
    fixture, fixture_raw = load_json(fixture_path)
    assessment_schema, schema_raw = load_json(ASSESSMENT_SCHEMA_PATH)
    report_schema, report_schema_raw = load_json(REPORT_SCHEMA_PATH)
    pairs, policy, policy_digest, tenant_scope_digest, privacy_closed = _validate_fixture_contract(fixture)
    assessment_ids: list[str] = []
    session_ids: list[tuple[str, str]] = []
    for _scenario, assessment in pairs:
        schema_errors = _schema_errors(assessment, assessment_schema)
        if schema_errors:
            raise MatchAssessmentGateError("assessment schema validation failed")
        if assessment["tenant_scope_digest"] != tenant_scope_digest:
            raise MatchAssessmentGateError("mixed tenant scope rejected")
        semantic_errors = _semantic_errors(assessment, policy, policy_digest)
        if semantic_errors:
            raise MatchAssessmentGateError(semantic_errors[0])
        assessment_ids.append(assessment["assessment_id"])
        session_ids.append((assessment["session"]["match_id_digest"], assessment["session"]["player_session_id_digest"]))
    if len(assessment_ids) != len(set(assessment_ids)) or len(session_ids) != len(set(session_ids)):
        raise MatchAssessmentGateError("fixture assessment or player-session identities are duplicated")
    assessments = [assessment for _scenario, assessment in pairs]
    tooling_ok = _tooling_performance(assessments, policy, policy_digest, 10000, 10.0)
    if not tooling_ok:
        raise MatchAssessmentGateError("local validator tooling p95 exceeds its 10 ms smoke budget")
    report = _report(
        fixture_raw, schema_raw, report_schema_raw, pairs, tooling_ok,
        tenant_scope_digest, policy_digest, privacy_closed,
    )
    if report["payload_size"]["within_budget"] is not True:
        raise MatchAssessmentGateError("assessment payload size budget exceeded")
    if _report(
        fixture_raw, schema_raw, report_schema_raw, pairs, tooling_ok,
        tenant_scope_digest, policy_digest, privacy_closed,
    ) != report:
        raise MatchAssessmentGateError("report construction is not deterministic")
    if _schema_errors(report, report_schema):
        raise MatchAssessmentGateError("gate report schema validation failed")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE_PATH)
    args = parser.parse_args(argv)
    try:
        report = validate_gate(args.fixture)
    except (OSError, MatchAssessmentGateError) as error:
        print(f"anti-cheat match assessment gate failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
