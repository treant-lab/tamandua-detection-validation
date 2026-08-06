#!/usr/bin/env python3
"""Validate the synthetic anti-cheat sanction and appeal governance tabletop."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tools/detection_validation/fixtures/anti_cheat_sanction_appeal_synthetic_v1.json"
DECISION_SCHEMA = ROOT / "schemas/anti_cheat_sanction_decision_v1.schema.json"
APPEAL_SCHEMA = ROOT / "schemas/anti_cheat_appeal_case_v1.schema.json"
MATCH_FIXTURE = ROOT / "tools/detection_validation/fixtures/anti_cheat_match_assessment_synthetic_v1.json"
MATCH_GATE = ROOT / "tools/detection_validation/scripts/anti_cheat_match_assessment_gate.py"
POLICY_FIXTURE = ROOT / "tools/detection_validation/fixtures/anti_cheat_game_policy_authority_synthetic_v1.json"
POLICY_GATE = ROOT / "tools/detection_validation/scripts/anti_cheat_game_policy_authority_gate.py"
ASSESSMENT_DOMAIN = b"tamandua.anti_cheat.governance_assessment_binding/v1\0"
DECISION_ID_DOMAIN = b"tamandua.anti_cheat.sanction_decision_id/v1\0"
DECISION_DOMAIN = b"tamandua.anti_cheat.sanction_decision/v1\0"
CASE_ID_DOMAIN = b"tamandua.anti_cheat.appeal_case_id/v1\0"
CASE_DOMAIN = b"tamandua.anti_cheat.appeal_case/v1\0"
AUDIT_DOMAIN = b"tamandua.anti_cheat.governance_audit_event/v1\0"
REPORT_DOMAIN = b"tamandua.anti_cheat.governance_readiness/v1\0"
ROSTER_DOMAIN = b"tamandua.anti_cheat.governance_human_roster/v1\0"
AUTHORIZED_PROPOSERS = {"a" * 64}
AUTHORIZED_APPROVERS = {"b" * 64, "c" * 64}
AUTHORIZED_REVIEWERS = {"e" * 64}
RESTRICTIVE_ACTIONS = {"temporary_restriction", "permanent_sanction"}
EXPECTED_SCENARIOS = {
    "abuse", "mistaken_clean_mod_accessibility", "compromised_moderator",
    "duplicate_replay", "cross_tenant", "expiry_deletion", "uphold",
}
FORBIDDEN_PARTS = {
    "raw", "name", "email", "phone", "address", "ip", "device", "serial",
    "secret", "password", "credential", "token", "cookie", "authorization",
}


class GovernanceError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def roster_digest(role: str, members: set[str]) -> str:
    return sha256(ROSTER_DOMAIN + canonical({"role": role, "members": sorted(members)}))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise GovernanceError("duplicate_json_member")
        value[key] = member
    return value


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if not 1 <= len(raw) <= 2_000_000 or b"\0" in raw:
        raise GovernanceError("json_bounds_invalid")
    value = json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_float=lambda _v: (_ for _ in ()).throw(GovernanceError("floating_point_rejected")),
        parse_constant=lambda _v: (_ for _ in ()).throw(GovernanceError("non_finite_rejected")),
    )
    if type(value) is not dict:
        raise GovernanceError("json_root_invalid")
    return value, raw


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise GovernanceError("source_gate_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _source_authority() -> tuple[dict[str, str], dict[str, str]]:
    match_fixture = json.loads(MATCH_FIXTURE.read_bytes(), object_pairs_hook=_pairs)
    assessment = next(
        item["assessment"] for item in match_fixture["assessments"]
        if item["scenario"] == "server_corroborated"
    )
    match_gate = _load_module("tamandua_game001_gate", MATCH_GATE)
    match_report = match_gate.validate_gate(MATCH_FIXTURE)
    policy_gate = _load_module("tamandua_game003_gate", POLICY_GATE)
    policy_document, _ = policy_gate.load_json(POLICY_FIXTURE)
    policy_report = policy_gate.verify_authority(policy_document, 1780000100)
    bindings = {
        "game_001_assessment_digest": sha256(ASSESSMENT_DOMAIN + canonical(assessment)),
        "game_001_report_digest": match_report["report_id"],
        "game_003_policy_digest": policy_report["policy_digest"],
        "game_003_report_digest": policy_report["report_digest"],
    }
    scope = {
        "tenant_digest": assessment["tenant_scope_digest"],
        "game_digest": assessment["protected_target"]["game_id_digest"],
        "build_digest": assessment["protected_target"]["build_id_digest"],
        "match_digest": assessment["session"]["match_id_digest"],
        "player_digest": assessment["session"]["player_pseudonym_digest"],
    }
    return bindings, scope


def privacy_errors(value: Any, path: str = "fixture") -> list[str]:
    errors: list[str] = []
    if type(value) is dict:
        for key, member in value.items():
            parts = set(filter(None, re.sub(r"[^a-z0-9]+", "_", key.casefold()).split("_")))
            if parts & FORBIDDEN_PARTS:
                errors.append(f"privacy_forbidden_member:{path}.{key}")
            errors.extend(privacy_errors(member, f"{path}.{key}"))
    elif type(value) is list:
        for index, member in enumerate(value):
            errors.extend(privacy_errors(member, f"{path}[{index}]"))
    elif type(value) is float:
        errors.append(f"privacy_float:{path}")
    elif type(value) is str and re.search(r"(?i)(?:bearer|basic)\s+|(?:password|secret|token)\s*[:=]", value):
        errors.append(f"privacy_secret_shape:{path}")
    return errors


def decision_identity_basis(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: document[key]
        for key in (
            "idempotency_key_digest", "scope", "source_bindings", "action",
            "evidence_class", "reason_codes", "evidence_refs", "policy_version",
            "requested_at_unix", "appeal_case_id",
        )
    }


def expected_decision_id(document: dict[str, Any]) -> str:
    return sha256(DECISION_ID_DOMAIN + canonical(decision_identity_basis(document)))


def decision_digest(document: dict[str, Any]) -> str:
    return sha256(DECISION_DOMAIN + canonical(document))


def expected_case_id(document: dict[str, Any]) -> str:
    basis = {
        "decision_id": document["decision_id"], "scope": document["scope"],
        "appellant_digest": document["appellant_digest"],
        "opened_at_unix": document["opened_at_unix"],
    }
    return sha256(CASE_ID_DOMAIN + canonical(basis))


def case_digest(document: dict[str, Any]) -> str:
    return sha256(CASE_DOMAIN + canonical(document))


def expected_audit_digest(kind: str, document: dict[str, Any]) -> str:
    body = {key: value for key, value in document.items() if key != "audit"}
    basis = {
        "kind": kind,
        "sequence": document["audit"]["sequence"],
        "prior_event_digest": document["audit"]["prior_event_digest"],
        "body": body,
    }
    return sha256(AUDIT_DOMAIN + canonical(basis))


@dataclass
class CaseState:
    decision_heads: dict[tuple[str, ...], tuple[int, str, dict[str, Any]]] = field(default_factory=dict)
    decisions: dict[str, tuple[str, dict[str, Any]]] = field(default_factory=dict)
    idempotency: dict[str, bytes] = field(default_factory=dict)
    appeal_heads: dict[str, tuple[int, str, str, dict[str, Any]]] = field(default_factory=dict)
    audit_sequence: int = 0
    audit_digest: str | None = None


def _scope_key(scope: dict[str, str]) -> tuple[str, ...]:
    return tuple(scope[key] for key in ("tenant_digest", "game_digest", "build_digest", "match_digest", "player_digest"))


def _validate_audit(kind: str, document: dict[str, Any], state: CaseState) -> None:
    audit = document["audit"]
    if audit["sequence"] != state.audit_sequence + 1 or audit["prior_event_digest"] != state.audit_digest:
        raise GovernanceError("audit_chain_conflict")
    if audit["event_digest"] != expected_audit_digest(kind, document):
        raise GovernanceError("audit_digest_mismatch")


def _audit(kind: str, document: dict[str, Any], state: CaseState) -> None:
    document["audit"] = {
        "sequence": state.audit_sequence + 1,
        "prior_event_digest": state.audit_digest,
        "event_digest": "0" * 64,
    }
    document["audit"]["event_digest"] = expected_audit_digest(kind, document)


def _make_decision(
    variant: str, state: CaseState, bindings: dict[str, str], scope: dict[str, str],
    context: dict[str, Any],
) -> dict[str, Any]:
    if variant == "repeat_last":
        return copy.deepcopy(context["last_decision"])
    if variant == "idempotency_conflict":
        document = copy.deepcopy(context["last_decision"])
        document["action"] = "manual_review"
        return document
    actions = {
        "permanent_abuse": "permanent_sanction",
        "temporary_mistake": "temporary_restriction",
        "compromised_moderator": "permanent_sanction",
        "temporary_cross_tenant": "temporary_restriction",
        "temporary_expiry": "temporary_restriction",
        "temporary_uphold": "temporary_restriction",
        "appeal_reversal": "reverse",
    }
    if variant not in actions:
        raise GovernanceError("decision_variant_invalid")
    action = actions[variant]
    scope_key = _scope_key(scope)
    head = state.decision_heads.get(scope_key)
    version = 1 if head is None else head[0] + 1
    appeal_case_id = None
    if action == "reverse":
        appeal_case_id = next(iter(state.appeal_heads), None)
    approvers = ["b" * 64, "c" * 64] if action == "permanent_sanction" else (["b" * 64] if action == "temporary_restriction" else [])
    proposer = "a" * 64
    if variant == "compromised_moderator":
        approvers = [proposer, "c" * 64]
    reasons = {
        "permanent_abuse": ["server_movement_violation", "server_action_violation"],
        "temporary_mistake": ["server_movement_violation"],
        "compromised_moderator": ["moderator_compromise", "server_movement_violation"],
        "temporary_cross_tenant": ["server_action_violation"],
        "temporary_expiry": ["server_movement_violation"],
        "temporary_uphold": ["server_action_violation"],
        "appeal_reversal": ["appeal_reversal", "clean_behavior", "approved_mod", "accessibility_tool"],
    }[variant]
    requested = 1780000200 + (version - 1) * 100
    document: dict[str, Any] = {
        "schema": "tamandua.anti_cheat.sanction_decision/v1",
        "decision_id": "0" * 64,
        "decision_version": version,
        "prior_decision_digest": None if head is None else head[1],
        "appeal_case_id": appeal_case_id,
        "idempotency_key_digest": sha256(f"{variant}:{version}".encode()),
        "scope": copy.deepcopy(scope),
        "source_bindings": copy.deepcopy(bindings),
        "action": action,
        "evidence_class": "corroborated_synthetic",
        "reason_codes": reasons,
        "evidence_refs": [sha256(f"evidence:{variant}".encode())],
        "policy_version": "1",
        "requested_at_unix": requested,
        "expires_at_unix": None if action in {"permanent_sanction", "reverse"} else requested + 3600,
        "human_review": {"required": action in RESTRICTIVE_ACTIONS, "proposer_digest": proposer, "approver_digests": approvers, "authorized_roster_digest": roster_digest("sanction_approver", AUTHORIZED_APPROVERS), "separation_of_duties": True},
        "appeal_entitlement": {"entitled": True, "deadline_unix": 1780500000, "sla_hours": 72, "channel": "in_product"},
        "retention": {"region": "br", "window_days": 30, "delete_after_unix": 1781000000, "legal_hold": False},
        "audit": {},
        "claims": {"enforcement_executed": False, "durable_state_written": False, "production_ready": False, "external_claim_allowed": False},
    }
    document["decision_id"] = expected_decision_id(document)
    _audit("decision", document, state)
    return document


def _original_appeal_decision(state: CaseState) -> tuple[str, dict[str, Any]]:
    if state.appeal_heads:
        appeal = next(iter(state.appeal_heads.values()))[3]
        return state.decisions[appeal["decision_id"]]
    candidates = [entry for entry in state.decisions.values() if entry[1]["action"] in RESTRICTIVE_ACTIONS]
    if not candidates:
        raise GovernanceError("appeal_decision_missing")
    return candidates[-1]


def _make_appeal(variant: str, state: CaseState, context: dict[str, Any]) -> dict[str, Any]:
    if variant not in {"open", "review", "reverse", "uphold", "cross_tenant_open", "expired_open", "deleted_open"}:
        raise GovernanceError("appeal_variant_invalid")
    decision_digest_value, decision = _original_appeal_decision(state)
    head = next(iter(state.appeal_heads.values()), None)
    version = 1 if head is None else head[0] + 1
    opened = 1780000300
    if variant == "expired_open":
        opened = decision["appeal_entitlement"]["deadline_unix"] + 1
    elif variant == "deleted_open":
        opened = decision["retention"]["delete_after_unix"] + 1
    status = variant if variant in {"review", "reverse", "uphold"} else "open"
    result = {"reverse": "reversed", "uphold": "upheld"}.get(status, "pending")
    document: dict[str, Any] = {
        "schema": "tamandua.anti_cheat.appeal_case/v1",
        "case_id": "0" * 64 if head is None else head[3]["case_id"],
        "case_version": version,
        "prior_case_digest": None if head is None else head[1],
        "decision_id": decision["decision_id"],
        "decision_digest": decision_digest_value,
        "scope": copy.deepcopy(decision["scope"]),
        "status": status,
        "opened_at_unix": opened if head is None else head[3]["opened_at_unix"],
        "updated_at_unix": opened + (version - 1) * 60,
        "sla_due_at_unix": opened + 72 * 3600,
        "appellant_digest": "d" * 64,
        "reviewer_digest": None if status == "open" else "e" * 64,
        "reviewer_roster_digest": roster_digest("appeal_reviewer", AUTHORIZED_REVIEWERS),
        "reason_codes": {
            "open": ["mistaken_identity"],
            "review": ["clean_behavior", "approved_mod", "accessibility_tool"],
            "reverse": ["sanction_reversed", "clean_behavior", "approved_mod", "accessibility_tool"],
            "uphold": ["sanction_upheld"],
        }[status],
        "evidence_refs": [sha256(f"appeal:{variant}".encode())],
        "outcome": {
            "result": result,
            "reversal_decision_id": None,
            "remediation_actions": [],
            "deletion_due_at_unix": decision["retention"]["delete_after_unix"],
        },
        "retention": copy.deepcopy(decision["retention"]),
        "audit": {},
        "claims": {"enforcement_executed": False, "durable_state_written": False, "production_ready": False, "external_claim_allowed": False},
    }
    if head is None:
        document["case_id"] = expected_case_id(document)
    if variant == "cross_tenant_open":
        document["scope"]["tenant_digest"] = "f" * 64
    if status == "reverse":
        reversal = state.decision_heads[_scope_key(decision["scope"])][2]
        document["outcome"]["reversal_decision_id"] = reversal["decision_id"]
        document["outcome"]["remediation_actions"] = ["restore_access", "remove_restriction", "annotate_false_positive", "delete_eligible_evidence"]
    _audit("appeal", document, state)
    return document


def _schema_validate(document: dict[str, Any], schema: dict[str, Any], code: str) -> None:
    if list(Draft202012Validator(schema).iter_errors(document)):
        raise GovernanceError(code)


def apply_decision(
    document: dict[str, Any], state: CaseState, bindings: dict[str, str], scope: dict[str, str],
    schema: dict[str, Any],
) -> str:
    _schema_validate(document, schema, "decision_schema_invalid")
    errors = privacy_errors(document, "decision")
    if errors:
        raise GovernanceError(errors[0])
    if document["source_bindings"] != bindings:
        raise GovernanceError("source_binding_mismatch")
    if document["scope"] != scope:
        raise GovernanceError("cross_scope_rejected")
    canonical_document = canonical(document)
    prior_idempotent = state.idempotency.get(document["idempotency_key_digest"])
    if prior_idempotent is not None:
        if prior_idempotent == canonical_document:
            return "idempotent_duplicate"
        raise GovernanceError("idempotency_conflict")
    if document["decision_id"] != expected_decision_id(document):
        raise GovernanceError("decision_id_mismatch")
    if document["requested_at_unix"] > document["retention"]["delete_after_unix"]:
        raise GovernanceError("retention_expired")
    expires = document["expires_at_unix"]
    if expires is not None and expires <= document["requested_at_unix"]:
        raise GovernanceError("decision_expiry_invalid")
    action = document["action"]
    review = document["human_review"]
    if action in RESTRICTIVE_ACTIONS and document["evidence_class"] in {"single_local", "inconclusive"}:
        raise GovernanceError("insufficient_evidence_for_restriction")
    if action in RESTRICTIVE_ACTIONS and (not review["required"] or not review["approver_digests"]):
        raise GovernanceError("human_approval_required")
    if review["proposer_digest"] in review["approver_digests"]:
        raise GovernanceError("separation_of_duties_failed")
    if review["proposer_digest"] not in AUTHORIZED_PROPOSERS:
        raise GovernanceError("unauthorized_proposer")
    if review["authorized_roster_digest"] != roster_digest("sanction_approver", AUTHORIZED_APPROVERS) or not set(review["approver_digests"]).issubset(AUTHORIZED_APPROVERS):
        raise GovernanceError("unauthorized_approver")
    if action == "permanent_sanction" and len(review["approver_digests"]) != 2:
        raise GovernanceError("two_approvers_required")
    if action != "reverse" and document["appeal_case_id"] is not None:
        raise GovernanceError("unexpected_appeal_binding")
    if action == "reverse":
        appeal_id = document["appeal_case_id"]
        appeal_head = state.appeal_heads.get(appeal_id or "")
        if appeal_head is None or appeal_head[2] != "review":
            raise GovernanceError("appeal_not_in_review")
        if "appeal_reversal" not in document["reason_codes"]:
            raise GovernanceError("reversal_reason_required")
    key = _scope_key(document["scope"])
    head = state.decision_heads.get(key)
    if head is None:
        if document["decision_version"] != 1 or document["prior_decision_digest"] is not None:
            raise GovernanceError("decision_version_conflict")
    elif document["decision_version"] != head[0] + 1 or document["prior_decision_digest"] != head[1]:
        raise GovernanceError("decision_version_conflict")
    _validate_audit("decision", document, state)
    digest = decision_digest(document)
    state.idempotency[document["idempotency_key_digest"]] = canonical_document
    state.decisions[document["decision_id"]] = (digest, document)
    state.decision_heads[key] = (document["decision_version"], digest, document)
    state.audit_sequence = document["audit"]["sequence"]
    state.audit_digest = document["audit"]["event_digest"]
    return "accepted"


def apply_appeal(document: dict[str, Any], state: CaseState, schema: dict[str, Any]) -> str:
    _schema_validate(document, schema, "appeal_schema_invalid")
    errors = privacy_errors(document, "appeal")
    if errors:
        raise GovernanceError(errors[0])
    decision_entry = state.decisions.get(document["decision_id"])
    if decision_entry is None or decision_entry[0] != document["decision_digest"]:
        raise GovernanceError("decision_binding_mismatch")
    decision = decision_entry[1]
    if document["scope"] != decision["scope"]:
        raise GovernanceError("cross_scope_rejected")
    if document["case_id"] != expected_case_id(document):
        raise GovernanceError("case_id_mismatch")
    if document["opened_at_unix"] > decision["retention"]["delete_after_unix"] and not decision["retention"]["legal_hold"]:
        raise GovernanceError("appeal_evidence_deleted")
    if document["opened_at_unix"] > decision["appeal_entitlement"]["deadline_unix"]:
        raise GovernanceError("appeal_entitlement_expired")
    if document["updated_at_unix"] > document["sla_due_at_unix"]:
        raise GovernanceError("appeal_sla_expired")
    if document["retention"] != decision["retention"]:
        raise GovernanceError("retention_binding_mismatch")
    status = document["status"]
    head = state.appeal_heads.get(document["case_id"])
    if head is None:
        if document["case_version"] != 1 or document["prior_case_digest"] is not None or status != "open":
            raise GovernanceError("appeal_version_conflict")
        if document["reviewer_digest"] is not None or document["outcome"]["result"] != "pending":
            raise GovernanceError("appeal_open_state_invalid")
    else:
        allowed = {"open": {"review"}, "review": {"uphold", "reverse"}, "uphold": set(), "reverse": set()}
        if (
            document["case_version"] != head[0] + 1
            or document["prior_case_digest"] != head[1]
            or status not in allowed[head[2]]
            or document["opened_at_unix"] != head[3]["opened_at_unix"]
        ):
            raise GovernanceError("appeal_version_conflict")
    reviewer = document["reviewer_digest"]
    barred = {document["appellant_digest"], decision["human_review"]["proposer_digest"], *decision["human_review"]["approver_digests"]}
    if status != "open" and (reviewer is None or reviewer in barred):
        raise GovernanceError("independent_reviewer_required")
    if document["reviewer_roster_digest"] != roster_digest("appeal_reviewer", AUTHORIZED_REVIEWERS) or (reviewer is not None and reviewer not in AUTHORIZED_REVIEWERS):
        raise GovernanceError("unauthorized_reviewer")
    outcome = document["outcome"]
    if status in {"open", "review"} and (outcome["result"] != "pending" or outcome["reversal_decision_id"] is not None or outcome["remediation_actions"]):
        raise GovernanceError("appeal_pending_state_invalid")
    if status == "uphold" and (outcome["result"] != "upheld" or outcome["reversal_decision_id"] is not None or "sanction_upheld" not in document["reason_codes"]):
        raise GovernanceError("appeal_uphold_state_invalid")
    if status == "reverse":
        reversal = state.decisions.get(outcome["reversal_decision_id"] or "")
        required = {"restore_access", "remove_restriction", "annotate_false_positive", "delete_eligible_evidence"}
        if (
            outcome["result"] != "reversed" or reversal is None
            or reversal[1]["action"] != "reverse"
            or reversal[1]["appeal_case_id"] != document["case_id"]
            or not required.issubset(outcome["remediation_actions"])
            or "sanction_reversed" not in document["reason_codes"]
        ):
            raise GovernanceError("appeal_reversal_state_invalid")
    _validate_audit("appeal", document, state)
    digest = case_digest(document)
    state.appeal_heads[document["case_id"]] = (document["case_version"], digest, status, document)
    state.audit_sequence = document["audit"]["sequence"]
    state.audit_digest = document["audit"]["event_digest"]
    return "accepted"


def evaluate_fixture(path: Path = FIXTURE) -> dict[str, Any]:
    fixture, fixture_raw = load_json(path)
    decision_schema, _ = load_json(DECISION_SCHEMA)
    appeal_schema, _ = load_json(APPEAL_SCHEMA)
    Draft202012Validator.check_schema(decision_schema)
    Draft202012Validator.check_schema(appeal_schema)
    if privacy_errors(fixture):
        raise GovernanceError(privacy_errors(fixture)[0])
    if set(fixture) != {"schema", "evidence_class", "source_bindings", "scope", "governance_roles", "tabletop_cases", "claims"}:
        raise GovernanceError("fixture_shape_invalid")
    if fixture["schema"] != "tamandua.anti_cheat.sanction_appeal_fixture/v1" or fixture["evidence_class"] != "synthetic_tabletop":
        raise GovernanceError("fixture_identity_invalid")
    bindings, scope = _source_authority()
    if fixture["source_bindings"] != bindings or fixture["scope"] != scope:
        raise GovernanceError("fixture_source_binding_mismatch")
    expected_roles = {"proposer_digests": sorted(AUTHORIZED_PROPOSERS), "sanction_approver_digests": sorted(AUTHORIZED_APPROVERS), "appeal_reviewer_digests": sorted(AUTHORIZED_REVIEWERS)}
    if fixture["governance_roles"] != expected_roles:
        raise GovernanceError("governance_role_roster_mismatch")
    if fixture["claims"] != {"enforcement_executed": False, "durable_state_written": False, "production_ready": False, "external_claim_allowed": False}:
        raise GovernanceError("fixture_claim_boundary_invalid")
    scenarios = [case.get("scenario") for case in fixture["tabletop_cases"]]
    if set(scenarios) != EXPECTED_SCENARIOS or len(scenarios) != len(set(scenarios)):
        raise GovernanceError("scenario_coverage_invalid")
    accepted = rejected = duplicates = 0
    results: list[dict[str, Any]] = []
    for case in fixture["tabletop_cases"]:
        if set(case) != {"scenario", "operations", "expected"} or len(case["operations"]) != len(case["expected"]):
            raise GovernanceError("tabletop_case_shape_invalid")
        state = CaseState()
        context: dict[str, Any] = {}
        observed: list[dict[str, str]] = []
        for operation in case["operations"]:
            if set(operation) != {"kind", "variant"} or operation["kind"] not in {"decision", "appeal"}:
                raise GovernanceError("operation_shape_invalid")
            try:
                if operation["kind"] == "decision":
                    document = _make_decision(operation["variant"], state, bindings, scope, context)
                    outcome = apply_decision(document, state, bindings, scope, decision_schema)
                    context["last_decision"] = document
                else:
                    document = _make_appeal(operation["variant"], state, context)
                    outcome = apply_appeal(document, state, appeal_schema)
                    context["last_appeal"] = document
                result = {"outcome": outcome, "reason": "none"}
                if outcome == "accepted":
                    accepted += 1
                else:
                    duplicates += 1
            except GovernanceError as error:
                result = {"outcome": "rejected", "reason": error.code}
                rejected += 1
            observed.append(result)
        if observed != case["expected"]:
            raise GovernanceError(f"tabletop_expectation_mismatch:{case['scenario']}")
        results.append({"scenario": case["scenario"], "results": observed})
    basis = {
        "schema": "tamandua.anti_cheat.sanction_appeal_governance_readiness/v1",
        "evidence_class": "synthetic_tabletop",
        "readiness_state": "governance_contract_ready_for_integration",
        "fixture_sha256": sha256(fixture_raw),
        "source_bindings": bindings,
        "scope": scope,
        "scenario_coverage": sorted(EXPECTED_SCENARIOS),
        "counts": {"accepted": accepted, "rejected_attacks": rejected, "idempotent_duplicates": duplicates},
        "results": results,
        "enforcement_executed": False,
        "durable_state_written": False,
        "production_ready": False,
        "external_claim_allowed": False,
    }
    return {"report_digest": sha256(REPORT_DOMAIN + canonical(basis)), **basis}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    args = parser.parse_args(argv)
    try:
        print(canonical(evaluate_fixture(args.fixture)).decode())
    except (OSError, json.JSONDecodeError, GovernanceError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
