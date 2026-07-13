#!/usr/bin/env python3
"""Validate Wazuh-style posture/inventory/compliance contract boundaries.

This is an offline contract gate. It validates the evidence shape required
before stronger operational posture claims can be made; it does not collect
endpoint inventory, score compliance controls, or query vulnerability feeds.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]


DEFAULT_FIXTURE = (
    ROOT
    / "tools"
    / "detection_validation"
    / "fixtures"
    / "wazuh_posture_inventory_compliance_gap_v1.json"
)

REQUIRED_CAPABILITIES = {
    "software_inventory",
    "license_inventory",
    "vulnerability_mapping",
    "compliance_posture",
    "configuration_posture",
    "fim_baseline",
    "fleet_freshness",
}

VALID_STATUS_LABELS = {"synthetic", "local", "live missing"}
VALID_CURRENT_EVIDENCE = {"synthetic_contract"}
VALID_ACCEPTED_EVIDENCE = {"live_endpoint", "fleet_api", "governed_holdout", "replay"}
VALID_ARTIFACT_REF_STATUS = {"missing", "future_required", "not_attached"}
VALID_UNSUPPORTED_COLLECTOR_STATES = {"unsupported", "degraded", "collection_error"}
VALID_LICENSE_NEGATIVE_OUTCOMES = {"rejected", "needs_review"}
VALID_GAP_CLASSES = {
    "claim-boundary",
    "collector",
    "fleet-coverage",
    "integration",
    "normalization",
}

REQUIRED_COMMON_FIELDS = {
    "tenant_id",
    "agent_id",
    "host_id",
    "hostname",
    "platform",
    "collected_at",
    "schema_version",
    "evidence_id",
    "source_collector",
    "freshness_status",
}

REQUIRED_BOUNDARY_PHRASES = [
    "Synthetic posture/inventory/compliance contract only",
    "does not prove live endpoint inventory",
    "Wazuh replacement readiness",
]

REQUIRED_PROMOTION_REQUIREMENTS = {
    "live_endpoint_inventory_artifact",
    "multi_agent_fleet_freshness_artifact",
    "negative_license_exception_cases",
    "governed_cve_cpe_matching_artifact",
    "per_control_compliance_evidence",
    "unsupported_collector_state_artifact",
}

REQUIRED_ARTIFACT_REF_TYPES = {
    "live_endpoint_inventory",
    "multi_agent_fleet_freshness",
    "license_exception_negative_cases",
    "governed_cve_cpe_matching",
    "per_control_compliance",
    "unsupported_collector_state",
}

REQUIRED_FRESHNESS_THRESHOLDS = {
    "max_inventory_age_seconds",
    "max_fleet_last_seen_age_seconds",
    "stale_after_seconds",
    "critical_after_seconds",
}

FORBIDDEN_OVERCLAIMS = [
    "wazuh replacement ready",
    "wazuh-ready",
    "production compliance scoring is validated",
    "complete software license audit is validated",
    "complete vulnerability coverage is validated",
    "fleet-wide posture coverage is validated",
]


def require_object(value: Any, prefix: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{prefix}: must be an object")
        return {}
    return value


def require_non_empty_string(value: Any, prefix: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{prefix}: must be a non-empty string")


def require_positive_int(value: Any, prefix: str, errors: list[str]) -> None:
    if not isinstance(value, int) or value <= 0:
        errors.append(f"{prefix}: must be a positive integer")


def validate_artifact_bridge(data: dict[str, Any], path: Path, errors: list[str]) -> dict[str, Any]:
    bridge = require_object(data.get("live_artifact_bridge"), f"{path}:live_artifact_bridge", errors)
    if not bridge:
        return {"artifact_refs": 0, "future_artifact_types": []}

    if bridge.get("schema_name") != "tamandua.wazuh_posture_live_artifact_bridge":
        errors.append(f"{path}:live_artifact_bridge.schema_name must be tamandua.wazuh_posture_live_artifact_bridge")
    if bridge.get("schema_version") != 1:
        errors.append(f"{path}:live_artifact_bridge.schema_version must be 1")
    if bridge.get("status") != "future_artifact_bridge":
        errors.append(f"{path}:live_artifact_bridge.status must be future_artifact_bridge")
    if bridge.get("external_claim_allowed") is not False:
        errors.append(f"{path}:live_artifact_bridge.external_claim_allowed must be false")

    artifact_refs = bridge.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not artifact_refs:
        errors.append(f"{path}:live_artifact_bridge.artifact_refs must be a non-empty list")
        artifact_refs = []

    seen_ids: set[str] = set()
    artifact_types: set[str] = set()
    for index, artifact in enumerate(artifact_refs):
        prefix = f"{path}:live_artifact_bridge.artifact_refs:{index}"
        if not isinstance(artifact, dict):
            errors.append(f"{prefix}: artifact ref must be an object")
            continue

        artifact_id = artifact.get("id")
        require_non_empty_string(artifact_id, f"{prefix}.id", errors)
        if isinstance(artifact_id, str):
            if artifact_id in seen_ids:
                errors.append(f"{prefix}.id duplicate {artifact_id}")
            seen_ids.add(artifact_id)

        artifact_type = artifact.get("artifact_type")
        if artifact_type not in REQUIRED_ARTIFACT_REF_TYPES:
            errors.append(f"{prefix}.artifact_type must be one of {sorted(REQUIRED_ARTIFACT_REF_TYPES)}")
        else:
            artifact_types.add(str(artifact_type))

        require_non_empty_string(artifact.get("schema_name"), f"{prefix}.schema_name", errors)
        require_positive_int(artifact.get("schema_version"), f"{prefix}.schema_version", errors)
        if artifact.get("evidence_class") not in VALID_ACCEPTED_EVIDENCE:
            errors.append(f"{prefix}.evidence_class must be one of {sorted(VALID_ACCEPTED_EVIDENCE)}")
        if artifact.get("status") not in VALID_ARTIFACT_REF_STATUS:
            errors.append(f"{prefix}.status must be one of {sorted(VALID_ARTIFACT_REF_STATUS)}")
        if artifact.get("satisfied") is not False:
            errors.append(f"{prefix}.satisfied must remain false until live/governed evidence is attached")
        if artifact.get("external_claim_allowed") is not False:
            errors.append(f"{prefix}.external_claim_allowed must be false")
        require_non_empty_string(artifact.get("blocked_claim_reason"), f"{prefix}.blocked_claim_reason", errors)

    missing_artifacts = sorted(REQUIRED_ARTIFACT_REF_TYPES - artifact_types)
    if missing_artifacts:
        errors.append(f"{path}:live_artifact_bridge.artifact_refs missing artifact types {missing_artifacts}")

    thresholds = require_object(bridge.get("freshness_thresholds"), f"{path}:live_artifact_bridge.freshness_thresholds", errors)
    missing_thresholds = sorted(REQUIRED_FRESHNESS_THRESHOLDS - set(thresholds))
    if missing_thresholds:
        errors.append(f"{path}:live_artifact_bridge.freshness_thresholds missing {missing_thresholds}")
    for threshold in REQUIRED_FRESHNESS_THRESHOLDS:
        if threshold in thresholds:
            require_positive_int(thresholds.get(threshold), f"{path}:live_artifact_bridge.freshness_thresholds.{threshold}", errors)
    if all(isinstance(thresholds.get(name), int) for name in REQUIRED_FRESHNESS_THRESHOLDS):
        if thresholds["max_inventory_age_seconds"] > thresholds["stale_after_seconds"]:
            errors.append(f"{path}:live_artifact_bridge.freshness_thresholds max_inventory_age_seconds must be <= stale_after_seconds")
        if thresholds["max_fleet_last_seen_age_seconds"] > thresholds["stale_after_seconds"]:
            errors.append(f"{path}:live_artifact_bridge.freshness_thresholds max_fleet_last_seen_age_seconds must be <= stale_after_seconds")
        if thresholds["stale_after_seconds"] >= thresholds["critical_after_seconds"]:
            errors.append(f"{path}:live_artifact_bridge.freshness_thresholds stale_after_seconds must be < critical_after_seconds")

    unsupported_states = bridge.get("unsupported_collector_states")
    if not isinstance(unsupported_states, list) or not unsupported_states:
        errors.append(f"{path}:live_artifact_bridge.unsupported_collector_states must be a non-empty list")
        unsupported_states = []
    seen_states: set[str] = set()
    for index, state in enumerate(unsupported_states):
        prefix = f"{path}:live_artifact_bridge.unsupported_collector_states:{index}"
        if not isinstance(state, dict):
            errors.append(f"{prefix}: unsupported collector state must be an object")
            continue
        state_id = state.get("state")
        if state_id not in VALID_UNSUPPORTED_COLLECTOR_STATES:
            errors.append(f"{prefix}.state must be one of {sorted(VALID_UNSUPPORTED_COLLECTOR_STATES)}")
        else:
            seen_states.add(str(state_id))
        require_non_empty_string(state.get("operator_status"), f"{prefix}.operator_status", errors)
        if state.get("blocks_claims") is not True:
            errors.append(f"{prefix}.blocks_claims must be true")
    missing_states = sorted(VALID_UNSUPPORTED_COLLECTOR_STATES - seen_states)
    if missing_states:
        errors.append(f"{path}:live_artifact_bridge.unsupported_collector_states missing {missing_states}")

    return {"artifact_refs": len(artifact_refs), "future_artifact_types": sorted(artifact_types)}


def validate_license_negative_cases(data: dict[str, Any], path: Path, errors: list[str]) -> int:
    cases = data.get("license_exception_negative_cases")
    if not isinstance(cases, list) or not cases:
        errors.append(f"{path}: license_exception_negative_cases must be a non-empty list")
        return 0

    seen_ids: set[str] = set()
    for index, case in enumerate(cases):
        prefix = f"{path}:license_exception_negative_cases:{index}"
        if not isinstance(case, dict):
            errors.append(f"{prefix}: negative case must be an object")
            continue
        case_id = case.get("id")
        require_non_empty_string(case_id, f"{prefix}.id", errors)
        if isinstance(case_id, str):
            if case_id in seen_ids:
                errors.append(f"{prefix}.id duplicate {case_id}")
            seen_ids.add(case_id)
        if case.get("current_evidence_class") not in VALID_CURRENT_EVIDENCE:
            errors.append(f"{prefix}.current_evidence_class must be synthetic_contract")
        accepted = set(case.get("accepted_evidence_classes") or [])
        if not accepted or not accepted <= VALID_ACCEPTED_EVIDENCE:
            errors.append(f"{prefix}.accepted_evidence_classes invalid {sorted(accepted)}")
        if not accepted.intersection({"live_endpoint", "governed_holdout"}):
            errors.append(f"{prefix}.accepted_evidence_classes must require live_endpoint or governed_holdout")
        if case.get("expected_outcome") not in VALID_LICENSE_NEGATIVE_OUTCOMES:
            errors.append(f"{prefix}.expected_outcome must be one of {sorted(VALID_LICENSE_NEGATIVE_OUTCOMES)}")
        if case.get("satisfied") is not False:
            errors.append(f"{prefix}.satisfied must remain false until governed negative evidence is attached")
        require_non_empty_string(case.get("blocked_claim_reason"), f"{prefix}.blocked_claim_reason", errors)
    return len(cases)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def validate_fixture(path: Path) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    data = load_json(path)
    lower_blob = json.dumps(data, sort_keys=True).lower()

    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    if data.get("vendor_context") != "Wazuh":
        errors.append(f"{path}: vendor_context must be Wazuh")
    if data.get("evidence_class") not in VALID_CURRENT_EVIDENCE:
        errors.append(f"{path}: evidence_class must be synthetic_contract")
    if data.get("status_label") not in VALID_STATUS_LABELS:
        errors.append(f"{path}: status_label must be one of {sorted(VALID_STATUS_LABELS)}")

    boundary = str(data.get("claim_boundary") or "")
    missing_boundary = [phrase for phrase in REQUIRED_BOUNDARY_PHRASES if phrase not in boundary]
    if missing_boundary:
        errors.append(f"{path}: claim_boundary missing phrases {missing_boundary}")

    present_overclaims = [phrase for phrase in FORBIDDEN_OVERCLAIMS if phrase in lower_blob]
    if present_overclaims:
        errors.append(f"{path}: forbidden overclaims present {present_overclaims}")

    common_fields = set(data.get("required_common_fields") or [])
    missing_common = sorted(REQUIRED_COMMON_FIELDS - common_fields)
    if missing_common:
        errors.append(f"{path}: required_common_fields missing {missing_common}")

    capabilities = set(data.get("required_capabilities") or [])
    missing_capabilities = sorted(REQUIRED_CAPABILITIES - capabilities)
    if missing_capabilities:
        errors.append(f"{path}: required_capabilities missing {missing_capabilities}")

    promotion_requirements = set(data.get("promotion_requirements") or [])
    missing_promotion = sorted(REQUIRED_PROMOTION_REQUIREMENTS - promotion_requirements)
    if missing_promotion:
        errors.append(f"{path}: promotion_requirements missing {missing_promotion}")

    bridge_summary = validate_artifact_bridge(data, path, errors)
    license_negative_case_count = validate_license_negative_cases(data, path, errors)

    controls = data.get("controls")
    if not isinstance(controls, list) or not controls:
        errors.append(f"{path}: controls must be a non-empty list")
        controls = []

    seen_ids: set[str] = set()
    covered_capabilities: set[str] = set()
    for index, control in enumerate(controls):
        prefix = f"{path}:control:{index}"
        if not isinstance(control, dict):
            errors.append(f"{prefix}: control must be an object")
            continue
        control_id = control.get("id")
        if not control_id:
            errors.append(f"{prefix}: id is required")
        elif control_id in seen_ids:
            errors.append(f"{prefix}: duplicate control id {control_id}")
        else:
            seen_ids.add(str(control_id))

        capability = control.get("capability")
        if capability not in REQUIRED_CAPABILITIES:
            errors.append(f"{prefix}: capability must be one of {sorted(REQUIRED_CAPABILITIES)}")
        else:
            covered_capabilities.add(str(capability))

        required_fields = control.get("required_fields")
        if not isinstance(required_fields, list) or len(required_fields) < 4:
            errors.append(f"{prefix}: required_fields must contain at least 4 fields")

        accepted = set(control.get("accepted_evidence_classes") or [])
        if not accepted or not accepted <= VALID_ACCEPTED_EVIDENCE:
            errors.append(f"{prefix}: accepted_evidence_classes invalid {sorted(accepted)}")
        if not accepted.intersection({"live_endpoint", "fleet_api", "governed_holdout"}):
            errors.append(f"{prefix}: accepted_evidence_classes must require promotion beyond synthetic")

        if control.get("current_evidence_class") not in VALID_CURRENT_EVIDENCE:
            errors.append(f"{prefix}: current_evidence_class must be synthetic_contract")
        if control.get("gap_classification") not in VALID_GAP_CLASSES:
            errors.append(f"{prefix}: gap_classification must be one of {sorted(VALID_GAP_CLASSES)}")
        if not control.get("remaining_gap"):
            errors.append(f"{prefix}: remaining_gap is required")

    missing_control_coverage = sorted(REQUIRED_CAPABILITIES - covered_capabilities)
    if missing_control_coverage:
        errors.append(f"{path}: controls missing capabilities {missing_control_coverage}")

    blocked_claims = data.get("blocked_claims")
    if not isinstance(blocked_claims, list) or len(blocked_claims) < 4:
        errors.append(f"{path}: blocked_claims must list the non-claimable posture outcomes")

    summary = {
        "fixture": str(path),
        "evidence_class": data.get("evidence_class"),
        "status_label": data.get("status_label"),
        "vendor_context": data.get("vendor_context"),
        "controls": len(controls),
        "capabilities": sorted(covered_capabilities),
        "promotion_requirements": sorted(promotion_requirements),
        "future_artifact_refs": bridge_summary["artifact_refs"],
        "future_artifact_types": bridge_summary["future_artifact_types"],
        "license_exception_negative_cases": license_negative_case_count,
        "external_claim_allowed": False,
    }
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()

    errors, summary = validate_fixture(args.fixture)
    if errors:
        for error in errors:
            print(error)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
