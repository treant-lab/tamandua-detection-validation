#!/usr/bin/env python3
"""Validate Mobile App Guard aggressive benchmark replay coverage.

This gate checks the benchmark metadata around the App Guard replay fixture. It
does not execute SDK, app, server, or device code.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, is_standalone
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    is_standalone = lambda: False

DEFAULT_FIXTURE = (
    ROOT / "fixtures" / "mobile_app_guard_aggressive_replay_v1.json"
    if is_standalone()
    else ROOT / "tools" / "detection_validation" / "fixtures" / "mobile_app_guard_aggressive_replay_v1.json"
)

VALID_CLAIM_STATUSES = {"implemented_contract", "roadmap_device_evidence_required"}
GOODWARE_CATEGORY = "goodware_false_positive"
VALID_CONTROL_TYPES = {"positive_replay", "negative_goodware_control"}
REQUIRED_SCENARIO_COVERAGE_FIELDS = {
    "appdome_gap",
    "verimatrix_gap",
    "control_type",
    "platform",
    "expected_decision",
    "coverage_tags",
    "evidence_bucket",
}
DEFAULT_REQUIRED_COVERAGE_TAGS = {
    "accessibility",
    "fraud",
    "goodware_negative",
    "malware",
    "mitm",
    "overlay",
    "tamper",
}
VALID_EVIDENCE_BUCKETS = {"implemented_contract", "physical_device_lab_required"}
REQUIRED_RELEASE_EVIDENCE = {
    "live": {
        "live_signed_app_guard_ingestion",
        "live_duplicate_signed_request_rejection",
    },
    "device": {
        "physical_device_collection_packet",
    },
    "ios": {
        "ios_native_build_evidence",
        "ios_xcframework_binding_evidence",
    },
    "lab": {
        "governed_physical_attack_lab_evidence",
    },
}
REQUIRED_NON_CLAIMS = {
    "live backend ingestion",
    "live anti-replay",
    "physical-device collection",
    "iOS native build",
    "iOS XCFramework",
    "physical attack-lab protection evidence",
    "production malware accuracy",
}
SENSITIVE_EVIDENCE_KEYS = {
    "raw_body",
    "raw_payload",
    "page_content",
    "dom_snapshot",
    "request_body",
    "response_body",
    "raw_pointer_data",
    "raw_key_data",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def validate_gate(path: Path) -> tuple[list[str], dict[str, Any]]:
    data = load_json(path)
    errors: list[str] = []
    gate = data.get("benchmark_gate")
    fixtures = data.get("fixtures")

    if not isinstance(gate, dict):
        return [f"{path}: benchmark_gate is required"], {}
    if not isinstance(fixtures, list) or not fixtures:
        return [f"{path}: fixtures must be a non-empty list"], {}

    required_categories = set(gate.get("required_categories", []))
    if not required_categories:
        errors.append(f"{path}: benchmark_gate.required_categories must be non-empty")
    required_coverage_tags = set(string_list(gate.get("required_coverage_tags"))) or DEFAULT_REQUIRED_COVERAGE_TAGS

    control_requirements = gate.get("control_requirements")
    if not isinstance(control_requirements, dict):
        errors.append(f"{path}: benchmark_gate.control_requirements is required")
        control_requirements = {}
    if control_requirements.get("goodware_category") != GOODWARE_CATEGORY:
        errors.append(f"{path}: benchmark_gate.control_requirements.goodware_category must be {GOODWARE_CATEGORY!r}")
    if control_requirements.get("minimum_negative_controls") != gate.get("minimum_goodware_fixtures"):
        errors.append(
            f"{path}: benchmark_gate.control_requirements.minimum_negative_controls "
            "must match minimum_goodware_fixtures"
        )
    if control_requirements.get("negative_control_type") != "negative_goodware_control":
        errors.append(
            f"{path}: benchmark_gate.control_requirements.negative_control_type "
            "must be 'negative_goodware_control'"
        )
    if set(control_requirements.get("allowed_negative_decisions", [])) != {"allow"}:
        errors.append(f"{path}: benchmark_gate.control_requirements.allowed_negative_decisions must be ['allow']")
    if control_requirements.get("privacy_boundary") != "metadata_only":
        errors.append(f"{path}: benchmark_gate.control_requirements.privacy_boundary must be metadata_only")

    allowed_statuses = set(gate.get("allowed_claim_statuses", []))
    if allowed_statuses != VALID_CLAIM_STATUSES:
        errors.append(f"{path}: allowed_claim_statuses must be {sorted(VALID_CLAIM_STATUSES)}")

    claim_boundary = data.get("claim_boundary", "")
    for phrase in [
        "Synthetic offline replay contract only",
        "do not prove live backend ingestion",
        "physical-device collection",
        "production malware accuracy",
    ]:
        if phrase not in claim_boundary:
            errors.append(f"{path}: claim_boundary must include {phrase!r}")

    boundary = gate.get("evidence_boundary")
    if not isinstance(boundary, dict):
        errors.append(f"{path}: benchmark_gate.evidence_boundary is required")
    else:
        expected_boundary = {
            "fixture_evidence_class": "synthetic_replay_contract",
            "local_fixture_claimable": True,
            "live_signed_ingestion_claimable": False,
            "live_anti_replay_claimable": False,
        }
        for key, expected in expected_boundary.items():
            if boundary.get(key) != expected:
                errors.append(f"{path}: benchmark_gate.evidence_boundary.{key} must be {expected!r}")
        release_claim_requires = set(boundary.get("release_claim_requires", []))
        for evidence_class, required in REQUIRED_RELEASE_EVIDENCE.items():
            missing_required = sorted(required - release_claim_requires)
            if missing_required:
                errors.append(
                    f"{path}: benchmark_gate.evidence_boundary.release_claim_requires missing "
                    f"{evidence_class} evidence requirements {missing_required}"
                )
        if not REQUIRED_NON_CLAIMS.issubset(set(boundary.get("non_claims", []))):
            errors.append(
                f"{path}: benchmark_gate.evidence_boundary.non_claims must include {sorted(REQUIRED_NON_CLAIMS)}"
            )

    categories: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    coverage_tags: Counter[str] = Counter()
    implemented_contract_ids: list[str] = []
    physical_device_lab_required_ids: list[str] = []
    goodware_negative_control_ids: list[str] = []
    goodware_count = 0

    for index, item in enumerate(fixtures):
        prefix = f"{path}:{index}"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: fixture must be an object")
            continue

        category = item.get("benchmark_category")
        claim_status = item.get("claim_status")
        validation_label = item.get("validation_label")
        event = item.get("input")
        scenario_coverage = item.get("scenario_coverage")

        if category not in required_categories:
            errors.append(f"{prefix}: benchmark_category must be one of {sorted(required_categories)}")
        else:
            categories[str(category)] += 1

        if claim_status not in VALID_CLAIM_STATUSES:
            errors.append(f"{prefix}: claim_status must be one of {sorted(VALID_CLAIM_STATUSES)}")
        else:
            statuses[str(claim_status)] += 1

        if not isinstance(validation_label, str) or not validation_label.startswith("synthetic"):
            errors.append(f"{prefix}: validation_label must be a synthetic replay label")

        if not isinstance(scenario_coverage, dict):
            errors.append(f"{prefix}: scenario_coverage must be an object")
            scenario_coverage = {}
        missing_coverage = sorted(REQUIRED_SCENARIO_COVERAGE_FIELDS - set(scenario_coverage))
        if missing_coverage:
            errors.append(f"{prefix}: scenario_coverage missing required fields {missing_coverage}")
        item_coverage_tags = set(string_list(scenario_coverage.get("coverage_tags")))
        if not item_coverage_tags:
            errors.append(f"{prefix}: scenario_coverage.coverage_tags must be a non-empty string array")
        coverage_tags.update(item_coverage_tags)
        evidence_bucket = scenario_coverage.get("evidence_bucket")
        if evidence_bucket not in VALID_EVIDENCE_BUCKETS:
            errors.append(f"{prefix}: scenario_coverage.evidence_bucket must be one of {sorted(VALID_EVIDENCE_BUCKETS)}")
        elif isinstance(item.get("id"), str):
            if evidence_bucket == "implemented_contract":
                implemented_contract_ids.append(item["id"])
            if evidence_bucket == "physical_device_lab_required":
                physical_device_lab_required_ids.append(item["id"])

        if not isinstance(event, dict):
            errors.append(f"{prefix}: input must be an object")
            continue
        evidence = event.get("evidence")
        risk = event.get("risk")
        if not isinstance(evidence, dict):
            errors.append(f"{prefix}: input.evidence must be an object")
            continue
        forbidden = sorted(SENSITIVE_EVIDENCE_KEYS & set(evidence))
        if forbidden:
            errors.append(f"{prefix}: evidence contains sensitive/raw fields {forbidden}")
        if evidence.get("privacy_mode") != "metadata_only":
            errors.append(f"{prefix}: evidence.privacy_mode must be metadata_only")
        if isinstance(risk, dict):
            decisions[str(risk.get("decision"))] += 1
        expected_decision = risk.get("decision") if isinstance(risk, dict) else None
        if scenario_coverage.get("expected_decision") != expected_decision:
            errors.append(f"{prefix}: scenario_coverage.expected_decision must match input.risk.decision")
        if scenario_coverage.get("platform") != event.get("platform"):
            errors.append(f"{prefix}: scenario_coverage.platform must match input.platform")
        if scenario_coverage.get("control_type") not in VALID_CONTROL_TYPES:
            errors.append(f"{prefix}: scenario_coverage.control_type must be one of {sorted(VALID_CONTROL_TYPES)}")
        if category == GOODWARE_CATEGORY:
            goodware_count += 1
            if isinstance(item.get("id"), str):
                goodware_negative_control_ids.append(item["id"])
            if scenario_coverage.get("control_type") != "negative_goodware_control":
                errors.append(f"{prefix}: goodware FP fixture must be a negative_goodware_control")
            if not isinstance(risk, dict) or risk.get("decision") != "allow":
                errors.append(f"{prefix}: goodware FP fixture must expect allow decision")
            if event.get("severity") != "info":
                errors.append(f"{prefix}: goodware FP fixture must use info severity")
            if "goodware_negative" not in item_coverage_tags:
                errors.append(f"{prefix}: goodware FP fixture coverage_tags must include goodware_negative")
        elif scenario_coverage.get("control_type") != "positive_replay":
            errors.append(f"{prefix}: non-goodware fixture must be a positive_replay")
        if claim_status == "roadmap_device_evidence_required" and evidence_bucket != "physical_device_lab_required":
            errors.append(f"{prefix}: roadmap_device_evidence_required must use physical_device_lab_required bucket")
        if claim_status == "implemented_contract" and evidence_bucket != "implemented_contract":
            errors.append(f"{prefix}: implemented_contract must use implemented_contract bucket")

    missing = sorted(required_categories - set(categories))
    if missing:
        errors.append(f"{path}: missing required benchmark categories {missing}")

    minimum_total = int(gate.get("minimum_total_fixtures", 0))
    if len(fixtures) < minimum_total:
        errors.append(f"{path}: fixture count {len(fixtures)} is below minimum_total_fixtures {minimum_total}")

    minimum_goodware = int(gate.get("minimum_goodware_fixtures", 0))
    if goodware_count < minimum_goodware:
        errors.append(f"{path}: goodware fixture count {goodware_count} is below {minimum_goodware}")

    missing_coverage_tags = sorted(required_coverage_tags - set(coverage_tags))
    if missing_coverage_tags:
        errors.append(f"{path}: missing required coverage tags {missing_coverage_tags}")

    summary = {
        "fixture": str(path),
        "fixtures": len(fixtures),
        "categories": dict(sorted(categories.items())),
        "claim_statuses": dict(sorted(statuses.items())),
        "evidence_buckets": {
            "implemented_contract": statuses.get("implemented_contract", 0),
            "physical_device_smoke": 0,
            "physical_device_lab_required": len(physical_device_lab_required_ids),
            "roadmap_device_evidence_required": statuses.get("roadmap_device_evidence_required", 0),
        },
        "claim_separation": {
            "implemented_contract": implemented_contract_ids,
            "physical_device_lab_required": physical_device_lab_required_ids,
            "goodware_negative_controls": goodware_negative_control_ids,
        },
        "coverage_tags": dict(sorted(coverage_tags.items())),
        "required_coverage_tags": sorted(required_coverage_tags),
        "decisions": dict(sorted(decisions.items())),
        "goodware_false_positive_fixtures": goodware_count,
        "negative_goodware_controls": goodware_count,
        "scenario_coverage_fields": sorted(REQUIRED_SCENARIO_COVERAGE_FIELDS),
        "evidence_class": gate.get("evidence_class"),
        "evidence_boundary": boundary if isinstance(boundary, dict) else {},
        "evidence_boundary_notes": {
            "implemented_contract": "synthetic replay contract only",
            "physical_device_smoke": "not collected by this runner; use mobile_app_guard_adb_smoke_probe.py",
            "roadmap_device_evidence_required": "requires physical-device/lab evidence before stronger shielding claims",
        },
    }
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()

    errors, summary = validate_gate(args.fixture)
    if errors:
        for error in errors:
            print(error)
        return 1

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
