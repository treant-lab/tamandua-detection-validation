#!/usr/bin/env python3
"""Validate the synthetic runtime-integrity lifecycle contract.

This gate replays fixture observations through the collector's documented
state machine. It does not execute a collector or inspect a live host.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, is_standalone
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    is_standalone = lambda: False


DEFAULT_FIXTURE = (
    ROOT / "fixtures" / "runtime_integrity_lifecycle_contract_v1.json"
    if is_standalone()
    else ROOT
    / "tools"
    / "detection_validation"
    / "fixtures"
    / "runtime_integrity_lifecycle_contract_v1.json"
)
API_VERSION = "tamandua.io/runtime-integrity-lifecycle-contract/v1"
EVIDENCE_CLASS = "synthetic_contract"
EXECUTION_SCOPE = "local"
SUPPORTED_PLATFORMS = {"linux", "macos", "windows"}
REQUIRED_STATES = {"supported", "degraded", "unsupported"}
FINDING_KINDS = {
    "writable_executable_mapping",
    "debugger_or_tracer_attached",
    "instrumentation_library_loaded",
}
REQUIRED_TRANSITIONS = {
    "finding_detected",
    "finding_changed",
    "collector_degraded",
    "recovered",
}
PATH_PATTERN = re.compile(r"(?:[A-Za-z]:[\\/]|/[^\s]+|\\\\[^\s]+)")
ADDRESS_PATTERN = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,16}\b")


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return payload


def expected_event(
    previous: dict[str, Any] | None, evidence: dict[str, Any]
) -> dict[str, str] | None:
    if previous == evidence:
        return None

    findings = evidence["findings"]
    reportable = bool(findings) or evidence["state"] != "supported"
    previously_reportable = previous is not None and (
        bool(previous["findings"]) or previous["state"] != "supported"
    )
    if reportable:
        if findings:
            transition = "finding_changed" if previously_reportable else "finding_detected"
        else:
            transition = "collector_degraded"
    elif previously_reportable:
        transition = "recovered"
    else:
        return None

    kinds = {finding["kind"] for finding in findings}
    if findings:
        severity = (
            "high"
            if "instrumentation_library_loaded" in kinds or len(kinds) > 1
            else "medium"
        )
    elif evidence["state"] == "supported":
        severity = "info"
    else:
        severity = "low"
    return {"transition": transition, "severity": severity}


def privacy_errors(path: Path, field: str, value: Any) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        forbidden_keys = {
            key for key in value if "path" in key.lower() or "address" in key.lower()
        }
        if forbidden_keys:
            errors.append(
                f"{path}: {field} contains forbidden privacy fields {sorted(forbidden_keys)}"
            )
        for key, child in value.items():
            errors.extend(privacy_errors(path, f"{field}.{key}", child))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(privacy_errors(path, f"{field}[{index}]", child))
    elif isinstance(value, str) and (
        PATH_PATTERN.search(value) or ADDRESS_PATTERN.search(value)
    ):
        errors.append(f"{path}: {field} must not contain paths or addresses")
    return errors


def validate_evidence(path: Path, field: str, evidence: Any) -> list[str]:
    if not isinstance(evidence, dict):
        return [f"{path}: {field} must be an object"]
    errors: list[str] = []
    if not isinstance(evidence.get("platform"), str) or not evidence["platform"]:
        errors.append(f"{path}: {field}.platform must be a non-empty string")
    if evidence.get("state") not in REQUIRED_STATES:
        errors.append(f"{path}: {field}.state must be one of {sorted(REQUIRED_STATES)}")
    findings = evidence.get("findings")
    if not isinstance(findings, list):
        errors.append(f"{path}: {field}.findings must be an array")
        findings = []
    limitations = evidence.get("limitations")
    if not isinstance(limitations, list) or not all(
        isinstance(item, str) and item for item in limitations
    ):
        errors.append(f"{path}: {field}.limitations must be a non-empty-string array")
    if evidence.get("state") == "unsupported":
        if findings:
            errors.append(f"{path}: {field} unsupported evidence must have no findings")
        if not limitations:
            errors.append(f"{path}: {field} unsupported evidence must state a limitation")

    errors.extend(privacy_errors(path, field, evidence))

    for index, finding in enumerate(findings):
        finding_field = f"{field}.findings[{index}]"
        if not isinstance(finding, dict):
            errors.append(f"{path}: {finding_field} must be an object")
            continue
        if finding.get("kind") not in FINDING_KINDS:
            errors.append(f"{path}: {finding_field}.kind must be a known finding kind")
        value = finding.get("evidence")
        if not isinstance(value, str) or not value:
            errors.append(f"{path}: {finding_field}.evidence must be a non-empty string")
    return errors


def validate_gate(path: Path) -> tuple[list[str], dict[str, Any]]:
    payload = load_json(path)
    errors: list[str] = []
    if payload.get("api_version") != API_VERSION:
        errors.append(f"{path}: api_version must be {API_VERSION!r}")
    if payload.get("evidence_class") != EVIDENCE_CLASS:
        errors.append(f"{path}: evidence_class must remain {EVIDENCE_CLASS!r}")
    if payload.get("execution_scope") != EXECUTION_SCOPE:
        errors.append(f"{path}: execution_scope must remain {EXECUTION_SCOPE!r}")
    if payload.get("external_claim_allowed") is not False:
        errors.append(f"{path}: external_claim_allowed must remain false")

    claim_boundary = payload.get("claim_boundary", "")
    for phrase in (
        "Synthetic local contract replay only",
        "does not prove live-host collection",
        "detection efficacy",
        "production readiness",
        "parity with any vendor",
    ):
        if phrase not in claim_boundary:
            errors.append(f"{path}: claim_boundary must include {phrase!r}")

    platform_contract = payload.get("platform_contract")
    if not isinstance(platform_contract, dict):
        errors.append(f"{path}: platform_contract must be an object")
    else:
        if set(platform_contract.get("supported_platforms", [])) != SUPPORTED_PLATFORMS:
            errors.append(f"{path}: supported_platforms must be {sorted(SUPPORTED_PLATFORMS)}")
        if set(platform_contract.get("required_states", [])) != REQUIRED_STATES:
            errors.append(f"{path}: required_states must be {sorted(REQUIRED_STATES)}")
        if (
            platform_contract.get("unsupported_behavior")
            != "explicit_state_with_no_findings_and_non_empty_limitations"
        ):
            errors.append(f"{path}: unsupported_behavior must remain explicit")

    privacy = payload.get("privacy_contract")
    expected_privacy = {
        "evidence_shape": "metadata_only",
        "forbid_paths": True,
        "forbid_addresses": True,
    }
    if privacy != expected_privacy:
        errors.append(f"{path}: privacy_contract must be metadata-only and forbid paths/addresses")

    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        return errors + [f"{path}: scenarios must be a non-empty array"], {}

    scenario_ids: list[str] = []
    observed_transitions: set[str] = set()
    duplicate_suppressions = 0
    observed_platforms: set[str] = set()
    observed_states: set[str] = set()
    for scenario_index, scenario in enumerate(scenarios):
        field = f"scenarios[{scenario_index}]"
        if not isinstance(scenario, dict):
            errors.append(f"{path}: {field} must be an object")
            continue
        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not scenario_id:
            errors.append(f"{path}: {field}.id must be a non-empty string")
        else:
            scenario_ids.append(scenario_id)
        previous = scenario.get("initial_previous")
        if previous is not None:
            previous_errors = validate_evidence(path, f"{field}.initial_previous", previous)
            errors.extend(previous_errors)
            if previous_errors:
                previous = None
        observations = scenario.get("observations")
        if not isinstance(observations, list) or not observations:
            errors.append(f"{path}: {field}.observations must be a non-empty array")
            continue
        for observation_index, observation in enumerate(observations):
            observation_field = f"{field}.observations[{observation_index}]"
            if not isinstance(observation, dict):
                errors.append(f"{path}: {observation_field} must be an object")
                continue
            evidence = observation.get("evidence")
            evidence_errors = validate_evidence(path, f"{observation_field}.evidence", evidence)
            errors.extend(evidence_errors)
            if evidence_errors or not isinstance(evidence, dict):
                continue
            observed_platforms.add(evidence["platform"])
            observed_states.add(evidence["state"])
            actual = expected_event(previous, evidence)
            declared = observation.get("expected_event")
            if declared != actual:
                errors.append(
                    f"{path}: {observation_field}.expected_event is {declared!r}; replay produced {actual!r}"
                )
            if actual is None and previous == evidence:
                duplicate_suppressions += 1
            elif actual is not None:
                observed_transitions.add(actual["transition"])
            previous = evidence

    duplicate_ids = sorted({item for item in scenario_ids if scenario_ids.count(item) > 1})
    if duplicate_ids:
        errors.append(f"{path}: duplicate scenario ids {duplicate_ids}")
    missing_transitions = sorted(REQUIRED_TRANSITIONS - observed_transitions)
    if missing_transitions:
        errors.append(f"{path}: scenarios do not cover transitions {missing_transitions}")
    if duplicate_suppressions < 2:
        errors.append(f"{path}: scenarios must cover at least two duplicate suppressions")
    if not SUPPORTED_PLATFORMS.issubset(observed_platforms):
        errors.append(
            f"{path}: scenarios do not cover supported platforms {sorted(SUPPORTED_PLATFORMS - observed_platforms)}"
        )
    if not REQUIRED_STATES.issubset(observed_states):
        errors.append(f"{path}: scenarios do not cover states {sorted(REQUIRED_STATES - observed_states)}")

    summary = {
        "evidence_class": EVIDENCE_CLASS,
        "execution_scope": EXECUTION_SCOPE,
        "external_claim_allowed": False,
        "scenario_count": len(scenarios),
        "covered_transitions": sorted(observed_transitions),
        "duplicate_suppressions": duplicate_suppressions,
        "covered_platforms": sorted(SUPPORTED_PLATFORMS & observed_platforms),
        "covered_states": sorted(REQUIRED_STATES & observed_states),
    }
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()
    try:
        errors, summary = validate_gate(args.fixture)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error)
        return 1
    if errors:
        for error in errors:
            print(error)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
