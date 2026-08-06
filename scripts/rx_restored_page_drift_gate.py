#!/usr/bin/env python3
"""Validate the synthetic RX-restored page drift contract.

This gate models a future runtime-integrity page-content check with deterministic
metadata-only fixtures. It does not inspect a live host or change production
collectors.
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
    ROOT / "fixtures" / "rx_restored_page_drift_contract_v1.json"
    if is_standalone()
    else ROOT
    / "tools"
    / "detection_validation"
    / "fixtures"
    / "rx_restored_page_drift_contract_v1.json"
)

API_VERSION = "tamandua.io/rx-restored-page-drift-contract/v1"
EVIDENCE_CLASS = "synthetic_lab_contract"
SUPPORTED_PLATFORMS = {"android", "linux"}
REQUIRED_STATES = {"supported", "degraded", "unsupported"}
ALLOWLIST_CONTEXTS = {"none", "benign_relocation", "managed_jit"}
REQUIRED_SCENARIOS = {
    "unchanged-rx-page-is-suppressed",
    "rx-restored-drift-alerts",
    "benign-relocation-drift-is-suppressed",
    "managed-jit-drift-is-suppressed",
    "collector-degraded-is-explicit",
    "unsupported-platform-is-explicit",
}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|/[^\s]+|\\\\[^\s]+)")
ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,16}\b")


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return payload


def privacy_errors(path: Path, field: str, value: Any) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_lower = key.lower()
            if any(token in key_lower for token in ("path", "address", "bytes", "raw_bytes")):
                errors.append(f"{path}: {field}.{key} is a forbidden privacy field")
            errors.extend(privacy_errors(path, f"{field}.{key}", child))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(privacy_errors(path, f"{field}[{index}]", child))
    elif isinstance(value, str) and (PATH_RE.search(value) or ADDRESS_RE.search(value)):
        errors.append(f"{path}: {field} must not contain paths or addresses")
    return errors


def expected_result(evidence: dict[str, Any]) -> dict[str, str]:
    state = evidence["state"]
    if state == "unsupported":
        return {"decision": "unsupported", "severity": "low"}
    if state == "degraded":
        return {"decision": "degraded", "severity": "low"}

    drifted = evidence["baseline_digest"] != evidence["observed_digest"]
    allowlisted = evidence["allowlist_context"] in {"benign_relocation", "managed_jit"}
    if drifted and not allowlisted:
        return {"decision": "alert", "severity": "high"}
    return {"decision": "suppress", "severity": "info"}


def validate_evidence(path: Path, field: str, evidence: Any) -> list[str]:
    if not isinstance(evidence, dict):
        return [f"{path}: {field} must be an object"]
    errors: list[str] = []
    platform = evidence.get("platform")
    state = evidence.get("state")
    if not isinstance(platform, str) or not platform:
        errors.append(f"{path}: {field}.platform must be a non-empty string")
    if state not in REQUIRED_STATES:
        errors.append(f"{path}: {field}.state must be one of {sorted(REQUIRED_STATES)}")
    if evidence.get("allowlist_context") not in ALLOWLIST_CONTEXTS:
        errors.append(f"{path}: {field}.allowlist_context is not known")

    findings = evidence.get("findings")
    if not isinstance(findings, list):
        errors.append(f"{path}: {field}.findings must be an array")
        findings = []
    limitations = evidence.get("limitations")
    if not isinstance(limitations, list) or not all(isinstance(item, str) and item for item in limitations):
        errors.append(f"{path}: {field}.limitations must be a non-empty-string array")

    for digest_field in ("baseline_digest", "observed_digest"):
        digest = evidence.get(digest_field)
        if state == "supported":
            if not isinstance(digest, str) or not DIGEST_RE.match(digest):
                errors.append(f"{path}: {field}.{digest_field} must be a sha256 digest")
        elif digest is not None:
            errors.append(f"{path}: {field}.{digest_field} must be null outside supported state")

    if state in {"degraded", "unsupported"} and findings:
        errors.append(f"{path}: {field} degraded/unsupported evidence must have no findings")
    if state == "unsupported" and not limitations:
        errors.append(f"{path}: {field} unsupported evidence must state a limitation")

    drifted = evidence.get("baseline_digest") != evidence.get("observed_digest")
    allowlisted = evidence.get("allowlist_context") in {"benign_relocation", "managed_jit"}
    if state == "supported" and drifted and not allowlisted:
        kinds = {finding.get("kind") for finding in findings if isinstance(finding, dict)}
        if "rx_restored_page_drift" not in kinds:
            errors.append(f"{path}: {field} unallowlisted drift must include rx_restored_page_drift")
    if state == "supported" and allowlisted and findings:
        errors.append(f"{path}: {field} allowlisted drift must not emit findings")

    errors.extend(privacy_errors(path, field, evidence))
    return errors


def validate_gate(path: Path) -> tuple[list[str], dict[str, Any]]:
    payload = load_json(path)
    errors: list[str] = []
    if payload.get("api_version") != API_VERSION:
        errors.append(f"{path}: api_version must be {API_VERSION!r}")
    if payload.get("evidence_class") != EVIDENCE_CLASS:
        errors.append(f"{path}: evidence_class must remain {EVIDENCE_CLASS!r}")
    if payload.get("execution_scope") != "local":
        errors.append(f"{path}: execution_scope must remain 'local'")
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

    privacy = payload.get("privacy_contract")
    if privacy != {
        "evidence_shape": "metadata_only",
        "forbid_paths": True,
        "forbid_addresses": True,
        "forbid_raw_bytes": True,
    }:
        errors.append(f"{path}: privacy_contract must be metadata-only and forbid raw identifiers")

    platform_contract = payload.get("platform_contract")
    if not isinstance(platform_contract, dict):
        errors.append(f"{path}: platform_contract must be an object")
    else:
        if set(platform_contract.get("supported_platforms", [])) != SUPPORTED_PLATFORMS:
            errors.append(f"{path}: supported_platforms must be {sorted(SUPPORTED_PLATFORMS)}")
        if set(platform_contract.get("required_states", [])) != REQUIRED_STATES:
            errors.append(f"{path}: required_states must be {sorted(REQUIRED_STATES)}")

    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        return errors + [f"{path}: scenarios must be a non-empty array"], {}

    scenario_ids: list[str] = []
    decisions: set[str] = set()
    platforms: set[str] = set()
    states: set[str] = set()
    for index, scenario in enumerate(scenarios):
        field = f"scenarios[{index}]"
        if not isinstance(scenario, dict):
            errors.append(f"{path}: {field} must be an object")
            continue
        scenario_id = scenario.get("id")
        if isinstance(scenario_id, str) and scenario_id:
            scenario_ids.append(scenario_id)
        else:
            errors.append(f"{path}: {field}.id must be a non-empty string")
        evidence = scenario.get("evidence")
        evidence_errors = validate_evidence(path, f"{field}.evidence", evidence)
        errors.extend(evidence_errors)
        if evidence_errors or not isinstance(evidence, dict):
            continue
        platforms.add(evidence["platform"])
        states.add(evidence["state"])
        actual = expected_result(evidence)
        decisions.add(actual["decision"])
        if scenario.get("expected_result") != actual:
            errors.append(f"{path}: {field}.expected_result is not the replay result {actual!r}")

    missing = sorted(REQUIRED_SCENARIOS - set(scenario_ids))
    if missing:
        errors.append(f"{path}: scenarios missing required ids {missing}")
    duplicates = sorted({item for item in scenario_ids if scenario_ids.count(item) > 1})
    if duplicates:
        errors.append(f"{path}: duplicate scenario ids {duplicates}")
    if not SUPPORTED_PLATFORMS.issubset(platforms):
        errors.append(f"{path}: scenarios do not cover platforms {sorted(SUPPORTED_PLATFORMS - platforms)}")
    if not REQUIRED_STATES.issubset(states):
        errors.append(f"{path}: scenarios do not cover states {sorted(REQUIRED_STATES - states)}")
    if {"alert", "suppress", "degraded", "unsupported"} - decisions:
        errors.append(f"{path}: scenarios do not cover all decisions")

    summary = {
        "evidence_class": EVIDENCE_CLASS,
        "execution_scope": "local",
        "external_claim_allowed": False,
        "scenario_count": len(scenarios),
        "covered_decisions": sorted(decisions),
        "covered_platforms": sorted(SUPPORTED_PLATFORMS & platforms),
        "covered_states": sorted(REQUIRED_STATES & states),
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
