#!/usr/bin/env python3
"""Validate external-rule implementation readiness artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
ROADMAP = ROOT / "tools" / "detection_validation" / "roadmaps" / "external_rule_global_improvement_roadmap.json"
EVENT_CONTRACTS = ROOT / "tools" / "detection_validation" / "roadmaps" / "external_rule_event_contracts.json"
PROFILE_DIR = ROOT / "tools" / "detection_validation" / "profiles"
KNOWN_OWNER_AREAS = {
    "agent_process_collector",
    "agent_file_collector",
    "agent_file_read_collector",
    "agent_network_collector",
    "identity_auth_collector",
    "windows_registry_directory_collector",
    "service_persistence_collector",
    "deep_endpoint_sensor",
    "specialized_context_collectors",
    "detection_engine",
    "benchmark_fixtures",
    "provenance",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def semantic_profiles() -> list[dict[str, Any]]:
    profiles = []
    for path in sorted(PROFILE_DIR.glob("*_external_semantic_rewrite_*.json")):
        profile = load_json(path)
        profile["_path"] = str(path.relative_to(ROOT))
        profiles.append(profile)
    return profiles


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roadmap", type=Path, default=ROADMAP)
    parser.add_argument("--event-contracts", type=Path, default=EVENT_CONTRACTS)
    args = parser.parse_args()

    errors: list[str] = []
    roadmap = load_json(args.roadmap)
    event_contracts = load_json(args.event_contracts)
    items = roadmap.get("items") or []
    contracts = {
        str(contract.get("event_type")): contract
        for contract in event_contracts.get("contracts") or []
        if isinstance(contract, dict)
    }
    profiles = semantic_profiles()

    if not items:
        errors.append("global improvement roadmap has no items")
    if not profiles:
        errors.append("no external semantic rewrite profiles found")

    required_events = sorted(
        {
            event
            for item in items
            for event in ((item.get("collector_contract") or {}).get("required_events") or [])
        }
    )
    missing_contracts = [event for event in required_events if event not in contracts]
    for event in missing_contracts:
        errors.append(f"missing event contract event_type={event}")

    unmapped_contracts = sorted(
        str(contract.get("event_type"))
        for contract in contracts.values()
        if contract.get("runtime_status") == "unmapped"
        or contract.get("owner_area") == "unmapped"
        or not contract.get("agent_event_aliases")
    )
    for event in unmapped_contracts:
        errors.append(f"unmapped event contract event_type={event}")

    unknown_areas = sorted(
        {
            area
            for item in items
            for area in (item.get("owner_areas") or [])
            if area not in KNOWN_OWNER_AREAS
        }
    )
    for area in unknown_areas:
        errors.append(f"unknown owner_area={area}")

    p0_p1 = [item for item in items if item.get("priority") in {"p0-gap", "p1-high-signal"}]
    p0_p1_planned_events = sorted(
        {
            event
            for item in p0_p1
            for event in ((item.get("collector_contract") or {}).get("required_events") or [])
            if (contracts.get(str(event)) or {}).get("runtime_status") == "planned"
        }
    )
    p0_p1_ids = {str(item.get("source_candidate_id")) for item in p0_p1}
    profile_candidate_ids: set[str] = set()
    generic_immediate: list[str] = []
    for profile in profiles:
        immediate = str(profile.get("profile_id") or "").endswith("p0-p1-execution")
        for test in profile.get("tests") or []:
            candidate = test.get("semantic_rewrite_candidate") or {}
            candidate_id = str(candidate.get("id") or "")
            profile_candidate_ids.add(candidate_id)
            if immediate and candidate.get("execution_command_coverage") == "platform-generic":
                generic_immediate.append(str(test.get("id")))

    missing_immediate = sorted(p0_p1_ids - profile_candidate_ids)
    for candidate_id in missing_immediate[:25]:
        errors.append(f"p0/p1 candidate missing execution profile candidate_id={candidate_id}")
    if len(missing_immediate) > 25:
        errors.append(f"p0/p1 candidates missing execution profile count={len(missing_immediate)}")

    for test_id in generic_immediate:
        errors.append(f"immediate p0/p1 test still uses platform-generic command test_id={test_id}")

    if errors:
        print(f"external_rule_readiness=fail errors={len(errors)}")
        for error in errors:
            print(error)
        return 1

    print(
        "external_rule_readiness=ok "
        f"items={len(items)} p0_p1={len(p0_p1)} event_contracts={len(contracts)} "
        f"p0_p1_planned_event_contracts={len(p0_p1_planned_events)} "
        f"semantic_profiles={len(profiles)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
