#!/usr/bin/env python3
"""Build an implementation backlog from external-rule improvement roadmap."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROADMAP = ROOT / "tools" / "detection_validation" / "roadmaps" / "external_rule_global_improvement_roadmap.json"
DEFAULT_OUT_JSON = ROOT / "tools" / "detection_validation" / "roadmaps" / "external_rule_implementation_backlog.json"
DEFAULT_OUT_MD = ROOT / "docs" / "benchmarks" / "EXTERNAL_RULE_IMPLEMENTATION_BACKLOG.md"


OWNER_AREA_TARGETS = {
    "agent_process_collector": {
        "track": "agent",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/process.rs",
            "libs/tamandua-core/src/telemetry/mod.rs",
        ],
        "implementation_theme": "normalize process_create with stable parent, command line, user, pid, and platform identity fields",
    },
    "agent_file_collector": {
        "track": "agent",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/file.rs",
            "apps/tamandua_agent/src/collectors/fim.rs",
            "apps/tamandua_agent/src/collectors/file_journal.rs",
        ],
        "implementation_theme": "separate file_create, file_modify, file_delete, and source collector health",
    },
    "agent_file_read_collector": {
        "track": "agent",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/file.rs",
            "apps/tamandua_agent/src/collectors/credential_theft.rs",
        ],
        "implementation_theme": "add safe file_read visibility for credential and sensitive-path access where platform permits",
    },
    "agent_network_collector": {
        "track": "agent",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/network.rs",
            "apps/tamandua_agent/src/collectors/dns.rs",
            "apps/tamandua_agent/src/collectors/network_anomaly.rs",
        ],
        "implementation_theme": "normalize network_connect, dns_query, remote address/domain, process attribution, and drop counters",
    },
    "identity_auth_collector": {
        "track": "collector",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/identity.rs",
            "apps/tamandua_agent/src/collectors/ad_monitor.rs",
            "apps/tamandua_agent/src/collectors/lateral_movement.rs",
        ],
        "implementation_theme": "normalize auth_event, failed_login, session_start, account_change, and privilege_change",
    },
    "windows_registry_directory_collector": {
        "track": "collector",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/registry.rs",
            "apps/tamandua_agent/src/collectors/etw.rs",
            "apps/tamandua_agent/src/collectors/ad_monitor.rs",
        ],
        "implementation_theme": "normalize registry_modify, directory_change, policy_object, and actor_user",
    },
    "service_persistence_collector": {
        "track": "collector",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/persistence.rs",
            "apps/tamandua_agent/src/collectors/scheduled_tasks.rs",
            "apps/tamandua_agent/src/collectors/registry.rs",
        ],
        "implementation_theme": "normalize service_create, service_modify, scheduled_event, task, daemon, and launch item metadata",
    },
    "deep_endpoint_sensor": {
        "track": "sensor",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/injection.rs",
            "apps/tamandua_agent/src/collectors/memory.rs",
            "apps/tamandua_agent/src/collectors/process_hollowing.rs",
            "apps/tamandua_agent/src/collectors/endpoint_security.rs",
        ],
        "implementation_theme": "normalize process_access, memory_event, image_load, access masks, and target process evidence",
    },
    "specialized_context_collectors": {
        "track": "collector",
        "primary_files": [
            "apps/tamandua_agent/src/collectors/office_email.rs",
            "apps/tamandua_agent/src/collectors/ai_usage.rs",
            "apps/tamandua_agent/src/collectors/health.rs",
        ],
        "implementation_theme": "add context collectors for mail_access, secret_scan, resource_usage, and service_health",
    },
    "detection_engine": {
        "track": "detection",
        "primary_files": [
            "tools/detection_response",
            "apps/tamandua_agent/rules",
            "apps/tamandua_agent/src/detection",
        ],
        "implementation_theme": "promote Tamandua-authored D&R candidates with explainable evidence and benign allowlists",
    },
    "benchmark_fixtures": {
        "track": "validation",
        "primary_files": [
            "tools/detection_validation/fixtures",
            "tools/detection_validation/profiles",
            "docs/benchmarks/runs",
        ],
        "implementation_theme": "add benign and suspicious fixtures plus promoted benchmark cases",
    },
    "provenance": {
        "track": "governance",
        "primary_files": [
            "tools/detection_validation/roadmaps/external_rule_inventory.json",
            "tools/detection_validation/roadmaps/external_rule_semantic_rewrite_candidates.json",
        ],
        "implementation_theme": "retain source repo, commit, source IDs, source mix, and license class",
    },
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def priority_rank(priority: str) -> int:
    return {"p0-gap": 0, "p1-high-signal": 1, "p2-roadmap-hardening": 2, "p3-backlog": 3}.get(priority, 9)


def build_backlog(roadmap: dict[str, Any]) -> dict[str, Any]:
    items = roadmap.get("items") or []
    by_area: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_track: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for item in items:
        for area in item.get("owner_areas") or []:
            target = OWNER_AREA_TARGETS.get(area)
            if not target:
                continue
            compact = {
                "id": item["id"],
                "source_candidate_id": item["source_candidate_id"],
                "platform": item["platform"],
                "technique_id": item["technique_id"],
                "priority": item["priority"],
                "source_rule_count": item["source_rule_count"],
                "source_mix": item["source_mix"],
                "collector_contract": item["collector_contract"],
                "execution_probe": item["execution_probe"],
            }
            by_area[area].append(compact)
            by_track[target["track"]].append(compact)

    area_entries = []
    for area, area_items in sorted(by_area.items()):
        target = OWNER_AREA_TARGETS[area]
        sorted_items = sorted(
            area_items,
            key=lambda item: (priority_rank(str(item["priority"])), str(item["platform"]), -int(item["source_rule_count"])),
        )
        area_entries.append(
            {
                "owner_area": area,
                "track": target["track"],
                "implementation_theme": target["implementation_theme"],
                "primary_files": target["primary_files"],
                "item_count": len(sorted_items),
                "priority_counts": dict(Counter(str(item["priority"]) for item in sorted_items)),
                "platform_counts": dict(Counter(str(item["platform"]) for item in sorted_items)),
                "top_items": sorted_items[:25],
            }
        )

    return {
        "schema_version": 1,
        "source": str(DEFAULT_ROADMAP.relative_to(ROOT)),
        "summary": {
            "item_count": len(items),
            "owner_area_count": len(area_entries),
            "track_counts": dict(Counter(OWNER_AREA_TARGETS[area]["track"] for area in by_area)),
            "priority_counts": dict(Counter(str(item.get("priority")) for item in items)),
            "platform_counts": dict(Counter(str(item.get("platform")) for item in items)),
        },
        "owner_areas": area_entries,
    }


def render_markdown(backlog: dict[str, Any]) -> str:
    summary = backlog["summary"]
    lines = [
        "# External Rule Implementation Backlog",
        "",
        "Status: generated implementation planning artifact",
        "Last updated: 2026-05-28",
        "",
        "This backlog maps external-rule-inspired semantic rewrite candidates to concrete Tamandua code areas.",
        "It is implementation planning only; runtime behavior changes must land through normal code review and tests.",
        "",
        "## Summary",
        "",
        f"- Items: `{summary['item_count']}`",
        f"- Owner areas: `{summary['owner_area_count']}`",
        "",
        "Priority counts:",
        "",
    ]
    for key, value in summary["priority_counts"].items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "Platform counts:", ""])
    for key, value in summary["platform_counts"].items():
        lines.append(f"- `{key}`: `{value}`")

    lines.extend(["", "## Owner Areas", ""])
    for area in backlog["owner_areas"]:
        lines.extend(
            [
                f"### {area['owner_area']}",
                "",
                f"- Track: `{area['track']}`",
                f"- Items: `{area['item_count']}`",
                f"- Theme: {area['implementation_theme']}",
                "- Primary files:",
            ]
        )
        for path in area["primary_files"]:
            lines.append(f"  - `{path}`")
        lines.extend(["", "| Priority | Platform | Technique | Source rules | Candidate |", "| --- | --- | --- | ---: | --- |"])
        for item in area["top_items"][:12]:
            lines.append(
                f"| `{item['priority']}` | `{item['platform']}` | `{item['technique_id']}` | "
                f"{item['source_rule_count']} | `{item['source_candidate_id']}` |"
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roadmap", type=Path, default=DEFAULT_ROADMAP)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    args = parser.parse_args()

    backlog = build_backlog(load_json(args.roadmap))
    args.out_json.write_text(json.dumps(backlog, indent=2) + "\n", encoding="utf-8")
    args.out_md.write_text(render_markdown(backlog), encoding="utf-8")
    print(f"external_rule_implementation_backlog=ok json={args.out_json} markdown={args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
