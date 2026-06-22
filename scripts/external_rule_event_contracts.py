#!/usr/bin/env python3
"""Generate event contracts required by external-rule-inspired benchmarks."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
DEFAULT_ROADMAP = ROOT / "tools" / "detection_validation" / "roadmaps" / "external_rule_global_improvement_roadmap.json"
DEFAULT_OUT_JSON = ROOT / "tools" / "detection_validation" / "roadmaps" / "external_rule_event_contracts.json"
DEFAULT_OUT_MD = ROOT / "docs" / "benchmarks" / "EXTERNAL_RULE_EVENT_CONTRACTS.md"


EVENT_TARGETS: dict[str, dict[str, Any]] = {
    "process_create": {
        "owner_area": "agent_process_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["ProcessCreate", "process_create"],
        "source_names": ["endpoint_process", "kernel_driver", "auditd"],
        "primary_files": [
            "apps/tamandua_agent/src/collectors/process.rs",
            "apps/tamandua_agent/src/collectors/linux/event_normalizer.rs",
        ],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "process_name", "command_line"],
    },
    "file_create": {
        "owner_area": "agent_file_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["FileCreate", "file_create"],
        "source_names": ["endpoint_file", "kernel_driver", "fim", "auditd"],
        "primary_files": [
            "apps/tamandua_agent/src/collectors/file.rs",
            "apps/tamandua_agent/src/collectors/fim.rs",
            "apps/tamandua_agent/src/collectors/file_journal.rs",
        ],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "file_path", "pid"],
    },
    "file_modify": {
        "owner_area": "agent_file_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["FileModify", "file_modify", "file_write"],
        "source_names": ["endpoint_file", "kernel_driver", "fim", "auditd"],
        "primary_files": [
            "apps/tamandua_agent/src/collectors/file.rs",
            "apps/tamandua_agent/src/collectors/fim.rs",
            "apps/tamandua_agent/src/collectors/file_journal.rs",
        ],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "file_path", "pid"],
    },
    "file_read": {
        "owner_area": "agent_file_read_collector",
        "runtime_status": "planned",
        "agent_event_aliases": ["file_read"],
        "source_names": ["credential_theft", "auditd", "kernel_driver"],
        "primary_files": [
            "apps/tamandua_agent/src/collectors/file.rs",
            "apps/tamandua_agent/src/collectors/credential_theft.rs",
        ],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "file_path", "pid", "user"],
    },
    "network_connect": {
        "owner_area": "agent_network_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["NetworkConnect", "network_connect"],
        "source_names": ["endpoint_network", "auditd"],
        "primary_files": [
            "apps/tamandua_agent/src/collectors/network.rs",
            "apps/tamandua_agent/src/collectors/network_anomaly.rs",
        ],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "remote_address", "remote_port", "pid"],
    },
    "dns_query": {
        "owner_area": "agent_network_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["DnsQuery", "dns_query"],
        "source_names": ["endpoint_dns"],
        "primary_files": ["apps/tamandua_agent/src/collectors/dns.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "remote_domain", "pid"],
    },
    "registry_modify": {
        "owner_area": "windows_registry_directory_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["RegistryCreate", "RegistrySetValue", "RegistryDelete", "registry_set_value", "registry_delete"],
        "source_names": ["endpoint_registry", "kernel_driver", "etw"],
        "primary_files": [
            "apps/tamandua_agent/src/collectors/registry.rs",
            "apps/tamandua_agent/src/collectors/etw.rs",
        ],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "registry_key", "registry_value", "pid"],
    },
    "auth_event": {
        "owner_area": "identity_auth_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["AuthLogin", "AuthFailed", "auth_event"],
        "source_names": ["endpoint_auth", "auditd", "windows_security"],
        "primary_files": [
            "apps/tamandua_agent/src/collectors/identity.rs",
            "apps/tamandua_agent/src/collectors/lateral_movement.rs",
        ],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "user"],
    },
    "failed_login": {
        "owner_area": "identity_auth_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["AuthFailed", "failed_login"],
        "source_names": ["endpoint_auth", "auditd", "windows_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/identity.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "user", "failure_count"],
    },
    "session_start": {
        "owner_area": "identity_auth_collector",
        "runtime_status": "normalize-alias",
        "agent_event_aliases": ["AuthLogin", "session_start"],
        "source_names": ["endpoint_auth", "auditd", "windows_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/identity.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "user", "logon_type"],
    },
    "account_change": {
        "owner_area": "identity_auth_collector",
        "runtime_status": "planned",
        "agent_event_aliases": ["account_change"],
        "source_names": ["endpoint_auth", "ad_monitor", "windows_security"],
        "primary_files": [
            "apps/tamandua_agent/src/collectors/identity.rs",
            "apps/tamandua_agent/src/collectors/ad_monitor.rs",
        ],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "actor_user", "target_domain"],
    },
    "privilege_change": {
        "owner_area": "identity_auth_collector",
        "runtime_status": "planned",
        "agent_event_aliases": ["privilege_change"],
        "source_names": ["endpoint_auth", "ad_monitor", "windows_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/identity.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "actor_user", "change_type"],
    },
    "security_event": {
        "owner_area": "specialized_context_collectors",
        "runtime_status": "normalize-alias",
        "agent_event_aliases": ["security_event"],
        "source_names": ["windows_security", "endpoint_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/endpoint_security.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "security_product"],
    },
    "directory_change": {
        "owner_area": "windows_registry_directory_collector",
        "runtime_status": "planned",
        "agent_event_aliases": ["directory_change"],
        "source_names": ["ad_monitor", "windows_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/ad_monitor.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "policy_object", "actor_user"],
    },
    "service_create": {
        "owner_area": "service_persistence_collector",
        "runtime_status": "planned",
        "agent_event_aliases": ["service_create"],
        "source_names": ["persistence", "scheduled_tasks", "windows_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/persistence.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "service_name", "service_path"],
    },
    "service_modify": {
        "owner_area": "service_persistence_collector",
        "runtime_status": "planned",
        "agent_event_aliases": ["service_modify"],
        "source_names": ["persistence", "scheduled_tasks", "windows_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/persistence.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "service_name", "service_path"],
    },
    "scheduled_event": {
        "owner_area": "service_persistence_collector",
        "runtime_status": "existing",
        "agent_event_aliases": ["ScheduledTask", "scheduled_event"],
        "source_names": ["scheduled_tasks", "persistence"],
        "primary_files": ["apps/tamandua_agent/src/collectors/scheduled_tasks.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "trigger_path", "trigger_type"],
    },
    "process_access": {
        "owner_area": "deep_endpoint_sensor",
        "runtime_status": "planned",
        "agent_event_aliases": ["ProcessInject", "process_access"],
        "source_names": ["injection", "kernel_driver", "endpoint_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/injection.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "source_process", "target_process", "access_mask"],
    },
    "memory_event": {
        "owner_area": "deep_endpoint_sensor",
        "runtime_status": "existing",
        "agent_event_aliases": ["MemoryScan", "memory_event"],
        "source_names": ["memory", "kernel_driver"],
        "primary_files": ["apps/tamandua_agent/src/collectors/memory.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "target_process"],
    },
    "image_load": {
        "owner_area": "deep_endpoint_sensor",
        "runtime_status": "existing",
        "agent_event_aliases": ["module_load", "image_load"],
        "source_names": ["kernel_driver", "endpoint_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/endpoint_security.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "file_path", "pid"],
    },
    "wmi_event": {
        "owner_area": "windows_registry_directory_collector",
        "runtime_status": "planned",
        "agent_event_aliases": ["wmi_event"],
        "source_names": ["etw", "windows_security"],
        "primary_files": ["apps/tamandua_agent/src/collectors/etw.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "actor_process"],
    },
    "web_request": {
        "owner_area": "agent_network_collector",
        "runtime_status": "planned",
        "agent_event_aliases": ["web_request"],
        "source_names": ["network_dpi", "cloud"],
        "primary_files": ["apps/tamandua_agent/src/collectors/network_dpi.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "remote_domain", "remote_address"],
    },
    "rate_window": {
        "owner_area": "detection_engine",
        "runtime_status": "planned",
        "agent_event_aliases": ["rate_window"],
        "source_names": ["detection_engine"],
        "primary_files": ["tools/detection_response", "apps/tamandua_agent/src/detection"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "failure_count", "time_window"],
    },
    "secret_scan": {
        "owner_area": "specialized_context_collectors",
        "runtime_status": "existing",
        "agent_event_aliases": ["SecretExposure", "secret_scan"],
        "source_names": ["credential_theft", "script_inspector"],
        "primary_files": ["apps/tamandua_agent/src/collectors/credential_theft.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "file_path"],
    },
    "mail_access": {
        "owner_area": "specialized_context_collectors",
        "runtime_status": "existing",
        "agent_event_aliases": ["mail_access"],
        "source_names": ["office_email"],
        "primary_files": ["apps/tamandua_agent/src/collectors/office_email.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type", "user"],
    },
    "resource_usage": {
        "owner_area": "specialized_context_collectors",
        "runtime_status": "existing",
        "agent_event_aliases": ["resource_usage"],
        "source_names": ["health"],
        "primary_files": ["apps/tamandua_agent/src/collectors/health.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type"],
    },
    "service_health": {
        "owner_area": "specialized_context_collectors",
        "runtime_status": "existing",
        "agent_event_aliases": ["service_health"],
        "source_names": ["health"],
        "primary_files": ["apps/tamandua_agent/src/collectors/health.rs"],
        "minimum_fields": ["agent_id", "hostname", "timestamp", "event_type"],
    },
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def priority_rank(priority: str) -> int:
    return {"p0-gap": 0, "p1-high-signal": 1, "p2-roadmap-hardening": 2, "p3-backlog": 3}.get(priority, 9)


def build_contracts(roadmap: dict[str, Any]) -> dict[str, Any]:
    event_usage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    field_usage: dict[str, Counter[str]] = defaultdict(Counter)

    for item in roadmap.get("items") or []:
        contract = item.get("collector_contract") or {}
        events = [str(event) for event in contract.get("required_events") or []]
        fields = [str(field) for field in contract.get("required_fields") or []]
        for event in events:
            event_usage[event].append(
                {
                    "source_candidate_id": item.get("source_candidate_id"),
                    "platform": item.get("platform"),
                    "technique_id": item.get("technique_id"),
                    "priority": item.get("priority"),
                    "source_rule_count": item.get("source_rule_count"),
                    "source_mix": item.get("source_mix"),
                }
            )
            field_usage[event].update(fields)

    contracts = []
    for event_type, usages in sorted(event_usage.items()):
        target = EVENT_TARGETS.get(event_type, {})
        sorted_usages = sorted(
            usages,
            key=lambda item: (
                priority_rank(str(item.get("priority"))),
                str(item.get("platform")),
                -int(item.get("source_rule_count") or 0),
                str(item.get("technique_id")),
            ),
        )
        observed_fields = [field for field, _ in field_usage[event_type].most_common()]
        minimum_fields = list(dict.fromkeys(target.get("minimum_fields", []) + observed_fields[:8]))
        contracts.append(
            {
                "event_type": event_type,
                "runtime_status": target.get("runtime_status", "unmapped"),
                "owner_area": target.get("owner_area", "unmapped"),
                "agent_event_aliases": target.get("agent_event_aliases", []),
                "source_names": target.get("source_names", []),
                "primary_files": target.get("primary_files", []),
                "minimum_fields": minimum_fields,
                "usage": {
                    "item_count": len(usages),
                    "priority_counts": dict(Counter(str(item.get("priority")) for item in usages)),
                    "platform_counts": dict(Counter(str(item.get("platform")) for item in usages)),
                    "top_candidates": sorted_usages[:15],
                },
            }
        )

    return {
        "schema_version": 1,
        "source": "tools/detection_validation/roadmaps/external_rule_global_improvement_roadmap.json",
        "normalization_target": "tamandua.events.v1",
        "runtime_effect": "none",
        "summary": {
            "event_type_count": len(contracts),
            "runtime_status_counts": dict(Counter(contract["runtime_status"] for contract in contracts)),
            "owner_area_counts": dict(Counter(contract["owner_area"] for contract in contracts)),
        },
        "contracts": contracts,
    }


def render_markdown(contract_map: dict[str, Any]) -> str:
    summary = contract_map["summary"]
    lines = [
        "# External Rule Event Contracts",
        "",
        "Status: generated implementation contract",
        "Last updated: 2026-05-28",
        "",
        "This file maps external-rule-inspired semantic rewrite coverage to Tamandua normalized event contracts.",
        "It is a planning and validation artifact only; it does not copy external rule bodies or change runtime behavior.",
        "",
        "## Summary",
        "",
        f"- Event types: `{summary['event_type_count']}`",
        f"- Normalization target: `{contract_map['normalization_target']}`",
        "",
        "Runtime status counts:",
        "",
    ]
    for status, count in summary["runtime_status_counts"].items():
        lines.append(f"- `{status}`: `{count}`")

    lines.extend(
        [
            "",
            "## Contracts",
            "",
            "| Event type | Status | Owner | Items | Required aliases | Primary files |",
            "| --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for contract in contract_map["contracts"]:
        aliases = ", ".join(f"`{alias}`" for alias in contract["agent_event_aliases"][:4])
        files = ", ".join(f"`{path}`" for path in contract["primary_files"][:2])
        lines.append(
            f"| `{contract['event_type']}` | `{contract['runtime_status']}` | "
            f"`{contract['owner_area']}` | {contract['usage']['item_count']} | {aliases} | {files} |"
        )

    lines.extend(
        [
            "",
            "## Immediate Implementation Rule",
            "",
            "P0/P1 benchmark work can use `existing` and `normalize-alias` contracts immediately.",
            "`planned` contracts must land with collector/schema changes or remain `report_only` until implemented.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roadmap", type=Path, default=DEFAULT_ROADMAP)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    args = parser.parse_args()

    contract_map = build_contracts(load_json(args.roadmap))
    args.out_json.write_text(json.dumps(contract_map, indent=2) + "\n", encoding="utf-8")
    args.out_md.write_text(render_markdown(contract_map), encoding="utf-8")
    print(
        "external_rule_event_contracts=ok "
        f"contracts={contract_map['summary']['event_type_count']} json={args.out_json} markdown={args.out_md}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
