#!/usr/bin/env python3
"""Build a live endpoint health bundle from exported Agent API JSON.

Accepted inputs are JSON exports from either:
- /api/v1/agents/data-sources/health, shaped as {"data": [agent health rows]}
- /api/v1/agents/:id, shaped as {"data": {agent detail}}

The probe refuses readiness/synthetic evidence classes. A passing bundle proves
recent live endpoint health for the listed endpoints only.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LIVE_ENDPOINT_EVIDENCE_CLASS = "live_endpoint_health"
SYNTHETIC_EVIDENCE_CLASSES = {
    "readiness",
    "readiness_fixture",
    "synthetic",
    "synthetic_contract",
    "synthetic_parity",
}
PLATFORM_ALIASES = {
    "darwin": "macos",
    "ios": "mobile",
    "android": "mobile",
}
VALID_PLATFORMS = {"linux", "windows", "macos", "mobile"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        parsed = json.load(handle)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return parsed


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def first_string(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def nested(mapping: dict[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def truthy(value: Any) -> bool:
    return value is True or str(value).lower() in {"true", "1", "yes", "healthy", "ok", "online"}


def healthy_status(value: Any) -> bool:
    return str(value or "").lower() in {"healthy", "ok", "online", "isolated", "passing", "pass"}


def normalize_platform(value: Any) -> str:
    platform = str(value or "").lower()
    platform = PLATFORM_ALIASES.get(platform, platform)
    return platform if platform in VALID_PLATFORMS else platform


def evidence_class(payload: dict[str, Any]) -> str:
    return first_string(
        payload.get("evidence_class"),
        payload.get("evidenceClass"),
        nested(payload, "metadata", "evidence_class"),
        nested(payload, "meta", "evidence_class"),
    )


def exported_rows(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    data = payload.get("data", payload)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)], "data_sources_health_export"
    if isinstance(data, dict):
        return [data], "agent_detail_export"
    return [], "unknown_export"


def row_sources(row: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = [
        row.get("sources"),
        row.get("dataSourceHealth"),
        row.get("data_source_health"),
        nested(row, "dataSourceHealth", "sources"),
        nested(row, "data_source_health", "sources"),
    ]
    for candidate in candidates:
        if isinstance(candidate, dict):
            candidate = candidate.get("sources")
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    return []


def source_recent(sources: list[dict[str, Any]]) -> bool:
    for source in sources:
        status = str(source.get("status") or source.get("state") or "").lower()
        count = source.get("count", source.get("eventCount", source.get("event_count", 0)))
        try:
            count_value = int(count or 0)
        except (TypeError, ValueError):
            count_value = 0
        if status == "healthy" and (count_value > 0 or source.get("lastSeen") or source.get("last_seen")):
            return True
    return False


def clock_synchronized(row: dict[str, Any], health_status: dict[str, Any]) -> bool:
    metrics = health_status.get("metrics") if isinstance(health_status.get("metrics"), dict) else {}
    explicit = first_string(
        row.get("clockSynchronized"),
        row.get("clock_synchronized"),
        metrics.get("clock_synchronized"),
        metrics.get("clockSynchronized"),
    )
    if explicit:
        return truthy(explicit)

    skew = metrics.get("clock_skew_ms", metrics.get("clockSkewMs"))
    try:
        return abs(float(skew)) <= 300_000
    except (TypeError, ValueError):
        return False


def normalize_endpoint(row: dict[str, Any], collected_at: str) -> tuple[dict[str, Any], list[str]]:
    health_status = row.get("healthStatus") or row.get("health_status") or row.get("health") or {}
    health_status = health_status if isinstance(health_status, dict) else {"status": health_status}
    sources = row_sources(row)

    endpoint_id = first_string(row.get("agentId"), row.get("agent_id"), row.get("id"), row.get("endpoint_id"))
    platform = normalize_platform(first_string(row.get("osType"), row.get("os_type"), row.get("platform")))
    last_telemetry_at = first_string(row.get("lastTelemetryAt"), row.get("last_telemetry_at"), row.get("last_seen"))
    last_heartbeat_at = first_string(row.get("lastHeartbeatAt"), row.get("last_heartbeat_at"), row.get("last_seen"))
    agent_state = first_string(row.get("heartbeatState"), row.get("status"), health_status.get("status"))

    health = {
        "agent_running": healthy_status(agent_state),
        "telemetry_recent": bool(last_telemetry_at or source_recent(sources)),
        "clock_synchronized": clock_synchronized(row, health_status),
    }
    endpoint = {
        "endpoint_id": endpoint_id,
        "platform": platform,
        "collected_at": collected_at,
        "source": "agent_health_api",
        "health": health,
        "api_fields": {
            "heartbeat_state": agent_state,
            "health_status": health_status.get("status"),
            "last_telemetry_at": last_telemetry_at or None,
            "last_heartbeat_at": last_heartbeat_at or None,
            "healthy_source_count": sum(1 for source in sources if str(source.get("status") or "").lower() == "healthy"),
        },
    }

    errors: list[str] = []
    if not endpoint_id:
        errors.append("missing endpoint id")
    if platform not in VALID_PLATFORMS:
        errors.append(f"unsupported or missing platform: {platform or '<missing>'}")
    failed_checks = [key for key, value in health.items() if value is not True]
    if failed_checks:
        errors.append(f"live health checks did not pass: {', '.join(failed_checks)}")
    return endpoint, errors


def build_bundle(payload: dict[str, Any], *, bundle_id: str | None = None) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    input_evidence_class = evidence_class(payload)
    if input_evidence_class in SYNTHETIC_EVIDENCE_CLASSES:
        errors.append(f"input evidence_class={input_evidence_class!r} is not live endpoint health")

    rows, export_shape = exported_rows(payload)
    if not rows:
        errors.append("input does not contain data-sources health rows or an agent detail object")

    collected_at = first_string(
        payload.get("collected_at"),
        payload.get("collectedAt"),
        nested(payload, "meta", "collected_at"),
        nested(payload, "metadata", "collected_at"),
        utc_now(),
    )
    endpoints: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        endpoint, endpoint_errors = normalize_endpoint(row, collected_at)
        endpoints.append(endpoint)
        errors.extend(f"endpoint[{index}] {message}" for message in endpoint_errors)

    bundle = {
        "schema_version": 1,
        "bundle_id": bundle_id or f"platform-endpoint-health-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "schema": "platform_endpoint_health_bundle.schema.json",
        "evidence_class": LIVE_ENDPOINT_EVIDENCE_CLASS,
        "source_export_shape": export_shape,
        "claim_boundary": (
            "Live endpoint health bundle generated from exported Agent API JSON. "
            "This proves recent agent health for the listed endpoints only; it does "
            "not prove production detection efficacy, packet fidelity, prevention, "
            "or fleet-wide coverage."
        ),
        "endpoints": endpoints,
    }
    return bundle, errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Exported JSON from Agent API or agent detail.")
    parser.add_argument("--output", type=Path, help="Write the generated bundle to this path.")
    parser.add_argument("--bundle-id", help="Override generated bundle_id.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    payload = load_json_file(args.input)
    bundle, errors = build_bundle(payload, bundle_id=args.bundle_id)
    report = {
        "status": "fail" if errors else "pass",
        "bundle": bundle,
        "errors": errors,
    }
    if args.output and not errors:
        write_json(args.output, bundle)
        report["output"] = str(args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
