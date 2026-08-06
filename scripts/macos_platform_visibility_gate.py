#!/usr/bin/env python3
"""Classify synthetic macOS platform visibility readiness fixtures.

The gate is intentionally contract-focused. It maps which macOS visibility
model is supportable from declared entitlements and permissions without
claiming kernel extension coverage or production endpoint efficacy.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CLASSES = ("active", "degraded", "unavailable")
REQUIRED_FIELDS = (
    "endpoint_security_entitled",
    "sysext_installed",
    "tcc_permissions",
    "bpf_access",
    "network_extension_entitled",
    "dns_log_visibility",
    "full_disk_access",
)


@dataclass(frozen=True)
class Classification:
    scenario_id: str
    category: str
    classification: str
    expected: str | None
    status: str
    missing_minimum_fields: list[str]
    signals: dict[str, str]
    active_capabilities: list[str]
    degraded_capabilities: list[str]
    reasons: list[str]


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def as_bool(value: Any) -> bool:
    return bool(value) if isinstance(value, bool) else str(value).lower() == "true"


def tcc_granted(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return as_bool(value.get(key))
    if isinstance(value, list):
        return key in value
    return False


def tcc_signal(tcc: Any, full_disk_access: bool) -> str:
    if not isinstance(tcc, (dict, list)):
        return "missing"
    automation = tcc_granted(tcc, "automation") or tcc_granted(tcc, "apple_events")
    user_events = tcc_granted(tcc, "accessibility") or tcc_granted(tcc, "input_monitoring")
    if full_disk_access and automation and user_events:
        return "complete"
    if full_disk_access or automation or user_events:
        return "partial"
    return "missing"


def missing_minimum_fields(readiness: dict[str, Any]) -> list[str]:
    return [field for field in REQUIRED_FIELDS if field not in readiness]


def classify_scenario(scenario: dict[str, Any]) -> Classification:
    readiness = scenario.get("readiness") if isinstance(scenario.get("readiness"), dict) else {}
    missing_fields = missing_minimum_fields(readiness)

    endpoint_security_entitled = as_bool(readiness.get("endpoint_security_entitled"))
    sysext_installed = as_bool(readiness.get("sysext_installed"))
    bpf_access = as_bool(readiness.get("bpf_access"))
    network_extension_entitled = as_bool(readiness.get("network_extension_entitled"))
    dns_log_visibility = as_bool(readiness.get("dns_log_visibility"))
    full_disk_access = as_bool(readiness.get("full_disk_access"))
    tcc = readiness.get("tcc_permissions")

    endpoint_security_ready = (
        endpoint_security_entitled
        and sysext_installed
        and full_disk_access
        and tcc_signal(tcc, full_disk_access) in {"complete", "partial"}
    )
    network_ready = network_extension_entitled
    dns_fallback_ready = bpf_access and dns_log_visibility
    any_endpoint_partial = (
        endpoint_security_entitled
        or sysext_installed
        or full_disk_access
        or tcc_signal(tcc, full_disk_access) == "partial"
    )
    any_network_partial = network_extension_entitled or bpf_access or dns_log_visibility

    active_capabilities: list[str] = []
    degraded_capabilities: list[str] = []
    reasons: list[str] = []

    if missing_fields:
        reasons.append("minimum readiness field contract is incomplete")

    if endpoint_security_ready:
        active_capabilities.extend(["process_events", "exec_events", "file_events"])
    elif endpoint_security_entitled or sysext_installed:
        degraded_capabilities.append("endpoint_security_not_fully_ready")
        reasons.append("EndpointSecurity requires entitlement, installed System Extension, FDA, and TCC approval")
    elif full_disk_access or tcc_signal(tcc, full_disk_access) == "partial":
        degraded_capabilities.append("app_only_tcc_or_fda")
        reasons.append("app-only permissions do not provide process/file/exec event streams")
    else:
        reasons.append("EndpointSecurity visibility is unavailable")

    if network_ready:
        active_capabilities.append("app_traffic_visibility")
    elif dns_fallback_ready:
        degraded_capabilities.append("dns_bpf_fallback")
        reasons.append("BPF plus DNS logs can support DNS fallback, not app traffic or VPN-style visibility")
    elif bpf_access or dns_log_visibility:
        degraded_capabilities.append("incomplete_dns_fallback")
        reasons.append("DNS fallback requires both BPF access and DNS log visibility")
    else:
        reasons.append("Network Extension or DNS fallback visibility is unavailable")

    if endpoint_security_ready and (network_ready or dns_fallback_ready):
        classification = "active"
    elif not missing_fields and (any_endpoint_partial or any_network_partial):
        classification = "degraded"
    else:
        classification = "unavailable"

    signals = {
        "endpoint_security": "ready" if endpoint_security_ready else "missing_or_incomplete",
        "system_extension": "installed" if sysext_installed else "missing",
        "tcc": tcc_signal(tcc, full_disk_access),
        "full_disk_access": "granted" if full_disk_access else "missing",
        "network_extension": "entitled" if network_extension_entitled else "missing",
        "bpf_dns_fallback": "ready" if dns_fallback_ready else "missing_or_incomplete",
    }
    expected = scenario.get("expected_classification")
    status = "pass" if expected == classification and not missing_fields else "fail"
    return Classification(
        scenario_id=str(scenario.get("id") or "<missing-id>"),
        category=str(scenario.get("category") or "<missing-category>"),
        classification=classification,
        expected=str(expected) if expected is not None else None,
        status=status,
        missing_minimum_fields=missing_fields,
        signals=signals,
        active_capabilities=active_capabilities,
        degraded_capabilities=degraded_capabilities,
        reasons=reasons,
    )


def build_report(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    scenarios = payload.get("scenarios") if isinstance(payload, dict) else None
    if not isinstance(scenarios, list):
        raise ValueError(f"{path} does not contain a scenarios list")

    results = [classify_scenario(scenario).__dict__ for scenario in scenarios]
    failed = [result for result in results if result["status"] == "fail"]
    return {
        "schema_version": 1,
        "kind": "MacosPlatformVisibilityGate",
        "fixture": str(path),
        "status": "fail" if failed else "pass",
        "checked_scenarios": len(results),
        "failed_scenarios": len(failed),
        "classes": list(CLASSES),
        "required_fields": list(REQUIRED_FIELDS),
        "claim_boundary": (
            "Classifies synthetic macOS visibility readiness only. active means the fixture "
            "has EndpointSecurity/System Extension readiness plus Network Extension or "
            "BPF/DNS fallback evidence. degraded means visibility exists but is incomplete. "
            "unavailable means neither entitlement-backed visibility nor a realistic fallback "
            "is present. This does not prove live collection or kernel extension support."
        ),
        "results": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="macOS platform visibility fixture JSON")
    parser.add_argument("--output", type=Path, help="Optional JSON report output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report = build_report(args.fixture)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
