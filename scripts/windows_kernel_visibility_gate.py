#!/usr/bin/env python3
"""Classify Windows kernel visibility readiness snapshots.

This gate is synthetic and contract-focused. It checks whether a readiness
snapshot has enough evidence to label Windows kernel visibility as active,
degraded, or unavailable without claiming live endpoint enforcement.
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
    "etw_enabled",
    "kernel_process",
    "kernel_file",
    "kernel_network",
    "kernel_registry",
    "dns_client",
    "tamper_detection",
    "driver_embedded",
    "wfp_available",
    "signed_driver",
    "admin_or_service",
)

ACTIVE_REQUIRED_TRUE = tuple(REQUIRED_FIELDS)

UNAVAILABLE_IF_FALSE = (
    "etw_enabled",
    "admin_or_service",
)


@dataclass(frozen=True)
class Classification:
    snapshot_id: str
    classification: str
    expected: str | None
    status: str
    health_label: str
    missing_fields: list[str]
    false_fields: list[str]
    signals: dict[str, bool]
    reasons: list[str]


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def bool_signal(snapshot: dict[str, Any], field: str) -> bool:
    return snapshot.get(field) is True


def classify_snapshot(scenario: dict[str, Any]) -> Classification:
    snapshot = scenario.get("snapshot") if isinstance(scenario.get("snapshot"), dict) else {}
    signals = {field: bool_signal(snapshot, field) for field in REQUIRED_FIELDS}
    missing_fields = [field for field in REQUIRED_FIELDS if field not in snapshot]
    false_fields = [field for field in REQUIRED_FIELDS if field in snapshot and snapshot.get(field) is not True]

    reasons: list[str] = []
    if missing_fields:
        reasons.append("snapshot is missing required readiness fields")

    for field in UNAVAILABLE_IF_FALSE:
        if not signals[field]:
            reasons.append(f"{field} is not available")

    if any(not signals[field] for field in UNAVAILABLE_IF_FALSE):
        classification = "unavailable"
        health_label = "windows_kernel_visibility_unavailable"
    elif all(signals[field] for field in ACTIVE_REQUIRED_TRUE):
        classification = "active"
        health_label = "windows_kernel_visibility_active"
    else:
        classification = "degraded"
        health_label = "windows_kernel_visibility_degraded"
        degraded = [field for field in ACTIVE_REQUIRED_TRUE if not signals[field]]
        reasons.append(f"missing active readiness signals: {', '.join(degraded)}")

    expected = scenario.get("expected_classification")
    status = "pass" if expected == classification else "fail"
    return Classification(
        snapshot_id=str(scenario.get("id") or "<missing-id>"),
        classification=classification,
        expected=str(expected) if expected is not None else None,
        status=status,
        health_label=health_label,
        missing_fields=missing_fields,
        false_fields=false_fields,
        signals=signals,
        reasons=reasons,
    )


def build_report(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    scenarios = payload.get("scenarios") if isinstance(payload, dict) else None
    if not isinstance(scenarios, list):
        raise ValueError(f"{path} does not contain a scenarios list")

    results = [classify_snapshot(scenario).__dict__ for scenario in scenarios]
    failed = [result for result in results if result["status"] == "fail"]
    return {
        "schema_version": 1,
        "kind": "WindowsKernelVisibilityGate",
        "fixture": str(path),
        "status": "fail" if failed else "pass",
        "checked_scenarios": len(results),
        "failed_scenarios": len(failed),
        "classes": list(CLASSES),
        "required_fields": list(REQUIRED_FIELDS),
        "claim_boundary": (
            "Classifies synthetic Windows readiness snapshots only. active means "
            "all required ETW, kernel provider, tamper, embedded-driver, WFP, "
            "driver-signing, DNS ETW, and admin/service signals are present; "
            "degraded means ETW can run but at least one active signal is absent; "
            "unavailable means the base ETW or privilege prerequisite is absent."
        ),
        "results": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="Windows kernel visibility fixture JSON")
    parser.add_argument("--output", type=Path, help="Optional JSON report output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report = build_report(args.fixture)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
