#!/usr/bin/env python3
"""Validate static replay fixture structure.

This intentionally does not execute Tamandua server code. It keeps replay data
machine-checkable so future Elixir/Phoenix replay tests can consume the same
fixtures without schema drift.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURE_DIR = ROOT / "tools" / "detection_validation" / "fixtures"
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_CONTRACT_GAPS = {
    "alert-quality",
    "analyst-ux",
    "audit",
    "authentication",
    "authorization",
    "claim-boundary",
    "collector",
    "evidence-integrity",
    "identity",
    "integration",
    "normalization",
    "orchestration",
    "reliability",
    "runner",
    "scale",
    "tenant-boundary",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def validate_fixture_file(path: Path) -> list[str]:
    errors: list[str] = []
    data = load_json(path)
    fixtures = data.get("fixtures")
    lanes = data.get("lanes")

    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    if not data.get("fixture_id"):
        errors.append(f"{path}: fixture_id is required")
    if isinstance(lanes, list):
        errors.extend(validate_contract_lanes(path, lanes))
        return errors
    if not isinstance(fixtures, list) or not fixtures:
        errors.append(f"{path}: fixtures must be a non-empty list")
        return errors

    seen_ids: set[str] = set()
    for index, item in enumerate(fixtures):
        prefix = f"{path}:{index}"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: fixture must be an object")
            continue

        fixture_id = item.get("id")
        if not fixture_id:
            errors.append(f"{prefix}: id is required")
        elif fixture_id in seen_ids:
            errors.append(f"{prefix}: duplicate id {fixture_id}")
        else:
            seen_ids.add(str(fixture_id))

        if not item.get("event_type"):
            errors.append(f"{prefix}: event_type is required")
        if not isinstance(item.get("input"), dict):
            errors.append(f"{prefix}: input must be an object")
        expected = item.get("expected")
        if not isinstance(expected, dict):
            errors.append(f"{prefix}: expected must be an object")
            continue

        severity = expected.get("alert_severity")
        is_suppressed = expected.get("suppressed") is True
        if severity is None and is_suppressed:
            pass  # suppressed alerts have no surviving severity
        elif severity not in VALID_SEVERITIES:
            errors.append(f"{prefix}: expected.alert_severity must be one of {sorted(VALID_SEVERITIES)}")
        if not isinstance(expected.get("severity_adjusted"), bool):
            errors.append(f"{prefix}: expected.severity_adjusted must be boolean")
        if "fp_reason" not in expected:
            errors.append(f"{prefix}: expected.fp_reason must be present, use null when not adjusted")

    return errors


def validate_contract_lanes(path: Path, lanes: list[Any]) -> list[str]:
    errors: list[str] = []
    if not lanes:
        return [f"{path}: lanes must be a non-empty list"]

    seen_ids: set[str] = set()
    for lane_index, lane in enumerate(lanes):
        prefix = f"{path}:lane:{lane_index}"
        if not isinstance(lane, dict):
            errors.append(f"{prefix}: lane must be an object")
            continue
        for field in ["roadmap", "profile_id", "owner_area"]:
            if not lane.get(field):
                errors.append(f"{prefix}: {field} is required")
        if not isinstance(lane.get("required_evidence_fields"), list) or not lane["required_evidence_fields"]:
            errors.append(f"{prefix}: required_evidence_fields must be a non-empty list")

        lane_fixtures = lane.get("fixtures")
        if not isinstance(lane_fixtures, list) or not lane_fixtures:
            errors.append(f"{prefix}: fixtures must be a non-empty list")
            continue

        for fixture_index, item in enumerate(lane_fixtures):
            item_prefix = f"{prefix}:fixture:{fixture_index}"
            if not isinstance(item, dict):
                errors.append(f"{item_prefix}: fixture must be an object")
                continue
            fixture_id = item.get("id")
            if not fixture_id:
                errors.append(f"{item_prefix}: id is required")
            elif fixture_id in seen_ids:
                errors.append(f"{item_prefix}: duplicate id {fixture_id}")
            else:
                seen_ids.add(str(fixture_id))
            for field in ["capability", "expected_artifact", "gap_classification", "remaining_gap"]:
                if not item.get(field):
                    errors.append(f"{item_prefix}: {field} is required")
            gap = item.get("gap_classification")
            if gap and gap not in VALID_CONTRACT_GAPS:
                errors.append(
                    f"{item_prefix}: gap_classification must be one of {sorted(VALID_CONTRACT_GAPS)}"
                )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    args = parser.parse_args()

    paths = sorted(args.fixture_dir.glob("*.json"))
    if not paths:
        raise SystemExit(f"no fixture files found under {args.fixture_dir}")

    errors: list[str] = []
    for path in paths:
        errors.extend(validate_fixture_file(path))

    if errors:
        for error in errors:
            print(error)
        return 1

    print(f"validated {len(paths)} replay fixture file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
