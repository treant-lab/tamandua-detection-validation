#!/usr/bin/env python3
"""Validate report-only roadmap contract fixtures.

This is an offline shape check for K/N/S/T-style roadmap contracts. It does not
contact the Tamandua server, read benchmark run artifacts, or execute profiles.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURE = ROOT / "tools" / "detection_validation" / "fixtures" / "roadmap_k_n_s_t_contracts_v1.json"
REQUIRED_ROADMAPS = {"K", "N", "S", "T"}
VALID_GAP_CLASSES = {
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
    "scale",
    "tenant-boundary",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def validate_lane(path: Path, lane: dict[str, Any], seen_roadmaps: set[str]) -> list[str]:
    errors: list[str] = []
    prefix = f"{path}:roadmap:{lane.get('roadmap', '<missing>')}"

    roadmap = lane.get("roadmap")
    if roadmap not in REQUIRED_ROADMAPS:
        errors.append(f"{prefix}: roadmap must be one of {sorted(REQUIRED_ROADMAPS)}")
    elif roadmap in seen_roadmaps:
        errors.append(f"{prefix}: duplicate roadmap {roadmap}")
    else:
        seen_roadmaps.add(str(roadmap))

    if not lane.get("profile_id"):
        errors.append(f"{prefix}: profile_id is required")
    if not lane.get("owner_area"):
        errors.append(f"{prefix}: owner_area is required")

    capabilities = lane.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        errors.append(f"{prefix}: capabilities must be a non-empty list")
        capabilities = []

    required_fields = lane.get("required_evidence_fields")
    if not isinstance(required_fields, list) or len(required_fields) < 4:
        errors.append(f"{prefix}: required_evidence_fields must contain at least 4 fields")

    fixtures = lane.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        errors.append(f"{prefix}: fixtures must be a non-empty list")
        return errors

    seen_fixture_ids: set[str] = set()
    for index, fixture in enumerate(fixtures):
        item_prefix = f"{prefix}:fixture:{index}"
        if not isinstance(fixture, dict):
            errors.append(f"{item_prefix}: fixture must be an object")
            continue
        fixture_id = fixture.get("id")
        if not fixture_id:
            errors.append(f"{item_prefix}: id is required")
        elif fixture_id in seen_fixture_ids:
            errors.append(f"{item_prefix}: duplicate fixture id {fixture_id}")
        else:
            seen_fixture_ids.add(str(fixture_id))
        if fixture.get("capability") not in capabilities:
            errors.append(f"{item_prefix}: capability must be declared in lane.capabilities")
        if not fixture.get("expected_artifact"):
            errors.append(f"{item_prefix}: expected_artifact is required")
        if fixture.get("gap_classification") not in VALID_GAP_CLASSES:
            errors.append(f"{item_prefix}: gap_classification must be one of {sorted(VALID_GAP_CLASSES)}")
        if not fixture.get("remaining_gap"):
            errors.append(f"{item_prefix}: remaining_gap is required")

    return errors


def validate_fixture(path: Path) -> list[str]:
    errors: list[str] = []
    data = load_json(path)
    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    if not data.get("fixture_id"):
        errors.append(f"{path}: fixture_id is required")
    if not data.get("claim_boundary"):
        errors.append(f"{path}: claim_boundary is required")

    lanes = data.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        errors.append(f"{path}: lanes must be a non-empty list")
        return errors

    seen_roadmaps: set[str] = set()
    for lane in lanes:
        if not isinstance(lane, dict):
            errors.append(f"{path}: lane must be an object")
            continue
        errors.extend(validate_lane(path, lane, seen_roadmaps))

    missing = REQUIRED_ROADMAPS - seen_roadmaps
    if missing:
        errors.append(f"{path}: missing required roadmaps {sorted(missing)}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()

    errors = validate_fixture(args.fixture)
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"validated roadmap contract fixture {args.fixture}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
