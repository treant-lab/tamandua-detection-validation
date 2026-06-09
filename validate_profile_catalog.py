#!/usr/bin/env python3
"""Validate generated detection-validation profile catalog invariants."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIR = ROOT / "tools" / "detection_validation" / "profiles"
ROADMAP_DIR = ROOT / "tools" / "detection_validation" / "roadmaps"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: root must be a JSON object")
    return data


def profile_paths() -> list[Path]:
    return sorted(PROFILE_DIR.glob("*.json"))


def require(condition: bool, errors: list[str], message: str) -> None:
    if not condition:
        errors.append(message)


def validate_profile(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        profile = load_json(path)
    except ValueError as exc:
        errors.append(str(exc))
        return None

    tests = profile.get("tests")
    profile_id = str(profile.get("profile_id") or "")
    require(profile.get("schema_version") == 1, errors, f"{path}: schema_version must be 1")
    require(bool(profile_id), errors, f"{path}: missing profile_id")
    require(isinstance(tests, list), errors, f"{path}: tests must be a list")

    test_ids: list[str] = []
    for index, test in enumerate(tests or []):
        if not isinstance(test, dict):
            errors.append(f"{path}: tests[{index}] must be an object")
            continue
        test_id = str(test.get("id") or "")
        test_ids.append(test_id)
        require(bool(test_id), errors, f"{path}: tests[{index}] missing id")
        require(bool(test.get("name")), errors, f"{path}: {test_id or index} missing name")
        require(bool(test.get("executor")), errors, f"{path}: {test_id or index} missing executor")
        if test.get("executor") in {"command", "atomic_or_command"}:
            require(
                bool(test.get("fallback_command") or test.get("command") or test.get("atomic")),
                errors,
                f"{path}: {test_id or index} has no command/atomic definition",
            )
        require(
            bool(test.get("expected_telemetry")),
            errors,
            f"{path}: {test_id or index} missing expected_telemetry",
        )
        require(
            bool(test.get("expected_fields") or test.get("expected_fields_by_event_type")),
            errors,
            f"{path}: {test_id or index} missing expected field contract",
        )

    duplicates = sorted(item for item, count in Counter(test_ids).items() if item and count > 1)
    for duplicate in duplicates:
        errors.append(f"{path}: duplicate test id {duplicate}")
    return profile


def validate_windows_priority_batches(profiles: dict[str, dict[str, Any]], errors: list[str]) -> None:
    roadmap = load_json(ROADMAP_DIR / "windows_detection_roadmap_300.json")
    scenarios = roadmap.get("scenarios") or []
    expected = Counter(str(item.get("priority")) for item in scenarios)
    expected = Counter({key: value for key, value in expected.items() if key in {"P0", "P1", "P2"}})

    observed: Counter[str] = Counter()
    for profile_id, profile in profiles.items():
        for priority in ("p0", "p1", "p2"):
            if profile_id.startswith(f"windows-roadmap-300-{priority}-batch-"):
                observed[priority.upper()] += len(profile.get("tests") or [])

    for priority in ("P0", "P1", "P2"):
        require(
            observed[priority] == expected[priority],
            errors,
            (
                f"windows {priority} batch count mismatch: "
                f"observed={observed[priority]} expected={expected[priority]}"
            ),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="Require every profile to pass catalog validation")
    args = parser.parse_args()

    errors: list[str] = []
    profiles: dict[str, dict[str, Any]] = {}
    for path in profile_paths():
        profile = validate_profile(path, errors)
        if profile:
            profiles[str(profile.get("profile_id"))] = profile

    validate_windows_priority_batches(profiles, errors)

    if errors:
        print(f"profile_catalog=fail errors={len(errors)}")
        for error in errors:
            print(error)
        return 1 if args.strict else 0

    print(f"profile_catalog=ok profiles={len(profiles)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
