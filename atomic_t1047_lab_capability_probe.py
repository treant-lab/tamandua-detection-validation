#!/usr/bin/env python3
"""Read-only claim-boundary probe for Atomic T1047 lab capability.

This probe does not execute Atomic tests and does not contact the endpoint. It
validates whether the latest ``windows-atomic-extended-safe`` artifact contains
bounded precondition evidence for the T1047 WMIC/WMI lab blocker.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_PATH = ROOT / "tools" / "detection_validation" / "profiles" / "windows_atomic_extended_safe.json"
PROFILE_ID = "atomic-t1047-lab-capability-probe"
SOURCE_PROFILE_ID = "windows-atomic-extended-safe"
TEST_ID = "T1047-wmi-discovery"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--short"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} root must be an object")
    return data


def timestamp_key(path: Path) -> str:
    return path.name.split("-", 1)[0] if path.name[:8].isdigit() else path.name


def declared_profile(data: dict[str, Any]) -> str:
    profile = data.get("profile")
    if isinstance(profile, dict):
        profile = profile.get("profile_id")
    return str(data.get("profile_id") or profile or "")


def latest_source_artifact() -> tuple[Path | None, dict[str, Any]]:
    candidates: list[tuple[int, str, Path, dict[str, Any]]] = []
    for path in RUNS_DIR.glob("*.json"):
        if path.name.endswith(".comparison.json") or path.name == "index.json":
            continue
        try:
            data = read_json(path)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        run_id = str(data.get("run_id") or path.stem)
        if declared_profile(data) == SOURCE_PROFILE_ID or SOURCE_PROFILE_ID in run_id or SOURCE_PROFILE_ID in path.stem:
            test = artifact_test_result(data)
            precondition = test.get("precondition") if isinstance(test.get("precondition"), dict) else {}
            has_t1047 = bool(test)
            has_precondition = bool(precondition)
            # Prefer focused artifacts that carry the T1047 precondition payload
            # over older aggregate exec-batch runs with the same source profile.
            rank = (2 if has_precondition else 1 if has_t1047 else 0)
            candidates.append((rank, timestamp_key(path), path, data))
    if not candidates:
        return None, {}
    _, _, path, data = sorted(candidates, key=lambda item: (item[0], item[1]))[-1]
    return path, data


def profile_test_definition() -> dict[str, Any]:
    profile = read_json(PROFILE_PATH)
    for test in profile.get("tests") or []:
        if isinstance(test, dict) and test.get("id") == TEST_ID:
            return test
    return {}


def artifact_test_result(report: dict[str, Any]) -> dict[str, Any]:
    for test in report.get("tests") or []:
        if isinstance(test, dict) and test.get("id") == TEST_ID:
            return test
    return {}


def nested_values(value: Any, key: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for item_key, item_value in value.items():
            if item_key == key:
                found.append(item_value)
            found.extend(nested_values(item_value, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(nested_values(item, key))
    return found


def result(
    test_id: str,
    name: str,
    passed: bool,
    evidence: dict[str, Any],
    missing: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else "claim-boundary",
        "validation_category": "atomic_t1047_lab_capability",
        "execution_class": "local_artifact_probe",
        "executor_used": PROFILE_ID,
        "fallback_used": False,
        "upstream_backed": False,
        "claim_level": "lab_capability_claim_boundary",
        "techniques": ["T1047"],
        "coverage": {
            "telemetry": "not_expected",
            "fields": "ok" if passed else "missing",
            "detection": "not_expected",
            "alert": "not_expected",
            "correlation": "not_expected",
            "driver_raw": "not_expected",
            "timeline": "not_expected",
            "values": "ok" if passed else "missing",
        },
        "evidence": evidence,
        "missing_expected_fields": missing or [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def build_tests() -> list[dict[str, Any]]:
    source_path, source = latest_source_artifact()
    definition = profile_test_definition()
    artifact_test = artifact_test_result(source)
    precondition = artifact_test.get("precondition") if isinstance(artifact_test.get("precondition"), dict) else {}
    error_codes = {str(value) for value in nested_values(artifact_test, "error_code") if value}
    guest_exit_codes = {str(value) for value in nested_values(precondition, "guest_exit_code") if value is not None}
    command_confirmed = any(value is True for value in nested_values(precondition, "command_confirmed"))
    end_reasons = {str(value) for value in nested_values(precondition, "end_reason") if value}
    output_text = "\n".join(str(value) for value in nested_values(precondition, "guest_stdout") if value)

    source_path_text = str(source_path.relative_to(ROOT)).replace("\\", "/") if source_path else None
    definition_precondition = str(definition.get("precondition_command") or "")
    expected_error_code = str(definition.get("precondition_error_code") or "wmi_cli_unavailable_on_target")

    return [
        result(
            "atomic-t1047-profile-has-wmic-precondition",
            "T1047 profile declares a bounded WMIC precondition",
            bool(definition_precondition and "wmic.exe" in definition_precondition and definition.get("precondition_timeout_seconds")),
            {
                "profile_path": str(PROFILE_PATH.relative_to(ROOT)).replace("\\", "/"),
                "precondition_command": definition_precondition,
                "precondition_timeout_seconds": definition.get("precondition_timeout_seconds"),
                "precondition_error_code": definition.get("precondition_error_code"),
            },
            ["precondition_command", "precondition_timeout_seconds"] if not definition_precondition else [],
        ),
        result(
            "atomic-t1047-latest-artifact-present",
            "Latest windows-atomic-extended-safe artifact includes T1047 result",
            bool(source_path and artifact_test),
            {
                "source_profile_id": SOURCE_PROFILE_ID,
                "source_path": source_path_text,
                "source_run_id": source.get("run_id"),
                "test_id": artifact_test.get("id"),
                "test_status": artifact_test.get("status"),
            },
            ["latest_windows_atomic_extended_safe_t1047_artifact"] if not artifact_test else [],
        ),
        result(
            "atomic-t1047-precondition-executed-bounded",
            "Latest T1047 precondition executed through live response and completed bounded",
            bool(command_confirmed and "command_confirmed" in end_reasons),
            {
                "source_path": source_path_text,
                "source_run_id": source.get("run_id"),
                "command_confirmed": command_confirmed,
                "end_reasons": sorted(end_reasons),
                "guest_exit_codes": sorted(guest_exit_codes),
            },
            ["command_confirmed_end_reason"] if not command_confirmed else [],
        ),
        result(
            "atomic-t1047-wmic-unavailable-classified",
            "Latest T1047 artifact classifies WMIC absence instead of running an unsupported scenario",
            bool(expected_error_code in error_codes and "2" in guest_exit_codes and "__TAMANDUA_CTL_DONE_1__:2" in output_text),
            {
                "source_path": source_path_text,
                "source_run_id": source.get("run_id"),
                "expected_error_code": expected_error_code,
                "observed_error_codes": sorted(error_codes),
                "guest_exit_codes": sorted(guest_exit_codes),
                "done_marker_exit_2_observed": "__TAMANDUA_CTL_DONE_1__:2" in output_text,
            },
            ["wmi_cli_unavailable_on_target", "guest_exit_code=2"] if expected_error_code not in error_codes else [],
        ),
    ]


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# Atomic T1047 Lab Capability Probe",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Profile: `{PROFILE_ID}`",
        f"- Source profile: `{SOURCE_PROFILE_ID}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        "",
        "## Results",
        "",
        "| Test | Status | Missing |",
        "|------|--------|---------|",
    ]
    for test in report["tests"]:
        missing = ", ".join(test.get("missing_expected_fields") or []) or "-"
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{missing}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact proves only the local lab capability boundary for T1047/WMIC using archived Atomic artifacts. "
            "It does not execute Atomic Red Team, does not prove WMI telemetry, and does not close Roadmap M.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    started = utc_now()
    tests = build_tests()
    finished = utc_now()
    passed = all(test["status"] == "covered" for test in tests)
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"
    failures = [] if passed else ["atomic_t1047_lab_capability_gaps"]

    report: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "name": "Atomic T1047 Lab Capability Probe",
        "mode": "execute",
        "benchmark_lane": "claim-boundary",
        "started_at": started,
        "finished_at": finished,
        "git": git_snapshot(),
        "summary": {
            "tests": len(tests),
            "covered": covered,
            "missed": missed,
            "partial": 0,
            "execution_failed": 0,
            "unknown_source_events": 0,
            "unexpected_high_or_critical_events": 0,
            "unexpected_high_or_critical_alerts": 0,
            "gap_category_counts": {
                "claim-boundary": missed,
            }
            if missed
            else {},
            "category_coverage": {"atomic_t1047_lab_capability": {"covered": covered, "missed": missed}},
            "executor_counts": {PROFILE_ID: len(tests)},
            "claim_level_counts": {"lab_capability_claim_boundary": len(tests)},
        },
        "quality_gate": {
            "passed": passed,
            "failures": failures,
            "actionable_gaps": [
                {
                    "test_id": test["id"],
                    "gap_category": test["gap_category"],
                    "missing": test.get("missing_expected_fields") or [],
                }
                for test in tests
                if test["status"] != "covered"
            ],
        },
        "scorecard": {
            "maturity_score": 80 if passed else 40,
            "maturity_band": "lab-capability-boundary-recorded" if passed else "lab-capability-boundary-gaps",
            "recommended_claim": (
                "T1047 is blocked by lab WMIC capability, with bounded precondition evidence"
                if passed
                else "T1047 lab capability boundary is not fully evidenced"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": failures,
            "covered_rate": covered / len(tests) if tests else 0,
            "telemetry_rate": 1.0,
            "field_quality": 1.0 if passed else 0.0,
            "context_quality": 1.0 if passed else 0.0,
            "analytic_quality": 1.0,
            "noise_quality": 1.0,
            "driver_quality": 1.0,
            "upstream_rate": 0.0,
        },
        "tests": tests,
        "claim_boundary": "Local read-only artifact interpretation only; no endpoint/server mutation.",
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    comparison_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(report, md_path)
    print(f"atomic_t1047_lab_capability={'ok' if passed else 'gaps'} json={json_path} markdown={md_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
