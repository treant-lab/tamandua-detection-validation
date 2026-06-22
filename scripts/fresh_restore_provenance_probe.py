#!/usr/bin/env python3
"""Roadmap B fresh-restore provenance probe.

This probe is intentionally non-destructive. It does not restore a VM and does
not query live alerts. It validates whether the current benchmark corpus carries
enough provenance to support a "Windows 300 after fresh VM restore" claim.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "fresh-restore-provenance-probe"
PROFILE_NAME = "Fresh Restore Provenance Probe"
WINDOWS_300_BATCHES = [f"windows-roadmap-300-batch-{idx:02d}" for idx in range(1, 7)]
REQUIRED_RESTORE_FIELDS = [
    "fresh_restore",
    "restore_started_at",
    "restore_finished_at",
    "snapshot_name",
    "snapshot_id",
    "vmid",
    "agent_id_after_restore",
    "hostname_after_restore",
]
OBSERVED_CONTEXT_FIELDS = [
    "run_id",
    "profile_id",
    "started_at",
    "finished_at",
    "vmid",
    "agent_id",
    "hostname",
]
RESTORE_FIELD_INPUTS = {
    "fresh_restore": {
        "flag": "--fresh-restore",
        "env": "TAMANDUA_FRESH_RESTORE",
        "description": "marks the run as a post-restore benchmark claim",
    },
    "restore_started_at": {
        "flag": "--fresh-restore-started-at",
        "env": "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "description": "UTC timestamp when the restore operation started",
    },
    "restore_finished_at": {
        "flag": "--fresh-restore-finished-at",
        "env": "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "description": "UTC timestamp when the restore operation finished",
    },
    "snapshot_name": {
        "flag": "--fresh-restore-snapshot-name",
        "env": "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "description": "snapshot or restore point name",
    },
    "snapshot_id": {
        "flag": "--fresh-restore-snapshot-id",
        "env": "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "description": "snapshot id, task id, or immutable restore reference",
    },
    "vmid": {
        "flag": "--fresh-restore-vmid",
        "env": "TAMANDUA_FRESH_RESTORE_VMID",
        "description": "VM id used for the restored Windows target",
    },
    "agent_id_after_restore": {
        "flag": "--fresh-restore-agent-id",
        "env": "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "description": "agent identity observed after restore",
    },
    "hostname_after_restore": {
        "flag": "--fresh-restore-hostname",
        "env": "TAMANDUA_FRESH_RESTORE_HOSTNAME",
        "description": "hostname observed after restore",
    },
}


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
    return json.loads(path.read_text(encoding="utf-8"))


def timestamp_key(path: Path) -> str:
    name = path.name
    return name.split("-", 1)[0] if name[:8].isdigit() else name


def artifact_timestamp(report: dict[str, Any], path: Path) -> str:
    run_id = str(report.get("run_id") or "")
    for key in ("finished_at", "started_at", "generated_at"):
        value = report.get(key)
        if isinstance(value, str) and value:
            return value
    if run_id:
        return run_id.split("-", 1)[0]
    return timestamp_key(path)


def latest_artifact_for_profile(profile_id: str) -> tuple[Path | None, dict[str, Any]]:
    candidates: list[tuple[str, Path, dict[str, Any]]] = []
    for path in RUNS_DIR.glob("*.json"):
        if path.name.endswith(".comparison.json") or path.name == "index.json":
            continue
        try:
            data = read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        declared_profile = data.get("profile")
        if isinstance(declared_profile, dict):
            declared_profile = declared_profile.get("profile_id")
        declared = str(data.get("profile_id") or declared_profile or "")
        run_id = str(data.get("run_id") or path.stem)
        if declared == profile_id or profile_id in run_id or profile_id in path.stem:
            candidates.append((artifact_timestamp(data, path), path, data))
    if not candidates:
        return None, {}
    _, path, data = sorted(candidates, key=lambda item: item[0])[-1]
    return path, data


def execution_status(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    mode = str(report.get("mode") or report.get("execution_mode") or "").lower()
    execute = report.get("execute")
    planned = summary.get("planned", 0)
    tests = summary.get("tests", len(report.get("tests") or []))
    reasons = []
    if execute is False:
        reasons.append("execute=false")
    if mode in {"planned", "plan", "dry-run", "dry_run", "report-only", "report_only"}:
        reasons.append(f"mode={mode}")
    try:
        if int(planned or 0) > 0:
            reasons.append("planned>0")
    except (TypeError, ValueError):
        reasons.append("planned:invalid")
    try:
        if int(tests or 0) <= 0:
            reasons.append("tests=0")
    except (TypeError, ValueError):
        reasons.append("tests:invalid")
    return {
        "executed": not reasons,
        "mode": mode or None,
        "execute": execute,
        "planned": planned,
        "tests": tests,
        "reasons": reasons,
    }


def restore_metadata(report: dict[str, Any]) -> dict[str, Any]:
    for key in ("fresh_restore_provenance", "restore_provenance", "vm_restore"):
        value = report.get(key)
        if isinstance(value, dict):
            return value
    metadata = report.get("metadata")
    if isinstance(metadata, dict):
        for key in ("fresh_restore_provenance", "restore_provenance", "vm_restore"):
            value = metadata.get(key)
            if isinstance(value, dict):
                return value
    return {}


def observed_restore_context(report: dict[str, Any]) -> dict[str, Any]:
    """Collect non-claim context that can help diagnose missing provenance."""
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    context: dict[str, Any] = {}
    for field in OBSERVED_CONTEXT_FIELDS:
        value = report.get(field)
        if value in (None, "", []):
            value = metadata.get(field)
        if value not in (None, "", []):
            context[field] = value
    if "profile_id" not in context:
        profile = report.get("profile")
        if isinstance(profile, dict):
            profile = profile.get("profile_id")
        if profile:
            context["profile_id"] = profile
    return context


def make_result(
    test_id: str,
    name: str,
    passed: bool,
    category: str,
    evidence: dict[str, Any],
    missing: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else category,
        "execution_class": "provenance_probe",
        "claim_level": "fresh_restore_claim_boundary",
        "executor_used": PROFILE_ID,
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": "fresh_restore_provenance",
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
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [],
    }


def input_hints_for_fields(fields: list[str]) -> dict[str, dict[str, Any]]:
    return {field: RESTORE_FIELD_INPUTS[field] for field in fields if field in RESTORE_FIELD_INPUTS}


def next_action_hint(tests: list[dict[str, Any]], passed: bool) -> dict[str, Any]:
    missing_profiles: list[str] = []
    non_executed_profiles: list[str] = []
    missing_metadata_profiles: list[str] = []
    field_gaps: dict[str, list[str]] = {}
    blockers: list[str] = []

    for test in tests:
        if test.get("status") == "covered":
            continue
        test_id = str(test.get("id") or "")
        if test_id:
            blockers.append(test_id)
        missing = [str(value) for value in test.get("missing_expected_fields") or []]
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        if test_id == "fresh-restore-windows-300-artifact-set-present":
            missing_profiles = missing
        elif test_id == "fresh-restore-windows-300-artifacts-executed":
            non_executed_profiles = [value.split(":", 1)[0] for value in missing]
        elif test_id == "fresh-restore-provenance-metadata-present":
            missing_metadata_profiles = missing
        elif test_id == "fresh-restore-required-fields-complete":
            raw_gaps = evidence.get("field_gaps")
            if isinstance(raw_gaps, dict):
                field_gaps = {
                    str(profile_id): [str(field) for field in fields]
                    for profile_id, fields in raw_gaps.items()
                    if isinstance(fields, list)
                }

    required_inputs = input_hints_for_fields(REQUIRED_RESTORE_FIELDS)
    rerun_commands = [
        "python tools/detection_validation/fresh_restore_provenance_probe.py --output-dir docs/benchmarks/runs",
    ]
    if passed:
        action = "Fresh-restore provenance is ready; keep the six Windows 300 batch artifacts tied to the same restore window."
    else:
        action = (
            "Restore WIN-TEMPLATE from the selected snapshot, capture the restore metadata inputs, "
            "run all six Windows 300 batches on that restored VM without dry-run mode, then rerun this probe."
        )
    return {
        "missing_profiles": missing_profiles,
        "non_executed_profiles": non_executed_profiles,
        "missing_metadata_profiles": missing_metadata_profiles,
        "field_gaps": field_gaps,
        "required_env": [
            str(details["env"])
            for details in required_inputs.values()
            if details.get("env")
        ],
        "required_inputs": required_inputs,
        "blockers": blockers,
        "rerun_commands": rerun_commands,
        "manual_prerequisites": [
            "Restore WIN-TEMPLATE from the intended Windows 300 snapshot.",
            "Run windows-roadmap-300-batch-01 through windows-roadmap-300-batch-06 on the restored VM.",
            "Attach identical fresh_restore_provenance metadata to all six batch artifacts.",
        ],
        "action": action,
    }


def parse_utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def provenance_field_gaps(metadata: dict[str, Any], report: dict[str, Any]) -> list[str]:
    missing = [field for field in REQUIRED_RESTORE_FIELDS if metadata.get(field) in (None, "", [])]
    if metadata.get("fresh_restore") is not True and "fresh_restore" not in missing:
        missing.append("fresh_restore:true")

    restore_started = parse_utc_timestamp(metadata.get("restore_started_at"))
    restore_finished = parse_utc_timestamp(metadata.get("restore_finished_at"))
    benchmark_started = parse_utc_timestamp(report.get("started_at"))
    if metadata.get("restore_started_at") not in (None, "", []) and restore_started is None:
        missing.append("restore_started_at:valid_utc")
    if metadata.get("restore_finished_at") not in (None, "", []) and restore_finished is None:
        missing.append("restore_finished_at:valid_utc")
    if restore_started and restore_finished and restore_started >= restore_finished:
        missing.append("restore_started_at_before_restore_finished_at")
    if restore_finished and benchmark_started and benchmark_started < restore_finished:
        missing.append("benchmark_started_at_after_restore_finished_at")
    return missing


def build_tests() -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    missing_profiles: list[str] = []
    latest_paths: dict[str, str] = {}
    provenance_by_profile: dict[str, dict[str, Any]] = {}
    observed_context_by_profile: dict[str, dict[str, Any]] = {}
    execution_status_by_profile: dict[str, dict[str, Any]] = {}

    for profile_id in WINDOWS_300_BATCHES:
        path, report = latest_artifact_for_profile(profile_id)
        if not path:
            missing_profiles.append(profile_id)
            continue
        latest[profile_id] = report
        latest_paths[profile_id] = str(path.relative_to(ROOT)).replace("\\", "/")
        provenance_by_profile[profile_id] = restore_metadata(report)
        observed_context_by_profile[profile_id] = observed_restore_context(report)
        execution_status_by_profile[profile_id] = execution_status(report)

    tests = [
        make_result(
            "fresh-restore-windows-300-artifact-set-present",
            "Latest Windows 300 batch artifacts exist for all six batches",
            not missing_profiles,
            "infrastructure",
            {
                "expected_profiles": WINDOWS_300_BATCHES,
                "present_profiles": sorted(latest),
                "latest_paths": latest_paths,
                "observed_context_by_profile": observed_context_by_profile,
            },
            missing_profiles,
        )
    ]

    non_executed_profiles = [
        profile_id
        for profile_id in WINDOWS_300_BATCHES
        if profile_id not in latest or not execution_status_by_profile.get(profile_id, {}).get("executed")
    ]
    tests.append(
        make_result(
            "fresh-restore-windows-300-artifacts-executed",
            "Latest Windows 300 batch artifacts are executed benchmark artifacts, not planned or dry-run records",
            not non_executed_profiles,
            "claim-boundary",
            {
                "latest_paths": latest_paths,
                "execution_status_by_profile": execution_status_by_profile,
                "observed_context_by_profile": observed_context_by_profile,
            },
            [
                f"{profile_id}:{','.join(execution_status_by_profile.get(profile_id, {}).get('reasons') or ['missing_artifact'])}"
                for profile_id in non_executed_profiles
            ],
        )
    )

    missing_metadata_profiles = [profile_id for profile_id in WINDOWS_300_BATCHES if not provenance_by_profile.get(profile_id)]
    tests.append(
        make_result(
            "fresh-restore-provenance-metadata-present",
            "Windows 300 artifacts carry explicit fresh-restore provenance metadata",
            not missing_metadata_profiles,
            "claim-boundary",
            {
                "required_metadata_fields": REQUIRED_RESTORE_FIELDS,
                "required_inputs": input_hints_for_fields(REQUIRED_RESTORE_FIELDS),
                "profiles_with_metadata": [
                    profile_id for profile_id, metadata in provenance_by_profile.items() if metadata
                ],
                "latest_paths": latest_paths,
                "observed_context_by_profile": observed_context_by_profile,
            },
            missing_metadata_profiles,
        )
    )

    field_gaps: dict[str, list[str]] = {}
    for profile_id, metadata in provenance_by_profile.items():
        if not metadata:
            field_gaps[profile_id] = REQUIRED_RESTORE_FIELDS
            continue
        missing = provenance_field_gaps(metadata, latest.get(profile_id) or {})
        if missing:
            field_gaps[profile_id] = missing
    tests.append(
        make_result(
            "fresh-restore-required-fields-complete",
            "Fresh-restore provenance includes snapshot, VM, agent, and timing fields",
            not field_gaps,
            "claim-boundary",
            {
                "required_metadata_fields": REQUIRED_RESTORE_FIELDS,
                "required_inputs": input_hints_for_fields(REQUIRED_RESTORE_FIELDS),
                "field_gaps": field_gaps,
                "observed_context_by_profile": observed_context_by_profile,
            },
            [f"{profile_id}:{','.join(fields)}" for profile_id, fields in field_gaps.items()],
        )
    )

    restore_keys = {
        json.dumps(
            {
                field: metadata.get(field)
                for field in (
                    "snapshot_name",
                    "snapshot_id",
                    "restore_started_at",
                    "restore_finished_at",
                    "vmid",
                    "agent_id_after_restore",
                    "hostname_after_restore",
                )
            },
            sort_keys=True,
        )
        for metadata in provenance_by_profile.values()
        if metadata
    }
    tests.append(
        make_result(
            "fresh-restore-single-provenance-window",
            "All Windows 300 batch artifacts map to one restored VM/provenance window",
            bool(restore_keys) and len(restore_keys) == 1 and not missing_metadata_profiles,
            "claim-boundary",
            {
                "unique_restore_windows": len(restore_keys),
                "restore_windows": sorted(restore_keys),
                "profiles_without_metadata": missing_metadata_profiles,
            },
            ["no single complete restore window"] if len(restore_keys) != 1 or missing_metadata_profiles else [],
        )
    )

    return tests


def write_markdown(report: dict[str, Any], path: Path) -> None:
    observed_context_by_profile: dict[str, dict[str, Any]] = {}
    for test in report.get("tests", []):
        evidence = test.get("evidence") if isinstance(test, dict) else {}
        if isinstance(evidence, dict) and isinstance(evidence.get("observed_context_by_profile"), dict):
            observed_context_by_profile = evidence["observed_context_by_profile"]
            break

    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Profile: `{PROFILE_ID}`",
        f"- Started: `{report['started_at']}`",
        f"- Finished: `{report['finished_at']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        "",
        "## Results",
        "",
        "| Test | Status | Gap | Missing |",
        "|------|--------|-----|---------|",
    ]
    for test in report["tests"]:
        missing = ", ".join(test.get("missing_expected_fields") or []) or "-"
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['gap_category']}` | `{missing}` |")
    lines.extend(
        [
            "",
            "## Required Inputs",
            "",
            "| Field | Flag | Env | Description |",
            "|-------|------|-----|-------------|",
        ]
    )
    for field in REQUIRED_RESTORE_FIELDS:
        details = RESTORE_FIELD_INPUTS[field]
        env = details["env"] or "-"
        lines.append(
            f"| `{field}` | `{details['flag']}` | `{env}` | {details['description']} |"
        )
    action = (report.get("fresh_restore_provenance") or {}).get("next_action") or {}
    if action:
        field_gaps = action.get("field_gaps") if isinstance(action.get("field_gaps"), dict) else {}
        lines.extend(
            [
                "",
                "## Next Action",
                "",
                f"- Missing profiles: `{', '.join(action.get('missing_profiles') or []) or '-'}`",
                f"- Non-executed profiles: `{', '.join(action.get('non_executed_profiles') or []) or '-'}`",
                f"- Missing metadata profiles: `{', '.join(action.get('missing_metadata_profiles') or []) or '-'}`",
                f"- Field gaps: `{json.dumps(field_gaps, sort_keys=True) if field_gaps else '-'}`",
                f"- Required env: `{', '.join(action.get('required_env') or []) or '-'}`",
                f"- Action: {action.get('action') or '-'}",
            ]
        )
    lines.extend(
        [
            "",
            "## Observed Latest Artifact Context",
            "",
            "| Profile | Path | Observed context fields |",
            "|---------|------|-------------------------|",
        ]
    )
    latest_paths = {}
    if report.get("tests"):
        first_evidence = report["tests"][0].get("evidence") or {}
        if isinstance(first_evidence, dict):
            latest_paths = first_evidence.get("latest_paths") or {}
    for profile_id in WINDOWS_300_BATCHES:
        path_value = latest_paths.get(profile_id, "-") if isinstance(latest_paths, dict) else "-"
        context = observed_context_by_profile.get(profile_id, {})
        observed = ", ".join(sorted(context)) if context else "-"
        lines.append(f"| `{profile_id}` | `{path_value}` | `{observed}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact proves whether the current benchmark corpus can support a fresh-restore claim. "
            "It does not perform VM restore and does not prove Windows 300 coverage by itself.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=PROFILE_NAME)
    parser.add_argument(
        "--output-dir",
        default=str(RUNS_DIR),
        help="Directory where JSON/markdown artifacts are written.",
    )
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

    report = {
        "schema_version": 1,
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "name": PROFILE_NAME,
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
            "missing_expected_fields": sum(len(test.get("missing_expected_fields") or []) for test in tests),
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "executor_counts": {PROFILE_ID: len(tests)},
            "claim_level_counts": {"fresh_restore_claim_boundary": len(tests)},
            "category_coverage": {"fresh_restore_provenance": {"covered": covered, "missed": missed}},
        },
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["fresh_restore_provenance_gaps"],
            "actionable_gaps": [
                {
                    "test_id": test["id"],
                    "gap_category": test["gap_category"],
                    "missing": test.get("missing_expected_fields") or [],
                }
                for test in tests
                if test["status"] != "covered"
            ],
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "thresholds": {
                "benchmark_lane": "claim-boundary",
                "requires_fresh_restore_metadata": True,
                "requires_single_restore_window": True,
            },
        },
        "fresh_restore_provenance": {
            "ready_for_fresh_restore_claim": passed,
            "next_action": next_action_hint(tests, passed),
        },
        "scorecard": {
            "maturity_score": 100 if passed else 40,
            "maturity_band": "fresh-restore-provenance-ready" if passed else "fresh-restore-provenance-gaps",
            "recommended_claim": (
                "Windows 300 artifacts carry fresh-restore provenance"
                if passed
                else "Windows 300 coverage cannot be claimed as fresh-restore validated yet"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else ["fresh_restore_provenance_missing"],
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
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    md_path = output_dir / f"{run_id}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    comparison_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"fresh_restore_provenance={'ok' if passed else 'gaps'} json={json_path} markdown={md_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
