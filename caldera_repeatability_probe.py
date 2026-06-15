#!/usr/bin/env python3
"""Roadmap D CALDERA repeatability probe.

This probe is local and non-destructive. It does not call CALDERA and does not
create operations. It reads archived benchmark artifacts and answers whether the
selected CALDERA profiles have three consecutive passing runs with upstream
operation evidence.
"""

from __future__ import annotations

import argparse
import json
import subprocess
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
PROFILE_ID = "caldera-repeatability-probe"
PROFILE_NAME = "CALDERA Repeatability Probe"
CALDERA_PROFILES = ["windows-caldera-smoke", "windows-caldera-enterprise-safe"]
REQUIRED_CONSECUTIVE_PASSES = 3
HISTORY_LIMIT = 5
PROFILE_FILES = {
    "windows-caldera-smoke": "tools/detection_validation/profiles/windows_caldera_smoke.json",
    "windows-caldera-enterprise-safe": "tools/detection_validation/profiles/windows_caldera_enterprise_safe.json",
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


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def profile_id(report: dict[str, Any]) -> str:
    profile = report.get("profile")
    if isinstance(profile, dict):
        return str(report.get("profile_id") or profile.get("profile_id") or "")
    return str(report.get("profile_id") or profile or "")


def run_id(path: Path, report: dict[str, Any]) -> str:
    return str(report.get("run_id") or path.name.removesuffix(".comparison.json").removesuffix(".json"))


def timestamp_key(path: Path, report: dict[str, Any]) -> str:
    return str(report.get("finished_at") or report.get("started_at") or run_id(path, report))


def quality_passed(report: dict[str, Any]) -> bool:
    return bool((report.get("quality_gate") or {}).get("passed"))


def executor_counts(report: dict[str, Any]) -> dict[str, Any]:
    return (report.get("summary") or {}).get("executor_counts") or {}


def upstream_backed(report: dict[str, Any]) -> bool:
    summary = report.get("summary") or {}
    return int(summary.get("upstream_backed_tests") or 0) > 0 or int(executor_counts(report).get("caldera_operation") or 0) > 0


def caldera_error_codes(report: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    for test in report.get("tests") or []:
        if not isinstance(test, dict):
            continue
        execution = test.get("execution") if isinstance(test.get("execution"), dict) else {}
        code = execution.get("error_code") or ((execution.get("caldera_proof") or {}).get("error_code"))
        if code:
            codes.append(str(code))
        proof = execution.get("caldera_proof") if isinstance(execution.get("caldera_proof"), dict) else {}
        preflight = proof.get("agent_preflight") if isinstance(proof.get("agent_preflight"), dict) else {}
        for issue in preflight.get("issues") or []:
            codes.append(str(issue))
    return sorted(set(codes))


def compact_run(path: Path, report: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": run_id(path, report),
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "timestamp": timestamp_key(path, report),
        "quality_gate_passed": quality_passed(report),
        "upstream_backed": upstream_backed(report),
        "error_codes": caldera_error_codes(report),
    }


def streak_reset_reason(report: dict[str, Any]) -> str:
    if not quality_passed(report):
        codes = caldera_error_codes(report)
        return f"quality_gate_failed:{','.join(codes)}" if codes else "quality_gate_failed"
    if not upstream_backed(report):
        return "missing_upstream_caldera_operation_evidence"
    return "none"


def latest_streak_reset(reports: list[tuple[Path, dict[str, Any]]]) -> dict[str, Any] | None:
    for path, report in reversed(reports):
        reason = streak_reset_reason(report)
        if reason != "none":
            return {
                "run_id": run_id(path, report),
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "reason": reason,
            }
    return None


def reports_for_profile(target_profile: str) -> list[tuple[Path, dict[str, Any]]]:
    reports: list[tuple[str, Path, dict[str, Any]]] = []
    for path in RUNS_DIR.glob(f"*{target_profile}*.json"):
        if path.name == "index.json" or path.name.endswith(".comparison.json"):
            continue
        report = read_json(path)
        if not report:
            continue
        if profile_id(report) == target_profile or target_profile in run_id(path, report):
            reports.append((timestamp_key(path, report), path, report))
    return [(path, report) for _, path, report in sorted(reports, key=lambda item: item[0])]


def consecutive_passes(reports: list[tuple[Path, dict[str, Any]]]) -> list[tuple[Path, dict[str, Any]]]:
    streak: list[tuple[Path, dict[str, Any]]] = []
    for path, report in reports:
        if quality_passed(report) and upstream_backed(report):
            streak.append((path, report))
        else:
            streak = []
    return streak


def next_action_hint(target_profile: str, streak_len: int, passed: bool) -> dict[str, Any]:
    passes_needed = max(0, REQUIRED_CONSECUTIVE_PASSES - streak_len)
    profile_file = PROFILE_FILES.get(target_profile, f"tools/detection_validation/profiles/{target_profile}.json")
    command = (
        "python tools/detection_validation/tamandua_detection_validation.py "
        f"--profile {profile_file} "
        "--benchmark-lane caldera-upstream "
        "--caldera-url $env:CALDERA_URL "
        "--caldera-group $env:CALDERA_GROUP "
        "--caldera-agent-paw $env:CALDERA_AGENT_PAW "
        "--caldera-timeout-seconds 600 "
        "--caldera-poll-seconds 10"
    )
    return {
        "next_profile_to_run": None if passed else target_profile,
        "profile_file": profile_file,
        "passes_needed": passes_needed,
        "required_consecutive_passes": REQUIRED_CONSECUTIVE_PASSES,
        "next_command_hint": None if passed else command,
        "required_env": [] if passed else ["CALDERA_API_KEY", "CALDERA_GROUP", "CALDERA_AGENT_PAW"],
    }


def make_result(test_id: str, name: str, passed: bool, category: str, evidence: dict[str, Any], missing: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else category,
        "execution_class": "repeatability_probe",
        "claim_level": "caldera_repeatability_claim_boundary",
        "executor_used": PROFILE_ID,
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": "caldera_repeatability",
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


def build_tests() -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for target_profile in CALDERA_PROFILES:
        reports = reports_for_profile(target_profile)
        streak = consecutive_passes(reports)
        latest_path, latest = reports[-1] if reports else (None, {})
        evidence = {
            "profile_id": target_profile,
            "artifact_count": len(reports),
            "required_consecutive_passes": REQUIRED_CONSECUTIVE_PASSES,
            "consecutive_passing_tail": len(streak),
            "history_limit": HISTORY_LIMIT,
            "recent_history": [compact_run(path, report) for path, report in reports[-HISTORY_LIMIT:]],
            "latest_streak_reset": latest_streak_reset(reports),
            "latest_run_id": run_id(latest_path, latest) if latest_path else None,
            "latest_path": str(latest_path.relative_to(ROOT)).replace("\\", "/") if latest_path else None,
            "latest_quality_gate_passed": quality_passed(latest) if latest else False,
            "latest_error_codes": caldera_error_codes(latest) if latest else [],
            "passing_tail_run_ids": [run_id(path, report) for path, report in streak],
        }
        passed = len(streak) >= REQUIRED_CONSECUTIVE_PASSES
        evidence["next_action"] = next_action_hint(target_profile, len(streak), passed)
        category = "upstream" if reports else "infrastructure"
        if evidence["latest_error_codes"]:
            category = "runner"
        tests.append(
            make_result(
                f"caldera-repeatability-{target_profile}",
                f"{target_profile} has {REQUIRED_CONSECUTIVE_PASSES} consecutive upstream-backed passes",
                passed,
                category,
                evidence,
                [] if passed else [f"{len(streak)}/{REQUIRED_CONSECUTIVE_PASSES} consecutive passes"],
            )
        )
    return tests


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        "",
        "## Results",
        "",
        "| Test | Status | Gap | Latest | Passing tail | Needed | Latest reset | Missing |",
        "|------|--------|-----|--------|--------------|--------|--------------|---------|",
    ]
    for test in report["tests"]:
        evidence = test.get("evidence") or {}
        missing = ", ".join(test.get("missing_expected_fields") or []) or "-"
        lines.append(
            f"| `{test['id']}` | `{test['status']}` | `{test['gap_category']}` | "
            f"`{evidence.get('latest_run_id') or '-'}` | "
            f"`{evidence.get('consecutive_passing_tail')}/{evidence.get('required_consecutive_passes')}` | "
            f"`{(evidence.get('next_action') or {}).get('passes_needed')}` | "
            f"`{(evidence.get('latest_streak_reset') or {}).get('reason') or '-'}` | "
            f"`{missing}` |"
        )
    lines.extend(
        [
            "",
            "## Next Actions",
            "",
            "| Profile | Passes needed | Required env | Command hint |",
            "|---------|---------------|--------------|--------------|",
        ]
    )
    for test in report["tests"]:
        evidence = test.get("evidence") or {}
        action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        if not action or not action.get("next_profile_to_run"):
            continue
        env_text = ", ".join(action.get("required_env") or []) or "-"
        lines.append(
            f"| `{action.get('next_profile_to_run')}` | `{action.get('passes_needed')}` | "
            f"`{env_text}` | `{action.get('next_command_hint')}` |"
        )
    lines.extend(
        [
            "",
            "## Recent Artifact History",
            "",
            "| Profile | Run | Gate | Upstream | Errors |",
            "|---------|-----|------|----------|--------|",
        ]
    )
    for test in report["tests"]:
        evidence = test.get("evidence") or {}
        profile = evidence.get("profile_id") or "-"
        for item in evidence.get("recent_history") or []:
            errors = ", ".join(item.get("error_codes") or []) or "-"
            lines.append(
                f"| `{profile}` | `{item.get('run_id') or '-'}` | "
                f"`{item.get('quality_gate_passed')}` | `{item.get('upstream_backed')}` | `{errors}` |"
            )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact validates repeatability evidence from archived CALDERA benchmark artifacts only. "
            "It does not create CALDERA operations and does not prove new endpoint detection.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=PROFILE_NAME)
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = utc_now()
    tests = build_tests()
    finished = utc_now()
    passed = all(test["status"] == "covered" for test in tests)
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    run_id_value = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"

    report = {
        "schema_version": 1,
        "run_id": run_id_value,
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
            "claim_level_counts": {"caldera_repeatability_claim_boundary": len(tests)},
            "category_coverage": {"caldera_repeatability": {"covered": covered, "missed": missed}},
        },
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["caldera_repeatability_gaps"],
            "actionable_gaps": [
                {
                    "test_id": test["id"],
                    "gap_category": test["gap_category"],
                    "missing": test.get("missing_expected_fields") or [],
                    "evidence": test.get("evidence") or {},
                }
                for test in tests
                if test["status"] != "covered"
            ],
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "thresholds": {
                "required_consecutive_passes": REQUIRED_CONSECUTIVE_PASSES,
                "requires_upstream_backed_caldera_artifacts": True,
            },
        },
        "scorecard": {
            "maturity_score": 100 if passed else 45,
            "maturity_band": "caldera-repeatability-ready" if passed else "caldera-repeatability-gaps",
            "recommended_claim": (
                "CALDERA repeatability gate is proven for selected profiles"
                if passed
                else "CALDERA repeatability is not proven; fresh PAW and consecutive passes are still required"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else ["caldera_repeatability_missing"],
            "covered_rate": covered / len(tests) if tests else 0,
            "telemetry_rate": 1.0,
            "field_quality": 1.0 if passed else 0.0,
            "context_quality": 1.0 if passed else 0.0,
            "analytic_quality": 1.0,
            "noise_quality": 1.0,
            "driver_quality": 1.0,
            "upstream_rate": 1.0 if passed else 0.0,
        },
        "tests": tests,
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id_value}.json"
    comparison_path = output_dir / f"{run_id_value}.comparison.json"
    md_path = output_dir / f"{run_id_value}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    comparison_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"caldera_repeatability={'ok' if passed else 'gaps'} json={json_path} markdown={md_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
