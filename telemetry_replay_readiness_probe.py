#!/usr/bin/env python3
"""Non-destructive Roadmap P telemetry replay readiness probe.

The probe validates sanitized replay fixture files and emits benchmark artifacts
that the roadmap scorecard can consume. It does not execute server replay logic
or mutate live alerts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from validate_replay_fixtures import validate_fixture_file


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
FIXTURE_DIR = ROOT / "tools" / "detection_validation" / "fixtures"
PROFILE_ID = "telemetry-replay-readiness-probe"
PROFILE_NAME = "Telemetry Replay Readiness Probe"


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
    return {"commit": commit, "commit_short": commit[:8] if commit else "", "dirty": bool(status), "status_short": status}


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def make_result(test_id: str, name: str, passed: bool, category: str, evidence: dict[str, Any], missing: list[str] | None = None) -> dict[str, Any]:
    status = "covered" if passed else "missed"
    return {
        "id": test_id,
        "name": name,
        "status": status,
        "gap_category": "none" if passed else category,
        "execution_class": "fixture_schema_probe",
        "claim_level": "replay_fixture_readiness",
        "executor_used": "telemetry_replay_readiness_probe",
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": category,
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


def fixture_results(fixture_dir: Path) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    paths = sorted(fixture_dir.glob("*.json"))
    for path in paths:
        data = load(path)
        errors = validate_fixture_file(path)
        fixtures = data.get("fixtures") if isinstance(data.get("fixtures"), list) else []
        lanes = data.get("lanes") if isinstance(data.get("lanes"), list) else []
        event_types = Counter(str(item.get("event_type") or "contract_lane") for item in fixtures if isinstance(item, dict))
        severities = Counter(
            str((item.get("expected") or {}).get("alert_severity") or "contract")
            for item in fixtures
            if isinstance(item, dict)
        )
        evidence = {
            "path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "fixture_id": data.get("fixture_id"),
            "fixture_count": len(fixtures),
            "lane_count": len(lanes),
            "event_type_counts": dict(event_types),
            "expected_severity_counts": dict(severities),
            "claim_boundary": data.get("claim_boundary"),
            "errors": errors,
        }
        tests.append(
            make_result(
                "replay-fixture-schema-" + path.stem.replace("_", "-"),
                f"Replay fixture schema valid: {path.name}",
                not errors,
                "fixture-schema",
                evidence,
                errors,
            )
        )

    aggregate = {
        "fixture_files": len(paths),
        "has_windows_fp_fixture": any(path.name == "windows_false_positive_replay_v1.json" for path in paths),
        "has_macos_fp_fixture": any(path.name == "macos_false_positive_replay_v1.json" for path in paths),
        "has_roadmap_contract_fixture": any(path.name == "roadmap_k_n_s_t_contracts_v1.json" for path in paths),
    }
    tests.append(
        make_result(
            "replay-fixture-platform-coverage",
            "Replay fixture set includes Windows FP, macOS FP, and roadmap contract fixtures",
            aggregate["has_windows_fp_fixture"] and aggregate["has_macos_fp_fixture"] and aggregate["has_roadmap_contract_fixture"],
            "fixture-coverage",
            aggregate,
            [key for key, ok in aggregate.items() if key.startswith("has_") and not ok],
        )
    )
    return tests


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = []
    gap_counts: dict[str, int] = {}
    for test in tests:
        if test["status"] == "covered":
            continue
        gaps.append({
            "test_id": test["id"],
            "status": test["status"],
            "gap_category": test["gap_category"],
            "validation_category": test.get("validation_category"),
            "missing_expected_fields": test.get("missing_expected_fields", []),
            "missing_expected_telemetry": [],
            "missing_expected_detections": [],
            "missing_expected_alerts": [],
            "missing_expected_correlations": [],
            "missing_expected_driver_raw_event_types": [],
            "execution_class": test.get("execution_class"),
            "fallback_used": False,
            "tactics": [],
            "techniques": [],
        })
        gap_counts[test["gap_category"]] = gap_counts.get(test["gap_category"], 0) + 1
    return {
        "tests": len(tests),
        "covered": covered,
        "partial": 0,
        "missed": missed,
        "planned": 0,
        "execution_failed": 0,
        "unknown_source_events": 0,
        "unexpected_high_or_critical_events": 0,
        "unexpected_high_or_critical_alerts": 0,
        "missing_expected_fields": missed,
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"telemetry_replay_readiness_probe": len(tests)},
        "execution_class_counts": {"fixture_schema_probe": len(tests)},
        "claim_level_counts": {"replay_fixture_readiness": len(tests)},
        "category_coverage": {},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": gap_counts,
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 68 if passed else int(45 * covered_rate),
        "maturity_band": "replay-fixture-readiness" if passed else "replay-fixture-gaps",
        "recommended_claim": (
            "Sanitized replay fixtures are schema-valid and ready for a future replay executor; no historical replay execution claim"
            if passed
            else "Replay fixture readiness has gaps; do not use fixtures as release gates"
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if passed else covered_rate,
        "context_quality": 1.0 if passed else covered_rate,
        "analytic_quality": 1.0 if passed else covered_rate,
        "noise_quality": 1.0,
        "driver_quality": 1.0,
        "upstream_rate": 0.0,
        "blocking_gaps": [] if passed else sorted(summary["gap_category_counts"].keys()),
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- Scope: fixture/schema readiness only; no historical replay execution or live alert mutation proof.",
        "",
        "| Test | Status | Category |",
        "|------|--------|----------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['validation_category']}` |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=FIXTURE_DIR)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = fixture_results(args.fixture_dir)
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "telemetry-replay",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "telemetry_replay_readiness_probe",
                "requires_persisted_events": False,
                "requires_driver_health": False,
                "max_unknown_source_events": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
            },
        },
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["replay_fixture_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "telemetry-replay",
                "fail_on_missed": True,
                "fail_on_partial": False,
                "max_unknown_source": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
                "require_upstream": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": "Validates sanitized replay fixture readiness only. It does not execute historical replay, persist retrospective results, or mutate live alerts.",
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "telemetry-replay",
        "summary": summary,
        "quality_gate": report["quality_gate"],
        "scorecard": report["scorecard"],
        "tests": tests,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{run_id}.json"
    comparison_path = args.output_dir / f"{run_id}.comparison.json"
    md_path = args.output_dir / f"{run_id}.md"
    write_json(json_path, report)
    write_json(comparison_path, comparison)
    write_markdown(md_path, report)
    print(f"json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
