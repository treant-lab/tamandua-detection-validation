#!/usr/bin/env python3
"""Report-only Event Envelope retrospective replay benchmark probe.

This probe wraps the existing Detection & Response report-only tools and emits
standard benchmark artifacts. It proves fixture/Event Envelope replay contract
health without database access, endpoint execution, live alert mutation, or
response execution.
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
PROFILE_ID = "event-envelope-retrospective-replay-report-only"
PROFILE_NAME = "Event Envelope Retrospective Replay Report-Only"

SCHEMA = ROOT / "schemas" / "event_envelope_v1.schema.json"
VALIDATOR = ROOT / "tools" / "detection_response" / "validate_event_envelope.py"
REPLAY = ROOT / "tools" / "detection_response" / "replay_report.py"
SUITE = ROOT / "tools" / "detection_response" / "run_report_only_suite.py"
DOC = ROOT / "docs" / "detection-response" / "replay-retrospective-contract.md"
RULE = ROOT / "examples" / "detection_response" / "rules" / "suspicious-powershell-dry-run.yaml"
EVENTS_DIR = ROOT / "examples" / "detection_response" / "events"
POWERSHELL_EVENT = EVENTS_DIR / "windows-process-create-envelope.json"


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


def run_json(args: list[str]) -> tuple[int, dict[str, Any], str]:
    completed = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = completed.stdout.strip()
    try:
        parsed = json.loads(output) if output else {}
    except json.JSONDecodeError:
        parsed = {"stdout": output}
    return completed.returncode, parsed, completed.stderr.strip()


def test_result(test_id: str, name: str, covered: bool, evidence: dict[str, Any], gap: str | None = None) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if covered else "missed",
        "gap_category": None if covered else (gap or "replay-contract"),
        "validation_category": "event_envelope_replay",
        "execution_class": "fixture_report_only",
        "fallback_used": False,
        "claim_level": "report_only_contract",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": [] if covered else [gap or "replay-contract"],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    required_paths = {
        "schema": SCHEMA,
        "validator": VALIDATOR,
        "replay": REPLAY,
        "suite": SUITE,
        "contract_doc": DOC,
        "rule_fixture": RULE,
        "event_fixture": POWERSHELL_EVENT,
    }
    missing = [name for name, path in required_paths.items() if not path.exists()]
    tests.append(
        test_result(
            "event-envelope-replay-required-assets",
            "Event Envelope replay assets exist",
            not missing,
            {"checked_paths": {name: str(path.relative_to(ROOT)) for name, path in required_paths.items()}, "missing": missing},
            "missing-assets",
        )
    )

    event_paths = sorted(EVENTS_DIR.glob("*.json"))
    code, envelope_report, stderr = run_json([sys.executable, str(VALIDATOR), *map(str, event_paths), "--json"])
    reports = envelope_report.get("reports", [])
    tests.append(
        test_result(
            "event-envelope-fixtures-validate",
            "All D&R Event Envelope fixtures validate",
            code == 0 and envelope_report.get("valid") is True and len(reports) == len(event_paths),
            {
                "event_count": len(event_paths),
                "valid_count": len(reports),
                "failures": envelope_report.get("failures", []),
                "stderr": stderr,
            },
            "event-envelope-validation",
        )
    )

    platforms = sorted({report.get("platform") for report in reports if report.get("platform")})
    event_types = sorted({report.get("event_type") for report in reports if report.get("event_type")})
    tests.append(
        test_result(
            "event-envelope-routing-fields-present",
            "Validated fixtures expose routing/platform/event_type metadata",
            bool(reports) and all(report.get("agent_id") and report.get("tenant_id") and report.get("event_type") for report in reports),
            {"platforms": platforms, "event_types": event_types},
            "event-routing-fields",
        )
    )

    code, replay_report, stderr = run_json([sys.executable, str(REPLAY), "--rule", str(RULE), "--event", str(POWERSHELL_EVENT), "--json"])
    replay_safe = (
        code == 0
        and replay_report.get("status") == "report_only_replay"
        and replay_report.get("matched") is True
        and replay_report.get("alert_created") is False
        and replay_report.get("response_executed") is False
    )
    tests.append(
        test_result(
            "event-envelope-retrospective-replay-matches",
            "Replay harness matches suspicious PowerShell fixture without alert mutation",
            replay_safe,
            {
                "status": replay_report.get("status"),
                "matched": replay_report.get("matched"),
                "alert_created": replay_report.get("alert_created"),
                "response_executed": replay_report.get("response_executed"),
                "rule": (replay_report.get("rule") or {}).get("id"),
                "event_type": (replay_report.get("event") or {}).get("event_type"),
                "stderr": stderr,
            },
            "replay-match-or-safety",
        )
    )

    code, suite_report, stderr = run_json([sys.executable, str(SUITE), "--json"])
    checks = suite_report.get("checks", [])
    suite_safe = (
        code == 0
        and suite_report.get("status") == "pass"
        and suite_report.get("runtime_effect") == "none"
        and len(checks) >= 8
        and all(check.get("status") == "pass" for check in checks)
    )
    tests.append(
        test_result(
            "detection-response-report-only-suite-pass",
            "D&R report-only suite passes with runtime_effect none",
            suite_safe,
            {
                "status": suite_report.get("status"),
                "runtime_effect": suite_report.get("runtime_effect"),
                "check_count": len(checks),
                "checks": [check.get("name") for check in checks],
                "stderr": stderr,
            },
            "report-only-suite",
        )
    )

    doc_text = DOC.read_text(encoding="utf-8") if DOC.exists() else ""
    normalized_doc_text = " ".join(doc_text.split())
    boundary_terms = [
        "alert_created: false",
        "response_executed: false",
        "TimescaleDB-backed query layer",
        "retrospective detection records separate from live alerts",
        "tenant/RBAC controls",
    ]
    missing_terms = [term for term in boundary_terms if term not in normalized_doc_text]
    tests.append(
        test_result(
            "replay-retrospective-boundary-documented",
            "Replay contract documents live-alert immutability and remaining production gaps",
            not missing_terms,
            {"document": str(DOC.relative_to(ROOT)), "missing_terms": missing_terms},
            "claim-boundary",
        )
    )

    return tests


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gap_counts: dict[str, int] = {}
    gaps = []
    for test in tests:
        if test["status"] != "covered":
            gap = test["gap_category"] or "unknown"
            gap_counts[gap] = gap_counts.get(gap, 0) + 1
            gaps.append(test)
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
        "executor_counts": {"event_envelope_replay_probe": len(tests)},
        "execution_class_counts": {"fixture_report_only": len(tests)},
        "claim_level_counts": {"report_only_contract": len(tests)},
        "category_coverage": {"event_envelope_replay": {"covered": covered, "missed": missed}},
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
        "maturity_score": 82 if passed else int(60 * covered_rate),
        "maturity_band": "event-envelope-report-only-replay-ready" if passed else "event-envelope-replay-contract-gaps",
        "recommended_claim": (
            "Event Envelope report-only replay contract is validated on fixtures; no historical DB replay or live alert mutation claim"
            if passed
            else "Event Envelope replay contract gaps exist; do not promote retrospective replay claims"
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0 if passed else covered_rate,
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
        "- Scope: Event Envelope and D&R replay report-only fixtures.",
        "- Runtime effect: none; no DB access, endpoint execution, alert mutation, or response execution.",
        "",
        "| Test | Status | Gap |",
        "|------|--------|-----|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['gap_category'] or '-'}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            report["claim_boundary"],
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = collect_tests()
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
                "purpose": "event_envelope_retrospective_replay_report_only",
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
            "failures": [] if passed else ["event_envelope_replay_contract_gaps"],
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
        "claim_boundary": (
            "Validates Event Envelope and D&R report-only replay fixtures only. It does not query historical "
            "events from TimescaleDB/Postgres, persist retrospective detection records, mutate live alerts, "
            "execute endpoint actions, or prove tenant/RBAC controls for production replay."
        ),
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
