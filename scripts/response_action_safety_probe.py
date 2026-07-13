#!/usr/bin/env python3
"""Non-destructive response action safety matrix probe.

This probe validates the response-action safety contract without killing
processes, moving files, changing firewall rules, calling live response APIs,
or mutating mobile/host endpoints.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"


PROFILE_ID = "response-action-safety-probe"
PROFILE_NAME = "Response Action Safety Matrix Probe"
API_VERSION = "tamandua.io/response-action-safety-probe/v1"
MATRIX_PATH = ROOT / "docs" / "validation" / "RESPONSE_ACTION_VALIDATION_MATRIX.md"
RULE_SCHEMA_PATH = ROOT / "schemas" / "detection_response_rule.schema.json"
PROBE_SCHEMA_PATH = ROOT / "schemas" / "response_action_safety_probe_v1.schema.json"

DESTRUCTIVE_ACTIONS = {"kill_process", "quarantine_file", "isolate_network"}
HOST_PLATFORMS = {"windows", "linux", "macos"}
UNSUPPORTED_PLATFORMS = {"android", "ios", "browser", "mobile"}
REQUIRED_CAPABILITIES = [
    "dry_run",
    "rbac",
    "audit",
    "timeout",
    "rollback",
    "unsupported_platform_status",
    "mobile_host_boundary",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            completed = subprocess.run(
                args,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return completed.stdout.strip()
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


def result(
    test_id: str,
    name: str,
    passed: bool,
    capability: str,
    evidence: dict[str, Any],
    missing: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else capability,
        "validation_category": capability,
        "execution_class": "local_static_contract_probe",
        "claim_level": "response_action_safety_contract",
        "fallback_used": False,
        "upstream_backed": False,
        "evidence": evidence,
        "missing_expected_fields": missing or [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "tactics": [],
        "techniques": [],
    }


def safety_schema_checks(rule_schema: dict[str, Any]) -> list[dict[str, Any]]:
    respond = rule_schema["properties"]["respond"]
    safety = respond["properties"]["safety"]
    safety_props = safety["properties"]
    action_type = respond["properties"]["actions"]["items"]["properties"]["type"]
    destructive_present = DESTRUCTIVE_ACTIONS.issubset(set(action_type["enum"]))

    return [
        result(
            "response-rule-defaults-to-dry-run",
            "Response rule schema requires dry-run default for response safety",
            safety_props.get("dry_run_default", {}).get("const") is True
            and respond["properties"]["mode"]["enum"][0] == "dry_run",
            "dry_run",
            {
                "schema": rel(RULE_SCHEMA_PATH),
                "dry_run_default": safety_props.get("dry_run_default"),
                "respond_modes": respond["properties"]["mode"]["enum"],
            },
            ["respond.safety.dry_run_default const true"] if safety_props.get("dry_run_default", {}).get("const") is not True else [],
        ),
        result(
            "response-rule-requires-audit-reason-approval",
            "Destructive response rule schema requires reason, audit, and approval",
            safety_props.get("require_reason", {}).get("const") is True
            and safety_props.get("require_audit", {}).get("const") is True
            and safety_props.get("destructive_actions_require_approval", {}).get("const") is True
            and destructive_present,
            "audit",
            {
                "schema": rel(RULE_SCHEMA_PATH),
                "safety": safety_props,
                "destructive_actions": sorted(DESTRUCTIVE_ACTIONS),
            },
            [
                field
                for field in (
                    "respond.safety.require_reason",
                    "respond.safety.require_audit",
                    "respond.safety.destructive_actions_require_approval",
                    "respond.actions destructive action enum",
                )
                if (
                    field.endswith("require_reason")
                    and safety_props.get("require_reason", {}).get("const") is not True
                )
                or (
                    field.endswith("require_audit")
                    and safety_props.get("require_audit", {}).get("const") is not True
                )
                or (
                    field.endswith("destructive_actions_require_approval")
                    and safety_props.get("destructive_actions_require_approval", {}).get("const") is not True
                )
                or (field.endswith("enum") and not destructive_present)
            ],
        ),
    ]


def matrix_checks(matrix: str) -> list[dict[str, Any]]:
    lower = matrix.lower()

    def has_all(needles: list[str]) -> tuple[bool, list[str]]:
        missing = [needle for needle in needles if needle.lower() not in lower]
        return not missing, missing

    checks = [
        (
            "response-matrix-covers-rbac",
            "Response action matrix documents RBAC allow/deny gate",
            "rbac",
            ["rbac", "deny", "response action id", "tenant"],
        ),
        (
            "response-matrix-covers-audit",
            "Response action matrix documents audit evidence for allow and deny decisions",
            "audit",
            ["audit event", "actor", "decision", "correlation id"],
        ),
        (
            "response-matrix-covers-timeout",
            "Response action matrix documents timeout behavior",
            "timeout",
            ["timeout", "30,000ms", "command_timeout"],
        ),
        (
            "response-matrix-covers-rollback",
            "Response action matrix documents rollback and no-rollback boundaries",
            "rollback",
            ["rollback", "kill process", "none", "network isolation"],
        ),
        (
            "response-matrix-covers-unsupported-platform",
            "Response action matrix documents unsupported-platform statuses",
            "unsupported_platform_status",
            ["unsupported", "android", "ios", "browser", "unsupported_platform"],
        ),
        (
            "response-matrix-covers-mobile-host-boundary",
            "Response action matrix separates mobile app guard from host-only response actions",
            "mobile_host_boundary",
            ["mobile", "host-only", "app guard", "no host os mutation"],
        ),
        (
            "response-matrix-covers-dry-run",
            "Response action matrix documents dry-run and no-mutation behavior",
            "dry_run",
            ["dry-run", "no os mutation", "no process", "no firewall"],
        ),
    ]

    tests = []
    for test_id, name, capability, needles in checks:
        passed, missing = has_all(needles)
        tests.append(
            result(
                test_id,
                name,
                passed,
                capability,
                {"document": rel(MATRIX_PATH), "required_terms": needles},
                missing,
            )
        )
    return tests


def fixture_matrix() -> list[dict[str, Any]]:
    return [
        {
            "platform": platform,
            "action": action,
            "default_mode": "dry_run",
            "requires_rbac": True,
            "requires_reason": True,
            "requires_audit": True,
            "timeout_seconds": 30,
            "rollback": "none" if action == "kill_process" else "required",
            "status": "host_only_supported",
            "runtime_effect": "none_probe_only",
        }
        for platform in sorted(HOST_PLATFORMS)
        for action in sorted(DESTRUCTIVE_ACTIONS)
    ] + [
        {
            "platform": platform,
            "action": action,
            "default_mode": "disabled",
            "requires_rbac": True,
            "requires_reason": True,
            "requires_audit": True,
            "timeout_seconds": 0,
            "rollback": "not_applicable",
            "status": "unsupported_platform",
            "runtime_effect": "none_probe_only",
        }
        for platform in sorted(UNSUPPORTED_PLATFORMS)
        for action in sorted(DESTRUCTIVE_ACTIONS)
    ]


def fixture_checks(matrix: list[dict[str, Any]]) -> list[dict[str, Any]]:
    missing_host = [
        f"{platform}:{action}"
        for platform in HOST_PLATFORMS
        for action in DESTRUCTIVE_ACTIONS
        if not any(row["platform"] == platform and row["action"] == action for row in matrix)
    ]
    unsupported_bad = [
        row
        for row in matrix
        if row["platform"] in UNSUPPORTED_PLATFORMS and row["status"] != "unsupported_platform"
    ]
    destructive_runtime = [
        row
        for row in matrix
        if row.get("runtime_effect") != "none_probe_only"
        or row.get("default_mode") not in {"dry_run", "disabled"}
    ]
    host_boundary_bad = [
        row
        for row in matrix
        if row["platform"] in {"android", "ios", "mobile"} and row["action"] in DESTRUCTIVE_ACTIONS
    ]
    host_boundary_ok = all(row["status"] == "unsupported_platform" for row in host_boundary_bad)
    rollback_bad = [
        row
        for row in matrix
        if row["status"] == "host_only_supported"
        and (
            row["action"] == "kill_process"
            and row["rollback"] != "none"
            or row["action"] in {"quarantine_file", "isolate_network"}
            and row["rollback"] != "required"
        )
        or row["status"] == "unsupported_platform"
        and row["rollback"] != "not_applicable"
    ]

    return [
        result(
            "response-fixture-covers-host-actions",
            "Fixture matrix covers all host-only destructive actions across Windows, Linux, and macOS",
            not missing_host,
            "mobile_host_boundary",
            {"host_platforms": sorted(HOST_PLATFORMS), "actions": sorted(DESTRUCTIVE_ACTIONS)},
            missing_host,
        ),
        result(
            "response-fixture-unsupported-platforms-disabled",
            "Fixture matrix marks mobile/browser platforms unsupported for host-only response actions",
            not unsupported_bad and host_boundary_ok,
            "unsupported_platform_status",
            {"unsupported_platforms": sorted(UNSUPPORTED_PLATFORMS), "bad_rows": unsupported_bad},
            [f"{row['platform']}:{row['action']}" for row in unsupported_bad],
        ),
        result(
            "response-fixture-never-mutates-host",
            "Fixture matrix remains dry-run or disabled and has no runtime endpoint effect",
            not destructive_runtime,
            "dry_run",
            {"bad_rows": destructive_runtime},
            [f"{row['platform']}:{row['action']}" for row in destructive_runtime],
        ),
        result(
            "response-fixture-rollback-semantics",
            "Fixture matrix records rollback-required and no-rollback semantics",
            not rollback_bad,
            "rollback",
            {"bad_rows": rollback_bad},
            [f"{row['platform']}:{row['action']}" for row in rollback_bad],
        ),
    ]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    category_coverage: dict[str, dict[str, int]] = {
        capability: {"covered": 0, "missed": 0} for capability in REQUIRED_CAPABILITIES
    }
    gap_counts: dict[str, int] = {}

    for test in tests:
        category = test["validation_category"]
        bucket = "covered" if test["status"] == "covered" else "missed"
        category_coverage.setdefault(category, {"covered": 0, "missed": 0})[bucket] += 1
        if test["status"] != "covered":
            gap = str(test["gap_category"])
            gap_counts[gap] = gap_counts.get(gap, 0) + 1

    actionable_gaps = [test for test in tests if test["status"] != "covered"]
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
        "missing_expected_fields": sum(len(test["missing_expected_fields"]) for test in actionable_gaps),
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"response_action_safety_probe": len(tests)},
        "execution_class_counts": {"local_static_contract_probe": len(tests)},
        "claim_level_counts": {"response_action_safety_contract": len(tests)},
        "category_coverage": category_coverage,
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": gap_counts,
        "actionable_gaps": actionable_gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    passed = summary["missed"] == 0
    rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "maturity_score": 80 if passed else int(50 * rate),
        "maturity_band": "response-action-safety-contract-ready" if passed else "response-action-safety-contract-gaps",
        "recommended_claim": (
            "Response action safety matrix and local non-destructive probe cover dry-run, RBAC, audit, "
            "timeout, rollback, unsupported-platform, and mobile/host-only boundaries. This is not live "
            "endpoint execution evidence."
        )
        if passed
        else "Response action safety contract has gaps; do not claim response actions are safe.",
        "external_claim_allowed": False,
        "covered_rate": rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if passed else rate,
        "context_quality": 1.0 if passed else rate,
        "analytic_quality": 1.0 if passed else rate,
        "noise_quality": 1.0,
        "driver_quality": 1.0,
        "upstream_rate": 0.0,
        "blocking_gaps": [] if passed else sorted(summary["gap_category_counts"].keys()),
    }


def build_report() -> dict[str, Any]:
    started_at = utc_now()
    matrix = read_text(MATRIX_PATH)
    rule_schema = read_json(RULE_SCHEMA_PATH)
    static_matrix = fixture_matrix()
    tests = safety_schema_checks(rule_schema) + matrix_checks(matrix) + fixture_checks(static_matrix)
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    return {
        "api_version": API_VERSION,
        "kind": "ResponseActionSafetyProbe",
        "schema_version": 1,
        "run_id": f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{PROFILE_ID}",
        "started_at": started_at,
        "finished_at": utc_now(),
        "execute": False,
        "benchmark_lane": "response-action-safety",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "runtime_effect": "none_probe_only",
        },
        "selected_tests": [test["id"] for test in tests],
        "safety_contract": {
            "capabilities": REQUIRED_CAPABILITIES,
            "host_only_actions": sorted(DESTRUCTIVE_ACTIONS),
            "host_platforms": sorted(HOST_PLATFORMS),
            "unsupported_platforms": sorted(UNSUPPORTED_PLATFORMS),
            "destructive_actions_executed": False,
            "host_os_mutated": False,
            "mobile_host_boundary": "mobile/app-guard may report risk and request server-side workflow only; host-only response actions return unsupported_platform on mobile/browser targets",
        },
        "static_matrix": static_matrix,
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["response_action_safety_contract_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "response-action-safety",
                "fail_on_missed": True,
                "require_live_endpoint_execution": False,
                "allow_destructive_actions": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Local static/contract probe only. It verifies response-action safety documentation, "
            "schema guardrails, and a deterministic no-mutation matrix. It does not prove live "
            "kill, quarantine, isolation, rollback, or endpoint RBAC behavior."
        ),
        "schema_ref": rel(PROBE_SCHEMA_PATH),
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
        "- Runtime effect: none; no process, file, firewall, network, mobile, or host mutation.",
        "- Claim boundary: local static/contract validation only.",
        "",
        "| Test | Status | Category |",
        "|------|--------|----------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['validation_category']}` |")
    if report["summary"]["actionable_gaps"]:
        lines += ["", "## Gaps", ""]
        for gap in report["summary"]["actionable_gaps"]:
            lines.append(f"- `{gap['id']}` missing `{gap['missing_expected_fields']}`")
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()

    report = build_report()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{report['run_id']}.json"
    md_path = args.output_dir / f"{report['run_id']}.md"
    comparison_path = args.output_dir / f"{report['run_id']}.comparison.json"
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": False,
        "benchmark_lane": report["benchmark_lane"],
        "summary": report["summary"],
        "quality_gate": report["quality_gate"],
        "scorecard": report["scorecard"],
        "tests": report["tests"],
    }
    write_json(json_path, report)
    write_json(comparison_path, comparison)
    write_markdown(md_path, report)
    print(f"json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
