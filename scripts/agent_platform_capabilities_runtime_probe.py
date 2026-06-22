#!/usr/bin/env python3
"""Local probe for agent platform capability runtime semantics.

This validates that the API-side capability contract distinguishes:
- observed telemetry from collector/data-source evidence;
- reported runtime capability from an online healthy agent;
- not observed capability from offline/unknown agents.

It does not contact the production server or mutate endpoint state.
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
PROFILE_ID = "agent-platform-capabilities-runtime-probe"
PROFILE_NAME = "Agent Platform Capabilities Runtime Probe"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            ).stdout.strip()
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


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def docker_elixir_test() -> dict[str, Any]:
    script = (
        'ExUnit.start(); '
        'Code.compile_file("apps/tamandua_server/lib/tamandua_server/agents/platform_capabilities.ex"); '
        'Code.compile_file("apps/tamandua_server/test/tamandua_server/agents/platform_capabilities_test.exs")'
    )
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{ROOT}:/repo",
        "-w",
        "/repo",
        "elixir:1.17-alpine",
        "elixir",
        "-e",
        script,
    ]
    try:
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        return {
            "available": True,
            "exit_code": completed.returncode,
            "stdout_tail": completed.stdout[-2000:],
            "stderr_tail": completed.stderr[-2000:],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "available": False,
            "exit_code": None,
            "error": str(exc),
        }


def test_result(test_id: str, name: str, passed: bool, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else "analyst-ux-capability-contract",
        "validation_category": "agent_platform_capabilities_runtime",
        "execution_class": "local_source_and_unit_probe",
        "fallback_used": False,
        "claim_level": "agent_capability_runtime_contract",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    module_path = ROOT / "apps" / "tamandua_server" / "lib" / "tamandua_server" / "agents" / "platform_capabilities.ex"
    controller_path = (
        ROOT
        / "apps"
        / "tamandua_server"
        / "lib"
        / "tamandua_server_web"
        / "controllers"
        / "api"
        / "v1"
        / "agent_controller.ex"
    )
    test_path = ROOT / "apps" / "tamandua_server" / "test" / "tamandua_server" / "agents" / "platform_capabilities_test.exs"

    module = read_text(module_path)
    controller = read_text(controller_path)
    test_file = read_text(test_path)

    runtime_contract_ok = all(
        marker in module
        for marker in [
            "online_runtime?(agent_status, health)",
            "online_status?(agent_status)",
            "critical_health?(health)",
            'observed_state("endpoint_telemetry"',
            'observed_state("live_response"',
        ]
    )
    controller_ok = all(
        marker in controller
        for marker in [
            "PlatformCapabilities.for_agent(agent",
            "status: status",
            "health: health_status",
        ]
    )
    unit = docker_elixir_test()
    unit_ok = bool(unit.get("available")) and unit.get("exit_code") == 0 and "2 tests, 0 failures" in str(unit.get("stdout_tail"))
    test_contract_ok = all(
        marker in test_file
        for marker in [
            "online healthy runtime is reported",
            "offline runtime remains not observed",
            'endpoint.observed == "reported"',
            'live_response.observed == "reported"',
            'endpoint.observed == "not_observed"',
        ]
    )

    return [
        test_result(
            "agent-capabilities-runtime-source-contract",
            "PlatformCapabilities reports online healthy runtime without claiming observed telemetry",
            runtime_contract_ok,
            {
                "file": str(module_path.relative_to(ROOT)),
                "required_markers_present": runtime_contract_ok,
                "claim_boundary": "reported is runtime/config evidence; observed still requires collector/data-source evidence",
            },
        ),
        test_result(
            "agent-capabilities-api-serialization-contract",
            "Agent API serialization passes effective status and health into platform capability derivation",
            controller_ok,
            {
                "file": str(controller_path.relative_to(ROOT)),
                "required_markers_present": controller_ok,
                "claim_boundary": "API list/detail can render online reported state without relying on live alert counts",
            },
        ),
        test_result(
            "agent-capabilities-unit-contract",
            "Elixir unit contract covers online reported and offline not_observed semantics",
            unit_ok and test_contract_ok,
            {
                "file": str(test_path.relative_to(ROOT)),
                "docker_elixir": unit,
                "test_markers_present": test_contract_ok,
            },
        ),
    ]


def summarize(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
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
        "missing_expected_fields": 0,
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {PROFILE_ID: len(tests)},
        "execution_class_counts": {"local_source_and_unit_probe": len(tests)},
        "claim_level_counts": {"agent_capability_runtime_contract": len(tests)},
        "category_coverage": {"agent_platform_capabilities_runtime": {"covered": covered, "missed": missed}},
        "roadmap_coverage": {"R": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {"local_source_and_unit_probe": covered},
        "gap_category_counts": {"analyst-ux-capability-contract": missed} if missed else {},
        "actionable_gaps": [test for test in tests if test["status"] != "covered"],
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    passed = summary["missed"] == 0
    rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "maturity_score": 82 if passed else int(50 * rate),
        "maturity_band": "agent-capability-runtime-contract-ready" if passed else "agent-capability-runtime-gaps",
        "recommended_claim": (
            "Agent capability UI/API contract distinguishes runtime-reported capabilities from observed telemetry"
            if passed
            else "Agent capability UI/API contract still has runtime reporting gaps"
        ),
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


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- Scope: local source and unit-test contract for agent capability UX/API only.",
        "- Runtime effect: none; no endpoint or server mutation.",
        "",
        "| Test | Status |",
        "|------|--------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` |")
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_outputs(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base = output_dir / report["run_id"]
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    comparison_path = output_dir / f"{report['run_id']}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    comparison_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": report["run_id"],
                "profile_id": report["profile_id"],
                "quality_gate": report["quality_gate"],
                "summary": report["summary"],
                "scorecard": report["scorecard"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return json_path, md_path, comparison_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = collect_tests()
    summary = summarize(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "analyst-ux",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {"profile_id": PROFILE_ID, "name": PROFILE_NAME, "platform": "multi"},
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["agent_platform_capabilities_runtime_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "analyst-ux",
                "fail_on_missed": True,
                "require_upstream": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Local source and unit-test contract only. It proves the code path for online/healthy "
            "runtime-reported capabilities versus observed telemetry, but it does not prove the "
            "currently deployed server has been updated or that endpoint collectors emitted data."
        ),
    }
    json_path, md_path, comparison_path = write_outputs(report, args.output_dir)
    print(f"agent_platform_capabilities_runtime_probe={'ok' if passed else 'fail'} json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
