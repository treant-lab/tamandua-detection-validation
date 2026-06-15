#!/usr/bin/env python3
"""Non-destructive Roadmap S fleet inventory probe."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
CTL = ROOT / "apps" / "tamandua_ctl" / "target" / "release" / "tamandua-ctl.exe"
PROFILE_ID = "fleet-scale-inventory-api-probe"
PROFILE_NAME = "Fleet Scale Inventory API Probe"


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


def tamandua_ctl_env(server: str | None, base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base_env or os.environ)
    if not server:
        return env
    host = urlparse(server).hostname
    if not host:
        return env

    existing_values: list[str] = []
    for name in ("NO_PROXY", "no_proxy"):
        existing = env.get(name)
        if existing:
            existing_values.extend(item.strip() for item in existing.split(",") if item.strip())

    merged: list[str] = []
    for value in [*existing_values, host]:
        if value and value not in merged:
            merged.append(value)
    no_proxy = ",".join(merged)
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    return env


def run_ctl_agents_list(server: str, timeout: int) -> dict[str, Any]:
    command = [str(CTL), "--json", "remote", "agents", "list", "--server", server]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=tamandua_ctl_env(server),
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "exit_code": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "error": "timeout",
        }
    result = {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    try:
        result["json"] = json.loads(completed.stdout)
    except json.JSONDecodeError:
        result["json_error"] = "stdout_not_json"
    return result


def agent_items(result: dict[str, Any]) -> list[dict[str, Any]]:
    data = (result.get("json") or {}).get("data")
    return data if isinstance(data, list) else []


def test_result(
    test_id: str,
    name: str,
    passed: bool,
    category: str,
    evidence: dict[str, Any],
    missing: list[str] | None = None,
) -> dict[str, Any]:
    status = "covered" if passed else "missed"
    return {
        "id": test_id,
        "name": name,
        "status": status,
        "gap_category": "none" if passed else category,
        "execution_class": "remote_api_probe",
        "claim_level": "fleet_inventory",
        "executor_used": "tamandua_ctl_agents_list",
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


def build_tests(result: dict[str, Any]) -> list[dict[str, Any]]:
    agents = agent_items(result)
    ids = [str(agent.get("id") or "") for agent in agents]
    hostnames = [str(agent.get("hostname") or "") for agent in agents]
    platforms = sorted({str(agent.get("os_type") or "") for agent in agents if agent.get("os_type")})
    online = [agent for agent in agents if str(agent.get("status") or "").lower() == "online"]
    offline = [agent for agent in agents if str(agent.get("status") or "").lower() == "offline"]
    unhealthy_online = [
        agent
        for agent in online
        if (((agent.get("health_status") or {}).get("status") or "").lower() not in {"healthy", "degraded"})
    ]
    inventory = {
        "agent_count": len(agents),
        "online_count": len(online),
        "offline_count": len(offline),
        "platforms": platforms,
        "hostnames": hostnames,
        "agents": [
            {
                "id": agent.get("id"),
                "hostname": agent.get("hostname"),
                "status": agent.get("status"),
                "os_type": agent.get("os_type"),
                "health_status": (agent.get("health_status") or {}).get("status"),
                "last_seen": agent.get("last_seen"),
            }
            for agent in agents
        ],
    }
    return [
        test_result(
            "fleet-authenticated-inventory-list",
            "Authenticated CLI can list fleet inventory",
            result.get("exit_code") == 0 and len(agents) > 0,
            "auth",
            {"exit_code": result.get("exit_code"), "stderr": result.get("stderr"), "agent_count": len(agents)},
            [] if result.get("exit_code") == 0 else ["tamandua_ctl_agents_list_failed"],
        ),
        test_result(
            "fleet-agent-id-uniqueness",
            "Fleet inventory has unique non-empty agent IDs",
            bool(ids) and len(ids) == len(set(ids)) and all(ids),
            "agent-identity",
            inventory,
            [] if ids and len(ids) == len(set(ids)) and all(ids) else ["duplicate_or_empty_agent_id"],
        ),
        test_result(
            "fleet-cross-platform-inventory",
            "Fleet inventory includes at least two OS platforms",
            len(platforms) >= 2,
            "fleet-coverage",
            inventory,
            [] if len(platforms) >= 2 else ["need_two_or_more_platforms"],
        ),
        test_result(
            "fleet-online-offline-state-split",
            "Fleet inventory exposes online and offline state split",
            len(online) >= 1 and len(offline) >= 1,
            "agent-status",
            inventory,
            [] if len(online) >= 1 and len(offline) >= 1 else ["need_online_and_offline_state_evidence"],
        ),
        test_result(
            "fleet-online-health-known",
            "Online agents have healthy or degraded health state",
            len(online) >= 1 and not unhealthy_online,
            "agent-health",
            inventory,
            [] if len(online) >= 1 and not unhealthy_online else ["online_agent_health_unknown_or_critical"],
        ),
    ]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = []
    gap_counts: dict[str, int] = {}
    for test in tests:
        if test["status"] == "covered":
            continue
        gap = {
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
        }
        gaps.append(gap)
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
        "executor_counts": {"tamandua_ctl_agents_list": len(tests)},
        "execution_class_counts": {"remote_api_probe": len(tests)},
        "claim_level_counts": {"fleet_inventory": len(tests)},
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
        "maturity_score": 70 if passed else int(45 * covered_rate),
        "maturity_band": "fleet-inventory-validation" if passed else "fleet-inventory-gaps",
        "recommended_claim": (
            "Authenticated fleet inventory and multi-agent state visibility are validated; "
            "no scale or simultaneous workload claim"
        )
        if passed
        else "Fleet inventory probe has gaps; do not claim fleet readiness",
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
        "- Scope: authenticated fleet inventory/state proof only; not simultaneous workload or scale proof.",
        "",
        "| Test | Status | Category |",
        "|------|--------|----------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['validation_category']}` |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="https://tamandua.treantlab.org")
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    started_at = utc_now()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    ctl_result = run_ctl_agents_list(args.server, args.timeout)
    tests = build_tests(ctl_result)
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "fleet-scale",
        "server": args.server,
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "fleet_scale_inventory_api_probe",
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
            "failures": [] if passed else ["fleet_inventory_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "fleet-scale",
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
        "ctl_result": {
            "exit_code": ctl_result.get("exit_code"),
            "stderr": ctl_result.get("stderr"),
            "json_error": ctl_result.get("json_error"),
            "error": ctl_result.get("error"),
        },
        "claim_boundary": (
            "Validates authenticated fleet inventory and online/offline visibility only. "
            "It does not prove simultaneous workload scale, latency, loss, or cross-agent evidence isolation."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "fleet-scale",
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
