#!/usr/bin/env python3
"""Local fleet scale/isolation fixture for Roadmap S.

This deterministic fixture models simultaneous workloads across multiple
agents, event ownership, latency, loss, queue depth, and cross-agent isolation.
It does not execute endpoint workloads or query the live server.
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
PROFILE_ID = "fleet-scale-isolation-fixture-probe"
PROFILE_NAME = "Fleet Scale Isolation Fixture Probe"


AGENTS = [
    {"agent_id": "agent-win-a", "tenant_id": "tenant-alpha", "os": "windows", "online": True},
    {"agent_id": "agent-win-b", "tenant_id": "tenant-alpha", "os": "windows", "online": True},
    {"agent_id": "agent-linux-a", "tenant_id": "tenant-alpha", "os": "linux", "online": True},
    {"agent_id": "agent-macos-a", "tenant_id": "tenant-alpha", "os": "macos", "online": False},
]


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


def make_events() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    sequence = 0
    for agent in AGENTS:
        if not agent["online"]:
            continue
        for idx in range(10):
            sequence += 1
            latency_ms = 120 + (idx * 11) + (sequence % 7)
            events.append(
                {
                    "event_id": f"evt-{agent['agent_id']}-{idx:02d}",
                    "agent_id": agent["agent_id"],
                    "tenant_id": agent["tenant_id"],
                    "os": agent["os"],
                    "workload_id": f"workload-{agent['agent_id']}",
                    "sequence": idx,
                    "ingest_latency_ms": latency_ms,
                    "alert_latency_ms": latency_ms + 210,
                    "queue_depth": 2 + (idx % 4),
                    "dropped": False,
                }
            )
    return events


def result(test_id: str, name: str, passed: bool, evidence: dict[str, Any], missing: list[str] | None = None) -> dict[str, Any]:
    missing = missing or []
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else "fleet-fixture",
        "validation_category": "fleet_scale_fixture",
        "execution_class": "local_fixture_probe",
        "fallback_used": False,
        "claim_level": "fleet_scale_fixture_contract",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": missing,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    events = make_events()
    online_agents = [agent for agent in AGENTS if agent["online"]]
    by_agent: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_agent.setdefault(event["agent_id"], []).append(event)

    tests: list[dict[str, Any]] = []
    tests.append(
        result(
            "fleet-simultaneous-workload-fixture",
            "Fixture contains simultaneous workload evidence for multiple online agents",
            len(online_agents) >= 3 and all(len(by_agent.get(agent["agent_id"], [])) == 10 for agent in online_agents),
            {"online_agents": [agent["agent_id"] for agent in online_agents], "events": len(events)},
        )
    )

    max_ingest = max(event["ingest_latency_ms"] for event in events)
    max_alert = max(event["alert_latency_ms"] for event in events)
    tests.append(
        result(
            "fleet-latency-budget-fixture",
            "Fleet fixture records ingest and alert latency inside budget",
            max_ingest <= 250 and max_alert <= 500,
            {"max_ingest_latency_ms": max_ingest, "max_alert_latency_ms": max_alert, "ingest_budget_ms": 250, "alert_budget_ms": 500},
        )
    )

    drops = [event for event in events if event["dropped"]]
    max_queue = max(event["queue_depth"] for event in events)
    tests.append(
        result(
            "fleet-loss-queue-depth-fixture",
            "Fleet fixture records zero loss and bounded queue depth",
            not drops and max_queue <= 5,
            {"dropped_events": len(drops), "max_queue_depth": max_queue, "queue_depth_budget": 5},
        )
    )

    isolation_ok = all(event["agent_id"] in by_agent and event["tenant_id"] == "tenant-alpha" for event in events)
    no_cross_agent_mix = all(all(item["agent_id"] == agent_id for item in agent_events) for agent_id, agent_events in by_agent.items())
    tests.append(
        result(
            "fleet-cross-agent-evidence-isolation-fixture",
            "Fleet fixture keeps event ownership isolated by agent id",
            isolation_ok and no_cross_agent_mix,
            {"agent_event_counts": {agent: len(items) for agent, items in by_agent.items()}},
        )
    )

    offline_agents = [agent["agent_id"] for agent in AGENTS if not agent["online"]]
    offline_event_leak = [event for event in events if event["agent_id"] in offline_agents]
    tests.append(
        result(
            "fleet-offline-agent-no-event-leak-fixture",
            "Offline agents remain visible but do not emit workload events",
            bool(offline_agents) and not offline_event_leak,
            {"offline_agents": offline_agents, "offline_event_leaks": offline_event_leak},
        )
    )

    return tests


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = [test for test in tests if test["status"] != "covered"]
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
        "executor_counts": {"fleet_scale_isolation_fixture_probe": len(tests)},
        "execution_class_counts": {"local_fixture_probe": len(tests)},
        "claim_level_counts": {"fleet_scale_fixture_contract": len(tests)},
        "category_coverage": {"fleet_scale_fixture": {"covered": covered, "missed": missed}},
        "roadmap_coverage": {"S": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"fleet-fixture": missed} if missed else {},
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 78 if passed else int(50 * covered_rate),
        "maturity_band": "fleet-fixture-contract-ready" if passed else "fleet-fixture-gaps",
        "recommended_claim": (
            "Fleet workload, latency, loss, queue-depth, and evidence-isolation fixture contracts are green"
            if passed
            else "Fleet fixture contract gaps remain"
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
        "- Scope: local deterministic fleet fixture contract only.",
        "- Runtime effect: none; no endpoint, server, DB, or alert mutation.",
        "",
        "| Test | Status |",
        "|------|--------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` |")
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
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
        "benchmark_lane": "fleet-scale",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "fleet_scale_isolation_fixture",
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
            "failures": [] if passed else ["fleet_scale_fixture_gaps"],
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
        "claim_boundary": (
            "Local fleet fixture only. It proves expected multi-agent workload, latency, loss, queue-depth, "
            "and evidence-isolation semantics are executable as a regression gate, but it does not prove "
            "real simultaneous endpoint throughput, server ingest SLOs, UI behavior under load, or fleet scale."
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
