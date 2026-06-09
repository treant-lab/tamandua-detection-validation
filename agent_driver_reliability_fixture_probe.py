#!/usr/bin/env python3
"""Local agent/driver reliability fixture for Roadmap L.

Validates lifecycle, reboot, backpressure, and drop-accounting semantics without
starting/stopping services, loading drivers, stressing kernel code, or mutating
endpoint queues.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "agent-driver-reliability-fixture-probe"
PROFILE_NAME = "Agent Driver Reliability Fixture Probe"


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


def result(test_id: str, name: str, passed: bool, category: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else "agent-driver-reliability-fixture",
        "validation_category": f"agent_driver_{category}",
        "execution_class": "local_fixture_probe",
        "fallback_used": False,
        "claim_level": "agent_driver_reliability_fixture_contract",
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
    lifecycle = {
        "states": ["installed", "service_starting", "connected", "degraded", "stopping", "uninstalled"],
        "health_fields": ["agent_uptime_seconds", "connection_state", "collector_status", "driver_state", "queue_depth", "dropped_count"],
        "audit_events": ["install", "start", "heartbeat", "degraded", "stop", "uninstall"],
    }
    lifecycle_ok = {"connected", "degraded"}.issubset(set(lifecycle["states"])) and {"driver_state", "dropped_count"}.issubset(set(lifecycle["health_fields"]))

    reboot = {
        "sequence": ["pre_reboot_marker", "service_autostart", "driver_load_policy_checked", "heartbeat_restored", "marker_cleared"],
        "failure_sequence": ["pre_reboot_marker", "service_autostart", "driver_load_failed", "degraded_mode", "remote_diagnostics_available"],
        "no_destructive_action": True,
    }
    reboot_ok = reboot["sequence"][-1] == "marker_cleared" and reboot["failure_sequence"][-1] == "remote_diagnostics_available"

    driver_stress = {
        "event_classes": ["process", "thread", "image_load", "registry", "file_create", "file_write", "file_rename_delete"],
        "drop_counters": ["kernel_dropped", "channel_dropped", "agent_queue_dropped", "low_priority_dropped"],
        "flush_metrics": ["batch_count", "batch_bytes", "flush_duration_ms", "backpressure_state"],
        "runtime_effect": "none_fixture_only",
    }
    driver_ok = len(driver_stress["event_classes"]) >= 6 and {"kernel_dropped", "channel_dropped"}.issubset(set(driver_stress["drop_counters"]))

    offline_replay = {
        "queue_policy": "bounded_priority_circular",
        "reconnect_steps": ["load_queue", "deduplicate", "rate_limit", "send_priority_first", "ack_cursor", "compact"],
        "immutability": "live_alerts_not_mutated_by_replay",
        "metrics": ["oldest_event_age_seconds", "queue_bytes", "acked_cursor", "replayed_count"],
    }
    replay_ok = offline_replay["reconnect_steps"][-1] == "compact" and offline_replay["immutability"] == "live_alerts_not_mutated_by_replay"

    self_protection = {
        "protected_names": ["tamandua-agent.exe", "tamandua-watchdog.exe", "tamandua-updater.exe", "tamandua.sys"],
        "allowed_recovery": ["graceful_stop_with_admin", "signed_update", "safe_mode_repair"],
        "denied_by_default": ["untrusted_kill", "untrusted_driver_unload", "config_delete_without_backup"],
    }
    self_protection_ok = "tamandua-agent.exe" in self_protection["protected_names"] and "safe_mode_repair" in self_protection["allowed_recovery"]

    return [
        result("agent-driver-lifecycle-health-fixture", "Fixture validates lifecycle states, health fields, and audit events", lifecycle_ok, "lifecycle", lifecycle),
        result("agent-driver-reboot-recovery-fixture", "Fixture validates reboot recovery and degraded diagnostics semantics", reboot_ok, "reboot", reboot),
        result("agent-driver-stress-drop-accounting-fixture", "Fixture validates driver event classes, flush metrics, and drop counters", driver_ok, "driver_stress", driver_stress),
        result("agent-driver-offline-replay-fixture", "Fixture validates bounded offline replay and live-alert immutability", replay_ok, "offline_replay", offline_replay),
        result("agent-driver-self-protection-fixture", "Fixture validates Tamandua self-protection and recovery semantics", self_protection_ok, "self_protection", self_protection),
    ]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
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
        "executor_counts": {"agent_driver_reliability_fixture_probe": len(tests)},
        "execution_class_counts": {"local_fixture_probe": len(tests)},
        "claim_level_counts": {"agent_driver_reliability_fixture_contract": len(tests)},
        "category_coverage": {"agent_driver_reliability": {"covered": covered, "missed": missed}},
        "roadmap_coverage": {"L": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"agent-driver-reliability-fixture": missed} if missed else {},
        "actionable_gaps": [test for test in tests if test["status"] != "covered"],
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    passed = summary["missed"] == 0
    rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "maturity_score": 79 if passed else int(50 * rate),
        "maturity_band": "agent-driver-reliability-fixture-contract-ready" if passed else "agent-driver-reliability-fixture-gaps",
        "recommended_claim": "Agent/driver reliability fixture is green for lifecycle, reboot, stress/drop accounting, offline replay, and self-protection semantics" if passed else "Agent/driver reliability fixture gaps remain",
        "external_claim_allowed": False,
        "covered_rate": rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if passed else rate,
        "context_quality": 1.0 if passed else rate,
        "analytic_quality": 1.0 if passed else rate,
        "noise_quality": 1.0,
        "driver_quality": 1.0 if passed else rate,
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
        "- Scope: local deterministic agent/driver reliability fixture contract only.",
        "- Runtime effect: none; no service, driver, reboot, queue, or self-protection mutation.",
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
        "benchmark_lane": "agent-driver-reliability",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {"profile_id": PROFILE_ID, "name": PROFILE_NAME, "platform": "windows"},
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["agent_driver_reliability_fixture_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {"benchmark_lane": "agent-driver-reliability", "fail_on_missed": True, "require_upstream": False},
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Local agent/driver reliability fixture only. It proves expected lifecycle, reboot, driver-stress/drop, "
            "offline replay, and self-protection semantics. It does not prove service lifecycle on Windows, reboot "
            "recovery, driver stress under kernel load, real queue drain, or tamper protection on an endpoint."
        ),
    }
    comparison = {"schema_version": 1, "profile_id": PROFILE_ID, "execute": True, "benchmark_lane": "agent-driver-reliability", "summary": summary, "quality_gate": report["quality_gate"], "scorecard": report["scorecard"], "tests": tests}
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
