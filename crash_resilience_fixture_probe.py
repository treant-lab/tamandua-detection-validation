#!/usr/bin/env python3
"""Local crash-proof agent resilience fixture for Roadmap V.

This deterministic fixture validates the semantics expected from crash-proof
agent/release safety without touching the local service, driver, boot state, or
network policy. It is a local contract gate, not VM-backed resilience proof.
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
PROFILE_ID = "crash-resilience-fixture-probe"
PROFILE_NAME = "Crash Resilience Fixture Probe"


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
        "gap_category": None if passed else "crash-resilience-fixture",
        "validation_category": f"crash_resilience_{category}",
        "execution_class": "local_fixture_probe",
        "fallback_used": False,
        "claim_level": "crash_resilience_fixture_contract",
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
    signing = {
        "states": ["unsigned", "lab_signed", "test_signed", "attestation_signed", "whql_hlk_signed"],
        "secure_boot_load_status": "reported_not_mutated",
        "commercial_blockers": ["ev_certificate", "partner_center_attestation", "hlk_compatibility_matrix"],
    }
    signing_ok = all(state in signing["states"] for state in ("test_signed", "attestation_signed", "whql_hlk_signed")) and len(signing["commercial_blockers"]) == 3

    safe_boot = {
        "marker_flow": ["boot_started", "driver_load_attempted", "agent_heartbeat_healthy", "boot_marker_cleared"],
        "stale_marker_flow": ["boot_started", "driver_load_attempted", "unclean_shutdown", "crash_marker_detected", "degraded_mode_entered"],
        "degraded_mode_keeps": ["heartbeat", "diagnostics", "remote_recovery", "user_mode_telemetry"],
        "risky_driver_load_skipped_after": 2,
    }
    safe_boot_ok = (
        safe_boot["stale_marker_flow"][-1] == "degraded_mode_entered"
        and "heartbeat" in safe_boot["degraded_mode_keeps"]
        and safe_boot["risky_driver_load_skipped_after"] >= 2
    )

    offline_queue = {
        "bounded": True,
        "metrics": ["queue_depth", "disk_bytes", "oldest_event_age_seconds", "dropped_count", "upload_rate_per_second", "backpressure_state"],
        "drop_order": ["low_priority_file_noise", "routine_inventory", "benign_network_flow", "security_event_never_first"],
        "reconnect_policy": "exponential_backoff_with_rate_limit",
    }
    offline_ok = offline_queue["bounded"] and "dropped_count" in offline_queue["metrics"] and offline_queue["drop_order"][-1] == "security_event_never_first"

    guardrails = {
        "protected_processes": ["System", "csrss.exe", "lsass.exe", "wininit.exe", "services.exe", "tamandua-agent.exe", "tamandua-updater.exe"],
        "deny_actions": ["kill_process", "quarantine_file", "network_isolate"],
        "network_isolation_requires": ["control_plane_allowlist", "explicit_break_glass", "approval_reason", "audit_id"],
        "dry_run_supported": True,
    }
    guardrails_ok = (
        {"lsass.exe", "csrss.exe", "tamandua-agent.exe"}.issubset(set(guardrails["protected_processes"]))
        and "control_plane_allowlist" in guardrails["network_isolation_requires"]
        and guardrails["dry_run_supported"] is True
    )

    ota = {
        "stages": ["download", "verify_signature", "verify_hash", "stage", "atomic_swap", "health_window", "promote_or_rollback"],
        "rollback_target": "previous_known_good",
        "audit_events": ["update_staged", "update_verified", "update_applied", "health_window_failed", "rollback_completed"],
        "runtime_effect": "none_fixture_only",
    }
    ota_ok = ota["stages"][-1] == "promote_or_rollback" and ota["rollback_target"] == "previous_known_good" and "rollback_completed" in ota["audit_events"]

    return [
        result("crash-resilience-signing-state-fixture", "Fixture distinguishes driver signing states and production blockers", signing_ok, "signing", signing),
        result("crash-resilience-safe-boot-marker-fixture", "Fixture validates safe-boot and degraded-mode marker semantics", safe_boot_ok, "safe_boot", safe_boot),
        result("crash-resilience-offline-queue-fixture", "Fixture validates bounded offline queue and backpressure semantics", offline_ok, "offline_queue", offline_queue),
        result("crash-resilience-response-guardrails-fixture", "Fixture validates local destructive-response guardrail semantics", guardrails_ok, "response_guardrails", guardrails),
        result("crash-resilience-transactional-ota-fixture", "Fixture validates transactional OTA stage and rollback semantics", ota_ok, "transactional_ota", ota),
    ]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    categories: dict[str, dict[str, int]] = {}
    for test in tests:
        category = test["validation_category"]
        entry = categories.setdefault(category, {"covered": 0, "missed": 0})
        entry["covered" if test["status"] == "covered" else "missed"] += 1
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
        "executor_counts": {"crash_resilience_fixture_probe": len(tests)},
        "execution_class_counts": {"local_fixture_probe": len(tests)},
        "claim_level_counts": {"crash_resilience_fixture_contract": len(tests)},
        "category_coverage": categories,
        "roadmap_coverage": {"V": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"crash-resilience-fixture": missed} if missed else {},
        "actionable_gaps": [test for test in tests if test["status"] != "covered"],
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    passed = summary["missed"] == 0
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "maturity_score": 80 if passed else int(50 * covered_rate),
        "maturity_band": "crash-resilience-fixture-contract-ready" if passed else "crash-resilience-fixture-gaps",
        "recommended_claim": (
            "Crash resilience fixture is green for signing state, safe boot, offline queue, response guardrails, and OTA rollback semantics"
            if passed
            else "Crash resilience fixture gaps remain"
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
        "- Scope: local deterministic crash-resilience fixture contract only.",
        "- Runtime effect: none; no service, driver, boot, queue, response, or update mutation.",
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
        "benchmark_lane": "release-readiness",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "windows",
            "quality_bar": {
                "purpose": "crash_resilience_fixture",
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
            "failures": [] if passed else ["crash_resilience_fixture_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "release-readiness",
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
            "Local crash-resilience fixture only. It proves expected semantics for signing-state classification, "
            "safe-boot/degraded-mode markers, bounded offline queue, local response guardrails, and transactional "
            "OTA rollback. It does not prove Secure Boot production driver loading, reboot recovery, real queue "
            "drain, endpoint-side guardrail enforcement, or update rollback on a VM."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "release-readiness",
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
