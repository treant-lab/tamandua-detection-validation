#!/usr/bin/env python3
"""Static release/resilience readiness probe for Roadmaps G/L/V.

This probe validates repo-side contracts for release readiness, installer
operations, signing, reliability surfaces, response guardrails, safe-boot
runbooks, offline/backpressure documentation, and transactional update
configuration. It never installs, uninstalls, signs, loads/unloads drivers,
reboots, mutates queues, or applies updates.
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
PROFILE_ID = "release-resilience-static-probe"
PROFILE_NAME = "Release Resilience Static Probe"


CHECKS: list[dict[str, Any]] = [
    {
        "id": "release-windows-installer-upgrade-uninstall-contract",
        "name": "Windows MSI declares service install, upgrade, uninstall, hidden credentials, and driver feature switch",
        "roadmaps": ["G"],
        "category": "installer",
        "file": "apps/tamandua_agent/installer/windows/Product.wxs",
        "required": [
            "<MajorUpgrade",
            "<ServiceInstall",
            '<ServiceControl Id="TamanduaServiceControl"',
            'Remove="uninstall"',
            '<Property Id="AGENT_TOKEN"',
            'Hidden="yes"',
            '<Property Id="ENROLLMENT_TOKEN"',
            '<Feature Id="DriverFeature"',
            '<Property Id="INSTALL_DRIVER"',
        ],
    },
    {
        "id": "release-windows-installer-docs-signing-enrollment-contract",
        "name": "Windows installer docs cover enrollment, signing, silent install, upgrade, and uninstall",
        "roadmaps": ["G"],
        "category": "installer-docs",
        "file": "apps/tamandua_agent/installer/windows/README.md",
        "required": [
            "Enrollment Mode",
            "One-time enrollment token",
            "-SignCert",
            "Code Signing",
            "Silent Installation",
            "Uninstallation",
            "Upgrade",
        ],
    },
    {
        "id": "release-build-script-signing-contract",
        "name": "Windows installer build script supports WiX and optional Authenticode signing",
        "roadmaps": ["G"],
        "category": "build-signing",
        "file": "apps/tamandua_agent/installer/windows/build.ps1",
        "required": [
            "WiX Toolset v4",
            "SignCert",
            "signtool",
            "/fd",
            "sha256",
            "timestamp.digicert.com",
            "Build-Installer",
        ],
    },
    {
        "id": "release-driver-signing-secureboot-runbook",
        "name": "Driver signing runbook distinguishes test, EV, attestation, WHQL/HLK, HVCI, and Secure Boot",
        "roadmaps": ["G", "V"],
        "category": "driver-signing",
        "file": "apps/tamandua_driver/docs/CODE_SIGNING.md",
        "required": [
            "Secure Boot",
            "HVCI",
            "Test Signing",
            "EV Code Signing",
            "Attestation",
            "WHQL",
            "HLK",
            "Partner Center",
            "signtool verify",
        ],
    },
    {
        "id": "release-safe-boot-crash-marker-runbook",
        "name": "Safe-boot runbook defines crash markers, degraded mode, signing chain, and production blockers",
        "roadmaps": ["V"],
        "category": "safe-boot",
        "file": "docs/runbooks/windows_safe_boot_and_signing.md",
        "required": [
            "EV code signing certificate",
            "HLK test plan",
            "WHQL/attestation signing",
            "Secure Boot load behavior",
            "crash marker",
            "Repeated crash markers trigger driver-safe mode",
            "Safe mode keeps user-mode telemetry",
            "signing_chain",
        ],
    },
    {
        "id": "release-agent-updater-config-contract",
        "name": "Agent config declares signed self-update, integrity, atomic install, and rollback intent",
        "roadmaps": ["G", "L", "V"],
        "category": "ota-config",
        "file": "apps/tamandua_agent/config/agent.toml",
        "required": [
            "[updater]",
            "enabled = true",
            "Ed25519",
            "SHA-256",
            "atomic install with rollback",
            "signing_public_key",
            "auto_restart",
        ],
    },
    {
        "id": "release-config-rollback-doc-contract",
        "name": "Agent config rollback documentation covers backup, verification, rollback telemetry, and monitoring",
        "roadmaps": ["G", "L", "V"],
        "category": "rollback",
        "file": "apps/tamandua_agent/docs/config_rollback.md",
        "required": [
            "automatic rollback",
            "verify_backups",
            "restore_version",
            "config_rollback",
            "Alerts the backend",
            "rollback events",
        ],
    },
    {
        "id": "release-response-guardrails-contract",
        "name": "Response guardrails deny protected OS/Tamandua processes and unsafe isolation without allowlist",
        "roadmaps": ["F", "V"],
        "category": "response-guardrails",
        "file": "tools/response_validation/local_guardrails.yml",
        "required": [
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "tamandua-agent.exe",
            "tamandua-watchdog.exe",
            "require_management_allowlist: true",
            "deny_if_allowed_ips_empty: true",
        ],
    },
    {
        "id": "release-response-rollback-harness-contract",
        "name": "Response validation harness covers rollback, reversible commands, audit sequence, and denied paths",
        "roadmaps": ["F", "L", "V"],
        "category": "response-validation",
        "file": "tools/response_validation/harness.py",
        "required": [
            "REVERSIBLE_COMMANDS",
            "rollback_for",
            "audit_events",
            "rollback_path_covered",
            "denial_path_covered",
            "dry_run_only",
        ],
    },
    {
        "id": "release-driver-telemetry-queue-contract",
        "name": "Driver docs declare telemetry ring buffer, dropped counters, priority behavior, and queue depth",
        "roadmaps": ["L", "V"],
        "category": "driver-queue",
        "file": "apps/tamandua_driver/docs/IMPLEMENTATION_SUMMARY.md",
        "required": [
            "telemetry ring buffer",
            "queue depth",
            "dropped events",
            "Critical events",
            "Events queued/dropped",
            "Batch flush metrics",
        ],
    },
    {
        "id": "release-driver-stress-test-contract",
        "name": "Driver test tree has stress, IOCTL, telemetry, callback, and hardening tests",
        "roadmaps": ["L", "V"],
        "category": "driver-tests",
        "files": [
            "apps/tamandua_driver/tests/stress_tests.c",
            "apps/tamandua_driver/tests/test_ioctl.c",
            "apps/tamandua_driver/tests/test_telemetry.c",
            "apps/tamandua_driver/tests/test_callbacks.c",
            "apps/tamandua_driver/tests/test_hardening.c",
        ],
    },
    {
        "id": "release-windows-installer-validation-contract",
        "name": "Windows installer has repo-side validation script for expected assets and installation shape",
        "roadmaps": ["G"],
        "category": "installer-validation",
        "file": "apps/tamandua_agent/installer/windows/validate-installation.ps1",
        "required": [
            "installer assets",
            "Tamandua",
            "Test-Path",
        ],
    },
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


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def check_item(item: dict[str, Any]) -> dict[str, Any]:
    missing_files: list[str] = []
    missing_terms: list[str] = []
    checked_paths: list[str] = []

    paths = [item["file"]] if "file" in item else item.get("files", [])
    combined = ""
    for relative in paths:
        path = ROOT / relative
        checked_paths.append(relative)
        if not path.exists():
            missing_files.append(relative)
            continue
        combined += "\n" + read_text(path)

    for term in item.get("required", []):
        if term.lower() not in combined.lower():
            missing_terms.append(term)

    covered = not missing_files and not missing_terms
    return {
        "id": item["id"],
        "name": item["name"],
        "status": "covered" if covered else "missed",
        "gap_category": None if covered else "release-resilience-contract",
        "validation_category": "release_resilience_static",
        "execution_class": "static_source_probe",
        "fallback_used": False,
        "claim_level": "source_contract_readiness",
        "tactics": [],
        "techniques": [],
        "evidence": {
            "roadmaps": item["roadmaps"],
            "category": item["category"],
            "checked_paths": checked_paths,
            "missing_files": missing_files,
            "missing_terms": missing_terms,
        },
        "missing_expected_fields": missing_files + missing_terms,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    return [check_item(item) for item in CHECKS]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = [test for test in tests if test["status"] != "covered"]
    roadmap_counts: dict[str, dict[str, int]] = {}
    for test in tests:
        for roadmap in test["evidence"]["roadmaps"]:
            entry = roadmap_counts.setdefault(roadmap, {"covered": 0, "missed": 0})
            entry["covered" if test["status"] == "covered" else "missed"] += 1
    gap_counts = {"release-resilience-contract": missed} if missed else {}
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
        "executor_counts": {"release_resilience_static_probe": len(tests)},
        "execution_class_counts": {"static_source_probe": len(tests)},
        "claim_level_counts": {"source_contract_readiness": len(tests)},
        "category_coverage": {"release_resilience_static": {"covered": covered, "missed": missed}},
        "roadmap_coverage": roadmap_counts,
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
        "maturity_score": 76 if passed else int(50 * covered_rate),
        "maturity_band": "release-resilience-source-contract-ready" if passed else "release-resilience-source-contract-gaps",
        "recommended_claim": (
            "Release/resilience source contracts are present; production install/update/driver/reboot evidence still pending"
            if passed
            else "Release/resilience source contract gaps exist; do not promote release readiness"
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if passed else covered_rate,
        "context_quality": 1.0 if passed else covered_rate,
        "analytic_quality": 1.0,
        "noise_quality": 1.0,
        "driver_quality": 1.0 if passed else covered_rate,
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
        "- Scope: static repo-side release/resilience source contracts only.",
        "- Runtime effect: none; no install, uninstall, signing, update, reboot, driver load, or response execution.",
        "",
        "| Test | Roadmaps | Status | Missing |",
        "|------|----------|--------|---------|",
    ]
    for test in report["tests"]:
        evidence = test["evidence"]
        missing = evidence["missing_files"] + evidence["missing_terms"]
        lines.append(
            f"| `{test['id']}` | `{','.join(evidence['roadmaps'])}` | `{test['status']}` | `{'; '.join(missing) if missing else '-'}` |"
        )
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
                "purpose": "release_resilience_static_probe",
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
            "failures": [] if passed else ["release_resilience_source_contract_gaps"],
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
            "Validates repo-side release/resilience source contracts only. It does not prove signed release artifacts, "
            "SBOM attachment, install/upgrade/rollback/uninstall execution, Secure Boot driver loading, reboot safety, "
            "offline queue drain, driver stress, local response enforcement, or transactional OTA rollback."
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
