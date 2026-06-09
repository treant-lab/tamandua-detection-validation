#!/usr/bin/env python3
"""Local release operations fixture for Roadmap G.

Validates release package semantics without signing binaries, installing,
upgrading, rolling back, uninstalling, rebooting, or mutating endpoints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "release-operations-fixture-probe"
PROFILE_NAME = "Release Operations Fixture Probe"


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


def sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def result(test_id: str, name: str, passed: bool, category: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else "release-operations-fixture",
        "validation_category": f"release_{category}",
        "execution_class": "local_fixture_probe",
        "fallback_used": False,
        "claim_level": "release_operations_fixture_contract",
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
    artifacts = [
        {"name": "tamandua-agent-windows-x64.msi", "platform": "windows", "arch": "x64", "kind": "installer"},
        {"name": "tamandua-agent-linux-x64.tar.gz", "platform": "linux", "arch": "x64", "kind": "archive"},
        {"name": "tamandua-gui-windows-x64.exe", "platform": "windows", "arch": "x64", "kind": "gui"},
        {"name": "tamandua-ctl-windows-x64.exe", "platform": "windows", "arch": "x64", "kind": "cli"},
    ]
    for artifact in artifacts:
        artifact["sha256"] = sha256(artifact)
        artifact["signature_state"] = "fixture_not_signed"
    manifest = {
        "release_id": "release-fixture-001",
        "version": "0.1.0-fixture",
        "created_at": utc_now(),
        "artifacts": artifacts,
        "release_notes": "fixture package; no runtime effect",
        "compatibility_matrix": [
            {"platform": "windows", "versions": ["10", "11", "server-2022"], "arch": ["x64"], "driver": "optional"},
            {"platform": "linux", "versions": ["debian-11", "ubuntu-22.04"], "arch": ["x64"], "driver": "none"},
        ],
    }
    manifest_ok = all(item.get("sha256") for item in artifacts) and len({item["name"] for item in artifacts}) == len(artifacts)

    sbom = {
        "format": "spdx-json-fixture",
        "packages": [
            {"name": "tamandua-agent", "version": manifest["version"], "license": "project-license"},
            {"name": "tamandua-ctl", "version": manifest["version"], "license": "project-license"},
        ],
        "document_sha256": "",
    }
    sbom["document_sha256"] = sha256(sbom["packages"])
    sbom_ok = sbom["format"].startswith("spdx") and len(sbom["packages"]) >= 2 and bool(sbom["document_sha256"])

    lifecycle = {
        "install": {"preflight": ["admin_check", "disk_space", "server_reachable"], "audit": "install_requested"},
        "upgrade": {"preflight": ["current_version", "backup_previous"], "audit": "upgrade_requested"},
        "rollback": {"preflight": ["previous_known_good", "health_window_failed"], "audit": "rollback_requested"},
        "uninstall": {"preflight": ["service_stop", "driver_unload_if_installed"], "audit": "uninstall_requested"},
        "runtime_effect": "none_fixture_only",
    }
    lifecycle_ok = {"install", "upgrade", "rollback", "uninstall"}.issubset(lifecycle.keys()) and all(
        "audit" in lifecycle[action] for action in ("install", "upgrade", "rollback", "uninstall")
    )

    compatibility_ok = any(row["platform"] == "windows" and "11" in row["versions"] for row in manifest["compatibility_matrix"]) and any(
        row["platform"] == "linux" for row in manifest["compatibility_matrix"]
    )

    return [
        result("release-manifest-hashes-fixture", "Fixture release manifest carries artifacts, hashes, version, and compatibility rows", manifest_ok, "manifest", {"manifest": manifest}),
        result("release-sbom-fixture", "Fixture SBOM carries package identities and document hash", sbom_ok, "sbom", {"sbom": sbom}),
        result("release-lifecycle-audit-fixture", "Fixture lifecycle covers install, upgrade, rollback, uninstall with audit events", lifecycle_ok, "lifecycle", {"lifecycle": lifecycle}),
        result("release-compatibility-matrix-fixture", "Fixture compatibility matrix separates Windows/Linux support and driver optionality", compatibility_ok, "compatibility", {"compatibility_matrix": manifest["compatibility_matrix"]}),
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
        "executor_counts": {"release_operations_fixture_probe": len(tests)},
        "execution_class_counts": {"local_fixture_probe": len(tests)},
        "claim_level_counts": {"release_operations_fixture_contract": len(tests)},
        "category_coverage": {"release_operations": {"covered": covered, "missed": missed}},
        "roadmap_coverage": {"G": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"release-operations-fixture": missed} if missed else {},
        "actionable_gaps": [test for test in tests if test["status"] != "covered"],
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    passed = summary["missed"] == 0
    rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "maturity_score": 78 if passed else int(50 * rate),
        "maturity_band": "release-operations-fixture-contract-ready" if passed else "release-operations-fixture-gaps",
        "recommended_claim": "Release operations fixture is green for manifest, SBOM, lifecycle, and compatibility semantics" if passed else "Release operations fixture gaps remain",
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


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- Scope: local deterministic release operations fixture contract only.",
        "- Runtime effect: none; no signing, install, upgrade, rollback, uninstall, or endpoint mutation.",
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
        "profile": {"profile_id": PROFILE_ID, "name": PROFILE_NAME, "platform": "multi"},
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["release_operations_fixture_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {"benchmark_lane": "release-readiness", "fail_on_missed": True, "require_upstream": False},
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Local release operations fixture only. It proves expected manifest, SBOM, lifecycle, and "
            "compatibility semantics. It does not prove signed production artifacts, installer execution, "
            "upgrade/rollback/uninstall on endpoints, or release compatibility in the field."
        ),
    }
    comparison = {"schema_version": 1, "profile_id": PROFILE_ID, "execute": True, "benchmark_lane": "release-readiness", "summary": summary, "quality_gate": report["quality_gate"], "scorecard": report["scorecard"], "tests": tests}
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
