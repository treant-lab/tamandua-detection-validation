#!/usr/bin/env python3
"""Static supply-chain and release-governance readiness probe.

Validates repo-side contracts for SBOM, dependency audit, signing,
provenance, secrets hygiene, and honest release notes. It never builds,
signs, publishes, uploads, rotates secrets, scans live infrastructure, or
creates a GitHub release.
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


PROFILE_ID = "supply-chain-release-governance-probe"
PROFILE_NAME = "Supply Chain Release Governance Probe"


CHECKS: list[dict[str, Any]] = [
    {
        "id": "sbom-workflow-generates-and-scans",
        "name": "SBOM workflow generates SPDX/CycloneDX artifacts and scans them",
        "category": "sbom",
        "files": [".github/workflows/sbom.yml"],
        "required": [
            "spdx-json",
            "cyclonedx-json",
            "syft",
            "grype",
            "osv-scanner",
            "license",
            "upload-artifact",
            "retention-days",
        ],
    },
    {
        "id": "dependency-audit-matrix-present",
        "name": "Dependency audit covers Rust, Elixir, Python, Node, containers, and GitHub Actions",
        "category": "dependency-audit",
        "files": [".github/dependabot.yml", ".github/workflows/security-scan.yml"],
        "required": [
            "github-actions",
            "cargo",
            "mix",
            "pip",
            "npm",
            "docker",
            "cargo audit",
            "cargo deny",
            "pip-audit",
            "npm audit",
        ],
    },
    {
        "id": "binary-signing-and-checksum-contract",
        "name": "Binary release workflow signs Windows/macOS/Linux artifacts and emits checksums",
        "category": "signing",
        "files": [".github/workflows/sign_binaries.yml", ".github/workflows/release.yml"],
        "required": [
            "Set-AuthenticodeSignature",
            "signtool",
            "codesign",
            "notarytool",
            "gpg --verify",
            "sha256",
            "Get-AuthenticodeSignature",
            "verify_signed_binary.sh",
        ],
    },
    {
        "id": "container-signing-and-provenance-contract",
        "name": "Container workflow signs images, attaches SBOMs, and emits provenance attestations",
        "category": "provenance",
        "files": [".github/workflows/sign_containers.yml"],
        "required": [
            "id-token: write",
            "cosign sign",
            "cosign verify",
            "cosign attach sbom",
            "cosign attest",
            "slsa.dev/provenance",
            "token.actions.githubusercontent.com",
        ],
    },
    {
        "id": "secrets-hygiene-scan-contract",
        "name": "Secret hygiene workflow scans repository history and PR diffs",
        "category": "secrets",
        "files": [".github/workflows/security-scan.yml"],
        "required": [
            "fetch-depth: 0",
            "gitleaks/gitleaks-action",
            "trufflesecurity/trufflehog",
            "--only-verified",
            "GITLEAKS_LICENSE",
        ],
    },
    {
        "id": "release-notes-honest-claim-boundary",
        "name": "Release governance docs require evidence-linked notes and deny unsupported production claims",
        "category": "release-notes",
        "files": [
            "docs/operations/release-governance.md",
            "docs/KNOWN_PRODUCTION_GAPS.md",
        ],
        "required": [
            "Evidence packet",
            "Release notes claim boundary",
            "Known production gaps",
            "Do not claim",
            "not production validated",
            "external_claim_allowed",
        ],
    },
    {
        "id": "operator-checklist-usable",
        "name": "Supply-chain checklist has owner inputs, commands, evidence, and blockers",
        "category": "operator-checklist",
        "files": ["docs/operations/supply-chain-release-checklist.md"],
        "required": [
            "SBOM",
            "Dependency audit",
            "Signing",
            "Provenance",
            "Secrets hygiene",
            "Release notes",
            "Block release",
            "python tools/detection_validation/scripts/supply_chain_release_governance_probe.py",
        ],
    },
]


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
    return path.read_text(encoding="utf-8", errors="replace")


def check_item(item: dict[str, Any]) -> dict[str, Any]:
    missing_files: list[str] = []
    missing_terms: list[str] = []
    checked_paths: list[str] = []
    combined = ""

    for relative in item["files"]:
        path = ROOT / relative
        checked_paths.append(relative)
        if not path.exists():
            missing_files.append(relative)
            continue
        combined += "\n" + read_text(path)

    combined_lower = combined.lower()
    for term in item["required"]:
        if term.lower() not in combined_lower:
            missing_terms.append(term)

    covered = not missing_files and not missing_terms
    return {
        "id": item["id"],
        "name": item["name"],
        "status": "covered" if covered else "missed",
        "gap_category": None if covered else "supply-chain-release-governance",
        "validation_category": f"supply_chain_{item['category'].replace('-', '_')}",
        "execution_class": "static_source_probe",
        "fallback_used": False,
        "claim_level": "repo_side_release_governance_contract",
        "tactics": [],
        "techniques": [],
        "evidence": {
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
    category_coverage: dict[str, dict[str, int]] = {}
    for test in tests:
        category = test["evidence"]["category"]
        entry = category_coverage.setdefault(category, {"covered": 0, "missed": 0})
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
        "missing_expected_fields": sum(len(test["missing_expected_fields"]) for test in tests),
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"supply_chain_release_governance_probe": len(tests)},
        "execution_class_counts": {"static_source_probe": len(tests)},
        "claim_level_counts": {"repo_side_release_governance_contract": len(tests)},
        "category_coverage": category_coverage,
        "roadmap_coverage": {"supply-chain-release-governance": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"supply-chain-release-governance": missed} if missed else {},
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 74 if passed else int(45 * covered_rate),
        "maturity_band": "repo-side-supply-chain-release-governance-contract-ready"
        if passed
        else "repo-side-supply-chain-release-governance-gaps",
        "recommended_claim": (
            "Repo-side supply-chain and release-governance checklist/probe contracts are present"
            if passed
            else "Supply-chain or release-governance contract gaps remain; do not promote release readiness"
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if passed else covered_rate,
        "context_quality": 1.0 if passed else covered_rate,
        "analytic_quality": 1.0,
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
        "- Scope: static repo-side supply-chain and release-governance contracts only.",
        "- Runtime effect: none; no build, signing, upload, publish, release, mirror, or secret rotation.",
        "",
        "| Test | Category | Status | Missing |",
        "|------|----------|--------|---------|",
    ]
    for test in report["tests"]:
        evidence = test["evidence"]
        missing = evidence["missing_files"] + evidence["missing_terms"]
        lines.append(
            f"| `{test['id']}` | `{evidence['category']}` | `{test['status']}` | `{'; '.join(missing) if missing else '-'}` |"
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
            "platform": "multi",
            "quality_bar": {
                "purpose": "supply_chain_release_governance_probe",
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
            "failures": [] if passed else ["supply_chain_release_governance_contract_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "release-readiness",
                "fail_on_missed": True,
                "fail_on_partial": False,
                "require_upstream": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Validates static repo-side supply-chain and release-governance contracts only. "
            "It does not prove a production release, signed published artifacts, live SBOM attachment, "
            "SLSA compliance, clean dependency posture at release time, successful secret scanning in CI, "
            "or field deployment safety. Keep public wording bounded as not production validated until "
            "release artifacts and their evidence packet are generated and reviewed."
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
