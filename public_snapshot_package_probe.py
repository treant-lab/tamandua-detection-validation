#!/usr/bin/env python3
"""Build a claim-safe public validation snapshot package for Roadmap H.

This probe is intentionally local and redacted. It reads already-generated
benchmark artifacts, validates that selected evidence is green and scoped, and
emits a publishable snapshot package that separates allowed claims from
blocked claims. It does not query the server, inspect live alerts, or include
raw endpoint telemetry.
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
SCORECARD_PATH = ROOT / "docs" / "benchmarks" / "generated" / "validation_roadmap_scorecard.json"
PROFILE_ID = "public-snapshot-package-probe"
PROFILE_NAME = "Public Snapshot Package Probe"


EVIDENCE_INPUTS: list[dict[str, Any]] = [
    {
        "id": "atomic-smoke-selected-profile",
        "profile_id": "windows-atomic-upstream-smoke",
        "run_id": "20260524T223852Z-windows-atomic-upstream-smoke",
        "roadmaps": ["C", "H", "Q"],
        "claim_scope": "Selected Windows Atomic Red Team smoke profile only.",
        "allowed_claim": "Tamandua passed the selected Windows Atomic Red Team smoke profile with upstream-backed execution evidence.",
        "blocked_claims": [
            "Full Atomic Red Team coverage",
            "Full ATT&CK coverage",
            "CrowdStrike or SentinelOne parity",
        ],
        "requires_external_claim_allowed": True,
        "requires_upstream_rate": 1.0,
    },
    {
        "id": "caldera-smoke-selected-profile",
        "profile_id": "windows-caldera-smoke",
        "run_id": "20260525T000306Z-windows-caldera-smoke",
        "roadmaps": ["D", "H", "R"],
        "claim_scope": "Selected Windows CALDERA smoke profile only; repeatability gate is not closed.",
        "allowed_claim": "Tamandua passed one selected Windows CALDERA smoke run with upstream-backed operation evidence.",
        "blocked_claims": [
            "CALDERA repeatability",
            "Full CALDERA enterprise emulation coverage",
            "Full adversary emulation parity",
        ],
        "requires_external_claim_allowed": True,
        "requires_upstream_rate": 1.0,
    },
    {
        "id": "windows-p1-deterministic-final",
        "profile_id": "windows-roadmap-300-p1-batch-01",
        "run_id": "exec-windows-p1-batch-01-live-response-audit-contract-clean-rerun",
        "roadmaps": ["B1", "H"],
        "claim_scope": "Windows deterministic/live-response contract evidence for the selected P1 batch; not external-tool-backed.",
        "allowed_claim": "Tamandua has passing deterministic Windows P1 validation evidence for the selected batch.",
        "blocked_claims": [
            "Fresh-restore endpoint sensor parity",
            "Driver-loaded process-create proof for every P1/P2 scenario",
            "Production fleet coverage",
        ],
        "requires_external_claim_allowed": False,
        "requires_upstream_rate": None,
    },
    {
        "id": "unified-dr-selected-fixtures",
        "profile_id": "windows-unified-dr-engine-v1",
        "run_id": "20260602T081730Z-windows-unified-dr-engine-v1",
        "roadmaps": ["U", "H"],
        "claim_scope": "Selected report-only unified D&R fixtures.",
        "allowed_claim": "Tamandua has a selected-fixture proof for event to detection to alert contract to storyline contract to response/audit plan to feedback to replay.",
        "blocked_claims": [
            "Runtime backend unified D&R execution",
            "Production replay executor",
            "LimaCharlie parity",
        ],
        "requires_external_claim_allowed": False,
        "requires_upstream_rate": None,
    },
    {
        "id": "release-resilience-static-boundary",
        "profile_id": "release-resilience-static-probe",
        "run_id_prefix": "20260602T082413Z-release-resilience-static-probe",
        "roadmaps": ["G", "L", "V", "H"],
        "claim_scope": "Static/source release and resilience contracts only.",
        "allowed_claim": "Tamandua has repo-side source contracts for release/resilience readiness surfaces.",
        "blocked_claims": [
            "Signed production release readiness",
            "VM-backed install/update/rollback/uninstall proof",
            "Secure Boot driver loading proof",
            "Crash-proof endpoint claim",
        ],
        "requires_external_claim_allowed": False,
        "requires_upstream_rate": None,
    },
]

PROHIBITED_PUBLIC_CLAIMS = [
    "Full ATT&CK coverage",
    "Full Atomic Red Team coverage",
    "Full CALDERA coverage",
    "CrowdStrike parity",
    "SentinelOne parity",
    "Wazuh enterprise replacement",
    "LimaCharlie parity",
    "Linux/macOS parity",
    "Production signed Windows release readiness",
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
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def artifact_path(item: dict[str, Any]) -> Path:
    if "run_id" in item:
        return RUNS_DIR / f"{item['run_id']}.comparison.json"
    prefix = item["run_id_prefix"]
    matches = sorted(RUNS_DIR.glob(f"{prefix}*.comparison.json"))
    return matches[-1] if matches else RUNS_DIR / f"{prefix}.comparison.json"


def load_scorecard_status() -> dict[str, Any]:
    if not SCORECARD_PATH.exists():
        return {"missing": True, "roadmaps": {}}
    scorecard = read_json(SCORECARD_PATH)
    roadmaps = {str(item["key"]): item for item in scorecard.get("roadmaps", [])}
    return {"missing": False, "roadmaps": roadmaps, "source": scorecard.get("source", {})}


def validate_input(item: dict[str, Any]) -> dict[str, Any]:
    path = artifact_path(item)
    missing: list[str] = []
    warnings: list[str] = []
    report: dict[str, Any] = {}

    if not path.exists():
        missing.append(f"missing artifact {path.relative_to(ROOT)}")
    else:
        report = read_json(path)

    summary = report.get("summary", {})
    quality_gate = report.get("quality_gate", {})
    scorecard = report.get("scorecard", {})
    profile_id = report.get("profile_id")

    if profile_id and profile_id != item["profile_id"]:
        missing.append(f"profile mismatch {profile_id} != {item['profile_id']}")
    if quality_gate.get("passed") is not True:
        missing.append("quality gate is not pass")
    if int(summary.get("missed", 0) or 0) != 0:
        missing.append("missed tests present")
    if int(summary.get("execution_failed", 0) or 0) != 0:
        missing.append("execution failures present")
    if int(summary.get("unknown_source_events", 0) or 0) != 0:
        missing.append("unknown-source events present")
    if int(summary.get("unexpected_high_or_critical_events", 0) or 0) != 0:
        missing.append("unexpected high/critical events present")
    if int(summary.get("unexpected_high_or_critical_alerts", 0) or 0) != 0:
        missing.append("unexpected high/critical alerts present")

    upstream_required = item.get("requires_upstream_rate")
    if upstream_required is not None and float(scorecard.get("upstream_rate", 0.0) or 0.0) < float(upstream_required):
        missing.append("required upstream rate not met")
    if item.get("requires_external_claim_allowed") and scorecard.get("external_claim_allowed") is not True:
        missing.append("external claim is not allowed by artifact scorecard")
    if item.get("requires_external_claim_allowed") is False and scorecard.get("external_claim_allowed") is True:
        warnings.append("artifact allows external claim, but snapshot keeps this claim internally scoped")

    status = "covered" if not missing else "missed"
    return {
        "id": item["id"],
        "name": item["allowed_claim"],
        "status": status,
        "gap_category": None if status == "covered" else "claim-boundary",
        "validation_category": "public_snapshot_package",
        "execution_class": "artifact_packaging_probe",
        "fallback_used": False,
        "claim_level": "claim_safe_public_snapshot",
        "tactics": [],
        "techniques": [],
        "evidence": {
            "roadmaps": item["roadmaps"],
            "profile_id": item["profile_id"],
            "run_id": report.get("run_id") or item.get("run_id") or item.get("run_id_prefix"),
            "artifact": str(path.relative_to(ROOT)),
            "claim_scope": item["claim_scope"],
            "allowed_claim": item["allowed_claim"],
            "blocked_claims": item["blocked_claims"],
            "quality_gate_passed": quality_gate.get("passed"),
            "maturity_score": scorecard.get("maturity_score"),
            "maturity_band": scorecard.get("maturity_band"),
            "external_claim_allowed": scorecard.get("external_claim_allowed", False),
            "upstream_rate": scorecard.get("upstream_rate", 0.0),
            "tests": summary.get("tests", 0),
            "covered": summary.get("covered", 0),
            "missing": missing,
            "warnings": warnings,
        },
        "missing_expected_fields": missing,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def build_tests(scorecard_status: dict[str, Any]) -> list[dict[str, Any]]:
    tests = [validate_input(item) for item in EVIDENCE_INPUTS]
    roadmaps = scorecard_status.get("roadmaps", {})
    h = roadmaps.get("H", {})
    tests.append(
        {
            "id": "roadmap-h-scorecard-present",
            "name": "Generated roadmap scorecard includes Roadmap H with candidate evidence",
            "status": "covered" if not scorecard_status.get("missing") and h else "missed",
            "gap_category": None if h else "claim-boundary",
            "validation_category": "public_snapshot_package",
            "execution_class": "artifact_packaging_probe",
            "fallback_used": False,
            "claim_level": "claim_safe_public_snapshot",
            "tactics": [],
            "techniques": [],
            "evidence": {
                "roadmaps": ["H", "O"],
                "artifact": str(SCORECARD_PATH.relative_to(ROOT)),
                "roadmap_h_status": h.get("status"),
                "claim_scope": "Generated scorecard status only; public language still requires review.",
                "allowed_claim": "Roadmap H evidence candidates are visible in the generated scorecard.",
                "blocked_claims": ["Automatically public-ready claim without package review"],
                "missing": [] if h else ["Roadmap H missing from generated scorecard"],
                "warnings": [],
            },
            "missing_expected_fields": [] if h else ["Roadmap H missing from generated scorecard"],
            "missing_expected_telemetry": [],
            "missing_expected_detections": [],
            "missing_expected_alerts": [],
            "missing_expected_correlations": [],
            "missing_expected_driver_raw_event_types": [],
        }
    )
    tests.append(
        {
            "id": "prohibited-public-claims-denied",
            "name": "Snapshot explicitly denies broad public claims that are not supported yet",
            "status": "covered",
            "gap_category": None,
            "validation_category": "public_snapshot_package",
            "execution_class": "artifact_packaging_probe",
            "fallback_used": False,
            "claim_level": "claim_safe_public_snapshot",
            "tactics": [],
            "techniques": [],
            "evidence": {
                "roadmaps": ["H"],
                "artifact": "generated by this probe",
                "claim_scope": "Negative claim guardrail.",
                "allowed_claim": "Broad unsupported parity and coverage claims are explicitly disallowed.",
                "blocked_claims": PROHIBITED_PUBLIC_CLAIMS,
                "missing": [],
                "warnings": [],
            },
            "missing_expected_fields": [],
            "missing_expected_telemetry": [],
            "missing_expected_detections": [],
            "missing_expected_alerts": [],
            "missing_expected_correlations": [],
            "missing_expected_driver_raw_event_types": [],
        }
    )
    return tests


def public_snapshot(tests: list[dict[str, Any]]) -> dict[str, Any]:
    allowed = []
    blocked: list[str] = []
    evidence = []
    for test in tests:
        item = test["evidence"]
        if test["status"] == "covered":
            allowed.append(item["allowed_claim"])
        blocked.extend(item.get("blocked_claims", []))
        evidence.append(
            {
                "id": test["id"],
                "status": test["status"],
                "profile_id": item.get("profile_id"),
                "run_id": item.get("run_id"),
                "artifact": item.get("artifact"),
                "claim_scope": item.get("claim_scope"),
                "quality_gate_passed": item.get("quality_gate_passed"),
                "maturity_score": item.get("maturity_score"),
                "maturity_band": item.get("maturity_band"),
            }
        )
    return {
        "schema_version": 1,
        "snapshot_type": "tamandua_public_validation_snapshot_package",
        "snapshot_date": datetime.now(timezone.utc).date().isoformat(),
        "redaction_policy": {
            "raw_payloads_removed": True,
            "stdout_stderr_removed": True,
            "hostnames_redacted": True,
            "agent_ids_redacted": True,
            "internal_ips_redacted": True,
            "secret_values_removed": True,
        },
        "allowed_claims": sorted(set(allowed)),
        "disallowed_claims": sorted(set(blocked + PROHIBITED_PUBLIC_CLAIMS)),
        "evidence": evidence,
        "known_boundaries": [
            "This package summarizes selected benchmark artifacts only.",
            "It is not a live production SOC or fleet-scale proof.",
            "It does not publish raw endpoint telemetry or server logs.",
            "Alert cleanup in the live server does not affect these archived artifacts.",
        ],
    }


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = [test for test in tests if test["status"] != "covered"]
    roadmap_counts: dict[str, dict[str, int]] = {}
    for test in tests:
        for roadmap in test["evidence"].get("roadmaps", []):
            entry = roadmap_counts.setdefault(roadmap, {"covered": 0, "missed": 0})
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
        "missing_expected_fields": missed,
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"public_snapshot_package_probe": len(tests)},
        "execution_class_counts": {"artifact_packaging_probe": len(tests)},
        "claim_level_counts": {"claim_safe_public_snapshot": len(tests)},
        "category_coverage": {"public_snapshot_package": {"covered": covered, "missed": missed}},
        "roadmap_coverage": roadmap_counts,
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"claim-boundary": missed} if missed else {},
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 82 if passed else int(50 * covered_rate),
        "maturity_band": "claim-safe-snapshot-ready" if passed else "claim-safe-snapshot-gaps",
        "recommended_claim": (
            "Claim-safe public validation snapshot package is ready for human copy review"
            if passed
            else "Public validation snapshot has evidence or claim-boundary gaps"
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
        "- Scope: selected archived benchmark artifacts and claim-safe public packaging.",
        "- Runtime effect: none; no server, database, VM, agent, or live alert dependency.",
        "",
        "## Allowed Claims",
        "",
    ]
    lines.extend(f"- {claim}" for claim in report["public_snapshot"]["allowed_claims"])
    lines.extend(["", "## Disallowed Claims", ""])
    lines.extend(f"- {claim}" for claim in report["public_snapshot"]["disallowed_claims"])
    lines.extend(["", "## Evidence", "", "| Evidence | Profile | Run | Status | Scope |", "|----------|---------|-----|--------|-------|"])
    for test in report["tests"]:
        evidence = test["evidence"]
        lines.append(
            f"| `{test['id']}` | `{evidence.get('profile_id', '-')}` | `{evidence.get('run_id', '-')}` | `{test['status']}` | {evidence.get('claim_scope', '-')} |"
        )
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = build_tests(load_scorecard_status())
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "public-snapshot",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "public_snapshot_package_probe",
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
            "failures": [] if passed else ["public_snapshot_claim_boundary_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "public-snapshot",
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
        "public_snapshot": public_snapshot(tests),
        "claim_boundary": (
            "This package is claim-safe packaging for selected archived benchmark artifacts only. "
            "It does not prove full ATT&CK coverage, full Atomic/CALDERA coverage, CrowdStrike/SentinelOne parity, "
            "Wazuh replacement readiness, Linux/macOS parity, signed production release readiness, or fleet-scale SOC operation."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "public-snapshot",
        "summary": summary,
        "quality_gate": report["quality_gate"],
        "scorecard": report["scorecard"],
        "public_snapshot": report["public_snapshot"],
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
