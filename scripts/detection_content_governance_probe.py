#!/usr/bin/env python3
"""Detection content governance probe for Roadmap Q.

The probe validates governance evidence around detection rules without running
endpoint workloads or querying live alerts. It checks high/critical rule
metadata, selected positive/benign benchmark evidence, replay support, and
clean-room provenance artifacts used by semantic rewrite work.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
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
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"
PROFILE_ID = "detection-content-governance-probe"
PROFILE_NAME = "Detection Content Governance Probe"


def layout_path(monorepo_path: str, standalone_path: str) -> str:
    return standalone_path if is_standalone() else monorepo_path


def script_path(script_name: str) -> str:
    return layout_path(
        f"tools/detection_validation/scripts/{script_name}",
        f"scripts/{script_name}",
    )


ARTIFACT_CHECKS: list[dict[str, Any]] = [
    {
        "id": "governance-enterprise-eval-positive-evidence",
        "name": "Enterprise eval profile provides positive detection evidence",
        "profile_id": "windows-enterprise-eval-safe-v1",
        "run_id": "exec-windows-enterprise-eval-safe-v1-full-alt-telemetry-final5",
        "roadmaps": ["I", "Q"],
        "claim_scope": "Selected enterprise-eval profile evidence only.",
    },
    {
        "id": "governance-atomic-positive-evidence",
        "name": "Atomic smoke profile provides upstream-backed positive evidence",
        "profile_id": "windows-atomic-upstream-smoke",
        "run_id": "20260524T223852Z-windows-atomic-upstream-smoke",
        "roadmaps": ["C", "Q"],
        "claim_scope": "Selected Atomic smoke profile evidence only.",
        "requires_external_claim_allowed": True,
    },
    {
        "id": "governance-caldera-positive-evidence",
        "name": "CALDERA smoke profile provides upstream-backed positive evidence",
        "profile_id": "windows-caldera-smoke",
        "run_id": "20260525T000306Z-windows-caldera-smoke",
        "roadmaps": ["D", "Q"],
        "claim_scope": "One selected CALDERA smoke run; repeatability is separate.",
        "requires_external_claim_allowed": True,
    },
    {
        "id": "governance-benign-noise-evidence",
        "name": "Broad benign/noise profile provides contrast evidence",
        "profile_id": "windows-benign-noise-broad-v1",
        "run_id": "exec-windows-benign-noise-broad-v1-tamandua-ctl-live-response-contract",
        "roadmaps": ["J", "Q"],
        "claim_scope": "Selected benign/noise broad profile evidence only.",
    },
    {
        "id": "governance-replay-evidence",
        "name": "Offline FP/severity replay profile provides regression evidence",
        "profile_id": "telemetry-replay-offline-fp-severity-v1",
        "run_id": "20260602T075916Z-telemetry-replay-offline-fp-severity-v1",
        "roadmaps": ["P", "Q"],
        "claim_scope": "Selected offline replay decisions only.",
    },
]

SOURCE_CHECKS: list[dict[str, Any]] = [
    {
        "id": "governance-clean-room-acquisition-doc",
        "name": "External rule acquisition document preserves clean-room boundaries",
        "file": layout_path(
            "tools/detection_validation/EXTERNAL_RULE_ACQUISITION.md",
            "EXTERNAL_RULE_ACQUISITION.md",
        ),
        "roadmaps": ["Q"],
        "required": [
            "Do not copy rule bodies",
            "semantic rewrite",
            "provenance",
            "license",
        ],
    },
    {
        "id": "governance-external-coverage-doc",
        "name": "External rule coverage mapping documents source mix and claim boundaries",
        "file": "docs/benchmarks/EXTERNAL_RULE_COVERAGE_MAPPING.md",
        "roadmaps": ["Q"],
        "required": [
            "source",
            "coverage",
            "Tamandua-authored",
            "claim",
        ],
    },
    {
        "id": "governance-event-contract-doc",
        "name": "External rule event contracts document existing, normalize-alias, and planned telemetry",
        "file": "docs/benchmarks/EXTERNAL_RULE_EVENT_CONTRACTS.md",
        "roadmaps": ["Q"],
        "required": [
            "existing",
            "normalize-alias",
            "planned",
            "report_only",
        ],
    },
    {
        "id": "governance-metadata-checker-conservative-fields",
        "name": "Metadata checker enforces high/critical explanation fields",
        "file": script_path("check_detection_rule_metadata.py"),
        "roadmaps": ["Q"],
        "required": [
            "REQUIRED_HIGH_FIELDS",
            "falsepositives",
            "tags",
            "description",
            "logsource",
            "detection block lacks explicit condition",
        ],
    },
]

JSON_CHECKS: list[dict[str, Any]] = [
    {
        "id": "governance-external-inventory-shape",
        "name": "External rule inventory preserves source and candidate accounting",
        "file": layout_path(
            "tools/detection_validation/roadmaps/external_rule_inventory.json",
            "roadmaps/external_rule_inventory.json",
        ),
        "roadmaps": ["Q"],
        "required_keys": ["items"],
        "min_items": 1000,
    },
    {
        "id": "governance-semantic-candidate-shape",
        "name": "Semantic rewrite candidate list exists for Tamandua-authored promotion",
        "file": layout_path(
            "tools/detection_validation/roadmaps/external_rule_semantic_rewrite_candidates.json",
            "roadmaps/external_rule_semantic_rewrite_candidates.json",
        ),
        "roadmaps": ["Q"],
        "required_keys": ["candidates"],
        "min_items": 20,
    },
    {
        "id": "governance-rule-evidence-matrix-shape",
        "name": "High/critical rule evidence matrix records positive and benign mapping gaps",
        "file": "docs/benchmarks/generated/detection_rule_evidence_matrix.json",
        "roadmaps": ["Q"],
        "required_keys": ["rules"],
        "min_items": 100,
    },
    {
        "id": "governance-rule-evidence-backlog-shape",
        "name": "High/critical rule evidence backlog prioritizes missing positive mappings",
        "file": "docs/benchmarks/generated/detection_rule_evidence_backlog.json",
        "roadmaps": ["Q"],
        "required_keys": ["waves"],
        "min_items": 4,
    },
    {
        "id": "governance-rule-wave1-fixture-plan-shape",
        "name": "Wave 1 high/critical rule fixture plan is implementation-ready",
        "file": "docs/benchmarks/generated/detection_rule_wave_1_fixture_plan.json",
        "roadmaps": ["Q"],
        "required_keys": ["fixtures"],
        "min_items": 25,
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


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def artifact_check(item: dict[str, Any]) -> dict[str, Any]:
    path = RUNS_DIR / f"{item['run_id']}.comparison.json"
    missing: list[str] = []
    report: dict[str, Any] = {}
    if not path.exists():
        missing.append(f"missing artifact {path.relative_to(ROOT)}")
    else:
        report = read_json(path)
    summary = report.get("summary", {})
    quality_gate = report.get("quality_gate", {})
    scorecard = report.get("scorecard", {})
    if report.get("profile_id") and report.get("profile_id") != item["profile_id"]:
        missing.append(f"profile mismatch {report.get('profile_id')} != {item['profile_id']}")
    if quality_gate.get("passed") is not True:
        missing.append("quality gate is not pass")
    for key in ("missed", "execution_failed", "unknown_source_events", "unexpected_high_or_critical_events", "unexpected_high_or_critical_alerts"):
        if int(summary.get(key, 0) or 0) != 0:
            missing.append(f"{key}={summary.get(key)}")
    if item.get("requires_external_claim_allowed") and scorecard.get("external_claim_allowed") is not True:
        missing.append("external claim not allowed by artifact scorecard")
    return test_result(item, "artifact_governance_evidence", missing, {
        "artifact": str(path.relative_to(ROOT)),
        "profile_id": item["profile_id"],
        "run_id": item["run_id"],
        "quality_gate_passed": quality_gate.get("passed"),
        "tests": summary.get("tests", 0),
        "covered": summary.get("covered", 0),
        "maturity_score": scorecard.get("maturity_score"),
        "maturity_band": scorecard.get("maturity_band"),
        "claim_scope": item["claim_scope"],
    })


def source_check(item: dict[str, Any]) -> dict[str, Any]:
    path = ROOT / item["file"]
    missing: list[str] = []
    if not path.exists():
        missing.append(f"missing source {item['file']}")
        text = ""
    else:
        text = path.read_text(encoding="utf-8", errors="replace").lower()
    for term in item["required"]:
        if term.lower() not in text:
            missing.append(f"missing term {term}")
    return test_result(item, "source_governance_contract", missing, {
        "artifact": item["file"],
        "checked_terms": item["required"],
        "claim_scope": "Source contract only.",
    })


def json_check(item: dict[str, Any]) -> dict[str, Any]:
    path = ROOT / item["file"]
    missing: list[str] = []
    count = 0
    if not path.exists():
        missing.append(f"missing json {item['file']}")
        payload: dict[str, Any] = {}
    else:
        payload = read_json(path)
    for key in item["required_keys"]:
        if key not in payload:
            missing.append(f"missing key {key}")
        elif isinstance(payload[key], list):
            count = len(payload[key])
        elif isinstance(payload[key], dict):
            count = len(payload[key])
    if count < item["min_items"]:
        missing.append(f"item count {count} < {item['min_items']}")
    return test_result(item, "json_governance_contract", missing, {
        "artifact": item["file"],
        "item_count": count,
        "claim_scope": "Inventory/provenance shape only.",
    })


def metadata_report_check() -> dict[str, Any]:
    path = GENERATED_DIR / "detection_rule_metadata_report.json"
    missing: list[str] = []
    if not path.exists():
        missing.append("metadata report missing")
        report: dict[str, Any] = {}
    else:
        report = read_json(path)
    if int(report.get("rules_scanned", 0) or 0) <= 0:
        missing.append("rules_scanned is zero")
    if int(report.get("high_critical_rules", 0) or 0) <= 0:
        missing.append("high_critical_rules is zero")
    if int(report.get("high_critical_review", 0) or 0) != 0:
        missing.append(f"high_critical_review={report.get('high_critical_review')}")
    return test_result(
        {
            "id": "governance-high-critical-metadata-report",
            "name": "High/critical rule metadata report is clean",
            "roadmaps": ["Q"],
        },
        "metadata_report",
        missing,
        {
            "artifact": str(path.relative_to(ROOT)),
            "rules_scanned": report.get("rules_scanned", 0),
            "high_critical_rules": report.get("high_critical_rules", 0),
            "high_critical_review": report.get("high_critical_review", 0),
            "claim_scope": "Metadata completeness only; not rule syntax or runtime detection proof.",
        },
    )


def test_result(item: dict[str, Any], category: str, missing: list[str], evidence: dict[str, Any]) -> dict[str, Any]:
    covered = not missing
    return {
        "id": item["id"],
        "name": item["name"],
        "status": "covered" if covered else "missed",
        "gap_category": None if covered else "detection-governance",
        "validation_category": "detection_content_governance",
        "execution_class": category,
        "fallback_used": False,
        "claim_level": "content_governance_evidence",
        "tactics": [],
        "techniques": [],
        "evidence": {"roadmaps": item["roadmaps"], "missing": missing, **evidence},
        "missing_expected_fields": missing,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    subprocess.run(
        [sys.executable, script_path("check_detection_rule_metadata.py"), "--fail-on-review"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        [sys.executable, script_path("detection_rule_evidence_matrix.py")],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        [sys.executable, script_path("detection_rule_evidence_backlog.py")],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        [sys.executable, script_path("detection_rule_wave_fixture_plan.py"), "--wave", "wave_1"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return (
        [metadata_report_check()]
        + [artifact_check(item) for item in ARTIFACT_CHECKS]
        + [source_check(item) for item in SOURCE_CHECKS]
        + [json_check(item) for item in JSON_CHECKS]
    )


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
        "executor_counts": {"detection_content_governance_probe": len(tests)},
        "execution_class_counts": {},
        "claim_level_counts": {"content_governance_evidence": len(tests)},
        "category_coverage": {"detection_content_governance": {"covered": covered, "missed": missed}},
        "roadmap_coverage": roadmap_counts,
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"detection-governance": missed} if missed else {},
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 83 if passed else int(55 * covered_rate),
        "maturity_band": "content-governance-selected-evidence-ready" if passed else "content-governance-gaps",
        "recommended_claim": (
            "Detection content governance has selected positive, benign, replay, metadata, and provenance evidence"
            if passed
            else "Detection content governance gaps remain"
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
        "- Scope: selected detection content governance evidence.",
        "- Runtime effect: none; local artifact/source checks only.",
        "",
        "| Test | Status | Evidence | Missing |",
        "|------|--------|----------|---------|",
    ]
    for test in report["tests"]:
        evidence = test["evidence"]
        missing = "; ".join(evidence.get("missing", [])) or "-"
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{evidence.get('artifact', '-')}` | {missing} |")
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
        "benchmark_lane": "detection-governance",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "detection_content_governance_probe",
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
            "failures": [] if passed else ["detection_content_governance_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "detection-governance",
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
            "Selected content-governance evidence only. This does not prove all rules have positive and benign fixtures, "
            "that every high/critical rule is non-bypassable, or that external-source-inspired candidates are implemented."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "detection-governance",
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
