#!/usr/bin/env python3
"""Audit consistency between comparative benchmark artifacts.

This report-only tool verifies that the human positioning document and the
generated comparative scorecard agree with their two upstream sources:
attack_coverage_matrix.json and fp_severity_decision_matrix.json. It does not
execute benchmarks, contact services, or create external validation claims.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"
DEFAULT_POSITIONING = ROOT / "docs" / "benchmarks" / "COMPARATIVE_BENCHMARK_POSITIONING.md"

ATTACK_COVERAGE = "attack_coverage_matrix.json"
FP_SEVERITY = "fp_severity_decision_matrix.json"
COMPARATIVE_SCORECARD = "comparative_benchmark_scorecard.json"
OUTPUT_STEM = "comparative_artifact_consistency"


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            ).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--porcelain"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"error: required artifact not found: {rel(path)}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: could not read {rel(path)}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"error: expected JSON object: {rel(path)}")
    return data


def load_text(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"error: required document not found: {rel(path)}")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"error: could not read {rel(path)}: {exc}")


def dimension(scorecard: dict[str, Any], dim_id: str) -> dict[str, Any]:
    for entry in scorecard.get("dimensions") or []:
        if isinstance(entry, dict) and entry.get("id") == dim_id:
            return entry
    raise SystemExit(f"error: comparative scorecard is missing dimension {dim_id!r}")


def metric(scorecard: dict[str, Any], dim_id: str, key: str) -> Any:
    return (dimension(scorecard, dim_id).get("metrics") or {}).get(key)


def rounded(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 6)
    return value


def check(checks: list[dict[str, Any]], name: str, actual: Any, expected: Any, sources: list[str]) -> None:
    actual_norm = rounded(actual)
    expected_norm = rounded(expected)
    checks.append(
        {
            "name": name,
            "status": "PASS" if actual_norm == expected_norm else "FAIL",
            "actual": actual_norm,
            "expected": expected_norm,
            "source_files": sources,
        }
    )


def check_contains(
    checks: list[dict[str, Any]], name: str, text: str, needle: str, source: str
) -> None:
    checks.append(
        {
            "name": name,
            "status": "PASS" if needle in text else "FAIL",
            "actual": needle in text,
            "expected": True,
            "needle": needle,
            "source_files": [source],
        }
    )


def artifact_safety_checks(checks: list[dict[str, Any]], name: str, data: dict[str, Any]) -> None:
    check(checks, f"{name}: external_claim_allowed == false", data.get("external_claim_allowed"), False, [name])
    check(checks, f"{name}: claim_boundary present", bool(data.get("claim_boundary")), True, [name])
    check(checks, f"{name}: schema_version present", bool(data.get("schema_version")), True, [name])


def build_payload(
    coverage: dict[str, Any],
    fp: dict[str, Any],
    scorecard: dict[str, Any],
    positioning_text: str,
    positioning_source: str,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    coverage_source = ATTACK_COVERAGE
    fp_source = FP_SEVERITY
    scorecard_source = COMPARATIVE_SCORECARD

    coverage_summary = coverage.get("summary") or {}
    evidence = coverage_summary.get("evidence_status_counts") or {}
    platforms = coverage_summary.get("platform_technique_counts") or {}
    total = int(coverage_summary.get("total_techniques") or 0)
    live = int(evidence.get("live") or 0)
    replay = int(evidence.get("replay") or 0)
    fixture = int(evidence.get("fixture") or 0)
    none = int(evidence.get("none") or 0)
    runtime = live + replay + fixture

    fp_aggregate = fp.get("aggregate") or {}

    check(checks, "Scorecard total_techniques == coverage matrix", metric(scorecard, "technique_coverage", "total_techniques"), total, [coverage_source, scorecard_source])
    check(checks, "Scorecard runtime-evidence == coverage matrix", metric(scorecard, "technique_coverage", "techniques_with_runtime_evidence"), runtime, [coverage_source, scorecard_source])
    check(checks, "Scorecard rule-content-only == coverage none count", metric(scorecard, "technique_coverage", "techniques_rule_content_only"), none, [coverage_source, scorecard_source])
    check(checks, "Scorecard runtime_evidence_rate == coverage matrix", metric(scorecard, "technique_coverage", "runtime_evidence_rate"), runtime / total if total else None, [coverage_source, scorecard_source])
    check(checks, "Scorecard rule_content_only_rate == coverage matrix", metric(scorecard, "technique_coverage", "rule_content_only_rate"), none / total if total else None, [coverage_source, scorecard_source])
    check(checks, "Scorecard cross_platform == coverage matrix", metric(scorecard, "technique_coverage", "cross_platform_techniques"), coverage_summary.get("cross_platform_techniques"), [coverage_source, scorecard_source])
    for platform in ("windows", "linux", "macos"):
        check(checks, f"Scorecard {platform} count == coverage matrix", (metric(scorecard, "technique_coverage", "platform_technique_counts") or {}).get(platform), platforms.get(platform), [coverage_source, scorecard_source])

    for tier, expected in (("live", live), ("replay", replay), ("fixture", fixture), ("none", none)):
        check(checks, f"Scorecard evidence_depth {tier} == coverage matrix", metric(scorecard, "evidence_depth", tier), expected, [coverage_source, scorecard_source])
    check(checks, "Scorecard evidence_depth total == coverage matrix", metric(scorecard, "evidence_depth", "total_techniques"), total, [coverage_source, scorecard_source])
    check(checks, "Scorecard evidence_depth live_rate == coverage matrix", metric(scorecard, "evidence_depth", "live_rate"), live / total if total else None, [coverage_source, scorecard_source])

    fp_metric_map = {
        "classifier_rules_total": "classifier_rules_total",
        "classifier_reduce_severity_rules": "classifier_reduce_severity_rules",
        "classifier_suppress_rules": "classifier_suppress_rules",
        "fp_downgrade_count": "fp_downgrade_count",
        "fixture_scenarios_total": "fixture_scenarios_total",
        "fixture_downgrade_scenarios": "fixture_downgrade_scenarios",
        "fixture_coverage_rate": "fixture_coverage_rate",
        "classifier_reasons_without_fixture": "classifier_reasons_without_fixture",
    }
    for score_key, fp_key in fp_metric_map.items():
        check(checks, f"Scorecard {score_key} == FP matrix", metric(scorecard, "false_positive_noise_handling", score_key), fp_aggregate.get(fp_key), [fp_source, scorecard_source])
    check(checks, "Scorecard uncovered_fp_reason_count == FP matrix", metric(scorecard, "false_positive_noise_handling", "uncovered_fp_reason_count"), len(fp_aggregate.get("uncovered_fp_reasons") or []), [fp_source, scorecard_source])

    for key in ("tp_retention_count", "tp_retention_test_total", "tp_retention_rate", "fixture_retain_critical_scenarios"):
        check(checks, f"Scorecard {key} == FP matrix", metric(scorecard, "true_positive_retention", key), fp_aggregate.get(key), [fp_source, scorecard_source])

    check(checks, "Coverage: live+replay+fixture+none == total", live + replay + fixture + none, total, [coverage_source])
    check(checks, "Coverage: platform sum >= total", sum(int(v or 0) for v in platforms.values()) >= total, True, [coverage_source])
    check(checks, "FP: downgrade+retain == total scenarios", int(fp_aggregate.get("fixture_downgrade_scenarios") or 0) + int(fp_aggregate.get("fixture_retain_critical_scenarios") or 0), fp_aggregate.get("fixture_scenarios_total"), [fp_source])
    check(checks, "FP: reasons-with-fixture + without == total rules", int(fp_aggregate.get("classifier_reasons_with_fixture") or 0) + int(fp_aggregate.get("classifier_reasons_without_fixture") or 0), fp_aggregate.get("classifier_rules_total"), [fp_source])
    check(checks, "FP: reduce + suppress == total rules", int(fp_aggregate.get("classifier_reduce_severity_rules") or 0) + int(fp_aggregate.get("classifier_suppress_rules") or 0), fp_aggregate.get("classifier_rules_total"), [fp_source])
    check(checks, "FP: uncovered_fp_reasons list length == without-fixture count", len(fp_aggregate.get("uncovered_fp_reasons") or []), fp_aggregate.get("classifier_reasons_without_fixture"), [fp_source])
    check(checks, "FP: tp_retention_rate == count/test_total", fp_aggregate.get("tp_retention_rate"), (int(fp_aggregate.get("tp_retention_count") or 0) / int(fp_aggregate.get("tp_retention_test_total") or 1)), [fp_source])

    artifact_safety_checks(checks, coverage_source, coverage)
    artifact_safety_checks(checks, fp_source, fp)
    artifact_safety_checks(checks, scorecard_source, scorecard)

    check_contains(checks, "Positioning quotes 41/218 runtime evidence", positioning_text, "41/218", positioning_source)
    check_contains(checks, "Positioning quotes evidence depth", positioning_text, "live=41, replay=0, fixture=0,\n    none=177", positioning_source)
    check_contains(checks, "Positioning quotes FP scenario counts", positioning_text, "43** fixture scenarios, **21** downgrade\n    scenarios", positioning_source)
    check_contains(checks, "Positioning quotes FP fixture coverage", positioning_text, "**21/21** (rate **1.0**)", positioning_source)
    check_contains(checks, "Positioning quotes zero uncovered reasons", positioning_text, "classifier reasons **without** a fixture **0**", positioning_source)
    check_contains(checks, "Positioning quotes TP retention", positioning_text, "tp_retention_rate = 1.0 (22/22)", positioning_source)
    check_contains(checks, "Positioning states external_claim_allowed false", positioning_text, "external_claim_allowed: false", positioning_source)

    failed = sum(1 for item in checks if item["status"] == "FAIL")
    passed = sum(1 for item in checks if item["status"] == "PASS")
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "git": git_snapshot(),
        "external_claim_allowed": False,
        "claim_boundary": "offline consistency audit of generated comparative artifacts",
        "source": {
            "attack_coverage_matrix": f"docs/benchmarks/generated/{ATTACK_COVERAGE}",
            "fp_severity_decision_matrix": f"docs/benchmarks/generated/{FP_SEVERITY}",
            "comparative_benchmark_scorecard": f"docs/benchmarks/generated/{COMPARATIVE_SCORECARD}",
            "comparative_positioning": positioning_source,
        },
        "summary": {
            "total_checks": len(checks),
            "passed": passed,
            "failed": failed,
            "warnings": 0,
        },
        "checks": checks,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Comparative Artifact Consistency",
        "",
        "Status: generated (offline audit)",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Git commit: `{payload['git'].get('commit_short') or 'unknown'}`"
        + (" (dirty)" if payload["git"].get("dirty") else ""),
        f"- Checks: {summary['passed']}/{summary['total_checks']} passed; {summary['failed']} failed",
        "- external_claim_allowed: false",
        "",
        "## Claim Boundary",
        "",
        payload["claim_boundary"],
        "",
        "## Checks",
        "",
        "| Status | Check | Actual | Expected | Sources |",
        "|--------|-------|--------|----------|---------|",
    ]
    for item in payload["checks"]:
        sources = ", ".join(f"`{source}`" for source in item.get("source_files") or [])
        lines.append(
            f"| `{item['status']}` | {item['name']} | `{item.get('actual')}` | "
            f"`{item.get('expected')}` | {sources} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_outputs(payload: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{OUTPUT_STEM}.json"
    md_path = output_dir / f"{OUTPUT_STEM}.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload).rstrip() + "\n", encoding="utf-8")
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", default=str(DEFAULT_GENERATED_DIR))
    parser.add_argument("--positioning", default=str(DEFAULT_POSITIONING))
    parser.add_argument("--output-dir", default=str(DEFAULT_GENERATED_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    generated_dir = Path(args.generated_dir)
    positioning_path = Path(args.positioning)
    output_dir = Path(args.output_dir)

    coverage = load_json(generated_dir / ATTACK_COVERAGE)
    fp = load_json(generated_dir / FP_SEVERITY)
    scorecard = load_json(generated_dir / COMPARATIVE_SCORECARD)
    positioning_text = load_text(positioning_path)

    payload = build_payload(
        coverage,
        fp,
        scorecard,
        positioning_text,
        rel(positioning_path),
    )
    json_path, md_path = write_outputs(payload, output_dir)
    summary = payload["summary"]
    print(
        f"comparative_artifact_consistency={summary['failed'] == 0} "
        f"checks={summary['passed']}/{summary['total_checks']} "
        f"written={rel(json_path)},{rel(md_path)}"
    )
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
