#!/usr/bin/env python3
"""Synthesize a comparative benchmark scorecard for Tamandua (report-only).

This tool models Tamandua's self-assessed posture in the structured dimensions
that third-party labs (MITRE ATT&CK Evaluations, AV-Comparatives, SE Labs)
report on: technique coverage, evidence depth, false-positive / noise handling,
true-positive retention, detection latency, and independent validation.

It is intentionally artifact-driven. It CONSUMES the Wave 1 generated artifacts
(``attack_coverage_matrix.json`` and ``fp_severity_decision_matrix.json``) plus
run-level signals from ``validation_roadmap_scorecard.json`` and
``runs/index.json``. It does NOT contact the Tamandua server, query a database,
execute benchmarks, or recompute coverage. Every dimension is explicitly marked
``calculated`` (numeric offline evidence exists) or ``pending_live`` (requires a
live endpoint or an independent lab), and ``external_claim_allowed`` is false.

This is a self-assessment scaffold, NOT a vendor comparison claim.
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
DEFAULT_RUNS_INDEX = ROOT / "docs" / "benchmarks" / "runs" / "index.json"
DEFAULT_OUTPUT_DIR = DEFAULT_GENERATED_DIR

ATTACK_COVERAGE_FILE = "attack_coverage_matrix.json"
FP_SEVERITY_FILE = "fp_severity_decision_matrix.json"
ROADMAP_SCORECARD_FILE = "validation_roadmap_scorecard.json"

WAVE1_HINT = (
    "Run the Wave 1 tools first: "
    "`python tools/detection_validation/attack_coverage_matrix.py` and "
    "`python tools/detection_validation/fp_severity_decision_matrix.py`."
)

RUN_LEVEL_CLAIM_BOUNDARY = (
    "Self-assessed offline scorecard; not a third-party-validated vendor "
    "comparison. Every dimension is marked calculated (numeric offline evidence "
    "exists) or pending_live (requires a live endpoint or an independent lab). "
    "external_claim_allowed is false."
)

# Aspirational mapping to external frameworks. This labels what each dimension
# corresponds to conceptually. It does NOT imply participation or submission.
COMPARATOR_FRAMEWORK_MAPPING = {
    "technique_coverage": "MITRE ATT&CK Evaluations (detection breadth per technique)",
    "evidence_depth": "MITRE ATT&CK Evaluations (detection/telemetry/analytic depth)",
    "false_positive_noise_handling": "AV-Comparatives False Alarm Test",
    "true_positive_retention": "AV-Comparatives Real-World Protection (no protection regression)",
    "detection_latency": "SE Labs / MITRE Evals (time-to-detect)",
    "independent_validation": "MITRE ATT&CK Evals / AV-Comparatives / SE Labs (third-party submission)",
    "ml_classifier_quality": "EMBER / SOREL-20M (ML malware classifier benchmark)",
}

COMPARATOR_FRAMEWORK_MAPPING_NOTE = (
    "Aspirational mapping only. It describes the external framework each "
    "dimension conceptually corresponds to. It is NOT a claim of participation, "
    "submission, or third-party validation."
)


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


def load_required_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(
            f"error: required upstream artifact not found: "
            f"{path.relative_to(ROOT) if path.is_absolute() and ROOT in path.parents else path}\n{WAVE1_HINT}"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: could not read upstream artifact {path}: {exc}\n{WAVE1_HINT}")
    if not isinstance(data, dict):
        raise SystemExit(f"error: upstream artifact {path} is not a JSON object.\n{WAVE1_HINT}")
    return data


def load_optional_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def safe_rate(numerator: float, denominator: float) -> float | None:
    if not denominator:
        return None
    return round(numerator / denominator, 6)


def technique_coverage_dimension(coverage: dict[str, Any], source: str) -> dict[str, Any]:
    summary = coverage.get("summary") or {}
    status_counts = summary.get("evidence_status_counts") or {}
    total = int(summary.get("total_techniques") or 0)
    live = int(status_counts.get("live") or 0)
    replay = int(status_counts.get("replay") or 0)
    fixture = int(status_counts.get("fixture") or 0)
    none = int(status_counts.get("none") or 0)
    runtime_evidence = live + replay + fixture
    runtime_rate = safe_rate(runtime_evidence, total)
    platform_counts = summary.get("platform_technique_counts") or {}
    return {
        "id": "technique_coverage",
        "title": "Technique coverage (detection breadth)",
        "framework_analog": COMPARATOR_FRAMEWORK_MAPPING["technique_coverage"],
        "status": "calculated",
        "metrics": {
            "total_techniques": total,
            "techniques_with_runtime_evidence": runtime_evidence,
            "runtime_evidence_rate": runtime_rate,
            "techniques_rule_content_only": none,
            "rule_content_only_rate": safe_rate(none, total),
            "cross_platform_techniques": int(summary.get("cross_platform_techniques") or 0),
            "platform_technique_counts": {k: int(v) for k, v in sorted(platform_counts.items())},
        },
        "source": source,
        "claim_boundary": (
            "Calculated offline from sigma rule content plus linked evidence. "
            "Coverage is not proven detection for techniques marked `none` "
            "(rule-content-only, no runtime evidence). Runtime-evidence rate "
            f"({runtime_evidence}/{total}) reflects techniques with at least live/replay/fixture "
            "evidence; full breadth proof is pending_live."
        ),
    }


def evidence_depth_dimension(coverage: dict[str, Any], source: str) -> dict[str, Any]:
    summary = coverage.get("summary") or {}
    status_counts = summary.get("evidence_status_counts") or {}
    total = int(summary.get("total_techniques") or 0)
    live = int(status_counts.get("live") or 0)
    replay = int(status_counts.get("replay") or 0)
    fixture = int(status_counts.get("fixture") or 0)
    none = int(status_counts.get("none") or 0)
    return {
        "id": "evidence_depth",
        "title": "Evidence depth (per-technique strongest evidence)",
        "framework_analog": COMPARATOR_FRAMEWORK_MAPPING["evidence_depth"],
        "status": "calculated",
        "metrics": {
            "total_techniques": total,
            "live": live,
            "replay": replay,
            "fixture": fixture,
            "none": none,
            "live_rate": safe_rate(live, total),
        },
        "source": source,
        "claim_boundary": (
            "Calculated offline. Counts techniques by strongest linked evidence tier "
            "(live > replay > fixture > none). Live tier is the only tier backed by "
            "endpoint runs; replay/fixture/none tiers are weaker and the `none` tier "
            "has no runtime evidence at all."
        ),
    }


def fp_noise_dimension(fp: dict[str, Any], source: str) -> dict[str, Any]:
    aggregate = fp.get("aggregate") or {}
    return {
        "id": "false_positive_noise_handling",
        "title": "False-positive / noise handling",
        "framework_analog": COMPARATOR_FRAMEWORK_MAPPING["false_positive_noise_handling"],
        "status": "calculated",
        "metrics": {
            "classifier_rules_total": int(aggregate.get("classifier_rules_total") or 0),
            "classifier_reduce_severity_rules": int(aggregate.get("classifier_reduce_severity_rules") or 0),
            "classifier_suppress_rules": int(aggregate.get("classifier_suppress_rules") or 0),
            "fp_downgrade_count": int(aggregate.get("fp_downgrade_count") or 0),
            "fixture_scenarios_total": int(aggregate.get("fixture_scenarios_total") or 0),
            "fixture_downgrade_scenarios": int(aggregate.get("fixture_downgrade_scenarios") or 0),
            "fixture_coverage_rate": aggregate.get("fixture_coverage_rate"),
            "classifier_reasons_without_fixture": int(aggregate.get("classifier_reasons_without_fixture") or 0),
            "uncovered_fp_reason_count": len(aggregate.get("uncovered_fp_reasons") or []),
        },
        "source": source,
        "claim_boundary": (
            "Calculated at fixture scale only. Maps conceptually to the "
            "AV-Comparatives False Alarm Test but is NOT a measured false-positive "
            "rate. There is no large benign corpus run; true FPR is pending_live. "
            f"{int(aggregate.get('classifier_reasons_without_fixture') or 0)} classifier "
            "reasons still lack a fixture scenario."
        ),
    }


def tp_retention_dimension(fp: dict[str, Any], source: str) -> dict[str, Any]:
    aggregate = fp.get("aggregate") or {}
    return {
        "id": "true_positive_retention",
        "title": "True-positive retention (downgrades never mask attacks)",
        "framework_analog": COMPARATOR_FRAMEWORK_MAPPING["true_positive_retention"],
        "status": "calculated",
        "metrics": {
            "tp_retention_count": int(aggregate.get("tp_retention_count") or 0),
            "tp_retention_test_total": int(aggregate.get("tp_retention_test_total") or 0),
            "tp_retention_rate": aggregate.get("tp_retention_rate"),
            "fixture_retain_critical_scenarios": int(aggregate.get("fixture_retain_critical_scenarios") or 0),
        },
        "source": source,
        "claim_boundary": (
            "Calculated offline. This is the strongest defensible number: a "
            "fixture-contract proof that the false-positive downgrade rules never "
            "mask the retained-critical attack scenarios. It is a contract proof, "
            "not a live production guarantee."
        ),
    }


def latency_dimension(run_signal: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "id": "detection_latency",
        "title": "Detection latency (time-to-detect)",
        "framework_analog": COMPARATOR_FRAMEWORK_MAPPING["detection_latency"],
        "status": "pending_live",
        "metrics": {
            "per_detection_latency_available": False,
            "run_level_signal": run_signal,
        },
        "source": source,
        "claim_boundary": (
            "pending_live. Run artifacts record run wall-clock (started_at / "
            "finished_at) but NOT per-detection time-to-detect, and transport "
            "instability on the lab host makes reliable latency capture impossible "
            "today. A true latency metric requires stable live-endpoint detection "
            "timestamping. No latency number is invented here."
        ),
    }


def independent_validation_dimension() -> dict[str, Any]:
    return {
        "id": "independent_validation",
        "title": "Independent / third-party validation",
        "framework_analog": COMPARATOR_FRAMEWORK_MAPPING["independent_validation"],
        "status": "pending_live",
        "metrics": {
            "mitre_attack_evals_submission": False,
            "av_comparatives_submission": False,
            "se_labs_submission": False,
        },
        "source": "n/a (no third-party submission)",
        "claim_boundary": (
            "pending_live. Tamandua has not been submitted to MITRE ATT&CK "
            "Evaluations, AV-Comparatives, or SE Labs. This row is included "
            "explicitly so the gap is visible. No external validation exists."
        ),
    }


def run_level_signal(runs_index: dict[str, Any] | None, roadmap: dict[str, Any] | None) -> dict[str, Any]:
    signal: dict[str, Any] = {
        "runs_index_present": runs_index is not None,
        "roadmap_scorecard_present": roadmap is not None,
    }
    if runs_index:
        runs = runs_index.get("runs") or []
        gate_passed = 0
        covered = 0
        tests = 0
        for run in runs:
            if not isinstance(run, dict):
                continue
            if (run.get("quality_gate") or {}).get("passed"):
                gate_passed += 1
            summary = run.get("summary") or {}
            covered += int(summary.get("covered") or 0)
            tests += int(summary.get("tests") or 0)
        signal["run_artifact_count"] = len(runs)
        signal["quality_gate_passed_count"] = gate_passed
        signal["aggregate_covered"] = covered
        signal["aggregate_tests"] = tests
        signal["aggregate_covered_rate"] = safe_rate(covered, tests)
    if roadmap:
        roadmaps = roadmap.get("roadmaps") or []
        status_counts: dict[str, int] = {}
        for entry in roadmaps:
            if isinstance(entry, dict):
                status = str(entry.get("status") or "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1
        signal["roadmap_status_counts"] = dict(sorted(status_counts.items()))
    return signal


def build_payload(
    coverage: dict[str, Any],
    fp: dict[str, Any],
    runs_index: dict[str, Any] | None,
    roadmap: dict[str, Any] | None,
    coverage_source: str,
    fp_source: str,
    runs_source: str,
    roadmap_source: str,
) -> dict[str, Any]:
    run_signal = run_level_signal(runs_index, roadmap)
    dimensions = [
        technique_coverage_dimension(coverage, coverage_source),
        evidence_depth_dimension(coverage, coverage_source),
        fp_noise_dimension(fp, fp_source),
        tp_retention_dimension(fp, fp_source),
        latency_dimension({"covered_rate": run_signal.get("aggregate_covered_rate"),
                           "quality_gate_passed_count": run_signal.get("quality_gate_passed_count"),
                           "run_artifact_count": run_signal.get("run_artifact_count")}, runs_source),
        independent_validation_dimension(),
    ]
    calculated = [d for d in dimensions if d["status"] == "calculated"]
    pending_live = [d for d in dimensions if d["status"] == "pending_live"]
    readiness_summary = {
        "total_dimensions": len(dimensions),
        "calculated": len(calculated),
        "pending_live": len(pending_live),
        "calculated_ids": sorted(d["id"] for d in calculated),
        "pending_live_ids": sorted(d["id"] for d in pending_live),
    }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "git": git_snapshot(),
        "external_claim_allowed": False,
        "claim_boundary": RUN_LEVEL_CLAIM_BOUNDARY,
        "source": {
            "attack_coverage_matrix": coverage_source,
            "fp_severity_decision_matrix": fp_source,
            "validation_roadmap_scorecard": roadmap_source if roadmap is not None else None,
            "runs_index": runs_source if runs_index is not None else None,
        },
        "run_level_signal": run_signal,
        "comparator_framework_mapping": COMPARATOR_FRAMEWORK_MAPPING,
        "comparator_framework_mapping_note": COMPARATOR_FRAMEWORK_MAPPING_NOTE,
        "dimensions": dimensions,
        "readiness_summary": readiness_summary,
    }


def metric_summary(dimension: dict[str, Any]) -> str:
    metrics = dimension.get("metrics") or {}
    did = dimension["id"]
    if did == "technique_coverage":
        return (
            f"{metrics.get('techniques_with_runtime_evidence')}/{metrics.get('total_techniques')} "
            f"runtime-evidence ({metrics.get('runtime_evidence_rate')}); "
            f"{metrics.get('techniques_rule_content_only')} rule-content-only"
        )
    if did == "evidence_depth":
        return (
            f"live={metrics.get('live')} replay={metrics.get('replay')} "
            f"fixture={metrics.get('fixture')} none={metrics.get('none')}"
        )
    if did == "false_positive_noise_handling":
        return (
            f"fp_downgrade_count={metrics.get('fp_downgrade_count')}; "
            f"classifier_rules={metrics.get('classifier_rules_total')}; "
            f"fixture_scenarios={metrics.get('fixture_scenarios_total')}"
        )
    if did == "true_positive_retention":
        return (
            f"tp_retention_rate={metrics.get('tp_retention_rate')} "
            f"({metrics.get('tp_retention_count')}/{metrics.get('tp_retention_test_total')})"
        )
    if did == "detection_latency":
        return "no per-detection latency captured"
    if did == "independent_validation":
        return "no submission"
    return "-"


def md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def render_markdown(payload: dict[str, Any]) -> str:
    readiness = payload["readiness_summary"]
    lines = [
        "# Comparative Benchmark Scorecard",
        "",
        "Status: generated (self-assessment)",
        "",
        "Synthesized from upstream offline artifacts by",
        "`tools/detection_validation/generate_comparative_scorecard.py`.",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Git commit: `{payload['git'].get('commit_short') or 'unknown'}`"
        + (" (dirty)" if payload["git"].get("dirty") else ""),
        "",
        "## Claim Boundary",
        "",
        "This is a **self-assessed offline scorecard**, NOT a third-party-validated",
        "vendor comparison. `external_claim_allowed: false` is enforced throughout.",
        "Each dimension is marked `calculated` (numeric offline evidence exists) or",
        "`pending_live` (requires a live endpoint or an independent lab).",
        "",
        f"> {payload['claim_boundary']}",
        "",
        "## Readiness",
        "",
        f"{readiness['calculated']} calculated / {readiness['pending_live']} pending_live "
        f"(of {readiness['total_dimensions']} dimensions).",
        "",
        "## Comparative Dimensions",
        "",
        "| Dimension | Framework analog | Status | Metric | Source | Claim boundary |",
        "|-----------|------------------|--------|--------|--------|----------------|",
    ]
    for dimension in payload["dimensions"]:
        lines.append(
            f"| {md_escape(dimension['title'])} "
            f"| {md_escape(dimension['framework_analog'])} "
            f"| `{dimension['status']}` "
            f"| {md_escape(metric_summary(dimension))} "
            f"| `{md_escape(str(dimension['source']))}` "
            f"| {md_escape(dimension['claim_boundary'])} |"
        )

    calculated = [d for d in payload["dimensions"] if d["status"] == "calculated"]
    pending = [d for d in payload["dimensions"] if d["status"] == "pending_live"]
    lines.extend(
        [
            "",
            "## What is exposable today vs pending",
            "",
            "**Exposable today (calculated offline):**",
            "",
        ]
    )
    for dimension in calculated:
        lines.append(f"- {dimension['title']}: {metric_summary(dimension)}")
    lines.extend(["", "**Pending live endpoint / independent lab:**", ""])
    for dimension in pending:
        lines.append(f"- {dimension['title']}: {metric_summary(dimension)}")

    lines.extend(
        [
            "",
            "## Comparator Framework Mapping",
            "",
            f"_{payload['comparator_framework_mapping_note']}_",
            "",
            "| Dimension | External framework analog |",
            "|-----------|---------------------------|",
        ]
    )
    for key, value in payload["comparator_framework_mapping"].items():
        lines.append(f"| `{key}` | {md_escape(value)} |")
    lines.append("")
    return "\n".join(lines)


def write_outputs(payload: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "comparative_benchmark_scorecard.json"
    md_path = output_dir / "comparative_benchmark_scorecard.md"
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(
        render_markdown(payload).rstrip() + "\n",
        encoding="utf-8",
    )
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", default=str(DEFAULT_GENERATED_DIR))
    parser.add_argument("--runs-index", default=str(DEFAULT_RUNS_INDEX))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    generated_dir = Path(args.generated_dir)
    runs_index_path = Path(args.runs_index)
    output_dir = Path(args.output_dir)

    coverage_path = generated_dir / ATTACK_COVERAGE_FILE
    fp_path = generated_dir / FP_SEVERITY_FILE
    roadmap_path = generated_dir / ROADMAP_SCORECARD_FILE

    coverage = load_required_json(coverage_path)
    fp = load_required_json(fp_path)
    roadmap = load_optional_json(roadmap_path)
    runs_index = load_optional_json(runs_index_path)

    payload = build_payload(
        coverage=coverage,
        fp=fp,
        runs_index=runs_index,
        roadmap=roadmap,
        coverage_source=rel(coverage_path),
        fp_source=rel(fp_path),
        runs_source=rel(runs_index_path),
        roadmap_source=rel(roadmap_path),
    )
    json_path, md_path = write_outputs(payload, output_dir)
    readiness = payload["readiness_summary"]
    print(
        f"wrote {json_path} and {md_path} "
        f"({readiness['calculated']} calculated / {readiness['pending_live']} pending_live)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
