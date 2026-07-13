#!/usr/bin/env python3
"""Gate benchmark artifacts on alert evidence-quality provenance.

The gate is intentionally narrow: it scans JSON artifacts for Tamandua alert
evidence-quality summaries and rejects any alert/result that is marked
``synthetic``, ``missing``, ``malformed``, non-benchmark-eligible, or carrying a
non-boolean benchmark eligibility flag. Reports without evidence-quality
annotations are reported as not-applicable unless ``--require-evidence-quality``
is set.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


BLOCKED_QUALITIES = {"synthetic", "missing", "malformed"}


@dataclass(frozen=True)
class Finding:
    path: str
    location: str
    quality: str
    label: str
    summary: str


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def evidence_quality_from(value: dict[str, Any]) -> dict[str, Any] | None:
    has_explicit_quality = "evidence_quality" in value or "evidenceQuality" in value
    quality = value.get("evidence_quality") or value.get("evidenceQuality")
    if not isinstance(quality, dict):
        return {"quality": "malformed", "benchmark_eligible": False} if has_explicit_quality else None

    has_quality = bool(quality.get("quality"))
    has_benchmark_flag = "benchmark_eligible" in quality or "benchmarkEligible" in quality
    return quality if has_quality or has_benchmark_flag else {"quality": "malformed", "benchmark_eligible": False}


def benchmark_eligible_value(quality: dict[str, Any]) -> tuple[Any, bool]:
    if "benchmark_eligible" in quality:
        value = quality.get("benchmark_eligible")
    elif "benchmarkEligible" in quality:
        value = quality.get("benchmarkEligible")
    else:
        return None, False

    return value, isinstance(value, bool)


def iter_evidence_quality(value: Any, location: str = "$") -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        quality = evidence_quality_from(value)
        if quality is not None and not is_aggregate_score_location(location):
            yield location, quality

        for key, child in value.items():
            yield from iter_evidence_quality(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_evidence_quality(child, f"{location}[{index}]")


def is_aggregate_score_location(location: str) -> bool:
    return location == "$.score" or location.endswith(".score")


def evaluate(path: Path, *, require_evidence_quality: bool = False) -> dict[str, Any]:
    payload = load_json(path)
    scanned = 0
    findings: list[Finding] = []

    for location, quality in iter_evidence_quality(payload):
        scanned += 1
        quality_value = str(quality.get("quality") or "").strip().lower()
        if not quality_value:
            quality_value = "malformed"
        benchmark_eligible, valid_benchmark_flag = benchmark_eligible_value(quality)
        malformed_flag = not valid_benchmark_flag and (
            "benchmark_eligible" in quality or "benchmarkEligible" in quality
        )
        if quality_value in BLOCKED_QUALITIES or benchmark_eligible is False or malformed_flag:
            if malformed_flag and quality_value not in BLOCKED_QUALITIES:
                quality_value = "malformed"
            findings.append(
                Finding(
                    path=str(path),
                    location=location,
                    quality=quality_value,
                    label=str(quality.get("label") or quality_value),
                    summary=str(quality.get("summary") or ""),
                )
            )

    missing_required = require_evidence_quality and scanned == 0

    return {
        "path": str(path),
        "status": "fail" if findings or missing_required else "pass",
        "scanned_evidence_quality": scanned,
        "require_evidence_quality": require_evidence_quality,
        "missing_required_evidence_quality": missing_required,
        "blocked_qualities": sorted(BLOCKED_QUALITIES),
        "findings": [finding.__dict__ for finding in findings],
    }


def build_report(paths: list[Path], *, require_evidence_quality: bool = False) -> dict[str, Any]:
    results = [
        evaluate(path, require_evidence_quality=require_evidence_quality)
        for path in paths
    ]
    failed = [result for result in results if result["status"] == "fail"]

    return {
        "schema_version": 1,
        "kind": "AlertEvidenceQualityGate",
        "status": "fail" if failed else "pass",
        "checked_artifacts": len(results),
        "failed_artifacts": len(failed),
        "claim_boundary": (
            "Rejects benchmark artifacts containing alert evidence_quality values "
            "synthetic, missing, or malformed, plus any alert evidence marked "
            "benchmark_eligible=false or carrying a non-boolean benchmark eligibility flag. "
            "It does not prove production alert quality."
        ),
        "results": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path, help="JSON benchmark artifacts to scan")
    parser.add_argument(
        "--require-evidence-quality",
        action="store_true",
        help="Fail artifacts that contain no evidence_quality/evidenceQuality annotations",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON report output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report = build_report(args.artifacts, require_evidence_quality=args.require_evidence_quality)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))

    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
