"""Merge completed Tamandua validation slice reports into one run artifact."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

from tamandua_detection_validation import (
    benchmark_scorecard,
    evaluate_gates,
    summarize_tests,
    upstream_readiness_checklist,
    write_report,
)


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def format_timestamp(value: dt.datetime | None, fallback: str | None = None) -> str:
    if value is None:
        return fallback or dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_report(path: Path) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise SystemExit(f"{path}: expected JSON object")
    if not isinstance(report.get("tests"), list):
        raise SystemExit(f"{path}: expected report.tests list")
    return report


def gate_args(args: argparse.Namespace, base_report: dict[str, Any]) -> argparse.Namespace:
    thresholds = (base_report.get("quality_gate") or {}).get("thresholds") or {}
    return argparse.Namespace(
        benchmark_lane=args.benchmark_lane
        or base_report.get("benchmark_lane")
        or thresholds.get("benchmark_lane")
        or "enterprise-eval",
        fail_on_missed=not args.allow_missed
        if args.allow_missed is not None
        else bool(thresholds.get("fail_on_missed", True)),
        fail_on_partial=not args.allow_partial
        if args.allow_partial is not None
        else bool(thresholds.get("fail_on_partial", True)),
        max_driver_channel_drops=args.max_driver_channel_drops
        if args.max_driver_channel_drops is not None
        else int(thresholds.get("max_driver_channel_drops", 0)),
        max_driver_kernel_drops=args.max_driver_kernel_drops
        if args.max_driver_kernel_drops is not None
        else int(thresholds.get("max_driver_kernel_drops", 0)),
        max_unexpected_high_critical=args.max_unexpected_high_critical
        if args.max_unexpected_high_critical is not None
        else int(thresholds.get("max_unexpected_high_critical", 0)),
        max_unknown_source=args.max_unknown_source
        if args.max_unknown_source is not None
        else int(thresholds.get("max_unknown_source", 0)),
        require_upstream=args.require_upstream
        if args.require_upstream is not None
        else bool(thresholds.get("require_upstream", False)),
    )


def merge_reports(paths: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    reports = [load_report(path) for path in paths]
    if not reports:
        raise SystemExit("at least one report is required")

    base = dict(reports[0])
    tests: list[dict[str, Any]] = []
    selected: list[str] = []
    seen_ids: set[str] = set()
    duplicate_ids: list[str] = []

    for report in reports:
        profile_id = (report.get("profile") or {}).get("profile_id")
        base_profile_id = args.profile_id or (base.get("profile") or {}).get("profile_id")
        if profile_id != base_profile_id and not args.profile_id:
            raise SystemExit(f"mixed profile_id values are not supported: {profile_id!r}")
        for test in report.get("tests") or []:
            test_id = str(test.get("id") or "")
            if test_id and test_id in seen_ids:
                duplicate_ids.append(test_id)
            if test_id:
                seen_ids.add(test_id)
            tests.append(test)
        selected.extend(str(item) for item in report.get("selected_tests") or [])

    if duplicate_ids and getattr(args, "dedupe_tests", None):
        tests = dedupe_tests(tests, args.dedupe_tests)
    elif duplicate_ids and not args.allow_duplicates:
        joined = ", ".join(sorted(set(duplicate_ids)))
        raise SystemExit(f"duplicate test ids in slice reports: {joined}")

    started_values = [parse_timestamp(report.get("started_at")) for report in reports]
    finished_values = [parse_timestamp(report.get("finished_at")) for report in reports]
    started_values = [value for value in started_values if value is not None]
    finished_values = [value for value in finished_values if value is not None]

    run_id = args.run_id or f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{(base.get('profile') or {}).get('profile_id', 'merged-validation')}-merged"
    base["run_id"] = run_id
    if args.profile_id:
        base.setdefault("profile", {})["profile_id"] = args.profile_id
    base["started_at"] = format_timestamp(min(started_values) if started_values else None, base.get("started_at"))
    base["finished_at"] = format_timestamp(max(finished_values) if finished_values else None, base.get("finished_at"))
    base["selected_tests"] = sorted(set(selected)) if selected else [test.get("id") for test in tests]
    base["tests"] = tests
    base["merge"] = {
        "source_run_ids": [report.get("run_id") for report in reports],
        "source_paths": [str(path) for path in paths],
        "source_benchmark_lanes": sorted(
            {
                str(report.get("benchmark_lane") or "")
                for report in reports
                if str(report.get("benchmark_lane") or "")
            }
        ),
        "source_count": len(reports),
    }
    if "diagnostic-only" in base["merge"]["source_benchmark_lanes"]:
        base["benchmark_lane"] = "diagnostic-only"
    base["summary"] = summarize_tests(tests)
    base["quality_gate"] = evaluate_gates(base, gate_args(args, base))
    base["scorecard"] = benchmark_scorecard(base)
    base["upstream_readiness"] = upstream_readiness_checklist(base)
    return base


def dedupe_tests(tests: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    if mode != "prefer-covered":
        raise SystemExit(f"unsupported dedupe mode: {mode}")
    selected: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for test in tests:
        test_id = str(test.get("id") or "")
        if not test_id:
            order.append(f"__index_{len(order)}")
            selected[order[-1]] = test
            continue
        if test_id not in selected:
            order.append(test_id)
            selected[test_id] = test
            continue
        previous = selected[test_id]
        previous_covered = previous.get("status") == "covered"
        current_covered = test.get("status") == "covered"
        if current_covered or not previous_covered:
            selected[test_id] = test
    return [selected[test_id] for test_id in order]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--profile-id")
    parser.add_argument("--benchmark-lane")
    parser.add_argument("--allow-duplicates", action="store_true")
    parser.add_argument("--dedupe-tests", choices=["prefer-covered"])
    parser.add_argument("--allow-missed", action="store_true", default=None)
    parser.add_argument("--allow-partial", action="store_true", default=None)
    parser.add_argument("--require-upstream", action="store_true", default=None)
    parser.add_argument("--max-driver-channel-drops", type=int)
    parser.add_argument("--max-driver-kernel-drops", type=int)
    parser.add_argument("--max-unexpected-high-critical", type=int)
    parser.add_argument("--max-unknown-source", type=int)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report = merge_reports(args.reports, args)
    json_path, md_path, comparison_path = write_report(report, args.output_dir)
    print(f"merged_reports={len(args.reports)} json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if (report.get("quality_gate") or {}).get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
