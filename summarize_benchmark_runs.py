#!/usr/bin/env python3
"""Summarize detection validation runs into a review document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_PROFILES = [
    "windows-caldera-smoke",
    "windows-atomic-upstream-smoke",
    "windows-enterprise-eval-safe-v1",
    "windows-roadmap-p0-safe-expansion",
    "windows-roadmap-300-batch-01",
    "windows-roadmap-300-batch-02",
    "windows-roadmap-300-batch-03",
    "windows-roadmap-300-batch-04",
    "windows-roadmap-300-batch-05",
    "windows-roadmap-300-batch-06",
    "windows-roadmap-p0-existing-sensor-contract",
    "windows-roadmap-p0-existing-benign-baseline",
    "windows-roadmap-p0-existing-driver-contract",
    "windows-false-positive-regression-noise",
    "linux-roadmap-p0-sensor-contract-smoke",
    "macos-roadmap-p0-sensor-contract-smoke",
]

CLAIM_VALID_LANES = {
    "windows-atomic-upstream-smoke": "atomic-upstream",
    "windows-caldera-smoke": "caldera-upstream",
}


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def run_json_paths(runs_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for path in runs_dir.glob("*.json"):
        if path.name == "index.json" or path.name.endswith(".comparison.json"):
            continue
        paths.append(path)
    return sorted(paths)


def profile_id(report: dict[str, Any]) -> str:
    return str(report.get("profile_id") or report.get("profile", {}).get("profile_id") or "unknown")


def started_at(report: dict[str, Any]) -> str:
    return str(report.get("started_at") or "")


def quality_gate(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("quality_gate") or {}


def summary(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("summary") or {}


def scorecard(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("scorecard") or {}


def latest_by_profile(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for report in reports:
        pid = profile_id(report)
        current = latest.get(pid)
        if current is None:
            latest[pid] = report
            continue

        current_executed = bool(current.get("execute"))
        report_executed = bool(report.get("execute"))
        current_tests = int(summary(current).get("tests") or 0)
        report_tests = int(summary(report).get("tests") or 0)
        if report_executed and not current_executed:
            latest[pid] = report
        elif report_executed == current_executed and report_tests > current_tests:
            latest[pid] = report
        elif (
            report_executed == current_executed
            and report_tests == current_tests
            and started_at(report) > started_at(current)
        ):
            latest[pid] = report
    return latest


def best_passing_by_profile(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for report in reports:
        if not (quality_gate(report).get("passed") and report.get("execute")):
            continue

        pid = profile_id(report)
        current = best.get(pid)
        if current is None:
            best[pid] = report
            continue

        report_score = int(scorecard(report).get("maturity_score") or 0)
        current_score = int(scorecard(current).get("maturity_score") or 0)
        report_tests = int(summary(report).get("covered") or 0)
        current_tests = int(summary(current).get("covered") or 0)

        if (report_score, report_tests, started_at(report)) > (current_score, current_tests, started_at(current)):
            best[pid] = report
    return best


def latest_claim_valid_by_profile(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for report in reports:
        pid = profile_id(report)
        lane = CLAIM_VALID_LANES.get(pid)
        if not lane or report.get("benchmark_lane") != lane or not report.get("execute"):
            continue

        current = selected.get(pid)
        if current is None:
            selected[pid] = report
            continue
        if started_at(report) > started_at(current):
            selected[pid] = report
    return selected


def gap_text(score: dict[str, Any]) -> str:
    parts: list[str] = []
    mapping = [
        ("missing_expected_telemetry", "telemetry"),
        ("missing_expected_detections", "detections"),
        ("missing_expected_alerts", "alerts"),
        ("missing_expected_fields", "fields"),
        ("missing_expected_driver_raw_event_types", "driver_raw"),
        ("missing_expected_correlations", "correlations"),
    ]
    for key, label in mapping:
        values = score.get(key) or []
        if values:
            parts.append(f"{label}: {', '.join(str(value) for value in values)}")
    return "; ".join(parts) if parts else "-"


def covered_test_ids(reports: list[dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for report in reports:
        for item in report.get("tests") or []:
            score = item.get("score") or {}
            status = str(score.get("status") or item.get("status") or "")
            if status == "covered":
                test_id = str(item.get("id") or "")
                if test_id:
                    ids.add(test_id)
    return ids


def gap_rows(report: dict[str, Any], globally_covered: set[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in report.get("tests") or []:
        score = item.get("score") or {}
        status = str(score.get("status") or item.get("status") or "")
        test_id = str(item.get("id") or "")
        gaps = gap_text(score)
        if status in {"missed", "execution_failed"} and test_id in globally_covered:
            continue
        if status in {"partial", "missed", "execution_failed"} or gaps != "-":
            rows.append(
                {
                    "id": test_id,
                    "name": str(item.get("name") or ""),
                    "status": status,
                    "gaps": gaps,
                }
            )
    return rows


def row_for_profile(report: dict[str, Any]) -> str:
    summ = summary(report)
    gate = quality_gate(report)
    score = scorecard(report)
    run_id = str(report.get("run_id") or "")
    score_value = score.get("maturity_score", "-")
    gate_value = "pass" if gate.get("passed") else "fail"
    if report.get("execute") is False:
        gate_value = f"{gate_value} (dry-run)"
    return (
        f"| `{profile_id(report)}` | `{run_id}` | `{report.get('benchmark_lane', '-')}` | "
        f"`{score_value}` | `{gate_value}` | `{summ.get('tests', 0)}` | "
        f"`{summ.get('covered', 0)}` | `{summ.get('partial', 0)}` | `{summ.get('missed', 0)}` | "
        f"`{summ.get('planned', 0)}` | `{summ.get('upstream_backed_tests', 0)}` | "
        f"`{summ.get('fallback_command_tests', 0)}` |"
    )


def render_report(reports: list[dict[str, Any]], selected_profiles: list[str]) -> str:
    latest = latest_by_profile(reports)
    best_passing = best_passing_by_profile(reports)
    claim_valid = latest_claim_valid_by_profile(reports)
    globally_covered = covered_test_ids(reports)
    lines: list[str] = [
        "# Detection Benchmark Results Review",
        "",
        "Status: generated review",
        "",
        "This file is generated from `docs/benchmarks/runs/*.json` by",
        "`tools/detection_validation/summarize_benchmark_runs.py`.",
        "",
        "## Latest Selected Profiles",
        "",
        "| Profile | Run | Lane | Score | Gate | Tests | Covered | Partial | Missed | Planned | Upstream | Fallback |",
        "|---------|-----|------|-------|------|-------|---------|---------|--------|---------|----------|----------|",
    ]

    for pid in selected_profiles:
        report = latest.get(pid)
        if report:
            lines.append(row_for_profile(report))
        else:
            lines.append(f"| `{pid}` | `missing` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` | `0` |")

    lines.extend(
        [
            "",
            "## Best Passing Evidence",
            "",
            "This table can include narrower passing slices. Use the latest run above for the current full-profile gate.",
            "",
            "| Profile | Run | Lane | Score | Gate | Tests | Covered | Partial | Missed | Planned | Upstream | Fallback |",
            "|---------|-----|------|-------|------|-------|---------|---------|--------|---------|----------|----------|",
        ]
    )

    for pid in selected_profiles:
        report = best_passing.get(pid)
        if report:
            lines.append(row_for_profile(report))
        else:
            lines.append(f"| `{pid}` | `none` | `-` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` | `0` |")

    lines.extend(
        [
            "",
            "## Latest Claim-Valid Upstream Evidence",
            "",
            "This table ignores fallback or deterministic reruns that reuse an upstream profile id.",
            "",
            "| Profile | Run | Lane | Score | Gate | Tests | Covered | Partial | Missed | Planned | Upstream | Fallback |",
            "|---------|-----|------|-------|------|-------|---------|---------|--------|---------|----------|----------|",
        ]
    )
    for pid in CLAIM_VALID_LANES:
        report = claim_valid.get(pid)
        if report:
            lines.append(row_for_profile(report))
        else:
            lines.append(f"| `{pid}` | `missing` | `{CLAIM_VALID_LANES[pid]}` | `-` | `-` | `0` | `0` | `0` | `0` | `0` | `0` | `0` |")

    lines.extend(["", "## Open Gaps", ""])
    any_gap = False
    for pid in selected_profiles:
        report = latest.get(pid)
        if not report:
            continue
        gaps = gap_rows(report, globally_covered)
        if not gaps:
            continue
        any_gap = True
        lines.extend(
            [
                f"### {pid}",
                "",
                "| Test | Status | Gap |",
                "|------|--------|-----|",
            ]
        )
        for gap in gaps:
            label = f"{gap['id']} {gap['name']}".strip()
            lines.append(f"| `{label}` | `{gap['status']}` | `{gap['gaps']}` |")
        lines.append("")

    if not any_gap:
        lines.append("No open gaps in the selected latest runs.")
        lines.append("")

    lines.extend(
        [
            "## Current Interpretation",
            "",
            "- CALDERA smoke is claimable only for the selected upstream smoke profile when the latest run remains green.",
            "- Atomic upstream smoke remains engineering validation until all partial tests and gate failures are closed.",
            "- Windows P0 safe expansion is closed by accumulated deterministic evidence: the full `31` profile ran, and targeted reruns closed the original execution failures.",
            "- Windows 300 now has deterministic execution evidence across six 50-scenario batches; the first pass covered `296/300`, and targeted reruns closed the four QGA timeout scenarios.",
            "- Windows 300 deterministic coverage is not an Atomic/CALDERA upstream claim and should remain profile-scoped in public language.",
            "- Windows existing P0 benign baseline now has a server-backed passing batch; sensor mapped batch, driver mapped batch, and Linux/macOS smoke still need full passing execution before stronger claims.",
            "- Enterprise evaluation remains a product-readiness lane, not a vendor comparison claim unless upstream proof exists.",
            "",
            "## Next Commands",
            "",
            "```powershell",
            "$env:TAMANDUA_PROXMOX_HOST = \"192.168.12.149\"",
            "$env:TAMANDUA_PROXMOX_USER = \"root\"",
            "$env:TAMANDUA_PROXMOX_PASSWORD = \"<load from approved secret store>\"",
            "$env:TAMANDUA_RESOLVE_AGENT_BY_HOSTNAME = \"1\"",
            "$env:TAMANDUA_AGENT_HOSTNAME = \"WIN-TEMPLATE\"",
            "python tools\\detection_validation\\summarize_benchmark_runs.py --output docs\\benchmarks\\BENCHMARK_RESULTS_REVIEW.md",
            "python tools\\detection_validation\\tamandua_detection_validation.py --execute --vmid 1521 --profile tools\\detection_validation\\profiles\\windows_atomic_upstream_smoke.json --benchmark-lane atomic-upstream --require-upstream --fail-on-gate",
            "python tools\\detection_validation\\tamandua_detection_validation.py --execute --vmid 1521 --profile tools\\detection_validation\\profiles\\windows_roadmap_p0_safe_expansion.json --benchmark-lane enterprise-eval --baseline-seconds 60 --fail-on-gate",
            "python tools\\detection_validation\\tamandua_detection_validation.py --execute --vmid 1521 --profile tools\\detection_validation\\profiles\\windows_roadmap_p0_existing_sensor_contract.json --benchmark-lane enterprise-eval --baseline-seconds 60 --fail-on-gate",
            "python tools\\detection_validation\\tamandua_detection_validation.py --execute --vmid 1521 --profile tools\\detection_validation\\profiles\\windows_roadmap_p0_existing_benign_baseline.json --benchmark-lane enterprise-eval --baseline-seconds 60 --fail-on-gate",
            "python tools\\detection_validation\\tamandua_detection_validation.py --execute --vmid 1521 --profile tools\\detection_validation\\profiles\\windows_roadmap_p0_existing_driver_contract.json --benchmark-lane enterprise-eval --baseline-seconds 60 --fail-on-gate",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", default="docs/benchmarks/runs")
    parser.add_argument("--output", default=None)
    parser.add_argument("--profile", action="append", dest="profiles")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runs_dir = Path(args.runs_dir)
    reports = [
        report
        for path in run_json_paths(runs_dir)
        if isinstance(report := load_json(path), dict)
    ]
    profiles = args.profiles or DEFAULT_PROFILES
    rendered = render_report(reports, profiles)
    if args.output:
        Path(args.output).write_text(rendered.rstrip() + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
