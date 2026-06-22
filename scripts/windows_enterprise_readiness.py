#!/usr/bin/env python3
"""Build a Windows enterprise-readiness scorecard from benchmark artifacts.

This scorecard is intentionally conservative. It rewards reproducible evidence
and keeps deterministic roadmap coverage separate from upstream Atomic/CALDERA,
response, release, and reliability maturity.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
OUTPUT = ROOT / "docs" / "benchmarks" / "WINDOWS_ENTERPRISE_READINESS_SCORECARD.md"


WINDOWS_300_BATCHES = [f"windows-roadmap-300-batch-{index:02d}" for index in range(1, 7)]


@dataclass
class Dimension:
    name: str
    score: float
    evidence: list[str]
    blockers: list[str]
    next_actions: list[str]


def load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_reports(runs_dir: Path) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for path in sorted(runs_dir.glob("*.json")):
        if path.name == "index.json" or path.name.endswith(".comparison.json"):
            continue
        report = load_json(path)
        if isinstance(report, dict) and (report.get("profile_id") or report.get("profile")):
            reports.append(report)
    return reports


def profile_id(report: dict[str, Any]) -> str:
    profile = report.get("profile") or {}
    return str(report.get("profile_id") or profile.get("profile_id") or "unknown")


def run_id(report: dict[str, Any]) -> str:
    return str(report.get("run_id") or "")


def summary(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("summary") or {}


def scorecard(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("scorecard") or {}


def quality_gate(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("quality_gate") or {}


def started_at(report: dict[str, Any]) -> str:
    return str(report.get("started_at") or "")


def all_tests(report: dict[str, Any]) -> list[dict[str, Any]]:
    return list(report.get("tests") or [])


def report_score(report: dict[str, Any]) -> int:
    return int(scorecard(report).get("maturity_score") or 0)


def is_executed(report: dict[str, Any]) -> bool:
    return bool(report.get("execute"))


def latest_by_profile(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for report in reports:
        pid = profile_id(report)
        current = latest.get(pid)
        if current is None:
            latest[pid] = report
            continue

        report_tests = int(summary(report).get("tests") or 0)
        current_tests = int(summary(current).get("tests") or 0)
        if is_executed(report) and not is_executed(current):
            latest[pid] = report
        elif is_executed(report) == is_executed(current) and report_tests > current_tests:
            latest[pid] = report
        elif (
            is_executed(report) == is_executed(current)
            and report_tests == current_tests
            and started_at(report) > started_at(current)
        ):
            latest[pid] = report
    return latest


def latest_by_profile_and_lane(reports: list[dict[str, Any]], lane: str) -> dict[str, dict[str, Any]]:
    return latest_by_profile([report for report in reports if report.get("benchmark_lane") == lane])


def covered_test_ids(reports: list[dict[str, Any]]) -> set[str]:
    covered: set[str] = set()
    for report in reports:
        for item in all_tests(report):
            status = str((item.get("score") or {}).get("status") or item.get("status") or "")
            if status == "covered" and item.get("id"):
                covered.add(str(item["id"]))
    return covered


def full_profile_gaps(report: dict[str, Any], globally_covered: set[str]) -> list[str]:
    gaps: list[str] = []
    for item in all_tests(report):
        score = item.get("score") or {}
        status = str(score.get("status") or item.get("status") or "")
        test_id = str(item.get("id") or "")
        if status in {"missed", "execution_failed"} and test_id in globally_covered:
            continue
        if status in {"partial", "missed", "execution_failed"}:
            gaps.append(f"{test_id}: {status}")
            continue
        for key in [
            "missing_expected_telemetry",
            "missing_expected_detections",
            "missing_expected_alerts",
            "missing_expected_fields",
            "missing_expected_driver_raw_event_types",
            "missing_expected_correlations",
        ]:
            values = score.get(key) or []
            if values:
                gaps.append(f"{test_id}: {key}={','.join(str(value) for value in values)}")
    return gaps


def windows_300_dimension(reports: list[dict[str, Any]], latest: dict[str, dict[str, Any]]) -> Dimension:
    globally_covered = covered_test_ids(reports)
    batch_reports = [latest[pid] for pid in WINDOWS_300_BATCHES if pid in latest]
    full_ids: set[str] = set()
    covered_ids: set[str] = set()
    open_gaps: list[str] = []
    driver_drops = 0
    unknown = 0
    noisy = 0

    for report in batch_reports:
        for item in all_tests(report):
            test_id = str(item.get("id") or "")
            if not test_id:
                continue
            full_ids.add(test_id)
            if test_id in globally_covered:
                covered_ids.add(test_id)
        open_gaps.extend(full_profile_gaps(report, globally_covered))
        summ = summary(report)
        driver_drops += int(summ.get("driver_channel_drops") or 0) + int(summ.get("driver_kernel_drops") or 0)
        unknown += int(summ.get("unknown_source_events") or 0)
        noisy += int(summ.get("unexpected_high_or_critical_alerts") or 0)

    coverage_rate = len(covered_ids) / 300 if len(full_ids) >= 300 else len(covered_ids) / 300
    score = min(10.0, 10.0 * coverage_rate)
    if open_gaps:
        score -= 0.5
    if driver_drops or unknown or noisy:
        score -= 1.0

    return Dimension(
        "Windows 300 deterministic evidence",
        max(0.0, round(score, 1)),
        [
            f"Batch profiles present: {len(batch_reports)}/6.",
            f"Accumulated covered scenario ids: {len(covered_ids)}/300.",
            f"Open deterministic gaps after reruns: {len(open_gaps)}.",
            f"Driver drops={driver_drops}, unknown source events={unknown}, unexpected high/critical alerts={noisy}.",
            "Source: docs/benchmarks/WINDOWS_ROADMAP_300_EXECUTION_RESULTS.md.",
        ],
        open_gaps[:8],
        [
            "Repeat all six batches after a fresh VM restore and keep a single latest green pass per batch.",
            "Promote the most representative deterministic tests into upstream Atomic/CALDERA lanes.",
        ],
    )


def upstream_dimension(reports: list[dict[str, Any]]) -> Dimension:
    caldera_latest = latest_by_profile_and_lane(reports, "caldera-upstream")
    atomic_latest = latest_by_profile_and_lane(reports, "atomic-upstream")
    caldera = caldera_latest.get("windows-caldera-smoke")
    atomic = atomic_latest.get("windows-atomic-upstream-smoke")
    caldera_score = 0.0
    atomic_score = 0.0
    blockers: list[str] = []
    evidence: list[str] = []

    if caldera:
        caldera_score = 10.0 if quality_gate(caldera).get("passed") else report_score(caldera) / 10
        evidence.append(
            f"CALDERA smoke: {summary(caldera).get('covered', 0)}/{summary(caldera).get('tests', 0)} covered, gate={quality_gate(caldera).get('passed')}."
        )
    else:
        blockers.append("CALDERA smoke artifact missing.")

    if atomic:
        atomic_score = report_score(atomic) / 10
        if not quality_gate(atomic).get("passed"):
            blockers.extend(full_profile_gaps(atomic, covered_test_ids([atomic]))[:5])
        evidence.append(
            f"Atomic smoke: {summary(atomic).get('covered', 0)}/{summary(atomic).get('tests', 0)} covered, score={report_score(atomic)}, gate={quality_gate(atomic).get('passed')}."
        )
    else:
        blockers.append("Atomic upstream smoke artifact missing.")

    score = round((caldera_score * 0.45) + (atomic_score * 0.55), 1)
    return Dimension(
        "Upstream Atomic/CALDERA proof",
        score,
        evidence,
        blockers,
        [
            "Make Atomic upstream smoke fully green without fallback.",
            "Expand CALDERA from smoke to credential access, lateral movement, C2-safe, exfil-safe, and response-linked chains.",
        ],
    )


def enterprise_eval_dimension(latest: dict[str, dict[str, Any]]) -> Dimension:
    report = latest.get("windows-enterprise-eval-safe-v1")
    if not report:
        return Dimension(
            "Enterprise evaluation profile",
            0.0,
            ["No latest enterprise-eval artifact found."],
            ["windows-enterprise-eval-safe-v1 missing."],
            ["Run the enterprise eval profile on the driver-ready lab."],
        )
    gaps = full_profile_gaps(report, covered_test_ids([report]))
    score = round(report_score(report) / 10, 1)
    return Dimension(
        "Enterprise evaluation profile",
        score,
        [
            f"Run: {run_id(report)}.",
            f"Covered={summary(report).get('covered', 0)}/{summary(report).get('tests', 0)}, partial={summary(report).get('partial', 0)}, gate={quality_gate(report).get('passed')}.",
        ],
        gaps[:10],
        [
            "Fix execution_failed cases first; they are harness/product readiness gaps, not detection misses.",
            "Close remaining encoded PowerShell and masquerading expectation mismatches.",
        ],
    )


def noise_and_baseline_dimension(latest: dict[str, dict[str, Any]]) -> Dimension:
    benign = latest.get("windows-roadmap-p0-existing-benign-baseline")
    broad = latest.get("windows-benign-baseline")
    score = 0.0
    evidence: list[str] = []
    blockers: list[str] = []
    if benign:
        summ = summary(benign)
        gate = bool(quality_gate(benign).get("passed"))
        score = 8.0 if gate else 5.0
        if int(summ.get("unexpected_high_or_critical_alerts") or 0) == 0:
            score += 1.0
        evidence.append(
            f"Benign P0 baseline: {summ.get('covered', 0)}/{summ.get('tests', 0)} covered, gate={gate}, unexpected high/critical alerts={summ.get('unexpected_high_or_critical_alerts', 0)}."
        )
    else:
        blockers.append("Benign baseline artifact missing.")
    if broad:
        broad_summary = summary(broad)
        broad_gate = bool(quality_gate(broad).get("passed"))
        evidence.append(
            f"Broad benign baseline: {broad_summary.get('covered', 0)}/{broad_summary.get('tests', 0)} covered, gate={broad_gate}, unexpected high/critical alerts={broad_summary.get('unexpected_high_or_critical_alerts', 0)}."
        )
        if not broad_gate:
            score = min(score, 6.0) if score else 5.0
            blockers.extend(full_profile_gaps(broad, covered_test_ids([broad]))[:5])
    else:
        blockers.append("Broad benign baseline artifact missing.")
    blockers.append("Current benign corpus is still narrow for enterprise desktop/server reality.")
    return Dimension(
        "Benign baseline and false-positive control",
        min(10.0, round(score, 1)),
        evidence,
        blockers,
        [
            "Add browser, update, developer tools, WMI admin, PowerShell admin, backup, installer, and remote-admin benign workloads.",
            "Require every high/critical rule to have a benign contrast or structured suppression provenance.",
        ],
    )


def response_dimension(latest: dict[str, dict[str, Any]]) -> Dimension:
    response = latest.get("windows-response-validation-safe-v1")
    score = 3.0
    evidence = ["Response dry-run harness exists under tools/response_validation."]
    blockers = [
        "No selected live response end-to-end artifact in the benchmark review.",
        "Kill/quarantine/isolate/de-isolate/live shell need audit-backed execution evidence.",
    ]
    if response:
        score = report_score(response) / 10
        evidence.append(
            f"Benchmark response profile present: {run_id(response)}, gate={quality_gate(response).get('passed')}."
        )
    return Dimension(
        "Response and containment",
        round(score, 1),
        evidence,
        blockers,
        [
            "Add a non-destructive live response validation profile that proves command dispatch, agent result, audit persistence, and rollback state.",
            "Gate destructive actions behind RBAC/approval and require transcript/audit export evidence.",
        ],
    )


def release_dimension() -> Dimension:
    return Dimension(
        "Release, signing, and operations",
        3.5,
        [
            "Build artifacts and deployment scripts exist, but enterprise release evidence is not yet represented as a benchmark gate.",
        ],
        [
            "Windows installer/driver signing pipeline is not proven in the benchmark artifacts.",
            "SBOM, hashes, compatibility matrix, update rollback, and clean uninstall evidence are not yet release gates.",
        ],
        [
            "Add release-readiness profile: install, upgrade, rollback, uninstall, service recovery, driver state, hashes, and SBOM checks.",
            "Track Windows 10, Windows 11, and Windows Server compatibility as first-class artifacts.",
        ],
    )


def render(dimensions: list[Dimension]) -> str:
    weighted = sum(d.score for d in dimensions) / len(dimensions) if dimensions else 0.0
    lines: list[str] = [
        "# Windows Enterprise Readiness Scorecard",
        "",
        "Status: generated from current benchmark artifacts",
        "Last updated: 2026-05-23",
        "",
        "This scorecard tracks how close the Windows product is to enterprise",
        "maturity. It is deliberately stricter than deterministic coverage: a",
        "10/10 requires reproducibility, upstream proof, low false positives,",
        "response auditability, driver reliability, and release operations.",
        "",
        f"Overall score: `{weighted:.1f}/10`",
        "",
        "| Dimension | Score | Primary blockers |",
        "|-----------|-------|------------------|",
    ]
    for d in dimensions:
        blockers = "; ".join(d.blockers[:2]) if d.blockers else "-"
        lines.append(f"| {d.name} | `{d.score:.1f}/10` | {blockers} |")

    for d in dimensions:
        lines.extend(["", f"## {d.name}", "", f"Score: `{d.score:.1f}/10`", "", "Evidence:"])
        for item in d.evidence:
            lines.append(f"- {item}")
        lines.append("")
        lines.append("Blockers:")
        if d.blockers:
            for item in d.blockers:
                lines.append(f"- {item}")
        else:
            lines.append("- None recorded.")
        lines.append("")
        lines.append("Next actions:")
        for item in d.next_actions:
            lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "## Evidence Provenance Boundary",
            "",
            "| Evidence lane | What it proves | What it does not prove | Current use in scorecard |",
            "|---------------|----------------|------------------------|--------------------------|",
            "| Deterministic roadmap command | Tamandua can observe and score a safe behavior surrogate on the lab VM. | Real Atomic Red Team execution, real CALDERA adversary execution, or production detection breadth. | Windows 300 deterministic evidence only. |",
            "| Atomic upstream | `Invoke-AtomicTest` executed the selected Atomic tests without deterministic fallback. | Full ATT&CK or CALDERA coverage. | Upstream Atomic/CALDERA proof. |",
            "| CALDERA upstream | CALDERA operation/adversary/PAW evidence exists for the selected chains. | Every CALDERA ability, every technique, or response containment maturity. | Upstream Atomic/CALDERA proof. |",
            "| Enterprise-eval | Driver, source, field, noise, and quality gates passed for selected profile. | External vendor parity unless upstream and release gates also pass. | Enterprise evaluation, benign baseline, response dimensions. |",
            "",
            "Reports now surface `gap_category_counts` and `actionable_gaps` in the JSON, comparison JSON, quality gate, and Markdown run output. Treat these categories as owners: `collector`, `normalization`, `detector`, `alert-quality`, `runner`, `noise`, and `claim-boundary`.",
            "",
            "## Wazuh/CrowdStrike-Comparable Gate Checklist",
            "",
            "| Gate | 10/10 Evidence Required | Current Status |",
            "|------|-------------------------|----------------|",
            "| Windows installation | signed MSI/EXE, silent install, upgrade, uninstall, rollback, proxy, enterprise deployment logs | partial; not benchmark-gated |",
            "| Enrollment and identity | one-time enrollment, stable mTLS identity, revoke/re-enroll, duplicate host handling, reconnect proof | partial; benchmark agent identity is stable, lifecycle gaps remain |",
            "| RBAC and audit | scoped permissions, MFA/approval for destructive actions, immutable audit, tenant-safe API paths | partial; docs/code exist, needs end-to-end security review evidence |",
            "| Response | kill, quarantine, isolate/unisolate, collect, live response, rollback and failure reasons | weak; dry-run/contract exists, live audit-backed proof missing |",
            "| FIM | realtime and scan policies, registry monitoring, baseline, allowlist, tuning, UI/export evidence | partial; needs Windows collector-to-alert proof |",
            "| Inventory and vulnerability | hardware/software inventory, CPE/CVE mapping, affected asset evidence | partial; schema exists, Windows evidence needs promotion |",
            "| Compliance | CIS/NIST/SOC2/PCI-style controls mapped to host evidence, no synthetic score without proof | partial; must be evidence-per-control |",
            "| SIEM/export | JSON/CEF/syslog/Event Streams, replay cursors, schemas, delivery SLO, Splunk/Sentinel examples | partial; streaming exists, supported connectors need proof |",
            "| Threat intelligence | Sigma/YARA/IOC/STIX/TAXII provenance, feed health, parse errors, rule performance | partial; integrations exist, feed health must be gated |",
            "| Scale and release | load tests, signed artifacts, SBOM, hashes, compatibility matrix, canary update and rollback | weak; release evidence pack missing |",
            "",
            "## Enterprise 10/10 Definition",
            "",
            "- Windows 300 deterministic batches pass after fresh VM restore in repeated runs.",
            "- Atomic upstream smoke and selected expanded Atomic profiles pass without fallback.",
            "- CALDERA smoke plus expanded enterprise chains pass with storyline and alert evidence.",
            "- Benign baseline is broad enough to represent real enterprise desktops and servers.",
            "- Response actions are proven end to end with RBAC, audit, rollback, and transcript evidence.",
            "- Driver and agent reliability are proven through stress, unload/reload, replay, backpressure, and compatibility artifacts.",
            "- Release pipeline proves signing, SBOM, hashes, upgrade, rollback, uninstall, and supportable version matrix.",
            "",
            "## Current Claim",
            "",
            "Allowed: Tamandua has strong Windows deterministic validation evidence and selected CALDERA smoke proof.",
            "",
            "Not allowed yet: broad CrowdStrike-equivalent or Wazuh-enterprise replacement claims.",
            "",
        ]
    )
    return "\n".join(lines)


def build_scorecard(runs_dir: Path) -> str:
    reports = load_reports(runs_dir)
    latest = latest_by_profile(reports)
    dimensions = [
        windows_300_dimension(reports, latest),
        upstream_dimension(reports),
        enterprise_eval_dimension(latest),
        noise_and_baseline_dimension(latest),
        response_dimension(latest),
        release_dimension(),
    ]
    return render(dimensions)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", default=str(RUNS_DIR))
    parser.add_argument("--output", default=str(OUTPUT))
    args = parser.parse_args()

    rendered = build_scorecard(Path(args.runs_dir))
    Path(args.output).write_text(rendered, encoding="utf-8")
    print(f"wrote {Path(args.output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
