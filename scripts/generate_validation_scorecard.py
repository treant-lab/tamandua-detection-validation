#!/usr/bin/env python3
"""Generate roadmap validation status from benchmark run artifacts.

The scorecard is intentionally artifact-driven: it reads JSON outputs under
``docs/benchmarks/runs`` and writes generated Markdown/JSON summaries. It does
not contact the Tamandua server or execute benchmarks.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
DEFAULT_RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
DEFAULT_OUTPUT_DIR = ROOT / "docs" / "benchmarks" / "generated"
DEFAULT_PROFILES_DIR = ROOT / "tools" / "detection_validation" / "profiles"
DEFAULT_MANUAL_STATUS_DOCS = (
    ROOT / "docs" / "benchmarks" / "PARALLEL_EXECUTION_BOARD.md",
    ROOT / "docs" / "benchmarks" / "NEXT_VALIDATION_WORK_QUEUE.md",
)
ROADMAP_STATUSES = {
    "dry-run",
    "fail",
    "generated",
    "needs-repeatability",
    "no-artifact",
    "partial",
    "pass",
    "seeded",
}
PROFILE_STATUSES = {
    "dry-run",
    "fail",
    "no-artifact",
    "partial-scope",
    "pass",
}
NON_AGGREGATED_PROFILES = {
    "validation-status-consistency-probe",
}
TIMESTAMP_RE = re.compile(r"^(?P<stamp>\d{8}T\d{6}Z)-")
POSITIVE_CLAIM_RE = re.compile(
    r"\b(pass|passes|passed|green|covered|closed|clean|verde|conclu[ií]d[oa]|fechad[oa]|limp[oa])\b",
    re.IGNORECASE,
)
NEGATIVE_CLAIM_RE = re.compile(
    r"\b(fail|fails|failed|blocked|blocker|pending|open|missing|no-artifact|dry-run|staged|planned|partial|"
    r"bloquead[oa]|pendente|falha|falhou)\b",
    re.IGNORECASE,
)
FUTURE_POSITIVE_RE = re.compile(
    r"\b(after|before|until|once|then|get|needs?|requires?|execute|rerun|triage|wait|aguard[ae]|precisa)\b"
    r".{0,90}\b(pass|passes|green|covered|closed|verde)\b",
    re.IGNORECASE,
)
HISTORICAL_STATUS_CONTEXT_RE = re.compile(
    r"\b("
    r"older|historical|previous|prior|earlier|before that|recent failures before|"
    r"latest green|latest pass|diagnostic run|diagnostic artifact|accepted full|"
    r"closed that case|from\s+`?fail`?\s+to\s+`?pass`?|passed the full profile|"
    r"exposed one runner|classified"
    r")\b",
    re.IGNORECASE,
)
POSITIVE_HISTORICAL_CONTEXT_RE = re.compile(
    r"\b("
    r"older|historical|previous|prior|earlier|before that|"
    r"prior .* proof|prior .* artifact|prior .* evidence|"
    r"was green|was `?pass`?|confirmed .* existed"
    r")\b",
    re.IGNORECASE,
)


def normalize_macos_action_text(value: str) -> str:
    text = str(value or "")
    if (
        "com.apple.developer.endpoint-security.client" in text
        and "com.apple.developer.system-extension.install" not in text
    ):
        text = text.replace(
            "com.apple.developer.endpoint-security.client",
            (
                "com.apple.developer.endpoint-security.client and "
                "com.apple.developer.system-extension.install"
            ),
        )
    return text


def normalize_nested_actions(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized[key] = normalize_macos_action_text(item) if key == "action" else normalize_nested_actions(item)
        return normalized
    if isinstance(value, list):
        return [normalize_nested_actions(item) for item in value]
    return value
HISTORICAL_ARTIFACT_LINE_RE = re.compile(r"^-\s*`\d{8}T\d{6}Z-[^`]+`:\s*`?\d+/\d+`?,\s*gate\s+(fail|pass)", re.IGNORECASE)
CLAIM_BOUNDARY_CONTEXT_RE = re.compile(
    r"\b("
    r"claim boundary|claim remains|claim-safe|do not claim|does not prove|"
    r"not production|not full|not unrestricted|not runtime|not upstream|"
    r"still requires|still needs|requires .* evidence|needs .* evidence|"
    r"partial executed evidence|partial-scope|fixture-only|local fixture|"
    r"report-only|dry-run evidence|scope remains"
    r")\b",
    re.IGNORECASE,
)
OPEN_FULL_SCOPE_NOTE_RE = re.compile(
    r"\b("
    r"Full Roadmap [A-Z0-9]+ still requires|"
    r"Full governance still requires|"
    r"Full Roadmap [A-Z0-9]+ requires|"
    r"Full .* still requires|"
    r"production .* still requires|"
    r"Real fleet scale still requires|"
    r"VM evidence is still required"
    r")\b",
    re.IGNORECASE,
)
STATUS_CONSISTENCY_CONTEXT_RE = re.compile(
    r"\b("
    r"status consistency|validation_status_consistency|validation-status-consistency-probe|"
    r"consistency audit|alignment only"
    r")\b",
    re.IGNORECASE,
)
CLOSURE_CRITERION_POSITIVE_RE = re.compile(
    r"^-\s*`?[^`]+`?\s+passes\s+with\b",
    re.IGNORECASE,
)
ROADMAP_SCOPE_CAVEAT_RE = re.compile(
    r"\bRoadmap\s+[A-Z0-9]+\s+is\s+partial\s+overall\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ProfileRule:
    profile_id: str
    label: str | None = None


@dataclass(frozen=True)
class RoadmapRule:
    key: str
    title: str
    owner_area: str
    profiles: tuple[ProfileRule, ...] = ()
    required_passes: int = 1
    note: str = ""


ROADMAPS: tuple[RoadmapRule, ...] = (
    RoadmapRule(
        "A",
        "Finish Windows P0 Segmented Pass",
        "Windows deterministic P0",
        tuple(ProfileRule(f"windows-roadmap-300-p0-batch-{idx:02d}") for idx in range(1, 4))
        + (
            ProfileRule("windows-lab-execution-readiness-probe"),
            ProfileRule("windows-agent-connection-stability-probe"),
            ProfileRule("windows-proxmox-qga-readiness-probe"),
            ProfileRule("windows-proxmox-qga-file-diagnostics-probe"),
        ),
        note="Requires latest segmented P0 batches plus Windows lab readiness and connection-stability probes to remain green.",
    ),
    RoadmapRule(
        "B",
        "Repeat Windows 300 After Fresh VM Restore",
        "Windows 300 deterministic",
        tuple(ProfileRule(f"windows-roadmap-300-batch-{idx:02d}") for idx in range(1, 7))
        + (ProfileRule("fresh-restore-provenance-probe"),),
        note=(
            "Windows 300 batch artifacts must be executed, non-planned runs paired with fresh-restore provenance metadata. "
            "The provenance probe requires `fresh_restore=true`, valid restore timing order, "
            "snapshot/restore, VM, agent, and hostname fields before any fresh-restore claim is allowed."
        ),
    ),
    RoadmapRule(
        "B1",
        "Windows P1 Enterprise Finalization",
        "Windows P1 deterministic",
        tuple(ProfileRule(f"windows-roadmap-300-p1-batch-{idx:02d}") for idx in range(1, 4)),
        note=(
            "P1 profiles are the enterprise-evaluation expansion layer. Dry-run artifacts prove runnable "
            "coverage shape; executed artifacts are required before public coverage claims."
        ),
    ),
    RoadmapRule(
        "B2",
        "Windows P2 Advanced Finalization",
        "Windows P2 deterministic",
        tuple(ProfileRule(f"windows-roadmap-300-p2-batch-{idx:02d}") for idx in range(1, 3)),
        note=(
            "P2 profiles cover advanced variants and edge cases. They should run after P1 is stable, "
            "unless a P2 detector gap blocks a P1 storyline or false-positive fix. Full Roadmap B2 "
            "still requires endpoint-sensor evidence without deterministic/live-response boundaries "
            "before broader production claims."
        ),
    ),
    RoadmapRule(
        "C",
        "Close Atomic Upstream Smoke",
        "Atomic upstream",
        (ProfileRule("windows-atomic-upstream-smoke"),),
        note=(
            "Closure requires a fresh Atomic Red Team run with Invoke-AtomicTest available and "
            "--require-upstream enforced. Fallback-backed or live-response substitute evidence "
            "does not close the upstream smoke claim."
        ),
    ),
    RoadmapRule(
        "D",
        "CALDERA Repeatability Gate",
        "CALDERA upstream",
        (
            ProfileRule("windows-caldera-smoke"),
            ProfileRule("windows-caldera-enterprise-safe"),
            ProfileRule("caldera-api-shape-probe"),
            ProfileRule("caldera-paw-readiness-probe"),
            ProfileRule("caldera-repeatability-probe"),
        ),
        required_passes=3,
        note=(
            "Repeatability requires a fresh target PAW plus three consecutive passing artifacts for the selected profile. "
            "The PAW readiness probe records whether CALDERA is executable before creating operations, and the "
            "repeatability probe records whether archived CALDERA runs actually satisfy the consecutive-pass gate."
        ),
    ),
    RoadmapRule(
        "E",
        "Linux and macOS P0 Sensor Smoke",
        "Cross-platform sensor smoke",
        (
            ProfileRule("linux-roadmap-p0-sensor-contract-smoke"),
            ProfileRule("linux-ebpf-readiness-probe"),
            ProfileRule("macos-backend-readiness-probe"),
            ProfileRule("macos-roadmap-p0-sensor-contract-smoke"),
        ),
        note=(
            "Linux has server-backed P0 evidence. macOS closure requires backend readiness "
            "and then a server-backed P0 sensor-contract run; local-only contracts are not enough. "
            "The Linux eBPF/LSM readiness probe records local host prerequisites for the eBPF "
            "sensor stack; it is gate-neutral on non-Linux scheduling hosts."
        ),
    ),
    RoadmapRule(
        "F",
        "Response and Investigation Proof",
        "Response validation",
        (
            ProfileRule("windows-response-validation-safe-v1"),
            ProfileRule("linux-response-validation-safe-v1"),
        ),
        note=(
            "Selected non-destructive response audit evidence is green. Full Roadmap F still "
            "requires RBAC/approval proof, rollback/no-op safety, destructive-action guardrails, "
            "and broader investigation workflow evidence."
        ),
    ),
    RoadmapRule(
        "G",
        "Release, Signing, and Operations Gate",
        "Release operations",
        (
            ProfileRule("linux-release-readiness-dry-run"),
            ProfileRule("release-resilience-static-probe"),
            ProfileRule("release-operations-fixture-probe"),
        ),
        note=(
            "Dry-run, static/source, and local fixture evidence validate release operations contract shape; "
            "production readiness still requires signed artifacts, install/upgrade/rollback/uninstall execution, and "
            "compatibility evidence."
        ),
    ),
    RoadmapRule(
        "H",
        "Public Snapshot Package",
        "Claim-safe evidence packaging",
        (
            ProfileRule("windows-atomic-upstream-smoke"),
            ProfileRule("windows-caldera-smoke"),
            ProfileRule("windows-roadmap-300-p1-batch-01"),
            ProfileRule("public-snapshot-package-probe"),
        ),
        note=(
            "Generated status identifies candidate evidence and the local snapshot package validates claim-safe "
            "allowed/disallowed language. Final public copy still needs human review."
        ),
    ),
    RoadmapRule(
        "I",
        "Enterprise Eval Closure",
        "Enterprise evaluation",
        (ProfileRule("windows-enterprise-eval-safe-v1"),),
        note=(
            "The selected Windows enterprise-eval profile has clean engineering-validation "
            "coverage. Full Roadmap I still requires endpoint-sensor evidence without fallback "
            "boundaries, stable lab execution, and expanded production-equivalent validation."
        ),
    ),
    RoadmapRule(
        "J",
        "Broad Benign and Noise Corpus",
        "Benign/noise validation",
        (
            ProfileRule("windows-false-positive-regression-noise"),
            ProfileRule("windows-benign-baseline"),
            ProfileRule("windows-benign-noise-broad-v1"),
            ProfileRule("linux-benign-noise-broad-v1"),
        ),
        note=(
            "Selected Windows/Linux benign and false-positive regression evidence is green, but the live "
            "Windows benign baseline remains a closure gate for endpoint-sensor coverage and missing-field "
            "normalization before broad FP claims are complete."
        ),
    ),
    RoadmapRule(
        "K",
        "FIM, Inventory, Compliance, and SIEM Evidence",
        "Platform capability evidence",
        (
            ProfileRule("platform-capabilities-static-api-probe"),
            ProfileRule("platform-capability-evidence-fixture-probe"),
            ProfileRule("linux-platform-capability-live-proof"),
        ),
        note=(
            "The static/API probe validates source/API readiness across FIM, inventory, compliance, "
            "and SIEM/export. The fixture probe validates expected FIM, inventory, compliance, and "
            "SIEM evidence semantics locally. The Linux live proof validates bounded endpoint execution "
            "and evidence shape for selected platform checks. Full Roadmap K still requires production "
            "FIM collector events and external SIEM delivery evidence."
        ),
    ),
    RoadmapRule(
        "L",
        "Agent and Driver Reliability",
        "Agent/driver reliability",
        (
            ProfileRule("release-resilience-static-probe"),
            ProfileRule("agent-driver-reliability-fixture-probe"),
        ),
        note=(
            "Static/source and local fixture evidence validate reliability contract shape. VM evidence "
            "is still required for lifecycle, reboot, driver stress, offline replay/backpressure, and "
            "drop-accounting under load."
        ),
    ),
    RoadmapRule(
        "M",
        "Expanded Upstream Profiles",
        "Expanded Atomic/CALDERA",
        (
            ProfileRule("windows-atomic-extended-safe"),
            ProfileRule("atomic-t1047-lab-capability-probe"),
            ProfileRule("windows-caldera-enterprise-safe"),
        ),
        note=(
            "Atomic extended and CALDERA enterprise must both have authoritative green execution artifacts. "
            "The T1047 lab capability probe only records whether the current lab has bounded WMIC precondition "
            "evidence; it does not replace Atomic/CALDERA execution."
        ),
    ),
    RoadmapRule(
        "N",
        "Product Security and Tenant Safety Gate",
        "Control-plane safety",
        (
            ProfileRule("control-plane-tenant-safety-static-probe"),
            ProfileRule("control-plane-two-tenant-fixture-probe"),
        ),
        note=(
            "The static/API probe validates source-level guardrails and unauthenticated deny behavior. "
            "The two-tenant fixture probe validates expected RBAC, token, audit, and approval semantics locally. "
            "Full Roadmap N still requires authenticated two-tenant runtime API fixtures and persisted audit proof."
        ),
    ),
    RoadmapRule(
        "O",
        "Evidence Index and Scorecard Automation",
        "Generated roadmap scorecard",
        note="This generated artifact is the first automation output; validate it after every run refresh.",
    ),
    RoadmapRule(
        "P",
        "Telemetry Replay and Regression Dataset",
        "Offline replay",
        (
            ProfileRule("telemetry-replay-readiness-probe"),
            ProfileRule("telemetry-replay-offline-fp-severity-v1"),
            ProfileRule("event-envelope-retrospective-replay-report-only"),
            ProfileRule("historical-replay-adapter-report-only"),
        ),
        note=(
            "The replay readiness probe validates sanitized fixture/schema coverage, and the "
            "offline FP/severity executor validates selected replay decisions without DB access "
            "or live alert mutation. The Event Envelope probe validates D&R report-only replay "
            "fixtures and live-alert immutability boundaries. The historical adapter probe validates "
            "retrospective-result persistence semantics in a local report-only database. Full Roadmap P "
            "still requires production historical event replay against persisted server Event Envelopes."
        ),
    ),
    RoadmapRule(
        "Q",
        "Detection Content Governance",
        "Detection governance",
        (
            ProfileRule("windows-enterprise-eval-safe-v1"),
            ProfileRule("windows-atomic-upstream-smoke"),
            ProfileRule("windows-caldera-smoke"),
            ProfileRule("windows-benign-noise-broad-v1"),
            ProfileRule("telemetry-replay-offline-fp-severity-v1"),
            ProfileRule("detection-content-governance-probe"),
            ProfileRule("detection-rule-wave-1-fixture-probe"),
            ProfileRule("detection-rule-backlog-fixture-probe"),
        ),
        note=(
            "Passing profiles and the local governance probe are supporting evidence for selected content "
            "governance. The wave fixture probe validates local positive/benign fixture contracts for the "
            "prioritized high/critical gaps. Full governance still requires runtime-backed positive "
            "and benign fixtures for every promoted rule."
        ),
    ),
    RoadmapRule(
        "R",
        "Analyst UX Evidence Gate",
        "Analyst workflow evidence",
        (
            ProfileRule("windows-enterprise-eval-safe-v1"),
            ProfileRule("windows-response-validation-safe-v1"),
            ProfileRule("windows-caldera-smoke"),
            ProfileRule("agent-platform-capabilities-runtime-probe"),
            ProfileRule("agent-platform-capabilities-live-api-probe"),
        ),
        note=(
            "Selected internal API/rendering and workflow evidence is green. Full Roadmap R still "
            "requires public HTTPS reachability, collector-observed telemetry, live-response command "
            "success, and broader storyline/evidence-quality proof."
        ),
    ),
    RoadmapRule(
        "S",
        "Fleet Scale and Multi-Agent Benchmark",
        "Fleet scale",
        (
            ProfileRule("fleet-scale-inventory-api-probe"),
            ProfileRule("fleet-scale-isolation-fixture-probe"),
        ),
        note=(
            "The inventory API probe validates authenticated multi-agent state visibility. "
            "The fixture probe validates workload, latency/loss, queue-depth, and evidence-isolation "
            "semantics locally. Real fleet scale still requires simultaneous endpoint execution and ingest/UI SLOs."
        ),
    ),
    RoadmapRule(
        "T",
        "DFIR Hunting and Artifact Collection",
        "DFIR hunting",
        (
            ProfileRule("dfir-hunting-readiness-static-probe"),
            ProfileRule("dfir-collection-fixture-probe"),
            ProfileRule("linux-dfir-live-collection-proof"),
        ),
        note=(
            "The readiness probe validates API/catalog/manifest shape. The fixture probe validates "
            "package semantics for artifact catalog, collection status, export hashes, redaction, "
            "analyst review, and chain-of-custody. The Linux live proof validates bounded endpoint "
            "metadata collection and manifest hash shape. Full Roadmap T still requires production "
            "collector orchestration, export delivery, and analyst review proof."
        ),
    ),
    RoadmapRule(
        "U",
        "Unified Detection and Response Engine",
        "Unified D&R engine",
        (ProfileRule("windows-unified-dr-engine-v1"),),
        note=(
            "The first unified D&R proof validates selected Windows fixtures as one report-only "
            "loop: Event Envelope, detection, alert contract, storyline/correlation contract, "
            "response plan/audit, analyst feedback, and replay stability. Full Roadmap U still "
            "requires runtime backend execution, production replay, collector policy, sync, rollout, "
            "safe-boot, and multi-tenant controls."
        ),
    ),
    RoadmapRule(
        "V",
        "Crash-Proof Agent and Defensive Resilience",
        "Agent/release safety",
        (ProfileRule("release-resilience-static-probe"), ProfileRule("crash-resilience-fixture-probe")),
        note=(
            "Static/source and local fixture evidence validate the release/resilience contract shape. "
            "VM evidence is still required for Secure Boot driver loading, stale-marker degraded mode, "
            "offline replay, local response guardrail enforcement, and OTA rollback."
        ),
    ),
)


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def run_paths(runs_dir: Path) -> list[Path]:
    return sorted(path for path in runs_dir.rglob("*.json") if path.name != "index.json")


def infer_run_id(path: Path, report: dict[str, Any]) -> str:
    if report.get("run_id"):
        return str(report["run_id"])
    stem = path.name.removesuffix(".comparison.json").removesuffix(".json")
    return stem


def infer_timestamp(path: Path, report: dict[str, Any]) -> str:
    for key in ("finished_at", "started_at", "generated_at"):
        value = report.get(key)
        if value:
            return str(value)
    match = TIMESTAMP_RE.match(path.name)
    if match:
        stamp = match.group("stamp")
        return datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except OSError:
        return ""


def profile_id(report: dict[str, Any]) -> str:
    profile = report.get("profile") or {}
    return str(report.get("profile_id") or profile.get("profile_id") or "")


def summary(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("summary") or {}


def scorecard(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("scorecard") or {}


def quality_gate(report: dict[str, Any]) -> dict[str, Any]:
    return report.get("quality_gate") or {}


def int_value(data: dict[str, Any], key: str) -> int:
    try:
        return int(data.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def is_executed(report: dict[str, Any]) -> bool:
    return report.get("execute") is not False


def load_profile_test_counts(profiles_dir: Path = DEFAULT_PROFILES_DIR) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not profiles_dir.exists():
        return counts
    for path in profiles_dir.glob("*.json"):
        profile = load_json(path)
        if not isinstance(profile, dict):
            continue
        pid = str(profile.get("profile_id") or "")
        tests = profile.get("tests")
        if pid and isinstance(tests, list):
            counts[pid] = len(tests)
    return counts


PROFILE_TEST_COUNTS = load_profile_test_counts()


def expected_profile_tests(report: dict[str, Any]) -> int | None:
    configured = PROFILE_TEST_COUNTS.get(profile_id(report))
    observed = int_value(summary(report), "tests")
    if configured and observed:
        return max(configured, observed)
    return configured or (observed if observed else None)


def is_complete_profile_scope(report: dict[str, Any]) -> bool:
    expected = expected_profile_tests(report)
    if not expected:
        return True
    return int_value(summary(report), "tests") >= expected


def is_pass(report: dict[str, Any]) -> bool:
    return is_executed(report) and is_complete_profile_scope(report) and bool(quality_gate(report).get("passed"))


def is_raw_gate_pass(report: dict[str, Any]) -> bool:
    return is_executed(report) and bool(quality_gate(report).get("passed"))


def can_contribute_partial_coverage(report: dict[str, Any]) -> bool:
    if not is_executed(report):
        return False
    gate = quality_gate(report)
    failures = set(str(failure) for failure in (gate.get("failures") or []))
    if not failures:
        return True
    if failures != {"infrastructure_blocked_tests"}:
        return False
    summ = summary(report)
    noisy_events = int_value(summ, "unexpected_high_or_critical_events")
    noisy_alerts = int_value(summ, "unexpected_high_or_critical_alerts")
    unknown_events = int_value(summ, "unknown_source_events")
    return noisy_events == 0 and noisy_alerts == 0 and unknown_events == 0


def load_reports(runs_dir: Path) -> list[dict[str, Any]]:
    reports_by_run: dict[tuple[str, str], dict[str, Any]] = {}
    for path in run_paths(runs_dir):
        report = load_json(path)
        if not report:
            continue
        pid = profile_id(report)
        if not pid:
            continue
        report = dict(report)
        report["_path"] = str(path.relative_to(ROOT)).replace("\\", "/")
        report["_run_id"] = infer_run_id(path, report)
        report["_timestamp"] = infer_timestamp(path, report)
        report["_is_comparison"] = path.name.endswith(".comparison.json")
        key = (pid, str(report["_run_id"]))
        current = reports_by_run.get(key)
        if current is not None and not current.get("_is_comparison"):
            continue
        if current is None or (current.get("_is_comparison") and not report.get("_is_comparison")):
            reports_by_run[key] = report
    return list(reports_by_run.values())


def report_sort_key(report: dict[str, Any]) -> tuple[str, int, int, str]:
    summ = summary(report)
    return (
        str(report.get("_timestamp") or ""),
        int_value(summ, "tests"),
        int_value(summ, "covered"),
        str(report.get("_path") or ""),
    )


def latest_by_profile(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for report in reports:
        pid = profile_id(report)
        current = latest.get(pid)
        if current is None or report_sort_key(report) > report_sort_key(current):
            latest[pid] = report
    return latest


def by_profile(reports: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for report in reports:
        grouped.setdefault(profile_id(report), []).append(report)
    for items in grouped.values():
        items.sort(key=report_sort_key, reverse=True)
    return grouped


def passing_by_profile(reports: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped = by_profile([report for report in reports if is_pass(report)])
    return grouped


def failing_by_profile(reports: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return by_profile(
        [
            report
            for report in reports
            if is_executed(report) and is_complete_profile_scope(report) and not is_raw_gate_pass(report)
        ]
    )


def diagnostic_failing_by_profile(reports: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return by_profile(
        [
            report
            for report in reports
            if is_executed(report) and not is_complete_profile_scope(report) and not is_raw_gate_pass(report)
        ]
    )


def consecutive_pass_count(report_list: list[dict[str, Any]]) -> int:
    count = 0
    for report in sorted(report_list, key=report_sort_key, reverse=True):
        if not is_executed(report):
            continue
        if not is_pass(report):
            break
        count += 1
    return count


def best_pass(report_list: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not report_list:
        return None
    return max(
        report_list,
        key=lambda report: (
            int_value(scorecard(report), "maturity_score"),
            int_value(summary(report), "covered"),
            report_sort_key(report),
        ),
    )


def aggregate_profile_coverage(report_list: list[dict[str, Any]], expected: int | None) -> dict[str, Any]:
    covered_ids: set[str] = set()
    raw_gate_failures = 0
    latest_raw_gate_pass: dict[str, Any] | None = None
    partial_contributor_count = 0
    partial_contributor_ids: list[str] = []

    for report in sorted(report_list, key=report_sort_key, reverse=True):
        if not is_executed(report):
            continue
        raw_gate_pass = is_raw_gate_pass(report)
        if not raw_gate_pass:
            raw_gate_failures += 1
            if not can_contribute_partial_coverage(report):
                continue
        if raw_gate_pass and latest_raw_gate_pass is None:
            latest_raw_gate_pass = report
        if not raw_gate_pass:
            partial_contributor_count += 1
            run_id = str(report.get("_run_id") or "")
            if run_id:
                partial_contributor_ids.append(run_id)
        for test in report.get("tests") or []:
            if not isinstance(test, dict):
                continue
            test_id = str(test.get("id") or "")
            if test_id and str(test.get("status") or "").lower() == "covered":
                covered_ids.add(test_id)

    covered = len(covered_ids)
    effective_expected = max(expected or 0, covered) or expected
    complete = bool(effective_expected and covered >= effective_expected)
    return {
        "covered_test_ids": sorted(covered_ids),
        "covered": covered,
        "expected": effective_expected,
        "complete": complete,
        "raw_gate_failures": raw_gate_failures,
        "latest_raw_gate_pass": compact_report(latest_raw_gate_pass),
        "partial_contributor_count": partial_contributor_count,
        "partial_contributor_ids": sorted(set(partial_contributor_ids)),
    }


def compact_report(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not report:
        return None
    summ = summary(report)
    gate = quality_gate(report)
    score = scorecard(report)
    return {
        "run_id": report.get("_run_id"),
        "profile_id": profile_id(report),
        "path": report.get("_path"),
        "timestamp": report.get("_timestamp"),
        "benchmark_lane": report.get("benchmark_lane"),
        "execute": report.get("execute"),
        "quality_gate_passed": is_pass(report),
        "raw_quality_gate_passed": gate.get("passed"),
        "quality_gate_failures": gate.get("failures") or [],
        "maturity_score": score.get("maturity_score"),
        "maturity_band": score.get("maturity_band"),
        "tests": int_value(summ, "tests"),
        "expected_profile_tests": expected_profile_tests(report),
        "complete_profile_scope": is_complete_profile_scope(report),
        "covered": int_value(summ, "covered"),
        "partial": int_value(summ, "partial"),
        "missed": int_value(summ, "missed"),
        "planned": int_value(summ, "planned"),
        "skipped": int_value(summ, "skipped"),
        "execution_failed": int_value(summ, "execution_failed"),
        "unknown_source_events": int_value(summ, "unknown_source_events"),
        "unexpected_high_or_critical_events": int_value(summ, "unexpected_high_or_critical_events")
        + int_value(summ, "unexpected_high_or_critical_alerts"),
        "upstream_backed_tests": int_value(summ, "upstream_backed_tests"),
        "fallback_command_tests": int_value(summ, "fallback_command_tests"),
        "gap_category_counts": summ.get("gap_category_counts") or gate.get("gap_category_counts") or {},
        "actionable_gaps": normalize_nested_actions(
            (summ.get("actionable_gaps") or gate.get("actionable_gaps") or [])[:10]
        ),
        "blocking_gaps": score.get("blocking_gaps") or [],
    }


def profile_status(
    profile: str,
    latest: dict[str, dict[str, Any]],
    passes: dict[str, list[dict[str, Any]]],
    failures: dict[str, list[dict[str, Any]]],
    diagnostic_failures: dict[str, list[dict[str, Any]]],
    all_reports: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    latest_report = latest.get(profile)
    pass_list = passes.get(profile, [])
    fail_list = failures.get(profile, [])
    aggregate_reports = [latest_report] if latest_report and profile in NON_AGGREGATED_PROFILES else all_reports.get(profile, [])
    aggregate = aggregate_profile_coverage(
        aggregate_reports,
        expected_profile_tests(latest_report) if latest_report else PROFILE_TEST_COUNTS.get(profile),
    )
    best = best_pass(pass_list)
    latest_pass = pass_list[0] if pass_list else None
    latest_fail = fail_list[0] if fail_list else None
    diagnostic_fail_list = diagnostic_failures.get(profile, [])
    latest_diagnostic_fail = diagnostic_fail_list[0] if diagnostic_fail_list else None
    status = "no-artifact"
    if latest_report:
        if not is_executed(latest_report):
            status = "dry-run"
        elif is_complete_profile_scope(latest_report) and not is_raw_gate_pass(latest_report) and not can_contribute_partial_coverage(latest_report):
            status = "fail"
        elif aggregate["complete"]:
            status = "pass"
        elif not is_complete_profile_scope(latest_report):
            status = "partial-scope"
        else:
            status = "pass" if is_pass(latest_report) else "fail"
    return {
        "profile_id": profile,
        "status": status,
        "latest": compact_report(latest_report),
        "latest_pass": compact_report(latest_pass),
        "latest_fail": compact_report(latest_fail),
        "latest_diagnostic_fail": compact_report(latest_diagnostic_fail),
        "best_pass": compact_report(best),
        "aggregate": aggregate,
        "passing_artifacts": len(pass_list),
        "failing_artifacts": len(fail_list),
        "diagnostic_failing_artifacts": len(diagnostic_fail_list),
        "consecutive_latest_passes": consecutive_pass_count(all_reports.get(profile, [])),
    }


def latest_fail_after_pass(row: dict[str, Any]) -> bool:
    latest = row.get("latest") or {}
    latest_pass = row.get("latest_pass") or {}
    return (
        bool(latest_pass)
        and latest.get("quality_gate_passed") is False
    )


def has_latest_pass(row: dict[str, Any]) -> bool:
    return bool(row.get("latest_pass"))


def roadmap_status(profile_rows: list[dict[str, Any]], required_passes: int) -> str:
    if not profile_rows:
        return "no-artifact"
    if all(row["status"] == "no-artifact" for row in profile_rows):
        return "no-artifact"
    if all(row["status"] in {"no-artifact", "dry-run"} for row in profile_rows):
        return "dry-run"
    if required_passes > 1:
        if (
            all(row["status"] == "pass" for row in profile_rows)
            and all(has_latest_pass(row) for row in profile_rows)
            and not any(latest_fail_after_pass(row) for row in profile_rows)
            and any(
                row["consecutive_latest_passes"] >= required_passes
                for row in profile_rows
            )
        ):
            return "pass"
        return "needs-repeatability"
    if (
        all(row["status"] == "pass" for row in profile_rows)
        and all(has_latest_pass(row) for row in profile_rows)
        and not any(latest_fail_after_pass(row) for row in profile_rows)
    ):
        return "pass"
    if any(row["latest_pass"] or row["status"] in {"pass", "partial-scope"} for row in profile_rows):
        return "partial"
    return "fail"


def note_declares_open_full_scope(note: str) -> bool:
    return bool(OPEN_FULL_SCOPE_NOTE_RE.search(note))


def static_roadmap_evidence(output_dir: Path) -> dict[str, list[str]]:
    evidence: dict[str, list[str]] = {}

    replay_fixture = ROOT / "tools" / "detection_validation" / "fixtures" / "windows_false_positive_replay_v1.json"
    replay_validator = ROOT / "tools" / "detection_validation" / "validate_replay_fixtures.py"
    if replay_fixture.exists() and replay_validator.exists():
        evidence["P"] = [
            "`windows_false_positive_replay_v1.json` fixture seed",
            "`validate_replay_fixtures.py` schema check",
        ]

    k_n_s_t_fixture = ROOT / "tools" / "detection_validation" / "fixtures" / "roadmap_k_n_s_t_contracts_v1.json"
    k_n_s_t_validator = ROOT / "tools" / "detection_validation" / "validate_roadmap_contract_fixtures.py"
    if k_n_s_t_fixture.exists() and k_n_s_t_validator.exists():
        evidence["K"] = ["`roadmap_k_n_s_t_contracts_v1.json` Roadmap K contract fixture"]
        evidence["N"] = ["`roadmap_k_n_s_t_contracts_v1.json` Roadmap N contract fixture"]
        evidence["S"] = ["`roadmap_k_n_s_t_contracts_v1.json` Roadmap S contract fixture"]
        evidence["T"] = ["`roadmap_k_n_s_t_contracts_v1.json` Roadmap T contract fixture"]

    metadata_report = output_dir / "detection_rule_metadata_report.json"
    if metadata_report.exists():
        try:
            report = load_json(metadata_report) or {}
        except (OSError, json.JSONDecodeError):
            report = {}
        review = int(report.get("high_critical_review") or 0)
        scanned = int(report.get("high_critical_rules") or 0)
        if scanned and review == 0:
            evidence["Q"] = [f"`detection_rule_metadata_report` high/critical metadata clean `{scanned}/0 review`"]
        elif scanned:
            evidence["Q"] = [f"`detection_rule_metadata_report` high/critical metadata review open `{review}`"]

    return evidence


def build_payload(reports: list[dict[str, Any]], runs_dir: Path) -> dict[str, Any]:
    latest = latest_by_profile(reports)
    grouped = by_profile(reports)
    passes = passing_by_profile(reports)
    failures = failing_by_profile(reports)
    diagnostic_failures = diagnostic_failing_by_profile(reports)
    static_evidence = static_roadmap_evidence(DEFAULT_OUTPUT_DIR)
    roadmaps: list[dict[str, Any]] = []
    for rule in ROADMAPS:
        profile_rows = [
            profile_status(item.profile_id, latest, passes, failures, diagnostic_failures, grouped)
            for item in rule.profiles
        ]
        status = roadmap_status(profile_rows, rule.required_passes)
        if rule.key == "O":
            status = "generated"
        if rule.key in static_evidence and status in {"no-artifact", "dry-run"}:
            status = "seeded"
        elif rule.key in static_evidence and status == "fail":
            status = "partial"
        if status == "pass" and note_declares_open_full_scope(rule.note):
            status = "partial"
        roadmaps.append(
            {
                "key": rule.key,
                "title": rule.title,
                "owner_area": rule.owner_area,
                "status": status,
                "required_passes": rule.required_passes,
                "note": rule.note,
                "profiles": profile_rows,
                "static_evidence": static_evidence.get(rule.key, []),
            }
        )
    all_profiles = sorted({profile_id(report) for report in reports})
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {
            "runs_dir": str(DEFAULT_RUNS_DIR.relative_to(ROOT)).replace("\\", "/"),
            "resolved_runs_dir": str(runs_dir),
            "artifact_count": len(reports),
            "profile_count": len(all_profiles),
            "profiles": all_profiles,
        },
        "roadmaps": roadmaps,
        "profiles": [
            profile_status(profile, latest, passes, failures, diagnostic_failures, grouped)
            for profile in all_profiles
        ],
        "contradictions": find_contradictions(roadmaps),
    }
    payload["manual_claim_review"] = dispatch_manual_claim_review(latest)
    return payload


def find_contradictions(roadmaps: list[dict[str, Any]]) -> list[dict[str, str]]:
    contradictions: list[dict[str, str]] = []
    for roadmap in roadmaps:
        for row in roadmap["profiles"]:
            latest = row.get("latest") or {}
            latest_pass = row.get("latest_pass") or {}
            latest_fail = row.get("latest_fail") or {}
            if (
                latest.get("quality_gate_passed") is False
                and latest.get("complete_profile_scope") is not False
                and latest_pass
            ):
                contradictions.append(
                    {
                        "roadmap": roadmap["key"],
                        "profile_id": row["profile_id"],
                        "type": "newer-fail-after-pass",
                        "message": f"Latest artifact {latest.get('run_id')} fails, but earlier pass {latest_pass.get('run_id')} exists.",
                    }
                )
            if latest.get("quality_gate_passed") is True and latest_fail:
                contradictions.append(
                    {
                        "roadmap": roadmap["key"],
                        "profile_id": row["profile_id"],
                        "type": "green-after-failure",
                        "message": (
                            f"Latest artifact {latest.get('run_id')} passes after failing artifact "
                            f"{latest_fail.get('run_id')}; verify manual docs preserve the scoped-pass "
                            "claim boundary instead of carrying a stale profile-blocked status."
                        ),
                    }
                )
    return contradictions


def is_positive_generated_status(status: str) -> bool:
    return status in {"pass", "generated", "seeded"}


def manual_claim_entities(payload: dict[str, Any]) -> list[dict[str, str]]:
    entities: list[dict[str, str]] = []
    for roadmap in payload["roadmaps"]:
        title = str(roadmap["title"])
        key = str(roadmap["key"])
        entities.append(
            {
                "kind": "roadmap",
                "id": key,
                "status": str(roadmap["status"]),
                "needle": title,
                "match": "substring",
            }
        )
        entities.append(
            {
                "kind": "roadmap",
                "id": key,
                "status": str(roadmap["status"]),
                "needle": f"Roadmap {key}",
                "match": "roadmap-key",
            }
        )
    for row in payload["profiles"]:
        entities.append(
            {
                "kind": "profile",
                "id": str(row["profile_id"]),
                "status": str(row["status"]),
                "needle": str(row["profile_id"]),
                "match": "substring",
            }
        )
    return entities


def claim_polarity(line: str) -> str | None:
    negative = bool(NEGATIVE_CLAIM_RE.search(line))
    positive = bool(POSITIVE_CLAIM_RE.search(line))
    if STATUS_CONSISTENCY_CONTEXT_RE.search(line):
        return None
    if CLAIM_BOUNDARY_CONTEXT_RE.search(line):
        return None
    if negative and (HISTORICAL_STATUS_CONTEXT_RE.search(line) or HISTORICAL_ARTIFACT_LINE_RE.search(line)):
        return None
    if negative:
        return "negative"
    if positive and (POSITIVE_HISTORICAL_CONTEXT_RE.search(line) or CLOSURE_CRITERION_POSITIVE_RE.search(line)):
        return None
    if positive and FUTURE_POSITIVE_RE.search(line):
        return None
    if positive:
        return "positive"
    return None


def manual_entity_matches(entity: dict[str, str], line: str, lowered: str) -> bool:
    needle = entity["needle"]
    if not needle:
        return False
    if entity.get("match") == "roadmap-key":
        key = re.escape(entity["id"])
        return bool(re.search(rf"\broadmap\s+{key}\b", line, re.IGNORECASE))
    return needle.lower() in lowered


def line_has_roadmap_scope_caveat(line: str) -> bool:
    return bool(ROADMAP_SCOPE_CAVEAT_RE.search(line))


def find_manual_claim_review(
    payload: dict[str, Any],
    docs: tuple[Path, ...] = DEFAULT_MANUAL_STATUS_DOCS,
    limit: int = 60,
) -> list[dict[str, str]]:
    """Find manual status text that should be reviewed against artifact state.

    This is intentionally heuristic. It does not fail the scorecard; it creates
    a review queue for old manual "green/pass/blocked" statements that mention
    a roadmap or profile whose generated artifact state says something else.
    """

    review: list[dict[str, str]] = []
    seen: set[tuple[str, str, int, str]] = set()
    entities = manual_claim_entities(payload)
    for path in docs:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        rel_path = str(path.relative_to(ROOT)).replace("\\", "/")
        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("```") or line.startswith("#"):
                continue
            polarity = claim_polarity(line)
            if not polarity:
                continue
            lowered = line.lower()
            for entity in entities:
                if not manual_entity_matches(entity, line, lowered):
                    continue
                if (
                    polarity == "negative"
                    and entity.get("kind") == "profile"
                    and line_has_roadmap_scope_caveat(line)
                ):
                    continue
                status = entity["status"]
                positive_status = is_positive_generated_status(status)
                if polarity == "positive" and positive_status:
                    continue
                if polarity == "negative" and not positive_status:
                    continue
                key = (rel_path, entity["id"], lineno, polarity)
                if key in seen:
                    continue
                seen.add(key)
                review.append(
                    {
                        "kind": entity["kind"],
                        "id": entity["id"],
                        "generated_status": status,
                        "polarity": polarity,
                        "doc": rel_path,
                        "line": str(lineno),
                        "snippet": line[:240],
                    }
                )
                if len(review) >= limit:
                    return review
    return review


def dispatch_manual_claim_review(latest: dict[str, dict[str, Any]], limit: int = 60) -> list[dict[str, str]]:
    dispatch = latest.get("validation-dispatch-results-probe") or {}
    manifest_ref = str(dispatch.get("dispatch_manifest") or "")
    if not manifest_ref:
        return []
    manifest_path = ROOT / manifest_ref.replace("\\", "/")
    if not manifest_path.exists():
        return []
    try:
        manifest = load_json(manifest_path)
    except json.JSONDecodeError:
        return []
    claims_ref = str(manifest.get("agent_claims_json_path") or "")
    if not claims_ref:
        return []
    claims_path = ROOT / claims_ref.replace("\\", "/")
    if not claims_path.exists():
        return []
    try:
        claims_payload = load_json(claims_path)
    except json.JSONDecodeError:
        return []
    packages = {
        str(package.get("package_id") or ""): package
        for package in manifest.get("packages") or []
        if isinstance(package, dict)
    }
    review: list[dict[str, str]] = []
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        state = str(claim.get("claim_state") or "")
        blocked_reasons = [str(value) for value in claim.get("blocked_reasons") or []]
        if state != "manual_claim_required" and "manual_launch_required" not in blocked_reasons:
            continue
        package_id = str(claim.get("package_id") or "")
        package = packages.get(package_id, {})
        current_next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        action_text = normalize_macos_action_text(
            str(current_next_action.get("action") or package.get("action") or "")
        )
        owner = str(claim.get("owner") or "unassigned")
        manual_reason = str(package.get("manual_reason") or "manual launch required")
        missing_env = [str(value) for value in claim.get("missing_effective_env") or []]
        prompt_path = str(claim.get("prompt_path") or "-")
        item = {
            "kind": "dispatch-claim",
            "id": str(claim.get("claim_id") or ""),
            "package_id": package_id,
            "generated_status": state or "manual_claim_required",
            "polarity": "manual",
            "doc": claims_ref,
            "line": "-",
            "owner": owner,
            "manual_reason": manual_reason,
            "missing_env": missing_env,
            "action": action_text or "-",
            "prompt_path": prompt_path,
            "snippet": (
                f"{package_id}: {manual_reason}; "
                f"owner={owner}; "
                f"missing_env={', '.join(missing_env) or '-'}; "
                f"action={action_text or '-'}; "
                f"prompt={prompt_path}"
            ),
        }
        review.append(item)
        if len(review) >= limit:
            return review
    return review


def md_value(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "pass" if value else "fail"
    return str(value)


def aggregate_display_source(row: dict[str, Any]) -> dict[str, Any]:
    aggregate = row.get("aggregate") or {}
    latest = row.get("latest") or {}
    if row.get("status") != "fail" and aggregate.get("complete"):
        return aggregate.get("latest_raw_gate_pass") or latest
    return latest


def roadmap_profile_bit(row: dict[str, Any]) -> str:
    latest = row.get("latest") or {}
    aggregate = row.get("aggregate") or {}
    display_source = aggregate_display_source(row)
    run = display_source.get("run_id") or latest.get("run_id") or "none"
    if row.get("status") != "fail" and aggregate.get("complete"):
        covered = aggregate.get("covered")
        tests = aggregate.get("expected")
    else:
        covered = display_source.get("covered", 0)
        tests = display_source.get("tests", 0)
    suffix = ""
    if aggregate.get("complete") and latest.get("run_id") and latest.get("run_id") != run:
        suffix = f" (latest `{latest.get('run_id')}` {md_value(latest.get('raw_quality_gate_passed'))})"
    return f"`{row['profile_id']}` {row['status']} `{covered}/{tests}` `{run}`{suffix}"


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Validation Roadmap Scorecard",
        "",
        "Status: generated",
        "",
        "Generated from `docs/benchmarks/runs/**/*.json` and `*.comparison.json` by",
        "`tools/detection_validation/generate_validation_scorecard.py`.",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Artifacts read: `{payload['source']['artifact_count']}`",
        f"- Profiles found: `{payload['source']['profile_count']}`",
        "",
        "## Roadmaps A-V",
        "",
        "| Roadmap | Status | Owner Area | Evidence Profiles | Note |",
        "|---------|--------|------------|-------------------|------|",
    ]
    for roadmap in payload["roadmaps"]:
        profile_bits = []
        for row in roadmap["profiles"]:
            profile_bits.append(roadmap_profile_bit(row))
        profile_bits.extend(roadmap.get("static_evidence") or [])
        if not profile_bits and roadmap["key"] == "O":
            profile_bits.append("this generated scorecard")
        elif not profile_bits:
            profile_bits.append("no mapped artifact profile yet")
        lines.append(
            f"| {roadmap['key']}. {roadmap['title']} | `{roadmap['status']}` | "
            f"{roadmap['owner_area']} | {'<br>'.join(profile_bits)} | {roadmap['note'] or '-'} |"
        )

    lines.extend(
        [
            "",
            "## Profile Evidence",
            "",
            "| Profile | Latest | Raw Gate | Scope | Score | Covered | Partial | Missed | Exec Failed | Latest Pass | Latest Fail | Diagnostic Fails | Open Gaps |",
            "|---------|--------|----------|-------|-------|---------|---------|--------|-------------|-------------|-------------|------------------|-----------|",
        ]
    )
    for row in payload["profiles"]:
        latest = row.get("latest") or {}
        aggregate = row.get("aggregate") or {}
        latest_pass = row.get("latest_pass") or {}
        latest_fail = row.get("latest_fail") or {}
        aggregate_complete = bool(aggregate.get("complete"))
        display_source = aggregate_display_source(row) or latest
        gaps = display_source.get("quality_gate_failures") or display_source.get("blocking_gaps") or []
        gap_text = ", ".join(str(item) for item in gaps[:5]) if gaps else "-"
        if row.get("status") != "fail" and aggregate_complete and int(aggregate.get("partial_contributor_count") or 0) > 0:
            suffix = f"aggregate_partial_contributors={aggregate.get('partial_contributor_count')}"
            gap_text = suffix if gap_text == "-" else f"{gap_text}, {suffix}"
        if row.get("status") != "fail" and aggregate.get("complete"):
            covered = aggregate.get("covered")
            tests = aggregate.get("expected")
        else:
            covered = display_source.get("covered", 0)
            tests = display_source.get("tests", 0)
        if row.get("status") == "dry-run":
            scope = "not-executed"
            raw_gate = "not-executed"
        else:
            scope = "complete" if aggregate_complete or latest.get("complete_profile_scope") else "partial"
            raw_gate = (
                "aggregate-pass"
                if row.get("status") != "fail" and aggregate_complete and not latest.get("raw_quality_gate_passed")
                else latest.get("raw_quality_gate_passed")
            )
        displayed_run_id = display_source.get("run_id") or latest.get("run_id")
        lines.append(
            f"| `{row['profile_id']}` | `{md_value(displayed_run_id)}` | "
            f"`{md_value(raw_gate)}` | "
            f"`{md_value(scope)}` | "
            f"`{md_value(display_source.get('maturity_score'))}` | "
            f"`{covered}/{tests}` | `{display_source.get('partial', 0)}` | "
            f"`{display_source.get('missed', 0)}` | `{display_source.get('execution_failed', 0)}` | "
            f"`{md_value(latest_pass.get('run_id'))}` | `{md_value(latest_fail.get('run_id'))}` | "
            f"`{row.get('diagnostic_failing_artifacts', 0)}` | {gap_text} |"
        )

    lines.extend(["", "## Contradiction Hints", ""])
    if payload["contradictions"]:
        for item in payload["contradictions"]:
            lines.append(f"- `{item['roadmap']}` `{item['profile_id']}`: {item['message']}")
    else:
        lines.append("No pass/fail ordering hints found.")

    lines.extend(
        [
            "",
            "## Manual Claim Review",
            "",
            "Structured review queue for dispatch claims that require manual launch",
            "or operator-provided environment before they can be closed.",
            "",
        ]
    )
    review = payload.get("manual_claim_review") or []
    if review:
        lines.extend(
            [
                "| Entity | Package | Generated Status | Manual Wording | Owner | Missing Env | Action | Prompt | Location | Snippet |",
                "|--------|---------|------------------|----------------|-------|-------------|--------|--------|----------|---------|",
            ]
        )
        for item in review:
            snippet = str(item.get("snippet") or "").replace("|", "\\|")
            missing_env = item.get("missing_env")
            missing_env_text = (
                ", ".join(str(value) for value in missing_env)
                if isinstance(missing_env, list)
                else str(missing_env or "-")
            )
            owner = str(item.get("owner") or "-").replace("|", "\\|")
            action = str(item.get("action") or "-").replace("|", "\\|")
            prompt_path = str(item.get("prompt_path") or "-").replace("|", "\\|")
            lines.append(
                f"| `{item.get('kind')}:{item.get('id')}` | `{item.get('package_id') or '-'}` | `{item.get('generated_status')}` | "
                f"`{item.get('polarity')}` | `{owner}` | `{missing_env_text or '-'}` | {action} | "
                f"`{prompt_path}` | `{item.get('doc')}:{item.get('line')}` | {snippet} |"
            )
    else:
        lines.append("No manual claim review prompts found in configured docs.")
    lines.append("")
    return "\n".join(lines)


def markdown_summary_matches_payload(markdown: str, payload: dict[str, Any]) -> bool:
    source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    expected_artifacts = f"- Artifacts read: `{source.get('artifact_count')}`"
    expected_profiles = f"- Profiles found: `{source.get('profile_count')}`"
    return expected_artifacts in markdown and expected_profiles in markdown


def source_summary_matches_payload(payload: dict[str, Any]) -> bool:
    source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    source_profiles = source.get("profiles")
    profile_rows = payload.get("profiles")
    if not isinstance(source_profiles, list) or not isinstance(profile_rows, list):
        return False
    row_profile_ids = [row.get("profile_id") for row in profile_rows if isinstance(row, dict)]
    if len(row_profile_ids) != len(profile_rows):
        return False
    if source_profiles != sorted(source_profiles) or len(set(source_profiles)) != len(source_profiles):
        return False
    return (
        source.get("profile_count") == len(source_profiles)
        and source.get("profile_count") == len(row_profile_ids)
        and sorted(source_profiles) == sorted(row_profile_ids)
    )


def roadmap_keys_match_rules(payload: dict[str, Any]) -> bool:
    roadmaps = payload.get("roadmaps")
    if not isinstance(roadmaps, list):
        return False
    keys = [roadmap.get("key") for roadmap in roadmaps if isinstance(roadmap, dict)]
    if len(keys) != len(roadmaps):
        return False
    expected_keys = [rule.key for rule in ROADMAPS]
    return keys == expected_keys and len(set(keys)) == len(keys)


def roadmap_rows_are_well_formed(payload: dict[str, Any]) -> bool:
    roadmaps = payload.get("roadmaps")
    if not isinstance(roadmaps, list):
        return False
    required_fields = {
        "key",
        "title",
        "owner_area",
        "status",
        "required_passes",
        "note",
        "profiles",
        "static_evidence",
    }
    for row in roadmaps:
        if not isinstance(row, dict) or not required_fields.issubset(row):
            return False
        if row.get("status") not in ROADMAP_STATUSES:
            return False
        if not isinstance(row.get("profiles"), list):
            return False
        if not isinstance(row.get("static_evidence"), list):
            return False
        if not isinstance(row.get("required_passes"), int) or row.get("required_passes") < 1:
            return False
        for field in ("key", "title", "owner_area", "note"):
            if not isinstance(row.get(field), str):
                return False
    return True


def profile_aggregate_is_well_formed(aggregate: object) -> bool:
    if not isinstance(aggregate, dict):
        return False
    if not isinstance(aggregate.get("complete"), bool):
        return False
    for field in ("covered", "raw_gate_failures", "partial_contributor_count"):
        if not isinstance(aggregate.get(field), int) or aggregate.get(field) < 0:
            return False
    expected = aggregate.get("expected")
    if expected is not None and (not isinstance(expected, int) or expected < 0):
        return False
    for field in ("covered_test_ids", "partial_contributor_ids"):
        if not isinstance(aggregate.get(field), list):
            return False
    latest_raw_gate_pass = aggregate.get("latest_raw_gate_pass")
    if latest_raw_gate_pass is not None and not isinstance(latest_raw_gate_pass, dict):
        return False
    return True


def profile_rows_are_well_formed(payload: dict[str, Any]) -> bool:
    profiles = payload.get("profiles")
    if not isinstance(profiles, list):
        return False
    required_fields = {
        "profile_id",
        "status",
        "latest",
        "latest_pass",
        "latest_fail",
        "latest_diagnostic_fail",
        "best_pass",
        "aggregate",
        "passing_artifacts",
        "failing_artifacts",
        "diagnostic_failing_artifacts",
        "consecutive_latest_passes",
    }
    for row in profiles:
        if not isinstance(row, dict) or not required_fields.issubset(row):
            return False
        if not isinstance(row.get("profile_id"), str) or not row.get("profile_id"):
            return False
        if row.get("status") not in PROFILE_STATUSES:
            return False
        for field in ("latest", "latest_pass", "latest_fail", "latest_diagnostic_fail", "best_pass"):
            if row.get(field) is not None and not isinstance(row.get(field), dict):
                return False
        if not profile_aggregate_is_well_formed(row.get("aggregate")):
            return False
        for field in (
            "passing_artifacts",
            "failing_artifacts",
            "diagnostic_failing_artifacts",
            "consecutive_latest_passes",
        ):
            if not isinstance(row.get(field), int) or row.get(field) < 0:
                return False
    return True


def write_outputs(payload: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not source_summary_matches_payload(payload):
        raise ValueError("validation roadmap scorecard source summary does not match payload profiles")
    if not roadmap_keys_match_rules(payload):
        raise ValueError("validation roadmap scorecard roadmap keys do not match configured rules")
    if not roadmap_rows_are_well_formed(payload):
        raise ValueError("validation roadmap scorecard roadmap rows are malformed")
    if not profile_rows_are_well_formed(payload):
        raise ValueError("validation roadmap scorecard profile rows are malformed")
    markdown = render_markdown(payload)
    if not markdown_summary_matches_payload(markdown, payload):
        raise ValueError("validation roadmap scorecard markdown summary does not match payload source")
    (output_dir / "validation_roadmap_scorecard.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "validation_roadmap_scorecard.md").write_text(
        markdown.rstrip() + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", default=str(DEFAULT_RUNS_DIR))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runs_dir = Path(args.runs_dir)
    output_dir = Path(args.output_dir)
    reports = load_reports(runs_dir)
    payload = build_payload(reports, runs_dir)
    write_outputs(payload, output_dir)
    print(
        f"wrote {output_dir / 'validation_roadmap_scorecard.md'} and "
        f"{output_dir / 'validation_roadmap_scorecard.json'} "
        f"from {len(reports)} artifacts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
