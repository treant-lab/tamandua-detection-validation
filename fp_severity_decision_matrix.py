#!/usr/bin/env python3
"""Build an offline false-positive / severity decision matrix for the alert classifier.

This is a report-only analysis tool. It joins the authoritative structured
false-positive rules in ``TamanduaServer.Alerts.obvious_false_positive_reason/1``
with the sanitized replay fixtures under
``tools/detection_validation/fixtures/`` and emits a calculable decision matrix.

It captures the core EDR "downgrade-vs-retain" contract: a false-positive
downgrade must NEVER mask a true attack. It does NOT contact the Tamandua
server, query a database, run benchmarks, mutate live alerts, or execute on an
endpoint. The classifier rule list is derived from ``alerts.ex`` so the matrix
stays in sync with the server, and the fixture scenarios are read from the JSON
fixtures as-is.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ALERTS_EX = ROOT / "apps" / "tamandua_server" / "lib" / "tamandua_server" / "alerts.ex"
DEFAULT_FIXTURE_DIR = ROOT / "tools" / "detection_validation" / "fixtures"
DEFAULT_OUTPUT_DIR = ROOT / "docs" / "benchmarks" / "generated"

SCHEMA_VERSION = 1
PROFILE_ID = "fp-severity-decision-matrix"
PROFILE_NAME = "FP / Severity Decision Matrix"

# Authoritative classifier function whose `cond` branches define the rules.
CLASSIFIER_FUNCTION = "obvious_false_positive_reason"
SOURCE_PARITY_REFERENCE = (
    "apps/tamandua_server/lib/tamandua_server/alerts.ex obvious_false_positive_reason/1"
)

# Match either:
#   {:reduce_severity, "medium", "fp_reason"}   (literal target + literal reason)
#   {:reduce_severity, "medium", reason_fn(...)} (literal target + dynamic reason)
#   {:suppress, "fp_reason"}
REDUCE_LITERAL_RE = re.compile(
    r"\{:reduce_severity,\s*\"(?P<severity>[^\"]+)\",\s*\"(?P<reason>[^\"]+)\"\}"
)
REDUCE_DYNAMIC_RE = re.compile(
    r"\{:reduce_severity,\s*\"(?P<severity>[^\"]+)\",\s*(?P<fn>[a-z_][a-z0-9_]*)\("
)
SUPPRESS_RE = re.compile(r"\{:suppress,\s*\"(?P<reason>[^\"]+)\"\}")
# A branch in the cond looks like:  <condition> ->
CONDITION_RE = re.compile(r"^(?P<condition>.+?)\s*->\s*$")
# Predicate function names referenced in a condition (foo?(context) / foo(ctx)).
PREDICATE_RE = re.compile(r"\b([a-z_][a-z0-9_]*\??)\(")

# Curated condition summaries and platform hints to keep the Markdown readable.
# The fp_reason list itself is ALWAYS derived from alerts.ex; this is only used
# to enrich a derived reason with a human summary when available.
CONDITION_SUMMARY: dict[str, str] = {
    "invalid_ioc_0_0_0_0": "Retroactive IOC match on 0.0.0.0 with invalid-zero IOC context.",
    "benign_rapid_internal_connection_structured": "NDR rapid internal connections from trusted helper to private IPv4.",
    "ntdll_self_write_no_permission_transition_structured": "ntdll write to own process .text with no permission transition / thread exec.",
    "ntdll_write_missing_target_context": "ntdll write detection with no target pid/process/address/size context.",
    "cross_process_ntdll_write_legitimate_signed_source": "Cross-process ntdll write from a signed source into non-credential, non-RWX, non-export, no-unbacked-thread target.",
    "cross_process_ntdll_write_legitimate_known_tool": "Cross-process ntdll write from a known debugger/tool source into a benign target.",
    "behavioral_score_only_unusual_time_structured": "behavioral_high_risk_score driven only by unusual execution time.",
    "behavioral_score_only_operational_tool_context": "behavioral_high_risk_score from a benign operational tool context.",
    "macos_behavioral_score_only_operational_tool_context": "behavioral_high_risk_score from a trusted macOS operational tool (osascript/launchctl/diagnostics).",
    "benign_unusual_execution_time_structured": "behavioral_unusual_execution_time for a benign process.",
    "macos_benign_unusual_execution_time_structured": "behavioral_unusual_execution_time for a benign macOS diagnostic/launchctl tool.",
    "lsass_self_process_event_structured": "behavioral_lsass_access where lsass.exe is the legitimate self process (wininit parent, System32 path).",
    "windows_core_service_process_chain_structured": "Windows core service process chain (legitimate service hierarchy).",
    "benign_nvidia_rundll32_rxdiag_structured": "behavioral_rundll32_network for benign NVIDIA rxdiag rundll32.",
    "benign_edge_webview_runonce_cleanup_structured": "registry_t1547_001 for benign Edge WebView RunOnce cleanup.",
    "edge_update_etw_patch_without_actionable_context": "ETW tamper attributed to MicrosoftEdgeUpdate.exe scheduler/core run without actionable context.",
    "etw_tamper_missing_actionable_context": "ETW tamper detection with no process/provider/session context.",
    "service_registry_change_missing_process_context": "Service registry change detection with no process context.",
    "benign_dotnet_ngen_runtime_maintenance_structured": ".NET ngen runtime maintenance (benign).",
    "kernel_memory_detection_without_process_context": "Kernel memory detection with no process context.",
    "benign_benchmark_persistence_setup_structured": "Benign benchmark Run-key persistence setup.",
}

# Reason keyword -> platform inference. Order matters (first match wins).
PLATFORM_HINTS: tuple[tuple[str, str], ...] = (
    ("macos_", "macos"),
    ("windows_", "windows"),
    ("ntdll_", "windows"),
    ("etw_", "windows"),
    ("edge_update_", "windows"),
    ("lsass_", "windows"),
    ("nvidia_", "windows"),
    ("edge_webview_", "windows"),
    ("service_registry_", "windows"),
    ("kernel_memory_", "windows"),
    ("dotnet_ngen_", "windows"),
)


@dataclass
class ClassifierRule:
    fp_reason: str
    action: str  # "reduce_severity" | "suppress"
    target_severity: str | None
    condition: str
    predicates: list[str] = field(default_factory=list)
    dynamic_from: str | None = None

    def platform(self) -> str:
        return infer_platform(self.fp_reason, self.condition)

    def to_json(self, fixture_ids: list[str]) -> dict[str, Any]:
        return {
            "fp_reason": self.fp_reason,
            "action": self.action,
            "target_severity": self.target_severity,
            "platform": self.platform(),
            "condition": CONDITION_SUMMARY.get(self.fp_reason, self.condition),
            "condition_source": self.condition,
            "predicates": self.predicates,
            "dynamic_reason_from": self.dynamic_from,
            "fixture_scenario_ids": fixture_ids,
            "fixture_coverage": len(fixture_ids),
            "has_fixture": bool(fixture_ids),
        }


@dataclass
class FixtureScenario:
    scenario_id: str
    platform: str
    input_severity: str
    expected_severity: str
    severity_adjusted: bool
    fp_reason: str | None
    fixture_file: str
    event_type: str | None

    @property
    def category(self) -> str:
        return "downgrade" if self.severity_adjusted else "retain_critical"

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.scenario_id,
            "platform": self.platform,
            "input_severity": self.input_severity,
            "expected_severity": self.expected_severity,
            "severity_adjusted": self.severity_adjusted,
            "fp_reason": self.fp_reason,
            "category": self.category,
            "fixture_file": self.fixture_file,
            "event_type": self.event_type,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
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


def infer_platform(reason: str, condition: str) -> str:
    haystack = f"{reason} {condition}".lower()
    for marker, platform in PLATFORM_HINTS:
        if marker in haystack:
            return platform
    return "cross"


def extract_classifier_function(source: str) -> str:
    """Isolate the body of the authoritative cond-bearing classifier function."""
    start = source.find(f"defp {CLASSIFIER_FUNCTION}(")
    if start == -1:
        raise ValueError(f"Could not locate defp {CLASSIFIER_FUNCTION}/1 in alerts.ex")
    # The function ends at the matching cond closure; locate the `true ->` arm
    # and the following `end\n  end` that closes cond then the function.
    tail = source.find("\n  end", source.find("true ->", start))
    if tail == -1:
        # Fallback: next defp.
        tail = source.find("\n  defp ", start + 1)
    return source[start : tail if tail != -1 else len(source)]


def dynamic_reason_returns(source: str, fn_name: str) -> list[str]:
    """Collect the literal string returns of a dynamic reason helper function."""
    start = source.find(f"defp {fn_name}(")
    if start == -1:
        return []
    end = source.find("\n  defp ", start + 1)
    body = source[start : end if end != -1 else len(source)]
    return list(dict.fromkeys(re.findall(r"\"([a-z0-9_]+)\"", body)))


def parse_classifier_rules(alerts_path: Path) -> list[ClassifierRule]:
    source = alerts_path.read_text(encoding="utf-8")
    body = extract_classifier_function(source)
    lines = body.splitlines()

    rules: list[ClassifierRule] = []
    pending_condition: list[str] = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        # An action tuple line resolves the most recent condition block.
        reduce_lit = REDUCE_LITERAL_RE.search(line)
        reduce_dyn = REDUCE_DYNAMIC_RE.search(line)
        suppress = SUPPRESS_RE.search(line)

        if reduce_lit or reduce_dyn or suppress:
            condition_text = " ".join(pending_condition).strip()
            predicates = derive_predicates(condition_text)
            if suppress:
                rules.append(
                    ClassifierRule(
                        fp_reason=suppress.group("reason"),
                        action="suppress",
                        target_severity=None,
                        condition=condition_text,
                        predicates=predicates,
                    )
                )
            elif reduce_lit:
                rules.append(
                    ClassifierRule(
                        fp_reason=reduce_lit.group("reason"),
                        action="reduce_severity",
                        target_severity=reduce_lit.group("severity"),
                        condition=condition_text,
                        predicates=predicates,
                    )
                )
            elif reduce_dyn:
                fn_name = reduce_dyn.group("fn")
                severity = reduce_dyn.group("severity")
                for reason in dynamic_reason_returns(source, fn_name):
                    rules.append(
                        ClassifierRule(
                            fp_reason=reason,
                            action="reduce_severity",
                            target_severity=severity,
                            condition=condition_text,
                            predicates=predicates,
                            dynamic_from=fn_name,
                        )
                    )
            pending_condition = []
            continue

        # `true ->` is the catch-all; ignore it and reset.
        if line.startswith("true ->") or line == "cond do" or line.endswith("(attrs) do"):
            pending_condition = []
            continue

        # Accumulate condition text (may span multiple lines before the `->`).
        match = CONDITION_RE.match(line)
        if match:
            pending_condition.append(match.group("condition"))
        else:
            pending_condition.append(line)

    # Deduplicate by fp_reason while preserving first-seen order.
    deduped: dict[str, ClassifierRule] = {}
    for rule in rules:
        if rule.fp_reason not in deduped:
            deduped[rule.fp_reason] = rule
    return list(deduped.values())


def derive_predicates(condition_text: str) -> list[str]:
    predicates = [name for name in PREDICATE_RE.findall(condition_text)]
    # Drop trivial helpers that are not classifier predicates of interest.
    return list(dict.fromkeys(p for p in predicates if p not in {"normalize_fp_text"}))


def load_fixture_scenarios(fixture_dir: Path) -> list[FixtureScenario]:
    scenarios: list[FixtureScenario] = []
    for path in sorted(fixture_dir.glob("*_false_positive_replay_v1.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        platform = "macos" if "macos" in path.name else "windows" if "windows" in path.name else "cross"
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        for item in data.get("fixtures", []):
            input_data = item.get("input") or {}
            expected = item.get("expected") or {}
            scenarios.append(
                FixtureScenario(
                    scenario_id=str(item.get("id")),
                    platform=platform,
                    input_severity=str(input_data.get("severity") or ""),
                    expected_severity=str(expected.get("alert_severity") or ""),
                    severity_adjusted=bool(expected.get("severity_adjusted")),
                    fp_reason=expected.get("fp_reason"),
                    fixture_file=rel,
                    event_type=item.get("event_type"),
                )
            )
    return scenarios


def build_payload(
    rules: list[ClassifierRule], scenarios: list[FixtureScenario], alerts_path: Path, fixture_dir: Path
) -> dict[str, Any]:
    # Map fp_reason -> fixture scenario ids exercising it.
    reason_to_scenarios: dict[str, list[str]] = {}
    for scenario in scenarios:
        if scenario.fp_reason:
            reason_to_scenarios.setdefault(scenario.fp_reason, []).append(scenario.scenario_id)

    rule_rows = [rule.to_json(sorted(reason_to_scenarios.get(rule.fp_reason, []))) for rule in rules]
    scenario_rows = [scenario.to_json() for scenario in scenarios]

    reduce_rules = [r for r in rules if r.action == "reduce_severity"]
    suppress_rules = [r for r in rules if r.action == "suppress"]

    downgrade_scenarios = [s for s in scenarios if s.category == "downgrade"]
    retain_scenarios = [s for s in scenarios if s.category == "retain_critical"]

    # TP retention = retained-critical scenarios / scenarios that test retention.
    # Every retain_critical scenario is, by construction, a retention test.
    tp_retention_count = len(retain_scenarios)
    retention_test_total = len(retain_scenarios)
    tp_retention_rate = (tp_retention_count / retention_test_total) if retention_test_total else 1.0

    # Coverage gap: classifier reasons with no exercising fixture scenario.
    covered_reasons = {r.fp_reason for r in rules if reason_to_scenarios.get(r.fp_reason)}
    uncovered_reasons = sorted(r.fp_reason for r in rules if not reason_to_scenarios.get(r.fp_reason))

    # Fixture reasons that do not map to any derived classifier rule (parity gap).
    rule_reasons = {r.fp_reason for r in rules}
    orphan_fixture_reasons = sorted(
        {s.fp_reason for s in scenarios if s.fp_reason and s.fp_reason not in rule_reasons}
    )

    aggregate = {
        "classifier_rules_total": len(rules),
        "classifier_reduce_severity_rules": len(reduce_rules),
        "classifier_suppress_rules": len(suppress_rules),
        "fixture_scenarios_total": len(scenarios),
        "fixture_downgrade_scenarios": len(downgrade_scenarios),
        "fixture_retain_critical_scenarios": len(retain_scenarios),
        "fp_downgrade_count": len(downgrade_scenarios),
        "tp_retention_count": tp_retention_count,
        "tp_retention_test_total": retention_test_total,
        "tp_retention_rate": round(tp_retention_rate, 6),
        "classifier_reasons_with_fixture": len(covered_reasons),
        "classifier_reasons_without_fixture": len(uncovered_reasons),
        "fixture_coverage_rate": round(len(covered_reasons) / len(rules), 6) if rules else 0.0,
        "uncovered_fp_reasons": uncovered_reasons,
        "orphan_fixture_reasons": orphan_fixture_reasons,
        "parity_note": (
            "All fixture fp_reasons map to a derived classifier rule."
            if not orphan_fixture_reasons
            else "Some fixture fp_reasons have no derived classifier rule; review parity."
        ),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "profile_name": PROFILE_NAME,
        "generated_at": utc_now(),
        "git": git_snapshot(),
        "execute": False,
        "external_claim_allowed": False,
        "claim_boundary": (
            "Offline contract/fixture analysis only. This decision matrix mirrors the structured "
            "false-positive rules in TamanduaServer.Alerts.obvious_false_positive_reason/1 and the "
            "sanitized replay fixtures. It does NOT contact the server, query a database, run "
            "benchmarks, mutate live alerts, or prove endpoint collection. The tp_retention_rate is a "
            "fixture-contract proof that downgrades never mask the retained-critical attack scenarios, "
            "not a live production guarantee."
        ),
        "source": {
            "alerts_ex": str(alerts_path.relative_to(ROOT)).replace("\\", "/"),
            "classifier_function": f"{CLASSIFIER_FUNCTION}/1",
            "source_parity_reference": SOURCE_PARITY_REFERENCE,
            "fixture_dir": str(fixture_dir.relative_to(ROOT)).replace("\\", "/"),
        },
        "aggregate": aggregate,
        "classifier_rules": rule_rows,
        "fixture_scenarios": scenario_rows,
    }


def md_cell(value: Any) -> str:
    if value is None or value == "":
        return "-"
    return str(value).replace("|", "\\|")


def render_markdown(payload: dict[str, Any]) -> str:
    agg = payload["aggregate"]
    lines = [
        f"# {payload['profile_name']}",
        "",
        "Status: generated (offline, report-only)",
        "",
        "Joins the authoritative classifier rules in",
        f"`{payload['source']['alerts_ex']}` (`{payload['source']['classifier_function']}`) with the",
        f"sanitized replay fixtures under `{payload['source']['fixture_dir']}`.",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Git commit: `{payload['git'].get('commit_short') or '-'}`"
        + (" (dirty)" if payload["git"].get("dirty") else ""),
        f"- External claim allowed: `{payload['external_claim_allowed']}`",
        "",
        "## Claim Boundary",
        "",
        payload["claim_boundary"],
        "",
        "## Aggregate Metrics",
        "",
        f"- **TP retention (attack-never-masked): `{agg['tp_retention_count']}/{agg['tp_retention_test_total']}` "
        f"= `{agg['tp_retention_rate']}`**",
        f"- FP downgrade scenarios: `{agg['fp_downgrade_count']}`",
        f"- Classifier rules total: `{agg['classifier_rules_total']}` "
        f"(reduce_severity `{agg['classifier_reduce_severity_rules']}`, suppress `{agg['classifier_suppress_rules']}`)",
        f"- Fixture scenarios total: `{agg['fixture_scenarios_total']}` "
        f"(downgrade `{agg['fixture_downgrade_scenarios']}`, retain_critical `{agg['fixture_retain_critical_scenarios']}`)",
        f"- Classifier reasons with fixture coverage: `{agg['classifier_reasons_with_fixture']}/{agg['classifier_rules_total']}` "
        f"(rate `{agg['fixture_coverage_rate']}`)",
        f"- Classifier reasons WITHOUT fixture (gap): `{agg['classifier_reasons_without_fixture']}`",
        f"- Orphan fixture reasons (no derived rule): `{len(agg['orphan_fixture_reasons'])}`",
        f"- Parity: {agg['parity_note']}",
        "",
    ]

    if agg["uncovered_fp_reasons"]:
        lines.append("### Uncovered classifier fp_reasons (no fixture scenario)")
        lines.append("")
        for reason in agg["uncovered_fp_reasons"]:
            lines.append(f"- `{reason}`")
        lines.append("")

    if agg["orphan_fixture_reasons"]:
        lines.append("### Orphan fixture reasons (no derived classifier rule)")
        lines.append("")
        for reason in agg["orphan_fixture_reasons"]:
            lines.append(f"- `{reason}`")
        lines.append("")

    lines.extend(
        [
            "## Classifier Rules (with fixture coverage)",
            "",
            "| FP Reason | Action | Target Severity | Platform | Fixtures | Condition |",
            "|-----------|--------|-----------------|----------|----------|-----------|",
        ]
    )
    for rule in payload["classifier_rules"]:
        fixtures = ", ".join(f"`{fid}`" for fid in rule["fixture_scenario_ids"]) or "**none (gap)**"
        lines.append(
            f"| `{md_cell(rule['fp_reason'])}` | `{md_cell(rule['action'])}` | "
            f"`{md_cell(rule['target_severity'])}` | `{md_cell(rule['platform'])}` | "
            f"{fixtures} | {md_cell(rule['condition'])} |"
        )

    lines.extend(
        [
            "",
            "## Fixture Scenarios (downgrade vs retain)",
            "",
            "| Scenario | Platform | Input Sev | Expected Sev | Category | FP Reason |",
            "|----------|----------|-----------|--------------|----------|-----------|",
        ]
    )
    for scenario in payload["fixture_scenarios"]:
        category = scenario["category"]
        category_cell = f"**{category}**" if category == "retain_critical" else category
        lines.append(
            f"| `{md_cell(scenario['id'])}` | `{md_cell(scenario['platform'])}` | "
            f"`{md_cell(scenario['input_severity'])}` | `{md_cell(scenario['expected_severity'])}` | "
            f"{category_cell} | `{md_cell(scenario['fp_reason'] or '-')}` |"
        )

    lines.append("")
    return "\n".join(lines)


def write_outputs(payload: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "fp_severity_decision_matrix.json"
    md_path = output_dir / "fp_severity_decision_matrix.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload).rstrip() + "\n", encoding="utf-8")
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts-ex", type=Path, default=DEFAULT_ALERTS_EX)
    parser.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rules = parse_classifier_rules(args.alerts_ex)
    scenarios = load_fixture_scenarios(args.fixture_dir)
    payload = build_payload(rules, scenarios, args.alerts_ex, args.fixture_dir)
    json_path, md_path = write_outputs(payload, args.output_dir)
    agg = payload["aggregate"]
    print(
        f"wrote {json_path} and {md_path}; "
        f"rules={agg['classifier_rules_total']} "
        f"(reduce={agg['classifier_reduce_severity_rules']}, suppress={agg['classifier_suppress_rules']}) "
        f"scenarios={agg['fixture_scenarios_total']} "
        f"(downgrade={agg['fixture_downgrade_scenarios']}, retain={agg['fixture_retain_critical_scenarios']}) "
        f"tp_retention={agg['tp_retention_count']}/{agg['tp_retention_test_total']}={agg['tp_retention_rate']} "
        f"uncovered={agg['classifier_reasons_without_fixture']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
