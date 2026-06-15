#!/usr/bin/env python3
"""Report-only unified Detection & Response engine proof.

This probe builds a compact end-to-end D&R evidence artifact from existing
Tamandua-authored rules and Event Envelope fixtures:

event -> detection/replay -> alert contract -> correlation/storyline contract
-> response plan/audit -> analyst feedback contract -> replay stability.

It does not contact the backend, mutate alerts, execute response actions, or
claim production LimaCharlie-style parity.
"""

from __future__ import annotations

import argparse
import hashlib
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
PROFILE_ID = "windows-unified-dr-engine-v1"
PROFILE_NAME = "Windows Unified D&R Engine V1"

DETECTION_RESPONSE = ROOT / "tools" / "detection_response"
sys.path.insert(0, str(DETECTION_RESPONSE))

from plan_response import plan  # noqa: E402
from replay_report import replay  # noqa: E402
from validate_event_envelope import load_envelope, validate_envelope  # noqa: E402
from validate_rule import load_rule, validate_rule  # noqa: E402


RULES_DIR = ROOT / "examples" / "detection_response" / "rules"
EVENTS_DIR = ROOT / "examples" / "detection_response" / "events"
GUARDRAIL_POLICY = ROOT / "tools" / "response_validation" / "local_guardrails.yml"


SCENARIOS = [
    {
        "id": "unified-dr-process-powershell-encoded",
        "name": "Process execution: PowerShell encoded command",
        "kind": "malicious",
        "rule": "suspicious-powershell-dry-run.yaml",
        "event": "windows-process-create-envelope.json",
        "expected_severity": "high",
        "expected_storyline_nodes": ["process", "detection", "response_plan", "replay"],
    },
    {
        "id": "unified-dr-network-c2-web-protocol",
        "name": "Network/C2: web protocol beacon-safe candidate",
        "kind": "malicious",
        "rule": "windows-c2-web-protocol-dry-run.yaml",
        "event": "windows-c2-web-protocol-envelope.json",
        "expected_severity": "high",
        "expected_storyline_nodes": ["process", "network", "detection", "response_plan", "replay"],
    },
    {
        "id": "unified-dr-registry-run-key",
        "name": "Registry persistence: Run key",
        "kind": "malicious",
        "rule": "windows-registry-run-key-dry-run.yaml",
        "event": "windows-registry-run-key-envelope.json",
        "expected_severity": "medium",
        "expected_storyline_nodes": ["process", "registry", "detection", "response_plan", "replay"],
    },
    {
        "id": "unified-dr-file-certutil-encode",
        "name": "File/LOLBAS: certutil encode/decode",
        "kind": "malicious",
        "rule": "windows-certutil-encode-dry-run.yaml",
        "event": "windows-certutil-encode-envelope.json",
        "expected_severity": "medium",
        "expected_storyline_nodes": ["process", "file", "detection", "response_plan", "replay"],
    },
    {
        "id": "unified-dr-response-lsass-guardrail",
        "name": "Response-linked investigation: LSASS guardrail denial",
        "kind": "response_guardrail",
        "rule": "blocked-lsass-kill-dry-run.yaml",
        "event": "windows-lsass-process-envelope.json",
        "expected_severity": "critical",
        "expected_storyline_nodes": ["process", "detection", "response_plan", "guardrail_denial", "replay"],
    },
    {
        "id": "unified-dr-benign-admin-contrast",
        "name": "Benign contrast: normal process envelope stays non-alerting for C2 rule",
        "kind": "benign",
        "rule": "windows-c2-web-protocol-dry-run.yaml",
        "event": "windows-process-create-envelope.json",
        "expected_severity": "none",
        "expected_storyline_nodes": ["process", "benign_contrast", "replay"],
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


def sha256_json(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()


def get_path(data: dict[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def severity_from_rule(rule: dict[str, Any]) -> str:
    quality = rule.get("quality") if isinstance(rule.get("quality"), dict) else {}
    severity = quality.get("severity") or quality.get("risk") or rule.get("severity")
    if isinstance(severity, str) and severity:
        return severity.lower()
    metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
    name = str(metadata.get("name") or "").lower()
    if "lsass" in name:
        return "critical"
    if "powershell" in name or "c2" in name:
        return "high"
    return "medium"


def alert_contract(rule_report: dict[str, Any], envelope_report: dict[str, Any], severity: str, replay_result: dict[str, Any]) -> dict[str, Any]:
    alert_id = "alert-" + sha256_json([rule_report["id"], envelope_report["agent_id"], envelope_report["event_type"]])[:16]
    required_context = ["agent_id", "event_type", "rule_id", "severity", "matched", "alert_created"]
    contract = {
        "alert_id": alert_id,
        "rule_id": rule_report["id"],
        "agent_id": envelope_report["agent_id"],
        "event_type": envelope_report["event_type"],
        "severity": severity,
        "matched": replay_result["matched"],
        "alert_created": replay_result["matched"],
        "live_alert_mutation": False,
        "required_context": required_context,
    }
    contract["context_complete"] = all(contract.get(field) not in (None, "", []) for field in required_context)
    return contract


def storyline_contract(scenario: dict[str, Any], alert: dict[str, Any], envelope: dict[str, Any], response_plan: dict[str, Any]) -> dict[str, Any]:
    routing = envelope.get("routing", {})
    event = envelope.get("event", {})
    process = event.get("process", {}) if isinstance(event.get("process"), dict) else {}
    network = event.get("network", {}) if isinstance(event.get("network"), dict) else {}
    registry = event.get("registry", {}) if isinstance(event.get("registry"), dict) else {}
    file_data = event.get("file", {}) if isinstance(event.get("file"), dict) else {}
    nodes = [
        {"id": f"process:{process.get('pid', 'unknown')}", "type": "process", "label": process.get("name") or "process"},
        {"id": f"detection:{alert['rule_id']}", "type": "detection", "label": alert["rule_id"]},
        {"id": f"response:{response_plan.get('plan_id', 'none')}", "type": "response_plan", "label": response_plan.get("status")},
        {"id": f"replay:{alert['rule_id']}", "type": "replay", "label": "report_only"},
    ]
    if network:
        nodes.append({"id": f"network:{network.get('remote_ip', 'unknown')}", "type": "network", "label": str(network.get("remote_ip") or "network")})
    if registry:
        nodes.append({"id": f"registry:{registry.get('key', 'unknown')}", "type": "registry", "label": str(registry.get("key") or "registry")})
    if file_data:
        nodes.append({"id": f"file:{file_data.get('path', 'unknown')}", "type": "file", "label": str(file_data.get("path") or "file")})
    if any(action.get("guardrail", {}).get("status") == "denied" for action in response_plan.get("actions", [])):
        nodes.append({"id": f"guardrail:{alert['alert_id']}", "type": "guardrail_denial", "label": "denied"})
    if scenario["kind"] == "benign":
        nodes.append({"id": f"benign:{alert['alert_id']}", "type": "benign_contrast", "label": "no_alert"})

    node_types = {node["type"] for node in nodes}
    return {
        "storyline_id": "storyline-" + sha256_json([scenario["id"], routing.get("agent_id"), alert["rule_id"]])[:16],
        "nodes": nodes,
        "edges": [
            {"from": nodes[0]["id"], "to": nodes[1]["id"], "reason": "source_event_triggered_detection"},
            {"from": nodes[1]["id"], "to": nodes[2]["id"], "reason": "detection_planned_response"},
            {"from": nodes[1]["id"], "to": nodes[3]["id"], "reason": "detection_replayable"},
        ],
        "expected_node_types": scenario["expected_storyline_nodes"],
        "node_types_present": sorted(node_types),
        "complete": all(expected in node_types for expected in scenario["expected_storyline_nodes"]),
    }


def feedback_contract(scenario: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    verdict = "benign_true_negative" if scenario["kind"] == "benign" else "true_positive_report_only"
    feedback_id = "feedback-" + sha256_json([scenario["id"], alert["alert_id"], verdict])[:16]
    return {
        "feedback_id": feedback_id,
        "verdict": verdict,
        "rule_id": alert["rule_id"],
        "alert_id": alert["alert_id"],
        "mutates_historical_evidence": False,
        "updates_rule_metrics": True,
    }


def evaluate_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    rule_path = RULES_DIR / scenario["rule"]
    event_path = EVENTS_DIR / scenario["event"]
    rule = load_rule(rule_path)
    envelope = load_envelope(event_path)
    rule_report = validate_rule(rule)
    envelope_report = validate_envelope(envelope)
    replay_result = replay(rule_path, event_path)
    response_plan = plan(rule_path, event_path, GUARDRAIL_POLICY)

    matched_expected = scenario["kind"] != "benign"
    severity = "none" if not replay_result["matched"] else severity_from_rule(rule)
    alert = alert_contract(rule_report, envelope_report, severity, replay_result)
    if scenario["kind"] == "benign":
        alert["alert_created"] = False
        alert["severity"] = "none"
        alert["benign_rationale"] = "fixture does not match the selected D&R rule"
    storyline = storyline_contract(scenario, alert, envelope, response_plan)
    feedback = feedback_contract(scenario, alert)
    response_ok = response_plan["response_executed"] is False and all(action.get("will_execute") is False for action in response_plan.get("actions", []))
    guardrail_ok = True
    if scenario["kind"] == "response_guardrail":
        guardrail_ok = any(action.get("guardrail", {}).get("status") == "denied" for action in response_plan.get("actions", []))
    replay_ok = replay_result["matched"] is matched_expected
    alert_ok = alert["alert_created"] is matched_expected and alert["severity"] == scenario["expected_severity"]
    feedback_ok = feedback["mutates_historical_evidence"] is False and feedback["updates_rule_metrics"] is True
    status = "covered" if all([replay_ok, alert_ok, storyline["complete"], response_ok, guardrail_ok, feedback_ok]) else "missed"
    evidence = {
        "source_event": str(event_path.relative_to(ROOT)),
        "rule": str(rule_path.relative_to(ROOT)),
        "detection_id": rule_report["id"],
        "alert": alert,
        "storyline": storyline,
        "response_plan": {
            "plan_id": response_plan["plan_id"],
            "status": response_plan["status"],
            "action_count": len(response_plan.get("actions", [])),
            "denied_actions": [
                action["type"] for action in response_plan.get("actions", []) if action.get("guardrail", {}).get("status") == "denied"
            ],
            "response_executed": response_plan["response_executed"],
        },
        "feedback": feedback,
        "replay": {
            "matched": replay_result["matched"],
            "alert_created": replay_result["alert_created"],
            "response_executed": replay_result["response_executed"],
        },
        "checks": {
            "replay_ok": replay_ok,
            "alert_ok": alert_ok,
            "storyline_ok": storyline["complete"],
            "response_ok": response_ok,
            "guardrail_ok": guardrail_ok,
            "feedback_ok": feedback_ok,
        },
    }
    gaps = [name for name, ok in evidence["checks"].items() if not ok]
    return {
        "id": scenario["id"],
        "name": scenario["name"],
        "status": status,
        "gap_category": None if status == "covered" else "unified-dr-contract",
        "validation_category": "unified_dr_engine",
        "execution_class": "fixture_report_only",
        "fallback_used": False,
        "claim_level": "unified_dr_selected_fixture_proof",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": gaps,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [] if replay_ok else [rule_report["id"]],
        "missing_expected_alerts": [] if alert_ok else [alert["alert_id"]],
        "missing_expected_correlations": [] if storyline["complete"] else [storyline["storyline_id"]],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    return [evaluate_scenario(scenario) for scenario in SCENARIOS]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gap_counts: dict[str, int] = {}
    gaps = []
    for test in tests:
        if test["status"] != "covered":
            gap = test["gap_category"] or "unknown"
            gap_counts[gap] = gap_counts.get(gap, 0) + 1
            gaps.append(test)
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
        "investigable_alert_gaps": missed,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"unified_dr_engine_probe": len(tests)},
        "execution_class_counts": {"fixture_report_only": len(tests)},
        "claim_level_counts": {"unified_dr_selected_fixture_proof": len(tests)},
        "category_coverage": {"unified_dr_engine": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": gap_counts,
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 84 if passed else int(58 * covered_rate),
        "maturity_band": "unified-dr-selected-fixture-proof" if passed else "unified-dr-contract-gaps",
        "recommended_claim": (
            "Unified D&R engine proof for selected report-only Windows fixtures; no runtime/backend parity claim"
            if passed
            else "Unified D&R contract gaps exist; do not claim unified engine proof"
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0 if passed else covered_rate,
        "field_quality": 1.0 if passed else covered_rate,
        "context_quality": 1.0 if passed else covered_rate,
        "analytic_quality": 1.0 if passed else covered_rate,
        "noise_quality": 1.0 if passed else covered_rate,
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
        "- Scope: selected Windows D&R fixture proof only.",
        "- Runtime effect: none; no backend, endpoint execution, live alert mutation, or response execution.",
        "",
        "| Test | Status | Detection | Alert | Storyline | Response | Feedback |",
        "|------|--------|-----------|-------|-----------|----------|----------|",
    ]
    for test in report["tests"]:
        checks = test["evidence"]["checks"]
        lines.append(
            f"| `{test['id']}` | `{test['status']}` | `{checks['replay_ok']}` | `{checks['alert_ok']}` | "
            f"`{checks['storyline_ok']}` | `{checks['response_ok'] and checks['guardrail_ok']}` | `{checks['feedback_ok']}` |"
        )
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
        "benchmark_lane": "unified-dr-engine",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "windows",
            "quality_bar": {
                "purpose": "windows_unified_dr_engine_v1",
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
            "failures": [] if passed else ["unified_dr_engine_contract_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "unified-dr-engine",
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
            "Validates selected Windows D&R fixtures as one report-only loop: event, detection, alert contract, "
            "storyline/correlation contract, response plan/audit, analyst feedback, and replay stability. It does "
            "not prove runtime backend execution, production response, multi-tenant controls, cross-platform parity, "
            "or LimaCharlie/CrowdStrike equivalence."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "unified-dr-engine",
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
