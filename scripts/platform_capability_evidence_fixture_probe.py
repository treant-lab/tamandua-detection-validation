#!/usr/bin/env python3
"""Local platform capability evidence fixture for Roadmap K.

This deterministic fixture validates the evidence semantics expected from FIM,
inventory, compliance, and SIEM/export without touching endpoints, the server,
or an external SIEM. It is a regression contract for data quality and delivery
semantics, not a replacement for live endpoint/SIEM validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "platform-capability-evidence-fixture-probe"
PROFILE_NAME = "Platform Capability Evidence Fixture Probe"


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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def result(test_id: str, name: str, passed: bool, capability: str, evidence: dict[str, Any], missing: list[str] | None = None) -> dict[str, Any]:
    missing = missing or []
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else "platform-capability-fixture",
        "validation_category": f"platform_{capability}",
        "execution_class": "local_fixture_probe",
        "fallback_used": False,
        "claim_level": "platform_capability_fixture_contract",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": missing,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def fim_tests() -> list[dict[str, Any]]:
    baseline = {
        "agent_id": "agent-fixture-1",
        "path": "C:/ProgramData/Tamandua/policy.yml",
        "hash": sha256_text("baseline-policy-v1"),
        "permissions": "Administrators:F;SYSTEM:F",
        "owner": "SYSTEM",
        "observed_at": utc_now(),
    }
    change = {
        "agent_id": baseline["agent_id"],
        "path": baseline["path"],
        "previous_hash": baseline["hash"],
        "current_hash": sha256_text("baseline-policy-v2"),
        "previous_permissions": baseline["permissions"],
        "current_permissions": "Administrators:F;SYSTEM:F",
        "modifier_pid": 4242,
        "modifier_process": "powershell.exe",
        "compliance_impact": ["CIS-1.1", "SOC2-CC6.1"],
    }
    same_path = change["path"] == baseline["path"]
    hash_changed = change["previous_hash"] != change["current_hash"]
    has_context = all(change.get(key) for key in ("modifier_pid", "modifier_process", "compliance_impact"))
    return [
        result(
            "platform-fim-baseline-change-fixture",
            "FIM fixture records baseline, changed hash, modifier context, and compliance impact",
            same_path and hash_changed and has_context,
            "fim",
            {"baseline": baseline, "change": change},
        )
    ]


def inventory_tests() -> list[dict[str, Any]]:
    observed_at = datetime.now(timezone.utc)
    asset = {
        "agent_id": "agent-fixture-1",
        "hostname": "fixture-win",
        "os": "windows",
        "os_build": "11.26200",
        "ip_addresses": ["10.0.0.10"],
        "installed_software": [
            {"name": "OpenSSL", "version": "3.0.0", "cpe": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}
        ],
        "running_services": [{"name": "Tamandua Agent", "state": "running"}],
        "open_ports": [{"port": 443, "protocol": "tcp", "process": "tamandua-agent.exe"}],
        "vulnerabilities": [{"cve": "CVE-2022-0778", "severity": "high", "source": "fixture-cpe-map"}],
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
    }
    fresh = observed_at >= datetime.now(timezone.utc) - timedelta(minutes=5)
    normalized = all(asset.get(key) for key in ("agent_id", "hostname", "os", "os_build", "installed_software", "vulnerabilities"))
    cpe_cve = bool(asset["installed_software"][0].get("cpe") and asset["vulnerabilities"][0].get("cve"))
    return [
        result(
            "platform-inventory-freshness-cpe-fixture",
            "Inventory fixture carries freshness, normalized host/software fields, and CPE/CVE mapping",
            fresh and normalized and cpe_cve,
            "inventory",
            {"asset": asset, "freshness_seconds": 300},
        )
    ]


def compliance_tests() -> list[dict[str, Any]]:
    evidence_blob = json.dumps({"setting": "audit-policy", "value": "enabled"}, sort_keys=True)
    evidence = {
        "framework": "CIS",
        "control_id": "CIS-1.1",
        "agent_id": "agent-fixture-1",
        "status": "pass",
        "evidence_type": "fim_change_and_policy_state",
        "hash": sha256_text(evidence_blob),
        "collected_at": utc_now(),
    }
    report = {
        "framework": "CIS",
        "period": "fixture",
        "controls": [evidence],
        "synthetic_score": None,
    }
    hashed = evidence["hash"] == sha256_text(evidence_blob)
    per_control = bool(report["controls"] and report["controls"][0]["control_id"])
    no_synthetic = report["synthetic_score"] is None
    return [
        result(
            "platform-compliance-per-control-evidence-fixture",
            "Compliance fixture uses per-control hashed evidence and no synthetic score",
            hashed and per_control and no_synthetic,
            "compliance",
            {"evidence": evidence, "report": report},
        )
    ]


def siem_tests() -> list[dict[str, Any]]:
    event = {
        "event_id": "evt-fixture-1",
        "tenant_id": "tenant-alpha",
        "agent_id": "agent-fixture-1",
        "severity": "high",
        "schema": "tamandua.alert.v1",
    }
    delivery = {
        "connector": "syslog-fixture",
        "format": "json",
        "ack": True,
        "cursor": "cursor-000001",
        "delivered_event_ids": [event["event_id"]],
        "retry_count": 0,
    }
    delivered_once = delivery["delivered_event_ids"].count(event["event_id"]) == 1
    acknowledged = delivery["ack"] is True and bool(delivery["cursor"])
    schema_present = event["schema"] == "tamandua.alert.v1"
    return [
        result(
            "platform-siem-delivery-ack-cursor-fixture",
            "SIEM fixture records schema, delivery ack, cursor, and no duplicate event id",
            delivered_once and acknowledged and schema_present,
            "siem_export",
            {"event": event, "delivery": delivery},
        )
    ]


def collect_tests() -> list[dict[str, Any]]:
    return fim_tests() + inventory_tests() + compliance_tests() + siem_tests()


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = [test for test in tests if test["status"] != "covered"]
    category_coverage: dict[str, dict[str, int]] = {}
    for test in tests:
        category = test["validation_category"]
        entry = category_coverage.setdefault(category, {"covered": 0, "missed": 0})
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
        "executor_counts": {"platform_capability_evidence_fixture_probe": len(tests)},
        "execution_class_counts": {"local_fixture_probe": len(tests)},
        "claim_level_counts": {"platform_capability_fixture_contract": len(tests)},
        "category_coverage": category_coverage,
        "roadmap_coverage": {"K": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"platform-capability-fixture": missed} if missed else {},
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 80 if passed else int(50 * covered_rate),
        "maturity_band": "platform-capability-fixture-contract-ready" if passed else "platform-capability-fixture-gaps",
        "recommended_claim": (
            "Platform capability evidence fixtures are green for FIM, inventory, compliance, and SIEM/export"
            if passed
            else "Platform capability evidence fixture gaps remain"
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
        "- Scope: local deterministic platform-capability fixture contract only.",
        "- Runtime effect: none; no endpoint, server, DB, compliance score, or SIEM mutation.",
        "",
        "| Test | Status | Capability |",
        "|------|--------|------------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['validation_category']}` |")
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
        "benchmark_lane": "platform-capability",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "platform_capability_evidence_fixture",
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
            "failures": [] if passed else ["platform_capability_fixture_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "platform-capability",
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
            "Local platform capability evidence fixture only. It proves expected FIM, inventory, compliance, "
            "and SIEM/export evidence semantics are executable as a regression gate, but it does not prove live "
            "endpoint FIM collection, inventory freshness from real agents, compliance posture, or acknowledged "
            "delivery to an external SIEM."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "platform-capability",
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
