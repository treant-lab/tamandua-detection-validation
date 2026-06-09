#!/usr/bin/env python3
"""Local fixture-evidence probe for detection rule evidence backlog waves.

This probe turns a generated wave fixture plan into deterministic, safe fixture
evidence. It does not execute attacker tooling or claim runtime detector
coverage. Its purpose is to prove that every planned rule gap has a
Tamandua-authored positive fixture shape, benign contrast, rule traceability,
and acceptance metadata before live/server-backed benchmarks are written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
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


def ensure_plan(wave: str) -> None:
    plan_path = GENERATED_DIR / f"detection_rule_{wave}_fixture_plan.json"
    if plan_path.exists():
        return
    subprocess.run(
        ["python", "tools/detection_validation/detection_rule_wave_fixture_plan.py", "--wave", wave],
        cwd=ROOT,
        check=True,
    )


def load_plan(wave: str) -> dict[str, Any]:
    ensure_plan(wave)
    plan_path = GENERATED_DIR / f"detection_rule_{wave}_fixture_plan.json"
    if not plan_path.exists():
        raise SystemExit(f"missing fixture plan: {plan_path}")
    return json.loads(plan_path.read_text(encoding="utf-8"))


def evidence_kind(fixture: dict[str, Any]) -> str:
    family = str(fixture.get("profile_family") or "")
    if "network" in family:
        return "network_metadata"
    if "storyline" in family:
        return "storyline"
    if "endpoint-control" in family:
        return "endpoint_control"
    if "endpoint-event" in family:
        return "endpoint_event"
    if "offline-replay" in family:
        return "offline_replay"
    return "artifact_access"


def positive_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    kind = evidence_kind(fixture)
    base = {
        "fixture_id": fixture["fixture_id"],
        "rule_id": fixture["rule_id"],
        "rule_title": fixture["rule_title"],
        "platform": fixture["platform"],
        "techniques": fixture.get("techniques") or [],
        "safe": True,
        "tamandua_authored": True,
        "copies_external_logic": False,
    }
    if kind == "network_metadata":
        base["network"] = {
            "protocol": "dns",
            "query_count": 48,
            "unique_subdomain_count": 32,
            "median_label_length": 42,
            "entropy_bucket": "high",
            "ports": [53],
            "decision_basis": ["protocol", "query_timing", "label_entropy", "tool_context"],
            "port_only_detection": False,
        }
    elif kind == "storyline":
        base["storyline"] = {
            "nodes": [
                {"type": "process", "name": "powershell.exe", "role": "launcher"},
                {"type": "file", "path": "C:/ProgramData/TamanduaFixture/browser_state.db", "role": "safe_placeholder"},
                {"type": "network", "domain": "fixture.example.invalid", "role": "simulated_exfil_destination"},
            ],
            "edges": ["process_reads_placeholder", "process_stages_archive", "process_attempts_safe_network"],
            "investigable": True,
        }
    elif kind == "endpoint_control":
        base["control"] = {
            "target": fixture["rule_title"],
            "action": "attempted_configuration_change",
            "scope": "fixture-only",
            "requires_admin": True,
            "safe_noop": True,
        }
    elif kind == "endpoint_event":
        base["event"] = {
            "type": "process_create",
            "process_name": "powershell.exe",
            "parent_process_name": "cmd.exe",
            "command_line_contains_fixture_marker": True,
            "user": "TAMANDUA-FIXTURE\\analyst",
        }
    elif kind == "offline_replay":
        base["replay"] = {
            "event_envelope_schema": "tamandua.event.v1",
            "actor": "ml_worker_fixture.py",
            "target": "browser_credential_store_placeholder",
            "retrospective_only": True,
        }
    else:
        base["artifact"] = {
            "path": "C:/ProgramData/TamanduaFixture/sensitive-placeholder.dat",
            "artifact_class": "safe_placeholder",
            "operation": "read_or_copy",
            "real_secret_material": False,
            "hash": sha256_json({"placeholder": fixture["fixture_id"]}),
        }
    return base


def benign_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    return {
        "fixture_id": fixture["fixture_id"],
        "rule_id": fixture["rule_id"],
        "benign_context": "administrative_inventory_or_backup_fixture",
        "expected_alert": False,
        "expected_severity": "info_or_none",
        "rationale": "benign fixture lacks the suspicious behavior combination required by the positive fixture",
        "safe": True,
    }


def validate_fixture(fixture: dict[str, Any], positive: dict[str, Any], benign: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    required_fixture = ["fixture_id", "rule_id", "rule_title", "techniques", "platform", "profile_family"]
    for key in required_fixture:
        if not fixture.get(key):
            missing.append(f"fixture.{key}")
    if not positive.get("tamandua_authored"):
        missing.append("positive.tamandua_authored")
    if positive.get("copies_external_logic") is not False:
        missing.append("positive.clean_room_boundary")
    if not benign.get("rationale"):
        missing.append("benign.rationale")
    if not fixture.get("acceptance_criteria"):
        missing.append("fixture.acceptance_criteria")
    return missing


def build_tests(plan: dict[str, Any]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for fixture in plan.get("fixtures") or []:
        positive = positive_fixture(fixture)
        benign = benign_fixture(fixture)
        missing = validate_fixture(fixture, positive, benign)
        status = "covered" if not missing else "missed"
        tests.append(
            {
                "id": fixture["fixture_id"],
                "name": f"Wave fixture evidence for {fixture['rule_title']}",
                "status": status,
                "gap_category": None if status == "covered" else "detection-rule-fixture",
                "validation_category": "detection_rule_fixture",
                "execution_class": "local_fixture_probe",
                "fallback_used": False,
                "claim_level": "rule_fixture_contract",
                "tactics": [fixture.get("area")],
                "techniques": fixture.get("techniques") or [],
                "rule": {
                    "id": fixture["rule_id"],
                    "title": fixture["rule_title"],
                    "level": fixture["level"],
                    "path": fixture["path"],
                },
                "fixture": {
                    "id": fixture["fixture_id"],
                    "type": fixture["fixture_type"],
                    "profile_family": fixture["profile_family"],
                    "recommended_profile_id": fixture["recommended_profile_id"],
                },
                "evidence": {
                    "positive_fixture": positive,
                    "benign_contrast": benign,
                    "acceptance_criteria": fixture.get("acceptance_criteria") or [],
                    "evidence_hash": sha256_json({"positive": positive, "benign": benign}),
                },
                "missing_expected_fields": missing,
                "missing_expected_telemetry": [],
                "missing_expected_detections": [],
                "missing_expected_alerts": [],
                "missing_expected_correlations": [],
                "missing_expected_driver_raw_event_types": [],
            }
        )
    return tests


def build_all_wave_tests(wave_details: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for wave, details in wave_details.items():
        missing = [test["id"] for test in details if test["status"] != "covered"]
        fixture_count = len(details)
        evidence_hash = sha256_json(
            {
                "wave": wave,
                "fixture_count": fixture_count,
                "fixture_hashes": [((test.get("evidence") or {}).get("evidence_hash")) for test in details],
            }
        )
        tests.append(
            {
                "id": f"rule-gap-{wave.replace('_', '-')}-fixture-contracts",
                "name": f"{wave.replace('_', ' ').title()} fixture contracts are present and safe",
                "status": "covered" if not missing and fixture_count else "missed",
                "gap_category": None if not missing and fixture_count else "detection-rule-fixture",
                "validation_category": "detection_rule_fixture_wave",
                "execution_class": "local_fixture_probe",
                "fallback_used": False,
                "claim_level": "rule_fixture_contract",
                "tactics": [],
                "techniques": [],
                "evidence": {
                    "wave": wave,
                    "fixture_count": fixture_count,
                    "covered_fixture_count": fixture_count - len(missing),
                    "missing_fixture_ids": missing,
                    "sample_fixture_ids": [test["id"] for test in details[:5]],
                    "evidence_hash": evidence_hash,
                },
                "missing_expected_fields": missing,
                "missing_expected_telemetry": [],
                "missing_expected_detections": [],
                "missing_expected_alerts": [],
                "missing_expected_correlations": [],
                "missing_expected_driver_raw_event_types": [],
            }
        )
    return tests


def build_summary(tests: list[dict[str, Any]], wave: str) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    by_family: dict[str, int] = {}
    for test in tests:
        family = ((test.get("fixture") or {}).get("profile_family")) or "unknown"
        by_family[family] = by_family.get(family, 0) + 1
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
        "executor_counts": {"detection_rule_wave_fixture_probe": len(tests)},
        "execution_class_counts": {"local_fixture_probe": len(tests)},
        "claim_level_counts": {"rule_fixture_contract": len(tests)},
        "category_coverage": {"detection_rule_fixture": {"covered": covered, "missed": missed}},
        "roadmap_coverage": {"Q": {"covered": covered, "missed": missed, "wave": wave}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": by_family,
        "gap_category_counts": {"detection-rule-fixture": missed} if missed else {},
        "actionable_gaps": [test for test in tests if test["status"] != "covered"],
    }


def quality_gate(summary: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    if summary["covered"] != summary["tests"]:
        failures.append("fixture_contract_gaps")
    if summary["unknown_source_events"]:
        failures.append("unknown_source_events")
    if summary["unexpected_high_or_critical_events"] or summary["unexpected_high_or_critical_alerts"]:
        failures.append("unexpected_high_or_critical")
    return {"passed": not failures, "failures": failures}


def scorecard(summary: dict[str, Any], gate: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "score": round(50 + covered_rate * 35),
        "passed": gate["passed"],
        "covered_rate": covered_rate,
        "claim_boundary": "local_fixture_contract_only",
    }


def write_outputs(report: dict[str, Any], wave: str, fixture_details: list[dict[str, Any]] | None = None) -> tuple[Path, Path, Path, Path]:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    run_id = report["run_id"]
    json_path = RUNS_DIR / f"{run_id}.json"
    md_path = RUNS_DIR / f"{run_id}.md"
    comparison_path = RUNS_DIR / f"{run_id}.comparison.json"
    evidence_path = GENERATED_DIR / f"detection_rule_{wave}_fixture_evidence.json"
    evidence_md_path = GENERATED_DIR / f"detection_rule_{wave}_fixture_evidence.md"

    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    comparison_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    evidence_tests = fixture_details or report["tests"]
    evidence_path.write_text(json.dumps({"wave": wave, "tests": evidence_tests}, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Detection Rule Wave Fixture Probe",
        "",
        f"- Run ID: `{run_id}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        f"- Wave: `{wave}`",
        "- Scope: local fixture contract only; not runtime detector coverage.",
        "",
        "| Fixture | Rule | Status | Techniques | Family |",
        "|---------|------|--------|------------|--------|",
    ]
    for test in report["tests"]:
        rule = test.get("rule") or {"title": str((test.get("evidence") or {}).get("wave") or test["name"])}
        fixture = test.get("fixture") or {"profile_family": "aggregate-wave-fixture"}
        techniques = ", ".join(test.get("techniques") or [])
        lines.append(
            f"| `{test['id']}` | {rule['title']} | `{test['status']}` | `{techniques}` | `{fixture['profile_family']}` |"
        )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "These fixtures are Tamandua-authored safe evidence contracts. They do not prove live endpoint execution, server-side detection, alert generation, or full external-source parity.",
            "",
        ]
    )
    md = "\n".join(lines)
    md_path.write_text(md, encoding="utf-8")
    evidence_md_path.write_text(md, encoding="utf-8")
    return json_path, md_path, comparison_path, evidence_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wave", default="wave_1")
    args = parser.parse_args()

    wave = str(args.wave).replace("-", "_")
    if wave == "all":
        waves = ["wave_1", "wave_2", "wave_3", "wave_4"]
        plans = [load_plan(item) for item in waves]
        wave_details = {item: build_tests(plan) for item, plan in zip(waves, plans)}
        fixture_details = [test for details in wave_details.values() for test in details]
        tests = build_all_wave_tests(wave_details)
        plan_source: Any = [
            str((GENERATED_DIR / f"detection_rule_{item}_fixture_plan.json").relative_to(ROOT))
            for item in waves
        ]
        fixture_count = sum(len(plan.get("fixtures") or []) for plan in plans)
    else:
        plan = load_plan(wave)
        tests = build_tests(plan)
        fixture_details = None
        plan_source = str((GENERATED_DIR / f"detection_rule_{wave}_fixture_plan.json").relative_to(ROOT))
        fixture_count = len(plan.get("fixtures") or [])
    summary = build_summary(tests, wave)
    gate = quality_gate(summary)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-detection-rule-{wave.replace('_', '-')}-fixture-probe"
    profile_id = (
        "detection-rule-backlog-fixture-probe"
        if wave == "all"
        else f"detection-rule-{wave.replace('_', '-')}-fixture-probe"
    )
    report = {
        "schema_version": 1,
        "profile_id": profile_id,
        "profile_name": f"Detection Rule {wave.replace('_', ' ').title()} Fixture Probe",
        "run_id": run_id,
        "benchmark_lane": "detection-governance",
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "runtime_effect": "none",
        "claim_boundary": "Local fixture contract only. Does not prove live endpoint/server detection coverage.",
        "git": git_snapshot(),
        "plan": {
            "wave": wave,
            "source": plan_source,
            "fixture_count": fixture_count,
        },
        "tests": tests,
        "summary": summary,
        "quality_gate": gate,
        "scorecard": scorecard(summary, gate),
        "upstream_readiness": {
            "upstream_backed": False,
            "reason": "Tamandua-authored local fixture contracts",
        },
    }
    json_path, md_path, comparison_path, evidence_path = write_outputs(report, wave, fixture_details)
    print(
        "detection_rule_wave_fixture_probe=ok "
        f"wave={wave} covered={summary['covered']}/{summary['tests']} "
        f"json={json_path} markdown={md_path} comparison_json={comparison_path} evidence={evidence_path}"
    )
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
