#!/usr/bin/env python3
"""Generate a report-only release/reliability gate for Roadmaps G/L/V.

The report is profile-driven and does not inspect or modify benchmark run
artifacts. It is intended for parallel roadmap work that can run locally without
WIN-TEMPLATE, deployment, rollback, uninstall, reboot, driver reload, or OTA.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILES_DIR = ROOT / "tools" / "detection_validation" / "profiles"
DEFAULT_OUTPUT_DIR = ROOT / "docs" / "benchmarks" / "generated"


@dataclass(frozen=True)
class GateRule:
    roadmap: str
    title: str
    profile_id: str
    profile_path: str
    contract_key: str
    required_tags: tuple[str, ...]
    required_contract_terms: tuple[str, ...]
    production_blockers: tuple[str, ...]


GATE_RULES: tuple[GateRule, ...] = (
    GateRule(
        roadmap="G",
        title="Release, Signing, and Operations Gate",
        profile_id="windows-release-readiness-dry-run",
        profile_path="windows_release_readiness_dry_run.json",
        contract_key="release_contract",
        required_tags=("release-readiness", "report-only"),
        required_contract_terms=("signature", "SBOM", "rollback", "uninstall", "compatibility"),
        production_blockers=(
            "signed release manifest/SBOM not attached to gate input",
            "install/upgrade/rollback/uninstall not executed on clean disposable template",
            "compatibility matrix not attached",
        ),
    ),
    GateRule(
        roadmap="L",
        title="Agent and Driver Reliability Gate",
        profile_id="windows-release-reliability-dry-run",
        profile_path="windows_release_reliability_dry_run.json",
        contract_key="reliability_contract",
        required_tags=("release-reliability", "report-only"),
        required_contract_terms=("offline", "queue", "backpressure", "replay", "driver", "stress", "drops", "rollback"),
        production_blockers=(
            "offline replay/backpressure is metadata-only",
            "agent restart/reconnect/reboot stress not executed",
            "driver reload and drop accounting not executed",
        ),
    ),
    GateRule(
        roadmap="V",
        title="Crash-Proof Agent Resilience Gate",
        profile_id="windows-crash-resilience-dry-run",
        profile_path="windows_crash_resilience_dry_run.json",
        contract_key="resilience_contract",
        required_tags=("crash-resilience", "roadmap:V"),
        required_contract_terms=("Secure Boot", "safe-boot", "backpressure", "guardrails", "transactional"),
        production_blockers=(
            "Secure Boot production-loadable driver state not proven",
            "safe-boot stale marker simulation not executed",
            "local response guardrails and transactional OTA not executed",
        ),
    ),
)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: root must be a JSON object")
    return data


def test_tags(test: dict[str, Any]) -> set[str]:
    tags = test.get("tags") or []
    return {str(tag) for tag in tags if str(tag)}


def classify_rule(rule: GateRule, profile: dict[str, Any]) -> dict[str, Any]:
    tests = profile.get("tests") or []
    if not isinstance(tests, list):
        tests = []

    missing_contract = rule.contract_key not in profile
    contract_text = json.dumps(profile.get(rule.contract_key) or {}, sort_keys=True)
    missing_contract_terms = [
        term for term in rule.required_contract_terms if term.lower() not in contract_text.lower()
    ]
    missing_commands = [
        str(test.get("id") or index)
        for index, test in enumerate(tests)
        if isinstance(test, dict)
        and test.get("executor") in {"command", "atomic_or_command"}
        and not (test.get("fallback_command") or test.get("command") or test.get("atomic"))
    ]
    destructive_markers = (
        " Remove-Item ",
        " reg delete ",
        " sc stop ",
        " sc delete ",
        "Restart-Computer",
        "Stop-Service",
        "msiexec /x",
        "fltmc unload",
    )
    destructive_commands = []
    planned_not_executed = 0
    required_tag_hits = {tag: 0 for tag in rule.required_tags}

    for index, test in enumerate(tests):
        if not isinstance(test, dict):
            continue
        command = str(test.get("fallback_command") or test.get("command") or "")
        lowered = command.lower()
        if any(marker.lower() in lowered for marker in destructive_markers):
            destructive_commands.append(str(test.get("id") or index))
        if "planned_not_executed" in command or "report_only" in command:
            planned_not_executed += 1
        tags = test_tags(test)
        for tag in rule.required_tags:
            if tag in tags:
                required_tag_hits[tag] += 1

    missing_tags = [tag for tag, count in required_tag_hits.items() if count == 0]
    status = "report-only-ready"
    if missing_contract or missing_contract_terms or missing_commands or destructive_commands or missing_tags:
        status = "contract-gap"

    return {
        "roadmap": rule.roadmap,
        "title": rule.title,
        "profile_id": rule.profile_id,
        "status": status,
        "profile_tests": len(tests),
        "report_only_tests": planned_not_executed,
        "missing_contract": missing_contract,
        "missing_contract_terms": missing_contract_terms,
        "missing_commands": missing_commands,
        "destructive_commands": destructive_commands,
        "missing_required_tags": missing_tags,
        "production_blockers": list(rule.production_blockers),
        "claim_boundary": str(profile.get("claim_boundary") or ""),
    }


def generate(profiles_dir: Path) -> dict[str, Any]:
    rows = []
    errors = []
    for rule in GATE_RULES:
        path = profiles_dir / rule.profile_path
        if not path.exists():
            errors.append(f"{rule.profile_id}: missing profile {path}")
            rows.append(
                {
                    "roadmap": rule.roadmap,
                    "title": rule.title,
                    "profile_id": rule.profile_id,
                    "status": "missing-profile",
                    "profile_tests": 0,
                    "report_only_tests": 0,
                    "missing_contract": True,
                    "missing_contract_terms": list(rule.required_contract_terms),
                    "missing_commands": [],
                    "destructive_commands": [],
                    "missing_required_tags": list(rule.required_tags),
                    "production_blockers": list(rule.production_blockers),
                    "claim_boundary": "",
                }
            )
            continue
        profile = load_json(path)
        if str(profile.get("profile_id") or "") != rule.profile_id:
            errors.append(f"{path}: profile_id mismatch, expected {rule.profile_id}")
        rows.append(classify_rule(rule, profile))

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runtime_effect": "none",
        "source": "profile_contracts_only",
        "manual_run_artifacts_modified": False,
        "roadmaps": rows,
        "status_counts": counts,
        "errors": errors,
        "overall_status": "report-only-ready" if not errors and counts.get("contract-gap", 0) == 0 and counts.get("missing-profile", 0) == 0 else "contract-gap",
    }


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Release Reliability Gate",
        "",
        "Status: generated",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Runtime effect: `{report['runtime_effect']}`",
        f"- Source: `{report['source']}`",
        f"- Overall status: `{report['overall_status']}`",
        "",
        "## Roadmaps G/L/V",
        "",
        "| Roadmap | Status | Profile | Tests | Report-only tests | Production blockers |",
        "|---------|--------|---------|-------|-------------------|---------------------|",
    ]
    for row in report["roadmaps"]:
        blockers = "<br>".join(f"- {item}" for item in row["production_blockers"])
        lines.append(
            f"| {row['roadmap']}. {row['title']} | `{row['status']}` | "
            f"`{row['profile_id']}` | `{row['profile_tests']}` | "
            f"`{row['report_only_tests']}` | {blockers} |"
        )

    lines.extend(["", "## Contract Gaps", ""])
    any_gap = False
    for row in report["roadmaps"]:
        gaps = []
        if row["missing_contract"]:
            gaps.append("missing contract block")
        if row["missing_contract_terms"]:
            gaps.append("missing contract terms: " + ", ".join(row["missing_contract_terms"]))
        if row["missing_commands"]:
            gaps.append("tests without command definitions: " + ", ".join(row["missing_commands"]))
        if row["destructive_commands"]:
            gaps.append("destructive command markers: " + ", ".join(row["destructive_commands"]))
        if row["missing_required_tags"]:
            gaps.append("missing required tags: " + ", ".join(row["missing_required_tags"]))
        if gaps:
            any_gap = True
            lines.append(f"- `{row['profile_id']}`: {'; '.join(gaps)}")
    if not any_gap:
        lines.append("- No profile contract gaps found. Remaining gaps are production blockers, not dry-run shape blockers.")

    lines.extend(["", "## Claim Boundary", ""])
    for row in report["roadmaps"]:
        lines.append(f"- `{row['profile_id']}`: {row['claim_boundary']}")

    lines.append("")
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "release_reliability_gate.json"
    md_path = output_dir / "release_reliability_gate.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(markdown(report), encoding="utf-8")
    return json_path, md_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profiles-dir", type=Path, default=DEFAULT_PROFILES_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--check", action="store_true", help="Generate in memory and fail if contract gaps exist")
    args = parser.parse_args()

    report = generate(args.profiles_dir)
    if args.check:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        json_path, md_path = write_report(report, args.output_dir)
        print(f"release_reliability_gate={report['overall_status']} json={json_path} markdown={md_path}")
    return 0 if report["overall_status"] == "report-only-ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
