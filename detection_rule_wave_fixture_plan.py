#!/usr/bin/env python3
"""Generate implementation-ready fixture plans from the rule evidence backlog."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"
BACKLOG_PATH = GENERATED_DIR / "detection_rule_evidence_backlog.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return re.sub(r"-+", "-", value)[:80] or "rule"


def load_backlog() -> dict[str, Any]:
    return json.loads(BACKLOG_PATH.read_text(encoding="utf-8"))


def platform_for_item(item: dict[str, Any]) -> str:
    area = str(item.get("area") or "")
    techniques = {str(value).upper() for value in item.get("techniques") or []}
    if area in {"ai_runtime", "serverless", "web3"}:
        return "multi"
    if any(technique.startswith("T1003") or technique in {"T1555.003", "T1218.005", "T1562.001"} for technique in techniques):
        return "windows"
    if area in {"command_and_control", "exfiltration"}:
        return "multi"
    return "windows"


def profile_family_for_item(item: dict[str, Any]) -> str:
    fixture_type = str(item.get("recommended_fixture_type") or "")
    if fixture_type == "offline_event_envelope_ai_runtime_fixture":
        return "offline-replay"
    if fixture_type == "multi_step_storyline_fixture":
        return "storyline-fixture"
    if fixture_type == "safe_network_metadata_fixture":
        return "network-fixture"
    if fixture_type == "safe_process_registry_service_fixture":
        return "endpoint-control-fixture"
    if fixture_type == "safe_artifact_access_or_staging_fixture":
        return "artifact-access-fixture"
    return "endpoint-event-fixture"


def acceptance_criteria(item: dict[str, Any]) -> list[str]:
    criteria = [
        "fixture is Tamandua-authored and does not copy external rule logic",
        "benchmark artifact has quality_gate.passed=true",
        "artifact links rule id/title, ATT&CK technique, expected telemetry, and evidence source",
        "benign contrast or structured suppression rationale is recorded",
        "no unknown-source events and no unexpected high/critical events or alerts",
    ]
    family = profile_family_for_item(item)
    if family == "storyline-fixture":
        criteria.append("storyline/correlation nodes are present and investigable")
    if family == "network-fixture":
        criteria.append("network evidence uses protocol/domain/timing metadata, not port-only logic")
    if family == "artifact-access-fixture":
        criteria.append("sensitive artifact access is simulated with safe placeholder files")
    if family == "offline-replay":
        criteria.append("offline Event Envelope replay does not mutate live alerts")
    return criteria


def planned_fixture(item: dict[str, Any], index: int) -> dict[str, Any]:
    title = str(item.get("title") or "untitled")
    area = str(item.get("area") or "unknown")
    techniques = [str(value) for value in item.get("techniques") or []]
    platform = platform_for_item(item)
    family = profile_family_for_item(item)
    fixture_id = f"rule-gap-wave1-{index:02d}-{slug(area)}-{slug(title)}"
    return {
        "fixture_id": fixture_id,
        "rule_id": item.get("rule_id"),
        "rule_title": title,
        "level": item.get("level"),
        "area": area,
        "path": item.get("path"),
        "document_index": item.get("document_index"),
        "techniques": techniques,
        "priority_score": item.get("priority_score"),
        "platform": platform,
        "profile_family": family,
        "recommended_profile_id": f"{platform}-{family}-wave1",
        "recommended_test_id": fixture_id,
        "fixture_type": item.get("recommended_fixture_type"),
        "expected_evidence": [
            "process/file/registry/network/event-envelope telemetry appropriate to fixture type",
            "rule/title/technique traceability",
            "positive suspicious fixture",
            "benign contrast fixture or suppression rationale",
        ],
        "acceptance_criteria": acceptance_criteria(item),
        "status": "planned",
        "claim_boundary": "Planned fixture only; no coverage claim until a passing artifact is linked.",
    }


def build_plan(backlog: dict[str, Any], wave: str) -> dict[str, Any]:
    wave_payload = (backlog.get("waves") or {}).get(wave) or {}
    items = wave_payload.get("items") or []
    fixtures = [planned_fixture(item, index + 1) for index, item in enumerate(items)]
    return {
        "generated_at": utc_now(),
        "source_backlog": str(BACKLOG_PATH.relative_to(ROOT)),
        "wave": wave,
        "fixture_count": len(fixtures),
        "profile_families": sorted({fixture["profile_family"] for fixture in fixtures}),
        "platforms": sorted({fixture["platform"] for fixture in fixtures}),
        "fixtures": fixtures,
        "claim_boundary": "Fixture implementation plan only. Items are not detection coverage until implemented and benchmarked.",
    }


def render_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# Detection Rule Wave Fixture Plan",
        "",
        "Status: generated",
        "",
        f"- Generated at: `{plan['generated_at']}`",
        f"- Source backlog: `{plan['source_backlog']}`",
        f"- Wave: `{plan['wave']}`",
        f"- Planned fixtures: `{plan['fixture_count']}`",
        f"- Platforms: `{', '.join(plan['platforms'])}`",
        f"- Profile families: `{', '.join(plan['profile_families'])}`",
        "",
        "## Claim Boundary",
        "",
        plan["claim_boundary"],
        "",
        "## Fixtures",
        "",
        "| Fixture | Rule | Level | Area | Platform | Family | Techniques |",
        "|---------|------|-------|------|----------|--------|------------|",
    ]
    for fixture in plan["fixtures"]:
        lines.append(
            f"| `{fixture['fixture_id']}` | {fixture['rule_title']} | `{fixture['level']}` | "
            f"`{fixture['area']}` | `{fixture['platform']}` | `{fixture['profile_family']}` | "
            f"`{', '.join(fixture['techniques']) or '-'}` |"
        )
    lines.extend(
        [
            "",
            "## Acceptance Pattern",
            "",
            "Every planned fixture must produce a passing artifact that records rule traceability, telemetry evidence, positive behavior, benign contrast, and no unexpected high/critical noise.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wave", default="wave_1")
    parser.add_argument("--output-dir", type=Path, default=GENERATED_DIR)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    plan = build_plan(load_backlog(), args.wave)
    json_path = args.output_dir / f"detection_rule_{args.wave}_fixture_plan.json"
    md_path = args.output_dir / f"detection_rule_{args.wave}_fixture_plan.md"
    json_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(plan), encoding="utf-8")
    print(
        "detection_rule_wave_fixture_plan=ok "
        f"wave={args.wave} fixtures={plan['fixture_count']} "
        f"json={json_path} markdown={md_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
