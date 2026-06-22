#!/usr/bin/env python3
"""Build a prioritized backlog from high/critical rule evidence gaps."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
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
MATRIX_PATH = GENERATED_DIR / "detection_rule_evidence_matrix.json"

AREA_WEIGHTS = {
    "credential_access": 35,
    "command_and_control": 32,
    "exfiltration": 30,
    "defense_evasion": 28,
    "attack_chains": 27,
    "ai_runtime": 26,
    "persistence": 24,
    "privilege_escalation": 23,
    "lateral_movement": 22,
    "collection": 20,
}

TECHNIQUE_WEIGHTS = {
    "T1555.003": 24,
    "T1552.001": 23,
    "T1055": 22,
    "T1562.001": 21,
    "T1071.004": 20,
    "T1041": 20,
    "T1105": 19,
    "T1218.005": 19,
    "T1059": 18,
    "T1567": 18,
    "T1547.001": 17,
    "T1090": 17,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_matrix() -> dict[str, Any]:
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def area_for_path(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    if "sigma_rules" in parts:
        index = parts.index("sigma_rules")
        if index + 1 < len(parts):
            area = parts[index + 1]
            if area.endswith((".yml", ".yaml")):
                return Path(area).stem
            return area
    return "unknown"


def priority_score(rule: dict[str, Any]) -> int:
    score = 0
    if rule.get("level") == "critical":
        score += 60
    elif rule.get("level") == "high":
        score += 40
    area = area_for_path(str(rule.get("path") or ""))
    score += AREA_WEIGHTS.get(area, 10)
    for technique in rule.get("techniques") or []:
        score += TECHNIQUE_WEIGHTS.get(str(technique).upper(), 8)
    if not rule.get("has_false_positive_notes"):
        score += 10
    return score


def recommended_fixture_type(rule: dict[str, Any]) -> str:
    area = area_for_path(str(rule.get("path") or ""))
    techniques = {str(value).upper() for value in rule.get("techniques") or []}
    if area == "ai_runtime":
        return "offline_event_envelope_ai_runtime_fixture"
    if area in {"credential_access", "collection", "exfiltration"}:
        return "safe_artifact_access_or_staging_fixture"
    if area == "command_and_control" or "T1071.004" in techniques or "T1090" in techniques:
        return "safe_network_metadata_fixture"
    if area in {"defense_evasion", "persistence", "privilege_escalation"}:
        return "safe_process_registry_service_fixture"
    if area == "attack_chains":
        return "multi_step_storyline_fixture"
    return "safe_endpoint_event_fixture"


def build_backlog(matrix: dict[str, Any]) -> dict[str, Any]:
    missing = [
        rule for rule in matrix.get("rules") or []
        if int(rule.get("positive_evidence_count") or 0) == 0
    ]
    rows: list[dict[str, Any]] = []
    for rule in missing:
        area = area_for_path(str(rule.get("path") or ""))
        rows.append(
            {
                "rule_id": rule.get("rule_id"),
                "title": rule.get("title"),
                "level": rule.get("level"),
                "area": area,
                "path": rule.get("path"),
                "document_index": rule.get("document_index"),
                "techniques": rule.get("techniques") or [],
                "priority_score": priority_score(rule),
                "recommended_fixture_type": recommended_fixture_type(rule),
                "required_evidence": [
                    "Tamandua-authored suspicious fixture",
                    "benign contrast or structured suppression reason",
                    "accepted benchmark artifact with gate pass",
                    "storyline/evidence fields when alert-quality rule is promoted",
                ],
                "claim_boundary": "Backlog item only; not implemented until a passing artifact is linked.",
            }
        )
    rows.sort(key=lambda item: (-int(item["priority_score"]), str(item["area"]), str(item["title"])))

    area_counts = Counter(str(row["area"]) for row in rows)
    technique_counts: Counter[str] = Counter()
    for row in rows:
        for technique in row["techniques"]:
            technique_counts[str(technique)] += 1

    waves = {
        "wave_1": rows[:25],
        "wave_2": rows[25:75],
        "wave_3": rows[75:150],
        "wave_4": rows[150:],
    }
    return {
        "generated_at": utc_now(),
        "source_matrix": str(MATRIX_PATH.relative_to(ROOT)),
        "missing_positive_total": len(rows),
        "area_counts": dict(area_counts.most_common()),
        "technique_counts": dict(technique_counts.most_common()),
        "waves": {
            key: {
                "count": len(value),
                "items": value,
            }
            for key, value in waves.items()
        },
        "claim_boundary": "Prioritized implementation backlog only. Items are not detection coverage until a dedicated passing artifact is linked.",
    }


def render_markdown(backlog: dict[str, Any]) -> str:
    lines = [
        "# Detection Rule Evidence Backlog",
        "",
        "Status: generated",
        "",
        f"- Generated at: `{backlog['generated_at']}`",
        f"- Source matrix: `{backlog['source_matrix']}`",
        f"- Missing positive evidence mappings: `{backlog['missing_positive_total']}`",
        "",
        "## Claim Boundary",
        "",
        backlog["claim_boundary"],
        "",
        "## Area Counts",
        "",
        "| Area | Missing rules |",
        "|------|---------------|",
    ]
    for area, count in backlog["area_counts"].items():
        lines.append(f"| `{area}` | `{count}` |")

    lines.extend(["", "## Top Techniques", "", "| Technique | Missing rules |", "|-----------|---------------|"])
    for technique, count in list(backlog["technique_counts"].items())[:25]:
        lines.append(f"| `{technique}` | `{count}` |")

    for wave, payload in backlog["waves"].items():
        lines.extend(
            [
                "",
                f"## {wave.replace('_', ' ').title()}",
                "",
                f"- Items: `{payload['count']}`",
                "",
                "| Priority | Rule | Level | Area | Techniques | Fixture type |",
                "|----------|------|-------|------|------------|--------------|",
            ]
        )
        for item in payload["items"][:50]:
            lines.append(
                f"| `{item['priority_score']}` | {item['title']} | `{item['level']}` | "
                f"`{item['area']}` | `{', '.join(item['techniques']) or '-'}` | "
                f"`{item['recommended_fixture_type']}` |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=GENERATED_DIR)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    backlog = build_backlog(load_matrix())
    json_path = args.output_dir / "detection_rule_evidence_backlog.json"
    md_path = args.output_dir / "detection_rule_evidence_backlog.md"
    json_path.write_text(json.dumps(backlog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(backlog), encoding="utf-8")
    print(
        "detection_rule_evidence_backlog=ok "
        f"missing_positive={backlog['missing_positive_total']} "
        f"json={json_path} markdown={md_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
