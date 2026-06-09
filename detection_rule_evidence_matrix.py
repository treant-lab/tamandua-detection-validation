#!/usr/bin/env python3
"""Generate selected evidence mapping for high/critical detection rules.

This is intentionally conservative: it maps rule metadata to benchmark
evidence by ATT&CK technique and accepted benchmark artifacts. It does not mark
external-source-inspired candidates as implemented and does not claim every
rule has a dedicated fixture unless an artifact explicitly proves that.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"
RULE_DIR = ROOT / "apps" / "tamandua_server" / "priv" / "sigma_rules"
HIGH_LEVELS = {"high", "critical"}

POSITIVE_ARTIFACTS = [
    "exec-windows-enterprise-eval-safe-v1-full-alt-telemetry-final5",
    "20260524T223852Z-windows-atomic-upstream-smoke",
    "20260525T000306Z-windows-caldera-smoke",
    "20260602T081730Z-windows-unified-dr-engine-v1",
    "20260602T174349Z-linux-external-semantic-rewrite-p0-p1-execution",
]

BENIGN_ARTIFACTS = [
    "exec-windows-benign-noise-broad-v1-tamandua-ctl-live-response-contract",
    "20260601T235619Z-linux-benign-noise-broad-v1",
    "20260602T132824Z-telemetry-replay-offline-fp-severity-v1",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def split_yaml_documents(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?m)^---\s*$", text) if part.strip()]


def scalar_value(document: str, key: str) -> str:
    match = re.search(rf"(?m)^{re.escape(key)}\s*:\s*(.*?)\s*$", document)
    return match.group(1).strip().strip("'\"") if match else ""


def section_text(document: str, key: str) -> str:
    lines = document.splitlines()
    capture = False
    collected: list[str] = []
    for line in lines:
        if re.match(rf"^{re.escape(key)}\s*:", line):
            capture = True
            collected.append(line)
            continue
        if capture and line and not line.startswith((" ", "\t", "-")):
            break
        if capture:
            collected.append(line)
    return "\n".join(collected)


def extract_attack_tags(document: str) -> list[str]:
    text = section_text(document, "tags").lower()
    tags = sorted(set(re.findall(r"attack\.t[0-9]{4}(?:\.[0-9]{3})?", text)))
    return [tag.replace("attack.", "").upper() for tag in tags]


def extract_rule_id(document: str) -> str:
    return scalar_value(document, "id") or ""


def load_high_rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(RULE_DIR.rglob("*.yml")) + sorted(RULE_DIR.rglob("*.yaml")):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8-sig")
        for index, document in enumerate(split_yaml_documents(text), start=1):
            level = (scalar_value(document, "level") or "").lower()
            if level not in HIGH_LEVELS:
                continue
            rules.append(
                {
                    "rule_id": extract_rule_id(document),
                    "title": scalar_value(document, "title") or "(untitled)",
                    "level": level,
                    "path": str(path.relative_to(ROOT)),
                    "document_index": index,
                    "techniques": extract_attack_tags(document),
                    "has_false_positive_notes": bool(section_text(document, "falsepositives").strip()),
                }
            )
    return rules


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def artifact_path(run_id: str) -> Path:
    return RUNS_DIR / f"{run_id}.comparison.json"


def techniques_for_test(test: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for value in test.get("techniques") or []:
        if isinstance(value, str):
            found.add(value.upper())
    trace = test.get("roadmap_traceability") if isinstance(test.get("roadmap_traceability"), dict) else {}
    technique = trace.get("technique")
    if isinstance(technique, str) and technique:
        found.add(technique.upper())
    for value in test.get("tags") or []:
        if isinstance(value, str):
            match = re.search(r"t[0-9]{4}(?:\.[0-9]{3})?", value, flags=re.I)
            if match:
                found.add(match.group(0).upper())
    return found


def artifact_passed(report: dict[str, Any]) -> bool:
    return bool((report.get("quality_gate") or {}).get("passed"))


def collect_positive_evidence() -> dict[str, list[dict[str, Any]]]:
    by_technique: dict[str, list[dict[str, Any]]] = {}
    for run_id in POSITIVE_ARTIFACTS:
        path = artifact_path(run_id)
        if not path.exists():
            continue
        report = read_json(path)
        if not artifact_passed(report):
            continue
        technique_coverage = (report.get("summary") or {}).get("technique_coverage") or {}
        if isinstance(technique_coverage, dict):
            for technique, coverage in technique_coverage.items():
                if not isinstance(coverage, dict):
                    continue
                covered = int(coverage.get("covered") or 0)
                if covered <= 0:
                    continue
                by_technique.setdefault(str(technique).upper(), []).append(
                    {
                        "run_id": run_id,
                        "profile_id": report.get("profile_id"),
                        "test_id": "summary.technique_coverage",
                        "status": "covered",
                        "covered": covered,
                    }
                )
        for test in report.get("tests") or []:
            if test.get("status") not in {"covered", "partial"}:
                continue
            for technique in techniques_for_test(test):
                by_technique.setdefault(technique, []).append(
                    {
                        "run_id": run_id,
                        "profile_id": report.get("profile_id"),
                        "test_id": test.get("id"),
                        "status": test.get("status"),
                    }
                )
    return by_technique


def collect_benign_evidence() -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for run_id in BENIGN_ARTIFACTS:
        path = artifact_path(run_id)
        if not path.exists():
            continue
        report = read_json(path)
        summary = report.get("summary") or {}
        if not artifact_passed(report):
            continue
        if int(summary.get("unexpected_high_or_critical_alerts") or 0) != 0:
            continue
        if int(summary.get("unexpected_high_or_critical_events") or 0) != 0:
            continue
        evidence.append(
            {
                "run_id": run_id,
                "profile_id": report.get("profile_id"),
                "tests": summary.get("tests", 0),
                "covered": summary.get("covered", 0),
                "scope": "broad benign/noise or replay contrast; not per-rule unless separately stated",
            }
        )
    return evidence


def build_matrix() -> dict[str, Any]:
    rules = load_high_rules()
    positive_by_technique = collect_positive_evidence()
    benign_evidence = collect_benign_evidence()
    rows: list[dict[str, Any]] = []

    for rule in rules:
        positive: list[dict[str, Any]] = []
        for technique in rule["techniques"]:
            positive.extend(positive_by_technique.get(technique, []))
        positive = sorted(
            {json.dumps(item, sort_keys=True): item for item in positive}.values(),
            key=lambda item: (str(item.get("profile_id")), str(item.get("test_id"))),
        )
        rows.append(
            {
                **rule,
                "positive_evidence": positive,
                "positive_evidence_count": len(positive),
                "benign_contrast_evidence": benign_evidence,
                "benign_contrast_count": len(benign_evidence),
                "coverage_status": (
                    "mapped_positive_and_broad_benign"
                    if positive and benign_evidence
                    else "missing_positive_mapping"
                    if not positive
                    else "missing_benign_contrast"
                ),
            }
        )

    missing_positive = [row for row in rows if not row["positive_evidence"]]
    missing_benign = [row for row in rows if not row["benign_contrast_evidence"]]
    return {
        "generated_at": utc_now(),
        "rules_total": len(rows),
        "mapped_positive_rules": len(rows) - len(missing_positive),
        "mapped_broad_benign_rules": len(rows) - len(missing_benign),
        "missing_positive_rules": len(missing_positive),
        "missing_benign_rules": len(missing_benign),
        "positive_artifacts": POSITIVE_ARTIFACTS,
        "benign_artifacts": BENIGN_ARTIFACTS,
        "claim_boundary": (
            "Technique-level evidence matrix for release governance. Positive evidence is mapped by ATT&CK technique from accepted artifacts. "
            "Benign contrast is broad corpus/replay evidence unless a future artifact proves per-rule benign contrast."
        ),
        "rules": rows,
    }


def render_markdown(matrix: dict[str, Any]) -> str:
    lines = [
        "# Detection Rule Evidence Matrix",
        "",
        "Status: generated",
        "",
        f"- Generated at: `{matrix['generated_at']}`",
        f"- High/critical rules: `{matrix['rules_total']}`",
        f"- Rules with mapped positive evidence: `{matrix['mapped_positive_rules']}`",
        f"- Rules with broad benign contrast evidence: `{matrix['mapped_broad_benign_rules']}`",
        f"- Rules missing positive mapping: `{matrix['missing_positive_rules']}`",
        f"- Rules missing benign evidence: `{matrix['missing_benign_rules']}`",
        "",
        "## Claim Boundary",
        "",
        matrix["claim_boundary"],
        "",
        "## Rules Missing Positive Mapping",
        "",
        "| Rule | Level | Techniques | File |",
        "|------|-------|------------|------|",
    ]
    missing = [row for row in matrix["rules"] if row["positive_evidence_count"] == 0]
    for row in missing[:200]:
        lines.append(
            f"| {row['title']} | `{row['level']}` | `{', '.join(row['techniques']) or '-'}` | `{row['path']}` |"
        )
    if not missing:
        lines.append("| - | - | - | - |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=GENERATED_DIR)
    parser.add_argument("--fail-on-missing-positive", action="store_true")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    matrix = build_matrix()
    json_path = args.output_dir / "detection_rule_evidence_matrix.json"
    md_path = args.output_dir / "detection_rule_evidence_matrix.md"
    json_path.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(matrix), encoding="utf-8")
    print(
        "detection_rule_evidence_matrix=ok "
        f"rules={matrix['rules_total']} "
        f"mapped_positive={matrix['mapped_positive_rules']} "
        f"missing_positive={matrix['missing_positive_rules']} "
        f"json={json_path} markdown={md_path}"
    )
    if args.fail_on_missing_positive and matrix["missing_positive_rules"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
