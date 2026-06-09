#!/usr/bin/env python3
"""Check Sigma-style detection rule metadata for release readiness.

The checker is intentionally conservative and dependency-light. It does not
validate Sigma syntax; it verifies the metadata needed for trustworthy alert
claims, especially high/critical rules.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULE_DIR = ROOT / "apps" / "tamandua_server" / "priv" / "sigma_rules"
DEFAULT_OUTPUT_DIR = ROOT / "docs" / "benchmarks" / "generated"
HIGH_LEVELS = {"high", "critical"}
REQUIRED_HIGH_FIELDS = ("title", "id", "description", "logsource", "detection", "falsepositives", "tags")


@dataclass
class RuleFinding:
    path: str
    document_index: int
    title: str
    level: str
    status: str
    missing_fields: list[str]
    notes: list[str]


def split_yaml_documents(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?m)^---\s*$", text) if part.strip()]


def top_level_keys(document: str) -> set[str]:
    keys: set[str] = set()
    for line in document.splitlines():
        if not line or line.startswith((" ", "\t", "#")):
            continue
        match = re.match(r"^([A-Za-z0-9_\-]+)\s*:", line)
        if match:
            keys.add(match.group(1))
    return keys


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


def analyze_document(path: Path, document: str, index: int) -> RuleFinding | None:
    keys = top_level_keys(document)
    title = scalar_value(document, "title") or "(untitled)"
    level = (scalar_value(document, "level") or "unknown").lower()

    if not keys:
        return None

    missing = [field for field in REQUIRED_HIGH_FIELDS if field not in keys] if level in HIGH_LEVELS else []
    notes: list[str] = []

    tags = section_text(document, "tags").lower()
    falsepositives = section_text(document, "falsepositives").lower()
    detection = section_text(document, "detection").lower()

    if level in HIGH_LEVELS:
        if "attack." not in tags and "mitre" not in tags:
            notes.append("high/critical rule lacks ATT&CK-style tag")
        if not falsepositives.strip() or falsepositives.strip() == "falsepositives:":
            notes.append("high/critical rule lacks false-positive notes")
        if "condition:" not in detection:
            notes.append("detection block lacks explicit condition")

    status = "pass" if not missing and not notes else "review"
    return RuleFinding(str(path.relative_to(ROOT)), index, title, level, status, missing, notes)


def load_findings(rule_dir: Path) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for path in sorted(rule_dir.rglob("*.yml")) + sorted(rule_dir.rglob("*.yaml")):
        try:
            documents = split_yaml_documents(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            documents = split_yaml_documents(path.read_text(encoding="utf-8-sig"))
        for index, document in enumerate(documents, start=1):
            finding = analyze_document(path, document, index)
            if finding is not None:
                findings.append(finding)
    return findings


def render_markdown(findings: list[RuleFinding], generated_at: str) -> str:
    high = [item for item in findings if item.level in HIGH_LEVELS]
    review = [item for item in high if item.status != "pass"]

    lines = [
        "# Detection Rule Metadata Report",
        "",
        "Status: generated",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Rules scanned: `{len(findings)}`",
        f"- High/critical rules scanned: `{len(high)}`",
        f"- High/critical rules needing review: `{len(review)}`",
        "",
        "## High/Critical Review Findings",
        "",
        "| Rule | Level | File | Missing Fields | Notes |",
        "|------|-------|------|----------------|-------|",
    ]

    if review:
        for item in review[:200]:
            missing = ", ".join(item.missing_fields) or "-"
            notes = "; ".join(item.notes) or "-"
            lines.append(f"| {item.title} | `{item.level}` | `{item.path}` | {missing} | {notes} |")
    else:
        lines.append("| - | - | - | - | - |")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule-dir", type=Path, default=DEFAULT_RULE_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--fail-on-review", action="store_true")
    args = parser.parse_args()

    findings = load_findings(args.rule_dir)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": generated_at,
        "rules_scanned": len(findings),
        "high_critical_rules": sum(1 for item in findings if item.level in HIGH_LEVELS),
        "high_critical_review": sum(
            1 for item in findings if item.level in HIGH_LEVELS and item.status != "pass"
        ),
        "findings": [asdict(item) for item in findings],
    }

    json_path = args.output_dir / "detection_rule_metadata_report.json"
    md_path = args.output_dir / "detection_rule_metadata_report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(render_markdown(findings, generated_at), encoding="utf-8")

    print(f"wrote {md_path} and {json_path}")
    if args.fail_on_review and report["high_critical_review"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
