#!/usr/bin/env python3
"""Generate a per-MITRE-ATT&CK-technique coverage matrix for Windows/Linux/macOS.

This is an offline, report-only analysis tool. It reads sigma rule frontmatter
under ``apps/tamandua_server/priv/sigma_rules`` and joins it against the already
generated ``docs/benchmarks/generated/detection_rule_evidence_matrix.json`` to
report, per ATT&CK technique, how many rules exist, which platforms they target,
and the strongest evidence status that has been linked to that technique.

It does NOT contact the Tamandua server, run any benchmark, or execute attacker
tooling. The output is rule-content + linked-evidence analysis, never a
third-party-validated external coverage claim.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RULE_DIR = ROOT / "apps" / "tamandua_server" / "priv" / "sigma_rules"
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"
EVIDENCE_MATRIX = GENERATED_DIR / "detection_rule_evidence_matrix.json"

SCHEMA_VERSION = 1
ALL_PLATFORMS = ("windows", "linux", "macos")

# Highest-to-lowest evidence ordering. ``none`` means rule content only.
EVIDENCE_RANK = {"none": 0, "fixture": 1, "replay": 2, "live": 3}

# Per-technique claim boundary strings, keyed by evidence_status. These mirror
# the conservative wording used by the other detection_validation tools.
CLAIM_BOUNDARY_BY_STATUS = {
    "live": "live_endpoint_evidence",
    "replay": "offline_replay_only",
    "fixture": "local_fixture_contract_only",
    "none": "rule_content_only_no_runtime_evidence",
}

# Replay artifacts are offline telemetry replays; live artifacts are bounded
# endpoint executions. Anything else linked as positive evidence is treated as a
# local fixture contract. These ids come from the evidence matrix inputs.
REPLAY_RUN_MARKERS = ("telemetry-replay", "offline-fp", "replay")
LIVE_RUN_MARKERS = (
    "windows-enterprise-eval-safe",
    "windows-atomic-upstream-smoke",
    "windows-caldera-smoke",
    "windows-unified-dr-engine",
    "linux-external-semantic-rewrite",
    "live-proof",
    "live-collection",
)

# Tactic tag -> human readable area. Derived from the ``attack.<tactic>`` tags
# present in the sigma corpus.
TACTIC_AREAS = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
}

TECHNIQUE_RE = re.compile(r"attack\.t[0-9]{4}(?:\.[0-9]{3})?", re.IGNORECASE)
TACTIC_RE = re.compile(r"attack\.([a-z_]+)", re.IGNORECASE)


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
    status = run(["git", "status", "--porcelain"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def split_yaml_documents(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?m)^---\s*$", text) if part.strip()]


def scalar_value(document: str, key: str) -> str:
    match = re.search(rf"(?m)^{re.escape(key)}\s*:\s*(.*?)\s*$", document)
    return match.group(1).strip().strip("'\"") if match else ""


def logsource_product(document: str) -> str:
    """Extract ``product`` from the ``logsource`` block of a rule document."""
    lines = document.splitlines()
    capture = False
    for line in lines:
        if re.match(r"^logsource\s*:", line):
            capture = True
            continue
        if capture:
            if line and not line.startswith((" ", "\t", "-")):
                break
            match = re.match(r"\s+product\s*:\s*(.*?)\s*$", line)
            if match:
                return match.group(1).strip().strip("'\"").lower()
    return ""


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


def tags_block(document: str) -> str:
    return section_text(document, "tags")


def extract_techniques(tags: str) -> list[str]:
    found = sorted(set(match.group(0) for match in TECHNIQUE_RE.finditer(tags.lower())))
    return [tag.replace("attack.", "").upper() for tag in found]


def extract_tactics(tags: str) -> list[str]:
    tactics: list[str] = []
    for line in tags.splitlines():
        match = TACTIC_RE.search(line.lower())
        if not match:
            continue
        candidate = match.group(1)
        if candidate in TACTIC_AREAS:
            tactics.append(candidate)
    return sorted(set(tactics))


def platforms_for_product(product: str) -> set[str]:
    """Map a sigma ``logsource.product`` to platform labels.

    - ``windows`` / ``linux`` / ``macos`` map directly.
    - ``any`` is treated as cross-platform (all three) because such rules are
      product-agnostic detection content.
    - cloud/serverless/app products (``tamandua``, ``aws_lambda``, ``apache`` ...)
      do not map to an endpoint OS platform and contribute no platform label.
    """
    product = (product or "").lower()
    if product in {"windows", "linux", "macos"}:
        return {product}
    if product == "any":
        return set(ALL_PLATFORMS)
    return set()


def tactic_area(tactics: list[str]) -> str:
    if not tactics:
        return "Uncategorized"
    return TACTIC_AREAS.get(tactics[0], tactics[0].replace("_", " ").title())


def load_rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    paths = sorted(RULE_DIR.rglob("*.yml")) + sorted(RULE_DIR.rglob("*.yaml"))
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8-sig")
        for index, document in enumerate(split_yaml_documents(text), start=1):
            tags = tags_block(document)
            techniques = extract_techniques(tags)
            if not techniques:
                continue
            product = logsource_product(document)
            rules.append(
                {
                    "rule_id": scalar_value(document, "id") or "",
                    "title": scalar_value(document, "title") or "(untitled)",
                    "level": (scalar_value(document, "level") or "unknown").lower(),
                    "product": product,
                    "platforms": sorted(platforms_for_product(product)),
                    "techniques": techniques,
                    "tactics": extract_tactics(tags),
                    "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                    "document_index": index,
                }
            )
    return rules


def classify_run_status(run_id: str) -> str:
    rid = (run_id or "").lower()
    if any(marker in rid for marker in REPLAY_RUN_MARKERS):
        return "replay"
    if any(marker in rid for marker in LIVE_RUN_MARKERS):
        return "live"
    return "fixture"


def load_technique_evidence() -> dict[str, dict[str, Any]]:
    """Join the evidence matrix to derive the strongest status per technique.

    Returns a mapping ``technique -> {"status": ..., "run_ids": [...]}`` where
    ``status`` is the highest applicable evidence level supported by a linked
    passing positive artifact for any rule carrying that technique.
    """
    evidence: dict[str, dict[str, Any]] = {}
    if not EVIDENCE_MATRIX.exists():
        return evidence
    try:
        data = json.loads(EVIDENCE_MATRIX.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return evidence
    for rule in data.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        positives = rule.get("positive_evidence") or []
        rule_techniques = [str(t).upper() for t in (rule.get("techniques") or [])]
        for technique in rule_techniques:
            bucket = evidence.setdefault(technique, {"status": "none", "run_ids": set()})
            for item in positives:
                if not isinstance(item, dict):
                    continue
                run_id = str(item.get("run_id") or "")
                if not run_id:
                    continue
                status = classify_run_status(run_id)
                bucket["run_ids"].add(run_id)
                if EVIDENCE_RANK[status] > EVIDENCE_RANK[bucket["status"]]:
                    bucket["status"] = status
    return evidence


def build_matrix(platforms_filter: set[str] | None) -> dict[str, Any]:
    rules = load_rules()
    technique_evidence = load_technique_evidence()

    techniques: dict[str, dict[str, Any]] = {}
    for rule in rules:
        for technique in rule["techniques"]:
            entry = techniques.setdefault(
                technique,
                {
                    "technique": technique,
                    "platforms": set(),
                    "tactics": set(),
                    "rule_count": 0,
                    "level_counts": {},
                    "rule_paths": set(),
                },
            )
            entry["rule_count"] += 1
            entry["platforms"].update(rule["platforms"])
            entry["tactics"].update(rule["tactics"])
            entry["level_counts"][rule["level"]] = entry["level_counts"].get(rule["level"], 0) + 1
            entry["rule_paths"].add(rule["path"])

    rows: list[dict[str, Any]] = []
    for technique, entry in techniques.items():
        platforms = sorted(entry["platforms"])
        if platforms_filter is not None and not (entry["platforms"] & platforms_filter):
            continue
        tactics = sorted(entry["tactics"])
        evidence = technique_evidence.get(technique, {"status": "none", "run_ids": set()})
        status = evidence["status"]
        level_counts = entry["level_counts"]
        high_crit = level_counts.get("high", 0) + level_counts.get("critical", 0)
        rows.append(
            {
                "technique": technique,
                "tactic_area": tactic_area(tactics),
                "tactics": tactics,
                "platforms": platforms,
                "rule_count": entry["rule_count"],
                "level_counts": dict(sorted(level_counts.items())),
                "high_critical_rule_count": high_crit,
                "evidence_status": status,
                "evidence_run_ids": sorted(evidence["run_ids"]),
                "claim_boundary": CLAIM_BOUNDARY_BY_STATUS[status],
            }
        )

    rows.sort(key=lambda row: (row["tactic_area"], row["technique"]))

    status_counts = {key: 0 for key in EVIDENCE_RANK}
    platform_counts = {platform: 0 for platform in ALL_PLATFORMS}
    cross_platform = 0
    for row in rows:
        status_counts[row["evidence_status"]] += 1
        for platform in row["platforms"]:
            if platform in platform_counts:
                platform_counts[platform] += 1
        if len(row["platforms"]) > 1:
            cross_platform += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "git": git_snapshot(),
        "external_claim_allowed": False,
        "claim_boundary": (
            "Offline rule-content coverage analysis. Per-technique rows count sigma rule "
            "content and report the strongest evidence status linked via "
            "detection_rule_evidence_matrix.json (live > replay > fixture > none). This is "
            "rule-content plus linked-evidence analysis, not a third-party-validated coverage "
            "claim, and never an external claim."
        ),
        "source": {
            "rule_dir": str(RULE_DIR.relative_to(ROOT)).replace("\\", "/"),
            "evidence_matrix": str(EVIDENCE_MATRIX.relative_to(ROOT)).replace("\\", "/"),
            "evidence_matrix_present": EVIDENCE_MATRIX.exists(),
            "rules_with_techniques": len(rules),
        },
        "platforms_filter": sorted(platforms_filter) if platforms_filter is not None else None,
        "summary": {
            "total_techniques": len(rows),
            "evidence_status_counts": status_counts,
            "platform_technique_counts": platform_counts,
            "cross_platform_techniques": cross_platform,
        },
        "techniques": rows,
    }


def render_markdown(matrix: dict[str, Any]) -> str:
    summary = matrix["summary"]
    status = summary["evidence_status_counts"]
    platform = summary["platform_technique_counts"]
    git = matrix.get("git") or {}
    lines = [
        "# ATT&CK Coverage Matrix",
        "",
        "Status: generated",
        "",
        "Offline rule-content analysis generated by",
        "`tools/detection_validation/attack_coverage_matrix.py` from sigma rule frontmatter",
        "and `docs/benchmarks/generated/detection_rule_evidence_matrix.json`.",
        "",
        f"- Generated at: `{matrix['generated_at']}`",
        f"- Git commit: `{git.get('commit_short') or '-'}`"
        + (" (dirty)" if git.get("dirty") else ""),
        f"- External claim allowed: `{str(matrix['external_claim_allowed']).lower()}`",
        f"- Total techniques: `{summary['total_techniques']}`",
        f"- Cross-platform techniques: `{summary['cross_platform_techniques']}`",
        "",
        "## Claim Boundary",
        "",
        matrix["claim_boundary"],
        "",
        "## Summary Counts",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total techniques | `{summary['total_techniques']}` |",
        f"| Windows techniques | `{platform.get('windows', 0)}` |",
        f"| Linux techniques | `{platform.get('linux', 0)}` |",
        f"| macOS techniques | `{platform.get('macos', 0)}` |",
        f"| Evidence: live | `{status.get('live', 0)}` |",
        f"| Evidence: replay | `{status.get('replay', 0)}` |",
        f"| Evidence: fixture | `{status.get('fixture', 0)}` |",
        f"| Evidence: none | `{status.get('none', 0)}` |",
        "",
        "## Techniques",
        "",
        "| Technique | Tactic/Area | Platforms | Rules (total / high+crit) | Evidence status | Claim boundary |",
        "|-----------|-------------|-----------|---------------------------|-----------------|----------------|",
    ]
    for row in matrix["techniques"]:
        platforms = ", ".join(row["platforms"]) or "-"
        lines.append(
            f"| `{row['technique']}` | {row['tactic_area']} | `{platforms}` | "
            f"`{row['rule_count']} / {row['high_critical_rule_count']}` | "
            f"`{row['evidence_status']}` | `{row['claim_boundary']}` |"
        )
    if not matrix["techniques"]:
        lines.append("| - | - | - | - | - | - |")
    return "\n".join(lines) + "\n"


def parse_platforms(value: str | None) -> set[str] | None:
    if not value:
        return None
    requested = {part.strip().lower() for part in value.split(",") if part.strip()}
    invalid = requested - set(ALL_PLATFORMS)
    if invalid:
        raise SystemExit(
            f"unknown platform(s): {', '.join(sorted(invalid))}; "
            f"valid values are {', '.join(ALL_PLATFORMS)}"
        )
    return requested or None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=GENERATED_DIR)
    parser.add_argument(
        "--platforms",
        default=None,
        help="Comma-separated platform filter (windows,linux,macos). Default: all.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    platforms_filter = parse_platforms(args.platforms)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    matrix = build_matrix(platforms_filter)
    json_path = args.output_dir / "attack_coverage_matrix.json"
    md_path = args.output_dir / "attack_coverage_matrix.md"
    json_path.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(matrix), encoding="utf-8")
    summary = matrix["summary"]
    status = summary["evidence_status_counts"]
    platform = summary["platform_technique_counts"]
    print(
        "attack_coverage_matrix=ok "
        f"techniques={summary['total_techniques']} "
        f"windows={platform.get('windows', 0)} "
        f"linux={platform.get('linux', 0)} "
        f"macos={platform.get('macos', 0)} "
        f"live={status.get('live', 0)} "
        f"replay={status.get('replay', 0)} "
        f"fixture={status.get('fixture', 0)} "
        f"none={status.get('none', 0)} "
        f"json={json_path} markdown={md_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
