#!/usr/bin/env python3
"""Readiness-artifact reference linter for hand-written benchmark docs.

Hand-written markdown under ``docs/benchmarks/`` references run artifacts in
``docs/benchmarks/runs/`` either as full relative paths
(``docs/benchmarks/runs/20260609T003928Z-ablation-static-latent.json``) or as
bare timestamped stems (``20260618T175420Z-macos-backend-readiness-probe``).
Those references silently rot when artifacts are renamed, archived, or never
land. This linter scans the hand-written docs, extracts both reference forms,
and verifies each referenced artifact still exists on disk under
``docs/benchmarks/runs/`` (any extension counts for bare stems; an explicit
extension must match exactly).

Scope rules:
- Scans ``docs/benchmarks/**/*.md`` EXCLUDING ``docs/benchmarks/generated/``
  (tool output, never hand-edited), ``docs/benchmarks/runs/`` (the artifacts
  themselves), and known tool-generated top-level docs (the per-OS
  ``*_DETECTION_ROADMAP_300.md`` docs, ``DETECTION_ROADMAP_INDEX.md``,
  ``BENCHMARK_RESULTS_REVIEW.md``, and the generated ``EXTERNAL_RULE_*`` set).
- References that point into ``docs/benchmarks/generated/`` are out of scope
  (different authority; regenerated wholesale) and are skipped.
- References whose original text ends with ``.*`` (glob-for-future-artifact
  form, e.g. lab-runbook acceptance bullets naming artifacts a future operator
  run will create) are PROSPECTIVE: when they do not resolve on disk they are
  reported in a separate "prospective" category and do not affect the exit
  code; when they do resolve they count as ok.
- For referenced ``.json`` artifacts that exist, a light sanity check is run:
  the file must parse as JSON (BOM-tolerant, decoded as ``utf-8-sig``) and be
  non-empty; a top-level ``schema`` / ``$schema`` / ``schema_version`` /
  ``$id`` key is recorded when present. This is NOT schema validation.

Usage:
    python tools/detection_validation/readiness_probe_linter.py
    python tools/detection_validation/readiness_probe_linter.py --json-out %TEMP%/readiness_linter_report.json

Exit code 0 when no missing references were found, 1 otherwise. Prospective
references and JSON sanity warnings are reported but do not affect the exit
code.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = ROOT / "docs" / "benchmarks"
RUNS_DIR = BENCH_DIR / "runs"
GENERATED_DIR = BENCH_DIR / "generated"

# Top-level docs under docs/benchmarks/ that are tool output, not hand-written.
# See tools/detection_validation/scripts/build_roadmap_index.py,
# generate_unix_roadmaps_300.py, generate_windows_roadmap_300.py,
# summarize_benchmark_runs.py, generate_external_rule_coverage_map.py,
# external_rule_event_contracts.py, external_rule_implementation_backlog.py.
GENERATED_DOC_NAMES = {
    "DETECTION_ROADMAP_INDEX.md",
    "BENCHMARK_RESULTS_REVIEW.md",
    "EXTERNAL_RULE_COVERAGE_MAPPING.md",
    "EXTERNAL_RULE_EVENT_CONTRACTS.md",
    "EXTERNAL_RULE_IMPLEMENTATION_BACKLOG.md",
}
GENERATED_DOC_PATTERNS = (re.compile(r"^[A-Z]+_DETECTION_ROADMAP_300\.md$"),)

STEM_RE = re.compile(r"\d{8}T\d{6}Z-[A-Za-z0-9_-]+(?:\.[A-Za-z0-9][A-Za-z0-9.]*)?")
RUNS_PATH_RE = re.compile(r"docs[/\\]benchmarks[/\\]runs[/\\][A-Za-z0-9_.\\/\-]+")
PATHISH_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-/\\")
SCHEMA_KEYS = ("schema", "$schema", "schema_version", "$id")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def is_generated_doc(path: Path) -> bool:
    rel_parts = path.relative_to(BENCH_DIR).parts
    if rel_parts and rel_parts[0] in ("generated", "runs"):
        return True
    name = path.name
    if name in GENERATED_DOC_NAMES:
        return True
    return any(pattern.match(name) for pattern in GENERATED_DOC_PATTERNS)


def collect_docs() -> tuple[list[Path], list[Path]]:
    scanned: list[Path] = []
    excluded: list[Path] = []
    for path in sorted(BENCH_DIR.rglob("*.md")):
        if is_generated_doc(path):
            excluded.append(path)
        else:
            scanned.append(path)
    return scanned, excluded


class RunsIndex:
    """Index of runs/ contents (files and directories, recursive)."""

    def __init__(self) -> None:
        self.rel_paths: set[str] = set()
        self.basenames: dict[str, list[str]] = {}
        self.stems: dict[str, list[str]] = {}
        if not RUNS_DIR.exists():
            return
        stem_prefix = re.compile(r"^(\d{8}T\d{6}Z-[A-Za-z0-9_-]+)")
        for entry in RUNS_DIR.rglob("*"):
            rel = entry.relative_to(RUNS_DIR).as_posix()
            self.rel_paths.add(rel)
            self.basenames.setdefault(entry.name, []).append(rel)
            match = stem_prefix.match(entry.name)
            if match:
                self.stems.setdefault(match.group(1), []).append(rel)

    def resolve(self, raw: str) -> tuple[bool, list[str]]:
        """Resolve a reference (rel path, basename, or bare stem) under runs/.

        Rules: exact path/basename match wins; a timestamped stem without an
        extension matches any extension; an explicit extension must match
        exactly; non-standard stems (e.g. ``20260630T-...``) match any entry
        named ``<raw>.<ext>`` so directory and truncated-timestamp artifacts
        do not read as false misses.
        """
        raw = raw.rstrip("/")
        if not raw:
            return False, []
        if raw in self.rel_paths:
            return True, [raw]
        if "/" not in raw and raw in self.basenames:
            return True, self.basenames[raw]
        match = re.match(r"^(\d{8}T\d{6}Z-[A-Za-z0-9_-]+)(\..+)?$", raw)
        if match:
            if match.group(2):
                return False, []  # explicit extension, exact match required
            resolved = self.stems.get(match.group(1), [])
            return bool(resolved), resolved
        prefix = raw + "."
        resolved = sorted(
            {rel for name, rels in self.basenames.items() if name.startswith(prefix) for rel in rels}
        )
        return bool(resolved), resolved


def path_prefix_before(line: str, start: int) -> str:
    """Return the contiguous path-ish text immediately preceding ``start``."""
    idx = start
    while idx > 0 and line[idx - 1] in PATHISH_CHARS:
        idx -= 1
    return line[idx:start]


def strip_trailing_punct(text: str) -> str:
    return text.rstrip(".,;:)]}`'\"")


def is_prospective_glob(line: str, matched: str, end: int) -> bool:
    """True when the reference's ORIGINAL text ends with ``.*``.

    The extraction regexes never consume the ``*`` (and ``STEM_RE`` never
    consumes a dot not followed by an alphanumeric), so the glob suffix shows
    up as either a matched trailing ``.`` followed by ``*`` on the line, or as
    a literal ``.*`` immediately after the match.
    """
    tail = line[end:]
    if matched.endswith(".") and tail.startswith("*"):
        return True
    return tail.startswith(".*")


def json_sanity_check(rel_name: str) -> dict[str, Any]:
    """Light sanity check for a .json artifact under runs/ (not schema validation)."""
    result: dict[str, Any] = {"artifact": f"docs/benchmarks/runs/{rel_name}", "ok": True, "schema_field": None}
    path = RUNS_DIR / rel_name
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        result.update(ok=False, error=f"unreadable: {exc}")
        return result
    if not text.strip():
        result.update(ok=False, error="empty file")
        return result
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        result.update(ok=False, error=f"invalid JSON: {exc}")
        return result
    if payload in ({}, []):
        result.update(ok=False, error="empty JSON document")
        return result
    if isinstance(payload, dict):
        for key in SCHEMA_KEYS:
            if key in payload:
                result["schema_field"] = key
                break
    return result


def scan_doc(
    doc: Path,
    index: RunsIndex,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    """Scan one doc. Returns (ok_refs, missing_refs, prospective_refs, referenced json artifacts)."""
    ok_refs: list[dict[str, Any]] = []
    missing_refs: list[dict[str, Any]] = []
    prospective_refs: list[dict[str, Any]] = []
    json_artifacts: set[str] = set()
    rel_doc = doc.relative_to(ROOT).as_posix()
    text = doc.read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        consumed_spans: list[tuple[int, int]] = []

        for match in RUNS_PATH_RE.finditer(line):
            raw = strip_trailing_punct(match.group(0)).replace("\\", "/")
            consumed_spans.append(match.span())
            rel_in_runs = raw[len("docs/benchmarks/runs/") :]
            if not rel_in_runs.rstrip("/"):
                continue
            record = {"doc": rel_doc, "line": lineno, "reference": raw, "kind": "path"}
            exists, resolved = index.resolve(rel_in_runs)
            if exists:
                ok_refs.append(record)
                json_artifacts.update(n for n in resolved if n.endswith(".json"))
            elif is_prospective_glob(line, match.group(0), match.end()):
                prospective_refs.append(record)
            else:
                missing_refs.append(record)

        for match in STEM_RE.finditer(line):
            start, end = match.span()
            if any(s <= start and end <= e for s, e in consumed_spans):
                continue  # already handled as part of a full runs/ path
            prefix = path_prefix_before(line, start).replace("\\", "/").lower()
            if "/" in prefix and "runs/" not in prefix:
                continue  # path into some other directory (e.g. generated/)
            raw = strip_trailing_punct(match.group(0))
            record = {"doc": rel_doc, "line": lineno, "reference": raw, "kind": "stem"}
            exists, resolved = index.resolve(raw)
            if exists:
                ok_refs.append(record)
                json_artifacts.update(n for n in resolved if n.endswith(".json"))
            elif is_prospective_glob(line, match.group(0), end):
                prospective_refs.append(record)
            else:
                missing_refs.append(record)

    return ok_refs, missing_refs, prospective_refs, json_artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint docs/benchmarks/*.md for broken runs/ artifact references.")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional path for a machine-readable JSON report.")
    args = parser.parse_args()

    docs, excluded = collect_docs()
    index = RunsIndex()

    all_ok: list[dict[str, Any]] = []
    all_missing: list[dict[str, Any]] = []
    all_prospective: list[dict[str, Any]] = []
    json_artifacts: set[str] = set()
    for doc in docs:
        ok_refs, missing_refs, prospective_refs, doc_json = scan_doc(doc, index)
        all_ok.extend(ok_refs)
        all_missing.extend(missing_refs)
        all_prospective.extend(prospective_refs)
        json_artifacts.update(doc_json)

    json_checks = [json_sanity_check(rel) for rel in sorted(json_artifacts)]
    json_invalid = [check for check in json_checks if not check["ok"]]
    json_with_schema = sum(1 for check in json_checks if check["schema_field"])

    verdict = "ok" if not all_missing else "missing-references"
    report = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "profile_id": "readiness-probe-linter",
        "verdict": verdict,
        "docs_scanned": len(docs),
        "docs_excluded": len(excluded),
        "excluded_docs": [p.relative_to(ROOT).as_posix() for p in excluded if p.parent == BENCH_DIR],
        "references_total": len(all_ok) + len(all_missing) + len(all_prospective),
        "references_ok": len(all_ok),
        "references_missing": len(all_missing),
        "references_prospective": len(all_prospective),
        "missing": sorted(all_missing, key=lambda r: (r["doc"], r["line"], r["reference"])),
        "prospective": sorted(all_prospective, key=lambda r: (r["doc"], r["line"], r["reference"])),
        "json_sanity": {
            "checked": len(json_checks),
            "with_schema_field": json_with_schema,
            "invalid": json_invalid,
        },
    }

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"readiness_probe_linter verdict={verdict}")
    print(f"  docs scanned:        {len(docs)} (excluded generated/run docs: {len(excluded)})")
    print(f"  references found:    {len(all_ok) + len(all_missing) + len(all_prospective)}")
    print(f"  references ok:       {len(all_ok)}")
    print(f"  references missing:  {len(all_missing)}")
    print(f"  references prospective: {len(all_prospective)}")
    print(f"  json artifacts checked: {len(json_checks)} (schema field: {json_with_schema}, invalid: {len(json_invalid)})")
    if all_missing:
        print("missing references:")
        for record in report["missing"]:
            print(f"  {record['doc']}:{record['line']}: {record['reference']} [{record['kind']}]")
    if all_prospective:
        print("prospective references (future artifacts named as `<name>.*`; do not affect exit code):")
        for record in report["prospective"]:
            print(f"  {record['doc']}:{record['line']}: {record['reference']} [{record['kind']}]")
    if json_invalid:
        print("json sanity warnings (do not affect exit code):")
        for check in json_invalid:
            print(f"  {check['artifact']}: {check.get('error', 'unknown error')}")
    if args.json_out is not None:
        print(f"json report: {args.json_out}")

    return 0 if not all_missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
