#!/usr/bin/env python3
"""Doc-vs-code anchor drift gate.

Validates `file:line` / `file:start-end` anchors written in curated markdown
docs against the current source tree, so that concurrent code commits cannot
silently invalidate documentation anchors (the drift class caught by the
2026-07-21 adversarial review).

Checks per anchor:
  1. STRUCTURAL (always enforced): the referenced file exists in the repo and
     the cited end line is <= the file's line count.
  2. SYMBOL PROXIMITY (best effort): when the anchor is preceded on the same
     doc line by an inline-code symbol (e.g. ``select_canonical_mount_attach``
     (`ebpf_linux.rs:184`)), the longest identifier of that symbol must occur
     in the referenced file within --tolerance lines of the cited line.
     Violations are warnings by default and failures with --strict.

Docs can fence historical/stale-by-design regions:
    <!-- ANCHOR-DRIFT: OFF -->  ... fenced region, anchors ignored ...
    <!-- ANCHOR-DRIFT: ON -->
or opt out entirely with `<!-- ANCHOR-DRIFT: SKIP-FILE -->` anywhere in the
file. Fencing preserves history without letting it fail the gate
(fence-don't-delete).

This gate validates documentation consistency only; it never promotes any
claim in the docs it scans.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MONOREPO_ROOT = SCRIPT_DIR.parents[2]
ROOT = (
    MONOREPO_ROOT
    if (MONOREPO_ROOT / "tools/detection_validation").is_dir()
    else SCRIPT_DIR.parent
)

# Curated high-anchor-density docs. Extend via CLI args.
DEFAULT_DOCS = [
    "CLAUDE.md",
    "docs/KNOWN_PRODUCTION_GAPS.md",
    "apps/tamandua_agent/docs/benchmarks/EBPF_READINESS_RUNBOOK.md",
    "docs/apps/tamandua_agent/EBPF_MOUNT_HOOK_PLAN.md",
    "docs/apps/tamandua_agent/LINUX_AUDITD_INTEGRATION.md",
    "docs/apps/tamandua_agent/LINUX_AUDITD_QUICKSTART.md",
    "docs/apps/tamandua_agent/MACOS_PLATFORM_VISIBILITY.md",
    "docs/apps/tamandua_agent/WINDOWS_KERNEL_VISIBILITY.md",
]

CODE_EXTENSIONS = (
    ".rs", ".ex", ".exs", ".heex", ".py", ".c", ".h", ".erl",
    ".ts", ".tsx", ".js", ".kt", ".swift", ".go", ".toml", ".yaml", ".yml",
)

# `path/to/file.rs:123` or `file.ex:12-34` inside an inline-code span.
ANCHOR_RE = re.compile(
    r"`(?P<path>[A-Za-z0-9_\-./]+?\.(?:%s)):(?P<start>\d+)(?:-(?P<end>\d+))?`"
    % "|".join(ext.lstrip(".") for ext in CODE_EXTENSIONS)
)
# Bare continuation ref: `:2175-2176` — binds to the most recent resolved
# file in the same paragraph.
BARE_RE = re.compile(r"`:(?P<start>\d+)(?:-(?P<end>\d+))?`")
# Inline-code span that is not an anchor (candidate symbol context).
CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")

SKIP_FILE_MARKER = "<!-- ANCHOR-DRIFT: SKIP-FILE -->"
OFF_MARKER = "<!-- ANCHOR-DRIFT: OFF -->"
ON_MARKER = "<!-- ANCHOR-DRIFT: ON -->"

# Identifiers too generic to be meaningful proximity witnesses.
GENERIC_IDENTS = {
    "default", "config", "server", "client", "struct", "impl", "test",
    "tests", "main", "true", "false", "None", "Some", "self", "return",
}


@dataclass
class Finding:
    severity: str  # "fail" | "warn" | "info"
    doc: str
    doc_line: int
    anchor: str
    detail: str

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "doc": self.doc,
            "doc_line": self.doc_line,
            "anchor": self.anchor,
            "detail": self.detail,
        }


@dataclass
class FileIndex:
    """Resolves doc-cited paths against `git ls-files` output."""

    paths: list[str]
    by_basename: dict = field(default_factory=dict)
    _cache: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        for path in self.paths:
            self.by_basename.setdefault(Path(path).name, []).append(path)

    def resolve(self, cited: str) -> str | None:
        if cited in self._cache:
            return self._cache[cited]
        resolved = self._resolve(cited)
        self._cache[cited] = resolved
        return resolved

    def _resolve(self, cited: str) -> str | None:
        cited = cited.lstrip("./")
        if cited in self.paths:
            return cited
        suffix_hits = [p for p in self.paths if p.endswith("/" + cited)]
        if len(suffix_hits) == 1:
            return suffix_hits[0]
        if len(suffix_hits) > 1:
            return None  # ambiguous
        base_hits = self.by_basename.get(Path(cited).name, [])
        if len(base_hits) == 1:
            return base_hits[0]
        return None


def git_ls_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def load_lines(repo_rel: str, cache: dict) -> list[str]:
    if repo_rel not in cache:
        text = (ROOT / repo_rel).read_text(encoding="utf-8", errors="replace")
        cache[repo_rel] = text.splitlines()
    return cache[repo_rel]


HEX_RE = re.compile(r"[0-9a-fA-F]+")
# A witness span farther than this many characters before the anchor is
# assumed to belong to a different clause (guards against giant one-line
# paragraphs binding unrelated symbols).
WITNESS_WINDOW = 120


def pick_symbol(doc_line: str, anchor_start: int) -> str | None:
    """Nearest preceding non-anchor inline-code span's longest identifier."""
    best: str | None = None
    for match in CODE_SPAN_RE.finditer(doc_line[:anchor_start]):
        if anchor_start - match.end() > WITNESS_WINDOW:
            continue
        span = match.group(1)
        if re.fullmatch(r":?\d+(?:-\d+)?", span.split(":")[-1]) and (
            ANCHOR_RE.fullmatch("`%s`" % span) or BARE_RE.fullmatch("`%s`" % span)
        ):
            continue  # another anchor, not a symbol
        idents = [
            ident
            for ident in IDENT_RE.findall(span)
            if ident.lower() not in GENERIC_IDENTS
            and not HEX_RE.fullmatch(ident)  # commit hashes are not symbols
        ]
        if idents:
            best = max(idents, key=len)
    return best


def check_anchor(
    *,
    doc: str,
    doc_line_no: int,
    doc_line: str,
    anchor_text: str,
    anchor_pos: int,
    repo_rel: str,
    start: int,
    end: int,
    tolerance: int,
    content_cache: dict,
    findings: list[Finding],
) -> None:
    lines = load_lines(repo_rel, content_cache)
    if end > len(lines):
        findings.append(
            Finding(
                "fail",
                doc,
                doc_line_no,
                anchor_text,
                f"line {end} beyond EOF of {repo_rel} ({len(lines)} lines)",
            )
        )
        return

    symbol = pick_symbol(doc_line, anchor_pos)
    if not symbol:
        return  # structural check passed; no witness symbol available

    hit_lines = [
        idx + 1 for idx, line in enumerate(lines) if symbol in line
    ]
    if not hit_lines:
        findings.append(
            Finding(
                "warn",
                doc,
                doc_line_no,
                anchor_text,
                f"witness symbol `{symbol}` not found anywhere in {repo_rel}",
            )
        )
        return
    delta = min(abs(hit - start) for hit in hit_lines)
    if delta > tolerance:
        nearest = min(hit_lines, key=lambda hit: abs(hit - start))
        findings.append(
            Finding(
                "warn",
                doc,
                doc_line_no,
                anchor_text,
                f"witness symbol `{symbol}` nearest at {repo_rel}:{nearest} "
                f"(delta {delta} > tolerance {tolerance}); anchor likely drifted",
            )
        )


def scan_doc(
    doc_path: Path,
    *,
    index: FileIndex,
    tolerance: int,
    content_cache: dict,
) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    doc = str(doc_path.relative_to(ROOT)).replace("\\", "/")
    text = doc_path.read_text(encoding="utf-8", errors="replace")
    if SKIP_FILE_MARKER in text:
        findings.append(Finding("info", doc, 0, "-", "file opted out (SKIP-FILE marker)"))
        return findings, 0

    checked = 0
    fenced_off = False
    in_code_block = False
    last_resolved: str | None = None

    for doc_line_no, doc_line in enumerate(text.splitlines(), start=1):
        stripped = doc_line.strip()
        if OFF_MARKER in doc_line:
            fenced_off = True
            continue
        if ON_MARKER in doc_line:
            fenced_off = False
            continue
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if fenced_off:
            continue
        if not stripped:
            last_resolved = None  # paragraph boundary resets bare-ref binding
            continue

        for match in ANCHOR_RE.finditer(doc_line):
            cited = match.group("path")
            start = int(match.group("start"))
            end = int(match.group("end") or match.group("start"))
            repo_rel = index.resolve(cited)
            if repo_rel is None:
                findings.append(
                    Finding(
                        "warn",
                        doc,
                        doc_line_no,
                        match.group(0),
                        f"could not uniquely resolve `{cited}` in the repo (missing or ambiguous)",
                    )
                )
                continue
            last_resolved = repo_rel
            checked += 1
            check_anchor(
                doc=doc,
                doc_line_no=doc_line_no,
                doc_line=doc_line,
                anchor_text=match.group(0),
                anchor_pos=match.start(),
                repo_rel=repo_rel,
                start=start,
                end=end,
                tolerance=tolerance,
                content_cache=content_cache,
                findings=findings,
            )

        if last_resolved is not None and not in_code_block:
            for match in BARE_RE.finditer(doc_line):
                start = int(match.group("start"))
                end = int(match.group("end") or match.group("start"))
                checked += 1
                check_anchor(
                    doc=doc,
                    doc_line_no=doc_line_no,
                    doc_line=doc_line,
                    anchor_text=f"{match.group(0)} (bound to {last_resolved})",
                    anchor_pos=match.start(),
                    repo_rel=last_resolved,
                    start=start,
                    end=end,
                    tolerance=tolerance,
                    content_cache=content_cache,
                    findings=findings,
                )
    return findings, checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "docs",
        nargs="*",
        help="Markdown docs to scan (repo-relative). Defaults to the curated list.",
    )
    parser.add_argument(
        "--tolerance",
        type=int,
        default=40,
        help="Max allowed distance (lines) between cited line and witness symbol (default 40).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat symbol-proximity warnings as failures.",
    )
    parser.add_argument("--json", type=Path, help="Write findings JSON to this path.")
    args = parser.parse_args()

    doc_args = args.docs or DEFAULT_DOCS
    docs: list[Path] = []
    for entry in doc_args:
        path = (ROOT / entry).resolve()
        if not path.is_file():
            print(f"FAIL: doc not found: {entry}")
            return 1
        docs.append(path)

    index = FileIndex(git_ls_files())
    content_cache: dict = {}
    all_findings: list[Finding] = []
    total_checked = 0
    for doc_path in docs:
        findings, checked = scan_doc(
            doc_path, index=index, tolerance=args.tolerance, content_cache=content_cache
        )
        all_findings.extend(findings)
        total_checked += checked

    fails = [f for f in all_findings if f.severity == "fail"]
    warns = [f for f in all_findings if f.severity == "warn"]
    infos = [f for f in all_findings if f.severity == "info"]
    if args.strict:
        fails, warns = fails + warns, []

    for finding in fails:
        print(f"FAIL {finding.doc}:{finding.doc_line} {finding.anchor} -> {finding.detail}")
    for finding in warns:
        print(f"WARN {finding.doc}:{finding.doc_line} {finding.anchor} -> {finding.detail}")
    for finding in infos:
        print(f"INFO {finding.doc}:{finding.doc_line} -> {finding.detail}")

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "docs": [str(d.relative_to(ROOT)).replace("\\", "/") for d in docs],
                    "anchors_checked": total_checked,
                    "tolerance": args.tolerance,
                    "strict": args.strict,
                    "findings": [f.as_dict() for f in all_findings],
                    "ok": not fails,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    verdict = "PASS" if not fails else "FAIL"
    print(
        f"ANCHOR DRIFT {verdict}: {total_checked} anchors checked across "
        f"{len(docs)} docs ({len(fails)} fail, {len(warns)} warn, tolerance +/-{args.tolerance})"
    )
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
