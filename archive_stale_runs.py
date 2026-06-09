#!/usr/bin/env python3
"""Archive stale validation run artifacts.

Moves files in ``docs/benchmarks/runs/`` older than a configurable threshold
(default 7 days) into ``docs/benchmarks/runs/archive/<YYYY-MM>/``. For each
distinct *probe family* (inferred from filename suffix such as
``-validation-status-consistency-probe`` or ``-ml-execution-status``), the
latest run is always preserved outside the archive so that downstream tools
(scorecard generators, dispatch promotion gates) keep finding a current
artifact.

The default mode is ``--dry-run`` (no filesystem changes). Pass ``--execute``
to actually move files.

Output is a JSON+Markdown report under ``docs/benchmarks/runs/`` describing
the proposed/applied moves so it can be referenced by the validation
consistency probe.

Usage:
    python tools/detection_validation/archive_stale_runs.py --dry-run
    python tools/detection_validation/archive_stale_runs.py --execute --age-days 14
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
DEFAULT_ARCHIVE_SUBDIR = "archive"
DEFAULT_AGE_DAYS = 7

# Filename pattern: <timestamp>-<family>(.<modifier>)?(.<ext>)
# Examples:
#   20260604T190000Z-validation-status-consistency-probe.json
#   20260604T-ml-execution-status.md
#   ml-prod-candidate-v1-acquisition-dry-run.json (no timestamp prefix)
TIMESTAMP_PREFIX = re.compile(r"^(?P<ts>\d{8}T\d*Z?)[-_.](?P<rest>.+)$")


@dataclass
class RunArtifact:
    path: Path
    family: str
    timestamp: datetime | None
    is_directory: bool = False

    @property
    def relative(self) -> str:
        return str(self.path.relative_to(DEFAULT_RUNS_DIR))


@dataclass
class ArchiveReport:
    runs_dir: str
    archive_dir: str
    age_days: int
    cutoff: str
    dry_run: bool
    total_artifacts: int = 0
    families_inspected: int = 0
    archived: list[dict] = field(default_factory=list)
    preserved_latest: list[dict] = field(default_factory=list)
    skipped_untimestamped: list[dict] = field(default_factory=list)


def infer_family(name: str) -> tuple[str, datetime | None]:
    """Return ``(family, timestamp)`` for an artifact filename.

    Family is the filename with the leading timestamp + trailing extension
    stripped, plus any ``.comparison`` / ``.details`` / ``.run`` modifier
    collapsed so that grouped artifacts share a family.
    """
    match = TIMESTAMP_PREFIX.match(name)
    if not match:
        return _strip_extension(name), None

    ts_raw = match.group("ts")
    rest = match.group("rest")
    timestamp = _parse_timestamp(ts_raw)

    family = _strip_extension(rest)
    # Collapse common companion suffixes so that the comparison/details/run
    # variants of the same probe are grouped under one family.
    family = re.sub(r"\.(comparison|details|run|print|package-artifacts|handoff)(?=$|\.)", "", family)
    return family, timestamp


def _strip_extension(name: str) -> str:
    # Strip all trailing dot-suffixes that look like extensions (.json/.md/.csv/etc).
    parts = name.split(".")
    while len(parts) > 1 and len(parts[-1]) <= 6 and parts[-1].isalnum():
        parts.pop()
    return ".".join(parts) if parts else name


def _parse_timestamp(raw: str) -> datetime | None:
    # Accept 20260604T190000Z, 20260604T, 20260604T1313Z
    raw = raw.rstrip("Z")
    if "T" not in raw:
        return None
    date_part, time_part = raw.split("T", 1)
    if not date_part or len(date_part) != 8 or not date_part.isdigit():
        return None
    fmts = ["%Y%m%dT%H%M%S", "%Y%m%dT%H%M", "%Y%m%dT%H", "%Y%m%dT"]
    if time_part:
        candidates = [f"{date_part}T{time_part}"]
    else:
        candidates = [f"{date_part}T"]
    for cand in candidates:
        for fmt in fmts:
            try:
                return datetime.strptime(cand, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    # Fallback: just the date with midnight UTC
    try:
        return datetime.strptime(date_part, "%Y%m%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def discover_artifacts(runs_dir: Path, archive_subdir: str) -> Iterable[RunArtifact]:
    archive_root = runs_dir / archive_subdir
    for entry in sorted(runs_dir.iterdir()):
        if entry == archive_root:
            continue
        if entry.name.startswith("."):
            continue
        family, ts = infer_family(entry.name)
        yield RunArtifact(path=entry, family=family, timestamp=ts, is_directory=entry.is_dir())


def plan_archive(
    artifacts: list[RunArtifact],
    cutoff: datetime,
) -> tuple[list[RunArtifact], list[RunArtifact], list[RunArtifact]]:
    """Return ``(to_archive, preserved_latest, skipped_untimestamped)``."""
    by_family: dict[str, list[RunArtifact]] = defaultdict(list)
    skipped: list[RunArtifact] = []

    for art in artifacts:
        if art.timestamp is None:
            skipped.append(art)
            continue
        by_family[art.family].append(art)

    to_archive: list[RunArtifact] = []
    preserved: list[RunArtifact] = []

    for family, members in by_family.items():
        members.sort(key=lambda a: a.timestamp or datetime.min.replace(tzinfo=timezone.utc))
        latest = members[-1]
        preserved.append(latest)
        for art in members[:-1]:
            assert art.timestamp is not None
            if art.timestamp < cutoff:
                to_archive.append(art)
            else:
                # Recent but not the latest — keep in place for now.
                preserved.append(art)

    return to_archive, preserved, skipped


def archive_path_for(art: RunArtifact, archive_root: Path) -> Path:
    assert art.timestamp is not None
    bucket = art.timestamp.strftime("%Y-%m")
    return archive_root / bucket / art.path.name


def move_into_archive(art: RunArtifact, archive_root: Path) -> Path:
    destination = archive_path_for(art, archive_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"archive destination already exists: {destination}")
    art.path.rename(destination)
    return destination


def render_markdown(report: ArchiveReport) -> str:
    lines = [
        "# Validation Run Archive Report",
        "",
        f"- runs_dir: `{report.runs_dir}`",
        f"- archive_dir: `{report.archive_dir}`",
        f"- age_days: {report.age_days}",
        f"- cutoff: {report.cutoff}",
        f"- dry_run: {str(report.dry_run).lower()}",
        f"- total_artifacts: {report.total_artifacts}",
        f"- families_inspected: {report.families_inspected}",
        f"- archived: {len(report.archived)}",
        f"- preserved_latest: {len(report.preserved_latest)}",
        f"- skipped_untimestamped: {len(report.skipped_untimestamped)}",
        "",
    ]

    if report.archived:
        lines.append("## Archived")
        lines.append("")
        lines.append("| family | source | destination |")
        lines.append("|--------|--------|-------------|")
        for entry in report.archived:
            lines.append(
                f"| `{entry['family']}` | `{entry['source']}` | `{entry['destination']}` |"
            )
        lines.append("")

    if report.preserved_latest:
        lines.append("## Preserved (latest per family or within age window)")
        lines.append("")
        lines.append("| family | path | timestamp |")
        lines.append("|--------|------|-----------|")
        for entry in report.preserved_latest:
            lines.append(
                f"| `{entry['family']}` | `{entry['path']}` | {entry['timestamp'] or '-'} |"
            )
        lines.append("")

    if report.skipped_untimestamped:
        lines.append("## Skipped (no parseable timestamp)")
        lines.append("")
        for entry in report.skipped_untimestamped:
            lines.append(f"- `{entry['path']}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR)
    parser.add_argument("--archive-subdir", default=DEFAULT_ARCHIVE_SUBDIR)
    parser.add_argument("--age-days", type=int, default=DEFAULT_AGE_DAYS)
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually move files. Default behaviour is dry-run.",
    )
    parser.add_argument("--report-name", default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    runs_dir: Path = args.runs_dir.resolve()
    if not runs_dir.is_dir():
        print(f"runs directory does not exist: {runs_dir}", file=sys.stderr)
        return 2

    dry_run = not args.execute
    archive_root = runs_dir / args.archive_subdir
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.age_days)

    artifacts = list(discover_artifacts(runs_dir, args.archive_subdir))
    to_archive, preserved, skipped = plan_archive(artifacts, cutoff)

    report = ArchiveReport(
        runs_dir=str(runs_dir),
        archive_dir=str(archive_root),
        age_days=args.age_days,
        cutoff=cutoff.isoformat(),
        dry_run=dry_run,
        total_artifacts=len(artifacts),
        families_inspected=len({a.family for a in artifacts if a.timestamp is not None}),
    )

    for art in to_archive:
        destination = archive_path_for(art, archive_root)
        report.archived.append(
            {
                "family": art.family,
                "source": str(art.path.relative_to(runs_dir)),
                "destination": str(destination.relative_to(runs_dir)),
                "timestamp": art.timestamp.isoformat() if art.timestamp else None,
                "is_directory": art.is_directory,
            }
        )

    for art in preserved:
        report.preserved_latest.append(
            {
                "family": art.family,
                "path": str(art.path.relative_to(runs_dir)),
                "timestamp": art.timestamp.isoformat() if art.timestamp else None,
            }
        )

    for art in skipped:
        report.skipped_untimestamped.append(
            {"path": str(art.path.relative_to(runs_dir))}
        )

    if not dry_run:
        for art in to_archive:
            try:
                move_into_archive(art, archive_root)
            except FileExistsError as exc:
                print(f"skip: {exc}", file=sys.stderr)

    timestamp_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_basename = args.report_name or f"{timestamp_tag}-validation-run-archive"
    json_path = runs_dir / f"{report_basename}.json"
    md_path = runs_dir / f"{report_basename}.md"

    json_path.write_text(json.dumps(asdict(report), indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")

    if not args.quiet:
        mode = "dry-run" if dry_run else "execute"
        print(
            f"[{mode}] inspected {report.total_artifacts} artifacts across "
            f"{report.families_inspected} families; "
            f"to_archive={len(report.archived)} preserved={len(report.preserved_latest)} "
            f"skipped={len(report.skipped_untimestamped)}"
        )
        print(f"report: {json_path.relative_to(ROOT)}")
        print(f"report: {md_path.relative_to(ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
