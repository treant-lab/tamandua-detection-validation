#!/usr/bin/env python3
"""Validate the hand-written competitive gap matrix without promoting its claims."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
MONOREPO_ROOT = SCRIPT_DIR.parents[2]
ROOT = (
    MONOREPO_ROOT
    if (MONOREPO_ROOT / "tools/detection_validation").is_dir()
    else SCRIPT_DIR.parent
)
DEFAULT_ROADMAP = ROOT / "docs/strategy/COMPETITIVE_GAPS_ROADMAP.md"
EXPECTED_ROWS = 89
EXPECTED_ADJACENT_IDS = {
    "CW-ID-001", "CW-EXP-001", "CW-DATA-001", "CW-BRW-001",
    "CW-NDR-001", "CW-EMAIL-001", "CW-SOAR-001", "CW-TI-001",
    "CW-MDR-001", "CW-AIS-001", "CW-OT-001", "CW-APPSEC-001",
}
EXPECTED_PARENTS = {
    "CG-MOB-001", "CG-MOB-002", "CG-MOB-003", "CG-MOB-004",
    "CG-EDR-001", "CG-EDR-002", "CG-EDR-003", "CG-EDR-004", "CG-EDR-005",
    "CG-SIEM-001", "CG-SIEM-002", "CG-MTD-001", "CG-MTD-002",
    "CG-CNA-001", "CG-CNA-002", "CG-BMK-001",
}
EXPECTED_STATUS_COUNTS = Counter({
    "mapped": 44,
    "external-blocked": 26,
    "active": 15,
    "hold": 4,
})
ALLOWED_PRIORITIES = {"P0", "P1", "P2"}
ALLOWED_STATUSES = set(EXPECTED_STATUS_COUNTS)
ALLOWED_DECISIONS = {"build", "build evidence", "integrate", "hybrid", "defer"}
ID_RE = re.compile(r"CG-(?:[A-Z]+|[0-9]{3})(?:-(?:[A-Z]+|[0-9]{3}))*")


def _plain(value: str) -> str:
    value = value.strip()
    if value.startswith("`") and value.endswith("`"):
        return value[1:-1]
    return value


def validate_roadmap(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    rows: list[list[str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("| `CG-"):
            continue
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        if len(columns) != 9:
            errors.append(f"line {line_number}: expected 9 matrix columns, got {len(columns)}")
            continue
        rows.append(columns)

    if len(rows) != EXPECTED_ROWS:
        errors.append(f"matrix: expected {EXPECTED_ROWS} rows, got {len(rows)}")

    ids = [_plain(row[0]) for row in rows]
    duplicates = sorted(item for item, count in Counter(ids).items() if count > 1)
    if duplicates:
        errors.append(f"matrix: duplicate IDs: {', '.join(duplicates)}")

    parents = {item for item in ids if item in EXPECTED_PARENTS}
    missing_parents = sorted(EXPECTED_PARENTS - parents)
    extra_parent_like = sorted(
        item for item in ids
        if re.fullmatch(r"CG-[A-Z]+-[0-9]{3}", item) and item not in EXPECTED_PARENTS
    )
    if missing_parents:
        errors.append(f"matrix: missing parent IDs: {', '.join(missing_parents)}")
    if extra_parent_like:
        errors.append(f"matrix: unexpected parent IDs: {', '.join(extra_parent_like)}")

    status_counts: Counter[str] = Counter()
    known = set(ids)
    for row in rows:
        gap_id, priority, owner, status, decision, dependencies, acceptance, command, evidence = row
        gap_id = _plain(gap_id)
        priority = _plain(priority)
        status = _plain(status)
        decision = _plain(decision)
        status_counts[status] += 1
        if priority not in ALLOWED_PRIORITIES:
            errors.append(f"{gap_id}: invalid priority {priority!r}")
        if status not in ALLOWED_STATUSES:
            errors.append(f"{gap_id}: invalid status {status!r}")
        if decision not in ALLOWED_DECISIONS:
            errors.append(f"{gap_id}: invalid decision {decision!r}")
        for label, value in (
            ("owner", owner), ("dependencies", dependencies),
            ("acceptance", acceptance), ("command", command), ("evidence", evidence),
        ):
            if not _plain(value):
                errors.append(f"{gap_id}: empty {label}")
        missing_dependencies = sorted(set(ID_RE.findall(dependencies)) - known)
        if missing_dependencies:
            errors.append(
                f"{gap_id}: unresolved dependencies: {', '.join(missing_dependencies)}"
            )
        command_text = _plain(command)
        if command_text.startswith("TBD:"):
            candidate = command_text[4:].strip().split()[1:2]
            if candidate and (ROOT / candidate[0]).exists():
                errors.append(f"{gap_id}: TBD command points to an existing path {candidate[0]}")

    if status_counts != EXPECTED_STATUS_COUNTS:
        errors.append(
            "matrix: status counts differ; expected "
            f"{dict(EXPECTED_STATUS_COUNTS)}, got {dict(status_counts)}"
        )

    adjacent_heading = "### Adjacent-category execution contracts"
    if adjacent_heading not in text:
        errors.append("adjacent: missing execution-contract section")
    else:
        adjacent_text = text.split(adjacent_heading, 1)[1]
        adjacent_rows: list[list[str]] = []
        for line_number, line in enumerate(adjacent_text.splitlines(), start=1):
            if not line.startswith("| `CW-"):
                continue
            columns = [column.strip() for column in line.strip().strip("|").split("|")]
            if len(columns) != 5:
                errors.append(
                    f"adjacent line {line_number}: expected 5 columns, got {len(columns)}"
                )
                continue
            adjacent_rows.append(columns)
        adjacent_ids = [_plain(row[0]) for row in adjacent_rows]
        if set(adjacent_ids) != EXPECTED_ADJACENT_IDS:
            errors.append(
                "adjacent: IDs differ; expected "
                f"{sorted(EXPECTED_ADJACENT_IDS)}, got {sorted(set(adjacent_ids))}"
            )
        if len(adjacent_ids) != len(EXPECTED_ADJACENT_IDS):
            errors.append(
                f"adjacent: expected {len(EXPECTED_ADJACENT_IDS)} rows, got {len(adjacent_ids)}"
            )
        for row in adjacent_rows:
            backlog_id, owner, dependencies, acceptance, command_evidence = row
            backlog_id = _plain(backlog_id)
            for label, value in (
                ("owner", owner), ("dependencies", dependencies),
                ("acceptance", acceptance), ("command/evidence", command_evidence),
            ):
                if not _plain(value):
                    errors.append(f"{backlog_id}: empty adjacent {label}")
            command_evidence = _plain(command_evidence)
            if "TBD:" not in command_evidence:
                errors.append(f"{backlog_id}: adjacent command must remain explicit TBD")
            if "docs/benchmarks/runs/adjacent/" not in command_evidence:
                errors.append(f"{backlog_id}: missing adjacent planned evidence path")

    snapshot_markers = (
        "89 stable items", "12 adjacent-category backlog items", "15 `active`", "44\n`mapped`", "26 `external-blocked`", "4 `hold`",
        "Thirteen rows name an existing", "76 intentionally retain a `TBD:`",
    )
    normalized = text.replace("\r\n", "\n")
    for marker in snapshot_markers:
        if marker not in normalized:
            errors.append(f"snapshot: missing synchronized marker {marker!r}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("roadmap", nargs="?", type=Path, default=DEFAULT_ROADMAP)
    parser.add_argument("--strict", action="store_true", help="reserved explicit strict lane")
    args = parser.parse_args(argv)
    try:
        errors = validate_roadmap(args.roadmap)
    except (OSError, UnicodeError) as exc:
        print(f"competitive roadmap: ERROR: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("competitive roadmap: INVALID", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        "competitive roadmap: STRUCTURAL PASS "
        "(89 core items + 12 adjacent backlog contracts); planning evidence only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
