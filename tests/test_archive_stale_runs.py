"""Unit tests for archive_stale_runs."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from archive_stale_runs import (
    DEFAULT_ARCHIVE_SUBDIR,
    discover_artifacts,
    infer_family,
    main,
    plan_archive,
)


@pytest.fixture()
def runs_dir(tmp_path: Path) -> Path:
    runs = tmp_path / "runs"
    runs.mkdir()
    return runs


def make_file(path: Path, mtime: datetime | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("ok", encoding="utf-8")
    if mtime is not None:
        ts = mtime.timestamp()
        import os

        os.utime(path, (ts, ts))
    return path


def test_infer_family_strips_timestamp_and_extension() -> None:
    family, ts = infer_family("20260604T190000Z-validation-status-consistency-probe.json")
    assert family == "validation-status-consistency-probe"
    assert ts == datetime(2026, 6, 4, 19, 0, 0, tzinfo=timezone.utc)


def test_infer_family_collapses_comparison_suffix() -> None:
    family_a, _ = infer_family("20260604T190000Z-foo-probe.json")
    family_b, _ = infer_family("20260604T190000Z-foo-probe.comparison.json")
    family_c, _ = infer_family("20260604T190000Z-foo-probe.details.json")
    assert family_a == family_b == family_c == "foo-probe"


def test_infer_family_handles_partial_timestamp() -> None:
    family, ts = infer_family("20260604T-ml-execution-status.md")
    assert family == "ml-execution-status"
    assert ts == datetime(2026, 6, 4, 0, 0, 0, tzinfo=timezone.utc)


def test_infer_family_returns_none_when_no_timestamp() -> None:
    family, ts = infer_family("ml-prod-candidate-v1-acquisition-dry-run.json")
    assert ts is None
    assert "ml-prod-candidate" in family


def test_plan_archive_preserves_latest_per_family(runs_dir: Path) -> None:
    old = make_file(runs_dir / "20260101T000000Z-foo-probe.json")
    older = make_file(runs_dir / "20251201T000000Z-foo-probe.json")
    newest = make_file(runs_dir / "20260604T000000Z-foo-probe.json")
    # bar-probe has only one run; it must be preserved as its family's latest
    # even though it predates the cutoff.
    singleton = make_file(runs_dir / "20260101T000000Z-bar-probe.json")

    artifacts = list(discover_artifacts(runs_dir, DEFAULT_ARCHIVE_SUBDIR))
    cutoff = datetime(2026, 5, 1, tzinfo=timezone.utc)
    to_archive, preserved, skipped = plan_archive(artifacts, cutoff)

    archive_paths = {a.path for a in to_archive}
    preserved_paths = {a.path for a in preserved}

    assert newest in preserved_paths
    assert singleton in preserved_paths
    assert old in archive_paths
    assert older in archive_paths
    assert not skipped


def test_plan_archive_skips_untimestamped(runs_dir: Path) -> None:
    untimestamped = make_file(runs_dir / "ml-prod-candidate-v1-acquisition-dry-run.json")
    artifacts = list(discover_artifacts(runs_dir, DEFAULT_ARCHIVE_SUBDIR))
    to_archive, preserved, skipped = plan_archive(
        artifacts, datetime.now(timezone.utc)
    )
    assert untimestamped not in {a.path for a in to_archive}
    assert untimestamped in {a.path for a in preserved + skipped}
    assert skipped


def test_main_dry_run_writes_report_without_moving(runs_dir: Path) -> None:
    make_file(runs_dir / "20260101T000000Z-foo-probe.json")
    make_file(runs_dir / "20260604T000000Z-foo-probe.json")

    rc = main(
        [
            "--runs-dir",
            str(runs_dir),
            "--age-days",
            "30",
            "--quiet",
        ]
    )
    assert rc == 0

    reports = list(runs_dir.glob("*-validation-run-archive.json"))
    assert len(reports) == 1
    data = json.loads(reports[0].read_text(encoding="utf-8"))
    assert data["dry_run"] is True
    assert data["total_artifacts"] >= 2

    # No archive directory was created (dry-run).
    assert not (runs_dir / "archive").exists()


def test_main_execute_moves_stale_runs(runs_dir: Path) -> None:
    old = make_file(runs_dir / "20260101T000000Z-foo-probe.json")
    newest = make_file(runs_dir / "20260604T000000Z-foo-probe.json")

    rc = main(
        [
            "--runs-dir",
            str(runs_dir),
            "--age-days",
            "30",
            "--execute",
            "--quiet",
        ]
    )
    assert rc == 0

    assert not old.exists()
    assert newest.exists()
    archive_target = runs_dir / "archive" / "2026-01" / "20260101T000000Z-foo-probe.json"
    assert archive_target.exists()
