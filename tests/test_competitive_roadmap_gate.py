from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from competitive_roadmap_gate import validate_roadmap


TEST_DIR = Path(__file__).resolve().parent
MONOREPO_ROOT = TEST_DIR.parents[2]
ROOT = (
    MONOREPO_ROOT
    if (MONOREPO_ROOT / "tools/detection_validation").is_dir()
    else TEST_DIR.parent
)
DETECTION_ROOT = (
    ROOT / "tools/detection_validation"
    if (ROOT / "tools/detection_validation").is_dir()
    else ROOT
)
ROADMAP = ROOT / "docs/strategy/COMPETITIVE_GAPS_ROADMAP.md"
SCRIPT = DETECTION_ROOT / "scripts/competitive_roadmap_gate.py"


def mutate(tmp_path: Path, old: str, new: str) -> Path:
    text = ROADMAP.read_text(encoding="utf-8")
    assert old in text
    path = tmp_path / "roadmap.md"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return path


def test_canonical_roadmap_passes() -> None:
    assert validate_roadmap(ROADMAP) == []


def test_cli_reports_planning_boundary() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--strict"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "STRUCTURAL PASS (89 core items + 12 adjacent backlog contracts)" in completed.stdout
    assert "planning evidence only" in completed.stdout


def test_duplicate_id_fails(tmp_path: Path) -> None:
    path = mutate(tmp_path, "| `CG-MOB-001-A` |", "| `CG-MOB-001` |")
    errors = validate_roadmap(path)
    assert any("duplicate IDs" in error for error in errors)


def test_unknown_dependency_fails(tmp_path: Path) -> None:
    path = mutate(tmp_path, "CG-MOB-001-A, signed artifacts", "CG-MOB-999, signed artifacts")
    errors = validate_roadmap(path)
    assert any("unresolved dependencies: CG-MOB-999" in error for error in errors)


def test_status_snapshot_drift_fails(tmp_path: Path) -> None:
    path = mutate(tmp_path, "| active | build evidence |", "| mapped | build evidence |")
    errors = validate_roadmap(path)
    assert any("status counts differ" in error for error in errors)


def test_missing_adjacent_execution_contract_fails(tmp_path: Path) -> None:
    path = mutate(
        tmp_path,
        "| `CW-OT-001` | OT Safety Integration |",
        "| `CW-OT-MISSING` | OT Safety Integration |",
    )
    errors = validate_roadmap(path)
    assert any("adjacent: IDs differ" in error for error in errors)


def test_adjacent_contract_requires_planned_evidence_path(tmp_path: Path) -> None:
    path = mutate(
        tmp_path,
        "docs/benchmarks/runs/adjacent/itdr/<run-id>/protocol-receipt.json",
        "planned elsewhere",
    )
    errors = validate_roadmap(path)
    assert any("CW-ID-001: missing adjacent planned evidence path" in error for error in errors)
