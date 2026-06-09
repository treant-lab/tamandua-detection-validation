from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from ml_public_claims_guard import DEFAULT_PUBLIC_FILES, validate_public_claims  # noqa: E402


def test_public_claims_guard_rejects_ml_powered_overclaim(tmp_path: Path) -> None:
    public_doc = tmp_path / "claim.md"
    public_doc.write_text(
        "Tamandua provides ML-powered detection with Malware-SMELL.",
        encoding="utf-8",
    )

    try:
        validate_public_claims([public_doc])
    except SystemExit as exc:
        assert "public ML overclaims found" in str(exc)
        assert "ml-powered" in str(exc)
    else:
        raise AssertionError("expected public ML overclaim to fail")


def test_public_claims_guard_requires_boundary_for_ml_files(tmp_path: Path) -> None:
    public_doc = tmp_path / "claim.md"
    public_doc.write_text(
        "Tamandua includes Malware-SMELL inspired scoring.",
        encoding="utf-8",
    )

    try:
        validate_public_claims([public_doc])
    except SystemExit as exc:
        assert "missing validation boundary" in str(exc)
    else:
        raise AssertionError("expected ML public doc without boundary to fail")


def test_public_claims_guard_accepts_bounded_claim(tmp_path: Path) -> None:
    public_doc = tmp_path / "claim.md"
    public_doc.write_text(
        "Tamandua includes Malware-SMELL inspired scoring. "
        "Current artifacts are validation-ready and production validation pending.",
        encoding="utf-8",
    )

    validate_public_claims([public_doc])


def test_public_claims_guard_includes_ml_training_pipeline_roadmap() -> None:
    roadmap = ROOT / "docs" / "benchmarks" / "ML_TRAINING_PIPELINE_ROADMAP.md"

    assert roadmap in DEFAULT_PUBLIC_FILES
    validate_public_claims([roadmap])
