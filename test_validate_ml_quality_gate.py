from __future__ import annotations

import sys
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import ContractError, validate_quality_gate  # noqa: E402


def test_validate_quality_gate_accepts_pass_with_all_checks_passed() -> None:
    validate_quality_gate(
        {"status": "pass", "checks": [{"name": "contract", "status": "pass"}]},
        "memory://quality_gate",
    )


def test_validate_quality_gate_rejects_pass_with_warning_check() -> None:
    try:
        validate_quality_gate(
            {"status": "pass", "checks": [{"name": "thresholds", "status": "warning"}]},
            "memory://quality_gate",
        )
    except ContractError as exc:
        assert "pass requires all checks to pass" in str(exc)
    else:
        raise AssertionError("expected pass gate with warning check to fail")


def test_validate_quality_gate_accepts_partial_with_warning_check() -> None:
    validate_quality_gate(
        {
            "status": "partial",
            "checks": [
                {"name": "model_execution", "status": "pass"},
                {"name": "thresholds", "status": "warning"},
            ],
        },
        "memory://quality_gate",
    )


def test_validate_quality_gate_rejects_partial_with_only_passed_checks() -> None:
    try:
        validate_quality_gate(
            {"status": "partial", "checks": [{"name": "contract", "status": "pass"}]},
            "memory://quality_gate",
        )
    except ContractError as exc:
        assert "partial requires warning or not_run checks" in str(exc)
    else:
        raise AssertionError("expected stale partial quality gate to fail")


def test_validate_quality_gate_accepts_not_run_with_not_run_check() -> None:
    validate_quality_gate(
        {
            "status": "not_run",
            "checks": [
                {"name": "manifest_shape", "status": "pass"},
                {"name": "model_execution", "status": "not_run"},
            ],
        },
        "memory://quality_gate",
    )


def test_validate_quality_gate_rejects_not_run_without_not_run_check() -> None:
    try:
        validate_quality_gate(
            {"status": "not_run", "checks": [{"name": "contract", "status": "pass"}]},
            "memory://quality_gate",
        )
    except ContractError as exc:
        assert "not_run requires at least one not_run check" in str(exc)
    else:
        raise AssertionError("expected not_run quality gate without not_run check to fail")


def test_validate_quality_gate_accepts_fail_with_failed_check() -> None:
    validate_quality_gate(
        {"status": "fail", "checks": [{"name": "quality_threshold", "status": "fail"}]},
        "memory://quality_gate",
    )


def test_validate_quality_gate_rejects_fail_without_failed_check() -> None:
    try:
        validate_quality_gate(
            {"status": "fail", "checks": [{"name": "contract", "status": "pass"}]},
            "memory://quality_gate",
        )
    except ContractError as exc:
        assert "fail requires at least one failed check" in str(exc)
    else:
        raise AssertionError("expected fail quality gate without failed check to fail")
