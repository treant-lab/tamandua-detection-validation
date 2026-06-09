from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    WAVE1_EXECUTE_GUARD_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_execute_guard,
)
from test_validate_ml_wave2_ml1_readiness import GOAL_SNAPSHOT  # noqa: E402


def valid_wave1_execute_guard() -> dict:
    checks = [
        {"name": "launcher_exists", "passed": True, "detail": "wave_1_real_acquisition_launcher.ps1"},
        {"name": "direct_cli_exists", "passed": True, "detail": "download_production_dataset.py"},
        {"name": "execute_rejected_without_guard", "passed": True, "detail": "returncode=1"},
        {"name": "direct_cli_rejected_without_guard", "passed": True, "detail": "returncode=2"},
        {
            "name": "production_manifest_absent_after_rejection",
            "passed": True,
            "detail": "D:/tamandua_ml_lab_data/production/manifest.json",
        },
        {
            "name": "canonical_dataset_manifest_absent_after_rejection",
            "passed": True,
            "detail": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
        },
    ]
    return {
        "api_version": "tamandua.io/ml-wave1-execute-guard-probe/v1",
        "kind": "MLWave1ExecuteGuardProbe",
        "metadata": {
            "report_id": "test_wave1_execute_guard",
            "generated_at": "2026-06-04T21:00:00Z",
            "created_by": "tamandua-ml-wave1-execute-guard-probe",
            "claim_boundary": "No-execution guard probe only. Verifies -Execute is rejected without the explicit TAMANDUA_ALLOW_ML_REAL_ACQUISITION guard and does not download malware.",
        },
        "source_status_summary": {
            **GOAL_SNAPSHOT,
            "launcher_exists": True,
            "direct_cli_exists": True,
            "execute_rejected_without_guard": True,
            "direct_cli_rejected_without_guard": True,
            "production_manifest_absent_after_rejection": True,
            "canonical_dataset_manifest_absent_after_rejection": True,
            "guard_env_removed": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
            "returncode": 1,
            "returncode_nonzero": True,
            "guard_message_present": True,
            "direct_cli_returncode": 2,
            "direct_cli_returncode_nonzero": True,
            "direct_cli_guard_message_present": True,
            "check_count": 6,
            "passed_checks": 6,
            "failed_checks": 0,
            "passed": True,
        },
        "configuration": {
            "launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1",
            "direct_cli": "apps/tamandua_ml/scripts/download_production_dataset.py",
            "data_root": "D:/tamandua_ml_lab_data",
            "production_manifest": "D:/tamandua_ml_lab_data/production/manifest.json",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "guard_env_removed": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        },
        "passed": True,
        "returncode": 1,
        "stdout": "validated Wave 1 go/no-go",
        "stderr": (
            "Set TAMANDUA_ALLOW_ML_REAL_ACQUISITION with "
            "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1' to run real malware/goodware acquisition."
        ),
        "direct_cli_returncode": 2,
        "direct_cli_stdout": "",
        "direct_cli_stderr": (
            "Refusing real acquisition: set TAMANDUA_ALLOW_ML_REAL_ACQUISITION=1 "
            "inside the isolated malware lab shell."
        ),
        "checks": checks,
    }


def test_validate_wave1_execute_guard_accepts_valid_contract() -> None:
    validate_wave1_execute_guard(valid_wave1_execute_guard(), Path("memory://ml-wave1-execute-guard.json"))


def test_validate_wave1_execute_guard_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-wave1-execute-guard.json"
    report_path.write_text(json.dumps(valid_wave1_execute_guard()), encoding="utf-8")

    mode = validate_contract(report_path, WAVE1_EXECUTE_GUARD_SCHEMA, validate_wave1_execute_guard)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_execute_guard_rejects_zero_returncode_for_green_report() -> None:
    payload = copy.deepcopy(valid_wave1_execute_guard())
    payload["returncode"] = 0
    payload["source_status_summary"]["returncode"] = 0
    payload["source_status_summary"]["returncode_nonzero"] = False

    try:
        validate_wave1_execute_guard(payload, Path("memory://ml-wave1-execute-guard.json"))
    except ContractError as exc:
        assert "returncode" in str(exc)
    else:
        raise AssertionError("expected zero returncode to fail")


def test_validate_wave1_execute_guard_rejects_missing_guard_output() -> None:
    payload = copy.deepcopy(valid_wave1_execute_guard())
    payload["stderr"] = "other failure"
    payload["source_status_summary"]["guard_message_present"] = False

    try:
        validate_wave1_execute_guard(payload, Path("memory://ml-wave1-execute-guard.json"))
    except ContractError as exc:
        assert "acquisition guard" in str(exc)
    else:
        raise AssertionError("expected missing guard output to fail")


def test_validate_wave1_execute_guard_rejects_missing_direct_cli_guard_output() -> None:
    payload = copy.deepcopy(valid_wave1_execute_guard())
    payload["direct_cli_stderr"] = "other failure"
    payload["source_status_summary"]["direct_cli_guard_message_present"] = False

    try:
        validate_wave1_execute_guard(payload, Path("memory://ml-wave1-execute-guard.json"))
    except ContractError as exc:
        assert "direct CLI guard" in str(exc) or "direct_cli_guard_message_present" in str(exc)
    else:
        raise AssertionError("expected missing direct CLI guard output to fail")


def test_validate_wave1_execute_guard_rejects_manifest_present_for_green_report() -> None:
    payload = copy.deepcopy(valid_wave1_execute_guard())
    check = next(item for item in payload["checks"] if item["name"] == "production_manifest_absent_after_rejection")
    check["passed"] = False
    payload["source_status_summary"]["production_manifest_absent_after_rejection"] = False
    payload["source_status_summary"]["passed_checks"] = 5
    payload["source_status_summary"]["failed_checks"] = 1

    try:
        validate_wave1_execute_guard(payload, Path("memory://ml-wave1-execute-guard.json"))
    except ContractError as exc:
        assert ".passed" in str(exc)
    else:
        raise AssertionError("expected manifest-present guard probe to fail")


def test_validate_wave1_execute_guard_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_wave1_execute_guard())
    payload["source_status_summary"]["passed_checks"] = 3

    try:
        validate_wave1_execute_guard(payload, Path("memory://ml-wave1-execute-guard.json"))
    except ContractError as exc:
        assert "source_status_summary.passed_checks" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")
