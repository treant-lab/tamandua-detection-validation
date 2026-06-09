from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
SCRIPTS = ROOT / "apps" / "tamandua_ml" / "scripts"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(SCRIPTS))

from ml_execution_plan import build_plan, write_handoff  # noqa: E402
from ml_execution_status import build_status  # noqa: E402
from validate_ml_contracts import (  # noqa: E402
    ContractError,
    NEXT_ACTION_RUN_SCHEMA,
    validate_contract,
    validate_next_action_run,
)


def valid_next_action_run() -> dict:
    return {
        "api_version": "tamandua.io/ml-next-action-run/v1",
        "kind": "MLNextActionRun",
        "status_ref": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
        "mode": "validation_only",
        "action": {
            "priority": 1,
            "action_type": "launch_package",
            "package_id": "ml_data_governed_acquisition",
            "wave": 1,
            "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        },
        "command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1",
        "returncode": 0,
        "stdout": (
            "validated execution status: docs\\benchmarks\\runs\\20260604T-ml-execution-status.json\n"
            "Validation-only mode. Real acquisition was not executed.\n"
            "Guard set command for the isolated lab shell:\n"
            "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1'\n"
            "Guard cleanup command after the run:\n"
            "Remove-Item Env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION -ErrorAction SilentlyContinue\n"
            "Command that would run after -Execute with the guard set:\n"
            "python apps\\tamandua_ml\\scripts\\download_production_dataset.py --output "
            "$env:TAMANDUA_ML_DATA_ROOT\\production --samples-per-class 10000 --resume --yes\n"
        ),
        "stderr": "",
        "env_snapshot": {
            "status_required_env": [
                {
                    "name": "TAMANDUA_ML_DATA_ROOT",
                    "present": True,
                    "placeholder": False,
                    "value_redacted": "present",
                    "outside_repo": True,
                }
            ],
            "execute_guard_env": {
                "name": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
                "present": False,
                "value_redacted": "missing_or_placeholder",
            },
        },
        "safety_assertions": {
            "command_validation_only": True,
            "execute_guard_absent": True,
            "selected_action_only": True,
            "no_success_stderr": True,
            "no_real_operation_evidence": True,
            "guarded_command_printed": True,
            "no_real_acquisition_evidence": True,
            "guarded_would_run_command_printed": True,
            "data_root_outside_repo": True,
        },
        "validation_scope": {
            "scope_type": "selected_action_only",
            "selected_package_id": "ml_data_governed_acquisition",
            "selected_wave": 1,
            "full_platform_sweep": False,
        },
        "claim_boundary": (
            "Next-action runner evidence only. Validation-only mode does not download malware, "
            "train models, run inference, or contact live services."
        ),
    }


def fresh_next_action_run(tmp_path: Path) -> dict:
    handoff_dir = tmp_path / "handoff"
    write_handoff(build_plan(environ={}), handoff_dir)
    status = build_status(
        handoff_dir=handoff_dir,
        environ={"TAMANDUA_ML_DATA_ROOT": str(tmp_path / "external-ml-data")},
    )
    status_path = tmp_path / "ml-execution-status.json"
    status_path.write_text(json.dumps(status), encoding="utf-8")
    action = status["next_actions"][0]
    payload = valid_next_action_run()
    payload["status_ref"] = str(status_path)
    payload["action"] = {
        "priority": action["priority"],
        "action_type": action["action_type"],
        "package_id": action["package_id"],
        "wave": action["wave"],
        "execute_guard_env": action["execute_guard_env"],
    }
    payload["command"] = action["validation_command"]
    payload["stdout"] = (
        f"validated execution status: {status_path}\n"
        "Validation-only mode. Real acquisition was not executed.\n"
        "Guard set command for the isolated lab shell:\n"
        "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1'\n"
        "Guard cleanup command after the run:\n"
        "Remove-Item Env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION -ErrorAction SilentlyContinue\n"
        "Command that would run after -Execute with the guard set:\n"
        "python apps\\tamandua_ml\\scripts\\download_production_dataset.py --output "
        "$env:TAMANDUA_ML_DATA_ROOT\\production --samples-per-class 10000 --resume --yes\n"
    )
    return payload


def test_validate_next_action_run_accepts_valid_contract() -> None:
    validate_next_action_run(valid_next_action_run(), Path("memory://ml-next-action-run.json"))


def test_validate_next_action_run_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-next-action-run.json"
    report_path.write_text(json.dumps(fresh_next_action_run(tmp_path)), encoding="utf-8")

    mode = validate_contract(report_path, NEXT_ACTION_RUN_SCHEMA, validate_next_action_run)

    assert mode == "jsonschema+built-in"


def test_validate_next_action_run_rejects_stale_status_command(tmp_path: Path) -> None:
    payload = fresh_next_action_run(tmp_path)
    payload["command"] = "Write-Host 'stale validation command'"
    report_path = tmp_path / "ml-next-action-run.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(report_path, NEXT_ACTION_RUN_SCHEMA, validate_next_action_run)
    except ContractError as exc:
        assert "must match status_ref validation_command" in str(exc)
    else:
        raise AssertionError("expected stale status command to fail")


def test_validate_next_action_run_rejects_stale_status_priority(tmp_path: Path) -> None:
    payload = fresh_next_action_run(tmp_path)
    payload["action"]["priority"] = 99
    report_path = tmp_path / "ml-next-action-run.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(report_path, NEXT_ACTION_RUN_SCHEMA, validate_next_action_run)
    except ContractError as exc:
        assert "not present in status_ref next_actions" in str(exc)
    else:
        raise AssertionError("expected stale status priority to fail")


def test_validate_next_action_run_rejects_validation_only_execute_command() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["command"] += " -Execute"

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "validation_only" in str(exc)
    else:
        raise AssertionError("expected validation_only report with -Execute to fail")


def test_validate_next_action_run_rejects_direct_wave1_selected_command() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["command"] = (
        "python apps\\tamandua_ml\\scripts\\download_production_dataset.py --output "
        "$env:TAMANDUA_ML_DATA_ROOT\\production --samples-per-class 10000 --resume --yes"
    )

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "must not select direct acquisition" in str(exc)
    else:
        raise AssertionError("expected direct Wave 1 selected command to fail")


def test_validate_next_action_run_rejects_unscoped_direct_command_stdout() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["stdout"] = (
        "Validation-only mode. Real acquisition was not executed.\n"
        "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1'\n"
        "python apps\\tamandua_ml\\scripts\\download_production_dataset.py --output "
        "$env:TAMANDUA_ML_DATA_ROOT\\production --samples-per-class 10000 --resume --yes\n"
    )

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "direct acquisition command may appear only as guarded would-run evidence" in str(exc)
    else:
        raise AssertionError("expected unscoped direct command stdout to fail")


def test_validate_next_action_run_rejects_success_without_no_acquisition_evidence() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["stdout"] = "validated execution status: docs\\benchmarks\\runs\\20260604T-ml-execution-status.json\n"
    payload["safety_assertions"]["no_real_operation_evidence"] = False
    payload["safety_assertions"]["guarded_command_printed"] = False
    payload["safety_assertions"]["no_real_acquisition_evidence"] = False
    payload["safety_assertions"]["guarded_would_run_command_printed"] = False

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "no-real-operation evidence" in str(exc)
    else:
        raise AssertionError("expected missing no-acquisition evidence to fail")


def test_validate_next_action_run_rejects_success_without_guarded_would_run_command() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["stdout"] = (
        "validated execution status: docs\\benchmarks\\runs\\20260604T-ml-execution-status.json\n"
        "Validation-only mode. Real acquisition was not executed.\n"
    )
    payload["safety_assertions"]["guarded_command_printed"] = False
    payload["safety_assertions"]["guarded_would_run_command_printed"] = False

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "would-run command evidence" in str(exc)
    else:
        raise AssertionError("expected missing would-run command evidence to fail")


def test_validate_next_action_run_rejects_validation_only_with_present_guard() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["env_snapshot"]["execute_guard_env"]["present"] = True
    payload["env_snapshot"]["execute_guard_env"]["value_redacted"] = "present"
    payload["safety_assertions"]["execute_guard_absent"] = False

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "safety_assertions.execute_guard_absent" in str(exc)
    else:
        raise AssertionError("expected validation_only receipt with present guard to fail")


def test_validate_next_action_run_accepts_future_ml1_launcher_without_acquisition_text() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["action"] = {
        "priority": 1,
        "action_type": "launch_package",
        "package_id": "ml1_train_candidate_and_model_card",
        "wave": 2,
        "execute_guard_env": "TAMANDUA_ALLOW_ML_TRAINING",
    }
    payload["command"] = ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_2_ml1_candidate_launcher.ps1"
    payload["stdout"] = (
        "Validation-only mode. ML-1 candidate training/export/benchmark was not executed.\n"
        "Commands that would run after -Execute and TAMANDUA_ALLOW_ML_TRAINING=1:\n"
        "python apps\\tamandua_ml\\scripts\\ml1_model_benchmark.py --output docs\\benchmarks\\runs\\ml-prod-candidate-v1-ml1.json\n"
    )
    payload["env_snapshot"]["execute_guard_env"]["name"] = "TAMANDUA_ALLOW_ML_TRAINING"
    payload["safety_assertions"]["no_real_operation_evidence"] = True
    payload["safety_assertions"]["guarded_command_printed"] = True
    payload["safety_assertions"]["no_real_acquisition_evidence"] = False
    payload["safety_assertions"]["guarded_would_run_command_printed"] = False
    payload["validation_scope"]["selected_package_id"] = "ml1_train_candidate_and_model_card"
    payload["validation_scope"]["selected_wave"] = 2

    validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))


def test_validate_next_action_run_rejects_success_without_external_data_root_snapshot() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["env_snapshot"]["status_required_env"][0]["outside_repo"] = False
    payload["safety_assertions"]["data_root_outside_repo"] = False

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "safety_assertions.data_root_outside_repo" in str(exc)
    else:
        raise AssertionError("expected missing external data root snapshot to fail")


def test_validate_next_action_run_accepts_manifest_publish_validation_only() -> None:
    payload = valid_next_action_run()
    payload["action"]["action_type"] = "publish_dataset_manifest"
    payload["action"]["execute_guard_env"] = "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH"
    payload["env_snapshot"]["execute_guard_env"]["name"] = "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH"
    payload["command"] = "Write-Host 'Validation-only mode. Sanitized dataset manifest was not published.'"
    payload["stdout"] = (
        "Validation-only mode. Sanitized dataset manifest was not published.\n"
        "Guard set command for the isolated publish shell:\n"
        "$env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH = '1'\n"
        "Guard cleanup command after the run:\n"
        "Remove-Item Env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH -ErrorAction SilentlyContinue\n"
        "Command that would run after -Execute with the guard set:\n"
        ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_manifest_publish_launcher.ps1\n"
    )
    payload["safety_assertions"]["no_real_operation_evidence"] = True
    payload["safety_assertions"]["guarded_command_printed"] = True
    payload["safety_assertions"]["no_real_acquisition_evidence"] = False
    payload["safety_assertions"]["guarded_would_run_command_printed"] = False

    validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))


def test_validate_next_action_run_rejects_manifest_publish_without_no_publication_evidence() -> None:
    payload = valid_next_action_run()
    payload["action"]["action_type"] = "publish_dataset_manifest"
    payload["action"]["execute_guard_env"] = "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH"
    payload["env_snapshot"]["execute_guard_env"]["name"] = "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH"
    payload["command"] = "Write-Host 'Validation-only mode.'"
    payload["stdout"] = "Validation-only mode.\n"
    payload["safety_assertions"]["no_real_operation_evidence"] = False
    payload["safety_assertions"]["guarded_command_printed"] = False
    payload["safety_assertions"]["no_real_acquisition_evidence"] = False
    payload["safety_assertions"]["guarded_would_run_command_printed"] = False

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "no-publication evidence" in str(exc)
    else:
        raise AssertionError("expected missing no-publication evidence to fail")


def test_validate_next_action_run_rejects_manifest_publish_without_guarded_command_evidence() -> None:
    payload = valid_next_action_run()
    payload["action"]["action_type"] = "publish_dataset_manifest"
    payload["action"]["execute_guard_env"] = "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH"
    payload["env_snapshot"]["execute_guard_env"]["name"] = "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH"
    payload["command"] = "Write-Host 'Validation-only mode. Sanitized dataset manifest was not published.'"
    payload["stdout"] = "Validation-only mode. Sanitized dataset manifest was not published.\n"
    payload["safety_assertions"]["no_real_operation_evidence"] = True
    payload["safety_assertions"]["guarded_command_printed"] = False
    payload["safety_assertions"]["no_real_acquisition_evidence"] = False
    payload["safety_assertions"]["guarded_would_run_command_printed"] = False

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "guarded_command_printed" in str(exc)
    else:
        raise AssertionError("expected missing manifest publish guarded command evidence to fail")


def test_validate_next_action_run_rejects_safety_assertion_drift() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["safety_assertions"]["command_validation_only"] = False

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "safety_assertions.command_validation_only" in str(exc)
    else:
        raise AssertionError("expected stale safety assertion to fail")


def test_validate_next_action_run_rejects_non_guard_execute_env() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["action"]["execute_guard_env"] = "TAMANDUA_ML_DATA_ROOT"

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "execute_guard_env" in str(exc)
    else:
        raise AssertionError("expected non TAMANDUA_ALLOW guard to fail")


def test_validate_next_action_run_rejects_full_platform_sweep_scope() -> None:
    payload = copy.deepcopy(valid_next_action_run())
    payload["validation_scope"]["full_platform_sweep"] = True

    try:
        validate_next_action_run(payload, Path("memory://ml-next-action-run.json"))
    except ContractError as exc:
        assert "full_platform_sweep" in str(exc)
    else:
        raise AssertionError("expected full platform sweep scope to fail")
