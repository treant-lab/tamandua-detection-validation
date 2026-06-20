from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
TOOLS = ROOT / "tools" / "detection_validation"
SCRIPTS = ROOT / "apps" / "tamandua_ml" / "scripts"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(SCRIPTS))

from ml_execution_plan import build_plan, write_handoff
from ml_execution_status import build_status
from validate_ml_contracts import (
    ContractError,
    EXECUTION_STATUS_SCHEMA,
    validate_contract,
    validate_execution_status,
)


def valid_status(tmp_path: Path) -> dict:
    handoff_dir = tmp_path / "handoff"
    write_handoff(build_plan(environ={}), handoff_dir)
    return build_status(
        handoff_dir=handoff_dir,
        environ={
            "TAMANDUA_ML_DATA_ROOT": str(tmp_path / "external-ml-data"),
            "TAMANDUA_MALWAREBAZAAR_AUTH_KEY": "redacted-test-key",
        },
        report_id="test_ml_execution_status",
    )


def test_validate_execution_status_accepts_valid_contract(tmp_path: Path) -> None:
    validate_execution_status(valid_status(tmp_path), Path("memory://ml-execution-status.json"))


def test_validate_execution_status_accepts_jsonschema_path(tmp_path: Path) -> None:
    status_path = tmp_path / "ml-execution-status.json"
    status_path.write_text(json.dumps(valid_status(tmp_path)), encoding="utf-8")

    mode = validate_contract(status_path, EXECUTION_STATUS_SCHEMA, validate_execution_status)

    assert mode == "jsonschema+built-in"


def test_validate_execution_status_rejects_non_consecutive_next_action_priorities(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["next_actions"][0]["priority"] = 99

    try:
        validate_execution_status(payload, Path("memory://ml-execution-status.json"))
    except ContractError as exc:
        assert "next_actions.priority" in str(exc)
    else:
        raise AssertionError("expected non-consecutive next_action priorities to fail")


def test_validate_execution_status_rejects_launch_action_without_guard(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    launch_action = next(action for action in payload["next_actions"] if action["action_type"] == "launch_package")
    launch_action["execute_guard_env"] = "TAMANDUA_ML_DATA_ROOT"

    try:
        validate_execution_status(payload, Path("memory://ml-execution-status.json"))
    except ContractError as exc:
        assert "execute_guard_env" in str(exc)
    else:
        raise AssertionError("expected launch action without TAMANDUA_ALLOW_* guard to fail")


def test_validate_execution_status_rejects_missing_global_launcher(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["global_launchers"][0]["exists"] = False

    try:
        validate_execution_status(payload, Path("memory://ml-execution-status.json"))
    except ContractError as exc:
        assert "required global launcher must exist" in str(exc)
    else:
        raise AssertionError("expected missing global launcher to fail")


def test_validate_execution_status_schema_rejects_missing_global_launcher(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["global_launchers"][0]["exists"] = False
    status_path = tmp_path / "ml-execution-status.json"
    status_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(status_path, EXECUTION_STATUS_SCHEMA, validate_execution_status)
    except ContractError as exc:
        assert "schema validation failed at global_launchers.0.exists" in str(exc)
        assert "True was expected" in str(exc)
    else:
        raise AssertionError("expected missing global launcher to fail jsonschema validation")


def test_validate_execution_status_schema_rejects_manifest_publish_without_guard(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["next_actions"].insert(
        0,
        {
            "action_type": "publish_dataset_manifest",
            "package_id": "ml_data_governed_acquisition",
            "wave": 1,
            "priority": 1,
            "description": "Publish sanitized manifest.",
            "artifact": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "source_artifact": str(tmp_path / "external-ml-data" / "production" / "manifest.json"),
            "validation_command": (
                "Write-Host 'Validation-only mode. Sanitized dataset manifest was not published.'; "
                "Write-Host '$env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH = ''1'''"
            ),
            "execute_command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute",
            "claim_boundary": "Manifest publication only; raw samples remain outside Git.",
        },
    )
    for index, action in enumerate(payload["next_actions"], start=1):
        action["priority"] = index
    status_path = tmp_path / "ml-execution-status.json"
    status_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(status_path, EXECUTION_STATUS_SCHEMA, validate_execution_status)
    except ContractError as exc:
        assert "schema validation failed at next_actions.0" in str(exc)
        assert "'execute_guard_env' is a required property" in str(exc)
    else:
        raise AssertionError("expected manifest publish action without guard to fail jsonschema validation")


def test_validate_execution_status_schema_rejects_dependency_action_without_evidence_state(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    dependency_action = next(action for action in payload["next_actions"] if action["action_type"] == "wait_for_dependency_evidence")
    del dependency_action["dependency_evidence_state"]
    status_path = tmp_path / "ml-execution-status.json"
    status_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(status_path, EXECUTION_STATUS_SCHEMA, validate_execution_status)
    except ContractError as exc:
        assert "schema validation failed at next_actions" in str(exc)
        assert "'dependency_evidence_state' is a required property" in str(exc)
    else:
        raise AssertionError("expected dependency action without evidence state to fail jsonschema validation")


def test_validate_execution_status_rejects_launcher_outside_source_handoff(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["global_launchers"][0]["path"] = str(tmp_path / "other" / "ml_readiness_refresh_launcher.ps1")

    try:
        validate_execution_status(payload, Path("memory://ml-execution-status.json"))
    except ContractError as exc:
        assert "source_plan.handoff_dir" in str(exc)
    else:
        raise AssertionError("expected launcher outside source handoff to fail")


def test_validate_execution_status_rejects_missing_wave_launcher_without_blocker(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    wave_2 = next(wave for wave in payload["waves"] if wave["wave"] == 2)
    launcher = next(item for item in wave_2["handoff"]["required_launchers"] if item["name"] == "wave_2_ml4_service_launcher.ps1")
    launcher["exists"] = False
    wave_2["blockers"] = [blocker for blocker in wave_2["blockers"] if blocker != "missing_launcher:wave_2_ml4_service_launcher.ps1"]

    try:
        validate_execution_status(payload, Path("memory://ml-execution-status.json"))
    except ContractError as exc:
        assert "missing launcher wave_2_ml4_service_launcher.ps1" in str(exc)
    else:
        raise AssertionError("expected missing wave launcher without blocker to fail")


def test_validate_execution_status_accepts_manifest_publish_action(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["next_actions"].insert(
        0,
        {
            "action_type": "publish_dataset_manifest",
            "package_id": "ml_data_governed_acquisition",
            "wave": 1,
            "priority": 1,
            "description": "Publish sanitized manifest.",
            "artifact": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "source_artifact": str(tmp_path / "external-ml-data" / "production" / "manifest.json"),
            "validation_command": (
                "Write-Host 'Validation-only mode. Sanitized dataset manifest was not published.'; "
                "Write-Host '$env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH = ''1'''"
            ),
            "execute_command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute",
            "execute_guard_env": "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
            "claim_boundary": "Manifest publication only; raw samples remain outside Git.",
        },
    )
    for index, action in enumerate(payload["next_actions"], start=1):
        action["priority"] = index

    validate_execution_status(payload, Path("memory://ml-execution-status.json"))


def test_validate_execution_status_accepts_post_acquisition_refresh_action(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["next_actions"].insert(
        0,
        {
            "action_type": "refresh_post_acquisition_receipts",
            "package_id": "ml_data_governed_acquisition",
            "wave": 1,
            "priority": 1,
            "description": "Refresh Wave 1 receipts before sanitized publication.",
            "source_artifact": str(tmp_path / "external-ml-data" / "production" / "manifest.json"),
            "validation_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_post_acquisition_refresh_launcher.ps1",
            "execute_guard_env": None,
            "claim_boundary": "No-execution post-acquisition refresh only. Raw samples remain outside Git.",
        },
    )
    for index, action in enumerate(payload["next_actions"], start=1):
        action["priority"] = index

    validate_execution_status(payload, Path("memory://ml-execution-status.json"))


def test_validate_execution_status_rejects_manifest_publish_wrong_artifact(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["next_actions"].insert(
        0,
        {
            "action_type": "publish_dataset_manifest",
            "package_id": "ml_data_governed_acquisition",
            "wave": 1,
            "priority": 1,
            "description": "Publish sanitized manifest.",
            "artifact": "docs/benchmarks/runs/wrong.json",
            "source_artifact": str(tmp_path / "external-ml-data" / "production" / "manifest.json"),
            "validation_command": (
                "Write-Host 'Validation-only mode. Sanitized dataset manifest was not published.'; "
                "Write-Host '$env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH = ''1'''"
            ),
            "execute_command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute",
            "execute_guard_env": "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
            "claim_boundary": "Manifest publication only; raw samples remain outside Git.",
        },
    )
    for index, action in enumerate(payload["next_actions"], start=1):
        action["priority"] = index

    try:
        validate_execution_status(payload, Path("memory://ml-execution-status.json"))
    except ContractError as exc:
        assert "unexpected dataset manifest artifact" in str(exc)
    else:
        raise AssertionError("expected wrong manifest publish artifact to fail")


def test_validate_execution_status_rejects_manifest_publish_without_guarded_validation_command(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    payload["next_actions"].insert(
        0,
        {
            "action_type": "publish_dataset_manifest",
            "package_id": "ml_data_governed_acquisition",
            "wave": 1,
            "priority": 1,
            "description": "Publish sanitized manifest.",
            "artifact": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "source_artifact": str(tmp_path / "external-ml-data" / "production" / "manifest.json"),
            "validation_command": "Write-Host 'Validation-only mode. Sanitized dataset manifest was not published.'",
            "execute_command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute",
            "execute_guard_env": "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
            "claim_boundary": "Manifest publication only; raw samples remain outside Git.",
        },
    )
    for index, action in enumerate(payload["next_actions"], start=1):
        action["priority"] = index

    try:
        validate_execution_status(payload, Path("memory://ml-execution-status.json"))
    except ContractError as exc:
        assert "guarded manifest publish command evidence" in str(exc)
    else:
        raise AssertionError("expected manifest publish validation command without guard evidence to fail")


def test_validate_execution_status_rejects_unknown_dependency_action(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_status(tmp_path))
    dependency_action = next(action for action in payload["next_actions"] if action["action_type"] == "wait_for_dependency_evidence")
    dependency_action["dependency_id"] = "ml_missing_dependency"

    try:
        validate_execution_status(payload, Path("memory://ml-execution-status.json"))
    except ContractError as exc:
        assert "unknown dependency" in str(exc)
    else:
        raise AssertionError("expected unknown dependency action to fail")
