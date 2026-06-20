from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_execution_environment_preflight,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-execution-environment-preflight.json"


def test_validate_wave1_execution_environment_preflight_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_execution_environment_preflight_rejects_data_root_inside_repo(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["data_root"]["outside_repo"] = False
    data["source_status_summary"]["data_root_outside_repo"] = False
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="data_root"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_capacity_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["data_root"]["free_bytes"] = 49 * 1024 * 1024 * 1024
    data["data_root"]["capacity_sufficient_for_guarded_execution"] = True
    data["source_status_summary"]["data_root_free_bytes"] = 49 * 1024 * 1024 * 1024
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="capacity_sufficient_for_guarded_execution"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_guard_mode_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["guard_policy"]["enabled_guard_env"] = ["TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH"]
    data["guard_policy"]["guard_state_matches_mode"] = False
    data["source_status_summary"]["guard_state_matches_mode"] = False
    data["checks"][3]["passed"] = False
    data["source_status_summary"]["passed_checks"] -= 1
    data["source_status_summary"]["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="prohibited_enabled_guard_env"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_vx_policy_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_inventory_metadata_only"] = False
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_policy"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_vx_guard_enabled(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["guard_policy"]["enabled_guard_env"] = ["TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD"]
    data["guard_policy"]["prohibited_enabled_guard_env"] = ["TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD"]
    data["guard_policy"]["vx_archive_download_guard_enabled"] = True
    data["guard_policy"]["guard_state_matches_mode"] = False
    data["source_status_summary"]["guard_state_matches_mode"] = False
    data["source_status_summary"]["vx_archive_download_guard_absent"] = False
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_archive_download_guard"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_operator_sequence_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_sequence"][0]["command"] = data["operator_sequence"][1]["command"]
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_sequence"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_transcript_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["transcript_contract_validation_before_run"] = "jsonschema+built-in"
    data["source_status_summary"]["transcript_contract_valid_before_run"] = True
    data["source_status_summary"]["transcript_contract_missing_before_run"] = False
    for check in data["checks"]:
        if check["name"] == "transcript_contract_missing_before_run":
            check["passed"] = False
            break
    passed_checks = sum(1 for check in data["checks"] if check["passed"])
    data["source_status_summary"]["passed_checks"] = passed_checks
    data["source_status_summary"]["failed_checks"] = len(data["checks"]) - passed_checks
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_contract"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_goal_snapshot_anchor_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["goal_snapshot_anchor_check_passed"] = False
    for check in data["checks"]:
        if check["name"] == "goal_snapshot_anchor_preserved_before_guard":
            check["passed"] = False
            break
    data["source_status_summary"]["passed_checks"] -= 1
    data["source_status_summary"]["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_snapshot_anchor"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_wave1_publish_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["pre_execution_checklist"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*sha256"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["pre_execution_checklist"]["path"] = "docs/benchmarks/runs/wrong.json"
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)


def test_validate_wave1_execution_environment_preflight_rejects_next_unproven_requirement_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["next_unproven_requirement"]["id"] = "ml1_model_quality"
    drifted = tmp_path / "20260604T-ml-wave1-execution-environment-preflight.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="next_unproven_requirement"):
        validate_contract(drifted, WAVE1_EXECUTION_ENVIRONMENT_PREFLIGHT_SCHEMA, validate_wave1_execution_environment_preflight)
