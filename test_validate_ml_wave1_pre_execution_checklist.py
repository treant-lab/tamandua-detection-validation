from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_pre_execution_checklist,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-pre-execution-checklist.json"


def test_validate_wave1_pre_execution_checklist_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_pre_execution_checklist_rejects_false_ready_claim(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["ready_to_set_real_acquisition_guard"] = True
    data["source_status_summary"]["ready_to_set_real_acquisition_guard"] = True
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="ready_to_set_real_acquisition_guard"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_started_post_acquisition(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["post_acquisition_not_started"] = False
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="post_acquisition_not_started"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_authorization_packet_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["authorization"]["authorization_inputs_sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="authorization.authorization_inputs_sha256"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["authorization_packet"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*sha256"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["lab_run_intake"]["path"] = "docs/benchmarks/runs/wrong.json"
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_operator_sequence_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_sequence"][0]["command"] = data["authorization"]["execute_command"]
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_sequence"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_source_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["transcript_absent_before_run"] = True
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_absent_before_run"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_transcript_pre_run_state_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["transcript_pre_run_state"]["stale_or_invalid"] = not data["transcript_pre_run_state"]["stale_or_invalid"]
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_pre_run_state.stale_or_invalid"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_goal_snapshot_anchor_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["goal_snapshot_anchor_check_passed"] = False
    for check in data["checks"]:
        if check["name"] == "goal_snapshot_anchor_preserved_before_guard":
            check["passed"] = False
            break
    data["source_status_summary"]["passed_checks"] -= 1
    data["source_status_summary"]["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_snapshot_anchor"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_benchmark_surface_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["benchmark_detection_surface_contract_ready"] = False
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="benchmark_detection_surface_contract_ready"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_transcript_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["transcript_contract_validation_before_run"] = "missing"
    data["source_status_summary"]["transcript_contract_valid_before_run"] = True
    data["source_status_summary"]["transcript_contract_missing_before_run"] = True
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_contract"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_wave1_publish_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_guard_precondition_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["guard_preconditions"]["required_unset_guard_env"] = ["TAMANDUA_ALLOW_ML_REAL_ACQUISITION"]
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="guard_preconditions.required_unset_guard_env"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_vx_policy_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_inventory_metadata_only"] = False
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_policy"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_vx_summary_authorization(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["vx_download_authorized_by_this_checklist"] = True
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_download_authorized_by_this_checklist"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_transcript_capture_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["transcript_capture_contract"]["capture_helper_command_count"] -= 1
    data["source_status_summary"]["transcript_capture_helper_command_count"] -= 1
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_capture_contract|transcript_capture_helper_command_count"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)


def test_validate_wave1_pre_execution_checklist_rejects_next_unproven_requirement_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["next_unproven_requirement"]["id"] = "ml1_model_quality"
    drifted = tmp_path / "20260604T-ml-wave1-pre-execution-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="next_unproven_requirement"):
        validate_contract(drifted, WAVE1_PRE_EXECUTION_CHECKLIST_SCHEMA, validate_wave1_pre_execution_checklist)
