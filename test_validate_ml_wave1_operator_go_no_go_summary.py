from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_operator_go_no_go_summary,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-operator-go-no-go-summary.json"


def test_validate_wave1_operator_go_no_go_summary_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_operator_go_no_go_summary_rejects_completion_claim(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["goal_complete"] = True
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_complete"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_guard_drift_claim(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["guard_drift_rejected"] = False
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="guard_drift_rejected"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_execute_command_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["execute_command"] = "docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1"
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execute_command"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_operator_sequence_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_sequence"][1]["guard_set_command"] = "$env:TAMANDUA_ALLOW_ML_TRAINING = '1'"
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_sequence"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["execution_environment_preflight"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*sha256"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["validation_only_guard_drift_probe"]["path"] = "docs/benchmarks/runs/wrong.json"
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_next_unproven_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["next_unproven_requirement_id"] = "ml1_model_quality"
    data["source_status_summary"]["next_unproven_requirement"]["id"] = "ml1_model_quality"
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="next_unproven_requirement"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_benchmark_surface_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["benchmark_detection_surface_contract_ready"] = False
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="benchmark_detection_surface_contract_ready"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_goal_snapshot_anchor_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["goal_snapshot_anchor_check_passed"] = False
    for check in data["checks"]:
        if check["name"] == "goal_snapshot_anchor_preserved_before_guard":
            check["passed"] = False
            break
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_snapshot_anchor"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_transcript_contract_drift(tmp_path: Path) -> None:
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
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_contract"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_wave1_publish_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_vx_authorization_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_download_authorized_by_this_packet"] = True
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_policy.vx_download_authorized_by_this_packet"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)


def test_validate_wave1_operator_go_no_go_summary_rejects_vx_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["vx_inventory_metadata_only"] = False
    drifted = tmp_path / "20260604T-ml-wave1-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_status_summary.vx_inventory_metadata_only"):
        validate_contract(drifted, WAVE1_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA, validate_wave1_operator_go_no_go_summary)
