from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_guarded_run_command_packet,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-guarded-run-command-packet.json"


def test_validate_wave1_guarded_run_command_packet_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_guarded_run_command_packet_rejects_inline_guard(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_commands"]["execute_command_inlines_guard"] = True
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execute_command_inlines_guard|guard must remain separate"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_data_root_command_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_commands"]["data_root_set_command"] = "$env:TAMANDUA_ML_DATA_ROOT = '<wrong-root>'"
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="data_root_set_command"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_manifest_claim(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["repo_manifest"]["present"] = True
    data["source_status_summary"]["repo_manifest_present"] = True
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="repo_manifest|manifests"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_acquisition_command_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_commands"]["acquisition_command"] = data["operator_commands"]["acquisition_command"].replace("--resume", "--dry-run-plan")
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="acquisition_command"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_interactive_acquisition_command(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_commands"]["acquisition_command"] = data["operator_commands"]["acquisition_command"].replace(" --yes", "")
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="acquisition_command"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_next_unproven_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["next_unproven_requirement_id"] = "ml1_model_quality"
    data["source_status_summary"]["next_unproven_requirement"]["id"] = "ml1_model_quality"
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="next_unproven_requirement"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_benchmark_surface_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["benchmark_detection_surface_contract_ready"] = False
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="benchmark_detection_surface_contract_ready"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_goal_snapshot_anchor_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["goal_snapshot_anchor_check_passed"] = False
    for check in data["checks"]:
        if check["name"] == "goal_snapshot_anchor_preserved_before_guard":
            check["passed"] = False
            break
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_snapshot_anchor"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_vx_policy_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["vx_inventory_metadata_only"] = False
    data["source_status_summary"]["vx_archive_download_guard_must_be_unset"] = False
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_inventory_metadata_only|vx_archive_download_guard"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_top_level_vx_policy_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_samples_allowed_in_training_splits"] = True
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_policy"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_transcript_capture_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["transcript_capture_contract"]["capture_helper_requires_guard_env"] = "TAMANDUA_ALLOW_OTHER"
    data["source_status_summary"]["transcript_capture_requires_guard_env"] = "TAMANDUA_ALLOW_OTHER"
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_capture_contract|transcript_capture_requires_guard_env"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_transcript_contract_state_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["transcript_contract_validation_before_run"] = "jsonschema+built-in"
    data["source_status_summary"]["transcript_contract_valid_before_run"] = True
    data["source_status_summary"]["transcript_contract_missing_before_run"] = False
    for check in data["checks"]:
        if check["name"] == "transcript_contract_missing_before_run":
            check["passed"] = False
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_contract"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_wave1_publish_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["operator_go_no_go_summary"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*sha256"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["launcher"]["path"] = (
        "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wrong_launcher.ps1"
    )
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)


def test_validate_wave1_guarded_run_command_packet_rejects_extra_source_artifact_hash(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["unexpected"] = {
        "path": "docs/benchmarks/runs/unexpected.json",
        "sha256": "0" * 64,
    }
    drifted = tmp_path / "20260604T-ml-wave1-guarded-run-command-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes"):
        validate_contract(drifted, WAVE1_GUARDED_RUN_COMMAND_PACKET_SCHEMA, validate_wave1_guarded_run_command_packet)
