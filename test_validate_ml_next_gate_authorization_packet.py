from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_next_gate_authorization_packet,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-next-gate-authorization-packet.json"


def test_validate_ml_next_gate_authorization_packet_accepts_jsonschema_path() -> None:
    mode = validate_contract(
        CANONICAL,
        ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
        validate_ml_next_gate_authorization_packet,
    )

    assert mode == "jsonschema+built-in"


def test_validate_ml_next_gate_authorization_packet_rejects_execute_guard_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["authorization"]["execute_guard_env"] = "TAMANDUA_ALLOW_OTHER"
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execute_guard_env"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_false_authorized_claim(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["checks"][0]["passed"] = False
    data["authorized_for_guarded_execution"] = True
    data["source_status_summary"]["authorized_for_guarded_execution"] = True
    data["source_status_summary"]["passed_checks"] -= 1
    data["source_status_summary"]["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="authorized_for_guarded_execution"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_authorization_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["authorization"]["authorization_inputs_sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="authorization_inputs_sha256"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_vx_authorization_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_download_authorized_by_this_packet"] = True
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_download_authorized_by_this_packet"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_vx_guard_present(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_archive_download_guard_present"] = True
    data["source_status_summary"]["vx_archive_download_guard_present"] = True
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_archive_download_guard_present"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["master_handoff"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*sha256"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_goal_snapshot_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["goal_snapshot"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*goal_snapshot.*sha256"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_missing_goal_snapshot_anchor_check(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["checks"] = [check for check in data["checks"] if check["name"] != "goal_snapshot_anchors_authorization"]
    data["source_status_summary"]["check_count"] -= 1
    data["source_status_summary"]["passed_checks"] -= 1
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_snapshot_anchors_authorization|authorization_inputs_sha256"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["operator_launch_brief"]["path"] = "docs/benchmarks/runs/wrong.json"
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_inlined_guard_in_execute_step(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_sequence"][1]["command"] = (
        "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION=1; "
        + data["operator_sequence"][1]["command"]
    )
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_sequence"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_missing_data_root_required_env(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    del data["operator_sequence"][1]["required_env"]["TAMANDUA_ML_DATA_ROOT"]
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator launch brief data root"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_validation_run_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["next_action_validation_run_guard_absent"] = False
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="next_action_validation_run_guard_absent"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_benchmark_surface_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["benchmark_detection_surface_contract_ready"] = False
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="benchmark_detection_surface_contract_ready"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_next_unproven_requirement_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["next_unproven_requirement"]["id"] = "ml1_model_quality"
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="next_unproven_requirement"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_wave1_transcript_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_wave1_transcript_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["wave1_manifest_transcript_stdout_sha256"] = "f" * 64
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_manifest_transcript_stdout_sha256"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )


def test_validate_ml_next_gate_authorization_packet_rejects_transcript_capture_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["transcript_capture_contract"]["capture_helper_command_count"] -= 1
    data["source_status_summary"]["transcript_capture_helper_command_count"] -= 1
    drifted = tmp_path / "20260604T-ml-next-gate-authorization-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_capture_contract"):
        validate_contract(
            drifted,
            ML_NEXT_GATE_AUTHORIZATION_PACKET_SCHEMA,
            validate_ml_next_gate_authorization_packet,
        )
