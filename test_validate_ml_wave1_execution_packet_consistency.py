import copy
import hashlib
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA,
    validate_contract,
    validate_wave1_execution_packet_consistency,
)


ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-execution-packet-consistency.json"


def test_validate_wave1_execution_packet_consistency_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_execution_packet_consistency_rejects_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["command_mismatches"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_rejects_source_status_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["operator_ready"] = False
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_rejects_source_mismatch_count_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["command_mismatch_fields"] = ["execute:command"]
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="command_mismatch_count"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_rejects_hash_mismatch_count_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["hash_mismatch_fields"] = ["operator_commands_by_mode_sha256:packet_vs_brief"]
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="hash_mismatch_count"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_rejects_source_check_count_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["check_count"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source.source_status_summary.check_count"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_rejects_operator_sequence_step_count_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["operator_sequence_step_count"] = 4
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_sequence_step_count"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_rejects_packet_operator_sequence_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["execution_packet_operator_sequence_modes"].append("unexpected_extra_step")
    data["source"]["source_status_summary"]["execution_packet_operator_sequence_step_count"] = 6
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execution_packet_operator_sequence_modes"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_requires_operator_sequence_blocker(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["consistent"] = False
    data["blockers"] = ["wrong_blocker"]
    source_summary = data["source"]["source_status_summary"]
    source_summary["blockers"] = ["wrong_blocker"]
    source_summary["blocker_count"] = 1
    source_summary["operator_sequence_modes"].append("unexpected_extra_step")
    source_summary["operator_sequence_step_count"] = 6
    source_summary["operator_sequence_exact"] = False
    source_summary["execution_packet_operator_sequence_modes"].append("unexpected_extra_step")
    source_summary["execution_packet_operator_sequence_step_count"] = 6
    source_summary["execution_packet_operator_sequence_modes_sha256"] = hashlib.sha256(
        json.dumps(
            source_summary["execution_packet_operator_sequence_modes"],
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    data["summary"]["operator_sequence_steps"] = 6
    for check in data["checks"]:
        if check["name"] == "operator_sequence_modes_exact":
            check["passed"] = False
    source_summary["passed_checks"] -= 1
    source_summary["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator sequence mismatch"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_requires_packet_operator_sequence_blocker(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["consistent"] = False
    data["blockers"] = ["wrong_blocker"]
    source_summary = data["source"]["source_status_summary"]
    source_summary["blockers"] = ["wrong_blocker"]
    source_summary["blocker_count"] = 1
    source_summary["execution_packet_operator_sequence_preserved"] = False
    for check in data["checks"]:
        if check["name"] == "execution_packet_operator_sequence_preserved":
            check["passed"] = False
    source_summary["passed_checks"] -= 1
    source_summary["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execution packet operator sequence mismatch"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_requires_operator_hash_blocker(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["consistent"] = False
    data["blockers"] = ["wrong_blocker"]
    source_summary = data["source"]["source_status_summary"]
    source_summary["blockers"] = ["wrong_blocker"]
    source_summary["blocker_count"] = 1
    source_summary["hash_mismatch_fields"] = ["operator_commands_by_mode_sha256:packet_vs_brief"]
    source_summary["hash_mismatch_count"] = 1
    data["summary"]["hash_mismatches"] = 1
    for check in data["checks"]:
        if check["name"] == "packet_operator_hashes_match_sources":
            check["passed"] = False
    source_summary["passed_checks"] -= 1
    source_summary["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator hash mismatch"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_requires_authorized_acquisition_blocker(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["consistent"] = False
    data["blockers"] = ["wrong_blocker"]
    source_summary = data["source"]["source_status_summary"]
    source_summary["blockers"] = ["wrong_blocker"]
    source_summary["blocker_count"] = 1
    source_summary["authorized_acquisition_mismatch_fields"] = ["acquisition_command"]
    source_summary["authorized_acquisition_mismatch_count"] = 1
    data["summary"]["authorized_acquisition_mismatches"] = 1
    for check in data["checks"]:
        if check["name"] == "packet_authorized_acquisition_matches_transcript_template":
            check["passed"] = False
    source_summary["passed_checks"] -= 1
    source_summary["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="authorized acquisition mismatch"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_requires_guard_boundary_blocker(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["consistent"] = False
    data["blockers"] = ["wrong_blocker"]
    source_summary = data["source"]["source_status_summary"]
    source_summary["blockers"] = ["wrong_blocker"]
    source_summary["blocker_count"] = 1
    source_summary["command_guard_boundary_preserved"] = False
    data["summary"]["command_guard_boundary_preserved"] = False
    for check in data["checks"]:
        if check["name"] == "packet_command_guard_boundaries_preserved":
            check["passed"] = False
    source_summary["passed_checks"] -= 1
    source_summary["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="command guard boundary mismatch"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)


def test_validate_wave1_execution_packet_consistency_requires_lab_guard_proof_blocker(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["consistent"] = False
    data["blockers"] = ["wrong_blocker"]
    source_summary = data["source"]["source_status_summary"]
    source_summary["blockers"] = ["wrong_blocker"]
    source_summary["blocker_count"] = 1
    source_summary["lab_standby_guard_proof_mismatch_fields"] = ["ml_lab_standby_enabled_guards"]
    source_summary["lab_standby_guard_proof_mismatch_count"] = 1
    source_summary["ml_lab_standby_enabled_guards"] = ["TAMANDUA_ALLOW_ML_REAL_ACQUISITION"]
    data["summary"]["lab_standby_guard_proof_mismatches"] = 1
    for check in data["checks"]:
        if check["name"] == "packet_lab_standby_guard_proof_matches_operator_brief":
            check["passed"] = False
    source_summary["passed_checks"] -= 1
    source_summary["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-execution-packet-consistency.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="lab standby guard proof mismatch"):
        validate_contract(drifted, WAVE1_EXECUTION_PACKET_CONSISTENCY_SCHEMA, validate_wave1_execution_packet_consistency)
