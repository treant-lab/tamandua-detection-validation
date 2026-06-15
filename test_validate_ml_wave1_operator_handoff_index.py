import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA,
    validate_contract,
    validate_wave1_operator_handoff_index,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-operator-handoff-index.json"


def test_validate_wave1_operator_handoff_index_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_operator_handoff_index_rejects_drifted_first_unblock(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["first_unblock_target"] = "ml1_train_candidate_and_model_card"
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_missing_execute_step(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_path"] = [item for item in data["operator_path"] if item["step"] != "execute"]
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_extra_operator_step(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    extra = copy.deepcopy(data["operator_path"][-1])
    extra["step"] = "unexpected_extra_step"
    data["operator_path"].append(extra)
    data["source_status_summary"]["operator_path_steps"].append("unexpected_extra_step")
    data["source_status_summary"]["operator_path_step_count"] = 7
    data["source_status_summary"]["operator_path_exact"] = False
    data["summary"]["operator_path_steps"] = 7
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_path"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_operator_path_step_count_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["operator_path_step_count"] = 4
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_path_step_count"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_execution_packet_operator_sequence_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["execution_packet_operator_sequence"][2]["mode"] = "unexpected_execute"
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execution_packet_operator_sequence"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_source_queue_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_unblock_queue_summary"]["queue_item_ids"] = ["ml-unblock-002"]
    data["source"]["source_unblock_queue_summary"]["queue_items"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_source_status_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["passed_checks"] = 9
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError) as exc:
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)

    assert "source_status_summary.passed_checks" in str(exc.value)


def test_validate_wave1_operator_handoff_index_rejects_intake_transcript_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["intake_transcript_contract_validation"] = "jsonschema+built-in"
    data["summary"]["intake_transcript_contract_valid"] = True
    data["source_status_summary"]["intake_transcript_contract_validation"] = "jsonschema+built-in"
    data["source_status_summary"]["intake_transcript_contract_valid"] = True
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="intake_transcript_contract"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_acceptance_transcript_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["pre_execution_transcript_contract_validation_before_run"] = "failed"
    data["source_status_summary"]["pre_execution_transcript_contract_validation_before_run"] = "failed"
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="pre_execution_transcript_contract"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_wave1_transcript_alias_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    data["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_transcript_hash_rollup_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["manifest_transcript_stdout_sha256"] = "f" * 64
    data["source_status_summary"]["manifest_transcript_stdout_sha256"] = "f" * 64
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="manifest_transcript_stdout_sha256"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_vx_policy_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["guarded_packet_vx_samples_allowed_in_training_splits"] = True
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="guarded_packet_vx_samples_allowed_in_training_splits"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_benchmark_surface_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["benchmark_detection_surface_contract_ready"] = False
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="benchmark_detection_surface_contract_ready"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_goal_snapshot_anchor_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["goal_snapshot_anchor_check_passed"] = False
    data["source_status_summary"]["goal_snapshot_anchor_check_passed"] = False
    for check in data["checks"]:
        if check["name"] == "goal_snapshot_anchor_preserved_before_operator_handoff":
            check["passed"] = False
            break
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_snapshot_anchor"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_packet_consistency_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["packet_consistency_command_mismatch_count"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError) as exc:
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)

    assert "source_status_summary.packet_consistency_command_mismatch_count" in str(exc.value)


def test_validate_wave1_operator_handoff_index_rejects_packet_consistency_hash_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["packet_consistency_hash_mismatch_count"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError) as exc:
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)

    assert "source_status_summary.packet_consistency_hash_mismatch_count" in str(exc.value)


def test_validate_wave1_operator_handoff_index_rejects_packet_consistency_lab_guard_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["packet_consistency_lab_standby_guard_proof_mismatch_count"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError) as exc:
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)

    assert "source_status_summary.packet_consistency_lab_standby_guard_proof_mismatch_count" in str(exc.value)


def test_validate_wave1_operator_handoff_index_rejects_safe_with_packet_consistency_mismatch(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_packet_consistency_summary"]["command_mismatch_count"] = 1
    data["source_status_summary"]["packet_consistency_command_mismatch_count"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="packet consistency mismatches"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_safe_with_packet_consistency_hash_mismatch(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_packet_consistency_summary"]["hash_mismatch_count"] = 1
    data["source_status_summary"]["packet_consistency_hash_mismatch_count"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="packet consistency mismatches"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_safe_with_lab_guard_proof_mismatch(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_packet_consistency_summary"]["lab_standby_guard_proof_mismatch_count"] = 1
    data["source_status_summary"]["packet_consistency_lab_standby_guard_proof_mismatch_count"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="packet consistency mismatches"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_safe_with_lab_guards_set(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_packet_consistency_summary"]["ml_lab_standby_guards_unset"] = False
    data["source_status_summary"]["packet_consistency_ml_lab_standby_guards_unset"] = False
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="packet consistency mismatches"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_safe_with_lab_readiness_failure(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["ml_lab_standby_readiness_ready"] = False
    data["source_status_summary"]["ml_lab_standby_readiness_ready"] = False
    for check in data["checks"]:
        if check["name"] == "ml_lab_standby_readiness_green":
            check["passed"] = False
            break
    data["source_status_summary"]["passed_checks"] -= 1
    data["source_status_summary"]["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="cannot be true with failed required checks"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_safe_with_local_training_readiness_failure(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["ml_local_training_readiness_ready"] = False
    data["source_status_summary"]["ml_local_training_readiness_ready"] = False
    for check in data["checks"]:
        if check["name"] == "ml_local_training_readiness_green":
            check["passed"] = False
            break
    data["source_status_summary"]["passed_checks"] -= 1
    data["source_status_summary"]["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="cannot be true with failed required checks"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_hash_verification_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["transcript_template_hash_verification_ready"] = False
    data["source_status_summary"]["transcript_template_hash_verification_ready"] = False
    for check in data["checks"]:
        if check["name"] == "transcript_template_hash_verification_ready":
            check["passed"] = False
            break
    data["source_status_summary"]["passed_checks"] -= 1
    data["source_status_summary"]["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="cannot be true with failed required checks"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)


def test_validate_wave1_operator_handoff_index_rejects_transcript_capture_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["transcript_capture_contract"]["hash_verification"]["required_file_hash_fields"] = [
        "guarded_run_command_packet_sha256",
        "stdout_sha256",
    ]
    drifted = tmp_path / "20260604T-ml-wave1-operator-handoff-index.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_capture_contract"):
        validate_contract(drifted, WAVE1_OPERATOR_HANDOFF_INDEX_SCHEMA, validate_wave1_operator_handoff_index)
