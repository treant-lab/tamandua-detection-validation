from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ML_EXECUTION_MASTER_HANDOFF_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_execution_master_handoff,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-execution-master-handoff.json"
if not CANONICAL.exists():
    pytest.skip("ML execution master handoff run artifact is not present in this standalone deployment", allow_module_level=True)
POST_MIRROR_PUBLISH = (
    ROOT
    / "docs"
    / "benchmarks"
    / "runs"
    / "20260621T-ml-execution-master-handoff-post-mirror-publish.json"
)
POST_LAB_ROOT = ROOT / "docs" / "benchmarks" / "runs" / "20260621T-ml-execution-master-handoff-post-lab-root.json"


def test_validate_ml_execution_master_handoff_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)

    assert mode == "jsonschema+built-in"


def test_validate_ml_execution_master_handoff_accepts_post_mirror_publish_path() -> None:
    if not POST_MIRROR_PUBLISH.exists():
        pytest.skip("post mirror publish handoff has not been generated")

    mode = validate_contract(POST_MIRROR_PUBLISH, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)

    assert mode == "jsonschema+built-in"


def test_validate_ml_execution_master_handoff_accepts_post_lab_root_path() -> None:
    if not POST_LAB_ROOT.exists():
        pytest.skip("post lab root handoff has not been generated")

    mode = validate_contract(POST_LAB_ROOT, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)

    assert mode == "jsonschema+built-in"


def test_validate_ml_execution_master_handoff_rejects_execute_guard_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["next_gate"]["execute_guard_env"] = "TAMANDUA_ALLOW_OTHER"
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execute_guard_env"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_ready_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["ready_for_lab_operator"] = not data["summary"]["ready_for_lab_operator"]
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="summary.ready_for_lab_operator"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_summary_next_gate_guard_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["next_gate_execute_guard_env"] = "TAMANDUA_ALLOW_OTHER"
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="summary.next_gate_execute_guard_env"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_vx_policy_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["wave1_guarded_packet_vx_download_authorized"] = True
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_guarded_packet_vx_download_authorized"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_benchmark_surface_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["benchmark_detection_surface_contract_ready"] = False
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="benchmark_detection_surface_contract_ready"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_summary_next_gate_command_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["next_gate_execute_command"] = data["summary"]["next_gate_validation_command"]
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="summary.next_gate_execute_command"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_requirement_validation_execute_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["goal_completion_audit"]["requirements"][0]["validation_command"] += " -Execute"
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="validation_command"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_requirement_execute_command_without_execute(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["goal_completion_audit"]["requirements"][0]["execute_command"] = data["goal_completion_audit"]["requirements"][0][
        "validation_command"
    ]
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execute_command"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_requirement_command_claim_boundary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["goal_completion_audit"]["requirements"][0]["command_claim_boundary"] = "wrong boundary"
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="command_claim_boundary"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_public_boundary_command_exposure(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    public_boundary = data["goal_completion_audit"]["requirements"][-1]
    public_boundary["command_available"] = True
    public_boundary["validation_command"] = data["goal_completion_audit"]["requirements"][0]["validation_command"]
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="public boundary"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_execution_sequence_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["execution_sequence"][1]["execute_guard_env"] = "TAMANDUA_ALLOW_ML_PARITY"
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execution_sequence"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_wave1_publish_guard_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["wave1_operator_publish_guard_env"] = ""
    data["summary"]["wave1_operator_publish_guard_env"] = ""
    data["execution_sequence"][0]["operator_subsequence"][-1]["guard_env"] = ""
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_operator_publish_guard_env|operator_subsequence"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_wave1_transcript_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = False
    data["summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = False
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_wave1_transcript_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["wave1_manifest_transcript_stdout_sha256"] = "f" * 64
    data["summary"]["wave1_manifest_transcript_stdout_sha256"] = "f" * 64
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(
        ContractError,
        match="wave1_manifest_transcript_stdout_sha256|wave1_transcript_hashes_match_between_receipts",
    ):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_wave1_goal_snapshot_anchor_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["wave1_goal_snapshot_anchor_check_passed"] = False
    data["summary"]["wave1_goal_snapshot_anchor_check_passed"] = False
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_goal_snapshot_anchor_check_passed"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_non_wave1_operator_subsequence(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["execution_sequence"][1]["operator_subsequence"] = copy.deepcopy(data["execution_sequence"][0]["operator_subsequence"])
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_subsequence"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_goal_completion_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["goal_completion_audit"]["complete"] = True
    data["summary"]["goal_complete"] = True
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_completion_audit.complete"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_completion_state_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["goal_completion_audit"]["completion_state"] = "complete"
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_completion_audit.completion_state"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_summary_completion_state_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["completion_state"] = "complete"
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="summary.completion_state"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_summary_missing_requirement_ids_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["missing_requirement_ids"] = data["summary"]["missing_requirement_ids"][1:]
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="summary.missing_requirement_ids"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_summary_missing_required_evidence_refs_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["missing_required_evidence_refs"] = data["summary"]["missing_required_evidence_refs"][1:]
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="summary.missing_required_evidence_refs"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_summary_missing_required_evidence_by_requirement_drift(
    tmp_path: Path,
) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["summary"]["missing_required_evidence_by_requirement"]["wave1_sanitized_manifest_published"] = []
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="summary.missing_required_evidence_by_requirement"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_missing_requirement_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["goal_completion_audit"]["requirements"][2]["status"] = "proven"
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="goal_completion_audit.requirements"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_evidence_usability_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["goal_completion_audit"]["requirements"][0]["evidence"][0]["usable"] = True
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="status|evidence usability"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_critical_path_evidence_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["critical_path_evidence_usable_for_goal"] = 1
    data["summary"]["critical_path_evidence_usable_for_goal"] = 1
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="critical_path_evidence_usable_for_goal"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_ready_with_lab_readiness_false(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["ready_for_lab_operator"] = True
    data["summary"]["ready_for_lab_operator"] = True
    data["source"]["source_status_summary"]["wave1_lab_standby_readiness_ready"] = False
    data["summary"]["wave1_lab_standby_readiness_ready"] = False
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="ready_for_lab_operator"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_ready_with_local_training_readiness_false(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["ready_for_lab_operator"] = True
    data["summary"]["ready_for_lab_operator"] = True
    data["source"]["source_status_summary"]["wave1_local_training_readiness_ready"] = False
    data["summary"]["wave1_local_training_readiness_ready"] = False
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="ready_for_lab_operator"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_ready_with_lab_guard_proof_mismatch(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["ready_for_lab_operator"] = True
    data["summary"]["ready_for_lab_operator"] = True
    data["source"]["source_status_summary"]["wave1_packet_consistency_lab_standby_guard_proof_mismatch_count"] = 1
    data["summary"]["wave1_packet_consistency_lab_standby_guard_proof_mismatch_count"] = 1
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="ready_for_lab_operator"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_ready_with_lab_guards_set(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["ready_for_lab_operator"] = True
    data["summary"]["ready_for_lab_operator"] = True
    data["source"]["source_status_summary"]["wave1_packet_consistency_ml_lab_standby_guards_unset"] = False
    data["summary"]["wave1_packet_consistency_ml_lab_standby_guards_unset"] = False
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="ready_for_lab_operator"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)


def test_validate_ml_execution_master_handoff_rejects_validation_run_evidence_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["next_gate"]["validation_run_evidence"]["execute_guard_absent"] = False
    data["source"]["source_status_summary"]["next_action_validation_run_guard_absent"] = False
    data["summary"]["next_gate_validation_run_guard_absent"] = False
    drifted = tmp_path / "20260604T-ml-execution-master-handoff.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="validation_run_evidence.execute_guard_absent"):
        validate_contract(drifted, ML_EXECUTION_MASTER_HANDOFF_SCHEMA, validate_ml_execution_master_handoff)
