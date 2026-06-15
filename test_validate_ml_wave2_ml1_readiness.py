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
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    WAVE2_ML1_READINESS_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave2_ml1_readiness,
)


GOAL_SNAPSHOT = {
    "goal_complete": False,
    "completion_state": "partial_evidence",
    "goal_missing_requirements": 9,
    "goal_required_evidence_total": 16,
    "goal_present_required_evidence": 4,
    "goal_usable_required_evidence": 1,
    "goal_missing_required_evidence": 12,
    "goal_unusable_present_required_evidence": 3,
    "next_unproven_requirement_id": "wave1_governed_acquisition",
    "next_unproven_requirement_phase": "01-wave1-manifest-publication",
    "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
    "missing_requirement_ids": [
        "wave1_governed_acquisition",
        "wave1_sanitized_manifest",
        "ml1_model_quality",
        "ml1_model_contract_and_card",
        "ml2_pytorch_onnx_parity",
        "ml3_agent_onnx_parity",
        "ml4_service_benchmark",
        "ml5_tamandua_replay",
        "ml6_cross_time_holdout",
    ],
    "evidence_status_summary": {
        "total_required_evidence": 16,
        "present_required_evidence": 4,
        "usable_required_evidence": 1,
        "missing_required_evidence": 12,
        "unusable_present_required_evidence": 3,
        "by_status": {"blocked_artifact": 3, "missing": 12, "usable": 1},
    },
    "next_unproven_requirement": {
        "id": "wave1_governed_acquisition",
        "phase": "01-wave1-manifest-publication",
        "phase_state": "ready_validation_only",
        "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        "pending_targets": [
            "manifest_publish_receipt_incomplete",
            "missing_canonical_dataset_manifest",
        ],
        "required_evidence": [
            "D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-real-acquisition-transcript.json",
            "D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-acquisition-receipt.json",
        ],
        "missing_or_unusable_evidence": [
            "D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-real-acquisition-transcript.json",
            "D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-acquisition-receipt.json",
        ],
    },
}


def valid_wave2_ml1_readiness() -> dict:
    return {
        "api_version": "tamandua.io/ml-wave2-ml1-readiness-probe/v1",
        "kind": "MLWave2ML1ReadinessProbe",
        "metadata": {
            "report_id": "test_wave2_ml1_readiness",
            "generated_at": "2026-06-04T22:00:00Z",
            "created_by": "tamandua-ml-wave2-ml1-readiness-probe",
            "claim_boundary": "No-execution ML-1 readiness probe only. Does not train models, export ONNX, run benchmarks, publish manifests, run inference, or contact live services.",
        },
        "configuration": {
            "status_ref": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
            "ml_execution_master_handoff_ref": "docs/benchmarks/runs/20260604T-ml-execution-master-handoff.json",
            "ml_local_training_readiness_ref": "docs/benchmarks/runs/20260604T-ml-local-training-readiness.json",
            "wave1_operator_launch_brief_ref": "docs/benchmarks/runs/20260604T-ml-wave1-operator-launch-brief.json",
            "wave1_manifest_publish_receipt_ref": "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
            "dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml1_candidate_launcher.ps1",
            "data_root": "D:/tamandua_ml_lab_data",
        },
        "source": {
            "execution_status": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
            "execution_status_validation": "jsonschema+built-in",
            "ml_execution_master_handoff": "docs/benchmarks/runs/20260604T-ml-execution-master-handoff.json",
            "ml_execution_master_handoff_validation": "jsonschema+built-in",
            "ml_local_training_readiness": "docs/benchmarks/runs/20260604T-ml-local-training-readiness.json",
            "ml_local_training_readiness_validation": "jsonschema+built-in",
            "wave1_operator_launch_brief": "docs/benchmarks/runs/20260604T-ml-wave1-operator-launch-brief.json",
            "wave1_operator_launch_brief_validation": "jsonschema+built-in",
            "wave1_manifest_publish_receipt": "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
            "wave1_manifest_publish_receipt_validation": "jsonschema+built-in",
            "dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "dataset_manifest_validation": "missing",
            "source_status_summary": {
                **GOAL_SNAPSHOT,
                "manifest_publish_receipt_complete": False,
                "manifest_publish_receipt_canonical_dataset_manifest_sha256": "",
                "ml_execution_master_handoff_ready": True,
                "ml_execution_master_handoff_lab_guard_proof_mismatch_count": 0,
                "ml_execution_master_handoff_ml_lab_standby_guards_unset": True,
                "ml_local_training_readiness_ready": True,
                "canonical_dataset_manifest_present": False,
                "canonical_dataset_manifest_sha256": "",
                "canonical_dataset_manifest_sha256_matches_publish_receipt": False,
                "canonical_dataset_manifest_dataset_id": "",
                "canonical_dataset_manifest_purpose": "",
                "canonical_dataset_manifest_raw_sample_storage_external": False,
                "canonical_dataset_manifest_unresolved_label_count": 0,
                "ml1_launcher_exists": True,
                "data_root_outside_repo": True,
                "required_input_count": 6,
                "required_inputs_present": 6,
                "blocker_count": 2,
                "blockers": ["missing_canonical_dataset_manifest", "manifest_publish_receipt_incomplete"],
            },
        },
        "ready_for_ml1_candidate": False,
        "blockers": ["missing_canonical_dataset_manifest", "manifest_publish_receipt_incomplete"],
        "checks": [
            {"name": "execution_status_valid", "passed": True, "detail": "status"},
            {"name": "ml_execution_master_handoff_valid", "passed": True, "detail": "master"},
            {"name": "ml_local_training_readiness_valid", "passed": True, "detail": "local training"},
            {"name": "ml_execution_master_handoff_ready", "passed": True, "detail": "master ready"},
            {
                "name": "ml_execution_master_handoff_lab_guard_proof_clean",
                "passed": True,
                "detail": "wave1_packet_consistency_lab_standby_guard_proof_mismatch_count=0",
            },
            {
                "name": "ml_execution_master_handoff_ml_lab_standby_guards_unset",
                "passed": True,
                "detail": "wave1_packet_consistency_ml_lab_standby_guards_unset=True",
            },
            {"name": "ml_local_training_readiness_ready", "passed": True, "detail": "local training ready"},
            {"name": "wave1_operator_launch_brief_valid", "passed": True, "detail": "brief"},
            {"name": "wave1_manifest_publish_receipt_valid", "passed": True, "detail": "receipt"},
            {"name": "manifest_publish_receipt_complete", "passed": False, "detail": "receipt blockers"},
            {"name": "canonical_dataset_manifest_present", "passed": False, "detail": "manifest"},
            {
                "name": "canonical_dataset_manifest_sha256_matches_publish_receipt",
                "passed": False,
                "detail": "{\"dataset_manifest_sha256\": \"\", \"receipt_canonical_dataset_manifest_sha256\": \"\"}",
            },
            {"name": "ml1_launcher_exists", "passed": True, "detail": "launcher"},
            {"name": "data_root_outside_repo", "passed": True, "detail": "data-root"},
            {"name": "required_input_exists:apps/tamandua_ml/train.py", "passed": True, "detail": "train"},
            {"name": "required_input_exists:apps/tamandua_ml/scripts/export_onnx.py", "passed": True, "detail": "export"},
            {"name": "required_input_exists:apps/tamandua_ml/scripts/ml1_model_benchmark.py", "passed": True, "detail": "bench"},
            {
                "name": "required_input_exists:apps/tamandua_ml/scripts/generate_model_contract.py",
                "passed": True,
                "detail": "contract generator",
            },
            {"name": "required_input_exists:apps/tamandua_ml/scripts/generate_model_card.py", "passed": True, "detail": "card"},
            {
                "name": "required_input_exists:docs/apps/tamandua_ml/examples/ml_model_contract_malware_smell_onnx_v1.json",
                "passed": True,
                "detail": "contract",
            },
        ],
        "operator_sequence": [
            {
                "step": 1,
                "mode": "validation_only",
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml1_candidate_launcher.ps1'",
                "claim_boundary": "Validates ML-1 prerequisites and prints training/export/benchmark commands without running them.",
            },
            {
                "step": 2,
                "mode": "execute",
                "guard_set_command": "$env:TAMANDUA_ALLOW_ML_TRAINING = '1'",
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:/tamandua_ml_lab_data",
                    "TAMANDUA_ALLOW_ML_TRAINING": "1",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml1_candidate_launcher.ps1' -Execute",
                "guard_cleanup_command": "Remove-Item Env:TAMANDUA_ALLOW_ML_TRAINING -ErrorAction SilentlyContinue",
                "claim_boundary": "Runs candidate training, ONNX export, ML-1 benchmark, model-contract generation, and model-card generation.",
            },
        ],
    }


def sync_source(payload: dict) -> None:
    source_summary = payload["source"]["source_status_summary"]
    check_by_name = {check["name"]: check for check in payload["checks"]}
    source_summary["manifest_publish_receipt_complete"] = check_by_name["manifest_publish_receipt_complete"]["passed"]
    source_summary["ml_execution_master_handoff_ready"] = check_by_name["ml_execution_master_handoff_ready"]["passed"]
    source_summary["ml_execution_master_handoff_lab_guard_proof_mismatch_count"] = (
        0 if check_by_name["ml_execution_master_handoff_lab_guard_proof_clean"]["passed"] else 1
    )
    source_summary["ml_execution_master_handoff_ml_lab_standby_guards_unset"] = check_by_name[
        "ml_execution_master_handoff_ml_lab_standby_guards_unset"
    ]["passed"]
    source_summary["ml_local_training_readiness_ready"] = check_by_name["ml_local_training_readiness_ready"]["passed"]
    source_summary["canonical_dataset_manifest_present"] = check_by_name["canonical_dataset_manifest_present"]["passed"]
    source_summary["canonical_dataset_manifest_sha256_matches_publish_receipt"] = check_by_name[
        "canonical_dataset_manifest_sha256_matches_publish_receipt"
    ]["passed"]
    if "canonical_dataset_manifest_dataset_id_candidate" in check_by_name:
        source_summary["canonical_dataset_manifest_dataset_id"] = (
            "ml-prod-candidate-v1" if check_by_name["canonical_dataset_manifest_dataset_id_candidate"]["passed"] else "other"
        )
    if "canonical_dataset_manifest_purpose_training" in check_by_name:
        source_summary["canonical_dataset_manifest_purpose"] = (
            "training" if check_by_name["canonical_dataset_manifest_purpose_training"]["passed"] else "smoke"
        )
    if "canonical_dataset_manifest_storage_external" in check_by_name:
        source_summary["canonical_dataset_manifest_raw_sample_storage_external"] = check_by_name[
            "canonical_dataset_manifest_storage_external"
        ]["passed"]
    if "canonical_dataset_manifest_labels_resolved" in check_by_name:
        source_summary["canonical_dataset_manifest_unresolved_label_count"] = (
            0 if check_by_name["canonical_dataset_manifest_labels_resolved"]["passed"] else 1
        )
    source_summary["ml1_launcher_exists"] = check_by_name["ml1_launcher_exists"]["passed"]
    source_summary["data_root_outside_repo"] = check_by_name["data_root_outside_repo"]["passed"]
    input_checks = [name for name in check_by_name if name.startswith("required_input_exists:")]
    source_summary["required_input_count"] = len(input_checks)
    source_summary["required_inputs_present"] = sum(1 for name in input_checks if check_by_name[name]["passed"] is True)
    source_summary["blockers"] = list(payload["blockers"])
    source_summary["blocker_count"] = len(payload["blockers"])


def mark_candidate_manifest_ready(payload: dict) -> None:
    payload["source"]["dataset_manifest_validation"] = "jsonschema+built-in"
    payload["source"]["source_status_summary"]["manifest_publish_receipt_canonical_dataset_manifest_sha256"] = "c" * 64
    payload["source"]["source_status_summary"]["canonical_dataset_manifest_sha256"] = "c" * 64
    for check in payload["checks"]:
        if check["name"] == "canonical_dataset_manifest_present":
            check["passed"] = True
        if check["name"] == "canonical_dataset_manifest_sha256_matches_publish_receipt":
            check["passed"] = True
            break
    payload["checks"].extend(
        [
            {"name": "canonical_dataset_manifest_valid", "passed": True, "detail": "dataset"},
            {
                "name": "canonical_dataset_manifest_dataset_id_candidate",
                "passed": True,
                "detail": "ml-prod-candidate-v1",
            },
            {"name": "canonical_dataset_manifest_purpose_training", "passed": True, "detail": "training"},
            {
                "name": "canonical_dataset_manifest_storage_external",
                "passed": True,
                "detail": "external://tamandua-ml-production/ml-prod-candidate-v1",
            },
            {"name": "canonical_dataset_manifest_labels_resolved", "passed": True, "detail": "unresolved=0"},
        ]
    )
    sync_source(payload)


def test_validate_wave2_ml1_readiness_accepts_blocked_manifest_contract() -> None:
    validate_wave2_ml1_readiness(valid_wave2_ml1_readiness(), Path("memory://ml-wave2-ml1-readiness.json"))


def test_validate_wave2_ml1_readiness_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-wave2-ml1-readiness.json"
    report_path.write_text(json.dumps(valid_wave2_ml1_readiness()), encoding="utf-8")

    mode = validate_contract(report_path, WAVE2_ML1_READINESS_SCHEMA, validate_wave2_ml1_readiness)

    assert mode == "jsonschema+built-in"


def test_validate_wave2_ml1_readiness_rejects_ready_without_manifest() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["ready_for_ml1_candidate"] = True
    payload["blockers"] = []
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "failed checks" in str(exc)
    else:
        raise AssertionError("expected ready without manifest to fail")


def test_validate_wave2_ml1_readiness_rejects_ready_with_failed_required_input() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["ready_for_ml1_candidate"] = True
    payload["blockers"] = []
    for check in payload["checks"]:
        check["passed"] = True
    failed_input = next(check for check in payload["checks"] if check["name"] == "required_input_exists:apps/tamandua_ml/train.py")
    failed_input["passed"] = False
    mark_candidate_manifest_ready(payload)
    failed_input["passed"] = False
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "failed checks" in str(exc)
    else:
        raise AssertionError("expected ready report with failed required input to fail")


def test_validate_wave2_ml1_readiness_rejects_missing_manifest_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["blockers"] = ["other_blocker", "manifest_publish_receipt_incomplete"]
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "missing canonical dataset manifest" in str(exc)
    else:
        raise AssertionError("expected missing manifest blocker to fail")


def test_validate_wave2_ml1_readiness_rejects_missing_manifest_publish_receipt_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["blockers"] = ["missing_canonical_dataset_manifest"]
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "incomplete manifest publish receipt" in str(exc)
    else:
        raise AssertionError("expected missing manifest publish receipt blocker to fail")


def test_validate_wave2_ml1_readiness_rejects_missing_candidate_dataset_checks() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["source"]["dataset_manifest_validation"] = "jsonschema+built-in"
    for check in payload["checks"]:
        if check["name"] == "canonical_dataset_manifest_present":
            check["passed"] = True
            break
    payload["blockers"] = ["manifest_publish_receipt_incomplete"]
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "missing required candidate dataset check" in str(exc)
    else:
        raise AssertionError("expected missing candidate dataset checks to fail")


def test_validate_wave2_ml1_readiness_rejects_missing_master_lab_guard_proof_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    for check in payload["checks"]:
        if check["name"] == "ml_execution_master_handoff_lab_guard_proof_clean":
            check["passed"] = False
            break
    payload["blockers"] = ["missing_canonical_dataset_manifest", "manifest_publish_receipt_incomplete"]
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "lab guard proof blocker" in str(exc)
    else:
        raise AssertionError("expected missing master lab guard proof blocker to fail")


def test_validate_wave2_ml1_readiness_rejects_missing_master_lab_guard_unset_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    for check in payload["checks"]:
        if check["name"] == "ml_execution_master_handoff_ml_lab_standby_guards_unset":
            check["passed"] = False
            break
    payload["blockers"] = ["missing_canonical_dataset_manifest", "manifest_publish_receipt_incomplete"]
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "lab execution guard blocker" in str(exc)
    else:
        raise AssertionError("expected missing master lab guard unset blocker to fail")


def test_validate_wave2_ml1_readiness_rejects_complete_manifest_receipt_when_receipt_invalid() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    for check in payload["checks"]:
        if check["name"] == "wave1_manifest_publish_receipt_valid":
            check["passed"] = False
        if check["name"] == "manifest_publish_receipt_complete":
            check["passed"] = True
    payload["source"]["wave1_manifest_publish_receipt_validation"] = "failed"
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "cannot pass when manifest publish receipt is invalid" in str(exc)
    else:
        raise AssertionError("expected invalid receipt with complete check to fail")


def test_validate_wave2_ml1_readiness_requires_manifest_sha_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    mark_candidate_manifest_ready(payload)
    for check in payload["checks"]:
        if check["name"] == "manifest_publish_receipt_complete":
            check["passed"] = True
        if check["name"] == "canonical_dataset_manifest_sha256_matches_publish_receipt":
            check["passed"] = False
    payload["source"]["source_status_summary"]["manifest_publish_receipt_canonical_dataset_manifest_sha256"] = "a" * 64
    payload["source"]["source_status_summary"]["canonical_dataset_manifest_sha256"] = "b" * 64
    payload["blockers"] = ["stale_blocker"]
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "SHA mismatch blocker" in str(exc)
    else:
        raise AssertionError("expected missing SHA mismatch blocker to fail")


def test_validate_wave2_ml1_readiness_rejects_missing_training_guard() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["operator_sequence"][1]["required_env"]["TAMANDUA_ALLOW_ML_TRAINING"] = "0"

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "ML training guard" in str(exc)
    else:
        raise AssertionError("expected missing training guard to fail")


def test_validate_wave2_ml1_readiness_rejects_missing_training_guard_set_command() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["operator_sequence"][1]["guard_set_command"] = "$env:TAMANDUA_ALLOW_ML_TRAINING='1'"

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "guard_set_command" in str(exc)
    else:
        raise AssertionError("expected missing training guard set command to fail")


def test_validate_wave2_ml1_readiness_rejects_missing_training_guard_cleanup_command() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["operator_sequence"][1]["guard_cleanup_command"] = "Remove-Item Env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION"

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "guard_cleanup_command" in str(exc)
    else:
        raise AssertionError("expected missing training guard cleanup command to fail")


def test_validate_wave2_ml1_readiness_rejects_inline_training_guard_assignment() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["operator_sequence"][1]["command"] = (
        "$env:TAMANDUA_ALLOW_ML_TRAINING = '1'; "
        "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml1_candidate_launcher.ps1' -Execute"
    )

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "inline training guard assignment" in str(exc)
    else:
        raise AssertionError("expected inline training guard assignment to fail")


def test_validate_wave2_ml1_readiness_rejects_not_ready_when_all_checks_pass() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["blockers"] = ["stale_blocker"]
    for check in payload["checks"]:
        check["passed"] = True
    mark_candidate_manifest_ready(payload)
    payload["blockers"] = ["stale_blocker"]
    sync_source(payload)

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "cannot be false when all checks pass" in str(exc)
    else:
        raise AssertionError("expected stale not-ready report to fail")


def test_validate_wave2_ml1_readiness_rejects_source_status_summary_drift() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["source"]["source_status_summary"]["canonical_dataset_manifest_present"] = True

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "source_status_summary" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_wave2_ml1_readiness_rejects_source_validation_mode_drift() -> None:
    payload = copy.deepcopy(valid_wave2_ml1_readiness())
    payload["source"]["execution_status_validation"] = "failed"

    try:
        validate_wave2_ml1_readiness(payload, Path("memory://ml-wave2-ml1-readiness.json"))
    except ContractError as exc:
        assert "execution_status_validation" in str(exc)
    else:
        raise AssertionError("expected source validation drift to fail")
