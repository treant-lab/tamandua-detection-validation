from __future__ import annotations

import copy
import sys
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import ContractError, validate_ml_goal_snapshot  # noqa: E402


def valid_goal_snapshot() -> dict:
    evidence_summary = {
        "total_required_evidence": 16,
        "present_required_evidence": 4,
        "usable_required_evidence": 1,
        "missing_required_evidence": 12,
        "unusable_present_required_evidence": 3,
        "by_status": {"blocked_artifact": 3, "missing": 12, "usable": 1},
    }
    missing_ids = [
        "wave1_governed_acquisition",
        "wave1_sanitized_manifest",
        "ml1_model_quality",
        "ml1_model_contract_and_card",
        "ml2_pytorch_onnx_parity",
        "ml3_agent_onnx_parity",
        "ml4_service_benchmark",
        "ml5_tamandua_replay",
        "ml6_cross_time_holdout",
    ]
    next_requirement = {
        "id": "wave1_governed_acquisition",
        "phase": "01-wave1-manifest-publication",
        "phase_state": "ready_validation_only",
        "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        "pending_targets": ["manifest_publish_receipt_incomplete", "missing_canonical_dataset_manifest"],
        "required_evidence": [
            "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
            "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
        ],
        "missing_or_unusable_evidence": [
            "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
            "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
        ],
    }
    matrix = [
        {
            "id": "wave1_governed_acquisition",
            "phase": "01-wave1-manifest-publication",
            "status": "missing_evidence",
            "phase_state": "ready_validation_only",
            "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
            "pending_targets": ["manifest_publish_receipt_incomplete", "missing_canonical_dataset_manifest"],
            "required_evidence": ["w1_transcript.json", "w1_receipt.json"],
            "missing_or_unusable_evidence": ["w1_transcript.json", "w1_receipt.json"],
            "platform_status": "missing",
            "platform_blockers": ["unusable_evidence:w1_transcript.json", "unusable_evidence:w1_receipt.json"],
            "evidence_state": "not_proven",
            "evidence": [
                {
                    "ref": "w1_transcript.json",
                    "type": "file",
                    "present": False,
                    "usable": False,
                    "status": "missing",
                },
                {"ref": "w1_receipt.json", "type": "file", "present": True, "usable": False, "status": "blocked_artifact"},
            ],
        },
        {
            "id": "wave1_sanitized_manifest",
            "phase": "01-wave1-manifest-publication",
            "status": "missing_evidence",
            "phase_state": "ready_validation_only",
            "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
            "pending_targets": ["manifest_publish_receipt_incomplete", "missing_canonical_dataset_manifest"],
            "required_evidence": ["publish_receipt.json", "acceptance.json", "dataset.json"],
            "missing_or_unusable_evidence": ["publish_receipt.json", "acceptance.json", "dataset.json"],
            "platform_status": "missing",
            "platform_blockers": [],
            "evidence_state": "not_proven",
            "evidence": [
                {"ref": "publish_receipt.json", "type": "file", "present": True, "usable": False, "status": "blocked_artifact"},
                {"ref": "acceptance.json", "type": "file", "present": True, "usable": False, "status": "blocked_artifact"},
                {"ref": "dataset.json", "type": "file", "present": False, "usable": False, "status": "missing"},
            ],
        },
    ]
    for requirement_id, guard, evidence_refs in [
        ("ml1_model_quality", "TAMANDUA_ALLOW_ML_TRAINING", ["ml1.json"]),
        ("ml1_model_contract_and_card", "TAMANDUA_ALLOW_ML_TRAINING", ["contract.json", "card.md"]),
        ("ml2_pytorch_onnx_parity", "TAMANDUA_ALLOW_ML_PARITY", ["model.onnx", "ml2.json"]),
        ("ml3_agent_onnx_parity", "TAMANDUA_ALLOW_ML_PARITY", ["model.onnx", "ml3.json"]),
        ("ml4_service_benchmark", "TAMANDUA_ALLOW_ML_SERVICE_BENCH", ["ml4.json"]),
        ("ml5_tamandua_replay", "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY", ["ml5.json"]),
        ("ml6_cross_time_holdout", "TAMANDUA_ALLOW_ML_HOLDOUT", ["ml6.json"]),
    ]:
        matrix.append(
            {
                "id": requirement_id,
                "phase": "02-ml1-candidate-quality",
                "status": "missing_evidence",
                "phase_state": "blocked_upstream_evidence",
                "execute_guard_env": guard,
                "pending_targets": [],
                "required_evidence": evidence_refs,
                "missing_or_unusable_evidence": evidence_refs,
                "platform_status": "missing",
                "platform_blockers": [],
                "evidence_state": "not_proven",
                "evidence": [
                    {"ref": ref, "type": "file", "present": False, "usable": False, "status": "missing"}
                    for ref in evidence_refs
                ],
            }
        )
    matrix.append(
        {
            "id": "public_claim_evidence_boundary",
            "phase": "00-public-claim-boundary",
            "status": "proven",
            "phase_state": "evidence_exists",
            "execute_guard_env": "",
            "pending_targets": [],
            "required_evidence": ["tools/detection_validation/scripts/ml_public_claims_guard.py"],
            "missing_or_unusable_evidence": [],
            "platform_status": "proven",
            "platform_blockers": [],
            "evidence_state": "proven",
            "evidence": [
                {
                    "ref": "tools/detection_validation/scripts/ml_public_claims_guard.py",
                    "type": "file",
                    "present": True,
                    "usable": True,
                    "status": "usable",
                }
            ],
        }
    )
    command_by_phase = {
        "01-wave1-manifest-publication": (
            "wave_1_real_acquisition_launcher.ps1",
            "wave_1_real_acquisition_launcher.ps1 -Execute",
            "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        ),
        "02-ml1-candidate-quality": (
            "wave_2_ml1_candidate_launcher.ps1",
            "wave_2_ml1_candidate_launcher.ps1 -Execute",
            "TAMANDUA_ALLOW_ML_TRAINING",
        ),
        "03-onnx-agent-parity": (
            "wave_2_ml2_ml3_parity_launcher.ps1",
            "wave_2_ml2_ml3_parity_launcher.ps1 -Execute",
            "TAMANDUA_ALLOW_ML_PARITY",
        ),
        "04-service-benchmark": (
            "wave_2_ml4_service_launcher.ps1",
            "wave_2_ml4_service_launcher.ps1 -Execute",
            "TAMANDUA_ALLOW_ML_SERVICE_BENCH",
        ),
        "05-platform-replay": (
            "wave_3_ml5_pipeline_launcher.ps1",
            "wave_3_ml5_pipeline_launcher.ps1 -Execute",
            "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY",
        ),
        "06-cross-time-holdout": (
            "wave_3_ml6_holdout_launcher.ps1",
            "wave_3_ml6_holdout_launcher.ps1 -Execute",
            "TAMANDUA_ALLOW_ML_HOLDOUT",
        ),
    }
    for item in matrix:
        if item["id"] == "public_claim_evidence_boundary":
            item.update(
                {
                    "command_available": False,
                    "validation_command": "",
                    "execute_command": "",
                    "command_claim_boundary": "No guarded command is required for already-proven coordination boundary evidence.",
                }
            )
            continue
        validation_launcher, execute_launcher, guard = command_by_phase[item["phase"]]
        item.update(
            {
                "command_available": True,
                "validation_command": f".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\{validation_launcher}",
                "execute_command": f".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\{execute_launcher}",
                "execute_guard_env": guard,
                "command_claim_boundary": "Guarded execution in isolated ML lab only.",
            }
        )
    goal = {
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
        "missing_requirement_ids": missing_ids,
        "evidence_status_summary": evidence_summary,
        "next_unproven_requirement": next_requirement,
        "requirement_evidence_matrix": matrix,
    }
    summary = {
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
        "missing_requirement_ids": missing_ids,
        "wave1_pre_execution_transcript_contract_validation_before_run": "missing",
        "wave1_pre_execution_transcript_contract_valid_before_run": False,
        "wave1_pre_execution_transcript_contract_missing_before_run": True,
        "wave1_acceptance_intake_transcript_contract_validation": "failed",
        "wave1_acceptance_intake_transcript_contract_valid": False,
        "wave1_transcript_contract_valid_for_manifest_publish": False,
        "wave1_acquisition_transcript_guarded_run_command_packet_sha256": "",
        "wave1_acquisition_transcript_stdout_sha256": "",
        "wave1_acquisition_transcript_stderr_sha256": "",
        "wave1_manifest_transcript_guarded_run_command_packet_sha256": "",
        "wave1_manifest_transcript_stdout_sha256": "",
        "wave1_manifest_transcript_stderr_sha256": "",
        "wave1_transcript_hashes_match_between_receipts": True,
        "goal_snapshot_anchor_check_passed": True,
        "mismatched_snapshot_fields": [],
        "requirement_matrix_items": 10,
        "requirement_matrix_not_proven": 9,
        "requirement_matrix_proven": 1,
        "check_count": 5,
        "passed_checks": 5,
        "failed_checks": 0,
    }
    return {
        "api_version": "tamandua.io/ml-goal-snapshot/v1",
        "kind": "MLGoalSnapshot",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-06T14:28:00Z",
            "created_by": "tamandua-ml-goal-snapshot",
            "claim_boundary": (
                "No-execution goal audit only. It does not set guards, acquire samples, "
                "publish manifests, train models, run inference, run benchmarks, or contact live services."
            ),
        },
        "source": {
            "master_handoff": "docs/benchmarks/runs/20260604T-ml-execution-master-handoff.json",
            "master_handoff_validation": "jsonschema+built-in",
        },
        "goal": goal,
        "source_status_summary": summary,
        "ready_for_completion_claim": False,
        "checks": [
            {"name": "master_handoff_valid", "passed": True, "detail": "ok"},
            {"name": "goal_not_complete", "passed": True, "detail": "ok"},
            {"name": "next_unproven_requirement_is_wave1", "passed": True, "detail": "ok"},
            {"name": "shared_snapshot_matches_master", "passed": True, "detail": "ok"},
            {"name": "goal_snapshot_anchor_check_passed", "passed": True, "detail": "ok"},
        ],
    }


def test_validate_ml_goal_snapshot_accepts_incomplete_goal() -> None:
    validate_ml_goal_snapshot(valid_goal_snapshot(), Path("memory://ml-goal-snapshot.json"))


def test_validate_ml_goal_snapshot_accepts_post_refresh_master_handoff() -> None:
    payload = valid_goal_snapshot()
    payload["source"]["master_handoff"] = (
        "docs/benchmarks/runs/20260621T-ml-execution-master-handoff-post-readiness-refresh.json"
    )

    validate_ml_goal_snapshot(payload, Path("memory://ml-goal-snapshot.json"))


def test_validate_ml_goal_snapshot_rejects_completion_claim() -> None:
    payload = copy.deepcopy(valid_goal_snapshot())
    payload["ready_for_completion_claim"] = True

    try:
        validate_ml_goal_snapshot(payload, Path("memory://ml-goal-snapshot.json"))
    except ContractError as exc:
        assert "ready_for_completion_claim" in str(exc)
    else:
        raise AssertionError("expected completion claim to fail")


def test_validate_ml_goal_snapshot_rejects_wrong_next_requirement() -> None:
    payload = copy.deepcopy(valid_goal_snapshot())
    payload["goal"]["next_unproven_requirement_id"] = "ml1_model_quality"

    try:
        validate_ml_goal_snapshot(payload, Path("memory://ml-goal-snapshot.json"))
    except ContractError as exc:
        assert "next_unproven_requirement_id" in str(exc)
    else:
        raise AssertionError("expected wrong next requirement to fail")


def test_validate_ml_goal_snapshot_rejects_wave1_transcript_contract_drift() -> None:
    payload = copy.deepcopy(valid_goal_snapshot())
    payload["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True

    try:
        validate_ml_goal_snapshot(payload, Path("memory://ml-goal-snapshot.json"))
    except ContractError as exc:
        assert "wave1_transcript_contract_valid_for_manifest_publish" in str(exc)
    else:
        raise AssertionError("expected transcript contract drift to fail")


def test_validate_ml_goal_snapshot_rejects_wave1_transcript_hash_drift() -> None:
    payload = copy.deepcopy(valid_goal_snapshot())
    payload["source_status_summary"]["wave1_manifest_transcript_stdout_sha256"] = "f" * 64

    try:
        validate_ml_goal_snapshot(payload, Path("memory://ml-goal-snapshot.json"))
    except ContractError as exc:
        assert "wave1_manifest_transcript_stdout_sha256" in str(exc)
    else:
        raise AssertionError("expected transcript hash drift to fail")


def test_validate_ml_goal_snapshot_rejects_goal_snapshot_anchor_drift() -> None:
    payload = copy.deepcopy(valid_goal_snapshot())
    payload["source_status_summary"]["goal_snapshot_anchor_check_passed"] = False

    try:
        validate_ml_goal_snapshot(payload, Path("memory://ml-goal-snapshot.json"))
    except ContractError as exc:
        assert "goal_snapshot_anchor_check_passed" in str(exc)
    else:
        raise AssertionError("expected goal snapshot anchor drift to fail")


def test_validate_ml_goal_snapshot_rejects_extra_proven_requirement() -> None:
    payload = copy.deepcopy(valid_goal_snapshot())
    requirement = payload["goal"]["requirement_evidence_matrix"][0]
    requirement["status"] = "proven"
    requirement["evidence_state"] = "proven"
    for evidence in requirement["evidence"]:
        evidence["present"] = True
        evidence["usable"] = True
        evidence["status"] = "usable"
    requirement["missing_or_unusable_evidence"] = []
    payload["source_status_summary"]["requirement_matrix_not_proven"] = 8
    payload["source_status_summary"]["requirement_matrix_proven"] = 2

    try:
        validate_ml_goal_snapshot(payload, Path("memory://ml-goal-snapshot.json"))
    except ContractError as exc:
        assert "only public claim boundary" in str(exc)
    else:
        raise AssertionError("expected extra proven requirement to fail")


def test_validate_ml_goal_snapshot_rejects_execute_in_validation_command() -> None:
    payload = copy.deepcopy(valid_goal_snapshot())
    payload["goal"]["requirement_evidence_matrix"][0]["validation_command"] += " -Execute"

    try:
        validate_ml_goal_snapshot(payload, Path("memory://ml-goal-snapshot.json"))
    except ContractError as exc:
        assert "validation_command" in str(exc)
    else:
        raise AssertionError("expected execute flag in validation command to fail")
