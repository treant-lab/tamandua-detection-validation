from __future__ import annotations

import copy
import hashlib
import json
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

from validate_ml_contracts import (  # noqa: E402
    ML_PARALLEL_WORK_PACKAGES_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_parallel_work_packages,
)


def fingerprints(commands: list[str]) -> list[dict[str, object]]:
    return [
        {"index": index, "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest()}
        for index, command in enumerate(commands)
    ]


def goal_snapshot() -> dict:
    return {
        "goal_complete": False,
        "completion_state": "partial_evidence",
        "goal_snapshot_anchor_check_passed": True,
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
            "by_status": {
                "blocked_artifact": 3,
                "missing": 12,
                "usable": 1,
            },
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


def valid_dispatch() -> dict:
    return {
        "api_version": "tamandua.io/ml-parallel-work-packages/v1",
        "kind": "MLParallelWorkPackages",
        "metadata": {
            "report_id": "test_parallel_work_packages",
            "generated_at": "2026-06-04T23:45:00Z",
            "created_by": "tamandua-ml-parallel-work-packages",
            "claim_boundary": "No-execution ML parallel work package dispatch only. Does not acquire samples, train models, run inference, execute launchers, or contact live services.",
        },
        "source": {
            "execution_plan": "docs/benchmarks/runs/plan.json",
            "execution_plan_validation": "jsonschema+built-in",
            "execution_status": "docs/benchmarks/runs/status.json",
            "execution_status_validation": "jsonschema+built-in",
            "master_handoff": "docs/benchmarks/runs/20260604T-ml-execution-master-handoff.json",
            "master_handoff_validation": "jsonschema+built-in",
            "source_status_summary": {
                "execution_plan_validated": True,
                "execution_status_validated": True,
                "master_handoff_validated": True,
                "plan_packages": 2,
                "status_packages": 2,
                "status_package_ids_match_plan": True,
                "next_actions": 1,
                "claim_count": 2,
                "ready_validation_only": 1,
                "blocked": 1,
                "evidence_exists": 0,
                "blocked_env": 0,
                "blocked_artifact": 1,
                "blocked_dependency": 0,
                "evidence_usable_for_goal": 0,
                "blocked_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
                "claims_with_validation_command": 1,
                "claims_with_execute_guard": 1,
                "validation_only_batch_claims": 1,
                "blocked_followup_batch_claims": 1,
                **goal_snapshot(),
                "by_status": {"ready_validation_only": 1, "blocked_artifact": 1},
                "by_wave": {"1": {"ready_validation_only": 1}, "2": {"blocked_artifact": 1}},
            },
        },
        "summary": {
            "total_claims": 2,
            "ready_validation_only": 1,
            "blocked": 1,
            "evidence_usable_for_goal": 0,
            "goal_complete": False,
            "completion_state": "partial_evidence",
            "goal_snapshot_anchor_check_passed": True,
            "goal_usable_required_evidence": 1,
            "goal_required_evidence_total": 16,
            "next_unproven_requirement_id": "wave1_governed_acquisition",
            "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
            "blocked_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
            "by_wave": {"1": {"ready_validation_only": 1}, "2": {"blocked_artifact": 1}},
        },
        "claims": [
            {
                "claim_id": "ml-ml_data_governed_acquisition",
                "package_id": "ml_data_governed_acquisition",
                "wave": 1,
                "parallel_group": "dataset",
                "owner_role": "ml-data",
                "claim_status": "ready_validation_only",
                "evidence_state": "ready_validation_only",
                "evidence_status": "validation_only_not_evidence",
                "evidence_usable_for_goal": False,
                "dependencies": [],
                "required_env": ["TAMANDUA_ML_DATA_ROOT"],
                "required_artifacts": ["runbook.md"],
                "expected_artifacts": ["manifest.json"],
                "validation_command": ".\\wave_1.ps1",
                "execute_command": ".\\wave_1.ps1 -Execute",
                "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
                "safe_commands": ["validate"],
                "safe_command_fingerprints": fingerprints(["validate"]),
                "blockers": [],
                "claim_boundary": "Governed acquisition only.",
                "next_action": "Validate launcher.",
                "resolution_contract": [
                    "Use an external TAMANDUA_ML_DATA_ROOT outside the repository.",
                    "Publish docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json only after no unresolved labels.",
                ],
            },
            {
                "claim_id": "ml-ml1_train_candidate_and_model_card",
                "package_id": "ml1_train_candidate_and_model_card",
                "wave": 2,
                "parallel_group": "model-quality",
                "owner_role": "ml-training",
                "claim_status": "blocked_artifact",
                "evidence_state": "blocked_missing_artifact",
                "evidence_status": "blocked_artifact",
                "evidence_usable_for_goal": False,
                "dependencies": ["ml_data_governed_acquisition"],
                "required_env": ["TAMANDUA_ML_DATA_ROOT"],
                "required_artifacts": ["dataset-manifest.json"],
                "expected_artifacts": ["ml1.json"],
                "validation_command": None,
                "execute_command": None,
                "execute_guard_env": None,
                "safe_commands": ["train"],
                "safe_command_fingerprints": fingerprints(["train"]),
                "blockers": ["missing_required_artifact:dataset-manifest.json"],
                "claim_boundary": "Standalone quality only.",
                "next_action": "Wait for manifest.",
                "resolution_contract": [
                    "Produce canonical malware_smell.onnx with recorded lowercase SHA-256 before downstream parity.",
                ],
            },
        ],
        "recommended_batches": [
            {
                "batch_id": "ml-validation-only-ready",
                "claim_ids": ["ml-ml_data_governed_acquisition"],
                "mode": "validation_only",
                "claim_boundary": "Runs validation-only checks only.",
            },
            {
                "batch_id": "ml-blocked-followups",
                "claim_ids": ["ml-ml1_train_candidate_and_model_card"],
                "mode": "dependency_followup",
                "claim_boundary": "Collect missing inputs.",
            },
        ],
    }


def test_validate_ml_parallel_work_packages_accepts_contract() -> None:
    validate_ml_parallel_work_packages(valid_dispatch(), Path("memory://ml-parallel-work-packages.json"))


def test_validate_ml_parallel_work_packages_accepts_post_refresh_master_handoff() -> None:
    payload = valid_dispatch()
    payload["source"]["master_handoff"] = (
        "docs/benchmarks/runs/20260621T-ml-execution-master-handoff-post-readiness-refresh.json"
    )

    validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))


def test_validate_ml_parallel_work_packages_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-parallel-work-packages.json"
    report_path.write_text(json.dumps(valid_dispatch()), encoding="utf-8")

    mode = validate_contract(report_path, ML_PARALLEL_WORK_PACKAGES_SCHEMA, validate_ml_parallel_work_packages)

    assert mode == "jsonschema+built-in"


def test_validate_ml_parallel_work_packages_schema_rejects_ready_claim_without_guard(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["claims"][0]["execute_guard_env"] = None
    report_path = tmp_path / "ml-parallel-work-packages.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(report_path, ML_PARALLEL_WORK_PACKAGES_SCHEMA, validate_ml_parallel_work_packages)
    except ContractError as exc:
        assert "schema validation failed at claims.0.execute_guard_env" in str(exc)
    else:
        raise AssertionError("expected ready claim without execute guard to fail jsonschema validation")


def test_validate_ml_parallel_work_packages_schema_rejects_blocked_claim_with_execute_command(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["claims"][1]["execute_command"] = ".\\wave_2_ml1_candidate_launcher.ps1 -Execute"
    payload["claims"][1]["execute_guard_env"] = "TAMANDUA_ALLOW_ML_TRAINING"
    report_path = tmp_path / "ml-parallel-work-packages.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(report_path, ML_PARALLEL_WORK_PACKAGES_SCHEMA, validate_ml_parallel_work_packages)
    except ContractError as exc:
        assert "schema validation failed at claims.1.execute_command" in str(exc)
    else:
        raise AssertionError("expected blocked claim with execute command to fail jsonschema validation")


def test_validate_ml_parallel_work_packages_rejects_validation_execute() -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["claims"][0]["validation_command"] = ".\\wave_1.ps1 -Execute"

    try:
        validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))
    except ContractError as exc:
        assert "must not execute" in str(exc)
    else:
        raise AssertionError("expected validation command using -Execute to fail")


def test_validate_ml_parallel_work_packages_rejects_safe_command_hash_drift() -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["claims"][0]["safe_command_fingerprints"][0]["command_sha256"] = "0" * 64

    try:
        validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))
    except ContractError as exc:
        assert "safe_command_fingerprints" in str(exc)
    else:
        raise AssertionError("expected safe command hash drift to fail")


def test_validate_ml_parallel_work_packages_rejects_blocked_without_blockers() -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["claims"][1]["blockers"] = []

    try:
        validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))
    except ContractError as exc:
        assert "blocked claim" in str(exc)
    else:
        raise AssertionError("expected blocked claim without blockers to fail")


def test_validate_ml_parallel_work_packages_rejects_empty_resolution_contract() -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["claims"][0]["resolution_contract"] = []

    try:
        validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))
    except ContractError as exc:
        assert "resolution_contract" in str(exc)
    else:
        raise AssertionError("expected empty resolution contract to fail")


def test_validate_ml_parallel_work_packages_rejects_source_status_drift() -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["source"]["source_status_summary"]["by_status"]["blocked_artifact"] = 0

    try:
        validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))
    except ContractError as exc:
        assert "source_status_summary.by_status" in str(exc)
    else:
        raise AssertionError("expected source status summary drift to fail")


def test_validate_ml_parallel_work_packages_rejects_evidence_state_drift() -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["claims"][1]["evidence_state"] = "blocked_dependency"

    try:
        validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))
    except ContractError as exc:
        assert "claim_status: must match evidence_state" in str(exc)
    else:
        raise AssertionError("expected claim status and evidence state drift to fail")


def test_validate_ml_parallel_work_packages_rejects_category_rollup_drift() -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["summary"]["blocked_by_category"]["artifact"] = 0
    payload["summary"]["blocked_by_category"]["dependency"] = 1

    try:
        validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))
    except ContractError as exc:
        assert "summary.blocked_by_category" in str(exc)
    else:
        raise AssertionError("expected blocked category drift to fail")


def test_validate_ml_parallel_work_packages_rejects_coordination_evidence_as_goal_proof() -> None:
    payload = copy.deepcopy(valid_dispatch())
    payload["claims"][0]["claim_status"] = "evidence_exists"
    payload["claims"][0]["evidence_state"] = "evidence_exists"
    payload["claims"][0]["evidence_status"] = "metadata_only"
    payload["claims"][0]["evidence_usable_for_goal"] = True
    payload["claims"][0]["validation_command"] = None
    payload["claims"][0]["execute_command"] = None
    payload["claims"][0]["execute_guard_env"] = None
    payload["source"]["source_status_summary"]["ready_validation_only"] = 0
    payload["source"]["source_status_summary"]["evidence_exists"] = 1
    payload["source"]["source_status_summary"]["evidence_usable_for_goal"] = 1
    payload["source"]["source_status_summary"]["claims_with_validation_command"] = 0
    payload["source"]["source_status_summary"]["claims_with_execute_guard"] = 0
    payload["source"]["source_status_summary"]["validation_only_batch_claims"] = 0
    payload["source"]["source_status_summary"]["by_status"] = {"evidence_exists": 1, "blocked_artifact": 1}
    payload["source"]["source_status_summary"]["by_wave"] = {"1": {"evidence_exists": 1}, "2": {"blocked_artifact": 1}}
    payload["summary"]["ready_validation_only"] = 0
    payload["summary"]["evidence_usable_for_goal"] = 1
    payload["summary"]["by_wave"] = {"1": {"evidence_exists": 1}, "2": {"blocked_artifact": 1}}
    payload["recommended_batches"][0]["claim_ids"] = []

    try:
        validate_ml_parallel_work_packages(payload, Path("memory://ml-parallel-work-packages.json"))
    except ContractError as exc:
        assert "coordination-only evidence is not goal proof" in str(exc)
    else:
        raise AssertionError("expected coordination-only evidence as goal proof to fail")
