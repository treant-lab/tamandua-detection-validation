from __future__ import annotations

import copy
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
    ML_UNBLOCK_QUEUE_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_unblock_queue,
)


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


def valid_queue() -> dict:
    return {
        "api_version": "tamandua.io/ml-unblock-queue/v1",
        "kind": "MLUnblockQueue",
        "metadata": {
            "report_id": "test_unblock_queue",
            "generated_at": "2026-06-04T23:59:59Z",
            "created_by": "tamandua-ml-unblock-queue",
            "claim_boundary": "No-execution ML unblock queue only. It records missing inputs and does not run launchers.",
        },
        "source": {
            "parallel_work_packages": "docs/benchmarks/runs/20260604T-ml-parallel-work-packages.json",
            "parallel_work_packages_validation": "jsonschema+built-in",
            "platform_readiness_audit": "docs/benchmarks/runs/20260604T-ml-platform-readiness-audit.json",
            "platform_readiness_audit_validation": "jsonschema+built-in",
            "source_status_summary": {
                "parallel_work_packages_validated": True,
                "platform_readiness_audit_validated": True,
                "dispatch_claims": 1,
                "dispatch_blocked_claims": 1,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "dispatch_blockers": 3,
                "queue_items": 3,
                "dependency": 1,
                "artifact": 1,
                "env": 1,
                "other": 0,
                "readiness_blocker_links": 1,
                "items_from_blocked_claims": 3,
                "items_without_command_exposure": 3,
                "items_with_resolution_command_exposure": 0,
                "items_without_resolution_command_exposure": 3,
                **goal_snapshot(),
                "pending_items": 3,
                "resolved_items": 0,
                "pending_item_ids": ["ml-unblock-001", "ml-unblock-002", "ml-unblock-003"],
                "priority_sequence_valid": True,
            },
        },
        "summary": {
            "total_items": 3,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "dependency": 1,
            "artifact": 1,
            "env": 1,
            "other": 0,
            "readiness_blocker_links": 1,
            "items_from_blocked_claims": 3,
            "items_without_command_exposure": 3,
            "items_with_resolution_command_exposure": 0,
            "items_without_resolution_command_exposure": 3,
            "goal_complete": False,
            "completion_state": "partial_evidence",
            "goal_snapshot_anchor_check_passed": True,
            "goal_usable_required_evidence": 1,
            "goal_required_evidence_total": 16,
            "next_unproven_requirement_id": "wave1_governed_acquisition",
            "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        },
        "items": [
            {
                "unblock_id": "ml-unblock-001",
                "claim_id": "ml-ml4_live_service_benchmark",
                "package_id": "ml4_live_service_benchmark",
                "wave": 2,
                "owner_role": "ml-service",
                "parallel_group": "service",
                "source_claim_status": "blocked_dependency",
                "source_evidence_state": "blocked_dependency",
                "source_validation_command_present": False,
                "source_execute_guard_present": False,
                "category": "dependency",
                "target": "ml1_train_candidate_and_model_card",
                "blocker_status": "blocked_dependency",
                "blocker": "dependency_not_evidence:ml1_train_candidate_and_model_card:blocked_dependency",
                "description": "Complete dependency.",
                "resolution_state": "pending",
                "priority": 1,
                "readiness_blockers": ["ml4_service_benchmark:wave2_ml1_readiness_blocked"],
                "resolution_plan": {
                    "kind": "dependency_package",
                    "command_source_package_id": "ml1_train_candidate_and_model_card",
                    "command_available": False,
                    "validation_command": None,
                    "execute_command": None,
                    "execute_guard_env": None,
                    "operator_note": "Dependency package is not ready for command exposure yet.",
                },
            },
            {
                "unblock_id": "ml-unblock-002",
                "claim_id": "ml-ml4_live_service_benchmark",
                "package_id": "ml4_live_service_benchmark",
                "wave": 2,
                "owner_role": "ml-service",
                "parallel_group": "service",
                "source_claim_status": "blocked_artifact",
                "source_evidence_state": "blocked_missing_artifact",
                "source_validation_command_present": False,
                "source_execute_guard_present": False,
                "category": "artifact",
                "target": "docs/benchmarks/runs/example.json",
                "blocker_status": "missing_artifact",
                "blocker": "missing_required_artifact:docs/benchmarks/runs/example.json",
                "description": "Produce artifact.",
                "resolution_state": "pending",
                "priority": 2,
                "readiness_blockers": [],
                "resolution_plan": {
                    "kind": "artifact",
                    "command_source_package_id": "ml4_live_service_benchmark",
                    "command_available": False,
                    "validation_command": None,
                    "execute_command": None,
                    "execute_guard_env": None,
                    "operator_note": "Produce artifact.",
                },
            },
            {
                "unblock_id": "ml-unblock-003",
                "claim_id": "ml-ml4_live_service_benchmark",
                "package_id": "ml4_live_service_benchmark",
                "wave": 2,
                "owner_role": "ml-service",
                "parallel_group": "service",
                "source_claim_status": "blocked_env",
                "source_evidence_state": "blocked_missing_env",
                "source_validation_command_present": False,
                "source_execute_guard_present": False,
                "category": "env",
                "target": "TAMANDUA_ML_API_KEY",
                "blocker_status": "missing_env",
                "blocker": "missing_env:TAMANDUA_ML_API_KEY",
                "description": "Set env.",
                "resolution_state": "pending",
                "priority": 3,
                "readiness_blockers": [],
                "resolution_plan": {
                    "kind": "env",
                    "command_source_package_id": "ml4_live_service_benchmark",
                    "command_available": False,
                    "validation_command": None,
                    "execute_command": None,
                    "execute_guard_env": None,
                    "operator_note": "Set env.",
                },
            },
        ],
    }


def test_validate_ml_unblock_queue_accepts_contract() -> None:
    validate_ml_unblock_queue(valid_queue(), Path("memory://ml-unblock-queue.json"))


def test_validate_ml_unblock_queue_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-unblock-queue.json"
    report_path.write_text(json.dumps(valid_queue()), encoding="utf-8")

    mode = validate_contract(report_path, ML_UNBLOCK_QUEUE_SCHEMA, validate_ml_unblock_queue)

    assert mode == "jsonschema+built-in"


def test_validate_ml_unblock_queue_rejects_bad_summary_count() -> None:
    payload = copy.deepcopy(valid_queue())
    payload["summary"]["env"] = 0

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "summary.env" in str(exc)
    else:
        raise AssertionError("expected bad summary count to fail")


def test_validate_ml_unblock_queue_rejects_noncontiguous_priority() -> None:
    payload = copy.deepcopy(valid_queue())
    payload["items"][2]["priority"] = 5

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "priorities" in str(exc)
    else:
        raise AssertionError("expected noncontiguous priority to fail")


def test_validate_ml_unblock_queue_rejects_missing_platform_audit_source() -> None:
    payload = copy.deepcopy(valid_queue())
    del payload["source"]["platform_readiness_audit"]

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "platform_readiness_audit" in str(exc)
    else:
        raise AssertionError("expected missing platform audit source to fail")


def test_validate_ml_unblock_queue_rejects_source_status_drift() -> None:
    payload = copy.deepcopy(valid_queue())
    payload["source"]["source_status_summary"]["pending_items"] = 2

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "source_status_summary.pending_items" in str(exc)
    else:
        raise AssertionError("expected source status summary drift to fail")


def test_validate_ml_unblock_queue_rejects_upstream_summary_drift() -> None:
    payload = copy.deepcopy(valid_queue())
    payload["source"]["source_status_summary"]["upstream_blocked"] = 4

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "source_status_summary.upstream_blocked" in str(exc)
    else:
        raise AssertionError("expected upstream summary drift to fail")


def test_validate_ml_unblock_queue_rejects_item_from_ready_claim() -> None:
    payload = copy.deepcopy(valid_queue())
    payload["items"][0]["source_claim_status"] = "ready_validation_only"
    payload["items"][0]["source_evidence_state"] = "ready_validation_only"

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "source_claim_status" in str(exc)
    else:
        raise AssertionError("expected unblock item from ready claim to fail")


def test_validate_ml_unblock_queue_rejects_item_with_command_exposure() -> None:
    payload = copy.deepcopy(valid_queue())
    payload["items"][0]["source_execute_guard_present"] = True
    payload["summary"]["items_without_command_exposure"] = 2
    payload["source"]["source_status_summary"]["items_without_command_exposure"] = 2

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "source_execute_guard_present" in str(exc)
    else:
        raise AssertionError("expected unblock item with command exposure to fail")


def test_validate_ml_unblock_queue_rejects_bad_resolution_plan_count() -> None:
    payload = copy.deepcopy(valid_queue())
    payload["summary"]["items_with_resolution_command_exposure"] = 1

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "items_with_resolution_command_exposure" in str(exc)
    else:
        raise AssertionError("expected resolution command count drift to fail")


def test_validate_ml_unblock_queue_rejects_guarded_validation_resolution_command() -> None:
    payload = copy.deepcopy(valid_queue())
    plan = payload["items"][0]["resolution_plan"]
    plan["command_available"] = True
    plan["validation_command"] = ".\\docs\\benchmarks\\runs\\launcher.ps1 -Execute"
    plan["execute_command"] = ".\\docs\\benchmarks\\runs\\launcher.ps1 -Execute"
    plan["execute_guard_env"] = "TAMANDUA_ALLOW_ML_REAL_ACQUISITION"
    payload["summary"]["items_with_resolution_command_exposure"] = 1
    payload["summary"]["items_without_resolution_command_exposure"] = 2
    payload["source"]["source_status_summary"]["items_with_resolution_command_exposure"] = 1
    payload["source"]["source_status_summary"]["items_without_resolution_command_exposure"] = 2

    try:
        validate_ml_unblock_queue(payload, Path("memory://ml-unblock-queue.json"))
    except ContractError as exc:
        assert "validation_command" in str(exc)
    else:
        raise AssertionError("expected guarded validation resolution command to fail")
