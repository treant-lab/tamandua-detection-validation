from pathlib import Path

import pytest

from validate_ml_contracts import ContractError, ML_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_contract, validate_ml_unblock_validation_status


def goal_full() -> dict:
    return {
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
        "missing_requirement_ids": ["wave1_governed_acquisition"],
        "evidence_status_summary": {"usable_required_evidence": 1},
        "next_unproven_requirement": {"id": "wave1_governed_acquisition"},
    }


def goal_summary() -> dict:
    snapshot = goal_full()
    return {
        "goal_complete": snapshot["goal_complete"],
        "completion_state": snapshot["completion_state"],
        "goal_usable_required_evidence": snapshot["goal_usable_required_evidence"],
        "goal_required_evidence_total": snapshot["goal_required_evidence_total"],
        "next_unproven_requirement_id": snapshot["next_unproven_requirement_id"],
        "next_unproven_execute_guard_env": snapshot["next_unproven_execute_guard_env"],
    }


def valid_status() -> dict:
    return {
        "api_version": "tamandua.io/ml-unblock-validation-status/v1",
        "kind": "MLUnblockValidationStatus",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-04T00:00:00+00:00",
            "created_by": "tamandua-ml-unblock-validation-status",
            "claim_boundary": "No-execution ML unblock validation status only. Does not run commands.",
        },
        "source": {
            "parallel_work_packages": "docs/benchmarks/runs/20260604T-ml-parallel-work-packages.json",
            "parallel_work_packages_validation": "jsonschema+built-in",
            "unblock_queue": "docs/benchmarks/runs/20260604T-ml-unblock-queue.json",
            "unblock_queue_validation": "jsonschema+built-in",
            "unblock_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-unblock-handoff-bundle.json",
            "unblock_handoff_bundle_validation": "jsonschema+built-in",
            "platform_readiness_audit": "docs/benchmarks/runs/20260604T-ml-platform-readiness-audit.json",
            "platform_readiness_audit_validation": "jsonschema+built-in",
            "source_status_summary": {
                "parallel_work_packages_validated": True,
                "unblock_queue_validated": True,
                "unblock_handoff_bundle_validated": True,
                "platform_readiness_audit_validated": True,
                "dispatch_claims": 1,
                "queue_items": 1,
                "handoff_files": 1,
                "status_items": 1,
                "resolved": 0,
                "pending": 1,
                "missing_handoff_ids": 0,
                "pending_item_ids": ["ml-unblock-001"],
                "resolved_item_ids": [],
                "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "items_from_blocked_claims": 1,
                "items_without_command_exposure": 1,
                "items_with_resolution_command_exposure": 1,
                "items_without_resolution_command_exposure": 0,
                "handoff_items_from_blocked_claims": 1,
                "handoff_items_without_command_exposure": 1,
                "handoff_items_with_resolution_command_exposure": 1,
                "handoff_items_without_resolution_command_exposure": 0,
                "dependency_pending": 1,
                "artifact_pending": 0,
                "env_pending": 0,
                "readiness_blocker_links": 1,
                "readiness_blockers_active": 1,
                "primary_resolved_but_readiness_blocked": 0,
                "all_queue_items_have_status": True,
                "all_status_items_have_handoffs": True,
                "priority_sequence_valid": True,
                **goal_full(),
            },
        },
        "summary": {
            "total_items": 1,
            "resolved": 0,
            "pending": 1,
            "missing_handoff_ids": 0,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "items_from_blocked_claims": 1,
            "items_without_command_exposure": 1,
            "items_with_resolution_command_exposure": 1,
            "items_without_resolution_command_exposure": 0,
            "handoff_items_from_blocked_claims": 1,
            "handoff_items_without_command_exposure": 1,
            "handoff_items_with_resolution_command_exposure": 1,
            "handoff_items_without_resolution_command_exposure": 0,
            "dependency_pending": 1,
            "artifact_pending": 0,
            "env_pending": 0,
            "readiness_blocker_links": 1,
            "readiness_blockers_active": 1,
            "primary_resolved_but_readiness_blocked": 0,
            **goal_summary(),
        },
        "missing_handoff_ids": [],
        "items": [
            {
                "unblock_id": "ml-unblock-001",
                "claim_id": "ml-ml1_train_candidate_and_model_card",
                "package_id": "ml1_train_candidate_and_model_card",
                "wave": 2,
                "owner_role": "ml-training",
                "parallel_group": "model-quality",
                "category": "dependency",
                "target": "ml_data_governed_acquisition",
                "priority": 1,
                "primary_resolved": False,
                "readiness_blockers": ["ml1_candidate:manifest_publish_receipt_incomplete"],
                "readiness_blockers_active": ["ml1_candidate:manifest_publish_receipt_incomplete"],
                "readiness_evidence_paths": [
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-lab-run-intake.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acceptance-checklist.json",
                    "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
                ],
                "resolved": False,
                "resolution_state": "pending",
                "detail": "dependency package status=ready",
            }
        ],
        "next_pending_items": [],
    }


def test_validate_ml_unblock_validation_status_accepts_contract() -> None:
    validate_ml_unblock_validation_status(valid_status(), Path("memory://ml-unblock-validation-status.json"))


def test_validate_ml_unblock_validation_status_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-unblock-validation-status.json"
    report_path.write_text(__import__("json").dumps(valid_status()), encoding="utf-8")

    mode = validate_contract(report_path, ML_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_ml_unblock_validation_status)

    assert mode == "jsonschema+built-in"


def test_validate_ml_unblock_validation_status_rejects_bad_state() -> None:
    payload = valid_status()
    payload["items"][0]["primary_resolved"] = True
    payload["items"][0]["readiness_blockers_active"] = []
    payload["summary"]["readiness_blockers_active"] = 0
    payload["summary"]["primary_resolved_but_readiness_blocked"] = 0
    payload["items"][0]["resolved"] = True

    with pytest.raises(ContractError, match="resolved state"):
        validate_ml_unblock_validation_status(payload, Path("memory://ml-unblock-validation-status.json"))


def test_validate_ml_unblock_validation_status_rejects_bad_count() -> None:
    payload = valid_status()
    payload["summary"]["pending"] = 2

    with pytest.raises(ContractError, match="pending"):
        validate_ml_unblock_validation_status(payload, Path("memory://ml-unblock-validation-status.json"))


def test_validate_ml_unblock_validation_status_rejects_missing_wave1_readiness_evidence() -> None:
    payload = valid_status()
    payload["items"][0]["readiness_evidence_paths"] = [
        "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json"
    ]

    with pytest.raises(ContractError, match="ML-1 Wave 1 blocker missing evidence"):
        validate_ml_unblock_validation_status(payload, Path("memory://ml-unblock-validation-status.json"))


def test_validate_ml_unblock_validation_status_rejects_source_summary_drift() -> None:
    payload = valid_status()
    payload["source"]["source_status_summary"]["pending"] = 0

    with pytest.raises(ContractError, match="source_status_summary.pending"):
        validate_ml_unblock_validation_status(payload, Path("memory://ml-unblock-validation-status.json"))


def test_validate_ml_unblock_validation_status_rejects_category_count_drift() -> None:
    payload = valid_status()
    payload["source"]["source_status_summary"]["pending_by_category"]["dependency"] = 0

    with pytest.raises(ContractError, match="pending_by_category.dependency"):
        validate_ml_unblock_validation_status(payload, Path("memory://ml-unblock-validation-status.json"))


def test_validate_ml_unblock_validation_status_rejects_upstream_summary_drift() -> None:
    payload = valid_status()
    payload["summary"]["upstream_ready_validation_only"] = 0

    with pytest.raises(ContractError, match="upstream_ready_validation_only"):
        validate_ml_unblock_validation_status(payload, Path("memory://ml-unblock-validation-status.json"))


def test_validate_ml_unblock_validation_status_rejects_command_exposure_count_drift() -> None:
    payload = valid_status()
    payload["summary"]["handoff_items_without_command_exposure"] = 0
    payload["source"]["source_status_summary"]["handoff_items_without_command_exposure"] = 0

    with pytest.raises(ContractError, match="handoff_items_without_command_exposure"):
        validate_ml_unblock_validation_status(payload, Path("memory://ml-unblock-validation-status.json"))
