from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    ML_UNBLOCK_VALIDATION_STATUS_CONSISTENCY_SCHEMA,
    validate_contract,
    validate_ml_unblock_validation_status_consistency,
)


def goal_summary() -> dict:
    return {
        "goal_complete": False,
        "completion_state": "partial_evidence",
        "goal_usable_required_evidence": 1,
        "goal_required_evidence_total": 16,
        "next_unproven_requirement_id": "wave1_governed_acquisition",
        "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
    }


def valid_report() -> dict:
    payload = {
        "api_version": "tamandua.io/ml-unblock-validation-status-consistency/v1",
        "kind": "MLUnblockValidationStatusConsistency",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-04T00:00:00+00:00",
            "created_by": "tamandua-ml-unblock-validation-status-consistency",
            "claim_boundary": "No-execution ML unblock validation status consistency probe only.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "unblock_queue_validation": "jsonschema+built-in",
            "unblock_validation_status_validation": "jsonschema+built-in",
            "platform_readiness_audit_validation": "jsonschema+built-in",
            "unblock_queue_valid": True,
            "unblock_validation_status_valid": True,
            "platform_readiness_audit_valid": True,
            "status_source_matches_queue": True,
            "status_source_matches_platform_audit": True,
            "all_queue_items_have_status": True,
            "no_stale_status_items": True,
            "readiness_links_match_queue": True,
            "active_readiness_blockers_match_audit": True,
            "upstream_summary_matches": True,
            "status_preserves_handoff_coverage": True,
            "status_preserves_blocked_no_command_counts": True,
            "status_preserves_resolution_command_counts": True,
            "goal_snapshot_matches_sources": True,
            "check_count": 14,
            "passed_checks": 14,
            "failed_checks": 0,
            "blocker_count": 0,
            "queue_items": 1,
            "status_items": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "source_mismatches": 0,
            "missing_status_items": 0,
            "stale_status_items": 0,
            "readiness_blocker_links": 1,
            "active_readiness_blockers_expected": 1,
            "active_readiness_blockers_reported": 1,
            "mismatched_active_readiness_items": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "missing_handoff_ids": 0,
            "items_from_blocked_claims": 1,
            "items_without_command_exposure": 1,
            "items_with_resolution_command_exposure": 1,
            "items_without_resolution_command_exposure": 0,
            "handoff_items_from_blocked_claims": 1,
            "handoff_items_without_command_exposure": 1,
            "handoff_items_with_resolution_command_exposure": 1,
            "handoff_items_without_resolution_command_exposure": 0,
            "consistent": True,
            **goal_summary(),
        },
        "configuration": {
            "unblock_queue": "docs/benchmarks/runs/20260604T-ml-unblock-queue.json",
            "unblock_validation_status": "docs/benchmarks/runs/20260604T-ml-unblock-validation-status.json",
            "platform_readiness_audit": "docs/benchmarks/runs/20260604T-ml-platform-readiness-audit.json",
        },
        "summary": {
            "queue_items": 1,
            "status_items": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "source_mismatches": 0,
            "missing_status_items": 0,
            "stale_status_items": 0,
            "readiness_blocker_links": 1,
            "active_readiness_blockers_expected": 1,
            "active_readiness_blockers_reported": 1,
            "mismatched_active_readiness_items": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "missing_handoff_ids": 0,
            "items_from_blocked_claims": 1,
            "items_without_command_exposure": 1,
            "items_with_resolution_command_exposure": 1,
            "items_without_resolution_command_exposure": 0,
            "handoff_items_from_blocked_claims": 1,
            "handoff_items_without_command_exposure": 1,
            "handoff_items_with_resolution_command_exposure": 1,
            "handoff_items_without_resolution_command_exposure": 0,
            **goal_summary(),
        },
        "checks": [
            {"name": "unblock_queue_valid", "passed": True, "detail": ""},
            {"name": "unblock_validation_status_valid", "passed": True, "detail": ""},
            {"name": "platform_readiness_audit_valid", "passed": True, "detail": ""},
            {"name": "status_source_matches_queue", "passed": True, "detail": ""},
            {"name": "status_source_matches_platform_audit", "passed": True, "detail": ""},
            {"name": "all_queue_items_have_status", "passed": True, "detail": ""},
            {"name": "no_stale_status_items", "passed": True, "detail": ""},
            {"name": "readiness_links_match_queue", "passed": True, "detail": ""},
            {"name": "active_readiness_blockers_match_audit", "passed": True, "detail": ""},
            {"name": "upstream_summary_matches", "passed": True, "detail": ""},
            {"name": "status_preserves_handoff_coverage", "passed": True, "detail": ""},
            {"name": "status_preserves_blocked_no_command_counts", "passed": True, "detail": ""},
            {"name": "status_preserves_resolution_command_counts", "passed": True, "detail": ""},
            {"name": "goal_snapshot_matches_sources", "passed": True, "detail": ""},
        ],
    }
    payload["source_status_summary"]["check_count"] = len(payload["checks"])
    payload["source_status_summary"]["passed_checks"] = len(payload["checks"])
    return payload


def test_validate_ml_unblock_validation_status_consistency_accepts_contract() -> None:
    validate_ml_unblock_validation_status_consistency(
        valid_report(),
        Path("memory://ml-unblock-validation-status-consistency.json"),
    )


def test_validate_ml_unblock_validation_status_consistency_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-unblock-validation-status-consistency.json"
    report_path.write_text(__import__("json").dumps(valid_report()), encoding="utf-8")

    mode = validate_contract(
        report_path,
        ML_UNBLOCK_VALIDATION_STATUS_CONSISTENCY_SCHEMA,
        validate_ml_unblock_validation_status_consistency,
    )

    assert mode == "jsonschema+built-in"


def test_validate_ml_unblock_validation_status_consistency_rejects_missing_blocker_for_mismatch() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 11
    payload["source_status_summary"]["failed_checks"] = 1
    payload["summary"]["mismatched_active_readiness_items"] = 1
    payload["source_status_summary"]["mismatched_active_readiness_items"] = 1
    payload["source_status_summary"]["active_readiness_blockers_match_audit"] = False
    for check in payload["checks"]:
        if check["name"] == "active_readiness_blockers_match_audit":
            check["passed"] = False

    with pytest.raises(ContractError, match="active readiness mismatch"):
        validate_ml_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_unblock_validation_status_consistency_requires_queue_source_mismatch_blocker() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 11
    payload["source_status_summary"]["failed_checks"] = 1
    payload["summary"]["source_mismatches"] = 1
    payload["source_status_summary"]["source_mismatches"] = 1
    for check in payload["checks"]:
        if check["name"] == "status_source_matches_queue":
            check["passed"] = False
            payload["source_status_summary"]["status_source_matches_queue"] = False

    with pytest.raises(ContractError, match="status queue source mismatch"):
        validate_ml_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_unblock_validation_status_consistency_requires_audit_source_mismatch_blocker() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 11
    payload["source_status_summary"]["failed_checks"] = 1
    payload["summary"]["source_mismatches"] = 1
    payload["source_status_summary"]["source_mismatches"] = 1
    for check in payload["checks"]:
        if check["name"] == "status_source_matches_platform_audit":
            check["passed"] = False
            payload["source_status_summary"]["status_source_matches_platform_audit"] = False

    with pytest.raises(ContractError, match="status platform audit source mismatch"):
        validate_ml_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_unblock_validation_status_consistency_rejects_source_summary_drift() -> None:
    payload = valid_report()
    payload["source_status_summary"]["status_items"] = 0

    with pytest.raises(ContractError, match="source_status_summary.status_items"):
        validate_ml_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_unblock_validation_status_consistency_rejects_category_drift() -> None:
    payload = valid_report()
    payload["source_status_summary"]["pending_by_category"]["dependency"] = 0

    with pytest.raises(ContractError, match="pending_by_category.dependency"):
        validate_ml_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_unblock_validation_status_consistency_requires_command_exposure_blocker() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 11
    payload["source_status_summary"]["failed_checks"] = 1
    payload["summary"]["handoff_items_without_command_exposure"] = 0
    payload["source_status_summary"]["handoff_items_without_command_exposure"] = 0
    payload["source_status_summary"]["status_preserves_blocked_no_command_counts"] = False
    for check in payload["checks"]:
        if check["name"] == "status_preserves_blocked_no_command_counts":
            check["passed"] = False

    with pytest.raises(ContractError, match="command exposure mismatch"):
        validate_ml_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_unblock_validation_status_consistency_requires_handoff_coverage_blocker() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 11
    payload["source_status_summary"]["failed_checks"] = 1
    payload["summary"]["missing_handoff_ids"] = 1
    payload["source_status_summary"]["missing_handoff_ids"] = 1
    payload["source_status_summary"]["status_preserves_handoff_coverage"] = False
    for check in payload["checks"]:
        if check["name"] == "status_preserves_handoff_coverage":
            check["passed"] = False

    with pytest.raises(ContractError, match="handoff coverage mismatch"):
        validate_ml_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-unblock-validation-status-consistency.json"),
        )
