from pathlib import Path

import pytest

from validate_ml_contracts import ContractError, ML_UNBLOCK_HANDOFF_CONSISTENCY_SCHEMA, validate_contract, validate_ml_unblock_handoff_consistency


def goal_summary() -> dict:
    return {
        "goal_complete": False,
        "completion_state": "partial_evidence",
        "goal_usable_required_evidence": 1,
        "goal_required_evidence_total": 16,
        "next_unproven_requirement_id": "wave1_governed_acquisition",
        "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
    }


def valid_consistency() -> dict:
    payload = {
        "api_version": "tamandua.io/ml-unblock-handoff-consistency/v1",
        "kind": "MLUnblockHandoffConsistency",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-04T00:00:00+00:00",
            "created_by": "tamandua-ml-unblock-handoff-consistency",
            "claim_boundary": "No-execution ML unblock handoff consistency probe only. Does not execute.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "unblock_queue_validation": "jsonschema+built-in",
            "unblock_handoff_bundle_validation": "jsonschema+built-in",
            "unblock_queue_valid": True,
            "unblock_handoff_bundle_valid": True,
            "bundle_source_matches_queue": True,
            "all_queue_items_have_handoffs": True,
            "no_stale_handoffs": True,
            "handoff_fields_match_queue": True,
            "validation_command_hashes_match": True,
            "handoff_markdown_matches_manifest": True,
            "category_rollups_match": True,
            "upstream_summary_matches": True,
            "handoffs_preserve_blocked_no_command_counts": True,
            "handoffs_preserve_resolution_command_counts": True,
            "goal_snapshot_matches_queue": True,
            "check_count": 13,
            "passed_checks": 13,
            "failed_checks": 0,
            "blocker_count": 0,
            "queue_items": 11,
            "handoff_files": 11,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "items_from_blocked_claims": 11,
            "items_without_command_exposure": 11,
            "items_with_resolution_command_exposure": 11,
            "items_without_resolution_command_exposure": 0,
            "handoff_items_from_blocked_claims": 11,
            "handoff_items_without_command_exposure": 11,
            "handoff_items_with_resolution_command_exposure": 11,
            "handoff_items_without_resolution_command_exposure": 0,
            "source_mismatches": 0,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "field_mismatches": 0,
            "command_hash_mismatches": 0,
            "content_mismatches": 0,
            "pending_by_category": {
                "dependency": 6,
                "artifact": 3,
                "env": 2,
                "other": 0,
            },
            "resolved_by_category": {
                "dependency": 0,
                "artifact": 0,
                "env": 0,
                "other": 0,
            },
            "consistent": True,
            **goal_summary(),
        },
        "configuration": {
            "unblock_queue": "docs/benchmarks/runs/20260604T-ml-unblock-queue.json",
            "unblock_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-unblock-handoff-bundle.json",
        },
        "summary": {
            "queue_items": 11,
            "handoff_files": 11,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "items_from_blocked_claims": 11,
            "items_without_command_exposure": 11,
            "items_with_resolution_command_exposure": 11,
            "items_without_resolution_command_exposure": 0,
            "handoff_items_from_blocked_claims": 11,
            "handoff_items_without_command_exposure": 11,
            "handoff_items_with_resolution_command_exposure": 11,
            "handoff_items_without_resolution_command_exposure": 0,
            "source_mismatches": 0,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "command_hash_mismatches": 0,
            "pending_by_category": {
                "dependency": 6,
                "artifact": 3,
                "env": 2,
                "other": 0,
            },
            "resolved_by_category": {
                "dependency": 0,
                "artifact": 0,
                "env": 0,
                "other": 0,
            },
            **goal_summary(),
        },
        "checks": [
            {"name": "unblock_queue_valid", "passed": True, "detail": ""},
            {"name": "unblock_handoff_bundle_valid", "passed": True, "detail": ""},
            {"name": "bundle_source_matches_queue", "passed": True, "detail": ""},
            {"name": "all_queue_items_have_handoffs", "passed": True, "detail": ""},
            {"name": "no_stale_handoffs", "passed": True, "detail": ""},
            {"name": "handoff_fields_match_queue", "passed": True, "detail": ""},
            {"name": "validation_command_hashes_match", "passed": True, "detail": ""},
            {"name": "handoff_markdown_matches_manifest", "passed": True, "detail": ""},
            {"name": "category_rollups_match", "passed": True, "detail": ""},
            {"name": "upstream_summary_matches", "passed": True, "detail": ""},
            {"name": "handoffs_preserve_blocked_no_command_counts", "passed": True, "detail": ""},
            {"name": "handoffs_preserve_resolution_command_counts", "passed": True, "detail": ""},
            {"name": "goal_snapshot_matches_queue", "passed": True, "detail": ""},
        ],
    }
    payload["source_status_summary"]["check_count"] = len(payload["checks"])
    payload["source_status_summary"]["passed_checks"] = len(payload["checks"])
    return payload


def test_validate_ml_unblock_handoff_consistency_accepts_contract() -> None:
    validate_ml_unblock_handoff_consistency(valid_consistency(), Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-unblock-handoff-consistency.json"
    report_path.write_text(__import__("json").dumps(valid_consistency()), encoding="utf-8")

    mode = validate_contract(report_path, ML_UNBLOCK_HANDOFF_CONSISTENCY_SCHEMA, validate_ml_unblock_handoff_consistency)

    assert mode == "jsonschema+built-in"


def test_validate_ml_unblock_handoff_consistency_rejects_true_with_failed_check() -> None:
    payload = valid_consistency()
    payload["checks"][0]["passed"] = False

    with pytest.raises(ContractError, match="failed checks"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_rejects_missing_blocker_without_explanation() -> None:
    payload = valid_consistency()
    payload["consistent"] = False
    payload["summary"]["missing_handoffs"] = 1

    with pytest.raises(ContractError, match="inconsistent report"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_requires_source_mismatch_blocker() -> None:
    payload = valid_consistency()
    payload["consistent"] = False
    payload["source_status_summary"]["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["blocker_count"] = 1
    payload["summary"]["source_mismatches"] = 1
    payload["source_status_summary"]["source_mismatches"] = 1
    for check in payload["checks"]:
        if check["name"] == "bundle_source_matches_queue":
            check["passed"] = False
    payload["source_status_summary"]["bundle_source_matches_queue"] = False

    with pytest.raises(ContractError, match="source mismatch"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_rejects_source_summary_drift() -> None:
    payload = valid_consistency()
    payload["source_status_summary"]["handoff_files"] = 10

    with pytest.raises(ContractError, match="source_status_summary.handoff_files"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_rejects_category_summary_drift() -> None:
    payload = valid_consistency()
    payload["source_status_summary"]["pending_by_category"]["env"] = 1

    with pytest.raises(ContractError, match="source_status_summary.pending_by_category.env"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_requires_category_rollup_blocker() -> None:
    payload = valid_consistency()
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    for check in payload["checks"]:
        if check["name"] == "category_rollups_match":
            check["passed"] = False
    payload["source_status_summary"]["category_rollups_match"] = False

    with pytest.raises(ContractError, match="category rollup mismatch"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_requires_upstream_summary_mismatch_blocker() -> None:
    payload = valid_consistency()
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["upstream_summary_matches"] = False
    for check in payload["checks"]:
        if check["name"] == "upstream_summary_matches":
            check["passed"] = False

    with pytest.raises(ContractError, match="upstream summary mismatch"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_requires_command_hash_mismatch_blocker() -> None:
    payload = valid_consistency()
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["validation_command_hashes_match"] = False
    payload["source_status_summary"]["command_hash_mismatches"] = 1
    payload["summary"]["command_hash_mismatches"] = 1
    for check in payload["checks"]:
        if check["name"] == "validation_command_hashes_match":
            check["passed"] = False

    with pytest.raises(ContractError, match="command hash mismatch"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))


def test_validate_ml_unblock_handoff_consistency_requires_command_exposure_mismatch_blocker() -> None:
    payload = valid_consistency()
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["handoffs_preserve_blocked_no_command_counts"] = False
    payload["source_status_summary"]["handoff_items_without_command_exposure"] = 10
    payload["summary"]["handoff_items_without_command_exposure"] = 10
    for check in payload["checks"]:
        if check["name"] == "handoffs_preserve_blocked_no_command_counts":
            check["passed"] = False

    with pytest.raises(ContractError, match="command exposure mismatch"):
        validate_ml_unblock_handoff_consistency(payload, Path("memory://ml-unblock-handoff-consistency.json"))
