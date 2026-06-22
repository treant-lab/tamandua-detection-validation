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
    ML_UNBLOCK_QUEUE_CONSISTENCY_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_unblock_queue_consistency,
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


def valid_consistency() -> dict:
    payload = {
        "api_version": "tamandua.io/ml-unblock-queue-consistency/v1",
        "kind": "MLUnblockQueueConsistency",
        "metadata": {
            "report_id": "test_unblock_queue_consistency",
            "generated_at": "2026-06-04T23:59:59Z",
            "created_by": "tamandua-ml-unblock-queue-consistency",
            "claim_boundary": "No-execution ML unblock queue consistency probe only. Does not run launchers or commands.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "parallel_work_packages_validation": "jsonschema+built-in",
            "unblock_queue_validation": "jsonschema+built-in",
            "platform_readiness_audit_validation": "jsonschema+built-in",
            "dispatch_valid": True,
            "unblock_queue_valid": True,
            "platform_readiness_audit_valid": True,
            "queue_source_matches_dispatch": True,
            "queue_source_matches_platform_audit": True,
            "all_dispatch_blockers_queued": True,
            "no_stale_queue_items": True,
            "upstream_summary_matches": True,
            "queue_items_blocked_without_command_exposure": True,
            "goal_snapshot_matches_queue_summary": True,
            "check_count": 9,
            "passed_checks": 10,
            "failed_checks": 0,
            "blocker_count": 0,
            "dispatch_blockers": 11,
            "queue_items": 11,
            "items_from_blocked_claims": 11,
            "items_without_command_exposure": 11,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "source_mismatches": 0,
            "missing_queue_items": 0,
            "stale_queue_items": 0,
            **goal_summary(),
            "consistent": True,
        },
        "configuration": {
            "parallel_work_packages": "docs/benchmarks/runs/20260604T-ml-parallel-work-packages.json",
            "unblock_queue": "docs/benchmarks/runs/20260604T-ml-unblock-queue.json",
            "platform_readiness_audit": "docs/benchmarks/runs/20260604T-ml-platform-readiness-audit.json",
        },
        "summary": {
            "dispatch_blockers": 11,
            "queue_items": 11,
            "items_from_blocked_claims": 11,
            "items_without_command_exposure": 11,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "source_mismatches": 0,
            "missing_queue_items": 0,
            "stale_queue_items": 0,
            **goal_summary(),
        },
        "checks": [
            {"name": "dispatch_valid", "passed": True, "detail": "dispatch"},
            {"name": "unblock_queue_valid", "passed": True, "detail": "queue"},
            {"name": "platform_readiness_audit_valid", "passed": True, "detail": "audit"},
            {"name": "queue_source_matches_dispatch", "passed": True, "detail": "dispatch"},
            {"name": "queue_source_matches_platform_audit", "passed": True, "detail": "audit"},
            {"name": "all_dispatch_blockers_queued", "passed": True, "detail": ""},
            {"name": "no_stale_queue_items", "passed": True, "detail": ""},
            {"name": "upstream_summary_matches", "passed": True, "detail": ""},
            {"name": "queue_items_blocked_without_command_exposure", "passed": True, "detail": ""},
            {"name": "goal_snapshot_matches_queue_summary", "passed": True, "detail": ""},
        ],
    }
    payload["source_status_summary"]["check_count"] = len(payload["checks"])
    return payload


def test_validate_ml_unblock_queue_consistency_accepts_contract() -> None:
    validate_ml_unblock_queue_consistency(valid_consistency(), Path("memory://ml-unblock-queue-consistency.json"))


def test_validate_ml_unblock_queue_consistency_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-unblock-queue-consistency.json"
    report_path.write_text(json.dumps(valid_consistency()), encoding="utf-8")

    mode = validate_contract(report_path, ML_UNBLOCK_QUEUE_CONSISTENCY_SCHEMA, validate_ml_unblock_queue_consistency)

    assert mode == "jsonschema+built-in"


def test_validate_ml_unblock_queue_consistency_rejects_true_with_failed_check() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["checks"][2]["passed"] = False

    try:
        validate_ml_unblock_queue_consistency(payload, Path("memory://ml-unblock-queue-consistency.json"))
    except ContractError as exc:
        assert "cannot be true" in str(exc)
    else:
        raise AssertionError("expected true consistency with failed check to fail")


def test_validate_ml_unblock_queue_consistency_rejects_inconsistent_without_blockers() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False

    try:
        validate_ml_unblock_queue_consistency(payload, Path("memory://ml-unblock-queue-consistency.json"))
    except ContractError as exc:
        assert "must explain blockers" in str(exc)
    else:
        raise AssertionError("expected inconsistent report without blockers to fail")


def test_validate_ml_unblock_queue_consistency_rejects_source_mismatch_without_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["source_status_summary"]["consistent"] = False
    payload["summary"]["source_mismatches"] = 1
    payload["source_status_summary"]["source_mismatches"] = 1
    payload["checks"][3]["passed"] = False
    payload["source_status_summary"]["queue_source_matches_dispatch"] = False
    payload["blockers"] = ["unrelated"]
    payload["source_status_summary"]["blocker_count"] = 1

    try:
        validate_ml_unblock_queue_consistency(payload, Path("memory://ml-unblock-queue-consistency.json"))
    except ContractError as exc:
        assert "source mismatch" in str(exc)
    else:
        raise AssertionError("expected source mismatch without blocker to fail")


def test_validate_ml_unblock_queue_consistency_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["queue_items"] = 10

    try:
        validate_ml_unblock_queue_consistency(payload, Path("memory://ml-unblock-queue-consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.queue_items" in str(exc)
    else:
        raise AssertionError("expected source status summary drift to fail")


def test_validate_ml_unblock_queue_consistency_requires_upstream_summary_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["source_status_summary"]["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["upstream_summary_matches"] = False
    for check in payload["checks"]:
        if check["name"] == "upstream_summary_matches":
            check["passed"] = False

    try:
        validate_ml_unblock_queue_consistency(payload, Path("memory://ml-unblock-queue-consistency.json"))
    except ContractError as exc:
        assert "upstream summary mismatch" in str(exc)
    else:
        raise AssertionError("expected upstream mismatch without blocker to fail")


def test_validate_ml_unblock_queue_consistency_requires_command_exposure_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["source_status_summary"]["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["blocker_count"] = 1
    payload["summary"]["items_without_command_exposure"] = 10
    payload["source_status_summary"]["items_without_command_exposure"] = 10
    payload["source_status_summary"]["queue_items_blocked_without_command_exposure"] = False
    for check in payload["checks"]:
        if check["name"] == "queue_items_blocked_without_command_exposure":
            check["passed"] = False

    try:
        validate_ml_unblock_queue_consistency(payload, Path("memory://ml-unblock-queue-consistency.json"))
    except ContractError as exc:
        assert "command exposure mismatch" in str(exc)
    else:
        raise AssertionError("expected command exposure mismatch without blocker to fail")
