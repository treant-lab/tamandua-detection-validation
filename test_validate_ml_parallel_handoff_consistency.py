from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    ML_PARALLEL_HANDOFF_CONSISTENCY_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_parallel_handoff_consistency,
)


def valid_consistency() -> dict:
    goal_summary = {
        "goal_complete": False,
        "completion_state": "partial_evidence",
        "goal_usable_required_evidence": 1,
        "goal_required_evidence_total": 16,
        "next_unproven_requirement_id": "wave1_governed_acquisition",
        "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
    }
    return {
        "api_version": "tamandua.io/ml-parallel-handoff-consistency/v1",
        "kind": "MLParallelHandoffConsistency",
        "metadata": {
            "report_id": "test_consistency",
            "generated_at": "2026-06-04T23:59:00Z",
            "created_by": "tamandua-ml-parallel-handoff-consistency",
            "claim_boundary": "No-execution ML handoff consistency probe only. Does not run launchers or execute commands.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "parallel_work_packages_validation": "jsonschema+built-in",
            "parallel_handoff_bundle_validation": "jsonschema+built-in",
            "dispatch_valid": True,
            "handoff_bundle_valid": True,
            "bundle_source_matches_dispatch": True,
            "claim_ids_match": True,
            "claim_status_and_guard_match": True,
            "claim_evidence_usability_match": True,
            "claim_safe_command_fingerprints_match": True,
            "claim_block_category_match": True,
            "handoff_content_matches_claims": True,
            "no_orphan_handoff_files": True,
            "claim_command_exposure_match": True,
            "blocked_category_rollups_match": True,
            "goal_snapshot_matches_dispatch": True,
            "category_mismatches": 0,
            "fingerprint_mismatches": 0,
            "check_count": 13,
            "passed_checks": 13,
            "failed_checks": 0,
            "blocker_count": 0,
            "dispatch_claims": 8,
            "handoff_claim_files": 8,
            "source_mismatches": 0,
            "orphan_handoff_files": 0,
            "dispatch_validation_command_claims": 1,
            "handoff_validation_command_claim_files": 1,
            "dispatch_execute_guard_claims": 1,
            "handoff_execute_guard_claim_files": 1,
            "dispatch_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "ready_validation_only": 1,
            "blocked": 5,
            "blocked_by_category": {
                "dependency": 0,
                "artifact": 1,
                "env": 4,
                "other": 0,
            },
            "evidence_exists": 2,
            **goal_summary,
            "consistent": True,
        },
        "configuration": {
            "parallel_work_packages": "docs/benchmarks/runs/20260604T-ml-parallel-work-packages.json",
            "parallel_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-parallel-handoff-bundle.json",
        },
        "summary": {
            "dispatch_claims": 8,
            "handoff_claim_files": 8,
            "source_mismatches": 0,
            "orphan_handoff_files": 0,
            "dispatch_validation_command_claims": 1,
            "handoff_validation_command_claim_files": 1,
            "dispatch_execute_guard_claims": 1,
            "handoff_execute_guard_claim_files": 1,
            "dispatch_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "ready_validation_only": 1,
            "blocked": 5,
            "blocked_by_category": {
                "dependency": 0,
                "artifact": 1,
                "env": 4,
                "other": 0,
            },
            "evidence_exists": 2,
            "category_mismatches": 0,
            "fingerprint_mismatches": 0,
            **goal_summary,
        },
        "checks": [
            {"name": "dispatch_valid", "passed": True, "detail": "dispatch"},
            {"name": "handoff_bundle_valid", "passed": True, "detail": "bundle"},
            {"name": "bundle_source_matches_dispatch", "passed": True, "detail": ""},
            {"name": "claim_ids_match", "passed": True, "detail": "dispatch=8 bundle=8"},
            {"name": "claim_status_and_guard_match", "passed": True, "detail": ""},
            {"name": "claim_evidence_usability_match", "passed": True, "detail": ""},
            {"name": "claim_safe_command_fingerprints_match", "passed": True, "detail": ""},
            {"name": "claim_block_category_match", "passed": True, "detail": ""},
            {"name": "handoff_content_matches_claims", "passed": True, "detail": ""},
            {"name": "no_orphan_handoff_files", "passed": True, "detail": ""},
            {"name": "claim_command_exposure_match", "passed": True, "detail": ""},
            {"name": "blocked_category_rollups_match", "passed": True, "detail": ""},
            {"name": "goal_snapshot_matches_dispatch", "passed": True, "detail": ""},
        ],
    }


def test_validate_ml_parallel_handoff_consistency_accepts_contract() -> None:
    validate_ml_parallel_handoff_consistency(valid_consistency(), Path("memory://consistency.json"))


def test_validate_ml_parallel_handoff_consistency_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "consistency.json"
    report_path.write_text(json.dumps(valid_consistency()), encoding="utf-8")

    mode = validate_contract(report_path, ML_PARALLEL_HANDOFF_CONSISTENCY_SCHEMA, validate_ml_parallel_handoff_consistency)

    assert mode == "jsonschema+built-in"


def test_validate_ml_parallel_handoff_consistency_rejects_true_with_failed_check() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["checks"][2]["passed"] = False

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "cannot be true" in str(exc)
    else:
        raise AssertionError("expected true consistency with failed check to fail")


def test_validate_ml_parallel_handoff_consistency_rejects_missing_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "must explain blockers" in str(exc)
    else:
        raise AssertionError("expected inconsistent report without blockers to fail")


def test_validate_ml_parallel_handoff_consistency_requires_source_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["summary"]["source_mismatches"] = 1
    payload["source_status_summary"]["source_mismatches"] = 1
    for check in payload["checks"]:
        if check["name"] == "bundle_source_matches_dispatch":
            check["passed"] = False
    payload["source_status_summary"]["bundle_source_matches_dispatch"] = False

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source mismatch" in str(exc)
    else:
        raise AssertionError("expected missing source mismatch blocker to fail")


def test_validate_ml_parallel_handoff_consistency_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["passed_checks"] = 7

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.passed_checks" in str(exc)
    else:
        raise AssertionError("expected source status summary drift to fail")


def test_validate_ml_parallel_handoff_consistency_rejects_category_rollup_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["blocked_by_category"]["env"] = 3

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.blocked_by_category.env" in str(exc)
    else:
        raise AssertionError("expected category rollup drift to fail")


def test_validate_ml_parallel_handoff_consistency_requires_category_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["summary"]["category_mismatches"] = 1
    payload["source_status_summary"]["category_mismatches"] = 1
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    for check in payload["checks"]:
        if check["name"] == "claim_block_category_match":
            check["passed"] = False
    payload["source_status_summary"]["claim_block_category_match"] = False

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "category mismatch" in str(exc)
    else:
        raise AssertionError("expected missing category mismatch blocker to fail")


def test_validate_ml_parallel_handoff_consistency_requires_command_exposure_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["summary"]["handoff_execute_guard_claim_files"] = 0
    payload["source_status_summary"]["handoff_execute_guard_claim_files"] = 0
    payload["source_status_summary"]["claim_command_exposure_match"] = False
    for check in payload["checks"]:
        if check["name"] == "claim_command_exposure_match":
            check["passed"] = False

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "command exposure mismatch" in str(exc)
    else:
        raise AssertionError("expected missing command exposure mismatch blocker to fail")


def test_validate_ml_parallel_handoff_consistency_requires_fingerprint_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["summary"]["fingerprint_mismatches"] = 1
    payload["source_status_summary"]["fingerprint_mismatches"] = 1
    payload["source_status_summary"]["claim_safe_command_fingerprints_match"] = False
    for check in payload["checks"]:
        if check["name"] == "claim_safe_command_fingerprints_match":
            check["passed"] = False

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "fingerprint mismatch" in str(exc)
    else:
        raise AssertionError("expected missing fingerprint mismatch blocker to fail")


def test_validate_ml_parallel_handoff_consistency_requires_orphan_handoff_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["summary"]["orphan_handoff_files"] = 1
    payload["source_status_summary"]["orphan_handoff_files"] = 1
    payload["source_status_summary"]["no_orphan_handoff_files"] = False
    for check in payload["checks"]:
        if check["name"] == "no_orphan_handoff_files":
            check["passed"] = False

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "orphan handoff" in str(exc)
    else:
        raise AssertionError("expected missing orphan handoff blocker to fail")


def test_validate_ml_parallel_handoff_consistency_requires_evidence_usability_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["summary"]["handoff_evidence_usable_for_goal"] = 1
    payload["source_status_summary"]["handoff_evidence_usable_for_goal"] = 1
    payload["source_status_summary"]["claim_evidence_usability_match"] = False
    for check in payload["checks"]:
        if check["name"] == "claim_evidence_usability_match":
            check["passed"] = False

    try:
        validate_ml_parallel_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "evidence usability mismatch" in str(exc)
    else:
        raise AssertionError("expected missing evidence usability mismatch blocker to fail")
