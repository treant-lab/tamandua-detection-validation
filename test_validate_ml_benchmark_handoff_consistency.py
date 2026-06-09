from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    ML_BENCHMARK_HANDOFF_CONSISTENCY_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_benchmark_handoff_consistency,
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
        "api_version": "tamandua.io/ml-benchmark-handoff-consistency/v1",
        "kind": "MLBenchmarkHandoffConsistency",
        "metadata": {
            "report_id": "test_consistency",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "tamandua-ml-benchmark-handoff-consistency",
            "claim_boundary": "No-execution ML benchmark handoff consistency probe only.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "benchmark_matrix_validation": "jsonschema+built-in",
            "benchmark_handoff_bundle_validation": "jsonschema+built-in",
            "matrix_validated": True,
            "bundle_validated": True,
            "bundle_source_matches_matrix": True,
            "lane_ids_match": True,
            "lane_status_scope_and_guard_match": True,
            "lane_evidence_usability_match": True,
            "handoff_content_matches_lanes": True,
            "lane_guarded_command_fingerprints_match": True,
            "no_orphan_handoff_files": True,
            "status_rollups_match": True,
            "upstream_parallel_summary_matches": True,
            "goal_snapshot_matches_matrix": True,
            "passed_checks": 12,
            "failed_checks": 0,
            "check_count": 12,
            "blocker_count": 0,
            "matrix_lanes": 7,
            "handoff_lane_files": 7,
            "source_mismatches": 0,
            "orphan_handoff_files": 0,
            "fingerprint_mismatches": 0,
            "ready_validation_only": 0,
            "blocked": 6,
            "evidence_exists": 1,
            "matrix_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            **goal_summary,
            "consistent": True,
        },
        "configuration": {
            "benchmark_execution_matrix": "docs/benchmarks/runs/20260604T-ml-benchmark-execution-matrix.json",
            "benchmark_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-handoff-bundle.json",
        },
        "summary": {
            "matrix_lanes": 7,
            "handoff_lane_files": 7,
            "source_mismatches": 0,
            "orphan_handoff_files": 0,
            "fingerprint_mismatches": 0,
            "ready_validation_only": 0,
            "blocked": 6,
            "evidence_exists": 1,
            "matrix_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            **goal_summary,
        },
        "checks": [
            {"name": "benchmark_matrix_valid", "passed": True, "detail": "matrix"},
            {"name": "benchmark_handoff_bundle_valid", "passed": True, "detail": "bundle"},
            {"name": "bundle_source_matches_matrix", "passed": True, "detail": ""},
            {"name": "lane_ids_match", "passed": True, "detail": "matrix=7 bundle=7"},
            {"name": "lane_status_scope_and_guard_match", "passed": True, "detail": ""},
            {"name": "lane_evidence_usability_match", "passed": True, "detail": ""},
            {"name": "handoff_content_matches_lanes", "passed": True, "detail": ""},
            {"name": "lane_guarded_command_fingerprints_match", "passed": True, "detail": ""},
            {"name": "no_orphan_handoff_files", "passed": True, "detail": ""},
            {"name": "status_rollups_match", "passed": True, "detail": ""},
            {"name": "upstream_parallel_summary_matches", "passed": True, "detail": ""},
            {"name": "goal_snapshot_matches_matrix", "passed": True, "detail": ""},
        ],
    }


def test_validate_ml_benchmark_handoff_consistency_accepts_contract() -> None:
    validate_ml_benchmark_handoff_consistency(valid_consistency(), Path("memory://consistency.json"))


def test_validate_ml_benchmark_handoff_consistency_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "consistency.json"
    report_path.write_text(json.dumps(valid_consistency()), encoding="utf-8")

    mode = validate_contract(report_path, ML_BENCHMARK_HANDOFF_CONSISTENCY_SCHEMA, validate_ml_benchmark_handoff_consistency)

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_handoff_consistency_rejects_true_with_failed_check() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["checks"][2]["passed"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "cannot be true" in str(exc)
    else:
        raise AssertionError("expected true consistency with failed check to fail")


def test_validate_ml_benchmark_handoff_consistency_rejects_missing_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "must explain blockers" in str(exc)
    else:
        raise AssertionError("expected inconsistent report without blockers to fail")


def test_validate_ml_benchmark_handoff_consistency_requires_source_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["summary"]["source_mismatches"] = 1
    for check in payload["checks"]:
        if check["name"] == "bundle_source_matches_matrix":
            check["passed"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source mismatch" in str(exc)
    else:
        raise AssertionError("expected missing source mismatch blocker to fail")


def test_validate_ml_benchmark_handoff_consistency_rejects_source_summary_check_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["passed_checks"] = 6

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.passed_checks" in str(exc)
    else:
        raise AssertionError("expected source summary check drift to fail")


def test_validate_ml_benchmark_handoff_consistency_rejects_source_validation_mode_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["benchmark_handoff_bundle_validation"] = "failed"

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.bundle_validated" in str(exc)
    else:
        raise AssertionError("expected source validation mode drift to fail")


def test_validate_ml_benchmark_handoff_consistency_rejects_status_summary_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["blocked"] = 5

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.blocked" in str(exc)
    else:
        raise AssertionError("expected status summary drift to fail")


def test_validate_ml_benchmark_handoff_consistency_requires_status_rollup_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    for check in payload["checks"]:
        if check["name"] == "status_rollups_match":
            check["passed"] = False
    payload["source_status_summary"]["status_rollups_match"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "status rollup mismatch" in str(exc)
    else:
        raise AssertionError("expected missing status rollup blocker to fail")


def test_validate_ml_benchmark_handoff_consistency_requires_fingerprint_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["summary"]["fingerprint_mismatches"] = 1
    payload["source_status_summary"]["fingerprint_mismatches"] = 1
    payload["source_status_summary"]["lane_guarded_command_fingerprints_match"] = False
    for check in payload["checks"]:
        if check["name"] == "lane_guarded_command_fingerprints_match":
            check["passed"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "fingerprint mismatch" in str(exc)
    else:
        raise AssertionError("expected missing fingerprint blocker to fail")


def test_validate_ml_benchmark_handoff_consistency_requires_orphan_handoff_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["summary"]["orphan_handoff_files"] = 1
    payload["source_status_summary"]["orphan_handoff_files"] = 1
    payload["source_status_summary"]["no_orphan_handoff_files"] = False
    for check in payload["checks"]:
        if check["name"] == "no_orphan_handoff_files":
            check["passed"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "orphan handoff" in str(exc)
    else:
        raise AssertionError("expected missing orphan handoff blocker to fail")


def test_validate_ml_benchmark_handoff_consistency_requires_upstream_summary_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    for check in payload["checks"]:
        if check["name"] == "upstream_parallel_summary_matches":
            check["passed"] = False
    payload["source_status_summary"]["upstream_parallel_summary_matches"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "upstream parallel summary mismatch" in str(exc)
    else:
        raise AssertionError("expected missing upstream summary blocker to fail")


def test_validate_ml_benchmark_handoff_consistency_requires_evidence_usability_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["summary"]["handoff_evidence_usable_for_goal"] = 1
    payload["source_status_summary"]["handoff_evidence_usable_for_goal"] = 1
    payload["source_status_summary"]["lane_evidence_usability_match"] = False
    for check in payload["checks"]:
        if check["name"] == "lane_evidence_usability_match":
            check["passed"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "evidence usability mismatch" in str(exc)
    else:
        raise AssertionError("expected missing evidence usability blocker to fail")


def test_validate_ml_benchmark_handoff_consistency_requires_goal_snapshot_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["goal_snapshot_matches_matrix"] = False
    for check in payload["checks"]:
        if check["name"] == "goal_snapshot_matches_matrix":
            check["passed"] = False

    try:
        validate_ml_benchmark_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "goal snapshot mismatch" in str(exc)
    else:
        raise AssertionError("expected missing goal snapshot blocker to fail")
