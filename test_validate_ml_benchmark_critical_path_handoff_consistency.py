import json
from pathlib import Path

from validate_ml_contracts import (
    ML_BENCHMARK_CRITICAL_PATH_HANDOFF_CONSISTENCY_SCHEMA,
    validate_contract,
    validate_ml_benchmark_critical_path_handoff_consistency,
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
    "missing_requirement_ids": ["wave1_governed_acquisition"],
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
        "pending_targets": ["manifest_publish_receipt_incomplete"],
        "required_evidence": ["wave1-transcript.json"],
        "missing_or_unusable_evidence": ["wave1-transcript.json"],
    },
}


def add_goal_snapshot(report: dict) -> dict:
    report["source_status_summary"].update(GOAL_SNAPSHOT)
    report["summary"]["goal_complete"] = GOAL_SNAPSHOT["goal_complete"]
    report["summary"]["completion_state"] = GOAL_SNAPSHOT["completion_state"]
    report["summary"]["goal_usable_required_evidence"] = GOAL_SNAPSHOT["goal_usable_required_evidence"]
    report["summary"]["goal_required_evidence_total"] = GOAL_SNAPSHOT["goal_required_evidence_total"]
    report["summary"]["next_unproven_requirement_id"] = GOAL_SNAPSHOT["next_unproven_requirement_id"]
    report["summary"]["next_unproven_execute_guard_env"] = GOAL_SNAPSHOT["next_unproven_execute_guard_env"]
    return report


def test_validate_ml_benchmark_critical_path_handoff_consistency_accepts_jsonschema_path(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path-handoff-consistency/v1",
        "kind": "MLBenchmarkCriticalPathHandoffConsistency",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path handoff consistency probe only.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "benchmark_critical_path_validation": "jsonschema+built-in",
            "benchmark_critical_path_handoff_bundle_validation": "jsonschema+built-in",
            "critical_path_validated": True,
            "handoff_bundle_validated": True,
            "bundle_source_matches_critical_path": True,
            "all_critical_steps_have_handoffs": True,
            "no_stale_critical_handoffs": True,
            "handoff_fields_match_critical_path": True,
            "handoff_evidence_items_match_critical_path": True,
            "validation_command_hashes_match": True,
            "handoff_markdown_matches_manifest": True,
            "category_rollups_match": True,
            "upstream_summary_matches": True,
            "check_count": 11,
            "passed_checks": 11,
            "failed_checks": 0,
            "blocker_count": 0,
            "critical_path_steps": 1,
            "handoff_files": 1,
            "source_mismatches": 0,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "field_mismatches": 0,
            "evidence_mismatches": 0,
            "command_hash_mismatches": 0,
            "category_mismatches": 0,
            "content_mismatches": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "critical_path_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "consistent": True,
        },
        "configuration": {
            "benchmark_critical_path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.json",
            "benchmark_critical_path_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path-handoff-bundle.json",
        },
        "summary": {
            "critical_path_steps": 1,
            "handoff_files": 1,
            "source_mismatches": 0,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "field_mismatches": 0,
            "evidence_mismatches": 0,
            "command_hash_mismatches": 0,
            "category_mismatches": 0,
            "content_mismatches": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "critical_path_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
        },
        "checks": [
            {"name": "benchmark_critical_path_valid", "passed": True, "detail": ""},
            {"name": "benchmark_critical_path_handoff_bundle_valid", "passed": True, "detail": ""},
            {"name": "bundle_source_matches_critical_path", "passed": True, "detail": ""},
            {"name": "all_critical_steps_have_handoffs", "passed": True, "detail": ""},
            {"name": "no_stale_critical_handoffs", "passed": True, "detail": ""},
            {"name": "handoff_fields_match_critical_path", "passed": True, "detail": ""},
            {"name": "handoff_evidence_items_match_critical_path", "passed": True, "detail": ""},
            {"name": "validation_command_hashes_match", "passed": True, "detail": ""},
            {"name": "handoff_markdown_matches_manifest", "passed": True, "detail": ""},
            {"name": "category_rollups_match", "passed": True, "detail": ""},
            {"name": "upstream_summary_matches", "passed": True, "detail": ""},
        ],
    }
    path = tmp_path / "consistency.json"
    path.write_text(json.dumps(add_goal_snapshot(report)), encoding="utf-8")

    mode = validate_contract(
        path,
        ML_BENCHMARK_CRITICAL_PATH_HANDOFF_CONSISTENCY_SCHEMA,
        validate_ml_benchmark_critical_path_handoff_consistency,
    )

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_critical_path_handoff_consistency_requires_source_mismatch_blocker(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path-handoff-consistency/v1",
        "kind": "MLBenchmarkCriticalPathHandoffConsistency",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path handoff consistency probe only.",
        },
        "consistent": False,
        "blockers": ["some_other_blocker"],
        "source_status_summary": {
            "benchmark_critical_path_validation": "jsonschema+built-in",
            "benchmark_critical_path_handoff_bundle_validation": "jsonschema+built-in",
            "critical_path_validated": True,
            "handoff_bundle_validated": True,
            "bundle_source_matches_critical_path": False,
            "all_critical_steps_have_handoffs": True,
            "no_stale_critical_handoffs": True,
            "handoff_fields_match_critical_path": True,
            "handoff_evidence_items_match_critical_path": True,
            "validation_command_hashes_match": True,
            "handoff_markdown_matches_manifest": True,
            "category_rollups_match": True,
            "upstream_summary_matches": True,
            "check_count": 11,
            "passed_checks": 10,
            "failed_checks": 1,
            "blocker_count": 1,
            "critical_path_steps": 1,
            "handoff_files": 1,
            "source_mismatches": 1,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "field_mismatches": 0,
            "evidence_mismatches": 0,
            "command_hash_mismatches": 0,
            "category_mismatches": 0,
            "content_mismatches": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "critical_path_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "consistent": False,
        },
        "configuration": {
            "benchmark_critical_path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.json",
            "benchmark_critical_path_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path-handoff-bundle.json",
        },
        "summary": {
            "critical_path_steps": 1,
            "handoff_files": 1,
            "source_mismatches": 1,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "field_mismatches": 0,
            "evidence_mismatches": 0,
            "command_hash_mismatches": 0,
            "category_mismatches": 0,
            "content_mismatches": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "critical_path_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
        },
        "checks": [
            {"name": "benchmark_critical_path_valid", "passed": True, "detail": ""},
            {"name": "benchmark_critical_path_handoff_bundle_valid", "passed": True, "detail": ""},
            {"name": "bundle_source_matches_critical_path", "passed": False, "detail": ""},
            {"name": "all_critical_steps_have_handoffs", "passed": True, "detail": ""},
            {"name": "no_stale_critical_handoffs", "passed": True, "detail": ""},
            {"name": "handoff_fields_match_critical_path", "passed": True, "detail": ""},
            {"name": "handoff_evidence_items_match_critical_path", "passed": True, "detail": ""},
            {"name": "validation_command_hashes_match", "passed": True, "detail": ""},
            {"name": "handoff_markdown_matches_manifest", "passed": True, "detail": ""},
            {"name": "category_rollups_match", "passed": True, "detail": ""},
            {"name": "upstream_summary_matches", "passed": True, "detail": ""},
        ],
    }
    path = tmp_path / "consistency.json"
    path.write_text(json.dumps(add_goal_snapshot(report)), encoding="utf-8")

    try:
        validate_contract(
            path,
            ML_BENCHMARK_CRITICAL_PATH_HANDOFF_CONSISTENCY_SCHEMA,
            validate_ml_benchmark_critical_path_handoff_consistency,
        )
    except Exception as exc:
        assert "source mismatch" in str(exc)
    else:
        raise AssertionError("expected missing source mismatch blocker failure")


def test_validate_ml_benchmark_critical_path_handoff_consistency_rejects_source_summary_drift(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path-handoff-consistency/v1",
        "kind": "MLBenchmarkCriticalPathHandoffConsistency",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path handoff consistency probe only.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "benchmark_critical_path_validation": "jsonschema+built-in",
            "benchmark_critical_path_handoff_bundle_validation": "jsonschema+built-in",
            "critical_path_validated": True,
            "handoff_bundle_validated": True,
            "bundle_source_matches_critical_path": True,
            "all_critical_steps_have_handoffs": True,
            "no_stale_critical_handoffs": True,
            "handoff_fields_match_critical_path": True,
            "handoff_evidence_items_match_critical_path": True,
            "validation_command_hashes_match": True,
            "handoff_markdown_matches_manifest": True,
            "category_rollups_match": True,
            "upstream_summary_matches": True,
            "check_count": 11,
            "passed_checks": 6,
            "failed_checks": 0,
            "blocker_count": 0,
            "critical_path_steps": 1,
            "handoff_files": 1,
            "source_mismatches": 0,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "field_mismatches": 0,
            "evidence_mismatches": 0,
            "command_hash_mismatches": 0,
            "category_mismatches": 0,
            "content_mismatches": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "critical_path_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "consistent": True,
        },
        "configuration": {
            "benchmark_critical_path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.json",
            "benchmark_critical_path_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path-handoff-bundle.json",
        },
        "summary": {
            "critical_path_steps": 1,
            "handoff_files": 1,
            "source_mismatches": 0,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "field_mismatches": 0,
            "evidence_mismatches": 0,
            "command_hash_mismatches": 0,
            "category_mismatches": 0,
            "content_mismatches": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "critical_path_evidence_usable_for_goal": 0,
            "handoff_evidence_usable_for_goal": 0,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
        },
        "checks": [
            {"name": "benchmark_critical_path_valid", "passed": True, "detail": ""},
            {"name": "benchmark_critical_path_handoff_bundle_valid", "passed": True, "detail": ""},
            {"name": "bundle_source_matches_critical_path", "passed": True, "detail": ""},
            {"name": "all_critical_steps_have_handoffs", "passed": True, "detail": ""},
            {"name": "no_stale_critical_handoffs", "passed": True, "detail": ""},
            {"name": "handoff_fields_match_critical_path", "passed": True, "detail": ""},
            {"name": "handoff_evidence_items_match_critical_path", "passed": True, "detail": ""},
            {"name": "validation_command_hashes_match", "passed": True, "detail": ""},
            {"name": "handoff_markdown_matches_manifest", "passed": True, "detail": ""},
            {"name": "category_rollups_match", "passed": True, "detail": ""},
            {"name": "upstream_summary_matches", "passed": True, "detail": ""},
        ],
    }
    path = tmp_path / "consistency.json"
    path.write_text(json.dumps(add_goal_snapshot(report)), encoding="utf-8")

    try:
        validate_contract(
            path,
            ML_BENCHMARK_CRITICAL_PATH_HANDOFF_CONSISTENCY_SCHEMA,
            validate_ml_benchmark_critical_path_handoff_consistency,
        )
    except Exception as exc:
        assert "source_status_summary.passed_checks" in str(exc)
    else:
        raise AssertionError("expected source summary drift failure")
