import json
from pathlib import Path

from validate_ml_contracts import (
    ML_BENCHMARK_MODALITIES,
    ML_BENCHMARK_LANE_ROLLUP_SCHEMA,
    validate_contract,
    validate_ml_benchmark_lane_rollup,
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


def modality(lane_id: str) -> dict:
    return {
        key: value
        for key, value in ML_BENCHMARK_MODALITIES[lane_id].items()
        if key != "scope"
    }


def add_goal_snapshot(report: dict) -> dict:
    report["source"]["source_status_summary"].update(GOAL_SNAPSHOT)
    report["summary"]["goal_complete"] = GOAL_SNAPSHOT["goal_complete"]
    report["summary"]["completion_state"] = GOAL_SNAPSHOT["completion_state"]
    report["summary"]["goal_usable_required_evidence"] = GOAL_SNAPSHOT["goal_usable_required_evidence"]
    report["summary"]["goal_required_evidence_total"] = GOAL_SNAPSHOT["goal_required_evidence_total"]
    report["summary"]["next_unproven_requirement_id"] = GOAL_SNAPSHOT["next_unproven_requirement_id"]
    report["summary"]["next_unproven_execute_guard_env"] = GOAL_SNAPSHOT["next_unproven_execute_guard_env"]
    return report


def test_validate_ml_benchmark_lane_rollup_accepts_jsonschema_path(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-lane-rollup/v1",
        "kind": "MLBenchmarkLaneRollup",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark lane rollup only.",
        },
        "source": {
            "benchmark_execution_matrix": "docs/benchmarks/runs/20260604T-ml-benchmark-execution-matrix.json",
            "benchmark_execution_matrix_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status.json",
            "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status-consistency.json",
            "benchmark_unblock_validation_status_consistency_validation": "jsonschema+built-in",
            "source_alignment": {
                "status_source_matches_handoff_consistency": True,
                "consistency_configuration_matches_status": True,
                "consistency_configuration_matches_queue": True,
            },
            "source_status_summary": {
                "benchmark_execution_matrix_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_consistency_validation": "jsonschema+built-in",
                "matrix_validated": True,
                "status_validated": True,
                "status_consistency_validated": True,
                "source_alignment_verified": True,
                "source_status_pending_items": 1,
                "rollup_pending_items": 1,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "matrix_lanes": 7,
                "rollup_lanes": 7,
                "ready_lane_ids": ["ML-0"],
                "blocked_lane_ids": ["ML-1", "ML-2", "ML-3", "ML-4", "ML-5", "ML-6"],
                "standalone_detection_lane_ids": ["ML-1"],
                "agent_onnx_detection_lane_ids": ["ML-3", "ML-5"],
                "tamandua_detection_lane_ids": ["ML-3", "ML-4", "ML-5"],
                "ready_lanes": 1,
                "blocked_lanes": 6,
                "standalone_detection_lanes": 1,
                "agent_onnx_detection_lanes": 2,
                "tamandua_detection_lanes": 3,
                "standalone_detection_surface_covered": True,
                "agent_onnx_detection_surface_covered": True,
                "tamandua_detection_surface_covered": True,
                "benchmark_detection_surface_contract_ready": True,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "dependency_pending": 0,
                "artifact_pending": 1,
                "env_pending": 0,
            },
        },
        "summary": {
            "total_lanes": 7,
            "evidence_exists_lanes": 1,
            "blocked_lanes": 6,
            "ready_lanes": 1,
            "standalone_detection_lanes": 1,
            "agent_onnx_detection_lanes": 2,
            "tamandua_detection_lanes": 3,
            "standalone_detection_surface_covered": True,
            "agent_onnx_detection_surface_covered": True,
            "tamandua_detection_surface_covered": True,
            "benchmark_detection_surface_contract_ready": True,
            "total_pending_items": 1,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "dependency_pending": 0,
            "artifact_pending": 1,
            "env_pending": 0,
        },
        "lanes": [
            {
                "lane_id": lane_id,
                "title": "Lane",
                "scope": scope,
                "benchmark_modality": modality(lane_id),
                "parallel_group": "group",
                "current_status": "evidence_exists" if lane_id == "ML-0" else "blocked_artifact",
                "ready_for_benchmark": lane_id == "ML-0",
                "pending_total": 1 if lane_id == "ML-1" else 0,
                "pending_by_category": {
                    "dependency": 0,
                    "artifact": 1 if lane_id == "ML-1" else 0,
                    "env": 0,
                    "other": 0,
                },
                "next_pending_items": ["ml-benchmark-unblock-001"] if lane_id == "ML-1" else [],
                "execute_guard_env": None,
                "claim_boundary": "No production claim.",
            }
            for lane_id, scope in [
                ("ML-0", "pipeline_smoke"),
                ("ML-1", "isolated_model"),
                ("ML-2", "onnx_parity"),
                ("ML-3", "agent_local"),
                ("ML-4", "service_api"),
                ("ML-5", "platform_replay"),
                ("ML-6", "cross_time_holdout"),
            ]
        ],
    }
    path = tmp_path / "rollup.json"
    path.write_text(json.dumps(add_goal_snapshot(report)), encoding="utf-8")

    mode = validate_contract(path, ML_BENCHMARK_LANE_ROLLUP_SCHEMA, validate_ml_benchmark_lane_rollup)

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_lane_rollup_rejects_source_summary_pending_drift(tmp_path: Path) -> None:
    report = json.loads(json.dumps({
        "api_version": "tamandua.io/ml-benchmark-lane-rollup/v1",
        "kind": "MLBenchmarkLaneRollup",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark lane rollup only.",
        },
        "source": {
            "benchmark_execution_matrix": "docs/benchmarks/runs/20260604T-ml-benchmark-execution-matrix.json",
            "benchmark_execution_matrix_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status.json",
            "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status-consistency.json",
            "benchmark_unblock_validation_status_consistency_validation": "jsonschema+built-in",
            "source_alignment": {
                "status_source_matches_handoff_consistency": True,
                "consistency_configuration_matches_status": True,
                "consistency_configuration_matches_queue": True,
            },
            "source_status_summary": {
                "benchmark_execution_matrix_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_consistency_validation": "jsonschema+built-in",
                "matrix_validated": True,
                "status_validated": True,
                "status_consistency_validated": True,
                "source_alignment_verified": True,
                "source_status_pending_items": 2,
                "rollup_pending_items": 1,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "matrix_lanes": 7,
                "rollup_lanes": 7,
                "ready_lane_ids": ["ML-0"],
                "blocked_lane_ids": ["ML-1", "ML-2", "ML-3", "ML-4", "ML-5", "ML-6"],
                "standalone_detection_lane_ids": ["ML-1"],
                "agent_onnx_detection_lane_ids": ["ML-3", "ML-5"],
                "tamandua_detection_lane_ids": ["ML-3", "ML-4", "ML-5"],
                "ready_lanes": 1,
                "blocked_lanes": 6,
                "standalone_detection_lanes": 1,
                "agent_onnx_detection_lanes": 2,
                "tamandua_detection_lanes": 3,
                "standalone_detection_surface_covered": True,
                "agent_onnx_detection_surface_covered": True,
                "tamandua_detection_surface_covered": True,
                "benchmark_detection_surface_contract_ready": True,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "dependency_pending": 0,
                "artifact_pending": 1,
                "env_pending": 0,
            },
        },
        "summary": {
            "total_lanes": 7,
            "evidence_exists_lanes": 1,
            "blocked_lanes": 6,
            "ready_lanes": 1,
            "standalone_detection_lanes": 1,
            "agent_onnx_detection_lanes": 2,
            "tamandua_detection_lanes": 3,
            "standalone_detection_surface_covered": True,
            "agent_onnx_detection_surface_covered": True,
            "tamandua_detection_surface_covered": True,
            "benchmark_detection_surface_contract_ready": True,
            "total_pending_items": 1,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "dependency_pending": 0,
            "artifact_pending": 1,
            "env_pending": 0,
        },
        "lanes": [
            {
                "lane_id": lane_id,
                "title": "Lane",
                "scope": scope,
                "benchmark_modality": modality(lane_id),
                "parallel_group": "group",
                "current_status": "evidence_exists" if lane_id == "ML-0" else "blocked_artifact",
                "ready_for_benchmark": lane_id == "ML-0",
                "pending_total": 1 if lane_id == "ML-1" else 0,
                "pending_by_category": {
                    "dependency": 0,
                    "artifact": 1 if lane_id == "ML-1" else 0,
                    "env": 0,
                    "other": 0,
                },
                "next_pending_items": ["ml-benchmark-unblock-001"] if lane_id == "ML-1" else [],
                "execute_guard_env": None,
                "claim_boundary": "No production claim.",
            }
            for lane_id, scope in [
                ("ML-0", "pipeline_smoke"),
                ("ML-1", "isolated_model"),
                ("ML-2", "onnx_parity"),
                ("ML-3", "agent_local"),
                ("ML-4", "service_api"),
                ("ML-5", "platform_replay"),
                ("ML-6", "cross_time_holdout"),
            ]
        ],
    }))
    path = tmp_path / "rollup.json"
    path.write_text(json.dumps(add_goal_snapshot(report)), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_LANE_ROLLUP_SCHEMA, validate_ml_benchmark_lane_rollup)
    except Exception as exc:
        assert "source.source_status_summary.source_status_pending_items" in str(exc)
    else:
        raise AssertionError("expected source summary pending drift to fail")


def test_validate_ml_benchmark_lane_rollup_rejects_summary_category_rollup_drift(tmp_path: Path) -> None:
    report = json.loads(json.dumps({
        "api_version": "tamandua.io/ml-benchmark-lane-rollup/v1",
        "kind": "MLBenchmarkLaneRollup",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark lane rollup only.",
        },
        "source": {
            "benchmark_execution_matrix": "docs/benchmarks/runs/20260604T-ml-benchmark-execution-matrix.json",
            "benchmark_execution_matrix_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status.json",
            "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status-consistency.json",
            "benchmark_unblock_validation_status_consistency_validation": "jsonschema+built-in",
            "source_alignment": {
                "status_source_matches_handoff_consistency": True,
                "consistency_configuration_matches_status": True,
                "consistency_configuration_matches_queue": True,
            },
            "source_status_summary": {
                "benchmark_execution_matrix_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_consistency_validation": "jsonschema+built-in",
                "matrix_validated": True,
                "status_validated": True,
                "status_consistency_validated": True,
                "source_alignment_verified": True,
                "source_status_pending_items": 1,
                "rollup_pending_items": 1,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "matrix_lanes": 7,
                "rollup_lanes": 7,
                "ready_lane_ids": ["ML-0"],
                "blocked_lane_ids": ["ML-1", "ML-2", "ML-3", "ML-4", "ML-5", "ML-6"],
                "standalone_detection_lane_ids": ["ML-1"],
                "agent_onnx_detection_lane_ids": ["ML-3", "ML-5"],
                "tamandua_detection_lane_ids": ["ML-3", "ML-4", "ML-5"],
                "ready_lanes": 1,
                "blocked_lanes": 6,
                "standalone_detection_lanes": 1,
                "agent_onnx_detection_lanes": 2,
                "tamandua_detection_lanes": 3,
                "standalone_detection_surface_covered": True,
                "agent_onnx_detection_surface_covered": True,
                "tamandua_detection_surface_covered": True,
                "benchmark_detection_surface_contract_ready": True,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "dependency_pending": 0,
                "artifact_pending": 1,
                "env_pending": 0,
            },
        },
        "summary": {
            "total_lanes": 7,
            "evidence_exists_lanes": 1,
            "blocked_lanes": 6,
            "ready_lanes": 1,
            "standalone_detection_lanes": 1,
            "agent_onnx_detection_lanes": 2,
            "tamandua_detection_lanes": 3,
            "standalone_detection_surface_covered": True,
            "agent_onnx_detection_surface_covered": True,
            "tamandua_detection_surface_covered": True,
            "benchmark_detection_surface_contract_ready": True,
            "total_pending_items": 1,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "dependency_pending": 0,
            "artifact_pending": 1,
            "env_pending": 0,
        },
        "lanes": [
            {
                "lane_id": lane_id,
                "title": "Lane",
                "scope": scope,
                "benchmark_modality": modality(lane_id),
                "parallel_group": "group",
                "current_status": "evidence_exists" if lane_id == "ML-0" else "blocked_artifact",
                "ready_for_benchmark": lane_id == "ML-0",
                "pending_total": 1 if lane_id == "ML-1" else 0,
                "pending_by_category": {
                    "dependency": 0,
                    "artifact": 1 if lane_id == "ML-1" else 0,
                    "env": 0,
                    "other": 0,
                },
                "next_pending_items": ["ml-benchmark-unblock-001"] if lane_id == "ML-1" else [],
                "execute_guard_env": None,
                "claim_boundary": "No production claim.",
            }
            for lane_id, scope in [
                ("ML-0", "pipeline_smoke"),
                ("ML-1", "isolated_model"),
                ("ML-2", "onnx_parity"),
                ("ML-3", "agent_local"),
                ("ML-4", "service_api"),
                ("ML-5", "platform_replay"),
                ("ML-6", "cross_time_holdout"),
            ]
        ],
    }))
    path = tmp_path / "rollup.json"
    path.write_text(json.dumps(add_goal_snapshot(report)), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_LANE_ROLLUP_SCHEMA, validate_ml_benchmark_lane_rollup)
    except Exception as exc:
        assert "summary.pending_by_category" in str(exc)
    else:
        raise AssertionError("expected category rollup drift to fail")
