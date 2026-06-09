import json
from pathlib import Path

from validate_ml_contracts import (
    ML_BENCHMARK_CRITICAL_PATH_SCHEMA,
    validate_contract,
    validate_ml_benchmark_critical_path,
)

ROOT = Path(__file__).resolve().parents[2]

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


def category_counts_for(item: dict) -> dict:
    category = item["category"] if item["category"] in {"dependency", "artifact", "env"} else "other"
    return {name: len(item["pending_item_ids"]) if name == category else 0 for name in ["dependency", "artifact", "env", "other"]}


def add_evidence_contract(report: dict) -> dict:
    total_items = 0
    total_usable = 0
    total_plans = 0
    total_commands = 0
    steps_with_commands = 0
    for step in report["critical_path"]:
        step.setdefault("pending_by_category", category_counts_for(step))
        evidence_items = []
        for evidence_path in step["evidence_paths"]:
            resolved = (ROOT / evidence_path).resolve()
            present = resolved.exists()
            status = "missing"
            if present:
                if resolved.name.endswith(".template.json"):
                    status = "template_only"
                elif resolved.name == "20260604T-ml-wave1-manifest-publish-receipt.json":
                    status = "blocked_artifact"
                elif resolved.name.startswith("ml-prod-candidate-v1-"):
                    status = "candidate_required_artifact"
                else:
                    status = "coordination_only"
            evidence_items.append(
                {
                    "path": evidence_path,
                    "present": present,
                    "evidence_status": status,
                    "evidence_usable_for_goal": False,
                    "claim_boundary": "Critical-path evidence reference only; not sufficient goal proof without governed execution.",
                }
            )
        step["evidence_items"] = evidence_items
        step["evidence_item_count"] = len(evidence_items)
        step["evidence_usable_for_goal"] = 0
        step.setdefault("resolution_plans", [])
        step["resolution_plan_count"] = len(step["resolution_plans"])
        step["resolution_command_available_count"] = sum(
            1 for plan in step["resolution_plans"] if plan.get("command_available") is True
        )
        total_items += len(evidence_items)
        total_usable += 0
        total_plans += step["resolution_plan_count"]
        total_commands += step["resolution_command_available_count"]
        if step["resolution_command_available_count"]:
            steps_with_commands += 1
    report["source"]["source_status_summary"]["evidence_item_count"] = total_items
    report["source"]["source_status_summary"]["evidence_usable_for_goal"] = total_usable
    report["source"]["source_status_summary"]["resolution_plan_count"] = total_plans
    report["source"]["source_status_summary"]["resolution_command_available_count"] = total_commands
    report["source"]["source_status_summary"]["steps_with_resolution_command"] = steps_with_commands
    report["source"]["source_status_summary"]["standalone_detection_surface_covered"] = True
    report["source"]["source_status_summary"]["agent_onnx_detection_surface_covered"] = True
    report["source"]["source_status_summary"]["tamandua_detection_surface_covered"] = True
    report["source"]["source_status_summary"]["benchmark_detection_surface_contract_ready"] = True
    report["source"]["source_status_summary"].update(GOAL_SNAPSHOT)
    report["summary"]["evidence_item_count"] = total_items
    report["summary"]["evidence_usable_for_goal"] = total_usable
    report["summary"]["resolution_plan_count"] = total_plans
    report["summary"]["resolution_command_available_count"] = total_commands
    report["summary"]["steps_with_resolution_command"] = steps_with_commands
    report["summary"]["standalone_detection_surface_covered"] = True
    report["summary"]["agent_onnx_detection_surface_covered"] = True
    report["summary"]["tamandua_detection_surface_covered"] = True
    report["summary"]["benchmark_detection_surface_contract_ready"] = True
    report["summary"]["goal_complete"] = GOAL_SNAPSHOT["goal_complete"]
    report["summary"]["completion_state"] = GOAL_SNAPSHOT["completion_state"]
    report["summary"]["goal_usable_required_evidence"] = GOAL_SNAPSHOT["goal_usable_required_evidence"]
    report["summary"]["goal_required_evidence_total"] = GOAL_SNAPSHOT["goal_required_evidence_total"]
    report["summary"]["next_unproven_requirement_id"] = GOAL_SNAPSHOT["next_unproven_requirement_id"]
    report["summary"]["next_unproven_execute_guard_env"] = GOAL_SNAPSHOT["next_unproven_execute_guard_env"]
    return report


def test_validate_ml_benchmark_critical_path_accepts_jsonschema_path(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path/v1",
        "kind": "MLBenchmarkCriticalPath",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path only.",
        },
        "source": {
            "benchmark_lane_rollup": "docs/benchmarks/runs/20260604T-ml-benchmark-lane-rollup.json",
            "benchmark_lane_rollup_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status.json",
            "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
            "source_alignment": {
                "critical_path_status_matches_rollup_status": True,
                "rollup_source_alignment_verified": True,
            },
            "source_status_summary": {
                "benchmark_lane_rollup_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
                "rollup_validated": True,
                "status_validated": True,
                "source_alignment_verified": True,
                "rollup_pending_items": 1,
                "status_pending_items": 1,
                "pending_items": 1,
                "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "pending_items_covered": 1,
                "covered_pending_item_ids": ["ml-benchmark-unblock-001"],
                "critical_path_steps": 1,
                "critical_path_targets": 1,
                "phase_count": 1,
                "phase_ids": ["01-wave1-manifest-publication"],
                "lanes_impacted": 1,
                "impacted_lane_ids": ["ML-1"],
                "evidence_path_count": 6,
            },
        },
        "summary": {
            "total_steps": 1,
            "pending_items_covered": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "lanes_impacted": 1,
            "first_phase": "01-wave1-manifest-publication",
            "last_phase": "01-wave1-manifest-publication",
        },
        "critical_path": [
            {
                "step": 1,
                "phase": "01-wave1-manifest-publication",
                "category": "dependency",
                "target": "manifest_publish_receipt_incomplete",
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "impacted_lanes": ["ML-1"],
                "lane_count": 1,
                "evidence_paths": [
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-lab-run-intake.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acceptance-checklist.json",
                ],
                "why_now": "first gate",
                "claim_boundary": "Coordination-only blocker ordering.",
            }
        ],
    }
    path = tmp_path / "critical-path.json"
    path.write_text(json.dumps(add_evidence_contract(report)), encoding="utf-8")

    mode = validate_contract(path, ML_BENCHMARK_CRITICAL_PATH_SCHEMA, validate_ml_benchmark_critical_path)

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_critical_path_rejects_false_source_alignment(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path/v1",
        "kind": "MLBenchmarkCriticalPath",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path only.",
        },
        "source": {
            "benchmark_lane_rollup": "docs/benchmarks/runs/20260604T-ml-benchmark-lane-rollup.json",
            "benchmark_lane_rollup_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status.json",
            "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
            "source_alignment": {
                "critical_path_status_matches_rollup_status": False,
                "rollup_source_alignment_verified": True,
            },
            "source_status_summary": {
                "benchmark_lane_rollup_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
                "rollup_validated": True,
                "status_validated": True,
                "source_alignment_verified": True,
                "rollup_pending_items": 1,
                "status_pending_items": 1,
                "pending_items": 1,
                "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "pending_items_covered": 1,
                "covered_pending_item_ids": ["ml-benchmark-unblock-001"],
                "critical_path_steps": 1,
                "critical_path_targets": 1,
                "phase_count": 1,
                "phase_ids": ["01-wave1-manifest-publication"],
                "lanes_impacted": 1,
                "impacted_lane_ids": ["ML-1"],
                "evidence_path_count": 6,
            },
        },
        "summary": {
            "total_steps": 1,
            "pending_items_covered": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "lanes_impacted": 1,
            "first_phase": "01-wave1-manifest-publication",
            "last_phase": "01-wave1-manifest-publication",
        },
        "critical_path": [
            {
                "step": 1,
                "phase": "01-wave1-manifest-publication",
                "category": "dependency",
                "target": "manifest_publish_receipt_incomplete",
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "impacted_lanes": ["ML-1"],
                "lane_count": 1,
                "evidence_paths": [
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-lab-run-intake.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acceptance-checklist.json",
                ],
                "why_now": "first gate",
                "claim_boundary": "Coordination-only blocker ordering.",
            }
        ],
    }
    path = tmp_path / "critical-path.json"
    path.write_text(json.dumps(add_evidence_contract(report)), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_CRITICAL_PATH_SCHEMA, validate_ml_benchmark_critical_path)
    except Exception as exc:
        assert "source_alignment" in str(exc)
    else:
        raise AssertionError("expected source alignment validation failure")


def test_validate_ml_benchmark_critical_path_rejects_wave1_step_without_transcript(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path/v1",
        "kind": "MLBenchmarkCriticalPath",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path only.",
        },
        "source": {
            "benchmark_lane_rollup": "docs/benchmarks/runs/20260604T-ml-benchmark-lane-rollup.json",
            "benchmark_lane_rollup_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status.json",
            "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
            "source_alignment": {
                "critical_path_status_matches_rollup_status": True,
                "rollup_source_alignment_verified": True,
            },
            "source_status_summary": {
                "benchmark_lane_rollup_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
                "rollup_validated": True,
                "status_validated": True,
                "source_alignment_verified": True,
                "rollup_pending_items": 1,
                "status_pending_items": 1,
                "pending_items": 1,
                "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "pending_items_covered": 1,
                "covered_pending_item_ids": ["ml-benchmark-unblock-001"],
                "critical_path_steps": 1,
                "critical_path_targets": 1,
                "phase_count": 1,
                "phase_ids": ["01-wave1-manifest-publication"],
                "lanes_impacted": 1,
                "impacted_lane_ids": ["ML-1"],
                "evidence_path_count": 1,
            },
        },
        "summary": {
            "total_steps": 1,
            "pending_items_covered": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "lanes_impacted": 1,
            "first_phase": "01-wave1-manifest-publication",
            "last_phase": "01-wave1-manifest-publication",
        },
        "critical_path": [
            {
                "step": 1,
                "phase": "01-wave1-manifest-publication",
                "category": "dependency",
                "target": "manifest_publish_receipt_incomplete",
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "impacted_lanes": ["ML-1"],
                "lane_count": 1,
                "evidence_paths": ["docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json"],
                "why_now": "first gate",
                "claim_boundary": "Coordination-only blocker ordering.",
            }
        ],
    }
    path = tmp_path / "critical-path.json"
    path.write_text(json.dumps(add_evidence_contract(report)), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_CRITICAL_PATH_SCHEMA, validate_ml_benchmark_critical_path)
    except Exception as exc:
        assert "real-acquisition-transcript" in str(exc)
    else:
        raise AssertionError("expected missing Wave 1 transcript evidence to fail")


def test_validate_ml_benchmark_critical_path_rejects_missing_source_pending_item(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path/v1",
        "kind": "MLBenchmarkCriticalPath",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path only.",
        },
        "source": {
            "benchmark_lane_rollup": "docs/benchmarks/runs/20260604T-ml-benchmark-lane-rollup.json",
            "benchmark_lane_rollup_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-validation-status.json",
            "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
            "source_alignment": {
                "critical_path_status_matches_rollup_status": True,
                "rollup_source_alignment_verified": True,
            },
            "source_status_summary": {
                "benchmark_lane_rollup_validation": "jsonschema+built-in",
                "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
                "rollup_validated": True,
                "status_validated": True,
                "source_alignment_verified": True,
                "rollup_pending_items": 2,
                "status_pending_items": 2,
                "pending_items": 2,
                "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_item_ids": ["ml-benchmark-unblock-001", "ml-benchmark-unblock-002"],
                "pending_items_covered": 1,
                "covered_pending_item_ids": ["ml-benchmark-unblock-001"],
                "critical_path_steps": 1,
                "critical_path_targets": 1,
                "phase_count": 1,
                "phase_ids": ["01-wave1-manifest-publication"],
                "lanes_impacted": 1,
                "impacted_lane_ids": ["ML-1"],
                "evidence_path_count": 6,
            },
        },
        "summary": {
            "total_steps": 1,
            "pending_items_covered": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "lanes_impacted": 1,
            "first_phase": "01-wave1-manifest-publication",
            "last_phase": "01-wave1-manifest-publication",
        },
        "critical_path": [
            {
                "step": 1,
                "phase": "01-wave1-manifest-publication",
                "category": "dependency",
                "target": "manifest_publish_receipt_incomplete",
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "impacted_lanes": ["ML-1"],
                "lane_count": 1,
                "evidence_paths": [
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-lab-run-intake.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acceptance-checklist.json",
                ],
                "why_now": "first gate",
                "claim_boundary": "Coordination-only blocker ordering.",
            }
        ],
    }
    path = tmp_path / "critical-path.json"
    path.write_text(json.dumps(add_evidence_contract(report)), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_CRITICAL_PATH_SCHEMA, validate_ml_benchmark_critical_path)
    except Exception as exc:
        assert "missing source pending items: ml-benchmark-unblock-002" in str(exc)
    else:
        raise AssertionError("expected missing source pending item to fail")
