import json
import hashlib
from pathlib import Path

from validate_ml_contracts import (
    ML_BENCHMARK_CRITICAL_PATH_HANDOFF_BUNDLE_SCHEMA,
    validate_contract,
    validate_ml_benchmark_critical_path_handoff_bundle,
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


def category_counts_for(item: dict) -> dict:
    category = item["category"] if item["category"] in {"dependency", "artifact", "env"} else "other"
    return {name: len(item["pending_item_ids"]) if name == category else 0 for name in ["dependency", "artifact", "env", "other"]}


def add_resolution_contract(report: dict) -> dict:
    total_plans = 0
    total_commands = 0
    files_with_commands = 0
    for item in report["handoff_files"]:
        item.setdefault("pending_by_category", category_counts_for(item))
        item.setdefault("resolution_plans", [])
        item["resolution_plan_count"] = len(item["resolution_plans"])
        item["resolution_command_available_count"] = sum(
            1 for plan in item["resolution_plans"] if plan.get("command_available") is True
        )
        total_plans += item["resolution_plan_count"]
        total_commands += item["resolution_command_available_count"]
        if item["resolution_command_available_count"]:
            files_with_commands += 1
    report["summary"]["resolution_plan_count"] = total_plans
    report["summary"]["resolution_command_available_count"] = total_commands
    report["summary"]["handoff_files_with_resolution_command"] = files_with_commands
    source_summary = report["source"]["source_critical_path_summary"]
    source_summary["resolution_plan_count"] = total_plans
    source_summary["resolution_command_available_count"] = total_commands
    source_summary["handoff_files_with_resolution_command"] = files_with_commands
    source_summary.update(GOAL_SNAPSHOT)
    report["summary"]["goal_complete"] = GOAL_SNAPSHOT["goal_complete"]
    report["summary"]["completion_state"] = GOAL_SNAPSHOT["completion_state"]
    report["summary"]["goal_usable_required_evidence"] = GOAL_SNAPSHOT["goal_usable_required_evidence"]
    report["summary"]["goal_required_evidence_total"] = GOAL_SNAPSHOT["goal_required_evidence_total"]
    report["summary"]["next_unproven_requirement_id"] = GOAL_SNAPSHOT["next_unproven_requirement_id"]
    report["summary"]["next_unproven_execute_guard_env"] = GOAL_SNAPSHOT["next_unproven_execute_guard_env"]
    return report


def test_validate_ml_benchmark_critical_path_handoff_bundle_accepts_jsonschema_path(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path-handoff-bundle/v1",
        "kind": "MLBenchmarkCriticalPathHandoffBundle",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path handoff bundle only.",
        },
        "source": {
            "benchmark_critical_path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.json",
            "benchmark_critical_path_validation": "jsonschema+built-in",
            "source_critical_path_summary": {
                "benchmark_critical_path_validated": True,
                "steps": 1,
                "step_ids": [1],
                "handoff_files": 1,
                "readme_written": True,
                "pending_items_covered": 1,
                "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "handoff_pending_item_ids": ["ml-benchmark-unblock-001"],
                "lanes_impacted": 1,
                "impacted_lane_ids": ["ML-1"],
                "phase_count": 1,
                "validation_command_count": 1,
                "validation_commands_are_validation_only": True,
                "evidence_item_count": 0,
                "evidence_usable_for_goal": 0,
            },
        },
        "output_dir": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff",
        "readme": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff/README.md",
        "summary": {
            "total_handoff_files": 1,
            "pending_items_covered": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "lanes_impacted": 1,
            "evidence_item_count": 0,
            "evidence_usable_for_goal": 0,
        },
        "handoff_files": [
            {
                "step": 1,
                "phase": "01-wave1-manifest-publication",
                "category": "dependency",
                "target": "manifest_publish_receipt_incomplete",
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "impacted_lanes": ["ML-1"],
                "path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff/01-step.md",
                "expected_evidence": "Expected evidence path(s): `docs/benchmarks/runs/receipt.json`",
                "evidence_items": [],
                "evidence_item_count": 0,
                "evidence_usable_for_goal": 0,
                "validation_command": "python apps\\tamandua_ml\\scripts\\ml_benchmark_lane_rollup.py; python apps\\tamandua_ml\\scripts\\ml_benchmark_critical_path.py",
                "validation_command_sha256": hashlib.sha256(
                    "python apps\\tamandua_ml\\scripts\\ml_benchmark_lane_rollup.py; python apps\\tamandua_ml\\scripts\\ml_benchmark_critical_path.py".encode("utf-8")
                ).hexdigest(),
            }
        ],
    }
    validate_ml_benchmark_critical_path_handoff_bundle(
        add_resolution_contract(report),
        Path("memory://bundle.json"),
    )


def test_validate_ml_benchmark_critical_path_handoff_bundle_rejects_stale_command_order(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path-handoff-bundle/v1",
        "kind": "MLBenchmarkCriticalPathHandoffBundle",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path handoff bundle only.",
        },
        "source": {
            "benchmark_critical_path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.json",
            "benchmark_critical_path_validation": "jsonschema+built-in",
            "source_critical_path_summary": {
                "benchmark_critical_path_validated": True,
                "steps": 1,
                "step_ids": [1],
                "handoff_files": 1,
                "readme_written": True,
                "pending_items_covered": 1,
                "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "handoff_pending_item_ids": ["ml-benchmark-unblock-001"],
                "lanes_impacted": 1,
                "impacted_lane_ids": ["ML-1"],
                "phase_count": 1,
                "validation_command_count": 1,
                "validation_commands_are_validation_only": True,
                "evidence_item_count": 0,
                "evidence_usable_for_goal": 0,
            },
        },
        "output_dir": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff",
        "readme": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff/README.md",
        "summary": {
            "total_handoff_files": 1,
            "pending_items_covered": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "lanes_impacted": 1,
            "evidence_item_count": 0,
            "evidence_usable_for_goal": 0,
        },
        "handoff_files": [
            {
                "step": 1,
                "phase": "01-wave1-manifest-publication",
                "category": "dependency",
                "target": "manifest_publish_receipt_incomplete",
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "impacted_lanes": ["ML-1"],
                "path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff/01-step.md",
                "expected_evidence": "Expected evidence path(s): `docs/benchmarks/runs/receipt.json`",
                "evidence_items": [],
                "evidence_item_count": 0,
                "evidence_usable_for_goal": 0,
                "validation_command": "python apps\\tamandua_ml\\scripts\\ml_benchmark_critical_path.py; python apps\\tamandua_ml\\scripts\\ml_benchmark_lane_rollup.py",
                "validation_command_sha256": hashlib.sha256(
                    "python apps\\tamandua_ml\\scripts\\ml_benchmark_critical_path.py; python apps\\tamandua_ml\\scripts\\ml_benchmark_lane_rollup.py".encode("utf-8")
                ).hexdigest(),
            }
        ],
    }
    try:
        validate_ml_benchmark_critical_path_handoff_bundle(
            add_resolution_contract(report),
            Path("memory://bundle.json"),
        )
    except Exception as exc:
        assert "lane rollup must refresh before critical path" in str(exc)
    else:
        raise AssertionError("expected stale validation command order to fail")


def test_validate_ml_benchmark_critical_path_handoff_bundle_rejects_missing_source_pending_item(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-critical-path-handoff-bundle/v1",
        "kind": "MLBenchmarkCriticalPathHandoffBundle",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark critical path handoff bundle only.",
        },
        "source": {
            "benchmark_critical_path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.json",
            "benchmark_critical_path_validation": "jsonschema+built-in",
            "source_critical_path_summary": {
                "benchmark_critical_path_validated": True,
                "steps": 1,
                "step_ids": [1],
                "handoff_files": 1,
                "readme_written": True,
                "pending_items_covered": 2,
                "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "pending_item_ids": ["ml-benchmark-unblock-001", "ml-benchmark-unblock-002"],
                "handoff_pending_item_ids": ["ml-benchmark-unblock-001", "ml-benchmark-unblock-002"],
                "lanes_impacted": 1,
                "impacted_lane_ids": ["ML-1"],
                "phase_count": 1,
                "validation_command_count": 1,
                "validation_commands_are_validation_only": True,
                "evidence_item_count": 0,
                "evidence_usable_for_goal": 0,
            },
        },
        "output_dir": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff",
        "readme": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff/README.md",
        "summary": {
            "total_handoff_files": 1,
            "pending_items_covered": 1,
            "pending_by_category": {"dependency": 1, "artifact": 0, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "lanes_impacted": 1,
            "evidence_item_count": 0,
            "evidence_usable_for_goal": 0,
        },
        "handoff_files": [
            {
                "step": 1,
                "phase": "01-wave1-manifest-publication",
                "category": "dependency",
                "target": "manifest_publish_receipt_incomplete",
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "impacted_lanes": ["ML-1"],
                "path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.handoff/01-step.md",
                "expected_evidence": "Expected evidence path(s): `docs/benchmarks/runs/receipt.json`",
                "evidence_items": [],
                "evidence_item_count": 0,
                "evidence_usable_for_goal": 0,
                "validation_command": "python apps\\tamandua_ml\\scripts\\ml_benchmark_lane_rollup.py; python apps\\tamandua_ml\\scripts\\ml_benchmark_critical_path.py",
                "validation_command_sha256": hashlib.sha256(
                    "python apps\\tamandua_ml\\scripts\\ml_benchmark_lane_rollup.py; python apps\\tamandua_ml\\scripts\\ml_benchmark_critical_path.py".encode("utf-8")
                ).hexdigest(),
            }
        ],
    }
    try:
        validate_ml_benchmark_critical_path_handoff_bundle(
            add_resolution_contract(report),
            Path("memory://bundle.json"),
        )
    except Exception as exc:
        assert "missing source pending items: ml-benchmark-unblock-002" in str(exc)
    else:
        raise AssertionError("expected missing source pending item to fail")
