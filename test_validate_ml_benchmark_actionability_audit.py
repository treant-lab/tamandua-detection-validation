from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from validate_ml_contracts import (  # noqa: E402
    ML_BENCHMARK_ACTIONABILITY_AUDIT_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_benchmark_actionability_audit,
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
    "standalone_detection_surface_covered": True,
    "agent_onnx_detection_surface_covered": True,
    "tamandua_detection_surface_covered": True,
    "benchmark_detection_surface_contract_ready": True,
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


def valid_audit() -> dict:
    return {
        "api_version": "tamandua.io/ml-benchmark-actionability-audit/v1",
        "kind": "MLBenchmarkActionabilityAudit",
        "metadata": {
            "report_id": "test_actionability_audit",
            "generated_at": "2026-06-06T00:00:00Z",
            "created_by": "tamandua-ml-benchmark-actionability-audit",
            "claim_boundary": (
                "No-execution actionability audit only. It verifies validation-only command exposure and "
                "does not run launchers, set env vars, execute guards, acquire data, train, infer, benchmark, or contact services."
            ),
        },
        "actionable": True,
        "source": {
            "benchmark_unblock_queue": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.json",
            "benchmark_unblock_queue_validation": "jsonschema+built-in",
            "benchmark_critical_path": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path.json",
            "benchmark_critical_path_validation": "jsonschema+built-in",
            "benchmark_critical_path_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path-handoff-bundle.json",
            "benchmark_critical_path_handoff_bundle_validation": "jsonschema+built-in",
            "benchmark_critical_path_handoff_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-critical-path-handoff-consistency.json",
            "benchmark_critical_path_handoff_consistency_validation": "jsonschema+built-in",
            "source_status_summary": GOAL_SNAPSHOT,
        },
        "summary": {
            "queue_items": 23,
            "queue_items_with_resolution_command": 23,
            "queue_items_without_resolution_command": 0,
            "critical_path_steps": 14,
            "critical_path_steps_with_resolution_command": 14,
            "critical_path_steps_without_resolution_command": 0,
            "handoff_files": 14,
            "handoff_files_with_resolution_command": 14,
            "validation_command_count": 14,
            "validation_commands_are_validation_only": True,
            "guarded_execute_commands_exposed": 13,
            "non_guarded_resolution_commands": 2,
            "env_validation_commands": 2,
            "env_validation_commands_redacted": True,
            "env_validation_commands_parse_cutoff": True,
            "evidence_usable_for_goal": 0,
            "actionability_gap_count": 0,
            "check_count": 2,
            "passed_checks": 2,
            "failed_checks": 0,
            "goal_complete": False,
            "completion_state": "partial_evidence",
            "goal_usable_required_evidence": 1,
            "goal_required_evidence_total": 16,
            "next_unproven_requirement_id": "wave1_governed_acquisition",
            "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
            "standalone_detection_surface_covered": True,
            "agent_onnx_detection_surface_covered": True,
            "tamandua_detection_surface_covered": True,
            "benchmark_detection_surface_contract_ready": True,
        },
        "checks": [
            {"name": "queue_all_items_have_resolution_command", "passed": True, "detail": "23/23 queue items expose commands"},
            {"name": "no_goal_evidence_claimed", "passed": True, "detail": "usable evidence across critical path and handoffs=0"},
        ],
    }


def write_json(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_validate_actionability_audit_accepts_contract(tmp_path: Path) -> None:
    mode = validate_contract(
        write_json(tmp_path, valid_audit()),
        ML_BENCHMARK_ACTIONABILITY_AUDIT_SCHEMA,
        validate_ml_benchmark_actionability_audit,
    )

    assert mode in {"jsonschema+built-in", "built-in"}


def test_validate_actionability_audit_requires_redacted_env_validator() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["summary"]["env_validation_commands_redacted"] = False

    with pytest.raises(ContractError, match="env_validation_commands_redacted"):
        validate_ml_benchmark_actionability_audit(payload, Path("memory://audit.json"))


def test_validate_actionability_audit_rejects_goal_evidence_claim() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["summary"]["evidence_usable_for_goal"] = 1

    with pytest.raises(ContractError, match="evidence_usable_for_goal"):
        validate_ml_benchmark_actionability_audit(payload, Path("memory://audit.json"))


def test_validate_actionability_audit_rejects_detection_surface_drift() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["summary"]["benchmark_detection_surface_contract_ready"] = False

    with pytest.raises(ContractError, match="benchmark_detection_surface_contract_ready"):
        validate_ml_benchmark_actionability_audit(payload, Path("memory://audit.json"))
