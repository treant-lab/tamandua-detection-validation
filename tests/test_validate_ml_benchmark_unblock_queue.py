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
    ML_BENCHMARK_UNBLOCK_QUEUE_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_benchmark_unblock_queue,
)


def goal_snapshot() -> dict:
    fallback = {
        "goal_complete": False,
        "completion_state": "partial_evidence",
        "goal_snapshot_anchor_check_passed": True,
        "goal_missing_requirements": 9,
        "goal_required_evidence_total": 16,
        "goal_present_required_evidence": 4,
        "goal_usable_required_evidence": 1,
        "goal_missing_required_evidence": 12,
        "goal_unusable_present_required_evidence": 3,
        "next_unproven_requirement_id": "wave1_governed_acquisition",
        "next_unproven_requirement_phase": "01-wave1-manifest-publication",
        "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        "missing_requirement_ids": [
            "wave1_governed_acquisition",
            "wave1_sanitized_manifest",
            "ml1_model_quality",
            "ml1_model_contract_and_card",
            "ml2_pytorch_onnx_parity",
            "ml3_agent_onnx_parity",
            "ml4_service_benchmark",
            "ml5_tamandua_replay",
            "ml6_cross_time_holdout",
        ],
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
            "pending_targets": ["manifest_publish_receipt_incomplete", "missing_canonical_dataset_manifest"],
            "required_evidence": [
                "D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-real-acquisition-transcript.json",
                "D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-acquisition-receipt.json",
            ],
            "missing_or_unusable_evidence": [
                "D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-real-acquisition-transcript.json",
                "D:\\treant\\tamandua\\docs\\benchmarks\\runs\\20260604T-ml-wave1-acquisition-receipt.json",
            ],
        },
    }
    matrix = RUNS_DIR / "20260604T-ml-benchmark-execution-matrix.json"
    if not matrix.exists():
        return fallback
    payload = json.loads(matrix.read_text(encoding="utf-8"))
    summary = payload.get("source", {}).get("source_status_summary", {})
    if not isinstance(summary, dict):
        return fallback
    for key in fallback:
        if key in summary:
            fallback[key] = summary[key]
    return fallback


def valid_queue() -> dict:
    return {
        "api_version": "tamandua.io/ml-benchmark-unblock-queue/v1",
        "kind": "MLBenchmarkUnblockQueue",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "tamandua-ml-benchmark-unblock-queue",
            "claim_boundary": "No-execution ML benchmark unblock queue only.",
        },
        "source": {
            "benchmark_execution_matrix": "docs/benchmarks/runs/20260604T-ml-benchmark-execution-matrix.json",
            "benchmark_execution_matrix_validation": "jsonschema+built-in",
            "benchmark_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-handoff-bundle.json",
            "benchmark_handoff_bundle_validation": "jsonschema+built-in",
            "benchmark_handoff_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-handoff-consistency.json",
            "benchmark_handoff_consistency_validation": "jsonschema+built-in",
            "ml_platform_readiness_audit": "docs/benchmarks/runs/20260604T-ml-platform-readiness-audit.json",
            "ml_platform_readiness_audit_validation": "jsonschema+built-in",
            "source_status_summary": {
                **goal_snapshot(),
                "benchmark_execution_matrix_validated": True,
                "benchmark_handoff_bundle_validated": True,
                "benchmark_handoff_consistency_validated": True,
                "platform_readiness_audit_validated": True,
                "handoff_consistency_passed": True,
                "source_lane_count": 7,
                "blocked_lane_count": 1,
                "blocked_lane_ids": ["ML-1"],
                "pending_items": 2,
                "dependency_items": 1,
                "artifact_items": 1,
                "env_items": 0,
                "other_items": 0,
                "unique_handoff_refs": 1,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "priority_sequence_valid": True,
                "items_with_resolution_command_exposure": 2,
                "items_without_resolution_command_exposure": 0,
            },
        },
        "summary": {
            "total_items": 2,
            "dependency": 1,
            "artifact": 1,
            "env": 0,
            "other": 0,
            "blocked_lanes": 1,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "items_with_resolution_command_exposure": 2,
            "items_without_resolution_command_exposure": 0,
            "goal_complete": False,
            "completion_state": "partial_evidence",
            "goal_snapshot_anchor_check_passed": True,
            "goal_usable_required_evidence": 1,
            "goal_required_evidence_total": 16,
            "next_unproven_requirement_id": "wave1_governed_acquisition",
            "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        },
        "items": [
            {
                "unblock_id": "ml-benchmark-unblock-001",
                "priority": 1,
                "lane_id": "ML-1",
                "scope": "isolated_model",
                "parallel_group": "model-quality",
                "category": "dependency",
                "target": "manifest_publish_receipt_incomplete",
                "blocker": "manifest_publish_receipt_incomplete",
                "handoff_ref": "docs/benchmarks/runs/20260604T-ml-benchmark-execution-matrix.handoff/ml-1-isolated-model-quality.md",
                "description": "Clear blocker.",
                "resolution_state": "pending",
                "resolution_plan": {
                    "kind": "wave1_governed_acquisition",
                    "command_available": True,
                    "validation_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1",
                    "execute_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1 -Execute",
                    "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
                    "operator_note": (
                        "Run Wave 1 validation-only first. Keep TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD unset; "
                        "VX/InTheWild remains metadata-only holdout_candidate context and must not enter "
                        "train/validation/test splits."
                    ),
                },
            },
            {
                "unblock_id": "ml-benchmark-unblock-002",
                "priority": 2,
                "lane_id": "ML-1",
                "scope": "isolated_model",
                "parallel_group": "model-quality",
                "category": "artifact",
                "target": "missing_canonical_dataset_manifest",
                "blocker": "missing_canonical_dataset_manifest",
                "handoff_ref": "docs/benchmarks/runs/20260604T-ml-benchmark-execution-matrix.handoff/ml-1-isolated-model-quality.md",
                "description": "Produce artifact.",
                "resolution_state": "pending",
                "resolution_plan": {
                    "kind": "wave1_governed_acquisition",
                    "command_available": True,
                    "validation_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1",
                    "execute_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1 -Execute",
                    "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
                    "operator_note": (
                        "Run Wave 1 validation-only first. Keep TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD unset; "
                        "VX/InTheWild remains metadata-only holdout_candidate context and must not enter "
                        "train/validation/test splits."
                    ),
                },
            },
        ],
    }


def test_validate_ml_benchmark_unblock_queue_accepts_contract() -> None:
    validate_ml_benchmark_unblock_queue(valid_queue(), Path("memory://queue.json"))


def test_validate_ml_benchmark_unblock_queue_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "queue.json"
    report_path.write_text(json.dumps(valid_queue()), encoding="utf-8")

    mode = validate_contract(report_path, ML_BENCHMARK_UNBLOCK_QUEUE_SCHEMA, validate_ml_benchmark_unblock_queue)

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_unblock_queue_rejects_bad_summary(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_queue())
    payload["summary"]["total_items"] = 3

    try:
        validate_ml_benchmark_unblock_queue(payload, tmp_path / "queue.json")
    except ContractError as exc:
        assert "total_items" in str(exc)
    else:
        raise AssertionError("expected invalid summary to fail")


def test_validate_ml_benchmark_unblock_queue_rejects_source_summary_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_queue())
    payload["source"]["source_status_summary"]["pending_items"] = 3

    try:
        validate_ml_benchmark_unblock_queue(payload, tmp_path / "queue.json")
    except ContractError as exc:
        assert "source_status_summary.pending_items" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_ml_benchmark_unblock_queue_rejects_source_validation_mode_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_queue())
    payload["source"]["benchmark_handoff_bundle_validation"] = "built-in"
    payload["source"]["source_status_summary"]["benchmark_handoff_bundle_validated"] = False

    try:
        validate_ml_benchmark_unblock_queue(payload, tmp_path / "queue.json")
    except ContractError as exc:
        assert "benchmark_handoff_bundle_validated" in str(exc)
    else:
        raise AssertionError("expected source validation mode drift to fail")


def test_validate_ml_benchmark_unblock_queue_rejects_wave1_vx_guard_note_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_queue())
    payload["items"][0]["resolution_plan"]["operator_note"] = "Run Wave 1 validation-only first."

    try:
        validate_ml_benchmark_unblock_queue(payload, tmp_path / "queue.json")
    except ContractError as exc:
        assert "operator_note" in str(exc)
    else:
        raise AssertionError("expected missing VX guard note to fail")


def test_validate_ml_benchmark_unblock_queue_rejects_upstream_summary_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_queue())
    payload["source"]["source_status_summary"]["upstream_ready_validation_only"] = 0

    try:
        validate_ml_benchmark_unblock_queue(payload, tmp_path / "queue.json")
    except ContractError as exc:
        assert "upstream_ready_validation_only" in str(exc)
    else:
        raise AssertionError("expected upstream summary drift to fail")


def test_validate_ml_benchmark_unblock_queue_rejects_bad_resolution_command_count(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_queue())
    payload["summary"]["items_with_resolution_command_exposure"] = 1

    try:
        validate_ml_benchmark_unblock_queue(payload, tmp_path / "queue.json")
    except ContractError as exc:
        assert "items_with_resolution_command_exposure" in str(exc)
    else:
        raise AssertionError("expected resolution command count drift to fail")


def test_validate_ml_benchmark_unblock_queue_rejects_guarded_validation_command(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_queue())
    payload["items"][0]["resolution_plan"]["validation_command"] += " -Execute"

    try:
        validate_ml_benchmark_unblock_queue(payload, tmp_path / "queue.json")
    except ContractError as exc:
        assert "validation_command" in str(exc)
    else:
        raise AssertionError("expected guarded validation command to fail")


def test_validate_ml_benchmark_unblock_queue_rejects_wrong_wave2_guard(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_queue())
    item = payload["items"][1]
    item["target"] = "missing_ml1_benchmark_report"
    item["blocker"] = "missing_ml1_benchmark_report"
    item["resolution_plan"] = {
        "kind": "wave2_ml1_candidate",
        "command_available": True,
        "validation_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_2_ml1_candidate_launcher.ps1",
        "execute_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_2_ml1_candidate_launcher.ps1 -Execute",
        "execute_guard_env": "TAMANDUA_ALLOW_ML_PARITY",
        "operator_note": "Run validation first.",
    }

    try:
        validate_ml_benchmark_unblock_queue(payload, tmp_path / "queue.json")
    except ContractError as exc:
        assert "TAMANDUA_ALLOW_ML_TRAINING" in str(exc)
    else:
        raise AssertionError("expected wrong Wave 2 guard to fail")
