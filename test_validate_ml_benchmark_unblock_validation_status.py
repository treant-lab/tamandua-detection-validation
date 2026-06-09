import json
from pathlib import Path

from validate_ml_contracts import (
    ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_SCHEMA,
    validate_contract,
    validate_ml_benchmark_unblock_validation_status,
)


NO_COMMAND_PLAN = {
    "kind": "artifact",
    "command_available": False,
    "validation_command": None,
    "execute_command": None,
    "execute_guard_env": None,
    "operator_note": "Produce the required artifact before rerunning the lane.",
}
WAVE1_PLAN = {
    "kind": "wave1_governed_acquisition",
    "command_available": True,
    "validation_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1",
    "execute_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1 -Execute",
    "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
    "operator_note": (
        "Run Wave 1 validation-only first; execute only in the isolated lab with the guard set. "
        "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD must remain unset because VX input is metadata-only; "
        "holdout_candidate is excluded from train/validation/test."
    ),
}
API_KEY_ENV_PLAN = {
    "kind": "ml4_api_key_env_validation",
    "command_available": True,
    "validation_command": (
        "powershell -NoProfile -Command "
        "\"$value=[Environment]::GetEnvironmentVariable('TAMANDUA_ML_API_KEY','Process'); "
        "if ([string]::IsNullOrWhiteSpace($value) -or $value -eq '<ml-service-api-key>' -or $value.StartsWith('<')) "
        "{ throw 'TAMANDUA_ML_API_KEY missing or placeholder' }; "
        "Write-Host 'TAMANDUA_ML_API_KEY present (value redacted)'\""
    ),
    "execute_command": None,
    "execute_guard_env": None,
    "operator_note": "Validate TAMANDUA_ML_API_KEY without writing or printing the secret.",
}
TRAINING_CUTOFF_ENV_PLAN = {
    "kind": "ml6_training_cutoff_env_validation",
    "command_available": True,
    "validation_command": (
        "powershell -NoProfile -Command "
        "\"$value=[Environment]::GetEnvironmentVariable('TAMANDUA_ML_TRAINING_CUTOFF','Process'); "
        "if ([string]::IsNullOrWhiteSpace($value) -or $value -eq '<candidate-training-cutoff-iso8601>' -or $value.StartsWith('<')) "
        "{ throw 'TAMANDUA_ML_TRAINING_CUTOFF missing or placeholder' }; "
        "try { [DateTimeOffset]::Parse($value) | Out-Null } catch { throw 'TAMANDUA_ML_TRAINING_CUTOFF must be ISO-8601' }; "
        "Write-Host 'TAMANDUA_ML_TRAINING_CUTOFF present and parseable'\""
    ),
    "execute_command": None,
    "execute_guard_env": None,
    "operator_note": "Validate TAMANDUA_ML_TRAINING_CUTOFF before ML-6 holdout.",
}

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


def add_resolution_contract(report: dict) -> dict:
    exposed = 0
    for item in report["items"]:
        if item["target"] in {"manifest_publish_receipt_incomplete", "missing_canonical_dataset_manifest"}:
            plan = dict(WAVE1_PLAN)
        elif item["target"] == "TAMANDUA_ML_API_KEY":
            plan = dict(API_KEY_ENV_PLAN)
        elif item["target"] == "TAMANDUA_ML_TRAINING_CUTOFF":
            plan = dict(TRAINING_CUTOFF_ENV_PLAN)
        else:
            plan = dict(NO_COMMAND_PLAN)
            plan["kind"] = item["category"]
        item.setdefault("resolution_plan", plan)
        if item["resolution_plan"]["command_available"] is True:
            exposed += 1
    missing = len(report["items"]) - exposed
    report["summary"]["items_with_resolution_command_exposure"] = exposed
    report["summary"]["items_without_resolution_command_exposure"] = missing
    report["summary"]["goal_complete"] = GOAL_SNAPSHOT["goal_complete"]
    report["summary"]["completion_state"] = GOAL_SNAPSHOT["completion_state"]
    report["summary"]["goal_usable_required_evidence"] = GOAL_SNAPSHOT["goal_usable_required_evidence"]
    report["summary"]["goal_required_evidence_total"] = GOAL_SNAPSHOT["goal_required_evidence_total"]
    report["summary"]["next_unproven_requirement_id"] = GOAL_SNAPSHOT["next_unproven_requirement_id"]
    report["summary"]["next_unproven_execute_guard_env"] = GOAL_SNAPSHOT["next_unproven_execute_guard_env"]
    report["source"]["source_status_summary"].update(GOAL_SNAPSHOT)
    report["source"]["source_status_summary"]["items_with_resolution_command_exposure"] = exposed
    report["source"]["source_status_summary"]["items_without_resolution_command_exposure"] = missing
    return report


def minimal_status_report() -> dict:
    return add_resolution_contract({
        "api_version": "tamandua.io/ml-benchmark-unblock-validation-status/v1",
        "kind": "MLBenchmarkUnblockValidationStatus",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark unblock validation status only.",
        },
        "source": {
            "benchmark_unblock_queue": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.json",
            "benchmark_unblock_queue_validation": "jsonschema+built-in",
            "benchmark_unblock_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-handoff-bundle.json",
            "benchmark_unblock_handoff_bundle_validation": "jsonschema+built-in",
            "benchmark_unblock_handoff_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-handoff-consistency.json",
            "benchmark_unblock_handoff_consistency_validation": "jsonschema+built-in",
            "source_status_summary": {
                "benchmark_unblock_queue_validation": "jsonschema+built-in",
                "benchmark_unblock_handoff_bundle_validation": "jsonschema+built-in",
                "benchmark_unblock_handoff_consistency_validation": "jsonschema+built-in",
                "queue_validated": True,
                "handoff_bundle_validated": True,
                "handoff_consistency_validated": True,
                "handoff_consistency_passed": True,
                "handoff_validation_commands_preserved": True,
                "source_queue_items": 1,
                "status_items": 1,
                "resolved_items": 0,
                "pending_items": 1,
                "pending_by_category": {"dependency": 0, "artifact": 0, "env": 1, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "dependency_pending": 0,
                "artifact_pending": 0,
                "env_pending": 1,
                "unknown_evidence_targets": 0,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "evidence_mapped_items": 0,
                "evidence_path_count": 0,
                "pending_item_ids": ["ml-benchmark-unblock-020"],
                "resolved_item_ids": [],
            },
        },
        "summary": {
            "total_items": 1,
            "resolved": 0,
            "pending": 1,
            "pending_by_category": {"dependency": 0, "artifact": 0, "env": 1, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "dependency_pending": 0,
            "artifact_pending": 0,
            "env_pending": 1,
            "unknown_evidence_targets": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
        },
        "items": [
            {
                "unblock_id": "ml-benchmark-unblock-020",
                "lane_id": "ML-4",
                "scope": "service_api",
                "parallel_group": "service",
                "category": "env",
                "target": "TAMANDUA_ML_API_KEY",
                "blocker": "missing_env:TAMANDUA_ML_API_KEY",
                "priority": 20,
                "primary_resolved": False,
                "evidence_paths": [],
                "resolved": False,
                "resolution_state": "pending",
                "detail": "env present=False: TAMANDUA_ML_API_KEY",
            }
        ],
        "next_pending_items": [],
    })


def test_validate_ml_benchmark_unblock_validation_status_accepts_jsonschema_path(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-unblock-validation-status/v1",
        "kind": "MLBenchmarkUnblockValidationStatus",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark unblock validation status only.",
        },
        "source": {
            "benchmark_unblock_queue": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.json",
            "benchmark_unblock_queue_validation": "jsonschema+built-in",
            "benchmark_unblock_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-handoff-bundle.json",
            "benchmark_unblock_handoff_bundle_validation": "jsonschema+built-in",
            "benchmark_unblock_handoff_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-handoff-consistency.json",
            "benchmark_unblock_handoff_consistency_validation": "jsonschema+built-in",
            "source_status_summary": {
                "benchmark_unblock_queue_validation": "jsonschema+built-in",
                "benchmark_unblock_handoff_bundle_validation": "jsonschema+built-in",
                "benchmark_unblock_handoff_consistency_validation": "jsonschema+built-in",
                "queue_validated": True,
                "handoff_bundle_validated": True,
                "handoff_consistency_validated": True,
                "handoff_consistency_passed": True,
                "handoff_validation_commands_preserved": True,
                "source_queue_items": 1,
                "status_items": 1,
                "resolved_items": 0,
                "pending_items": 1,
                "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "dependency_pending": 0,
                "artifact_pending": 1,
                "env_pending": 0,
                "unknown_evidence_targets": 0,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "evidence_mapped_items": 1,
                "evidence_path_count": 7,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "resolved_item_ids": [],
            },
        },
        "summary": {
            "total_items": 1,
            "resolved": 0,
            "pending": 1,
            "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "dependency_pending": 0,
            "artifact_pending": 1,
            "env_pending": 0,
            "unknown_evidence_targets": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
        },
        "items": [
            {
                "unblock_id": "ml-benchmark-unblock-001",
                "lane_id": "ML-1",
                "scope": "isolated_model",
                "parallel_group": "model-quality",
                "category": "artifact",
                "target": "missing_canonical_dataset_manifest",
                "blocker": "missing_canonical_dataset_manifest",
                "priority": 1,
                "primary_resolved": False,
                "evidence_paths": [
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-lab-run-intake.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
                    "docs/benchmarks/runs/20260604T-ml-wave1-acceptance-checklist.json",
                    "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
                ],
                "resolved": False,
                "resolution_state": "pending",
                "detail": "evidence paths present=0/1: docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            }
        ],
        "next_pending_items": [],
    }
    path = tmp_path / "status.json"
    path.write_text(json.dumps(add_resolution_contract(report)), encoding="utf-8")

    mode = validate_contract(path, ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_ml_benchmark_unblock_validation_status)

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_unblock_validation_status_rejects_short_wave1_chain(tmp_path: Path) -> None:
    report = {
        "api_version": "tamandua.io/ml-benchmark-unblock-validation-status/v1",
        "kind": "MLBenchmarkUnblockValidationStatus",
        "metadata": {
            "report_id": "unit",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "unit",
            "claim_boundary": "No-execution ML benchmark unblock validation status only.",
        },
        "source": {
            "benchmark_unblock_queue": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.json",
            "benchmark_unblock_queue_validation": "jsonschema+built-in",
            "benchmark_unblock_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-handoff-bundle.json",
            "benchmark_unblock_handoff_bundle_validation": "jsonschema+built-in",
            "benchmark_unblock_handoff_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-handoff-consistency.json",
            "benchmark_unblock_handoff_consistency_validation": "jsonschema+built-in",
            "source_status_summary": {
                "benchmark_unblock_queue_validation": "jsonschema+built-in",
                "benchmark_unblock_handoff_bundle_validation": "jsonschema+built-in",
                "benchmark_unblock_handoff_consistency_validation": "jsonschema+built-in",
                "queue_validated": True,
                "handoff_bundle_validated": True,
                "handoff_consistency_validated": True,
                "handoff_consistency_passed": True,
                "handoff_validation_commands_preserved": True,
                "source_queue_items": 1,
                "status_items": 1,
                "resolved_items": 0,
                "pending_items": 1,
                "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
                "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "dependency_pending": 0,
                "artifact_pending": 1,
                "env_pending": 0,
                "unknown_evidence_targets": 0,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "evidence_mapped_items": 1,
                "evidence_path_count": 1,
                "pending_item_ids": ["ml-benchmark-unblock-001"],
                "resolved_item_ids": [],
            },
        },
        "summary": {
            "total_items": 1,
            "resolved": 0,
            "pending": 1,
            "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "dependency_pending": 0,
            "artifact_pending": 1,
            "env_pending": 0,
            "unknown_evidence_targets": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
        },
        "items": [
            {
                "unblock_id": "ml-benchmark-unblock-001",
                "lane_id": "ML-1",
                "scope": "isolated_model",
                "parallel_group": "model-quality",
                "category": "artifact",
                "target": "missing_canonical_dataset_manifest",
                "blocker": "missing_canonical_dataset_manifest",
                "priority": 1,
                "primary_resolved": False,
                "evidence_paths": ["docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json"],
                "resolved": False,
                "resolution_state": "pending",
                "detail": "evidence paths present=0/1: docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            }
        ],
        "next_pending_items": [],
    }
    path = tmp_path / "status.json"
    path.write_text(json.dumps(add_resolution_contract(report)), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_ml_benchmark_unblock_validation_status)
    except Exception as exc:
        assert "canonical manifest blocker missing Wave 1 evidence" in str(exc)
    else:
        raise AssertionError("expected missing Wave 1 evidence to fail")


def test_validate_ml_benchmark_unblock_validation_status_rejects_source_summary_count_drift(tmp_path: Path) -> None:
    report = minimal_status_report()
    report["source"]["source_status_summary"]["pending_items"] = 2
    path = tmp_path / "status.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_ml_benchmark_unblock_validation_status)
    except Exception as exc:
        assert "source.source_status_summary.pending_items" in str(exc)
    else:
        raise AssertionError("expected source summary count drift to fail")


def test_validate_ml_benchmark_unblock_validation_status_rejects_source_summary_validation_drift(tmp_path: Path) -> None:
    report = minimal_status_report()
    report["source"]["source_status_summary"]["queue_validated"] = False
    path = tmp_path / "status.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_ml_benchmark_unblock_validation_status)
    except Exception as exc:
        assert "source.source_status_summary.queue_validated" in str(exc)
    else:
        raise AssertionError("expected source summary validation drift to fail")


def test_validate_ml_benchmark_unblock_validation_status_rejects_missing_validation_command_proof(tmp_path: Path) -> None:
    report = minimal_status_report()
    report["source"]["source_status_summary"]["handoff_validation_commands_preserved"] = False
    path = tmp_path / "status.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_ml_benchmark_unblock_validation_status)
    except Exception as exc:
        assert "handoff_validation_commands_preserved" in str(exc)
    else:
        raise AssertionError("expected missing validation command proof to fail")


def test_validate_ml_benchmark_unblock_validation_status_rejects_category_rollup_drift(tmp_path: Path) -> None:
    report = minimal_status_report()
    report["summary"]["pending_by_category"]["artifact"] = 1
    report["summary"]["pending_by_category"]["env"] = 0
    path = tmp_path / "status.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_ml_benchmark_unblock_validation_status)
    except Exception as exc:
        assert "summary.pending_by_category" in str(exc)
    else:
        raise AssertionError("expected category rollup drift to fail")


def test_validate_ml_benchmark_unblock_validation_status_rejects_upstream_summary_drift(tmp_path: Path) -> None:
    report = minimal_status_report()
    report["summary"]["upstream_ready_validation_only"] = 0
    path = tmp_path / "status.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    try:
        validate_contract(path, ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_SCHEMA, validate_ml_benchmark_unblock_validation_status)
    except Exception as exc:
        assert "summary.upstream_ready_validation_only" in str(exc)
    else:
        raise AssertionError("expected upstream summary drift to fail")
