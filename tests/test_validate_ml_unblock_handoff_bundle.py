import hashlib
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    ML_UNBLOCK_HANDOFF_BUNDLE_SCHEMA,
    validate_contract,
    validate_ml_unblock_handoff_bundle,
)


def command_sha256(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def refresh_command_sha(payload: dict) -> None:
    for item in payload["handoff_files"]:
        item["validation_command_sha256"] = command_sha256(item["validation_command"])


def goal_full() -> dict:
    return {
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
        "missing_requirement_ids": ["wave1_governed_acquisition"],
        "evidence_status_summary": {"usable_required_evidence": 1},
        "next_unproven_requirement": {"id": "wave1_governed_acquisition"},
    }


def goal_summary() -> dict:
    snapshot = goal_full()
    return {
        "goal_complete": snapshot["goal_complete"],
        "completion_state": snapshot["completion_state"],
        "goal_snapshot_anchor_check_passed": snapshot["goal_snapshot_anchor_check_passed"],
        "goal_usable_required_evidence": snapshot["goal_usable_required_evidence"],
        "goal_required_evidence_total": snapshot["goal_required_evidence_total"],
        "next_unproven_requirement_id": snapshot["next_unproven_requirement_id"],
        "next_unproven_execute_guard_env": snapshot["next_unproven_execute_guard_env"],
    }


def valid_bundle() -> dict:
    validation_command = "if (-not (Test-Path 'docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json')) { throw 'missing' }"
    return {
        "api_version": "tamandua.io/ml-unblock-handoff-bundle/v1",
        "kind": "MLUnblockHandoffBundle",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-04T00:00:00+00:00",
            "created_by": "tamandua-ml-unblock-handoff-bundle",
            "claim_boundary": "No-execution ML unblock handoff bundle only. Does not execute launchers.",
        },
        "source": {
            "unblock_queue": "docs/benchmarks/runs/20260604T-ml-unblock-queue.json",
            "unblock_queue_validation": "jsonschema+built-in",
            "source_queue_summary": {
                "queue_items": 1,
                "queue_item_ids": ["ml-unblock-001"],
                "unblock_queue_validated": True,
                "source_queue_items": 1,
                "pending_items": 1,
                "resolved_items": 0,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "dependency": 0,
                "artifact": 1,
                "env": 0,
                "other": 0,
                "readiness_blocker_links": 0,
                "items_from_blocked_claims": 1,
                "items_without_command_exposure": 1,
                "items_with_resolution_command_exposure": 1,
                "items_without_resolution_command_exposure": 0,
                "handoff_files": 1,
                "readme_written": True,
                "priority_sequence_valid": True,
                **goal_full(),
            },
        },
        "output_dir": "docs/benchmarks/runs/20260604T-ml-unblock-queue.handoff",
        "readme": "docs/benchmarks/runs/20260604T-ml-unblock-queue.handoff/README.md",
        "summary": {
            "total_handoff_files": 1,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "dependency": 0,
            "artifact": 1,
            "env": 0,
            "other": 0,
            "items_from_blocked_claims": 1,
            "items_without_command_exposure": 1,
            "items_with_resolution_command_exposure": 1,
            "items_without_resolution_command_exposure": 0,
            **goal_summary(),
        },
        "handoff_files": [
            {
                "unblock_id": "ml-unblock-001",
                "claim_id": "ml-ml1_train_candidate_and_model_card",
                "package_id": "ml1_train_candidate_and_model_card",
                "wave": 2,
                "owner_role": "ml-training",
                "parallel_group": "model-quality",
                "category": "artifact",
                "target": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
                "priority": 1,
                "path": "docs/benchmarks/runs/20260604T-ml-unblock-queue.handoff/ml-unblock-001-artifact-dataset.md",
                "expected_evidence": "Required artifact docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json exists.",
                "validation_command": validation_command,
                "validation_command_sha256": command_sha256(validation_command),
                "readiness_evidence_paths": [],
            }
        ],
    }


def valid_dependency_bundle() -> dict:
    payload = valid_bundle()
    payload["summary"] = {
        "total_handoff_files": 1,
        "upstream_ready_validation_only": 1,
        "upstream_blocked": 5,
        "dependency": 1,
        "artifact": 0,
        "env": 0,
        "other": 0,
        "items_from_blocked_claims": 1,
        "items_without_command_exposure": 1,
        "items_with_resolution_command_exposure": 1,
        "items_without_resolution_command_exposure": 0,
        **goal_summary(),
    }
    payload["handoff_files"][0].update(
        {
            "category": "dependency",
            "target": "ml_data_governed_acquisition",
            "path": "docs/benchmarks/runs/20260604T-ml-unblock-queue.handoff/ml-unblock-001-dependency-ml-data-governed-acquisition.md",
            "expected_evidence": "Dependency package ml_data_governed_acquisition has evidence.",
            "validation_command": (
                "python apps\\tamandua_ml\\scripts\\ml_parallel_work_packages.py; "
                "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
                "python apps\\tamandua_ml\\scripts\\ml_unblock_queue.py; "
                "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
                "Write-Host 'Recheck dependency blocker'"
            ),
            "readiness_blockers": ["ml1_candidate:missing_canonical_dataset_manifest"],
            "readiness_evidence_paths": [
                "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
                "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
                "docs/benchmarks/runs/20260604T-ml-wave1-lab-run-intake.json",
                "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
                "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
                "docs/benchmarks/runs/20260604T-ml-wave1-acceptance-checklist.json",
                "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            ],
        }
    )
    refresh_command_sha(payload)
    return payload


def test_validate_ml_unblock_handoff_bundle_accepts_contract() -> None:
    validate_ml_unblock_handoff_bundle(valid_bundle(), Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-unblock-handoff-bundle.json"
    report_path.write_text(__import__("json").dumps(valid_bundle()), encoding="utf-8")

    mode = validate_contract(report_path, ML_UNBLOCK_HANDOFF_BUNDLE_SCHEMA, validate_ml_unblock_handoff_bundle)

    assert mode == "jsonschema+built-in"


def test_validate_ml_unblock_handoff_bundle_rejects_execute_command() -> None:
    payload = valid_bundle()
    payload["handoff_files"][0]["validation_command"] = ".\\launcher.ps1 -Execute"
    refresh_command_sha(payload)

    with pytest.raises(ContractError, match="validation-only"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_rejects_validation_command_hash_drift() -> None:
    payload = valid_bundle()
    payload["handoff_files"][0]["validation_command_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="validation_command_sha256"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_rejects_non_contiguous_priority() -> None:
    payload = valid_bundle()
    payload["handoff_files"][0]["priority"] = 2

    with pytest.raises(ContractError, match="contiguous"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_rejects_missing_source_queue_item() -> None:
    payload = valid_bundle()
    payload["source"]["source_queue_summary"] = {
        "queue_items": 2,
        "queue_item_ids": ["ml-unblock-001", "ml-unblock-002"],
        "unblock_queue_validated": True,
        "source_queue_items": 2,
        "pending_items": 2,
        "resolved_items": 0,
        "upstream_ready_validation_only": 1,
        "upstream_blocked": 5,
        "dependency": 0,
        "artifact": 1,
        "env": 0,
        "other": 0,
        "readiness_blocker_links": 0,
        "items_from_blocked_claims": 1,
        "items_without_command_exposure": 1,
        "items_with_resolution_command_exposure": 1,
        "items_without_resolution_command_exposure": 0,
        "handoff_files": 1,
        "readme_written": True,
        "priority_sequence_valid": True,
        **goal_full(),
    }

    with pytest.raises(ContractError, match="missing queue items: ml-unblock-002"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_accepts_dependency_fail_fast_command() -> None:
    payload = valid_dependency_bundle()
    payload["source"]["source_queue_summary"].update(
        {"dependency": 1, "artifact": 0, "readiness_blocker_links": 1}
    )
    validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_rejects_dependency_without_fail_fast() -> None:
    payload = valid_dependency_bundle()
    payload["source"]["source_queue_summary"].update(
        {"dependency": 1, "artifact": 0, "readiness_blocker_links": 1}
    )
    payload["handoff_files"][0]["validation_command"] = (
        "python apps\\tamandua_ml\\scripts\\ml_parallel_work_packages.py; "
        "python apps\\tamandua_ml\\scripts\\ml_unblock_queue.py"
    )
    refresh_command_sha(payload)

    with pytest.raises(ContractError, match="fail fast"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_rejects_missing_wave1_readiness_evidence() -> None:
    payload = valid_dependency_bundle()
    payload["source"]["source_queue_summary"].update(
        {"dependency": 1, "artifact": 0, "readiness_blocker_links": 1}
    )
    payload["handoff_files"][0]["readiness_evidence_paths"] = [
        "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json"
    ]

    with pytest.raises(ContractError, match="ML-1 Wave 1 blocker missing evidence"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_rejects_source_summary_drift() -> None:
    payload = valid_bundle()
    payload["source"]["source_queue_summary"]["handoff_files"] = 0

    with pytest.raises(ContractError, match="source_queue_summary.handoff_files"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_rejects_upstream_summary_drift() -> None:
    payload = valid_bundle()
    payload["source"]["source_queue_summary"]["upstream_ready_validation_only"] = 0

    with pytest.raises(ContractError, match="source_queue_summary.upstream_ready_validation_only"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))


def test_validate_ml_unblock_handoff_bundle_rejects_command_exposure_summary_drift() -> None:
    payload = valid_bundle()
    payload["summary"]["items_without_command_exposure"] = 0

    with pytest.raises(ContractError, match="source_queue_summary.items_without_command_exposure|summary.items_without_command_exposure"):
        validate_ml_unblock_handoff_bundle(payload, Path("memory://ml-unblock-handoff-bundle.json"))
