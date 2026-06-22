from __future__ import annotations

import copy
import hashlib
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
    ML_BENCHMARK_UNBLOCK_HANDOFF_BUNDLE_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_benchmark_unblock_handoff_bundle,
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def goal_snapshot() -> dict:
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
        "evidence_status_summary": {
            "total_required_evidence": 16,
            "present_required_evidence": 4,
            "usable_required_evidence": 1,
            "missing_required_evidence": 12,
            "unusable_present_required_evidence": 3,
            "by_status": {"usable": 1, "blocked_artifact": 3, "missing": 12},
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


def valid_bundle() -> dict:
    snapshot = goal_snapshot()
    validation_command = (
        "python apps\\tamandua_ml\\scripts\\ml_benchmark_execution_matrix.py; "
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
        "python apps\\tamandua_ml\\scripts\\ml_benchmark_handoff_bundle.py; "
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
        "python apps\\tamandua_ml\\scripts\\ml_benchmark_handoff_consistency.py; "
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
        "Write-Host 'Recheck benchmark blocker'"
    )
    return {
        "api_version": "tamandua.io/ml-benchmark-unblock-handoff-bundle/v1",
        "kind": "MLBenchmarkUnblockHandoffBundle",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "tamandua-ml-benchmark-unblock-handoff-bundle",
            "claim_boundary": "No-execution ML benchmark unblock handoff bundle only.",
        },
        "source": {
            "benchmark_unblock_queue": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.json",
            "benchmark_unblock_queue_validation": "jsonschema+built-in",
            "source_queue_summary": {
                "queue_items": 1,
                "queue_item_ids": ["ml-benchmark-unblock-001"],
            },
            "source_status_summary": {
                "benchmark_unblock_queue_validated": True,
                "source_queue_items": 1,
                "source_queue_item_ids": ["ml-benchmark-unblock-001"],
                "readme_written": True,
                "handoff_files_written": 1,
                "dependency": 0,
                "artifact": 1,
                "env": 0,
                "other": 0,
                "validation_command_count": 1,
                "validation_only_commands": 1,
                "wave1_evidence_items": 1,
                "upstream_ready_validation_only": 1,
                "upstream_blocked": 5,
                "items_with_resolution_command_exposure": 1,
                "items_without_resolution_command_exposure": 0,
                **snapshot,
            },
        },
        "output_dir": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.handoff",
        "readme": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.handoff/README.md",
        "summary": {
            "total_handoff_files": 1,
            "dependency": 0,
            "artifact": 1,
            "env": 0,
            "other": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "validation_command_count": 1,
            "validation_only_commands": 1,
            "items_with_resolution_command_exposure": 1,
            "items_without_resolution_command_exposure": 0,
            "goal_complete": snapshot["goal_complete"],
            "completion_state": snapshot["completion_state"],
            "goal_snapshot_anchor_check_passed": snapshot["goal_snapshot_anchor_check_passed"],
            "goal_usable_required_evidence": snapshot["goal_usable_required_evidence"],
            "goal_required_evidence_total": snapshot["goal_required_evidence_total"],
            "next_unproven_requirement_id": snapshot["next_unproven_requirement_id"],
            "next_unproven_execute_guard_env": snapshot["next_unproven_execute_guard_env"],
        },
        "handoff_files": [
            {
                "unblock_id": "ml-benchmark-unblock-001",
                "lane_id": "ML-1",
                "scope": "isolated_model",
                "parallel_group": "model-quality",
                "category": "artifact",
                "target": "missing_canonical_dataset_manifest",
                "priority": 1,
                "path": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.handoff/ml-benchmark-unblock-001-ml-1-artifact-missing-canonical-dataset-manifest.md",
                "expected_evidence": "Benchmark evidence exists.",
                "validation_command": validation_command,
                "validation_command_sha256": sha256_text(validation_command),
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
        ],
    }


def test_validate_ml_benchmark_unblock_handoff_bundle_accepts_contract() -> None:
    validate_ml_benchmark_unblock_handoff_bundle(valid_bundle(), Path("memory://bundle.json"))


def test_validate_ml_benchmark_unblock_handoff_bundle_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "bundle.json"
    report_path.write_text(json.dumps(valid_bundle()), encoding="utf-8")

    mode = validate_contract(report_path, ML_BENCHMARK_UNBLOCK_HANDOFF_BUNDLE_SCHEMA, validate_ml_benchmark_unblock_handoff_bundle)

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_execute_command() -> None:
    payload = copy.deepcopy(valid_bundle())
    payload["handoff_files"][0]["validation_command"] = ".\\launcher.ps1 -Execute"
    payload["handoff_files"][0]["validation_command_sha256"] = sha256_text(".\\launcher.ps1 -Execute")

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "validation-only" in str(exc)
    else:
        raise AssertionError("expected execute command to fail")


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_non_fail_fast_refresh() -> None:
    payload = copy.deepcopy(valid_bundle())
    command = (
        "python apps\\tamandua_ml\\scripts\\ml_benchmark_execution_matrix.py; "
        "python apps\\tamandua_ml\\scripts\\ml_benchmark_handoff_bundle.py; "
        "python apps\\tamandua_ml\\scripts\\ml_benchmark_handoff_consistency.py"
    )
    payload["handoff_files"][0]["validation_command"] = command
    payload["handoff_files"][0]["validation_command_sha256"] = sha256_text(command)

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "fail fast" in str(exc)
    else:
        raise AssertionError("expected non-fail-fast command to fail")


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_missing_source_queue_item() -> None:
    payload = copy.deepcopy(valid_bundle())
    payload["source"]["source_queue_summary"] = {
        "queue_items": 2,
        "queue_item_ids": ["ml-benchmark-unblock-001", "ml-benchmark-unblock-002"],
    }
    payload["source"]["source_status_summary"]["source_queue_items"] = 2
    payload["source"]["source_status_summary"]["source_queue_item_ids"] = [
        "ml-benchmark-unblock-001",
        "ml-benchmark-unblock-002",
    ]

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "missing queue items: ml-benchmark-unblock-002" in str(exc)
    else:
        raise AssertionError("expected missing source queue item to fail")


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_source_status_summary_drift() -> None:
    payload = copy.deepcopy(valid_bundle())
    payload["source"]["source_status_summary"]["handoff_files_written"] = 2

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "source_status_summary.handoff_files_written" in str(exc)
    else:
        raise AssertionError("expected source status summary drift to fail")


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_source_validation_mode_drift() -> None:
    payload = copy.deepcopy(valid_bundle())
    payload["source"]["source_status_summary"]["benchmark_unblock_queue_validated"] = False

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "benchmark_unblock_queue_validated" in str(exc)
    else:
        raise AssertionError("expected source validation mode drift to fail")


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_missing_wave1_evidence() -> None:
    payload = copy.deepcopy(valid_bundle())
    payload["handoff_files"][0]["readiness_evidence_paths"] = [
        "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json"
    ]

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "benchmark Wave 1 blocker missing evidence" in str(exc)
    else:
        raise AssertionError("expected missing Wave 1 evidence to fail")


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_upstream_summary_drift() -> None:
    payload = copy.deepcopy(valid_bundle())
    payload["source"]["source_status_summary"]["upstream_ready_validation_only"] = 0

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "upstream_ready_validation_only" in str(exc)
    else:
        raise AssertionError("expected upstream summary drift to fail")


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_validation_command_summary_drift() -> None:
    payload = copy.deepcopy(valid_bundle())
    payload["summary"]["validation_only_commands"] = 0

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "validation_only_commands" in str(exc)
    else:
        raise AssertionError("expected validation command summary drift to fail")


def test_validate_ml_benchmark_unblock_handoff_bundle_rejects_command_hash_drift() -> None:
    payload = copy.deepcopy(valid_bundle())
    payload["handoff_files"][0]["validation_command_sha256"] = "0" * 64

    try:
        validate_ml_benchmark_unblock_handoff_bundle(payload, Path("memory://bundle.json"))
    except ContractError as exc:
        assert "validation_command_sha256" in str(exc)
    else:
        raise AssertionError("expected validation command hash drift to fail")
