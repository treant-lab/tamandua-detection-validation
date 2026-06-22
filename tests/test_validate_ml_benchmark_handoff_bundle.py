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
    ML_BENCHMARK_HANDOFF_BUNDLE_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_benchmark_handoff_bundle,
)


VALIDATION_HASH = "1" * 64
EXECUTE_HASH = "2" * 64


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


def fingerprints_for(validation_present: bool, execute_guard_env: str | None) -> list[dict[str, str]]:
    fingerprints: list[dict[str, str]] = []
    if validation_present:
        fingerprints.append({"name": "validation_command", "command_sha256": VALIDATION_HASH})
    if execute_guard_env:
        fingerprints.append({"name": "execute_command", "command_sha256": EXECUTE_HASH})
    return fingerprints


def write_handoff_files(tmp_path: Path) -> tuple[Path, dict[str, Path]]:
    handoff_dir = tmp_path / "20260604T-ml-benchmark-execution-matrix.handoff"
    handoff_dir.mkdir()
    readme = handoff_dir / "README.md"
    readme.write_text("# ML Benchmark Handoff Bundle\n\nml-ml_data_governed_acquisition\n", encoding="utf-8")
    lane_files = {}
    for lane_id in ["ML-0", "ML-1", "ML-2", "ML-3", "ML-4", "ML-5", "ML-6"]:
        lane_file = handoff_dir / f"{lane_id.lower()}-lane.md"
        lane_file.write_text(
            f"# {lane_id}: Lane\n\n## Claim Boundary\n\nNo-execution.\n\n{VALIDATION_HASH}\n{EXECUTE_HASH}\n",
            encoding="utf-8",
        )
        lane_files[lane_id] = lane_file
    return readme, lane_files


def valid_bundle(tmp_path: Path) -> dict:
    readme, lane_files = write_handoff_files(tmp_path)
    snapshot = goal_snapshot()
    return {
        "api_version": "tamandua.io/ml-benchmark-handoff-bundle/v1",
        "kind": "MLBenchmarkHandoffBundle",
        "metadata": {
            "report_id": "test_benchmark_handoff",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "tamandua-ml-benchmark-handoff-bundle",
            "claim_boundary": "No-execution ML benchmark handoff bundle only.",
        },
        "source": {
            "benchmark_execution_matrix": "docs/benchmarks/runs/20260604T-ml-benchmark-execution-matrix.json",
            "benchmark_execution_matrix_validation": "jsonschema+built-in",
            "source_matrix_summary": {
                "lanes": 7,
                "lane_ids": ["ML-0", "ML-1", "ML-2", "ML-3", "ML-4", "ML-5", "ML-6"],
            },
            "source_parallel_work_summary": {
                "parallel_claims": 3,
                "ready_validation_only_claims": 1,
                "blocked_claims": 1,
                "evidence_exists_claims": 1,
                "ready_validation_only_claim_ids": ["ml-ml_data_governed_acquisition"],
                "blocked_claim_ids": ["ml-ml1_train_candidate_and_model_card"],
                "evidence_exists_claim_ids": ["ml-ml0_contracts_and_smoke_refresh"],
            },
            "source_status_summary": {
                "matrix_validated": True,
                "source_matrix_lanes": 7,
                "source_matrix_lane_ids": ["ML-0", "ML-1", "ML-2", "ML-3", "ML-4", "ML-5", "ML-6"],
                "readme_written": True,
                "lane_files_written": 7,
                "validation_command_lanes": 6,
                "execute_guard_lanes": 6,
                "evidence_exists": 1,
                "evidence_usable_for_goal": 0,
                "ready_validation_only": 0,
                "blocked": 6,
                **snapshot,
            },
        },
        "output_dir": str(readme.parent),
        "readme": str(readme),
        "lane_files": [
            {
                "lane_id": "ML-0",
                "scope": "pipeline_smoke",
                "current_status": "evidence_exists",
                "evidence_status": "smoke_artifact",
                "evidence_usable_for_goal": False,
                "path": str(lane_files["ML-0"]),
                "validation_command_present": False,
                "execute_guard_env": None,
                "guarded_command_fingerprints": fingerprints_for(False, None),
            },
            {
                "lane_id": "ML-1",
                "scope": "isolated_model",
                "current_status": "blocked_artifact",
                "evidence_status": "blocked_artifact",
                "evidence_usable_for_goal": False,
                "path": str(lane_files["ML-1"]),
                "validation_command_present": True,
                "execute_guard_env": "TAMANDUA_ALLOW_ML_TRAINING",
                "guarded_command_fingerprints": fingerprints_for(True, "TAMANDUA_ALLOW_ML_TRAINING"),
            },
            {
                "lane_id": "ML-2",
                "scope": "onnx_parity",
                "current_status": "blocked_artifact",
                "evidence_status": "blocked_artifact",
                "evidence_usable_for_goal": False,
                "path": str(lane_files["ML-2"]),
                "validation_command_present": True,
                "execute_guard_env": "TAMANDUA_ALLOW_ML_PARITY",
                "guarded_command_fingerprints": fingerprints_for(True, "TAMANDUA_ALLOW_ML_PARITY"),
            },
            {
                "lane_id": "ML-3",
                "scope": "agent_local",
                "current_status": "blocked_artifact",
                "evidence_status": "blocked_artifact",
                "evidence_usable_for_goal": False,
                "path": str(lane_files["ML-3"]),
                "validation_command_present": True,
                "execute_guard_env": "TAMANDUA_ALLOW_ML_PARITY",
                "guarded_command_fingerprints": fingerprints_for(True, "TAMANDUA_ALLOW_ML_PARITY"),
            },
            {
                "lane_id": "ML-4",
                "scope": "service_api",
                "current_status": "blocked_env",
                "evidence_status": "blocked_env",
                "evidence_usable_for_goal": False,
                "path": str(lane_files["ML-4"]),
                "validation_command_present": True,
                "execute_guard_env": "TAMANDUA_ALLOW_ML_SERVICE_BENCH",
                "guarded_command_fingerprints": fingerprints_for(True, "TAMANDUA_ALLOW_ML_SERVICE_BENCH"),
            },
            {
                "lane_id": "ML-5",
                "scope": "platform_replay",
                "current_status": "blocked_artifact",
                "evidence_status": "blocked_artifact",
                "evidence_usable_for_goal": False,
                "path": str(lane_files["ML-5"]),
                "validation_command_present": True,
                "execute_guard_env": "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY",
                "guarded_command_fingerprints": fingerprints_for(True, "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY"),
            },
            {
                "lane_id": "ML-6",
                "scope": "cross_time_holdout",
                "current_status": "blocked_env",
                "evidence_status": "blocked_env",
                "evidence_usable_for_goal": False,
                "path": str(lane_files["ML-6"]),
                "validation_command_present": True,
                "execute_guard_env": "TAMANDUA_ALLOW_ML_HOLDOUT",
                "guarded_command_fingerprints": fingerprints_for(True, "TAMANDUA_ALLOW_ML_HOLDOUT"),
            },
        ],
        "summary": {
            "total_lane_files": 7,
            "evidence_exists": 1,
            "evidence_usable_for_goal": 0,
            "ready_validation_only": 0,
            "blocked": 6,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 1,
            "goal_complete": snapshot["goal_complete"],
            "completion_state": snapshot["completion_state"],
            "goal_snapshot_anchor_check_passed": snapshot["goal_snapshot_anchor_check_passed"],
            "goal_usable_required_evidence": snapshot["goal_usable_required_evidence"],
            "goal_required_evidence_total": snapshot["goal_required_evidence_total"],
            "next_unproven_requirement_id": snapshot["next_unproven_requirement_id"],
            "next_unproven_execute_guard_env": snapshot["next_unproven_execute_guard_env"],
        },
    }


def test_validate_ml_benchmark_handoff_bundle_accepts_contract(tmp_path: Path) -> None:
    validate_ml_benchmark_handoff_bundle(valid_bundle(tmp_path), tmp_path / "bundle.json")


def test_validate_ml_benchmark_handoff_bundle_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "bundle.json"
    report_path.write_text(json.dumps(valid_bundle(tmp_path)), encoding="utf-8")

    mode = validate_contract(report_path, ML_BENCHMARK_HANDOFF_BUNDLE_SCHEMA, validate_ml_benchmark_handoff_bundle)

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_handoff_bundle_rejects_missing_lane_file(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["lane_files"][0]["path"] = str(tmp_path / "missing.md")

    try:
        validate_ml_benchmark_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "missing handoff file" in str(exc)
    else:
        raise AssertionError("expected missing handoff file to fail")


def test_validate_ml_benchmark_handoff_bundle_rejects_source_lane_mismatch(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["source"]["source_matrix_summary"] = {
        "lanes": 6,
        "lane_ids": ["ML-0", "ML-1", "ML-2", "ML-3", "ML-4", "ML-5"],
    }
    payload["source"]["source_status_summary"]["source_matrix_lanes"] = 6
    payload["source"]["source_status_summary"]["source_matrix_lane_ids"] = ["ML-0", "ML-1", "ML-2", "ML-3", "ML-4", "ML-5"]

    try:
        validate_ml_benchmark_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "stale lane files: ML-6" in str(exc)
    else:
        raise AssertionError("expected source lane mismatch to fail")


def test_validate_ml_benchmark_handoff_bundle_rejects_source_status_summary_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["source"]["source_status_summary"]["lane_files_written"] = 6

    try:
        validate_ml_benchmark_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "source_status_summary.lane_files_written" in str(exc)
    else:
        raise AssertionError("expected source status summary drift to fail")


def test_validate_ml_benchmark_handoff_bundle_rejects_source_validation_mode_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["source"]["benchmark_execution_matrix_validation"] = "failed"

    try:
        validate_ml_benchmark_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "matrix_validated" in str(exc)
    else:
        raise AssertionError("expected validation mode drift to fail")


def test_validate_ml_benchmark_handoff_bundle_rejects_upstream_summary_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["summary"]["upstream_ready_validation_only"] = 0

    try:
        validate_ml_benchmark_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "upstream_ready_validation_only" in str(exc)
    else:
        raise AssertionError("expected upstream summary drift to fail")


def test_validate_ml_benchmark_handoff_bundle_rejects_goal_summary_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["summary"]["goal_usable_required_evidence"] = 0

    try:
        validate_ml_benchmark_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "summary.goal_usable_required_evidence" in str(exc)
    else:
        raise AssertionError("expected goal summary drift to fail")
