from __future__ import annotations

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

from validate_ml_contracts import ML_BENCHMARK_MODALITIES, validate_ml_benchmark_execution_matrix  # noqa: E402


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


def valid_matrix() -> dict:
    lanes = []
    evidence_names_by_lane = {
        "ML-0": ["artifact"],
        "ML-1": ["canonical_dataset_manifest", "candidate_ml1_report"],
        "ML-2": ["candidate_onnx", "candidate_ml2_report", "smoke_onnx_parity"],
        "ML-3": ["agent_parity_fixture", "candidate_ml3_report"],
        "ML-4": ["ml4_contract_dry_run", "candidate_ml4_report"],
        "ML-5": ["ml5_contract_dry_run", "candidate_ml5_report"],
        "ML-6": ["vx_inventory", "ml6_contract_dry_run", "candidate_ml6_report"],
    }
    for lane_id, scope in [
        ("ML-0", "pipeline_smoke"),
        ("ML-1", "isolated_model"),
        ("ML-2", "onnx_parity"),
        ("ML-3", "agent_local"),
        ("ML-4", "service_api"),
        ("ML-5", "platform_replay"),
        ("ML-6", "cross_time_holdout"),
    ]:
        blocked = lane_id != "ML-0"
        current_evidence = [
            {
                "name": name,
                "path": f"memory:{name}",
                "exists": not blocked,
                "evidence_status": "missing" if blocked else "smoke_artifact",
                "evidence_usable_for_goal": False,
                "claim": "claim",
            }
            for name in evidence_names_by_lane[lane_id]
        ]
        lanes.append(
            {
                "lane_id": lane_id,
                "title": lane_id,
                "scope": scope,
                "benchmark_modality": {
                    key: value
                    for key, value in ML_BENCHMARK_MODALITIES[lane_id].items()
                    if key != "scope"
                },
                "parallel_group": "group",
                "current_status": "blocked_dependency" if blocked else "evidence_exists",
                "evidence_status": "blocked_dependency" if blocked else "smoke_artifact",
                "evidence_usable_for_goal": False,
                "dependencies": [] if lane_id == "ML-0" else ["ML-1"],
                "required_evidence": ["evidence"],
                "current_evidence": current_evidence,
                "guarded_commands": {
                    "validation_command": None if lane_id == "ML-0" else "& 'launcher.ps1'",
                    "execute_command": None if lane_id == "ML-0" else "& 'launcher.ps1' -Execute",
                    "execute_guard_env": None if lane_id == "ML-0" else "TAMANDUA_ALLOW_ML_TRAINING",
                },
                "blockers": ["blocked"] if blocked else [],
                "promotion_gate": "gate",
                "claim_boundary": "No-execution benchmark lane boundary.",
            }
        )
    return {
        "api_version": "tamandua.io/ml-benchmark-execution-matrix/v1",
        "kind": "MLBenchmarkExecutionMatrix",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "test",
            "claim_boundary": "No-execution ML benchmark planning matrix only.",
        },
        "source": {
            "benchmark_plan": "docs/apps/tamandua_ml/ML_BENCHMARK_VALIDATION_PLAN.md",
            "benchmark_plan_validation": "exists",
            "platform_readiness_audit": "audit",
            "platform_readiness_audit_validation": "jsonschema+built-in",
            "parallel_work_packages": "packages",
            "parallel_work_packages_validation": "jsonschema+built-in",
            "execution_status": "status",
            "execution_status_validation": "jsonschema+built-in",
            "source_parallel_work_summary": {
                "parallel_claims": 3,
                "ready_validation_only_claims": 1,
                "blocked_claims": 1,
                "evidence_exists_claims": 1,
                "ready_validation_only_claim_ids": ["ml-ready"],
                "blocked_claim_ids": ["ml-blocked"],
                "evidence_exists_claim_ids": ["ml-evidence"],
            },
            "source_status_summary": {
                **goal_snapshot(),
                "benchmark_plan_present": True,
                "platform_readiness_audit_valid": True,
                "parallel_work_packages_valid": True,
                "execution_status_valid": True,
                "source_inputs_valid": 4,
                "source_input_count": 4,
                "total_lanes": 7,
                "blocked_lanes": 6,
                "evidence_exists_lanes": 1,
                "ready_validation_only_lanes": 0,
                "isolated_model_lanes": 3,
                "tamandua_integration_lanes": 3,
                "standalone_detection_lanes": 1,
                "agent_onnx_detection_lanes": 2,
                "tamandua_detection_lanes": 3,
                "standalone_detection_surface_covered": True,
                "agent_onnx_detection_surface_covered": True,
                "tamandua_detection_surface_covered": True,
                "benchmark_detection_surface_contract_ready": True,
                "lanes_with_validation_commands": 6,
                "lanes_with_execute_guards": 6,
                "lane_evidence_usable_for_goal": 0,
                "current_evidence_usable_for_goal": 0,
            },
        },
        "summary": {
            "total_lanes": 7,
            "evidence_exists": 1,
            "ready_validation_only": 0,
            "blocked": 6,
            "evidence_usable_for_goal": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 1,
            "isolated_model_lanes": 3,
            "tamandua_integration_lanes": 3,
            "standalone_detection_lanes": 1,
            "agent_onnx_detection_lanes": 2,
            "tamandua_detection_lanes": 3,
            "standalone_detection_surface_covered": True,
            "agent_onnx_detection_surface_covered": True,
            "tamandua_detection_surface_covered": True,
            "benchmark_detection_surface_contract_ready": True,
            "goal_complete": False,
            "completion_state": "partial_evidence",
            "goal_snapshot_anchor_check_passed": True,
            "goal_usable_required_evidence": 1,
            "goal_required_evidence_total": 16,
            "next_unproven_requirement_id": "wave1_governed_acquisition",
            "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        },
        "lanes": lanes,
        "recommended_batches": [
            {
                "batch_id": "ml-benchmark-evidence-review",
                "lane_ids": ["ML-0"],
                "mode": "evidence_review",
                "claim_boundary": "Review only.",
            },
            {
                "batch_id": "ml-benchmark-validation-ready",
                "lane_ids": [],
                "mode": "validation_only",
                "claim_boundary": "Validation only.",
            },
            {
                "batch_id": "ml-benchmark-blocked-followup",
                "lane_ids": ["ML-1", "ML-2", "ML-3", "ML-4", "ML-5", "ML-6"],
                "mode": "dependency_followup",
                "claim_boundary": "Follow up blockers.",
            },
        ],
    }


def test_validate_ml_benchmark_execution_matrix_accepts_valid_matrix(tmp_path: Path) -> None:
    validate_ml_benchmark_execution_matrix(valid_matrix(), Path("memory://matrix.json"))


def test_validate_ml_benchmark_execution_matrix_rejects_missing_lane(tmp_path: Path) -> None:
    data = valid_matrix()
    data["lanes"] = data["lanes"][:-1]
    data["summary"]["total_lanes"] = 6

    try:
        validate_ml_benchmark_execution_matrix(data, Path("memory://matrix.json"))
    except ValueError as exc:
        assert "missing lanes" in str(exc)
    else:
        raise AssertionError("expected validation failure")


def test_validate_ml_benchmark_execution_matrix_rejects_source_summary_drift(tmp_path: Path) -> None:
    data = valid_matrix()
    data["source"]["source_status_summary"]["blocked_lanes"] = 5

    try:
        validate_ml_benchmark_execution_matrix(data, Path("memory://matrix.json"))
    except ValueError as exc:
        assert "source_status_summary.blocked_lanes" in str(exc)
    else:
        raise AssertionError("expected validation failure")


def test_validate_ml_benchmark_execution_matrix_rejects_source_validation_mode_drift(tmp_path: Path) -> None:
    data = valid_matrix()
    data["source"]["execution_status_validation"] = "missing"

    try:
        validate_ml_benchmark_execution_matrix(data, Path("memory://matrix.json"))
    except ValueError as exc:
        assert "execution_status_valid" in str(exc)
    else:
        raise AssertionError("expected validation failure")


def test_validate_ml_benchmark_execution_matrix_rejects_upstream_summary_drift(tmp_path: Path) -> None:
    data = valid_matrix()
    data["summary"]["upstream_ready_validation_only"] = 0

    try:
        validate_ml_benchmark_execution_matrix(data, Path("memory://matrix.json"))
    except ValueError as exc:
        assert "upstream_ready_validation_only" in str(exc)
    else:
        raise AssertionError("expected validation failure")


def test_validate_ml_benchmark_execution_matrix_rejects_modality_drift(tmp_path: Path) -> None:
    data = valid_matrix()
    ml5_lane = next(lane for lane in data["lanes"] if lane["lane_id"] == "ML-5")
    ml5_lane["benchmark_modality"]["mode"] = "tamandua_service_detection"

    try:
        validate_ml_benchmark_execution_matrix(data, Path("memory://matrix.json"))
    except ValueError as exc:
        assert "benchmark_modality.mode" in str(exc)
    else:
        raise AssertionError("expected modality drift to fail")


def test_validate_ml_benchmark_execution_matrix_rejects_detection_surface_contract_drift(tmp_path: Path) -> None:
    data = valid_matrix()
    data["summary"]["tamandua_detection_surface_covered"] = False
    data["summary"]["benchmark_detection_surface_contract_ready"] = False

    try:
        validate_ml_benchmark_execution_matrix(data, Path("memory://matrix.json"))
    except ValueError as exc:
        assert "benchmark detection surface coverage" in str(exc) or "tamandua_detection_surface_covered" in str(exc)
    else:
        raise AssertionError("expected detection surface coverage drift to fail")


def test_validate_ml_benchmark_execution_matrix_rejects_smoke_as_goal_proof(tmp_path: Path) -> None:
    data = valid_matrix()
    data["lanes"][0]["evidence_usable_for_goal"] = True
    data["summary"]["evidence_usable_for_goal"] = 1
    data["source"]["source_status_summary"]["lane_evidence_usable_for_goal"] = 1

    try:
        validate_ml_benchmark_execution_matrix(data, Path("memory://matrix.json"))
    except ValueError as exc:
        assert "non-production lane evidence is not goal proof" in str(exc)
    else:
        raise AssertionError("expected smoke lane proof to fail")


def test_validate_ml_benchmark_execution_matrix_rejects_missing_ml2_report_evidence(tmp_path: Path) -> None:
    data = valid_matrix()
    ml2_lane = next(lane for lane in data["lanes"] if lane["lane_id"] == "ML-2")
    ml2_lane["current_evidence"] = [
        item for item in ml2_lane["current_evidence"] if item["name"] != "candidate_ml2_report"
    ]

    try:
        validate_ml_benchmark_execution_matrix(data, Path("memory://matrix.json"))
    except ValueError as exc:
        assert "candidate_ml2_report" in str(exc)
    else:
        raise AssertionError("expected missing ML-2 report evidence to fail")
