from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    ML_PARALLEL_HANDOFF_BUNDLE_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_parallel_handoff_bundle,
)


def fingerprints(commands: list[str]) -> list[dict[str, object]]:
    return [
        {"index": index, "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest()}
        for index, command in enumerate(commands)
    ]


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


def write_handoff_files(tmp_path: Path) -> tuple[Path, Path]:
    handoff_dir = tmp_path / "20260604T-ml-parallel-work-packages.handoff"
    handoff_dir.mkdir()
    readme = handoff_dir / "README.md"
    readme.write_text("# ML Parallel Handoff Bundle\n", encoding="utf-8")
    claim_file = handoff_dir / "ml-ml-data-governed-acquisition.md"
    claim_file.write_text(
        "# ml-ml_data_governed_acquisition\n\n## Claim Boundary\n\nNo-execution.\n\n"
        f"SHA-256: `{fingerprints(['validate'])[0]['command_sha256']}`\n",
        encoding="utf-8",
    )
    return readme, claim_file


def valid_bundle(tmp_path: Path) -> dict:
    readme, claim_file = write_handoff_files(tmp_path)
    snapshot = goal_snapshot()
    return {
        "api_version": "tamandua.io/ml-parallel-handoff-bundle/v1",
        "kind": "MLParallelHandoffBundle",
        "metadata": {
            "report_id": "test_handoff_bundle",
            "generated_at": "2026-06-04T23:55:00Z",
            "created_by": "tamandua-ml-parallel-handoff-bundle",
            "claim_boundary": "No-execution ML parallel handoff bundle only. Markdown files are coordination aids and do not execute launchers.",
        },
        "source": {
            "parallel_work_packages": "docs/benchmarks/runs/20260604T-ml-parallel-work-packages.json",
            "parallel_work_packages_validation": "jsonschema+built-in",
            "source_work_packages_summary": {
                "claims": 1,
                "claim_ids": ["ml-ml_data_governed_acquisition"],
                "parallel_work_packages_validated": True,
                "source_claim_count": 1,
                "ready_validation_only": 1,
                "blocked": 0,
                "blocked_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
                "evidence_exists": 0,
                "evidence_usable_for_goal": 0,
                "validation_only_batch_claims": 1,
                "blocked_followup_batch_claims": 0,
                "claims_with_validation_command": 1,
                "claims_with_execute_guard": 1,
                "by_status": {"ready_validation_only": 1},
                **snapshot,
            },
        },
        "output_dir": str(readme.parent),
        "readme": str(readme),
        "claim_files": [
            {
                "claim_id": "ml-ml_data_governed_acquisition",
                "package_id": "ml_data_governed_acquisition",
                "claim_status": "ready_validation_only",
                "evidence_status": "validation_only_not_evidence",
                "evidence_usable_for_goal": False,
                "block_category": None,
                "path": str(claim_file),
                "validation_command_present": True,
                "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
                "safe_command_fingerprints": fingerprints(["validate"]),
            }
        ],
        "summary": {
            "total_claim_files": 1,
            "ready_validation_only": 1,
            "blocked": 0,
            "blocked_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            "evidence_exists": 0,
            "evidence_usable_for_goal": 0,
            "goal_complete": snapshot["goal_complete"],
            "completion_state": snapshot["completion_state"],
            "goal_snapshot_anchor_check_passed": snapshot["goal_snapshot_anchor_check_passed"],
            "goal_usable_required_evidence": snapshot["goal_usable_required_evidence"],
            "goal_required_evidence_total": snapshot["goal_required_evidence_total"],
            "next_unproven_requirement_id": snapshot["next_unproven_requirement_id"],
            "next_unproven_execute_guard_env": snapshot["next_unproven_execute_guard_env"],
        },
    }


def test_validate_ml_parallel_handoff_bundle_accepts_contract(tmp_path: Path) -> None:
    validate_ml_parallel_handoff_bundle(valid_bundle(tmp_path), tmp_path / "bundle.json")


def test_validate_ml_parallel_handoff_bundle_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "bundle.json"
    report_path.write_text(json.dumps(valid_bundle(tmp_path)), encoding="utf-8")

    mode = validate_contract(report_path, ML_PARALLEL_HANDOFF_BUNDLE_SCHEMA, validate_ml_parallel_handoff_bundle)

    assert mode == "jsonschema+built-in"


def test_validate_ml_parallel_handoff_bundle_schema_rejects_ready_claim_without_guard(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["claim_files"][0]["execute_guard_env"] = None
    report_path = tmp_path / "bundle.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(report_path, ML_PARALLEL_HANDOFF_BUNDLE_SCHEMA, validate_ml_parallel_handoff_bundle)
    except ContractError as exc:
        assert "schema validation failed at claim_files.0.execute_guard_env" in str(exc)
    else:
        raise AssertionError("expected ready claim without guard to fail jsonschema validation")


def test_validate_ml_parallel_handoff_bundle_schema_rejects_blocked_claim_with_guard(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["claim_files"][0]["claim_status"] = "blocked_artifact"
    payload["claim_files"][0]["evidence_status"] = "blocked_artifact"
    payload["claim_files"][0]["block_category"] = "artifact"
    payload["claim_files"][0]["validation_command_present"] = False
    payload["summary"]["ready_validation_only"] = 0
    payload["summary"]["blocked"] = 1
    payload["summary"]["blocked_by_category"] = {"dependency": 0, "artifact": 1, "env": 0, "other": 0}
    source_summary = payload["source"]["source_work_packages_summary"]
    source_summary["ready_validation_only"] = 0
    source_summary["blocked"] = 1
    source_summary["blocked_by_category"] = {"dependency": 0, "artifact": 1, "env": 0, "other": 0}
    source_summary["validation_only_batch_claims"] = 0
    source_summary["blocked_followup_batch_claims"] = 1
    source_summary["claims_with_validation_command"] = 0
    source_summary["by_status"] = {"blocked_artifact": 1}
    report_path = tmp_path / "bundle.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        validate_contract(report_path, ML_PARALLEL_HANDOFF_BUNDLE_SCHEMA, validate_ml_parallel_handoff_bundle)
    except ContractError as exc:
        assert "schema validation failed at claim_files.0.execute_guard_env" in str(exc)
    else:
        raise AssertionError("expected blocked claim with guard to fail jsonschema validation")


def test_validate_ml_parallel_handoff_bundle_rejects_missing_claim_file(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["claim_files"][0]["path"] = str(tmp_path / "missing.md")

    try:
        validate_ml_parallel_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "missing handoff file" in str(exc)
    else:
        raise AssertionError("expected missing handoff file to fail")


def test_validate_ml_parallel_handoff_bundle_rejects_missing_fingerprint_in_claim_file(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    Path(payload["claim_files"][0]["path"]).write_text("# ml-ml_data_governed_acquisition\n\n## Claim Boundary\n", encoding="utf-8")

    try:
        validate_ml_parallel_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "safe_command_fingerprints" in str(exc)
    else:
        raise AssertionError("expected missing fingerprint in handoff file to fail")


def test_validate_ml_parallel_handoff_bundle_rejects_missing_source_claim(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["source"]["source_work_packages_summary"] = {
        "claims": 2,
        "claim_ids": ["ml-ml_data_governed_acquisition", "ml-ml1_train_candidate_and_model_card"],
        "parallel_work_packages_validated": True,
        "source_claim_count": 2,
        "ready_validation_only": 1,
        "blocked": 0,
        "blocked_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
        "evidence_exists": 0,
        "evidence_usable_for_goal": 0,
        "validation_only_batch_claims": 1,
        "blocked_followup_batch_claims": 0,
        "claims_with_validation_command": 1,
        "claims_with_execute_guard": 1,
        "by_status": {"ready_validation_only": 1},
        **goal_snapshot(),
    }

    try:
        validate_ml_parallel_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "missing source claims: ml-ml1_train_candidate_and_model_card" in str(exc)
    else:
        raise AssertionError("expected missing source claim to fail")


def test_validate_ml_parallel_handoff_bundle_rejects_source_summary_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["source"]["source_work_packages_summary"]["claims_with_execute_guard"] = 0

    try:
        validate_ml_parallel_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "claims_with_execute_guard" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_ml_parallel_handoff_bundle_rejects_block_category_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["claim_files"][0]["claim_status"] = "blocked_env"
    payload["claim_files"][0]["evidence_status"] = "blocked_env"
    payload["claim_files"][0]["block_category"] = "artifact"
    payload["claim_files"][0]["validation_command_present"] = False
    payload["claim_files"][0]["execute_guard_env"] = None
    payload["summary"]["ready_validation_only"] = 0
    payload["summary"]["blocked"] = 1
    payload["summary"]["blocked_by_category"] = {"dependency": 0, "artifact": 0, "env": 1, "other": 0}
    source_summary = payload["source"]["source_work_packages_summary"]
    source_summary["ready_validation_only"] = 0
    source_summary["blocked"] = 1
    source_summary["validation_only_batch_claims"] = 0
    source_summary["blocked_followup_batch_claims"] = 1
    source_summary["claims_with_validation_command"] = 0
    source_summary["claims_with_execute_guard"] = 0
    source_summary["by_status"] = {"blocked_env": 1}
    source_summary["blocked_by_category"] = {"dependency": 0, "artifact": 0, "env": 1, "other": 0}

    try:
        validate_ml_parallel_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "block_category" in str(exc)
    else:
        raise AssertionError("expected block category drift to fail")


def test_validate_ml_parallel_handoff_bundle_rejects_evidence_claim_with_validation(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_bundle(tmp_path))
    payload["claim_files"][0]["claim_status"] = "evidence_exists"
    payload["claim_files"][0]["evidence_status"] = "coordination_only"
    payload["claim_files"][0]["block_category"] = None
    payload["claim_files"][0]["execute_guard_env"] = None
    payload["summary"]["ready_validation_only"] = 0
    payload["summary"]["evidence_exists"] = 1
    source_summary = payload["source"]["source_work_packages_summary"]
    source_summary["ready_validation_only"] = 0
    source_summary["evidence_exists"] = 1
    source_summary["validation_only_batch_claims"] = 0
    source_summary["claims_with_execute_guard"] = 0
    source_summary["by_status"] = {"evidence_exists": 1}

    try:
        validate_ml_parallel_handoff_bundle(payload, tmp_path / "bundle.json")
    except ContractError as exc:
        assert "evidence claim must not expose validation" in str(exc)
    else:
        raise AssertionError("expected evidence claim with validation marker to fail")
