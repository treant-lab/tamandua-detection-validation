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
    ML_BENCHMARK_UNBLOCK_HANDOFF_CONSISTENCY_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_benchmark_unblock_handoff_consistency,
)


def valid_consistency() -> dict:
    goal_summary = {
        "goal_complete": False,
        "completion_state": "partial_evidence",
        "goal_usable_required_evidence": 1,
        "goal_required_evidence_total": 16,
        "next_unproven_requirement_id": "wave1_governed_acquisition",
        "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
    }
    return {
        "api_version": "tamandua.io/ml-benchmark-unblock-handoff-consistency/v1",
        "kind": "MLBenchmarkUnblockHandoffConsistency",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-05T00:00:00Z",
            "created_by": "tamandua-ml-benchmark-unblock-handoff-consistency",
            "claim_boundary": "No-execution ML benchmark unblock handoff consistency probe only.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "benchmark_unblock_queue_validation": "jsonschema+built-in",
            "benchmark_unblock_handoff_bundle_validation": "jsonschema+built-in",
            "queue_validated": True,
            "bundle_validated": True,
            "bundle_source_matches_queue": True,
            "all_queue_items_have_handoffs": True,
            "no_stale_handoffs": True,
            "handoff_fields_match_queue": True,
            "validation_command_hashes_match": True,
            "handoff_markdown_matches_manifest": True,
            "category_rollups_match": True,
            "upstream_summary_matches": True,
            "goal_snapshot_matches_queue": True,
            "validation_commands_preserved": True,
            "passed_checks": 12,
            "failed_checks": 0,
            "check_count": 12,
            "blocker_count": 0,
            "queue_items": 21,
            "handoff_files": 21,
            "source_mismatches": 0,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "command_hash_mismatches": 0,
            "pending_by_category": {
                "dependency": 7,
                "artifact": 12,
                "env": 2,
                "other": 0,
            },
            "resolved_by_category": {
                "dependency": 0,
                "artifact": 0,
                "env": 0,
                "other": 0,
            },
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "validation_command_count": 21,
            "validation_only_commands": 21,
            **goal_summary,
            "consistent": True,
        },
        "configuration": {
            "benchmark_unblock_queue": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.json",
            "benchmark_unblock_handoff_bundle": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-handoff-bundle.json",
        },
        "summary": {
            "queue_items": 21,
            "handoff_files": 21,
            "source_mismatches": 0,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "command_hash_mismatches": 0,
            "pending_by_category": {
                "dependency": 7,
                "artifact": 12,
                "env": 2,
                "other": 0,
            },
            "resolved_by_category": {
                "dependency": 0,
                "artifact": 0,
                "env": 0,
                "other": 0,
            },
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "validation_command_count": 21,
            "validation_only_commands": 21,
            **goal_summary,
        },
        "checks": [
            {"name": "benchmark_unblock_queue_valid", "passed": True, "detail": ""},
            {"name": "benchmark_unblock_handoff_bundle_valid", "passed": True, "detail": ""},
            {"name": "bundle_source_matches_queue", "passed": True, "detail": ""},
            {"name": "all_queue_items_have_handoffs", "passed": True, "detail": ""},
            {"name": "no_stale_handoffs", "passed": True, "detail": ""},
            {"name": "handoff_fields_match_queue", "passed": True, "detail": ""},
            {"name": "validation_command_hashes_match", "passed": True, "detail": ""},
            {"name": "handoff_markdown_matches_manifest", "passed": True, "detail": ""},
            {"name": "category_rollups_match", "passed": True, "detail": ""},
            {"name": "upstream_summary_matches", "passed": True, "detail": ""},
            {"name": "goal_snapshot_matches_queue", "passed": True, "detail": ""},
            {"name": "validation_commands_preserved", "passed": True, "detail": ""},
        ],
    }


def test_validate_ml_benchmark_unblock_handoff_consistency_accepts_contract() -> None:
    validate_ml_benchmark_unblock_handoff_consistency(valid_consistency(), Path("memory://consistency.json"))


def test_validate_ml_benchmark_unblock_handoff_consistency_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "consistency.json"
    report_path.write_text(json.dumps(valid_consistency()), encoding="utf-8")

    mode = validate_contract(
        report_path,
        ML_BENCHMARK_UNBLOCK_HANDOFF_CONSISTENCY_SCHEMA,
        validate_ml_benchmark_unblock_handoff_consistency,
    )

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_unblock_handoff_consistency_rejects_true_with_failed_check() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["checks"][0]["passed"] = False

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "failed checks" in str(exc)
    else:
        raise AssertionError("expected failed check to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_rejects_missing_blocker_without_explanation() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["summary"]["missing_handoffs"] = 1

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "inconsistent report" in str(exc)
    else:
        raise AssertionError("expected inconsistent report without blockers to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_requires_source_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["summary"]["source_mismatches"] = 1
    for check in payload["checks"]:
        if check["name"] == "bundle_source_matches_queue":
            check["passed"] = False

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source mismatch" in str(exc)
    else:
        raise AssertionError("expected missing source mismatch blocker to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["passed_checks"] = 7

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.passed_checks" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_rejects_source_validation_mode_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["benchmark_unblock_handoff_bundle_validation"] = "failed"

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.bundle_validated" in str(exc)
    else:
        raise AssertionError("expected source validation mode drift to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_rejects_category_summary_drift() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["source_status_summary"]["pending_by_category"]["artifact"] = 11

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "source_status_summary.pending_by_category.artifact" in str(exc)
    else:
        raise AssertionError("expected category summary drift to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_requires_category_rollup_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    for check in payload["checks"]:
        if check["name"] == "category_rollups_match":
            check["passed"] = False
    payload["source_status_summary"]["category_rollups_match"] = False

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "category rollup mismatch" in str(exc)
    else:
        raise AssertionError("expected missing category rollup blocker to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_requires_upstream_summary_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    for check in payload["checks"]:
        if check["name"] == "upstream_summary_matches":
            check["passed"] = False
    payload["source_status_summary"]["upstream_summary_matches"] = False

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "upstream summary mismatch" in str(exc)
    else:
        raise AssertionError("expected missing upstream summary blocker to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_requires_command_hash_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 10
    payload["source_status_summary"]["failed_checks"] = 1
    payload["source_status_summary"]["validation_command_hashes_match"] = False
    payload["summary"]["command_hash_mismatches"] = 1
    payload["source_status_summary"]["command_hash_mismatches"] = 1
    for check in payload["checks"]:
        if check["name"] == "validation_command_hashes_match":
            check["passed"] = False

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "command hash mismatch" in str(exc)
    else:
        raise AssertionError("expected missing command hash blocker to fail")


def test_validate_ml_benchmark_unblock_handoff_consistency_requires_validation_command_blocker() -> None:
    payload = copy.deepcopy(valid_consistency())
    payload["consistent"] = False
    payload["blockers"] = ["some_other_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 10
    payload["source_status_summary"]["failed_checks"] = 1
    payload["source_status_summary"]["validation_commands_preserved"] = False
    payload["summary"]["validation_only_commands"] = 20
    payload["source_status_summary"]["validation_only_commands"] = 20
    for check in payload["checks"]:
        if check["name"] == "validation_commands_preserved":
            check["passed"] = False

    try:
        validate_ml_benchmark_unblock_handoff_consistency(payload, Path("memory://consistency.json"))
    except ContractError as exc:
        assert "validation command mismatch" in str(exc)
    else:
        raise AssertionError("expected missing validation command blocker to fail")
