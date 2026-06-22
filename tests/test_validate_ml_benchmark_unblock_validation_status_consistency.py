from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_CONSISTENCY_SCHEMA,
    validate_contract,
    validate_ml_benchmark_unblock_validation_status_consistency,
)


def valid_report() -> dict:
    goal_summary = {
        "goal_complete": False,
        "completion_state": "partial_evidence",
        "goal_usable_required_evidence": 1,
        "goal_required_evidence_total": 16,
        "next_unproven_requirement_id": "wave1_governed_acquisition",
        "next_unproven_execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
    }
    return {
        "api_version": "tamandua.io/ml-benchmark-unblock-validation-status-consistency/v1",
        "kind": "MLBenchmarkUnblockValidationStatusConsistency",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-05T00:00:00+00:00",
            "created_by": "tamandua-ml-benchmark-unblock-validation-status-consistency",
            "claim_boundary": "No-execution ML benchmark unblock validation status consistency probe only.",
        },
        "consistent": True,
        "blockers": [],
        "source_status_summary": {
            "benchmark_unblock_queue_validation": "jsonschema+built-in",
            "benchmark_unblock_validation_status_validation": "jsonschema+built-in",
            "benchmark_unblock_handoff_consistency_validation": "jsonschema+built-in",
            "queue_validated": True,
            "status_validated": True,
            "handoff_consistency_validated": True,
            "status_source_matches_queue": True,
            "status_source_matches_handoff_consistency": True,
            "all_queue_items_have_status": True,
            "no_stale_status_items": True,
            "status_fields_match_queue": True,
            "status_summary_matches_items": True,
            "upstream_summary_matches": True,
            "goal_snapshot_matches_sources": True,
            "status_preserves_handoff_coverage": True,
            "status_preserves_validation_command_proof": True,
            "status_preserves_contract_packet_coverage": True,
            "check_count": 14,
            "passed_checks": 14,
            "failed_checks": 0,
            "blocker_count": 0,
            "queue_items": 1,
            "status_items": 1,
            "missing_status_items": 0,
            "stale_status_items": 0,
            "field_mismatches": 0,
            "summary_mismatches": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "contract_packets_all_validated": True,
            "contract_packets_validated": 3,
            "next_operator_publication_decision": "hold_do_not_push",
            "ml2_ml3_agent_smoke_unblocks_production": False,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            **goal_summary,
            "consistent": True,
        },
        "configuration": {
            "benchmark_unblock_queue": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-queue.json",
            "benchmark_unblock_validation_status": "docs/benchmarks/runs/20260620T1935Z-ml-benchmark-unblock-validation-status-contract-packets.json",
            "benchmark_unblock_handoff_consistency": "docs/benchmarks/runs/20260604T-ml-benchmark-unblock-handoff-consistency.json",
        },
        "summary": {
            "queue_items": 1,
            "status_items": 1,
            "missing_status_items": 0,
            "stale_status_items": 0,
            "field_mismatches": 0,
            "summary_mismatches": 0,
            "upstream_ready_validation_only": 1,
            "upstream_blocked": 5,
            "contract_packets_all_validated": True,
            "contract_packets_validated": 3,
            "next_operator_publication_decision": "hold_do_not_push",
            "ml2_ml3_agent_smoke_unblocks_production": False,
            "missing_handoffs": 0,
            "stale_handoffs": 0,
            "pending_by_category": {"dependency": 0, "artifact": 1, "env": 0, "other": 0},
            "resolved_by_category": {"dependency": 0, "artifact": 0, "env": 0, "other": 0},
            **goal_summary,
        },
        "checks": [
            {"name": "benchmark_unblock_queue_valid", "passed": True, "detail": ""},
            {"name": "benchmark_unblock_validation_status_valid", "passed": True, "detail": ""},
            {"name": "benchmark_unblock_handoff_consistency_valid", "passed": True, "detail": ""},
            {"name": "status_source_matches_queue", "passed": True, "detail": ""},
            {"name": "status_source_matches_handoff_consistency", "passed": True, "detail": ""},
            {"name": "all_queue_items_have_status", "passed": True, "detail": ""},
            {"name": "no_stale_status_items", "passed": True, "detail": ""},
            {"name": "status_fields_match_queue", "passed": True, "detail": ""},
            {"name": "status_summary_matches_items", "passed": True, "detail": ""},
            {"name": "upstream_summary_matches", "passed": True, "detail": ""},
            {"name": "goal_snapshot_matches_sources", "passed": True, "detail": ""},
            {"name": "status_preserves_handoff_coverage", "passed": True, "detail": ""},
            {"name": "status_preserves_validation_command_proof", "passed": True, "detail": ""},
            {"name": "status_preserves_contract_packet_coverage", "passed": True, "detail": ""},
        ],
    }


def test_validate_ml_benchmark_unblock_validation_status_consistency_accepts_contract() -> None:
    validate_ml_benchmark_unblock_validation_status_consistency(
        valid_report(),
        Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
    )


def test_validate_ml_benchmark_unblock_validation_status_consistency_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-benchmark-unblock-validation-status-consistency.json"
    report_path.write_text(__import__("json").dumps(valid_report()), encoding="utf-8")

    mode = validate_contract(
        report_path,
        ML_BENCHMARK_UNBLOCK_VALIDATION_STATUS_CONSISTENCY_SCHEMA,
        validate_ml_benchmark_unblock_validation_status_consistency,
    )

    assert mode == "jsonschema+built-in"


def test_validate_ml_benchmark_unblock_validation_status_consistency_rejects_missing_blocker_for_summary_mismatch() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["summary"]["summary_mismatches"] = 1
    payload["checks"][-1]["passed"] = False

    with pytest.raises(ContractError, match="summary mismatch"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_benchmark_unblock_validation_status_consistency_rejects_missing_blocker_for_source_mismatch() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["checks"][3]["passed"] = False

    with pytest.raises(ContractError, match="status queue source mismatch"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_benchmark_unblock_validation_status_consistency_rejects_source_summary_drift() -> None:
    payload = valid_report()
    payload["source_status_summary"]["passed_checks"] = 9

    with pytest.raises(ContractError, match="source_status_summary.passed_checks"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_benchmark_unblock_validation_status_consistency_rejects_validation_mode_drift() -> None:
    payload = valid_report()
    payload["source_status_summary"]["benchmark_unblock_validation_status_validation"] = "failed"

    with pytest.raises(ContractError, match="source_status_summary.status_validated"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_benchmark_unblock_validation_status_consistency_rejects_category_rollup_drift() -> None:
    payload = valid_report()
    payload["source_status_summary"]["pending_by_category"]["artifact"] = 0
    payload["source_status_summary"]["pending_by_category"]["env"] = 1

    with pytest.raises(ContractError, match="source_status_summary.pending_by_category"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_benchmark_unblock_validation_status_consistency_rejects_missing_blocker_for_upstream_mismatch() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["upstream_summary_matches"] = False
    for check in payload["checks"]:
        if check["name"] == "upstream_summary_matches":
            check["passed"] = False

    with pytest.raises(ContractError, match="upstream summary mismatch"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_benchmark_unblock_validation_status_consistency_requires_validation_command_proof_blocker() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 11
    payload["source_status_summary"]["failed_checks"] = 1
    payload["source_status_summary"]["status_preserves_validation_command_proof"] = False
    for check in payload["checks"]:
        if check["name"] == "status_preserves_validation_command_proof":
            check["passed"] = False

    with pytest.raises(ContractError, match="validation command proof mismatch"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_benchmark_unblock_validation_status_consistency_requires_handoff_coverage_blocker() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 11
    payload["source_status_summary"]["failed_checks"] = 1
    payload["summary"]["missing_handoffs"] = 1
    payload["source_status_summary"]["missing_handoffs"] = 1
    payload["source_status_summary"]["status_preserves_handoff_coverage"] = False
    for check in payload["checks"]:
        if check["name"] == "status_preserves_handoff_coverage":
            check["passed"] = False

    with pytest.raises(ContractError, match="handoff coverage mismatch"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )


def test_validate_ml_benchmark_unblock_validation_status_consistency_requires_contract_packet_blocker() -> None:
    payload = valid_report()
    payload["consistent"] = False
    payload["blockers"] = ["wrong_blocker"]
    payload["source_status_summary"]["consistent"] = False
    payload["source_status_summary"]["blocker_count"] = 1
    payload["source_status_summary"]["passed_checks"] = 13
    payload["source_status_summary"]["failed_checks"] = 1
    payload["source_status_summary"]["status_preserves_contract_packet_coverage"] = False
    for check in payload["checks"]:
        if check["name"] == "status_preserves_contract_packet_coverage":
            check["passed"] = False

    with pytest.raises(ContractError, match="contract packet coverage mismatch"):
        validate_ml_benchmark_unblock_validation_status_consistency(
            payload,
            Path("memory://ml-benchmark-unblock-validation-status-consistency.json"),
        )
