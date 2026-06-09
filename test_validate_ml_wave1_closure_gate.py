from pathlib import Path

import pytest

from validate_ml_contracts import ContractError, WAVE1_CLOSURE_GATE_SCHEMA, validate_contract, validate_wave1_closure_gate


def goal_snapshot() -> dict:
    return {
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
            "required_evidence": ["wave1 transcript", "acquisition receipt"],
            "missing_or_unusable_evidence": ["wave1 transcript", "acquisition receipt"],
        },
    }


def expected_vx_policy() -> dict:
    return {
        "vx_inventory_ref": "docs\\benchmarks\\runs\\ml-vx-inthewild-inventory.json",
        "vx_inventory_metadata_only": True,
        "vx_samples_in_training_splits": False,
        "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
        "vx_archive_download_guard_must_be_unset": True,
        "operator_note": (
            "Wave 1 records the VX InTheWild inventory as metadata-only holdout context. "
            "It must not download VX archives or include VX samples in train/val/test splits."
        ),
    }


def valid_gate() -> dict:
    return {
        "api_version": "tamandua.io/ml-wave1-closure-gate/v1",
        "kind": "MLWave1ClosureGate",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-04T00:00:00+00:00",
            "created_by": "tamandua-ml-wave1-closure-gate",
            "claim_boundary": "No-execution Wave 1 closure gate only. Does not run acquisition.",
        },
        "wave1_closed": False,
        "blockers": [
            "manifest_publish_receipt_incomplete",
            "missing_canonical_dataset_manifest",
            "missing_external_production_manifest",
        ],
        "configuration": {
            "wave1_go_no_go": "docs/benchmarks/runs/20260604T-ml-wave1-go-no-go.json",
            "wave1_execution_packet": "docs/benchmarks/runs/20260604T-ml-wave1-execution-packet.json",
            "wave1_acquisition_receipt": "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
            "wave1_manifest_publish_receipt": "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
            "wave1_post_acquisition_go_no_go": "docs/benchmarks/runs/20260604T-ml-wave1-post-acquisition-go-no-go-summary.json",
            "wave2_ml1_readiness": "docs/benchmarks/runs/20260604T-ml-wave2-ml1-readiness-probe.json",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
        },
        "source_artifact_hashes": {
            "wave1_go_no_go": {
                "path": "docs/benchmarks/runs/20260604T-ml-wave1-go-no-go.json",
                "sha256": "1" * 64,
            },
            "wave1_execution_packet": {
                "path": "docs/benchmarks/runs/20260604T-ml-wave1-execution-packet.json",
                "sha256": "2" * 64,
            },
            "wave1_acquisition_receipt": {
                "path": "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
                "sha256": "3" * 64,
            },
            "wave1_manifest_publish_receipt": {
                "path": "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
                "sha256": "4" * 64,
            },
            "wave1_post_acquisition_go_no_go": {
                "path": "docs/benchmarks/runs/20260604T-ml-wave1-post-acquisition-go-no-go-summary.json",
                "sha256": "5" * 64,
            },
            "wave2_ml1_readiness": {
                "path": "docs/benchmarks/runs/20260604T-ml-wave2-ml1-readiness-probe.json",
                "sha256": "6" * 64,
            },
        },
        "vx_policy": expected_vx_policy(),
        "source": {
            "wave1_go_no_go": "docs/benchmarks/runs/20260604T-ml-wave1-go-no-go.json",
            "wave1_go_no_go_validation": "jsonschema+built-in",
            "wave1_execution_packet": "docs/benchmarks/runs/20260604T-ml-wave1-execution-packet.json",
            "wave1_execution_packet_validation": "jsonschema+built-in",
            "wave1_acquisition_receipt": "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
            "wave1_acquisition_receipt_validation": "jsonschema+built-in",
            "wave1_manifest_publish_receipt": "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
            "wave1_manifest_publish_receipt_validation": "jsonschema+built-in",
            "wave1_post_acquisition_go_no_go": "docs/benchmarks/runs/20260604T-ml-wave1-post-acquisition-go-no-go-summary.json",
            "wave1_post_acquisition_go_no_go_validation": "jsonschema+built-in",
            "wave2_ml1_readiness": "docs/benchmarks/runs/20260604T-ml-wave2-ml1-readiness-probe.json",
            "wave2_ml1_readiness_validation": "jsonschema+built-in",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "canonical_dataset_manifest_validation": "missing",
            "source_status_summary": {
                "wave1_closed": False,
                "go_for_guarded_real_acquisition": True,
                "execution_packet_safe_to_operator": True,
                "receipt_ready_for_publish": False,
                "manifest_publish_complete": False,
                "post_acquisition_expected_vx_policy_valid": True,
                "acquisition_transcript_guarded_run_command_packet_sha256": "",
                "acquisition_transcript_stdout_sha256": "",
                "acquisition_transcript_stderr_sha256": "",
                "manifest_transcript_guarded_run_command_packet_sha256": "",
                "manifest_transcript_stdout_sha256": "",
                "manifest_transcript_stderr_sha256": "",
                "transcript_hashes_match_between_receipts": True,
                "pre_execution_transcript_contract_validation_before_run": "missing",
                "pre_execution_transcript_contract_valid_before_run": False,
                "pre_execution_transcript_contract_missing_before_run": True,
                "intake_transcript_contract_validation": "missing",
                "intake_transcript_contract_valid": False,
                "transcript_contract_valid_for_manifest_publish": False,
                "wave1_pre_execution_transcript_contract_validation_before_run": "missing",
                "wave1_pre_execution_transcript_contract_valid_before_run": False,
                "wave1_pre_execution_transcript_contract_missing_before_run": True,
                "wave1_acceptance_intake_transcript_contract_validation": "missing",
                "wave1_acceptance_intake_transcript_contract_valid": False,
                "wave1_transcript_contract_valid_for_manifest_publish": False,
                "expected_vx_inventory_ref": "docs\\benchmarks\\runs\\ml-vx-inthewild-inventory.json",
                "expected_vx_inventory_metadata_only": True,
                "expected_vx_samples_in_training_splits": False,
                "expected_vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
                "expected_vx_archive_download_guard_must_be_unset": True,
                "wave2_ml1_ready": False,
                "canonical_dataset_manifest_present": False,
                "canonical_dataset_manifest_samples": 0,
                "check_count": 13,
                "passed_checks": 9,
                "failed_checks": 4,
                "blocker_count": 3,
                "blockers": [
                    "manifest_publish_receipt_incomplete",
                    "missing_canonical_dataset_manifest",
                    "missing_external_production_manifest",
                ],
                "next_required_action": "Run guarded Wave 1 acquisition.",
                **goal_snapshot(),
            },
        },
        "summary": {
            "canonical_dataset_manifest_present": False,
            "canonical_dataset_manifest_samples": 0,
            "receipt_ready_for_publish": False,
            "manifest_publish_complete": False,
            "post_acquisition_expected_vx_policy_valid": True,
            "wave2_ml1_ready": False,
        },
        "checks": [
            {"name": "wave1_go_no_go_valid", "passed": True, "detail": ""},
            {"name": "wave1_execution_packet_valid", "passed": True, "detail": ""},
            {"name": "wave1_acquisition_receipt_valid", "passed": True, "detail": ""},
            {"name": "wave1_manifest_publish_receipt_valid", "passed": True, "detail": ""},
            {"name": "wave1_post_acquisition_go_no_go_valid", "passed": True, "detail": ""},
            {"name": "wave2_ml1_readiness_valid", "passed": True, "detail": ""},
            {"name": "go_for_guarded_real_acquisition", "passed": True, "detail": ""},
            {"name": "execution_packet_safe_to_operator", "passed": True, "detail": ""},
            {"name": "acquisition_receipt_ready_for_publish", "passed": False, "detail": ""},
            {"name": "manifest_publish_receipt_complete", "passed": False, "detail": ""},
            {
                "name": "post_acquisition_expected_vx_policy_metadata_only_boundary",
                "passed": True,
                "detail": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            },
            {"name": "canonical_dataset_manifest_valid", "passed": False, "detail": ""},
            {"name": "wave2_ml1_ready", "passed": False, "detail": ""},
        ],
        "next_required_action": "Run guarded Wave 1 acquisition.",
    }


def sync_source(payload: dict) -> None:
    source_summary = payload["source"]["source_status_summary"]
    source_summary["wave1_closed"] = payload["wave1_closed"]
    source_summary["receipt_ready_for_publish"] = payload["summary"]["receipt_ready_for_publish"]
    source_summary["manifest_publish_complete"] = payload["summary"]["manifest_publish_complete"]
    source_summary["post_acquisition_expected_vx_policy_valid"] = payload["summary"][
        "post_acquisition_expected_vx_policy_valid"
    ]
    source_summary["wave2_ml1_ready"] = payload["summary"]["wave2_ml1_ready"]
    source_summary["canonical_dataset_manifest_present"] = payload["summary"]["canonical_dataset_manifest_present"]
    source_summary["canonical_dataset_manifest_samples"] = payload["summary"]["canonical_dataset_manifest_samples"]
    source_summary["blockers"] = list(payload["blockers"])
    source_summary["blocker_count"] = len(payload["blockers"])
    source_summary["check_count"] = len(payload["checks"])
    source_summary["passed_checks"] = sum(1 for check in payload["checks"] if check["passed"] is True)
    source_summary["failed_checks"] = sum(1 for check in payload["checks"] if check["passed"] is not True)
    source_summary["next_required_action"] = payload["next_required_action"]
    for check in payload["checks"]:
        if check["name"] == "go_for_guarded_real_acquisition":
            source_summary["go_for_guarded_real_acquisition"] = check["passed"]
        if check["name"] == "execution_packet_safe_to_operator":
            source_summary["execution_packet_safe_to_operator"] = check["passed"]


def test_validate_wave1_closure_gate_accepts_contract() -> None:
    validate_wave1_closure_gate(valid_gate(), Path("memory://gate.json"))


def test_validate_wave1_closure_gate_accepts_jsonschema_path(tmp_path: Path) -> None:
    path = tmp_path / "gate.json"
    path.write_text(__import__("json").dumps(valid_gate()), encoding="utf-8")

    mode = validate_contract(path, WAVE1_CLOSURE_GATE_SCHEMA, validate_wave1_closure_gate)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_closure_gate_rejects_closed_with_failed_check() -> None:
    payload = valid_gate()
    payload["wave1_closed"] = True
    payload["blockers"] = []
    sync_source(payload)

    with pytest.raises(ContractError, match="failed checks"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_open_without_blockers() -> None:
    payload = valid_gate()
    payload["blockers"] = []

    with pytest.raises(ContractError, match="open gate"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_open_when_required_checks_pass() -> None:
    payload = valid_gate()
    payload["blockers"] = ["stale_blocker"]
    payload["summary"]["canonical_dataset_manifest_present"] = True
    payload["summary"]["canonical_dataset_manifest_samples"] = 3
    payload["summary"]["receipt_ready_for_publish"] = True
    payload["summary"]["manifest_publish_complete"] = True
    payload["summary"]["wave2_ml1_ready"] = True
    for check in payload["checks"]:
        check["passed"] = True
    payload["source"]["canonical_dataset_manifest_validation"] = "jsonschema+built-in"
    sync_source(payload)

    with pytest.raises(ContractError, match="cannot be false when all required checks pass"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_missing_canonical_manifest_blocker() -> None:
    payload = valid_gate()
    payload["blockers"] = ["manifest_publish_receipt_incomplete", "missing_external_production_manifest"]
    sync_source(payload)

    with pytest.raises(ContractError, match="canonical dataset manifest blocker"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_complete_manifest_receipt_when_receipt_invalid() -> None:
    payload = valid_gate()
    payload["summary"]["manifest_publish_complete"] = True
    for check in payload["checks"]:
        if check["name"] == "wave1_manifest_publish_receipt_valid":
            check["passed"] = False
        if check["name"] == "manifest_publish_receipt_complete":
            check["passed"] = True
    payload["source"]["wave1_manifest_publish_receipt_validation"] = "failed"
    payload["source"]["source_status_summary"]["manifest_publish_complete"] = True

    with pytest.raises(ContractError, match="cannot pass when manifest publish receipt is invalid"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_source_status_summary_drift() -> None:
    payload = valid_gate()
    payload["source"]["source_status_summary"]["receipt_ready_for_publish"] = True

    with pytest.raises(ContractError, match="source_status_summary"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_transcript_contract_rollup_drift() -> None:
    payload = valid_gate()
    payload["source"]["source_status_summary"]["pre_execution_transcript_contract_validation_before_run"] = "failed"

    with pytest.raises(ContractError, match="pre_execution_transcript_contract"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_wave1_transcript_alias_drift() -> None:
    payload = valid_gate()
    payload["source"]["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_transcript_hash_rollup_drift() -> None:
    payload = valid_gate()
    payload["source"]["source_status_summary"]["manifest_transcript_stdout_sha256"] = "f" * 64

    with pytest.raises(ContractError, match="transcript_hashes_match_between_receipts"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_expected_vx_policy_drift() -> None:
    payload = valid_gate()
    payload["vx_policy"]["vx_samples_in_training_splits"] = True

    with pytest.raises(ContractError, match="vx_samples_in_training_splits"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_expected_vx_summary_drift() -> None:
    payload = valid_gate()
    payload["source"]["source_status_summary"]["expected_vx_inventory_metadata_only"] = False

    with pytest.raises(ContractError, match="expected_vx_inventory_metadata_only"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_requires_expected_vx_check() -> None:
    payload = valid_gate()
    payload["checks"] = [
        check for check in payload["checks"] if check["name"] != "post_acquisition_expected_vx_policy_metadata_only_boundary"
    ]
    sync_source(payload)

    with pytest.raises(ContractError, match="post_acquisition_expected_vx_policy_metadata_only_boundary"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_source_validation_mode_drift() -> None:
    payload = valid_gate()
    payload["source"]["wave1_execution_packet_validation"] = "failed"

    with pytest.raises(ContractError, match="wave1_execution_packet_validation"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_source_artifact_path_drift() -> None:
    payload = valid_gate()
    payload["source_artifact_hashes"]["wave1_acquisition_receipt"]["path"] = "docs/benchmarks/runs/wrong.json"

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))


def test_validate_wave1_closure_gate_rejects_extra_source_artifact_hash() -> None:
    payload = valid_gate()
    payload["source_artifact_hashes"]["unexpected"] = {
        "path": "docs/benchmarks/runs/unexpected.json",
        "sha256": "0" * 64,
    }

    with pytest.raises(ContractError, match="source_artifact_hashes"):
        validate_wave1_closure_gate(payload, Path("memory://gate.json"))
