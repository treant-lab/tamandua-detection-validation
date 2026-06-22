from pathlib import Path
import hashlib

import pytest

from validate_ml_contracts import (
    ContractError,
    WAVE1_MANIFEST_PUBLISH_RECEIPT_SCHEMA,
    validate_contract,
    validate_wave1_manifest_publish_receipt,
)


def valid_receipt() -> dict:
    publish_command = "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute"
    return {
        "api_version": "tamandua.io/ml-wave1-manifest-publish-receipt/v1",
        "kind": "MLWave1ManifestPublishReceipt",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-04T00:00:00+00:00",
            "created_by": "tamandua-ml-wave1-manifest-publish-receipt",
            "claim_boundary": "No-execution Wave 1 manifest publish receipt only. Does not publish manifests.",
        },
        "manifest_publish_complete": False,
        "blockers": ["missing_external_production_manifest", "missing_canonical_dataset_manifest"],
        "source_status_summary": {
            "manifest_publish_complete": False,
            "receipt_ready_for_publish": True,
            "acquisition_transcript_present": True,
            "acquisition_transcript_valid": True,
            "acquisition_transcript_validation": "jsonschema+built-in",
            "acquisition_transcript_execute_succeeded": True,
            "acquisition_transcript_guarded_run_command_packet_ref": "docs/benchmarks/runs/20260604T-ml-wave1-guarded-run-command-packet.json",
            "acquisition_transcript_acquisition_command_sha256": "a" * 64,
            "acquisition_transcript_guarded_run_command_packet_sha256": "b" * 64,
            "acquisition_transcript_stdout_sha256": "c" * 64,
            "acquisition_transcript_stderr_sha256": "d" * 64,
            "acquisition_transcript_vx_policy_valid": True,
            "acquisition_transcript_vx_inventory_metadata_only": True,
            "acquisition_transcript_vx_samples_in_training_splits": False,
            "acquisition_transcript_vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "acquisition_transcript_vx_archive_download_guard_must_be_unset": True,
            "acquisition_receipt_expected_vx_policy_valid": True,
            "expected_vx_inventory_ref": "docs\\benchmarks\\runs\\ml-vx-inthewild-inventory.json",
            "expected_vx_inventory_metadata_only": True,
            "expected_vx_samples_in_training_splits": False,
            "expected_vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "expected_vx_archive_download_guard_must_be_unset": True,
            "production_manifest_exists": False,
            "production_manifest_shape_valid": False,
            "production_manifest_sha256": "",
            "canonical_dataset_manifest_exists": False,
            "canonical_dataset_manifest_valid": False,
            "canonical_dataset_manifest_sha256": "",
            "canonical_manifest_raw_samples_not_in_git": False,
            "canonical_manifest_raw_sample_storage_external": False,
            "canonical_manifest_storage_refs_external": False,
            "canonical_manifest_storage_refs_match_expected_layout": False,
            "external_sample_count": 0,
            "canonical_sample_count": 0,
            "external_split_counts": {"train": 0, "validation": 0, "test": 0},
            "canonical_split_counts": {"train": 0, "validation": 0, "test": 0},
            "check_count": 23,
            "passed_checks": 9,
            "failed_checks": 14,
            "blocker_count": 2,
            "blockers": ["missing_external_production_manifest", "missing_canonical_dataset_manifest"],
            "next_required_action": "Run guarded Wave 1 acquisition.",
        },
        "vx_policy": {
            "vx_inventory_ref": "docs\\benchmarks\\runs\\ml-vx-inthewild-inventory.json",
            "vx_inventory_metadata_only": True,
            "vx_samples_in_training_splits": False,
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_must_be_unset": True,
            "operator_note": (
                "Wave 1 records the VX InTheWild inventory as metadata-only holdout context. "
                "It must not download VX archives or include VX samples in train/val/test splits."
            ),
        },
        "configuration": {
            "acquisition_receipt": "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
            "production_manifest": "D:\\treant\\tamandua_ml_lab_data\\production\\manifest.json",
            "production_manifest_sha256": "",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "canonical_dataset_manifest_sha256": "",
            "publish_guard_env": "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
            "publish_command": publish_command,
            "publish_command_sha256": hashlib.sha256(publish_command.encode("utf-8")).hexdigest(),
        },
        "summary": {
            "external_sample_count": 0,
            "canonical_sample_count": 0,
            "external_split_counts": {"train": 0, "validation": 0, "test": 0},
            "canonical_split_counts": {"train": 0, "validation": 0, "test": 0},
            "production_manifest_sha256": "",
            "canonical_dataset_manifest_sha256": "",
            "receipt_ready_for_publish": True,
            "acquisition_transcript_present": True,
            "acquisition_transcript_valid": True,
            "acquisition_transcript_execute_succeeded": True,
            "acquisition_transcript_vx_policy_valid": True,
            "acquisition_transcript_vx_samples_in_training_splits": False,
            "acquisition_receipt_expected_vx_policy_valid": True,
        },
        "checks": [
            {"name": "acquisition_receipt_valid", "passed": True, "detail": ""},
            {"name": "acquisition_receipt_ready_for_publish", "passed": True, "detail": ""},
            {"name": "acquisition_transcript_valid_for_publish", "passed": True, "detail": ""},
            {"name": "acquisition_transcript_execute_succeeded_for_publish", "passed": True, "detail": ""},
            {"name": "acquisition_transcript_vx_policy_valid_for_publish", "passed": True, "detail": ""},
            {
                "name": "acquisition_receipt_expected_vx_policy_metadata_only_boundary",
                "passed": True,
                "detail": "{\"vx_archive_download_guard_env\": \"TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD\"}",
            },
            {"name": "acquisition_receipt_references_production_manifest", "passed": True, "detail": ""},
            {"name": "acquisition_receipt_references_canonical_manifest", "passed": True, "detail": ""},
            {"name": "production_manifest_outside_repo", "passed": True, "detail": ""},
            {"name": "production_manifest_exists", "passed": False, "detail": ""},
            {"name": "production_manifest_sha256_recorded", "passed": False, "detail": ""},
            {"name": "production_manifest_shape_valid", "passed": False, "detail": ""},
            {"name": "production_manifest_sample_count_matches_acquisition_receipt", "passed": False, "detail": ""},
            {"name": "canonical_dataset_manifest_exists", "passed": False, "detail": ""},
            {"name": "canonical_dataset_manifest_sha256_recorded", "passed": False, "detail": ""},
            {"name": "canonical_dataset_manifest_valid", "passed": False, "detail": ""},
            {"name": "canonical_manifest_raw_samples_not_in_git", "passed": False, "detail": ""},
            {"name": "canonical_manifest_raw_sample_storage_external", "passed": False, "detail": ""},
            {"name": "canonical_manifest_storage_refs_external", "passed": False, "detail": ""},
            {"name": "canonical_manifest_storage_refs_match_expected_layout", "passed": False, "detail": ""},
            {"name": "canonical_manifest_matches_external_sha_splits", "passed": False, "detail": ""},
            {"name": "canonical_manifest_matches_external_labels", "passed": False, "detail": ""},
            {"name": "canonical_manifest_split_counts_match_external", "passed": False, "detail": ""},
        ],
        "next_required_action": "Run guarded Wave 1 acquisition.",
    }


def test_validate_wave1_manifest_publish_receipt_accepts_contract() -> None:
    validate_wave1_manifest_publish_receipt(valid_receipt(), Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "receipt.json"
    report_path.write_text(__import__("json").dumps(valid_receipt()), encoding="utf-8")

    mode = validate_contract(
        report_path,
        WAVE1_MANIFEST_PUBLISH_RECEIPT_SCHEMA,
        validate_wave1_manifest_publish_receipt,
    )

    assert mode == "jsonschema+built-in"


def test_validate_wave1_manifest_publish_receipt_rejects_complete_with_failed_check() -> None:
    payload = valid_receipt()
    payload["manifest_publish_complete"] = True
    payload["blockers"] = []
    payload["source_status_summary"]["manifest_publish_complete"] = True
    payload["source_status_summary"]["blockers"] = []
    payload["source_status_summary"]["blocker_count"] = 0

    with pytest.raises(ContractError, match="failed checks"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_missing_guard() -> None:
    payload = valid_receipt()
    payload["configuration"]["publish_guard_env"] = "WRONG"

    with pytest.raises(ContractError, match="publish_guard_env"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_publish_command_hash_drift() -> None:
    payload = valid_receipt()
    payload["configuration"]["publish_command_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="publish_command_sha256"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_missing_receipt_ref_checks() -> None:
    payload = valid_receipt()
    payload["checks"] = [
        check
        for check in payload["checks"]
        if check["name"] != "acquisition_receipt_references_production_manifest"
    ]

    with pytest.raises(ContractError, match="acquisition_receipt_references_production_manifest"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_requires_receipt_ref_mismatch_blocker() -> None:
    payload = valid_receipt()
    for check in payload["checks"]:
        if check["name"] == "acquisition_receipt_references_production_manifest":
            check["passed"] = False
    payload["source_status_summary"]["passed_checks"] = 8
    payload["source_status_summary"]["failed_checks"] = 15

    with pytest.raises(ContractError, match="production manifest receipt mismatch blocker"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_requires_sample_count_mismatch_blocker() -> None:
    payload = valid_receipt()
    for check in payload["checks"]:
        if check["name"] == "production_manifest_shape_valid":
            check["passed"] = True
        if check["name"] == "production_manifest_sample_count_matches_acquisition_receipt":
            check["passed"] = False
    payload["source_status_summary"]["production_manifest_shape_valid"] = True
    payload["source_status_summary"]["passed_checks"] = 10
    payload["source_status_summary"]["failed_checks"] = 13

    with pytest.raises(ContractError, match="sample count mismatch blocker"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_negative_split_count() -> None:
    payload = valid_receipt()
    payload["summary"]["external_split_counts"]["train"] = -1
    payload["source_status_summary"]["external_split_counts"]["train"] = -1

    with pytest.raises(ContractError, match="split count must be non-negative"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_manifest_sha_drift() -> None:
    payload = valid_receipt()
    payload["configuration"]["production_manifest_sha256"] = "a" * 64

    with pytest.raises(ContractError, match="production_manifest_sha256"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_incomplete_when_required_checks_pass() -> None:
    payload = valid_receipt()
    payload["blockers"] = ["stale_blocker"]
    payload["source_status_summary"]["blockers"] = ["stale_blocker"]
    payload["source_status_summary"]["blocker_count"] = 1
    payload["summary"]["external_sample_count"] = 3
    payload["summary"]["canonical_sample_count"] = 3
    payload["summary"]["external_split_counts"] = {"train": 1, "validation": 1, "test": 1}
    payload["summary"]["canonical_split_counts"] = {"train": 1, "validation": 1, "test": 1}
    payload["source_status_summary"]["external_sample_count"] = 3
    payload["source_status_summary"]["canonical_sample_count"] = 3
    payload["source_status_summary"]["external_split_counts"] = {"train": 1, "validation": 1, "test": 1}
    payload["source_status_summary"]["canonical_split_counts"] = {"train": 1, "validation": 1, "test": 1}
    payload["summary"]["production_manifest_sha256"] = "a" * 64
    payload["summary"]["canonical_dataset_manifest_sha256"] = "b" * 64
    payload["configuration"]["production_manifest_sha256"] = "a" * 64
    payload["configuration"]["canonical_dataset_manifest_sha256"] = "b" * 64
    payload["source_status_summary"]["production_manifest_sha256"] = "a" * 64
    payload["source_status_summary"]["canonical_dataset_manifest_sha256"] = "b" * 64
    for check in payload["checks"]:
        check["passed"] = True
    payload["source_status_summary"]["passed_checks"] = 23
    payload["source_status_summary"]["failed_checks"] = 0
    payload["source_status_summary"]["production_manifest_exists"] = True
    payload["source_status_summary"]["production_manifest_shape_valid"] = True
    payload["source_status_summary"]["canonical_dataset_manifest_exists"] = True
    payload["source_status_summary"]["canonical_dataset_manifest_valid"] = True
    payload["source_status_summary"]["canonical_manifest_raw_samples_not_in_git"] = True
    payload["source_status_summary"]["canonical_manifest_raw_sample_storage_external"] = True
    payload["source_status_summary"]["canonical_manifest_storage_refs_external"] = True
    payload["source_status_summary"]["canonical_manifest_storage_refs_match_expected_layout"] = True

    with pytest.raises(ContractError, match="cannot be false when all required checks pass"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_source_status_summary_drift() -> None:
    payload = valid_receipt()
    payload["source_status_summary"]["passed_checks"] = 4

    with pytest.raises(ContractError, match="source_status_summary.passed_checks"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_complete_without_transcript() -> None:
    payload = valid_receipt()
    payload["manifest_publish_complete"] = True
    payload["blockers"] = []
    payload["source_status_summary"]["manifest_publish_complete"] = True
    payload["source_status_summary"]["blockers"] = []
    payload["source_status_summary"]["blocker_count"] = 0
    payload["source_status_summary"]["acquisition_transcript_valid"] = False
    payload["source_status_summary"]["acquisition_transcript_validation"] = "missing"
    payload["source_status_summary"]["acquisition_transcript_execute_succeeded"] = False
    payload["source_status_summary"]["acquisition_transcript_guarded_run_command_packet_sha256"] = ""
    payload["source_status_summary"]["acquisition_transcript_stdout_sha256"] = ""
    payload["source_status_summary"]["acquisition_transcript_stderr_sha256"] = ""
    payload["summary"]["acquisition_transcript_valid"] = False
    payload["summary"]["acquisition_transcript_execute_succeeded"] = False
    for check in payload["checks"]:
        check["passed"] = True
        if check["name"] in {
            "acquisition_transcript_valid_for_publish",
            "acquisition_transcript_execute_succeeded_for_publish",
        }:
            check["passed"] = False
    payload["source_status_summary"]["passed_checks"] = 21
    payload["source_status_summary"]["failed_checks"] = 2

    with pytest.raises(ContractError, match="failed checks|valid successful acquisition transcript"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_missing_transcript_hash_drift() -> None:
    payload = valid_receipt()
    payload["source_status_summary"]["acquisition_transcript_validation"] = "missing"
    payload["source_status_summary"]["acquisition_transcript_guarded_run_command_packet_sha256"] = ""
    payload["source_status_summary"]["acquisition_transcript_stdout_sha256"] = "c" * 64
    payload["source_status_summary"]["acquisition_transcript_stderr_sha256"] = ""

    with pytest.raises(ContractError, match="acquisition_transcript_stdout_sha256"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_requires_hashes_when_transcript_valid() -> None:
    payload = valid_receipt()
    payload["source_status_summary"]["acquisition_transcript_stdout_sha256"] = ""

    with pytest.raises(ContractError, match="acquisition_transcript_stdout_sha256"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_complete_without_vx_policy() -> None:
    payload = valid_receipt()
    payload["manifest_publish_complete"] = True
    payload["blockers"] = []
    payload["source_status_summary"]["manifest_publish_complete"] = True
    payload["source_status_summary"]["blockers"] = []
    payload["source_status_summary"]["blocker_count"] = 0
    payload["source_status_summary"]["acquisition_transcript_vx_policy_valid"] = False
    payload["source_status_summary"]["acquisition_transcript_vx_samples_in_training_splits"] = True
    payload["summary"]["acquisition_transcript_vx_policy_valid"] = False
    payload["summary"]["acquisition_transcript_vx_samples_in_training_splits"] = True
    for check in payload["checks"]:
        check["passed"] = True
        if check["name"] == "acquisition_transcript_vx_policy_valid_for_publish":
            check["passed"] = False
    payload["source_status_summary"]["passed_checks"] = 22
    payload["source_status_summary"]["failed_checks"] = 1

    with pytest.raises(ContractError, match="failed checks|VX policy"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_rejects_missing_raw_storage_checks() -> None:
    payload = valid_receipt()
    payload["checks"] = [
        check
        for check in payload["checks"]
        if check["name"] != "canonical_manifest_raw_sample_storage_external"
    ]

    with pytest.raises(ContractError, match="canonical_manifest_raw_sample_storage_external"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_manifest_publish_receipt_requires_storage_layout_blocker() -> None:
    payload = valid_receipt()
    payload["blockers"] = ["missing_external_production_manifest", "missing_canonical_dataset_manifest"]
    payload["source_status_summary"]["blockers"] = list(payload["blockers"])
    payload["source_status_summary"]["blocker_count"] = 2
    for check in payload["checks"]:
        if check["name"] == "canonical_dataset_manifest_exists":
            check["passed"] = True
        if check["name"] == "canonical_dataset_manifest_sha256_recorded":
            check["passed"] = True
        if check["name"] in {
            "canonical_manifest_raw_samples_not_in_git",
            "canonical_manifest_raw_sample_storage_external",
            "canonical_manifest_storage_refs_external",
        }:
            check["passed"] = True
        if check["name"] == "canonical_manifest_storage_refs_match_expected_layout":
            check["passed"] = False
    payload["source_status_summary"]["canonical_dataset_manifest_exists"] = True
    payload["configuration"]["canonical_dataset_manifest_sha256"] = "b" * 64
    payload["summary"]["canonical_dataset_manifest_sha256"] = "b" * 64
    payload["source_status_summary"]["canonical_dataset_manifest_sha256"] = "b" * 64
    payload["source_status_summary"]["canonical_manifest_raw_samples_not_in_git"] = True
    payload["source_status_summary"]["canonical_manifest_raw_sample_storage_external"] = True
    payload["source_status_summary"]["canonical_manifest_storage_refs_external"] = True
    payload["source_status_summary"]["passed_checks"] = 14
    payload["source_status_summary"]["failed_checks"] = 9

    with pytest.raises(ContractError, match="storage ref layout mismatch blocker"):
        validate_wave1_manifest_publish_receipt(payload, Path("memory://receipt.json"))
