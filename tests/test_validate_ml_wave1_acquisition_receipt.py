from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    WAVE1_ACQUISITION_RECEIPT_SCHEMA,
    validate_contract,
    validate_wave1_acquisition_receipt,
)


def valid_receipt() -> dict:
    return {
        "api_version": "tamandua.io/ml-wave1-acquisition-receipt/v1",
        "kind": "MLWave1AcquisitionReceipt",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-04T00:00:00+00:00",
            "created_by": "tamandua-ml-wave1-acquisition-receipt",
            "claim_boundary": "No-execution Wave 1 acquisition receipt only. Does not publish manifests.",
        },
        "source_status_summary": {
            "wave1_execution_packet_validated": True,
            "acquisition_readiness_validated": True,
            "wave1_lab_run_intake_validated": True,
            "acquisition_readiness_passed": True,
            "lab_run_intake_ready_for_post_acquisition_refresh": False,
            "acquisition_transcript_present": False,
            "acquisition_transcript_valid": False,
            "acquisition_transcript_validation": "missing",
            "acquisition_transcript_execute_returncode": None,
            "acquisition_transcript_execute_succeeded": False,
            "acquisition_transcript_guarded_run_command_packet_ref": "",
            "acquisition_transcript_acquisition_command_sha256": "",
            "acquisition_transcript_guarded_run_command_packet_sha256": "",
            "acquisition_transcript_stdout_sha256": "",
            "acquisition_transcript_stderr_sha256": "",
            "acquisition_transcript_vx_policy_valid": False,
            "acquisition_transcript_vx_inventory_metadata_only": False,
            "acquisition_transcript_vx_samples_in_training_splits": None,
            "acquisition_transcript_vx_archive_download_guard_env": "",
            "acquisition_transcript_vx_archive_download_guard_must_be_unset": False,
            "expected_vx_inventory_ref": "docs\\benchmarks\\runs\\ml-vx-inthewild-inventory.json",
            "expected_vx_inventory_metadata_only": True,
            "expected_vx_samples_in_training_splits": False,
            "expected_vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "expected_vx_archive_download_guard_must_be_unset": True,
            "production_manifest_outside_repo": True,
            "production_manifest_exists": False,
            "canonical_dataset_manifest_absent_before_publish": True,
            "production_manifest_shape_valid": False,
            "sample_count": 0,
            "train": 0,
            "validation": 0,
            "test": 0,
            "check_count": 12,
            "passed_checks": 5,
            "failed_checks": 7,
            "blocker_count": 3,
            "blockers": [
                "lab_run_intake_not_ready_for_post_acquisition_refresh",
                "missing_external_production_manifest",
                "missing_wave1_acquisition_transcript",
            ],
            "ready_for_manifest_publish": False,
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
        "source": {
            "wave1_execution_packet": "docs/benchmarks/runs/20260604T-ml-wave1-execution-packet.json",
            "wave1_execution_packet_validation": "jsonschema+built-in",
            "wave1_lab_run_intake": "docs/benchmarks/runs/20260604T-ml-wave1-lab-run-intake.json",
            "wave1_lab_run_intake_validation": "jsonschema+built-in",
            "wave1_acquisition_transcript": "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
            "wave1_acquisition_transcript_validation": "missing",
            "acquisition_readiness": "docs/benchmarks/runs/20260604T-ml-acquisition-readiness.json",
            "acquisition_readiness_validation": "jsonschema+built-in",
        },
        "ready_for_manifest_publish": False,
        "blockers": [
            "lab_run_intake_not_ready_for_post_acquisition_refresh",
            "missing_external_production_manifest",
            "missing_wave1_acquisition_transcript",
        ],
        "configuration": {
            "production_manifest": "D:\\treant\\tamandua_ml_lab_data\\production\\manifest.json",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "publish_command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute",
            "publish_guard_env": "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
        },
        "summary": {"sample_count": 0, "train": 0, "validation": 0, "test": 0},
        "checks": [
            {"name": "execution_packet_valid", "passed": True, "detail": ""},
            {"name": "lab_run_intake_ready_for_post_acquisition_refresh", "passed": False, "detail": ""},
            {"name": "acquisition_transcript_present", "passed": False, "detail": ""},
            {"name": "acquisition_transcript_valid", "passed": False, "detail": "transcript absent"},
            {"name": "acquisition_transcript_execute_succeeded", "passed": False, "detail": "{\"returncode\": null}"},
            {"name": "acquisition_transcript_vx_policy_valid", "passed": False, "detail": "{}"},
            {
                "name": "expected_vx_policy_metadata_only_boundary",
                "passed": True,
                "detail": "{\"vx_archive_download_guard_env\": \"TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD\"}",
            },
            {"name": "acquisition_readiness_valid", "passed": True, "detail": ""},
            {"name": "production_manifest_outside_repo", "passed": True, "detail": ""},
            {"name": "production_manifest_exists", "passed": False, "detail": ""},
            {"name": "canonical_dataset_manifest_absent_before_publish", "passed": True, "detail": ""},
            {"name": "production_manifest_shape_valid", "passed": False, "detail": "manifest absent"},
        ],
    }


def test_validate_wave1_acquisition_receipt_accepts_contract() -> None:
    validate_wave1_acquisition_receipt(valid_receipt(), Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "receipt.json"
    report_path.write_text(__import__("json").dumps(valid_receipt()), encoding="utf-8")

    mode = validate_contract(report_path, WAVE1_ACQUISITION_RECEIPT_SCHEMA, validate_wave1_acquisition_receipt)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_acquisition_receipt_rejects_ready_with_failed_check() -> None:
    payload = valid_receipt()
    payload["ready_for_manifest_publish"] = True
    payload["blockers"] = []
    payload["source_status_summary"]["ready_for_manifest_publish"] = True
    payload["source_status_summary"]["blockers"] = []
    payload["source_status_summary"]["blocker_count"] = 0

    with pytest.raises(ContractError, match="failed checks"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_rejects_missing_intake_source() -> None:
    payload = valid_receipt()
    payload["source"].pop("wave1_lab_run_intake")

    with pytest.raises(ContractError, match="wave1_lab_run_intake"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_requires_intake_blocker_when_not_ready() -> None:
    payload = valid_receipt()
    payload["blockers"] = ["missing_external_production_manifest", "missing_wave1_acquisition_transcript"]
    payload["source_status_summary"]["blockers"] = ["missing_external_production_manifest", "missing_wave1_acquisition_transcript"]
    payload["source_status_summary"]["blocker_count"] = 2

    with pytest.raises(ContractError, match="lab run intake blocker"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_rejects_bad_sample_count() -> None:
    payload = valid_receipt()
    payload["summary"]["sample_count"] = 1
    payload["source_status_summary"]["sample_count"] = 1

    with pytest.raises(ContractError, match="sample_count"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_rejects_missing_readiness_source() -> None:
    payload = valid_receipt()
    payload["source"].pop("acquisition_readiness")

    with pytest.raises(ContractError, match="acquisition_readiness"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_rejects_source_status_summary_drift() -> None:
    payload = valid_receipt()
    payload["source_status_summary"]["passed_checks"] = 3

    with pytest.raises(ContractError, match="source_status_summary.passed_checks"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_rejects_vx_policy_summary_drift() -> None:
    payload = valid_receipt()
    payload["source_status_summary"]["acquisition_transcript_vx_policy_valid"] = True
    payload["source_status_summary"]["acquisition_transcript_vx_inventory_metadata_only"] = True
    payload["source_status_summary"]["acquisition_transcript_vx_samples_in_training_splits"] = True
    payload["source_status_summary"]["acquisition_transcript_vx_archive_download_guard_env"] = "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD"
    payload["source_status_summary"]["acquisition_transcript_vx_archive_download_guard_must_be_unset"] = True
    payload["checks"][5]["passed"] = True

    with pytest.raises(ContractError, match="acquisition_transcript_vx_samples_in_training_splits"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_rejects_expected_vx_policy_drift() -> None:
    payload = valid_receipt()
    payload["vx_policy"]["vx_archive_download_guard_must_be_unset"] = False

    with pytest.raises(ContractError, match="vx_archive_download_guard_must_be_unset"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_rejects_expected_vx_summary_drift() -> None:
    payload = valid_receipt()
    payload["source_status_summary"]["expected_vx_inventory_metadata_only"] = False

    with pytest.raises(ContractError, match="expected_vx_inventory_metadata_only"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_requires_expected_vx_check() -> None:
    payload = valid_receipt()
    payload["checks"] = [
        check for check in payload["checks"] if check["name"] != "expected_vx_policy_metadata_only_boundary"
    ]
    payload["source_status_summary"]["check_count"] -= 1
    payload["source_status_summary"]["passed_checks"] -= 1

    with pytest.raises(ContractError, match="expected_vx_policy_metadata_only_boundary"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_requires_missing_transcript_blocker() -> None:
    payload = valid_receipt()
    payload["blockers"] = ["lab_run_intake_not_ready_for_post_acquisition_refresh", "missing_external_production_manifest"]
    payload["source_status_summary"]["blockers"] = [
        "lab_run_intake_not_ready_for_post_acquisition_refresh",
        "missing_external_production_manifest",
    ]
    payload["source_status_summary"]["blocker_count"] = 2

    with pytest.raises(ContractError, match="missing Wave 1 acquisition transcript blocker"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_rejects_missing_transcript_hash_drift() -> None:
    payload = valid_receipt()
    payload["source_status_summary"]["acquisition_transcript_stdout_sha256"] = "a" * 64

    with pytest.raises(ContractError, match="acquisition_transcript_stdout_sha256"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))


def test_validate_wave1_acquisition_receipt_requires_hashes_when_transcript_valid() -> None:
    payload = valid_receipt()
    summary = payload["source_status_summary"]
    summary["lab_run_intake_ready_for_post_acquisition_refresh"] = True
    summary["acquisition_transcript_present"] = True
    summary["acquisition_transcript_valid"] = True
    summary["acquisition_transcript_validation"] = "jsonschema+built-in"
    summary["acquisition_transcript_execute_returncode"] = 0
    summary["acquisition_transcript_execute_succeeded"] = True
    summary["acquisition_transcript_vx_policy_valid"] = True
    summary["acquisition_transcript_vx_inventory_metadata_only"] = True
    summary["acquisition_transcript_vx_samples_in_training_splits"] = False
    summary["acquisition_transcript_vx_archive_download_guard_env"] = "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD"
    summary["acquisition_transcript_vx_archive_download_guard_must_be_unset"] = True
    summary["acquisition_transcript_guarded_run_command_packet_sha256"] = "a" * 64
    summary["acquisition_transcript_stdout_sha256"] = ""
    summary["acquisition_transcript_stderr_sha256"] = "c" * 64
    payload["source"]["wave1_acquisition_transcript_validation"] = "jsonschema+built-in"
    for check in payload["checks"]:
        if check["name"] in {
            "lab_run_intake_ready_for_post_acquisition_refresh",
            "acquisition_transcript_present",
            "acquisition_transcript_valid",
            "acquisition_transcript_execute_succeeded",
            "acquisition_transcript_vx_policy_valid",
        }:
            check["passed"] = True
    summary["passed_checks"] = sum(1 for check in payload["checks"] if check["passed"] is True)
    summary["failed_checks"] = sum(1 for check in payload["checks"] if check["passed"] is not True)

    with pytest.raises(ContractError, match="acquisition_transcript_stdout_sha256"):
        validate_wave1_acquisition_receipt(payload, Path("memory://receipt.json"))
