from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    ACQUISITION_READINESS_SCHEMA,
    ContractError,
    validate_acquisition_readiness,
    validate_contract,
)


def valid_readiness() -> dict:
    checks = [
        {"name": "data_root_set", "passed": True, "detail": "D:/ml-data"},
        {"name": "data_root_outside_repo", "passed": True, "detail": "D:/ml-data"},
        {"name": "production_dir_writeable", "passed": True, "detail": "D:/ml-data/production"},
        {"name": "raw_dir_writeable", "passed": True, "detail": "D:/ml-data/raw"},
        {"name": "free_space_gib", "passed": True, "detail": "100 GiB free", "free_gib": 100.0, "min_free_gib": 50},
        {"name": "acquisition_dry_run_exists", "passed": True, "detail": "dry-run.json"},
        {"name": "dry_run_contract_shape_valid", "passed": True, "detail": "dry-run api/kind present and VX inventory configured"},
        {"name": "dry_run_output_matches_data_root", "passed": True, "detail": "matches"},
        {"name": "dry_run_safety_no_downloads", "passed": True, "detail": "safe"},
        {
            "name": "dry_run_vx_policy_metadata_only_boundary",
            "passed": True,
            "detail": (
                '{"vx_inventory_ref":"vx.json","vx_inventory_metadata_only":true,'
                '"vx_samples_in_training_splits":false,'
                '"vx_archive_download_guard_env":"TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",'
                '"vx_archive_download_guard_must_be_unset":true}'
            ),
        },
        {"name": "vx_inventory_metadata_present", "passed": True, "detail": "archives=10"},
        {"name": "vx_inventory_contract_shape_valid", "passed": True, "detail": "VX inventory api/kind present with at least one archive"},
        {"name": "status_next_action_is_acquisition", "passed": True, "detail": "ml_data_governed_acquisition"},
        {"name": "production_manifest_absent_before_real_run", "passed": True, "detail": "manifest.json"},
        {"name": "acquisition_guard_absent_before_real_run", "passed": True, "detail": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION"},
        {"name": "manifest_publish_guard_absent_before_real_run", "passed": True, "detail": "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH"},
        {
            "name": "malware_bazaar_auth_key_present",
            "passed": True,
            "detail": "TAMANDUA_MALWAREBAZAAR_AUTH_KEY=<redacted-present-or-absent>",
        },
        {
            "name": "real_acquisition_transcript_absent_before_real_run",
            "passed": True,
            "detail": "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
        },
        {
            "name": "canonical_dataset_manifest_absent_before_real_run",
            "passed": True,
            "detail": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
        },
    ]
    return {
        "api_version": "tamandua.io/ml-acquisition-readiness/v1",
        "kind": "MLAcquisitionReadinessProbe",
        "metadata": {
            "report_id": "test_readiness",
            "generated_at": "2026-06-04T20:06:16Z",
            "created_by": "tamandua-ml-acquisition-readiness-probe",
            "claim_boundary": "No-execution acquisition readiness only. Does not download malware, collect goodware, train models, run inference, or contact external services.",
        },
        "source_status_summary": {
            "data_root_set": True,
            "data_root_outside_repo": True,
            "production_dir_writeable": True,
            "raw_dir_writeable": True,
            "free_space_gib": 100.0,
            "min_free_gib": 50,
            "free_space_meets_minimum": True,
            "acquisition_dry_run_exists": True,
            "dry_run_contract_shape_valid": True,
            "dry_run_output_matches_data_root": True,
            "dry_run_safety_no_downloads": True,
            "dry_run_vx_policy_metadata_only_boundary": True,
            "vx_inventory_ref": "vx.json",
            "vx_inventory_metadata_only": True,
            "vx_samples_in_training_splits": False,
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_must_be_unset": True,
            "vx_inventory_metadata_present": True,
            "vx_inventory_contract_shape_valid": True,
            "status_next_action_is_acquisition": True,
            "production_manifest_absent_before_real_run": True,
            "acquisition_guard_absent_before_real_run": True,
            "manifest_publish_guard_absent_before_real_run": True,
            "malware_bazaar_auth_key_env": "TAMANDUA_MALWAREBAZAAR_AUTH_KEY",
            "malware_bazaar_auth_key_present": True,
            "real_acquisition_transcript_absent_before_real_run": True,
            "canonical_dataset_manifest_absent_before_real_run": True,
            "check_count": 19,
            "passed_checks": 19,
            "failed_checks": 0,
            "passed": True,
        },
        "vx_policy": {
            "vx_inventory_ref": "vx.json",
            "vx_inventory_metadata_only": True,
            "vx_samples_in_training_splits": False,
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_must_be_unset": True,
            "operator_note": (
                "Wave 1 dry-run may validate VX inventory metadata as holdout_candidate context only. "
                "VX archive downloads require a separate approved run and must not be enabled here."
            ),
        },
        "configuration": {
            "data_root": "D:/ml-data",
            "production_dir": "D:/ml-data/production",
            "raw_dir": "D:/ml-data/raw",
            "dry_run_ref": "dry-run.json",
            "vx_inventory_ref": "vx.json",
            "execution_status_ref": "status.json",
            "real_acquisition_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
            "manifest_publish_guard_env": "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
            "malware_bazaar_auth_key_env": "TAMANDUA_MALWAREBAZAAR_AUTH_KEY",
            "real_acquisition_transcript": "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "min_free_gib": 50,
        },
        "passed": True,
        "checks": checks,
}


def valid_vx_inventory() -> dict:
    return {
        "api_version": "tamandua.io/ml-vx-underground-inventory/v1",
        "kind": "VxUndergroundInTheWildInventory",
        "metadata": {
            "created_at": "2026-06-04T19:02:00Z",
            "listing_url": "https://vx-underground.org/Samples/InTheWild%20Collection/Downloadable%20Releases",
            "collection_method": "browser_observed_after_script_fetch_403",
            "script_fetch_status": "blocked_http_403",
            "archive_downloaded": False,
            "inventory_role": "holdout_candidate",
            "used_in_training": False,
            "raw_archives_in_repo": False,
            "archive_extraction_performed": False,
            "endpoint_exposed": False,
            "claim_boundary": "Inventory metadata only. It does not download, extract, execute, classify, or train on malware samples.",
        },
        "archives": [
            {
                "release_id": "0161",
                "filename": "InTheWild.0161.7z",
                "url": "",
                "listed_size": "33,461.54 MB",
                "listed_modified": "2025/04/23",
                "source": "vx-underground-inthewild-browser-observed",
            }
        ],
    }


def valid_dry_run() -> dict:
    return {
        "api_version": "tamandua.io/ml-production-acquisition-dry-run/v1",
        "kind": "MLProductionAcquisitionDryRun",
        "metadata": {
            "created_at": "2026-06-04T19:02:31Z",
            "dataset_version": "1.0.0",
            "claim_boundary": "Dry-run plan only. Does not download malware, collect goodware, validate samples, create train/val/test splits, or prove dataset quality.",
        },
        "configuration": {
            "output_dir": "D:/ml-data/production",
            "output_dir_inside_current_repo": False,
            "samples_per_class": 10000,
            "vt_validation": "disabled",
            "resume": True,
            "vx_inventory": "vx.json",
            "malware_bazaar_auth_key_env": "TAMANDUA_MALWAREBAZAAR_AUTH_KEY",
            "malware_bazaar_auth_key_present": True,
        },
        "safety_gates": {
            "requires_isolated_lab": True,
            "requires_output_outside_git": True,
            "downloads_raw_malware": False,
            "collects_goodware": False,
            "executes_samples": False,
        },
        "planned_phases": [
            {"phase": 1, "name": "malware_bazaar_acquisition", "executed_in_dry_run": False},
            {"phase": 2, "name": "goodware_collection", "executed_in_dry_run": False},
            {"phase": 3, "name": "sample_validation", "executed_in_dry_run": False},
            {"phase": 4, "name": "stratified_split", "executed_in_dry_run": False},
            {"phase": 5, "name": "manifest_generation", "executed_in_dry_run": False},
        ],
        "holdout_sources": [
            {
                "source_id": "vx-underground-inthewild",
                "role": "holdout_candidate",
                "manifest_ref": "vx.json",
                "used_in_training": False,
                "claim_boundary": "Metadata reference only. VX Underground samples are not included in train/validation/test splits.",
                "archive_count": 1,
                "api_version": "tamandua.io/ml-vx-underground-inventory/v1",
            }
        ],
        "vx_policy": {
            "vx_inventory_ref": "vx.json",
            "vx_inventory_metadata_only": True,
            "vx_samples_in_training_splits": False,
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_must_be_unset": True,
            "operator_note": (
                "Wave 1 dry-run may validate VX inventory metadata as holdout_candidate context only. "
                "VX archive downloads require a separate approved run and must not be enabled here."
            ),
        },
        "next_real_command": "python apps/tamandua_ml/scripts/download_production_dataset.py --output D:/ml-data/production --samples-per-class 10000 --skip-vt-validation --resume --yes",
    }


def write_readiness_refs(tmp_path: Path) -> dict:
    (tmp_path / "vx.json").write_text(json.dumps(valid_vx_inventory()), encoding="utf-8")
    (tmp_path / "dry-run.json").write_text(json.dumps(valid_dry_run()), encoding="utf-8")
    payload = valid_readiness()
    payload["configuration"]["dry_run_ref"] = "dry-run.json"
    payload["configuration"]["vx_inventory_ref"] = "vx.json"
    return payload


def test_validate_acquisition_readiness_accepts_valid_contract() -> None:
    validate_acquisition_readiness(valid_readiness(), Path("memory://ml-acquisition-readiness.json"))


def test_validate_acquisition_readiness_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-acquisition-readiness.json"
    report_path.write_text(json.dumps(write_readiness_refs(tmp_path)), encoding="utf-8")

    mode = validate_contract(report_path, ACQUISITION_READINESS_SCHEMA, validate_acquisition_readiness)

    assert mode == "jsonschema+built-in"


def test_validate_acquisition_readiness_rejects_passed_mismatch() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["checks"][0]["passed"] = False

    try:
        validate_acquisition_readiness(payload, Path("memory://ml-acquisition-readiness.json"))
    except ContractError as exc:
        assert ".passed" in str(exc)
    else:
        raise AssertionError("expected passed mismatch to fail")


def test_validate_acquisition_readiness_rejects_manifest_present_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    manifest_check = next(check for check in payload["checks"] if check["name"] == "production_manifest_absent_before_real_run")
    manifest_check["passed"] = False

    try:
        validate_acquisition_readiness(payload, Path("memory://ml-acquisition-readiness.json"))
    except ContractError as exc:
        assert ".passed" in str(exc)
    else:
        raise AssertionError("expected manifest-present readiness report to fail")


def test_validate_acquisition_readiness_rejects_guard_present_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    guard_check = next(check for check in payload["checks"] if check["name"] == "acquisition_guard_absent_before_real_run")
    guard_check["passed"] = False

    try:
        validate_acquisition_readiness(payload, Path("memory://ml-acquisition-readiness.json"))
    except ContractError as exc:
        assert ".passed" in str(exc)
    else:
        raise AssertionError("expected guard-present readiness report to fail")


def test_validate_acquisition_readiness_rejects_noncanonical_transcript_ref() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["configuration"]["real_acquisition_transcript"] = "transcript.json"

    try:
        validate_acquisition_readiness(payload, Path("memory://ml-acquisition-readiness.json"))
    except ContractError as exc:
        assert "real_acquisition_transcript" in str(exc)
    else:
        raise AssertionError("expected noncanonical transcript ref to fail")


def test_validate_acquisition_readiness_rejects_low_free_space() -> None:
    payload = copy.deepcopy(valid_readiness())
    free_check = next(check for check in payload["checks"] if check["name"] == "free_space_gib")
    free_check["free_gib"] = 1.0
    payload["source_status_summary"]["free_space_gib"] = 1.0

    try:
        validate_acquisition_readiness(payload, Path("memory://ml-acquisition-readiness.json"))
    except ContractError as exc:
        assert "free_space_gib" in str(exc)
    else:
        raise AssertionError("expected low free space to fail")


def test_validate_acquisition_readiness_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["source_status_summary"]["passed_checks"] = 12

    try:
        validate_acquisition_readiness(payload, Path("memory://ml-acquisition-readiness.json"))
    except ContractError as exc:
        assert "source_status_summary.passed_checks" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_acquisition_readiness_rejects_vx_training_split_drift() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["vx_policy"]["vx_samples_in_training_splits"] = True

    try:
        validate_acquisition_readiness(payload, Path("memory://ml-acquisition-readiness.json"))
    except ContractError as exc:
        assert "vx_samples_in_training_splits" in str(exc)
    else:
        raise AssertionError("expected VX training split drift to fail")


def test_validate_acquisition_readiness_rejects_vx_summary_drift() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["source_status_summary"]["vx_archive_download_guard_must_be_unset"] = False

    try:
        validate_acquisition_readiness(payload, Path("memory://ml-acquisition-readiness.json"))
    except ContractError as exc:
        assert "source_status_summary.vx_archive_download_guard_must_be_unset" in str(exc)
    else:
        raise AssertionError("expected VX source summary drift to fail")
