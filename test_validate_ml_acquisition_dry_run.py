from __future__ import annotations

import copy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import ContractError, validate_acquisition_dry_run


def valid_dry_run() -> dict:
    return {
        "api_version": "tamandua.io/ml-production-acquisition-dry-run/v1",
        "kind": "MLProductionAcquisitionDryRun",
        "metadata": {
            "created_at": "2026-06-04T19:02:31Z",
            "dataset_version": "1.0.0",
            "claim_boundary": (
                "Dry-run plan only. Does not download malware, collect goodware, "
                "validate samples, create train/val/test splits, or prove dataset quality."
            ),
        },
        "configuration": {
            "output_dir": "D:/treant/tamandua_ml_lab_data/production",
            "output_dir_inside_current_repo": False,
            "samples_per_class": 10000,
            "vt_validation": "disabled",
            "resume": True,
            "vx_inventory": "docs/benchmarks/runs/ml-vx-inthewild-inventory.json",
            "malware_bazaar_auth_key_env": "TAMANDUA_MALWAREBAZAAR_AUTH_KEY",
            "malware_bazaar_auth_key_present": False,
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
                "manifest_ref": "docs/benchmarks/runs/ml-vx-inthewild-inventory.json",
                "used_in_training": False,
                "claim_boundary": (
                    "Metadata reference only. VX Underground samples are not included in "
                    "train/validation/test splits."
                ),
                "archive_count": 10,
                "api_version": "tamandua.io/ml-vx-underground-inventory/v1",
            }
        ],
        "vx_policy": {
            "vx_inventory_ref": "docs/benchmarks/runs/ml-vx-inthewild-inventory.json",
            "vx_inventory_metadata_only": True,
            "vx_samples_in_training_splits": False,
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_must_be_unset": True,
            "operator_note": (
                "Wave 1 dry-run may validate VX inventory metadata as holdout_candidate "
                "context only. VX archive downloads require a separate approved run and "
                "must not be enabled here."
            ),
        },
        "next_real_command": (
            "python apps/tamandua_ml/scripts/download_production_dataset.py "
            "--output D:/treant/tamandua_ml_lab_data/production --samples-per-class 10000 --skip-vt-validation --resume --yes"
        ),
    }


def test_validate_acquisition_dry_run_accepts_valid_contract() -> None:
    validate_acquisition_dry_run(valid_dry_run(), Path("memory://acquisition-dry-run.json"))


def test_validate_acquisition_dry_run_tracks_malware_bazaar_auth_without_secret() -> None:
    payload = valid_dry_run()
    payload["configuration"]["malware_bazaar_auth_key_present"] = True
    payload["next_real_command"] += " --malware-bazaar-auth-key secret"

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "next_real_command" in str(exc) or "auth" in str(exc).lower()
    else:
        raise AssertionError("expected secret-bearing next_real_command to fail")


def test_validate_acquisition_dry_run_rejects_download_claim() -> None:
    payload = valid_dry_run()
    payload["safety_gates"]["downloads_raw_malware"] = True

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "downloads_raw_malware" in str(exc)
    else:
        raise AssertionError("expected downloads_raw_malware=true to fail")


def test_validate_acquisition_dry_run_rejects_vx_training_use() -> None:
    payload = valid_dry_run()
    payload["holdout_sources"][0]["used_in_training"] = True

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "used_in_training" in str(exc)
    else:
        raise AssertionError("expected VX used_in_training=true to fail")


def test_validate_acquisition_dry_run_rejects_mismatched_vx_manifest_ref() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["holdout_sources"][0]["manifest_ref"] = "docs/benchmarks/runs/other-vx.json"

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "manifest_ref" in str(exc)
    else:
        raise AssertionError("expected mismatched VX manifest_ref to fail")


def test_validate_acquisition_dry_run_rejects_mismatched_vx_policy_ref() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["vx_policy"]["vx_inventory_ref"] = "docs/benchmarks/runs/other-vx.json"

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "vx_inventory_ref" in str(exc)
    else:
        raise AssertionError("expected mismatched VX policy ref to fail")


def test_validate_acquisition_dry_run_rejects_enabled_vx_archive_guard() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["vx_policy"]["vx_archive_download_guard_must_be_unset"] = False

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "vx_archive_download_guard_must_be_unset" in str(exc)
    else:
        raise AssertionError("expected VX archive guard drift to fail")


def test_validate_acquisition_dry_run_rejects_unreadable_vx_inventory_summary() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["holdout_sources"][0]["read_error"] = "failed to read"

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "read_error" in str(exc)
    else:
        raise AssertionError("expected VX read_error to fail")


def test_validate_acquisition_dry_run_rejects_vx_source_without_configuration() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["configuration"]["vx_inventory"] = None

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "configuration.vx_inventory" in str(exc)
    else:
        raise AssertionError("expected VX holdout without configuration.vx_inventory to fail")


def test_validate_acquisition_dry_run_rejects_dry_run_next_command() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["next_real_command"] += " --dry-run-plan"

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "next_real_command" in str(exc)
    else:
        raise AssertionError("expected dry-run next_real_command to fail")


def test_validate_acquisition_dry_run_rejects_non_resumable_plan() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["configuration"]["resume"] = False

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "configuration.resume" in str(exc)
    else:
        raise AssertionError("expected non-resumable dry-run to fail")


def test_validate_acquisition_dry_run_rejects_non_resumable_next_command() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["next_real_command"] = payload["next_real_command"].replace(" --resume", "")

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "next_real_command" in str(exc)
    else:
        raise AssertionError("expected next_real_command without --resume to fail")


def test_validate_acquisition_dry_run_rejects_interactive_next_command() -> None:
    payload = copy.deepcopy(valid_dry_run())
    payload["next_real_command"] = payload["next_real_command"].replace(" --yes", "")

    try:
        validate_acquisition_dry_run(payload, Path("memory://acquisition-dry-run.json"))
    except ContractError as exc:
        assert "next_real_command" in str(exc)
    else:
        raise AssertionError("expected next_real_command without --yes to fail")
