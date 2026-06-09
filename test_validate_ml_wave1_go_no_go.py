from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    WAVE1_GO_NO_GO_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_go_no_go,
)
from test_validate_ml_wave2_ml1_readiness import GOAL_SNAPSHOT  # noqa: E402


def valid_wave1_go_no_go() -> dict:
    checks = [
        {"name": "acquisition_readiness_valid", "passed": True, "detail": "readiness.json"},
        {"name": "acquisition_dry_run_valid", "passed": True, "detail": "dry-run.json"},
        {"name": "execution_status_valid", "passed": True, "detail": "status.json"},
        {"name": "manifest_publish_transition_valid", "passed": True, "detail": "transition.json"},
        {"name": "dataset_manifest_publish_probe_valid", "passed": True, "detail": "publish-probe.json"},
        {"name": "wave1_real_acquisition_launcher_exists", "passed": True, "detail": "wave_1_real_acquisition_launcher.ps1"},
        {"name": "canonical_dataset_manifest_absent", "passed": True, "detail": "ml-prod-candidate-v1-dataset-manifest.json"},
        {
            "name": "next_action_is_guarded_acquisition",
            "passed": True,
            "detail": '{"execute_guard_env":"TAMANDUA_ALLOW_ML_REAL_ACQUISITION"}',
        },
        {
            "name": "vx_policy_metadata_only_boundary",
            "passed": True,
            "detail": (
                '{"vx_archive_download_guard_env":"TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",'
                '"vx_archive_download_guard_present":false,'
                '"vx_download_authorized_by_go_no_go":false,'
                '"vx_inventory_metadata_only":true,'
                '"vx_samples_allowed_in_training_splits":false,'
                '"vx_guard_must_remain_unset_for_wave1_acquisition":true}'
            ),
        },
    ]
    return {
        "api_version": "tamandua.io/ml-wave1-go-no-go/v1",
        "kind": "MLWave1GoNoGoProbe",
        "metadata": {
            "report_id": "test_wave1_go_no_go",
            "generated_at": "2026-06-04T20:34:34Z",
            "created_by": "tamandua-ml-wave1-go-no-go-probe",
            "claim_boundary": "No-execution Wave 1 go/no-go summary only. Does not download malware, collect goodware, publish the canonical dataset manifest, train models, run inference, or contact live services.",
        },
        "source_status_summary": {
            **GOAL_SNAPSHOT,
            "acquisition_readiness_valid": True,
            "acquisition_dry_run_valid": True,
            "execution_status_valid": True,
            "manifest_publish_transition_valid": True,
            "dataset_manifest_publish_probe_valid": True,
            "wave1_real_acquisition_launcher_exists": True,
            "canonical_dataset_manifest_absent": True,
            "next_action_is_guarded_acquisition": True,
            "vx_policy_metadata_only_boundary": True,
            "check_count": 9,
            "passed_checks": 9,
            "failed_checks": 0,
            "go_for_guarded_real_acquisition": True,
            "ml1_blocked_until_canonical_manifest": True,
            "canonical_manifest_path": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_present": False,
            "vx_download_authorized_by_go_no_go": False,
            "vx_inventory_metadata_only": True,
            "vx_samples_allowed_in_training_splits": False,
            "vx_guard_must_remain_unset_for_wave1_acquisition": True,
        },
        "vx_policy": {
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_present": False,
            "vx_download_authorized_by_go_no_go": False,
            "vx_inventory_metadata_only": True,
            "vx_samples_allowed_in_training_splits": False,
            "vx_guard_must_remain_unset_for_wave1_acquisition": True,
        },
        "configuration": {
            "readiness_ref": "readiness.json",
            "dry_run_ref": "dry-run.json",
            "execution_status_ref": "status.json",
            "manifest_publish_transition_ref": "transition.json",
            "dataset_manifest_publish_probe_ref": "publish-probe.json",
            "handoff_dir": "handoff",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
        },
        "go_for_guarded_real_acquisition": True,
        "ml1_blocked_until_canonical_manifest": True,
        "checks": checks,
        "next_operator_action": (
            "Run wave_1_real_acquisition_launcher.ps1 -Execute only inside the isolated lab with "
            "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1', save the structured transcript, rerun "
            "wave_1_post_acquisition_refresh_launcher.ps1, and publish the sanitized canonical dataset manifest "
            "only after the acquisition receipt is ready. Keep TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD unset; "
            "vx/InTheWild stays metadata-only for Wave 1 acquisition."
        ),
    }


def test_validate_wave1_go_no_go_accepts_valid_contract() -> None:
    validate_wave1_go_no_go(valid_wave1_go_no_go(), Path("memory://ml-wave1-go-no-go.json"))


def test_validate_wave1_go_no_go_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-wave1-go-no-go.json"
    report_path.write_text(json.dumps(valid_wave1_go_no_go()), encoding="utf-8")

    mode = validate_contract(report_path, WAVE1_GO_NO_GO_SCHEMA, validate_wave1_go_no_go)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_go_no_go_rejects_go_mismatch() -> None:
    payload = copy.deepcopy(valid_wave1_go_no_go())
    payload["checks"][0]["passed"] = False
    payload["source_status_summary"]["acquisition_readiness_valid"] = False
    payload["source_status_summary"]["passed_checks"] = 8
    payload["source_status_summary"]["failed_checks"] = 1

    try:
        validate_wave1_go_no_go(payload, Path("memory://ml-wave1-go-no-go.json"))
    except ContractError as exc:
        assert "go_for_guarded_real_acquisition" in str(exc)
    else:
        raise AssertionError("expected go mismatch to fail")


def test_validate_wave1_go_no_go_rejects_unblocked_ml1_on_go() -> None:
    payload = copy.deepcopy(valid_wave1_go_no_go())
    payload["ml1_blocked_until_canonical_manifest"] = False
    payload["source_status_summary"]["ml1_blocked_until_canonical_manifest"] = False

    try:
        validate_wave1_go_no_go(payload, Path("memory://ml-wave1-go-no-go.json"))
    except ContractError as exc:
        assert "ml1_blocked_until_canonical_manifest" in str(exc)
    else:
        raise AssertionError("expected unblocked ML-1 go report to fail")


def test_validate_wave1_go_no_go_rejects_missing_acquisition_guard() -> None:
    payload = copy.deepcopy(valid_wave1_go_no_go())
    guard_check = next(check for check in payload["checks"] if check["name"] == "next_action_is_guarded_acquisition")
    guard_check["detail"] = '{"execute_guard_env":"TAMANDUA_ALLOW_OTHER"}'

    try:
        validate_wave1_go_no_go(payload, Path("memory://ml-wave1-go-no-go.json"))
    except ContractError as exc:
        assert "acquisition guard" in str(exc)
    else:
        raise AssertionError("expected missing acquisition guard to fail")


def test_validate_wave1_go_no_go_rejects_publish_without_refresh() -> None:
    payload = copy.deepcopy(valid_wave1_go_no_go())
    payload["next_operator_action"] = (
        "Run wave_1_real_acquisition_launcher.ps1 -Execute only inside the isolated lab with "
        "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1', then publish the sanitized canonical dataset manifest."
    )

    try:
        validate_wave1_go_no_go(payload, Path("memory://ml-wave1-go-no-go.json"))
    except ContractError as exc:
        assert "post-acquisition refresh" in str(exc)
    else:
        raise AssertionError("expected missing post-acquisition refresh to fail")


def test_validate_wave1_go_no_go_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_wave1_go_no_go())
    payload["source_status_summary"]["passed_checks"] = 7

    try:
        validate_wave1_go_no_go(payload, Path("memory://ml-wave1-go-no-go.json"))
    except ContractError as exc:
        assert "source_status_summary.passed_checks" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_wave1_go_no_go_rejects_vx_authorization() -> None:
    payload = copy.deepcopy(valid_wave1_go_no_go())
    payload["vx_policy"]["vx_download_authorized_by_go_no_go"] = True

    try:
        validate_wave1_go_no_go(payload, Path("memory://ml-wave1-go-no-go.json"))
    except ContractError as exc:
        assert "vx_policy.vx_download_authorized_by_go_no_go" in str(exc)
    else:
        raise AssertionError("expected VX authorization drift to fail")


def test_validate_wave1_go_no_go_rejects_vx_summary_drift() -> None:
    payload = copy.deepcopy(valid_wave1_go_no_go())
    payload["source_status_summary"]["vx_inventory_metadata_only"] = False

    try:
        validate_wave1_go_no_go(payload, Path("memory://ml-wave1-go-no-go.json"))
    except ContractError as exc:
        assert "source_status_summary.vx_inventory_metadata_only" in str(exc)
    else:
        raise AssertionError("expected VX summary drift to fail")
