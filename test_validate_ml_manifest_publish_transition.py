from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    MANIFEST_PUBLISH_TRANSITION_SCHEMA,
    ContractError,
    validate_contract,
    validate_manifest_publish_transition,
)


def valid_transition() -> dict:
    source_manifest = "D:/ml-data/transition_probe/production/manifest.json"
    return {
        "api_version": "tamandua.io/ml-manifest-publish-transition-probe/v1",
        "kind": "MLManifestPublishTransitionProbe",
        "metadata": {
            "report_id": "test_transition",
            "generated_at": "2026-06-04T20:23:43Z",
            "created_by": "tamandua-ml-manifest-publish-transition-probe",
            "claim_boundary": "No-execution transition proof only. Does not download malware, collect goodware, publish the canonical repo manifest, train models, run inference, or contact live services.",
        },
        "source_status_summary": {
            "simulation_root_outside_repo": True,
            "synthetic_external_manifest_exists": True,
            "next_action_is_post_acquisition_refresh": True,
            "refresh_has_no_execute_guard": True,
            "validation_only_refreshed_without_publish": True,
            "selected_action_type": "refresh_post_acquisition_receipts",
            "selected_package_id": "ml_data_governed_acquisition",
            "selected_wave": 1,
            "selected_priority": 1,
            "selected_execute_guard_env": None,
            "check_count": 5,
            "passed_checks": 5,
            "failed_checks": 0,
            "passed": True,
        },
        "configuration": {
            "simulation_root": "D:/ml-data/transition_probe",
            "source_manifest": source_manifest,
            "status_ref": "status.json",
            "next_action_run_ref": "run.json",
        },
        "passed": True,
        "checks": [
            {"name": "simulation_root_outside_repo", "passed": True, "detail": "D:/ml-data/transition_probe"},
            {"name": "synthetic_external_manifest_exists", "passed": True, "detail": source_manifest},
            {"name": "next_action_is_post_acquisition_refresh", "passed": True, "detail": "refresh_post_acquisition_receipts"},
            {"name": "refresh_has_no_execute_guard", "passed": True, "detail": "None"},
            {"name": "validation_only_refreshed_without_publish", "passed": True, "detail": "returncode=0"},
        ],
        "selected_action": {
            "action_type": "refresh_post_acquisition_receipts",
            "package_id": "ml_data_governed_acquisition",
            "wave": 1,
            "priority": 1,
            "description": "Refresh Wave 1 receipts before manifest publication.",
            "source_artifact": source_manifest,
            "validation_command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_post_acquisition_refresh_launcher.ps1",
            "execute_guard_env": None,
            "claim_boundary": "No-execution post-acquisition refresh only. Raw samples remain outside Git.",
        },
    }


def test_validate_manifest_publish_transition_accepts_valid_contract() -> None:
    validate_manifest_publish_transition(valid_transition(), Path("memory://ml-manifest-publish-transition.json"))


def test_validate_manifest_publish_transition_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-manifest-publish-transition.json"
    report_path.write_text(json.dumps(valid_transition()), encoding="utf-8")

    mode = validate_contract(report_path, MANIFEST_PUBLISH_TRANSITION_SCHEMA, validate_manifest_publish_transition)

    assert mode == "jsonschema+built-in"


def test_validate_manifest_publish_transition_rejects_source_mismatch() -> None:
    payload = copy.deepcopy(valid_transition())
    payload["selected_action"]["source_artifact"] = "D:/other/manifest.json"

    try:
        validate_manifest_publish_transition(payload, Path("memory://ml-manifest-publish-transition.json"))
    except ContractError as exc:
        assert "source_artifact" in str(exc)
    else:
        raise AssertionError("expected source_artifact mismatch to fail")


def test_validate_manifest_publish_transition_rejects_wrong_refresh_command() -> None:
    payload = copy.deepcopy(valid_transition())
    payload["selected_action"]["validation_command"] = "Write-Host ok"

    try:
        validate_manifest_publish_transition(payload, Path("memory://ml-manifest-publish-transition.json"))
    except ContractError as exc:
        assert "post-acquisition refresh launcher" in str(exc)
    else:
        raise AssertionError("expected wrong refresh command to fail")


def test_validate_manifest_publish_transition_rejects_publish_action_bypass() -> None:
    payload = copy.deepcopy(valid_transition())
    payload["selected_action"]["action_type"] = "publish_dataset_manifest"

    try:
        validate_manifest_publish_transition(payload, Path("memory://ml-manifest-publish-transition.json"))
    except ContractError as exc:
        assert "refresh_post_acquisition_receipts" in str(exc)
    else:
        raise AssertionError("expected publish action bypass to fail")


def test_validate_manifest_publish_transition_rejects_passed_mismatch() -> None:
    payload = copy.deepcopy(valid_transition())
    payload["checks"][0]["passed"] = False

    try:
        validate_manifest_publish_transition(payload, Path("memory://ml-manifest-publish-transition.json"))
    except ContractError as exc:
        assert ".passed" in str(exc)
    else:
        raise AssertionError("expected passed mismatch to fail")


def test_validate_manifest_publish_transition_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_transition())
    payload["source_status_summary"]["passed_checks"] = 4

    try:
        validate_manifest_publish_transition(payload, Path("memory://ml-manifest-publish-transition.json"))
    except ContractError as exc:
        assert "source_status_summary.passed_checks" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")
