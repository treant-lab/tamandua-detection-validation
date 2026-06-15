from __future__ import annotations

import copy
import hashlib
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
    WAVE1_OPERATOR_LAUNCH_BRIEF_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_operator_launch_brief,
)
from test_validate_ml_wave2_ml1_readiness import GOAL_SNAPSHOT  # noqa: E402


def stable_sha256(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


NEXT_ACTION_SAFETY = {
    "command_validation_only": True,
    "execute_guard_absent": True,
    "selected_action_only": True,
    "no_success_stderr": True,
    "no_real_operation_evidence": True,
    "guarded_command_printed": True,
    "no_real_acquisition_evidence": True,
    "guarded_would_run_command_printed": True,
    "data_root_outside_repo": True,
}


def valid_wave1_operator_launch_brief() -> dict:
    payload = {
        "api_version": "tamandua.io/ml-wave1-operator-launch-brief/v1",
        "kind": "MLWave1OperatorLaunchBrief",
        "metadata": {
            "report_id": "test_wave1_operator_launch_brief",
            "generated_at": "2026-06-04T21:30:00Z",
            "created_by": "tamandua-ml-wave1-operator-launch-brief",
            "claim_boundary": "No-execution operator launch brief only. Does not set acquisition guards, download malware, collect goodware, publish manifests, train models, run inference, or contact live services.",
        },
        "source_status_summary": {
            **GOAL_SNAPSHOT,
            "execution_status_validated": True,
            "acquisition_readiness_validated": True,
            "acquisition_dry_run_validated": True,
            "wave1_go_no_go_validated": True,
            "wave1_execute_guard_validated": True,
            "next_action_run_validated": True,
            "ml_lab_standby_readiness_validated": True,
            "ml_lab_standby_guards_unset": True,
            "ml_lab_standby_required_unset_guard_env": [
                "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
                "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
                "TAMANDUA_ALLOW_ML_TRAINING",
                "TAMANDUA_ALLOW_ML_PARITY",
                "TAMANDUA_ALLOW_ML_SERVICE_BENCH",
                "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY",
                "TAMANDUA_ALLOW_ML_HOLDOUT",
                "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            ],
            "ml_lab_standby_enabled_guards": [],
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_present": False,
            "vx_download_authorized_by_operator_brief": False,
            "vx_inventory_metadata_only": True,
            "vx_samples_allowed_in_training_splits": False,
            "vx_guard_must_remain_unset_for_wave1_acquisition": True,
            "ml_local_training_readiness_validated": True,
            "next_action_run_mode": "validation_only",
            "next_action_run_returncode": 0,
            "next_action_run_package_id": "ml_data_governed_acquisition",
            "next_action_run_wave": 1,
            "next_action_validation_scope_selected": True,
            "next_action_safety_assertions": dict(NEXT_ACTION_SAFETY),
            "next_action_safety_assertions_passed": True,
            "check_count": 31,
            "passed_checks": 31,
            "failed_checks": 0,
            "operator_steps": 5,
            "operator_sequence_modes": [
                "prelab_validation",
                "validation_only",
                "execute",
                "post_acquisition_refresh",
                "post_acquisition_publish",
            ],
            "operator_sequence_modes_sha256": "",
            "operator_command_modes": [
                "execute",
                "post_acquisition_publish",
                "post_acquisition_refresh",
                "prelab_validation",
                "validation_only",
            ],
            "operator_commands_by_mode": {
                "prelab_validation": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/ml_prelab_validation_launcher.ps1'",
                "validation_only": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1'",
                "execute": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1' -Execute",
                "post_acquisition_refresh": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_post_acquisition_refresh_launcher.ps1'",
                "post_acquisition_publish": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute",
            },
            "operator_commands_by_mode_sha256": "",
            "configuration_paths": {
                "data_root": "D:/tamandua_ml_lab_data",
                "production_manifest": "D:/tamandua_ml_lab_data/production/manifest.json",
                "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
                "lab_transcript_template": "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
                "prelab_validation_launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/ml_prelab_validation_launcher.ps1",
                "launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1",
                "post_acquisition_refresh_launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_post_acquisition_refresh_launcher.ps1",
                "publish_launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1",
            },
            "operator_sequence_valid": True,
            "prelab_has_data_root": True,
            "validation_command_no_execute": True,
            "execute_requires_real_acquisition_guard": True,
            "execute_command_has_execute": True,
            "refresh_command_no_execute": True,
            "publish_requires_manifest_guard": True,
            "publish_validation_no_execute": True,
            "publish_command_has_execute": True,
            "validation_only_command_count": 3,
            "guarded_execute_command_count": 2,
            "guarded_required_env_count": 2,
            "command_guard_boundary_preserved": True,
            "data_root_outside_repo": True,
            "production_manifest_absent": True,
            "canonical_dataset_manifest_absent": True,
            "ready_for_operator": True,
        },
        "vx_policy": {
            "vx_archive_download_guard_env": "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            "vx_archive_download_guard_present": False,
            "vx_download_authorized_by_this_brief": False,
            "vx_inventory_metadata_only": True,
            "vx_samples_allowed_in_training_splits": False,
            "vx_guard_must_remain_unset_for_wave1_acquisition": True,
        },
        "configuration": {
            "status_ref": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
            "readiness_ref": "docs/benchmarks/runs/20260604T-ml-acquisition-readiness.json",
            "dry_run_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-acquisition-dry-run.json",
            "go_no_go_ref": "docs/benchmarks/runs/20260604T-ml-wave1-go-no-go.json",
            "execute_guard_ref": "docs/benchmarks/runs/20260604T-ml-wave1-execute-guard-probe.json",
            "next_action_run_ref": "docs/benchmarks/runs/20260604T-ml-prelab-next-action-validation.run.json",
            "ml_lab_standby_readiness_ref": "docs/benchmarks/runs/20260604T-ml-lab-standby-readiness.json",
            "ml_local_training_readiness_ref": "docs/benchmarks/runs/20260604T-ml-local-training-readiness.json",
            "prelab_validation_launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/ml_prelab_validation_launcher.ps1",
            "launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1",
            "post_acquisition_refresh_launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_post_acquisition_refresh_launcher.ps1",
            "publish_launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1",
            "lab_transcript_template": "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
            "data_root": "D:/tamandua_ml_lab_data",
            "production_manifest": "D:/tamandua_ml_lab_data/production/manifest.json",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
        },
        "ready_for_operator": True,
        "checks": [
            {"name": "execution_status_valid", "passed": True, "detail": "status"},
            {"name": "acquisition_readiness_valid", "passed": True, "detail": "readiness"},
            {"name": "acquisition_dry_run_valid", "passed": True, "detail": "dry-run"},
            {"name": "wave1_go_no_go_valid", "passed": True, "detail": "go/no-go"},
            {"name": "wave1_execute_guard_valid", "passed": True, "detail": "guard"},
            {"name": "next_action_run_valid", "passed": True, "detail": "next-action"},
            {"name": "ml_lab_standby_readiness_valid", "passed": True, "detail": "lab standby"},
            {"name": "ml_lab_standby_guards_unset", "passed": True, "detail": "enabled_guards=[]"},
            {"name": "vx_policy_metadata_only_boundary", "passed": True, "detail": "vx metadata-only"},
            {"name": "ml_local_training_readiness_valid", "passed": True, "detail": "local training"},
            {"name": "next_action_is_wave1_guarded_acquisition", "passed": True, "detail": "guarded"},
            {"name": "next_action_run_is_selected_wave1_acquisition", "passed": True, "detail": "selected"},
            {"name": "next_action_safety_command_validation_only", "passed": True, "detail": "true"},
            {"name": "next_action_safety_execute_guard_absent", "passed": True, "detail": "true"},
            {"name": "next_action_safety_selected_action_only", "passed": True, "detail": "true"},
            {"name": "next_action_safety_no_success_stderr", "passed": True, "detail": "true"},
            {"name": "next_action_safety_no_real_operation_evidence", "passed": True, "detail": "true"},
            {"name": "next_action_safety_guarded_command_printed", "passed": True, "detail": "true"},
            {"name": "next_action_safety_no_real_acquisition_evidence", "passed": True, "detail": "true"},
            {"name": "next_action_safety_guarded_would_run_command_printed", "passed": True, "detail": "true"},
            {"name": "next_action_safety_data_root_outside_repo", "passed": True, "detail": "true"},
            {"name": "go_no_go_allows_guarded_real_acquisition", "passed": True, "detail": "go"},
            {"name": "execute_guard_probe_passed", "passed": True, "detail": "passed"},
            {"name": "launcher_exists", "passed": True, "detail": "launcher"},
            {"name": "prelab_validation_launcher_exists", "passed": True, "detail": "prelab launcher"},
            {"name": "post_acquisition_refresh_launcher_exists", "passed": True, "detail": "refresh launcher"},
            {"name": "publish_launcher_exists", "passed": True, "detail": "publish launcher"},
            {"name": "lab_transcript_template_exists", "passed": True, "detail": "transcript template"},
            {"name": "data_root_outside_repo", "passed": True, "detail": "D:/tamandua_ml_lab_data"},
            {"name": "production_manifest_absent_before_operator_run", "passed": True, "detail": "manifest"},
            {"name": "canonical_dataset_manifest_absent_before_operator_run", "passed": True, "detail": "manifest"},
        ],
        "operator_sequence": [
            {
                "step": 1,
                "mode": "prelab_validation",
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:/tamandua_ml_lab_data",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/ml_prelab_validation_launcher.ps1'",
                "claim_boundary": "Runs pre-lab validation without acquisition or guarded execution.",
            },
            {
                "step": 2,
                "mode": "validation_only",
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1'",
                "claim_boundary": "Revalidates Wave 1 contracts and prints the real acquisition command without acquisition.",
            },
            {
                "step": 3,
                "mode": "execute",
                "guard_set_command": "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1'",
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:/tamandua_ml_lab_data",
                    "TAMANDUA_ALLOW_ML_REAL_ACQUISITION": "1",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1' -Execute",
                "guard_cleanup_command": "Remove-Item Env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION -ErrorAction SilentlyContinue",
                "claim_boundary": (
                    "Runs governed MalwareBazaar, vx/InTheWild inventory, and goodware acquisition in the "
                    "isolated external data root and writes the acquisition transcript."
                ),
            },
            {
                "step": 4,
                "mode": "post_acquisition_refresh",
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:/tamandua_ml_lab_data",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_post_acquisition_refresh_launcher.ps1'",
                "claim_boundary": "Consumes the acquisition transcript and regenerates receipts after acquisition without publication or training.",
            },
            {
                "step": 5,
                "mode": "post_acquisition_publish",
                "guard_set_command": "$env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH = '1'",
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:/tamandua_ml_lab_data",
                    "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH": "1",
                },
                "validation_command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1'",
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute",
                "guard_cleanup_command": "Remove-Item Env:TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH -ErrorAction SilentlyContinue",
                "claim_boundary": "Runs guarded sanitized hash-only manifest publication after the acquisition receipt is ready.",
            },
        ],
    }
    source_status_summary = payload["source_status_summary"]
    source_status_summary["operator_sequence_modes_sha256"] = stable_sha256(
        source_status_summary["operator_sequence_modes"]
    )
    source_status_summary["operator_commands_by_mode_sha256"] = stable_sha256(
        source_status_summary["operator_commands_by_mode"]
    )
    return payload


def test_validate_wave1_operator_launch_brief_accepts_valid_contract() -> None:
    validate_wave1_operator_launch_brief(valid_wave1_operator_launch_brief(), Path("memory://ml-wave1-operator-launch-brief.json"))


def test_validate_wave1_operator_launch_brief_rejects_ready_with_enabled_lab_guard() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["ml_lab_standby_guards_unset"] = False
    payload["source_status_summary"]["ml_lab_standby_enabled_guards"] = ["TAMANDUA_ALLOW_ML_REAL_ACQUISITION"]
    check = next(item for item in payload["checks"] if item["name"] == "ml_lab_standby_guards_unset")
    check["passed"] = False
    check["detail"] = "enabled_guards=['TAMANDUA_ALLOW_ML_REAL_ACQUISITION']"
    payload["source_status_summary"]["passed_checks"] = 30
    payload["source_status_summary"]["failed_checks"] = 1

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "ready_for_operator" in str(exc) or "ml_lab_standby" in str(exc)
    else:
        raise AssertionError("expected enabled lab guard to fail ready launch brief")


def test_validate_wave1_operator_launch_brief_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-wave1-operator-launch-brief.json"
    report_path.write_text(json.dumps(valid_wave1_operator_launch_brief()), encoding="utf-8")

    mode = validate_contract(report_path, WAVE1_OPERATOR_LAUNCH_BRIEF_SCHEMA, validate_wave1_operator_launch_brief)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_operator_launch_brief_rejects_ready_mismatch() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["checks"][0]["passed"] = False

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "ready_for_operator" in str(exc)
    else:
        raise AssertionError("expected ready mismatch to fail")


def test_validate_wave1_operator_launch_brief_rejects_missing_acquisition_guard() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["operator_sequence"][2]["required_env"]["TAMANDUA_ALLOW_ML_REAL_ACQUISITION"] = "0"

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "acquisition guard" in str(exc)
    else:
        raise AssertionError("expected missing acquisition guard to fail")


def test_validate_wave1_operator_launch_brief_rejects_guard_boundary_count_drift() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["validation_only_command_count"] = 2

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "validation_only_command_count" in str(exc)
    else:
        raise AssertionError("expected command guard boundary count drift to fail")


def test_validate_wave1_operator_launch_brief_rejects_false_guard_boundary_proof() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["command_guard_boundary_preserved"] = False

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "command_guard_boundary_preserved" in str(exc)
    else:
        raise AssertionError("expected false command guard boundary proof to fail")


def test_validate_wave1_operator_launch_brief_rejects_validation_execute_command() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["operator_sequence"][1]["command"] += " -Execute"

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "validation command" in str(exc)
    else:
        raise AssertionError("expected validation command with -Execute to fail")


def test_validate_wave1_operator_launch_brief_rejects_refresh_without_transcript_boundary() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["operator_sequence"][3]["claim_boundary"] = "Regenerates receipts after acquisition."

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "transcript" in str(exc)
    else:
        raise AssertionError("expected refresh without transcript boundary to fail")


def test_validate_wave1_operator_launch_brief_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["operator_steps"] = 4

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "source_status_summary.operator_steps" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_wave1_operator_launch_brief_rejects_vx_policy_drift() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["vx_download_authorized_by_operator_brief"] = True

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "vx_download_authorized_by_operator_brief" in str(exc)
    else:
        raise AssertionError("expected VX policy drift to fail")


def test_validate_wave1_operator_launch_brief_rejects_source_command_drift() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["operator_commands_by_mode"]["execute"] = "& 'other.ps1' -Execute"

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "source_status_summary.operator_commands_by_mode.execute" in str(exc)
    else:
        raise AssertionError("expected source command drift to fail")


def test_validate_wave1_operator_launch_brief_rejects_operator_sequence_hash_drift() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["operator_sequence_modes_sha256"] = "0" * 64

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "operator_sequence_modes_sha256" in str(exc)
    else:
        raise AssertionError("expected operator sequence hash drift to fail")


def test_validate_wave1_operator_launch_brief_rejects_operator_commands_hash_drift() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["operator_commands_by_mode_sha256"] = "0" * 64

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "operator_commands_by_mode_sha256" in str(exc)
    else:
        raise AssertionError("expected operator commands hash drift to fail")


def test_validate_wave1_operator_launch_brief_rejects_source_path_drift() -> None:
    payload = copy.deepcopy(valid_wave1_operator_launch_brief())
    payload["source_status_summary"]["configuration_paths"]["lab_transcript_template"] = "other.template.json"

    try:
        validate_wave1_operator_launch_brief(payload, Path("memory://ml-wave1-operator-launch-brief.json"))
    except ContractError as exc:
        assert "source_status_summary.configuration_paths.lab_transcript_template" in str(exc)
    else:
        raise AssertionError("expected source path drift to fail")
