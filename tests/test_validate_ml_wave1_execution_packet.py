import hashlib
import json
from pathlib import Path

import pytest

from validate_ml_contracts import ContractError, WAVE1_EXECUTION_PACKET_SCHEMA, validate_contract, validate_wave1_execution_packet
from test_validate_ml_wave2_ml1_readiness import GOAL_SNAPSHOT


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


ACQUISITION_COMMAND = (
    "python apps\\tamandua_ml\\scripts\\download_production_dataset.py "
    "--output $env:TAMANDUA_ML_DATA_ROOT\\production "
    "--samples-per-class 10000 "
    "--skip-vt-validation "
    "--vx-inventory docs\\benchmarks\\runs\\ml-vx-inthewild-inventory.json "
    "--resume "
    "--yes"
)


def valid_packet() -> dict:
    payload = {
        "api_version": "tamandua.io/ml-wave1-execution-packet/v1",
        "kind": "MLWave1ExecutionPacket",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-04T00:00:00+00:00",
            "created_by": "tamandua-ml-wave1-execution-packet",
            "claim_boundary": "No-execution Wave 1 execution packet only. Does not run launchers.",
        },
        "source": {
            "operator_launch_brief": "docs/benchmarks/runs/20260604T-ml-wave1-operator-launch-brief.json",
            "operator_launch_brief_validation": "jsonschema+built-in",
            "lab_transcript_template": "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
            "lab_transcript_template_validation": "jsonschema+built-in",
            "source_operator_launch_brief_summary": {
                **GOAL_SNAPSHOT,
                "ready_for_operator": True,
                "checks": 30,
                "check_names": [
                    "acquisition_dry_run_valid",
                    "acquisition_readiness_valid",
                    "canonical_dataset_manifest_absent_before_operator_run",
                    "data_root_outside_repo",
                    "execute_guard_probe_passed",
                    "execution_status_valid",
                    "go_no_go_allows_guarded_real_acquisition",
                    "lab_transcript_template_exists",
                    "launcher_exists",
                    "ml_lab_standby_guards_unset",
                    "ml_lab_standby_readiness_valid",
                    "ml_local_training_readiness_valid",
                    "next_action_is_wave1_guarded_acquisition",
                    "next_action_run_is_selected_wave1_acquisition",
                    "next_action_run_valid",
                    "next_action_safety_command_validation_only",
                    "next_action_safety_data_root_outside_repo",
                    "next_action_safety_execute_guard_absent",
                    "next_action_safety_guarded_command_printed",
                    "next_action_safety_guarded_would_run_command_printed",
                    "next_action_safety_no_real_acquisition_evidence",
                    "next_action_safety_no_real_operation_evidence",
                    "next_action_safety_no_success_stderr",
                    "next_action_safety_selected_action_only",
                    "post_acquisition_refresh_launcher_exists",
                    "prelab_validation_launcher_exists",
                    "production_manifest_absent_before_operator_run",
                    "publish_launcher_exists",
                    "wave1_execute_guard_valid",
                    "wave1_go_no_go_valid",
                ],
                "operator_sequence_steps": 5,
                "operator_sequence_modes": [
                    "prelab_validation",
                    "validation_only",
                    "execute",
                    "post_acquisition_refresh",
                    "post_acquisition_publish",
                ],
                "operator_sequence_modes_sha256": "",
                "operator_commands_by_mode_sha256": "",
                "next_action_run_validated": True,
                "next_action_run_mode": "validation_only",
                "next_action_run_returncode": 0,
                "next_action_run_package_id": "ml_data_governed_acquisition",
                "next_action_run_wave": 1,
                "next_action_validation_scope_selected": True,
                "next_action_safety_assertions": dict(NEXT_ACTION_SAFETY),
                "next_action_safety_assertions_passed": True,
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
                "validation_only_command_count": 3,
                "guarded_execute_command_count": 2,
                "guarded_required_env_count": 2,
                "command_guard_boundary_preserved": True,
            },
        },
        "authorized_acquisition": {
            "transcript_template": "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.template.json",
            "acquisition_command": ACQUISITION_COMMAND,
            "acquisition_command_sha256": hashlib.sha256(ACQUISITION_COMMAND.encode("utf-8")).hexdigest(),
        },
        "safe_to_hand_to_operator": True,
        "blockers": [],
        "configuration": {
            "data_root": "D:\\treant\\tamandua_ml_lab_data",
            "production_manifest": "D:\\treant\\tamandua_ml_lab_data\\production\\manifest.json",
            "canonical_dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1",
            "post_acquisition_refresh_launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_post_acquisition_refresh_launcher.ps1",
            "publish_launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1",
        },
        "commands": {
            "prelab_validation": {
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:\\treant\\tamandua_ml_lab_data",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/ml_prelab_validation_launcher.ps1'",
                "claim_boundary": "Runs pre-lab validation without acquisition or guarded execution.",
            },
            "validation_only": {
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1'",
                "claim_boundary": "Validation only.",
            },
            "execute": {
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:\\treant\\tamandua_ml_lab_data",
                    "TAMANDUA_ALLOW_ML_REAL_ACQUISITION": "1",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_real_acquisition_launcher.ps1' -Execute",
                "claim_boundary": "Executes guarded acquisition.",
            },
            "post_acquisition_refresh": {
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:\\treant\\tamandua_ml_lab_data",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_post_acquisition_refresh_launcher.ps1'",
                "claim_boundary": "Regenerates receipts after acquisition without publication or training.",
            },
            "post_acquisition_publish": {
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:\\treant\\tamandua_ml_lab_data",
                    "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH": "1",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_1_manifest_publish_launcher.ps1' -Execute",
                "claim_boundary": "Runs guarded sanitized manifest publication.",
            },
        },
        "operator_sequence": [],
        "operator_checklist": ["Confirm lab.", "Run validation.", "Set guard."],
        "artifact_expectations": [
            {"artifact": "D:\\treant\\tamandua_ml_lab_data\\production\\manifest.json", "scope": "external_lab_only", "required_after": "execute"},
            {"artifact": "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json", "scope": "repo_no_execution_receipt", "required_after": "post_acquisition_refresh"},
            {"artifact": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json", "scope": "repo_hash_only_manifest", "required_after": "post_acquisition_publish"},
        ],
        "forbidden_actions": ["No workstation.", "No raw samples in repo.", "No inline guard script."],
    }
    source_summary = payload["source"]["source_operator_launch_brief_summary"]
    source_summary["operator_sequence_modes_sha256"] = stable_sha256(source_summary["operator_sequence_modes"])
    payload["operator_sequence"] = [
        {
            "step": index,
            "mode": mode,
            "required_env": payload["commands"][mode].get("required_env", {}),
            "command": payload["commands"][mode]["command"],
            "claim_boundary": payload["commands"][mode]["claim_boundary"],
        }
        for index, mode in enumerate(source_summary["operator_sequence_modes"], start=1)
    ]
    source_summary["operator_commands_by_mode_sha256"] = stable_sha256(
        {
            mode: payload["commands"][mode]["command"]
            for mode in source_summary["operator_sequence_modes"]
        }
    )
    return payload


def test_validate_wave1_execution_packet_accepts_contract() -> None:
    validate_wave1_execution_packet(valid_packet(), Path("memory://packet.json"))


def test_validate_wave1_execution_packet_accepts_jsonschema_path(tmp_path: Path) -> None:
    path = tmp_path / "packet.json"
    path.write_text(json.dumps(valid_packet()), encoding="utf-8")

    mode = validate_contract(path, WAVE1_EXECUTION_PACKET_SCHEMA, validate_wave1_execution_packet)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_execution_packet_rejects_inline_guard() -> None:
    payload = valid_packet()
    payload["commands"]["execute"]["command"] = "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION=1; .\\launcher.ps1 -Execute"

    with pytest.raises(ContractError, match="inline"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_requires_prelab_command() -> None:
    payload = valid_packet()
    del payload["commands"]["prelab_validation"]

    with pytest.raises(ContractError, match="prelab_validation"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_prelab_execute() -> None:
    payload = valid_packet()
    payload["commands"]["prelab_validation"]["command"] += " -Execute"

    with pytest.raises(ContractError, match="pre-lab"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_requires_blocker_when_unsafe() -> None:
    payload = valid_packet()
    payload["safe_to_hand_to_operator"] = False

    with pytest.raises(ContractError, match="unsafe"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_source_brief_summary_drift() -> None:
    payload = valid_packet()
    payload["source"]["source_operator_launch_brief_summary"]["operator_sequence_modes"] = [
        "validation_only",
        "prelab_validation",
        "execute",
        "post_acquisition_refresh",
        "post_acquisition_publish",
    ]

    with pytest.raises(ContractError, match="operator_sequence_modes"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_operator_sequence_hash_drift() -> None:
    payload = valid_packet()
    payload["source"]["source_operator_launch_brief_summary"]["operator_sequence_modes_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="operator_sequence_modes_sha256"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_operator_sequence_command_drift() -> None:
    payload = valid_packet()
    payload["operator_sequence"][2]["command"] = ".\\different.ps1 -Execute"

    with pytest.raises(ContractError, match="operator_sequence"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_operator_commands_hash_drift() -> None:
    payload = valid_packet()
    payload["source"]["source_operator_launch_brief_summary"]["operator_commands_by_mode_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="operator_commands_by_mode_sha256"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_authorized_acquisition_hash_drift() -> None:
    payload = valid_packet()
    payload["authorized_acquisition"]["acquisition_command_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="acquisition_command_sha256"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_guard_boundary_summary_drift() -> None:
    payload = valid_packet()
    payload["source"]["source_operator_launch_brief_summary"]["validation_only_command_count"] = 2

    with pytest.raises(ContractError, match="validation_only_command_count"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_false_guard_boundary_proof() -> None:
    payload = valid_packet()
    payload["source"]["source_operator_launch_brief_summary"]["command_guard_boundary_preserved"] = False

    with pytest.raises(ContractError, match="command_guard_boundary_preserved"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))


def test_validate_wave1_execution_packet_rejects_enabled_lab_standby_guard() -> None:
    payload = valid_packet()
    source_summary = payload["source"]["source_operator_launch_brief_summary"]
    source_summary["ml_lab_standby_enabled_guards"] = ["TAMANDUA_ALLOW_ML_REAL_ACQUISITION"]

    with pytest.raises(ContractError, match="ml_lab_standby_enabled_guards"):
        validate_wave1_execution_packet(payload, Path("memory://packet.json"))
