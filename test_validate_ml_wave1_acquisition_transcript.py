from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    WAVE1_ACQUISITION_TRANSCRIPT_SCHEMA,
    validate_contract,
    validate_wave1_acquisition_transcript,
)


ROOT = Path(__file__).resolve().parents[2]
GUARDED_RUN_PACKET = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-guarded-run-command-packet.json"
LAUNCHER = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-execution-plan.handoff" / "wave_1_real_acquisition_launcher.ps1"
SANITIZATION_RULES = [
    "replace_resolved_data_root_with_placeholder",
    "replace_raw_data_root_with_placeholder",
    "redact_infected_password_assignment",
    "redact_7z_infected_password_flag",
]


def sanitization_rules_sha256() -> str:
    payload = json.dumps(SANITIZATION_RULES, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def valid_transcript(tmp_path: Path) -> dict:
    stdout_ref = tmp_path / "20260604T-ml-wave1-real-acquisition.stdout.txt"
    stderr_ref = tmp_path / "20260604T-ml-wave1-real-acquisition.stderr.txt"
    stdout_ref.write_text("ok", encoding="utf-8")
    stderr_ref.write_text("", encoding="utf-8")
    acquisition_command = (
        "python apps\\tamandua_ml\\scripts\\download_production_dataset.py "
        "--output $env:TAMANDUA_ML_DATA_ROOT\\production --samples-per-class 10000 "
        "--skip-vt-validation --vx-inventory docs\\benchmarks\\runs\\ml-vx-inthewild-inventory.json --resume --yes"
    )
    return {
        "api_version": "tamandua.io/ml-wave1-acquisition-transcript/v1",
        "kind": "MLWave1AcquisitionTranscript",
        "metadata": {
            "report_id": "test",
            "created_by": "wave_1_real_acquisition_launcher.ps1",
            "claim_boundary": "Real Wave 1 acquisition transcript from isolated lab. Raw malware remains outside Git.",
        },
        "command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_1_real_acquisition_launcher.ps1 -Execute",
        "launcher_ref": str(LAUNCHER),
        "launcher_sha256": hashlib.sha256(LAUNCHER.read_bytes()).hexdigest(),
        "acquisition_command": acquisition_command,
        "acquisition_command_sha256": hashlib.sha256(acquisition_command.encode("utf-8")).hexdigest(),
        "guarded_run_command_packet_ref": str(GUARDED_RUN_PACKET),
        "guarded_run_command_packet_sha256": hashlib.sha256(GUARDED_RUN_PACKET.read_bytes()).hexdigest(),
        "started_at": "2026-06-05T00:00:00Z",
        "finished_at": "2026-06-05T00:01:00Z",
        "returncode": 0,
        "stdout_ref": str(stdout_ref),
        "stdout_sha256": hashlib.sha256(stdout_ref.read_bytes()).hexdigest(),
        "stderr_ref": str(stderr_ref),
        "stderr_sha256": hashlib.sha256(stderr_ref.read_bytes()).hexdigest(),
        "published_logs_are_sanitized": True,
        "hashes_cover_published_sanitized_logs": True,
        "sanitization_rules_sha256": sanitization_rules_sha256(),
        "operator": "lab-operator",
        "lab_host": "isolated-lab",
        "data_root_ref": "external://tamandua-ml-production/ml-prod-candidate-v1",
        "data_root_outside_repo": True,
        "guard_env": {"TAMANDUA_ALLOW_ML_REAL_ACQUISITION": "1"},
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
    }


def test_validate_wave1_acquisition_transcript_accepts_valid_contract(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)

    validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json"
    report_path.write_text(json.dumps(valid_transcript(tmp_path)), encoding="utf-8")

    mode = validate_contract(report_path, WAVE1_ACQUISITION_TRANSCRIPT_SCHEMA, validate_wave1_acquisition_transcript)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_acquisition_transcript_rejects_direct_acquisition_command(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["command"] = "python apps\\tamandua_ml\\scripts\\download_production_dataset.py --output data"

    with pytest.raises(ContractError):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_non_resumable_acquisition_command(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["acquisition_command"] = payload["acquisition_command"].replace(" --resume", "")

    with pytest.raises(ContractError, match="--resume"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_interactive_acquisition_command(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["acquisition_command"] = payload["acquisition_command"].replace(" --yes", "")

    with pytest.raises(ContractError, match="--yes"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_log_hash_mismatch(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["stdout_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="stdout_sha256"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_nonzero_returncode(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["returncode"] = 1

    with pytest.raises(ContractError, match="returncode"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_inverted_time_window(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["finished_at"] = "2026-06-04T23:59:00Z"

    with pytest.raises(ContractError, match="finished_at"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_noncanonical_log_ref(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    stdout_ref = tmp_path / "wave1.stdout.txt"
    stdout_ref.write_text("ok", encoding="utf-8")
    payload["stdout_ref"] = str(stdout_ref)
    payload["stdout_sha256"] = hashlib.sha256(stdout_ref.read_bytes()).hexdigest()

    with pytest.raises(ContractError, match="stdout"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_missing_sanitized_log_policy(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["published_logs_are_sanitized"] = False

    with pytest.raises(ContractError, match="published_logs_are_sanitized"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_sanitization_rule_drift(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["sanitization_rules_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="sanitization_rules_sha256"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_guarded_run_packet_hash_mismatch(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["guarded_run_command_packet_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="guarded_run_command_packet_sha256"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_launcher_hash_mismatch(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["launcher_sha256"] = "0" * 64

    with pytest.raises(ContractError, match="launcher_sha256"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_raw_data_root_path(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["data_root"] = str(Path(__file__).resolve().parents[2] / "apps" / "tamandua_ml" / "data")

    with pytest.raises(ContractError, match="data_root"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_wrong_data_root_ref(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["data_root_ref"] = "D:\\treant\\tamandua_ml_lab_data"

    with pytest.raises(ContractError, match="data_root_ref"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_unmarked_external_data_root(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["data_root_outside_repo"] = False

    with pytest.raises(ContractError, match="data_root_outside_repo"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_vx_policy_training_split_drift(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    payload["vx_policy"]["vx_samples_in_training_splits"] = True

    with pytest.raises(ContractError, match="vx_samples_in_training_splits"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_missing_log_ref(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_transcript(tmp_path))
    payload["stdout_ref"] = str(tmp_path / "missing.stdout.txt")

    with pytest.raises(ContractError):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_local_dataset_path_in_log(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    stdout_ref = Path(payload["stdout_ref"])
    stdout_ref.write_text("wrote D:\\treant\\tamandua_ml_lab\\production\\manifest.json", encoding="utf-8")
    payload["stdout_sha256"] = hashlib.sha256(stdout_ref.read_bytes()).hexdigest()

    with pytest.raises(ContractError, match="sanitized log"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_windows_slash_dataset_path_in_log(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    stdout_ref = Path(payload["stdout_ref"])
    stdout_ref.write_text("wrote D:/treant/tamandua_ml_lab/production/manifest.json", encoding="utf-8")
    payload["stdout_sha256"] = hashlib.sha256(stdout_ref.read_bytes()).hexdigest()

    with pytest.raises(ContractError, match="sanitized log"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_posix_dataset_path_in_log(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    stderr_ref = Path(payload["stderr_ref"])
    stderr_ref.write_text("extracting /mnt/tamandua_ml_lab/raw/vx_underground/archive.7z", encoding="utf-8")
    payload["stderr_sha256"] = hashlib.sha256(stderr_ref.read_bytes()).hexdigest()

    with pytest.raises(ContractError, match="sanitized log"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")


def test_validate_wave1_acquisition_transcript_rejects_archive_password_in_log(tmp_path: Path) -> None:
    payload = valid_transcript(tmp_path)
    stdout_ref = Path(payload["stdout_ref"])
    stdout_ref.write_text("7z x sample.7z -pinfected", encoding="utf-8")
    payload["stdout_sha256"] = hashlib.sha256(stdout_ref.read_bytes()).hexdigest()

    with pytest.raises(ContractError, match="archive password"):
        validate_wave1_acquisition_transcript(payload, tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.json")
