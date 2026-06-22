import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA,
    validate_contract,
    validate_wave1_lab_transcript_template,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-real-acquisition-transcript.template.json"


def test_validate_wave1_lab_transcript_template_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_lab_transcript_template_rejects_actual_transcript_output_as_template(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["output_path"] = str(CANONICAL)
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_source_field_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_validation"]["source_status_summary"]["required_transcript_field_names"] = ["command"]
    data["source_validation"]["source_status_summary"]["required_transcript_fields"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_operator_ready_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    summary = data["source_validation"]["source_status_summary"]
    summary["guarded_run_command_packet_ready"] = False
    summary["guarded_run_command_packet_acquisition_command_matches_template"] = True
    summary["template_ready_for_operator_execution"] = True
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="template_ready_for_operator_execution"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_output_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_validation"]["source_status_summary"]["output_path"] = "docs/benchmarks/runs/other.json"
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="output_path"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_template_field_count_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_validation"]["source_status_summary"]["template_field_count"] = 1
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="template_field_count"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_required_fields_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["required_fields_sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="required_fields_sha256"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_template_fields_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_validation"]["source_status_summary"]["template_fields_sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="template_fields_sha256"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_hash_algorithm_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["hash_verification"]["algorithm"] = "SHA-1"
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="hash_verification"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_hash_file_ref_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["hash_verification"]["file_fields"]["stdout_sha256"] = "docs/benchmarks/runs/other.stdout.txt"
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="stdout_sha256"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_capture_helper_without_vx_guard_cleanup(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["capture_helper"]["commands"] = [
        command
        for command in data["capture_helper"]["commands"]
        if "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD" not in command
    ]
    data["source_validation"]["source_status_summary"]["capture_helper_command_count"] = len(data["capture_helper"]["commands"])
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD|capture_helper"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_capture_helper_without_template_materialization(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["capture_helper"]["commands"] = [
        command
        for command in data["capture_helper"]["commands"]
        if "real-acquisition-transcript.template.json" not in command
        and ").template" not in command
        and "acquisition_command_sha256" not in command
        and "guarded_run_command_packet_sha256" not in command
    ]
    data["source_validation"]["source_status_summary"]["capture_helper_command_count"] = len(data["capture_helper"]["commands"])
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="capture_helper|template|acquisition_command_sha256"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)


def test_validate_wave1_lab_transcript_template_rejects_vx_policy_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_samples_in_training_splits"] = True
    drifted = tmp_path / "20260604T-ml-wave1-real-acquisition-transcript.template.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_samples_in_training_splits|vx_policy"):
        validate_contract(drifted, WAVE1_LAB_TRANSCRIPT_TEMPLATE_SCHEMA, validate_wave1_lab_transcript_template)
