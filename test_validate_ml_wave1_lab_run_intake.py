import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    WAVE1_LAB_RUN_INTAKE_SCHEMA,
    validate_contract,
    validate_wave1_lab_run_intake,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-lab-run-intake.json"


def test_validate_wave1_lab_run_intake_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_lab_run_intake_rejects_false_ready(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["ready_for_post_acquisition_refresh"] = True
    drifted = tmp_path / "20260604T-ml-wave1-lab-run-intake.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)


def test_validate_wave1_lab_run_intake_rejects_source_status_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["transcript_present"] = not data["summary"]["transcript_present"]
    drifted = tmp_path / "20260604T-ml-wave1-lab-run-intake.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)


def test_validate_wave1_lab_run_intake_rejects_required_transcript_fields_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["required_transcript_fields_sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-lab-run-intake.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)


def test_validate_wave1_lab_run_intake_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["execution_packet"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-lab-run-intake.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.execution_packet.sha256"):
        validate_contract(drifted, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)


def test_validate_wave1_lab_run_intake_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["execution_packet"]["path"] = "docs/benchmarks/runs/not-the-packet.json"
    drifted = tmp_path / "20260604T-ml-wave1-lab-run-intake.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.execution_packet.path"):
        validate_contract(drifted, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)


def test_validate_wave1_lab_run_intake_rejects_absent_transcript_hash(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["transcript"]["exists"] = True
    data["source_artifact_hashes"]["transcript"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-lab-run-intake.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.transcript.exists"):
        validate_contract(drifted, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)


def test_validate_wave1_lab_run_intake_rejects_vx_policy_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_archive_download_guard_must_be_unset"] = False
    drifted = tmp_path / "20260604T-ml-wave1-lab-run-intake.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_archive_download_guard_must_be_unset"):
        validate_contract(drifted, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)


def test_validate_wave1_lab_run_intake_rejects_vx_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["expected_vx_inventory_metadata_only"] = False
    drifted = tmp_path / "20260604T-ml-wave1-lab-run-intake.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="expected_vx_inventory_metadata_only"):
        validate_contract(drifted, WAVE1_LAB_RUN_INTAKE_SCHEMA, validate_wave1_lab_run_intake)
