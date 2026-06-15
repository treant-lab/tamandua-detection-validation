import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA,
    validate_contract,
    validate_wave1_acceptance_checklist,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-acceptance-checklist.json"


def test_validate_wave1_acceptance_checklist_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_acceptance_checklist_rejects_false_acceptance(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["accepted_for_ml1"] = True
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_requires_lab_run_intake(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["configuration"].pop("wave1_lab_run_intake", None)
    data["summary"].pop("lab_run_intake_ready", None)
    data["checks"] = [check for check in data["checks"] if check["name"] != "lab_run_intake_valid"]
    data["acceptance_criteria"] = [
        item for item in data["acceptance_criteria"] if item["name"] != "lab_run_intake_accepted"
    ]
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_lab_run_intake|lab_run_intake"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_requires_lab_transcript_template(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["configuration"].pop("wave1_lab_transcript_template", None)
    data["summary"].pop("lab_transcript_template_ready", None)
    data["checks"] = [check for check in data["checks"] if check["name"] != "lab_transcript_template_valid"]
    data["acceptance_criteria"] = [
        item for item in data["acceptance_criteria"] if item["name"] != "lab_transcript_template_valid"
    ]
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_lab_transcript_template|lab_transcript_template"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_source_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["lab_run_intake_ready_for_post_acquisition_refresh"] = True
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_status_summary"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_transcript_contract_rollup_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["pre_execution_transcript_contract_validation_before_run"] = "failed"
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="pre_execution_transcript_contract"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_wave1_transcript_alias_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_transcript_hash_rollup_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["manifest_transcript_stdout_sha256"] = "f" * 64
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="manifest_transcript_stdout_sha256"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_expected_vx_policy_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_archive_download_guard_must_be_unset"] = False
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_archive_download_guard_must_be_unset"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_expected_vx_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["expected_vx_inventory_metadata_only"] = False
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="expected_vx_inventory_metadata_only"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_requires_expected_vx_check(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["checks"] = [check for check in data["checks"] if check["name"] != "closure_expected_vx_policy_metadata_only_boundary"]
    data["source"]["source_status_summary"]["check_count"] -= 1
    data["source"]["source_status_summary"]["passed_checks"] -= 1
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="closure_expected_vx_policy_metadata_only_boundary"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_source_validation_mode_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["execution_packet_consistency_validation"] = "failed"
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execution_packet_consistency_validation"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["closure_gate"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*sha256"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["wave1_lab_run_intake"]["path"] = "docs/benchmarks/runs/wrong.json"
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)


def test_validate_wave1_acceptance_checklist_rejects_extra_source_artifact_hash(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["unexpected"] = {"path": "docs/benchmarks/runs/unexpected.json", "sha256": "0" * 64}
    drifted = tmp_path / "20260604T-ml-wave1-acceptance-checklist.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes"):
        validate_contract(drifted, WAVE1_ACCEPTANCE_CHECKLIST_SCHEMA, validate_wave1_acceptance_checklist)
