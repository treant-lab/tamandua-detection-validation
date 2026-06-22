from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_post_acquisition_go_no_go_summary,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"


def test_validate_wave1_post_acquisition_go_no_go_summary_accepts_jsonschema_path() -> None:
    mode = validate_contract(
        CANONICAL,
        WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
        validate_wave1_post_acquisition_go_no_go_summary,
    )

    assert mode == "jsonschema+built-in"


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_false_ready_claim(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["ready_for_manifest_publish_go_no_go"] = True
    data["operator_decision"]["decision"] = "go_for_guarded_manifest_publish"
    data["source_status_summary"]["ready_for_manifest_publish_go_no_go"] = True
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="ready_for_manifest_publish_go_no_go|decision"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_guard_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["publish_guard_env"] = "TAMANDUA_ALLOW_ML_REAL_ACQUISITION"
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="publish_guard_env"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_authorization_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["authorization_inputs_sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="authorization_inputs_sha256"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_validation_execute_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["validation_command"] = data["operator_decision"]["publish_command"]
    data["operator_sequence"][0]["command"] = data["operator_decision"]["publish_command"]
    data["source_status_summary"]["validation_command_no_execute"] = False
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="validation_command|operator_sequence"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_transcript_contract_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["pre_execution_transcript_contract_validation_before_run"] = "jsonschema+built-in"
    data["source_status_summary"]["pre_execution_transcript_contract_valid_before_run"] = True
    data["source_status_summary"]["pre_execution_transcript_contract_missing_before_run"] = False
    data["source_status_summary"]["transcript_contract_valid_for_manifest_publish"] = True
    for check in data["checks"]:
        if check["name"] == "transcript_contract_valid_for_manifest_publish":
            check["passed"] = True
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="transcript_contract"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_wave1_transcript_alias_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["wave1_transcript_contract_valid_for_manifest_publish"] = True
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="wave1_transcript_contract_valid_for_manifest_publish"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_missing_data_root_env(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_sequence"][1]["required_env"].pop("TAMANDUA_ML_DATA_ROOT", None)
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="manifest data root"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_source_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["production_manifest_exists"] = True
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="production_manifest_exists"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_transcript_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["manifest_transcript_stdout_sha256"] = "f" * 64
    data["source_status_summary"]["transcript_hashes_match_between_receipts"] = False
    for check in data["checks"]:
        if check["name"] == "transcript_hashes_match_between_receipts":
            check["passed"] = False
    data["source_status_summary"]["passed_checks"] -= 1
    data["source_status_summary"]["failed_checks"] += 1
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="manifest_transcript_stdout_sha256|transcript_hashes_match_between_receipts"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_expected_vx_policy_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["vx_policy"]["vx_archive_download_guard_must_be_unset"] = False
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_archive_download_guard_must_be_unset"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_expected_vx_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["expected_vx_inventory_metadata_only"] = False
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="expected_vx_inventory_metadata_only"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_requires_expected_vx_check(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["checks"] = [check for check in data["checks"] if check["name"] != "expected_vx_policy_metadata_only_boundary"]
    data["source_status_summary"]["check_count"] -= 1
    data["source_status_summary"]["passed_checks"] -= 1
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="expected_vx_policy_metadata_only_boundary"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["manifest_publish_receipt"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*sha256"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["acquisition_receipt"]["path"] = "docs/benchmarks/runs/wrong.json"
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )


def test_validate_wave1_post_acquisition_go_no_go_summary_rejects_extra_source_artifact_hash(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["unexpected"] = {"path": "docs/benchmarks/runs/unexpected.json", "sha256": "0" * 64}
    drifted = tmp_path / "20260604T-ml-wave1-post-acquisition-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes"):
        validate_contract(
            drifted,
            WAVE1_POST_ACQUISITION_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave1_post_acquisition_go_no_go_summary,
        )
