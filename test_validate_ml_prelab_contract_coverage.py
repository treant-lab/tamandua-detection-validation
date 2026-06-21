from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ContractError,
    ML_PRELAB_CONTRACT_COVERAGE_SCHEMA,
    validate_contract,
    validate_ml_prelab_contract_coverage,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-prelab-contract-coverage.json"


def test_validate_ml_prelab_contract_coverage_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, ML_PRELAB_CONTRACT_COVERAGE_SCHEMA, validate_ml_prelab_contract_coverage)

    assert mode == "jsonschema+built-in"


def test_validate_ml_prelab_contract_coverage_requires_parallel_resolution_contract_invariants() -> None:
    data = json.loads(CANONICAL.read_text(encoding="utf-8"))
    invariant_names = data["source"]["source_validator_invariant_summary"]["required_invariant_term_names"]

    assert "resolution_contract" in invariant_names
    assert "required_resolution_fragments_by_package" in invariant_names
    assert "required_artifacts.onnx_model.path" in invariant_names
    assert "ml-prod-candidate-v1-artifacts/malware_smell.onnx" in invariant_names
    assert "candidate_ml2_report" in invariant_names


def test_validate_ml_prelab_contract_coverage_requires_virusshare_contract_invariants() -> None:
    data = json.loads(CANONICAL.read_text(encoding="utf-8"))
    invariant_names = data["source"]["source_validator_invariant_summary"]["required_invariant_term_names"]

    assert "ML_VIRUSSHARE_FALLBACK_READINESS_SCHEMA" in invariant_names
    assert "validate_ml_virusshare_fallback_readiness" in invariant_names
    assert "--ml-virusshare-fallback-readiness" in invariant_names
    assert "--ml-virusshare-fallback-command-packet-check" in invariant_names
    assert "--ml-virusshare-fallback-transition-audit" in invariant_names
    assert "ready_for_guarded_virusshare_fallback" in invariant_names
    assert "virusshare_api_key_not_placeholder" in invariant_names


def test_validate_ml_prelab_contract_coverage_tracks_canonical_next_action_receipt() -> None:
    data = json.loads(CANONICAL.read_text(encoding="utf-8"))
    audit = data["source"]["source_next_action_receipt_summary"]

    assert audit["canonical_receipt"].endswith("20260604T-ml-prelab-next-action-validation.run.json")
    assert audit["canonical_receipt_exists"] is True
    assert audit["active_refs_to_canonical_receipt"] > 0
    assert audit["active_refs_to_historical_receipts"] == 0
    assert audit["passed"] is True
    assert data["summary"]["next_action_receipt_audit_passed"] is True


def test_validate_ml_prelab_contract_coverage_requires_preflight_storage_invariants() -> None:
    data = json.loads(CANONICAL.read_text(encoding="utf-8"))
    invariant_names = data["source"]["source_validator_invariant_summary"]["required_invariant_term_names"]

    assert "env:TAMANDUA_ML_DATA_ROOT_exists" in invariant_names
    assert "env:TAMANDUA_ML_DATA_ROOT_writable" in invariant_names
    assert "env:TAMANDUA_ML_DATA_ROOT_free_space_gb" in invariant_names
    assert "$dataRootFreeSpaceGb -ge 50" in invariant_names
    assert "env:TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD_unset" in invariant_names
    assert "env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION_ready_for_execute" in invariant_names


def test_validate_ml_prelab_contract_coverage_rejects_complete_with_missing(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["complete"] = True
    data["unexpected_missing"] = ["--new-contract"]
    data["summary"]["unexpected_missing"] = 1
    data["arguments"].append(
        {"argument": "--new-contract", "status": "unexpected_missing", "reason": "validator argument is not covered"}
    )
    drifted = tmp_path / "20260604T-ml-prelab-contract-coverage.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, ML_PRELAB_CONTRACT_COVERAGE_SCHEMA, validate_ml_prelab_contract_coverage)


def test_validate_ml_prelab_contract_coverage_rejects_complete_with_missing_invariant(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["complete"] = True
    data["missing_validator_invariants"] = ["operator_sequence_modes_sha256"]
    data["summary"]["missing_validator_invariants"] = 1
    invariant_summary = data["source"]["source_validator_invariant_summary"]
    invariant_summary["covered_invariant_term_names"] = [
        term for term in invariant_summary["covered_invariant_term_names"] if term != "operator_sequence_modes_sha256"
    ]
    invariant_summary["covered_invariant_terms"] = len(invariant_summary["covered_invariant_term_names"])
    invariant_summary["missing_invariant_term_names"] = ["operator_sequence_modes_sha256"]
    invariant_summary["missing_invariant_terms"] = 1
    data["source"]["source_status_summary"]["missing_invariant_term_names"] = ["operator_sequence_modes_sha256"]
    data["source"]["source_status_summary"]["missing_invariant_terms"] = 1
    drifted = tmp_path / "20260604T-ml-prelab-contract-coverage.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="complete"):
        validate_contract(drifted, ML_PRELAB_CONTRACT_COVERAGE_SCHEMA, validate_ml_prelab_contract_coverage)


def test_validate_ml_prelab_contract_coverage_rejects_unlisted_intentional_exclusion(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["arguments"][0]["status"] = "intentional_exclusion"
    data["arguments"][0]["reason"] = "pretend this is acceptable"
    data["summary"]["covered_args"] -= 1
    data["summary"]["intentional_exclusions"] += 1
    drifted = tmp_path / "20260604T-ml-prelab-contract-coverage.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, ML_PRELAB_CONTRACT_COVERAGE_SCHEMA, validate_ml_prelab_contract_coverage)


def test_validate_ml_prelab_contract_coverage_rejects_source_validator_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    source_summary = data["source"]["source_contract_argument_summary"]
    source_summary["validator_arg_names"] = [
        arg for arg in source_summary["validator_arg_names"] if arg != data["arguments"][0]["argument"]
    ]
    source_summary["validator_args"] = len(source_summary["validator_arg_names"])
    drifted = tmp_path / "20260604T-ml-prelab-contract-coverage.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError):
        validate_contract(drifted, ML_PRELAB_CONTRACT_COVERAGE_SCHEMA, validate_ml_prelab_contract_coverage)


def test_validate_ml_prelab_contract_coverage_rejects_source_status_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_status_summary"]["covered_arg_names"] = []
    data["source"]["source_status_summary"]["covered_args"] = 0
    drifted = tmp_path / "20260604T-ml-prelab-contract-coverage.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source.source_status_summary.covered_arg_names"):
        validate_contract(drifted, ML_PRELAB_CONTRACT_COVERAGE_SCHEMA, validate_ml_prelab_contract_coverage)


def test_validate_ml_prelab_contract_coverage_rejects_historical_next_action_active_ref(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    audit = data["source"]["source_next_action_receipt_summary"]
    audit["active_refs_to_historical_receipts"] = 1
    audit["active_ref_files_to_historical_receipts"] = [
        "docs/benchmarks/runs/20260604T-ml-execution-master-handoff.json::20260604T-ml-next-action-validation-only.run.json"
    ]
    audit["passed"] = False
    data["source"]["source_status_summary"]["active_refs_to_historical_next_action_receipts"] = 1
    data["source"]["source_status_summary"]["next_action_receipt_audit_passed"] = False
    data["summary"]["active_refs_to_historical_next_action_receipts"] = 1
    data["summary"]["next_action_receipt_audit_passed"] = False
    data["complete"] = False
    data["source"]["source_status_summary"]["complete"] = False
    drifted = tmp_path / "20260604T-ml-prelab-contract-coverage.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="historical next-action refs"):
        validate_contract(drifted, ML_PRELAB_CONTRACT_COVERAGE_SCHEMA, validate_ml_prelab_contract_coverage)


def test_validate_ml_prelab_contract_coverage_rejects_invariant_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source"]["source_validator_invariant_summary"]["covered_invariant_term_names"] = []
    data["source"]["source_validator_invariant_summary"]["covered_invariant_terms"] = 0
    drifted = tmp_path / "20260604T-ml-prelab-contract-coverage.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="covered plus missing"):
        validate_contract(drifted, ML_PRELAB_CONTRACT_COVERAGE_SCHEMA, validate_ml_prelab_contract_coverage)
