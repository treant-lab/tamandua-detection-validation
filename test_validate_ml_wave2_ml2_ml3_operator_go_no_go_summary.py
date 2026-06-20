from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave2_ml2_ml3_operator_go_no_go_summary,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
AGENT_SMOKE_CONTEXT = (
    ROOT
    / "docs"
    / "benchmarks"
    / "runs"
    / "20260620T1905Z-ml-wave2-ml2-ml3-agent-smoke-context-go-no-go.json"
)
if not CANONICAL.exists() or not AGENT_SMOKE_CONTEXT.exists():
    pytest.skip("ML Wave 2 ML-2/ML-3 run artifacts are not present in this standalone deployment", allow_module_level=True)


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_accepts_jsonschema_path() -> None:
    mode = validate_contract(
        CANONICAL,
        WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
        validate_wave2_ml2_ml3_operator_go_no_go_summary,
    )

    assert mode == "jsonschema+built-in"


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_accepts_agent_smoke_context_path() -> None:
    mode = validate_contract(
        AGENT_SMOKE_CONTEXT,
        WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
        validate_wave2_ml2_ml3_operator_go_no_go_summary,
    )

    assert mode == "jsonschema+built-in"


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_false_ready_claim(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["ready_for_ml2_ml3_parity_go_no_go"] = True
    data["operator_decision"]["decision"] = "go_for_guarded_ml2_ml3_parity"
    data["source_status_summary"]["ready_for_ml2_ml3_parity_go_no_go"] = True
    drifted = tmp_path / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="ready_for_ml2_ml3_parity_go_no_go|decision"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_guard_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["execute_guard_env"] = "TAMANDUA_ALLOW_ML_TRAINING"
    drifted = tmp_path / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="execute_guard_env"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_authorization_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["authorization_inputs_sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="authorization_inputs_sha256"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_inlined_guard_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_sequence"][1]["command"] = (
        "$env:TAMANDUA_ALLOW_ML_PARITY=1; " + data["operator_sequence"][1]["command"]
    )
    drifted = tmp_path / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="operator_sequence"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_source_summary_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_status_summary"]["candidate_onnx_model_present"] = True
    drifted = tmp_path / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="candidate_onnx_model_present"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_source_artifact_hash_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["wave2_ml2_ml3_readiness"]["sha256"] = "0" * 64
    drifted = tmp_path / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*sha256"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_source_artifact_path_drift(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["wave1_acceptance_checklist"]["path"] = "docs/benchmarks/runs/wrong.json"
    drifted = tmp_path / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes.*path"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_extra_source_artifact_hash(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["source_artifact_hashes"]["unexpected"] = {
        "path": "docs/benchmarks/runs/unexpected.json",
        "sha256": "0" * 64,
    }
    drifted = tmp_path / "20260604T-ml-wave2-ml2-ml3-operator-go-no-go-summary.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="source_artifact_hashes"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )


def test_validate_wave2_ml2_ml3_operator_go_no_go_summary_rejects_smoke_production_unblock_drift(
    tmp_path: Path,
) -> None:
    data = copy.deepcopy(json.loads(AGENT_SMOKE_CONTEXT.read_text(encoding="utf-8")))
    data["agent_smoke_context"]["smoke_agent_side_evidence_unblocks_production"] = True
    data["source_status_summary"]["agent_smoke_evidence_unblocks_production"] = True
    drifted = tmp_path / "20260620T1905Z-ml-wave2-ml2-ml3-agent-smoke-context-go-no-go.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="unblocks_production|agent_smoke_evidence_unblocks_production"):
        validate_contract(
            drifted,
            WAVE2_ML2_ML3_OPERATOR_GO_NO_GO_SUMMARY_SCHEMA,
            validate_wave2_ml2_ml3_operator_go_no_go_summary,
        )
