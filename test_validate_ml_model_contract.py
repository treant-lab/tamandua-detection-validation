from __future__ import annotations

import copy
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

from validate_ml_contracts import ContractError, validate_model_contract  # noqa: E402


def valid_model_contract() -> dict:
    return json.loads((ROOT / "docs/apps/tamandua_ml/examples/ml_model_contract_malware_smell_onnx_v1.json").read_text())


def test_validate_model_contract_accepts_canonical_contract() -> None:
    validate_model_contract(valid_model_contract(), Path("memory://model-contract.json"))


def test_validate_model_contract_rejects_missing_sha_requirement() -> None:
    payload = copy.deepcopy(valid_model_contract())
    payload["artifact"]["sha256_required"] = False

    try:
        validate_model_contract(payload, Path("memory://model-contract.json"))
    except ContractError as exc:
        assert "sha256_required" in str(exc)
    else:
        raise AssertionError("expected missing sha requirement to fail")


def test_validate_model_contract_rejects_missing_signature_requirement() -> None:
    payload = copy.deepcopy(valid_model_contract())
    payload["artifact"]["signature_required"] = False

    try:
        validate_model_contract(payload, Path("memory://model-contract.json"))
    except ContractError as exc:
        assert "signature_required" in str(exc)
    else:
        raise AssertionError("expected missing signature requirement to fail")


def test_validate_model_contract_rejects_non_onnx_agent_path() -> None:
    payload = copy.deepcopy(valid_model_contract())
    payload["artifact"]["agent_paths"]["linux"] = "/var/lib/tamandua/models/malware_smell.bin"

    try:
        validate_model_contract(payload, Path("memory://model-contract.json"))
    except ContractError as exc:
        assert "agent_paths.linux" in str(exc)
    else:
        raise AssertionError("expected non-ONNX agent path to fail")


def test_validate_model_contract_rejects_missing_ml_local_feature() -> None:
    payload = copy.deepcopy(valid_model_contract())
    payload["runtime"]["agent_features"] = ["onnx"]

    try:
        validate_model_contract(payload, Path("memory://model-contract.json"))
    except ContractError as exc:
        assert "ml-local" in str(exc)
    else:
        raise AssertionError("expected missing ml-local feature to fail")


def test_validate_model_contract_rejects_disabled_dynamic_runtime_loading() -> None:
    payload = copy.deepcopy(valid_model_contract())
    payload["runtime"]["dynamic_runtime_loading"] = False

    try:
        validate_model_contract(payload, Path("memory://model-contract.json"))
    except ContractError as exc:
        assert "dynamic_runtime_loading" in str(exc)
    else:
        raise AssertionError("expected disabled dynamic runtime loading to fail")


def test_validate_model_contract_rejects_unpinned_ort_family() -> None:
    payload = copy.deepcopy(valid_model_contract())
    payload["runtime"]["ort_version"] = "1.21.0"

    try:
        validate_model_contract(payload, Path("memory://model-contract.json"))
    except ContractError as exc:
        assert "ORT 2.0.0 release candidate" in str(exc)
    else:
        raise AssertionError("expected wrong ORT family to fail")
