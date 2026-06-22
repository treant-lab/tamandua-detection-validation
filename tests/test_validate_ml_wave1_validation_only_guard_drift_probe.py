from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    WAVE1_VALIDATION_ONLY_GUARD_DRIFT_PROBE_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_validation_only_guard_drift_probe,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-validation-only-guard-drift-probe.json"


def test_validate_wave1_validation_only_guard_drift_probe_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_VALIDATION_ONLY_GUARD_DRIFT_PROBE_SCHEMA, validate_wave1_validation_only_guard_drift_probe)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_validation_only_guard_drift_probe_rejects_execute_command(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["probe"]["command"].append("-Execute")
    drifted = tmp_path / "20260604T-ml-wave1-validation-only-guard-drift-probe.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="without -Execute"):
        validate_contract(drifted, WAVE1_VALIDATION_ONLY_GUARD_DRIFT_PROBE_SCHEMA, validate_wave1_validation_only_guard_drift_probe)


def test_validate_wave1_validation_only_guard_drift_probe_rejects_would_run_output(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["probe"]["stdout_preview"] = "Command that would run after -Execute and TAMANDUA_ALLOW_ML_REAL_ACQUISITION=1:"
    drifted = tmp_path / "20260604T-ml-wave1-validation-only-guard-drift-probe.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="would-run"):
        validate_contract(drifted, WAVE1_VALIDATION_ONLY_GUARD_DRIFT_PROBE_SCHEMA, validate_wave1_validation_only_guard_drift_probe)
