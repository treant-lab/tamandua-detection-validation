from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    WAVE1_GUARDED_EXTRA_GUARD_DRIFT_PROBE_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave1_guarded_extra_guard_drift_probe,
)


ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "docs" / "benchmarks" / "runs" / "20260604T-ml-wave1-guarded-extra-guard-drift-probe.json"


def test_validate_wave1_guarded_extra_guard_drift_probe_accepts_jsonschema_path() -> None:
    mode = validate_contract(CANONICAL, WAVE1_GUARDED_EXTRA_GUARD_DRIFT_PROBE_SCHEMA, validate_wave1_guarded_extra_guard_drift_probe)

    assert mode == "jsonschema+built-in"


def test_validate_wave1_guarded_extra_guard_drift_probe_rejects_launcher_command(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["probe"]["command"].append("wave_1_real_acquisition_launcher.ps1")
    drifted = tmp_path / "20260604T-ml-wave1-guarded-extra-guard-drift-probe.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="must not invoke acquisition launcher"):
        validate_contract(drifted, WAVE1_GUARDED_EXTRA_GUARD_DRIFT_PROBE_SCHEMA, validate_wave1_guarded_extra_guard_drift_probe)


def test_validate_wave1_guarded_extra_guard_drift_probe_rejects_success_return(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["probe"]["returncode"] = 0
    drifted = tmp_path / "20260604T-ml-wave1-guarded-extra-guard-drift-probe.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="returncode"):
        validate_contract(drifted, WAVE1_GUARDED_EXTRA_GUARD_DRIFT_PROBE_SCHEMA, validate_wave1_guarded_extra_guard_drift_probe)
