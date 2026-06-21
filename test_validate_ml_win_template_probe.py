from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ML_WIN_TEMPLATE_PROBE_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_win_template_probe,
)


def win_template_probe() -> dict:
    fixtures = [
        {
            "sample_id": "win_template_pe_minimal_benign",
            "label": "goodware_fixture",
            "fixture_type": "minimal_pe_like",
            "file_type": "pe",
            "source": "synthetic://tamandua/win-template/ml-probe/minimal-pe",
            "size_bytes": 192,
            "sha256": "a" * 64,
        },
        {
            "sample_id": "win_template_agent_service_config",
            "label": "goodware_fixture",
            "fixture_type": "service_config_text",
            "file_type": "text",
            "source": "synthetic://tamandua/win-template/ml-probe/service-config",
            "size_bytes": 91,
            "sha256": "b" * 64,
        },
        {
            "sample_id": "win_template_powershell_inventory",
            "label": "admin_script_fixture",
            "fixture_type": "powershell_inventory_script",
            "file_type": "script",
            "source": "synthetic://tamandua/win-template/ml-probe/powershell-inventory",
            "size_bytes": 77,
            "sha256": "c" * 64,
        },
        {
            "sample_id": "win_template_seeded_high_entropy_control",
            "label": "control_fixture",
            "fixture_type": "seeded_high_entropy",
            "file_type": "unknown",
            "source": "synthetic://tamandua/win-template/ml-probe/high-entropy-control",
            "size_bytes": 4096,
            "sha256": "d" * 64,
        },
    ]
    return {
        "api_version": "tamandua.io/ml-win-template-probe/v1",
        "kind": "MLWinTemplateProbe",
        "metadata": {
            "generated_at": "2026-06-21T00:00:00+00:00",
            "created_by": "test",
            "claim_boundary": (
                "Safe Windows-template ML probe. Fixtures are deterministic and non-malware. "
                "Completed local inference is not a production detection benchmark."
            ),
        },
        "win_template_target": {
            "hostname": "WIN-TEMPLATE",
            "agent_id": "agent-123",
            "server_host": "192.0.2.10",
            "transport": "local_fixture_probe",
            "endpoint_contacted": False,
            "requires_live_backend_for_agent_bound_run": True,
        },
        "model": {
            "model_dir": "apps/tamandua_ml/models",
            "checkpoint_expected": "apps/tamandua_ml/models/encoder.pt",
            "checkpoint_present": False,
            "reference_embeddings_present": False,
        },
        "fixtures": fixtures,
        "inference": {
            "status": "not_run",
            "reason": "metadata-only contract fixture",
            "predictions": [],
        },
        "next_agent_bound_command": (
            "python tools\\detection_validation\\tamandua_detection_validation.py --execute "
            "--profile tools\\detection_validation\\profiles\\windows_roadmap_p0_existing_sensor_contract.json "
            "--run-id exec-windows-ml-probe-win-template --agent-id agent-123 "
            "--execution-transport tamandua-ctl --server-host 192.0.2.10 --fail-on-gate"
        ),
    }


def write_probe(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_validate_ml_win_template_probe_accepts_metadata_only_contract(tmp_path: Path) -> None:
    path = tmp_path / "win-template-probe.json"
    write_probe(path, win_template_probe())

    mode = validate_contract(path, ML_WIN_TEMPLATE_PROBE_SCHEMA, validate_ml_win_template_probe)

    assert mode == "jsonschema+built-in"


def test_validate_ml_win_template_probe_rejects_endpoint_contact(tmp_path: Path) -> None:
    payload = win_template_probe()
    payload["win_template_target"]["endpoint_contacted"] = True
    path = tmp_path / "win-template-probe.json"
    write_probe(path, payload)

    with pytest.raises(ContractError, match="endpoint_contacted"):
        validate_contract(path, ML_WIN_TEMPLATE_PROBE_SCHEMA, validate_ml_win_template_probe)


def test_validate_ml_win_template_probe_rejects_not_run_predictions(tmp_path: Path) -> None:
    payload = win_template_probe()
    payload["inference"]["predictions"] = [
        {
            "sample_id": "win_template_pe_minimal_benign",
            "sha256": "a" * 64,
            "prediction": "benign",
            "confidence": 0.9,
        }
    ]
    path = tmp_path / "win-template-probe.json"
    write_probe(path, payload)

    with pytest.raises(ContractError, match="must be empty"):
        validate_contract(path, ML_WIN_TEMPLATE_PROBE_SCHEMA, validate_ml_win_template_probe)


def test_validate_ml_win_template_probe_rejects_completed_partial_scoring(tmp_path: Path) -> None:
    payload = win_template_probe()
    payload["inference"] = {
        "status": "completed",
        "reason": "test",
        "prediction_summary": {"total": 4, "malicious": 0, "benign": 1, "other": 0},
        "predictions": [
            {
                "sample_id": "win_template_pe_minimal_benign",
                "sha256": "a" * 64,
                "prediction": "benign",
                "confidence": 0.9,
            }
        ],
    }
    path = tmp_path / "win-template-probe.json"
    write_probe(path, payload)

    with pytest.raises(ContractError, match="score every fixture"):
        validate_contract(path, ML_WIN_TEMPLATE_PROBE_SCHEMA, validate_ml_win_template_probe)


def test_validate_ml_win_template_probe_rejects_prediction_hash_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(win_template_probe())
    payload["inference"] = {
        "status": "completed",
        "reason": "test",
        "prediction_summary": {"total": 4, "malicious": 0, "benign": 4, "other": 0},
        "predictions": [
            {
                "sample_id": fixture["sample_id"],
                "sha256": ("0" * 64 if index == 0 else fixture["sha256"]),
                "prediction": "benign",
                "confidence": 0.9,
            }
            for index, fixture in enumerate(payload["fixtures"])
        ],
    }
    path = tmp_path / "win-template-probe.json"
    write_probe(path, payload)

    with pytest.raises(ContractError, match="must match fixture sha256"):
        validate_contract(path, ML_WIN_TEMPLATE_PROBE_SCHEMA, validate_ml_win_template_probe)
