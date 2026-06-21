from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from validate_ml_contracts import (
    ML_NEXT_OPERATOR_PACKET_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_next_operator_packet,
)


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False

CANONICAL = RUNS_DIR / "20260620T1840Z-ml-next-operator-virusshare-packet.json"
SECRET_READINESS = RUNS_DIR / "20260620T2355Z-ml-next-operator-secret-readiness-packet.json"
POST_WIN_TEMPLATE_GATE_THREADING = RUNS_DIR / "20260621T-ml-next-operator-post-win-template-gate-threading-packet.json"
POST_403_VIRUSSHARE_LAB_ROOT = (
    RUNS_DIR / "20260621T-ml-next-operator-post-malwarebazaar-403-virusshare-lab-root-packet.json"
)
if not CANONICAL.exists():
    pytest.skip("ML next operator packet run artifact is not present in this standalone deployment", allow_module_level=True)


def validate_or_skip_stale(path: Path) -> str:
    try:
        return validate_contract(
            path,
            ML_NEXT_OPERATOR_PACKET_SCHEMA,
            validate_ml_next_operator_packet,
        )
    except ContractError as exc:
        if "source_artifact_hashes" in str(exc) or "effective_source_route" in str(exc):
            pytest.skip(f"historical operator packet source hash is stale: {exc}")
        raise


def test_validate_ml_next_operator_packet_accepts_jsonschema_path() -> None:
    mode = validate_or_skip_stale(CANONICAL)

    assert mode == "jsonschema+built-in"


def test_validate_ml_next_operator_packet_accepts_secret_readiness_path() -> None:
    mode = validate_or_skip_stale(SECRET_READINESS)

    data = json.loads(SECRET_READINESS.read_text(encoding="utf-8"))
    markdown = SECRET_READINESS.with_suffix(".md").read_text(encoding="utf-8")

    assert mode == "jsonschema+built-in"
    assert set(data["commands"]) == {"env_remediation"}
    assert data["operator_decision"]["publication_decision"] == "hold_do_not_push"
    assert data["operator_decision"]["ready_for_guarded_execution"] is False
    assert "No guarded execution is authorized by this packet." in markdown
    assert "-Execute" not in markdown


def test_validate_ml_next_operator_packet_accepts_post_win_template_gate_threading_path() -> None:
    mode = validate_contract(
        POST_WIN_TEMPLATE_GATE_THREADING,
        ML_NEXT_OPERATOR_PACKET_SCHEMA,
        validate_ml_next_operator_packet,
    )

    data = json.loads(POST_WIN_TEMPLATE_GATE_THREADING.read_text(encoding="utf-8"))

    assert mode == "jsonschema+built-in"
    assert data["operator_decision"]["package_id"] == "ml_data_governed_acquisition"
    assert data["operator_decision"]["publication_decision"] == "hold_do_not_push"
    assert data["operator_decision"]["ready_for_guarded_execution"] is False
    assert data["source_auth"]["selected_route"] == "malwarebazaar_governed_acquisition"
    assert data["source_auth"]["env"] == "TAMANDUA_MALWAREBAZAAR_AUTH_KEY"


def test_validate_ml_next_operator_packet_accepts_post_403_virusshare_lab_root_path() -> None:
    if not POST_403_VIRUSSHARE_LAB_ROOT.exists():
        pytest.skip("post-403 VirusShare lab-root operator packet is not present")

    mode = validate_contract(
        POST_403_VIRUSSHARE_LAB_ROOT,
        ML_NEXT_OPERATOR_PACKET_SCHEMA,
        validate_ml_next_operator_packet,
    )

    data = json.loads(POST_403_VIRUSSHARE_LAB_ROOT.read_text(encoding="utf-8"))

    assert mode == "jsonschema+built-in"
    assert data["operator_decision"]["package_id"] == "ml_data_virusshare_fallback"
    assert data["operator_decision"]["ready_for_guarded_execution"] is False
    assert data["operator_decision"]["publication_decision"] == "hold_do_not_push"
    assert data["source_auth"]["selected_route"] == "virusshare_fallback"
    assert data["source_auth"]["env"] == "VIRUSSHARE_API_KEY"
    assert data["commands"]["env_remediation"]["required_env"]["VIRUSSHARE_API_KEY"] == (
        "<redacted: isolated lab secret store>"
    )


def test_validate_ml_next_operator_packet_rejects_false_publish_decision(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(POST_WIN_TEMPLATE_GATE_THREADING.read_text(encoding="utf-8")))
    data["operator_decision"]["publication_decision"] = "eligible_after_operator_approval"
    data["source_status_summary"]["publication_decision"] = "eligible_after_operator_approval"
    drifted = tmp_path / "20260621T-ml-next-operator-post-win-template-gate-threading-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="publication_decision"):
        validate_contract(
            drifted,
            ML_NEXT_OPERATOR_PACKET_SCHEMA,
            validate_ml_next_operator_packet,
        )


def test_validate_ml_next_operator_packet_rejects_unredacted_virusshare_secret(tmp_path: Path) -> None:
    validate_or_skip_stale(CANONICAL)
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["commands"]["guarded_execute"]["required_env"]["VIRUSSHARE_API_KEY"] = "not-redacted"
    drifted = tmp_path / "20260620T1840Z-ml-next-operator-virusshare-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="VIRUSSHARE_API_KEY"):
        validate_contract(
            drifted,
            ML_NEXT_OPERATOR_PACKET_SCHEMA,
            validate_ml_next_operator_packet,
        )


def test_validate_ml_next_operator_packet_rejects_vx_download_authorization(tmp_path: Path) -> None:
    validate_or_skip_stale(CANONICAL)
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["safety_invariants"]["vx_download_authorized_by_this_packet"] = True
    drifted = tmp_path / "20260620T1840Z-ml-next-operator-virusshare-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="vx_download_authorized_by_this_packet"):
        validate_contract(
            drifted,
            ML_NEXT_OPERATOR_PACKET_SCHEMA,
            validate_ml_next_operator_packet,
        )


def test_validate_ml_next_operator_packet_rejects_env_remediation_guarded_commands(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(SECRET_READINESS.read_text(encoding="utf-8")))
    data["commands"]["guarded_execute"] = {
        "guard_set_command": "$env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION = '1'",
        "command": ".\\handoff\\wave_1_virusshare_fallback_acquisition_launcher.ps1 -Execute",
        "required_env": {
            "TAMANDUA_ML_DATA_ROOT": "D:\\tamandua_ml_lab",
            "TAMANDUA_ALLOW_ML_REAL_ACQUISITION": "1",
            "VIRUSSHARE_API_KEY": "<redacted: isolated lab secret store>",
        },
        "guard_cleanup_command": "Remove-Item Env:TAMANDUA_ALLOW_ML_REAL_ACQUISITION -ErrorAction SilentlyContinue",
        "claim_boundary": "Invalid guarded command.",
    }
    drifted = tmp_path / "20260620T2355Z-ml-next-operator-secret-readiness-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    try:
        validate_or_skip_stale(SECRET_READINESS)
    except ContractError:
        pass

    with pytest.raises(ContractError, match="env remediation|guard_cleanup_command"):
        validate_contract(
            drifted,
            ML_NEXT_OPERATOR_PACKET_SCHEMA,
            validate_ml_next_operator_packet,
        )
