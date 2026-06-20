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
if not CANONICAL.exists():
    pytest.skip("ML next operator packet run artifact is not present in this standalone deployment", allow_module_level=True)


def test_validate_ml_next_operator_packet_accepts_jsonschema_path() -> None:
    mode = validate_contract(
        CANONICAL,
        ML_NEXT_OPERATOR_PACKET_SCHEMA,
        validate_ml_next_operator_packet,
    )

    assert mode == "jsonschema+built-in"


def test_validate_ml_next_operator_packet_rejects_false_publish_decision(tmp_path: Path) -> None:
    data = copy.deepcopy(json.loads(CANONICAL.read_text(encoding="utf-8")))
    data["operator_decision"]["publication_decision"] = "eligible_after_operator_approval"
    data["source_status_summary"]["publication_decision"] = "eligible_after_operator_approval"
    drifted = tmp_path / "20260620T1840Z-ml-next-operator-virusshare-packet.json"
    drifted.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ContractError, match="publication_decision"):
        validate_contract(
            drifted,
            ML_NEXT_OPERATOR_PACKET_SCHEMA,
            validate_ml_next_operator_packet,
        )


def test_validate_ml_next_operator_packet_rejects_unredacted_virusshare_secret(tmp_path: Path) -> None:
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
