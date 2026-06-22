from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


try:
    from root_resolver import ROOT
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    ContractError,
    ML_AGENT_RUSH_BENCHMARK_EXECUTION_PACKET_SCHEMA,
    validate_contract,
    validate_ml_agent_rush_benchmark_execution_packet,
)


ARTIFACT = ROOT / "docs/benchmarks/runs/20260621T-ml-agent-rush-benchmark-execution-packet.json"


def load_packet() -> dict:
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def test_real_agent_rush_packet_validates() -> None:
    mode = validate_contract(
        ARTIFACT,
        ML_AGENT_RUSH_BENCHMARK_EXECUTION_PACKET_SCHEMA,
        validate_ml_agent_rush_benchmark_execution_packet,
    )

    assert mode == "jsonschema+built-in"


def test_agent_rush_packet_rejects_detection_claim_go() -> None:
    packet = load_packet()
    packet["go_no_go"]["production_detection_claim"] = "go"

    try:
        validate_ml_agent_rush_benchmark_execution_packet(packet, Path("memory://packet.json"))
    except ContractError as exc:
        assert "production_detection_claim" in str(exc)
    else:
        raise AssertionError("expected ContractError")


def test_agent_rush_packet_requires_false_positive_tracking_for_safe_fixture() -> None:
    packet = copy.deepcopy(load_packet())
    packet["current_detection_evidence"]["summary"]["false_positive_candidate_sample_ids"] = []

    try:
        validate_ml_agent_rush_benchmark_execution_packet(packet, Path("memory://packet.json"))
    except ContractError as exc:
        assert "false_positive_candidate_sample_ids" in str(exc)
    else:
        raise AssertionError("expected ContractError")
