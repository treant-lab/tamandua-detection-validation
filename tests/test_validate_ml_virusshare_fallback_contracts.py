from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


VALIDATION_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
RUNS_DIR = REPO_ROOT / "docs" / "benchmarks" / "runs"
sys.path.insert(0, str(VALIDATION_ROOT))

from validate_ml_contracts import (  # noqa: E402
    ML_VIRUSSHARE_FALLBACK_COMMAND_PACKET_CHECK_SCHEMA,
    ML_VIRUSSHARE_FALLBACK_READINESS_SCHEMA,
    ML_VIRUSSHARE_FALLBACK_TRANSITION_AUDIT_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_virusshare_fallback_command_packet_check,
    validate_ml_virusshare_fallback_readiness,
    validate_ml_virusshare_fallback_transition_audit,
)


READINESS = RUNS_DIR / "20260620T-ml-virusshare-fallback-readiness-secret-hardened.json"
POST_403_READINESS = RUNS_DIR / "20260621T-ml-virusshare-fallback-readiness-post-malwarebazaar-403.json"
PACKET_CHECK = RUNS_DIR / "20260618T-ml-virusshare-fallback-command-packet-check.json"
TRANSITION = RUNS_DIR / "20260618T-ml-virusshare-fallback-transition-audit.json"
POST_403_TRANSITION = RUNS_DIR / "20260621T-ml-virusshare-fallback-transition-audit-post-malwarebazaar-403.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_validate_virusshare_fallback_contracts_accept_canonical_artifacts() -> None:
    assert validate_contract(
        READINESS,
        ML_VIRUSSHARE_FALLBACK_READINESS_SCHEMA,
        validate_ml_virusshare_fallback_readiness,
    ) in {"jsonschema+built-in", "built-in"}
    assert validate_contract(
        PACKET_CHECK,
        ML_VIRUSSHARE_FALLBACK_COMMAND_PACKET_CHECK_SCHEMA,
        validate_ml_virusshare_fallback_command_packet_check,
    ) in {"jsonschema+built-in", "built-in"}
    assert validate_contract(
        TRANSITION,
        ML_VIRUSSHARE_FALLBACK_TRANSITION_AUDIT_SCHEMA,
        validate_ml_virusshare_fallback_transition_audit,
    ) in {"jsonschema+built-in", "built-in"}


def test_validate_virusshare_fallback_contracts_accept_post_malwarebazaar_403_artifacts() -> None:
    assert validate_contract(
        POST_403_READINESS,
        ML_VIRUSSHARE_FALLBACK_READINESS_SCHEMA,
        validate_ml_virusshare_fallback_readiness,
    ) in {"jsonschema+built-in", "built-in"}
    assert validate_contract(
        POST_403_TRANSITION,
        ML_VIRUSSHARE_FALLBACK_TRANSITION_AUDIT_SCHEMA,
        validate_ml_virusshare_fallback_transition_audit,
    ) in {"jsonschema+built-in", "built-in"}


def test_validate_virusshare_readiness_rejects_guarded_ready_with_secret_blockers() -> None:
    payload = copy.deepcopy(load(READINESS))
    payload["source_status_summary"]["ready_for_guarded_virusshare_fallback"] = True

    with pytest.raises(ContractError, match="blockers"):
        validate_ml_virusshare_fallback_readiness(payload, Path("memory://virusshare-readiness.json"))


def test_validate_virusshare_packet_check_rejects_inline_api_key_argument() -> None:
    payload = copy.deepcopy(load(PACKET_CHECK))
    payload["checks"][8]["detail"] = "--virusshare-api-key real-secret"

    with pytest.raises(ContractError, match="VirusShare API secrets"):
        validate_ml_virusshare_fallback_command_packet_check(payload, Path("memory://virusshare-packet-check.json"))


def test_validate_virusshare_packet_check_rejects_real_api_key_assignment() -> None:
    payload = copy.deepcopy(load(PACKET_CHECK))
    payload["checks"][8]["detail"] = "$env:VIRUSSHARE_API_KEY = 'real-secret'"

    with pytest.raises(ContractError, match="placeholder"):
        validate_ml_virusshare_fallback_command_packet_check(payload, Path("memory://virusshare-packet-check.json"))


def test_validate_virusshare_transition_rejects_manifest_ready_without_receipts() -> None:
    payload = copy.deepcopy(load(TRANSITION))
    payload["source_status_summary"]["ready_for_manifest_publish_after_fallback"] = True

    with pytest.raises(ContractError, match="manifest publish"):
        validate_ml_virusshare_fallback_transition_audit(payload, Path("memory://virusshare-transition.json"))
