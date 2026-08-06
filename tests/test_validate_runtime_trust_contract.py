import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(os.environ.get("TAMANDUA_ROOT", Path(__file__).resolve().parents[3]))
SCRIPTS = ROOT / "tools" / "detection_validation" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from validate_runtime_trust_contract import (  # noqa: E402
    GOLDEN_PATH,
    PLATFORM_CASES,
    canonical_sha256,
    load_json,
    map_app_guard_v1,
    platform_contract_errors,
    validate,
    validation_errors,
)


def golden():
    return load_json(GOLDEN_PATH)


def test_golden_is_deterministic_lossless_core_mapping():
    value = golden()
    source = value["compatibility"]["source_payload"]
    assert map_app_guard_v1(source) == value
    assert value["compatibility"]["source_payload_sha256"] == canonical_sha256(source)
    assert value["compatibility"]["core_fields_lossless"] is True
    assert validation_errors(value) == []


def test_all_six_platform_contracts_validate_without_implying_support():
    results = platform_contract_errors(golden())
    assert set(results) == set(PLATFORM_CASES)
    assert results == {platform: [] for platform in PLATFORM_CASES}
    assert golden()["capability_report"]["state"] == "degraded"


def test_anti_cheat_profile_requires_game_client_without_implying_enforcement():
    payload = golden()
    payload["profile"] = "anti_cheat"
    payload["platform"] = "windows"
    payload["protected_target"]["kind"] = "game_client"
    direct_source = {"profile_case": "anti_cheat_windows"}
    payload["compatibility"] = {
        "source_schema": "tamandua.runtime_trust.event/v1",
        "mapping_version": "runtime_trust_v1_direct",
        "source_payload_sha256": canonical_sha256(direct_source),
        "source_payload": direct_source,
        "core_fields_lossless": True,
        "unmapped_fields": [],
    }
    assert validation_errors(payload) == []

    payload["protected_target"]["kind"] = "desktop_process"
    assert validation_errors(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("platform", "solaris"),
        ("profile", "universal_guard"),
    ],
)
def test_unknown_platform_and_profile_are_rejected(field, value):
    payload = golden()
    payload[field] = value
    assert validation_errors(payload)


def test_profile_target_mismatch_and_unknown_fields_are_rejected():
    mismatch = golden()
    mismatch["protected_target"]["kind"] = "desktop_process"
    assert validation_errors(mismatch)

    extra = golden()
    extra["silent_support_assumption"] = True
    assert validation_errors(extra)


def test_raw_content_and_probability_shaped_signal_are_rejected():
    raw = golden()
    raw["evidence_boundary"]["contains_raw_content"] = True
    assert validation_errors(raw)

    probability = golden()
    probability["signals"][0]["confidence"] = 0.99
    assert validation_errors(probability)


def test_source_payload_tamper_and_mapping_drift_are_rejected():
    payload = golden()
    payload["compatibility"]["source_payload"]["risk"]["score"] = 1
    assert any("source_payload_sha256" in error for error in validation_errors(payload))

    wrong_mapping = golden()
    wrong_mapping["compatibility"]["mapping_version"] = "runtime_trust_v1_direct"
    assert validation_errors(wrong_mapping)

    normalized_drift = golden()
    normalized_drift["evaluation"]["score"] = 1
    assert any("deterministic App Guard v1 mapping" in error for error in validation_errors(normalized_drift))


def test_missing_legacy_context_is_explicitly_degraded():
    source = copy.deepcopy(golden()["compatibility"]["source_payload"])
    source.pop("event_id")
    source.pop("session")
    source["app"].pop("build")
    mapped = map_app_guard_v1(source)
    assert mapped["capability_report"]["state"] == "degraded"
    assert mapped["scope"] == {"tenant_resolution": "unresolved_legacy_adapter"}
    assert mapped["evaluation"]["evidence_class"] == "legacy_unclassified"
    assert "source_session_id_was_missing" in mapped["evaluation"]["limitations"]
    assert "source_build_id_was_missing" in mapped["evaluation"]["limitations"]
    assert validation_errors(mapped) == []


def test_cli_keeps_claim_boundary_synthetic_only():
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "validate_runtime_trust_contract.py"), "--strict"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["ok"] is True
    assert report["evidence_class"] == "synthetic_contract"
    assert report["external_claim_allowed"] is False
    assert "production_readiness" in report["non_claims"]
