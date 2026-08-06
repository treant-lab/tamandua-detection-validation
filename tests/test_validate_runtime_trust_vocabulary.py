from __future__ import annotations

import copy
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "validate_runtime_trust_vocabulary.py"
SPEC = importlib.util.spec_from_file_location("validate_runtime_trust_vocabulary", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CONTRACT_SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "validate_runtime_trust_contract.py"
CONTRACT_SPEC = importlib.util.spec_from_file_location("validate_runtime_trust_contract_for_vocabulary", CONTRACT_SCRIPT)
assert CONTRACT_SPEC and CONTRACT_SPEC.loader
CONTRACT = importlib.util.module_from_spec(CONTRACT_SPEC)
CONTRACT_SPEC.loader.exec_module(CONTRACT)


def direct_event() -> dict:
    event = CONTRACT.load_json(CONTRACT.GOLDEN_PATH)
    source_payload = {"platform_case": event["platform"]}
    event["compatibility"] = {
        "source_schema": "tamandua.runtime_trust.event/v1",
        "mapping_version": "runtime_trust_v1_direct",
        "source_payload_sha256": CONTRACT.canonical_sha256(source_payload),
        "source_payload": source_payload,
        "core_fields_lossless": True,
        "unmapped_fields": [],
    }
    return event


def test_strict_report_is_synthetic_and_deterministic() -> None:
    first = MODULE.validate(strict=True)
    second = MODULE.validate(strict=True)
    assert first == second
    assert first["ok"] is True
    assert first["evidence_class"] == "synthetic_contract"
    assert first["external_claim_allowed"] is False


def test_event_references_shared_vocabularies() -> None:
    event_schema = MODULE.load_json(MODULE.EVENT_SCHEMA_PATH)
    report = MODULE.load_json(MODULE.CAPABILITY_GOLDEN_PATH)
    assert MODULE.semantic_errors(report, event_schema) == []


def test_duplicate_capability_ids_are_rejected_semantically() -> None:
    event_schema = MODULE.load_json(MODULE.EVENT_SCHEMA_PATH)
    report = MODULE.load_json(MODULE.CAPABILITY_GOLDEN_PATH)
    report["capabilities"].append(copy.deepcopy(report["capabilities"][0]))
    assert "capability_id values must be unique within a report" in MODULE.semantic_errors(report, event_schema)


def test_supported_capability_cannot_be_missing() -> None:
    event_schema = MODULE.load_json(MODULE.EVENT_SCHEMA_PATH)
    report = MODULE.load_json(MODULE.CAPABILITY_GOLDEN_PATH)
    report["missing_capabilities"] = ["loaded_module_observation"]
    errors = MODULE.semantic_errors(report, event_schema)
    assert any("supported capabilities cannot also be missing" in error for error in errors)


def test_supported_report_cannot_hide_degradation() -> None:
    event_schema = MODULE.load_json(MODULE.EVENT_SCHEMA_PATH)
    report = MODULE.load_json(MODULE.CAPABILITY_GOLDEN_PATH)
    report["state"] = "supported"
    errors = MODULE.semantic_errors(report, event_schema)
    assert "supported report cannot declare missing capabilities or degraded reasons" in errors


def test_probability_shaped_signal_confidence_is_not_in_contract() -> None:
    signal_schema = MODULE.load_json(MODULE.SIGNAL_SCHEMA_PATH)
    signal = {
        "signal_id": "debugger_attached",
        "detector_family": "debugger",
        "state": "observed",
        "evidence_strength": "moderate",
        "source": "native",
        "observed_at": "2026-07-17T12:00:00Z",
        "evidence_ref": {
            "kind": "metadata_digest",
            "source_path": "detectors.debugger",
            "privacy_mode": "metadata_only"
        },
        "confidence": 0.97
    }
    errors = MODULE.schema_errors(signal, signal_schema)
    assert any("confidence" in error for error in errors)


def test_unknown_capability_state_is_rejected() -> None:
    schema = MODULE.load_json(MODULE.CAPABILITY_SCHEMA_PATH)
    report = MODULE.load_json(MODULE.CAPABILITY_GOLDEN_PATH)
    report["capabilities"][0]["state"] = "clean"
    assert MODULE.schema_errors(report, schema)


def test_event_rejects_supported_report_with_declared_gaps() -> None:
    event = direct_event()
    event["capability_report"]["state"] = "supported"
    assert CONTRACT.validation_errors(event)


def test_event_rejects_duplicate_capability_ids() -> None:
    event = direct_event()
    event["capability_report"]["capabilities"] = [
        {
            "capability_id": "loaded_module_observation",
            "state": "supported",
            "evidence_status": "source_validated",
            "limitations": ["synthetic_contract_only"],
        },
        {
            "capability_id": "loaded_module_observation",
            "state": "degraded",
            "evidence_status": "implemented",
            "limitations": ["physical_lab_pending"],
        },
    ]
    errors = CONTRACT.validation_errors(event)
    assert any("capability_id values must be unique" in error for error in errors)


def test_event_rejects_supported_capability_with_unsupported_evidence() -> None:
    event = direct_event()
    event["capability_report"]["capabilities"] = [
        {
            "capability_id": "loaded_module_observation",
            "state": "supported",
            "evidence_status": "unsupported",
            "limitations": [],
        }
    ]
    assert CONTRACT.validation_errors(event)


def test_event_rejects_raw_content_even_with_matching_source_digest() -> None:
    event = direct_event()
    source_payload = {"screen_content": "synthetic-sensitive-placeholder"}
    event["compatibility"]["source_payload"] = source_payload
    event["compatibility"]["source_payload_sha256"] = CONTRACT.canonical_sha256(source_payload)
    errors = CONTRACT.validation_errors(event)
    assert any("violates metadata-only boundary" in error for error in errors)


def test_event_rejects_unsupported_report_with_supported_capability() -> None:
    event = direct_event()
    event["capability_report"] = {
        "adapter_id": "tamandua.desktop.windows.v1",
        "adapter_version": "1",
        "state": "unsupported",
        "missing_capabilities": [],
        "degraded_reasons": [],
        "capabilities": [
            {
                "capability_id": "loaded_module_observation",
                "state": "supported",
                "evidence_status": "governed",
                "limitations": [],
            }
        ],
    }
    assert CONTRACT.validation_errors(event)


def test_direct_source_uses_allowlisted_metadata_envelope() -> None:
    event = direct_event()
    source_payload = {
        "nested": {
            "screenContent": "raw-frame",
            "password": "plaintext",
            "raw_memory_dump": "bytes",
        }
    }
    event["compatibility"]["source_payload"] = source_payload
    event["compatibility"]["source_payload_sha256"] = CONTRACT.canonical_sha256(source_payload)
    errors = CONTRACT.validation_errors(event)
    assert any("Additional properties are not allowed" in error for error in errors)
    assert any("violates metadata-only boundary" in error for error in errors)
