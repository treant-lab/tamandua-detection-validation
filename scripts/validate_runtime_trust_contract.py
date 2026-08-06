#!/usr/bin/env python3
"""Validate the additive Runtime Trust event contract and App Guard v1 adapter."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_event_v1.schema.json"
GOLDEN_PATH = ROOT / "schemas" / "examples" / "runtime_trust_event_mobile_v1.json"
APP_GUARD_SCHEMA_PATH = ROOT / "sdk" / "mobile" / "schema" / "app_guard_event.schema.json"
SIGNAL_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_signal_v1.schema.json"
CAPABILITY_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_capability_report_v1.schema.json"
EVALUATION_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_evaluation_v1.schema.json"
MAX_JSON_BYTES = 256 * 1024
PLATFORM_CASES = {
    "android": ("mobile_app_guard", "mobile_app"),
    "ios": ("mobile_app_guard", "mobile_app"),
    "windows": ("desktop_app_guard", "desktop_process"),
    "linux": ("desktop_app_guard", "desktop_process"),
    "macos": ("desktop_app_guard", "desktop_process"),
    "web": ("web_guard", "web_app"),
}
FORBIDDEN_CONTENT_KEYS = {
    "credentials",
    "keystrokes",
    "raw_dom",
    "raw_memory",
    "request_body",
    "response_body",
    "screen_content",
}
FORBIDDEN_CONTENT_KEY_FRAGMENTS = {
    "credential",
    "keystroke",
    "password",
    "rawdom",
    "rawmemory",
    "requestbody",
    "responsebody",
    "screencontent",
}


class RuntimeTrustContractError(ValueError):
    """Raised when a runtime-trust contract or adapter invariant fails."""


def _reject_non_finite(value: str) -> None:
    raise RuntimeTrustContractError(f"non-finite JSON constant rejected: {value}")


def load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise RuntimeTrustContractError(f"JSON document exceeds {MAX_JSON_BYTES} bytes: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_non_finite)
    if not isinstance(value, dict):
        raise RuntimeTrustContractError(f"expected JSON object: {path}")
    return value


def canonical_sha256(value: dict[str, Any]) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def local_schema_registry() -> Registry:
    schemas = (
        load_json(SIGNAL_SCHEMA_PATH),
        load_json(CAPABILITY_SCHEMA_PATH),
        load_json(EVALUATION_SCHEMA_PATH),
    )
    return Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )


def schema_errors(
    value: dict[str, Any], schema: dict[str, Any], registry: Registry | None = None
) -> list[str]:
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
        registry=registry or Registry(),
    )
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.absolute_path))
    return [
        f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in errors
    ]


def _stable_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def capability_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    capabilities = report.get("capabilities") or []
    ids = [item.get("capability_id") for item in capabilities if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        errors.append("capability_report capability_id values must be unique")
    missing = set(report.get("missing_capabilities") or [])
    supported = {
        item["capability_id"]
        for item in capabilities
        if isinstance(item, dict) and item.get("state") == "supported"
    }
    overlap = sorted(missing & supported)
    if overlap:
        errors.append(f"capability_report supported capabilities cannot also be missing: {overlap}")
    return errors


def forbidden_content_paths(value: Any, path: str = "compatibility.source_payload") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if str(key).lower() in FORBIDDEN_CONTENT_KEYS or any(
                fragment in normalized_key for fragment in FORBIDDEN_CONTENT_KEY_FRAGMENTS
            ):
                paths.append(child_path)
            paths.extend(forbidden_content_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(forbidden_content_paths(child, f"{path}[{index}]"))
    return paths


def _evidence_strength(signal: dict[str, Any]) -> str:
    confidence = signal.get("confidence")
    if not isinstance(confidence, int):
        return "unknown"
    if confidence >= 90:
        return "strong"
    if confidence >= 60:
        return "moderate"
    return "weak"


def map_app_guard_v1(source: dict[str, Any]) -> dict[str, Any]:
    """Map a validated App Guard v1 payload without mutating or discarding it."""
    source_hash = canonical_sha256(source)
    app = source["app"]
    risk = source["risk"]
    source_session = source.get("session") or {}
    source_signals = source.get("signals") or []
    event_id = source.get("event_id") or f"legacy-{source_hash[:32]}"
    timestamp = source["timestamp"]

    limitations = [
        "legacy_v1_has_no_runtime_trust_capability_negotiation",
        "legacy_v1_has_no_evidence_class",
        "tenant_resolution_requires_server_context",
        "synthetic_fixture_is_not_physical_or_release_evidence",
    ]
    if not source.get("event_id"):
        limitations.append("source_event_id_was_derived_from_payload_digest")
    if not source_session.get("session_id"):
        limitations.append("source_session_id_was_missing")
    if not source_session.get("workflow"):
        limitations.append("source_workflow_was_missing")
    if not app.get("build"):
        limitations.append("source_build_id_was_missing")

    target: dict[str, Any] = {
        "kind": "mobile_app",
        "target_id": app["package_or_bundle_id"],
        "build_id": str(app.get("build") or "unknown_legacy_build"),
        "version": app["version"],
    }
    if app.get("signing_hash"):
        target["signer_digest"] = app["signing_hash"]
    if app.get("manifest_hash"):
        target["manifest_digest"] = app["manifest_hash"]

    session: dict[str, Any] = {
        "session_id": source_session.get("session_id") or f"legacy-event:{event_id}",
        "workflow": source_session.get("workflow") or "unspecified_legacy_workflow",
    }
    for name in ("user_id_hash", "transaction_id_hash"):
        if source_session.get(name):
            session[name] = source_session[name]

    evaluation: dict[str, Any] = {
        "score": risk["score"],
        "decision": risk["decision"],
        "reasons": _stable_unique(risk.get("reasons") or []),
        "decision_source": "legacy_adapter",
        "evidence_class": "legacy_unclassified",
        "external_claim_allowed": False,
        "limitations": limitations,
    }
    policy = risk.get("policy") or {}
    if policy.get("policy_id"):
        evaluation["policy_id"] = policy["policy_id"]

    signals = []
    for index, signal in enumerate(source_signals):
        evidence = signal.get("evidence") or {}
        state = "not_observed" if evidence.get("kind") == "boolean" and evidence.get("value") is False else "observed"
        signals.append(
            {
                "signal_id": signal["name"],
                "detector_family": signal.get("category") or "legacy_unspecified",
                "state": state,
                "evidence_strength": _evidence_strength(signal),
                "source": "legacy_adapter",
                "observed_at": evidence.get("collected_at") or timestamp,
                "evidence_ref": {
                    "kind": "legacy_inline_metadata",
                    "source_path": f"signals[{index}].evidence",
                    "privacy_mode": evidence.get("privacy_mode") or "metadata_only",
                },
            }
        )

    return {
        "schema": "tamandua.runtime_trust.event/v1",
        "event_id": event_id,
        "observed_at": timestamp,
        "profile": "mobile_app_guard",
        "platform": source["platform"],
        "event_type": source["event_type"],
        "scope": {"tenant_resolution": "unresolved_legacy_adapter"},
        "protected_target": target,
        "session": session,
        "evaluation": evaluation,
        "capability_report": {
            "adapter_id": "tamandua.app_guard.v1_adapter",
            "adapter_version": "1",
            "state": "degraded",
            "missing_capabilities": ["runtime_trust_capability_negotiation", "tenant_resolution"],
            "degraded_reasons": ["source_schema_predates_runtime_trust_capability_report"],
        },
        "signals": signals,
        "evidence_boundary": {
            "metadata_only": True,
            "contains_raw_content": False,
            "excluded_fields": ["raw_memory", "screen_content", "request_body", "response_body", "credentials"],
        },
        "compatibility": {
            "source_schema": "tamandua.app_guard.event/v1",
            "mapping_version": "app_guard_v1_to_runtime_trust_v1",
            "source_payload_sha256": source_hash,
            "source_payload": copy.deepcopy(source),
            "core_fields_lossless": True,
            "unmapped_fields": [],
        },
    }


def validation_errors(value: dict[str, Any]) -> list[str]:
    runtime_schema = load_json(SCHEMA_PATH)
    errors = schema_errors(value, runtime_schema, local_schema_registry())
    capability_report = value.get("capability_report")
    if isinstance(capability_report, dict):
        errors.extend(capability_semantic_errors(capability_report))
    evaluation = value.get("evaluation")
    if (
        isinstance(capability_report, dict)
        and isinstance(evaluation, dict)
        and evaluation.get("capability_state") is not None
        and evaluation.get("capability_state") != capability_report.get("state")
    ):
        errors.append("evaluation.capability_state must match capability_report.state")
    compatibility = value.get("compatibility")
    if not isinstance(compatibility, dict):
        return errors
    source_payload = compatibility.get("source_payload")
    expected_hash = compatibility.get("source_payload_sha256")
    if isinstance(source_payload, dict) and expected_hash != canonical_sha256(source_payload):
        errors.append("compatibility.source_payload_sha256 does not match canonical source payload")
    if isinstance(source_payload, dict):
        forbidden_paths = forbidden_content_paths(source_payload)
        if forbidden_paths:
            errors.append(
                "compatibility.source_payload violates metadata-only boundary at: "
                + ", ".join(forbidden_paths)
            )
    if compatibility.get("source_schema") == "tamandua.app_guard.event/v1" and isinstance(source_payload, dict):
        app_guard_schema = load_json(APP_GUARD_SCHEMA_PATH)
        source_errors = schema_errors(source_payload, app_guard_schema)
        errors.extend(f"compatibility.source_payload.{error}" for error in source_errors)
        if compatibility.get("mapping_version") != "app_guard_v1_to_runtime_trust_v1":
            errors.append("App Guard v1 source requires app_guard_v1_to_runtime_trust_v1 mapping")
        elif not source_errors and map_app_guard_v1(source_payload) != value:
            errors.append("Runtime Trust event differs from deterministic App Guard v1 mapping")
    if compatibility.get("source_schema") == "tamandua.runtime_trust.event/v1" and compatibility.get(
        "mapping_version"
    ) != "runtime_trust_v1_direct":
        errors.append("direct Runtime Trust source requires runtime_trust_v1_direct mapping")
    return errors


def platform_contract_errors(golden: dict[str, Any]) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    for platform, (profile, kind) in PLATFORM_CASES.items():
        candidate = copy.deepcopy(golden)
        candidate["profile"] = profile
        candidate["platform"] = platform
        candidate["protected_target"]["kind"] = kind
        candidate["compatibility"] = {
            "source_schema": "tamandua.runtime_trust.event/v1",
            "mapping_version": "runtime_trust_v1_direct",
            "source_payload_sha256": canonical_sha256({"platform_case": platform}),
            "source_payload": {"platform_case": platform},
            "core_fields_lossless": True,
            "unmapped_fields": [],
        }
        results[platform] = validation_errors(candidate)
    return results


def validate(strict: bool = False) -> dict[str, Any]:
    golden = load_json(GOLDEN_PATH)
    errors = validation_errors(golden)
    source = golden.get("compatibility", {}).get("source_payload")
    if not isinstance(source, dict):
        errors.append("golden compatibility source payload missing")
    else:
        mapped = map_app_guard_v1(source)
        if mapped != golden:
            errors.append("golden event differs from deterministic App Guard v1 mapping")
    platform_results = platform_contract_errors(golden)
    for platform, platform_errors in platform_results.items():
        errors.extend(f"platform.{platform}: {error}" for error in platform_errors)
    if strict and golden.get("evaluation", {}).get("external_claim_allowed") is not False:
        errors.append("strict synthetic contract must keep external_claim_allowed=false")
    return {
        "schema": "tamandua.runtime_trust.contract_validation/v1",
        "ok": not errors,
        "evidence_class": "synthetic_contract",
        "external_claim_allowed": False,
        "platforms_validated": sorted(platform_results),
        "errors": errors,
        "non_claims": [
            "runtime_writer_enabled",
            "server_ingestion",
            "physical_device_or_desktop_evidence",
            "enforcement",
            "platform_parity",
            "production_readiness",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(strict=args.strict)
    except (OSError, json.JSONDecodeError, RuntimeTrustContractError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
