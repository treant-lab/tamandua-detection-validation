#!/usr/bin/env python3
"""Validate shared Runtime Trust signal/capability vocabulary contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[3]
SIGNAL_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_signal_v1.schema.json"
CAPABILITY_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_capability_report_v1.schema.json"
EVENT_SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_event_v1.schema.json"
CAPABILITY_GOLDEN_PATH = ROOT / "schemas" / "examples" / "runtime_trust_capability_report_v1.json"
MAX_JSON_BYTES = 256 * 1024


class RuntimeTrustVocabularyError(ValueError):
    """Raised for bounded-load or semantic vocabulary failures."""


def _reject_non_finite(value: str) -> None:
    raise RuntimeTrustVocabularyError(f"non-finite JSON constant rejected: {value}")


def load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise RuntimeTrustVocabularyError(f"JSON document exceeds {MAX_JSON_BYTES} bytes: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_non_finite)
    if not isinstance(value, dict):
        raise RuntimeTrustVocabularyError(f"expected JSON object: {path}")
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def schema_errors(value: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    return [
        f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in errors
    ]


def semantic_errors(capability_report: dict[str, Any], event_schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_capability_ref = "https://schemas.tamandua.local/runtime_trust_capability_report_v1.schema.json"
    expected_signal_ref = "https://schemas.tamandua.local/runtime_trust_signal_v1.schema.json"
    if event_schema.get("properties", {}).get("capability_report", {}).get("$ref") != expected_capability_ref:
        errors.append("event capability_report must reference the shared v1 capability schema")
    if event_schema.get("properties", {}).get("signals", {}).get("items", {}).get("$ref") != expected_signal_ref:
        errors.append("event signals items must reference the shared v1 signal schema")

    capabilities = capability_report.get("capabilities") or []
    ids = [item.get("capability_id") for item in capabilities if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        errors.append("capability_id values must be unique within a report")
    missing = set(capability_report.get("missing_capabilities") or [])
    supported = {
        item["capability_id"]
        for item in capabilities
        if isinstance(item, dict) and item.get("state") == "supported"
    }
    overlap = sorted(missing & supported)
    if overlap:
        errors.append(f"supported capabilities cannot also be missing: {overlap}")
    if capability_report.get("state") == "supported" and (
        capability_report.get("missing_capabilities") or capability_report.get("degraded_reasons")
    ):
        errors.append("supported report cannot declare missing capabilities or degraded reasons")
    return errors


def validate(strict: bool = False) -> dict[str, Any]:
    signal_schema = load_json(SIGNAL_SCHEMA_PATH)
    capability_schema = load_json(CAPABILITY_SCHEMA_PATH)
    event_schema = load_json(EVENT_SCHEMA_PATH)
    capability_report = load_json(CAPABILITY_GOLDEN_PATH)
    Draft202012Validator.check_schema(signal_schema)
    errors = schema_errors(capability_report, capability_schema)
    errors.extend(semantic_errors(capability_report, event_schema))
    serialized = canonical_json(capability_report)
    if json.loads(serialized) != capability_report:
        errors.append("canonical serialization is not lossless")
    if strict and capability_report.get("state") != "degraded":
        errors.append("strict synthetic golden must retain explicit degraded state")
    return {
        "schema": "tamandua.runtime_trust.vocabulary_validation/v1",
        "ok": not errors,
        "evidence_class": "synthetic_contract",
        "external_claim_allowed": False,
        "canonical_capability_report_sha256": canonical_sha256(capability_report),
        "errors": errors,
        "non_claims": [
            "runtime_detection_coverage",
            "physical_platform_evidence",
            "enforcement",
            "production_readiness",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(strict=args.strict)
    except (OSError, json.JSONDecodeError, RuntimeTrustVocabularyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
