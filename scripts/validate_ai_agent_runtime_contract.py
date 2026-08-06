#!/usr/bin/env python3
"""Validate experimental AI-agent runtime snapshot/event contracts.

This gate proves schema and deterministic integrity semantics for local fixtures.
It does not prove live collection, tenant isolation, security effectiveness,
release readiness, production readiness, or suitability for external claims.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Iterable

import jsonschema

from ai_runtime_integrity_v2 import validation_errors_v2


SCRIPT_DIR = Path(__file__).resolve().parent
STANDALONE_ROOT = SCRIPT_DIR.parent
if (STANDALONE_ROOT / "schemas").exists() and (STANDALONE_ROOT / "fixtures").exists():
    ROOT = STANDALONE_ROOT
    FIXTURES_DIR = ROOT / "fixtures"
else:
    ROOT = Path(os.environ.get("TAMANDUA_ROOT", SCRIPT_DIR.parents[2]))
    FIXTURES_DIR = ROOT / "tools" / "detection_validation" / "fixtures"

SNAPSHOT_SCHEMA = ROOT / "schemas" / "ai_agent_runtime_snapshot_v1.schema.json"
EVENT_SCHEMA = ROOT / "schemas" / "ai_agent_runtime_event_v1.schema.json"
SNAPSHOT_SCHEMA_V2 = ROOT / "schemas" / "ai_agent_runtime_snapshot_v2.schema.json"
EVENT_SCHEMA_V2 = ROOT / "schemas" / "ai_agent_runtime_event_v2.schema.json"
DEFAULT_FIXTURES = [
    FIXTURES_DIR / "ai_agent_runtime_codex_snapshot_v1.json",
    FIXTURES_DIR / "ai_agent_runtime_codex_event_v1.json",
    FIXTURES_DIR / "ai_agent_runtime_claude_snapshot_v1.json",
    FIXTURES_DIR / "ai_agent_runtime_claude_event_v1.json",
    FIXTURES_DIR / "ai_agent_runtime_opencode_snapshot_v1.json",
    FIXTURES_DIR / "ai_agent_runtime_opencode_event_v1.json",
]
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
EXPECTED_CHANNELS = {
    "session_metadata", "messages", "summaries", "commands", "tool_inputs",
    "tool_results", "file_evidence", "processes", "ports", "mcp", "tokens",
    "context", "rate_limits",
}
CONTENT_CHANNELS = {
    "message": "messages", "summary": "summaries", "command": "commands",
    "tool_input": "tool_inputs", "tool_result": "tool_results",
    "file_evidence": "file_evidence",
}
CONTENT_EVENT_TYPES = set(CONTENT_CHANNELS)
ZERO_SHA256 = "0" * 64


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def load_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"{path}: document exceeds 64 MiB; transport it as chunks")
    payload = json.loads(raw, parse_constant=_reject_non_finite)
    if isinstance(payload, dict) and payload.get("api_version") in {
        "tamandua.io/ai-agent-runtime-snapshot/v2",
        "tamandua.io/ai-agent-runtime-event/v2",
    }:
        payload = json.loads(raw, parse_constant=_reject_non_finite, object_pairs_hook=_v2_object)
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return payload


def _v2_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key is forbidden in v2: {key!r}")
        result[key] = value
    return result


def _schema_path(payload: dict[str, Any]) -> Path:
    version = payload.get("api_version")
    if version == "tamandua.io/ai-agent-runtime-snapshot/v1":
        return SNAPSHOT_SCHEMA
    if version == "tamandua.io/ai-agent-runtime-event/v1":
        return EVENT_SCHEMA
    if version == "tamandua.io/ai-agent-runtime-snapshot/v2":
        return SNAPSHOT_SCHEMA_V2
    if version == "tamandua.io/ai-agent-runtime-event/v2":
        return EVENT_SCHEMA_V2
    raise ValueError(f"unsupported api_version: {version!r}")


def build_validator(payload: dict[str, Any]) -> jsonschema.Draft202012Validator:
    schema = load_json(_schema_path(payload))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def event_digest(payload: dict[str, Any]) -> str:
    integrity = payload.get("integrity", {})
    previous = integrity.get("previous_event_digest") or ""
    material = (
        f"{integrity.get('stream_id')}:{integrity.get('sequence')}:{previous}:"
        f"{payload.get('raw_evidence', {}).get('content_sha256')}"
    )
    return _sha256(material.encode("utf-8"))


def snapshot_digest(payload: dict[str, Any]) -> str:
    integrity = payload.get("integrity", {})
    last = integrity.get("last_event_digest") or ""
    material = (
        f"{payload.get('snapshot_id')}:{integrity.get('stream_id')}:"
        f"{integrity.get('event_count')}:{last}"
    )
    return _sha256(material.encode("utf-8"))


def _walk_finite(value: Any, errors: list[str], path: str = "<root>") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        errors.append(f"{path}: number must be finite")
    elif isinstance(value, dict):
        for key, child in value.items():
            _walk_finite(child, errors, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_finite(child, errors, f"{path}.{index}")


def _governance_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    tenant = payload.get("tenant", {})
    governance = payload.get("governance", {})
    if tenant.get("tenant_id") == tenant.get("organization_id"):
        errors.append("tenant_id and organization_id must be independently bound identifiers")
    collection_basis = governance.get("collection_basis")
    if not isinstance(collection_basis, str) or collection_basis.strip().lower() in {"", "unknown", "none"}:
        errors.append("collection_basis must identify an affirmative governed basis")
    return errors


def _claim_errors(payload: dict[str, Any]) -> list[str]:
    claims = payload.get("claims", {})
    errors: list[str] = []
    if claims.get("maturity") != "experimental":
        errors.append("maturity must remain experimental")
    for field in ("product_ready", "release_ready", "production_ready", "external_claims_allowed"):
        if claims.get(field) is not False:
            errors.append(f"claims.{field} must be false")
    return errors


def _snapshot_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    capture = payload.get("capture", {})
    channels = capture.get("channels", [])
    if not isinstance(channels, list):
        return ["capture.channels must be an array"]
    names = [channel.get("name") for channel in channels if isinstance(channel, dict)]
    if set(names) != EXPECTED_CHANNELS or len(names) != len(EXPECTED_CHANNELS):
        errors.append("capture.channels must contain each of the 13 channels exactly once")
    if capture.get("overall_status") == "complete" and any(
        isinstance(channel, dict) and channel.get("status") != "complete" for channel in channels
    ):
        errors.append("capture.overall_status complete requires every channel complete")
    for channel in channels:
        if not isinstance(channel, dict):
            continue
        status = channel.get("status")
        reasons = channel.get("reason_codes", [])
        seen = channel.get("records_seen")
        captured = channel.get("records_captured")
        if status == "complete" and reasons:
            errors.append(f"capture channel {channel.get('name')}: complete cannot have reason_codes")
        if status != "complete" and not reasons:
            errors.append(f"capture channel {channel.get('name')}: degraded state requires reason_codes")
        if isinstance(seen, int) and isinstance(captured, int) and captured > seen:
            errors.append(f"capture channel {channel.get('name')}: records_captured exceeds records_seen")

    state = payload.get("session", {}).get("content_state", {})
    if not isinstance(state, dict):
        state = {}
    channels_by_name = {channel.get("name"): channel for channel in channels if isinstance(channel, dict)}
    for content_name, counters in state.items():
        if not isinstance(counters, dict):
            continue
        captured = counters.get("captured_count")
        raw_count = counters.get("raw_available_count")
        normalized = counters.get("normalized_count")
        if all(isinstance(value, int) for value in (captured, raw_count, normalized)):
            if raw_count > captured or normalized > captured:
                errors.append(f"content_state.{content_name}: projections cannot exceed captured_count")
            channel = channels_by_name.get(content_name)
            if channel and channel.get("status") == "complete" and (raw_count != captured or normalized != captured):
                errors.append(f"content_state.{content_name}: complete capture requires raw and normalized parity")
            if channel and channel.get("status") in {"unavailable", "unsupported"} and captured != 0:
                errors.append(f"content_state.{content_name}: unavailable/unsupported capture cannot claim captured content")

    usage = payload.get("session", {}).get("usage", {})
    window, used, remaining = (
        usage.get("context_window_tokens"), usage.get("context_used_tokens"), usage.get("context_remaining_tokens")
    )
    if all(isinstance(value, int) for value in (window, used, remaining)) and used + remaining != window:
        errors.append("usage context_used_tokens + context_remaining_tokens must equal context_window_tokens")

    integrity = payload.get("integrity", {})
    event_count = integrity.get("event_count")
    first, last = integrity.get("first_sequence"), integrity.get("last_sequence")
    last_digest = integrity.get("last_event_digest")
    if event_count == 0 and any(value is not None for value in (first, last, last_digest)):
        errors.append("empty stream must have null sequence bounds and last_event_digest")
    if isinstance(event_count, int) and event_count > 0:
        if not all(isinstance(value, int) for value in (first, last)) or last < first or last - first + 1 != event_count:
            errors.append("snapshot sequence bounds must be contiguous and match event_count")
        if not isinstance(last_digest, str):
            errors.append("non-empty stream requires last_event_digest")
    actual = integrity.get("snapshot_digest")
    if actual == ZERO_SHA256 or actual != snapshot_digest(payload):
        errors.append("integrity.snapshot_digest does not match deterministic snapshot digest")
    return errors


def _raw_bytes(raw: dict[str, Any]) -> bytes:
    content = raw.get("content", "")
    if not isinstance(content, str):
        raise ValueError("raw_evidence.content must be a string")
    if raw.get("format") == "base64":
        try:
            return base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"raw_evidence.content is invalid base64: {exc}") from exc
    return content.encode("utf-8")


def _event_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    capture = payload.get("capture", {})
    status, reasons = capture.get("status"), capture.get("reason_codes", [])
    if status == "complete" and reasons:
        errors.append("complete event capture cannot have reason_codes")
    if status != "complete" and not reasons:
        errors.append("degraded event capture requires reason_codes")

    raw = payload.get("raw_evidence", {})
    try:
        content = _raw_bytes(raw)
    except ValueError as exc:
        errors.append(str(exc))
        content = b""
    actual_content_digest = _sha256(content)
    if raw.get("byte_length") != len(content):
        errors.append("raw_evidence.byte_length does not match decoded content")
    if raw.get("content_sha256") == ZERO_SHA256 or raw.get("content_sha256") != actual_content_digest:
        errors.append("raw_evidence.content_sha256 does not match decoded content")
    if status == "complete" and (raw.get("is_redacted") or raw.get("is_truncated")):
        errors.append("complete capture cannot be redacted or truncated")

    integrity = payload.get("integrity", {})
    chunk = integrity.get("chunk", {})
    if isinstance(chunk.get("index"), int) and isinstance(chunk.get("count"), int) and chunk["index"] >= chunk["count"]:
        errors.append("chunk.index must be less than chunk.count")
    if chunk.get("chunk_sha256") != actual_content_digest:
        errors.append("chunk.chunk_sha256 does not match this event content")
    if chunk.get("count") == 1 and chunk.get("full_content_sha256") != actual_content_digest:
        errors.append("single chunk full_content_sha256 must equal content digest")
    actual_event_digest = integrity.get("event_digest")
    if actual_event_digest == ZERO_SHA256 or actual_event_digest != event_digest(payload):
        errors.append("integrity.event_digest does not match deterministic event digest")
    if integrity.get("sequence") == 1 and integrity.get("previous_event_digest") is not None:
        errors.append("first event in a stream must have null previous_event_digest")
    if integrity.get("sequence", 0) > 1 and not integrity.get("previous_event_digest"):
        errors.append("non-first event requires previous_event_digest")

    event_type = payload.get("event_type")
    normalized = payload.get("normalized", {})
    if event_type in CONTENT_EVENT_TYPES and normalized.get("category") not in {"content", "execution", "file"}:
        errors.append(f"{event_type} must retain a content/execution/file normalized projection")
    return errors


def validation_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        validator = build_validator(payload)
    except (OSError, ValueError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        return [str(exc)]
    errors.extend(
        f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in sorted(validator.iter_errors(payload), key=lambda item: tuple(str(part) for part in item.absolute_path))
    )
    _walk_finite(payload, errors)
    errors.extend(_governance_errors(payload))
    errors.extend(_claim_errors(payload))
    version = payload.get("api_version")
    if version in {
        "tamandua.io/ai-agent-runtime-snapshot/v2",
        "tamandua.io/ai-agent-runtime-event/v2",
    }:
        errors.extend(validation_errors_v2(payload))
    elif payload.get("kind") == "AiAgentRuntimeSnapshot":
        errors.extend(_snapshot_errors(payload))
    elif payload.get("kind") == "AiAgentRuntimeEvent":
        errors.extend(_event_errors(payload))
    return errors


def stream_errors(payloads: Iterable[dict[str, Any]]) -> list[str]:
    """Validate continuity when a caller supplies multiple events from a stream."""
    events = [payload for payload in payloads if payload.get("kind") == "AiAgentRuntimeEvent"]
    errors: list[str] = []
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_stream.setdefault(event.get("integrity", {}).get("stream_id", ""), []).append(event)
    for stream_id, stream in by_stream.items():
        structurally_valid = [
            event for event in stream
            if isinstance(event.get("integrity"), dict)
            and isinstance(event["integrity"].get("sequence"), int)
            and isinstance(event["integrity"].get("event_digest"), str)
        ]
        if len(structurally_valid) != len(stream):
            errors.append(f"stream {stream_id}: malformed integrity record")
        ordered = sorted(structurally_valid, key=lambda event: event["integrity"]["sequence"])
        sequences = [event.get("integrity", {}).get("sequence") for event in ordered]
        if len(sequences) != len(set(sequences)):
            errors.append(f"stream {stream_id}: duplicate sequence")
        for previous, current in zip(ordered, ordered[1:]):
            if current["integrity"]["sequence"] != previous["integrity"]["sequence"] + 1:
                errors.append(f"stream {stream_id}: sequence gap")
            if current["integrity"]["previous_event_digest"] != previous["integrity"]["event_digest"]:
                errors.append(f"stream {stream_id}: digest chain mismatch")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=DEFAULT_FIXTURES)
    args = parser.parse_args()
    failed = False
    payloads: list[dict[str, Any]] = []
    for path in args.paths:
        try:
            payload = load_json(path)
            payloads.append(payload)
            errors = validation_errors(payload)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors = [str(exc)]
            payload = {}
        if errors:
            failed = True
            print(f"INVALID {path}")
            for error in errors:
                print(f"- {error}")
        else:
            print(f"VALID {path} (experimental contract evidence; production/external claims false)")
    continuity = stream_errors(payloads)
    if continuity:
        failed = True
        print("INVALID supplied event stream set")
        for error in continuity:
            print(f"- {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
