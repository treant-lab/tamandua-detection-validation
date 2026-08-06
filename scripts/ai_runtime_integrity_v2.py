#!/usr/bin/env python3
"""Experimental AI-runtime v2 canonical integrity authority.

This is contract-smoke evidence only. It does not establish runtime, release,
production, or external-claim readiness.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import struct
from typing import Any


PREFIX = b"TMND-AIR\0"
CANONICALIZATION = "tmnd-tree-v1"
ALGORITHM = "sha-256"
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
DOMAINS = {
    "raw": "tamandua.ai-runtime.raw-evidence/v2",
    "normalized": "tamandua.ai-runtime.normalized/v2",
    "event": "tamandua.ai-runtime.event/v2",
    "units": "tamandua.ai-runtime.manifest-units/v2",
    "assemblies": "tamandua.ai-runtime.manifest-assemblies/v2",
    "manifest": "tamandua.ai-runtime.manifest/v2",
    "snapshot": "tamandua.ai-runtime.snapshot/v2",
}


class CanonicalizationError(ValueError):
    """Input cannot be represented by tmnd-tree-v1."""


def canonical_encode(value: Any) -> bytes:
    if value is None:
        return b"\x00"
    if value is False:
        return b"\x01"
    if value is True:
        return b"\x02"
    if isinstance(value, int):
        if not I64_MIN <= value <= I64_MAX:
            raise CanonicalizationError("integer is outside signed i64 range")
        return b"\x03" + struct.pack(">q", value)
    if isinstance(value, float):
        raise CanonicalizationError("floating-point numbers are forbidden")
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise CanonicalizationError("string is not valid Unicode") from exc
        return b"\x04" + _u64(len(raw)) + raw
    if isinstance(value, list):
        return b"\x05" + _u64(len(value)) + b"".join(canonical_encode(item) for item in value)
    if isinstance(value, dict):
        keyed: list[tuple[bytes, str, Any]] = []
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            try:
                key_bytes = key.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise CanonicalizationError("object key is not valid Unicode") from exc
            keyed.append((key_bytes, key, child))
        keyed.sort(key=lambda item: item[0])
        body = b"".join(canonical_encode(key) + canonical_encode(child) for _, key, child in keyed)
        return b"\x06" + _u64(len(keyed)) + body
    raise CanonicalizationError(f"unsupported value type: {type(value).__name__}")


def domain_hash(domain: str, value: Any) -> str:
    domain_bytes = domain.encode("utf-8", errors="strict")
    if len(domain_bytes) > 0xFFFFFFFF:
        raise CanonicalizationError("domain exceeds u32 length")
    material = PREFIX + struct.pack(">I", len(domain_bytes)) + domain_bytes + canonical_encode(value)
    return hashlib.sha256(material).hexdigest()


def raw_evidence_hash(event: dict[str, Any]) -> str:
    return domain_hash(DOMAINS["raw"], event["raw_evidence"])


def normalized_hash(event: dict[str, Any]) -> str:
    return domain_hash(DOMAINS["normalized"], event["normalized"])


def event_digest(event: dict[str, Any]) -> str:
    material = copy.deepcopy(event)
    integrity = material.get("integrity")
    if not isinstance(integrity, dict):
        raise CanonicalizationError("event integrity must be an object")
    integrity.pop("event_digest", None)
    return domain_hash(DOMAINS["event"], material)


def units_hash(units: list[dict[str, Any]]) -> str:
    return domain_hash(DOMAINS["units"], units)


def assemblies_hash(assemblies: list[dict[str, Any]]) -> str:
    return domain_hash(DOMAINS["assemblies"], assemblies)


def manifest_value(units: list[dict[str, Any]], assemblies: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": 1,
        "unit_count": len(units),
        "assembly_count": len(assemblies),
        "units_sha256": units_hash(units),
        "assemblies_sha256": assemblies_hash(assemblies),
    }


def manifest_hash(manifest: dict[str, Any]) -> str:
    return domain_hash(DOMAINS["manifest"], manifest)


def snapshot_digest(snapshot: dict[str, Any]) -> str:
    material = copy.deepcopy(snapshot)
    integrity = material.get("integrity")
    if not isinstance(integrity, dict):
        raise CanonicalizationError("snapshot integrity must be an object")
    integrity.pop("snapshot_digest", None)
    return domain_hash(DOMAINS["snapshot"], material)


def decoded_raw_bytes(raw: dict[str, Any]) -> bytes:
    content = raw.get("content")
    if not isinstance(content, str):
        raise CanonicalizationError("raw_evidence.content must be a string")
    if raw.get("format") == "base64":
        try:
            return base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CanonicalizationError("raw_evidence.content is invalid base64") from exc
    return content.encode("utf-8", errors="strict")


def validation_errors_v2(payload: dict[str, Any]) -> list[str]:
    try:
        canonical_encode(payload)
    except (CanonicalizationError, UnicodeError) as exc:
        return [f"tmnd-tree-v1: {exc}"]
    if payload.get("kind") == "AiAgentRuntimeEvent":
        return _event_errors(payload)
    if payload.get("kind") == "AiAgentRuntimeSnapshot":
        return _snapshot_errors(payload)
    return ["v2 api_version/kind tuple is unsupported"]


def _event_errors(event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    integrity = event.get("integrity", {})
    if integrity.get("version") != 2 or integrity.get("canonicalization") != CANONICALIZATION or integrity.get("algorithm") != ALGORITHM:
        errors.append("event integrity algorithm tuple must be v2/tmnd-tree-v1/sha-256")
    try:
        raw_bytes = decoded_raw_bytes(event.get("raw_evidence", {}))
        raw_hash = raw_evidence_hash(event)
        normalized = normalized_hash(event)
        digest = event_digest(event)
    except (KeyError, CanonicalizationError, UnicodeError) as exc:
        return errors + [str(exc)]
    raw = event.get("raw_evidence", {})
    if raw.get("byte_length") != len(raw_bytes):
        errors.append("raw_evidence.byte_length does not match decoded content")
    if raw.get("content_sha256") != hashlib.sha256(raw_bytes).hexdigest():
        errors.append("raw_evidence.content_sha256 does not match decoded content")
    if integrity.get("raw_evidence_sha256") != raw_hash:
        errors.append("integrity.raw_evidence_sha256 does not match domain hash")
    if integrity.get("normalized_sha256") != normalized:
        errors.append("integrity.normalized_sha256 does not match domain hash")
    if integrity.get("event_digest") != digest:
        errors.append("integrity.event_digest does not bind the complete event")
    chunk = integrity.get("chunk", {})
    if chunk.get("index", -1) >= chunk.get("count", 0):
        errors.append("chunk.index must be less than chunk.count")
    if chunk.get("chunk_content_sha256") != hashlib.sha256(raw_bytes).hexdigest():
        errors.append("chunk.chunk_content_sha256 does not match decoded content")
    if chunk.get("count") == 1:
        if chunk.get("full_content_sha256") != hashlib.sha256(raw_bytes).hexdigest():
            errors.append("single-chunk full_content_sha256 mismatch")
        if chunk.get("full_content_byte_length") != len(raw_bytes):
            errors.append("single-chunk full_content_byte_length mismatch")
    sequence = integrity.get("sequence")
    previous = integrity.get("previous_event_digest")
    if sequence == 1 and previous is not None:
        errors.append("first event must have null previous_event_digest")
    if isinstance(sequence, int) and sequence > 1 and not previous:
        errors.append("non-first event requires previous_event_digest")
    return errors


def _snapshot_errors(snapshot: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    integrity = snapshot.get("integrity", {})
    if integrity.get("version") != 2 or integrity.get("canonicalization") != CANONICALIZATION or integrity.get("algorithm") != ALGORITHM:
        errors.append("snapshot integrity algorithm tuple must be v2/tmnd-tree-v1/sha-256")
    units = integrity.get("units", [])
    assemblies = integrity.get("assemblies", [])
    manifest = integrity.get("manifest", {})
    if not isinstance(units, list) or not isinstance(assemblies, list) or not isinstance(manifest, dict):
        return errors + ["snapshot manifest structures are malformed"]
    expected_manifest = manifest_value(units, assemblies)
    if manifest != expected_manifest:
        errors.append("manifest counts or domain hashes do not match ordered arrays")
    if integrity.get("manifest_sha256") != manifest_hash(expected_manifest):
        errors.append("integrity.manifest_sha256 does not match exact manifest object")
    sequences = [unit.get("sequence") for unit in units if isinstance(unit, dict)]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        errors.append("manifest units must preserve strictly increasing received sequence order")
    if integrity.get("event_count") != len(units):
        errors.append("snapshot event_count must equal manifest unit_count")
    if units:
        if integrity.get("first_sequence") != sequences[0] or integrity.get("last_sequence") != sequences[-1]:
            errors.append("snapshot sequence bounds must match ordered units")
        if sequences != list(range(sequences[0], sequences[0] + len(sequences))):
            errors.append("manifest units must be sequence-contiguous")
        if integrity.get("last_event_digest") != units[-1].get("event_digest"):
            errors.append("last_event_digest must match the last ordered unit")
    expected_order = sorted(assemblies, key=lambda item: (item.get("sequences", [I64_MAX])[0], item.get("chunk_id", "")))
    if assemblies != expected_order:
        errors.append("assemblies must be ordered by first_sequence then chunk_id")
    covered: list[int] = []
    units_by_sequence = {unit.get("sequence"): unit for unit in units if isinstance(unit, dict)}
    for assembly in assemblies:
        assembly_sequences = assembly.get("sequences", [])
        assembly_units = [units_by_sequence.get(sequence) for sequence in assembly_sequences]
        if any(unit is None for unit in assembly_units):
            errors.append(f"assembly {assembly.get('chunk_id')}: references missing unit")
            continue
        covered.extend(assembly_sequences)
        expected_count = assembly.get("chunk_count")
        if len(assembly_units) != expected_count:
            errors.append(f"assembly {assembly.get('chunk_id')}: incomplete chunk count")
        if [unit.get("chunk_index") for unit in assembly_units] != list(range(expected_count)):
            errors.append(f"assembly {assembly.get('chunk_id')}: chunk indices are incomplete or unordered")
        if any(unit.get("chunk_id") != assembly.get("chunk_id") or unit.get("chunk_count") != expected_count for unit in assembly_units):
            errors.append(f"assembly {assembly.get('chunk_id')}: unit identity/count mismatch")
        if [unit.get("chunk_content_sha256") for unit in assembly_units] != assembly.get("chunk_content_sha256s"):
            errors.append(f"assembly {assembly.get('chunk_id')}: ordered chunk hashes mismatch")
        for field in ("full_content_sha256", "full_content_byte_length"):
            if any(unit.get(field) != assembly.get(field) for unit in assembly_units):
                errors.append(f"assembly {assembly.get('chunk_id')}: {field} mismatch")
    if sorted(covered) != sorted(sequences) or len(covered) != len(set(covered)):
        errors.append("assemblies must cover every unit exactly once")
    try:
        if integrity.get("snapshot_digest") != snapshot_digest(snapshot):
            errors.append("integrity.snapshot_digest does not bind the complete snapshot")
    except CanonicalizationError as exc:
        errors.append(str(exc))
    return errors


def _u64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise CanonicalizationError("length exceeds unsigned u64")
    return struct.pack(">Q", value)
