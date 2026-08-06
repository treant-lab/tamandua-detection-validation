#!/usr/bin/env python3
"""Validate a local owned-artifact static page-plan smoke receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_ELIGIBLE_BYTES = 32 * 1024 * 1024
SCHEMA_VERSION = "tamandua.runtime_self_image_page_plan_receipt/v1"
EVIDENCE_CLASS = "owned-artifact-static-smoke"

ROOT_KEYS = {
    "schema_version", "evidence_class", "target", "build_command_id",
    "artifact_sha256_before", "artifact_sha256_after", "artifact_size",
    "planner_source_sha256", "harness_sha256", "format", "page_size",
    "eligible_pages", "relocation_excluded_pages", "eligible_bytes",
    "executable_file_backed_bytes", "bounds", "claims",
}
BOUND_KEYS = {"max_input_bytes", "max_eligible_bytes"}
CLAIM_KEYS = {
    "live_memory_compared", "telemetry_emitted", "runtime_detection_proven",
    "release_authority", "external_claim_allowed",
}
TARGETS = {
    "x86_64-pc-windows-msvc": (
        "cargo-release-windows-x86_64-msvc", "pe64-amd64", 4096
    ),
}
FORBIDDEN_FIELD_PARTS = (
    "path", "offset", "address", "byte", "mtime", "modified", "page_hash",
    "per_page", "raw", "memory",
)


class GateError(ValueError):
    pass


def _exact_object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise GateError(f"{name} must be an object")
    actual = set(value)
    if actual != keys:
        raise GateError(f"{name} keys differ: missing={sorted(keys-actual)} unknown={sorted(actual-keys)}")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        raise GateError(f"{name} must be an integer without boolean coercion")
    if not minimum <= value <= maximum:
        raise GateError(f"{name} is outside [{minimum}, {maximum}]")
    return value


def _check_privacy_shape(value: Any, location: str = "receipt") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = key.lower()
            if key not in {
                "artifact_sha256_before", "artifact_sha256_after",
                "planner_source_sha256", "harness_sha256", "max_input_bytes",
                "max_eligible_bytes", "eligible_bytes",
                "executable_file_backed_bytes", "live_memory_compared",
            } and any(
                part in lowered for part in FORBIDDEN_FIELD_PARTS
            ):
                raise GateError(f"privacy-risk field is forbidden at {location}.{key}")
            _check_privacy_shape(child, f"{location}.{key}")
    elif isinstance(value, list):
        raise GateError(f"arrays are forbidden in sanitized receipts at {location}")


def _validate_schema_contract(schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if schema.get("additionalProperties") is not False:
        raise GateError("schema root must reject additional properties")
    if set(schema.get("required", [])) != ROOT_KEYS:
        raise GateError("schema root required keys do not match the gate")
    properties = schema.get("properties")
    if type(properties) is not dict or set(properties) != ROOT_KEYS:
        raise GateError("schema root properties do not match the gate")


def _pe64_page_metrics(data: bytes) -> dict[str, int]:
    """Independently derive the bounded PE64 RX page geometry used by v1."""
    def need(offset: int, size: int, name: str) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(data):
            raise GateError(f"PE {name} exceeds artifact bounds")
        return data[offset:offset + size]

    def u16(offset: int, name: str) -> int:
        return int.from_bytes(need(offset, 2, name), "little")

    def u32(offset: int, name: str) -> int:
        return int.from_bytes(need(offset, 4, name), "little")

    if need(0, 2, "DOS signature") != b"MZ":
        raise GateError("artifact is not PE")
    pe = u32(0x3C, "PE pointer")
    if need(pe, 4, "signature") != b"PE\0\0":
        raise GateError("PE signature is invalid")
    coff = pe + 4
    if u16(coff, "machine") != 0x8664:
        raise GateError("PE machine is not AMD64")
    section_count = u16(coff + 2, "section count")
    characteristics = u16(coff + 18, "characteristics")
    if not 1 <= section_count <= 96 or not characteristics & 0x0002 or characteristics & 0x2000:
        raise GateError("PE is not a bounded executable image")
    optional_size = u16(coff + 16, "optional size")
    optional = coff + 20
    if optional_size < 240 or u16(optional, "optional magic") != 0x20B:
        raise GateError("PE optional header is not PE32+")
    need(optional, optional_size, "optional header")
    if u32(optional + 32, "section alignment") != 4096:
        raise GateError("PE section alignment is not 4096")
    directory_count = u32(optional + 108, "directory count")
    if directory_count > 16:
        raise GateError("PE data-directory count is unsupported")
    sections = []
    table = optional + optional_size
    executable_file_backed_bytes = 0
    for index in range(section_count):
        header = table + index * 40
        need(header, 40, "section header")
        virtual_size = u32(header + 8, "section virtual size")
        virtual_start = u32(header + 12, "section RVA")
        raw_size = u32(header + 16, "section raw size")
        raw_start = u32(header + 20, "section raw pointer")
        flags = u32(header + 36, "section flags")
        need(raw_start, raw_size, "section bytes")
        is_rx = bool(flags & 0x40000000 and flags & 0x20000000 and not flags & 0x80000000)
        if is_rx:
            executable_file_backed_bytes += raw_size
        sections.append((virtual_start, max(virtual_size, raw_size), raw_start, raw_size, is_rx))

    def rva_to_file(rva: int, size: int) -> int:
        matches = [raw + rva - virtual for virtual, _loaded, raw, raw_size, _rx in sections
                   if virtual <= rva and rva + size <= virtual + raw_size]
        if len(matches) != 1:
            raise GateError("PE RVA is not uniquely file-backed")
        need(matches[0], size, "RVA bytes")
        return matches[0]

    touched: set[int] = set()
    if directory_count > 5:
        reloc_rva = u32(optional + 112 + 5 * 8, "relocation RVA")
        reloc_size = u32(optional + 112 + 5 * 8 + 4, "relocation size")
        if bool(reloc_rva) != bool(reloc_size):
            raise GateError("PE relocation directory is incomplete")
        if reloc_size:
            cursor = rva_to_file(reloc_rva, reloc_size)
            end = cursor + reloc_size
            while cursor < end:
                page_rva = u32(cursor, "relocation page")
                block_size = u32(cursor + 4, "relocation block")
                if block_size < 8 or block_size % 2 or cursor + block_size > end:
                    raise GateError("PE relocation block is malformed")
                for entry in range(cursor + 8, cursor + block_size, 2):
                    value = u16(entry, "relocation entry")
                    kind, offset = value >> 12, value & 0xFFF
                    if kind == 10:
                        start = page_rva + offset
                        touched.update((start // 4096, (start + 7) // 4096))
                    elif kind != 0:
                        raise GateError("PE relocation type is unsupported")
                cursor += block_size
    if directory_count > 12:
        iat_rva = u32(optional + 112 + 12 * 8, "IAT RVA")
        iat_size = u32(optional + 112 + 12 * 8 + 4, "IAT size")
        if bool(iat_rva) != bool(iat_size):
            raise GateError("PE IAT directory is incomplete")
        if iat_size:
            rva_to_file(iat_rva, iat_size)
            touched.update(range(iat_rva // 4096, (iat_rva + iat_size - 1) // 4096 + 1))

    eligible = excluded = 0
    for virtual, loaded, _raw, raw_size, is_rx in sections:
        if not is_rx:
            continue
        backed = min(loaded, raw_size)
        first = (virtual + 4095) // 4096 * 4096
        last = (virtual + backed) // 4096 * 4096
        for page in range(first, last, 4096):
            if page // 4096 in touched:
                excluded += 1
            else:
                eligible += 1
    if eligible == 0:
        raise GateError("PE has no eligible RX pages")
    return {
        "eligible_pages": eligible,
        "relocation_excluded_pages": excluded,
        "eligible_bytes": eligible * 4096,
        "executable_file_backed_bytes": executable_file_backed_bytes,
    }


def validate(
    receipt_path: Path,
    artifact_path: Path,
    schema_path: Path,
    planner_source_path: Path,
    harness_path: Path,
) -> dict[str, Any]:
    _validate_schema_contract(schema_path)
    raw_receipt = receipt_path.read_text(encoding="utf-8")
    receipt = json.loads(raw_receipt)
    canonical = json.dumps(receipt, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if raw_receipt != canonical:
        raise GateError("receipt JSON is not canonical compact key-sorted UTF-8")
    _check_privacy_shape(receipt)
    receipt = _exact_object(receipt, ROOT_KEYS, "receipt")
    bounds = _exact_object(receipt["bounds"], BOUND_KEYS, "bounds")
    claims = _exact_object(receipt["claims"], CLAIM_KEYS, "claims")

    if receipt["schema_version"] != SCHEMA_VERSION:
        raise GateError("schema_version is not v1")
    if receipt["evidence_class"] != EVIDENCE_CLASS:
        raise GateError("evidence_class is not owned-artifact-static-smoke")
    target = receipt["target"]
    if type(target) is not str or target not in TARGETS:
        raise GateError("target is unsupported")
    command, image_format, page_size = TARGETS[target]
    if receipt["build_command_id"] != command or receipt["format"] != image_format:
        raise GateError("target, build_command_id, and format are inconsistent")
    if receipt["page_size"] != page_size or type(receipt["page_size"]) is not int:
        raise GateError("page_size is inconsistent with target")

    digests = (
        receipt["artifact_sha256_before"], receipt["artifact_sha256_after"],
        receipt["planner_source_sha256"], receipt["harness_sha256"],
    )
    if any(type(digest) is not str or len(digest) != 64 or
           any(c not in "0123456789abcdef" for c in digest) for digest in digests):
        raise GateError("receipt digest is not normalized lowercase SHA-256")
    artifact_size = _integer(receipt["artifact_size"], "artifact_size", 1, MAX_INPUT_BYTES)
    eligible_pages = _integer(receipt["eligible_pages"], "eligible_pages", 1, 8192)
    excluded = _integer(
        receipt["relocation_excluded_pages"], "relocation_excluded_pages", 0, 16384
    )
    eligible_bytes = _integer(
        receipt["eligible_bytes"], "eligible_bytes", page_size, MAX_ELIGIBLE_BYTES
    )
    executable_file_backed_bytes = _integer(
        receipt["executable_file_backed_bytes"],
        "executable_file_backed_bytes", page_size, MAX_INPUT_BYTES,
    )
    if eligible_bytes != eligible_pages * page_size:
        raise GateError("eligible_bytes does not equal eligible_pages * page_size")
    if not eligible_bytes <= executable_file_backed_bytes <= artifact_size:
        raise GateError(
            "aggregate bytes must satisfy eligible <= executable-file-backed <= artifact"
        )
    if eligible_pages + excluded > (artifact_size + page_size - 1) // page_size:
        raise GateError("eligible and excluded page counts are impossible for artifact size")
    if bounds != {
        "max_input_bytes": MAX_INPUT_BYTES,
        "max_eligible_bytes": MAX_ELIGIBLE_BYTES,
    }:
        raise GateError("planner bounds are not the v1 constants")
    if any(type(value) is not bool or value for value in claims.values()):
        raise GateError("all exact v1 claims must be boolean false")

    before = artifact_path.stat()
    if not artifact_path.is_file() or before.st_size > MAX_INPUT_BYTES:
        raise GateError("artifact is not a bounded regular file")
    artifact_bytes = artifact_path.read_bytes()
    after = artifact_path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise GateError("artifact changed while the gate read it")
    actual_digest = hashlib.sha256(artifact_bytes).hexdigest()
    if (artifact_size != len(artifact_bytes) or
            receipt["artifact_sha256_before"] != actual_digest or
            receipt["artifact_sha256_after"] != actual_digest):
        raise GateError("receipt was transplanted or artifact size/hash was tampered")
    metrics = _pe64_page_metrics(artifact_bytes)
    expected_metrics = {
        "eligible_pages": eligible_pages,
        "relocation_excluded_pages": excluded,
        "eligible_bytes": eligible_bytes,
        "executable_file_backed_bytes": executable_file_backed_bytes,
    }
    if metrics != expected_metrics:
        raise GateError("receipt page metrics do not match independent PE geometry")
    for path, field in (
        (planner_source_path, "planner_source_sha256"),
        (harness_path, "harness_sha256"),
    ):
        if not path.is_file():
            raise GateError(f"{field} input is not a regular file")
        if hashlib.sha256(path.read_bytes()).hexdigest() != receipt[field]:
            raise GateError(f"{field} binding is stale or transplanted")
    return receipt


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument(
        "--planner-source",
        type=Path,
        default=root / "apps" / "tamandua_agent" / "src" / "collectors" /
        "runtime_integrity" / "page_content.rs",
    )
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument(
        "--schema",
        type=Path,
        default=root / "schemas" / "runtime_self_image_page_plan_receipt_v1.schema.json",
    )
    args = parser.parse_args(argv)
    try:
        validate(args.receipt, args.artifact, args.schema, args.planner_source, args.harness)
    except (GateError, OSError, json.JSONDecodeError) as error:
        print(f"runtime self-image page-plan gate: FAIL: {error}", file=sys.stderr)
        return 1
    print("runtime self-image page-plan gate: PASS (owned-artifact static smoke only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
