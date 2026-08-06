#!/usr/bin/env python3
"""Untrusted inert double for the Loop150 source-only container adapter contract."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "schemas/elixir_check_locked_probe_worker_adapter_protocol_v1.schema.json"
REQUEST_MAX_BYTES = 65536
RESPONSE_MAX_BYTES = 16384


class AdapterInputError(ValueError):
    pass


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise AdapterInputError("bound_file_invalid")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_request() -> dict[str, object]:
    raw = sys.stdin.buffer.read(REQUEST_MAX_BYTES + 1)
    if not raw or len(raw) > REQUEST_MAX_BYTES or not raw.endswith(b"\n"):
        raise AdapterInputError("request_framing_invalid")
    body = raw[:-1]
    if not body or body.startswith((b" ", b"\t", b"\r", b"\n")):
        raise AdapterInputError("request_canonical_invalid")
    try:
        value = json.loads(body.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AdapterInputError("request_json_invalid") from None
    if type(value) is not dict or canonical_bytes(value) != body:
        raise AdapterInputError("request_canonical_invalid")
    return value


def validate_request(request: dict[str, object]) -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(request)
    manifest = request["manifest"]
    if digest(manifest) != request["manifest_sha256"]:
        raise AdapterInputError("manifest_digest_mismatch")
    if request["invocation_id"] != manifest["invocation"]["id"]:
        raise AdapterInputError("invocation_mismatch")
    if hash_file(Path(__file__).resolve()) != manifest["bindings"]["double_source_sha256"]:
        raise AdapterInputError("double_source_drift")
    if hash_file(SCHEMA) != manifest["bindings"]["protocol_schema_sha256"]:
        raise AdapterInputError("protocol_schema_drift")


def response(request: dict[str, object]) -> dict[str, object]:
    manifest = request["manifest"]
    return {
        "schema": "tamandua.elixir_check_locked.worker_adapter_response/v1",
        "invocation_id": request["invocation_id"],
        "manifest_sha256": request["manifest_sha256"],
        "request_sha256": digest(request),
        "double_source_sha256": manifest["bindings"]["double_source_sha256"],
        "outcome": "source_only_not_executed",
        "adapter_runs": 0,
        "network_requests": 0,
        "check_locked_runs": 0,
        "observation": {
            "pre_absence": "not_observed",
            "exact_resource_id": None,
            "cleanup_attempted": False,
            "cleanup_succeeded": None,
            "final_absence": "not_observed",
            "inventory_before_sha256": None,
            "inventory_after_sha256": None,
            "inventory_unchanged": None,
        },
        "error_class": "source_only_not_executed",
        "claims": manifest["claims"],
    }


def main() -> int:
    request = read_request()
    validate_request(request)
    payload = canonical_bytes(response(request)) + b"\n"
    if len(payload) > RESPONSE_MAX_BYTES:
        raise AdapterInputError("response_too_large")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
