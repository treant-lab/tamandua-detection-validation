#!/usr/bin/env python3
"""Inert, untrusted child for the Loop148 process-boundary contract.

This worker performs one deterministic protocol self-check.  It has no real
adapter and never creates the parent receipt.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[3]
PROTOCOL_SCHEMA = REPO_ROOT / "schemas/elixir_check_locked_probe_worker_protocol_v1.schema.json"
RECEIPT_SCHEMA = REPO_ROOT / "schemas/elixir_check_locked_probe_worker_boundary_receipt_v1.schema.json"
PARENT_SOURCE = Path(__file__).with_name("elixir_check_locked_probe_worker_parent.py")
MAX_REQUEST_BYTES = 65536


class WorkerInputError(ValueError):
    pass


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise WorkerInputError("input_invalid")
        value[key] = item
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_value(value: Any) -> str:
    return _digest_bytes(_canonical(value))


def _hash_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise WorkerInputError("manifest_mismatch")
    return _digest_bytes(path.read_bytes())


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate)
        Draft202012Validator.check_schema(value)
    except Exception as exc:
        raise WorkerInputError("manifest_mismatch") from exc
    if not isinstance(value, dict):
        raise WorkerInputError("manifest_mismatch")
    return value


def _read_request() -> tuple[dict[str, Any], bytes]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
        raise WorkerInputError("input_invalid")
    body = raw[:-1]
    if not body or b"\n" in body or body.startswith(b"\xef\xbb\xbf"):
        raise WorkerInputError("input_invalid")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError, WorkerInputError) as exc:
        raise WorkerInputError("input_invalid") from exc
    if not isinstance(value, dict) or _canonical(value) != body:
        raise WorkerInputError("input_invalid")
    return value, body


def _validate_manifest(request: dict[str, Any], protocol_schema: dict[str, Any]) -> dict[str, Any]:
    try:
        Draft202012Validator(protocol_schema).validate(request)
    except Exception as exc:
        raise WorkerInputError("input_invalid") from exc
    manifest = request["manifest"]
    if request["manifest_sha256"] != _digest_value(manifest):
        raise WorkerInputError("manifest_mismatch")
    command = [str(Path(sys.executable).resolve()), "-I", "-B", str(Path(__file__).resolve())]
    environment_policy = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    if sys.platform == "win32":
        environment_policy["SystemRoot"] = "absolute_windows_directory"
        environment_policy["WINDIR"] = "absolute_windows_directory"
    expected = {
        "protocol_schema_sha256": _hash_file(PROTOCOL_SCHEMA),
        "receipt_schema_sha256": _hash_file(RECEIPT_SCHEMA),
        "parent_source_sha256": _hash_file(PARENT_SOURCE),
        "worker_source_sha256": _hash_file(Path(__file__)),
        "interpreter_executable_sha256": _hash_file(Path(sys.executable).resolve()),
        "interpreter_version_sha256": _digest_bytes(sys.version.encode("utf-8")),
        "argv_template_sha256": _digest_value(command),
        "environment_policy_sha256": _digest_value(environment_policy),
    }
    if any(manifest[name] != value for name, value in expected.items()):
        raise WorkerInputError("manifest_mismatch")
    return manifest


def _response(request: dict[str, Any], request_body: bytes) -> dict[str, Any]:
    protocol_schema = _load_schema(PROTOCOL_SCHEMA)
    manifest = _validate_manifest(request, protocol_schema)
    response = {
        "schema": "tamandua.elixir_check_locked.worker_response/v1",
        "invocation_id": request["invocation_id"],
        "manifest_sha256": request["manifest_sha256"],
        "request_sha256": _digest_bytes(request_body),
        "worker_source_sha256": manifest["worker_source_sha256"],
        "adapter_profile": "inert_contract_v1",
        "outcome": "inert_contract_observed",
        "operation_counts": {"adapter_runs": 0, "inert_checks": 1, "network_requests": 0},
        "finalization": {"adapter_cleanup_attempted": False, "real_cleanup_verified": False},
        "claims": manifest["claims"],
    }
    Draft202012Validator(protocol_schema).validate(response)
    return response


def main() -> int:
    try:
        request, body = _read_request()
        response = _response(request, body)
    except WorkerInputError:
        return 2
    except Exception:
        return 3
    sys.stdout.buffer.write(_canonical(response) + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
