#!/usr/bin/env python3
"""Offline, non-executing preregistration gate for a physical fleet experiment."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Any

INPUT_SCHEMA = "tamandua.android.device_identity.fleet_preregistration_input/v1"
PINS_SCHEMA = "tamandua.android.device_identity.fleet_preregistration_pins/v1"
REPORT_SCHEMA = "tamandua.android.device_identity.fleet_preregistration_report/v1"
PROFILE = "tamandua.android.device_identity.fleet_preregistration_offline/v1"
EVIDENCE_CLASS = "offline_physical_fleet_preregistration_candidate"
MAX_BYTES = 256 * 1024
MAX_CELLS = 256
MAX_FENCE = (1 << 63) - 1
SHA = re.compile(r"^[0-9a-f]{64}$")
SYMBOL = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

CATEGORIES = (
    "baseline_observed", "stable_match", "tenant_separation", "authorized_rotation",
    "authorized_reenrollment", "recovery_previous", "recovery_replacement",
    "attestation_assurance_change_only", "missing_key_hold",
    "unexpected_key_change_hold", "cross_slot_key_reuse_hold",
    "clone_restore_suspected_hold",
)
EVENTS = (
    "enroll", "observe", "restart", "update", "authorized_rotate",
    "authorized_reenroll", "recover_previous", "recover_replacement", "restore",
)
EVENT_FOR_CATEGORY = {
    "baseline_observed": {"enroll"},
    "stable_match": {"restart", "update"},
    "tenant_separation": {"enroll"},
    "authorized_rotation": {"authorized_rotate"},
    "authorized_reenrollment": {"authorized_reenroll"},
    "recovery_previous": {"recover_previous"},
    "recovery_replacement": {"recover_replacement"},
    "attestation_assurance_change_only": {"observe"},
    "missing_key_hold": {"observe"},
    "unexpected_key_change_hold": {"observe", "restart", "update"},
    "cross_slot_key_reuse_hold": {"observe"},
    "clone_restore_suspected_hold": {"restore"},
}
ROLES = (
    "continuity_validator", "continuity_schema", "physical_planner",
    "physical_plan_validator", "physical_evidence_schema", "collector_candidate",
    "collector_primitives", "sealed_authority_adapter", "operator_packet",
    "operator_packet_schema", "bridge_provenance", "supervisor_receipt_schema",
)
CONTROL_FIELDS = {
    "collector_enabled", "executor_enabled", "adapter_enabled", "target_enabled",
    "backend_enabled", "network_enabled", "physical_execution_authorized",
}
CLAIM_FIELDS = {
    "physical_device_validated", "real_fleet_uniqueness_validated",
    "hardware_attestation_validated", "clone_detection_validated", "product_ready",
    "production_ready", "external_claim_allowed", "vendor_parity",
}
SENSITIVE_PARTS = {
    "serial", "imei", "meid", "android_id", "mac_address", "phone", "email",
    "ip_address", "device_name", "manufacturer", "model", "operator_name",
    "public_key", "private_key", "spki", "jwk", "certificate", "attestation_evidence",
    "proof", "token", "secret", "password", "credential", "hardware_guid",
}
UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", re.I)
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MAC = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
GLOBAL_HEX_ID = re.compile(r"^[0-9a-f]{16}$", re.I)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class GateError(ValueError):
    pass


def fail(code: str) -> None:
    raise GateError(code)


class QuietArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        fail("arguments_invalid")

    def exit(self, _status: int = 0, _message: str | None = None) -> None:
        fail("arguments_invalid")


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError, OverflowError, RecursionError):
        fail("input_json_invalid")


def digest(value: Any, domain: str) -> str:
    return hashlib.sha256(domain.encode() + b"\0" + (value if isinstance(value, bytes) else canonical(value))).hexdigest()


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate_json_key")
        result[key] = value
    return result


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _path_chain(path: Path) -> tuple[tuple[int, int, int, int], ...]:
    identities = []
    for component in (path, *path.parents):
        info = os.lstat(component)
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            fail("input_path_unsafe")
        identities.append((info.st_dev, info.st_ino, info.st_mode, attributes))
    return tuple(identities)


def _parse_canonical(raw: bytes) -> dict[str, Any]:
    if not 1 <= len(raw) <= MAX_BYTES:
        fail("input_size_invalid")
    try:
        value = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=lambda _: fail("input_json_invalid"))
    except GateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        fail("input_json_invalid")
    if not isinstance(value, dict) or canonical(value) != raw:
        fail("input_not_canonical")
    return value


def _read_inputs(paths: tuple[Path, ...], require_independent: bool) -> list[tuple[dict[str, Any], bytes]]:
    descriptors: list[int] = []
    snapshots: list[tuple[Path, os.stat_result, tuple[tuple[int, int, int, int], ...]]] = []
    try:
        if require_independent and len(set(paths)) != len(paths):
            fail("inputs_not_independent")
        for path in paths:
            if not path.is_absolute() or path != path.resolve(strict=True):
                fail("input_path_unsafe")
            chain = _path_chain(path)
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode):
                fail("input_path_unsafe")
            if not 1 <= before.st_size <= MAX_BYTES:
                fail("input_size_invalid")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if _file_identity(opened) != _file_identity(before):
                fail("input_changed")
            snapshots.append((path, opened, chain))

        file_ids = {(opened.st_dev, opened.st_ino) for _, opened, _ in snapshots}
        if require_independent and len(file_ids) != len(snapshots):
            fail("inputs_not_independent")

        raw_inputs = []
        for descriptor, (_, opened, _) in zip(descriptors, snapshots):
            raw = b""
            while len(raw) <= MAX_BYTES:
                chunk = os.read(descriptor, min(65536, MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            if len(raw) != opened.st_size:
                fail("input_changed")
            raw_inputs.append(raw)
        if require_independent and len(set(raw_inputs)) != len(raw_inputs):
            fail("inputs_not_independent")

        for descriptor, (path, opened, chain) in zip(descriptors, snapshots):
            handle_after = os.fstat(descriptor)
            path_after = os.lstat(path)
            if (
                _file_identity(handle_after) != _file_identity(opened)
                or _file_identity(path_after) != _file_identity(opened)
                or _path_chain(path) != chain
            ):
                fail("input_changed")
        return [(_parse_canonical(raw), raw) for raw in raw_inputs]
    except GateError:
        raise
    except (OSError, ValueError):
        fail("input_path_unsafe" if not descriptors else "input_changed")
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def read_canonical(path: Path) -> tuple[dict[str, Any], bytes]:
    return _read_inputs((path,), require_independent=False)[0]


def read_canonical_pair(
    preregistration_path: Path, pins_path: Path
) -> tuple[tuple[dict[str, Any], bytes], tuple[dict[str, Any], bytes]]:
    preregistration, pins = _read_inputs(
        (preregistration_path, pins_path), require_independent=True
    )
    return preregistration, pins


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold()
    return "".join(char for char in value if unicodedata.category(char) != "Cf")


def decode_layer(value: str) -> set[str]:
    result: set[str] = set()
    try:
        if re.search(r"%[0-9a-f]{2}", value, re.I):
            from urllib.parse import unquote
            result.add(unquote(value, errors="strict"))
    except (UnicodeError, ValueError):
        pass
    if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", value, re.I):
        try: result.add(bytes.fromhex(value).decode())
        except (ValueError, UnicodeError): pass
    if len(value) >= 8 and re.fullmatch(r"[a-z0-9_+/=-]+", value, re.I):
        try: result.add(base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode())
        except (ValueError, UnicodeError): pass
    return result


def privacy_candidates(value: str) -> set[str]:
    seen, frontier, result = {value}, {value}, set()
    for _ in range(3):
        following: set[str] = set()
        for item in frontier:
            result.add(normalize(item))
            for decoded in decode_layer(item):
                if len(decoded) <= 512 and decoded not in seen:
                    seen.add(decoded); following.add(decoded)
        frontier = following
    for item in frontier:
        result.add(normalize(item))
    return result


def sensitive(value: Any, depth: int = 0) -> None:
    if depth > 9:
        fail("input_depth_exceeded")
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = normalize(key)
            if key != "coordinator_fencing_token" and any(part in lowered for part in SENSITIVE_PARTS):
                fail("sensitive_field_rejected")
            sensitive(child, depth + 1)
    elif isinstance(value, list):
        for child in value: sensitive(child, depth + 1)
    elif isinstance(value, str):
        if len(value) > 512: fail("string_bound_exceeded")
        for candidate in privacy_candidates(value):
            if (candidate.startswith(("tmnd-", "tmdk_v1_", "tmdks_v1_", "-----begin", "bearer "))
                    or UUID.fullmatch(candidate) or EMAIL.fullmatch(candidate)
                    or IP.fullmatch(candidate) or MAC.fullmatch(candidate)
                    or GLOBAL_HEX_ID.fullmatch(candidate) or re.fullmatch(r"\d{15}", candidate)
                    or re.fullmatch(r"(?:[0-9a-f]{2}:){31}[0-9a-f]{2}", candidate)):
                fail("sensitive_value_rejected")


def exact(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields: fail(code)
    return value


def sha(value: Any, code: str, nullable: bool = False) -> str | None:
    if nullable and value is None: return None
    if not isinstance(value, str) or not SHA.fullmatch(value) or value == "0" * 64: fail(code)
    return value


def validate(document: dict[str, Any], pins: dict[str, Any], raw_doc: bytes, raw_pins: bytes) -> dict[str, Any]:
    sensitive(document); sensitive(pins)
    top_fields = {"schema", "evidence_class", "profile", "source_sha256", "workspace_sha256", "head_sha256", "experiment_sha256", "matrix_sha256", "privacy", "authority", "roles", "slots", "tenants", "cells", "controls", "claims"}
    root = exact(document, top_fields, "preregistration_fields_invalid")
    pin_fields = {"schema", "source_sha256", "workspace_sha256", "head_sha256", "experiment_sha256", "matrix_sha256", "privacy", "authority", "roles"}
    pin = exact(pins, pin_fields, "pins_fields_invalid")
    if root["schema"] != INPUT_SCHEMA or root["profile"] != PROFILE or root["evidence_class"] != EVIDENCE_CLASS or pin["schema"] != PINS_SCHEMA:
        fail("input_identity_invalid")
    repeated = ("source_sha256", "workspace_sha256", "head_sha256", "experiment_sha256", "matrix_sha256", "privacy", "authority", "roles")
    if any(root[field] != pin[field] for field in repeated): fail("pins_mismatch")
    core = [sha(root[field], f"{field}_invalid") for field in ("source_sha256", "workspace_sha256", "head_sha256", "experiment_sha256", "matrix_sha256")]
    privacy = exact(root["privacy"], {"scheme", "pseudonym_context_sha256", "key_authority_sha256", "key_material_included"}, "privacy_fields_invalid")
    if privacy["scheme"] != "hmac-sha256-tmdk_v1-receipt-context-v1" or privacy["key_material_included"] is not False: fail("privacy_policy_invalid")
    privacy_digests = [sha(privacy["pseudonym_context_sha256"], "privacy_digest_invalid"), sha(privacy["key_authority_sha256"], "privacy_digest_invalid")]
    authority = exact(root["authority"], {"operator_packet_sha256", "bridge_provenance_sha256", "coordinator_snapshot_sha256", "coordinator_fencing_token", "expected_previous_fence", "previous_event_sha256", "operational_root_sha256"}, "authority_fields_invalid")
    authority_digests = [sha(authority[field], "authority_digest_invalid") for field in ("operator_packet_sha256", "bridge_provenance_sha256", "coordinator_snapshot_sha256", "previous_event_sha256")]
    root_digest = sha(authority["operational_root_sha256"], "authority_digest_invalid", nullable=True)
    if (type(authority["coordinator_fencing_token"]) is not int
            or not 1 <= authority["coordinator_fencing_token"] <= MAX_FENCE
            or type(authority["expected_previous_fence"]) is not int
            or not 0 <= authority["expected_previous_fence"] < MAX_FENCE
            or authority["coordinator_fencing_token"] <= authority["expected_previous_fence"]):
        fail("coordinator_fence_invalid")
    roles = exact(root["roles"], set(ROLES), "role_bindings_invalid")
    role_digests = [sha(roles[role], "role_digest_invalid") for role in ROLES]
    all_digests = core + privacy_digests + authority_digests + ([root_digest] if root_digest else []) + role_digests
    if len(set(all_digests)) != len(all_digests): fail("digest_reuse")
    slots, tenants, cells = root["slots"], root["tenants"], root["cells"]
    if not isinstance(slots, list) or not 3 <= len(slots) <= 64 or len(set(slots)) != len(slots) or any(not isinstance(x, str) or not x.startswith("slot_") or not SYMBOL.fullmatch(x) for x in slots): fail("slot_set_invalid")
    if not isinstance(tenants, list) or not 2 <= len(tenants) <= 32 or len(set(tenants)) != len(tenants) or any(not isinstance(x, str) or not x.startswith("tenant_") or not SYMBOL.fullmatch(x) for x in tenants): fail("tenant_set_invalid")
    if not isinstance(cells, list) or not len(CATEGORIES) + 1 <= len(cells) <= MAX_CELLS: fail("matrix_count_invalid")
    seen_cases: set[str] = set(); categories: list[str] = []; events: set[str] = set()
    observed_slots: set[str] = set(); observed_tenants: set[str] = set()
    for index, raw in enumerate(cells, 1):
        cell = exact(raw, {"case_id", "sequence", "slot", "tenant", "event", "expected_category"}, "matrix_cell_fields_invalid")
        if type(cell["sequence"]) is not int or cell["sequence"] != index: fail("matrix_order_invalid")
        if not isinstance(cell["case_id"], str) or not cell["case_id"].startswith("case_") or not SYMBOL.fullmatch(cell["case_id"]) or cell["case_id"] in seen_cases: fail("case_id_invalid")
        seen_cases.add(cell["case_id"])
        if cell["slot"] not in slots or cell["tenant"] not in tenants: fail("matrix_reference_invalid")
        observed_slots.add(cell["slot"]); observed_tenants.add(cell["tenant"])
        category, event = cell["expected_category"], cell["event"]
        if category not in CATEGORIES or event not in EVENTS or event not in EVENT_FOR_CATEGORY[category]: fail("matrix_semantics_invalid")
        categories.append(category); events.add(event)
    if (
        set(categories) != set(CATEGORIES)
        or any(categories.count(x) != (2 if x == "stable_match" else 1) for x in CATEGORIES)
        or events != set(EVENTS)
        or observed_slots != set(slots)
        or observed_tenants != set(tenants)
    ):
        fail("matrix_coverage_invalid")
    computed_matrix = digest(cells, "tamandua-fleet-preregistration-matrix-v1")
    if computed_matrix != root["matrix_sha256"]: fail("matrix_digest_mismatch")
    controls = exact(root["controls"], CONTROL_FIELDS, "controls_fields_invalid")
    claims = exact(root["claims"], CLAIM_FIELDS, "claims_fields_invalid")
    if any(value is not False for value in controls.values()): fail("execution_control_enabled")
    if any(value is not False for value in claims.values()): fail("claim_enabled")
    return {
        "schema": REPORT_SCHEMA, "evidence_class": EVIDENCE_CLASS, "profile": PROFILE,
        "outcome": "validated_hold", "decision": "hold",
        "hold_reason": "operational_root_unpinned" if root_digest is None else "separate_operator_authorization_required",
        "preregistration_sha256": digest(raw_doc, "tamandua-fleet-preregistration-input-v1"),
        "pins_sha256": digest(raw_pins, "tamandua-fleet-preregistration-pins-v1"),
        "matrix_sha256": computed_matrix,
        "role_bindings_sha256": digest(roles, "tamandua-fleet-preregistration-roles-v1"),
        "metrics": {"slot_count": len(slots), "tenant_count": len(tenants), "cell_count": len(cells), "required_category_count": len(CATEGORIES), "required_event_count": len(EVENTS)},
        "gates": {"canonical_inputs": True, "separate_pins_match": True, "matrix_complete": True, "privacy_context_bound": True, "authority_chain_bound": True, "collector_disabled": True, "executor_disabled": True, "adapter_disabled": True, "target_disabled": True, "backend_disabled": True, "network_disabled": True},
        "aggregate_only": True, "physical_matrix_ready": False, "execution_authorized": False,
        "claims": {field: False for field in sorted(CLAIM_FIELDS)},
    }


def error_report(reason: str) -> dict[str, Any]:
    return {"schema": REPORT_SCHEMA, "evidence_class": EVIDENCE_CLASS, "profile": PROFILE, "outcome": "invalid", "decision": "hold", "reason": reason, "aggregate_only": True, "physical_matrix_ready": False, "execution_authorized": False, "claims": {field: False for field in sorted(CLAIM_FIELDS)}}


def main(argv: list[str] | None = None) -> int:
    parser = QuietArgumentParser(add_help=False)
    sub = parser.add_subparsers(dest="command", required=True)
    validate_parser = sub.add_parser("validate", add_help=False)
    validate_parser.add_argument("--preregistration", type=Path, required=True)
    validate_parser.add_argument("--pins", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        (document, raw_doc), (pins, raw_pins) = read_canonical_pair(
            args.preregistration, args.pins
        )
        report = validate(document, pins, raw_doc, raw_pins); code = 0
    except GateError as exc:
        reason = str(exc)
        report = error_report(reason); code = 2 if reason == "arguments_invalid" else 1
    sys.stdout.write(canonical(report).decode() + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
