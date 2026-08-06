#!/usr/bin/env python3
"""Bounded synthetic fleet-continuity contract for Android device identity."""

from __future__ import annotations

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

INPUT_SCHEMA = "tamandua.android.device_identity.fleet_continuity_input/v1"
REPORT_SCHEMA = "tamandua.android.device_identity.fleet_continuity_report/v1"
EVIDENCE_CLASS = "synthetic_fleet_continuity_contract"
PROFILE = "tamandua.android.device_identity.fleet_continuity_offline/v1"
MAX_INPUT_BYTES = 512 * 1024
MAX_OBSERVATIONS = 4096
MAX_SLOTS = 512

CATEGORIES = (
    "baseline_observed",
    "stable_match",
    "tenant_separation",
    "authorized_rotation",
    "authorized_reenrollment",
    "recovery_previous",
    "recovery_replacement",
    "attestation_assurance_change_only",
    "missing_key_hold",
    "unexpected_key_change_hold",
    "cross_slot_key_reuse_hold",
    "clone_restore_suspected_hold",
)
EVENTS = {
    "enroll",
    "observe",
    "restart",
    "update",
    "authorized_rotate",
    "authorized_reenroll",
    "recover_previous",
    "recover_replacement",
    "restore",
}
ATTESTATION = {
    "verified_strongbox",
    "verified_tee",
    "present_unverified",
    "not_requested",
    "unavailable",
}
HOLD_CATEGORIES = {
    "missing_key_hold",
    "unexpected_key_change_hold",
    "cross_slot_key_reuse_hold",
    "clone_restore_suspected_hold",
}
TOP_FIELDS = {
    "schema",
    "evidence_class",
    "profile",
    "source_sha256",
    "observations",
}
OBSERVATION_FIELDS = {
    "case_id",
    "sequence",
    "fleet_slot_id",
    "tenant_id",
    "installation_epoch",
    "event",
    "key_state",
    "key_token",
    "previous_key_token",
    "authorization_id",
    "attestation_state",
    "expected_category",
}
SENSITIVE_FIELD_PARTS = {
    "serial",
    "imei",
    "meid",
    "android_id",
    "phone",
    "email",
    "ip_address",
    "device_name",
    "manufacturer",
    "model",
    "operator",
    "public_key",
    "private_key",
    "spki",
    "jwk",
    "certificate",
    "attestation_evidence",
    "proof",
    "secret",
    "password",
    "credential",
    "hardware_guid",
    "mac_address",
    "widevine",
}
SYMBOL = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MAC_ADDRESS = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)
UUID_VALUE = re.compile(
    r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$",
    re.IGNORECASE,
)
GLOBAL_HEX_ID_VALUE = re.compile(r"^[0-9a-f]{16}$", re.IGNORECASE)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
MAX_PRIVACY_DECODE_LAYERS = 2
MAX_PRIVACY_ENCODED_CHARS = 512


class ContractError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _fail(code: str) -> None:
    raise ContractError(code)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_key")
        result[key] = value
    return result


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError):
        _fail("input_json_invalid")


def parse_canonical(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_INPUT_BYTES:
        _fail("input_size_invalid")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: _fail("input_json_invalid"),
        )
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail("input_json_invalid")
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        _fail("input_not_canonical")
    return value


def _sensitive(value: Any, path: tuple[str, ...] = (), depth: int = 0) -> None:
    if depth > 8:
        _fail("input_depth_exceeded")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                _fail("input_json_invalid")
            lowered = _privacy_normalize(key)
            if any(part in lowered for part in SENSITIVE_FIELD_PARTS):
                _fail("sensitive_field_rejected")
            _sensitive(child, path + (key,), depth + 1)
    elif isinstance(value, list):
        for child in value:
            _sensitive(child, path, depth + 1)
    elif isinstance(value, str):
        if len(value) > MAX_PRIVACY_ENCODED_CHARS:
            _fail("string_bound_exceeded")
        if any(_is_sensitive_text(candidate) for candidate in _privacy_candidates(value)):
            _fail("sensitive_value_rejected")
        if len(value) > 128:
            _fail("string_bound_exceeded")


def _privacy_normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if unicodedata.category(character) != "Cf")


def _is_sensitive_text(value: str) -> bool:
    return bool(
        value.startswith(("tmnd-", "tmdk_v1_", "tmdks_v1_", "-----begin"))
        or EMAIL.fullmatch(value)
        or IPV4.fullmatch(value)
        or MAC_ADDRESS.fullmatch(value)
        or UUID_VALUE.fullmatch(value)
        or GLOBAL_HEX_ID_VALUE.fullmatch(value)
        or re.fullmatch(r"\d{15}", value)
        or re.fullmatch(r"(?:[0-9a-f]{2}:){31}[0-9a-f]{2}", value)
    )


def _percent_decode(value: str) -> str | None:
    if not re.search(r"%[0-9a-f]{2}", value, re.IGNORECASE):
        return None
    decoded = bytearray()
    index = 0
    while index < len(value):
        if value[index] == "%" and index + 2 < len(value) and re.fullmatch(
            r"[0-9a-f]{2}", value[index + 1 : index + 3], re.IGNORECASE
        ):
            decoded.append(int(value[index + 1 : index + 3], 16))
            index += 3
            continue
        if ord(value[index]) > 0x7F:
            return None
        decoded.append(ord(value[index]))
        index += 1
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_privacy_layer(value: str) -> set[str]:
    decoded: set[str] = set()
    percent = _percent_decode(value)
    if percent is not None:
        decoded.add(percent)
    if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", value, re.IGNORECASE):
        try:
            decoded.add(bytes.fromhex(value).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            pass
    if len(value) >= 8 and re.fullmatch(r"[a-z0-9_+/=-]+", value, re.IGNORECASE):
        try:
            padded = value + "=" * (-len(value) % 4)
            decoded.add(base64.b64decode(padded, altchars=b"-_", validate=True).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            pass
    return decoded


def _privacy_candidates(value: str) -> set[str]:
    candidates: set[str] = set()
    decoded_values = {value}
    frontier = {value}
    for _ in range(MAX_PRIVACY_DECODE_LAYERS):
        next_frontier: set[str] = set()
        for candidate in frontier:
            candidates.add(_privacy_normalize(candidate))
            for decoded in _decode_privacy_layer(candidate):
                normalized = _privacy_normalize(decoded)
                if normalized:
                    candidates.add(normalized)
                if decoded and len(decoded) <= MAX_PRIVACY_ENCODED_CHARS and decoded not in decoded_values:
                    decoded_values.add(decoded)
                    next_frontier.add(decoded)
        frontier = next_frontier
        if not frontier:
            break
    for candidate in frontier:
        candidates.add(_privacy_normalize(candidate))
    return candidates


def _exact(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(code)
    return value


def _symbol(value: Any, code: str, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or not SYMBOL.fullmatch(value)
    ):
        _fail(code)
    return value


def _nullable_symbol(value: Any, code: str, prefix: str) -> str | None:
    if value is None:
        return None
    return _symbol(value, code, prefix)


def _ratio(numerator: int, denominator: int) -> dict[str, int]:
    return {"numerator": numerator, "denominator": denominator}


def _classify(
    observation: dict[str, Any],
    previous: dict[str, Any] | None,
    prior_tenants_for_slot: set[str],
) -> str:
    event = observation["event"]
    state = observation["key_state"]
    key = observation["key_token"]
    old_key = observation["previous_key_token"]
    authorization = observation["authorization_id"]

    if state == "missing":
        if key is not None:
            _fail("missing_key_has_token")
        if old_key is not None or authorization is not None:
            _fail("unexpected_transition_authority")
        return "clone_restore_suspected_hold" if event == "restore" else "missing_key_hold"
    if key is None:
        _fail("present_key_missing_token")
    if previous is None:
        if event != "enroll" or old_key is not None or authorization is not None:
            _fail("baseline_invalid")
        if prior_tenants_for_slot:
            return "tenant_separation"
        return "baseline_observed"

    previous_key = previous["key_token"]
    if event in {"authorized_rotate", "authorized_reenroll", "recover_replacement"}:
        if not authorization or old_key != previous_key or key == previous_key:
            _fail("authorized_transition_binding_invalid")
        if event == "authorized_reenroll":
            if observation["installation_epoch"] == previous["installation_epoch"]:
                _fail("reenrollment_epoch_not_changed")
            return "authorized_reenrollment"
        if observation["installation_epoch"] != previous["installation_epoch"]:
            _fail("rotation_epoch_changed")
        return "authorized_rotation" if event == "authorized_rotate" else "recovery_replacement"
    if event == "recover_previous":
        if not authorization or old_key != previous_key or key != previous_key:
            _fail("recovery_previous_binding_invalid")
        return "recovery_previous"
    if authorization is not None or old_key is not None:
        _fail("unexpected_transition_authority")
    if event == "restore" and (
        key != previous_key or observation["installation_epoch"] != previous["installation_epoch"]
    ):
        return "clone_restore_suspected_hold"
    if key != previous_key:
        return "unexpected_key_change_hold"
    if observation["installation_epoch"] != previous["installation_epoch"]:
        return "clone_restore_suspected_hold"
    if observation["attestation_state"] != previous["attestation_state"]:
        return "attestation_assurance_change_only"
    return "stable_match"


def compile_report(document: dict[str, Any]) -> dict[str, Any]:
    _sensitive(document)
    root = _exact(document, TOP_FIELDS, "input_fields_invalid")
    if (
        root["schema"] != INPUT_SCHEMA
        or root["evidence_class"] != EVIDENCE_CLASS
        or root["profile"] != PROFILE
        or not isinstance(root["source_sha256"], str)
        or not SHA256.fullmatch(root["source_sha256"])
        or root["source_sha256"] == "0" * 64
    ):
        _fail("input_identity_invalid")
    observations = root["observations"]
    if not isinstance(observations, list) or not 2 <= len(observations) <= MAX_OBSERVATIONS:
        _fail("observation_count_invalid")

    parsed: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    slots: set[str] = set()
    seen_observations: set[tuple[Any, ...]] = set()
    for index, raw_observation in enumerate(observations, start=1):
        item = _exact(raw_observation, OBSERVATION_FIELDS, "observation_fields_invalid")
        if type(item["sequence"]) is not int or item["sequence"] != index:
            _fail("observation_order_invalid")
        case_id = _symbol(item["case_id"], "case_id_invalid", "case_")
        slot = _symbol(item["fleet_slot_id"], "fleet_slot_invalid", "slot_")
        tenant = _symbol(item["tenant_id"], "tenant_id_invalid", "tenant_")
        epoch = _symbol(item["installation_epoch"], "installation_epoch_invalid", "install_")
        key_token = _nullable_symbol(item["key_token"], "key_token_invalid", "key_")
        previous_key = _nullable_symbol(
            item["previous_key_token"], "previous_key_token_invalid", "key_"
        )
        authorization = _nullable_symbol(
            item["authorization_id"], "authorization_id_invalid", "auth_"
        )
        if item["event"] not in EVENTS or item["key_state"] not in {"present", "missing"}:
            _fail("observation_state_invalid")
        if item["attestation_state"] not in ATTESTATION or item["expected_category"] not in CATEGORIES:
            _fail("observation_category_invalid")
        if case_id in case_ids:
            _fail("duplicate_case_id")
        case_ids.add(case_id)
        slots.add(slot)
        fingerprint = (slot, tenant, epoch, item["event"], key_token, previous_key, authorization)
        if fingerprint in seen_observations:
            _fail("observation_replay")
        seen_observations.add(fingerprint)
        parsed.append(item)
    if len(slots) > MAX_SLOTS:
        _fail("fleet_slot_count_invalid")

    previous_by_subject: dict[tuple[str, str], dict[str, Any]] = {}
    tenants_by_slot: dict[str, set[str]] = {}
    key_owner: dict[tuple[str, str], str] = {}
    key_tenant: dict[str, str] = {}
    authorization_ids: set[str] = set()
    counts = {category: 0 for category in CATEGORIES}
    eligible = 0
    for item in parsed:
        subject = (item["tenant_id"], item["fleet_slot_id"])
        prior_tenants = tenants_by_slot.setdefault(item["fleet_slot_id"], set())
        previous = previous_by_subject.get(subject)
        category = _classify(item, previous, prior_tenants)
        authorization = item["authorization_id"]
        if authorization is not None:
            if authorization in authorization_ids:
                _fail("authorization_reuse")
            authorization_ids.add(authorization)
        key = item["key_token"]
        if key is not None:
            prior_tenant = key_tenant.get(key)
            if prior_tenant is not None and prior_tenant != item["tenant_id"]:
                _fail("cross_tenant_key_reuse")
            key_tenant[key] = item["tenant_id"]
            key_scope = (item["tenant_id"], key)
            owner = key_owner.get(key_scope)
            if owner is not None and owner != item["fleet_slot_id"]:
                category = "cross_slot_key_reuse_hold"
            else:
                key_owner[key_scope] = item["fleet_slot_id"]
        if category != item["expected_category"]:
            _fail("expected_category_mismatch")
        counts[category] += 1
        if previous is not None:
            eligible += 1
        previous_by_subject[subject] = item
        prior_tenants.add(item["tenant_id"])

    if eligible == 0:
        _fail("eligible_transition_count_invalid")

    holds = sum(counts[category] for category in HOLD_CATEGORIES)
    authorized = sum(
        counts[category]
        for category in (
            "authorized_rotation",
            "authorized_reenrollment",
            "recovery_previous",
            "recovery_replacement",
        )
    )
    stable = counts["stable_match"] + counts["attestation_assurance_change_only"]
    input_sha256 = hashlib.sha256(canonical_bytes(document)).hexdigest()
    return {
        "schema": REPORT_SCHEMA,
        "evidence_class": EVIDENCE_CLASS,
        "profile": PROFILE,
        "outcome": "synthetic_contract_match",
        "decision": "hold",
        "input_sha256": input_sha256,
        "aggregate_only": True,
        "identity_semantics": {
            "installation_handle": "install_scoped_handle_not_hardware_guid",
            "device_key": "tenant_scoped_key_continuity_not_physical_guid",
        },
        "metrics": {
            "observations": len(parsed),
            "fleet_slots": len(slots),
            "eligible_transitions": eligible,
            "category_counts": counts,
            "stable_continuity_ratio": _ratio(stable, eligible),
            "authorized_change_ratio": _ratio(authorized, eligible),
            "hold_ratio": _ratio(holds, len(parsed)),
        },
        "limitations": [
            "synthetic_semantics_only",
            "no_real_fleet_uniqueness_claim",
            "no_physical_hardware_guid_claim",
            "no_clone_detection_efficacy_claim",
            "no_attestation_verification",
            "no_sla_or_vendor_parity_claim",
        ],
        "claims": {
            "physical_device_validated": False,
            "hardware_attestation_validated": False,
            "real_fleet_uniqueness_validated": False,
            "clone_detection_validated": False,
            "product_ready": False,
            "production_ready": False,
            "external_claim_allowed": False,
            "vendor_parity": False,
        },
    }


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _assert_direct_path(path: Path) -> tuple[tuple[int, int, int, int], ...]:
    identities = []
    for component in (path, *path.parents):
        info = os.lstat(component)
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            _fail("input_path_unsafe")
        identities.append(
            (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                getattr(info, "st_file_attributes", 0),
            )
        )
    return tuple(identities)


def read_input(path: Path) -> bytes:
    try:
        if not path.is_absolute() or path != path.resolve(strict=True):
            _fail("input_path_unsafe")
        path_chain_before = _assert_direct_path(path)
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT_BYTES:
            _fail("input_path_unsafe")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except ContractError:
        raise
    except OSError:
        _fail("input_path_unsafe")
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            _fail("input_changed")
        raw = b""
        while len(raw) <= MAX_INPUT_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_INPUT_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(descriptor)
        path_chain_after = _assert_direct_path(path)
        path_after = os.lstat(path)
        if (
            len(raw) != opened.st_size
            or _file_identity(after) != _file_identity(opened)
            or _file_identity(path_after) != _file_identity(opened)
            or path_chain_after != path_chain_before
        ):
            _fail("input_changed")
        return raw
    except ContractError:
        raise
    except OSError:
        _fail("input_changed")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def error_report(raw: bytes, reason: str) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "evidence_class": EVIDENCE_CLASS,
        "profile": PROFILE,
        "outcome": "invalid",
        "decision": "hold",
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "aggregate_only": True,
        "reason": reason,
        "claims": {
            "physical_device_validated": False,
            "hardware_attestation_validated": False,
            "real_fleet_uniqueness_validated": False,
            "clone_detection_validated": False,
            "product_ready": False,
            "production_ready": False,
            "external_claim_allowed": False,
            "vendor_parity": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    raw = b""
    try:
        if len(arguments) != 2 or arguments[0] != "--input":
            _fail("arguments_invalid")
        raw = read_input(Path(arguments[1]))
        report = compile_report(parse_canonical(raw))
        code = 0
    except ContractError as error:
        report = error_report(raw, error.code)
        code = 2
    sys.stdout.buffer.write(canonical_bytes(report) + b"\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
