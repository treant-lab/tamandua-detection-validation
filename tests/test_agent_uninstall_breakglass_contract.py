import base64
import binascii
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "schemas" / "agent_uninstall_breakglass_v1.schema.json"
FIXTURE_PATH = (
    ROOT
    / "tools"
    / "detection_validation"
    / "fixtures"
    / "agent_uninstall_breakglass_v1.json"
)

DOMAIN = "tamandua.uninstall-breakglass.ed25519/v1"
DOMAIN_PREFIX = DOMAIN.encode("ascii") + b"\0"
UPDATE_CONFIG_DOMAIN_PREFIX = b"tamandua.update-config.ed25519/v1\0"
PAYLOAD_KEYS = [
    "action",
    "agent_id",
    "authorization_mode",
    "consumer",
    "expires_at",
    "intent_id",
    "issued_at",
    "issued_by_user_id",
    "key_domain",
    "key_id",
    "nonce",
    "not_before",
    "organization_id",
    "platform",
    "reason",
    "schema_version",
]
OUTER_KEYS = ["payload", "signature"]
MAX_OUTER_BYTES = 16_384
MAX_PAYLOAD_BYTES = 4_096
MAX_TTL_SECONDS = 86_400
MAX_CLOCK_SKEW_SECONDS = 300
EXPECTED_FIXTURE_SHA256 = "a725751a494b787c0b5822ada7844a23ccb4e1932a689173fa05e2a362fc5e57"


class ContractError(ValueError):
    pass


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: object, *, exact_bytes: int | None = None) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ContractError("base64url_no_pad_required")
    try:
        decoded = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise ContractError("base64url_invalid") from error
    if _b64url_encode(decoded) != value:
        raise ContractError("base64url_noncanonical")
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise ContractError("base64url_length_invalid")
    return decoded


def _load_json_object(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError("json_utf8_invalid") from error

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
        value: dict[str, object] = {}
        for key, member in pairs:
            if key in value:
                raise ContractError("json_duplicate_member")
            value[key] = member
        return value

    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ContractError("json_nonfinite_number")
            ),
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ContractError("json_invalid") from error
    if not isinstance(value, dict):
        raise ContractError("json_object_required")
    return value


def _compact_json(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as error:
        raise ContractError("time_invalid") from error
    return parsed.replace(tzinfo=timezone.utc)


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _payload_schema() -> dict:
    schema = _schema()
    return {
        "$schema": schema["$schema"],
        "$defs": schema["$defs"],
        "$ref": "#/$defs/payload",
    }


def verify_envelope(
    raw_outer: bytes,
    *,
    trusted_public_key: bytes,
    expected_key_id: str,
    expected_organization_id: str,
    expected_agent_id: str,
    expected_platform: str,
    expected_consumer: str,
    now: datetime,
) -> dict:
    if not isinstance(raw_outer, bytes) or not (1 <= len(raw_outer) <= MAX_OUTER_BYTES):
        raise ContractError("outer_size_invalid")
    outer = _load_json_object(raw_outer)
    if list(outer) != OUTER_KEYS or _compact_json(outer) != raw_outer:
        raise ContractError("outer_noncanonical")
    try:
        Draft202012Validator(_schema()).validate(outer)
    except ValidationError as error:
        raise ContractError("outer_schema_invalid") from error

    payload_raw = _b64url_decode(outer["payload"])
    if not (1 <= len(payload_raw) <= MAX_PAYLOAD_BYTES):
        raise ContractError("payload_size_invalid")
    payload = _load_json_object(payload_raw)
    if list(payload) != PAYLOAD_KEYS or _compact_json(payload) != payload_raw:
        raise ContractError("payload_noncanonical")
    try:
        Draft202012Validator(_payload_schema()).validate(payload)
    except ValidationError as error:
        raise ContractError("payload_schema_invalid") from error

    if payload["key_id"] != expected_key_id:
        raise ContractError("key_id_mismatch")
    if (
        payload["organization_id"] != expected_organization_id
        or payload["agent_id"] != expected_agent_id
        or payload["platform"] != expected_platform
        or payload["consumer"] != expected_consumer
    ):
        raise ContractError("target_binding_mismatch")
    _b64url_decode(payload["nonce"], exact_bytes=32)
    reason = payload["reason"]
    if reason != reason.strip() or not (8 <= len(reason.encode("utf-8")) <= 512):
        raise ContractError("reason_invalid")
    if any(ord(character) <= 0x1F or 0x7F <= ord(character) <= 0x9F for character in reason):
        raise ContractError("reason_control_character")

    issued_at = _parse_time(payload["issued_at"])
    not_before = _parse_time(payload["not_before"])
    expires_at = _parse_time(payload["expires_at"])
    if not (issued_at <= not_before < expires_at):
        raise ContractError("time_order_invalid")
    ttl_seconds = int((expires_at - issued_at).total_seconds())
    if not (1 <= ttl_seconds <= MAX_TTL_SECONDS):
        raise ContractError("ttl_invalid")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ContractError("verification_time_not_utc_aware")
    now = now.astimezone(timezone.utc)
    if now < not_before - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ContractError("authorization_not_yet_valid")
    if now > expires_at + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise ContractError("authorization_expired")

    public_key_raw = bytes(trusted_public_key)
    if len(public_key_raw) != 32:
        raise ContractError("public_key_length_invalid")
    signature = _b64url_decode(outer["signature"], exact_bytes=64)
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(
            signature, DOMAIN_PREFIX + payload_raw
        )
    except (InvalidSignature, ValueError) as error:
        raise ContractError("signature_invalid") from error
    return payload


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _fixture_material() -> tuple[dict, bytes, bytes, datetime]:
    fixture = _fixture()
    public_key = _b64url_decode(fixture["test_key"]["public_key_base64url"], exact_bytes=32)
    envelope = _compact_json(fixture["envelope"])
    now = _parse_time(fixture["payload"]["not_before"])
    return fixture, public_key, envelope, now


def _expected_target(fixture: dict, **overrides: str) -> dict[str, str]:
    payload = fixture["payload"]
    expected = {
        "expected_key_id": fixture["test_key"]["key_id"],
        "expected_organization_id": payload["organization_id"],
        "expected_agent_id": payload["agent_id"],
        "expected_platform": payload["platform"],
        "expected_consumer": payload["consumer"],
    }
    expected.update(overrides)
    return expected


def _signed_envelope(payload_raw: bytes, private_key: Ed25519PrivateKey, prefix: bytes = DOMAIN_PREFIX) -> bytes:
    return _compact_json(
        {
            "payload": _b64url_encode(payload_raw),
            "signature": _b64url_encode(private_key.sign(prefix + payload_raw)),
        }
    )


def test_schema_and_frozen_golden_vector_are_exact_and_test_only() -> None:
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == EXPECTED_FIXTURE_SHA256

    fixture, public_key, envelope, now = _fixture_material()
    assert list(fixture) == [
        "fixture_schema",
        "validation_scope",
        "domain_prefix_base64url",
        "test_key",
        "payload",
        "canonical_payload_base64url",
        "envelope",
    ]
    assert fixture["fixture_schema"] == "tamandua.agent-uninstall-breakglass.golden-vector/v1"
    assert fixture["validation_scope"] == {
        "classification": "synthetic-test-only",
        "test_only": True,
        "production_authority": False,
        "external_claim_allowed": False,
        "vendor_parity_claimed": False,
    }
    assert _b64url_decode(fixture["domain_prefix_base64url"]) == DOMAIN_PREFIX
    assert fixture["test_key"]["warning"] == "TEST ONLY - NEVER USE FOR PRODUCTION AUTHORIZATION"
    assert fixture["test_key"]["algorithm"] == "Ed25519"
    assert fixture["test_key"]["key_id"] == fixture["payload"]["key_id"]

    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    derived_public = private_key.public_key().public_bytes_raw()
    assert derived_public == public_key

    payload_raw = _compact_json(fixture["payload"])
    assert list(fixture["payload"]) == PAYLOAD_KEYS
    assert _b64url_encode(payload_raw) == fixture["canonical_payload_base64url"]
    assert fixture["envelope"]["payload"] == fixture["canonical_payload_base64url"]
    assert _signed_envelope(payload_raw, private_key) == envelope
    assert (_parse_time(fixture["payload"]["expires_at"]) - _parse_time(fixture["payload"]["issued_at"])).total_seconds() == 3_600
    assert verify_envelope(
        envelope,
        trusted_public_key=public_key,
        **_expected_target(fixture),
        now=now,
    ) == fixture["payload"]


@pytest.mark.parametrize(
    ("payload_changes", "expected_overrides"),
    [
        (
            {"organization_id": "55555555-5555-4555-8555-555555555555"},
            {},
        ),
        ({"agent_id": "66666666-6666-4666-8666-666666666666"}, {}),
        ({"consumer": "native_cli"}, {}),
        (
            {"consumer": "native_cli", "platform": "linux"},
            {"expected_consumer": "native_cli"},
        ),
    ],
)
def test_resigned_cross_target_payload_is_rejected(
    payload_changes: dict[str, str], expected_overrides: dict[str, str]
) -> None:
    fixture, public_key, _envelope, now = _fixture_material()
    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    payload = copy.deepcopy(fixture["payload"])
    payload.update(payload_changes)
    expected = _expected_target(fixture, **expected_overrides)
    with pytest.raises(ContractError, match="target_binding_mismatch"):
        verify_envelope(
            _signed_envelope(_compact_json(payload), private_key),
            trusted_public_key=public_key,
            **expected,
            now=now,
        )


@pytest.mark.parametrize("platform", ["windows", "linux", "macos"])
def test_native_cli_is_valid_on_each_supported_platform(platform: str) -> None:
    fixture, public_key, _envelope, now = _fixture_material()
    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    payload = copy.deepcopy(fixture["payload"])
    payload["consumer"] = "native_cli"
    payload["platform"] = platform
    assert verify_envelope(
        _signed_envelope(_compact_json(payload), private_key),
        trusted_public_key=public_key,
        **_expected_target(
            fixture,
            expected_consumer="native_cli",
            expected_platform=platform,
        ),
        now=now,
    ) == payload


def test_windows_msi_is_rejected_for_non_windows_platform_even_when_resigned() -> None:
    fixture, public_key, _envelope, now = _fixture_material()
    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    payload = copy.deepcopy(fixture["payload"])
    payload["platform"] = "linux"
    with pytest.raises(ContractError, match="payload_schema_invalid"):
        verify_envelope(
            _signed_envelope(_compact_json(payload), private_key),
            trusted_public_key=public_key,
            **_expected_target(fixture, expected_platform="linux"),
            now=now,
        )


def test_domain_wrong_key_and_update_config_substitution_fail_closed() -> None:
    fixture, public_key, _envelope, now = _fixture_material()
    payload_raw = _compact_json(fixture["payload"])
    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    update_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"tamandua-update-config-test-key-v1").digest())

    altered_domain = _signed_envelope(payload_raw, private_key, UPDATE_CONFIG_DOMAIN_PREFIX)
    with pytest.raises(ContractError, match="signature_invalid"):
        verify_envelope(
            altered_domain,
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now,
        )

    wrong_key_signature = _signed_envelope(payload_raw, update_key)
    with pytest.raises(ContractError, match="signature_invalid"):
        verify_envelope(
            wrong_key_signature,
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now,
        )

    substituted = copy.deepcopy(fixture["payload"])
    substituted["key_domain"] = "tamandua.update-config.ed25519/v1"
    substituted_raw = _compact_json(substituted)
    with pytest.raises(ContractError, match="payload_schema_invalid"):
        verify_envelope(
            _signed_envelope(substituted_raw, private_key),
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now,
        )


@pytest.mark.parametrize("kind", ["reordered", "whitespace", "duplicate"])
def test_noncanonical_or_duplicate_payload_is_rejected_even_with_valid_signature(kind: str) -> None:
    fixture, public_key, _envelope, now = _fixture_material()
    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    payload = fixture["payload"]
    if kind == "reordered":
        reordered = {"agent_id": payload["agent_id"], "action": payload["action"]}
        reordered.update({key: value for key, value in payload.items() if key not in reordered})
        payload_raw = _compact_json(reordered)
    elif kind == "whitespace":
        payload_raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    else:
        canonical = _compact_json(payload).decode("utf-8")
        payload_raw = canonical.replace(
            '"action":"agent_uninstall",',
            '"action":"agent_uninstall","action":"agent_uninstall",',
            1,
        ).encode("utf-8")
    with pytest.raises(ContractError, match="payload_noncanonical|json_duplicate_member"):
        verify_envelope(
            _signed_envelope(payload_raw, private_key),
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now,
        )


def test_outer_order_duplicates_padding_unknown_and_signature_mutation_are_rejected() -> None:
    fixture, public_key, envelope, now = _fixture_material()
    outer = fixture["envelope"]
    cases = [
        _compact_json({"signature": outer["signature"], "payload": outer["payload"]}),
        (
            '{"payload":"%s","payload":"%s","signature":"%s"}'
            % (outer["payload"], outer["payload"], outer["signature"])
        ).encode("ascii"),
        _compact_json({"payload": outer["payload"] + "=", "signature": outer["signature"]}),
        _compact_json({"payload": outer["payload"], "signature": outer["signature"] + "="}),
        _compact_json({"payload": outer["payload"], "signature": outer["signature"], "unknown": True}),
    ]
    mutated_signature = bytearray(_b64url_decode(outer["signature"], exact_bytes=64))
    mutated_signature[0] ^= 1
    cases.append(_compact_json({"payload": outer["payload"], "signature": _b64url_encode(bytes(mutated_signature))}))
    for candidate in cases:
        with pytest.raises(ContractError):
            verify_envelope(
                candidate,
                trusted_public_key=public_key,
                **_expected_target(fixture),
                now=now,
            )
    assert len(envelope) <= MAX_OUTER_BYTES


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"),
        ("consumer", "update_config"),
        ("platform", "android"),
        ("key_id", "-invalid"),
        ("key_id", "Uppercase-not-canonical"),
        ("nonce", "A" * 42),
        ("issued_at", "2030-01-02T03:04:05.000Z"),
        ("reason", " short "),
    ],
)
def test_uuid_enum_key_nonce_time_and_reason_constraints(field: str, value: str) -> None:
    fixture, public_key, _envelope, now = _fixture_material()
    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    payload = copy.deepcopy(fixture["payload"])
    payload[field] = value
    with pytest.raises(ContractError):
        verify_envelope(
            _signed_envelope(_compact_json(payload), private_key),
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now,
        )


@pytest.mark.parametrize(
    ("reason", "accepted"),
    [
        ("1234567", False),
        ("é" * 4, True),
        ("a" * 512, True),
        ("a" * 513, False),
    ],
)
def test_signed_reason_bounds_use_utf8_bytes_not_codepoints(
    reason: str, accepted: bool
) -> None:
    fixture, public_key, _envelope, now = _fixture_material()
    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    payload = copy.deepcopy(fixture["payload"])
    payload["reason"] = reason
    envelope = _signed_envelope(_compact_json(payload), private_key)
    if accepted:
        assert verify_envelope(
            envelope,
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now,
        )["reason"] == reason
    else:
        with pytest.raises(ContractError, match="reason_invalid|payload_schema_invalid"):
            verify_envelope(
                envelope,
                trusted_public_key=public_key,
                **_expected_target(fixture),
                now=now,
            )


def test_payload_unknown_missing_bounds_time_order_ttl_and_clock_skew_fail_closed() -> None:
    fixture, public_key, _envelope, now = _fixture_material()
    seed = _b64url_decode(fixture["test_key"]["private_seed_base64url"], exact_bytes=32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    mutations: list[dict] = []
    unknown = copy.deepcopy(fixture["payload"])
    unknown["unknown"] = True
    mutations.append(unknown)
    missing = copy.deepcopy(fixture["payload"])
    del missing["reason"]
    mutations.append(missing)
    control = copy.deepcopy(fixture["payload"])
    control["reason"] = "incident\u0085response"
    mutations.append(control)
    too_long = copy.deepcopy(fixture["payload"])
    too_long["reason"] = "é" * 257
    mutations.append(too_long)
    reversed_time = copy.deepcopy(fixture["payload"])
    reversed_time["not_before"] = reversed_time["expires_at"]
    mutations.append(reversed_time)
    excessive_ttl = copy.deepcopy(fixture["payload"])
    excessive_ttl["expires_at"] = "2030-01-03T03:04:06Z"
    mutations.append(excessive_ttl)

    for payload in mutations:
        with pytest.raises(ContractError):
            verify_envelope(
                _signed_envelope(_compact_json(payload), private_key),
                trusted_public_key=public_key,
                **_expected_target(fixture),
                now=now,
            )

    with pytest.raises(ContractError, match="payload_size_invalid"):
        oversized_payload = b"{" + b" " * MAX_PAYLOAD_BYTES + b"}"
        verify_envelope(
            _signed_envelope(oversized_payload, private_key),
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now,
        )
    with pytest.raises(ContractError, match="outer_size_invalid"):
        verify_envelope(
            b"{" + b" " * MAX_OUTER_BYTES + b"}",
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now,
        )
    with pytest.raises(ContractError, match="authorization_not_yet_valid"):
        verify_envelope(
            _compact_json(fixture["envelope"]),
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=now - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS + 1),
        )
    expires_at = _parse_time(fixture["payload"]["expires_at"])
    with pytest.raises(ContractError, match="authorization_expired"):
        verify_envelope(
            _compact_json(fixture["envelope"]),
            trusted_public_key=public_key,
            **_expected_target(fixture),
            now=expires_at + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS + 1),
        )
