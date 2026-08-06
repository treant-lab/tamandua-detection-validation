#!/usr/bin/env python3
"""Verify an offline synthetic signed game-policy authority envelope."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tools/detection_validation/fixtures/anti_cheat_game_policy_authority_synthetic_v1.json"
AUTHORITY_SCHEMA = ROOT / "schemas/anti_cheat_game_policy_authority_v1.schema.json"
REPORT_SCHEMA = ROOT / "schemas/anti_cheat_game_policy_verification_report_v1.schema.json"
GAME_003A = ROOT / "tools/detection_validation/fixtures/anti_cheat_unity_server_movement_replay_synthetic_v1.json"
ENVELOPE_DOMAIN = b"tamandua.anti_cheat.game_policy_envelope/v1\0"
CHECKPOINT_DOMAIN = b"tamandua.anti_cheat.game_policy_checkpoint/v1\0"
REVOCATION_DOMAIN = b"tamandua.anti_cheat.game_policy_revocations/v1\0"
REPORT_DOMAIN = b"tamandua.anti_cheat.game_policy_verification_report/v1\0"
TRUST_ROOT_DOMAIN = b"tamandua.anti_cheat.game_policy_trust_root/v1\0"
PINNED_TRUST_ROOT_DIGEST = "d3d3493f211121005a2dcdc32208ce3bd281740639c278c2efc2f96bcc7a9445"
PINNED_PRIOR_CHECKPOINT_DIGEST = "2b5f48a9543ef79f9e6b23a6fa19466e8ccbf2b05c9f9c434634b37e13c2a229"
PINNED_SCOPE = {"tenant_scope_digest": "1" * 64, "game_id": "sample.game", "build_digest": "2" * 64}
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SECRET_PARTS = {"secret", "password", "passwd", "credential", "credentials", "token", "cookie", "private", "authorization", "auth"}


class PolicyAuthorityError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyAuthorityError("duplicate JSON member rejected")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if not 1 <= len(raw) <= 1_048_576 or b"\0" in raw:
        raise PolicyAuthorityError("JSON bounds are invalid")
    value = json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_float=lambda _v: (_ for _ in ()).throw(PolicyAuthorityError("floating-point JSON rejected")),
        parse_constant=lambda _v: (_ for _ in ()).throw(PolicyAuthorityError("non-finite JSON rejected")),
    )
    if type(value) is not dict:
        raise PolicyAuthorityError("JSON root must be an object")
    return value, raw


def _name_parts(name: str) -> set[str]:
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return set(filter(None, re.sub(r"[^a-z0-9]+", "_", split.casefold()).split("_")))


def privacy_errors(value: Any, path: str = "authority") -> list[str]:
    errors: list[str] = []
    if type(value) is dict:
        for key, member in value.items():
            parts = _name_parts(key)
            if parts & SECRET_PARTS or ({"api", "key"} <= parts) or ({"access", "key"} <= parts):
                errors.append(f"secret/private member rejected at {path}.{key}")
            errors.extend(privacy_errors(member, f"{path}.{key}"))
    elif type(value) is list:
        for index, member in enumerate(value):
            errors.extend(privacy_errors(member, f"{path}[{index}]"))
    elif type(value) is float:
        errors.append(f"floating-point value rejected at {path}")
    elif type(value) is str and re.search(r"(?i)(?:basic|bearer)\s+[a-z0-9._~+/=-]{4,}|(?:password|secret|token)\s*[:=]", value):
        errors.append(f"secret-shaped value rejected at {path}")
    return errors


def checkpoint_digest(checkpoint: dict[str, Any]) -> str:
    basis = {key: checkpoint[key] for key in ("authority_epoch", "revision", "revocation_version", "revocation_set_digest", "revoked_key_ids", "policy_digest", "envelope_digest")}
    return sha256(CHECKPOINT_DOMAIN + canonical(basis))


def revocation_set_digest(version: int, revoked_key_ids: list[str]) -> str:
    return sha256(REVOCATION_DOMAIN + canonical({"version": version, "revoked_key_ids": revoked_key_ids}))


def _game_003a_digest() -> str:
    fixture, _ = load_json(GAME_003A)
    computed = sha256(b"tamandua.anti_cheat.server_movement_policy/v1\0" + canonical(fixture["policy"]))
    if fixture.get("policy_digest") != computed:
        raise PolicyAuthorityError("GAME-003A policy authority is incoherent")
    return computed


def verify_authority(
    document: dict[str, Any], trusted_time_unix: int,
    pinned_trust_root_digest: str = PINNED_TRUST_ROOT_DIGEST,
    pinned_prior_checkpoint_digest: str = PINNED_PRIOR_CHECKPOINT_DIGEST,
    pinned_scope: dict[str, str] | None = None,
) -> dict[str, Any]:
    if type(trusted_time_unix) is not int or trusted_time_unix < 0:
        raise PolicyAuthorityError("trusted time is invalid")
    if privacy_errors(document):
        raise PolicyAuthorityError(privacy_errors(document)[0])
    schema, _ = load_json(AUTHORITY_SCHEMA)
    Draft202012Validator.check_schema(schema)
    if list(Draft202012Validator(schema).iter_errors(document)):
        raise PolicyAuthorityError("authority schema validation failed")
    root_keys = document["trust_root"]["keys"]
    key_ids = [item["key_id"] for item in root_keys]
    public_keys = [item["public_key_hex"] for item in root_keys]
    if len(key_ids) != len(set(key_ids)):
        raise PolicyAuthorityError("duplicate trust-root key_id rejected")
    if len(public_keys) != len(set(public_keys)):
        raise PolicyAuthorityError("duplicate trust-root public key rejected")
    trust_root_digest = sha256(TRUST_ROOT_DOMAIN + canonical(document["trust_root"]))
    if not DIGEST.fullmatch(pinned_trust_root_digest) or trust_root_digest != pinned_trust_root_digest:
        raise PolicyAuthorityError("trust root is not caller-pinned")
    envelope = document["signed_envelope"]
    scope = envelope["scope"]
    policy = envelope["policy"]
    authority = envelope["authority"]
    validity = envelope["validity"]
    revocations = document["revocations"]
    prior = document["prior_checkpoint"]
    caller_scope = PINNED_SCOPE if pinned_scope is None else pinned_scope
    if scope != document["expected_scope"] or scope != caller_scope:
        raise PolicyAuthorityError("policy scope is not caller-pinned")
    expected_policy_digest = _game_003a_digest()
    if policy["policy_digest"] != expected_policy_digest or document["game_003a_policy_digest"] != expected_policy_digest:
        raise PolicyAuthorityError("GAME-003A policy digest mismatch")
    if policy["policy_id"] != "sample.server.movement" or policy["policy_version"] != "1":
        raise PolicyAuthorityError("policy identity/version mismatch")
    if envelope["mapping"] != {"features": ["server_position_fixed_point"], "detectors": ["server_movement_replay_v1"]}:
        raise PolicyAuthorityError("feature/detector mapping mismatch")
    if not validity["issued_at_unix"] <= validity["not_before_unix"] <= trusted_time_unix <= validity["expires_at_unix"]:
        raise PolicyAuthorityError("policy is stale, future, or expired")
    if checkpoint_digest(prior) != prior["checkpoint_digest"]:
        raise PolicyAuthorityError("prior checkpoint digest mismatch")
    if prior["checkpoint_digest"] != pinned_prior_checkpoint_digest:
        raise PolicyAuthorityError("prior checkpoint is not caller-pinned")
    if envelope["prior_checkpoint_digest"] != prior["checkpoint_digest"]:
        raise PolicyAuthorityError("signed envelope prior checkpoint mismatch")
    if authority["authority_epoch"] < prior["authority_epoch"] or (
        authority["authority_epoch"] == prior["authority_epoch"]
        and authority["revision"] <= prior["revision"]
    ):
        raise PolicyAuthorityError("policy rollback or replay rejected")
    if authority["authority_epoch"] > prior["authority_epoch"] and authority["revision"] != 1:
        raise PolicyAuthorityError("epoch rotation must restart revision")
    prior_revoked = prior["revoked_key_ids"]
    current_revoked = revocations["revoked_key_ids"]
    if prior_revoked != sorted(prior_revoked) or current_revoked != sorted(current_revoked):
        raise PolicyAuthorityError("revocation tombstones must be canonical")
    if prior["revocation_set_digest"] != revocation_set_digest(prior["revocation_version"], prior_revoked):
        raise PolicyAuthorityError("prior revocation set digest mismatch")
    if not set(prior_revoked).issubset(current_revoked):
        raise PolicyAuthorityError("revocation tombstone removal rejected")
    if revocations["version"] < prior["revocation_version"] or envelope["revocation_version"] != revocations["version"]:
        raise PolicyAuthorityError("revocation rollback or mismatch")
    if current_revoked != prior_revoked and revocations["version"] <= prior["revocation_version"]:
        raise PolicyAuthorityError("revocation changes require a newer version")
    current_revocation_digest = revocation_set_digest(revocations["version"], current_revoked)
    if envelope["revocation_digest"] != current_revocation_digest:
        raise PolicyAuthorityError("revocation set digest mismatch")
    keys = {item["key_id"]: item for item in root_keys}
    key = keys.get(authority["key_id"])
    if key is None or authority["authority_epoch"] not in key["authorized_epochs"]:
        raise PolicyAuthorityError("key rotation is not pinned")
    if authority["key_id"] in revocations["revoked_key_ids"]:
        raise PolicyAuthorityError("signing key is revoked")
    message = ENVELOPE_DOMAIN + canonical(envelope)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key_hex"])).verify(
            bytes.fromhex(document["signature_hex"]), message
        )
    except (ValueError, InvalidSignature):
        raise PolicyAuthorityError("Ed25519 signature verification failed") from None
    envelope_digest = sha256(message)
    next_basis = {
        "authority_epoch": authority["authority_epoch"], "revision": authority["revision"],
        "revocation_version": revocations["version"], "revocation_set_digest": current_revocation_digest,
        "revoked_key_ids": current_revoked, "policy_digest": policy["policy_digest"],
        "envelope_digest": envelope_digest,
    }
    next_checkpoint = {**next_basis, "checkpoint_digest": sha256(CHECKPOINT_DOMAIN + canonical(next_basis))}
    basis = {
        "schema": "tamandua.anti_cheat.game_policy_verification_report/v1",
        "evidence_class": "synthetic_offline_contract",
        "verification_state": "caller_parameterized_consistency",
        "authority_verified": False, "signature_verified": True,
        "pin_provenance": "caller_parameters_unauthenticated",
        "trusted_time_unix": trusted_time_unix, "scope": scope,
        "policy_id": policy["policy_id"], "policy_version": policy["policy_version"],
        "policy_digest": policy["policy_digest"], "key_id": authority["key_id"],
        "trust_root_digest": trust_root_digest,
        "signature_algorithm": "Ed25519", "envelope_digest": envelope_digest,
        "prior_checkpoint_digest": prior["checkpoint_digest"], "next_checkpoint": next_checkpoint,
        "claims": {"runtime_authorized": False, "enforcement_authorized": False, "external_latest_state_validated": False, "rollback_durability_validated": False, "production_ready": False, "external_claim_allowed": False},
    }
    report = {"report_digest": sha256(REPORT_DOMAIN + canonical(basis)), **basis}
    report_schema, _ = load_json(REPORT_SCHEMA)
    Draft202012Validator.check_schema(report_schema)
    if list(Draft202012Validator(report_schema).iter_errors(report)):
        raise PolicyAuthorityError("report schema validation failed")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--trusted-time-unix", type=int, default=1780000100)
    parser.add_argument("--pinned-trust-root-digest", default=PINNED_TRUST_ROOT_DIGEST)
    parser.add_argument("--pinned-prior-checkpoint-digest", default=PINNED_PRIOR_CHECKPOINT_DIGEST)
    parser.add_argument("--tenant-scope-digest", default=PINNED_SCOPE["tenant_scope_digest"])
    parser.add_argument("--game-id", default=PINNED_SCOPE["game_id"])
    parser.add_argument("--build-digest", default=PINNED_SCOPE["build_digest"])
    args = parser.parse_args(argv)
    try:
        document, _ = load_json(args.fixture)
        print(canonical(verify_authority(
            document, args.trusted_time_unix, args.pinned_trust_root_digest,
            args.pinned_prior_checkpoint_digest,
            {"tenant_scope_digest": args.tenant_scope_digest, "game_id": args.game_id, "build_digest": args.build_digest},
        )).decode())
    except (OSError, PolicyAuthorityError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
