import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_game_policy_authority_gate.py"
FIXTURE = ROOT / "tools/detection_validation/fixtures/anti_cheat_game_policy_authority_synthetic_v1.json"
AUTHORITY_SCHEMA = ROOT / "schemas/anti_cheat_game_policy_authority_v1.schema.json"
REPORT_SCHEMA = ROOT / "schemas/anti_cheat_game_policy_verification_report_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("game_policy_authority_gate", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


def fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def resign(value):
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    value["signed_envelope"]["revocation_digest"] = gate.sha256(
        gate.REVOCATION_DOMAIN + gate.canonical(value["revocations"])
    )
    value["signature_hex"] = key.sign(
        gate.ENVELOPE_DOMAIN + gate.canonical(value["signed_envelope"])
    ).hex()
    return value


def recheckpoint(value):
    prior = value["prior_checkpoint"]
    prior["revocation_set_digest"] = gate.revocation_set_digest(
        prior["revocation_version"], prior["revoked_key_ids"]
    )
    prior["checkpoint_digest"] = gate.checkpoint_digest(prior)
    value["signed_envelope"]["prior_checkpoint_digest"] = prior["checkpoint_digest"]
    return resign(value)


def verify(value=None, trusted_time=1780000100):
    return gate.verify_authority(fixture() if value is None else value, trusted_time)


def rejected(value, message, trusted_time=1780000100):
    with pytest.raises(gate.PolicyAuthorityError, match=message):
        verify(value, trusted_time)


def test_fixture_and_report_validate_and_bind_game_003a():
    value = fixture()
    Draft202012Validator(json.loads(AUTHORITY_SCHEMA.read_text())).validate(value)
    report = verify(value)
    Draft202012Validator(json.loads(REPORT_SCHEMA.read_text())).validate(report)
    assert report["verification_state"] == "caller_parameterized_consistency"
    assert report["authority_verified"] is False
    assert report["signature_verified"] is True
    assert report["pin_provenance"] == "caller_parameters_unauthenticated"
    assert report["policy_digest"] == value["game_003a_policy_digest"]
    assert report["next_checkpoint"]["revision"] == 8
    assert all(claim is False for claim in report["claims"].values())


def test_cli_is_deterministic_and_caller_time_bound():
    argv = [sys.executable, str(SCRIPT), "--trusted-time-unix", "1780000100"]
    first = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
    second = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
    assert first == second
    assert json.loads(first)["trusted_time_unix"] == 1780000100


@pytest.mark.parametrize("field", ["tenant_scope_digest", "game_id", "build_digest"])
def test_cross_scope_envelope_rejected_even_with_valid_signature(field):
    value = fixture()
    value["signed_envelope"]["scope"][field] = "other.game" if field == "game_id" else "f" * 64
    resign(value)
    rejected(value, "scope is not caller-pinned")


def test_self_consistent_document_scope_change_is_not_caller_pinned():
    value = fixture()
    value["signed_envelope"]["scope"]["game_id"] = "other.game"
    value["expected_scope"]["game_id"] = "other.game"
    resign(value)
    rejected(value, "scope is not caller-pinned")


def test_wrong_signature_and_cross_key_rejected():
    value = fixture()
    value["signature_hex"] = "00" * 64
    rejected(value, "signature verification failed")
    value = fixture()
    value["signed_envelope"]["authority"]["key_id"] = "unknown.key"
    resign(value)
    rejected(value, "key rotation is not pinned")


def test_attacker_supplied_self_consistent_trust_root_is_rejected():
    value = fixture()
    attacker = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    value["trust_root"]["keys"][0]["public_key_hex"] = attacker.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()
    value["signature_hex"] = attacker.sign(
        gate.ENVELOPE_DOMAIN + gate.canonical(value["signed_envelope"])
    ).hex()
    rejected(value, "trust root is not caller-pinned")


@pytest.mark.parametrize("trusted", [1779999999, 1780003601])
def test_future_and_expired_policy_rejected(trusted):
    rejected(fixture(), "stale, future, or expired", trusted)


def test_stale_issued_order_rejected():
    value = fixture()
    value["signed_envelope"]["validity"]["issued_at_unix"] = 1780000101
    resign(value)
    rejected(value, "stale, future, or expired")


@pytest.mark.parametrize("revision", [7, 6])
def test_replay_equal_and_rollback_revision_rejected(revision):
    value = fixture()
    value["signed_envelope"]["authority"]["revision"] = revision
    resign(value)
    rejected(value, "rollback or replay")


def test_equal_revision_different_policy_rejected_before_signature_matters():
    value = fixture()
    value["signed_envelope"]["authority"]["revision"] = 7
    value["signed_envelope"]["policy"]["policy_digest"] = "f" * 64
    resign(value)
    rejected(value, "GAME-003A policy digest mismatch")


def test_revocation_version_rollback_and_revoked_key_rejected():
    value = fixture()
    value["revocations"]["version"] = 1
    value["signed_envelope"]["revocation_version"] = 1
    resign(value)
    rejected(value, "revocation rollback")
    value = fixture()
    value["revocations"]["version"] = 3
    value["signed_envelope"]["revocation_version"] = 3
    value["revocations"]["revoked_key_ids"] = ["sample.root.key1"]
    resign(value)
    rejected(value, "signing key is revoked")


def test_signed_envelope_must_bind_exact_validated_prior_checkpoint():
    value = fixture()
    value["signed_envelope"]["prior_checkpoint_digest"] = "f" * 64
    resign(value)
    rejected(value, "signed envelope prior checkpoint mismatch")


def test_revocation_tombstones_cannot_be_removed():
    value = fixture()
    value["revocations"]["version"] = 3
    value["signed_envelope"]["revocation_version"] = 3
    prior = value["prior_checkpoint"]
    prior["revoked_key_ids"] = ["retired.key"]
    recheckpoint(value)
    with pytest.raises(gate.PolicyAuthorityError, match="tombstone removal"):
        gate.verify_authority(
            value, 1780000100,
            pinned_prior_checkpoint_digest=prior["checkpoint_digest"],
        )


def test_revocation_change_requires_newer_version_and_is_checkpointed():
    value = fixture()
    value["revocations"]["revoked_key_ids"] = ["retired.key"]
    resign(value)
    rejected(value, "changes require a newer version")

    value["revocations"]["version"] = 3
    value["signed_envelope"]["revocation_version"] = 3
    resign(value)
    report = verify(value)
    assert report["next_checkpoint"]["revoked_key_ids"] == ["retired.key"]
    assert report["next_checkpoint"]["revocation_set_digest"] == gate.revocation_set_digest(
        3, ["retired.key"]
    )


def test_prior_revocation_digest_and_canonical_tombstones_are_enforced():
    value = fixture()
    value["prior_checkpoint"]["revocation_set_digest"] = "f" * 64
    value["prior_checkpoint"]["checkpoint_digest"] = gate.checkpoint_digest(value["prior_checkpoint"])
    value["signed_envelope"]["prior_checkpoint_digest"] = value["prior_checkpoint"]["checkpoint_digest"]
    resign(value)
    with pytest.raises(gate.PolicyAuthorityError, match="prior revocation set digest mismatch"):
        gate.verify_authority(
            value, 1780000100,
            pinned_prior_checkpoint_digest=value["prior_checkpoint"]["checkpoint_digest"],
        )

    value = fixture()
    value["revocations"].update({"version": 3, "revoked_key_ids": ["z.key", "a.key"]})
    value["signed_envelope"]["revocation_version"] = 3
    resign(value)
    rejected(value, "tombstones must be canonical")


def test_duplicate_trust_root_members_are_rejected_deterministically():
    value = fixture()
    value["trust_root"]["keys"].append(copy.deepcopy(value["trust_root"]["keys"][0]))
    rejected(value, "duplicate trust-root key_id rejected")

    value = fixture()
    duplicate = copy.deepcopy(value["trust_root"]["keys"][0])
    duplicate["key_id"] = "sample.root.key2"
    value["trust_root"]["keys"].append(duplicate)
    rejected(value, "duplicate trust-root public key rejected")


def test_duplicate_json_root_member_is_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
    with pytest.raises(gate.PolicyAuthorityError, match="duplicate JSON member rejected"):
        gate.load_json(path)


def test_substituted_caller_pins_never_become_authority_proof():
    value = fixture()
    attacker = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    value["trust_root"]["keys"][0]["public_key_hex"] = attacker.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()
    value["expected_scope"]["game_id"] = "substituted.game"
    value["signed_envelope"]["scope"]["game_id"] = "substituted.game"
    value["prior_checkpoint"]["revision"] = 6
    recheckpoint(value)
    value["signature_hex"] = attacker.sign(
        gate.ENVELOPE_DOMAIN + gate.canonical(value["signed_envelope"])
    ).hex()
    report = gate.verify_authority(
        value,
        1780000100,
        pinned_trust_root_digest=gate.sha256(
            gate.TRUST_ROOT_DOMAIN + gate.canonical(value["trust_root"])
        ),
        pinned_prior_checkpoint_digest=value["prior_checkpoint"]["checkpoint_digest"],
        pinned_scope=value["expected_scope"],
    )
    assert report["verification_state"] == "caller_parameterized_consistency"
    assert report["authority_verified"] is False
    assert report["signature_verified"] is True


def test_prior_checkpoint_is_recomputed():
    value = fixture()
    value["prior_checkpoint"]["revision"] = 6
    rejected(value, "prior checkpoint digest mismatch")


def test_self_consistent_older_prior_checkpoint_is_not_caller_pinned():
    value = fixture()
    value["prior_checkpoint"]["revision"] = 6
    value["prior_checkpoint"]["checkpoint_digest"] = gate.checkpoint_digest(
        value["prior_checkpoint"]
    )
    value["signed_envelope"]["prior_checkpoint_digest"] = value["prior_checkpoint"]["checkpoint_digest"]
    resign(value)
    rejected(value, "prior checkpoint is not caller-pinned")


def test_unpinned_epoch_rotation_rejected():
    value = fixture()
    value["signed_envelope"]["authority"].update({"authority_epoch": 2, "revision": 1})
    resign(value)
    rejected(value, "key rotation is not pinned")


def test_unknown_algorithm_and_members_fail_schema():
    value = fixture()
    value["trust_root"]["algorithm"] = "ECDSA"
    rejected(value, "schema validation failed")
    value = fixture()
    value["signed_envelope"]["unknown"] = True
    rejected(value, "schema validation failed")


@pytest.mark.parametrize("key", ["clientSecret", "awsSecretAccessKey", "authorizationToken", "sessionToken", "privateCredential"])
def test_camel_case_secret_and_private_members_rejected_before_schema(key):
    value = fixture()
    value[key] = "hunter2"
    rejected(value, "secret/private member rejected")


def test_secret_shaped_string_rejected():
    value = fixture()
    value["trust_root"]["root_id"] = "Bearer abcdef123456"
    rejected(value, "secret-shaped value rejected")


def test_policy_mapping_and_identity_are_exact():
    value = fixture()
    value["signed_envelope"]["mapping"]["features"] = ["other_feature"]
    resign(value)
    rejected(value, "mapping mismatch")
    value = fixture()
    value["signed_envelope"]["policy"]["policy_version"] = "2"
    resign(value)
    rejected(value, "identity/version mismatch")


def test_next_checkpoint_and_report_digests_are_recomputable():
    report = verify()
    assert gate.checkpoint_digest(report["next_checkpoint"]) == report["next_checkpoint"]["checkpoint_digest"]
    basis = {key: value for key, value in report.items() if key != "report_digest"}
    assert report["report_digest"] == gate.sha256(gate.REPORT_DOMAIN + gate.canonical(basis))


def test_product_sources_and_fixture_contain_no_private_key_or_runtime_path():
    source = SCRIPT.read_text(encoding="utf-8")
    vector = FIXTURE.read_text(encoding="utf-8")
    for forbidden in ["private_key_hex", "private_key_pem", "BEGIN PRIVATE KEY", "requests", "socket", "boto", "enforcement_authorized\": true"]:
        assert forbidden not in source
        assert forbidden not in vector


def test_exact_scopes_are_utf8_without_trailing_whitespace():
    for path in (AUTHORITY_SCHEMA, REPORT_SCHEMA, FIXTURE, SCRIPT, Path(__file__)):
        raw = path.read_bytes()
        assert raw and b"\0" not in raw
        text = raw.decode("utf-8")
        assert all(line == line.rstrip(" \t") for line in text.splitlines())
