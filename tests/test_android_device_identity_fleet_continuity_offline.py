import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/android_device_identity_fleet_continuity_offline.py"
SCHEMA = ROOT / "schemas/android_device_identity_fleet_continuity_report_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("fleet_continuity", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def observation(
    case_id,
    slot,
    tenant,
    epoch,
    event,
    key,
    expected,
    *,
    state="present",
    previous=None,
    authorization=None,
    attestation="present_unverified",
):
    return {
        "case_id": case_id,
        "sequence": 0,
        "fleet_slot_id": slot,
        "tenant_id": tenant,
        "installation_epoch": epoch,
        "event": event,
        "key_state": state,
        "key_token": key,
        "previous_key_token": previous,
        "authorization_id": authorization,
        "attestation_state": attestation,
        "expected_category": expected,
    }


def valid_document():
    values = [
        observation("case_baseline", "slot_alpha", "tenant_alpha", "install_alpha", "enroll", "key_alpha", "baseline_observed"),
        observation("case_restart", "slot_alpha", "tenant_alpha", "install_alpha", "restart", "key_alpha", "stable_match"),
        observation("case_update", "slot_alpha", "tenant_alpha", "install_alpha", "update", "key_alpha", "attestation_assurance_change_only", attestation="verified_tee"),
        observation("case_rotate", "slot_alpha", "tenant_alpha", "install_alpha", "authorized_rotate", "key_beta", "authorized_rotation", previous="key_alpha", authorization="auth_rotate"),
        observation("case_recover_previous", "slot_alpha", "tenant_alpha", "install_alpha", "recover_previous", "key_beta", "recovery_previous", previous="key_beta", authorization="auth_recover_previous"),
        observation("case_recover_replacement", "slot_alpha", "tenant_alpha", "install_alpha", "recover_replacement", "key_gamma", "recovery_replacement", previous="key_beta", authorization="auth_recover_replacement"),
        observation("case_reenroll", "slot_alpha", "tenant_alpha", "install_beta", "authorized_reenroll", "key_delta", "authorized_reenrollment", previous="key_gamma", authorization="auth_reenroll", attestation="verified_strongbox"),
        observation("case_missing", "slot_alpha", "tenant_alpha", "install_beta", "observe", None, "missing_key_hold", state="missing", attestation="unavailable"),
        observation("case_tenant_separation", "slot_alpha", "tenant_beta", "install_tenant_beta", "enroll", "key_tenant_beta", "tenant_separation"),
        observation("case_cross_slot_reuse", "slot_beta", "tenant_alpha", "install_slot_beta", "enroll", "key_alpha", "cross_slot_key_reuse_hold"),
        observation("case_unexpected_base", "slot_gamma", "tenant_alpha", "install_gamma", "enroll", "key_epsilon", "baseline_observed"),
        observation("case_unexpected_change", "slot_gamma", "tenant_alpha", "install_gamma", "observe", "key_zeta", "unexpected_key_change_hold"),
        observation("case_restore_change", "slot_gamma", "tenant_alpha", "install_restored", "restore", "key_eta", "clone_restore_suspected_hold"),
        observation("case_restore_base", "slot_delta", "tenant_alpha", "install_delta", "enroll", "key_theta", "baseline_observed"),
        observation("case_restore_missing", "slot_delta", "tenant_alpha", "install_delta", "restore", None, "clone_restore_suspected_hold", state="missing", attestation="unavailable"),
    ]
    for sequence, item in enumerate(values, start=1):
        item["sequence"] = sequence
    return {
        "schema": MODULE.INPUT_SCHEMA,
        "evidence_class": MODULE.EVIDENCE_CLASS,
        "profile": MODULE.PROFILE,
        "source_sha256": "a" * 64,
        "observations": values,
    }


def canonical(value):
    return MODULE.canonical_bytes(value)


def compile_valid():
    document = valid_document()
    return MODULE.compile_report(MODULE.parse_canonical(canonical(document)))


def test_full_adversarial_matrix_is_aggregate_only_and_schema_valid():
    report = compile_valid()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(report)

    assert report["outcome"] == "synthetic_contract_match"
    assert report["decision"] == "hold"
    assert report["aggregate_only"] is True
    assert report["metrics"]["observations"] == 15
    assert report["metrics"]["fleet_slots"] == 4
    counts = report["metrics"]["category_counts"]
    assert counts == {
        "baseline_observed": 3,
        "stable_match": 1,
        "tenant_separation": 1,
        "authorized_rotation": 1,
        "authorized_reenrollment": 1,
        "recovery_previous": 1,
        "recovery_replacement": 1,
        "attestation_assurance_change_only": 1,
        "missing_key_hold": 1,
        "unexpected_key_change_hold": 1,
        "cross_slot_key_reuse_hold": 1,
        "clone_restore_suspected_hold": 2,
    }
    encoded = json.dumps(report, sort_keys=True)
    assert not any(
        marker in encoded
        for marker in (
            "case_baseline",
            "slot_alpha",
            "tenant_alpha",
            "install_alpha",
            "key_alpha",
        )
    )
    assert "threshold" not in encoded.lower()
    assert "no_sla_or_vendor_parity_claim" in report["limitations"]
    assert all(value is False for value in report["claims"].values())


def test_metrics_are_exact_integer_ratios_without_thresholds():
    metrics = compile_valid()["metrics"]
    assert metrics["eligible_transitions"] == 10
    assert metrics["stable_continuity_ratio"] == {"numerator": 2, "denominator": 10}
    assert metrics["authorized_change_ratio"] == {"numerator": 4, "denominator": 10}
    assert metrics["hold_ratio"] == {"numerator": 5, "denominator": 15}
    assert not any(isinstance(value, float) for value in metrics.values())
    assert sum(metrics["category_counts"].values()) == metrics["observations"]
    for name in ("stable_continuity_ratio", "authorized_change_ratio", "hold_ratio"):
        assert metrics[name]["numerator"] <= metrics[name]["denominator"]


def test_schema_documents_validator_only_arithmetic_and_disallows_zero_denominators():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    metrics = schema["$defs"]["validReport"]["allOf"][1]["properties"]["metrics"]
    assert "Validator-enforced cross-field invariants" in metrics["$comment"]
    assert metrics["properties"]["eligible_transitions"]["minimum"] == 1
    assert schema["$defs"]["ratio"]["properties"]["denominator"]["minimum"] == 1


@pytest.mark.parametrize(
    "mutation,code",
    [
        (lambda value: value.update({"unknown": False}), "input_fields_invalid"),
        (lambda value: value["observations"][0].update({"unknown": False}), "observation_fields_invalid"),
        (lambda value: value["observations"][1].update(sequence=99), "observation_order_invalid"),
        (lambda value: value["observations"][1].update(case_id="case_baseline"), "duplicate_case_id"),
        (lambda value: value["observations"][1].update(expected_category="unexpected_key_change_hold"), "expected_category_mismatch"),
        (lambda value: value["observations"][3].update(authorization_id=None), "authorized_transition_binding_invalid"),
        (lambda value: value["observations"][6].update(installation_epoch="install_alpha"), "reenrollment_epoch_not_changed"),
        (lambda value: value["observations"][7].update(key_token="key_forbidden"), "missing_key_has_token"),
        (lambda value: value["observations"][7].update(authorization_id="auth_missing"), "unexpected_transition_authority"),
    ],
)
def test_semantic_tamper_and_unknown_fields_fail_closed(mutation, code):
    document = valid_document()
    mutation(document)
    with pytest.raises(MODULE.ContractError, match=code):
        MODULE.compile_report(document)


def test_exact_replay_is_rejected():
    document = valid_document()
    replay = copy.deepcopy(document["observations"][1])
    replay["case_id"] = "case_replay"
    replay["sequence"] = len(document["observations"]) + 1
    document["observations"].append(replay)
    with pytest.raises(MODULE.ContractError, match="observation_replay"):
        MODULE.compile_report(document)


def test_authorization_ids_are_single_use_across_the_batch():
    document = valid_document()
    document["observations"][4]["authorization_id"] = "auth_rotate"
    with pytest.raises(MODULE.ContractError, match="authorization_reuse"):
        MODULE.compile_report(document)


def test_batch_requires_at_least_one_transition_for_defined_ratios():
    document = valid_document()
    second = copy.deepcopy(document["observations"][0])
    second.update(
        case_id="case_second",
        sequence=2,
        fleet_slot_id="slot_second",
        key_token="key_second",
    )
    document["observations"] = [document["observations"][0], second]
    with pytest.raises(MODULE.ContractError, match="eligible_transition_count_invalid"):
        MODULE.compile_report(document)


def test_tenant_separation_requires_a_distinct_tenant_bound_key_token():
    document = valid_document()
    document["observations"][8]["key_token"] = "key_alpha"
    with pytest.raises(MODULE.ContractError, match="cross_tenant_key_reuse"):
        MODULE.compile_report(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("device_serial", "serial_value"),
        ("android_id", "global_value"),
        ("imei", "123456789012345"),
        ("email", "person@example.test"),
        ("ip_address", "192.0.2.1"),
        ("public_key_spki", "raw_material"),
        ("certificate_chain", ["raw_material"]),
        ("attestation_evidence", "raw_material"),
        ("proof", "raw_material"),
        ("secret", "raw_material"),
    ],
)
def test_sensitive_fields_are_rejected_recursively(field, value):
    document = valid_document()
    document["observations"][0]["nested"] = {"deeper": {field: value}}
    with pytest.raises(MODULE.ContractError, match="sensitive_field_rejected"):
        MODULE.compile_report(document)


@pytest.mark.parametrize(
    "value",
    [
        "tmnd-0123456789abcdef0123456789abcdef",
        f"tmdk_v1_{'A' * 43}",
        "person@example.test",
        "192.0.2.7",
        "123456789012345",
        "-----BEGIN CERTIFICATE-----",
        "AA:BB:CC:DD:EE:FF",
        "550e8400-e29b-41d4-a716-446655440000",
        "0123456789ABCDEF",
        "ＴＭＮＤ－\u200b0123456789abcdef",
    ],
)
def test_real_or_globally_correlatable_identifier_values_are_rejected(value):
    document = valid_document()
    document["observations"][0]["key_token"] = value
    with pytest.raises(MODULE.ContractError, match="sensitive_value_rejected"):
        MODULE.compile_report(document)


@pytest.mark.parametrize(
    "cleartext",
    [
        "tmnd-0123456789abcdef0123456789abcdef",
        f"tmdk_v1_{'A' * 43}",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
@pytest.mark.parametrize("encoding", ["percent", "hex", "base64", "base64url"])
def test_whole_value_encoded_sensitive_material_is_rejected(cleartext, encoding):
    if encoding == "percent":
        value = "".join(f"%{byte:02X}" for byte in cleartext.encode())
    elif encoding == "hex":
        value = cleartext.encode().hex()
    elif encoding == "base64":
        value = base64.b64encode(cleartext.encode()).decode()
    else:
        value = base64.urlsafe_b64encode(cleartext.encode()).decode().rstrip("=")
    with pytest.raises(MODULE.ContractError, match="sensitive_value_rejected"):
        MODULE._sensitive(value)


def test_benign_encoded_synthetic_value_is_not_a_privacy_false_positive():
    value = base64.b64encode(b"synthetic-fleet-observation").decode()
    MODULE._sensitive(value)


def test_duplicate_json_keys_and_noncanonical_bytes_are_rejected():
    with pytest.raises(MODULE.ContractError, match="duplicate_json_key"):
        MODULE.parse_canonical(b'{"schema":"a","schema":"b"}')
    with pytest.raises(MODULE.ContractError, match="input_not_canonical"):
        MODULE.parse_canonical(json.dumps(valid_document(), indent=2).encode())
    with pytest.raises(MODULE.ContractError, match="input_json_invalid"):
        MODULE.parse_canonical(b'{"value":NaN}')
    for non_finite in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(MODULE.ContractError, match="input_json_invalid"):
            MODULE.canonical_bytes({"value": non_finite})
    with pytest.raises(MODULE.ContractError, match="duplicate_json_key"):
        MODULE.parse_canonical(
            b'{"authorization_id":"auth_first","authorization_id":"auth_second"}'
        )


def test_recursive_depth_and_nfkc_sensitive_keys_fail_closed():
    document = valid_document()
    nested = {"payload": "synthetic"}
    for _ in range(10):
        nested = {"wrapper": nested}
    document["observations"][0]["metadata"] = nested
    with pytest.raises(MODULE.ContractError, match="input_depth_exceeded"):
        MODULE.compile_report(document)

    document = valid_document()
    document["observations"][0]["ＳＥＣＲＥＴ"] = "synthetic"
    with pytest.raises(MODULE.ContractError, match="sensitive_field_rejected"):
        MODULE.compile_report(document)


def test_observation_and_slot_bounds_are_enforced():
    document = valid_document()
    document["observations"] = document["observations"][:1]
    with pytest.raises(MODULE.ContractError, match="observation_count_invalid"):
        MODULE.compile_report(document)


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("case_id", "realcase", "case_id_invalid"),
        ("fleet_slot_id", "r58m1234abc", "fleet_slot_invalid"),
        ("tenant_id", "customeralpha", "tenant_id_invalid"),
        ("installation_epoch", "deviceinstall", "installation_epoch_invalid"),
        ("key_token", "hardwareidentity", "key_token_invalid"),
    ],
)
def test_only_explicit_synthetic_symbol_namespaces_are_accepted(field, value, code):
    document = valid_document()
    document["observations"][0][field] = value
    with pytest.raises(MODULE.ContractError, match=code):
        MODULE.compile_report(document)

    document = valid_document()
    template = document["observations"][0]
    document["observations"] = []
    for index in range(MODULE.MAX_SLOTS + 1):
        item = copy.deepcopy(template)
        item.update(
            case_id=f"case_{index:04d}",
            sequence=index + 1,
            fleet_slot_id=f"slot_{index:04d}",
            key_token=f"key_{index:04d}",
        )
        document["observations"].append(item)
    with pytest.raises(MODULE.ContractError, match="fleet_slot_count_invalid"):
        MODULE.compile_report(document)


def test_schema_error_enum_matches_every_validator_error_literal():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    emitted = set()
    argument_by_call = {"_fail": 0, "_exact": 2, "_symbol": 1, "_nullable_symbol": 1}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        index = argument_by_call.get(node.func.id)
        if index is None or len(node.args) <= index:
            continue
        argument = node.args[index]
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            emitted.add(argument.value)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    reasons = set(
        schema["$defs"]["errorReport"]["allOf"][1]["properties"]["reason"]["enum"]
    )
    assert reasons == emitted


def test_symlinked_path_components_are_rejected(tmp_path):
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    input_path = real_directory / "input.json"
    input_path.write_bytes(canonical(valid_document()))
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real_directory, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(MODULE.ContractError, match="input_path_unsafe"):
        MODULE.read_input((alias / "input.json").absolute())


def test_same_size_mutation_during_read_is_rejected(tmp_path, monkeypatch):
    input_path = (tmp_path / "large.json").resolve()
    input_path.write_bytes(b"a" * 70000)
    original_read = MODULE.os.read
    mutated = False

    def mutating_read(descriptor, count):
        nonlocal mutated
        chunk = original_read(descriptor, count)
        if chunk and not mutated:
            mutated = True
            before = input_path.stat()
            with input_path.open("r+b") as stream:
                stream.seek(-1, os.SEEK_END)
                stream.write(b"b")
                stream.flush()
                os.fsync(stream.fileno())
            os.utime(input_path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        return chunk

    monkeypatch.setattr(MODULE.os, "read", mutating_read)
    with pytest.raises(MODULE.ContractError, match="input_changed"):
        MODULE.read_input(input_path)


def test_rename_and_same_size_replacement_during_read_is_rejected(tmp_path, monkeypatch):
    input_path = (tmp_path / "large.json").resolve()
    moved_path = tmp_path / "moved.json"
    payload = b"a" * 70000
    input_path.write_bytes(payload)
    original_read = MODULE.os.read
    replaced = False

    def replacing_read(descriptor, count):
        nonlocal replaced
        chunk = original_read(descriptor, count)
        if chunk and not replaced:
            replaced = True
            try:
                input_path.rename(moved_path)
                input_path.write_bytes(b"b" * len(payload))
            except OSError:
                pytest.skip("open-file rename is unavailable")
        return chunk

    monkeypatch.setattr(MODULE.os, "read", replacing_read)
    with pytest.raises(MODULE.ContractError, match="input_changed"):
        MODULE.read_input(input_path)


def test_ancestor_identity_change_during_read_is_rejected(tmp_path, monkeypatch):
    input_path = (tmp_path / "input.json").resolve()
    input_path.write_bytes(canonical(valid_document()))
    original_assert = MODULE._assert_direct_path
    calls = 0

    def changed_ancestor(path):
        nonlocal calls
        identities = original_assert(path)
        calls += 1
        if calls == 2:
            changed = list(identities)
            device, inode, mode, attributes = changed[1]
            changed[1] = (device, inode + 1, mode, attributes)
            return tuple(changed)
        return identities

    monkeypatch.setattr(MODULE, "_assert_direct_path", changed_ancestor)
    with pytest.raises(MODULE.ContractError, match="input_changed"):
        MODULE.read_input(input_path)


def test_cli_emits_one_canonical_aggregate_line_and_categorical_error(tmp_path):
    input_path = (tmp_path / "input.json").resolve()
    input_path.write_bytes(canonical(valid_document()))
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(input_path)],
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout.count(b"\n") == 1
    report = json.loads(result.stdout)
    assert result.stdout == canonical(report) + b"\n"
    assert "observations" not in report

    input_path.write_text(json.dumps(valid_document(), indent=2), encoding="utf-8")
    rejected = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(input_path)],
        check=False,
        capture_output=True,
    )
    assert rejected.returncode == 2
    error = json.loads(rejected.stdout)
    assert error["reason"] == "input_not_canonical"
    assert error["decision"] == "hold"
    assert all(value is False for value in error["claims"].values())
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(error)

    missing = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(tmp_path / "missing.json")],
        check=False,
        capture_output=True,
    )
    assert missing.returncode == 2
    assert json.loads(missing.stdout)["reason"] == "input_path_unsafe"

    bad_args = subprocess.run(
        [sys.executable, str(SCRIPT), "--unknown"],
        check=False,
        capture_output=True,
    )
    assert bad_args.returncode == 2
    assert bad_args.stderr == b""
    assert json.loads(bad_args.stdout)["reason"] == "arguments_invalid"


def test_cli_sensitive_error_is_one_line_and_does_not_echo_input_or_path(tmp_path):
    document = valid_document()
    marker = "ＴＭＮＤ－\u200b0123456789abcdef"
    document["observations"][0]["key_token"] = marker
    input_path = (tmp_path / "sensitive-input.json").resolve()
    raw = canonical(document)
    input_path.write_bytes(raw)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(input_path)],
        check=False,
        capture_output=True,
    )
    assert result.returncode == 2
    assert result.stderr == b""
    assert result.stdout.count(b"\n") == 1
    assert marker.encode("utf-8") not in result.stdout
    assert str(input_path).encode() not in result.stdout
    report = json.loads(result.stdout)
    assert report["reason"] == "sensitive_value_rejected"
    assert report["input_sha256"] == hashlib.sha256(raw).hexdigest()


def test_privacy_normalization_does_not_rewrite_accepted_input_or_report_digest():
    document = valid_document()
    raw = canonical(document)
    parsed = MODULE.parse_canonical(raw)
    assert canonical(parsed) == raw
    assert MODULE.compile_report(parsed)["input_sha256"] == hashlib.sha256(raw).hexdigest()


def test_source_has_no_execution_network_or_identifier_collection_surface():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in (
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "adb",
        "device_serial",
        "ANDROID_ID",
        "getprop",
        "SecureStore",
    ):
        assert forbidden not in source
    assert "install_scoped_handle_not_hardware_guid" in source
    assert "tenant_scoped_key_continuity_not_physical_guid" in source
