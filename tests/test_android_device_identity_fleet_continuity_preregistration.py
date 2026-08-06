from __future__ import annotations

import ast
import base64
import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import jsonschema

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/android_device_identity_fleet_continuity_preregistration.py"
SCHEMA = ROOT / "schemas/android_device_identity_fleet_continuity_preregistration_v1.schema.json"
spec = importlib.util.spec_from_file_location("prereg", SCRIPT)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)


def h(number: int) -> str:
    return f"{number:064x}"


def documents(root: bool = False):
    categories_events = [
        ("baseline_observed", "enroll"), ("stable_match", "restart"),
        ("stable_match", "update"), ("tenant_separation", "enroll"),
        ("authorized_rotation", "authorized_rotate"),
        ("authorized_reenrollment", "authorized_reenroll"),
        ("recovery_previous", "recover_previous"),
        ("recovery_replacement", "recover_replacement"),
        ("attestation_assurance_change_only", "observe"),
        ("missing_key_hold", "observe"), ("unexpected_key_change_hold", "observe"),
        ("cross_slot_key_reuse_hold", "observe"),
        ("clone_restore_suspected_hold", "restore"),
    ]
    cells = [{"case_id": f"case_{i:02d}", "sequence": i, "slot": f"slot_{(i - 1) % 3}", "tenant": f"tenant_{(i - 1) % 2}", "event": event, "expected_category": category} for i, (category, event) in enumerate(categories_events, 1)]
    roles = {role: h(20 + i) for i, role in enumerate(gate.ROLES)}
    privacy = {"scheme": "hmac-sha256-tmdk_v1-receipt-context-v1", "pseudonym_context_sha256": h(6), "key_authority_sha256": h(7), "key_material_included": False}
    authority = {"operator_packet_sha256": h(8), "bridge_provenance_sha256": h(9), "coordinator_snapshot_sha256": h(10), "coordinator_fencing_token": 4, "expected_previous_fence": 3, "previous_event_sha256": h(11), "operational_root_sha256": h(12) if root else None}
    doc = {"schema": gate.INPUT_SCHEMA, "evidence_class": gate.EVIDENCE_CLASS, "profile": gate.PROFILE, "source_sha256": h(1), "workspace_sha256": h(2), "head_sha256": h(3), "experiment_sha256": h(4), "matrix_sha256": gate.digest(cells, "tamandua-fleet-preregistration-matrix-v1"), "privacy": privacy, "authority": authority, "roles": roles, "slots": ["slot_0", "slot_1", "slot_2"], "tenants": ["tenant_0", "tenant_1"], "cells": cells, "controls": {field: False for field in gate.CONTROL_FIELDS}, "claims": {field: False for field in gate.CLAIM_FIELDS}}
    pins = {"schema": gate.PINS_SCHEMA, **{field: copy.deepcopy(doc[field]) for field in ("source_sha256", "workspace_sha256", "head_sha256", "experiment_sha256", "matrix_sha256", "privacy", "authority", "roles")}}
    return doc, pins


def write(path: Path, value) -> None:
    path.write_bytes(gate.canonical(value))


def run(tmp_path: Path, doc=None, pins=None):
    base_doc, base_pins = documents()
    doc = base_doc if doc is None else doc; pins = base_pins if pins is None else pins
    doc_path = tmp_path / "prereg.json"; pins_path = tmp_path / "pins.json"
    write(doc_path, doc); write(pins_path, pins)
    return subprocess.run([sys.executable, str(SCRIPT), "validate", "--preregistration", str(doc_path.resolve()), "--pins", str(pins_path.resolve())], text=True, capture_output=True, check=False)


def test_valid_unpinned_and_pinned_are_still_hold(tmp_path):
    result = run(tmp_path); report = json.loads(result.stdout)
    assert result.returncode == 0 and report["hold_reason"] == "operational_root_unpinned"
    assert report["metrics"] == {"slot_count": 3, "tenant_count": 2, "cell_count": 13, "required_category_count": 12, "required_event_count": 9}
    assert report["execution_authorized"] is False and "slot_0" not in result.stdout
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8-sig"))).validate(report)
    assert report["preregistration_sha256"] != report["pins_sha256"]
    doc, pins = documents(root=True); result = run(tmp_path, doc, pins)
    assert json.loads(result.stdout)["hold_reason"] == "separate_operator_authorization_required"


def test_matrix_digest_and_domain_separated_input_digests_are_exact(tmp_path):
    doc, pins = documents()
    result = run(tmp_path, doc, pins)
    report = json.loads(result.stdout)
    assert report["matrix_sha256"] == gate.digest(
        doc["cells"], "tamandua-fleet-preregistration-matrix-v1"
    )
    assert report["preregistration_sha256"] == gate.digest(
        gate.canonical(doc), "tamandua-fleet-preregistration-input-v1"
    )
    assert report["pins_sha256"] == gate.digest(
        gate.canonical(pins), "tamandua-fleet-preregistration-pins-v1"
    )


@pytest.mark.parametrize("mutation,reason", [
    (lambda d, p: p.__setitem__("source_sha256", h(60)), "pins_mismatch"),
    (lambda d, p: (d["roles"].__setitem__(gate.ROLES[0], p["roles"][gate.ROLES[1]]), d["roles"].__setitem__(gate.ROLES[1], p["roles"][gate.ROLES[0]])), "pins_mismatch"),
    (lambda d, p: (d["roles"].__setitem__(gate.ROLES[0], d["roles"][gate.ROLES[1]]), p["roles"].__setitem__(gate.ROLES[0], p["roles"][gate.ROLES[1]])), "digest_reuse"),
    (lambda d, p: (d["authority"].__setitem__("coordinator_fencing_token", 3), p["authority"].__setitem__("coordinator_fencing_token", 3)), "coordinator_fence_invalid"),
    (lambda d, p: d["slots"].pop(), "slot_set_invalid"),
    (lambda d, p: d["cells"].__setitem__(1, {**d["cells"][1], "sequence": 9}), "matrix_order_invalid"),
    (lambda d, p: d["cells"].__setitem__(0, {**d["cells"][0], "expected_category": "stable_match", "event": "restart"}), "matrix_coverage_invalid"),
    (lambda d, p: d["slots"].append("slot_unused"), "matrix_coverage_invalid"),
    (lambda d, p: d["tenants"].append("tenant_unused"), "matrix_coverage_invalid"),
    (lambda d, p: d["cells"][0].__setitem__("case_id", "case_changed"), "matrix_digest_mismatch"),
    (lambda d, p: d["controls"].__setitem__("collector_enabled", True), "execution_control_enabled"),
    (lambda d, p: d["claims"].__setitem__("product_ready", True), "claim_enabled"),
])
def test_adversarial_mutations(tmp_path, mutation, reason):
    doc, pins = documents(); mutation(doc, pins)
    if reason not in {"pins_mismatch", "digest_reuse", "coordinator_fence_invalid"}:
        doc["matrix_sha256"] = gate.digest(doc["cells"], "tamandua-fleet-preregistration-matrix-v1") if reason.startswith("matrix_") and reason != "matrix_digest_mismatch" else doc["matrix_sha256"]
        pins.update({field: copy.deepcopy(doc[field]) for field in ("matrix_sha256",)})
    result = run(tmp_path, doc, pins)
    assert result.returncode == 1 and json.loads(result.stdout)["reason"] == reason


@pytest.mark.parametrize("encoded", [
    "tmnd-secret", "746d646b5f76315f736563726574",
    "tmnd%2dsecret", base64.b64encode(b"tmdk_v1_secret").decode(),
    base64.b64encode(base64.b64encode(b"tmnd-secret")).decode(),
    "ＴＭＮＤ－\u200bsecret", "123e4567-e89b-02d3-0456-426614174000",
    "01:23:45:67:89:ab", "0123456789abcdef", "123456789012345",
    ":".join(["ab"] * 32),
])
def test_sensitive_values_including_encoded_are_rejected(tmp_path, encoded):
    doc, pins = documents(); doc["cells"][0]["case_id"] = encoded
    result = run(tmp_path, doc, pins)
    assert result.returncode == 1 and json.loads(result.stdout)["reason"] == "sensitive_value_rejected"


def test_noncanonical_duplicate_nan_depth_size_and_symlink(tmp_path):
    doc, pins = documents(); doc_path = tmp_path / "prereg.json"; pins_path = tmp_path / "pins.json"; write(pins_path, pins)
    cases = [b'{"x":1, "y":2}', b'{"x":1,"x":2}', b'{"x":NaN}']
    for raw in cases:
        doc_path.write_bytes(raw)
        result = subprocess.run([sys.executable, str(SCRIPT), "validate", "--preregistration", str(doc_path.resolve()), "--pins", str(pins_path.resolve())], text=True, capture_output=True)
        assert result.returncode != 0 and len(result.stdout.splitlines()) == 1
    with pytest.raises(gate.GateError, match="input_json_invalid"):
        gate.canonical({"nonfinite": float("nan")})
    nested = doc
    for _ in range(11): nested = {"safe": nested}
    write(doc_path, nested); assert json.loads(run(tmp_path, nested, pins).stdout)["reason"] == "input_depth_exceeded"
    doc_path.write_bytes(b"x" * (gate.MAX_BYTES + 1)); assert gate.main(["validate", "--preregistration", str(doc_path.resolve()), "--pins", str(pins_path.resolve())]) == 1
    if hasattr(os, "symlink"):
        target = tmp_path / "target.json"; write(target, doc); link = tmp_path / "link.json"
        try: os.symlink(target, link)
        except OSError: pytest.skip("symlinks unavailable")
        with pytest.raises(gate.GateError, match="input_path_unsafe"): gate.read_canonical(link)


def test_nested_nfkc_sensitive_key_is_rejected_before_shape_validation():
    with pytest.raises(gate.GateError, match="sensitive_field_rejected"):
        gate.sensitive({"safe": [{"ＳＥＣＲＥＴ\u200b": "synthetic"}]})


@pytest.mark.parametrize(
    "target,raw,reason",
    [
        ("preregistration", b'{"x":1, "y":2}', "input_not_canonical"),
        ("pins", b'{"x":1, "y":2}', "input_not_canonical"),
        ("preregistration", b'{"x":1,"x":2}', "duplicate_json_key"),
        ("pins", b'{"x":NaN}', "input_json_invalid"),
        ("preregistration", b"", "input_size_invalid"),
        ("pins", b"x" * (gate.MAX_BYTES + 1), "input_size_invalid"),
    ],
    ids=[
        "prereg-noncanonical",
        "pins-noncanonical",
        "prereg-duplicate-key",
        "pins-nonfinite",
        "prereg-empty",
        "pins-oversize",
    ],
)
def test_each_input_independently_enforces_canonical_and_size_contract(
    tmp_path, target, raw, reason
):
    doc, pins = documents()
    doc_path = (tmp_path / "doc.json").resolve(); pins_path = (tmp_path / "pins.json").resolve()
    write(doc_path, doc); write(pins_path, pins)
    (doc_path if target == "preregistration" else pins_path).write_bytes(raw)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "validate", "--preregistration", str(doc_path), "--pins", str(pins_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert json.loads(result.stdout)["reason"] == reason


def test_both_handles_are_open_before_either_input_is_read(monkeypatch, tmp_path):
    doc, pins = documents()
    doc_path = (tmp_path / "doc.json").resolve(); pins_path = (tmp_path / "pins.json").resolve()
    write(doc_path, doc); write(pins_path, pins)
    original_open = gate.os.open; original_read = gate.os.read; opened = []

    def tracked_open(path, flags):
        descriptor = original_open(path, flags); opened.append(descriptor); return descriptor

    def tracked_read(descriptor, count):
        assert len(opened) == 2
        return original_read(descriptor, count)

    monkeypatch.setattr(gate.os, "open", tracked_open)
    monkeypatch.setattr(gate.os, "read", tracked_read)
    gate.read_canonical_pair(doc_path, pins_path)


def test_same_path_and_hardlink_inputs_are_not_independent(tmp_path):
    doc, pins = documents()
    doc_path = (tmp_path / "doc.json").resolve(); pins_path = (tmp_path / "pins.json").resolve()
    write(doc_path, doc)
    with pytest.raises(gate.GateError, match="inputs_not_independent"):
        gate.read_canonical_pair(doc_path, doc_path)
    try:
        os.link(doc_path, pins_path)
    except OSError:
        pytest.skip("hardlinks unavailable")
    with pytest.raises(gate.GateError, match="inputs_not_independent"):
        gate.read_canonical_pair(doc_path, pins_path)


def test_distinct_files_with_identical_bytes_are_not_independent(tmp_path):
    doc, _ = documents()
    doc_path = (tmp_path / "doc.json").resolve(); pins_path = (tmp_path / "pins.json").resolve()
    write(doc_path, doc); write(pins_path, doc)
    with pytest.raises(gate.GateError, match="inputs_not_independent"):
        gate.read_canonical_pair(doc_path, pins_path)


def test_same_size_mutation_after_first_read_is_rejected(monkeypatch, tmp_path):
    doc, pins = documents()
    doc_path = (tmp_path / "doc.json").resolve(); pins_path = (tmp_path / "pins.json").resolve()
    write(doc_path, doc); write(pins_path, pins)
    original_read = gate.os.read; mutated = False

    def mutating_read(descriptor, count):
        nonlocal mutated
        chunk = original_read(descriptor, count)
        if chunk and not mutated:
            mutated = True
            before = doc_path.stat()
            with doc_path.open("r+b") as stream:
                stream.seek(-1, os.SEEK_END); current = stream.read(1)
                stream.seek(-1, os.SEEK_END); stream.write(b"x" if current != b"x" else b"y")
                stream.flush(); os.fsync(stream.fileno())
            os.utime(doc_path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        return chunk

    monkeypatch.setattr(gate.os, "read", mutating_read)
    with pytest.raises(gate.GateError, match="input_changed"):
        gate.read_canonical_pair(doc_path, pins_path)


def test_cross_input_path_swap_is_rejected_when_host_supports_rename(monkeypatch, tmp_path):
    doc, pins = documents()
    doc_path = (tmp_path / "doc.json").resolve(); pins_path = (tmp_path / "pins.json").resolve()
    spare_path = tmp_path / "spare.json"
    write(doc_path, doc); write(pins_path, pins)
    original_read = gate.os.read; swapped = False

    def swapping_read(descriptor, count):
        nonlocal swapped
        chunk = original_read(descriptor, count)
        if chunk and not swapped:
            swapped = True
            try:
                doc_path.rename(spare_path); pins_path.rename(doc_path); spare_path.rename(pins_path)
            except OSError:
                pytest.skip("open-file rename is unavailable")
        return chunk

    monkeypatch.setattr(gate.os, "read", swapping_read)
    with pytest.raises(gate.GateError, match="input_changed"):
        gate.read_canonical_pair(doc_path, pins_path)


def test_symlinked_ancestor_is_rejected(tmp_path):
    doc, _ = documents(); real = tmp_path / "real"; real.mkdir()
    doc_path = real / "doc.json"; write(doc_path, doc)
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(gate.GateError, match="input_path_unsafe"):
        gate.read_canonical((alias / "doc.json").absolute())


def test_cli_is_one_canonical_line(tmp_path):
    result = run(tmp_path)
    assert result.stderr == "" and len(result.stdout.splitlines()) == 1
    assert gate.canonical(json.loads(result.stdout)).decode() == result.stdout.rstrip("\n")


def test_cli_argument_and_privacy_errors_are_categorical_one_line_without_echo(tmp_path):
    label = "tmnd-private-label"
    invalid_args = subprocess.run(
        [sys.executable, str(SCRIPT), "--unknown", label],
        text=True,
        capture_output=True,
        check=False,
    )
    assert invalid_args.returncode == 2 and invalid_args.stderr == ""
    assert len(invalid_args.stdout.splitlines()) == 1 and label not in invalid_args.stdout
    assert json.loads(invalid_args.stdout)["reason"] == "arguments_invalid"

    doc, pins = documents(); doc["cells"][0]["case_id"] = label
    private_path = (tmp_path / "private-path-label.json").resolve()
    pins_path = (tmp_path / "private-pins-label.json").resolve()
    write(private_path, doc); write(pins_path, pins)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "validate", "--preregistration", str(private_path), "--pins", str(pins_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert label not in result.stdout and str(private_path) not in result.stdout
    error = json.loads(result.stdout)
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8-sig"))).validate(error)


@pytest.mark.parametrize("value", ["4", True, 0, gate.MAX_FENCE + 1])
def test_public_fencing_token_is_exact_integer_and_bounded(tmp_path, value):
    doc, pins = documents()
    doc["authority"]["coordinator_fencing_token"] = value
    pins["authority"]["coordinator_fencing_token"] = value
    result = run(tmp_path, doc, pins)
    assert result.returncode == 1
    assert json.loads(result.stdout)["reason"] == "coordinator_fence_invalid"


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_previous_fence", True),
        ("expected_previous_fence", -1),
        ("expected_previous_fence", gate.MAX_FENCE),
        ("coordinator_fencing_token", 3),
    ],
)
def test_fence_types_bounds_and_strict_order_are_closed(tmp_path, field, value):
    doc, pins = documents()
    doc["authority"][field] = value; pins["authority"][field] = value
    result = run(tmp_path, doc, pins)
    assert result.returncode == 1
    assert json.loads(result.stdout)["reason"] == "coordinator_fence_invalid"


def test_schema_reason_enum_matches_validator_literals():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    emitted = set()
    argument_indexes = {"fail": 0, "exact": 2, "sha": 1}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        index = argument_indexes.get(node.func.id)
        if index is None or len(node.args) <= index:
            continue
        argument = node.args[index]
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            emitted.add(argument.value)
    emitted.update(
        f"{field}_invalid"
        for field in (
            "source_sha256",
            "workspace_sha256",
            "head_sha256",
            "experiment_sha256",
            "matrix_sha256",
        )
    )
    schema = json.loads(SCHEMA.read_text(encoding="utf-8-sig"))
    reasons = set(schema["$defs"]["error"]["allOf"][1]["properties"]["reason"]["enum"])
    assert reasons == emitted


def test_similar_fencing_token_key_is_not_privacy_exempt():
    with pytest.raises(gate.GateError, match="sensitive_field_rejected"):
        gate.sensitive({"unsafe_coordinator_fencing_token_copy": "safe"})
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'key != "coordinator_fencing_token"' in source


def test_source_keeps_python38_zip_compatibility():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "zip(descriptors, snapshots, strict=True)" not in source
