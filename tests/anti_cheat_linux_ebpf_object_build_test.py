import base64
import copy
import importlib.util
import json
import os
import pathlib
import re
import shutil
import struct
import sys
import tempfile
import time

import jsonschema
import pytest


ROOT = pathlib.Path(__file__).resolve().parents[3]
GATE_PATH = ROOT / "tools/detection_validation/scripts/anti_cheat_linux_ebpf_object_build_gate.py"
SPEC = importlib.util.spec_from_file_location("anti_cheat_linux_ebpf_object_build_gate", GATE_PATH)
GATE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(GATE)


def schema():
    value = json.loads((ROOT / GATE.SCHEMA_PATH).read_text("utf-8"))
    jsonschema.Draft202012Validator.check_schema(value)
    return value


def copy_contract(tmp_path):
    for relative in GATE.SOURCE_PATHS:
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return tmp_path


def mutate(tmp_path, relative, old, new):
    root = copy_contract(tmp_path)
    path = root / relative
    source = path.read_text("utf-8")
    assert old in source
    path.write_text(source.replace(old, new, 1), "utf-8")
    return root


def synthetic_elf(programs=GATE.PROGRAM_SECTIONS):
    section_names = (".shstrtab", ".strtab", ".symtab", "license", ".maps", *programs, *(f".rel{name}" for name in programs))
    names = bytearray(b"\0")
    offsets = {}
    for name in section_names:
        offsets[name] = len(names)
        names.extend(name.encode())
        names.append(0)
    count = len(section_names) + 1
    section_offset = 64
    cursor = section_offset + count * 64
    payloads = {
        ".shstrtab": bytes(names), ".strtab": b"\0symbol\0", ".symtab": b"\0" * 24,
        "license": b"GPL\0", ".maps": b"\0" * 8,
        **{name: b"\0" * 8 for name in programs},
        **{f".rel{name}": b"\0" * 16 for name in programs},
    }
    data = bytearray(cursor + sum(len(payloads[name]) for name in section_names))
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 1, 247, 1)
    struct.pack_into("<Q", data, 40, section_offset)
    struct.pack_into("<HHH", data, 52, 64, 0, 64)
    struct.pack_into("<HHH", data, 58, 64, count, 1)
    indices = {name: index + 1 for index, name in enumerate(section_names)}
    for name in section_names:
        index = indices[name]
        header = section_offset + index * 64
        payload = payloads[name]
        section_type, flags, link, info, alignment, entry_size = 1, 0, 0, 0, 1, 0
        if name in (".shstrtab", ".strtab"):
            section_type = 3
        elif name == ".symtab":
            section_type, link, alignment, entry_size = 2, indices[".strtab"], 8, 24
        elif name in programs:
            flags, alignment = 4, 8
        elif name.startswith(".rel"):
            target = name[4:]
            section_type, link, info, alignment, entry_size = 9, indices[".symtab"], indices[target], 8, 16
        struct.pack_into("<IIQQQQIIQQ", data, header, offsets[name], section_type, flags, 0, cursor, len(payload), link, info, alignment, entry_size)
        data[cursor:cursor + len(payload)] = payload
        cursor += len(payload)
    return bytes(data)


def retained_stream(data=b""):
    return {
        "bytes_total": len(data),
        "full_sha256": GATE.sha256(data),
        "bounded_bytes": len(data),
        "bounded_sha256": GATE.sha256(data),
        "retained_base64": base64.b64encode(data).decode("ascii"),
        "evidence": "retained_full_bytes",
        "truncated": False,
    }


def test_repository_static_contract_passes():
    assert GATE.static_problems(ROOT) == []


def test_exact_six_coordinated_scopes():
    assert tuple(path.as_posix() for path in GATE.SCOPED_PATHS) == (
        "apps/tamandua_agent/bpf/Makefile",
        "apps/tamandua_agent/src/collectors/ebpf_linux.rs",
        "apps/tamandua_agent/tests/ebpf.rs",
        "schemas/anti_cheat_linux_ebpf_object_build_v1.schema.json",
        "tools/detection_validation/scripts/anti_cheat_linux_ebpf_object_build_gate.py",
        "tools/detection_validation/tests/anti_cheat_linux_ebpf_object_build_test.py",
    )


@pytest.mark.parametrize(("relative", "old", "new", "problem"), [
    (GATE.MAKEFILE_PATH, "OBJECT_NAME := tamandua_linux.bpf.o", "OBJECT_NAME := legacy.o", "makefile:canonical_contract"),
    (GATE.MAKEFILE_PATH, "OUTPUT_DIR ?=", "BUILD_DIR ?=", "makefile:canonical_contract"),
    (GATE.MAKEFILE_PATH, "does not prove compatibility with any running kernel BTF", "proves BTF", "makefile:canonical_contract"),
    (GATE.RUNTIME_PATH, "libc::O_CLOEXEC | libc::O_NOFOLLOW", "libc::O_CLOEXEC", "runtime:fail_closed_preflight"),
    (GATE.RUNTIME_PATH, ".load(object.bytes())", ".load_file(bpf_path)", "runtime:fail_closed_preflight"),
    (GATE.RUNTIME_PATH, "BPF object SHA-256 sidecar mismatch", "hash ignored", "runtime:fail_closed_preflight"),
])
def test_source_contract_mutations_fail_closed(tmp_path, relative, old, new, problem):
    root = mutate(tmp_path, relative, old, new)
    assert problem in GATE.static_problems(root)


def test_hidden_tenth_lsm_hook_fails_closed(tmp_path):
    root = copy_contract(tmp_path)
    path = root / GATE.C_PATH
    path.write_text(path.read_text("utf-8") + '\nSEC("lsm/hidden") int BPF_PROG(hidden, int ret) { return ret; }\n', "utf-8")
    assert "source:exact_nine_lsm_hooks" in GATE.static_problems(root)


def test_development_vmlinux_header_is_never_btf_proof(tmp_path):
    root = mutate(tmp_path, GATE.VMLINUX_PATH, "minimal type stubs", "production kernel BTF proof")
    assert "source:vmlinux_stub_disclosure" in GATE.static_problems(root)


def test_elf_parser_accepts_only_exact_inventory():
    result = GATE.parse_elf_programs(synthetic_elf())
    assert result["machine"] == "EM_BPF"
    assert tuple(result["program_sections"]) == GATE.PROGRAM_SECTIONS
    with pytest.raises(ValueError, match="inventory"):
        GATE.parse_elf_programs(synthetic_elf(GATE.PROGRAM_SECTIONS[:-1]))
    programs = list(GATE.PROGRAM_SECTIONS)
    programs[0] = "lsm/hidden"
    with pytest.raises(ValueError, match="unexpected executable"):
        GATE.parse_elf_programs(synthetic_elf(programs))


def test_elf_parser_rejects_exact_and_casefold_duplicates():
    for duplicate in (GATE.PROGRAM_SECTIONS[0], GATE.PROGRAM_SECTIONS[0].upper()):
        with pytest.raises(ValueError, match="duplicate section"):
            GATE.parse_elf_programs(synthetic_elf((*GATE.PROGRAM_SECTIONS, duplicate)))


def test_c_source_elf_inventory_and_attach_plan_are_one_contract():
    assert len(GATE.ATTACH_PLAN) == 8
    assert len(GATE.MOUNT_ATTACH_ALTERNATIVES) == 2
    planned = {entry[0] for entry in (*GATE.ATTACH_PLAN, *GATE.MOUNT_ATTACH_ALTERNATIVES)}
    assert planned == set(GATE.PROGRAM_SECTIONS)
    assert {entry[2] for entry in GATE.ATTACH_PLAN} == {"lsm"}
    assert {entry[2] for entry in GATE.MOUNT_ATTACH_ALTERNATIVES} == {"lsm", "tracepoint"}


def test_non_bpf_elf_rejected():
    data = bytearray(synthetic_elf())
    struct.pack_into("<H", data, 18, 62)
    with pytest.raises(ValueError, match="EM_BPF"):
        GATE.parse_elf_programs(bytes(data))


def test_toolchain_unavailable_is_honest_and_schema_valid(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    receipt = GATE.run(ROOT)
    assert receipt["state"] == "toolchain_unavailable"
    assert not receipt["build"]["attempted"]
    assert receipt["object"] is None
    assert set(receipt["lifecycle"].values()) == {False}
    assert set(receipt["claims"].values()) == {False}
    assert receipt["source"]["validator_authority_external"] is False
    assert "build_execution_authenticity_unbound" in receipt["blockers"]
    assert "kernel_verifier_unexecuted" in receipt["blockers"]
    jsonschema.validate(receipt, schema())


def test_success_promotion_and_zero_payload_elf_fail_closed(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    receipt = GATE.run(ROOT)
    promoted = copy.deepcopy(receipt)
    promoted["state"] = "success"
    with pytest.raises(GATE.ReceiptValidationError, match="promotion_forbidden"):
        GATE.validate_receipt(promoted)

    zero_payload = bytearray(synthetic_elf())
    section_offset = struct.unpack_from("<Q", zero_payload, 40)[0]
    first_program_index = 6
    struct.pack_into("<Q", zero_payload, section_offset + first_program_index * 64 + 32, 0)
    with pytest.raises(ValueError, match="empty or unbounded executable"):
        GATE.parse_elf_programs(bytes(zero_payload))


def test_post_build_snapshot_or_toolchain_drift_is_source_invalid(monkeypatch):
    toolchain = {
        "paths": {tool: f"/usr/bin/{tool}" for tool in ("make", "clang", "llvm-strip", "llvm-readelf", "sha256sum")},
        "sha256": {tool: "0" * 64 for tool in ("make", "clang", "llvm-strip", "llvm-readelf", "sha256sum")},
        "clang_version": "clang version 18.1.0",
        "libbpf_headers": {
            "bpf_helpers.h": {"path": "/usr/include/bpf/bpf_helpers.h", "sha256": "0" * 64},
            "bpf_tracing.h": {"path": "/usr/include/bpf/bpf_tracing.h", "sha256": "0" * 64},
        },
    }
    snapshot_holder = {}
    original_materialize = GATE.materialize_snapshot

    def materialize(snapshot, sources):
        result = original_materialize(snapshot, sources)
        snapshot_holder["path"] = snapshot
        return result

    def fake_run(argv, timeout):
        command = argv[-1]
        assert "/usr/bin/make -f" in command
        assert "CLANG=/usr/bin/clang" in command
        target = snapshot_holder["path"] / GATE.TEST_PATH
        target.chmod(0o600)
        target.write_bytes(target.read_bytes() + b"\n# post-build mutation\n")
        return {"outcome": "exited", "exit_code": 0, "stdout": retained_stream(), "stderr": retained_stream()}

    monkeypatch.setattr(GATE, "shell_context", lambda root: (["bash", "-lc"], str(root)))
    monkeypatch.setattr(GATE, "probe_toolchain", lambda prefix, root: (copy.deepcopy(toolchain), []))
    monkeypatch.setattr(GATE, "materialize_snapshot", materialize)
    monkeypatch.setattr(GATE, "run_bounded", fake_run)
    receipt = GATE.run(ROOT)
    assert receipt["state"] == "source_invalid"
    assert receipt["source"]["problems"] == ["post_build_source_or_toolchain_drift"]
    assert receipt["build"]["attempted"] is True


def test_source_and_object_pre_read_caps_are_aligned(tmp_path):
    source = tmp_path / "source"
    with source.open("wb") as stream:
        stream.truncate(GATE.SOURCE_LIMIT + 1)
    with pytest.raises(ValueError, match="unbounded or non-regular"):
        GATE.regular_file(tmp_path, pathlib.Path("source"))
    artifact = tmp_path / "artifact"
    with artifact.open("wb") as stream:
        stream.truncate(GATE.OBJECT_LIMIT + 1)
    with pytest.raises(ValueError, match="unbounded or non-regular"):
        GATE.regular_bytes(tmp_path, pathlib.Path("artifact"), maximum_bytes=GATE.OBJECT_LIMIT)


def test_toolchain_post_build_drift_is_categorical(monkeypatch):
    tools = ("make", "clang", "llvm-strip", "llvm-readelf", "sha256sum")
    base = {
        "paths": {tool: f"/usr/bin/{tool}" for tool in tools},
        "sha256": {tool: "0" * 64 for tool in tools},
        "clang_version": "clang version 18.1.0",
        "libbpf_headers": {
            "bpf_helpers.h": {"path": "/usr/include/bpf/bpf_helpers.h", "sha256": "0" * 64},
            "bpf_tracing.h": {"path": "/usr/include/bpf/bpf_tracing.h", "sha256": "0" * 64},
        },
    }
    calls = {"count": 0}

    def probe(prefix, root):
        value = copy.deepcopy(base)
        if calls["count"]:
            value["sha256"]["clang"] = "f" * 64
        calls["count"] += 1
        return value, []

    def fake_run(argv, timeout):
        assert "/usr/bin/make -f" in argv[-1]
        assert "LLVM_STRIP=/usr/bin/llvm-strip" in argv[-1]
        return {"outcome": "exited", "exit_code": 0, "stdout": retained_stream(), "stderr": retained_stream()}

    monkeypatch.setattr(GATE, "shell_context", lambda root: (["bash", "-lc"], str(root)))
    monkeypatch.setattr(GATE, "probe_toolchain", probe)
    monkeypatch.setattr(GATE, "run_bounded", fake_run)
    receipt = GATE.run(ROOT)
    assert receipt["state"] == "source_invalid"
    assert receipt["source"]["problems"] == ["post_build_source_or_toolchain_drift"]


def test_oversized_source_run_and_object_read_fail_categorically(monkeypatch, tmp_path):
    root = copy_contract(tmp_path)
    with (root / GATE.TEST_PATH).open("wb") as stream:
        stream.truncate(GATE.SOURCE_LIMIT + 1)
    receipt = GATE.run(root)
    assert receipt["state"] == "source_invalid"
    assert "unbounded or non-regular source" in receipt["source"]["problems"][0]

    tools = ("make", "clang", "llvm-strip", "llvm-readelf", "sha256sum")
    toolchain = {
        "paths": {tool: f"/usr/bin/{tool}" for tool in tools},
        "sha256": {tool: "0" * 64 for tool in tools},
        "clang_version": "clang version 18.1.0",
        "libbpf_headers": {
            "bpf_helpers.h": {"path": "/usr/include/bpf/bpf_helpers.h", "sha256": "0" * 64},
            "bpf_tracing.h": {"path": "/usr/include/bpf/bpf_tracing.h", "sha256": "0" * 64},
        },
    }
    monkeypatch.setattr(GATE, "shell_context", lambda root: (["bash", "-lc"], str(root)))
    monkeypatch.setattr(GATE, "probe_toolchain", lambda prefix, root: (copy.deepcopy(toolchain), []))
    monkeypatch.setattr(GATE, "run_bounded", lambda argv, timeout: {
        "outcome": "exited", "exit_code": 0, "stdout": retained_stream(), "stderr": retained_stream(),
    })
    monkeypatch.setattr(GATE, "regular_bytes", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("unbounded object")))
    receipt = GATE.run(ROOT)
    assert receipt["state"] == "object_invalid"
    assert receipt["object"] == {"error": "unbounded object"}


def test_snapshot_binds_captured_bytes_and_live_mutation_fails_closed(tmp_path):
    root = copy_contract(tmp_path)
    original = (root / GATE.MAKEFILE_PATH).read_bytes()

    def mutate_live_source(live_root):
        path = live_root / GATE.MAKEFILE_PATH
        path.write_bytes(original + b"\n# concurrent mutation\n")

    receipt = GATE.run(root, after_capture=mutate_live_source)
    key = GATE.MAKEFILE_PATH.as_posix()
    assert receipt["state"] == "source_invalid"
    assert receipt["source"]["problems"] == ["paths:live_sources_changed_after_capture"]
    assert receipt["source"]["snapshot_isolated"] is True
    assert receipt["source"]["build_input"] == "isolated_snapshot"
    assert receipt["source"]["files"][key]["sha256"] == GATE.sha256(original)
    assert receipt["source"]["snapshot_files"][key]["sha256"] == GATE.sha256(original)
    assert receipt["source"]["live_post_files"][key]["sha256"] != GATE.sha256(original)
    assert receipt["build"]["attempted"] is False
    jsonschema.validate(receipt, schema())


def test_missing_source_has_categorical_schema_valid_receipt(tmp_path):
    root = copy_contract(tmp_path)
    (root / GATE.C_PATH).unlink()
    receipt = GATE.run(root)
    assert receipt["state"] == "source_invalid"
    assert receipt["source"]["problems"][0].startswith("paths:")
    assert receipt["source"]["files"] == {}
    assert receipt["build"]["attempted"] is False
    jsonschema.validate(receipt, schema())


def test_schema_rejects_promoted_claim_and_fake_btf_proof(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    receipt = GATE.run(ROOT)
    promoted = copy.deepcopy(receipt)
    promoted["claims"]["kernel_btf_compatible"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(promoted, schema())


def test_semantic_validator_rejects_forged_identity_maps_and_keysets(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    receipt = GATE.run(ROOT)
    key = next(iter(receipt["source"]["live_post_files"]))
    cases = []
    value = copy.deepcopy(receipt); value["source"]["live_post_files"][key]["sha256"] = "f" * 64; cases.append(value)
    value = copy.deepcopy(receipt); value["source"]["snapshot_files"][key]["bytes"] += 1; cases.append(value)
    value = copy.deepcopy(receipt)
    for name in ("files", "live_post_files", "snapshot_files"):
        value["source"][name][key]["sha256"] = "f" * 64
    value["source"]["retained_snapshot"]["files"][key]["sha256"] = "f" * 64
    value["source"]["retained_snapshot"]["manifest_sha256"] = GATE.snapshot_manifest_sha256(value["source"]["retained_snapshot"]["files"])
    cases.append(value)
    value = copy.deepcopy(receipt)
    forged = b"coherent but arbitrary source bytes"
    forged_hash = GATE.sha256(forged)
    for name in ("files", "live_post_files", "snapshot_files"):
        value["source"][name][key]["sha256"] = forged_hash
        value["source"][name][key]["bytes"] = len(forged)
    value["source"]["retained_snapshot"]["files"][key].update({
        "sha256": forged_hash, "bytes": len(forged),
        "data_base64": base64.b64encode(forged).decode("ascii"),
    })
    value["source"]["retained_snapshot"]["manifest_sha256"] = GATE.snapshot_manifest_sha256(value["source"]["retained_snapshot"]["files"])
    cases.append(value)
    value = copy.deepcopy(receipt)
    value["source"]["snapshot_files"][key]["device"] = value["source"]["files"][key]["device"]
    value["source"]["snapshot_files"][key]["inode"] = value["source"]["files"][key]["inode"]
    if (value["source"]["files"][key]["device"], value["source"]["files"][key]["inode"]) != (0, 0):
        cases.append(value)
    value = copy.deepcopy(receipt); value["source"]["retained_snapshot"]["manifest_sha256"] = "f" * 64; cases.append(value)
    value = copy.deepcopy(receipt); value["source"]["retained_snapshot"]["files"][key]["data_base64"] = base64.b64encode(b"forged").decode("ascii"); cases.append(value)
    value = copy.deepcopy(receipt); value["source"]["files"].pop(key); cases.append(value)
    value = copy.deepcopy(receipt); value["state"] = "success"; cases.append(value)
    for value in cases:
        with pytest.raises(GATE.ReceiptValidationError):
            GATE.validate_receipt(value)
    promoted = copy.deepcopy(receipt)
    promoted["source"]["vmlinux_header_role"] = "kernel_btf_proven"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(promoted, schema())


def test_authoritative_policy_rejects_contract_neutral_full_map_forgery(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    receipt = GATE.run(ROOT)
    assert receipt["source"]["source_policy_sha256"] == GATE.SOURCE_POLICY_SHA256
    assert GATE.source_policy_sha256() == GATE.SOURCE_POLICY_SHA256
    key = GATE.MAKEFILE_PATH.as_posix()
    forged = base64.b64decode(
        receipt["source"]["retained_snapshot"]["files"][key]["data_base64"],
        validate=True,
    ) + b"\n"
    digest = GATE.sha256(forged)
    for name in ("files", "live_post_files", "snapshot_files"):
        receipt["source"][name][key]["bytes"] = len(forged)
        receipt["source"][name][key]["sha256"] = digest
    receipt["source"]["retained_snapshot"]["files"][key].update({
        "bytes": len(forged), "sha256": digest,
        "data_base64": base64.b64encode(forged).decode("ascii"),
    })
    receipt["source"]["retained_snapshot"]["manifest_sha256"] = GATE.snapshot_manifest_sha256(
        receipt["source"]["retained_snapshot"]["files"]
    )
    with pytest.raises(GATE.ReceiptValidationError, match="authoritative_source_pin"):
        GATE.validate_receipt(receipt)


def test_unknown_or_equal_snapshot_identity_never_proves_isolation(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    receipt = GATE.run(ROOT)
    forged = copy.deepcopy(receipt)
    for key in forged["source"]["files"]:
        for name in ("files", "live_post_files", "snapshot_files"):
            forged["source"][name][key]["device"] = 0
            forged["source"][name][key]["inode"] = 0
    with pytest.raises(GATE.ReceiptValidationError, match="snapshot_identity_not_isolated"):
        GATE.validate_receipt(forged)

    original_materialize = GATE.materialize_snapshot

    def unknown_identity(snapshot, sources):
        snapshot_sources, identities = original_materialize(snapshot, sources)
        for identity in identities.values():
            identity["device"] = 0
            identity["inode"] = 0
        return snapshot_sources, identities

    monkeypatch.setattr(GATE, "materialize_snapshot", unknown_identity)
    categorical = GATE.run(ROOT)
    assert categorical["state"] == "source_invalid"
    assert categorical["source"]["snapshot_isolated"] is False
    assert categorical["source"]["build_input"] == "none"
    assert categorical["source"]["problems"][0].startswith("snapshot:identity_not_isolated:")


def test_base64_and_receipt_file_limits_reject_before_decode(monkeypatch, tmp_path):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    receipt = GATE.run(ROOT)
    key = GATE.MAKEFILE_PATH.as_posix()
    oversized = copy.deepcopy(receipt)
    oversized["source"]["retained_snapshot"]["files"][key]["data_base64"] = (
        "A" * (GATE._canonical_base64_length(GATE.RETAINED_FILE_LIMIT) + 4)
    )
    with pytest.raises(GATE.ReceiptValidationError, match="predecode_limit"):
        GATE.validate_receipt(oversized)

    declared_small = copy.deepcopy(receipt)
    declared_small["source"]["retained_snapshot"]["files"][key]["bytes"] = 1
    declared_small["source"]["retained_snapshot"]["files"][key]["data_base64"] = "A" * 4096
    with pytest.raises(GATE.ReceiptValidationError, match="base64_invalid"):
        GATE.validate_receipt(declared_small)

    too_large = tmp_path / "oversized-receipt.json"
    with too_large.open("wb") as stream:
        stream.truncate(GATE.RECEIPT_JSON_LIMIT + 1)
    with pytest.raises(GATE.ReceiptValidationError, match="receipt_json_file_invalid"):
        GATE.validate_receipt_file(too_large)

    duplicate = tmp_path / "duplicate-receipt.json"
    duplicate.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    with pytest.raises(GATE.ReceiptValidationError, match="duplicate_key"):
        GATE.validate_receipt_file(duplicate)

    defs = schema()["$defs"]
    assert defs["retainedFile"]["properties"]["data_base64"]["maxLength"] == 2796204
    assert defs["stream"]["properties"]["retained_base64"]["maxLength"] == 87384
    assert defs["objectValid"]["properties"]["retained_base64"]["maxLength"] == 22369624


def test_actual_local_result_is_categorical_and_schema_valid():
    receipt = GATE.run(ROOT)
    assert receipt["state"] in {"toolchain_unavailable", "artifact_observed_unbound"}
    assert set(receipt["lifecycle"].values()) == {False}
    assert set(receipt["claims"].values()) == {False}
    if receipt["state"] == "toolchain_unavailable":
        assert receipt["build"]["missing_tools"]
        assert not receipt["build"]["attempted"]
    jsonschema.validate(receipt, schema())


def test_schema_state_shapes_fail_closed(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    unavailable = GATE.run(ROOT)
    validator = jsonschema.Draft202012Validator(schema())
    cases = []
    value = copy.deepcopy(unavailable); value["build"]["attempted"] = True; cases.append(value)
    value = copy.deepcopy(unavailable); value["build"]["exit_code"] = 0; cases.append(value)
    value = copy.deepcopy(unavailable); value["object"] = {"error": "invented"}; cases.append(value)
    for value in cases:
        assert list(validator.iter_errors(value))


def test_schema_accepts_only_exact_attempt_exit_and_object_shapes(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    base = GATE.run(ROOT)
    digest = "0" * 64
    stream = retained_stream()
    tools = ("make", "clang", "llvm-strip", "llvm-readelf", "sha256sum")
    toolchain = {
        "paths": {tool: f"/usr/bin/{tool}" for tool in tools},
        "sha256": {tool: digest for tool in tools},
        "clang_version": "clang version 18.1.0",
        "libbpf_headers": {
            "bpf_helpers.h": {"path": "/usr/include/bpf/bpf_helpers.h", "sha256": digest},
            "bpf_tracing.h": {"path": "/usr/include/bpf/bpf_tracing.h", "sha256": digest},
        },
    }
    object_bytes = synthetic_elf()
    valid_object = {
        "filename": "tamandua_linux.bpf.o", "sha256": GATE.sha256(object_bytes), "bytes": len(object_bytes),
        "retained_base64": base64.b64encode(object_bytes).decode("ascii"),
        "elf": GATE.parse_elf_programs(object_bytes),
    }
    validator = jsonschema.Draft202012Validator(schema())
    states = (
        ("build_failed", "exited", 7, None),
        ("build_failed", "timed_out", None, None),
        ("build_failed", "termination_failed", None, None),
        ("object_invalid", "exited", 0, {"error": "invalid ELF"}),
        ("artifact_observed_unbound", "exited", 0, valid_object),
    )
    for state, outcome, exit_code, object_value in states:
        value = copy.deepcopy(base)
        value["state"] = state
        value["build"].update({"attempted": True, "outcome": outcome, "toolchain": toolchain, "missing_tools": [], "exit_code": exit_code, "stdout": stream, "stderr": stream})
        value["object"] = object_value
        assert list(validator.iter_errors(value)) == []
        broken = copy.deepcopy(value); broken["build"]["toolchain"] = {}
        assert list(validator.iter_errors(broken))


def test_makefile_compatibility_aliases_are_fail_safe():
    source = (ROOT / GATE.MAKEFILE_PATH).read_text("utf-8")
    assert "all: canonical" in source
    assert "verify: check-toolchain check-output-path" in source
    assert "clean: check-output-path" in source
    assert "rm -rf" not in source
    assert not re.search(r"(?m)^(?:load|install)\s*:", source)


def test_streaming_runner_bounds_output_and_times_out_direct_process():
    gate_source = GATE_PATH.read_text("utf-8")
    assert "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in gate_source
    assert "start_new_session" in gate_source and "os.killpg" in gate_source
    command = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x'*70000)"]
    result = GATE.run_bounded(command, timeout=10)
    assert result["outcome"] == "exited" and result["exit_code"] == 0
    assert result["stdout"]["bytes_total"] is None
    assert result["stdout"]["full_sha256"] is None
    assert result["stdout"]["bounded_bytes"] == GATE.LOG_LIMIT
    retained = base64.b64decode(result["stdout"]["retained_base64"], validate=True)
    assert retained == b"x" * GATE.LOG_LIMIT
    assert result["stdout"]["bounded_sha256"] == GATE.sha256(retained)
    assert result["stdout"]["evidence"] == "retained_bounded_prefix_only"
    assert result["stdout"]["truncated"] is True
    result = GATE.run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1)
    assert result["outcome"] == "timed_out" and result["exit_code"] is None


def test_semantic_validator_rejects_stream_and_object_evidence_tamper(monkeypatch):
    monkeypatch.setattr(GATE, "shell_context", lambda root: None)
    base = GATE.run(ROOT)
    digest = "0" * 64
    tools = ("make", "clang", "llvm-strip", "llvm-readelf", "sha256sum")
    toolchain = {
        "paths": {tool: f"/usr/bin/{tool}" for tool in tools},
        "sha256": {tool: digest for tool in tools},
        "clang_version": "clang version 18.1.0",
        "libbpf_headers": {
            "bpf_helpers.h": {"path": "/usr/include/bpf/bpf_helpers.h", "sha256": digest},
            "bpf_tracing.h": {"path": "/usr/include/bpf/bpf_tracing.h", "sha256": digest},
        },
    }
    value = copy.deepcopy(base)
    value["state"] = "build_failed"
    value["build"].update({
        "attempted": True, "outcome": "exited", "toolchain": toolchain,
        "missing_tools": [], "exit_code": 7,
        "stdout": retained_stream(b"stdout"), "stderr": retained_stream(b"stderr"),
    })
    GATE.validate_receipt(value)
    for field, replacement in (
        ("bounded_sha256", "f" * 64),
        ("full_sha256", "f" * 64),
        ("bytes_total", 999),
        ("retained_base64", base64.b64encode(b"tamper").decode("ascii")),
    ):
        tampered = copy.deepcopy(value)
        tampered["build"]["stdout"][field] = replacement
        with pytest.raises(GATE.ReceiptValidationError):
            GATE.validate_receipt(tampered)

    truncated = copy.deepcopy(value)
    truncated["build"]["stdout"] = GATE.run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x'*70000)"], timeout=10,
    )["stdout"]
    GATE.validate_receipt(truncated)
    for field, replacement in (("bytes_total", 70000), ("full_sha256", GATE.sha256(b"x" * 70000))):
        tampered = copy.deepcopy(truncated)
        tampered["build"]["stdout"][field] = replacement
        with pytest.raises(GATE.ReceiptValidationError):
            GATE.validate_receipt(tampered)

    object_bytes = synthetic_elf()
    success = copy.deepcopy(value)
    success["state"] = "artifact_observed_unbound"
    success["build"]["exit_code"] = 0
    success["object"] = {
        "filename": "tamandua_linux.bpf.o", "sha256": GATE.sha256(object_bytes),
        "bytes": len(object_bytes), "retained_base64": base64.b64encode(object_bytes).decode("ascii"),
        "elf": GATE.parse_elf_programs(object_bytes),
    }
    GATE.validate_receipt(success)
    success["object"]["sha256"] = "f" * 64
    with pytest.raises(GATE.ReceiptValidationError):
        GATE.validate_receipt(success)


def _process_alive(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel32.OpenProcess(0x00100000, False, pid)
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 0x102
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    if pathlib.Path(f"/proc/{pid}/stat").exists():
        return pathlib.Path(f"/proc/{pid}/stat").read_text("utf-8").split()[2] != "Z"
    return True


def _exercise_process_tree_timeout(allowed_outcomes=("timed_out",)):
    with tempfile.TemporaryDirectory(prefix="tamandua-ebpf-tree-test-") as temporary:
        root = pathlib.Path(temporary)
        child_pid = root / "child.pid"
        grandchild_pid = root / "grandchild.pid"
        grandchild = (
            "import os,pathlib,time; "
            f"pathlib.Path({str(grandchild_pid)!r}).write_text(str(os.getpid())); time.sleep(30)"
        )
        child = (
            "import os,pathlib,subprocess,sys,time; "
            f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
            f"pathlib.Path({str(child_pid)!r}).write_text(str(os.getpid())); "
            f"deadline=time.time()+5; p=pathlib.Path({str(grandchild_pid)!r})\n"
            "while not p.exists() and time.time()<deadline:\n    time.sleep(.02)\n"
            "time.sleep(30)"
        )
        parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(30)"
        result = GATE.run_bounded([sys.executable, "-c", parent], timeout=2)
        assert result["outcome"] in allowed_outcomes
        assert child_pid.exists() and grandchild_pid.exists()
        pids = (int(child_pid.read_text()), int(grandchild_pid.read_text()))
        deadline = time.time() + 5
        while any(_process_alive(pid) for pid in pids) and time.time() < deadline:
            time.sleep(0.05)
        survivors = [pid for pid in pids if _process_alive(pid)]
        if survivors:
            assert result["outcome"] == "termination_failed"
            if os.name == "nt":
                taskkill = GATE._trusted_windows_taskkill()
                for pid in survivors:
                    __import__('subprocess').run([str(taskkill), "/PID", str(pid), "/T", "/F"], capture_output=True)
        else:
            assert result["outcome"] == "timed_out"


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object branch")
def test_windows_timeout_terminates_real_child_and_grandchild():
    _exercise_process_tree_timeout()


@pytest.mark.skipif(os.name != "nt", reason="Windows trusted taskkill fallback")
def test_windows_forced_job_assignment_failure_is_closed(monkeypatch):
    monkeypatch.setattr(GATE, "_windows_kill_on_close_job", lambda _process: None)
    _exercise_process_tree_timeout(("timed_out", "termination_failed"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group branch")
def test_posix_timeout_terminates_real_child_and_grandchild():
    _exercise_process_tree_timeout()


def test_runner_source_uses_trusted_windows_fallback_and_closed_secondary_timeout():
    source = GATE_PATH.read_text("utf-8")
    assert "GetSystemDirectoryW" in source
    assert '["taskkill.exe"' not in source
    assert 'outcome = "termination_failed"' in source
    assert 'except subprocess.TimeoutExpired:' in source
    assert "completed.returncode == 0" in source
    assert "_windows_process_tree" in source and "_windows_pid_alive" in source


def test_posix_cleanup_is_source_contract_only_when_not_running_on_posix():
    source = GATE_PATH.read_text("utf-8")
    assert 'kwargs["start_new_session"] = True' in source
    assert "os.killpg(process.pid, signal.SIGKILL)" in source
    if os.name != "posix":
        assert sys.platform != "linux"


def test_all_six_scopes_receive_whole_file_validation():
    for relative in GATE.SCOPED_PATHS:
        data = (ROOT / relative).read_bytes()
        text = data.decode("utf-8")
        assert data and b"\0" not in data and __import__('hashlib').sha256(data).hexdigest()
        assert all(line == line.rstrip(" \t") for line in text.splitlines())
