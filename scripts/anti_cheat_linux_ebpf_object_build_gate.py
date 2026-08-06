#!/usr/bin/env python3
"""Canonical C BPF-LSM object source/build preflight (never loads BPF)."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable

from jsonschema import Draft202012Validator


ROOT = pathlib.Path(__file__).resolve().parents[3]
C_PATH = pathlib.Path("apps/tamandua_agent/bpf/lsm_hooks.bpf.c")
VMLINUX_PATH = pathlib.Path("apps/tamandua_agent/bpf/vmlinux.h")
MAKEFILE_PATH = pathlib.Path("apps/tamandua_agent/bpf/Makefile")
RUNTIME_PATH = pathlib.Path("apps/tamandua_agent/src/collectors/ebpf_linux.rs")
RUST_TEST_PATH = pathlib.Path("apps/tamandua_agent/tests/ebpf.rs")
SCHEMA_PATH = pathlib.Path("schemas/anti_cheat_linux_ebpf_object_build_v1.schema.json")
GATE_PATH = pathlib.Path("tools/detection_validation/scripts/anti_cheat_linux_ebpf_object_build_gate.py")
TEST_PATH = pathlib.Path("tools/detection_validation/tests/anti_cheat_linux_ebpf_object_build_test.py")
SCOPED_PATHS = (MAKEFILE_PATH, RUNTIME_PATH, RUST_TEST_PATH, SCHEMA_PATH, GATE_PATH, TEST_PATH)
SOURCE_PATHS = (C_PATH, VMLINUX_PATH, *SCOPED_PATHS)
AUTHORITATIVE_SOURCE_PINS = {
    "apps/tamandua_agent/bpf/lsm_hooks.bpf.c": {"bytes": 26003, "sha256": "b7b53aeaf200a5668532bd627252e904e0d7ab19f316d147a83186f9f18088bb"},
    "apps/tamandua_agent/bpf/vmlinux.h": {"bytes": 7716, "sha256": "c6a5b74edb6104351b8717fa6c14552a5231a8af742e1385fcb5cacc606393a4"},
    "apps/tamandua_agent/bpf/Makefile": {"bytes": 4150, "sha256": "c49779af21bc6054022de35ea8326197180d1d920c8b3ee9ebceca518fb204ba"},
    "apps/tamandua_agent/src/collectors/ebpf_linux.rs": {"bytes": 258291, "sha256": "cb0d32992d5aed2596324490e819e965b5d61a5f6497b84c2b4a87a4f9a70540"},
    "apps/tamandua_agent/tests/ebpf.rs": {"bytes": 7269, "sha256": "f2da24634d52c2537eaf2863551f7ed73513b0d8de6bfed1383140558494f6c4"},
}
SOURCE_POLICY_FORMAT = "tamandua.authoritative-source-policy.canonical-json/v1"
SOURCE_POLICY_SHA256 = "05659ad33cf6aabff94ea790f675eb907147936a6ab54d1abb596e98919798c6"

LSM_HOOKS = (
    "bprm_check_security", "file_open", "file_permission", "mmap_file",
    "ptrace_access_check", "sb_mount", "socket_bind", "socket_connect", "task_kill",
)
PROGRAM_SECTIONS = tuple(f"lsm/{hook}" for hook in LSM_HOOKS) + (
    "tracepoint/module/module_load",
    "tracepoint/syscalls/sys_enter_mount",
)
ATTACH_PLAN = (
    ("lsm/bprm_check_security", "lsm_bprm_check_security", "lsm", "bprm_check_security"),
    ("lsm/file_open", "lsm_file_open", "lsm", "file_open"),
    ("lsm/file_permission", "lsm_file_permission", "lsm", "file_permission"),
    ("lsm/mmap_file", "lsm_mmap_file", "lsm", "mmap_file"),
    ("lsm/ptrace_access_check", "lsm_ptrace_access_check", "lsm", "ptrace_access_check"),
    ("lsm/socket_bind", "lsm_socket_bind", "lsm", "socket_bind"),
    ("lsm/socket_connect", "lsm_socket_connect", "lsm", "socket_connect"),
    ("lsm/task_kill", "lsm_task_kill", "lsm", "task_kill"),
)
MOUNT_ATTACH_ALTERNATIVES = (
    ("lsm/sb_mount", "lsm_sb_mount", "lsm", "sb_mount"),
    ("tracepoint/syscalls/sys_enter_mount", "tp_sys_enter_mount", "tracepoint", "syscalls/sys_enter_mount"),
)
# VM/hypervisor kernel module load tracepoint (T1564.006).
# Unconditionally attached on every CONFIG_MODULES kernel.
MODULE_LOAD_TRACEPOINT = (
    ("tracepoint/module/module_load", "tp_module_load", "tracepoint", "module/module_load"),
)
FALSE_CLAIMS = (
    "verifier_validated", "kernel_btf_compatible", "loaded", "attached",
    "runtime_observed", "efficacy_validated", "production_ready", "external_claim_allowed",
)
BLOCKERS = (
    "build_execution_authenticity_unbound", "kernel_verifier_unexecuted",
    "validator_authority_external", "real_kernel_btf_compatibility_not_validated",
    "load_not_executed", "attach_not_executed", "ring_buffer_runtime_not_observed",
    "privileged_kernel_execution_not_authorized", "efficacy_not_validated",
)
LOG_LIMIT = 65536
SOURCE_LIMIT = 2 * 1024 * 1024
RETAINED_FILE_LIMIT = SOURCE_LIMIT
RETAINED_SOURCE_TOTAL_LIMIT = 4 * 1024 * 1024
OBJECT_LIMIT = 16 * 1024 * 1024
RECEIPT_DECODED_TOTAL_LIMIT = 21 * 1024 * 1024
RECEIPT_ENCODED_TOTAL_LIMIT = 29 * 1024 * 1024
RECEIPT_JSON_LIMIT = 32 * 1024 * 1024
SCHEMA_JSON_LIMIT = 1024 * 1024


class ReceiptValidationError(ValueError):
    pass


def _identity_payload(value: dict) -> tuple:
    return (value.get("sha256"), value.get("bytes"), value.get("device"), value.get("inode"), value.get("mtime_ns"))


def _canonical_base64_length(decoded_bytes: int) -> int:
    return 4 * ((decoded_bytes + 2) // 3)


def _decode_base64(value: str, error: str, *, expected_bytes: int, maximum_bytes: int) -> bytes:
    if (
        type(value) is not str
        or type(expected_bytes) is not int
        or not 0 <= expected_bytes <= maximum_bytes
        or len(value) != _canonical_base64_length(expected_bytes)
    ):
        raise ReceiptValidationError(error)
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ReceiptValidationError(error) from exc
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ReceiptValidationError(error)
    return decoded


def source_policy_sha256() -> str:
    payload = {
        "format": SOURCE_POLICY_FORMAT,
        "files": [
            {"path": path, **AUTHORITATIVE_SOURCE_PINS[path]}
            for path in sorted(AUTHORITATIVE_SOURCE_PINS)
        ],
    }
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _closed_json_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptValidationError("receipt_json_duplicate_key")
        result[key] = value
    return result


def _load_json_object(path: pathlib.Path, limit: int, error: str) -> dict:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0):
            raise ReceiptValidationError(error)
        size = metadata.st_size
        if not 1 <= size <= limit:
            raise ReceiptValidationError(error)
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) != size or len(raw) > limit or b"\0" in raw:
            raise ReceiptValidationError(error)
        value = json.loads(raw, object_pairs_hook=_closed_json_pairs)
    except ReceiptValidationError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise ReceiptValidationError(error) from exc
    if type(value) is not dict:
        raise ReceiptValidationError(error)
    return value


def _receipt_base64_preflight(receipt: dict) -> None:
    encoded_total = 0

    def bounded(value: object, maximum: int) -> None:
        nonlocal encoded_total
        if type(value) is not str or len(value) > _canonical_base64_length(maximum):
            raise ReceiptValidationError("receipt_base64_predecode_limit")
        encoded_total += len(value)
        if encoded_total > RECEIPT_ENCODED_TOTAL_LIMIT:
            raise ReceiptValidationError("receipt_base64_encoded_total_limit")

    try:
        retained = receipt.get("source", {}).get("retained_snapshot")
        if isinstance(retained, dict):
            files = retained.get("files", {})
            if isinstance(files, dict):
                for evidence in files.values():
                    if isinstance(evidence, dict) and "data_base64" in evidence:
                        bounded(evidence["data_base64"], RETAINED_FILE_LIMIT)
        build = receipt.get("build", {})
        if isinstance(build, dict):
            for name in ("stdout", "stderr"):
                stream = build.get(name)
                if isinstance(stream, dict) and "retained_base64" in stream:
                    bounded(stream["retained_base64"], LOG_LIMIT)
        object_evidence = receipt.get("object")
        if isinstance(object_evidence, dict) and "retained_base64" in object_evidence:
            bounded(object_evidence["retained_base64"], OBJECT_LIMIT)
    except AttributeError as exc:
        raise ReceiptValidationError("receipt_base64_predecode_limit") from exc


def snapshot_manifest_sha256(files: dict) -> str:
    entries = [
        {"path": path, "file_type": value["file_type"], "bytes": value["bytes"], "sha256": value["sha256"]}
        for path, value in sorted(files.items())
    ]
    payload = {"format": "tamandua.snapshot-manifest.canonical-json/v1", "files": entries}
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def retained_snapshot_evidence(sources: dict[pathlib.Path, bytes]) -> dict:
    files = {
        path.as_posix(): {
            "file_type": "regular", "sha256": sha256(data), "bytes": len(data),
            "data_base64": base64.b64encode(data).decode("ascii"),
        }
        for path, data in sources.items()
    }
    return {
        "manifest_format": "tamandua.snapshot-manifest.canonical-json/v1",
        "manifest_sha256": snapshot_manifest_sha256(files),
        "files": files,
    }


def validate_receipt(receipt: dict) -> dict:
    if type(receipt) is not dict:
        raise ReceiptValidationError("receipt_schema_invalid")
    if receipt.get("state") == "success" or receipt.get("build_validated") is True:
        raise ReceiptValidationError("receipt_promotion_forbidden")
    _receipt_base64_preflight(receipt)
    schema = _load_json_object(ROOT / SCHEMA_PATH, SCHEMA_JSON_LIMIT, "receipt_schema_file_invalid")
    if list(Draft202012Validator(schema).iter_errors(receipt)):
        raise ReceiptValidationError("receipt_schema_invalid")
    source = receipt["source"]
    if source["source_policy_sha256"] != SOURCE_POLICY_SHA256 or source_policy_sha256() != SOURCE_POLICY_SHA256:
        raise ReceiptValidationError("receipt_source_policy_invalid")
    expected = {path.as_posix() for path in SOURCE_PATHS}
    maps = [source["files"], source["live_post_files"], source["snapshot_files"]]
    for values in maps:
        if values and set(values) != expected:
            raise ReceiptValidationError("receipt_source_keyset_invalid")
    if not source["problems"]:
        for values in maps:
            for key, pin in AUTHORITATIVE_SOURCE_PINS.items():
                if values and (values[key]["bytes"] != pin["bytes"] or values[key]["sha256"] != pin["sha256"]):
                    raise ReceiptValidationError("receipt_authoritative_source_pin_invalid")
    decoded_total = 0
    encoded_total = 0
    if source["live_sources_unchanged"]:
        if maps[0] != maps[1]:
            raise ReceiptValidationError("receipt_live_identity_invalid")
        for key in expected:
            if (_identity_payload(maps[0][key])[:2] != _identity_payload(maps[2][key])[:2]):
                raise ReceiptValidationError("receipt_snapshot_bytes_invalid")
            live_identity = _identity_payload(maps[0][key])[2:4]
            snapshot_identity = _identity_payload(maps[2][key])[2:4]
            if live_identity == (0, 0) or snapshot_identity == (0, 0) or live_identity == snapshot_identity:
                raise ReceiptValidationError("receipt_snapshot_identity_not_isolated")
        retained = source["retained_snapshot"]
        if not isinstance(retained, dict) or set(retained["files"]) != expected:
            raise ReceiptValidationError("receipt_retained_snapshot_keyset_invalid")
        retained_sources: dict[pathlib.Path, bytes] = {}
        for key in expected:
            evidence = retained["files"][key]
            data = _decode_base64(
                evidence["data_base64"], "receipt_retained_snapshot_base64_invalid",
                expected_bytes=evidence["bytes"], maximum_bytes=RETAINED_FILE_LIMIT,
            )
            decoded_total += len(data)
            encoded_total += len(evidence["data_base64"])
            if decoded_total > RETAINED_SOURCE_TOTAL_LIMIT:
                raise ReceiptValidationError("receipt_retained_snapshot_total_limit")
            if evidence["file_type"] != "regular" or evidence["bytes"] != len(data) or evidence["sha256"] != sha256(data):
                raise ReceiptValidationError("receipt_retained_snapshot_bytes_invalid")
            if evidence["bytes"] != maps[2][key]["bytes"] or evidence["sha256"] != maps[2][key]["sha256"]:
                raise ReceiptValidationError("receipt_retained_snapshot_binding_invalid")
            retained_sources[pathlib.Path(key)] = data
        if retained["manifest_sha256"] != snapshot_manifest_sha256(retained["files"]):
            raise ReceiptValidationError("receipt_snapshot_manifest_invalid")
        if static_problems(ROOT, retained_sources):
            raise ReceiptValidationError("receipt_retained_snapshot_contract_invalid")
    if source["snapshot_isolated"] is not (source["build_input"] == "isolated_snapshot"):
        raise ReceiptValidationError("receipt_snapshot_topology_invalid")
    build = receipt["build"]
    if source["problems"]:
        derived = "source_invalid"
    elif build["missing_tools"]:
        derived = "toolchain_unavailable"
    elif build["attempted"] and (build["outcome"] != "exited" or build["exit_code"] != 0):
        derived = "build_failed"
    elif build["attempted"] and isinstance(receipt["object"], dict) and "error" in receipt["object"]:
        derived = "object_invalid"
    elif build["attempted"] and isinstance(receipt["object"], dict):
        derived = "artifact_observed_unbound"
    else:
        raise ReceiptValidationError("receipt_state_evidence_incomplete")
    if receipt["state"] != derived:
        raise ReceiptValidationError("receipt_state_not_derived")
    if any(receipt["lifecycle"].values()) or any(receipt["claims"].values()):
        raise ReceiptValidationError("receipt_lifecycle_claim_invalid")
    for stream_name in ("stdout", "stderr"):
        stream = build[stream_name]
        if stream is None:
            continue
        retained = _decode_base64(
            stream["retained_base64"], "receipt_stream_base64_invalid",
            expected_bytes=stream["bounded_bytes"], maximum_bytes=LOG_LIMIT,
        )
        decoded_total += len(retained)
        encoded_total += len(stream["retained_base64"])
        if stream["bounded_bytes"] != len(retained) or stream["bounded_sha256"] != sha256(retained):
            raise ReceiptValidationError("receipt_stream_retained_bytes_invalid")
        if stream["truncated"]:
            if stream["bytes_total"] is not None or stream["full_sha256"] is not None or stream["evidence"] != "retained_bounded_prefix_only" or len(retained) != LOG_LIMIT:
                raise ReceiptValidationError("receipt_stream_truncation_invalid")
        elif stream["bytes_total"] != len(retained) or stream["full_sha256"] != sha256(retained) or stream["evidence"] != "retained_full_bytes":
            raise ReceiptValidationError("receipt_stream_full_bytes_invalid")
    if receipt["state"] == "artifact_observed_unbound":
        object_evidence = receipt["object"]
        object_bytes = _decode_base64(
            object_evidence["retained_base64"], "receipt_object_base64_invalid",
            expected_bytes=object_evidence["bytes"], maximum_bytes=OBJECT_LIMIT,
        )
        decoded_total += len(object_bytes)
        encoded_total += len(object_evidence["retained_base64"])
        if object_evidence["bytes"] != len(object_bytes) or object_evidence["sha256"] != sha256(object_bytes):
            raise ReceiptValidationError("receipt_object_bytes_invalid")
        if object_evidence["elf"] != parse_elf_programs(object_bytes):
            raise ReceiptValidationError("receipt_object_elf_invalid")
    if decoded_total > RECEIPT_DECODED_TOTAL_LIMIT or encoded_total > RECEIPT_ENCODED_TOTAL_LIMIT:
        raise ReceiptValidationError("receipt_cumulative_evidence_limit")
    return receipt


def validate_receipt_file(path: pathlib.Path) -> dict:
    return validate_receipt(_load_json_object(path, RECEIPT_JSON_LIMIT, "receipt_json_file_invalid"))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_file(
    root: pathlib.Path, relative: pathlib.Path, *, maximum_bytes: int = SOURCE_LIMIT,
) -> tuple[bytes, dict]:
    root = root.resolve(strict=True)
    path = root / relative
    before = path.lstat()
    resolved = path.resolve(strict=True)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or root not in resolved.parents:
        raise ValueError(f"unsafe source path: {relative.as_posix()}")
    if getattr(before, "st_reparse_tag", 0):
        raise ValueError(f"unsafe source reparse point: {relative.as_posix()}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOINHERIT", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or opened.st_size > maximum_bytes:
            raise ValueError(f"unbounded or non-regular source: {relative.as_posix()}")
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(opened) or identity(opened) != identity(after) or len(data) != opened.st_size:
        raise ValueError(f"source changed while read: {relative.as_posix()}")
    identity_record = {
        "device": int(opened.st_dev),
        "inode": int(opened.st_ino),
        "mtime_ns": int(opened.st_mtime_ns),
    }
    return data, identity_record


def regular_bytes(root: pathlib.Path, relative: pathlib.Path, *, maximum_bytes: int = SOURCE_LIMIT) -> bytes:
    return regular_file(root, relative, maximum_bytes=maximum_bytes)[0]


def capture_sources(root: pathlib.Path) -> tuple[dict[pathlib.Path, bytes], dict[pathlib.Path, dict]]:
    sources: dict[pathlib.Path, bytes] = {}
    identities: dict[pathlib.Path, dict] = {}
    for path in SOURCE_PATHS:
        data, identity = regular_file(root, path)
        if sum(map(len, sources.values())) + len(data) > RETAINED_SOURCE_TOTAL_LIMIT:
            raise ValueError("aggregate source bytes exceed retained snapshot limit")
        sources[path] = data
        identities[path] = identity
    return sources, identities


def source_evidence(sources: dict[pathlib.Path, bytes], identities: dict[pathlib.Path, dict]) -> dict:
    return {
        path.as_posix(): {
            "sha256": sha256(data),
            "bytes": len(data),
            **identities[path],
        }
        for path, data in sources.items()
    }


def materialize_snapshot(snapshot: pathlib.Path, sources: dict[pathlib.Path, bytes]) -> tuple[dict, dict]:
    os.mkdir(snapshot, 0o700)
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise ValueError("snapshot root is not an exclusively created directory")
    for relative, data in sources.items():
        target = snapshot / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(target, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short snapshot write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    snapshot_sources, snapshot_identities = capture_sources(snapshot)
    if snapshot_sources != sources:
        raise ValueError("snapshot bytes differ from captured source bytes")
    return snapshot_sources, snapshot_identities


def seal_snapshot_read_only(snapshot: pathlib.Path) -> None:
    """Best-effort OS permissions plus mandatory post-build byte/identity recheck."""
    for path in sorted(snapshot.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(snapshot, 0o555)


def static_problems(root: pathlib.Path, captured: dict[pathlib.Path, bytes] | None = None) -> list[str]:
    problems: list[str] = []
    try:
        sources = captured if captured is not None else capture_sources(root)[0]
    except (OSError, ValueError) as error:
        return [f"paths:{error}"]
    for path, pin in AUTHORITATIVE_SOURCE_PINS.items():
        data = sources[pathlib.Path(path)]
        if len(data) != pin["bytes"] or sha256(data) != pin["sha256"]:
            problems.append(f"source_policy:{path}")
    c_source = sources[C_PATH].decode("utf-8")
    c_without_comments = re.sub(r"/\*.*?\*/|//[^\r\n]*", "", c_source, flags=re.DOTALL)
    hooks = re.findall(r'SEC\s*\(\s*"lsm/([^"]+)"\s*\)\s*int\s+BPF_PROG\s*\(', c_without_comments)
    programs = re.findall(r'SEC\s*\(\s*"((?:lsm|tracepoint)/[^"]+)"\s*\)', c_without_comments)
    source_plan = re.findall(
        r'SEC\s*\(\s*"((?:lsm|tracepoint)/[^"]+)"\s*\)\s*int\s+(?:BPF_PROG\s*\(\s*)?([a-zA-Z0-9_]+)',
        c_without_comments,
    )
    if tuple(sorted(hooks)) != LSM_HOOKS or len(hooks) != 9:
        problems.append("source:exact_nine_lsm_hooks")
    if tuple(sorted(programs)) != PROGRAM_SECTIONS:
        problems.append("source:program_inventory")
    expected_source_plan = {(section, program) for section, program, _kind, _target in (*ATTACH_PLAN, *MOUNT_ATTACH_ALTERNATIVES, *MODULE_LOAD_TRACEPOINT)}
    if set(source_plan) != expected_source_plan or len(source_plan) != len(expected_source_plan):
        problems.append("source:attach_plan_binding")
    if b"minimal type stubs" not in sources[VMLINUX_PATH]:
        problems.append("source:vmlinux_stub_disclosure")

    makefile = sources[MAKEFILE_PATH].decode("utf-8")
    required_make = (
        "OBJECT_NAME := tamandua_linux.bpf.o", "OUTPUT_DIR ?=", "-target bpf",
        "toolchain_unavailable:clang>=11", "toolchain_unavailable:clang-bpf-target",
        '$(SHA256SUM)" "$(OBJECT_NAME)"', "OUTPUT_DIR cannot be the source directory",
        "does not prove compatibility with any running kernel BTF", "libbpf-bpf_helpers.h",
        "libbpf-bpf_tracing.h", "all: canonical", "verify: check-toolchain check-output-path",
        "clean: check-output-path", "No load or install target exists",
    )
    if any(marker not in makefile for marker in required_make):
        problems.append("makefile:canonical_contract")
    if re.search(r"(?m)^(install|load|vmlinux)\s*:", makefile):
        problems.append("makefile:forbidden_mutating_target")

    runtime = sources[RUNTIME_PATH].decode("utf-8")
    required_runtime = (
        "CANONICAL_EBPF_PROGRAM_SECTIONS", "preflight_canonical_ebpf_object",
        "libc::O_CLOEXEC | libc::O_NOFOLLOW", "relocatable EM_BPF ELF",
        "BPF object SHA-256 sidecar mismatch", ".load(object.bytes())",
        "canonical eBPF object preflight failed", "CANONICAL_EBPF_NON_MOUNT_LSM_ATTACH_PLAN",
        "CANONICAL_EBPF_MOUNT_LSM_ATTACH", "CANONICAL_EBPF_MOUNT_TRACEPOINT_ATTACH",
        "canonical eBPF attach coverage incomplete", "duplicate executable BPF program section",
    )
    if any(marker not in runtime for marker in required_runtime) or ".load_file(bpf_path)" in runtime:
        problems.append("runtime:fail_closed_preflight")
    rust_test = sources[RUST_TEST_PATH].decode("utf-8")
    if any(marker not in rust_test for marker in (
        "exact_program_inventory_and_sidecar_pass", "hash_sidecar_mismatch_fails_closed",
        "missing_or_unknown_program_fails_closed", "non_bpf_elf_fails_closed",
        "source_inventory_and_attach_plan_are_exactly_linked",
        "exact_and_casefold_duplicate_program_sections_fail_closed",
    )):
        problems.append("runtime:focused_tests")
    gate = sources[GATE_PATH].decode("utf-8")
    required_gate = (
        "materialize_snapshot", "snapshot_sources != sources",
        "paths:live_sources_changed_after_capture", "isolated_snapshot",
        "GetSystemDirectoryW", "termination_failed", "os.killpg",
        "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    )
    unqualified_taskkill = '["' + 'taskkill.exe"'
    if any(marker not in gate for marker in required_gate) or unqualified_taskkill in gate:
        problems.append("gate:isolated_snapshot_runner")
    return problems


class StreamingDigest:
    def __init__(self) -> None:
        self.total = 0
        self.digest = hashlib.sha256()
        self.retained = bytearray()

    def consume(self, pipe) -> None:
        while True:
            chunk = pipe.read(65536)
            if not chunk:
                return
            self.total += len(chunk)
            self.digest.update(chunk)
            if len(self.retained) < LOG_LIMIT:
                self.retained.extend(chunk[:LOG_LIMIT - len(self.retained)])

    def report(self) -> dict:
        retained = bytes(self.retained)
        truncated = self.total != len(retained)
        return {
            "bytes_total": None if truncated else self.total,
            "full_sha256": None if truncated else self.digest.hexdigest(),
            "bounded_bytes": len(retained), "bounded_sha256": sha256(retained),
            "retained_base64": base64.b64encode(retained).decode("ascii"),
            "evidence": "retained_bounded_prefix_only" if truncated else "retained_full_bytes",
            "truncated": truncated,
        }


def _windows_kill_on_close_job(process: subprocess.Popen):
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimit), ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = ExtendedLimit()
    info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    configured = kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
    assigned = configured and kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(process._handle))
    if not assigned:
        kernel32.CloseHandle(job)
        return None
    return job


def _close_windows_job(job) -> None:
    if job is not None:
        import ctypes
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(job)


def _trusted_windows_taskkill() -> pathlib.Path:
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise OSError("GetSystemDirectoryW failed")
    system_directory = pathlib.Path(buffer.value).resolve(strict=True)
    candidate = system_directory / "taskkill.exe"
    before = candidate.lstat()
    resolved = candidate.resolve(strict=True)
    if (
        resolved.parent != system_directory
        or not stat.S_ISREG(before.st_mode)
        or getattr(before, "st_reparse_tag", 0)
    ):
        raise OSError("trusted System32 taskkill.exe is unavailable")
    return resolved


def _windows_process_tree(root_pid: int) -> set[int]:
    import ctypes
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
        ]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry))
    kernel32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry))
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot in (0, -1):
        raise OSError("CreateToolhelp32Snapshot failed")
    parents: dict[int, int] = {}
    entry = ProcessEntry(); entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    tree = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in tree and pid not in tree:
                tree.add(pid); changed = True
    return tree


def _windows_pid_alive(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    handle = kernel32.OpenProcess(0x00100000, False, pid)
    if not handle:
        return False
    try:
        return kernel32.WaitForSingleObject(handle, 0) == 0x102
    finally:
        kernel32.CloseHandle(handle)


def _terminate_process_tree(process: subprocess.Popen, windows_job=None) -> bool:
    if os.name == "nt":
        try:
            targets = _windows_process_tree(process.pid)
        except OSError:
            targets = {process.pid}
            tree_inventory_complete = False
        else:
            tree_inventory_complete = True
        if windows_job is not None:
            _close_windows_job(windows_job)
            command_succeeded = True
        else:
            try:
                taskkill = _trusted_windows_taskkill()
                completed = subprocess.run(
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=10, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                command_succeeded = completed.returncode == 0
            except (OSError, subprocess.SubprocessError):
                command_succeeded = False
        deadline = __import__('time').monotonic() + 5
        while any(_windows_pid_alive(pid) for pid in targets) and __import__('time').monotonic() < deadline:
            __import__('time').sleep(0.05)
        return command_succeeded and tree_inventory_complete and not any(_windows_pid_alive(pid) for pid in targets)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return True


def run_bounded(argv: list[str], timeout: float) -> dict:
    stdout = StreamingDigest()
    stderr = StreamingDigest()
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(argv, **kwargs)
    except OSError:
        return {"outcome": "spawn_failed", "exit_code": None, "stdout": stdout.report(), "stderr": stderr.report()}
    windows_job = _windows_kill_on_close_job(process)
    readers = [
        threading.Thread(target=stdout.consume, args=(process.stdout,), daemon=True),
        threading.Thread(target=stderr.consume, args=(process.stderr,), daemon=True),
    ]
    for reader in readers:
        reader.start()
    outcome = "exited"
    try:
        exit_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        outcome = "timed_out"
        exit_code = None
        termination_confirmed = _terminate_process_tree(process, windows_job)
        windows_job = None
        if not termination_confirmed:
            outcome = "termination_failed"
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            outcome = "termination_failed"
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
    finally:
        for reader in readers:
            reader.join(timeout=15)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()
        _close_windows_job(windows_job)
    return {"outcome": outcome, "exit_code": exit_code, "stdout": stdout.report(), "stderr": stderr.report()}


def wsl_path(path: pathlib.Path) -> str:
    completed = subprocess.run(
        ["wsl.exe", "-e", "wslpath", "-a", str(path)], capture_output=True, text=True, timeout=10, check=True,
    )
    return completed.stdout.strip()


def shell_context(root: pathlib.Path) -> tuple[list[str], str] | None:
    if sys.platform.startswith("linux"):
        return ["bash", "-lc"], str(root.resolve())
    if sys.platform == "win32" and shutil.which("wsl.exe"):
        try:
            return ["wsl.exe", "-e", "bash", "-lc"], wsl_path(root.resolve())
        except (OSError, subprocess.SubprocessError):
            return None
    return None


def probe_toolchain(prefix: list[str], root_shell: str) -> tuple[dict, list[str]]:
    command = """
set -u
for tool in make clang llvm-strip llvm-readelf sha256sum; do
  path=$(command -v "$tool" 2>/dev/null || true)
  resolved=$([ -n "$path" ] && readlink -f -- "$path" 2>/dev/null || true)
  digest=$([ -n "$resolved" ] && [ -f "$resolved" ] && sha256sum -- "$resolved" 2>/dev/null | awk '{print $1}' || true)
  printf 'tool.path.%s=%s\n' "$tool" "$resolved"
  printf 'tool.sha256.%s=%s\n' "$tool" "$digest"
done
for header in bpf_helpers.h bpf_tracing.h; do
  path="/usr/include/bpf/$header"
  digest=$([ -f "$path" ] && [ ! -L "$path" ] && sha256sum -- "$path" 2>/dev/null | awk '{print $1}' || true)
  printf 'header.path.%s=%s\n' "$header" "$path"
  printf 'header.sha256.%s=%s\n' "$header" "$digest"
done
clang --version 2>/dev/null | head -n 1 || true
clang -print-targets 2>/dev/null | grep -E '(^|[[:space:]])bpf([[:space:]]|$)' | head -n 1 || true
""".strip()
    completed = subprocess.run(prefix + [f"cd {shlex.quote(root_shell)} && {command}"], capture_output=True, timeout=20)
    text = completed.stdout.decode("utf-8", "replace")
    pairs = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    tools = ("make", "clang", "llvm-strip", "llvm-readelf", "sha256sum")
    headers = ("bpf_helpers.h", "bpf_tracing.h")
    paths = {tool: pairs.get(f"tool.path.{tool}", "") for tool in tools}
    hashes = {tool: pairs.get(f"tool.sha256.{tool}", "") for tool in tools}
    libbpf_headers = {
        header: {"path": pairs.get(f"header.path.{header}", ""), "sha256": pairs.get(f"header.sha256.{header}", "")}
        for header in headers
    }
    version = next((line for line in text.splitlines() if "clang version" in line), "")
    major_match = re.search(r"clang version (\d+)\.", version)
    missing = [tool for tool in tools if not paths.get(tool) or not re.fullmatch(r"[0-9a-f]{64}", hashes.get(tool, ""))]
    missing.extend(f"libbpf-{header}" for header in headers if not re.fullmatch(r"[0-9a-f]{64}", libbpf_headers[header]["sha256"]))
    if not major_match or int(major_match.group(1)) < 11:
        missing.append("clang>=11")
    if not any(re.search(r"(^|\s)bpf(\s|$)", line) for line in text.splitlines()):
        missing.append("clang-bpf-target")
    return {"paths": paths, "sha256": hashes, "clang_version": version, "libbpf_headers": libbpf_headers}, sorted(set(missing))


def parse_elf_programs(data: bytes) -> dict:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("not ELF64 little-endian version 1")
    e_type, machine, version = struct.unpack_from("<HHI", data, 16)
    if (e_type, machine, version) != (1, 247, 1):
        raise ValueError("not relocatable EM_BPF ELF")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count, names_index = struct.unpack_from("<HHH", data, 58)
    if entry_size != 64 or not 2 <= count <= 4096 or not 0 < names_index < count:
        raise ValueError("invalid section table")
    if section_offset + entry_size * count > len(data):
        raise ValueError("section table out of bounds")
    names_header = section_offset + names_index * entry_size
    names_offset, names_size = struct.unpack_from("<QQ", data, names_header + 24)
    names = data[names_offset:names_offset + names_size]
    if len(names) != names_size:
        raise ValueError("section names out of bounds")
    sections = []
    names_casefolded = set()
    for index in range(1, count):
        header = section_offset + index * entry_size
        name_offset, section_type = struct.unpack_from("<II", data, header)
        flags = struct.unpack_from("<Q", data, header + 8)[0]
        offset, size = struct.unpack_from("<QQ", data, header + 24)
        link, info = struct.unpack_from("<II", data, header + 40)
        entry_bytes = struct.unpack_from("<Q", data, header + 56)[0]
        if name_offset >= len(names) or b"\0" not in names[name_offset:]:
            raise ValueError("invalid section name")
        name = names[name_offset:].split(b"\0", 1)[0].decode("utf-8")
        folded = name.casefold()
        if folded in names_casefolded:
            raise ValueError(f"duplicate section (case-insensitive): {name}")
        names_casefolded.add(folded)
        if section_type != 8 and (offset > len(data) or size > len(data) - offset):
            raise ValueError(f"section payload out of bounds: {name}")
        sections.append({
            "index": index, "name": name, "type": section_type, "flags": flags,
            "offset": offset, "size": size, "link": link, "info": info,
            "entry_bytes": entry_bytes,
        })
    programs = []
    executable_ranges = []
    for section in sections:
        name = section["name"]
        section_type = section["type"]
        flags = section["flags"]
        if section_type == 1 and flags & 4 and name != ".text":
            if name not in PROGRAM_SECTIONS:
                raise ValueError(f"unexpected executable section: {name}")
            if not 0 < section["size"] <= 1024 * 1024:
                raise ValueError(f"empty or unbounded executable section: {name}")
            current = (section["offset"], section["offset"] + section["size"], name)
            if any(current[0] < end and start < current[1] for start, end, _ in executable_ranges):
                raise ValueError(f"overlapping executable section: {name}")
            executable_ranges.append(current)
            programs.append(name)
    if tuple(sorted(programs)) != PROGRAM_SECTIONS or len(programs) != len(PROGRAM_SECTIONS):
        raise ValueError("program inventory mismatch")
    by_name = {section["name"]: section for section in sections}
    license_section = by_name.get("license") or by_name.get(".license")
    maps_section = by_name.get(".maps")
    if license_section is None or license_section["type"] != 1 or not 0 < license_section["size"] <= 128:
        raise ValueError("bounded license section missing")
    if maps_section is None or maps_section["type"] != 1 or not 0 < maps_section["size"] <= 1024 * 1024:
        raise ValueError("bounded maps section missing")
    symbol_tables = [section for section in sections if section["type"] == 2]
    if len(symbol_tables) != 1:
        raise ValueError("exactly one symbol table is required")
    symbols = symbol_tables[0]
    if symbols["entry_bytes"] != 24 or symbols["size"] < 24 or symbols["size"] % 24:
        raise ValueError("invalid symbol table shape")
    if not 0 < symbols["link"] < count:
        raise ValueError("symbol string table link is invalid")
    linked = next((section for section in sections if section["index"] == symbols["link"]), None)
    if linked is None or linked["type"] != 3 or linked["size"] == 0:
        raise ValueError("symbol string table is missing")
    program_indices = {section["index"] for section in sections if section["name"] in PROGRAM_SECTIONS}
    relocation_targets = set()
    for section in sections:
        if section["type"] not in (4, 9):
            continue
        expected_entry = 24 if section["type"] == 4 else 16
        if section["entry_bytes"] != expected_entry or section["size"] == 0 or section["size"] % expected_entry:
            raise ValueError(f"invalid relocation section: {section['name']}")
        if section["link"] != symbols["index"] or section["info"] not in program_indices:
            raise ValueError(f"relocation target is not closed: {section['name']}")
        if section["info"] in relocation_targets:
            raise ValueError("duplicate relocation target")
        relocation_targets.add(section["info"])
    if relocation_targets != program_indices:
        raise ValueError("relocation coverage is incomplete")
    return {
        "class": "ELF64", "endianness": "little", "type": "ET_REL", "machine": "EM_BPF",
        "program_sections": programs,
        "structural_checks": {
            "executable_payloads": "nonempty_bounded_in_file_nonoverlapping",
            "symbols": "single_bounded_linked_symtab",
            "relocations": "bounded_exact_program_targets",
            "license": "present_bounded",
            "maps": "present_bounded",
            "kernel_verifier": "unexecuted",
        },
    }


def run(root: pathlib.Path = ROOT, after_capture: Callable[[pathlib.Path], None] | None = None) -> dict:
    observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        root = root.resolve(strict=True)
        captured, captured_identities = capture_sources(root)
        files = source_evidence(captured, captured_identities)
        capture_error = None
    except (OSError, ValueError) as error:
        captured, captured_identities, files = {}, {}, {}
        capture_error = f"paths:{error}"
    receipt = {
        "schema_version": "tamandua.anti_cheat_linux_ebpf_object_build/v1",
        "evidence_class": "local_source_build_preflight", "observed_at": observed_at,
        "state": "source_invalid", "source": {
            "source_policy_sha256": SOURCE_POLICY_SHA256,
            "validator_authority_external": False,
            "files": files,
            "live_post_files": {},
            "snapshot_files": {},
            "retained_snapshot": None,
            "snapshot_isolated": False,
            "live_sources_unchanged": False,
            "build_input": "none",
            "lsm_hooks": list(LSM_HOOKS), "program_sections": list(PROGRAM_SECTIONS),
            "attach_plan": {
                "required_non_mount": [list(entry) for entry in ATTACH_PLAN],
                "mount_alternatives": [list(entry) for entry in MOUNT_ATTACH_ALTERNATIVES],
                "required_attach_count": 9,
            },
            "vmlinux_header_role": "development_compile_stub_not_kernel_btf_proof",
        },
        "build": {"attempted": False, "outcome": "not_attempted", "isolated_output": True, "toolchain": {}, "missing_tools": [], "exit_code": None, "stdout": None, "stderr": None},
        "object": None,
        "lifecycle": {key: False for key in ("verifier_executed", "loaded", "attached", "privileged", "kernel_mutated", "deployed")},
        "claims": {key: False for key in FALSE_CLAIMS}, "blockers": list(BLOCKERS),
    }
    problems = [capture_error] if capture_error else static_problems(root, captured)
    if problems:
        receipt["source"]["problems"] = problems
        return validate_receipt(receipt)
    receipt["source"]["problems"] = []
    with tempfile.TemporaryDirectory(prefix="tamandua-ebpf-workspace-") as temporary:
        workspace = pathlib.Path(temporary).resolve(strict=True)
        if workspace == root or root in workspace.parents or workspace in root.parents:
            receipt["source"]["problems"] = ["snapshot:not_outside_repository"]
            return validate_receipt(receipt)
        snapshot = workspace / "source"
        output = workspace / "output"
        try:
            snapshot_sources, snapshot_identities = materialize_snapshot(snapshot, captured)
            receipt["source"]["snapshot_files"] = source_evidence(snapshot_sources, snapshot_identities)
            receipt["source"]["retained_snapshot"] = retained_snapshot_evidence(snapshot_sources)
            seal_snapshot_read_only(snapshot)
            for path in SOURCE_PATHS:
                live_identity = (captured_identities[path]["device"], captured_identities[path]["inode"])
                snapshot_identity = (snapshot_identities[path]["device"], snapshot_identities[path]["inode"])
                if live_identity == (0, 0) or snapshot_identity == (0, 0) or live_identity == snapshot_identity:
                    receipt["source"]["problems"] = [f"snapshot:identity_not_isolated:{path.as_posix()}"]
                    return validate_receipt(receipt)
            receipt["source"]["snapshot_isolated"] = True
            receipt["source"]["build_input"] = "isolated_snapshot"
            if after_capture is not None:
                after_capture(root)
            live_post, live_post_identities = capture_sources(root)
            receipt["source"]["live_post_files"] = source_evidence(live_post, live_post_identities)
        except (OSError, ValueError) as error:
            receipt["source"]["problems"] = [f"snapshot:{error}"]
            return validate_receipt(receipt)
        if live_post != captured or live_post_identities != captured_identities:
            receipt["source"]["problems"] = ["paths:live_sources_changed_after_capture"]
            return validate_receipt(receipt)
        receipt["source"]["live_sources_unchanged"] = True

        context = shell_context(snapshot)
        if context is None:
            receipt["state"] = "toolchain_unavailable"
            receipt["build"]["missing_tools"] = ["linux_or_wsl_shell"]
            return validate_receipt(receipt)
        prefix, snapshot_shell = context
        try:
            toolchain, missing = probe_toolchain(prefix, snapshot_shell)
        except (OSError, subprocess.SubprocessError) as error:
            receipt["state"] = "toolchain_unavailable"
            receipt["build"]["missing_tools"] = [f"toolchain_probe:{type(error).__name__}"]
            return validate_receipt(receipt)
        receipt["build"]["missing_tools"] = missing
        if missing:
            receipt["build"]["toolchain"] = {}
            receipt["state"] = "toolchain_unavailable"
            return validate_receipt(receipt)
        receipt["build"]["toolchain"] = toolchain

        output_shell = str(output)
        if sys.platform == "win32":
            output_shell = wsl_path(output)
        paths = toolchain["paths"]
        command = (
            f"{shlex.quote(paths['make'])} -f {shlex.quote(snapshot_shell + '/apps/tamandua_agent/bpf/Makefile')} "
            f"canonical OUTPUT_DIR={shlex.quote(output_shell)} "
            f"CLANG={shlex.quote(paths['clang'])} LLVM_STRIP={shlex.quote(paths['llvm-strip'])} "
            f"LLVM_READELF={shlex.quote(paths['llvm-readelf'])} SHA256SUM={shlex.quote(paths['sha256sum'])}"
        )
        completed = run_bounded(prefix + [f"cd {shlex.quote(snapshot_shell)} && {command}"], timeout=120)
        receipt["build"].update({
            "attempted": True, "outcome": completed["outcome"], "exit_code": completed["exit_code"],
            "stdout": completed["stdout"], "stderr": completed["stderr"],
        })
        if completed["outcome"] != "exited" or completed["exit_code"] != 0:
            receipt["state"] = "build_failed"
            return validate_receipt(receipt)
        try:
            snapshot_post, snapshot_post_identities = capture_sources(snapshot)
            post_toolchain, post_missing = probe_toolchain(prefix, snapshot_shell)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            receipt["state"] = "source_invalid"
            receipt["source"]["problems"] = [f"post_build_recheck:{type(error).__name__}"]
            return validate_receipt(receipt)
        if (
            snapshot_post != snapshot_sources
            or snapshot_post_identities != snapshot_identities
            or post_missing
            or post_toolchain != toolchain
        ):
            receipt["state"] = "source_invalid"
            receipt["source"]["problems"] = ["post_build_source_or_toolchain_drift"]
            return validate_receipt(receipt)
        object_path = output / "tamandua_linux.bpf.o"
        sidecar_path = output / "tamandua_linux.bpf.o.sha256"
        try:
            data = regular_bytes(output, pathlib.Path(object_path.name), maximum_bytes=OBJECT_LIMIT)
            digest = sha256(data)
            sidecar = regular_bytes(output, pathlib.Path(sidecar_path.name)).decode("utf-8")
            if sidecar != f"{digest}  tamandua_linux.bpf.o\n":
                raise ValueError("hash sidecar mismatch")
            elf = parse_elf_programs(data)
        except (OSError, UnicodeError, ValueError) as error:
            receipt["state"] = "object_invalid"
            receipt["object"] = {"error": str(error)}
            return validate_receipt(receipt)
        receipt["state"] = "artifact_observed_unbound"
        receipt["object"] = {
            "filename": object_path.name, "sha256": digest, "bytes": len(data),
            "retained_base64": base64.b64encode(data).decode("ascii"), "elf": elf,
        }
        return validate_receipt(receipt)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    receipt = run(args.root)
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if receipt["state"] in {"artifact_observed_unbound", "toolchain_unavailable"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
