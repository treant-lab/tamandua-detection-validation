#!/usr/bin/env python3
"""Validate closed capability receipts and the detached probe source contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    from pip._vendor import tomli as tomllib


ROOT = Path(__file__).resolve().parents[3]
MAX_JSON_BYTES = 64 * 1024
EXPECTED_CARGO_LOCK_SHA256 = "e9c2882946a4e33eef1eebd9dd103fc94077536ff67f9239224b3a2c237edaea"
CARGO_LOCK_DIGEST_UPDATE_WORKFLOW = "regenerate_lock_review_dependency_diff_then_update_expected_sha256"
TOP = {"schema_version", "evidence_class", "observed_at", "platform", "probe", "state", "error_code", "capabilities", "execution", "binding", "authorization", "claims"}
CAPS = {"protocol_version", "driver_version_major", "driver_version_minor", "driver_version_patch", "lab_level", "capability_flags", "active_flags", "health_flags", "compiled_control_flags", "active_control_flags", "invariant_flags", "command_policy_flags", "disabled_subsystem_flags", "read_only_command_flags"}
EXECUTION = {"isolation", "timeout_ms", "deadline_outcome", "containment"}
AUTHORIZATION = {"driver_lifecycle_mutation_requested", "driver_lifecycle_mutation_authorized"}
CLAIMS = {"runtime_validated", "efficacy_validated", "production_ready", "external_claim_allowed"}
STATES = {"observed_unbound", "not_loaded", "connection_failed", "invalid_protocol", "timed_out"}
ERRORS = {None, "port_absent", "connection_failed", "unsupported_runner", "invalid_protocol", "thread_spawn_failed", "supervisor_channel_disconnected", "timeout_process_exit_required"}


class DuplicateKey(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(f"duplicate key: {key}")
        result[key] = value
    return result


def load_json(path: Path):
    payload = path.read_bytes()
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError("json exceeds 64 KiB limit")
    return json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs)


def _closed(value, fields, name, errors):
    if not isinstance(value, dict):
        errors.append(f"{name}:object_required")
        return False
    if set(value) != fields:
        errors.append(f"{name}:fields")
        return False
    return True


def _u32(value) -> bool:
    return type(value) is int and 0 <= value <= 0xFFFF_FFFF


def validate_receipt(receipt) -> list[str]:
    errors: list[str] = []
    if not _closed(receipt, TOP, "receipt", errors):
        return errors
    if receipt["schema_version"] != 1:
        errors.append("schema_version")
    if type(receipt["evidence_class"]) is not str or receipt["evidence_class"] not in {"synthetic_contract", "local_probe_observation"}:
        errors.append("evidence_class")
    try:
        if not isinstance(receipt["observed_at"], str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", receipt["observed_at"]) is None:
            raise ValueError("timestamp shape")
        datetime.strptime(receipt["observed_at"], "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        errors.append("observed_at")
    if type(receipt["platform"]) is not str or receipt["platform"] not in {"windows", "non_windows"}:
        errors.append("platform")
    if receipt["probe"] != "anti_cheat_windows_driver_capability_probe":
        errors.append("probe")
    state, error, caps = receipt["state"], receipt["error_code"], receipt["capabilities"]
    if type(state) is not str or state not in STATES:
        errors.append("state")
    if error is not None and (type(error) is not str or error not in ERRORS):
        errors.append("error_code")
    expected = {
        "observed_unbound": (None, True),
        "not_loaded": ("port_absent", False),
    }
    if type(state) is str and state in expected and (error != expected[state][0] or (caps is not None) != expected[state][1]):
        errors.append("state_consistency")
    if state in {"observed_unbound", "not_loaded"} and receipt["platform"] != "windows":
        errors.append("state_platform")
    if state == "connection_failed" and (error not in {"connection_failed", "unsupported_runner", "thread_spawn_failed"} or caps is not None):
        errors.append("state_consistency")
    if state == "invalid_protocol" and (error not in {"invalid_protocol", "supervisor_channel_disconnected"} or caps is not None):
        errors.append("state_consistency")
    if state == "timed_out" and (error != "timeout_process_exit_required" or caps is not None):
        errors.append("state_consistency")
    if error == "unsupported_runner" and receipt["platform"] != "non_windows":
        errors.append("unsupported_runner_platform")
    if error == "unsupported_runner" and (state, error) != ("connection_failed", "unsupported_runner"):
        errors.append("non_windows_state")
    if error == "connection_failed" and receipt["platform"] != "windows":
        errors.append("connection_failed_platform")
    if error == "invalid_protocol" and receipt["platform"] != "windows":
        errors.append("invalid_protocol_platform")
    if caps is not None:
        if _closed(caps, CAPS, "capabilities", errors):
            if any(not _u32(caps[field]) for field in CAPS):
                errors.append("capabilities:u32")
            exact = {"protocol_version": 2, "capability_flags": 0, "active_flags": 0, "compiled_control_flags": 0, "active_control_flags": 0, "invariant_flags": 0xFF, "command_policy_flags": 3, "disabled_subsystem_flags": 0x1F, "read_only_command_flags": 0x1F}
            if any(caps.get(key) != value for key, value in exact.items()):
                errors.append("capabilities:contract")
            if type(caps.get("health_flags")) is not int or caps["health_flags"] & ~0x0F:
                errors.append("capabilities:health_bits")
    execution = receipt["execution"]
    if _closed(execution, EXECUTION, "execution", errors):
        if execution["timeout_ms"] != 2000:
            errors.append("execution:timeout")
        allowed_execution = {
            "isolation": {"in_process_thread", "not_started"},
            "deadline_outcome": {"completed_before_deadline", "timeout", "thread_spawn_failed", "channel_disconnected"},
            "containment": {"not_required", "process_exit_required"},
        }
        if any(type(execution[key]) is not str or execution[key] not in values for key, values in allowed_execution.items()):
            errors.append("execution:categorical")
        completed = {"isolation": "in_process_thread", "timeout_ms": 2000, "deadline_outcome": "completed_before_deadline", "containment": "not_required"}
        if state == "timed_out":
            if execution != {"isolation": "in_process_thread", "timeout_ms": 2000, "deadline_outcome": "timeout", "containment": "process_exit_required"}:
                errors.append("execution:timeout_consistency")
        elif error == "thread_spawn_failed":
            if execution != {"isolation": "not_started", "timeout_ms": 2000, "deadline_outcome": "thread_spawn_failed", "containment": "not_required"}:
                errors.append("execution:spawn")
        elif error == "supervisor_channel_disconnected":
            if execution != {"isolation": "in_process_thread", "timeout_ms": 2000, "deadline_outcome": "channel_disconnected", "containment": "not_required"}:
                errors.append("execution:channel_disconnected")
        elif execution != completed:
            errors.append("execution:completed_consistency")
    if _closed(receipt["binding"], {"bound", "loaded_artifact_digest", "reason"}, "binding", errors):
        if receipt["binding"] != {"bound": False, "loaded_artifact_digest": None, "reason": "loaded_artifact_digest_unbound"}:
            errors.append("binding:unbound_required")
    if _closed(receipt["authorization"], AUTHORIZATION, "authorization", errors):
        if any(value is not False for value in receipt["authorization"].values()):
            errors.append("authorization:false_required")
    if _closed(receipt["claims"], CLAIMS, "claims", errors):
        if any(value is not False for value in receipt["claims"].values()):
            errors.append("claims:false_required")
    return errors


def _macro(text: str, name: str) -> int | None:
    match = re.search(rf"^#define\s+{re.escape(name)}\s+(0x[0-9A-Fa-f]+|\d+)\b", text, re.MULTILINE)
    return int(match.group(1), 0) if match else None


def _rust_const(text: str, name: str) -> int | None:
    match = re.search(rf"(?:pub )?const {re.escape(name)}:\s*(?:u8|u32|u64|usize)\s*=\s*(0x[0-9A-Fa-f_]+|[0-9_]+);", text)
    return int(match.group(1).replace("_", ""), 0) if match else None


def _toml_section(text: str, header: str) -> str:
    match = re.search(rf"^\[{re.escape(header)}\]\s*(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def validate_source_contract(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    crate = root / "tools/anti_cheat_windows_driver_capability_probe"
    cargo = (crate / "Cargo.toml").read_text(encoding="utf-8")
    cargo_data = tomllib.loads(cargo)
    lock_bytes = (crate / "Cargo.lock").read_bytes()
    lock_data = tomllib.loads(lock_bytes.decode("utf-8"))
    main = (crate / "src/main.rs").read_text(encoding="utf-8")
    protocol = (crate / "src/protocol.rs").read_text(encoding="utf-8")
    source_files = sorted(path for path in (crate / "src").rglob("*") if path.is_file())
    rust_sources = [path.read_text(encoding="utf-8") for path in source_files]
    authored_crate_files = {
        path.relative_to(crate).as_posix()
        for path in crate.rglob("*")
        if path.is_file() and path.relative_to(crate).parts[0] != "target"
    }
    kernel = (root / "apps/tamandua_driver/src/tamandua.h").read_text(encoding="utf-8")
    user = (root / "apps/tamandua_driver/src/usermode_api.h").read_text(encoding="utf-8")
    schema = load_json(root / "schemas/anti_cheat_windows_driver_capability_receipt_v1.schema.json")

    if "[workspace]" not in cargo or (crate / "build.rs").exists() or "tamandua" in cargo.lower().replace("anti-cheat-windows-driver-capability-probe", ""):
        errors.append("crate:standalone")
    if {path.relative_to(crate / "src").as_posix() for path in source_files} != {"main.rs", "protocol.rs"}:
        errors.append("source:file_set")
    if authored_crate_files != {"Cargo.toml", "Cargo.lock", "src/main.rs", "src/protocol.rs"}:
        errors.append("source:crate_file_set")
    dependencies = cargo_data.get("dependencies", {})
    package = cargo_data.get("package", {})
    targets = cargo_data.get("target", {})
    windows_table = targets.get("cfg(windows)", {})
    windows_dependencies = windows_table.get("dependencies", {})
    windows_spec = windows_dependencies.get("windows", {})
    root_lock = next((package for package in lock_data.get("package", []) if package.get("name") == "anti-cheat-windows-driver-capability-probe"), None)
    expected_lock_packages = {
        "anti-cheat-windows-driver-capability-probe", "itoa", "memchr", "proc-macro2",
        "quote", "serde", "serde_core", "serde_derive", "serde_json", "syn",
        "unicode-ident", "windows", "windows-core", "windows-targets",
        "windows_aarch64_gnullvm", "windows_aarch64_msvc", "windows_i686_gnu",
        "windows_i686_gnullvm", "windows_i686_msvc", "windows_x86_64_gnu",
        "windows_x86_64_gnullvm", "windows_x86_64_msvc", "zmij",
    }
    lock_packages = lock_data.get("package", [])
    cargo_ok = (
        set(cargo_data) == {"package", "workspace", "dependencies", "target"}
        and package == {
            "name": "anti-cheat-windows-driver-capability-probe",
            "version": "0.1.0",
            "edition": "2021",
            "publish": False,
        }
        and set(dependencies) == {"serde", "serde_json"}
        and dependencies.get("serde") == {"version": "1.0", "features": ["derive"]}
        and dependencies.get("serde_json") == "1.0"
        and set(targets) == {"cfg(windows)"}
        and set(windows_table) == {"dependencies"}
        and set(windows_dependencies) == {"windows"}
        and set(windows_spec) == {"version", "features"}
        and windows_spec.get("version") == "0.52"
        and set(windows_spec.get("features", [])) == {"Win32_Foundation", "Win32_Security", "Win32_Storage_InstallableFileSystems"}
        and not any(key in cargo_data for key in ("build-dependencies", "dev-dependencies"))
        and cargo_data.get("workspace") == {}
        and root_lock is not None
        and set(root_lock.get("dependencies", [])) == {"serde", "serde_json", "windows"}
        and lock_data.get("version") == 4
        and [package.get("name") for package in lock_packages].count("anti-cheat-windows-driver-capability-probe") == 1
        and {package.get("name") for package in lock_packages} == expected_lock_packages
        and all("tamandua" not in package.get("name", "").lower() for package in lock_packages)
        and hashlib.sha256(lock_bytes).hexdigest() == EXPECTED_CARGO_LOCK_SHA256
    )
    if not cargo_ok:
        errors.append("crate:dependencies")
    rust_source = "\n".join(rust_sources)
    rust_code = rust_source
    if any(token in rust_source for token in ("//", "/*", "*/")):
        errors.append("source:comment_tokens_forbidden")
    if re.search(r"\b(?:r|br)\#*\"", rust_source):
        errors.append("source:raw_string_forbidden")
    if any(len(re.findall(rf"\b{symbol}\s*\(", rust_code)) != 1 for symbol in ("FilterConnectCommunicationPort", "FilterSendMessage", "CloseHandle")):
        errors.append("source:single_operation")
    windows_imports = {line.strip() for line in main.splitlines() if line.strip().startswith("use windows")}
    expected_imports = {
        "use windows::core::PCWSTR;",
        "use windows::Win32::Foundation::CloseHandle;",
        "use windows::Win32::Storage::InstallableFileSystems::FilterConnectCommunicationPort;",
        "use windows::Win32::Storage::InstallableFileSystems::FilterSendMessage;",
    }
    rust_without_imports = rust_source
    for item in expected_imports:
        rust_without_imports = rust_without_imports.replace(item, "", 1)
    operation_symbols = "FilterConnectCommunicationPort|FilterSendMessage|CloseHandle"
    indirect_operation = re.search(rf"\b(?:let|const|static)\s+\w+[^;=]*=\s*(?:{operation_symbols})\s*;", rust_code)
    operation_alias = re.search(rf"\b(?:pub\s+)?use\b[^;]*(?:{operation_symbols})[^;]*\bas\b", rust_code)
    windows_alias = re.search(r"\buse\s+windows\s+as\b", rust_code)
    if windows_imports != expected_imports or any(" as " in item for item in windows_imports) or "windows::" in rust_without_imports:
        errors.append("source:api_imports")
    if len(re.findall(r"\bunsafe\s*\{", main)) != 3 or indirect_operation or operation_alias or windows_alias or re.search(r"\bmacro_rules\s*!", rust_code):
        errors.append("source:api_allowlist")
    accounted = rust_code
    accounting_ok = True
    for import_line in expected_imports:
        if accounted.count(import_line) != 1:
            accounting_ok = False
        accounted = accounted.replace(import_line, "", 1)
    for symbol in ("FilterConnectCommunicationPort", "FilterSendMessage", "CloseHandle"):
        accounted, count = re.subn(rf"\b{symbol}\s*\(", "(", accounted, count=1)
        if count != 1:
            accounting_ok = False
    if not accounting_ok or re.search(r"\b(?:FilterConnectCommunicationPort|FilterSendMessage|CloseHandle)\b", accounted):
        errors.append("source:sensitive_symbol_accounting")
    external_modules = re.findall(r"^\s*mod\s+\w+\s*;", rust_code, re.MULTILINE)
    expansion_or_macro = re.search(r"\b(?:include|include_str|include_bytes|macro_rules|asm|global_asm)\s*!", rust_code)
    path_attribute = re.search(r"#\s*\[\s*path\b", rust_code)
    if external_modules != ["mod protocol;"] or expansion_or_macro or path_attribute:
        errors.append("source:expansion")
    ffi_tokens = re.search(r"\bextern\b|#\s*\[\s*(?:link|link_name|no_mangle)\b", rust_code)
    unsafe_escape = re.search(r"\b(?:transmute|GetProcAddress|LoadLibrary|libloading|windows_sys|winapi)\b", rust_code)
    unsafe_matches = list(re.finditer(r"\bunsafe\b", rust_code))
    unsafe_heads = []
    for match in unsafe_matches:
        head = re.match(r"unsafe\s*\{\s*(FilterConnectCommunicationPort|FilterSendMessage|let\s+_\s*=\s*CloseHandle)\s*\(", rust_code[match.start():])
        unsafe_heads.append(re.sub(r"\s+", "", head.group(1)) if head else None)
    compact_unsafe = re.sub(r"\s+", "", rust_code)
    exact_unsafe_blocks = (
        "unsafe{FilterConnectCommunicationPort(PCWSTR(port.as_ptr()),0,None,0,None)}",
        "unsafe{FilterSendMessage(handle,request.as_ptr().cast::<c_void>(),request.len()asu32,Some(response.as_mut_ptr().cast::<c_void>()),response.len()asu32,&mutreturned,)}",
        "unsafe{let_=CloseHandle(handle);}",
    )
    canonical_unsafe = len(unsafe_matches) == 3 and set(unsafe_heads) == {"FilterConnectCommunicationPort", "FilterSendMessage", "let_=CloseHandle"} and all(compact_unsafe.count(block) == 1 for block in exact_unsafe_blocks)
    if ffi_tokens or unsafe_escape or re.search(r"\bunsafe\s+fn\b", rust_code) or not canonical_unsafe:
        errors.append("source:ffi_or_unsafe_escape")
    forbidden = (
        "std::fs", "std::net", "fs::", "reqwest",
        "TcpStream", "OpenSCManager", "CreateService", "StartService", "DeleteService",
        "ControlService", "FilterLoad", "FilterUnload", "fltmc", "pub use", "std::process",
        "Command", "current_exe", "wait_with_output", "worker",
    )
    operation_audit_code = rust_code
    compact_operation_code = re.sub(r"\s+", "", operation_audit_code)
    sensitive_calls = set(re.findall(r"\b(Filter[A-Z]\w*|OpenSCManager\w*|CreateService\w*|StartService\w*|DeleteService\w*|ControlService\w*)\s*\(", rust_code))
    grouped_alias = re.search(r"use\s+std::\{[^}]*(?:process|fs)\s+as\b", operation_audit_code)
    compact_forbidden = tuple(re.sub(r"\s+", "", token) for token in forbidden)
    if any(token in compact_operation_code for token in compact_forbidden) or grouped_alias or not sensitive_calls <= {"FilterConnectCommunicationPort", "FilterSendMessage"}:
        errors.append("source:forbidden_operation")
    supervisor_constants = {"OPERATION_TIMEOUT_MS": 2000}
    canonical_imports = (
        "use std::sync::mpsc::{sync_channel, RecvTimeoutError};",
        "use std::thread::Builder;",
        "use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};",
    )
    library_audit = rust_code
    for canonical_import in canonical_imports:
        library_audit = library_audit.replace(canonical_import, "", 1)
    process_policy_ok = (
        not re.search(r"\b(?:std\s*::\s*)?process\s*::|\bCommand\b|\bChild\b|\bStdio\b", rust_code)
        and not re.search(r"\bstd\s*::\s*env\s*::|\bargs(?:_os)?\s*\(", main)
        and not re.search(r"\bstd\s*::\s*(?:thread|sync)\s*::", library_audit)
        and not re.search(r"\buse\s+std\s*::\s*(?:thread|sync)\b|\buse\s+std\s*::\s*\{[^}]*(?:thread|sync)\b", library_audit)
        and not re.search(r"\b(?:JoinHandle|join|park|sleep|wait|recv)\s*(?:::|\()|\b(?:mem\s*::\s*forget|forget|Box\s*::\s*leak)\s*\(", rust_code)
        and "worker" not in main.lower()
    )
    output_sink_escape = re.search(
        r"\bstd\s*::\s*(?:io\b|\{[^}]*\bio\b)"
        r"|\b(?:stdout|stderr|Write|write|writeln|format_args|_print)\b"
        r"|\b(?:print|eprint|eprintln|dbg|write|writeln|format_args)\s*!",
        rust_code,
    )
    compact_supervisor = re.sub(r"\s+", "", main)
    deadline_index = main.find("let deadline = Instant::now() + Duration::from_millis(OPERATION_TIMEOUT_MS);")
    channel_index = main.find("let (sender, receiver) = sync_channel(1);")
    spawn_index = main.find("Builder::new().spawn(move ||")
    remaining_index = main.find("let remaining = deadline.saturating_duration_since(Instant::now());")
    receive_index = main.find("receiver.recv_timeout(remaining)")
    supervisor_calls_ok = (
        all(rust_code.count(item) == 1 for item in canonical_imports)
        and process_policy_ok
        and all(_rust_const(main, name) == value for name, value in supervisor_constants.items())
        and len(re.findall(r"\bprobe_once\b", main)) == 3
        and len(re.findall(r"#\[cfg\((?:windows|not\(windows\))\)\]\s*fn\s+probe_once\s*\(\s*\)\s*->\s*ProbeOutcome", main)) == 2
        and main.count("Builder::new()") == 1
        and main.count("Builder::new().spawn(move ||") == 1
        and len(re.findall(r"(?:\.|::)\s*spawn\s*\(", main)) == 1
        and main.count("sync_channel(1)") == 1
        and main.count("sender.send(probe_once())") == 1
        and main.count("receiver.recv_timeout(remaining)") == 1
        and len(re.findall(r"\bprintln\s*!", rust_code)) == 1
        and not re.search(r"\b(?:print|eprint|eprintln|dbg)\s*!", rust_code)
        and output_sink_escape is None
        and "fnmain(){emit_public(supervise());}" in compact_supervisor
        and len(re.findall(r"\bfn\s+emit_public\b", main)) == 1
        and len(re.findall(r"\bfn\s+main\s*\(", main)) == 1
    )
    deadline_order_ok = (
        "fn deadline_reached(now: Instant, deadline: Instant) -> bool" in main
        and "now >= deadline" in main
        and -1 < deadline_index < channel_index < spawn_index < remaining_index < receive_index
        and compact_supervisor.count(
            "matchreceiver.recv_timeout(remaining){"
            "Ok(_outcome)ifdeadline_reached(Instant::now(),deadline)=>{receipt(ProbeOutcome::TimedOut,timeout_execution())}"
            "Ok(outcome)=>receipt(outcome,completed_execution()),"
            "Err(RecvTimeoutError::Timeout)=>receipt(ProbeOutcome::TimedOut,timeout_execution()),"
            "Err(RecvTimeoutError::Disconnected)=>{receipt(ProbeOutcome::ChannelDisconnected,disconnected_execution())}"
            "}"
        ) == 1
    )
    emit_match = re.search(
        r"(fn\s+emit_public\s*\(\s*receipt\s*:\s*Receipt\s*\)\s*\{.*?\n\})\s*fn\s+main\s*\(\s*\)",
        main,
        re.DOTALL,
    )
    expected_emit = (
        'fnemit_public(receipt:Receipt){'
        'letoutput=serde_json::to_string(&receipt).expect("receiptserializationisinfallible");'
        'println!("{output}");'
        '}'
    )
    if not emit_match or re.sub(r"\s+", "", emit_match.group(1)) != expected_emit:
        errors.append("source:public_emitter")
    if not supervisor_calls_ok or not deadline_order_ok:
        errors.append("source:supervisor_contract")
    receipt_contract_ok = (
        all(token in main for token in (
            'isolation: "in_process_thread"',
            'deadline_outcome: "timeout"',
            'containment: "process_exit_required"',
            'Some("timeout_process_exit_required")',
            'Some("thread_spawn_failed")',
            'Some("supervisor_channel_disconnected")',
        ))
        and not any(token in main for token in ("worker_termination", "timeout_confirmed", "timeout_cleanup_unconfirmed"))
    )
    if not receipt_contract_ok:
        errors.append("source:receipt_contract_parity")
    if r'"\\TamanduaPort\0"' not in main or "protocol::request_bytes()" not in main:
        errors.append("source:fixed_request")
    if (
        "fn main()" not in main
        or "emit_public(supervise());" not in main
        or "0x8007_0002 | 0x8007_0003" not in main
    ):
        errors.append("source:outcomes")

    parity = {
        "GET_CAPABILITIES": _macro(user, "TAMANDUA_CMD_GET_CAPABILITIES"),
        "RESPONSE_DATA": _macro(user, "TAMANDUA_RESP_DATA"),
        "PROTOCOL_V2": _macro(kernel, "TAMANDUA_CAPABILITY_CONTRACT_VERSION_V2"),
        "INVARIANTS_ALL": _macro(kernel, "TAMANDUA_OBSERVE_INVARIANTS_ALL"),
        "COMMAND_POLICY_ALL": _macro(kernel, "TAMANDUA_OBSERVE_COMMAND_POLICY_ALL"),
        "DISABLED_SUBSYSTEMS_ALL": _macro(kernel, "TAMANDUA_OBSERVE_DISABLED_SUBSYSTEMS_ALL"),
        "READ_ONLY_COMMANDS_ALL": _macro(kernel, "TAMANDUA_OBSERVE_READ_ONLY_COMMANDS_ALL"),
    }
    if any(value is None or _rust_const(protocol, name) != value for name, value in parity.items()):
        errors.append("wire:constant_parity")
    shared_capability_macros = {
        "PROTOCOL_V2": "TAMANDUA_CAPABILITY_CONTRACT_VERSION_V2",
        "INVARIANTS_ALL": "TAMANDUA_OBSERVE_INVARIANTS_ALL",
        "COMMAND_POLICY_ALL": "TAMANDUA_OBSERVE_COMMAND_POLICY_ALL",
        "DISABLED_SUBSYSTEMS_ALL": "TAMANDUA_OBSERVE_DISABLED_SUBSYSTEMS_ALL",
        "READ_ONLY_COMMANDS_ALL": "TAMANDUA_OBSERVE_READ_ONLY_COMMANDS_ALL",
    }
    if any(
        _macro(kernel, macro) is None
        or _macro(kernel, macro) != _macro(user, macro)
        or _rust_const(protocol, rust_name) != _macro(kernel, macro)
        for rust_name, macro in shared_capability_macros.items()
    ):
        errors.append("wire:header_parity")
    if _rust_const(protocol, "REQUEST_LEN") != 16 or _rust_const(protocol, "RESPONSE_LEN") != 80 or _rust_const(protocol, "CAPABILITY_DATA_LEN") != 64:
        errors.append("wire:lengths")
    expected_kernel = ["ProtocolVersion", "DriverVersionMajor", "DriverVersionMinor", "DriverVersionPatch", "LabLevel", "CapabilityFlags", "ActiveFlags", "HealthFlags", "Reserved[8]"]
    kernel_struct = re.search(r"typedef struct _TAMANDUA_CAPABILITIES \{(.*?)\} TAMANDUA_CAPABILITIES", kernel, re.DOTALL)
    user_struct = re.search(r"typedef struct _TAMANDUA_CAPABILITIES_RESPONSE \{(.*?)\} TAMANDUA_CAPABILITIES_RESPONSE", user, re.DOTALL)
    fields = lambda body: re.findall(r"\bULONG\s+(\w+(?:\[\d+\])?)\s*;", body)
    if not kernel_struct or fields(kernel_struct.group(1)) != expected_kernel or not user_struct or fields(user_struct.group(1)) != expected_kernel:
        errors.append("wire:abi")
    definitions = schema.get("$defs", {})
    if schema.get("additionalProperties") is not False or any(definition.get("additionalProperties") is not False for definition in definitions.values() if definition.get("type") == "object"):
        errors.append("schema:closed")
    schema_caps = definitions.get("capabilities", {})
    schema_auth = definitions.get("authorization", {})
    schema_claims = definitions.get("claims", {})
    schema_execution = definitions.get("execution", {})
    schema_exact = {
        "protocol_version": 2, "capability_flags": 0, "active_flags": 0,
        "compiled_control_flags": 0, "active_control_flags": 0,
        "invariant_flags": 0xFF, "command_policy_flags": 3,
        "disabled_subsystem_flags": 0x1F, "read_only_command_flags": 0x1F,
    }
    if (
        set(schema.get("required", [])) != TOP
        or set(schema.get("properties", {})) != TOP
        or set(schema_caps.get("required", [])) != CAPS
        or set(schema_caps.get("properties", {})) != CAPS
        or any(schema_caps.get("properties", {}).get(name, {}).get("const") != value for name, value in schema_exact.items())
        or set(schema_auth.get("required", [])) != AUTHORIZATION
        or set(schema_auth.get("properties", {})) != AUTHORIZATION
        or any(schema_auth["properties"][name].get("const") is not False for name in AUTHORIZATION)
        or set(schema_claims.get("required", [])) != CLAIMS
        or set(schema_claims.get("properties", {})) != CLAIMS
        or any(schema_claims["properties"][name].get("const") is not False for name in CLAIMS)
        or set(schema_execution.get("required", [])) != EXECUTION
        or set(schema_execution.get("properties", {})) != EXECUTION
        or schema_execution.get("properties", {}).get("timeout_ms", {}).get("const") != 2000
        or set(schema_execution.get("properties", {}).get("isolation", {}).get("enum", [])) != {"in_process_thread", "not_started"}
        or set(schema_execution.get("properties", {}).get("deadline_outcome", {}).get("enum", [])) != {"completed_before_deadline", "timeout", "thread_spawn_failed", "channel_disconnected"}
        or set(schema_execution.get("properties", {}).get("containment", {}).get("enum", [])) != {"not_required", "process_exit_required"}
        or set(schema.get("properties", {}).get("state", {}).get("enum", [])) != STATES
        or set(schema.get("properties", {}).get("error_code", {}).get("enum", [])) != ERRORS
    ):
        errors.append("schema:contract_parity")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    failures = {}
    source_errors = validate_source_contract()
    if source_errors:
        failures["source_contract"] = source_errors
    for path in args.paths:
        try:
            errors = validate_receipt(load_json(path))
        except (ValueError, OSError) as exc:
            errors = [str(exc)]
        if errors:
            failures[str(path)] = errors
    blockers = ["supervisor_timeout_not_live_validated"]
    print(json.dumps({
        "ok": not failures,
        "evidence_class": "synthetic_contract",
        "failures": failures,
        "live_execution_blockers": blockers,
        "cargo_lock_policy": {
            "expected_sha256": EXPECTED_CARGO_LOCK_SHA256,
            "update_workflow": CARGO_LOCK_DIGEST_UPDATE_WORKFLOW,
        },
    }, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
