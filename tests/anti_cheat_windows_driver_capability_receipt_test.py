import copy
import importlib.util
import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/validate_anti_cheat_windows_driver_capability_receipt.py"
SPEC = importlib.util.spec_from_file_location("capability_receipt_validator", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)
FIXTURES = ROOT / "tools/detection_validation/fixtures"
SOURCE_CONTRACT_PATHS = [
    "tools/anti_cheat_windows_driver_capability_probe/Cargo.toml",
    "tools/anti_cheat_windows_driver_capability_probe/Cargo.lock",
    "tools/anti_cheat_windows_driver_capability_probe/src/main.rs",
    "tools/anti_cheat_windows_driver_capability_probe/src/protocol.rs",
    "apps/tamandua_driver/src/tamandua.h",
    "apps/tamandua_driver/src/usermode_api.h",
    "schemas/anti_cheat_windows_driver_capability_receipt_v1.schema.json",
]


def copy_source_contract(destination_root):
    for rel in SOURCE_CONTRACT_PATHS:
        destination = destination_root / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, destination)


@pytest.mark.parametrize("name", ["observed_unbound", "not_loaded", "connection_failed", "invalid_protocol", "timeout_confirmed", "timeout_unconfirmed"])
def test_synthetic_fixture_is_valid_and_non_promotional(name):
    receipt = MODULE.load_json(FIXTURES / f"anti_cheat_windows_driver_capability_receipt_{name}.json")
    assert MODULE.validate_receipt(receipt) == []
    assert receipt["evidence_class"] == "synthetic_contract"
    assert receipt["binding"]["bound"] is False
    assert not any(receipt["authorization"].values())
    assert not any(receipt["claims"].values())


def valid_observed():
    return MODULE.load_json(FIXTURES / "anti_cheat_windows_driver_capability_receipt_observed_unbound.json")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(extra=True),
        lambda r: r.update(observed_at="2026-02-30T00:00:00Z"),
        lambda r: r.update(state="ready"),
        lambda r: r.update(error_code="raw error"),
        lambda r: r["capabilities"].update(active_flags=1),
        lambda r: r["capabilities"].update(health_flags=16),
        lambda r: r["binding"].update(bound=True),
        lambda r: r["authorization"].update(driver_lifecycle_mutation_authorized=True),
        lambda r: r["claims"].update(runtime_validated=True),
        lambda r: r["execution"].update(timeout_ms=1999),
        lambda r: r["execution"].update(containment="process_exit_required"),
        lambda r: r["execution"].update(deadline_outcome="timeout"),
        lambda r: r.update(platform="non_windows"),
    ],
)
def test_receipt_mutations_fail_closed(mutate):
    receipt = copy.deepcopy(valid_observed())
    mutate(receipt)
    assert MODULE.validate_receipt(receipt)


def test_timeout_contract_requires_process_exit_without_termination_claim():
    receipt = MODULE.load_json(FIXTURES / "anti_cheat_windows_driver_capability_receipt_timeout_confirmed.json")
    assert receipt["error_code"] == "timeout_process_exit_required"
    assert receipt["execution"]["containment"] == "process_exit_required"
    receipt["execution"]["containment"] = "not_required"
    assert "execution:timeout_consistency" in MODULE.validate_receipt(receipt)


def test_duplicate_keys_and_oversize_are_rejected(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(MODULE.DuplicateKey):
        MODULE.load_json(duplicate)
    oversized = tmp_path / "oversized.json"
    oversized.write_text(" " * (MODULE.MAX_JSON_BYTES + 1), encoding="utf-8")
    with pytest.raises(ValueError, match="64 KiB"):
        MODULE.load_json(oversized)


def test_current_source_contract_is_single_entry_and_read_only():
    assert MODULE.validate_source_contract(ROOT) == []


def test_json_schema_matches_manual_state_error_platform_execution_rejections():
    schema = MODULE.load_json(ROOT / "schemas/anti_cheat_windows_driver_capability_receipt_v1.schema.json")
    validator = Draft202012Validator(schema)
    for name in ["observed_unbound", "not_loaded", "connection_failed", "invalid_protocol", "timeout_confirmed", "timeout_unconfirmed"]:
        receipt = MODULE.load_json(FIXTURES / f"anti_cheat_windows_driver_capability_receipt_{name}.json")
        assert list(validator.iter_errors(receipt)) == []
    mutations = []
    observed = valid_observed()
    for change in (
        {"platform": "non_windows"},
        {"state": "connection_failed", "error_code": "invalid_protocol", "capabilities": None},
        {"state": "invalid_protocol", "error_code": "connection_failed", "capabilities": None},
    ):
        candidate = copy.deepcopy(observed)
        candidate.update(change)
        mutations.append(candidate)
    unsupported = MODULE.load_json(FIXTURES / "anti_cheat_windows_driver_capability_receipt_connection_failed.json")
    unsupported["platform"] = "windows"
    mutations.append(unsupported)
    timeout = MODULE.load_json(FIXTURES / "anti_cheat_windows_driver_capability_receipt_timeout_confirmed.json")
    timeout["execution"]["containment"] = "not_required"
    mutations.append(timeout)
    for candidate in mutations:
        assert MODULE.validate_receipt(candidate)
        assert list(validator.iter_errors(candidate))


@pytest.mark.parametrize(
    ("relative", "old", "new"),
    [
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "fn main() {", "fn main() { let _ = std::env::args();"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "fn main() {", "fn main() { std::process::exit(0);"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "Builder::new().spawn(move ||", "Builder::new().spawn(move || { let _ = Builder::new().spawn(|| {});"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "use std::thread::Builder;", "use std::thread::Builder;\nuse std::thread as hidden_thread;"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    let (sender, receiver) = sync_channel(1);", "    let (sender, receiver) = sync_channel(1);\n    std::thread::spawn(|| {});"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "sync_channel(1)", "sync_channel(2)"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "sender.send(probe_once())", "sender.send(ProbeOutcome::InvalidProtocol)"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    let request = protocol::request_bytes();", "    let callback = probe_once;\n    let _ = callback;\n    let request = protocol::request_bytes();"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "receiver.recv_timeout(remaining)", "receiver.recv_timeout(Duration::from_secs(60))"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    if spawn_result.is_err() {", "    let _: Option<std::thread::JoinHandle<()>> = None;\n    if spawn_result.is_err() {"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    if spawn_result.is_err() {", "    std::mem::forget(spawn_result);\n    if spawn_result.is_err() {"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "receiver.recv_timeout(remaining)", "receiver.recv()"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    let deadline = Instant::now() + Duration::from_millis(OPERATION_TIMEOUT_MS);\n    let (sender, receiver) = sync_channel(1);", "    let (sender, receiver) = sync_channel(1);\n    let deadline = Instant::now() + Duration::from_millis(OPERATION_TIMEOUT_MS);"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    println!(\"{output}\");", "    println!(\"{output}\");\n    println!(\"{output}\");"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    println!(\"{output}\");", "    eprintln!(\"{output}\");\n    println!(\"{output}\");"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    println!(\"{output}\");", "    return;\n    println!(\"{output}\");"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    println!(\"{output}\");", "    panic!(\"extra\");\n    println!(\"{output}\");"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    println!(\"{output}\");", "    assert!(false);\n    println!(\"{output}\");"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    println!(\"{output}\");", "    loop {}\n    println!(\"{output}\");"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "fn main() {", 'fn main() { use std::io::Write; let _ = writeln!(std::io::stdout(), "extra");'),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "fn main() {", 'fn main() { use std::io as sink; let _guard = sink::stdout().lock();'),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "fn main() {", 'fn main() { use std::{io::Write}; let _ = std::io::stdout().lock();'),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "fn main() {", 'fn main() { let _guard = std::io::stdout().lock();'),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "fn main() {", 'fn main() { std::io::_print(format_args!("extra"));'),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "fn main() {", 'fn main() { let _ = write!(std::io::stderr(), "extra");'),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "        Ok(outcome) => receipt(outcome, completed_execution()),\n        Err(RecvTimeoutError::Timeout) => receipt(ProbeOutcome::TimedOut, timeout_execution()),", "        Err(RecvTimeoutError::Timeout) => receipt(ProbeOutcome::TimedOut, timeout_execution()),\n        Ok(outcome) => receipt(outcome, completed_execution()),"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", 'containment: "process_exit_required"', 'containment: "not_required"'),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "use windows::Win32::Foundation::CloseHandle;", "use windows::Win32::Foundation::CloseHandle as close_handle;"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/main.rs", "    let request = protocol::request_bytes();", "    let send_again = FilterSendMessage;\n    let request = protocol::request_bytes();"),
        ("tools/anti_cheat_windows_driver_capability_probe/src/protocol.rs", "pub const RESPONSE_LEN: usize = 80;", "pub const RESPONSE_LEN: usize = 84;"),
        ("tools/anti_cheat_windows_driver_capability_probe/Cargo.toml", "publish = false", 'publish = false\nbuild = "hidden.rs"'),
        ("tools/anti_cheat_windows_driver_capability_probe/Cargo.lock", "# It is not intended for manual editing.", "# changed"),
        ("schemas/anti_cheat_windows_driver_capability_receipt_v1.schema.json", '"containment": {"enum": ["not_required", "process_exit_required"]}', '"containment": {"enum": ["not_required"]}'),
        ("schemas/anti_cheat_windows_driver_capability_receipt_v1.schema.json", '"external_claim_allowed": {"const": false}', '"external_claim_allowed": {"const": true}'),
    ],
)
def test_source_contract_mutations_fail_closed(tmp_path, relative, old, new):
    copy_source_contract(tmp_path)
    target = tmp_path / relative
    text = target.read_text(encoding="utf-8")
    assert old in text
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    assert MODULE.validate_source_contract(tmp_path)


def test_public_emitter_whitespace_is_normalized(tmp_path):
    copy_source_contract(tmp_path)
    target = tmp_path / "tools/anti_cheat_windows_driver_capability_probe/src/main.rs"
    text = target.read_text(encoding="utf-8")
    text = text.replace(
        "fn emit_public(receipt: Receipt) {",
        "fn  emit_public ( receipt : Receipt ) {",
        1,
    ).replace(
        '    println!("{output}");',
        '    println! ( "{output}" ) ;',
        1,
    )
    target.write_text(text, encoding="utf-8")
    assert MODULE.validate_source_contract(tmp_path) == []


@pytest.mark.parametrize("literal", ['r"spoof"', 'r#"spoof"#', 'r###"spoof"###', 'br"spoof"', 'br##"spoof"##'])
def test_raw_and_byte_raw_literals_fail_closed(tmp_path, literal):
    copy_source_contract(tmp_path)
    target = tmp_path / "tools/anti_cheat_windows_driver_capability_probe/src/main.rs"
    text = target.read_text(encoding="utf-8")
    target.write_text(f"const RAW_SPOOF: &str = {literal};\n{text}", encoding="utf-8")
    errors = MODULE.validate_source_contract(tmp_path)
    assert "source:raw_string_forbidden" in errors


def test_raw_string_cannot_spoof_emitter_and_main_cardinality(tmp_path):
    copy_source_contract(tmp_path)
    target = tmp_path / "tools/anti_cheat_windows_driver_capability_probe/src/main.rs"
    text = target.read_text(encoding="utf-8")
    spoof = (
        'const RAW_SPOOF: &str = r#"fn emit_public(receipt: Receipt) {'
        ' let output = serde_json::to_string(&receipt).expect(\"receipt serialization is infallible\");'
        ' println!(\"{output}\"); } fn main ( )"#;\n'
    )
    text = text.replace(
        "fn emit_public(receipt: Receipt) {",
        "fn emit_public(receipt: Receipt) { return;",
        1,
    )
    target.write_text(spoof + text, encoding="utf-8")
    errors = MODULE.validate_source_contract(tmp_path)
    assert "source:raw_string_forbidden" in errors
    assert "source:supervisor_contract" in errors
    assert "source:public_emitter" in errors
