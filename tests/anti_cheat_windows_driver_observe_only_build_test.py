from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_windows_driver_observe_only_build_gate.py"
SCHEMA = ROOT / "schemas/anti_cheat_windows_driver_observe_only_build_receipt_v1.schema.json"
AUTHORITY_SCHEMA = ROOT / "schemas/anti_cheat_windows_driver_observe_only_build_authority_v1.schema.json"
SCHEMA_V2 = ROOT / "schemas/anti_cheat_windows_driver_observe_only_build_receipt_v2.schema.json"


def _load():
    spec = importlib.util.spec_from_file_location("observe_build_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


def _minimal_pe(path: Path, *, machine: int = 0x8664, signed: bool = False) -> None:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, 240, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 108, 16)
    if signed:
        struct.pack_into("<II", data, optional + 112 + 32, 800, 16)
    section = optional + 240
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 512, 0x1000, 512, 512)
    path.write_bytes(data)


def test_source_inventory_binds_declared_inputs() -> None:
    entries = gate._canonical_source_inventory(ROOT / "apps/tamandua_driver/tamandua_driver.vcxproj")
    paths = {entry["path"] for entry in entries}
    assert "tamandua_driver.vcxproj" in paths
    assert "src/main.c" in paths
    assert "src/driver.h" in paths
    assert len(gate._inventory_digest(entries)) == 64


def test_build_argv_forces_observe_only_and_disables_packaging(tmp_path: Path) -> None:
    args = argparse.Namespace(
        msbuild=str(tmp_path / "MSBuild.exe"), configuration="Release", platform="x64", wdk="10.0.26100.0"
    )
    argv = gate._build_argv(args, ROOT / "apps/tamandua_driver/tamandua_driver.vcxproj", tmp_path / "out")
    assert "/p:TamanduaDriverObserveOnly=1" in argv
    assert "/p:DriverSign=Off" in argv
    assert "/p:EnableInf2cat=false" in argv
    assert "/p:PostBuildEventUseInBuild=false" in argv
    assert "/p:VCLibPackagePath=" in argv
    assert "/p:VcpkgEnabled=false" in argv
    assert "/m:1" in argv and "/nr:false" in argv
    assert all("latest" not in item.lower() for item in argv)


def test_bounded_process_hashes_full_output_and_caps_retention(tmp_path: Path) -> None:
    evidence = gate._run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('x'*300000)"], tmp_path, dict(**__import__('os').environ), 20
    )
    assert evidence.exit_code == 0 and not evidence.timed_out
    assert evidence.output_bytes == 300000
    assert len(evidence.retained_output) == gate.MAX_LOG_BYTES
    assert evidence.retained_truncated
    assert evidence.output_sha256 == __import__('hashlib').sha256(b"x" * 300000).hexdigest()


def test_bounded_process_deadline_is_categorical(tmp_path: Path) -> None:
    evidence = gate._run_bounded(
        [sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, dict(**__import__('os').environ), 1
    )
    assert evidence.timed_out
    assert evidence.exit_code is not None


def test_build_failure_classifies_missing_spectre_libraries() -> None:
    output = "error MSB8040: Spectre-mitigated libraries are required for this project"
    assert gate._classify_build_failure(output) == "spectre_mitigated_libraries_unavailable"
    assert gate._classify_build_failure("compiler returned 2") == "msbuild_nonzero_exit"


def test_pe_parser_accepts_only_amd64_and_reports_unsigned(tmp_path: Path) -> None:
    candidate = tmp_path / "tamandua.sys"
    _minimal_pe(candidate)
    result = gate._parse_pe(candidate)
    assert result["machine"] == "amd64"
    assert result["certificate_table_present"] is False
    _minimal_pe(candidate, machine=0x14C)
    try:
        gate._parse_pe(candidate)
    except ValueError as exc:
        assert "unexpected_machine" in str(exc)
    else:
        raise AssertionError("x86 artifact accepted")


def test_schema_rejects_runtime_claim_and_accepts_failure_shape() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    receipt = {
        "schema_version": gate.SCHEMA_VERSION,
        "observed_at": "2026-07-20T12:00:00Z",
        "evidence_class": "local_unsigned_build",
        "status": "toolchain_unavailable",
        "source": None, "toolchain": None, "policy": None, "execution": None, "process": None, "artifact": None,
        "artifact_check": None,
        "claims": {"build_validated": False, "link_validated": False, **gate.RUNTIME_FALSE_CLAIMS},
        "blockers": ["msbuild_not_found"],
    }
    jsonschema.validate(receipt, schema)
    receipt["claims"]["loaded"] = True
    try:
        jsonschema.validate(receipt, schema)
    except jsonschema.ValidationError:
        pass
    else:
        raise AssertionError("runtime claim accepted")


def test_cli_requires_observe_only_one() -> None:
    with tempfile.TemporaryDirectory() as directory:
        argv = [
            "--project", str(ROOT / "apps/tamandua_driver/tamandua_driver.vcxproj"),
            "--observe-only", "0", "--msbuild", str(Path(directory) / "missing.exe"),
            "--wdk", "10.0.26100.0", "--output", str(Path(directory) / "out"),
            "--receipt", str(Path(directory) / "receipt.json"),
        ]
        try:
            gate.parse_args(argv)
        except SystemExit as exc:
            assert exc.code != 0
        else:
            raise AssertionError("observe-only=0 accepted")


def test_project_contract_closes_imports_and_custom_build(tmp_path: Path) -> None:
    project = ROOT / "apps/tamandua_driver/tamandua_driver.vcxproj"
    contract = gate._project_contract(project)
    assert contract["disabled_user_imports"] == [r"$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props"]
    assert contract["custom_builds"][0]["include"] == r"src\TamanduaEvents.mc"
    mutated = tmp_path / project.name
    source = project.read_text(encoding="utf-8")
    mutated.write_text(source.replace("</Project>", '<Import Project="C:\\evil.props" /></Project>'), encoding="utf-8")
    try:
        gate._project_contract(mutated)
    except ValueError as exc:
        assert "unapproved_direct_import" in str(exc)
    else:
        raise AssertionError("external props accepted")


def test_preprocessed_import_inventory_rejects_user_local_props(tmp_path: Path) -> None:
    if os.name != "nt":
        return
    props = tmp_path / "injected.props"
    props.write_text("<Project />", encoding="utf-8")
    preprocessed = tmp_path / "preprocessed.xml"
    preprocessed.write_text(str(props.resolve()) + "\n", encoding="utf-8")
    try:
        gate._import_inventory(preprocessed, [tmp_path])
    except ValueError as exc:
        assert str(exc) == "user_local_import_observed"
    else:
        raise AssertionError("user-local imported props accepted")


def test_stage_contains_custom_input_but_not_generated_message_outputs(tmp_path: Path) -> None:
    source = ROOT / "apps/tamandua_driver/tamandua_driver.vcxproj"
    stage = tmp_path / "stage"
    stage.mkdir()
    staged = gate._stage_project(source, stage)
    assert staged.is_file()
    assert (stage / "src/TamanduaEvents.mc").is_file()
    assert not (stage / "src/TamanduaEvents.h").exists()
    assert not (stage / "src/TamanduaEvents.rc").exists()
    text = staged.read_text(encoding="utf-8")
    assert "$(UserRootDir)" not in text
    assert 'mc.exe -U "%(FullPath)" -h "$(ProjectDir)src"' in text


def test_privacy_redacts_user_and_isolated_paths(tmp_path: Path) -> None:
    raw = rf'C:\Users\secret-name\repo C:/Users/forward-user/private {tmp_path}\stage\file.c C:\Program Files\Microsoft Visual Studio\2022\MSBuild.exe C:\Program Files (x86)\Windows Kits\10\bin\mc.exe Authorization: Basic dXNlcjpwYXNz Bearer abcdef123456 password=hunter2 AWS_SECRET_ACCESS_KEY=ABCDEFGHIJKLMNOP awsSecretAccessKey=QRSTUVWX secretKey=ZZZZZZZZ {{"refreshToken":"YYYYYYYY"}} X-Api-Key: vendor-secret Cookie: session-cookie'
    redacted = gate._redact_text(raw, [tmp_path])
    assert "secret-name" not in redacted
    assert str(tmp_path) not in redacted
    assert "abcdef123456" not in redacted and "hunter2" not in redacted
    assert "forward-user" not in redacted and "ABCDEFGHIJKLMNOP" not in redacted
    assert "QRSTUVWX" not in redacted and "ZZZZZZZZ" not in redacted and "YYYYYYYY" not in redacted
    assert "dXNlcjpwYXNz" not in redacted and "vendor-secret" not in redacted and "session-cookie" not in redacted
    assert "<vs-root>" in redacted and "<wdk-root>" in redacted
    assert "<user-home>" in redacted or "<isolated>" in redacted


def test_source_and_toolchain_drift_is_detected() -> None:
    before = [{"role": "compiler", "sha256": "a" * 64}]
    assert gate._identities_unchanged(before, list(before))
    assert not gate._identities_unchanged(before, [{"role": "compiler", "sha256": "b" * 64}])


def test_preassign_failure_never_releases_child(tmp_path: Path, monkeypatch) -> None:
    if os.name != "nt":
        return
    marker = tmp_path / "executed"
    monkeypatch.setattr(gate, "_create_kill_job", lambda _handle: (_ for _ in ()).throw(OSError("deny")))
    try:
        gate._run_bounded(
            [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('bad')"],
            tmp_path, dict(os.environ), 10,
        )
    except OSError:
        pass
    else:
        raise AssertionError("preassign failure accepted")
    assert not marker.exists()


def _build_failed_receipt() -> dict:
    digest = "a" * 64
    retained = "error MSB8040: Spectre-mitigated libraries are required"
    process = {
        "exit_code": 1, "timed_out": False, "duration_ms": 1,
        "output_sha256": __import__('hashlib').sha256(retained.encode()).hexdigest(),
        "output_bytes": len(retained), "retained_output": retained,
        "retained_output_sha256": __import__('hashlib').sha256(retained.encode()).hexdigest(),
        "retained_raw_sha256": __import__('hashlib').sha256(retained.encode()).hexdigest(),
        "retained_raw_bytes": len(retained.encode()), "redaction_applied": False,
        "retained_truncated": False, "job_containment": "windows_job_kill_on_close",
    }
    preprocess = {
        **process, "exit_code": 0, "output_bytes": 0, "retained_output": "",
        "output_sha256": __import__('hashlib').sha256(b"").hexdigest(),
        "retained_output_sha256": __import__('hashlib').sha256(b"").hexdigest(),
        "retained_raw_sha256": __import__('hashlib').sha256(b"").hexdigest(),
        "retained_raw_bytes": 0,
    }
    inventory_file = {"path": "src/main.c", "size": 1, "sha256": digest}
    tool_file = {"role": "compiler", "basename": "cl.exe", "path_token": digest, "size": 1, "sha256": digest}
    receipt = {
        "schema_version": gate.SCHEMA_VERSION, "observed_at": "2026-07-20T12:00:00Z",
        "evidence_class": "local_unsigned_build", "status": "build_failed",
        "source": {
            "project_basename": "tamandua_driver.vcxproj", "project_path_token": digest,
            "inventory": [inventory_file, {**inventory_file, "path": "tamandua_driver.vcxproj"}],
            "inventory_sha256": "", "post_inventory": [], "post_inventory_sha256": "", "original_unchanged": True,
            "stage_input_inventory": [copy.deepcopy(inventory_file)], "stage_input_sha256": "",
            "stage_post_inventory": [copy.deepcopy(inventory_file)], "stage_post_sha256": "",
            "isolated_post_inventory": [copy.deepcopy(inventory_file)], "isolated_post_sha256": "",
            "project_contract": {},
        },
        "toolchain": {
            "wdk_version_requested": "10.0.26100.0", "files": [{**tool_file, "role": f"tool_{i}"} for i in range(7)],
            "post_files": [], "post_sha256": "", "unchanged": True, "imports": [{**tool_file, "role": "imported_project"}],
            "post_imports": [], "imports_post_sha256": "", "imports_unchanged": True,
        },
        "policy": {
            "observe_only": "1", "driver_sign": "Off", "sign_mode": "Off", "inf2cat": "false",
            "packaging": "false", "post_build": "false", "vcpkg_enabled": "false",
            "custom_build_stage_only": True, "user_props_loaded": False,
        },
        "execution": {
            "argv": [f"arg{i}" for i in range(15)], "cwd_token": digest, "timeout_seconds": 600,
            "environment_keys": ["PATH"], "preprocess": preprocess,
            "effective_properties": {
                "TamanduaDriverObserveOnly": "1", "DriverSign": "Off", "SignMode": "Off",
                "EnableInf2cat": "false", "SupportsPackaging": "false",
                "PostBuildEventUseInBuild": "false", "VcpkgEnabled": "false",
            },
        },
        "process": process, "artifact": None,
        "artifact_check": {"candidate_count": 0, "state": "not_evaluated", "failure": None},
        "claims": {"build_validated": False, "link_validated": False, **gate.RUNTIME_FALSE_CLAIMS},
        "blockers": ["spectre_mitigated_libraries_unavailable"],
    }
    value = receipt
    value["source"]["post_inventory"] = copy.deepcopy(value["source"]["inventory"])
    value["source"]["inventory_sha256"] = gate._inventory_digest(value["source"]["inventory"])
    value["source"]["post_inventory_sha256"] = gate._inventory_digest(value["source"]["post_inventory"])
    for prefix in ("stage_input", "stage_post", "isolated_post"):
        value["source"][f"{prefix}_sha256"] = gate._inventory_digest(value["source"][f"{prefix}_inventory"])
    value["toolchain"]["post_files"] = copy.deepcopy(value["toolchain"]["files"])
    value["toolchain"]["post_imports"] = copy.deepcopy(value["toolchain"]["imports"])
    value["toolchain"]["post_sha256"] = gate._inventory_digest(value["toolchain"]["post_files"])
    value["toolchain"]["imports_post_sha256"] = gate._inventory_digest(value["toolchain"]["post_imports"])
    return value


def _replace_retained_output(receipt: dict, retained: str) -> None:
    encoded = retained.encode()
    digest = __import__('hashlib').sha256(encoded).hexdigest()
    receipt["process"].update({
        "output_sha256": digest, "output_bytes": len(encoded),
        "retained_output": retained, "retained_output_sha256": digest,
        "retained_raw_sha256": digest, "retained_raw_bytes": len(encoded),
        "redaction_applied": False, "retained_truncated": False,
    })


def _assert_exact_json_containers(value: object) -> None:
    if type(value) is dict:
        assert all(type(key) is str for key in value)
        for member in value.values():
            _assert_exact_json_containers(member)
    elif type(value) is list:
        for member in value:
            _assert_exact_json_containers(member)


def test_receipt_semantics_reject_forged_success_and_failure_laundering() -> None:
    valid = _build_failed_receipt()
    gate._validate_receipt_document(valid)
    forged = copy.deepcopy(valid)
    forged["status"] = "success"
    forged["claims"]["build_validated"] = True
    forged["claims"]["link_validated"] = True
    forged["artifact"] = {
        "path": "tamandua.sys", "size": 1024, "sha256": "a" * 64, "machine": "amd64",
        "characteristics": 0, "imports": [], "certificate_table_present": False,
    }
    forged["artifact_check"] = {"candidate_count": 1, "state": "valid", "failure": None}
    forged["blockers"] = list(gate.ARTIFACT_OBSERVED_BLOCKERS)
    try:
        gate._validate_receipt_document(forged)
    except gate.ReceiptValidationError:
        pass
    else:
        raise AssertionError("forged success accepted")
    laundered = copy.deepcopy(valid)
    laundered["blockers"] = ["msbuild_nonzero_exit"]
    try:
        gate._validate_receipt_document(laundered)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "receipt_status_not_derived"
    else:
        raise AssertionError("categorical failure laundering accepted")


def test_coherent_synthetic_success_requires_actual_execution_context() -> None:
    forged = _build_failed_receipt()
    forged["status"] = "success"
    forged["process"]["exit_code"] = 0
    forged["process"]["retained_output"] = ""
    forged["process"]["retained_output_sha256"] = __import__('hashlib').sha256(b"").hexdigest()
    forged["process"]["retained_raw_sha256"] = __import__('hashlib').sha256(b"").hexdigest()
    forged["process"]["retained_raw_bytes"] = 0
    forged["process"]["output_sha256"] = __import__('hashlib').sha256(b"").hexdigest()
    forged["process"]["output_bytes"] = 0
    forged["artifact"] = {
        "path": "tamandua.sys", "size": 1024, "sha256": "b" * 64, "machine": "amd64",
        "characteristics": 0, "imports": [], "certificate_table_present": False,
    }
    forged["artifact_check"] = {"candidate_count": 1, "state": "valid", "failure": None}
    forged["claims"]["build_validated"] = True
    forged["claims"]["link_validated"] = True
    forged["blockers"] = list(gate.ARTIFACT_OBSERVED_BLOCKERS)
    try:
        gate._validate_receipt_document(forged)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "receipt_local_promotion_forbidden"
    else:
        raise AssertionError("coherent fabricated success accepted without bounded execution context")


def test_receipt_recomputes_embedded_inventory_and_retained_output_digests() -> None:
    for mutate_receipt in (
        lambda value: value["source"].__setitem__("inventory_sha256", "f" * 64),
        lambda value: value["toolchain"].__setitem__("post_sha256", "f" * 64),
        lambda value: value["process"].__setitem__("retained_output_sha256", "f" * 64),
    ):
        forged = _build_failed_receipt()
        mutate_receipt(forged)
        try:
            gate._validate_receipt_document(forged)
        except gate.ReceiptValidationError:
            pass
        else:
            raise AssertionError("forged embedded evidence digest accepted")


def test_process_raw_count_and_digest_are_bound() -> None:
    for field, value in (("output_sha256", "f" * 64), ("output_bytes", 999999)):
        forged = _build_failed_receipt()
        forged["process"][field] = value
        try:
            gate._validate_receipt_document(forged)
        except gate.ReceiptValidationError:
            pass
        else:
            raise AssertionError(f"forged process {field} accepted")


def test_self_consistent_stage_authority_forgery_is_rejected() -> None:
    forged = _build_failed_receipt()
    forged["source"]["stage_input_inventory"][0]["sha256"] = "f" * 64
    forged["source"]["stage_input_sha256"] = gate._inventory_digest(
        forged["source"]["stage_input_inventory"]
    )
    try:
        gate._validate_receipt_document(forged)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "receipt_stage_authority_invalid"
    else:
        raise AssertionError("self-consistent staged authority forgery accepted")


def test_staged_authoritative_inputs_reject_drift_and_missing_paths(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    source = stage / "src.c"
    source.write_bytes(b"original")
    expected = gate._stage_inventory(stage)
    assert gate._assert_authoritative_stage_unchanged(stage, expected) == expected
    source.write_bytes(b"mutated")
    try:
        gate._assert_authoritative_stage_unchanged(stage, expected)
    except ValueError as exc:
        assert str(exc) == "stage_authoritative_input_drift"
    else:
        raise AssertionError("staged source mutation accepted")
    source.unlink()
    try:
        gate._assert_authoritative_stage_unchanged(stage, expected)
    except ValueError as exc:
        assert str(exc) == "stage_authority_missing_or_non_regular"
    else:
        raise AssertionError("missing staged authority accepted")


def test_importer_cannot_construct_proof_that_upgrades_success() -> None:
    assert not hasattr(gate, "_ExecutionTranscript")
    forged = _build_failed_receipt()
    forged["status"] = "success"
    forged["process"]["exit_code"] = 0
    forged["claims"]["build_validated"] = True
    forged["claims"]["link_validated"] = True
    forged["artifact"] = {
        "path": "tamandua.sys", "size": 1024, "sha256": "b" * 64,
        "machine": "amd64", "characteristics": 0, "imports": [],
        "certificate_table_present": False,
    }
    forged["artifact_check"] = {"candidate_count": 1, "state": "valid", "failure": None}
    forged["blockers"] = list(gate.ARTIFACT_OBSERVED_BLOCKERS)
    forged["process"]["retained_output"] = ""
    forged["process"]["retained_output_sha256"] = __import__('hashlib').sha256(b"").hexdigest()
    forged["process"]["retained_raw_sha256"] = __import__('hashlib').sha256(b"").hexdigest()
    forged["process"]["output_sha256"] = __import__('hashlib').sha256(b"").hexdigest()
    forged["process"]["retained_raw_bytes"] = 0
    forged["process"]["output_bytes"] = 0
    try:
        gate._validate_receipt_document(forged)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "receipt_local_promotion_forbidden"
    else:
        raise AssertionError("importer upgraded a caller-supplied success")


def test_every_local_validator_and_emitter_rejects_promotion(tmp_path: Path) -> None:
    forged = _build_failed_receipt()
    forged["status"] = "success"
    forged["claims"]["build_validated"] = True
    forged["claims"]["link_validated"] = True
    for validator in (
        gate._reject_local_promotion,
        gate._validate_receipt_structure,
        gate._validate_receipt_document,
    ):
        try:
            validator(copy.deepcopy(forged))
        except gate.ReceiptValidationError as exc:
            assert str(exc) == "receipt_local_promotion_forbidden"
        else:
            raise AssertionError(f"{validator.__name__} accepted local promotion")
    for callable_with_context in (gate._finalize_receipt_integrity,):
        try:
            callable_with_context(copy.deepcopy(forged), None)
        except gate.ReceiptValidationError as exc:
            assert str(exc) == "receipt_local_promotion_forbidden"
        else:
            raise AssertionError(f"{callable_with_context.__name__} accepted local promotion")
    try:
        gate._finish_execution(copy.deepcopy(forged), 0, None)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "receipt_local_promotion_forbidden"
    else:
        raise AssertionError("finish execution returned local promotion")
    try:
        gate._write_receipt_exclusive(tmp_path / "forbidden.json", copy.deepcopy(forged), None)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "receipt_local_promotion_forbidden"
    else:
        raise AssertionError("exclusive writer persisted local promotion")
    assert not (tmp_path / "forbidden.json").exists()


def test_callable_boundaries_reject_hostile_primitive_subclasses_without_comparison(tmp_path: Path) -> None:
    class HostileStatus(str):
        comparisons = 0

        def __eq__(self, other: object) -> bool:
            type(self).comparisons += 1
            raise AssertionError("hostile equality was evaluated")

        __hash__ = str.__hash__

    class HostileMapping(dict):
        pass

    hostile = HostileMapping(_build_failed_receipt())
    hostile["status"] = HostileStatus("success")
    boundaries = (
        lambda value: gate._reject_local_promotion(value),
        lambda value: gate._validate_receipt_structure(value),
        lambda value: gate._validate_receipt_document(value),
        lambda value: gate._finalize_receipt_integrity(value, None),
        lambda value: gate._finish_execution(value, 0, None),
        lambda value: gate._write_receipt_exclusive(tmp_path / "hostile.json", value, None),
    )
    for boundary in boundaries:
        try:
            boundary(hostile)
        except gate.ReceiptValidationError as exc:
            assert str(exc) == "receipt_not_canonical_json"
        else:
            raise AssertionError("hostile JSON subclass accepted")
    assert HostileStatus.comparisons == 0
    assert not (tmp_path / "hostile.json").exists()


def test_callable_boundaries_reject_integer_false_claim_aliases(tmp_path: Path) -> None:
    for alias in (0, 1):
        forged = _build_failed_receipt()
        forged["claims"]["build_validated"] = alias
        boundaries = (
            lambda value: gate._reject_local_promotion(value),
            lambda value: gate._validate_receipt_structure(value),
            lambda value: gate._validate_receipt_document(value),
            lambda value: gate._finalize_receipt_integrity(value, None),
            lambda value: gate._finish_execution(value, 0, None),
            lambda value: gate._write_receipt_exclusive(tmp_path / f"claim-{alias}.json", value, None),
        )
        for boundary in boundaries:
            try:
                boundary(copy.deepcopy(forged))
            except gate.ReceiptValidationError as exc:
                assert str(exc) == "receipt_local_promotion_forbidden"
            else:
                raise AssertionError(f"integer claim alias {alias} accepted")
        assert not (tmp_path / f"claim-{alias}.json").exists()


def test_finish_execution_returns_detached_builtin_json_document() -> None:
    receipt = _build_failed_receipt()
    proof = SimpleNamespace(binding_sha256=None)
    finished, exit_code, returned_proof = gate._finish_execution(receipt, 4, proof)
    assert type(finished) is dict and finished is not receipt
    _assert_exact_json_containers(finished)
    receipt["status"] = "success"
    receipt["claims"]["build_validated"] = True
    assert finished["status"] == "build_failed"
    assert finished["claims"]["build_validated"] is False
    assert exit_code == 4 and returned_proof is proof


def test_privacy_rejects_camel_case_and_generic_secret_assignments() -> None:
    retained_values = (
        "awsSecretAccessKey=ABCDEFGHIJKLMNOP",
        "secretKey=ABCDEFGHIJKLMNOP",
        "privateKey=ABCDEFGHIJKLMNOP",
        "clientSecret=ABCDEFGHIJKLMNOP",
        "refreshToken=ABCDEFGHIJKLMNOP",
        "serviceCredential=ABCDEFGHIJKLMNOP",
    )
    for retained in retained_values:
        forged = _build_failed_receipt()
        _replace_retained_output(forged, retained)
        forged["blockers"] = ["msbuild_nonzero_exit"]
        try:
            gate._validate_receipt_document(forged)
        except gate.ReceiptValidationError as exc:
            assert str(exc) == "receipt_privacy_invalid"
        else:
            raise AssertionError(f"secret assignment accepted: {retained.split('=', 1)[0]}")


def test_zero_exit_artifact_is_portable_only_as_observed_unbound() -> None:
    value = _build_failed_receipt()
    empty = __import__('hashlib').sha256(b"").hexdigest()
    value["status"] = "artifact_observed_unbound"
    value["process"].update({
        "exit_code": 0, "retained_output": "", "retained_output_sha256": empty,
        "retained_raw_sha256": empty, "retained_raw_bytes": 0,
        "output_sha256": empty, "output_bytes": 0,
    })
    value["artifact"] = {
        "path": "tamandua.sys", "size": 1024, "sha256": "b" * 64,
        "machine": "amd64", "characteristics": 0, "imports": [],
        "certificate_table_present": False,
    }
    value["artifact_check"] = {"candidate_count": 1, "state": "valid", "failure": None}
    value["blockers"] = list(gate.ARTIFACT_OBSERVED_BLOCKERS)
    gate._validate_receipt_document(value)
    assert value["claims"]["build_validated"] is False
    assert value["claims"]["link_validated"] is False


def test_output_and_receipt_must_be_fresh_canonical_disjoint_and_outside_source(tmp_path: Path) -> None:
    project = ROOT / "apps/tamandua_driver/tamandua_driver.vcxproj"
    output, receipt = gate._canonical_fresh_locations(
        project, str(tmp_path / "output"), str(tmp_path / "receipt.json")
    )
    assert output.parent == tmp_path.resolve() and receipt.parent == tmp_path.resolve()
    try:
        gate._canonical_fresh_locations(project, str(project.parent / "forbidden-output"), str(tmp_path / "other.json"))
    except ValueError as exc:
        assert str(exc) == "unsafe_output_topology"
    else:
        raise AssertionError("source-tree output accepted")
    (tmp_path / "existing-output").mkdir()
    try:
        gate._canonical_fresh_locations(project, str(tmp_path / "existing-output"), str(tmp_path / "fresh.json"))
    except ValueError as exc:
        assert str(exc) == "unsafe_output_topology"
    else:
        raise AssertionError("existing output accepted")


def test_raw_exception_values_are_never_used_as_blockers() -> None:
    error = ValueError(r"C:\Users\alice\secret Bearer abcdef123456 token=raw-secret")
    assert gate._exception_blocker(error) == "internal_gate_error"
    assert "alice" not in gate._exception_blocker(error)
    assert "abcdef123456" not in gate._exception_blocker(error)


def test_final_integrity_check_catches_mutation_at_receipt_write_boundary(tmp_path: Path) -> None:
    source_project = ROOT / "apps/tamandua_driver/tamandua_driver.vcxproj"
    project_root = tmp_path / "project"
    for entry in gate._canonical_source_inventory(source_project):
        relative = Path(entry["path"])
        source = source_project.parent / relative
        target = project_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    args = argparse.Namespace(
        project=str(project_root / source_project.name), configuration="Release", platform="x64",
        observe_only="1", msbuild=str(tmp_path / "missing-MSBuild.exe"), wdk="10.0.26100.0",
        output=str(evidence_root / "output"), receipt=str(evidence_root / "receipt.json"), timeout_seconds=30,
    )
    receipt, _exit_code, proof = gate.execute(args)

    def mutate_final_source() -> None:
        path = project_root / "src/main.c"
        path.write_bytes(path.read_bytes() + b"\n/* final-boundary mutation */\n")

    gate._write_receipt_exclusive(Path(args.receipt), receipt, proof, mutate_final_source)
    persisted = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    assert persisted["status"] == "input_drift"
    assert persisted["claims"]["build_validated"] is False
    assert persisted["blockers"] == ["source_or_toolchain_changed_during_build"]


def test_exact_scopes_receive_whole_file_utf8_and_whitespace_validation() -> None:
    scopes = (SCHEMA, AUTHORITY_SCHEMA, SCHEMA_V2, SCRIPT, Path(__file__).resolve())
    for path in scopes:
        data = path.read_bytes()
        assert data and b"\0" not in data
        text = data.decode("utf-8")
        assert __import__('hashlib').sha256(data).hexdigest()
        assert all(line == line.rstrip(" \t") for line in text.splitlines())
    gate_source = SCRIPT.read_text(encoding="utf-8")
    assert 'base["status"] = "success"' not in gate_source
    assert 'base["status"] = "artifact_observed_unbound"' in gate_source
    assert "_ExecutionTranscript" not in gate_source


def _authority_args(tmp_path: Path) -> argparse.Namespace:
    msbuild = tmp_path / "MSBuild.exe"
    if not msbuild.exists():
        shutil.copyfile(sys.executable, msbuild)
    return argparse.Namespace(
        project=str(ROOT / "apps/tamandua_driver/tamandua_driver.vcxproj"),
        configuration="Release", platform="x64", observe_only="1", msbuild=str(msbuild),
        wdk="10.0.26100.0", output=str(tmp_path / "future-output"),
        receipt=str(tmp_path / "future-receipt.json"), timeout_seconds=600,
        freeze_authority=None, validate_authority=None, authority=None,
    )


def test_authority_freeze_is_detached_canonical_and_self_validating(tmp_path: Path) -> None:
    args = _authority_args(tmp_path)
    destination = tmp_path / "authority.json"
    document, digest = gate._freeze_authority(args, destination)
    encoded = destination.read_bytes()
    assert encoded == gate._canonical_json_bytes(document)
    assert not encoded.endswith(b"\n") and not encoded.startswith(b"\xef\xbb\xbf")
    assert "authority_sha256" not in document
    assert __import__('hashlib').sha256(encoded).hexdigest() == digest
    loaded, loaded_digest = gate._load_authority(destination, args)
    assert loaded == document and loaded_digest == digest
    jsonschema.Draft202012Validator(json.loads(AUTHORITY_SCHEMA.read_text(encoding="utf-8"))).validate(document)


def test_authority_parser_rejects_noncanonical_duplicate_float_and_bom() -> None:
    invalid = (
        b'{"a":1}\n', b'{"a":1,"a":1}', b'{"a":1.0}',
        b'\xef\xbb\xbf{"a":1}', b'{ "a":1}',
    )
    for payload in invalid:
        try:
            gate._load_exact_json_bytes(payload)
        except gate.ReceiptValidationError as exc:
            assert str(exc) == "authority_not_canonical"
        else:
            raise AssertionError(f"noncanonical authority accepted: {payload!r}")


def test_authority_claims_remain_false_without_schema_assistance(tmp_path: Path, monkeypatch) -> None:
    args = _authority_args(tmp_path)
    destination = tmp_path / "authority.json"
    document, _digest = gate._freeze_authority(args, destination)
    document["claims"]["build_executed"] = True
    monkeypatch.setattr(
        gate, "Draft202012Validator",
        lambda _schema: SimpleNamespace(iter_errors=lambda _value: []),
    )
    try:
        gate._validate_authority_document(document, args, destination)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "authority_claims_invalid"
    else:
        raise AssertionError("authority promotion accepted after schema weakening")


def test_strict_snapshot_binds_same_size_timestamp_drift(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"stable")
    real_fstat = gate.os.fstat
    calls = 0

    def drifting_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        info = real_fstat(descriptor)
        if calls == 2:
            return SimpleNamespace(
                st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size,
                st_mtime_ns=info.st_mtime_ns + 1, st_ctime_ns=info.st_ctime_ns,
            )
        return info

    monkeypatch.setattr(gate.os, "fstat", drifting_fstat)
    try:
        gate._read_strict_regular_bytes(source)
    except ValueError as exc:
        assert str(exc) == "file_identity_changed_during_read"
    else:
        raise AssertionError("same-size timestamp drift accepted")


def test_authority_binds_roles_python_and_complete_invocation(tmp_path: Path) -> None:
    args = _authority_args(tmp_path)
    destination = tmp_path / "authority.json"
    document, _digest = gate._freeze_authority(args, destination)
    assert [entry["role"] for entry in document["roles"]] == list(gate.PROVENANCE_ROLE_NAMES)
    assert document["roles"][3]["path_token"] == gate._path_token(gate._strict_regular_file(Path(sys.executable)))
    assert document["python"]["implementation"]
    contract = document["invocation"]
    assert (contract["configuration"], contract["platform"], contract["observe_only"]) == ("Release", "x64", "1")
    assert contract["wdk_version"] == "10.0.26100.0" and contract["timeout_seconds"] == 600
    args.timeout_seconds = 601
    try:
        gate._load_authority(destination, args)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "authority_invocation_mismatch"
    else:
        raise AssertionError("invocation substitution accepted")


def test_authority_role_or_tool_substitution_fails_before_child_spawn(tmp_path: Path, monkeypatch) -> None:
    args = _authority_args(tmp_path)
    destination = tmp_path / "authority.json"
    gate._freeze_authority(args, destination)
    Path(args.msbuild).write_bytes(Path(args.msbuild).read_bytes() + b"drift")
    monkeypatch.setattr(gate, "_run_bounded", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("child spawned")))
    try:
        gate._execute_v2(args, destination)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "authority_invocation_mismatch"
    else:
        raise AssertionError("tool substitution accepted")
    assert not Path(args.output).exists() and not Path(args.receipt).exists()


def test_authority_rejects_reparse_hardlink_alias_and_fresh_path_collisions(
    tmp_path: Path, monkeypatch,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    alias = tmp_path / "alias.bin"
    os.link(source, alias)
    for path in (source, alias):
        try:
            gate._strict_regular_file(path)
        except ValueError as exc:
            assert str(exc) == "regular_single_link_file_required"
        else:
            raise AssertionError("hardlink accepted")
    reparse = tmp_path / "reparse.bin"
    reparse.write_bytes(b"x")
    real_lstat = gate.os.lstat

    def reparse_lstat(path: Path):
        info = real_lstat(path)
        if Path(path) == reparse:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_file_attributes=getattr(info, "st_file_attributes", 0) | 0x400,
            )
        return info

    monkeypatch.setattr(gate.os, "lstat", reparse_lstat)
    try:
        gate._strict_regular_file(reparse)
    except ValueError as exc:
        assert str(exc) == "reparse_path_forbidden"
    else:
        raise AssertionError("reparse point accepted")
    monkeypatch.setattr(gate.os, "lstat", real_lstat)
    args = _authority_args(tmp_path)
    args.receipt = args.output
    try:
        gate._authority_document(args, tmp_path / "authority.json")
    except ValueError as exc:
        assert str(exc) == "authority_path_collision"
    else:
        raise AssertionError("output/receipt collision accepted")


def test_v2_receipt_binds_authority_and_provenance_without_promoting_claims(tmp_path: Path) -> None:
    args = _authority_args(tmp_path)
    authority_path = tmp_path / "authority.json"
    authority, authority_sha256 = gate._freeze_authority(args, authority_path)
    roles = gate._provenance_inventory()
    receipt = gate._convert_to_v2(_build_failed_receipt(), authority, authority_sha256, roles, roles)
    validated = gate._validate_receipt_document(receipt)
    assert validated["status"] == "build_failed"
    assert validated["provenance"]["unchanged"] is True
    assert all(value is False for value in validated["claims"].values())
    assert gate._validate_receipt_document(_build_failed_receipt())["schema_version"] == gate.SCHEMA_VERSION


def test_v2_post_drift_has_precedence_over_build_observation(tmp_path: Path) -> None:
    args = _authority_args(tmp_path)
    authority_path = tmp_path / "authority.json"
    authority, authority_sha256 = gate._freeze_authority(args, authority_path)
    before = gate._provenance_inventory()
    after = copy.deepcopy(before)
    after[0]["sha256"] = "0" * 64
    receipt = gate._convert_to_v2(_build_failed_receipt(), authority, authority_sha256, before, after)
    validated = gate._validate_receipt_document(receipt)
    assert validated["status"] == "provenance_drift"
    assert validated["blockers"] == ["authority_or_provenance_changed"]
    assert validated["provenance"]["unchanged"] is False


def test_authority_rejects_gate_schema_test_and_interpreter_substitution(tmp_path: Path, monkeypatch) -> None:
    args = _authority_args(tmp_path)
    authority_path = tmp_path / "authority.json"
    authority, _digest = gate._freeze_authority(args, authority_path)
    forged = copy.deepcopy(authority)
    forged["roles"][1]["sha256"] = "0" * 64
    forged["roles_sha256"] = gate._inventory_digest(forged["roles"])
    authority_path.write_bytes(gate._canonical_json_bytes(forged))
    try:
        gate._load_authority(authority_path, args)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "authority_role_mismatch"
    else:
        raise AssertionError("schema substitution accepted")

    authority_path.unlink()
    gate._freeze_authority(args, authority_path)
    alternate = tmp_path / "python.exe"
    shutil.copyfile(sys.executable, alternate)
    monkeypatch.setattr(gate.sys, "executable", str(alternate))
    try:
        gate._load_authority(authority_path, args)
    except gate.ReceiptValidationError as exc:
        assert str(exc) in {"authority_role_mismatch", "authority_invocation_mismatch"}
    else:
        raise AssertionError("interpreter substitution accepted")


def test_authority_freeze_never_overwrites_existing_file(tmp_path: Path) -> None:
    args = _authority_args(tmp_path)
    authority_path = tmp_path / "authority.json"
    authority_path.write_bytes(b"keep")
    try:
        gate._freeze_authority(args, authority_path)
    except ValueError as exc:
        assert str(exc) == "future_path_not_fresh"
    else:
        raise AssertionError("authority overwrite accepted")
    assert authority_path.read_bytes() == b"keep"


def test_authority_freeze_and_validate_have_no_child_path(tmp_path: Path, monkeypatch) -> None:
    args = _authority_args(tmp_path)
    authority_path = tmp_path / "authority.json"
    monkeypatch.setattr(
        gate, "_run_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("child spawned")),
    )
    document, digest = gate._freeze_authority(args, authority_path)
    loaded, loaded_digest = gate._load_authority(authority_path, args)
    assert loaded == document and loaded_digest == digest
    assert not Path(args.output).exists() and not Path(args.receipt).exists()


def test_v2_schema_and_semantics_reject_claim_and_authority_digest_forgery(tmp_path: Path) -> None:
    args = _authority_args(tmp_path)
    authority_path = tmp_path / "authority.json"
    authority, authority_sha256 = gate._freeze_authority(args, authority_path)
    roles = gate._provenance_inventory()
    receipt = gate._convert_to_v2(_build_failed_receipt(), authority, authority_sha256, roles, roles)
    schema = json.loads(SCHEMA_V2.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(receipt)
    forged_claim = copy.deepcopy(receipt)
    forged_claim["claims"]["runtime_validated"] = True
    try:
        gate._validate_receipt_document(forged_claim)
    except gate.ReceiptValidationError:
        pass
    else:
        raise AssertionError("v2 true claim accepted")
    forged_digest = copy.deepcopy(receipt)
    forged_digest["provenance"]["authority_sha256"] = "0" * 64
    try:
        gate._validate_receipt_document(forged_digest)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "receipt_authority_digest_invalid"
    else:
        raise AssertionError("authority digest forgery accepted")


def test_v2_authority_snapshot_claims_remain_false_without_schema_assistance(
    tmp_path: Path, monkeypatch,
) -> None:
    args = _authority_args(tmp_path)
    authority_path = tmp_path / "authority.json"
    authority, authority_sha256 = gate._freeze_authority(args, authority_path)
    roles = gate._provenance_inventory()
    receipt = gate._convert_to_v2(_build_failed_receipt(), authority, authority_sha256, roles, roles)
    snapshot = receipt["provenance"]["authority_snapshot"]
    snapshot["claims"]["build_executed"] = True
    receipt["provenance"]["authority_sha256"] = __import__('hashlib').sha256(
        gate._canonical_json_bytes(snapshot)
    ).hexdigest()
    receipt["provenance"]["authority_post_sha256"] = receipt["provenance"]["authority_sha256"]
    monkeypatch.setattr(
        gate, "Draft202012Validator",
        lambda _schema: SimpleNamespace(iter_errors=lambda _value: []),
    )
    try:
        gate._validate_receipt_document(receipt)
    except gate.ReceiptValidationError as exc:
        assert str(exc) == "authority_claims_invalid"
    else:
        raise AssertionError("v2 authority snapshot promotion accepted after schema weakening")
