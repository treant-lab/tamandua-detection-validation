import argparse
import copy
import json
import os
import sys
from pathlib import Path

import jsonschema
import pytest

from tools.detection_validation.scripts import ios_native_apns_categorical_receipt as receipt


OBS = {"outcome": "token_present", "permission": "granted", "token_type": "ios", "token_present": True, "token_length_bucket": "33-64"}
OUTPUT_NAME = "ios-native-apns-categorical-20260718T000000Z.json"

# receipt.generate/digest_file depend on POSIX-only semantics: exec-bit
# st_mode checks (chmod 0o755 is a no-op on Windows), os.O_DIRECTORY +
# dir_fd-based atomic publish, and fsync on a directory descriptor.  The
# receipt generator runs on macOS hosts; these tests cannot run on Windows.
requires_posix_fd_semantics = pytest.mark.skipif(
    os.name == "nt",
    reason="receipt.generate requires POSIX-only fd semantics "
    "(exec-bit checks, os.O_DIRECTORY, dir_fd atomic publish, directory fsync) "
    "not available on Windows",
)


def args(tmp_path, observation, executable, output=None):
    observation.write_text(json.dumps(OBS))
    executable.write_bytes(b"\xcf\xfa\xed\xfe"+b"app executable")
    executable.chmod(0o755)
    return argparse.Namespace(observation=str(observation), app_executable=str(executable), model_category="iphone_12", os_build_category="ios_26_0", output=str(output or tmp_path / OUTPUT_NAME))


def generate(tmp_path, monkeypatch):
    monkeypatch.setattr(receipt, "clean_source_sha", lambda: "a" * 40)
    monkeypatch.setattr(receipt, "GOVERNED_RUNS_DIR", tmp_path)
    return receipt.generate(args(tmp_path, tmp_path / "observation.json", tmp_path / "app", tmp_path / OUTPUT_NAME))


@requires_posix_fd_semantics
def test_generate_validate_strict_receipt(tmp_path, monkeypatch):
    value = generate(tmp_path, monkeypatch)
    receipt.validate_file(tmp_path / OUTPUT_NAME)
    jsonschema.validate(value, receipt.schema(), format_checker=jsonschema.FormatChecker())
    assert set(value["observation"]) == receipt.OBSERVATION_KEYS
    assert set(value["claims"].values()) == {False}
    assert value["receipt_signature_present"] is False
    rendered = json.dumps(value)
    assert "app executable" not in rendered and "/" not in value["device"]["model_category"]


@pytest.mark.parametrize("extra", ["raw_token", "token_hash", "device_id", "account_id", "path"])
def test_observation_rejects_extras(tmp_path, extra):
    path = tmp_path / "observation.json"
    path.write_text(json.dumps({**OBS, extra: "secret"}))
    with pytest.raises(receipt.ContractError, match="observation_fields_rejected"):
        receipt.read_observation(path)


@pytest.mark.parametrize("mutation", [
    lambda v: v["claims"].__setitem__("token_valid", True),
    lambda v: v["claims"].__setitem__("apns_delivery", True),
    lambda v: v["claims"].__setitem__("external_claim_allowed", True),
    lambda v: v.__setitem__("receipt_signature_present", True),
    lambda v: v["app"].__setitem__("configuration", "Release"),
    lambda v: v["app"].__setitem__("apns_environment", "production"),
    lambda v: v["device"].__setitem__("physical", False),
    lambda v: v.__setitem__("raw_token", "abc")
])
@requires_posix_fd_semantics
def test_claim_platform_and_extra_promotion_fail(tmp_path, monkeypatch, mutation):
    value = generate(tmp_path, monkeypatch)
    mutation(value)
    with pytest.raises((jsonschema.ValidationError, receipt.ContractError)):
        receipt.validate_receipt(value)


@requires_posix_fd_semantics
def test_digest_tamper_fails(tmp_path, monkeypatch):
    value = generate(tmp_path, monkeypatch)
    value["device"]["model_category"] = "iphone_17_pro_max"
    with pytest.raises(receipt.ContractError, match="manifest_digest_mismatch"):
        receipt.validate_receipt(value)


@pytest.mark.parametrize("category", ["device_id_123", "iphone_token_hash", "account_identifier_1", "file_path_1"])
@requires_posix_fd_semantics
def test_privacy_unsafe_model_category_rejected(tmp_path, monkeypatch, category):
    value = generate(tmp_path, monkeypatch)
    value["device"]["model_category"] = category
    unsigned = dict(value); unsigned.pop("manifest_sha256")
    value["manifest_sha256"] = receipt.hashlib.sha256(receipt.canonical(unsigned)).hexdigest()
    with pytest.raises((jsonschema.ValidationError,receipt.ContractError)):
        receipt.validate_receipt(value)


@requires_posix_fd_semantics
def test_unknown_model_category_is_not_an_identifier_escape(tmp_path,monkeypatch):
    value=generate(tmp_path,monkeypatch)
    value["device"]["model_category"]="iphone_deadbeef"
    unsigned=dict(value); unsigned.pop("manifest_sha256")
    value["manifest_sha256"]=receipt.hashlib.sha256(receipt.canonical(unsigned)).hexdigest()
    with pytest.raises(jsonschema.ValidationError):
        receipt.validate_receipt(value)


@requires_posix_fd_semantics
def test_overwrite_tmp_relative_and_traversal_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(receipt, "clean_source_sha", lambda: "a" * 40)
    monkeypatch.setattr(receipt, "GOVERNED_RUNS_DIR", tmp_path)
    observation, executable = tmp_path / "o.json", tmp_path / "app"
    a = args(tmp_path, observation, executable, tmp_path / OUTPUT_NAME)
    receipt.generate(a)
    with pytest.raises(FileExistsError): receipt.generate(a)
    for invalid in (Path("relative.json"), Path("/tmp/receipt.json"), tmp_path / ".." / "escape.json"):
        with pytest.raises(receipt.ContractError): receipt.safe_output(invalid)


def test_output_must_be_immediate_child_of_governed_runs(tmp_path, monkeypatch):
    governed=tmp_path/"runs"; governed.mkdir()
    monkeypatch.setattr(receipt,"GOVERNED_RUNS_DIR",governed)
    assert receipt.safe_output(governed/OUTPUT_NAME)==governed/OUTPUT_NAME
    outside=tmp_path/"outside"; outside.mkdir()
    with pytest.raises(receipt.ContractError,match="output_parent_missing"):
        receipt.safe_output(outside/OUTPUT_NAME)
    with pytest.raises(receipt.ContractError,match="output_filename_rejected"):
        receipt.safe_output(governed/"device-secret.json")


@requires_posix_fd_semantics
def test_partial_write_failure_removes_receipt(tmp_path,monkeypatch):
    monkeypatch.setattr(receipt,"clean_source_sha",lambda:"a"*40)
    monkeypatch.setattr(receipt,"GOVERNED_RUNS_DIR",tmp_path)
    arguments=args(tmp_path,tmp_path/"observation.json",tmp_path/"app",tmp_path/OUTPUT_NAME)
    monkeypatch.setattr(receipt.os,"write",lambda *_args:(_ for _ in ()).throw(OSError("private path")))
    with pytest.raises(OSError):
        receipt.generate(arguments)
    assert not (tmp_path/OUTPUT_NAME).exists()


@requires_posix_fd_semantics
def test_directory_fsync_failure_unpublishes_receipt(tmp_path,monkeypatch):
    monkeypatch.setattr(receipt,"clean_source_sha",lambda:"a"*40)
    monkeypatch.setattr(receipt,"GOVERNED_RUNS_DIR",tmp_path)
    arguments=args(tmp_path,tmp_path/"observation.json",tmp_path/"app",tmp_path/OUTPUT_NAME)
    real_fsync=receipt.os.fsync
    calls=0
    sentinel=OSError("directory durability failure")
    def fail_publish_fsync(descriptor):
        nonlocal calls
        calls+=1
        if calls==2:
            raise sentinel
        return real_fsync(descriptor)
    monkeypatch.setattr(receipt.os,"fsync",fail_publish_fsync)
    with pytest.raises(OSError,match="directory durability failure"):
        receipt.generate(arguments)
    assert calls==3
    assert not (tmp_path/OUTPUT_NAME).exists()


def test_cli_error_is_constant_and_does_not_reflect_path(monkeypatch,capsys):
    private="/private/customer/device-token.json"
    monkeypatch.setattr(sys,"argv",["receipt","validate",private])
    assert receipt.main()==1
    captured=capsys.readouterr()
    assert captured.out==""
    assert captured.err=="invalid: contract_rejected\n"
    assert private not in captured.err


def test_symlink_components_rejected(tmp_path):
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "link"; link.symlink_to(real, target_is_directory=True)
    with pytest.raises(receipt.ContractError, match="symlink_component_rejected"):
        receipt.safe_output(link / "receipt.json")
    observation = real / "o.json"; observation.write_text(json.dumps(OBS))
    alias = tmp_path / "o.json"; alias.symlink_to(observation)
    with pytest.raises(receipt.ContractError, match="symlink_component_rejected"):
        receipt.read_observation(alias)


def test_dirty_source_rejected(monkeypatch):
    class Result:
        stdout = " M file\n"
    monkeypatch.setattr(receipt.subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(receipt.ContractError, match="dirty_source_rejected"):
        receipt.clean_source_sha()


def test_nonhex_source_sha_rejected(monkeypatch):
    results=iter((type("Result",(),{"stdout":""})(),type("Result",(),{"stdout":"z"*40+"\n"})()))
    monkeypatch.setattr(receipt.subprocess,"run",lambda *a,**k:next(results))
    with pytest.raises(receipt.ContractError,match="source_sha_invalid"):
        receipt.clean_source_sha()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo does not exist on Windows")
def test_special_app_file_rejected(tmp_path):
    fifo=tmp_path/"app-fifo"
    receipt.os.mkfifo(fifo)
    with pytest.raises(receipt.ContractError,match="app_executable_rejected"):
        receipt.digest_file(fifo)


@pytest.mark.parametrize("payload,mode",((b"",0o755),(b"not-mach-o",0o755),(b"\xcf\xfa\xed\xfeapp",0o644)))
def test_app_binding_requires_nonempty_executable_macho(tmp_path,payload,mode):
    app=tmp_path/"app"
    app.write_bytes(payload); app.chmod(mode)
    with pytest.raises(receipt.ContractError,match="app_executable_rejected"):
        receipt.digest_file(app)


def test_observation_and_receipt_size_bounds(tmp_path):
    oversized=tmp_path/"oversized.json"
    oversized.write_bytes(b"x"*(64*1024+1))
    with pytest.raises(receipt.ContractError,match="observation_file_rejected"):
        receipt.read_observation(oversized)
    with pytest.raises(receipt.ContractError,match="receipt_file_rejected"):
        receipt.validate_file(oversized)


def test_read_limit_rejects_regular_file_growing_after_fstat(tmp_path,monkeypatch):
    path=tmp_path/"growing.json"; path.write_bytes(b"x")
    chunks=iter((b"a"*16,b"b"))
    monkeypatch.setattr(receipt.os,"read",lambda _fd,_size:next(chunks,b""))
    with pytest.raises(receipt.ContractError,match="observation_file_rejected"):
        receipt.read_regular_file(path,"observation_file_rejected",16)


@pytest.mark.parametrize("observation", [
    {**OBS, "token_present": False},
    {**OBS, "token_length_bucket": "none"},
    {**OBS, "permission": "denied"},
    {"outcome": "token_absent", "permission": "granted", "token_type": "unknown", "token_present": False, "token_length_bucket": "33-64"}
])
@requires_posix_fd_semantics
def test_incoherent_categories_rejected(tmp_path, monkeypatch, observation):
    value = generate(tmp_path, monkeypatch)
    value["observation"] = observation
    unsigned = dict(value); unsigned.pop("manifest_sha256")
    value["manifest_sha256"] = receipt.hashlib.sha256(receipt.canonical(unsigned)).hexdigest()
    with pytest.raises(receipt.ContractError, match="observation_categories_incoherent"):
        receipt.validate_receipt(value)


@pytest.mark.parametrize("observation",[
    {"outcome":"token_absent","permission":"granted","token_type":"unknown","token_present":False,"token_length_bucket":"none"},
    {"outcome":"permission_not_granted","permission":"denied","token_type":"unknown","token_present":False,"token_length_bucket":"none"},
    {"outcome":"permission_not_granted","permission":"undetermined","token_type":"unknown","token_present":False,"token_length_bucket":"none"},
    {"outcome":"error","permission":"unknown","token_type":"unknown","token_present":False,"token_length_bucket":"none"},
])
@requires_posix_fd_semantics
def test_closed_nonpresent_category_combinations_validate(tmp_path,monkeypatch,observation):
    value=generate(tmp_path,monkeypatch)
    value["observation"]=observation
    unsigned=dict(value); unsigned.pop("manifest_sha256")
    value["manifest_sha256"]=receipt.hashlib.sha256(receipt.canonical(unsigned)).hexdigest()
    receipt.validate_receipt(value)
