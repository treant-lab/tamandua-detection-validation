import copy
import importlib.util
import json
import os
import shutil
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_linux_ebpf_lsm_observe_only_static_gate.py"
SPEC = importlib.util.spec_from_file_location("linux_lsm_static_gate", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(GATE)


def copy_scope(root):
    for relative in GATE.ALL_FILES:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)


def fixture(root=ROOT):
    return GATE.load_json(root / GATE.FIXTURE_PATH)


def write_fixture(root, value):
    (root / GATE.FIXTURE_PATH).write_text(json.dumps(value), encoding="utf-8")


def test_historical_contract_is_immutable_and_current_head_drift_fails_closed():
    assert GATE.validate_paths(ROOT) == []
    source_errors = GATE.validate_sources(ROOT)
    assert "source:rust:sha256" in source_errors
    assert "source:c:sha256" in source_errors
    assert GATE.validate_gate_policy(ROOT) == []
    assert GATE.validate_schema(ROOT) == []
    assert GATE.validate_receipt(fixture()) == []
    result = GATE.run_gate(ROOT)
    assert result["ok"] is False
    assert result["failures"]["sources"] == source_errors


@pytest.mark.parametrize(
    "addition",
    [
        '\n// #[lsm(hook = "hidden_comment")]\n',
        '\nconst NOTE: &str = "#[lsm(hook = \\"hidden_string\\")]";\n',
        '\nconst RAW: &str = r#"#[lsm(hook = "hidden_raw")]"#;\n',
    ],
)
def test_comment_string_and_raw_source_drift_fail_by_immutable_hash(tmp_path, addition):
    copy_scope(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    source.write_text(source.read_text(encoding="utf-8") + addition, encoding="utf-8")
    errors = GATE.validate_sources(tmp_path)
    assert "source:rust:sha256" in errors


def test_duplicate_hook_fails_hash_and_closed_inventory(tmp_path):
    copy_scope(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    duplicate = '\n#[lsm(hook = "file_open")]\npub fn duplicate(ctx: LsmContext) -> i32 { 0 }\n'
    source.write_text(source.read_text(encoding="utf-8") + duplicate, encoding="utf-8")
    errors = GATE.validate_sources(tmp_path)
    assert "source:rust:sha256" in errors
    assert "source:rust:inventory" in errors


@pytest.mark.parametrize(
    "addition",
    [
        '\n#define EXTRA_LSM SEC("lsm/file_open")\n',
        '\n#define HOOK(name) SEC("lsm/" name)\n',
        '\n#if 0\nSEC("lsm/hidden") int BPF_PROG(hidden, int ret) { return ret; }\n#endif\n',
    ],
)
def test_preprocessor_and_macro_drift_fail_immutable_hash(tmp_path, addition):
    copy_scope(tmp_path)
    source = tmp_path / GATE.C_PATH
    source.write_text(source.read_text(encoding="utf-8") + addition, encoding="utf-8")
    assert "source:c:sha256" in GATE.validate_sources(tmp_path)


def test_source_symlink_is_rejected_before_read(tmp_path):
    copy_scope(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    target = tmp_path / "outside.rs"
    target.write_bytes(source.read_bytes())
    source.unlink()
    try:
        os.symlink(target, source)
    except OSError as error:
        pytest.skip(f"symlink unsupported on host: {error}")
    errors = GATE.validate_paths(tmp_path)
    assert f"path:{GATE.RUST_PATH}:regular_confined_required" in errors


@pytest.mark.parametrize(
    "injection",
    [
        "import importlib\nimportlib.import_module('subprocess')\n",
        "__import__('os').system('true')\n",
        "open('x', 'w')\n",
        "Path('x').write_text('x')\n",
        "writer = Path('x').write_text\nwriter('x')\n",
        "loader = __import__\nstage_two = loader\nstage_two('os')\n",
        "opener = open\nstage_two = opener\nstage_two('x', 'w')\n",
        "writer = Path.write_text\nstage_two = writer\nstage_two(Path('x'), 'x')\n",
        "stream = Path('x').open('w')\n",
        "getattr(json, 'loads')('{}')\n",
        "vars(vars(__builtins__)['__import__']('os'))['system']('true')\n",
    ],
)
def test_dynamic_import_and_write_paths_fail_ast_policy(tmp_path, injection):
    copy_scope(tmp_path)
    script = tmp_path / GATE.SCRIPT_PATH
    script.write_text(injection + script.read_text(encoding="utf-8"), encoding="utf-8")
    errors = GATE.validate_gate_policy(tmp_path)
    assert errors
    assert set(errors) & {"contract:dependencies", "contract:dynamic_or_write_call", "contract:dynamic_or_write_reference", "contract:dunder_reference"}


@pytest.mark.parametrize(
    "injection",
    [
        "__builtins__.__dict__['__import__']('os').system('true')\n",
        "Path.__dict__['open'](Path('x'), 'w').write('x')\n",
        "extracted = Path.__class__.__mro__[1].__subclasses__\n",
        "extracted = Path.__getattribute__\n",
    ],
)
def test_dunder_namespace_extraction_fails_closed(tmp_path, injection):
    copy_scope(tmp_path)
    script = tmp_path / GATE.SCRIPT_PATH
    script.write_text(injection + script.read_text(encoding="utf-8"), encoding="utf-8")
    assert "contract:dunder_reference" in GATE.validate_gate_policy(tmp_path)


def test_canonical_file_and_name_dunders_remain_allowed():
    assert GATE.validate_gate_policy(ROOT) == []


def test_prior_true_cannot_coexist_with_degraded_v1(tmp_path):
    copy_scope(tmp_path)
    value = fixture(tmp_path)
    value["assessment"]["prior_lsm_decision_preserved"] = True
    write_fixture(tmp_path, value)
    assert "receipt:assessment" in GATE.validate_receipt(value)


@pytest.mark.parametrize(
    "blockers",
    [
        [],
        ["prior_lsm_decision_not_preserved"],
        ["decisive_behavior_not_formally_proven", "prior_lsm_decision_not_preserved"],
        GATE.BLOCKERS + ["extra"],
    ],
)
def test_blockers_are_exact_and_ordered(blockers):
    value = copy.deepcopy(fixture())
    value["blockers"] = blockers
    assert "receipt:immutable_constants" in GATE.validate_receipt(value)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(capability_state="source_observe_only"),
        lambda value: value["assessment"].update(decisive_behavior_assessment="absent"),
        lambda value: value["lifecycle"].update(load_requested=True),
        lambda value: value["lifecycle"].update(attach_authorized=True),
        lambda value: value["claims"].update(build_validated=True),
        lambda value: value["claims"].update(external_claim_allowed=True),
    ],
)
def test_state_lifecycle_and_claims_are_immutable(mutate):
    value = copy.deepcopy(fixture())
    mutate(value)
    assert GATE.validate_receipt(value)


def test_schema_constants_and_closure_are_exact(tmp_path):
    copy_scope(tmp_path)
    schema = tmp_path / GATE.SCHEMA_PATH
    text = schema.read_text(encoding="utf-8")
    schema.write_text(text.replace('"additionalProperties": false', '"additionalProperties": true', 1), encoding="utf-8")
    assert "schema:top" in GATE.validate_schema(tmp_path)
    copy_scope(tmp_path)
    text = schema.read_text(encoding="utf-8")
    schema.write_text(text.replace('"capability_state": {"const": "degraded_unproven"}', '"capability_state": {"const": "source_observe_only"}', 1), encoding="utf-8")
    assert "schema:constants" in GATE.validate_schema(tmp_path)


@pytest.mark.parametrize(
    ("current", "replacement", "error"),
    [
        (GATE.RUST_PATH, "apps/tamandua_agent/other.rs", "schema:source:rust:binding"),
        (GATE.C_SHA256, "0" * 64, "schema:source:c:binding"),
        ('"task_kill"]', '"task_kill", "hidden"]', "schema:source:rust:binding"),
    ],
)
def test_schema_source_bindings_are_exact(tmp_path, current, replacement, error):
    copy_scope(tmp_path)
    schema = tmp_path / GATE.SCHEMA_PATH
    schema.write_text(schema.read_text(encoding="utf-8").replace(current, replacement, 1), encoding="utf-8")
    assert error in GATE.validate_schema(tmp_path)


def test_hidden_contract_file_and_dependency_are_rejected(tmp_path):
    copy_scope(tmp_path)
    hidden = tmp_path / "tools/detection_validation/scripts/anti_cheat_linux_ebpf_lsm_observe_only_hidden.py"
    hidden.write_text("pass\n", encoding="utf-8")
    assert "contract:file_set" in GATE.validate_gate_policy(tmp_path)
    hidden.unlink()
    script = tmp_path / GATE.SCRIPT_PATH
    script.write_text("import socket\n" + script.read_text(encoding="utf-8"), encoding="utf-8")
    assert "contract:dependencies" in GATE.validate_gate_policy(tmp_path)


def test_nested_hidden_contract_file_is_rejected(tmp_path):
    copy_scope(tmp_path)
    hidden = tmp_path / "tools/detection_validation/scripts/nested/anti_cheat_linux_ebpf_lsm_observe_only_hidden.py"
    hidden.parent.mkdir()
    hidden.write_text("pass\n", encoding="utf-8")
    assert "contract:file_set" in GATE.validate_gate_policy(tmp_path)
