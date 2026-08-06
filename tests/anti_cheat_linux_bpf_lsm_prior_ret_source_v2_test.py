import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_linux_bpf_lsm_prior_ret_source_v2_gate.py"
SPEC = importlib.util.spec_from_file_location("prior_ret_v2_gate", SCRIPT)
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


def test_current_v2_contract_passes_source_only():
    result = GATE.run_gate(ROOT)
    assert result["ok"] is True
    assert result["failures"] == {}
    assert result["blockers"] == GATE.BLOCKERS


@pytest.mark.parametrize("observed_at", ["2026-02-30T01:00:00Z", "2026-07-18T01:00:01Z", "not-a-time"])
def test_observed_at_is_an_immutable_constant(observed_at):
    value = copy.deepcopy(fixture())
    value["observed_at"] = observed_at
    assert "receipt:observed_at" in GATE.validate_receipt(value)


@pytest.mark.parametrize("name", ["ast", "json", "hashlib"])
def test_sibling_stdlib_shadow_is_rejected(tmp_path, name):
    copy_scope(tmp_path)
    shadow = tmp_path / "tools/detection_validation/scripts" / f"{name}.py"
    shadow.write_text("SHADOW_MARKER = True\n", encoding="utf-8")
    assert f"shadow:{name}" in GATE.validate_shadow_modules(tmp_path)


def test_sibling_stdlib_package_shadow_is_rejected(tmp_path):
    copy_scope(tmp_path)
    shadow = tmp_path / "tools/detection_validation/scripts/ast/__init__.py"
    shadow.parent.mkdir(parents=True)
    shadow.write_text("SHADOW_MARKER = True\n", encoding="utf-8")
    assert "shadow:ast" in GATE.validate_shadow_modules(tmp_path)


def test_pythonpath_workspace_shadow_cli_is_not_imported(tmp_path):
    copy_scope(tmp_path)
    scripts = tmp_path / "tools/detection_validation/scripts"
    (scripts / "ast.py").write_text("SHADOW_MARKER = True\n", encoding="utf-8")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(scripts)
    completed = subprocess.run([sys.executable, str(tmp_path / GATE.SCRIPT_PATH)], cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 1
    assert '"shadow:ast"' in completed.stdout
    assert "Traceback" not in completed.stderr


def _run_shadow_cli(tmp_path, pythonpath):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(pythonpath)
    return subprocess.run([sys.executable, str(tmp_path / GATE.SCRIPT_PATH)], cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=10)


def test_pythonpath_traversal_cannot_execute_shadow_marker(tmp_path):
    copy_scope(tmp_path)
    shadow = tmp_path / "traversal-shadow"
    shadow.mkdir()
    (shadow / "ast.py").write_text('print("SHADOW_MARKER_EXECUTED")\n', encoding="utf-8")
    relative = os.path.relpath(shadow, sys.base_prefix)
    if ".." not in Path(relative).parts:
        pytest.skip("host layout does not produce traversal from base_prefix")
    lexical = Path(sys.base_prefix) / relative
    completed = _run_shadow_cli(tmp_path, lexical)
    assert "SHADOW_MARKER_EXECUTED" not in completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr


def test_pythonpath_symlink_cannot_execute_shadow_marker(tmp_path):
    copy_scope(tmp_path)
    shadow = tmp_path / "symlink-shadow-target"
    shadow.mkdir()
    (shadow / "ast.py").write_text('print("SHADOW_MARKER_EXECUTED")\n', encoding="utf-8")
    link = tmp_path / "symlink-shadow-link"
    try:
        link.symlink_to(shadow, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink unsupported on host: {error}")
    assert GATE._bootstrap_realpath(str(link)) == GATE._bootstrap_realpath(str(shadow))
    completed = _run_shadow_cli(tmp_path, link)
    assert "SHADOW_MARKER_EXECUTED" not in completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr


def test_import_provenance_drift_is_rejected(tmp_path, monkeypatch):
    fake = tmp_path / "ast.py"
    fake.write_text("SHADOW_MARKER = True\n", encoding="utf-8")
    monkeypatch.setattr(GATE.ast.__spec__, "origin", str(fake))
    assert "provenance:ast" in GATE.validate_import_provenance()


@pytest.mark.parametrize("mutation", ["removed", "reordered"])
def test_bootstrap_removed_or_reordered_fails_policy(tmp_path, mutation):
    copy_scope(tmp_path)
    script = tmp_path / GATE.SCRIPT_PATH
    text = script.read_text(encoding="utf-8")
    if mutation == "removed":
        text = text.replace("    sys.path[:] = _trusted_sys_path\n", "", 1)
    else:
        text = text.replace("import ast\n", "", 1).replace("import sys\n", "import sys\nimport ast\n", 1)
    script.write_text(text, encoding="utf-8")
    assert "contract:bootstrap" in GATE.validate_policy(tmp_path)


def test_bootstrap_store_after_import_with_string_token_fails_policy(tmp_path):
    copy_scope(tmp_path)
    script = tmp_path / GATE.SCRIPT_PATH
    text = script.read_text(encoding="utf-8")
    text = text.replace("    sys.path[:] = _trusted_sys_path\n", "    'sys.path[:] = _trusted_sys_path'\n", 1)
    text = text.replace("import ast\n", "import ast\nsys.path[:] = _trusted_sys_path\n", 1)
    script.write_text(text, encoding="utf-8")
    assert "contract:bootstrap" in GATE.validate_policy(tmp_path)


def test_bootstrap_store_outside_main_guard_fails_policy(tmp_path):
    copy_scope(tmp_path)
    script = tmp_path / GATE.SCRIPT_PATH
    text = script.read_text(encoding="utf-8")
    text = text.replace("    sys.path[:] = _trusted_sys_path\n", "", 1)
    text = text.replace("import ast\n", "sys.path[:] = _trusted_sys_path\n\nimport ast\n", 1)
    script.write_text(text, encoding="utf-8")
    assert "contract:bootstrap" in GATE.validate_policy(tmp_path)


@pytest.mark.parametrize(
    "statement,replacement",
    [
        (
            "return _bootstrap_fs._getfinalpathname(_bootstrap_fs._getfullpathname(entry)).lower()",
            "return '_bootstrap_fs._getfinalpathname(_bootstrap_fs._getfullpathname(entry))'",
        ),
        (
            "target = _bootstrap_fs.readlink(candidate)",
            "'target = _bootstrap_fs.readlink(candidate)'",
        ),
        (
            "_expected_realpaths.add(_bootstrap_realpath(_expected))",
            "'_expected_realpaths.add(_bootstrap_realpath(_expected))'",
        ),
        (
            "_real_entry = _bootstrap_realpath(_entry)",
            "'_real_entry = _bootstrap_realpath(_entry)'",
        ),
        (
            "if _real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path:",
            "if '_real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path':",
        ),
    ],
)
def test_bootstrap_token_in_string_cannot_replace_ast_shape(tmp_path, statement, replacement):
    copy_scope(tmp_path)
    script = tmp_path / GATE.SCRIPT_PATH
    text = script.read_text(encoding="utf-8")
    assert statement in text
    script.write_text(text.replace(statement, replacement, 1), encoding="utf-8")
    assert "contract:bootstrap" in GATE.validate_policy(tmp_path)


@pytest.mark.parametrize(
    "replacement",
    [
        "if (_real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path) or True:",
        "if (_real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path) and False:",
        "_real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path\n        if True:",
    ],
)
def test_append_guard_condition_must_directly_dominate_append(tmp_path, replacement):
    copy_scope(tmp_path)
    script = tmp_path / GATE.SCRIPT_PATH
    text = script.read_text(encoding="utf-8")
    condition = "if _real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path:"
    assert condition in text
    script.write_text(text.replace(condition, replacement, 1), encoding="utf-8")
    assert "contract:bootstrap" in GATE.validate_policy(tmp_path)


@pytest.mark.parametrize("hook,index", sorted(GATE.RUST_INDICES.items()))
def test_each_rust_index_is_exact(tmp_path, hook, index):
    copy_scope(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    text = source.read_text(encoding="utf-8")
    old = f"let prior_ret: i32 = unsafe {{ ctx.arg({index}) }};"
    start = text.index(f"pub fn lsm_{hook}")
    end = text.index(f"fn try_lsm_{hook}", start)
    wrapper = text[start:end]
    assert old in wrapper
    mutated = wrapper.replace(old, f"let prior_ret: i32 = unsafe {{ ctx.arg({index + 1}) }};", 1)
    source.write_text(text[:start] + mutated + text[end:], encoding="utf-8")
    assert f"rust:{hook}:wrapper" in GATE.validate_rust_shape(source.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ("let prior_ret: i32 = unsafe { ctx.arg(1) };", "let prior_ret = unsafe { ctx.arg(1) };", "rust:bprm_check_security:wrapper"),
        ("if prior_ret != 0 {\n        return prior_ret;\n    }", "if prior_ret == 0 {\n        return prior_ret;\n    }", "rust:bprm_check_security:wrapper"),
        ("Err(_) => prior_ret", "Err(_) => 0", "rust:bprm_check_security:error_path"),
        ("return Ok(prior_ret);", "return Ok(0);", "rust:bprm_check_security:helper_exit"),
        ("(*event).ret = prior_ret;", "(*event).ret = 0;", "rust:bprm_check_security:event_ret"),
    ],
)
def test_rust_shape_mutations_fail_closed(tmp_path, old, new, expected):
    copy_scope(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    text = source.read_text(encoding="utf-8")
    assert old in text
    source.write_text(text.replace(old, new, 1), encoding="utf-8")
    assert expected in GATE.validate_rust_shape(source.read_text(encoding="utf-8"))


def test_rust_extraction_count_and_order_fail_closed(tmp_path):
    copy_scope(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    text = source.read_text(encoding="utf-8")
    marker = "let prior_ret: i32 = unsafe { ctx.arg(1) };"
    source.write_text(text.replace(marker, marker + "\n    " + marker, 1), encoding="utf-8")
    assert "rust:bprm_check_security:wrapper" in GATE.validate_rust_shape(source.read_text(encoding="utf-8"))


def test_rust_prior_ret_shadow_in_wrapper_fails_closed(tmp_path):
    copy_scope(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    text = source.read_text(encoding="utf-8")
    marker = "match try_lsm_bprm_check_security(&ctx, prior_ret) {"
    source.write_text(text.replace(marker, "let prior_ret = 0;\n    " + marker, 1), encoding="utf-8")
    assert "rust:bprm_check_security:ret_mutation" in GATE.validate_rust_shape(source.read_text(encoding="utf-8"))


@pytest.mark.parametrize("hook", sorted(GATE.C_HOOKS))
def test_each_c_return_is_prior_ret(tmp_path, hook):
    copy_scope(tmp_path)
    source = tmp_path / GATE.C_PATH
    text = source.read_text(encoding="utf-8")
    marker = f'SEC("lsm/{hook}")'
    start = text.index(marker)
    end = text.find('SEC("lsm/', start + len(marker))
    if end < 0:
        end = text.find('SEC("tracepoint/', start)
    body = text[start:end]
    assert "return ret;" in body
    source.write_text(text[:start] + body.replace("return ret;", "return 0;", 1) + text[end:], encoding="utf-8")
    assert f"c:{hook}:return" in GATE.validate_c_shape(source.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ("if (ret != 0)\n        return ret;", "if (ret == 0)\n        return ret;", "c:file_open:guard"),
        ("event->ret = ret;", "event->ret = 0;", "c:socket_connect:event_ret"),
        ("if (ret != 0)", "ret = 0;\n    if (ret != 0)", "c:file_open:guard"),
    ],
)
def test_c_guard_event_and_reassignment_fail_closed(tmp_path, old, new, expected):
    copy_scope(tmp_path)
    source = tmp_path / GATE.C_PATH
    text = source.read_text(encoding="utf-8")
    assert old in text
    source.write_text(text.replace(old, new, 1), encoding="utf-8")
    assert expected in GATE.validate_c_shape(source.read_text(encoding="utf-8"))


@pytest.mark.parametrize("mutation", ["ret++;", "--ret;", "ret %= 2;", "ret <<= 1;", "int ret;"])
def test_c_shadow_and_compound_ret_mutations_fail_closed(tmp_path, mutation):
    copy_scope(tmp_path)
    source = tmp_path / GATE.C_PATH
    text = source.read_text(encoding="utf-8")
    marker = "if (!is_enabled() || !file_monitoring_enabled())"
    source.write_text(text.replace(marker, mutation + "\n    " + marker, 1), encoding="utf-8")
    assert "c:file_open:ret_mutation" in GATE.validate_c_shape(source.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "path,old,expected",
    [
        (GATE.RUST_PATH, "(*event).ret = prior_ret;", "rust:bprm_check_security:event_ret"),
        (GATE.C_PATH, "event->ret = ret;", "c:socket_connect:event_ret"),
    ],
)
def test_required_event_ret_assignment_cannot_be_removed(tmp_path, path, old, expected):
    copy_scope(tmp_path)
    source = tmp_path / path
    text = source.read_text(encoding="utf-8")
    assert old in text
    source.write_text(text.replace(old, "", 1), encoding="utf-8")
    validator = GATE.validate_rust_shape if path == GATE.RUST_PATH else GATE.validate_c_shape
    assert expected in validator(source.read_text(encoding="utf-8"))


@pytest.mark.parametrize("kind", ["add", "duplicate", "omit"])
def test_hook_inventory_is_closed(tmp_path, kind):
    copy_scope(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    text = source.read_text(encoding="utf-8")
    if kind == "omit":
        text = text.replace('#[lsm(hook = "file_open")]', '#[tracepoint(name = "file_open")]', 1)
    else:
        hook = "hidden" if kind == "add" else "file_open"
        text += f'\n#[lsm(hook = "{hook}")]\npub fn extra(ctx: LsmContext) -> i32 {{ 0 }}\n'
    assert "rust:inventory" in GATE.validate_rust_shape(text)


def test_c_duplicate_hook_inventory_is_closed(tmp_path):
    copy_scope(tmp_path)
    source = tmp_path / GATE.C_PATH
    text = source.read_text(encoding="utf-8")
    text += '\nSEC("lsm/file_open") int BPF_PROG(extra, int ret) { return ret; }\n'
    assert "c:inventory" in GATE.validate_c_shape(text)


@pytest.mark.parametrize(
    "path,addition,label",
    [
        (GATE.RUST_PATH, '\n// #[lsm(hook = "hidden_comment")] {\n', "rust"),
        (GATE.RUST_PATH, '\nconst RAW: &str = r#"#[lsm(hook = \\"hidden_raw\\")] }"#;\n', "rust"),
        (GATE.C_PATH, '\n#define HIDDEN SEC("lsm/file_open")\n', "c"),
        (GATE.C_PATH, '\n#if 0\nSEC("lsm/hidden") int BPF_PROG(hidden, int ret) { return ret; }\n#endif\n', "c"),
    ],
)
def test_comment_raw_macro_and_preprocessor_drift_fail_by_hash(tmp_path, path, addition, label):
    copy_scope(tmp_path)
    source = tmp_path / path
    source.write_text(source.read_text(encoding="utf-8") + addition, encoding="utf-8")
    assert label in GATE.run_gate(tmp_path)["failures"]["hashes"]


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda value: value["lifecycle"].update(load_requested=True), "receipt:lifecycle"),
        (lambda value: value["claims"].update(build_validated=True), "receipt:claims"),
        (lambda value: value["assessment"].update(new_denial_introduced=True), "receipt:assessment"),
        (lambda value: value.update(blockers=[]), "receipt:blockers"),
        (lambda value: value["historical_v1"].update(fixture_sha256="0" * 64), "receipt:historical_v1"),
    ],
)
def test_receipt_lifecycle_claim_blocker_and_v1_digest_are_exact(mutate, expected):
    value = copy.deepcopy(fixture())
    mutate(value)
    assert expected in GATE.validate_receipt(value)


def test_schema_and_source_hash_drift_fail_closed(tmp_path):
    copy_scope(tmp_path)
    schema = tmp_path / GATE.SCHEMA_PATH
    schema.write_text(schema.read_text(encoding="utf-8").replace('"additionalProperties": false', '"additionalProperties": true', 1), encoding="utf-8")
    assert "schema:closed" in GATE.validate_schema(tmp_path)
    source = tmp_path / GATE.RUST_PATH
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert "rust" in GATE.run_gate(tmp_path)["failures"]["hashes"]


@pytest.mark.parametrize(
    "old,new,expected",
    [
        (GATE.RUST_PATH, "apps/tamandua_agent/other.rs", "schema:source:rust:binding"),
        (GATE.C_SHA256, "0" * 64, "schema:source:c:binding"),
        ('"file_open": {"const": 1}', '"file_open": {"const": 0}', "schema:sources:indices"),
        ('"build_validated": {"const": false}', '"build_validated": {"const": true}', "schema:claims:constants"),
        ('"supersedes_assessment_only"', '"replaces_history"', "schema:historical:constants"),
        ('"sources": {"$ref": "#/$defs/sources"}', '"sources": {"type": "object"}', "schema:sources:reference"),
    ],
)
def test_schema_manual_parity_bindings_fail_closed(tmp_path, old, new, expected):
    copy_scope(tmp_path)
    schema = tmp_path / GATE.SCHEMA_PATH
    text = schema.read_text(encoding="utf-8")
    assert old in text
    schema.write_text(text.replace(old, new, 1), encoding="utf-8")
    assert expected in GATE.validate_schema(tmp_path)


@pytest.mark.parametrize("injection", ["import subprocess\n", "open('x', 'w')\n", "Path('x').write_text('x')\n", "__builtins__.__dict__['open']('x','w')\n", "({'call': json.loads})['call']('{}')\n"])
def test_hidden_dependency_write_and_reflection_fail_closed(tmp_path, injection):
    copy_scope(tmp_path)
    script = tmp_path / GATE.SCRIPT_PATH
    script.write_text(injection + script.read_text(encoding="utf-8"), encoding="utf-8")
    assert GATE.validate_policy(tmp_path)
    hidden = tmp_path / "tools/detection_validation/scripts/anti_cheat_linux_bpf_lsm_prior_ret_source_v2_hidden.py"
    hidden.write_text("pass\n", encoding="utf-8")
    assert "contract:file_set" in GATE.validate_policy(tmp_path)


def test_nested_hidden_contract_file_is_rejected(tmp_path):
    copy_scope(tmp_path)
    hidden = tmp_path / "tools/detection_validation/scripts/nested/anti_cheat_linux_bpf_lsm_prior_ret_source_v2_hidden.py"
    hidden.parent.mkdir()
    hidden.write_text("pass\n", encoding="utf-8")
    assert "contract:file_set" in GATE.validate_policy(tmp_path)


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
    assert f"path:{GATE.RUST_PATH}" in GATE.validate_paths(tmp_path)
