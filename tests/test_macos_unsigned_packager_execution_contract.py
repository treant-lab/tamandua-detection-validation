import copy
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import sys
import textwrap

import jsonschema
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / "tools/detection_validation/scripts/macos_unsigned_packager_execution_contract.py"
FILES = (
    pathlib.Path(".github/workflows/macos-unsigned-bundle-smoke.yml"),
    pathlib.Path("apps/tamandua_agent/scripts/run_macos_unsigned_bundle_smoke.sh"),
    pathlib.Path("schemas/macos_unsigned_packager_execution_v1.schema.json"),
    pathlib.Path("apps/tamandua_agent/scripts/macos_unsigned_smoke_bootstrap_v1.json"),
    pathlib.Path("apps/tamandua_agent/scripts/macos_unsigned_smoke_requirements_v1.txt"),
    pathlib.Path("apps/tamandua_gui/.gitignore"),
    pathlib.Path("apps/tamandua_gui/package.json"),
    pathlib.Path("apps/tamandua_gui/package-lock.json"),
    pathlib.Path("apps/tamandua_gui/src-tauri/Cargo.toml"),
    pathlib.Path("apps/tamandua_gui/src-tauri/Cargo.lock"),
    pathlib.Path("schemas/macos_unsigned_smoke_attempt_v1.schema.json"),
)

ATTEMPT_SCHEMA = FILES[10]


def load_module():
    spec = importlib.util.spec_from_file_location("macos_unsigned_packager_execution_contract", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(tmp_path):
    for relative in FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    return tmp_path


def mutate(root, relative, old, new):
    path = root / relative
    source = path.read_text()
    assert old in source
    path.write_text(source.replace(old, new, 1))


def test_repository_contract_passes():
    assert load_module().validate(ROOT) == []


@pytest.mark.parametrize(("old", "new", "problem"), [
    ("workflow_dispatch:", "push:\n    branches: [main]", "workflow:not_dispatch_only"),
    ("ref: ${{ inputs.source_sha }}", "ref: main", "workflow:checkout_step"),
    ("persist-credentials: false", "persist-credentials: true", "workflow:checkout_step"),
    ("runs-on: macos-15", "runs-on: macos-latest", "workflow:job_shape"),
    ("permissions:\n  contents: read", "permissions: write-all", "workflow:permissions"),
])
def test_workflow_mutations_fail_closed(tmp_path, old, new, problem):
    root = fixture(tmp_path)
    mutate(root, FILES[0], old, new)
    assert problem in load_module().validate(root)


@pytest.mark.parametrize(("old", "new"), [
    ('--config "$BUILD_TAURI_CONFIG" -- --locked)', '--config src-tauri/tauri.posix.conf.json -- --locked)'),
    ('[[ "$(git rev-parse HEAD)" == "$SOURCE_SHA" ]]', 'echo "$SOURCE_SHA"'),
    ("git status --porcelain=v1 --untracked-files=all", "git status --short"),
    ('SWIFT_ARM_SCRATCH="$BUILD_ROOT/swift-arm64"', 'SWIFT_ARM_SCRATCH="/tmp/swift"'),
    ('"native_execution_observed": True', '"native_execution_observed": False'),
])
def test_harness_contract_mutations_fail_closed(tmp_path, old, new):
    root = fixture(tmp_path)
    mutate(root, FILES[1], old, new)
    assert "harness:sealed_sha256_mismatch" in load_module().validate(root)


@pytest.mark.parametrize("payload", [
    "\nsudo true\n", "\nnotarytool submit candidate.zip\n", "\nsystemextensionsctl install bad\n",
    "\nlaunchctl load bad\n", "\nspctl --assess candidate.app\n", "\ngh release create v1\n",
    "\ncodesign --sign identity candidate.app\n", "\nrm -r candidate.app\n",
])
def test_privilege_signing_deploy_and_delete_are_forbidden(tmp_path, payload):
    root = fixture(tmp_path)
    path = root / FILES[1]
    path.write_text(path.read_text() + payload)
    assert "harness:sealed_sha256_mismatch" in load_module().validate(root)


def test_secret_and_environment_binding_are_forbidden(tmp_path):
    root = fixture(tmp_path)
    path = root / FILES[0]
    path.write_text(path.read_text() + "\nenvironment: production\nenv:\n  TOKEN: ${{ secrets.TOKEN }}\n")
    problems = load_module().validate(root)
    assert "workflow:root_shape" in problems


def test_tauri_target_cannot_escape_unique_run_root(tmp_path):
    root = fixture(tmp_path)
    mutate(root, FILES[1], 'TAURI_TARGET_ROOT="$BUILD_ROOT/tauri"', 'TAURI_TARGET_ROOT="$GUI_ROOT/src-tauri/target"')
    assert "harness:sealed_sha256_mismatch" in load_module().validate(root)


def test_unsigned_app_is_not_uploaded_as_evidence(tmp_path):
    root = fixture(tmp_path)
    path = root / FILES[1]
    path.write_text(path.read_text() + '\nditto "$CANDIDATE" "$UPLOAD_ROOT/candidate.app"\n')
    assert "harness:sealed_sha256_mismatch" in load_module().validate(root)


def test_executed_workflow_must_match_requested_source(tmp_path):
    root = fixture(tmp_path)
    mutate(root, FILES[0], '[[ "$WORKFLOW_SHA" == "$SOURCE_SHA" ]]', '[[ -n "$WORKFLOW_SHA" ]]')
    assert "workflow:validate_step" in load_module().validate(root)


def test_checkout_ref_main_cannot_be_spoofed_by_inert_expected_comment(tmp_path):
    root = fixture(tmp_path)
    mutate(root, FILES[0], "ref: ${{ inputs.source_sha }}", "ref: main # ref: ${{ inputs.source_sha }}")
    assert "workflow:checkout_step" in load_module().validate(root)


@pytest.mark.parametrize("replacement", [
    '# [[ "$(git rev-parse HEAD)" == "$SOURCE_SHA" ]]\ntrue',
    ': <<\'INERT\'\n[[ "$(git rev-parse HEAD)" == "$SOURCE_SHA" ]]\nINERT\ntrue',
    'expected=\'[[ "$(git rev-parse HEAD)" == "$SOURCE_SHA" ]]\'\ntrue',
])
def test_shell_assertion_cannot_be_spoofed_by_comment_heredoc_or_string(tmp_path, replacement):
    root = fixture(tmp_path)
    mutate(root, FILES[1], '[[ "$(git rev-parse HEAD)" == "$SOURCE_SHA" ]]', replacement)
    assert "harness:sealed_sha256_mismatch" in load_module().validate(root)


def valid_receipt(schema):
    digest = "a" * 64
    return {
        "schema_version": "tamandua.macos_unsigned_packager_execution/v1",
        "evidence_class": "github_hosted_unsigned_native_smoke", "state": "unsigned_native_smoke_validated",
        "native_execution_observed": True,
        "source": {"sha": "b" * 40, "workflow_sha256": digest, "harness_sha256": digest, "packager_sha256": digest, "v7_generator_sha256": digest, "execution_schema_sha256": digest, "execution_contract_sha256": digest, "bootstrap_manifest_sha256": digest, "python_requirements_sha256": digest},
        "runner": {"os": "macOS", "run_id": "1", "run_attempt": "1", "run_root_binding_sha256": digest, "clean_checkout": True, "command_runner_sha256": digest, "github_label": "macos-15", "architecture": "arm64", "developer_dir": "/Applications/Xcode_16.4.app/Contents/Developer", "sandbox_profile_sha256": digest, "source_authority_snapshot_sha256": digest},
        "toolchain": {**{key: "observed" for key in ("macos", "swift", "rustc", "cargo")}, "xcode": "Xcode 16.4 | Build version 16F6", "macos_sdk": "15.5", "python": "Python 3.12.10", "node": "v20.19.1", "npm": "10.8.2", "jsonschema": "4.25.1", "pyyaml": "6.0.2"},
        "inputs": {key: digest for key in ("development_team_sha256", "base_tauri_config_sha256", "package_json_sha256", "package_lock_sha256", "tauri_cargo_toml_sha256", "tauri_cargo_lock_sha256", "source_app_inventory_sha256", "daemon_binary_sha256", "system_extension_binary_sha256", "host_entitlements_sha256", "daemon_entitlements_sha256", "system_extension_entitlements_sha256")},
        "commands": [{"name": f"command_{index}", "argv": ["command", str(index)], "argv_sha256": digest, "cwd": "/runner/root", "expected_exit": "zero", "command_runner_sha256": digest, "intent_sha256": digest, "exit_code": 0,
                      "stdout": {"bytes_total": 0, "full_sha256": digest, "bounded_bytes": 0, "bounded_sha256": digest, "bounded_path": f"logs/command_{index}.stdout", "truncated": False},
                      "stderr": {"bytes_total": 0, "full_sha256": digest, "bounded_bytes": 0, "bounded_sha256": digest, "bounded_path": f"logs/command_{index}.stderr", "truncated": False}} for index in range(8)],
        "outputs": {key: digest for key in ("candidate_inventory_sha256", "binary_evidence_sha256", "v7_receipt_sha256", "race_evidence_sha256", "sandbox_profile_sha256")},
        "v7": {"schema_version": "tamandua.macos_unsigned_bundle_evidence/v7", "state": "unsigned_candidate_validated", "receipt_sha256": digest, "schema_valid": True},
        "race": {"kind": "output_path_rename", "rename_observed": True, "packager_failed_closed": True, "packager_exit_code": 65, "original_path_absent": True, "renamed_path_present": True, "partial_output_preserved": True, "stdout_sha256": digest, "stderr_sha256": digest, "stdout_path": "logs/race_packager.stdout", "stderr_path": "logs/race_packager.stderr", "argv": ["packager", "--app", "input"], "argv_sha256": digest, "intent_sha256": digest, "command_runner_sha256": digest},
        "lifecycle": {key: False for key in ("signed", "notarized", "installed", "activated", "runtime_observed", "released")},
        "claims": {key: False for key in ("identity_verified", "capability_proven", "product_ready", "production_ready", "external_claim_allowed")},
    }


def test_schema_rejects_false_native_observation_promoted_claims_and_bad_v7_state():
    schema = json.loads((ROOT / FILES[2]).read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    receipt = valid_receipt(schema)
    jsonschema.validate(receipt, schema)
    for path, value in (("native_execution_observed", False), ("claims.product_ready", True), ("lifecycle.signed", True), ("v7.state", "invalid_unsigned_candidate"), ("race.packager_exit_code", 0)):
        changed = copy.deepcopy(receipt)
        cursor = changed
        parts = path.split(".")
        for part in parts[:-1]:
            cursor = cursor[part]
        cursor[parts[-1]] = value
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(changed, schema)


def test_receipt_validator_binds_exact_argv_and_uploaded_bounded_logs(tmp_path, monkeypatch):
    module = load_module()
    schema = json.loads((ROOT / FILES[2]).read_text())
    receipt = valid_receipt(schema)
    runner_sha = module.derived_runner_sha256((ROOT / FILES[1]).read_text())
    assert runner_sha
    receipt["runner"]["command_runner_sha256"] = runner_sha
    authority_snapshot = "c" * 64
    receipt["runner"]["source_authority_snapshot_sha256"] = authority_snapshot
    monkeypatch.setattr(module, "tree_snapshot_digest", lambda _root: authority_snapshot)
    receipt["race"]["command_runner_sha256"] = runner_sha
    receipt["toolchain"]["rustc"] = "rustc 1.88.0 (observed) | host: aarch64-apple-darwin"
    receipt["toolchain"]["cargo"] = "cargo 1.88.0 (observed)"
    logs = tmp_path / "logs"
    logs.mkdir()
    empty_sha = hashlib.sha256(b"").hexdigest()
    source_roles = {
        "workflow_sha256": FILES[0], "harness_sha256": FILES[1],
        "packager_sha256": pathlib.Path("apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh"),
        "v7_generator_sha256": pathlib.Path("apps/tamandua_agent/scripts/macos_unsigned_bundle_evidence_v7.py"),
        "execution_schema_sha256": FILES[2], "execution_contract_sha256": VALIDATOR.relative_to(ROOT),
        "bootstrap_manifest_sha256": FILES[3], "python_requirements_sha256": FILES[4],
    }
    for field, relative in source_roles.items():
        receipt["source"][field] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    input_roles = {
        "base_tauri_config_sha256": pathlib.Path("apps/tamandua_gui/src-tauri/tauri.conf.json"),
        "package_json_sha256": pathlib.Path("apps/tamandua_gui/package.json"),
        "package_lock_sha256": pathlib.Path("apps/tamandua_gui/package-lock.json"),
        "tauri_cargo_toml_sha256": pathlib.Path("apps/tamandua_gui/src-tauri/Cargo.toml"),
        "tauri_cargo_lock_sha256": pathlib.Path("apps/tamandua_gui/src-tauri/Cargo.lock"),
        "host_entitlements_sha256": pathlib.Path("deploy/installers/macos/entitlements.plist"),
        "system_extension_entitlements_sha256": pathlib.Path("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist"),
    }
    for field, relative in input_roles.items():
        receipt["inputs"][field] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    events = tmp_path / "events"
    events.mkdir()
    for command in receipt["commands"]:
        command["command_runner_sha256"] = runner_sha
        command["argv_sha256"] = hashlib.sha256(json.dumps(command["argv"], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        intent = {key: command[key] for key in ("name", "argv", "argv_sha256", "cwd", "expected_exit", "command_runner_sha256")}
        intent_bytes = (json.dumps(intent, sort_keys=True) + "\n").encode()
        command["intent_sha256"] = hashlib.sha256(intent_bytes).hexdigest()
        (events / f"{command['name']}.intent.json").write_bytes(intent_bytes)
        for stream_name in ("stdout", "stderr"):
            (tmp_path / command[stream_name]["bounded_path"]).write_bytes(b"")
            command[stream_name]["bounded_sha256"] = empty_sha
            command[stream_name]["full_sha256"] = empty_sha
        (events / f"{command['name']}.completion.json").write_text(json.dumps(command, sort_keys=True) + "\n")
    receipt["race"]["argv_sha256"] = hashlib.sha256(json.dumps(receipt["race"]["argv"], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    for stream_name in ("stdout", "stderr"):
        (tmp_path / receipt["race"][f"{stream_name}_path"]).write_bytes(b"")
        receipt["race"][f"{stream_name}_sha256"] = empty_sha
    race_intent = {"name": "race_packager", "argv": receipt["race"]["argv"], "argv_sha256": receipt["race"]["argv_sha256"], "cwd": "/runner/root", "expected_exit": "nonzero", "command_runner_sha256": runner_sha}
    race_intent_bytes = (json.dumps(race_intent, sort_keys=True) + "\n").encode()
    receipt["race"]["intent_sha256"] = hashlib.sha256(race_intent_bytes).hexdigest()
    (events / "race_packager.intent.json").write_bytes(race_intent_bytes)
    race_completion = {**race_intent, "intent_sha256": receipt["race"]["intent_sha256"], "exit_code": receipt["race"]["packager_exit_code"],
                       "stdout": {"bounded_sha256": empty_sha}, "stderr": {"bounded_sha256": empty_sha}}
    (events / "race_packager.completion.json").write_text(json.dumps(race_completion, sort_keys=True) + "\n")
    output_roles = {
        "candidate_inventory_sha256": "candidate-inventory.json", "binary_evidence_sha256": "binary-evidence.json",
        "v7_receipt_sha256": "macos-unsigned-bundle-evidence-v7.json", "race_evidence_sha256": "race-evidence.json",
        "sandbox_profile_sha256": "macos-build.sb",
    }
    for index, (field, name) in enumerate(output_roles.items()):
        (tmp_path / name).write_text(f"evidence-{index}\n")
        receipt["outputs"][field] = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
    receipt["runner"]["sandbox_profile_sha256"] = receipt["outputs"]["sandbox_profile_sha256"]
    receipt["v7"]["receipt_sha256"] = receipt["outputs"]["v7_receipt_sha256"]
    assert module.receipt_problems(receipt, tmp_path, schema, ROOT) == []
    receipt["runner"]["sandbox_profile_sha256"] = "b" * 64
    assert "receipt:sandbox_profile_binding" in module.receipt_problems(receipt, tmp_path, schema, ROOT)
    receipt["runner"]["sandbox_profile_sha256"] = receipt["outputs"]["sandbox_profile_sha256"]
    receipt["runner"]["source_authority_snapshot_sha256"] = "b" * 64
    assert "receipt:source_authority_snapshot" in module.receipt_problems(receipt, tmp_path, schema, ROOT)
    receipt["runner"]["source_authority_snapshot_sha256"] = authority_snapshot
    receipt["commands"][0]["command_runner_sha256"] = "b" * 64
    assert "receipt:command_runner_event:command_0" in module.receipt_problems(receipt, tmp_path, schema, ROOT)
    receipt["commands"][0]["command_runner_sha256"] = runner_sha
    receipt["commands"][0]["argv"].append("--mutated")
    assert "receipt:argv_hash:command_0" in module.receipt_problems(receipt, tmp_path, schema, ROOT)
    receipt["commands"][0]["argv"].pop()
    (logs / "command_0.stdout").write_bytes(b"tampered")
    assert "receipt:bounded_hash:command_0:stdout" in module.receipt_problems(receipt, tmp_path, schema, ROOT)


@pytest.mark.parametrize(("section", "field", "problem"), [
    ("source", "workflow_sha256", "receipt:source_hash:workflow_sha256"),
    ("source", "packager_sha256", "receipt:source_hash:packager_sha256"),
    ("source", "execution_contract_sha256", "receipt:source_hash:execution_contract_sha256"),
    ("source", "bootstrap_manifest_sha256", "receipt:source_hash:bootstrap_manifest_sha256"),
    ("source", "python_requirements_sha256", "receipt:source_hash:python_requirements_sha256"),
    ("inputs", "package_lock_sha256", "receipt:input_hash:package_lock_sha256"),
    ("inputs", "tauri_cargo_lock_sha256", "receipt:input_hash:tauri_cargo_lock_sha256"),
    ("outputs", "v7_receipt_sha256", "receipt:output_hash:v7_receipt_sha256"),
    ("outputs", "binary_evidence_sha256", "receipt:output_hash:binary_evidence_sha256"),
])
def test_receipt_validator_rejects_arbitrary_valid_binding_digests(tmp_path, monkeypatch, section, field, problem):
    # Build the coherent fixture through the preceding helper test setup would
    # obscure failures; a mutated real receipt is covered by the shared helper.
    module = load_module()
    schema = json.loads((ROOT / FILES[2]).read_text())
    receipt = valid_receipt(schema)
    monkeypatch.setattr(module, "tree_snapshot_digest", lambda _root: receipt["runner"]["source_authority_snapshot_sha256"])
    assert receipt[section][field] == "a" * 64
    assert problem in module.receipt_problems(receipt, tmp_path, schema, ROOT)


def test_tree_snapshot_digest_detects_protected_input_mutation(tmp_path):
    module = load_module()
    authority = tmp_path / "authority"
    authority.mkdir()
    protected = authority / "source.rs"
    protected.write_text("trusted\n")
    baseline = module.tree_snapshot_digest(authority)
    protected.write_text("mutated\n")
    assert module.tree_snapshot_digest(authority) != baseline


def test_schema_seal_rejects_weakened_state(tmp_path):
    root = fixture(tmp_path)
    mutate(root, FILES[2], '"state": {"const": "unsigned_native_smoke_validated"}', '"state": {"type": "string"}')
    assert "schema:sealed_sha256_mismatch" in load_module().validate(root)


def test_runner_heredoc_mutation_and_inert_old_hash_fail_closed(tmp_path):
    root = fixture(tmp_path)
    mutate(root, FILES[1], "LIMIT = 65536", "LIMIT = 1 # LIMIT = 65536")
    problems = load_module().validate(root)
    assert "harness:sealed_sha256_mismatch" in problems
    assert "harness:command_runner_binding" in problems


def test_inline_launcher_executes_verified_bytes_without_reopening_runner_path():
    source = (ROOT / FILES[1]).read_text()
    assert '/usr/bin/python3 "$COMMAND_RUNNER"' not in source
    assert source.count('/usr/bin/python3 -I -S - "$COMMAND_RUNNER"') == 2
    assert 'fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))' in source
    assert 'compiled = compile(data, fixed_filename, "exec")' in source
    assert 'exec(compiled, namespace, namespace)' in source


def test_launcher_swap_to_path_reopen_fails_sealed_contract(tmp_path):
    root = fixture(tmp_path)
    mutate(root, FILES[1], 'compiled = compile(data, fixed_filename, "exec")', 'compiled = compile(open(path, "rb").read(), fixed_filename, "exec")')
    problems = load_module().validate(root)
    assert "harness:sealed_sha256_mismatch" in problems
    assert "harness:sealed_inline_launcher" in problems


def test_isolated_python_ignores_hostile_stdlib_shadow_modules(tmp_path):
    (tmp_path / "hashlib.py").write_text("raise SystemExit('hostile hashlib loaded')\n")
    (tmp_path / "argparse.py").write_text("raise SystemExit('hostile argparse loaded')\n")
    code = "import argparse,hashlib,pathlib; print(pathlib.Path(hashlib.__file__).parent); print(pathlib.Path(argparse.__file__).parent)"
    completed = subprocess.run([sys.executable, "-I", "-S", "-c", code], cwd=tmp_path, text=True, capture_output=True, check=True)
    assert "hostile" not in completed.stdout + completed.stderr
    assert str(tmp_path) not in completed.stdout


@pytest.mark.parametrize(("old", "new", "problem"), [
    ("actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065", "actions/setup-python@v5", "workflow:python_step"),
    ("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "actions/setup-node@main", "workflow:node_step"),
    ("runs-on: macos-15", "runs-on: macos-14", "workflow:job_shape"),
])
def test_bootstrap_workflow_mutations_fail_closed(tmp_path, old, new, problem):
    root = fixture(tmp_path)
    mutate(root, FILES[0], old, new)
    assert problem in load_module().validate(root)


@pytest.mark.parametrize(("old", "new"), [
    ("npm ci --ignore-scripts --cache", "npm ci --cache"),
    ("-- --locked", "-- --verbose"),
    ('RUSTUP_TOOLCHAIN="1.88.0"', 'RUSTUP_TOOLCHAIN="stable"'),
    ('RUSTUP_HOME="$BUILD_ROOT/rustup-home"', 'RUSTUP_HOME="$HOME/.rustup"'),
    ("--target x86_64-apple-darwin", "--target aarch64-apple-darwin"),
    ('DEVELOPER_DIR="/Applications/Xcode_16.4.app/Contents/Developer"', 'xcode-select -s /Applications/Xcode.app'),
])
def test_mutable_or_incomplete_harness_bootstrap_fails_seal(tmp_path, old, new):
    root = fixture(tmp_path)
    mutate(root, FILES[1], old, new)
    assert "harness:sealed_sha256_mismatch" in load_module().validate(root)


def test_ignored_missing_and_drifted_locks_fail_closed(tmp_path):
    module = load_module()
    ignored = fixture(tmp_path / "ignored")
    path = ignored / FILES[5]
    path.write_text(path.read_text() + "\npackage-lock.json\n")
    assert "bootstrap:locks_ignored" in module.validate(ignored)
    missing = fixture(tmp_path / "missing")
    (missing / FILES[7]).unlink()
    assert "package_lock:missing_or_unsafe" in module.validate(missing)
    drift = fixture(tmp_path / "drift")
    path = drift / FILES[7]
    path.write_text(path.read_text() + "\n")
    assert any(item.startswith("bootstrap:lock_hash:") for item in module.validate(drift))


@pytest.mark.parametrize(("old", "new", "problem"), [
    ("    --hash=sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309", "", "bootstrap:python_hash_policy"),
    ("typing-extensions==4.16.0", "omitted-typing-extension==4.16.0", "bootstrap:python_transitive_closure"),
    ("attrs==26.1.0", "https://example.invalid/attrs.tar.gz", "bootstrap:python_hash_policy"),
])
def test_python_lock_mutations_fail_closed(tmp_path, old, new, problem):
    root = fixture(tmp_path)
    mutate(root, FILES[4], old, new)
    assert problem in load_module().validate(root)


def test_bootstrap_manifest_and_receipt_digest_spoof_fail_closed(tmp_path):
    module = load_module()
    root = fixture(tmp_path / "manifest")
    mutate(root, FILES[3], '"github_label": "macos-15"', '"github_label": "macos-14"')
    problems = module.validate(root)
    assert "bootstrap:sealed_sha256_mismatch" in problems
    assert "bootstrap:runner" in problems


def test_locked_time_msrv_chain_requires_rust_188(tmp_path):
    module = load_module()
    root = fixture(tmp_path / "rust")
    mutate(root, FILES[3], '"toolchain": "1.88.0"', '"toolchain": "1.87.0"')
    problems = module.validate(root)
    assert "bootstrap:sealed_sha256_mismatch" in problems
    assert "bootstrap:rust_msrv" in problems
    lock_root = fixture(tmp_path / "lock")
    lock = lock_root / FILES[9]
    source = lock.read_text()
    decisive = 'name = "time-core"\nversion = "0.1.9"'
    assert decisive in source
    lock.write_text(source.replace(decisive, 'name = "time-core"\nversion = "0.1.8"', 1))
    assert "bootstrap:locked_msrv_chain" in module.validate(lock_root)


def test_sandbox_contract_separates_authority_and_denies_network_and_writes():
    source = (ROOT / FILES[1]).read_text()
    assert 'SOURCE_ROOT="$RUN_ROOT/source-authority"' in source
    assert 'BUILD_SOURCE_ROOT="$BUILD_ROOT/source"' in source
    assert '(allow file-write* (subpath {quote(build)}))' not in source
    assert '(subpath {quote(build_source)}) (subpath {quote(node_modules)})' in source
    assert '(subpath {quote(cargo_registry)}) (subpath {quote(cargo_git)})' in source
    assert "(deny network*)" in source
    assert "CARGO_NET_OFFLINE=true" in source
    assert "sandbox_authority_write_denial" in source
    assert "sandbox_build_source_write_denial" in source
    assert "sandbox_node_modules_write_denial" in source
    assert "sandbox_cargo_source_write_denial" in source
    assert "BUILD_SOURCE_SNAPSHOT_BASELINE" in source
    assert "DEPENDENCY_SNAPSHOT_BASELINE" in source
    assert "post_build_execution_contract" in source
    receipt_emission = source.index('SANDBOX_PROFILE_SHA256="$SANDBOX_PROFILE_SHA256" AUTHORITY_SNAPSHOT_SHA256=')
    pre_receipt_gate = "authority_unchanged\nprotected_build_inputs_unchanged\n"
    assert source.rfind(pre_receipt_gate, 0, receipt_emission) == receipt_emission - len(pre_receipt_gate)
    final_validation = source.index('"$PYTHON" "$EXECUTION_CONTRACT" --root "$SOURCE_ROOT" --receipt "$EXECUTION_RECEIPT"')
    final_gate = "authority_unchanged\nprotected_build_inputs_unchanged\n"
    final_gate_offset = source.index(final_gate, final_validation)
    success_marker = source.index('--attempt-log "$ATTEMPT_LOG" --append-validated-marker', final_validation)
    assert final_validation < success_marker < final_gate_offset < source.index('echo "$UPLOAD_ROOT"', final_gate_offset)
    assert source.rfind("protected_build_inputs_unchanged") == source.index("protected_build_inputs_unchanged", final_gate_offset)
    assert source.index("race_packager") < receipt_emission
    assert source.index("v7_generation") < receipt_emission


def test_sandbox_or_final_authority_gate_removal_fails_seal(tmp_path):
    root = fixture(tmp_path)
    mutate(root, FILES[1], "(deny network*)", "(allow network*)")
    problems = load_module().validate(root)
    assert "harness:sealed_sha256_mismatch" in problems
    assert "harness:immutable_bootstrap_command_missing" in problems


@pytest.mark.parametrize("old", [
    '[[ "$(tree_snapshot "$BUILD_SOURCE_ROOT")" == "$BUILD_SOURCE_SNAPSHOT_BASELINE" ]]',
    '[[ "$(dependency_snapshot)" == "$DEPENDENCY_SNAPSHOT_BASELINE" ]]',
])
def test_build_or_dependency_mutation_cannot_hide_behind_unchanged_authority(tmp_path, old):
    root = fixture(tmp_path)
    mutate(root, FILES[1], old, "true")
    problems = load_module().validate(root)
    assert "harness:sealed_sha256_mismatch" in problems
    assert "harness:immutable_bootstrap_command_missing" in problems


def test_broad_build_root_write_allow_is_rejected(tmp_path):
    root = fixture(tmp_path)
    path = root / FILES[1]
    path.write_text(path.read_text() + '\n# (allow file-write* (subpath {quote(build)}))\n')
    problems = load_module().validate(root)
    assert "harness:sandbox_broad_build_write" in problems


def test_npm_ignore_scripts_blocks_hostile_postinstall(tmp_path):
    npm = shutil.which("npm")
    if npm is None:
        pytest.skip("npm is unavailable")
    marker = tmp_path / "postinstall-ran"
    package = {
        "name": "tamandua-hostile-install-fixture", "version": "1.0.0", "private": True,
        "scripts": {"postinstall": f'node -e "require(\'fs\').writeFileSync({json.dumps(str(marker))}, \'bad\')"'},
    }
    (tmp_path / "package.json").write_text(json.dumps(package))
    subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run([npm, "ci", "--ignore-scripts", "--offline", "--no-audit", "--no-fund"], cwd=tmp_path, check=True, capture_output=True)
    assert not marker.exists()


@pytest.mark.parametrize(("old", "new", "problem"), [
    ('"source_pinned_native_execution_hold"', '"native_execution_validated"', "bootstrap:state"),
    ('"setup_action_toolcache_outside_run_root": true', '"setup_action_toolcache_outside_run_root": false', "bootstrap:isolation"),
    ('"rustup_bootstrap_network_root_not_repository_pinned": true', '"rustup_bootstrap_network_root_not_repository_pinned": false', "bootstrap:residual_risks"),
])
def test_bootstrap_hold_and_external_roots_remain_honest(tmp_path, old, new, problem):
    root = fixture(tmp_path)
    mutate(root, FILES[3], old, new)
    assert problem in load_module().validate(root)


def attempt_common(record_type, ordinal):
    return {
        "schema_version": "tamandua.macos_unsigned_smoke_attempt/v1",
        "record_type": record_type, "ordinal": ordinal, "run_id": "7", "run_attempt": "2",
        "lifecycle": {key: False for key in ("signed", "notarized", "installed", "activated", "runtime_observed", "released")},
        "claims": {key: False for key in ("identity_verified", "capability_proven", "product_ready", "production_ready", "external_claim_allowed")},
    }


def started_record():
    return {**attempt_common("attempt_started", 0), "source_input_sha256": "a" * 64,
            "development_team_input_sha256": "b" * 64, "workflow_sha_input_sha256": "c" * 64}


def phase_record(ordinal, phase, receipt_sha=None):
    record = {**attempt_common("phase", ordinal), "phase": phase}
    if receipt_sha is not None:
        record["native_receipt_sha256"] = receipt_sha
    return record


def terminal_record(job_status, outcome, values, receipt_sha=None):
    names = ("input", "checkout", "setup_python", "setup_node", "harness")
    record = {**attempt_common("terminal", 100), "pre_upload_status": job_status,
              "smoke_status": outcome, "artifact_delivery": "unknown",
              "step_outcomes": [{"step": name, "outcome": value} for name, value in zip(names, values)]}
    if receipt_sha is not None:
        record["native_receipt_sha256"] = receipt_sha
    return record


def write_attempt(path, records):
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))


def test_attempt_schema_is_closed_false_claiming_and_digest_only():
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(started_record(), schema)
    raw = copy.deepcopy(started_record())
    raw["source_sha"] = "f" * 40
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(raw, schema)
    promoted = copy.deepcopy(started_record())
    promoted["claims"]["product_ready"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(promoted, schema)


def test_incomplete_or_absent_attempt_remains_unknown(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, [started_record(), phase_record(10, "harness_entered")])
    assert module.attempt_log_problems(log, schema) == []
    assert module.attempt_log_state([started_record(), phase_record(10, "harness_entered")]) == "unknown"
    assert module.attempt_log_state([]) == "unknown"
    assert module.attempt_log_problems(tmp_path / "runner-lost.ndjson", schema) == ["attempt:absent_unknown"]


@pytest.mark.parametrize(("job_status", "values", "outcome"), [
    ("failure", ("failure", "skipped", "skipped", "skipped", "skipped"), "input"),
    ("failure", ("success", "failure", "skipped", "skipped", "skipped"), "checkout"),
    ("failure", ("success", "success", "failure", "skipped", "skipped"), "setup"),
    ("failure", ("success", "success", "success", "success", "failure"), "harness"),
    ("cancelled", ("success", "success", "success", "success", "cancelled"), "cancel"),
    ("failure", ("success", "success", "success", "success", "skipped"), "internal"),
])
def test_attempt_terminal_taxonomy_is_closed(tmp_path, job_status, values, outcome):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    log = tmp_path / "attempt.ndjson"
    terminal = terminal_record(job_status, outcome, values)
    write_attempt(log, [started_record(), terminal])
    assert module.attempt_log_problems(log, schema) == []
    assert module.attempt_log_state([started_record(), terminal]) == outcome


def test_non_json_digest_matched_receipt_cannot_forge_success(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    receipt = tmp_path / "macos-unsigned-packager-execution-v1.json"
    receipt.write_text("validated-native-receipt\n")
    digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
    records = [started_record(), phase_record(10, "harness_entered"), phase_record(20, "bootstrap_prepared"),
               phase_record(30, "builds_completed"), phase_record(40, "evidence_completed"),
               phase_record(50, "native_receipt_validated", digest),
               terminal_record("success", "success", ("success",) * 5, digest)]
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, records)
    problems = module.attempt_log_problems(
        log, schema, receipt, execution_schema={}, evidence_root=tmp_path, source_root=ROOT,
    )
    assert "attempt:native_receipt_json" in problems
    assert "attempt:success_receipt_binding" in problems


def test_attempt_success_revalidates_exact_json_receipt_and_cross_binding(tmp_path, monkeypatch):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    receipt_value = {
        "source": {"sha": "e" * 40}, "runner": {"run_id": "7", "run_attempt": "2"},
        "inputs": {"development_team_sha256": "b" * 64},
    }
    receipt = tmp_path / "macos-unsigned-packager-execution-v1.json"
    receipt.write_text(json.dumps(receipt_value, sort_keys=True))
    digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
    started = started_record()
    source_digest = hashlib.sha256(receipt_value["source"]["sha"].encode()).hexdigest()
    started["source_input_sha256"] = source_digest
    started["workflow_sha_input_sha256"] = source_digest
    records = [started, phase_record(10, "harness_entered"), phase_record(20, "bootstrap_prepared"),
               phase_record(30, "builds_completed"), phase_record(40, "evidence_completed"),
               phase_record(50, "native_receipt_validated", digest),
               terminal_record("success", "success", ("success",) * 5, digest)]
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, records)
    observed = []
    monkeypatch.setattr(module, "receipt_problems", lambda value, evidence, execution, source: observed.append((value, evidence, execution, source)) or [])
    assert module.attempt_log_problems(log, schema, receipt, execution_schema={}, evidence_root=tmp_path, source_root=ROOT) == []
    assert observed == [(receipt_value, tmp_path, {}, ROOT)]
    records[0]["run_attempt"] = "3"
    write_attempt(log, records)
    assert "attempt:native_receipt_cross_binding" in module.attempt_log_problems(
        log, schema, receipt, execution_schema={}, evidence_root=tmp_path, source_root=ROOT,
    )


def test_failure_cannot_invent_completions_or_native_receipt(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    terminal = terminal_record("failure", "harness", ("success", "success", "success", "success", "failure"))
    terminal["completions"] = [{"phase": "native_receipt_validated"}]
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, [started_record(), terminal])
    assert module.attempt_log_problems(log, schema) == ["attempt:schema:1"]


def test_attempt_ordinals_and_terminal_position_fail_closed(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    terminal = terminal_record("failure", "harness", ("success", "success", "success", "success", "failure"))
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, [started_record(), terminal, phase_record(10, "harness_entered")])
    problems = module.attempt_log_problems(log, schema)
    assert "attempt:ordinal_order" in problems
    assert "attempt:terminal_order" in problems


def test_attempt_phase_gap_is_not_accepted_as_ordered_progress(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, [started_record(), phase_record(20, "bootstrap_prepared")])
    assert "attempt:phase_prefix" in module.attempt_log_problems(log, schema)


def test_attempt_symlink_is_unknown_not_followed(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    target = tmp_path / "target.ndjson"
    write_attempt(target, [started_record()])
    link = tmp_path / "attempt.ndjson"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert module.attempt_log_problems(link, schema) == ["attempt:absent_unknown"]


def test_workflow_attempt_registration_and_terminalizer_order_is_exact():
    document = load_module().parsed_workflow((ROOT / FILES[0]).read_text())
    steps = document["jobs"]["unsigned-bundle-smoke"]["steps"]
    assert [step["name"] for step in steps] == [
        "Register append-only attempt", "Validate immutable inputs", "Checkout exact source", "Setup exact Python",
        "Setup exact Node", "Execute unsigned native smoke once", "Finalize append-only attempt", "Upload bounded unsigned evidence",
    ]
    assert steps[0]["run"].count("os.O_CREAT | os.O_EXCL") == 1
    assert "dir_fd=parent_fd" in steps[0]["run"]
    assert steps[6]["if"] == "always()"
    assert steps[6]["run"].count("os.O_RDWR | os.O_APPEND") == 1
    assert "os.O_DIRECTORY | os.O_NOFOLLOW" in steps[6]["run"]
    assert "fcntl.flock(fd, fcntl.LOCK_EX)" in steps[6]["run"]
    assert "completions" not in steps[6]["run"]
    assert "RUNNER_TEMP_ROOT" not in steps[6]["env"]
    assert "receipts[0].read_bytes()" not in steps[6]["run"]
    assert '"artifact_delivery": "unknown"' in steps[6]["run"]


def test_harness_phase_markers_are_append_only_and_success_follows_receipt_validation():
    source = (ROOT / FILES[1]).read_text()
    markers = ["append_attempt_phase 10 harness_entered", "append_attempt_phase 20 bootstrap_prepared",
               "append_attempt_phase 30 builds_completed", "append_attempt_phase 40 evidence_completed"]
    offsets = [source.index(marker) for marker in markers]
    assert offsets == sorted(offsets)
    validation = source.index('"$PYTHON" "$EXECUTION_CONTRACT" --root "$SOURCE_ROOT" --receipt "$EXECUTION_RECEIPT"')
    marker_50_transaction = source.index('--attempt-log "$ATTEMPT_LOG" --append-validated-marker', validation)
    assert offsets[-1] < validation < marker_50_transaction
    assert 'append_attempt_phase 50' not in source
    assert "os.O_RDWR | os.O_APPEND" in source
    assert "os.fsync(fd)" in source


@pytest.mark.parametrize(("status", "values", "phases"), [
    ("input", ("failure", "skipped", "skipped", "skipped", "skipped"), [10]),
    ("checkout", ("success", "failure", "skipped", "skipped", "skipped"), [10]),
    ("setup", ("success", "success", "failure", "skipped", "skipped"), [10]),
    ("harness", ("success", "success", "success", "success", "failure"), [10, 20, 30, 40, 50]),
])
def test_failure_status_cannot_claim_impossible_phase_progress(tmp_path, status, values, phases):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    names = {10: "harness_entered", 20: "bootstrap_prepared", 30: "builds_completed", 40: "evidence_completed", 50: "native_receipt_validated"}
    records = [started_record()]
    for ordinal in phases:
        records.append(phase_record(ordinal, names[ordinal], "d" * 64 if ordinal == 50 else None))
    records.append(terminal_record("failure", status, values))
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, records)
    assert "attempt:phase_outcome_matrix" in module.attempt_log_problems(log, schema)


def test_success_requires_complete_phase_prefix_and_native_snapshot(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, [started_record(), terminal_record("success", "success", ("success",) * 5, "d" * 64)])
    problems = module.attempt_log_problems(log, schema)
    assert "attempt:success_context_missing" in problems
    assert "attempt:phase_outcome_matrix" in problems
    assert "attempt:success_receipt_binding" in problems
    assert "attempt:all_success_requires_success" not in problems


def test_all_success_without_complete_phases_cannot_be_internal(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, [started_record(), terminal_record("failure", "internal", ("success",) * 5)])
    problems = module.attempt_log_problems(log, schema)
    assert "attempt:step_outcome_shape" in problems
    assert "attempt:all_success_requires_success" in problems
    assert "attempt:terminal_taxonomy" in problems


@pytest.mark.parametrize(("pre_upload_status", "smoke_status", "values"), [
    ("success", "input", ("failure", "skipped", "skipped", "skipped", "skipped")),
    ("success", "internal", ("success", "success", "success", "success", "skipped")),
    ("failure", "cancel", ("success", "success", "success", "success", "cancelled")),
    ("cancelled", "internal", ("success", "success", "success", "success", "skipped")),
])
def test_pre_upload_status_cannot_cross_failure_cancel_internal_boundary(
    tmp_path, pre_upload_status, smoke_status, values,
):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, [started_record(), terminal_record(pre_upload_status, smoke_status, values)])
    problems = module.attempt_log_problems(log, schema)
    assert "attempt:step_outcome_shape" in problems
    assert "attempt:terminal_taxonomy" in problems


def test_cli_has_one_unambiguous_native_receipt_path():
    validator = VALIDATOR.read_text()
    assert 'parser.add_argument("--native-receipt"' not in validator
    assert 'parser.add_argument("--receipt"' in validator


def test_empty_json_native_receipt_fails_categorically_without_key_dereference(tmp_path):
    module = load_module()
    attempt_schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    execution_schema = json.loads((ROOT / FILES[2]).read_text())
    receipt = tmp_path / "empty-native-receipt.json"
    receipt.write_text("{}")
    digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
    records = [started_record(), phase_record(10, "harness_entered"), phase_record(20, "bootstrap_prepared"),
               phase_record(30, "builds_completed"), phase_record(40, "evidence_completed"),
               phase_record(50, "native_receipt_validated", digest),
               terminal_record("success", "success", ("success",) * 5, digest)]
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, records)
    problems = module.attempt_log_problems(
        log, attempt_schema, receipt, execution_schema=execution_schema, evidence_root=tmp_path, source_root=ROOT,
    )
    assert "attempt:native_receipt_validation" in problems
    assert "attempt:success_receipt_binding" in problems
    completed = subprocess.run(
        [sys.executable, str(VALIDATOR), "--root", str(ROOT), "--receipt", str(receipt),
         "--evidence-root", str(tmp_path), "--attempt-log", str(log)],
        text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 2
    assert json.loads(completed.stdout)["state"] == "fail"
    assert "Traceback" not in completed.stderr


def test_validated_marker_cross_binds_stable_receipt_snapshot(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    receipt = valid_receipt(json.loads((ROOT / FILES[2]).read_text()))
    receipt["runner"]["run_id"], receipt["runner"]["run_attempt"] = "7", "2"
    receipt["source"]["sha"] = "e" * 40
    receipt["inputs"]["development_team_sha256"] = "b" * 64
    started = started_record()
    started["source_input_sha256"] = hashlib.sha256(receipt["source"]["sha"].encode()).hexdigest()
    started["workflow_sha_input_sha256"] = started["source_input_sha256"]
    records = [started, phase_record(10, "harness_entered"), phase_record(20, "bootstrap_prepared"),
               phase_record(30, "builds_completed"), phase_record(40, "evidence_completed")]
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, records)
    snapshot = json.dumps(receipt, sort_keys=True).encode()
    assert module.append_validated_attempt_marker(log, schema, receipt, snapshot) == []
    appended = [json.loads(line) for line in log.read_text().splitlines()]
    assert appended[-1]["native_receipt_sha256"] == hashlib.sha256(snapshot).hexdigest()
    other = tmp_path / "cross-bind.ndjson"
    write_attempt(other, records)
    receipt["runner"]["run_attempt"] = "3"
    assert module.append_validated_attempt_marker(other, schema, receipt, snapshot) == ["attempt:native_receipt_snapshot_mismatch"]
    changed_snapshot = json.dumps(receipt, sort_keys=True).encode()
    assert module.append_validated_attempt_marker(other, schema, receipt, changed_snapshot) == ["attempt:native_receipt_cross_binding"]


def test_validated_marker_rejects_short_append(tmp_path, monkeypatch):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    receipt = valid_receipt(json.loads((ROOT / FILES[2]).read_text()))
    receipt["runner"]["run_id"], receipt["runner"]["run_attempt"] = "7", "2"
    receipt["source"]["sha"] = "e" * 40
    receipt["inputs"]["development_team_sha256"] = "b" * 64
    started = started_record()
    started["source_input_sha256"] = hashlib.sha256(receipt["source"]["sha"].encode()).hexdigest()
    started["workflow_sha_input_sha256"] = started["source_input_sha256"]
    records = [started, phase_record(10, "harness_entered"), phase_record(20, "bootstrap_prepared"),
               phase_record(30, "builds_completed"), phase_record(40, "evidence_completed")]
    log = tmp_path / "attempt.ndjson"
    write_attempt(log, records)
    before = log.read_bytes()
    snapshot = json.dumps(receipt, sort_keys=True).encode()
    monkeypatch.setattr(module.os, "write", lambda _fd, payload: len(payload) - 1)
    assert module.append_validated_attempt_marker(log, schema, receipt, snapshot) == ["attempt:append_failed"]
    assert log.read_bytes() == before


def test_native_receipt_snapshot_has_no_validation_rehash_path():
    validator = VALIDATOR.read_text()
    harness = (ROOT / FILES[1]).read_text()
    assert "receipt_snapshot = read_regular_snapshot(args.receipt)" in validator
    assert "append_validated_attempt_marker(args.attempt_log, attempt_schema, receipt, receipt_snapshot)" in validator
    assert 'append_attempt_phase 50' not in harness
    assert 'hash_file "$EXECUTION_RECEIPT"' not in harness


def test_symlinked_attempt_ancestor_is_unknown_not_followed(tmp_path):
    module = load_module()
    schema = json.loads((ROOT / ATTEMPT_SCHEMA).read_text())
    real = tmp_path / "real"
    real.mkdir()
    write_attempt(real / "attempt.ndjson", [started_record()])
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks unavailable")
    assert module.attempt_log_problems(linked / "attempt.ndjson", schema) == ["attempt:absent_unknown"]


def test_snapshot_contract_binds_ctime_and_parent_dirfds():
    validator = VALIDATOR.read_text()
    harness = (ROOT / FILES[1]).read_text()
    workflow = (ROOT / FILES[0]).read_text()
    assert '"ctime_ns": info.st_ctime_ns' in validator
    assert '"ctime_ns": info.st_ctime_ns' in harness
    for source in (validator, harness, workflow):
        assert "os.O_DIRECTORY | os.O_NOFOLLOW" in source
        assert "return value.st_dev, value.st_ino, value.st_ctime_ns" in source
    assert "fcntl.flock(fd, fcntl.LOCK_EX)" in validator
    assert "fcntl.flock(fd, fcntl.LOCK_EX)" in harness
    assert "fcntl.flock(fd, fcntl.LOCK_EX)" in workflow


@pytest.mark.parametrize("relative", (FILES[0], FILES[1]))
def test_embedded_python_heredocs_compile(relative):
    source = (ROOT / relative).read_text()
    blocks = re.findall(r"<<'PY'\r?\n(.*?)\r?\n[ \t]*PY(?:\r?\n|$)", source, re.DOTALL)
    assert blocks
    for index, block in enumerate(blocks, 1):
        compile(textwrap.dedent(block), f"{relative}:heredoc:{index}", "exec")
