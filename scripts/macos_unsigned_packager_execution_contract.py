#!/usr/bin/env python3
"""Parsed workflow contract plus an exact seal for the reviewed shell harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows-only static validation host
    fcntl = None

import jsonschema
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
WORKFLOW = pathlib.Path(".github/workflows/macos-unsigned-bundle-smoke.yml")
HARNESS = pathlib.Path("apps/tamandua_agent/scripts/run_macos_unsigned_bundle_smoke.sh")
SCHEMA = pathlib.Path("schemas/macos_unsigned_packager_execution_v1.schema.json")
ATTEMPT_SCHEMA = pathlib.Path("schemas/macos_unsigned_smoke_attempt_v1.schema.json")
BOOTSTRAP = pathlib.Path("apps/tamandua_agent/scripts/macos_unsigned_smoke_bootstrap_v1.json")
REQUIREMENTS = pathlib.Path("apps/tamandua_agent/scripts/macos_unsigned_smoke_requirements_v1.txt")
PACKAGE_JSON = pathlib.Path("apps/tamandua_gui/package.json")
PACKAGE_LOCK = pathlib.Path("apps/tamandua_gui/package-lock.json")
TAURI_CARGO_TOML = pathlib.Path("apps/tamandua_gui/src-tauri/Cargo.toml")
TAURI_CARGO_LOCK = pathlib.Path("apps/tamandua_gui/src-tauri/Cargo.lock")
GUI_GITIGNORE = pathlib.Path("apps/tamandua_gui/.gitignore")
EXPECTED_HARNESS_SHA256 = "c1b6787d26ee700939f7b46c3bff30cbc07561d96af2327c03ffa23373b2f5c2"
EXPECTED_SCHEMA_SHA256 = "dfc69147ce8f22416bfc33501f94c7cc9482efab455795505a0917ca17c700bb"
EXPECTED_BOOTSTRAP_SHA256 = "9b72d2903fdf2d7c79723bca30cbb3d18d1a4e84abfb3979884580930161bb94"
EXPECTED_REQUIREMENTS_SHA256 = "fdb66a11d0bdf416d292ba11068fe9dc34f20e9053b8e08361e885e66079f1cb"
EXPECTED_WORKFLOW_SHA256 = "774a0989c900d47b6d9c4a92c0dc7c16f4d7273770076b23d404c16cf0ccf9cb"
EXPECTED_ATTEMPT_SCHEMA_SHA256 = "881b96fdc40d57a1257aca26ed5f61dfdfe0dec4bd8ae6922d18d5b13bbaf0e8"
CHECKOUT_ACTION = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
PYTHON_ACTION = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
NODE_ACTION = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
UPLOAD_ACTION = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
RUNNER_START = 'cat > "$COMMAND_RUNNER" <<\'PY\'\n'
RUNNER_END = "\nPY\n"


def mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def parsed_workflow(source: str) -> dict:
    value = yaml.safe_load(source)
    if not isinstance(value, dict):
        return {}
    # PyYAML 1.1 resolves the plain key `on` as True. Normalize only that root
    # key, rejecting an ambiguous document that supplies both spellings.
    if True in value:
        if "on" in value:
            return {}
        value["on"] = value.pop(True)
    return value


def derived_runner_sha256(harness_source: str) -> str | None:
    if harness_source.count(RUNNER_START) != 1:
        return None
    remainder = harness_source.split(RUNNER_START, 1)[1]
    if RUNNER_END not in remainder:
        return None
    runner, _ = remainder.split(RUNNER_END, 1)
    return hashlib.sha256((runner + "\n").encode()).hexdigest()


def tree_snapshot_digest(root: pathlib.Path) -> str:
    entries = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        info = path.lstat()
        record = {"path": relative.as_posix(), "mode": stat.S_IMODE(info.st_mode), "ctime_ns": info.st_ctime_ns}
        if path.is_symlink():
            record.update(kind="symlink", target=os.readlink(path))
        elif path.is_dir():
            record["kind"] = "directory"
        elif path.is_file():
            record.update(kind="file", size=info.st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            record["kind"] = "special"
        entries.append(record)
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def workflow_problems(document: dict) -> list[str]:
    problems: list[str] = []
    if set(document) != {"name", "on", "permissions", "concurrency", "jobs"}:
        problems.append("workflow:root_shape")
    dispatch = mapping(mapping(document.get("on")).get("workflow_dispatch"))
    if set(mapping(document.get("on"))) != {"workflow_dispatch"}:
        problems.append("workflow:not_dispatch_only")
    inputs = mapping(dispatch.get("inputs"))
    expected_inputs = {
        "source_sha": {"description": "Exact lowercase Git SHA-1 or SHA-256 object ID", "required": True, "type": "string"},
        "development_team": {"description": "Ten-character Apple Development Team identifier (no signing occurs)", "required": True, "type": "string"},
    }
    if inputs != expected_inputs:
        problems.append("workflow:inputs")
    if document.get("permissions") != {"contents": "read"}:
        problems.append("workflow:permissions")
    if document.get("concurrency") != {"group": "macos-unsigned-${{ inputs.source_sha }}", "cancel-in-progress": False}:
        problems.append("workflow:concurrency")
    jobs = mapping(document.get("jobs"))
    if set(jobs) != {"unsigned-bundle-smoke"}:
        return problems + ["workflow:jobs"]
    job = mapping(jobs.get("unsigned-bundle-smoke"))
    if set(job) != {"runs-on", "timeout-minutes", "steps"} or job.get("runs-on") != "macos-15" or job.get("timeout-minutes") != 55:
        problems.append("workflow:job_shape")
    steps = job.get("steps")
    if not isinstance(steps, list) or len(steps) != 8 or not all(isinstance(step, dict) for step in steps):
        return problems + ["workflow:steps"]
    attempt, validate, checkout, setup_python, setup_node, execute, finalize, upload = steps
    attempt_run = attempt.get("run", "")
    if (set(attempt) != {"name", "id", "shell", "env", "run"} or attempt.get("name") != "Register append-only attempt"
            or attempt.get("id") != "attempt" or attempt.get("shell") != "bash"
            or set(mapping(attempt.get("env"))) != {"SOURCE_SHA", "DEVELOPMENT_TEAM", "WORKFLOW_SHA", "TMD_RUN_ID", "TMD_RUN_ATTEMPT", "ATTEMPT_LOG"}
            or any(token not in attempt_run for token in ("os.O_CREAT | os.O_EXCL", "os.O_DIRECTORY | os.O_NOFOLLOW", "dir_fd=parent_fd", "fcntl.flock(fd, fcntl.LOCK_EX)", "os.fsync(parent_fd)", '"source_input_sha256": digest(',
                                                           '"development_team_input_sha256": digest(', '"workflow_sha_input_sha256": digest('))):
        problems.append("workflow:attempt_step")
    expected_validate = {
        "name": "Validate immutable inputs", "id": "input", "shell": "bash",
        "env": {"SOURCE_SHA": "${{ inputs.source_sha }}", "WORKFLOW_SHA": "${{ github.workflow_sha }}", "DEVELOPMENT_TEAM": "${{ inputs.development_team }}"},
        "run": '[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]\n[[ "$WORKFLOW_SHA" == "$SOURCE_SHA" ]]\n[[ "$DEVELOPMENT_TEAM" =~ ^[A-Z0-9]{10}$ ]]\n',
    }
    if validate != expected_validate:
        problems.append("workflow:validate_step")
    if checkout != {"name": "Checkout exact source", "id": "checkout", "uses": CHECKOUT_ACTION, "with": {"ref": "${{ inputs.source_sha }}", "persist-credentials": False, "clean": True}}:
        problems.append("workflow:checkout_step")
    if setup_python != {"name": "Setup exact Python", "id": "setup_python", "uses": PYTHON_ACTION, "with": {"python-version": "3.12.10"}}:
        problems.append("workflow:python_step")
    if setup_node != {"name": "Setup exact Node", "id": "setup_node", "uses": NODE_ACTION, "with": {"node-version": "20.19.1"}}:
        problems.append("workflow:node_step")
    expected_execute = {
        "name": "Execute unsigned native smoke once", "id": "harness", "shell": "bash",
        "env": {"SOURCE_SHA": "${{ inputs.source_sha }}", "DEVELOPMENT_TEAM": "${{ inputs.development_team }}", "TMD_RUN_ID": "${{ github.run_id }}", "TMD_RUN_ATTEMPT": "${{ github.run_attempt }}", "TMD_WORKFLOW_SHA": "${{ github.workflow_sha }}", "ATTEMPT_LOG": "${{ runner.temp }}/tamandua-macos-unsigned-attempt-${{ github.run_id }}-${{ github.run_attempt }}/attempt.ndjson"},
        "run": "bash apps/tamandua_agent/scripts/run_macos_unsigned_bundle_smoke.sh",
    }
    if execute != expected_execute:
        problems.append("workflow:execute_step")
    finalize_run = finalize.get("run", "")
    finalize_env = mapping(finalize.get("env"))
    required_finalize_tokens = (
        'if: always()', "os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW", "os.O_DIRECTORY | os.O_NOFOLLOW",
        "fcntl.flock(fd, fcntl.LOCK_EX)", "os.fsync(fd)",
        '("input", os.environ["INPUT_OUTCOME"])', '("checkout", os.environ["CHECKOUT_OUTCOME"])',
        '("setup_python", os.environ["SETUP_PYTHON_OUTCOME"])', '("setup_node", os.environ["SETUP_NODE_OUTCOME"])',
        '("harness", os.environ["HARNESS_OUTCOME"])', 'smoke_status = "cancel"', 'smoke_status = "internal"',
        'smoke_status = "success"', 'record.get("phase") == "native_receipt_validated"',
        '"pre_upload_status": os.environ["PRE_UPLOAD_STATUS"]', '"artifact_delivery": "unknown"',
        'terminal["native_receipt_sha256"] = markers[0]["native_receipt_sha256"]',
        'phase_ordinals == [10, 20, 30, 40, 50]', "started_keys", "validated_keys",
    )
    finalize_source = yaml.safe_dump(finalize, sort_keys=True) + finalize_run
    if (set(finalize) != {"name", "if", "shell", "env", "run"} or finalize.get("name") != "Finalize append-only attempt"
            or finalize.get("if") != "always()" or finalize.get("shell") != "bash"
            or set(finalize_env) != {"ATTEMPT_LOG", "TMD_RUN_ID", "TMD_RUN_ATTEMPT", "PRE_UPLOAD_STATUS", "INPUT_OUTCOME", "CHECKOUT_OUTCOME", "SETUP_PYTHON_OUTCOME", "SETUP_NODE_OUTCOME", "HARNESS_OUTCOME"}
            or any(token not in finalize_source for token in required_finalize_tokens)):
        problems.append("workflow:finalize_step")
    expected_upload = {
        "name": "Upload bounded unsigned evidence", "if": "always()", "uses": UPLOAD_ACTION,
        "with": {"name": "macos-unsigned-${{ github.run_id }}-${{ github.run_attempt }}", "path": "${{ runner.temp }}/tamandua-macos-unsigned-attempt-${{ github.run_id }}-${{ github.run_attempt }}/attempt.ndjson\n${{ runner.temp }}/tamandua-macos-unsigned-${{ github.run_id }}-${{ github.run_attempt }}-*/upload\n", "if-no-files-found": "warn", "retention-days": 7, "compression-level": 6},
    }
    if upload != expected_upload:
        problems.append("workflow:upload_step")
    return problems


def validate(root: pathlib.Path) -> list[str]:
    problems: list[str] = []
    paths = {name: root / relative for name, relative in (("workflow", WORKFLOW), ("harness", HARNESS), ("schema", SCHEMA), ("attempt_schema", ATTEMPT_SCHEMA),
             ("bootstrap", BOOTSTRAP), ("requirements", REQUIREMENTS), ("package_json", PACKAGE_JSON),
             ("package_lock", PACKAGE_LOCK), ("tauri_cargo_toml", TAURI_CARGO_TOML),
             ("tauri_cargo_lock", TAURI_CARGO_LOCK), ("gui_gitignore", GUI_GITIGNORE))}
    for name, path in paths.items():
        if not path.is_file() or path.is_symlink():
            problems.append(f"{name}:missing_or_unsafe")
    if problems:
        return problems
    try:
        document = parsed_workflow(paths["workflow"].read_text(encoding="utf-8"))
    except yaml.YAMLError:
        document = {}
    problems.extend(workflow_problems(document))
    if hashlib.sha256(paths["workflow"].read_bytes()).hexdigest() != EXPECTED_WORKFLOW_SHA256:
        problems.append("workflow:sealed_sha256_mismatch")
    harness_source = paths["harness"].read_text(encoding="utf-8")
    harness_digest = hashlib.sha256(harness_source.encode()).hexdigest()
    if harness_digest != EXPECTED_HARNESS_SHA256:
        problems.append("harness:sealed_sha256_mismatch")
    runner_digest = derived_runner_sha256(harness_source)
    if runner_digest is None or harness_source.count(f'REVIEWED_COMMAND_RUNNER_SHA256="{runner_digest}"') != 1:
        problems.append("harness:command_runner_binding")
    launcher_tokens = (
        'fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))',
        'if digest.hexdigest() != expected: raise SystemExit(65)',
        'compiled = compile(data, fixed_filename, "exec")', 'exec(compiled, namespace, namespace)',
    )
    launcher_marker = 'invoke_command_runner() {\n  /usr/bin/python3 -I -S - "$COMMAND_RUNNER" "$REVIEWED_COMMAND_RUNNER_SHA256" "$@" <<\'PY\'\n'
    launcher_region = harness_source.split(launcher_marker, 1)[1].split("\nPY\n}", 1)[0] if harness_source.count(launcher_marker) == 1 else ""
    if any(launcher_region.count(token) != 1 for token in launcher_tokens):
        problems.append("harness:sealed_inline_launcher")
    if '/usr/bin/python3 "$COMMAND_RUNNER"' in harness_source:
        problems.append("harness:runner_path_reopened_for_execution")
    if harness_source.count('/usr/bin/python3 -I -S - "$COMMAND_RUNNER"') != 2:
        problems.append("harness:isolated_runner_interpreter")
    forbidden_harness = ("npm install", "cargo build --release", "RUSTUP_TOOLCHAIN=stable", "xcode-select", "sudo ", "runs-on: macos-14")
    if any(token in harness_source for token in forbidden_harness):
        problems.append("harness:mutable_bootstrap_command")
    required_harness = ("npm ci --ignore-scripts --cache", "--require-hashes", "--only-binary=:all:", "--no-deps", "-- --locked",
                        'RUSTUP_HOME="$BUILD_ROOT/rustup-home"', 'CARGO_HOME="$BUILD_ROOT/cargo-home"',
                        'RUSTUP_TOOLCHAIN="1.88.0"', 'RUSTUP_AUTO_INSTALL="0"',
                        'DEVELOPER_DIR="/Applications/Xcode_16.4.app/Contents/Developer"',
                        'SOURCE_ROOT="$RUN_ROOT/source-authority"', 'BUILD_SOURCE_ROOT="$BUILD_ROOT/source"',
                        "/usr/bin/sandbox-exec", "(deny network*)", "sandbox_authority_write_denial",
                        "sandbox_build_source_write_denial", "sandbox_node_modules_write_denial",
                        "sandbox_cargo_source_write_denial", "protected_build_inputs_unchanged",
                        'BUILD_SOURCE_SNAPSHOT_BASELINE="$(tree_snapshot "$BUILD_SOURCE_ROOT")"',
                        'DEPENDENCY_SNAPSHOT_BASELINE="$(dependency_snapshot)"',
                        '[[ "$(tree_snapshot "$BUILD_SOURCE_ROOT")" == "$BUILD_SOURCE_SNAPSHOT_BASELINE" ]]',
                        '[[ "$(dependency_snapshot)" == "$DEPENDENCY_SNAPSHOT_BASELINE" ]]',
                        "cargo fetch --manifest-path", "CARGO_NET_OFFLINE=true", "cargo build --locked --offline",
                        "authority_unchanged", 'value["build"]["beforeBuildCommand"] = ""',
                        ': "${ATTEMPT_LOG:?ATTEMPT_LOG is required}"', "os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW",
                        "os.O_DIRECTORY | os.O_NOFOLLOW", "fcntl.flock(fd, fcntl.LOCK_EX)",
                        "append_attempt_phase 10 harness_entered", "append_attempt_phase 20 bootstrap_prepared",
                        "append_attempt_phase 30 builds_completed", "append_attempt_phase 40 evidence_completed",
                        '--attempt-log "$ATTEMPT_LOG" --append-validated-marker')
    if any(token not in harness_source for token in required_harness):
        problems.append("harness:immutable_bootstrap_command_missing")
    if '(allow file-write* (subpath {quote(build)}))' in harness_source:
        problems.append("harness:sandbox_broad_build_write")
    phase_tokens = [
        "append_attempt_phase 10 harness_entered", "append_attempt_phase 20 bootstrap_prepared",
        "append_attempt_phase 30 builds_completed", "append_attempt_phase 40 evidence_completed",
    ]
    if [harness_source.find(token) for token in phase_tokens] != sorted(harness_source.find(token) for token in phase_tokens):
        problems.append("harness:attempt_phase_order")
    final_receipt_validation = harness_source.find('"$PYTHON" "$EXECUTION_CONTRACT" --root "$SOURCE_ROOT" --receipt "$EXECUTION_RECEIPT"')
    if (final_receipt_validation < 0 or '--attempt-log "$ATTEMPT_LOG" --append-validated-marker' not in harness_source[final_receipt_validation:]
            or "append_attempt_phase 50" in harness_source):
        problems.append("harness:attempt_success_before_receipt_validation")
    if hashlib.sha256(paths["schema"].read_bytes()).hexdigest() != EXPECTED_SCHEMA_SHA256:
        problems.append("schema:sealed_sha256_mismatch")
    if hashlib.sha256(paths["attempt_schema"].read_bytes()).hexdigest() != EXPECTED_ATTEMPT_SCHEMA_SHA256:
        problems.append("attempt_schema:sealed_sha256_mismatch")
    if hashlib.sha256(paths["bootstrap"].read_bytes()).hexdigest() != EXPECTED_BOOTSTRAP_SHA256:
        problems.append("bootstrap:sealed_sha256_mismatch")
    if hashlib.sha256(paths["requirements"].read_bytes()).hexdigest() != EXPECTED_REQUIREMENTS_SHA256:
        problems.append("bootstrap:requirements_sha256_mismatch")
    try:
        schema = json.loads(paths["schema"].read_text(encoding="utf-8"))
        attempt_schema = json.loads(paths["attempt_schema"].read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator.check_schema(attempt_schema)
    except (json.JSONDecodeError, jsonschema.SchemaError) as error:
        return problems + [f"schema:invalid:{type(error).__name__}"]
    try:
        bootstrap = json.loads(paths["bootstrap"].read_text(encoding="utf-8"))
        package_json = json.loads(paths["package_json"].read_text(encoding="utf-8"))
        package_lock = json.loads(paths["package_lock"].read_text(encoding="utf-8"))
        cargo_toml_source = paths["tauri_cargo_toml"].read_text(encoding="utf-8")
        cargo_lock_source = paths["tauri_cargo_lock"].read_text(encoding="utf-8")
    except json.JSONDecodeError:
        return problems + ["bootstrap:unreadable_lock"]
    if bootstrap.get("runner") != {"github_label": "macos-15", "architecture": "arm64", "deprecated_macos_14_label_allowed": False}:
        problems.append("bootstrap:runner")
    if bootstrap.get("state") != "source_pinned_native_execution_hold":
        problems.append("bootstrap:state")
    if bootstrap.get("actions") != {"checkout": CHECKOUT_ACTION, "setup_python": PYTHON_ACTION, "setup_node": NODE_ACTION, "upload_artifact": UPLOAD_ACTION}:
        problems.append("bootstrap:actions")
    expected_locks = {item["path"]: item for item in bootstrap.get("locks", []) if isinstance(item, dict) and "path" in item}
    lock_files = {PACKAGE_LOCK.as_posix(): paths["package_lock"], TAURI_CARGO_LOCK.as_posix(): paths["tauri_cargo_lock"]}
    for relative, path in lock_files.items():
        record = expected_locks.get(relative, {})
        if record.get("sha256") != hashlib.sha256(path.read_bytes()).hexdigest():
            problems.append(f"bootstrap:lock_hash:{relative}")
        source_path = root / record.get("source_path", "missing")
        if not source_path.is_file() or source_path.is_symlink() or record.get("source_sha256") != hashlib.sha256(source_path.read_bytes()).hexdigest():
            problems.append(f"bootstrap:lock_source_hash:{relative}")
    root_lock = package_lock.get("packages", {}).get("", {})
    for key in ("name", "version", "dependencies", "devDependencies"):
        if root_lock.get(key) != package_json.get(key):
            problems.append(f"bootstrap:npm_lock_semantics:{key}")
    if (package_lock.get("lockfileVersion") != 2 or "[package]" not in cargo_toml_source
            or not re.search(r"(?m)^version = 4$", cargo_lock_source)
            or cargo_lock_source.count("[[package]]") < 2):
        problems.append("bootstrap:lock_format")
    ignored = {line.strip() for line in paths["gui_gitignore"].read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")}
    if "package-lock.json" in ignored or "src-tauri/Cargo.lock" in ignored:
        problems.append("bootstrap:locks_ignored")
    requirements_source = paths["requirements"].read_text(encoding="utf-8")
    requirement_names = {name.lower() for name in re.findall(r"(?mi)^([a-z0-9_-]+)==[^\s\\]+\s*\\$", requirements_source)}
    if requirement_names != {"attrs", "jsonschema", "jsonschema-specifications", "pyyaml", "referencing", "rpds-py", "typing-extensions"}:
        problems.append("bootstrap:python_transitive_closure")
    if requirements_source.count("--hash=sha256:") != 7 or re.search(r"(?mi)(https?://|\.tar\.gz|\.zip)", requirements_source):
        problems.append("bootstrap:python_hash_policy")
    if bootstrap.get("python", {}).get("requirements_sha256") != hashlib.sha256(paths["requirements"].read_bytes()).hexdigest():
        problems.append("bootstrap:requirements_binding")
    expected_isolation = {
        "mutable_build_dependency_homes_under_run_root": True,
        "setup_action_toolcache_outside_run_root": True,
        "source_materialized_from_exact_git_archive": True,
        "source_authority_outside_build_root": True,
        "npm_install_scripts_enabled": False,
        "cargo_fetch_executes_build_scripts": False,
        "build_network_allowed": False,
        "sandbox_exec_required": True,
        "sandbox_denies_repository_and_authority_writes": True,
        "sandbox_denies_build_source_and_dependency_writes": True,
        "build_and_dependency_snapshots_checked_per_build": True,
        "sudo_allowed": False,
        "xcode_select_mutation_allowed": False,
    }
    if bootstrap.get("isolation") != expected_isolation:
        problems.append("bootstrap:isolation")
    expected_residual_risks = {
        "hosted_runner_image_mutable": True,
        "rustup_bootstrap_network_root_not_repository_pinned": True,
        "setup_python_node_distribution_not_repository_hash_pinned": True,
        "external_vcs_seal_coordination_required": True,
    }
    if bootstrap.get("residual_risks") != expected_residual_risks:
        problems.append("bootstrap:residual_risks")
    if set(bootstrap.get("claims", {}).values()) != {False}:
        problems.append("bootstrap:claims")
    locked_versions = {}
    for block in cargo_lock_source.split("[[package]]")[1:]:
        name = re.search(r'(?m)^name = "([^"]+)"$', block)
        version = re.search(r'(?m)^version = "([^"]+)"$', block)
        if name and version:
            locked_versions[name.group(1)] = version.group(1)
    expected_msrv = {"time": "0.3.53", "time-core": "0.1.9"}
    declared_msrv = {item.get("package"): item.get("version") for item in bootstrap.get("locked_msrv_constraints", []) if isinstance(item, dict)}
    if any(locked_versions.get(name) != version or declared_msrv.get(name) != version for name, version in expected_msrv.items()):
        problems.append("bootstrap:locked_msrv_chain")
    if bootstrap.get("rust", {}).get("toolchain") != "1.88.0":
        problems.append("bootstrap:rust_msrv")
    expected_root = {"schema_version", "evidence_class", "state", "native_execution_observed", "source", "runner", "toolchain", "inputs", "commands", "outputs", "v7", "race", "lifecycle", "claims"}
    if set(schema.get("required", [])) != expected_root or schema.get("additionalProperties") is not False:
        problems.append("schema:root_shape")
    command = mapping(mapping(schema.get("properties")).get("commands")).get("items")
    command_required = {"name", "argv", "argv_sha256", "cwd", "expected_exit", "command_runner_sha256", "intent_sha256", "exit_code", "stdout", "stderr"}
    if not isinstance(command, dict) or set(command.get("required", [])) != command_required or command.get("additionalProperties") is not False:
        problems.append("schema:command_shape")
    for section in ("lifecycle", "claims"):
        reference = mapping(mapping(schema.get("properties")).get(section)).get("$ref", "")
        definition = mapping(mapping(schema.get("$defs")).get(reference.rsplit("/", 1)[-1]))
        if not definition or any(mapping(rule).get("const") is not False for rule in mapping(definition.get("properties")).values()):
            problems.append(f"schema:{section}_not_false_closed")
    return problems


def classify_attempt_outcome(pre_upload_status: str, step_outcomes: list[dict], native_receipt_bound: bool) -> str:
    values = [item.get("outcome") for item in step_outcomes if isinstance(item, dict)]
    if pre_upload_status == "cancelled":
        return "cancel"
    if values == ["success"] * 5:
        return "success" if pre_upload_status == "success" and native_receipt_bound else "invalid"
    if pre_upload_status != "failure":
        return "invalid"
    first = next((index for index, value in enumerate(values) if value != "success"), None)
    if first is None or values[first] != "failure":
        return "internal"
    return ("input", "checkout", "setup", "setup", "harness")[first]


def attempt_log_state(records: list[dict]) -> str:
    terminals = [record for record in records if record.get("record_type") == "terminal"]
    return terminals[0]["smoke_status"] if len(terminals) == 1 else "unknown"


def _open_parent_chain(path: pathlib.Path) -> tuple[list[int], int, str] | None:
    absolute = path.absolute()
    if os.name != "posix":
        try:
            current = pathlib.Path(absolute.anchor)
            for part in absolute.parts[1:-1]:
                current /= part
                if current.is_symlink() or not current.is_dir():
                    return None
            return ([], -1, absolute.name)
        except OSError:
            return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        descriptor = os.open(absolute.anchor, flags)
        descriptors.append(descriptor)
        for part in absolute.parts[1:-1]:
            descriptor = os.open(part, flags, dir_fd=descriptor)
            descriptors.append(descriptor)
    except OSError:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        return None
    return descriptors, descriptors[-1], absolute.name


def _directory_identity(descriptor: int) -> tuple[int, int, int]:
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino, value.st_ctime_ns


def read_regular_snapshot(path: pathlib.Path) -> bytes | None:
    try:
        before = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(before.st_mode) or getattr(before, "st_reparse_tag", 0) or not stat.S_ISREG(before.st_mode):
        return None
    chain = _open_parent_chain(path)
    if chain is None:
        return None
    descriptors, parent_fd, name = chain
    parent_identities = [_directory_identity(descriptor) for descriptor in descriptors]
    absolute = path.absolute()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(absolute if os.name != "posix" else name, flags, dir_fd=None if os.name != "posix" else parent_fd)
    except OSError:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        return None
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_SH)
        opened = os.fstat(fd)
        chunks = []
        while chunk := os.read(fd, 16384):
            chunks.append(chunk)
        after_read = os.fstat(fd)
        path_after = os.stat(absolute if os.name != "posix" else name, dir_fd=None if os.name != "posix" else parent_fd,
                             follow_symlinks=False)
        parent_identities_after = [_directory_identity(descriptor) for descriptor in descriptors]
    except OSError:
        return None
    finally:
        os.close(fd)
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, stat.S_IMODE(value.st_mode))
    if (not stat.S_ISREG(opened.st_mode)
            or identity(before) != identity(opened)
            or identity(opened) != identity(after_read)
            or (opened.st_dev, opened.st_ino) != (path_after.st_dev, path_after.st_ino)
            or parent_identities != parent_identities_after):
        return None
    return b"".join(chunks)


def _attempt_records_problems(records: list[dict], schema: dict, native_snapshot: bytes | None = None) -> list[str]:
    if not records:
        return ["attempt:empty"]
    problems: list[str] = []
    for index, record in enumerate(records):
        try:
            jsonschema.validate(record, schema)
        except jsonschema.ValidationError:
            problems.append(f"attempt:schema:{index}")
    if problems:
        return problems
    ordinals = [record["ordinal"] for record in records]
    if ordinals != sorted(set(ordinals)):
        problems.append("attempt:ordinal_order")
    if records[0]["record_type"] != "attempt_started" or records[0]["ordinal"] != 0:
        problems.append("attempt:first_record")
    identity = (records[0]["run_id"], records[0]["run_attempt"])
    if any((record["run_id"], record["run_attempt"]) != identity for record in records):
        problems.append("attempt:run_identity")
    expected_phases = {10: "harness_entered", 20: "bootstrap_prepared", 30: "builds_completed", 40: "evidence_completed", 50: "native_receipt_validated"}
    phase_records = [record for record in records if record["record_type"] == "phase"]
    phase_ordinals = [record["ordinal"] for record in phase_records]
    if any(expected_phases.get(record["ordinal"]) != record["phase"] for record in phase_records):
        problems.append("attempt:phase_order")
    if phase_ordinals != [10, 20, 30, 40, 50][:len(phase_ordinals)]:
        problems.append("attempt:phase_prefix")
    terminals = [record for record in records if record["record_type"] == "terminal"]
    if len(terminals) > 1 or (terminals and records[-1] is not terminals[0]):
        problems.append("attempt:terminal_order")
    if not terminals:
        return problems
    terminal = terminals[0]
    values = [item["outcome"] for item in terminal["step_outcomes"]]
    status = terminal["smoke_status"]
    first_non_success = next((index for index, value in enumerate(values) if value != "success"), None)
    interrupted_shape = (first_non_success is not None and values[first_non_success] in {"cancelled", "skipped"}
                         and all(value == "success" for value in values[:first_non_success])
                         and all(value in {"cancelled", "skipped"} for value in values[first_non_success:]))
    exact_shapes = {
        "input": lambda: terminal["pre_upload_status"] == "failure"
                         and values[0] == "failure" and values[1:] == ["skipped"] * 4,
        "checkout": lambda: terminal["pre_upload_status"] == "failure"
                            and values[:2] == ["success", "failure"] and values[2:] == ["skipped"] * 3,
        "setup": lambda: terminal["pre_upload_status"] == "failure" and (
            (values[:3] == ["success", "success", "failure"] and values[3:] == ["skipped", "skipped"])
            or (values[:4] == ["success", "success", "success", "failure"] and values[4] == "skipped")
        ),
        "harness": lambda: terminal["pre_upload_status"] == "failure"
                           and values == ["success", "success", "success", "success", "failure"],
        "cancel": lambda: terminal["pre_upload_status"] == "cancelled" and interrupted_shape,
        "internal": lambda: terminal["pre_upload_status"] == "failure" and interrupted_shape,
        "success": lambda: terminal["pre_upload_status"] == "success" and values == ["success"] * 5,
    }
    if not exact_shapes[status]():
        problems.append("attempt:step_outcome_shape")
    interrupted_phase_lengths = ({0} if first_non_success is None or first_non_success < 4 else set(range(5)))
    allowed_phase_lengths = {"input": {0}, "checkout": {0}, "setup": {0}, "harness": set(range(5)),
                             "cancel": interrupted_phase_lengths, "internal": interrupted_phase_lengths, "success": {5}}
    if len(phase_records) not in allowed_phase_lengths[status]:
        problems.append("attempt:phase_outcome_matrix")
    native_digest = hashlib.sha256(native_snapshot).hexdigest() if native_snapshot is not None else None
    native_markers = [record for record in phase_records if record["phase"] == "native_receipt_validated"]
    receipt_bound = (len(native_markers) == 1 and native_digest is not None
                     and native_markers[0].get("native_receipt_sha256") == native_digest
                     and terminal.get("native_receipt_sha256") == native_digest)
    expected_status = classify_attempt_outcome(terminal["pre_upload_status"], terminal["step_outcomes"], receipt_bound)
    if status != expected_status:
        problems.append("attempt:terminal_taxonomy")
    if status == "success" and not receipt_bound:
        problems.append("attempt:success_receipt_binding")
    if values == ["success"] * 5 and status != "success":
        problems.append("attempt:all_success_requires_success")
    if terminal["artifact_delivery"] != "unknown":
        problems.append("attempt:artifact_delivery_claim")
    return problems


def attempt_log_problems(
    path: pathlib.Path,
    schema: dict,
    native_receipt: pathlib.Path | None = None,
    *,
    execution_schema: dict | None = None,
    evidence_root: pathlib.Path | None = None,
    source_root: pathlib.Path | None = None,
    native_receipt_value: dict | None = None,
    native_receipt_snapshot: bytes | None = None,
) -> list[str]:
    snapshot = read_regular_snapshot(path)
    if snapshot is None:
        return ["attempt:absent_unknown"]
    try:
        lines = snapshot.decode("utf-8").splitlines()
        records = [json.loads(line) for line in lines if line]
    except (UnicodeError, json.JSONDecodeError):
        return ["attempt:unreadable"]
    terminals = [record for record in records if isinstance(record, dict) and record.get("record_type") == "terminal"]
    success = len(terminals) == 1 and terminals[0].get("smoke_status") == "success"
    context_problems: list[str] = []
    validated_snapshot = None
    if success:
        if execution_schema is None or evidence_root is None or source_root is None:
            context_problems.append("attempt:success_context_missing")
        snapshot = native_receipt_snapshot
        value = native_receipt_value
        if snapshot is None and native_receipt is not None:
            snapshot = read_regular_snapshot(native_receipt)
        if snapshot is None:
            context_problems.append("attempt:native_receipt_snapshot_missing")
        else:
            try:
                parsed = json.loads(snapshot.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                context_problems.append("attempt:native_receipt_json")
            else:
                if value is not None and parsed != value:
                    context_problems.append("attempt:native_receipt_snapshot_mismatch")
                value = parsed
        if not context_problems and value is not None:
            native_problems = receipt_problems(value, evidence_root, execution_schema, source_root)
            if native_problems:
                context_problems.append("attempt:native_receipt_validation")
            else:
                started = records[0]
                source_digest = hashlib.sha256(value["source"]["sha"].encode()).hexdigest()
                if (started.get("run_id") != value["runner"]["run_id"]
                        or started.get("run_attempt") != value["runner"]["run_attempt"]
                        or started.get("source_input_sha256") != source_digest
                        or started.get("workflow_sha_input_sha256") != source_digest
                        or started.get("development_team_input_sha256") != value["inputs"]["development_team_sha256"]):
                    context_problems.append("attempt:native_receipt_cross_binding")
        if not context_problems:
            validated_snapshot = snapshot
    return context_problems + _attempt_records_problems(records, schema, validated_snapshot)


def append_validated_attempt_marker(
    path: pathlib.Path, schema: dict, receipt: dict, receipt_snapshot: bytes,
) -> list[str]:
    chain = _open_parent_chain(path)
    if chain is None:
        return ["attempt:append_path"]
    descriptors, parent_fd, name = chain
    parent_identities = [_directory_identity(descriptor) for descriptor in descriptors]
    absolute = path.absolute()
    flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(absolute if os.name != "posix" else name, flags, dir_fd=None if os.name != "posix" else parent_fd)
    except OSError:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        return ["attempt:append_path"]
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            return ["attempt:append_path"]
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        while chunk := os.read(fd, 16384):
            chunks.append(chunk)
        try:
            records = [json.loads(line) for line in b"".join(chunks).decode("utf-8").splitlines() if line]
        except (UnicodeError, json.JSONDecodeError):
            return ["attempt:unreadable"]
        problems = _attempt_records_problems(records, schema)
        if problems:
            return problems
        phases = [record["ordinal"] for record in records if record["record_type"] == "phase"]
        if phases != [10, 20, 30, 40] or any(record["record_type"] == "terminal" for record in records):
            return ["attempt:validated_marker_prefix"]
        started = records[0]
        try:
            if json.loads(receipt_snapshot.decode("utf-8")) != receipt:
                return ["attempt:native_receipt_snapshot_mismatch"]
        except (UnicodeError, json.JSONDecodeError):
            return ["attempt:native_receipt_snapshot_mismatch"]
        source_input_digest = hashlib.sha256(receipt["source"]["sha"].encode()).hexdigest()
        if (started["run_id"] != receipt["runner"]["run_id"]
                or started["run_attempt"] != receipt["runner"]["run_attempt"]
                or started["source_input_sha256"] != source_input_digest
                or started["workflow_sha_input_sha256"] != source_input_digest
                or started["development_team_input_sha256"] != receipt["inputs"]["development_team_sha256"]):
            return ["attempt:native_receipt_cross_binding"]
        digest = hashlib.sha256(receipt_snapshot).hexdigest()
        marker = {
            "schema_version": "tamandua.macos_unsigned_smoke_attempt/v1", "record_type": "phase", "ordinal": 50,
            "run_id": started["run_id"], "run_attempt": started["run_attempt"], "phase": "native_receipt_validated",
            "native_receipt_sha256": digest,
            "lifecycle": {key: False for key in ("signed", "notarized", "installed", "activated", "runtime_observed", "released")},
            "claims": {key: False for key in ("identity_verified", "capability_proven", "product_ready", "production_ready", "external_claim_allowed")},
        }
        jsonschema.validate(marker, schema)
        payload = (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if os.write(fd, payload) != len(payload):
            raise OSError("short append")
        os.fsync(fd)
        after = os.fstat(fd)
        path_after = os.stat(absolute if os.name != "posix" else name, dir_fd=None if os.name != "posix" else parent_fd,
                             follow_symlinks=False)
        parent_identities_after = [_directory_identity(descriptor) for descriptor in descriptors]
        if ((opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
                or (opened.st_dev, opened.st_ino) != (path_after.st_dev, path_after.st_ino)
                or parent_identities != parent_identities_after):
            return ["attempt:append_identity"]
    except (OSError, jsonschema.ValidationError):
        return ["attempt:append_failed"]
    finally:
        os.close(fd)
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return []


def safe_file(root: pathlib.Path, relative: pathlib.PurePosixPath) -> pathlib.Path | None:
    if relative.is_absolute() or ".." in relative.parts:
        return None
    path = root.joinpath(*relative.parts)
    chain = _open_parent_chain(path)
    if chain is None:
        return None
    descriptors, parent_fd, name = chain
    try:
        fd = os.open(path.absolute() if os.name != "posix" else name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                     dir_fd=None if os.name != "posix" else parent_fd)
        opened = os.fstat(fd)
        os.close(fd)
    except OSError:
        return None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        return None
    return path


def receipt_problems(receipt: dict, evidence_root: pathlib.Path, schema: dict, source_root: pathlib.Path) -> list[str]:
    problems: list[str] = []
    try:
        jsonschema.validate(receipt, schema)
    except jsonschema.ValidationError:
        return ["receipt:schema"]
    harness_path = safe_file(source_root, pathlib.PurePosixPath(HARNESS.as_posix()))
    runner_digest = derived_runner_sha256(harness_path.read_text(encoding="utf-8")) if harness_path is not None else None
    if runner_digest is None or receipt["runner"]["command_runner_sha256"] != runner_digest:
        problems.append("receipt:command_runner_hash")
    if receipt["runner"]["source_authority_snapshot_sha256"] != tree_snapshot_digest(source_root):
        problems.append("receipt:source_authority_snapshot")
    if (not receipt["toolchain"]["rustc"].startswith("rustc 1.88.0 ")
            or "host: aarch64-apple-darwin" not in receipt["toolchain"]["rustc"]
            or not receipt["toolchain"]["cargo"].startswith("cargo 1.88.0 ")):
        problems.append("receipt:rust_toolchain")
    source_files = {
        "workflow_sha256": WORKFLOW, "harness_sha256": HARNESS,
        "packager_sha256": pathlib.Path("apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh"),
        "v7_generator_sha256": pathlib.Path("apps/tamandua_agent/scripts/macos_unsigned_bundle_evidence_v7.py"),
        "execution_schema_sha256": SCHEMA,
        "execution_contract_sha256": pathlib.Path("tools/detection_validation/scripts/macos_unsigned_packager_execution_contract.py"),
        "bootstrap_manifest_sha256": BOOTSTRAP,
        "python_requirements_sha256": REQUIREMENTS,
    }
    for field, relative in source_files.items():
        path = safe_file(source_root, pathlib.PurePosixPath(relative.as_posix()))
        if path is None or hashlib.sha256(path.read_bytes()).hexdigest() != receipt["source"][field]:
            problems.append(f"receipt:source_hash:{field}")
    input_files = {
        "base_tauri_config_sha256": pathlib.Path("apps/tamandua_gui/src-tauri/tauri.conf.json"),
        "package_json_sha256": PACKAGE_JSON, "package_lock_sha256": PACKAGE_LOCK,
        "tauri_cargo_toml_sha256": TAURI_CARGO_TOML, "tauri_cargo_lock_sha256": TAURI_CARGO_LOCK,
        "host_entitlements_sha256": pathlib.Path("deploy/installers/macos/entitlements.plist"),
        "system_extension_entitlements_sha256": pathlib.Path("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist"),
    }
    for field, relative in input_files.items():
        path = safe_file(source_root, pathlib.PurePosixPath(relative.as_posix()))
        if path is None or hashlib.sha256(path.read_bytes()).hexdigest() != receipt["inputs"][field]:
            problems.append(f"receipt:input_hash:{field}")
    output_files = {
        "candidate_inventory_sha256": "candidate-inventory.json",
        "binary_evidence_sha256": "binary-evidence.json",
        "v7_receipt_sha256": "macos-unsigned-bundle-evidence-v7.json",
        "race_evidence_sha256": "race-evidence.json",
        "sandbox_profile_sha256": "macos-build.sb",
    }
    for field, relative in output_files.items():
        path = safe_file(evidence_root, pathlib.PurePosixPath(relative))
        if path is None or hashlib.sha256(path.read_bytes()).hexdigest() != receipt["outputs"][field]:
            problems.append(f"receipt:output_hash:{field}")
    sandbox_profile = safe_file(evidence_root, pathlib.PurePosixPath("macos-build.sb"))
    sandbox_profile_digest = hashlib.sha256(sandbox_profile.read_bytes()).hexdigest() if sandbox_profile is not None else None
    if not (sandbox_profile_digest == receipt["outputs"]["sandbox_profile_sha256"]
            == receipt["runner"]["sandbox_profile_sha256"]):
        problems.append("receipt:sandbox_profile_binding")
    if receipt["v7"]["receipt_sha256"] != receipt["outputs"]["v7_receipt_sha256"]:
        problems.append("receipt:v7_hash_binding")
    for command in receipt["commands"]:
        if command["command_runner_sha256"] != runner_digest:
            problems.append(f"receipt:command_runner_event:{command['name']}")
        canonical = json.dumps(command["argv"], ensure_ascii=False, separators=(",", ":")).encode()
        if hashlib.sha256(canonical).hexdigest() != command["argv_sha256"]:
            problems.append(f"receipt:argv_hash:{command['name']}")
        for stream_name in ("stdout", "stderr"):
            stream = command[stream_name]
            relative = pathlib.PurePosixPath(stream["bounded_path"])
            path = safe_file(evidence_root, relative)
            if path is None:
                problems.append(f"receipt:bounded_path:{command['name']}:{stream_name}")
                continue
            data = path.read_bytes()
            if len(data) != stream["bounded_bytes"] or hashlib.sha256(data).hexdigest() != stream["bounded_sha256"]:
                problems.append(f"receipt:bounded_hash:{command['name']}:{stream_name}")
            if stream["bounded_bytes"] > stream["bytes_total"] or stream["truncated"] != (stream["bounded_bytes"] < stream["bytes_total"]):
                problems.append(f"receipt:bounded_relation:{command['name']}:{stream_name}")
        intent_path = safe_file(evidence_root, pathlib.PurePosixPath(f"events/{command['name']}.intent.json"))
        completion_path = safe_file(evidence_root, pathlib.PurePosixPath(f"events/{command['name']}.completion.json"))
        if intent_path is None or hashlib.sha256(intent_path.read_bytes()).hexdigest() != command["intent_sha256"]:
            problems.append(f"receipt:intent:{command['name']}")
        else:
            try:
                intent = json.loads(intent_path.read_text())
            except json.JSONDecodeError:
                problems.append(f"receipt:intent:{command['name']}")
            else:
                expected_intent = {key: command[key] for key in ("name", "argv", "argv_sha256", "cwd", "expected_exit", "command_runner_sha256")}
                if intent != expected_intent:
                    problems.append(f"receipt:intent_binding:{command['name']}")
        if completion_path is None:
            problems.append(f"receipt:completion:{command['name']}")
        else:
            try:
                completion = json.loads(completion_path.read_text())
            except json.JSONDecodeError:
                problems.append(f"receipt:completion:{command['name']}")
            else:
                if completion != command:
                    problems.append(f"receipt:completion_binding:{command['name']}")
    race_canonical = json.dumps(receipt["race"]["argv"], ensure_ascii=False, separators=(",", ":")).encode()
    if hashlib.sha256(race_canonical).hexdigest() != receipt["race"]["argv_sha256"]:
        problems.append("receipt:race_argv_hash")
    for stream_name in ("stdout", "stderr"):
        path = safe_file(evidence_root, pathlib.PurePosixPath(receipt["race"][f"{stream_name}_path"]))
        if path is None:
            problems.append(f"receipt:race_log:{stream_name}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != receipt["race"][f"{stream_name}_sha256"]:
            problems.append(f"receipt:race_log_hash:{stream_name}")
    race_intent_path = safe_file(evidence_root, pathlib.PurePosixPath("events/race_packager.intent.json"))
    race_completion_path = safe_file(evidence_root, pathlib.PurePosixPath("events/race_packager.completion.json"))
    if race_intent_path is None or hashlib.sha256(race_intent_path.read_bytes()).hexdigest() != receipt["race"]["intent_sha256"]:
        problems.append("receipt:race_intent")
    if race_completion_path is None:
        problems.append("receipt:race_completion")
    else:
        try:
            race_completion = json.loads(race_completion_path.read_text())
        except json.JSONDecodeError:
            problems.append("receipt:race_completion")
        else:
            if not (race_completion.get("name") == "race_packager" and race_completion.get("expected_exit") == "nonzero"
                    and race_completion.get("argv") == receipt["race"]["argv"]
                    and race_completion.get("argv_sha256") == receipt["race"]["argv_sha256"]
                    and race_completion.get("intent_sha256") == receipt["race"]["intent_sha256"]
                    and race_completion.get("command_runner_sha256") == runner_digest == receipt["race"]["command_runner_sha256"]
                    and race_completion.get("exit_code") == receipt["race"]["packager_exit_code"]):
                problems.append("receipt:race_completion_binding")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--receipt", type=pathlib.Path)
    parser.add_argument("--evidence-root", type=pathlib.Path)
    parser.add_argument("--attempt-log", type=pathlib.Path)
    parser.add_argument("--append-validated-marker", action="store_true")
    args = parser.parse_args(argv)
    problems = validate(args.root.absolute())
    receipt = None
    receipt_snapshot = None
    if args.receipt is not None or args.evidence_root is not None:
        if args.receipt is None or args.evidence_root is None:
            parser.error("--receipt and --evidence-root must be provided together")
        try:
            receipt_snapshot = read_regular_snapshot(args.receipt)
            if receipt_snapshot is None:
                raise OSError("unsafe receipt path")
            receipt = json.loads(receipt_snapshot.decode("utf-8"))
            schema = json.loads((args.root / SCHEMA).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            problems.append("receipt:unreadable")
        else:
            problems.extend(receipt_problems(receipt, args.evidence_root.absolute(), schema, args.root.absolute()))
    if args.append_validated_marker and (args.attempt_log is None or receipt is None or receipt_snapshot is None):
        parser.error("--append-validated-marker requires --attempt-log, --receipt and --evidence-root")
    if args.attempt_log is not None:
        try:
            attempt_schema = json.loads((args.root / ATTEMPT_SCHEMA).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            problems.append("attempt_schema:unreadable")
        else:
            if args.append_validated_marker:
                if not problems:
                    problems.extend(append_validated_attempt_marker(args.attempt_log, attempt_schema, receipt, receipt_snapshot))
            else:
                problems.extend(attempt_log_problems(
                    args.attempt_log, attempt_schema,
                    execution_schema=schema if receipt is not None else None,
                    evidence_root=args.evidence_root.absolute() if args.evidence_root is not None else None,
                    source_root=args.root.absolute(),
                    native_receipt_value=receipt,
                    native_receipt_snapshot=receipt_snapshot,
                ))
    print(json.dumps({"state": "pass" if not problems else "fail", "problems": problems}, indent=2))
    return 0 if not problems else 2


if __name__ == "__main__":
    raise SystemExit(main())
