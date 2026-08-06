from __future__ import annotations

import importlib.util
import json
import shlex
import subprocess
import tempfile
from argparse import Namespace
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/run_elixir_postgres_runtime_validation.py"
SCHEMA = ROOT / "schemas/elixir_postgres_runtime_validation_receipt_v1.schema.json"


def load_module():
    spec = importlib.util.spec_from_file_location("run_elixir_postgres_runtime_validation", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def args(**changes):
    values = dict(
        db_container="db", network="lab", owned_database=False, db_image=None,
        runner_image="runner:tag",
        expected_db_container_id="d" * 64, expected_db_image_id="sha256:" + "a" * 64,
        expected_runner_image_id="sha256:" + "b" * 64, db_user="tamandua", test=[],
        execute=False, timeout=30, readiness_timeout=180, output=None,
    )
    values.update(changes)
    return Namespace(**values)


class InspectCommands:
    def __init__(self, *, networks=None, health="healthy", runner_id="sha256:" + "b" * 64):
        self.secret = None
        self.networks = networks or ["lab"]
        self.health = health
        self.runner_id = runner_id

    def run(self, command, **_kwargs):
        if command[1:3] == ["container", "inspect"]:
            payload = [{
                "Id": "d" * 64, "Image": "sha256:" + "a" * 64,
                "State": {"Health": {"Status": self.health}},
                "NetworkSettings": {"Networks": {
                    name: {"IPAddress": "172.19.0.2"} for name in self.networks
                }},
            }]
        elif command[1:3] == ["image", "inspect"]:
            payload = [{"Id": self.runner_id}]
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")


def make_receipt(module, namespace=None):
    namespace = namespace or args()
    tests = list(namespace.test) or [module.DEFAULT_TESTS[0]]
    receipt = module.base_receipt(namespace, "a" * 64, 1, tests)
    if namespace.execute:
        receipt["observed"] = {
            "db_container_id": "d" * 64,
            "db_image_id": "sha256:" + "a" * 64,
            "runner_image_id": "sha256:" + "b" * 64,
            "db_health": "healthy",
            "db_networks": ["lab"],
            "db_network_endpoint": "172.19.0.2",
        }
    return receipt


def test_wrong_network_fails_closed():
    module = load_module()
    namespace = args()
    receipt = make_receipt(module, namespace)
    assert module.pin_and_check(receipt, namespace, InspectCommands(networks=["bridge"])) is False
    assert receipt["checks"]["network_exact"] is False


def test_unhealthy_database_fails_closed():
    module = load_module()
    namespace = args()
    receipt = make_receipt(module, namespace)
    assert module.pin_and_check(receipt, namespace, InspectCommands(health="starting")) is False
    assert receipt["checks"]["database_healthy"] is False


def test_mutable_runner_tag_requires_matching_full_image_id():
    module = load_module()
    namespace = args()
    receipt = make_receipt(module, namespace)
    assert module.pin_and_check(receipt, namespace, InspectCommands(runner_id="sha256:drift")) is False
    assert receipt["checks"]["runner_image_id_pinned"] is False


def test_missing_expected_pin_is_blocked():
    module = load_module()
    namespace = args(expected_db_image_id=None)
    receipt = make_receipt(module, namespace)
    assert module.pin_and_check(receipt, namespace, InspectCommands()) is False
    assert receipt["checks"]["database_image_id_pinned"] is False


def test_commands_redact_operator_secret(monkeypatch):
    module = load_module()
    secret = "do-not-print-this-password"
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, f"out {secret}", f"err {secret}"),
    )
    result = module.Commands(secret).run(["example"])
    assert secret not in result.stdout + result.stderr
    assert result.stdout == "out [REDACTED]"


def test_commands_convert_timeout_to_redacted_failure(monkeypatch):
    module = load_module()
    secret = "do-not-print-this-password"
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(a[0], 1, output=f"out {secret}", stderr=f"err {secret}")
        ),
    )
    result = module.Commands(secret).run(["example"])
    assert result.returncode == 124
    assert secret not in result.stdout + result.stderr
    assert result.stderr.endswith("command_timeout")


def test_runner_script_shell_quotes_test_paths():
    module = load_module()
    test = "test/path with $(touch nope)'s_test.exs"
    script = module.runner_script([test])
    assert script.rstrip().endswith(f"mix test {shlex.quote(test)}")


class ExecutionCommands:
    def __init__(self, runner_exit=0, *, replace_db=False, cleanup_daemon_error=False,
                 wrong_runner_label=False, endpoint_drift=False, disappear_finished_runner=False,
                 finished_runner_inspect_error=False):
        self.secret = "secret"
        self.runner_exit = runner_exit
        self.replace_db = replace_db
        self.cleanup_daemon_error = cleanup_daemon_error
        self.wrong_runner_label = wrong_runner_label
        self.endpoint_drift = endpoint_drift
        self.disappear_finished_runner = disappear_finished_runner
        self.finished_runner_inspect_error = finished_runner_inspect_error
        self.calls = []
        self.runner_exists = False
        self.runner_removed = False
        self.database_exists = False
        self.invocation_id = None

    def container(self, container_id=None, labels=None, *, runner=False, endpoint="172.19.0.2"):
        return {
            "Id": container_id or "d" * 64, "Image": "sha256:" + "a" * 64,
            "State": ({"Status": "exited", "Running": False, "ExitCode": self.runner_exit}
                      if runner else {"Health": {"Status": "healthy"}}),
            "NetworkSettings": {"Networks": {"lab": {"IPAddress": endpoint}}},
            "Config": {"Labels": labels or {}},
        }

    def run(self, command, **_kwargs):
        self.calls.append(command)
        if command[:2] == ["docker", "run"]:
            self.runner_exists = True
            self.database_exists = True
            label = command[command.index("--label") + 1]
            self.invocation_id = label.split("=", 1)[1]
            if self.disappear_finished_runner:
                self.runner_exists = False
            stdout = (
                "TAMANDUA_MIGRATIONS_BEGIN\n20260718143000\n"
                "TAMANDUA_MIGRATIONS_END\n1 test, 0 failures\n"
            )
            return subprocess.CompletedProcess(command, self.runner_exit, stdout, "runner error")
        if command[:3] == ["docker", "container", "inspect"]:
            reference = command[3]
            if reference.startswith("tamandua-elixir-runtime-"):
                if self.finished_runner_inspect_error and self.runner_exists:
                    return subprocess.CompletedProcess(command, 125, "", "daemon unavailable")
                if not self.runner_exists:
                    return subprocess.CompletedProcess(command, 1, "", "not found")
                owner = "different-invocation" if self.wrong_runner_label else self.invocation_id
                payload = [self.container(
                    "c" * 64, {"tamandua.runtime-validation.invocation": owner}, runner=True
                )]
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            if reference == "c" * 64:
                if self.cleanup_daemon_error and self.runner_removed:
                    return subprocess.CompletedProcess(command, 125, "", "daemon unavailable")
                if not self.runner_exists:
                    return subprocess.CompletedProcess(command, 1, "", "not found")
                payload = [self.container(
                    "c" * 64, {"tamandua.runtime-validation.invocation": self.invocation_id}, runner=True
                )]
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            if reference == "d" * 64:
                endpoint = "172.19.0.99" if self.endpoint_drift and self.runner_removed else "172.19.0.2"
                payload = [self.container(endpoint=endpoint)]
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            if reference == "db":
                endpoint = "172.19.0.99" if self.endpoint_drift and self.runner_removed else "172.19.0.2"
                payload = [self.container("e" * 64 if self.replace_db else "d" * 64, endpoint=endpoint)]
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:4] == ["docker", "container", "ls", "--all"]:
            if ((self.cleanup_daemon_error and self.runner_removed)
                    or (self.finished_runner_inspect_error and self.runner_exists)):
                return subprocess.CompletedProcess(command, 125, "", "daemon unavailable")
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["docker", "rm", "-f"]:
            self.runner_exists = False
            self.runner_removed = True
            return subprocess.CompletedProcess(command, 0, command[-1], "")
        if command[:3] == ["docker", "exec", "d" * 64] and "psql" in command:
            if "shobj_description" in command[-1]:
                output = f"present:tamandua-runtime-validation:{self.invocation_id}" if self.database_exists else ""
                return subprocess.CompletedProcess(command, 0, output, "")
            return subprocess.CompletedProcess(command, 0, "1" if self.database_exists else "", "")
        if command[:3] == ["docker", "exec", "d" * 64] and "dropdb" in command:
            self.database_exists = False
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")


class DummyTemporary:
    def cleanup(self):
        return None


def prepare_execution(monkeypatch, module, *, source_after="a" * 64, staged="a" * 64):
    temporary = tempfile.TemporaryDirectory(prefix="tamandua-runtime-test-")
    staged_path = Path(temporary.name)
    (staged_path / module.STAGED_AUTHORITY_BOOTSTRAP).write_bytes(module.AUTHORITY_BOOTSTRAP.read_bytes())
    migrations = staged_path / "priv" / "repo" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / f"{module.BOOTSTRAP_MIGRATION_CUTOFF}_cutoff.exs").write_text(
        "cutoff\n", encoding="utf-8"
    )
    monkeypatch.setattr(module, "stage_source", lambda: (temporary, staged_path, staged, 1))
    monkeypatch.setattr(
        module, "canonical_source_digest",
        lambda *args, **_kwargs: ((staged if args else source_after), 1),
    )
    versions = "20260718043000\n20260718143000"
    monkeypatch.setattr(module, "migration_inventory", lambda _staged: {
        "migration_count": 2, "migration_max": "20260718143000",
        "migration_digest_sha256": module.hashlib.sha256(versions.encode("ascii")).hexdigest(),
    })


def test_transient_source_mutation_blocks_before_docker(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands()
    prepare_execution(monkeypatch, module, source_after="b" * 64)
    try:
        module.execute(receipt, args(execute=True), commands, "a" * 64)
    except RuntimeError as error:
        assert str(error) == "staged_source_digest_mismatch"
    else:
        raise AssertionError("source mutation must fail closed")
    assert not any(call[:2] == ["docker", "run"] for call in commands.calls)


def test_staged_digest_mismatch_blocks_before_docker(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands()
    prepare_execution(monkeypatch, module, staged="b" * 64)
    try:
        module.execute(receipt, args(execute=True), commands, "a" * 64)
    except RuntimeError as error:
        assert str(error) == "staged_source_digest_mismatch"
    else:
        raise AssertionError("staged mismatch must fail closed")
    assert not any(call[:2] == ["docker", "run"] for call in commands.calls)


def test_runner_failure_still_forces_and_verifies_cleanup(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands(runner_exit=7)
    prepare_execution(monkeypatch, module)
    assert module.execute(receipt, args(execute=True), commands, "a" * 64) is False
    assert any(call[:3] == ["docker", "rm", "-f"] for call in commands.calls)
    assert any("dropdb" in call for call in commands.calls)
    assert receipt["checks"]["cleanup_verified"] is True


def test_runner_uses_readonly_source_mount_and_pinned_image(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands()
    prepare_execution(monkeypatch, module)
    assert module.execute(receipt, args(execute=True), commands, "a" * 64) is True
    run_call = next(call for call in commands.calls if call[:2] == ["docker", "run"])
    assert any(value.endswith("dst=/source,readonly") for value in run_call)
    assert "sha256:" + "b" * 64 in run_call
    assert "secret" not in " ".join(run_call)
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(receipt)


def test_runner_uses_exact_database_endpoint_not_mutable_name(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands()
    prepare_execution(monkeypatch, module)
    assert module.execute(receipt, args(execute=True), commands, "a" * 64) is True
    run_call = next(call for call in commands.calls if call[:2] == ["docker", "run"])
    assert "TEST_DB_HOST=172.19.0.2" in run_call
    assert "TEST_DB_HOST=db" not in run_call
    assert receipt["execution"]["database_endpoint"] == "172.19.0.2"


def test_database_name_replacement_after_preflight_invalidates_success(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands(replace_db=True)
    prepare_execution(monkeypatch, module)
    assert module.execute(receipt, args(execute=True), commands, "a" * 64) is False
    assert receipt["checks"]["database_identity_stable"] is False


def test_database_endpoint_drift_after_run_invalidates_success(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands(endpoint_drift=True)
    prepare_execution(monkeypatch, module)
    assert module.execute(receipt, args(execute=True), commands, "a" * 64) is False
    assert receipt["checks"]["database_identity_stable"] is False


def test_finished_runner_disappearance_fails_closed(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands(disappear_finished_runner=True)
    prepare_execution(monkeypatch, module)
    try:
        module.execute(receipt, args(execute=True), commands, "a" * 64)
    except RuntimeError as error:
        assert str(error) == "finished_runner_missing"
    else:
        raise AssertionError("finished runner disappearance must fail closed")
    assert receipt["execution"]["runner_container_id"] is None


def test_finished_runner_inspect_error_fails_closed(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands(finished_runner_inspect_error=True)
    prepare_execution(monkeypatch, module)
    try:
        module.execute(receipt, args(execute=True), commands, "a" * 64)
    except RuntimeError as error:
        assert str(error).startswith("container_inspect_unknown")
    else:
        raise AssertionError("finished runner inspect error must fail closed")
    assert receipt["execution"]["runner_container_id"] is None


def test_readonly_bind_mount_serializes_normal_windows_drive_path():
    module = load_module()
    value = module.readonly_bind_mount(Path("C:/runtime source"))
    assert value.startswith("type=bind,src=C:\\runtime source,dst=/source")
    assert value.endswith(",readonly")


def test_readonly_bind_mount_rejects_comma_path():
    module = load_module()
    try:
        module.readonly_bind_mount(Path("C:/runtime,source"))
    except RuntimeError as error:
        assert str(error) == "bind_mount_path_not_serializable"
    else:
        raise AssertionError("comma path must fail closed")


def test_daemon_error_during_cleanup_is_not_treated_as_absence(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands(cleanup_daemon_error=True)
    prepare_execution(monkeypatch, module)
    try:
        module.execute(receipt, args(execute=True), commands, "a" * 64)
    except RuntimeError as error:
        assert str(error).startswith("container_inspect_unknown")
    else:
        raise AssertionError("daemon cleanup error must fail closed")


def test_preexisting_runner_name_is_never_started_or_removed(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands()
    original = module.inspect_container_optional
    first = True

    def preexisting(command_runner, reference):
        nonlocal first
        if first and reference.startswith("tamandua-elixir-runtime-"):
            first = False
            return commands.container("b" * 64, {"tamandua.runtime-validation.invocation": "other"})
        return original(command_runner, reference)

    monkeypatch.setattr(module, "inspect_container_optional", preexisting)
    prepare_execution(monkeypatch, module)
    try:
        module.execute(receipt, args(execute=True), commands, "a" * 64)
    except RuntimeError as error:
        assert str(error) == "runner_name_preexisting"
    else:
        raise AssertionError("preexisting runner must fail closed")
    assert not any(call[:2] == ["docker", "run"] for call in commands.calls)
    assert not any(call[:3] == ["docker", "rm", "-f"] for call in commands.calls)


def test_post_create_runner_ownership_mismatch_is_never_removed(monkeypatch):
    module = load_module()
    receipt = make_receipt(module, args(execute=True))
    commands = ExecutionCommands(wrong_runner_label=True)
    prepare_execution(monkeypatch, module)
    try:
        module.execute(receipt, args(execute=True), commands, "a" * 64)
    except RuntimeError as error:
        assert str(error) == "runner_ownership_mismatch"
    else:
        raise AssertionError("ownership mismatch must fail closed")
    assert not any(call[:3] == ["docker", "rm", "-f"] for call in commands.calls)


def test_receipt_schema_keeps_all_elevated_claims_false():
    module = load_module()
    receipt = make_receipt(module)
    receipt["status"] = "ready_inspect_only"
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(receipt)
    assert receipt["claims"] == {
        "local_dirty_worktree_runtime_smoke": False,
        "product_ready": False,
        "production_validated": False,
        "external_claim_allowed": False,
        "vendor_parity": False,
    }
    assert "Local dirty-worktree" in receipt["claim_boundary"]


def test_receipt_schema_rejects_unsubstantiated_pass():
    module = load_module()
    receipt = make_receipt(module)
    receipt["status"] = "pass"
    receipt["claims"]["local_dirty_worktree_runtime_smoke"] = True
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert list(validator.iter_errors(receipt))


def owned_args(**changes):
    image_db = "sha256:" + "a" * 64
    image_runner = "sha256:" + "b" * 64
    values = dict(
        db_container=None, network=None, owned_database=True, db_image=image_db,
        runner_image=image_runner, expected_db_container_id=None,
        expected_db_image_id=image_db, expected_runner_image_id=image_runner,
        db_user="tamandua", test=list(load_module().OWNED_RUNTIME_TESTS), execute=True,
        timeout=900, readiness_timeout=180, output=None,
    )
    values.update(changes)
    return Namespace(**values)


class OwnedCommands:
    def __init__(self, *, fail_phase=None, cleanup_fail=None, stdin_fail_prefix=None,
                 invalid_role_rows=False, post_stdout=None):
        self.secret = None
        self.calls = []
        self.stdin_calls = []
        self.invocation = None
        self.network_name = None
        self.network_exists = False
        self.database_exists = False
        self.database_name = None
        self.runners = {}
        self.fail_phase = fail_phase
        self.cleanup_fail = cleanup_fail
        self.stdin_fail_prefix = stdin_fail_prefix
        self.invalid_role_rows = invalid_role_rows
        self.post_stdout = post_stdout

    def run(self, command, **_kwargs):
        self.calls.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, json.dumps([{"Id": command[3]}]), "")
        if command[:3] == ["docker", "network", "create"]:
            self.network_exists = True
            self.network_name = command[-1]
            self.invocation = command[command.index("--label") + 1].split("=", 1)[1]
            return subprocess.CompletedProcess(command, 0, "e" * 64 + "\n", "")
        if command[:3] == ["docker", "network", "inspect"]:
            reference = command[3]
            if not self.network_exists:
                return subprocess.CompletedProcess(command, 1, "", "not found")
            payload = [{
                "Id": "e" * 64, "Name": self.network_name, "Internal": True,
                "Labels": {"tamandua.runtime-validation.invocation": self.invocation},
            }]
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:3] == ["docker", "network", "ls"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["docker", "network", "rm"]:
            self.network_exists = False
            return subprocess.CompletedProcess(command, 0, command[-1], "")
        if command[:2] == ["docker", "run"] and "--detach" in command:
            self.database_exists = True
            self.database_name = command[command.index("--name") + 1]
            return subprocess.CompletedProcess(command, 0, "d" * 64 + "\n", "")
        if command[:2] == ["docker", "run"]:
            name = command[command.index("--name") + 1]
            phase = "pre_bootstrap" if "-pre-" in name else "post_bootstrap"
            runner_id = ("c" if phase == "pre_bootstrap" else "f") * 64
            exit_code = 1 if self.fail_phase == phase else 0
            self.runners[name] = {"id": runner_id, "exit_code": exit_code}
            stdout = "" if phase == "pre_bootstrap" else (self.post_stdout or "22 tests, 0 failures\n")
            return subprocess.CompletedProcess(command, exit_code, stdout, "")
        if command[:3] == ["docker", "container", "inspect"]:
            reference = command[3]
            if reference in ("d" * 64, self.database_name) and self.database_exists:
                payload = [{
                    "Id": "d" * 64, "Image": "sha256:" + "a" * 64,
                    "Config": {"Labels": {"tamandua.runtime-validation.invocation": self.invocation}},
                    "HostConfig": {"PortBindings": {}},
                    "NetworkSettings": {"Networks": {self.network_name: {"IPAddress": "172.20.0.2"}}},
                    "State": {"Status": "running", "Running": True},
                }]
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            observed = next(
                ((name, state) for name, state in self.runners.items()
                 if reference in (name, state["id"])), None
            )
            if observed:
                name, state = observed
                payload = [{
                    "Id": state["id"], "Image": "sha256:" + "b" * 64,
                    "Config": {"Labels": {"tamandua.runtime-validation.invocation": self.invocation}},
                    "State": {"Status": "exited", "Running": False, "ExitCode": state["exit_code"]},
                    "NetworkSettings": {"Networks": {}},
                }]
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            return subprocess.CompletedProcess(command, 1, "", "not found")
        if command[:4] == ["docker", "container", "ls", "--all"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["docker", "exec", "d" * 64]:
            if command[3:5] == ["postgres", "--version"]:
                return subprocess.CompletedProcess(command, 0, "postgres (PostgreSQL) 16.4\n", "")
            if command[3:5] == ["psql", "--version"]:
                return subprocess.CompletedProcess(command, 0, "psql (PostgreSQL) 16.4\n", "")
            if "pg_isready" in command:
                return subprocess.CompletedProcess(command, 0, "accepting connections\n", "")
            if "createdb" in command:
                return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["docker", "rm", "-f"]:
            if self.cleanup_fail == command[3]:
                return subprocess.CompletedProcess(command, 1, "", "synthetic")
            for name, state in list(self.runners.items()):
                if state["id"] == command[3]:
                    del self.runners[name]
            if command[3] == "d" * 64:
                self.database_exists = False
            return subprocess.CompletedProcess(command, 0, command[3], "")
        raise AssertionError(command)

    def run_stdin(self, command, payload, **_kwargs):
        self.calls.append(command)
        self.stdin_calls.append((command, payload))
        if self.stdin_fail_prefix and payload.startswith(self.stdin_fail_prefix):
            return subprocess.CompletedProcess(command, 1, "", "raw database error must not escape")
        if payload.startswith(b"SELECT version::text"):
            return subprocess.CompletedProcess(command, 0, "20260718043000\n20260718143000\n", "")
        if payload.startswith(b"SELECT roles.rolname"):
            if self.invalid_role_rows:
                return subprocess.CompletedProcess(command, 0, "tamandua_runtime|t|t|t\n", "")
            rows = (
                "tamandua_authority_login|true|false|false|false|false|false|false|-1|true|true|true|tamandua_authority_retention_executor:false:false:true|-\n"
                "tamandua_authority_retention_executor|false|false|false|false|false|false|false|-1|true|true|true|-|tamandua_authority_login:false:false:true\n"
                "tamandua_authority_retention_owner|false|false|false|false|false|false|false|-1|true|true|true|-|-\n"
                "tamandua_migrator|true|false|false|false|false|false|false|-1|true|true|true|-|-\n"
                "tamandua_runtime|true|false|false|false|false|false|false|-1|true|true|true|-|-\n"
            )
            return subprocess.CompletedProcess(command, 0, rows, "")
        return subprocess.CompletedProcess(command, 0, "", "")


def test_owned_arguments_reject_tags_shared_resources_and_excessive_readiness():
    module = load_module()
    for namespace, expected in (
        (owned_args(runner_image="runner:latest"), "owned_database_requires_full_runner_image"),
        (owned_args(network="shared"), "owned_database_rejects_shared_resource_arguments"),
        (owned_args(readiness_timeout=181), "readiness_timeout_out_of_range"),
        (owned_args(test=[]), "owned_database_requires_explicit_tests"),
        (owned_args(test=["test/other_test.exs"]), "owned_database_requires_exact_runtime_tests"),
    ):
        try:
            module.validate_args(namespace)
        except ValueError as error:
            assert str(error) == expected
        else:
            raise AssertionError(f"unsafe arguments accepted: {namespace}")


def test_owned_runner_scripts_split_at_exact_bootstrap_cutoff_and_test_once():
    module = load_module()
    tests = list(module.OWNED_RUNTIME_TESTS)
    pre = module.owned_runner_script(tests, "pre_bootstrap")
    post = module.owned_runner_script(tests, "post_bootstrap")
    assert f"mix ecto.migrate --quiet --to {module.BOOTSTRAP_MIGRATION_CUTOFF}" in pre
    assert "mix test " not in pre and "psql" not in pre
    assert post.count("mix ecto.migrate --quiet") == 1
    assert post.count("mix test ") == 1
    assert "TAMANDUA_ACCESS_POLICY_GLOBAL_RLS_RUNTIME_PG_TESTS=true" in post
    assert all(test in post for test in tests)
    assert "psql" not in post and "password" not in post.lower()
    audit = {**module.parse_migration_rows("1\n20\n"),
             **module.parse_test_audit("7 tests, 0 failures, 2 excluded, 1 skipped\n", tests)}
    assert audit["migration_max"] == "20" and audit["test_command_count"] == 1
    assert (audit["tests_total"], audit["excluded"], audit["skipped"]) == (7, 2, 1)
    assert "tamandua_authority_retention_executor" in module.ROLE_AUDIT_SQL.decode("ascii")
    assert "membership.set_option::text" in module.ROLE_AUDIT_SQL.decode("ascii")
    assert len(module.EXPECTED_DEGRADED_ROLE_ROWS) == 5


def test_owned_migration_inventory_excludes_non_ecto_rollback_file(tmp_path):
    module = load_module()
    migrations = tmp_path / "priv" / "repo" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "1_first.exs").write_text("defmodule First do\nend\n", encoding="utf-8")
    (migrations / "20_second.exs").write_text("defmodule Second do\nend\n", encoding="utf-8")
    (migrations / "ROLLBACK_agent_groups.exs").write_text("not an Ecto migration\n", encoding="utf-8")
    inventory = module.migration_inventory(tmp_path)
    assert inventory["migration_count"] == 2
    assert inventory["migration_max"] == "20"


def test_owned_bootstrap_cutoff_must_exist_exactly_once_in_staged_source(tmp_path):
    module = load_module()
    migrations = tmp_path / "priv" / "repo" / "migrations"
    migrations.mkdir(parents=True)
    with pytest.raises(RuntimeError, match="bootstrap_migration_cutoff_source_invalid"):
        module.validate_bootstrap_cutoff(tmp_path)

    cutoff = migrations / f"{module.BOOTSTRAP_MIGRATION_CUTOFF}_cutoff.exs"
    cutoff.write_text("cutoff\n", encoding="utf-8")
    module.validate_bootstrap_cutoff(tmp_path)

    (migrations / f"{module.BOOTSTRAP_MIGRATION_CUTOFF}_duplicate.exs").write_text(
        "duplicate\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="bootstrap_migration_cutoff_source_invalid"):
        module.validate_bootstrap_cutoff(tmp_path)


def test_owned_database_contract_is_internal_passwordless_pinned_and_zero_residue(monkeypatch):
    module = load_module()
    namespace = owned_args()
    commands = OwnedCommands()
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    assert module.owned_execute(receipt, namespace, commands, "a" * 64) is True
    db_run = next(call for call in commands.calls if call[:2] == ["docker", "run"] and "--detach" in call)
    runner_runs = [call for call in commands.calls if call[:2] == ["docker", "run"] and "--detach" not in call]
    network_create = next(call for call in commands.calls if call[:3] == ["docker", "network", "create"])
    assert "--internal" in network_create
    assert "--publish" not in db_run and "-p" not in db_run
    assert "POSTGRES_HOST_AUTH_METHOD=trust" in db_run
    assert any(value.startswith("/var/lib/postgresql/data:rw,noexec,nosuid") for value in db_run)
    assert "sha256:" + "a" * 64 == db_run[-1]
    assert len(runner_runs) == 2
    assert runner_runs[0][runner_runs[0].index("--name") + 1] != runner_runs[1][runner_runs[1].index("--name") + 1]
    assert all("sha256:" + "b" * 64 in run for run in runner_runs)
    assert all(any(value.endswith("dst=/source,readonly") for value in run) for run in runner_runs)
    assert all(not any("PASSWORD" in value for value in run) for run in runner_runs)
    assert all("TAMANDUA_ALLOW_DEGRADED_CREDENTIALS=true" in run for run in runner_runs)
    assert [payload for _command, payload in commands.stdin_calls] == [
        module.DEGRADED_ROLE_SQL, module.AUTHORITY_BOOTSTRAP.read_bytes(),
        module.MIGRATION_AUDIT_SQL, module.ROLE_AUDIT_SQL,
    ]
    assert all(command[:4] == ["docker", "exec", "-i", "d" * 64]
               for command, _payload in commands.stdin_calls)
    assert receipt["execution_contract_version"] == 2
    assert receipt["execution"]["phase_order"] == [
        "database_created", "pre_bootstrap_migrated", "degraded_roles_created",
        "authority_bootstrapped", "post_bootstrap_tests_completed",
        "migrations_audited", "roles_audited",
    ]
    assert receipt["execution"]["role_audit"] == "closed_degraded"
    rendered = json.dumps(receipt, sort_keys=True)
    assert "CREATE ROLE" not in rendered and "SELECT version" not in rendered
    assert "tamandua_authority_login|t|f" not in rendered
    assert "stdout" not in receipt["execution"] and "stderr" not in receipt["execution"]
    for command, _payload in commands.stdin_calls:
        joined = " ".join(command)
        assert "sh -c" not in joined and " cp " not in f" {joined} " and "pull" not in joined
        assert "--no-password" in command
        assert "PGPASSWORD" not in joined and "PASSWORD=" not in joined
        assert "--publish" not in command and "-p" not in command
    assert receipt["audit"]["migration_count"] == 2
    assert receipt["audit"]["tests_total"] == 22
    assert receipt["cleanup"] == {
        "runner_absent": True, "pre_bootstrap_runner_absent": True,
        "post_bootstrap_runner_absent": True, "test_database_absent": True,
        "database_container_absent": True, "network_absent": True,
        "zero_residue": True, "verified": True,
    }
    receipt["status"] = "pass"
    receipt["claims"]["local_dirty_worktree_runtime_smoke"] = True
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(receipt)


def test_owned_pass_receipt_fails_closed_on_cleanup_residue(monkeypatch):
    module = load_module()
    namespace = owned_args()
    commands = OwnedCommands()
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    assert module.owned_execute(receipt, namespace, commands, "a" * 64) is True
    receipt["status"] = "pass"
    receipt["claims"]["local_dirty_worktree_runtime_smoke"] = True
    receipt["cleanup"]["network_absent"] = False
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert list(validator.iter_errors(receipt))


def test_owned_execution_fails_when_source_changes_after_runner(monkeypatch):
    module = load_module()
    namespace = owned_args()
    commands = OwnedCommands()
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    live_calls = 0
    def drifting_digest(*positional, **_kwargs):
        nonlocal live_calls
        if positional:
            return "a" * 64, 1
        live_calls += 1
        return (("a" if live_calls == 1 else "c") * 64, 1)
    monkeypatch.setattr(module, "canonical_source_digest", drifting_digest)
    try:
        module.owned_execute(receipt, namespace, commands, "a" * 64)
    except RuntimeError as error:
        assert str(error) == "source_drift_after_pre_bootstrap"
    else:
        raise AssertionError("phase source drift must fail closed")
    assert receipt["checks"]["pre_bootstrap_source_stable"] is False
    assert receipt["cleanup"]["zero_residue"] is True


def test_owned_harness_drift_blocks_before_first_resource_mutation(monkeypatch):
    module = load_module()
    namespace = owned_args()
    commands = OwnedCommands()
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    monkeypatch.setattr(module, "sha256_file", lambda _path: "c" * 64)

    with pytest.raises(RuntimeError, match="staged_source_digest_mismatch"):
        module.owned_execute(receipt, namespace, commands, "a" * 64)

    assert not any(call[:3] == ["docker", "network", "create"] for call in commands.calls)
    assert not any(call[:2] == ["docker", "run"] for call in commands.calls)


def test_source_symlink_is_rejected_before_staging_copy(tmp_path):
    module = load_module()
    server = tmp_path / "server"
    server.mkdir()
    for item in module.INPUTS:
        path = server / item
        if path.suffix:
            path.write_text(item, encoding="utf-8")
        else:
            path.mkdir()
    secret = tmp_path / "outside-secret"
    secret.write_text("must-not-enter-staging", encoding="utf-8")
    link = server / "config" / "linked-secret.exs"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(RuntimeError, match=r"^source_symlink_forbidden:config/linked-secret\.exs$"):
        module.stage_source(server)


def test_psql_stdin_is_byte_preserving_and_never_uses_text_mode(monkeypatch):
    module = load_module()
    payload = "SELECT 'ação';\n".encode("utf-8")
    observed = {}

    def fake_run(command, **kwargs):
        observed.update(command=command, kwargs=kwargs)
        return subprocess.CompletedProcess(command, 0, b"ok\n", b"")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    result = module.Commands().run_stdin(["docker", "exec", "-i", "d" * 64, "psql"], payload)
    assert result.stdout == "ok\n"
    assert observed["kwargs"]["input"] is payload
    assert "text" not in observed["kwargs"] and "shell" not in observed["kwargs"]


@pytest.mark.parametrize(("payload", "error"), [
    (b"SELECT 1;\x00", "psql_stdin_contains_nul"),
    (b"\xff", "psql_stdin_not_utf8"),
    (b"x" * (64 * 1024 + 1), "psql_stdin_too_large"),
], ids=["nul", "non-utf8", "oversize"])
def test_psql_stdin_rejects_nul_non_utf8_and_oversize(payload, error):
    module = load_module()
    with pytest.raises(ValueError, match=f"^{error}$"):
        module.Commands().run_stdin(["unused"], payload)


@pytest.mark.parametrize(("stream", "payload", "error"), [
    ("stdout", b"\x00", "psql_stdout_contains_nul"),
    ("stderr", b"\xff", "psql_stderr_not_utf8"),
    ("stdout", b"x" * (64 * 1024 + 1), "psql_stdout_too_large"),
], ids=["stdout-nul", "stderr-non-utf8", "stdout-oversize"])
def test_psql_output_rejects_nul_non_utf8_and_oversize(monkeypatch, stream, payload, error):
    module = load_module()
    stdout = payload if stream == "stdout" else b""
    stderr = payload if stream == "stderr" else b""
    monkeypatch.setattr(
        module.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout, stderr),
    )
    with pytest.raises(ValueError, match=f"^{error}$"):
        module.Commands().run_stdin(["unused"], b"SELECT 1;\n")


@pytest.mark.parametrize(("phase", "stdin_count"), [
    ("pre_bootstrap", 0),
    ("post_bootstrap", 2),
])
def test_owned_phase_failure_stops_without_retry_and_cleans_every_resource(monkeypatch, phase, stdin_count):
    module = load_module()
    namespace = owned_args()
    commands = OwnedCommands(fail_phase=phase)
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    with pytest.raises(RuntimeError, match=f"^{phase}_runner_failed$"):
        module.owned_execute(receipt, namespace, commands, "a" * 64)
    assert len(commands.stdin_calls) == stdin_count
    runner_runs = [call for call in commands.calls if call[:2] == ["docker", "run"] and "--detach" not in call]
    assert len(runner_runs) == (1 if phase == "pre_bootstrap" else 2)
    assert receipt["cleanup"]["zero_residue"] is True


def test_cleanup_attempts_post_runner_database_and_network_after_pre_runner_failure(monkeypatch):
    module = load_module()
    namespace = owned_args()
    commands = OwnedCommands(cleanup_fail="c" * 64)
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    assert module.owned_execute(receipt, namespace, commands, "a" * 64) is False
    assert receipt["cleanup"]["pre_bootstrap_runner_absent"] is False
    assert receipt["cleanup"]["post_bootstrap_runner_absent"] is True
    assert receipt["cleanup"]["database_container_absent"] is True
    assert receipt["cleanup"]["network_absent"] is True
    assert receipt["cleanup"]["zero_residue"] is False


def test_receipt_schema_preserves_legacy_and_v1_contracts():
    module = load_module()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    legacy = make_receipt(module)
    legacy["status"] = "ready_inspect_only"
    legacy.pop("execution_contract_version")
    legacy["source"].pop("harness_sha256")
    legacy["cleanup"].pop("pre_bootstrap_runner_absent")
    legacy["cleanup"].pop("post_bootstrap_runner_absent")
    validator.validate(legacy)
    version_one = json.loads(json.dumps(legacy))
    version_one["execution_contract_version"] = 1
    validator.validate(version_one)
    version_two = json.loads(json.dumps(legacy))
    version_two["execution_contract_version"] = 2
    assert list(validator.iter_errors(version_two))


def test_v2_owned_pass_rejects_missing_phase_or_raw_receipt_fields(monkeypatch):
    module = load_module()
    namespace = owned_args()
    commands = OwnedCommands()
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    assert module.owned_execute(receipt, namespace, commands, "a" * 64) is True
    receipt["status"] = "pass"
    receipt["claims"]["local_dirty_worktree_runtime_smoke"] = True
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    invalid = json.loads(json.dumps(receipt))
    invalid["execution"].pop("phase_order")
    assert list(validator.iter_errors(invalid))
    invalid = json.loads(json.dumps(receipt))
    invalid["execution"]["stdout"] = "raw database rows"
    assert list(validator.iter_errors(invalid))
    invalid = json.loads(json.dumps(receipt))
    invalid["source"].pop("harness_sha256")
    assert list(validator.iter_errors(invalid))
    assert receipt["source"]["harness_sha256"] == module.LOADED_HARNESS_SHA256
    assert module.LOADED_HARNESS_SHA256 == module.sha256_file(module.HARNESS)


@pytest.mark.parametrize(("commands", "expected"), [
    (OwnedCommands(stdin_fail_prefix=b"CREATE ROLE"), "degraded_roles_failed"),
    (OwnedCommands(stdin_fail_prefix=b"\\set ON_ERROR_STOP"), "authority_bootstrap_failed"),
    (OwnedCommands(invalid_role_rows=True), "degraded_role_attributes_invalid"),
])
def test_database_sql_failures_are_categorical_secretless_and_cleanup(monkeypatch, commands, expected):
    module = load_module()
    namespace = owned_args()
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    with pytest.raises(RuntimeError, match=f"^{expected}$") as captured:
        module.owned_execute(receipt, namespace, commands, "a" * 64)
    assert "raw database error" not in str(captured.value)
    assert receipt["cleanup"]["zero_residue"] is True


@pytest.mark.parametrize(("output", "expected"), [
    ("x" * (64 * 1024 + 1), "post_bootstrap_stdout_too_large"),
    ("22 tests, 0 failures\n\x00", "post_bootstrap_stdout_contains_nul"),
], ids=["oversize", "nul"])
def test_runner_output_is_bounded_and_never_enters_receipt(monkeypatch, output, expected):
    module = load_module()
    namespace = owned_args()
    commands = OwnedCommands(post_stdout=output)
    receipt = make_receipt(module, namespace)
    assert module.owned_pin_and_check(receipt, namespace, commands) is True
    prepare_execution(monkeypatch, module)
    with pytest.raises(ValueError, match=f"^{expected}$"):
        module.owned_execute(receipt, namespace, commands, "a" * 64)
    assert "stdout" not in receipt["execution"] and "stderr" not in receipt["execution"]
    assert receipt["cleanup"]["zero_residue"] is True
