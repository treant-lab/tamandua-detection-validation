from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[3]
PARENT_PATH = ROOT / "tools/detection_validation/scripts/elixir_check_locked_probe_worker_adapter_parent.py"
ADAPTER_PATH = ROOT / "tools/detection_validation/scripts/elixir_check_locked_probe_worker_adapter.py"
PROTOCOL_PATH = ROOT / "schemas/elixir_check_locked_probe_worker_adapter_protocol_v1.schema.json"
RECEIPT_PATH = ROOT / "schemas/elixir_check_locked_probe_worker_adapter_boundary_receipt_v1.schema.json"
INVOCATION = "0123456789abcdef0123456789abcdef"
PARENT_AST_SHA256 = "5bf893fbdef4837bbecae4a5cc65129e85ebf8368506fa3b79f98c32f6f23f78"
ADAPTER_AST_SHA256 = "53f39a124ae3ae62a43e2d292bd202f2428eb431d81c6cebdb0d1a4c119521de"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


parent = load_module("loop150_adapter_parent", PARENT_PATH)
adapter = load_module("loop150_adapter_double", ADAPTER_PATH)
PROTOCOL = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
RECEIPT = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
RECEIPT_VALIDATOR = Draft202012Validator(RECEIPT)


@pytest.fixture(scope="module")
def receipt():
    return parent.build_receipt(INVOCATION)


def set_path(value, path, replacement):
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement


def qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = qualified_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        base = qualified_name(node.func)
        return f"{base}()" if base else None
    return None


def semantic_ast_sha256(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            del body[0]
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()


def test_both_schemas_are_valid_draft_202012():
    Draft202012Validator.check_schema(PROTOCOL)
    Draft202012Validator.check_schema(RECEIPT)


def test_parent_and_double_executable_ast_manifests_are_exact():
    assert semantic_ast_sha256(PARENT_PATH) == PARENT_AST_SHA256
    assert semantic_ast_sha256(ADAPTER_PATH) == ADAPTER_AST_SHA256


def test_source_only_double_executes_once_but_adapter_never_executes(receipt):
    assert receipt["result"] == {"status": "observed", "outcome": "source_only_not_executed", "error_class": None}
    assert receipt["execution"] == {"double_spawn_count": 1, "adapter_runs": 0, "network_requests": 0, "check_locked_runs": 0}
    assert all(value is False for value in receipt["claims"].values())
    parent.validate_receipt(receipt)


def test_manifest_binds_all_required_source_schema_interpreter_runner_inputs():
    manifest = parent.build_manifest(INVOCATION)
    assert set(manifest["bindings"]) == {
        "parent_source_sha256", "double_source_sha256", "protocol_schema_sha256",
        "receipt_schema_sha256", "interpreter_executable_sha256",
        "interpreter_version_sha256", "mix_exs_sha256", "mix_lock_sha256",
        "config_sha256", "config_file_count", "runner_source_sha256",
        "runner_dockerfile_sha256",
    }
    assert all(len(value) == 64 for key, value in manifest["bindings"].items() if key != "config_file_count")
    Draft202012Validator(PROTOCOL).validate(manifest)


def test_unobserved_docker_identity_is_explicit_not_forged():
    identity = parent.build_manifest(INVOCATION)["adapter"]
    assert identity["identity_observed"] is False
    assert identity["executable_sha256"] == identity["version_sha256"] == identity["context_sha256"] == "0" * 64
    assert identity["image_id"] == parent.IMAGE_ID


def test_exact_planned_argv_is_offline_read_only_owned_and_cleanup_complete():
    manifest = parent.build_manifest(INVOCATION)
    argv = manifest["adapter"]["argv"]
    assert list(argv) == ["pre_absence", "inventory_before", "inspect_owned", "run", "cleanup_exact_id", "final_absence", "inventory_after"]
    run = argv["run"]
    assert run.count("--network") == 1 and run[run.index("--network") + 1] == "none"
    assert run.count("--pull") == 1 and run[run.index("--pull") + 1] == "never"
    assert run.count("--read-only") == 1
    assert run[-6:] == [parent.IMAGE_ID, "mix", "deps.get", "--only", "test", "--check-locked"]
    assert argv["cleanup_exact_id"][1:] == ["container", "rm", "--force", "${verified_exact_resource_id}"]
    assert argv["inspect_owned"][-1] == manifest["invocation"]["resource_name"]
    assert all(command[0] == parent.DOCKER_PATH for command in argv.values())


def test_invocation_derives_unique_name_owner_and_exact_labels():
    first = parent.build_manifest(INVOCATION)["invocation"]
    second = parent.build_manifest("f" * 32)["invocation"]
    assert first["resource_name"] != second["resource_name"]
    assert first["labels"]["io.tamandua.owner"] == INVOCATION
    assert first["resource_name"].endswith(INVOCATION)


@pytest.mark.parametrize("explicit", [None, False, True, 0, 1, b"", "", "0", "g" * 32, "A" * 32, "0" * 31, "0" * 33, [], {}])
def test_every_explicit_falsy_nonstr_or_noncanonical_id_is_input_invalid_without_spawn(monkeypatch, explicit):
    monkeypatch.setattr(parent, "run_double", lambda _request: pytest.fail("must not spawn"))
    value = parent.build_receipt(explicit)
    assert value["result"]["error_class"] == "input_invalid"
    assert value["execution"]["double_spawn_count"] == 0


def test_omitted_id_is_the_only_auto_generated_case(monkeypatch):
    monkeypatch.setattr(parent.secrets, "token_hex", lambda count: INVOCATION if count == 16 else pytest.fail("size"))
    assert parent.build_receipt()["invocation_id"] == INVOCATION


def test_mount_plan_is_content_addressed_read_only_and_consumed_by_argv():
    manifest = parent.build_manifest(INVOCATION)
    mounts = manifest["adapter"]["mounts"]
    run = manifest["adapter"]["argv"]["run"]
    assert len(mounts) == 4 + manifest["bindings"]["config_file_count"]
    assert manifest["adapter"]["mounts_sha256"] == parent.digest(mounts)
    bundle_ids = {mount["destination"].split("/")[2] for mount in mounts}
    assert len(bundle_ids) == 1 and all(len(value) == 64 for value in bundle_ids)
    for mount in mounts:
        assert mount["read_only"] is True
        assert mount["source_sha256"] == parent.hash_file(Path(mount["source"]))
        assert f"type=bind,src={mount['source']},dst={mount['destination']},readonly" in run
    assert not any("/probe" in item for item in run)
    for key in ("mix_exs_sha256", "mix_lock_sha256", "config_sha256", "runner_source_sha256", "runner_dockerfile_sha256"):
        assert manifest["bindings"][key] in manifest["invocation"]["labels"].values()


def test_cleanup_authority_requires_verified_exact_id_and_all_labels():
    manifest = parent.build_manifest(INVOCATION)
    predicate = manifest["adapter"]["ownership_predicate"]
    assert predicate["exact_id_pattern"] == "^[a-f0-9]{64}$"
    assert predicate["required_labels"] == manifest["invocation"]["labels"]
    cleanup = manifest["adapter"]["argv"]["cleanup_exact_id"]
    assert manifest["invocation"]["resource_name"] not in cleanup
    assert cleanup[-1] == "${verified_exact_resource_id}"


def test_full_invocation_suffix_prevents_same_prefix_resource_collision():
    left = "0123456789abcdef" + "0" * 16
    right = "0123456789abcdef" + "f" * 16
    assert parent.build_manifest(left)["invocation"]["resource_name"] != parent.build_manifest(right)["invocation"]["resource_name"]


def test_planned_state_machine_and_actual_observation_are_distinct(receipt):
    assert receipt["plan"]["state_machine"] == [
        "pre_absence", "optional_exact_resource_id", "ownership_verified", "cleanup_attempted",
        "final_absence", "inventory_reconciled",
    ]
    assert receipt["observation"] == parent._observation()


def test_stream_observation_is_complete_bounded_and_raw_output_is_excluded(receipt):
    transport = receipt["transport"]
    assert transport["stdout_observation_complete"] is True
    assert transport["stderr_observation_complete"] is True
    assert transport["stderr_seen"] is False
    assert 0 < transport["accepted_output_bytes"] <= transport["accepted_output_max_bytes"]
    assert transport["accepted_output_bytes"] == transport["accepted_stdout_bytes"] + transport["accepted_stderr_bytes"]
    request = parent.build_request(INVOCATION)
    response = parent._expected_response(request)
    assert transport["request_sha256"] == parent.digest(request)
    assert transport["response_sha256"] == parent.digest(response)
    assert transport["accepted_stdout_bytes"] == len(parent.canonical_bytes(response)) + 1
    encoded = parent.canonical_bytes(receipt).lower()
    assert b"raw_output" not in encoded and b"raw_stderr" not in encoded and b"raw_stdout" not in encoded


@pytest.mark.parametrize("path,replacement", [
    (("transport", "request_sha256"), "0" * 64),
    (("transport", "response_sha256"), "0" * 64),
    (("transport", "accepted_output_bytes"), 0),
    (("transport", "accepted_output_bytes"), 32768),
    (("transport", "accepted_stdout_bytes"), 0),
    (("transport", "accepted_stdout_bytes"), 32768),
    (("transport", "accepted_stderr_bytes"), 1),
    (("transport", "stderr_seen"), True),
    (("transport", "stdout_observation_complete"), False),
    (("transport", "stderr_observation_complete"), False),
])
def test_receipt_recomputes_protocol_hashes_bytes_and_stream_cardinality(receipt, path, replacement):
    value = copy.deepcopy(receipt)
    set_path(value, path, replacement)
    with pytest.raises((ValidationError, ValueError)):
        parent.validate_receipt(value)


@pytest.mark.parametrize("path,replacement", [
    (("process", "lifecycle_state"), "not_spawned"),
    (("process", "containment_established"), False),
    (("process", "termination_attempted"), True),
    (("process", "exit_confirmed"), False),
    (("process", "exit_code"), None),
    (("process", "exit_code"), 1),
    (("process", "timed_out"), True),
    (("execution", "double_spawn_count"), 0),
])
def test_observed_receipt_rejects_lifecycle_and_exit_drift(receipt, path, replacement):
    value = copy.deepcopy(receipt)
    set_path(value, path, replacement)
    with pytest.raises((ValidationError, ValueError)):
        parent.validate_receipt(value)


@pytest.mark.parametrize("mutation", [
    lambda value: value["plan"]["adapter"]["mounts"].pop(),
    lambda value: value["plan"]["adapter"]["mounts"][0].__setitem__("read_only", False),
    lambda value: value["plan"]["adapter"]["mounts"][0].__setitem__("source_sha256", "0" * 64),
    lambda value: value["plan"]["adapter"]["mounts"][0].__setitem__("destination", "/probe/mix.exs"),
    lambda value: value["plan"]["adapter"]["ownership_predicate"].__setitem__("exact_id_pattern", ".*"),
    lambda value: value["plan"]["adapter"]["ownership_predicate"]["required_labels"].__setitem__("io.tamandua.owner", "f" * 32),
])
def test_mount_staging_and_id_label_cleanup_predicate_are_immutable(receipt, mutation):
    value = copy.deepcopy(receipt)
    mutation(value)
    with pytest.raises((ValidationError, ValueError)):
        parent.validate_receipt(value)


@pytest.mark.parametrize("path,replacement", [
    (("execution", "adapter_runs"), 1),
    (("execution", "network_requests"), 1),
    (("execution", "check_locked_runs"), 1),
    (("claims", "adapter_executed"), True),
    (("claims", "check_locked_executed"), True),
    (("claims", "real_cleanup_verified"), True),
    (("claims", "product_ready"), True),
    (("claims", "production_ready"), True),
    (("claims", "release_ready"), True),
    (("claims", "external_claim_allowed"), True),
    (("claims", "verimatrix_parity"), True),
    (("observation", "pre_absence"), "absent"),
    (("observation", "exact_resource_id"), "a" * 64),
    (("observation", "cleanup_attempted"), True),
    (("observation", "cleanup_succeeded"), True),
    (("observation", "final_absence"), "absent"),
    (("observation", "inventory_before_sha256"), "0" * 64),
    (("observation", "inventory_after_sha256"), "0" * 64),
    (("observation", "inventory_unchanged"), True),
])
def test_receipt_rejects_execution_cleanup_observation_and_claim_promotion(receipt, path, replacement):
    value = copy.deepcopy(receipt)
    set_path(value, path, replacement)
    with pytest.raises((ValidationError, ValueError)):
        parent.validate_receipt(value)


@pytest.mark.parametrize("path,replacement", [
    (("plan", "resource", "id"), "f" * 32),
    (("plan", "resource", "resource_name"), "tamandua-check-locked-loop150-" + "f" * 32),
    (("plan", "resource", "labels", "io.tamandua.owner"), "f" * 32),
    (("plan", "resource", "labels", "io.tamandua.operation"), "alternate"),
    (("plan", "resource", "labels", "io.tamandua.source"), "0" * 40),
    (("plan", "adapter", "image_id"), "sha256:" + "0" * 64),
    (("plan", "adapter", "executable_path"), "docker"),
    (("plan", "adapter", "identity_observed"), True),
    (("plan", "adapter", "executable_sha256"), "1" * 64),
    (("plan", "adapter", "version_sha256"), "1" * 64),
    (("plan", "adapter", "context_sha256"), "1" * 64),
    (("plan", "adapter", "environment"), {"PATH": "private"}),
    (("plan", "adapter", "environment_sha256"), "1" * 64),
    (("plan", "adapter", "cwd"), "C:/alternate"),
    (("plan", "adapter", "cwd_sha256"), "1" * 64),
    (("plan", "adapter", "argv_sha256"), "1" * 64),
    (("bindings", "argv_sha256"), "1" * 64),
])
def test_receipt_rejects_ownership_identity_environment_cwd_and_argv_drift(receipt, path, replacement):
    value = copy.deepcopy(receipt)
    set_path(value, path, replacement)
    with pytest.raises((ValidationError, ValueError)):
        parent.validate_receipt(value)


@pytest.mark.parametrize("operation,index,replacement", [
    ("run", 0, "docker"),
    ("run", 1, "exec"),
    ("run", 3, "foreign-name"),
    ("run", 5, "always"),
    ("run", 7, "default"),
    ("run", 8, "--privileged"),
    ("cleanup_exact_id", 2, "stop"),
    ("cleanup_exact_id", 4, "foreign-name"),
    ("pre_absence", 2, "ls"),
    ("final_absence", 2, "ls"),
    ("inventory_before", 2, "rm"),
    ("inventory_after", 2, "rm"),
])
def test_receipt_rejects_exact_command_grammar_mutation(receipt, operation, index, replacement):
    value = copy.deepcopy(receipt)
    value["plan"]["adapter"]["argv"][operation][index] = replacement
    value["plan"]["adapter"]["argv_sha256"] = parent.digest(value["plan"]["adapter"]["argv"])
    value["bindings"]["argv_sha256"] = value["plan"]["adapter"]["argv_sha256"]
    with pytest.raises(ValueError):
        parent.validate_receipt(value)


@pytest.mark.parametrize("field,replacement", [
    ("total_timeout_ms", 4999), ("total_timeout_ms", 5001),
    ("cleanup_reserve_ms", 1499), ("cleanup_reserve_ms", 1501),
    ("combined_output_max_bytes", 32767), ("combined_output_max_bytes", 32769),
    ("request_max_bytes", 65535), ("response_max_bytes", 16385),
])
def test_receipt_rejects_deadline_reserve_and_stream_limit_drift(receipt, field, replacement):
    value = copy.deepcopy(receipt)
    value["plan"]["limits"][field] = replacement
    with pytest.raises(ValidationError):
        RECEIPT_VALIDATOR.validate(value)


@pytest.mark.parametrize("category", [
    "process_setup_error",
])
def test_closed_failure_taxonomy_produces_nonpromoting_blocked_receipts(monkeypatch, category):
    def fail(_request):
        raise parent.BoundaryError(category)
    monkeypatch.setattr(parent, "run_double", fail)
    value = parent.build_receipt(INVOCATION)
    assert value["result"] == {"status": "blocked", "outcome": "boundary_error", "error_class": category}
    assert value["execution"]["adapter_runs"] == 0
    assert all(claim is False for claim in value["claims"].values())


def test_invalid_invocation_is_input_invalid_without_spawning_double(monkeypatch):
    monkeypatch.setattr(parent, "run_double", lambda _request: pytest.fail("must not spawn"))
    for invalid in ("invalid", "z" * 32):
        value = parent.build_receipt(invalid)
        assert value["invocation_id"] == "0" * 32
        assert value["result"]["error_class"] == "input_invalid"
        assert value["execution"]["double_spawn_count"] == 0
        forged = copy.deepcopy(value)
        forged["transport"]["request_sha256"] = "0" * 64
        forged["transport"]["stdin_canonical"] = True
        with pytest.raises((ValidationError, ValueError)):
            parent.validate_receipt(forged)


@pytest.mark.parametrize("run,category", [
    (parent.DoubleRun(b"", 0, 0, False, False, False, False, False, False, 0, -9, True, True, True, True), "worker_timeout"),
    (parent.DoubleRun(b"", 32768, 0, False, True, True, True, False, False, 32768, 1, False, True, True, True), "stream_limit_exceeded"),
    (parent.DoubleRun(b"", 0, 0, False, False, True, False, True, False, 0, 1, False, True, False, True), "stream_observation_incomplete"),
    (parent.DoubleRun(b"{}\n", 3, 0, True, True, True, False, False, False, 3, 0, False, True, False, True), "worker_error"),
])
def test_timeout_overflow_incomplete_stream_and_stderr_are_categorical(monkeypatch, run, category):
    monkeypatch.setattr(parent, "run_double", lambda _request: run)
    value = parent.build_receipt(INVOCATION)
    assert value["result"]["error_class"] == category
    assert value["transport"]["stderr_seen"] is run.stderr_seen
    assert value["execution"]["adapter_runs"] == 0


def test_error_class_relations_reject_timeout_overflow_and_incomplete_spoofing(monkeypatch):
    cases = [
        (
            parent.DoubleRun(b"", 0, 0, False, False, False, False, False, False, 0, -9, True, True, True, True),
            lambda value: value["process"].__setitem__("timed_out", False),
        ),
        (
            parent.DoubleRun(b"", 32768, 0, False, True, True, True, False, False, 32768, 1, False, True, True, True),
            lambda value: value["transport"].__setitem__("output_limit_exceeded", False),
        ),
        (
            parent.DoubleRun(b"", 32768, 0, False, True, True, True, False, False, 32768, 1, False, True, True, True),
            lambda value: value["process"].__setitem__("timed_out", True),
        ),
        (
            parent.DoubleRun(b"", 0, 0, False, False, True, False, True, False, 0, 1, False, True, False, True),
            lambda value: (
                value["transport"].__setitem__("stream_read_error_seen", False),
                value["transport"].__setitem__("stdout_observation_complete", True),
                value["transport"].__setitem__("stderr_observation_complete", True),
            ),
        ),
        (
            parent.DoubleRun(b"", 0, 0, False, False, True, False, True, False, 0, 1, False, True, False, True),
            lambda value: value["transport"].__setitem__("output_limit_exceeded", True),
        ),
        (
            parent.DoubleRun(b"{}\n", 3, 0, False, True, True, False, False, False, 3, 0, False, True, False, True),
            lambda value: value["process"].__setitem__("exit_code", 1),
        ),
        (
            parent.DoubleRun(b"{}\n", 3, 0, True, True, True, False, False, False, 3, 1, False, True, False, True),
            lambda value: (
                value["transport"].__setitem__("stderr_seen", False),
                value["process"].__setitem__("exit_code", 0),
            ),
        ),
    ]
    for run, mutation in cases:
        monkeypatch.setattr(parent, "run_double", lambda _request, current=run: current)
        value = parent.build_receipt(INVOCATION)
        mutation(value)
        with pytest.raises((ValidationError, ValueError)):
            parent.validate_receipt(value)


def test_stream_limit_binds_exact_combined_cap_without_choosing_race_winner(monkeypatch):
    run = parent.DoubleRun(
        stdout=b"x" * 12000, stdout_accepted_bytes=12000, stderr_accepted_bytes=20768,
        stderr_seen=True, stdout_complete=True, stderr_complete=True,
        output_limit_exceeded=True, stream_read_error_seen=False, stdin_write_error_seen=False,
        accepted_output_bytes=32768, exit_code=1, timed_out=False,
        containment_established=True, termination_attempted=False, exit_confirmed=True,
    )
    monkeypatch.setattr(parent, "run_double", lambda _request: run)
    value = parent.build_receipt(INVOCATION)
    assert value["result"]["error_class"] == "stream_limit_exceeded"
    assert value["transport"]["accepted_output_bytes"] == value["transport"]["accepted_output_max_bytes"]
    for mutation in (
        lambda item: item["transport"].__setitem__("accepted_output_bytes", 32767),
        lambda item: item["transport"].__setitem__("accepted_stdout_bytes", 11999),
        lambda item: item["process"].__setitem__("containment_established", False),
        lambda item: (
            item["process"].__setitem__("exit_confirmed", False),
            item["process"].__setitem__("exit_code", None),
        ),
    ):
        forged = copy.deepcopy(value)
        mutation(forged)
        with pytest.raises((ValidationError, ValueError)):
            parent.validate_receipt(forged)

    timeout = parent.DoubleRun(
        stdout=b"", stdout_accepted_bytes=0, stderr_accepted_bytes=0,
        stderr_seen=False, stdout_complete=False, stderr_complete=False,
        output_limit_exceeded=False, stream_read_error_seen=False, stdin_write_error_seen=False,
        accepted_output_bytes=0, exit_code=-9, timed_out=True,
        containment_established=True, termination_attempted=True, exit_confirmed=True,
    )
    monkeypatch.setattr(parent, "run_double", lambda _request: timeout)
    forged = parent.build_receipt(INVOCATION)
    forged["transport"]["output_limit_exceeded"] = True
    with pytest.raises(ValidationError):
        RECEIPT_VALIDATOR.validate(forged)
    with pytest.raises((ValidationError, ValueError)):
        parent.validate_receipt(forged)


def test_overflow_race_may_observe_stderr_after_stdout_filled_without_accepting_it(monkeypatch):
    run = parent.DoubleRun(
        stdout=b"x" * 32768, stdout_accepted_bytes=32768, stderr_accepted_bytes=0,
        stderr_seen=True, stdout_complete=True, stderr_complete=True,
        output_limit_exceeded=True, stream_read_error_seen=False, stdin_write_error_seen=False,
        accepted_output_bytes=32768, exit_code=None, timed_out=False,
        containment_established=True, termination_attempted=True, exit_confirmed=False,
    )
    monkeypatch.setattr(parent, "run_double", lambda _request: run)
    value = parent.build_receipt(INVOCATION)
    assert value["transport"]["stderr_seen"] is True
    assert value["transport"]["accepted_stderr_bytes"] == 0
    parent.validate_receipt(value)


def test_normal_protocol_and_worker_exits_cannot_claim_cleanup_termination(monkeypatch):
    runs = [
        parent.DoubleRun(
            stdout=b"not-json\n", stdout_accepted_bytes=9, stderr_accepted_bytes=0,
            stderr_seen=False, stdout_complete=True, stderr_complete=True,
            output_limit_exceeded=False, stream_read_error_seen=False, stdin_write_error_seen=False,
            accepted_output_bytes=9, exit_code=0, timed_out=False,
            containment_established=True, termination_attempted=False, exit_confirmed=True,
        ),
        parent.DoubleRun(
            stdout=b"{}\n", stdout_accepted_bytes=3, stderr_accepted_bytes=1,
            stderr_seen=True, stdout_complete=True, stderr_complete=True,
            output_limit_exceeded=False, stream_read_error_seen=False, stdin_write_error_seen=False,
            accepted_output_bytes=4, exit_code=1, timed_out=False,
            containment_established=True, termination_attempted=False, exit_confirmed=True,
        ),
    ]
    for run in runs:
        monkeypatch.setattr(parent, "run_double", lambda _request, current=run: current)
        value = parent.build_receipt(INVOCATION)
        assert value["result"]["error_class"] in ("protocol_error", "worker_error")
        assert value["process"]["lifecycle_state"] == "contained_exited"
        forged = copy.deepcopy(value)
        forged["process"]["termination_attempted"] = True
        with pytest.raises((ValidationError, ValueError)):
            parent.validate_receipt(forged)


def test_stream_incomplete_lifecycle_allows_only_contained_exit_or_attempted_cleanup(monkeypatch):
    runs = [
        parent.DoubleRun(
            stdout=b"", stdout_accepted_bytes=0, stderr_accepted_bytes=0,
            stderr_seen=False, stdout_complete=False, stderr_complete=True,
            output_limit_exceeded=False, stream_read_error_seen=True, stdin_write_error_seen=False,
            accepted_output_bytes=0, exit_code=1, timed_out=False,
            containment_established=True, termination_attempted=False, exit_confirmed=True,
        ),
        parent.DoubleRun(
            stdout=b"", stdout_accepted_bytes=0, stderr_accepted_bytes=0,
            stderr_seen=False, stdout_complete=True, stderr_complete=True,
            output_limit_exceeded=False, stream_read_error_seen=False, stdin_write_error_seen=True,
            accepted_output_bytes=0, exit_code=None, timed_out=False,
            containment_established=True, termination_attempted=True, exit_confirmed=False,
        ),
    ]
    for run in runs:
        monkeypatch.setattr(parent, "run_double", lambda _request, current=run: current)
        value = parent.build_receipt(INVOCATION)
        assert value["result"]["error_class"] == "stream_observation_incomplete"
        assert value["process"]["containment_established"] is True
        forged = copy.deepcopy(value)
        forged["process"]["containment_established"] = False
        forged["process"]["lifecycle_state"] = (
            "uncontained_exited" if forged["process"]["exit_confirmed"] else "uncontained_exit_unconfirmed"
        )
        with pytest.raises((ValidationError, ValueError)):
            parent.validate_receipt(forged)


def test_process_setup_error_has_zero_pre_reader_transport_for_spawned_and_unspawned(monkeypatch):
    spawned = parent.DoubleRun(
        stdout=b"", stdout_accepted_bytes=0, stderr_accepted_bytes=0,
        stderr_seen=False, stdout_complete=False, stderr_complete=False,
        output_limit_exceeded=False, stream_read_error_seen=False, stdin_write_error_seen=False,
        accepted_output_bytes=0, exit_code=-9, timed_out=False,
        containment_established=False, termination_attempted=True, exit_confirmed=True,
    )
    for run in (None, spawned):
        def fail(_request, current=run):
            raise parent.BoundaryError("process_setup_error", current)
        monkeypatch.setattr(parent, "run_double", fail)
        value = parent.build_receipt(INVOCATION)
        assert value["transport"] == {
            "stdin_canonical": False, "stdout_canonical": False,
            "stdout_observation_complete": False, "stderr_observation_complete": False,
            "stderr_seen": False, "output_limit_exceeded": False,
            "stream_read_error_seen": False, "stdin_write_error_seen": False,
            "accepted_output_bytes": 0, "accepted_output_max_bytes": 32768,
            "accepted_stdout_bytes": 0, "accepted_stderr_bytes": 0,
            "request_sha256": None, "response_sha256": None,
        }
        for key, replacement in (
            ("stdin_canonical", True), ("stdout_observation_complete", True),
            ("stderr_seen", True), ("output_limit_exceeded", True),
            ("stream_read_error_seen", True), ("stdin_write_error_seen", True),
            ("accepted_output_bytes", 1), ("request_sha256", "0" * 64),
        ):
            forged = copy.deepcopy(value)
            forged["transport"][key] = replacement
            with pytest.raises((ValidationError, ValueError)):
                parent.validate_receipt(forged)


def test_windows_job_handle_is_consumed_once_by_terminate_and_normal_close(monkeypatch):
    class Kernel:
        def __init__(self):
            self.terminated = 0
            self.closed = 0

        def TerminateJobObject(self, _handle, _code):
            self.terminated += 1

        def CloseHandle(self, _handle):
            self.closed += 1

    class Process:
        pid = 7

        def __init__(self):
            self.code = None

        def poll(self):
            return self.code

        def kill(self):
            self.code = -9

        def wait(self, timeout):
            assert timeout >= 0
            self.code = -9
            return self.code

    kernel = Kernel()
    process = Process()
    monkeypatch.setattr(parent, "os", type("FakeOS", (), {"name": "nt"})())
    attempted, job = parent._terminate(process, parent.time.monotonic() + 1, (kernel, 123))
    assert attempted is True and job is None
    assert (kernel.terminated, kernel.closed) == (1, 1)
    parent._close_job(job, False)
    assert (kernel.terminated, kernel.closed) == (1, 1)
    parent._close_job((kernel, 456), False)
    assert (kernel.terminated, kernel.closed) == (1, 2)


def test_stdin_write_oserror_records_cleanup_and_never_double_closes(monkeypatch):
    class Input:
        def write(self, _payload):
            raise OSError("broken stdin")

        def flush(self):
            pytest.fail("flush must not follow failed write")

        def close(self):
            pass

    class Output:
        def read(self, _size):
            return b""

        def close(self):
            pass

    class Process:
        pid = 17

        def __init__(self):
            self.stdin, self.stdout, self.stderr = Input(), Output(), Output()
            self.code = None

        def poll(self):
            return self.code

        def kill(self):
            self.code = -9

        def wait(self, timeout):
            assert timeout >= 0
            return self.code

    process = Process()
    monkeypatch.setattr(parent.subprocess, "Popen", lambda *_args, **_kwargs: process)
    fake_os = type("FakeOS", (), {
        "name": "posix", "environ": parent.os.environ,
        "killpg": staticmethod(lambda pid, sig: setattr(process, "code", -int(sig))),
    })()
    monkeypatch.setattr(parent, "os", fake_os)
    monkeypatch.setattr(parent, "signal", type("FakeSignal", (), {"SIGKILL": 9})())
    value = parent.build_receipt(INVOCATION)
    assert value["result"]["error_class"] == "stream_observation_incomplete"
    assert value["transport"]["stdin_write_error_seen"] is True
    assert value["transport"]["stdin_canonical"] is False
    assert value["process"]["termination_attempted"] is True
    assert value["process"]["exit_confirmed"] is True


def test_post_double_manifest_drift_is_categorical_and_nonpromoting(monkeypatch):
    original = parent.build_manifest
    calls = 0

    def drifting(invocation_id):
        nonlocal calls
        calls += 1
        value = original(invocation_id)
        if calls == 2:
            value["bindings"]["mix_lock_sha256"] = "0" * 64
        return value

    monkeypatch.setattr(parent, "build_manifest", drifting)
    value = parent.build_receipt(INVOCATION)
    assert value["result"]["error_class"] == "manifest_drift"
    assert value["execution"]["adapter_runs"] == 0


def test_response_protocol_rejects_wrong_owner_request_digest_and_execution_counts():
    request = parent.build_request(INVOCATION)
    response = adapter.response(request)
    for path, replacement in (
        (("invocation_id",), "f" * 32),
        (("request_sha256",), "0" * 64),
        (("adapter_runs",), 1),
        (("network_requests",), 1),
        (("check_locked_runs",), 1),
        (("observation", "cleanup_attempted"), True),
    ):
        value = copy.deepcopy(response)
        set_path(value, path, replacement)
        with pytest.raises((ValidationError, ValueError)):
            parent._validate_protocol(value)
            parent._validate_response_bindings(value, request)


def test_adapter_source_has_no_process_network_docker_or_dynamic_execution_surface():
    tree = ast.parse(ADAPTER_PATH.read_text(encoding="utf-8"))
    imports = {
        node.names[0].name for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node.names
    }
    assert not imports & {"subprocess", "socket", "urllib", "http", "requests", "docker"}
    calls = {qualified_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    assert not calls & {"eval", "exec", "compile", "__import__", "open", "subprocess.Popen", "subprocess.run"}


def test_parent_has_exactly_one_process_api_and_never_calls_docker_adapter():
    tree = ast.parse(PARENT_PATH.read_text(encoding="utf-8"))
    calls = [qualified_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert calls.count("subprocess.Popen") == 1
    assert "subprocess.run" not in calls and "os.system" not in calls
    popen = next(node for node in ast.walk(tree) if isinstance(node, ast.Call) and qualified_name(node.func) == "subprocess.Popen")
    assert isinstance(popen.args[0], ast.List)
    assert any(qualified_name(item) == "str()" and any(
        isinstance(child, ast.Name) and child.id == "ADAPTER_SOURCE" for child in ast.walk(item)
    ) for item in popen.args[0].elts)


def test_parent_source_contains_both_platform_containment_and_bounded_termination_lifecycle():
    tree = ast.parse(PARENT_PATH.read_text(encoding="utf-8"))
    calls = [qualified_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
    for expected in (
        "kernel32.CreateJobObjectW", "kernel32.SetInformationJobObject",
        "kernel32.AssignProcessToJobObject", "ntdll.NtResumeProcess",
        "kernel32.TerminateJobObject", "os.killpg", "process.wait",
    ):
        assert expected in calls
    source = PARENT_PATH.read_text(encoding="utf-8")
    assert source.index("_windows_kill_job(process)") < source.index("_resume_windows_process(process)")
    assert "subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED" in source
    assert '"start_new_session": True' in source


@pytest.mark.parametrize("mutation", [
    "\nimport socket\n", "\nimport subprocess\n", "\nimport urllib.request\n",
    "\n__import__('docker')\n", "\neval('1')\n", "\nexec('pass')\n",
    "\nopen('escape', 'w')\n", "\nPath('escape').write_text('x')\n",
])
def test_static_policy_fixture_detects_forbidden_imports_and_calls(mutation):
    tree = ast.parse(ADAPTER_PATH.read_text(encoding="utf-8") + mutation)
    names = {qualified_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported & {"socket", "subprocess", "urllib"} or names & {"__import__", "eval", "exec", "open", "Path().write_text"}
