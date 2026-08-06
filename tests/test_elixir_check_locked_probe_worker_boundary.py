from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[3]
PARENT_PATH = ROOT / "tools/detection_validation/scripts/elixir_check_locked_probe_worker_parent.py"
WORKER_PATH = ROOT / "tools/detection_validation/scripts/elixir_check_locked_probe_worker.py"
PROTOCOL_PATH = ROOT / "schemas/elixir_check_locked_probe_worker_protocol_v1.schema.json"
RECEIPT_PATH = ROOT / "schemas/elixir_check_locked_probe_worker_boundary_receipt_v1.schema.json"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


parent = _load_module("loop148_worker_parent", PARENT_PATH)
worker = _load_module("loop148_worker", WORKER_PATH)
PROTOCOL = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
RECEIPT = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
PROTOCOL_VALIDATOR = Draft202012Validator(PROTOCOL)
RECEIPT_VALIDATOR = Draft202012Validator(RECEIPT)
INVOCATION = "0123456789abcdef0123456789abcdef"

# These digests pin a location-independent AST manifest.  They intentionally bind
# executable grammar, declaration/call cardinality and order, critical call
# arguments, and every Store/Del target while ignoring comments and docstrings.
WORKER_STRUCTURAL_MANIFEST_SHA256 = "8737b3ee4ea2b15c0f02b6cb34aec2813b168717a093012657f48c12a44e4d3f"
PARENT_STRUCTURAL_MANIFEST_SHA256 = "bf96e9406cade30c262e556653bfb35939c09289e4557ce8ac4d07b973c0b849"
SENSITIVE_RUNTIME_NAMES = {"__builtins__", "globals", "locals", "vars"}


def _qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent_name = _qualified_name(node.value)
        return f"{parent_name}.{node.attr}" if parent_name else node.attr
    if isinstance(node, ast.Call):
        called = _qualified_name(node.func)
        return f"{called}()" if called else None
    if isinstance(node, ast.Subscript):
        value = _qualified_name(node.value)
        return f"{value}[]" if value else None
    return None


def _without_docstrings(tree):
    tree = copy.deepcopy(tree)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(body, list) and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            del body[0]
    return tree


def _top_level_form(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return f"{type(node).__name__}:{node.name}"
    if isinstance(node, ast.Import):
        return "Import:" + ",".join(
            f"{alias.name} as {alias.asname}" if alias.asname else alias.name
            for alias in node.names
        )
    if isinstance(node, ast.ImportFrom):
        names = ",".join(
            f"{alias.name} as {alias.asname}" if alias.asname else alias.name
            for alias in node.names
        )
        return f"ImportFrom:{node.level}:{node.module}:{names}"
    if (
        isinstance(node, ast.If)
        and ast.dump(node.test, include_attributes=False)
        == "Compare(left=Name(id='__name__', ctx=Load()), ops=[Eq()], comparators=[Constant(value='__main__')])"
    ):
        return "MainGuard"
    return type(node).__name__


def _structural_manifest(source):
    """Return a canonical, location-free inventory plus a full semantic AST digest."""
    tree = _without_docstrings(ast.parse(source))
    declarations = []
    calls = []
    effects = []
    bindings = []

    def visit(node, owner="<module>", path="module"):
        next_owner = owner
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            declarations.append((owner, type(node).__name__, node.name, path))
            next_owner = f"{owner}.{node.name}"
        if isinstance(node, ast.Call):
            calls.append((owner, path, _qualified_name(node.func), ast.dump(node, include_attributes=False)))
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(
            getattr(node, "ctx", None), (ast.Store, ast.Del)
        ):
            effects.append((owner, path, type(node.ctx).__name__, _qualified_name(node)))
        if isinstance(node, ast.ExceptHandler) and node.name:
            bindings.append((owner, path, "ExceptHandler", node.name))
        if isinstance(node, ast.alias):
            bindings.append((owner, path, "Import", node.asname or node.name.split(".")[0]))
        if isinstance(node, ast.arg):
            bindings.append((owner, path, "Argument", node.arg))
        for field, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                visit(value, next_owner, f"{path}.{field}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    if isinstance(child, ast.AST):
                        visit(child, next_owner, f"{path}.{field}[{index}]")

    visit(tree)
    semantic_ast = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return {
        "sha256": hashlib.sha256(semantic_ast.encode("utf-8")).hexdigest(),
        "top_level": tuple(_top_level_form(node) for node in tree.body),
        "declarations": tuple(declarations),
        "calls": tuple(calls),
        "effects": tuple(effects),
        "bindings": tuple(bindings),
    }


def _structural_policy_violations(source, expected_sha256):
    try:
        manifest = _structural_manifest(source)
    except SyntaxError:
        return [("syntax_error", None)]
    violations = []
    if manifest["sha256"] != expected_sha256:
        violations.append(("structural_manifest_mismatch", manifest["sha256"]))
    declaration_keys = [(owner, kind, name) for owner, kind, name, _path in manifest["declarations"]]
    if len(declaration_keys) != len(set(declaration_keys)):
        violations.append(("duplicate_declaration", None))
    for owner, path, called, _shape in manifest["calls"]:
        if called is None or called in SENSITIVE_RUNTIME_NAMES:
            violations.append(("indirect_or_namespace_call", (owner, path, called)))
    return violations


def _worker_policy_violations(source):
    return _structural_policy_violations(source, WORKER_STRUCTURAL_MANIFEST_SHA256)


def _parent_effect_policy_violations(source):
    return _structural_policy_violations(source, PARENT_STRUCTURAL_MANIFEST_SHA256)


def _function_node(source, name):
    tree = ast.parse(source)
    return next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)


def _calls(function):
    return [
        (_qualified_name(node.func), node.lineno, node)
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
    ]


def _parent_lifecycle_policy_violations(source):
    violations = []
    try:
        run_worker = _function_node(source, "_run_worker")
        terminate_tree = _function_node(source, "_terminate_tree")
    except (StopIteration, SyntaxError):
        return ["required_function_missing"]
    calls = _calls(run_worker)
    by_name = {}
    for name, line, node in calls:
        by_name.setdefault(name, []).append((line, node))
    deadline_lines = [
        node.lineno for node in ast.walk(run_worker)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "total_deadline" for target in node.targets)
    ]
    popen = by_name.get("subprocess.Popen", [])
    if len(deadline_lines) != 1 or len(popen) != 1 or deadline_lines[0] >= popen[0][0]:
        violations.append("deadline_must_precede_single_spawn")
    job_calls = by_name.get("_windows_kill_job", [])
    resume_calls = by_name.get("_resume_windows_process", [])
    if len(job_calls) != 1 or len(resume_calls) != 1 or job_calls[0][0] >= resume_calls[0][0]:
        violations.append("job_must_precede_resume")
    joins = by_name.get("thread.join", [])
    overflows = by_name.get("overflow.is_set", [])
    reader_errors = by_name.get("reader_error.is_set", [])
    writer_errors = by_name.get("writer_error.is_set", [])
    join_line = min((line for line, _node in joins), default=10**9)
    post_overflow = min((line for line, _node in overflows if line > join_line), default=10**9)
    post_reader_error = min((line for line, _node in reader_errors if line > join_line), default=10**9)
    post_writer_error = min((line for line, _node in writer_errors if line > join_line), default=10**9)
    if (
        join_line == 10**9 or post_overflow == 10**9
        or post_reader_error == 10**9 or post_writer_error == 10**9
        or post_overflow >= post_reader_error or post_overflow >= post_writer_error
    ):
        violations.append("post_drain_error_order_invalid")
    start_session = any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name) and target.value.id == "creation"
            and isinstance(target.slice, ast.Constant) and target.slice.value == "start_new_session"
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant) and node.value.value is True
        for node in ast.walk(run_worker)
    )
    if not start_session:
        violations.append("posix_session_missing")
    if not any(name == "os.killpg" for name, _line, _node in _calls(terminate_tree)):
        violations.append("posix_tree_kill_missing")
    combined_budget = any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub)
        and isinstance(node.left, ast.Name) and node.left.id == "COMBINED_OUTPUT_MAX_BYTES"
        and isinstance(node.right, ast.Name) and node.right.id == "used"
        for node in ast.walk(run_worker)
    )
    if not combined_budget:
        violations.append("combined_output_budget_missing")
    return violations


def _set_path(value, path, replacement):
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement


@pytest.fixture(scope="module")
def observed_receipt():
    return parent.build_receipt(INVOCATION)


def test_both_schemas_are_valid_draft_202012_contracts():
    Draft202012Validator.check_schema(PROTOCOL)
    Draft202012Validator.check_schema(RECEIPT)


def test_workspace_base_head_is_exact_and_explicitly_not_file_provenance(observed_receipt):
    assert observed_receipt["workspace_base_head"] == parent.WORKSPACE_BASE_HEAD
    assert "source_head" not in observed_receipt
    description = RECEIPT["properties"]["workspace_base_head"]["description"].lower()
    assert "not file provenance" in description


def test_manifest_is_canonical_hash_bound_and_hard_false():
    manifest = parent.build_manifest()
    PROTOCOL_VALIDATOR.validate(manifest)
    request = parent.build_request(manifest, INVOCATION)
    PROTOCOL_VALIDATOR.validate(request)
    assert request["manifest_sha256"] == parent.digest_value(manifest)
    assert all(value is False for value in manifest["claims"].values())
    assert manifest["adapter_profile"] == "inert_contract_v1"
    assert manifest["operation"] == "inert_boundary_self_test"
    assert manifest["workspace_base_head"] == parent.WORKSPACE_BASE_HEAD
    assert "source_head" not in manifest


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b'{"a":1}',
        b'{"a":1, "b":2}\n',
        b'{"a":1,"a":2}\n',
        b'{"a":1}\n{"b":2}\n',
        b"\xef\xbb\xbf{}\n",
        b"\xff\n",
    ],
)
def test_parent_canonical_parser_rejects_empty_noncanonical_duplicate_and_trailing(raw):
    with pytest.raises(parent.BoundaryError, match="protocol_error"):
        parent.parse_canonical_document(raw, limit=1024)


def test_parent_executes_only_inert_worker_and_emits_valid_nonpromoting_receipt():
    receipt = parent.build_receipt(INVOCATION)
    RECEIPT_VALIDATOR.validate(receipt)
    parent.validate_receipt(receipt)
    assert receipt["result"] == {
        "status": "observed", "outcome": "inert_contract_observed", "error_class": None,
    }
    assert receipt["evidence_boundary"] == {
        "adapter_authenticity_verified": False,
        "manifest_canonical": True,
        "parent_is_sole_receipt_emitter": True,
        "process_separation_observed": True,
        "real_cleanup_verified": False,
        "same_user_replacement_resistance_proven": False,
        "worker_trust": "untrusted_categorical_producer",
    }
    assert receipt["process"]["worker_spawn_count"] == 1
    assert receipt["process"]["worker_exit_confirmed"] is True
    assert receipt["process"]["process_tree_containment_established"] is True
    assert receipt["process"]["process_tree_termination_attempted"] is True
    assert receipt["process"]["process_tree_exit_independently_verified"] is False
    assert all(value is False for value in receipt["claims"].values())


def test_worker_direct_transport_is_exactly_one_canonical_response_and_empty_stderr():
    request = parent.build_request(parent.build_manifest(), INVOCATION)
    body = parent.canonical_bytes(request)
    completed = subprocess.run(
        parent._command(), input=body + b"\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=ROOT, env=parent._environment(), timeout=4, check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == b""
    response = parent.parse_canonical_document(completed.stdout, limit=parent.RESPONSE_MAX_BYTES)
    PROTOCOL_VALIDATOR.validate(response)
    parent._validate_response(response, request)
    assert completed.stdout == parent.canonical_bytes(response) + b"\n"
    assert response["operation_counts"] == {
        "adapter_runs": 0, "inert_checks": 1, "network_requests": 0,
    }


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema":"tamandua.elixir_check_locked.worker_request/v1", "schema":"duplicate"}\n',
        b"{} \n",
        b"{}\n{}\n",
        b"\xef\xbb\xbf{}\n",
    ],
)
def test_worker_rejects_malformed_input_without_output_or_private_diagnostics(payload):
    completed = subprocess.run(
        parent._command(), input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=ROOT, env=parent._environment(), timeout=4, check=False,
    )
    assert completed.returncode == 2
    assert completed.stdout == completed.stderr == b""


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value["claims"].__setitem__("product_ready", True),
        lambda value: value["claims"].__setitem__("external_claim_allowed", True),
        lambda value: value["claims"].__setitem__("verimatrix_parity", True),
        lambda value: value.__setitem__("adapter_profile", "real_adapter"),
        lambda value: value["limits"].__setitem__("total_timeout_ms", 6000),
        lambda value: value.__setitem__("workspace_base_head", "0" * 40),
        lambda value: value.__setitem__("extra", "drift"),
    ],
)
def test_protocol_schema_rejects_claim_profile_limit_and_shape_promotion(mutator):
    value = copy.deepcopy(parent.build_manifest())
    mutator(value)
    with pytest.raises(ValidationError):
        PROTOCOL_VALIDATOR.validate(value)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value["claims"].__setitem__("production_ready", True),
        lambda value: value["evidence_boundary"].__setitem__("real_cleanup_verified", True),
        lambda value: value["evidence_boundary"].__setitem__("adapter_authenticity_verified", True),
        lambda value: value["process"].__setitem__("process_tree_exit_independently_verified", True),
        lambda value: value.__setitem__("workspace_base_head", "0" * 40),
        lambda value: value.__setitem__("raw_output", "private"),
    ],
)
def test_receipt_schema_rejects_promoted_or_raw_evidence(observed_receipt, mutator):
    value = copy.deepcopy(observed_receipt)
    mutator(value)
    with pytest.raises(ValidationError):
        RECEIPT_VALIDATOR.validate(value)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("result", "status"), "blocked"),
        (("result", "outcome"), "boundary_error"),
        (("result", "error_class"), "worker_error"),
        (("evidence_boundary", "process_separation_observed"), False),
        (("process", "lifecycle_state"), "not_spawned"),
        (("process", "worker_spawn_count"), 0),
        (("process", "worker_exit_confirmed"), False),
        (("process", "process_tree_containment_established"), False),
        (("process", "process_tree_termination_attempted"), False),
        (("process", "pre_post_drift_detected"), True),
        (("transport", "stdout_canonical"), False),
        (("transport", "stderr_empty"), False),
        (("transport", "accepted_output_bytes"), 0),
        (("transport", "stdout_observation_complete"), False),
        (("transport", "stderr_observation_complete"), False),
        (("transport", "stderr_seen"), True),
        (("transport", "output_limit_exceeded"), True),
        (("transport", "stream_read_error_seen"), True),
        (("transport", "response_sha256"), None),
    ],
)
def test_observed_receipt_relational_mutations_fail_schema_and_semantic_validator(
    observed_receipt, path, replacement,
):
    receipt = copy.deepcopy(observed_receipt)
    _set_path(receipt, path, replacement)
    with pytest.raises(ValidationError):
        RECEIPT_VALIDATOR.validate(receipt)
    with pytest.raises(parent.BoundaryError, match="protocol_error"):
        parent._validate_receipt_state_machine(receipt)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("result", "status"), "observed"),
        (("result", "outcome"), "inert_contract_observed"),
        (("result", "error_class"), None),
        (("evidence_boundary", "process_separation_observed"), True),
        (("process", "lifecycle_state"), "spawned_contained_exited"),
        (("process", "worker_exit_confirmed"), True),
        (("process", "process_tree_containment_established"), True),
        (("process", "process_tree_termination_attempted"), True),
        (("process", "pre_post_drift_detected"), True),
        (("transport", "stdout_canonical"), True),
        (("transport", "stderr_empty"), True),
        (("transport", "accepted_output_bytes"), 1),
        (("transport", "stdout_observation_complete"), True),
        (("transport", "stderr_observation_complete"), True),
        (("transport", "stderr_seen"), True),
        (("transport", "output_limit_exceeded"), True),
        (("transport", "stream_read_error_seen"), True),
        (("transport", "response_sha256"), "0" * 64),
    ],
)
def test_not_spawned_blocked_receipt_relational_mutations_fail_schema_and_validator(
    monkeypatch, path, replacement,
):
    monkeypatch.setattr(
        parent, "_run_worker", lambda _payload: (_ for _ in ()).throw(
            parent.BoundaryError("process_setup_error")
        ),
    )
    receipt = parent.build_receipt(INVOCATION)
    _set_path(receipt, path, replacement)
    with pytest.raises(ValidationError):
        RECEIPT_VALIDATOR.validate(receipt)
    with pytest.raises(parent.BoundaryError, match="protocol_error"):
        parent._validate_receipt_state_machine(receipt)


def test_response_replay_and_binding_swaps_are_rejected():
    request = parent.build_request(parent.build_manifest(), INVOCATION)
    response = worker._response(request, parent.canonical_bytes(request))
    for field in ("invocation_id", "manifest_sha256", "request_sha256", "worker_source_sha256"):
        candidate = copy.deepcopy(response)
        candidate[field] = "f" * (32 if field == "invocation_id" else 64)
        with pytest.raises(parent.BoundaryError, match="protocol_error"):
            parent._validate_response(candidate, request)


def test_worker_error_is_categorical_and_does_not_persist_stderr(monkeypatch):
    secret = b"token=sk_private_material"
    monkeypatch.setattr(parent, "_run_worker", lambda _payload: parent.WorkerRun(
        returncode=3, stdout=b"", stderr=secret,
        containment_established=True, termination_attempted=True,
        worker_exit_confirmed=True, stderr_seen=True,
        stdout_observation_complete=True, stderr_observation_complete=True,
        output_limit_exceeded=False, stream_read_error_seen=False,
    ))
    receipt = parent.build_receipt(INVOCATION)
    serialized = parent.canonical_bytes(receipt)
    assert secret not in serialized
    assert receipt["result"] == {
        "status": "blocked", "outcome": "boundary_error", "error_class": "worker_error",
    }
    assert receipt["transport"]["stderr_empty"] is False
    assert receipt["claims"] == parent.FALSE_CLAIMS


@pytest.mark.parametrize("category", ["worker_timeout", "stream_limit_exceeded", "process_setup_error"])
def test_supervisor_failures_remain_categorical_and_nonpromoting(monkeypatch, category):
    def fail(_payload):
        if category == "process_setup_error":
            raise parent.BoundaryError(category)
        raise parent.BoundaryError(
            category, spawn_count=1, containment_established=True,
            termination_attempted=True, worker_exit_confirmed=False,
            stdout_observation_complete=False,
            stderr_observation_complete=False,
            output_limit_exceeded=category == "stream_limit_exceeded",
        )

    monkeypatch.setattr(parent, "_run_worker", fail)
    receipt = parent.build_receipt(INVOCATION)
    assert receipt["result"]["error_class"] == category
    assert receipt["result"]["status"] == "blocked"
    assert receipt["evidence_boundary"]["process_separation_observed"] is False
    assert all(value is False for value in receipt["claims"].values())


def test_post_spawn_failure_preserves_honest_lifecycle_observations(monkeypatch):
    def fail(_payload):
        raise parent.BoundaryError(
            "worker_timeout", spawn_count=1, containment_established=True,
            termination_attempted=True, worker_exit_confirmed=True,
            accepted_output_bytes=17, stderr_seen=False,
            stdout_observation_complete=True, stderr_observation_complete=True,
        )

    monkeypatch.setattr(parent, "_run_worker", fail)
    receipt = parent.build_receipt(INVOCATION)
    assert receipt["process"]["worker_spawn_count"] == 1
    assert receipt["process"]["process_tree_containment_established"] is True
    assert receipt["process"]["process_tree_termination_attempted"] is True
    assert receipt["process"]["worker_exit_confirmed"] is True
    assert receipt["process"]["process_tree_exit_independently_verified"] is False
    assert receipt["transport"]["accepted_output_bytes"] == 17
    assert receipt["transport"]["stderr_empty"] is True


def test_overflow_preserves_stderr_seen_even_when_no_stderr_byte_was_accepted(monkeypatch):
    def fail(_payload):
        raise parent.BoundaryError(
            "stream_limit_exceeded", spawn_count=1,
            containment_established=True, termination_attempted=True,
            worker_exit_confirmed=True,
            accepted_output_bytes=parent.COMBINED_OUTPUT_MAX_BYTES,
            stderr_seen=True, stdout_observation_complete=True,
            stderr_observation_complete=True, output_limit_exceeded=True,
        )

    monkeypatch.setattr(parent, "_run_worker", fail)
    receipt = parent.build_receipt(INVOCATION)
    RECEIPT_VALIDATOR.validate(receipt)
    parent._validate_receipt_state_machine(receipt)
    assert receipt["transport"]["accepted_output_bytes"] == parent.COMBINED_OUTPUT_MAX_BYTES
    assert receipt["transport"]["stderr_seen"] is True
    assert receipt["transport"]["stderr_observation_complete"] is True
    assert receipt["transport"]["stderr_empty"] is False
    assert receipt["transport"]["output_limit_exceeded"] is True


def test_stream_read_error_and_incomplete_observation_cannot_claim_stderr_empty(monkeypatch):
    def fail(_payload):
        raise parent.BoundaryError(
            "worker_error", spawn_count=1, containment_established=True,
            termination_attempted=True, worker_exit_confirmed=True,
            stderr_seen=False, stdout_observation_complete=True,
            stderr_observation_complete=False, stream_read_error_seen=True,
        )

    monkeypatch.setattr(parent, "_run_worker", fail)
    receipt = parent.build_receipt(INVOCATION)
    RECEIPT_VALIDATOR.validate(receipt)
    parent._validate_receipt_state_machine(receipt)
    assert receipt["transport"]["stream_read_error_seen"] is True
    assert receipt["transport"]["stderr_observation_complete"] is False
    assert receipt["transport"]["stderr_seen"] is False
    assert receipt["transport"]["stderr_empty"] is False

    forged = copy.deepcopy(receipt)
    forged["transport"]["stderr_empty"] = True
    with pytest.raises(ValidationError):
        RECEIPT_VALIDATOR.validate(forged)
    with pytest.raises(parent.BoundaryError, match="protocol_error"):
        parent._validate_receipt_state_machine(forged)


def test_incomplete_stderr_reader_without_read_exception_remains_unknown_not_empty(monkeypatch):
    def fail(_payload):
        raise parent.BoundaryError(
            "worker_timeout", spawn_count=1, containment_established=True,
            termination_attempted=True, worker_exit_confirmed=False,
            stderr_seen=False, stdout_observation_complete=True,
            stderr_observation_complete=False, stream_read_error_seen=False,
        )

    monkeypatch.setattr(parent, "_run_worker", fail)
    receipt = parent.build_receipt(INVOCATION)
    RECEIPT_VALIDATOR.validate(receipt)
    parent._validate_receipt_state_machine(receipt)
    assert receipt["transport"]["stdout_observation_complete"] is True
    assert receipt["transport"]["stderr_observation_complete"] is False
    assert receipt["transport"]["stderr_seen"] is False
    assert receipt["transport"]["stderr_empty"] is False
    assert receipt["transport"]["stream_read_error_seen"] is False


def test_pre_post_worker_source_drift_fails_closed(monkeypatch):
    original = parent._hash_file
    worker_hash_calls = 0

    def hash_with_drift(path):
        nonlocal worker_hash_calls
        value = original(path)
        if Path(path) == parent.WORKER_SOURCE:
            worker_hash_calls += 1
            if worker_hash_calls > 1:
                return "0" * 64
        return value

    monkeypatch.setattr(parent, "_run_worker", lambda _payload: (_ for _ in ()).throw(parent.BoundaryError("worker_error")))
    monkeypatch.setattr(parent, "_hash_file", hash_with_drift)
    receipt = parent.build_receipt(INVOCATION)
    assert receipt["process"]["pre_post_drift_detected"] is True
    assert receipt["result"]["error_class"] == "manifest_drift"
    assert receipt["transport"]["response_sha256"] is None


@pytest.mark.parametrize(
    "binding",
    [
        "argv_template_sha256",
        "environment_policy_sha256",
        "interpreter_executable_sha256",
        "interpreter_version_sha256",
        "parent_source_sha256",
        "protocol_schema_sha256",
        "receipt_schema_sha256",
        "worker_source_sha256",
    ],
)
def test_every_recomputable_manifest_binding_is_checked_after_worker(monkeypatch, binding):
    original = parent._binding_snapshot
    calls = 0

    def snapshot_with_drift():
        nonlocal calls
        calls += 1
        value = original()
        if calls > 1:
            value[binding] = "0" * 64
        return value

    monkeypatch.setattr(parent, "_run_worker", lambda _payload: (_ for _ in ()).throw(parent.BoundaryError("worker_error")))
    monkeypatch.setattr(parent, "_binding_snapshot", snapshot_with_drift)
    receipt = parent.build_receipt(INVOCATION)
    assert receipt["process"]["pre_post_drift_detected"] is True
    assert receipt["result"]["error_class"] == "manifest_drift"
    assert receipt["transport"]["response_sha256"] is None


def test_worker_executable_ast_policy_is_closed_and_has_no_receipt_emitter():
    source = WORKER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    manifest = _structural_manifest(source)
    assert _worker_policy_violations(source) == []
    assert manifest["sha256"] == WORKER_STRUCTURAL_MANIFEST_SHA256
    assert tuple(len(manifest[name]) for name in (
        "top_level", "declarations", "calls", "effects", "bindings",
    )) == (24, 11, 72, 27, 20)
    assert manifest["top_level"][-1] == "MainGuard"
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "build_receipt" not in function_names and "validate_receipt" not in function_names


@pytest.mark.parametrize("executable_mutation", [
    "import socket as harmless\n",
    "from subprocess import Popen as harmless\n",
    "import importlib as loader_module\nloader_module.import_module('socket')\n",
    "loader = __import__\nloader('socket')\n",
    "from importlib import import_module as load\nload('socket')\n",
    "from tools.detection_validation.scripts import elixir_check_locked_probe_worker_parent as authority\n",
    "loader = vars(__builtins__)['__import__']\nloader('socket')\n",
    "globals()['__builtins__']['open']('escape', 'w')\n",
    "Path('escape').write_text('owned')\n",
    "Path('escape').open('w')\n",
    "__builtins__.__dict__['__import__']('socket')\n",
    "Path.read_text = lambda *_args: 'forged'\n",
])
def test_worker_ast_policy_rejects_reflection_subscript_loaders_writes_and_aliases(executable_mutation):
    source = WORKER_PATH.read_text(encoding="utf-8") + "\n" + executable_mutation
    assert _worker_policy_violations(source)


def test_worker_ast_policy_ignores_inert_strings_and_comments():
    source = WORKER_PATH.read_text(encoding="utf-8")
    inert = source.replace("Inert, untrusted child", "Inert text: subprocess.Popen and __import__")
    assert _worker_policy_violations(inert + "\n# __import__('socket')\n") == []


def test_parent_executable_ast_orders_deadline_containment_resume_and_post_drain_checks():
    source = PARENT_PATH.read_text(encoding="utf-8")
    manifest = _structural_manifest(source)
    assert _parent_effect_policy_violations(source) == []
    assert manifest["sha256"] == PARENT_STRUCTURAL_MANIFEST_SHA256
    assert tuple(len(manifest[name]) for name in (
        "top_level", "declarations", "calls", "effects", "bindings",
    )) == (62, 33, 253, 175, 64)
    assert manifest["top_level"][-1] == "MainGuard"
    assert _parent_lifecycle_policy_violations(source) == []


@pytest.mark.parametrize("executable_mutation", [
    "\nsubprocess.run(['alternate'])\n",
    "\nos.system('alternate')\n",
    "\nPath('escape').write_bytes(b'owned')\n",
    "\nopen('escape', 'w')\n",
    "\ngetattr(subprocess, 'Popen')(['alternate'])\n",
    "\nrunner = subprocess.Popen\nrunner(['alternate'])\n",
    "\nvars(__builtins__)['eval']('1+1')\n",
    "\nsubprocess.Popen = lambda *_args: None\n",
])
def test_parent_effect_policy_rejects_alternate_process_writes_reflection_and_aliases(executable_mutation):
    source = PARENT_PATH.read_text(encoding="utf-8") + executable_mutation
    assert _parent_effect_policy_violations(source)


def test_parent_ast_policy_rejects_executable_job_resume_reordering():
    tree = ast.parse(PARENT_PATH.read_text(encoding="utf-8"))
    run_worker = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_run_worker")
    calls = {name: node for name, _line, node in _calls(run_worker)}
    calls["_windows_kill_job"].func, calls["_resume_windows_process"].func = (
        calls["_resume_windows_process"].func, calls["_windows_kill_job"].func,
    )
    assert "job_must_precede_resume" in _parent_lifecycle_policy_violations(ast.unparse(tree))


def test_parent_ast_lifecycle_policy_ignores_inert_ordering_strings():
    source = PARENT_PATH.read_text(encoding="utf-8")
    inert = source.replace(
        "Parent-only authority", "Parent-only authority: Popen before deadline is inert text",
    )
    assert _parent_effect_policy_violations(inert + "\n# resume before Job Object\n") == []
    assert _parent_lifecycle_policy_violations(inert + "\n# resume before Job Object\n") == []


@pytest.mark.parametrize("mutation", [
    "\ndef _run_worker(payload):\n    return payload\n",
    "\ndef outer():\n    def unexpected_nested():\n        return None\n    return unexpected_nested()\n",
    "\nclass WorkerRun:\n    pass\n",
])
def test_structural_manifest_rejects_duplicate_and_unexpected_nested_declarations(mutation):
    source = PARENT_PATH.read_text(encoding="utf-8") + mutation
    assert _parent_effect_policy_violations(source)


@pytest.mark.parametrize("mutation, expected_context", [
    ("\nfor subprocess in ():\n    pass\n", "Store"),
    ("\ndel subprocess\n", "Del"),
    ("\n[x for subprocess in () for x in ()]\n", "Store"),
    ("\nwith open('x') as subprocess:\n    pass\n", "Store"),
    ("\nif (subprocess := None) is None:\n    pass\n", "Store"),
])
def test_structural_manifest_covers_all_store_and_del_target_families(mutation, expected_context):
    source = PARENT_PATH.read_text(encoding="utf-8") + mutation
    manifest = _structural_manifest(source)
    assert any(effect[2] == expected_context for effect in manifest["effects"])
    assert _parent_effect_policy_violations(source)


def test_structural_manifest_rejects_extra_read_bytes_plus_stdout_write_even_if_calls_are_known():
    source = PARENT_PATH.read_text(encoding="utf-8").replace(
        "def _hash_file(path: Path) -> str:\n",
        "def _hash_file(path: Path) -> str:\n"
        "    path.read_bytes()\n"
        "    sys.stdout.buffer.write(b'known-call-evasion')\n",
        1,
    )
    calls = _structural_manifest(source)["calls"]
    assert sum(call[2] == "path.read_bytes" for call in calls) == 2
    assert sum(call[2] == "sys.stdout.buffer.write" for call in calls) == 2
    assert sum(call[0] == "<module>._hash_file" for call in calls if call[2] == "path.read_bytes") == 2
    assert _parent_effect_policy_violations(source)


def test_structural_manifest_rejects_second_top_level_popen_with_exact_cardinality_and_owner():
    source = PARENT_PATH.read_text(encoding="utf-8") + "\nsubprocess.Popen(_command())\n"
    popen_calls = [call for call in _structural_manifest(source)["calls"] if call[2] == "subprocess.Popen"]
    assert len(popen_calls) == 2
    assert {call[0] for call in popen_calls} == {"<module>", "<module>._run_worker"}
    assert _parent_effect_policy_violations(source)


def test_environment_is_a_closed_noncredential_allowlist(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "private")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "private")
    monkeypatch.setenv("HTTPS_PROXY", "private")
    environment = parent._environment()
    assert set(environment).issubset({"PYTHONIOENCODING", "PYTHONUTF8", "SystemRoot", "WINDIR"})
    assert "PYTHONPATH" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "HTTPS_PROXY" not in environment
