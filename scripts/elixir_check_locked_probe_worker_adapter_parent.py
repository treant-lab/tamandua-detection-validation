#!/usr/bin/env python3
"""Parent authority for the Loop150 source-only container adapter contract."""

from __future__ import annotations

import hashlib
import json
import os
import ctypes
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from ctypes import wintypes

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
ADAPTER_SOURCE = Path(__file__).with_name("elixir_check_locked_probe_worker_adapter.py").resolve()
PROTOCOL_SCHEMA = ROOT / "schemas/elixir_check_locked_probe_worker_adapter_protocol_v1.schema.json"
RECEIPT_SCHEMA = ROOT / "schemas/elixir_check_locked_probe_worker_adapter_boundary_receipt_v1.schema.json"
MIX_EXS = ROOT / "apps/tamandua_server/mix.exs"
MIX_LOCK = ROOT / "apps/tamandua_server/mix.lock"
RUNNER_SOURCE = ROOT / "tools/detection_validation/scripts/build_elixir_runtime_validation_runner.py"
RUNNER_DOCKERFILE = ROOT / "apps/tamandua_server/Dockerfile.elixir-runtime-validation-runner"
WORKSPACE_BASE_HEAD = "ce97ccd64a686e91fbf6f613e3face7cb17843d2"
IMAGE_ID = "sha256:f31484716c92e442efbe163ff5df3456ac6dd3e0c96a2c3d1cc4fd295661e5a0"
DOCKER_PATH = "C:/Program Files/Docker/Docker/resources/bin/docker.exe"
UNOBSERVED_SHA256 = "0" * 64
TOTAL_TIMEOUT_MS = 5000
CLEANUP_RESERVE_MS = 1500
COMBINED_OUTPUT_MAX_BYTES = 32768
INVOCATION_PATTERN = re.compile(r"^[a-f0-9]{32}$")
RESOURCE_ID_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_INVOCATION_OMITTED = object()
_CREATE_SUSPENDED = 0x00000004
FALSE_CLAIMS = {
    "adapter_executed": False, "check_locked_executed": False,
    "external_claim_allowed": False, "product_ready": False,
    "production_ready": False, "real_cleanup_verified": False,
    "release_ready": False, "verimatrix_parity": False,
}


class BoundaryError(RuntimeError):
    def __init__(self, category: str, run: "DoubleRun | None" = None):
        super().__init__(category)
        self.category = category
        self.run = run


@dataclass(frozen=True)
class DoubleRun:
    stdout: bytes
    stdout_accepted_bytes: int
    stderr_accepted_bytes: int
    stderr_seen: bool
    stdout_complete: bool
    stderr_complete: bool
    output_limit_exceeded: bool
    stream_read_error_seen: bool
    stdin_write_error_seen: bool
    accepted_output_bytes: int
    exit_code: int | None
    timed_out: bool
    containment_established: bool
    termination_attempted: bool
    exit_confirmed: bool


class _JobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
    )]


class _JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimitInformation), ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError("bound_file_invalid")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def config_binding() -> tuple[str, int]:
    files = sorted((ROOT / "apps/tamandua_server/config").glob("*.exs"))
    if not files or any(not path.is_file() or path.is_symlink() for path in files):
        raise ValueError("config_invalid")
    manifest = [(path.name, hash_file(path)) for path in files]
    return digest(manifest), len(manifest)


def environment() -> dict[str, str]:
    value = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    for name in ("SystemRoot", "WINDIR"):
        if os.environ.get(name):
            value[name] = os.environ[name]
    return value


def input_mounts(bindings: dict[str, object]) -> list[dict[str, object]]:
    config_files = sorted((ROOT / "apps/tamandua_server/config").glob("*.exs"))
    bundle = digest({
        "mix_exs": bindings["mix_exs_sha256"], "mix_lock": bindings["mix_lock_sha256"],
        "config": bindings["config_sha256"], "runner": bindings["runner_source_sha256"],
        "dockerfile": bindings["runner_dockerfile_sha256"],
    })
    specs = [
        (MIX_EXS, f"/tamandua-inputs/{bundle}/server/mix.exs"),
        (MIX_LOCK, f"/tamandua-inputs/{bundle}/server/mix.lock"),
        (RUNNER_SOURCE, f"/tamandua-inputs/{bundle}/contract/build_runner.py"),
        (RUNNER_DOCKERFILE, f"/tamandua-inputs/{bundle}/contract/Dockerfile"),
        *[(path, f"/tamandua-inputs/{bundle}/server/config/{path.name}") for path in config_files],
    ]
    return [
        {"source": str(path.resolve()), "source_sha256": hash_file(path), "destination": destination, "read_only": True}
        for path, destination in specs
    ]


def planned_argv(resource_name: str, labels: dict[str, str], mounts: list[dict[str, object]]) -> dict[str, list[str]]:
    label_args = [item for pair in sorted(labels.items()) for item in ("--label", f"{pair[0]}={pair[1]}")]
    mount_args = [
        item for mount in mounts
        for item in ("--mount", f"type=bind,src={mount['source']},dst={mount['destination']},readonly")
    ]
    workdir = str(mounts[0]["destination"]).rsplit("/", 1)[0]
    return {
        "pre_absence": [DOCKER_PATH, "container", "inspect", resource_name],
        "inventory_before": [DOCKER_PATH, "image", "ls", "--no-trunc", "--quiet"],
        "inspect_owned": [DOCKER_PATH, "container", "inspect", "--format", "{{json .}}", resource_name],
        "run": [
            DOCKER_PATH, "run", "--name", resource_name, "--pull", "never",
            "--network", "none", "--read-only", "--workdir", workdir,
            *mount_args, *label_args, IMAGE_ID, "mix", "deps.get", "--only", "test", "--check-locked",
        ],
        "cleanup_exact_id": [DOCKER_PATH, "container", "rm", "--force", "${verified_exact_resource_id}"],
        "final_absence": [DOCKER_PATH, "container", "inspect", resource_name],
        "inventory_after": [DOCKER_PATH, "image", "ls", "--no-trunc", "--quiet"],
    }


def build_manifest(invocation_id: str) -> dict[str, object]:
    if type(invocation_id) is not str or not INVOCATION_PATTERN.fullmatch(invocation_id):
        raise ValueError("invocation_invalid")
    config_sha256, config_count = config_binding()
    resource_name = f"tamandua-check-locked-loop150-{invocation_id}"
    bindings = {
        "parent_source_sha256": hash_file(Path(__file__).resolve()),
        "double_source_sha256": hash_file(ADAPTER_SOURCE),
        "protocol_schema_sha256": hash_file(PROTOCOL_SCHEMA),
        "receipt_schema_sha256": hash_file(RECEIPT_SCHEMA),
        "interpreter_executable_sha256": hash_file(Path(sys.executable).resolve()),
        "interpreter_version_sha256": hashlib.sha256(sys.version.encode()).hexdigest(),
        "mix_exs_sha256": hash_file(MIX_EXS), "mix_lock_sha256": hash_file(MIX_LOCK),
        "config_sha256": config_sha256, "config_file_count": config_count,
        "runner_source_sha256": hash_file(RUNNER_SOURCE),
        "runner_dockerfile_sha256": hash_file(RUNNER_DOCKERFILE),
    }
    labels = {
        "io.tamandua.owner": invocation_id,
        "io.tamandua.operation": "check-locked-source-contract",
        "io.tamandua.source": WORKSPACE_BASE_HEAD,
        "io.tamandua.input.mix-exs-sha256": str(bindings["mix_exs_sha256"]),
        "io.tamandua.input.mix-lock-sha256": str(bindings["mix_lock_sha256"]),
        "io.tamandua.input.config-sha256": str(bindings["config_sha256"]),
        "io.tamandua.input.runner-sha256": str(bindings["runner_source_sha256"]),
        "io.tamandua.input.dockerfile-sha256": str(bindings["runner_dockerfile_sha256"]),
    }
    mounts = input_mounts(bindings)
    argv = planned_argv(resource_name, labels, mounts)
    manifest = {
        "schema": "tamandua.elixir_check_locked.worker_adapter_manifest/v1",
        "profile": "source_only_container_adapter_contract_v1",
        "operation": "source_only_container_adapter_contract",
        "workspace_base_head": WORKSPACE_BASE_HEAD,
        "invocation": {"id": invocation_id, "resource_name": resource_name, "labels": labels},
        "bindings": bindings,
        "adapter": {
            "executable_path": DOCKER_PATH, "executable_sha256": UNOBSERVED_SHA256,
            "version_sha256": UNOBSERVED_SHA256, "context_sha256": UNOBSERVED_SHA256,
            "identity_observed": False, "image_id": IMAGE_ID, "argv": argv,
            "argv_sha256": digest(argv), "environment": {}, "environment_sha256": digest({}),
            "cwd": str(ROOT.resolve()), "cwd_sha256": hashlib.sha256(str(ROOT.resolve()).encode()).hexdigest(),
            "mounts": mounts, "mounts_sha256": digest(mounts),
            "ownership_predicate": {"exact_id_pattern": "^[a-f0-9]{64}$", "required_labels": labels},
        },
        "limits": {
            "total_timeout_ms": TOTAL_TIMEOUT_MS, "cleanup_reserve_ms": CLEANUP_RESERVE_MS,
            "combined_output_max_bytes": COMBINED_OUTPUT_MAX_BYTES,
            "request_max_bytes": 65536, "response_max_bytes": 16384,
        },
        "planned_state_machine": [
            "pre_absence", "optional_exact_resource_id", "ownership_verified", "cleanup_attempted",
            "final_absence", "inventory_reconciled",
        ],
        "claims": dict(FALSE_CLAIMS),
    }
    _validate_protocol(manifest)
    return manifest


def _load_schema(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return value


def _validate_protocol(value: object) -> None:
    Draft202012Validator(_load_schema(PROTOCOL_SCHEMA)).validate(value)


def build_request(invocation_id: str) -> dict[str, object]:
    manifest = build_manifest(invocation_id)
    request = {
        "schema": "tamandua.elixir_check_locked.worker_adapter_request/v1",
        "invocation_id": invocation_id, "operation": manifest["operation"],
        "manifest": manifest, "manifest_sha256": digest(manifest),
    }
    _validate_protocol(request)
    return request


def _windows_kill_job(process: subprocess.Popen[bytes]) -> tuple[Any, Any] | None:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        return None
    limits = _JobExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = 0x00002000
    configured = kernel32.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits))
    assigned = configured and kernel32.AssignProcessToJobObject(handle, wintypes.HANDLE(int(process._handle)))
    if not assigned:
        kernel32.CloseHandle(handle)
        return None
    return kernel32, handle


def _resume_windows_process(process: subprocess.Popen[bytes]) -> bool:
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    return ntdll.NtResumeProcess(wintypes.HANDLE(int(process._handle))) == 0


def _close_job(job: tuple[Any, Any] | None, terminate: bool) -> None:
    if job is None:
        return
    kernel32, handle = job
    try:
        if terminate:
            kernel32.TerminateJobObject(handle, 1)
    finally:
        kernel32.CloseHandle(handle)


def _terminate(
    process: subprocess.Popen[bytes], deadline: float, job: tuple[Any, Any] | None,
) -> tuple[bool, None]:
    attempted = True
    try:
        if os.name == "nt":
            job = _close_job(job, True)
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    remaining = max(0.0, deadline - time.monotonic())
    if remaining:
        try:
            process.wait(timeout=remaining)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return attempted, None


def run_double(request: dict[str, object]) -> DoubleRun:
    total_deadline = time.monotonic() + TOTAL_TIMEOUT_MS / 1000
    operation_deadline = total_deadline - CLEANUP_RESERVE_MS / 1000
    creation = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED}
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", str(ADAPTER_SOURCE)], cwd=str(ROOT), env=environment(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            close_fds=True, **creation,
        )
    except OSError as error:
        raise BoundaryError("process_setup_error") from error
    job = None
    containment = os.name != "nt"
    if os.name == "nt":
        try:
            job = _windows_kill_job(process)
            containment = job is not None
            if not containment or not _resume_windows_process(process):
                raise OSError("windows_containment_failed")
        except Exception as error:
            terminated, job = _terminate(process, total_deadline, job)
            failed_run = DoubleRun(
                stdout=b"", stdout_accepted_bytes=0, stderr_accepted_bytes=0,
                stderr_seen=False, stdout_complete=False, stderr_complete=False,
                output_limit_exceeded=False, stream_read_error_seen=False,
                stdin_write_error_seen=False,
                accepted_output_bytes=0, exit_code=process.poll(), timed_out=False,
                containment_established=containment, termination_attempted=terminated,
                exit_confirmed=process.poll() is not None,
            )
            raise BoundaryError("process_setup_error", failed_run) from error
    assert process.stdin and process.stdout and process.stderr
    lock = threading.Lock()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    complete = {"stdout": False, "stderr": False}
    read_error = threading.Event()
    overflow = threading.Event()
    stderr_was_seen = False

    def reader(name: str, stream: Any) -> None:
        nonlocal stderr_was_seen
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    with lock:
                        complete[name] = True
                    return
                with lock:
                    if name == "stderr":
                        stderr_was_seen = True
                    used = len(buffers["stdout"]) + len(buffers["stderr"])
                    accepted = chunk[:max(0, COMBINED_OUTPUT_MAX_BYTES - used)]
                    buffers[name].extend(accepted)
                    if len(accepted) != len(chunk):
                        overflow.set()
        except (OSError, ValueError):
            read_error.set()
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = [threading.Thread(target=reader, args=(name, stream), daemon=True) for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
    for thread in threads:
        thread.start()
    payload = canonical_bytes(request) + b"\n"
    stdin_write_error = False
    termination_attempted = False
    try:
        process.stdin.write(payload); process.stdin.flush(); process.stdin.close()
    except OSError:
        stdin_write_error = True
        attempted, job = _terminate(process, total_deadline, job)
        termination_attempted = termination_attempted or attempted
    timed_out = False
    while (
        process.poll() is None
        and not overflow.is_set() and not read_error.is_set() and not stdin_write_error
        and time.monotonic() < operation_deadline
    ):
        time.sleep(0.005)
    if process.poll() is None:
        timed_out = not overflow.is_set() and not read_error.is_set() and not stdin_write_error
        attempted, job = _terminate(process, total_deadline, job)
        termination_attempted = termination_attempted or attempted
    try:
        process.wait(timeout=max(0.01, total_deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        attempted, job = _terminate(process, total_deadline, job)
        termination_attempted = termination_attempted or attempted
    for thread in threads:
        thread.join(timeout=max(0.0, total_deadline - time.monotonic()))
    with lock:
        run = DoubleRun(
            stdout=bytes(buffers["stdout"]),
            stdout_accepted_bytes=len(buffers["stdout"]), stderr_accepted_bytes=len(buffers["stderr"]),
            stderr_seen=stderr_was_seen,
            stdout_complete=complete["stdout"], stderr_complete=complete["stderr"],
            output_limit_exceeded=overflow.is_set(), stream_read_error_seen=read_error.is_set(),
            stdin_write_error_seen=stdin_write_error,
            accepted_output_bytes=len(buffers["stdout"]) + len(buffers["stderr"]),
            exit_code=process.poll(), timed_out=timed_out,
            containment_established=containment, termination_attempted=termination_attempted,
            exit_confirmed=process.poll() is not None,
        )
    if os.name == "nt" and job is not None:
        job = _close_job(job, False)
    return run


def _parse_response(run: DoubleRun, request: dict[str, object]) -> dict[str, object]:
    if run.timed_out:
        raise BoundaryError("worker_timeout", run)
    if run.output_limit_exceeded:
        raise BoundaryError("stream_limit_exceeded", run)
    if run.stdin_write_error_seen or run.stream_read_error_seen or not run.stdout_complete or not run.stderr_complete:
        raise BoundaryError("stream_observation_incomplete", run)
    if run.exit_code != 0 or run.stderr_seen or not run.stdout.endswith(b"\n"):
        raise BoundaryError("worker_error", run)
    try:
        value = json.loads(run.stdout[:-1].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BoundaryError("protocol_error", run) from None
    if type(value) is not dict or canonical_bytes(value) != run.stdout[:-1]:
        raise BoundaryError("protocol_error", run)
    try:
        _validate_protocol(value)
    except Exception:
        raise BoundaryError("protocol_error", run) from None
    try:
        _validate_response_bindings(value, request)
    except ValueError:
        raise BoundaryError("protocol_error", run) from None
    return value


def _validate_response_bindings(response: dict[str, object], request: dict[str, object]) -> None:
    manifest = request["manifest"]
    if (
        response["invocation_id"] != request["invocation_id"]
        or response["request_sha256"] != digest(request)
        or response["manifest_sha256"] != request["manifest_sha256"]
        or response["double_source_sha256"] != manifest["bindings"]["double_source_sha256"]
    ):
        raise ValueError("response_binding_mismatch")


def build_receipt(invocation_id: object = _INVOCATION_OMITTED) -> dict[str, object]:
    if invocation_id is _INVOCATION_OMITTED:
        invocation_id = secrets.token_hex(16)
    elif type(invocation_id) is not str or not INVOCATION_PATTERN.fullmatch(invocation_id):
        return _blocked_receipt("0" * 32, None, None, "input_invalid")
    try:
        request = build_request(invocation_id)
    except Exception:
        return _blocked_receipt(invocation_id, None, None, "input_invalid")
    before = {key: request["manifest"]["bindings"][key] for key in request["manifest"]["bindings"]}
    try:
        run = run_double(request)
        response = _parse_response(run, request)
        try:
            after = build_manifest(invocation_id)["bindings"]
        except Exception:
            raise BoundaryError("manifest_drift", run) from None
        if before != after:
            raise BoundaryError("manifest_drift", run)
        receipt = _receipt(request, run, response, None)
    except BoundaryError as error:
        receipt = _blocked_receipt(invocation_id, request, error.run, error.category)
    validate_receipt(receipt)
    return receipt


def _observation() -> dict[str, object]:
    return {
        "pre_absence": "not_observed", "exact_resource_id": None,
        "cleanup_attempted": False, "cleanup_succeeded": None,
        "final_absence": "not_observed", "inventory_before_sha256": None,
        "inventory_after_sha256": None, "inventory_unchanged": None,
    }


def _expected_response(request: dict[str, object]) -> dict[str, object]:
    manifest = request["manifest"]
    return {
        "schema": "tamandua.elixir_check_locked.worker_adapter_response/v1",
        "invocation_id": request["invocation_id"], "manifest_sha256": request["manifest_sha256"],
        "request_sha256": digest(request), "double_source_sha256": manifest["bindings"]["double_source_sha256"],
        "outcome": "source_only_not_executed", "adapter_runs": 0, "network_requests": 0,
        "check_locked_runs": 0, "observation": _observation(),
        "error_class": "source_only_not_executed", "claims": manifest["claims"],
    }


def _process_state(run: DoubleRun | None) -> dict[str, object]:
    if run is None:
        lifecycle = "not_spawned"
    elif run.containment_established and run.exit_confirmed:
        lifecycle = "contained_exited"
    elif run.containment_established:
        lifecycle = "contained_exit_unconfirmed"
    elif run.exit_confirmed:
        lifecycle = "uncontained_exited"
    else:
        lifecycle = "uncontained_exit_unconfirmed"
    return {
        "platform": "windows" if os.name == "nt" else "posix", "lifecycle_state": lifecycle,
        "containment_established": run.containment_established if run else False,
        "termination_attempted": run.termination_attempted if run else False,
        "exit_confirmed": run.exit_confirmed if run else False,
        "exit_code": run.exit_code if run and run.exit_confirmed else None,
        "timed_out": run.timed_out if run else False,
    }


def _receipt(request: dict[str, object], run: DoubleRun, response: dict[str, object], error: str | None) -> dict[str, object]:
    manifest = request["manifest"]
    return {
        "schema": "tamandua.elixir_check_locked.worker_adapter_boundary_receipt/v1",
        "evidence_class": "local_offline_source_only_container_adapter_contract",
        "workspace_base_head": WORKSPACE_BASE_HEAD, "invocation_id": request["invocation_id"],
        "bindings": {**manifest["bindings"], "manifest_sha256": request["manifest_sha256"], "argv_sha256": manifest["adapter"]["argv_sha256"]},
        "plan": {"adapter": manifest["adapter"], "resource": manifest["invocation"], "state_machine": manifest["planned_state_machine"], "limits": manifest["limits"]},
        "execution": {"double_spawn_count": 1, "adapter_runs": 0, "network_requests": 0, "check_locked_runs": 0},
        "process": _process_state(run),
        "observation": _observation(),
        "transport": {
            "stdin_canonical": True, "stdout_canonical": True,
            "stdout_observation_complete": run.stdout_complete,
            "stderr_observation_complete": run.stderr_complete,
            "stderr_seen": run.stderr_seen, "output_limit_exceeded": run.output_limit_exceeded,
            "stream_read_error_seen": run.stream_read_error_seen,
            "stdin_write_error_seen": run.stdin_write_error_seen,
            "accepted_output_bytes": run.accepted_output_bytes,
            "accepted_stdout_bytes": run.stdout_accepted_bytes,
            "accepted_stderr_bytes": run.stderr_accepted_bytes,
            "accepted_output_max_bytes": COMBINED_OUTPUT_MAX_BYTES,
            "request_sha256": digest(request), "response_sha256": digest(response),
        },
        "result": {"status": "observed", "outcome": "source_only_not_executed", "error_class": error},
        "claims": dict(FALSE_CLAIMS),
    }


def _blocked_receipt(invocation_id: object, request: dict[str, object] | None, run: DoubleRun | None, error: str) -> dict[str, object]:
    safe_id = (
        invocation_id
        if isinstance(invocation_id, str)
        and len(invocation_id) == 32
        and all(ch in "0123456789abcdef" for ch in invocation_id)
        else "0" * 32
    )
    manifest = request["manifest"] if request else build_manifest("0" * 32)
    setup_error = error == "process_setup_error"
    observed_run = None if setup_error else run
    accepted = observed_run.accepted_output_bytes if observed_run else 0
    return {
        "schema": "tamandua.elixir_check_locked.worker_adapter_boundary_receipt/v1",
        "evidence_class": "local_offline_source_only_container_adapter_contract",
        "workspace_base_head": WORKSPACE_BASE_HEAD, "invocation_id": safe_id,
        "bindings": {**manifest["bindings"], "manifest_sha256": digest(manifest), "argv_sha256": manifest["adapter"]["argv_sha256"]},
        "plan": {"adapter": manifest["adapter"], "resource": manifest["invocation"], "state_machine": manifest["planned_state_machine"], "limits": manifest["limits"]},
        "execution": {"double_spawn_count": 0 if run is None else 1, "adapter_runs": 0, "network_requests": 0, "check_locked_runs": 0},
        "process": _process_state(run),
        "observation": _observation(),
        "transport": {
            "stdin_canonical": request is not None and not setup_error and not (run and run.stdin_write_error_seen),
            "stdout_canonical": False,
            "stdout_observation_complete": observed_run.stdout_complete if observed_run else False,
            "stderr_observation_complete": observed_run.stderr_complete if observed_run else False,
            "stderr_seen": observed_run.stderr_seen if observed_run else False,
            "output_limit_exceeded": observed_run.output_limit_exceeded if observed_run else False,
            "stream_read_error_seen": observed_run.stream_read_error_seen if observed_run else False,
            "stdin_write_error_seen": observed_run.stdin_write_error_seen if observed_run else False,
            "accepted_output_bytes": accepted, "accepted_output_max_bytes": COMBINED_OUTPUT_MAX_BYTES,
            "accepted_stdout_bytes": observed_run.stdout_accepted_bytes if observed_run else 0,
            "accepted_stderr_bytes": observed_run.stderr_accepted_bytes if observed_run else 0,
            "request_sha256": digest(request) if request and not setup_error else None,
            "response_sha256": None,
        },
        "result": {"status": "blocked", "outcome": "boundary_error", "error_class": error},
        "claims": dict(FALSE_CLAIMS),
    }


def validate_receipt(receipt: dict[str, object]) -> None:
    Draft202012Validator(_load_schema(RECEIPT_SCHEMA)).validate(receipt)
    if receipt["execution"] != {"double_spawn_count": receipt["execution"]["double_spawn_count"], "adapter_runs": 0, "network_requests": 0, "check_locked_runs": 0}:
        raise ValueError("execution_not_source_only")
    observation = receipt["observation"]
    if observation != _observation():
        raise ValueError("observation_not_unobserved")
    if any(receipt["claims"].values()):
        raise ValueError("claim_promotion")
    resource = receipt["plan"]["resource"]
    adapter = receipt["plan"]["adapter"]
    invocation_id = receipt["invocation_id"]
    expected_manifest = build_manifest(invocation_id)
    if (
        resource != expected_manifest["invocation"]
        or adapter != expected_manifest["adapter"]
        or receipt["plan"]["limits"] != expected_manifest["limits"]
        or receipt["plan"]["state_machine"] != expected_manifest["planned_state_machine"]
    ):
        raise ValueError("receipt_plan_binding_mismatch")
    expected_bindings = {
        **expected_manifest["bindings"],
        "manifest_sha256": digest(expected_manifest),
        "argv_sha256": expected_manifest["adapter"]["argv_sha256"],
    }
    if receipt["bindings"] != expected_bindings:
        raise ValueError("receipt_binding_mismatch")
    if resource["id"] != invocation_id or resource["labels"]["io.tamandua.owner"] != invocation_id:
        raise ValueError("resource_owner_mismatch")
    if resource["resource_name"] != f"tamandua-check-locked-loop150-{invocation_id}":
        raise ValueError("resource_name_mismatch")
    if adapter["argv"] != planned_argv(resource["resource_name"], resource["labels"], adapter["mounts"]):
        raise ValueError("adapter_argv_mismatch")
    if (
        adapter["executable_path"] != DOCKER_PATH
        or adapter["image_id"] != IMAGE_ID
        or adapter["identity_observed"] is not False
        or adapter["executable_sha256"] != UNOBSERVED_SHA256
        or adapter["version_sha256"] != UNOBSERVED_SHA256
        or adapter["context_sha256"] != UNOBSERVED_SHA256
    ):
        raise ValueError("adapter_identity_mismatch")
    if adapter["argv_sha256"] != digest(adapter["argv"]):
        raise ValueError("adapter_argv_digest_mismatch")
    if adapter["mounts_sha256"] != digest(adapter["mounts"]):
        raise ValueError("adapter_mount_digest_mismatch")
    for mount in adapter["mounts"]:
        source = Path(mount["source"])
        if mount["read_only"] is not True or hash_file(source) != mount["source_sha256"]:
            raise ValueError("adapter_mount_binding_mismatch")
    if adapter["environment"] != {} or adapter["environment_sha256"] != digest({}):
        raise ValueError("adapter_environment_mismatch")
    if adapter["cwd_sha256"] != hashlib.sha256(adapter["cwd"].encode()).hexdigest():
        raise ValueError("adapter_cwd_digest_mismatch")
    if receipt["bindings"]["argv_sha256"] != adapter["argv_sha256"]:
        raise ValueError("receipt_argv_binding_mismatch")
    status = receipt["result"]["status"]
    transport = receipt["transport"]
    process = receipt["process"]
    error = receipt["result"]["error_class"]
    if receipt["execution"]["double_spawn_count"] == 0:
        expected_lifecycle = "not_spawned"
    elif process["containment_established"] and process["exit_confirmed"]:
        expected_lifecycle = "contained_exited"
    elif process["containment_established"]:
        expected_lifecycle = "contained_exit_unconfirmed"
    elif process["exit_confirmed"]:
        expected_lifecycle = "uncontained_exited"
    else:
        expected_lifecycle = "uncontained_exit_unconfirmed"
    if process["lifecycle_state"] != expected_lifecycle:
        raise ValueError("process_lifecycle_state_mismatch")
    if process["exit_confirmed"] is not (process["exit_code"] is not None):
        raise ValueError("process_exit_cardinality_mismatch")
    if (
        receipt["execution"]["double_spawn_count"] == 1
        and error != "process_setup_error" and not process["containment_established"]
    ):
        raise ValueError("post_setup_containment_mismatch")
    if process["termination_attempted"] and error not in (
        "worker_timeout", "stream_limit_exceeded", "stream_observation_incomplete",
        "process_setup_error",
    ):
        raise ValueError("termination_reason_mismatch")
    if transport["accepted_output_bytes"] != transport["accepted_stdout_bytes"] + transport["accepted_stderr_bytes"]:
        raise ValueError("accepted_output_cardinality_mismatch")
    if (
        transport["output_limit_exceeded"]
        and transport["accepted_output_bytes"] != transport["accepted_output_max_bytes"]
    ):
        raise ValueError("accepted_output_cap_mismatch")
    if transport["accepted_stderr_bytes"] > 0 and not transport["stderr_seen"]:
        raise ValueError("stderr_cardinality_mismatch")
    if status != "blocked" or error not in ("input_invalid", "process_setup_error"):
        expected_request = build_request(invocation_id)
        if transport["request_sha256"] != digest(expected_request):
            raise ValueError("request_digest_mismatch")
    if status == "observed" and not (
        receipt["execution"]["double_spawn_count"] == 1
        and transport["stdin_canonical"] and transport["stdout_canonical"]
        and transport["stdout_observation_complete"] and transport["stderr_observation_complete"]
        and not transport["stderr_seen"] and not transport["output_limit_exceeded"]
        and not transport["stream_read_error_seen"] and not transport["stdin_write_error_seen"]
        and transport["response_sha256"] is not None
    ):
        raise ValueError("observed_transport_state_invalid")
    if status == "observed":
        expected_response = _expected_response(expected_request)
        expected_stdout_bytes = len(canonical_bytes(expected_response)) + 1
        if (
            transport["response_sha256"] != digest(expected_response)
            or transport["accepted_stdout_bytes"] != expected_stdout_bytes
            or transport["accepted_stderr_bytes"] != 0
            or process["lifecycle_state"] != "contained_exited"
            or not process["containment_established"] or not process["exit_confirmed"]
            or process["termination_attempted"]
            or process["timed_out"] or process["exit_code"] != 0
        ):
            raise ValueError("observed_protocol_cardinality_mismatch")
    if error == "worker_timeout" and not (
        process["timed_out"] and process["termination_attempted"]
        and process["containment_established"]
    ):
        raise ValueError("timeout_lifecycle_mismatch")
    if error == "stream_limit_exceeded" and (
        not transport["output_limit_exceeded"] or process["timed_out"]
        or not process["containment_established"]
        or transport["accepted_output_bytes"] != transport["accepted_output_max_bytes"]
        or (not process["exit_confirmed"] and not process["termination_attempted"])
    ):
        raise ValueError("overflow_error_mismatch")
    if error == "stream_observation_incomplete" and not (
        not process["timed_out"]
        and not transport["output_limit_exceeded"]
        and process["containment_established"]
        and (process["exit_confirmed"] or process["termination_attempted"])
        and (
            transport["stdin_write_error_seen"]
            or transport["stream_read_error_seen"]
            or not transport["stdout_observation_complete"]
            or not transport["stderr_observation_complete"]
        )
    ):
        raise ValueError("stream_error_mismatch")
    if transport["stdin_write_error_seen"] and (
        error != "stream_observation_incomplete"
        or transport["stdin_canonical"] or not process["termination_attempted"]
    ):
        raise ValueError("stdin_transfer_lifecycle_mismatch")
    if error == "input_invalid" and (
        receipt["execution"]["double_spawn_count"] != 0
        or transport != {
            "stdin_canonical": False, "stdout_canonical": False,
            "stdout_observation_complete": False, "stderr_observation_complete": False,
            "stderr_seen": False, "output_limit_exceeded": False,
            "stream_read_error_seen": False, "stdin_write_error_seen": False,
            "accepted_output_bytes": 0,
            "accepted_output_max_bytes": COMBINED_OUTPUT_MAX_BYTES,
            "accepted_stdout_bytes": 0, "accepted_stderr_bytes": 0,
            "request_sha256": None, "response_sha256": None,
        }
    ):
        raise ValueError("pre_spawn_error_lifecycle_mismatch")
    if error == "process_setup_error":
        setup_transport = {
            "stdin_canonical": False, "stdout_canonical": False,
            "stdout_observation_complete": False, "stderr_observation_complete": False,
            "stderr_seen": False, "output_limit_exceeded": False,
            "stream_read_error_seen": False, "stdin_write_error_seen": False,
            "accepted_output_bytes": 0, "accepted_output_max_bytes": COMBINED_OUTPUT_MAX_BYTES,
            "accepted_stdout_bytes": 0, "accepted_stderr_bytes": 0,
            "request_sha256": None, "response_sha256": None,
        }
        if transport != setup_transport or not (
            (receipt["execution"]["double_spawn_count"] == 0 and process["lifecycle_state"] == "not_spawned")
            or (
                receipt["execution"]["double_spawn_count"] == 1
                and process["termination_attempted"] and not process["timed_out"]
            )
        ):
            raise ValueError("process_setup_lifecycle_mismatch")
    if error in ("manifest_drift", "protocol_error") and not (
        receipt["execution"]["double_spawn_count"] == 1
        and process["containment_established"] and process["exit_confirmed"]
        and process["exit_code"] == 0 and not process["timed_out"]
        and not process["termination_attempted"]
        and not transport["output_limit_exceeded"] and not transport["stream_read_error_seen"]
        and not transport["stdin_write_error_seen"]
        and transport["stdout_observation_complete"] and transport["stderr_observation_complete"]
        and not transport["stderr_seen"]
    ):
        raise ValueError("post_exit_protocol_lifecycle_mismatch")
    if error == "worker_error" and not (
        receipt["execution"]["double_spawn_count"] == 1 and process["exit_confirmed"]
        and process["containment_established"] and not process["termination_attempted"]
        and not process["timed_out"] and not transport["output_limit_exceeded"]
        and not transport["stream_read_error_seen"] and not transport["stdin_write_error_seen"]
        and transport["stdout_observation_complete"] and transport["stderr_observation_complete"]
        and (transport["stderr_seen"] or process["exit_code"] != 0)
    ):
        raise ValueError("worker_error_lifecycle_mismatch")


def main() -> int:
    receipt = build_receipt()
    sys.stdout.buffer.write(canonical_bytes(receipt) + b"\n")
    return 0 if receipt["result"]["status"] == "observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
