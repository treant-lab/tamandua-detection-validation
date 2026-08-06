#!/usr/bin/env python3
"""Parent-only authority for the Loop148 inert worker process boundary."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ctypes import wintypes
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[3]
PROTOCOL_SCHEMA = REPO_ROOT / "schemas/elixir_check_locked_probe_worker_protocol_v1.schema.json"
RECEIPT_SCHEMA = REPO_ROOT / "schemas/elixir_check_locked_probe_worker_boundary_receipt_v1.schema.json"
WORKER_SOURCE = Path(__file__).with_name("elixir_check_locked_probe_worker.py")
PARENT_SOURCE = Path(__file__)
WORKSPACE_BASE_HEAD = "ce97ccd64a686e91fbf6f613e3face7cb17843d2"
TOTAL_TIMEOUT_MS = 5000
CLEANUP_RESERVE_MS = 1500
REQUEST_MAX_BYTES = 65536
RESPONSE_MAX_BYTES = 16384
COMBINED_OUTPUT_MAX_BYTES = 32768
STREAM_CHUNK_BYTES = 4096
_CREATE_SUSPENDED = 0x00000004

FALSE_CLAIMS = {
    "external_claim_allowed": False,
    "product_ready": False,
    "production_ready": False,
    "real_adapter_validated": False,
    "real_cleanup_verified": False,
    "release_ready": False,
    "verimatrix_parity": False,
}

MANIFEST_BINDING_NAMES = (
    "argv_template_sha256",
    "environment_policy_sha256",
    "interpreter_executable_sha256",
    "interpreter_version_sha256",
    "parent_source_sha256",
    "protocol_schema_sha256",
    "receipt_schema_sha256",
    "worker_source_sha256",
)


class BoundaryError(ValueError):
    def __init__(
        self,
        category: str,
        *,
        spawn_count: int = 0,
        containment_established: bool = False,
        termination_attempted: bool = False,
        worker_exit_confirmed: bool = False,
        accepted_output_bytes: int = 0,
        stderr_seen: bool = False,
        stdout_observation_complete: bool = False,
        stderr_observation_complete: bool = False,
        output_limit_exceeded: bool = False,
        stream_read_error_seen: bool = False,
    ):
        super().__init__(category)
        self.category = category
        self.spawn_count = spawn_count
        self.containment_established = containment_established
        self.termination_attempted = termination_attempted
        self.worker_exit_confirmed = worker_exit_confirmed
        self.accepted_output_bytes = accepted_output_bytes
        self.stderr_seen = stderr_seen
        self.stdout_observation_complete = stdout_observation_complete
        self.stderr_observation_complete = stderr_observation_complete
        self.output_limit_exceeded = output_limit_exceeded
        self.stream_read_error_seen = stream_read_error_seen


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


@dataclass(frozen=True)
class WorkerRun:
    returncode: int
    stdout: bytes
    stderr: bytes
    containment_established: bool
    termination_attempted: bool
    worker_exit_confirmed: bool
    stderr_seen: bool
    stdout_observation_complete: bool
    stderr_observation_complete: bool
    output_limit_exceeded: bool
    stream_read_error_seen: bool


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BoundaryError("input_invalid")
        value[key] = item
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_value(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def _hash_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise BoundaryError("manifest_drift")
    return digest_bytes(path.read_bytes())


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate)
        Draft202012Validator.check_schema(value)
    except BoundaryError:
        raise
    except Exception as exc:
        raise BoundaryError("manifest_drift") from exc
    if not isinstance(value, dict):
        raise BoundaryError("manifest_drift")
    return value


def _command() -> list[str]:
    return [str(Path(sys.executable).resolve()), "-I", "-B", str(WORKER_SOURCE.resolve())]


def _windows_directory() -> Path | None:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel32.GetWindowsDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    directory = Path(buffer.value) if 0 < length < len(buffer) else Path()
    return directory if directory.is_absolute() else None


def _environment_policy() -> dict[str, str]:
    result = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    if os.name == "nt":
        result["SystemRoot"] = "absolute_windows_directory"
        result["WINDIR"] = "absolute_windows_directory"
    return result


def _environment() -> dict[str, str]:
    result = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    directory = _windows_directory()
    if os.name == "nt":
        if directory is None:
            raise BoundaryError("process_setup_error")
        result.update({"SystemRoot": str(directory), "WINDIR": str(directory)})
    return result


def _binding_snapshot() -> dict[str, str]:
    return {
        "protocol_schema_sha256": _hash_file(PROTOCOL_SCHEMA),
        "receipt_schema_sha256": _hash_file(RECEIPT_SCHEMA),
        "parent_source_sha256": _hash_file(PARENT_SOURCE),
        "worker_source_sha256": _hash_file(WORKER_SOURCE),
        "interpreter_executable_sha256": _hash_file(Path(sys.executable).resolve()),
        "interpreter_version_sha256": digest_bytes(sys.version.encode("utf-8")),
        "argv_template_sha256": digest_value(_command()),
        "environment_policy_sha256": digest_value(_environment_policy()),
    }


def build_manifest() -> dict[str, Any]:
    manifest = {
        "schema": "tamandua.elixir_check_locked.worker_manifest/v1",
        "adapter_profile": "inert_contract_v1",
        "operation": "inert_boundary_self_test",
        # This is the coordinator-pinned base label, not file provenance.  The
        # exact scoped bytes are bound independently by the hashes above.
        "workspace_base_head": WORKSPACE_BASE_HEAD,
        **_binding_snapshot(),
        "limits": {
            "cleanup_reserve_ms": CLEANUP_RESERVE_MS,
            "combined_output_max_bytes": COMBINED_OUTPUT_MAX_BYTES,
            "request_max_bytes": REQUEST_MAX_BYTES,
            "response_max_bytes": RESPONSE_MAX_BYTES,
            "total_timeout_ms": TOTAL_TIMEOUT_MS,
        },
        "claims": dict(FALSE_CLAIMS),
    }
    Draft202012Validator(_load_schema(PROTOCOL_SCHEMA)).validate(manifest)
    return manifest


def build_request(manifest: Mapping[str, Any], invocation_id: str | None = None) -> dict[str, Any]:
    request = {
        "schema": "tamandua.elixir_check_locked.worker_request/v1",
        "invocation_id": invocation_id or secrets.token_hex(16),
        "operation": "inert_boundary_self_test",
        "manifest": dict(manifest),
        "manifest_sha256": digest_value(manifest),
    }
    Draft202012Validator(_load_schema(PROTOCOL_SCHEMA)).validate(request)
    return request


def parse_canonical_document(raw: bytes, *, limit: int) -> dict[str, Any]:
    if not raw or len(raw) > limit or not raw.endswith(b"\n"):
        raise BoundaryError("protocol_error")
    body = raw[:-1]
    if not body or b"\n" in body or body.startswith(b"\xef\xbb\xbf"):
        raise BoundaryError("protocol_error")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError, BoundaryError) as exc:
        raise BoundaryError("protocol_error") from exc
    if not isinstance(value, dict) or canonical_bytes(value) != body:
        raise BoundaryError("protocol_error")
    return value


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


def _close_job(job: tuple[Any, Any] | None, *, terminate: bool) -> None:
    if job is None:
        return
    kernel32, handle = job
    try:
        if terminate:
            kernel32.TerminateJobObject(handle, 1)
    finally:
        kernel32.CloseHandle(handle)


def _terminate_tree(process: subprocess.Popen[bytes], deadline: float, job: tuple[Any, Any] | None) -> None:
    if os.name == "nt":
        _close_job(job, terminate=True)
    else:
        try:
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


def _run_worker(payload: bytes) -> WorkerRun:
    started = time.monotonic()
    total_deadline = started + TOTAL_TIMEOUT_MS / 1000
    execution_deadline = total_deadline - CLEANUP_RESERVE_MS / 1000
    if len(payload) > REQUEST_MAX_BYTES or execution_deadline <= started:
        raise BoundaryError("input_invalid")
    creation: dict[str, Any] = {}
    if os.name == "nt":
        creation["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED
    else:
        creation["start_new_session"] = True
    try:
        process = subprocess.Popen(
            _command(), cwd=str(REPO_ROOT), env=_environment(), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, close_fds=True, **creation,
        )
    except (OSError, BoundaryError) as exc:
        raise BoundaryError("process_setup_error") from exc
    job = None
    containment = os.name != "nt"
    if os.name == "nt":
        try:
            job = _windows_kill_job(process)
            containment = job is not None
            if not containment or time.monotonic() >= execution_deadline or not _resume_windows_process(process):
                raise BoundaryError("process_setup_error")
        except Exception as exc:
            _terminate_tree(process, total_deadline, job)
            raise BoundaryError(
                "process_setup_error", spawn_count=1,
                containment_established=containment,
                termination_attempted=True,
                worker_exit_confirmed=process.poll() is not None,
            ) from exc
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_tree(process, total_deadline, job)
        raise BoundaryError(
            "process_setup_error", spawn_count=1,
            containment_established=containment,
            termination_attempted=True,
            worker_exit_confirmed=process.poll() is not None,
        )

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    budget_lock = threading.Lock()
    overflow = threading.Event()
    writer_error = threading.Event()
    reader_error = threading.Event()
    stderr_seen = threading.Event()
    observations_complete = {"stdout": threading.Event(), "stderr": threading.Event()}
    used = 0

    def write_input() -> None:
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            writer_error.set()
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    def read_stream(name: str, stream: Any) -> None:
        nonlocal used
        try:
            while True:
                chunk = stream.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    observations_complete[name].set()
                    break
                if name == "stderr":
                    stderr_seen.set()
                with budget_lock:
                    remaining = COMBINED_OUTPUT_MAX_BYTES - used
                    accepted = chunk[:max(0, remaining)]
                    buffers[name].extend(accepted)
                    used += len(accepted)
                    if len(chunk) > remaining:
                        overflow.set()
        except (OSError, ValueError):
            reader_error.set()
        finally:
            try:
                stream.close()
            except OSError:
                pass

    writer = threading.Thread(target=write_input, daemon=True)
    readers = {
        "stdout": threading.Thread(target=read_stream, args=("stdout", process.stdout), daemon=True),
        "stderr": threading.Thread(target=read_stream, args=("stderr", process.stderr), daemon=True),
    }
    threads = [writer, *readers.values()]
    for thread in threads:
        thread.start()
    failure: str | None = None
    while process.poll() is None:
        if overflow.is_set():
            failure = "stream_limit_exceeded"
            break
        if writer_error.is_set() or reader_error.is_set():
            failure = "worker_error"
            break
        if time.monotonic() >= execution_deadline:
            failure = "worker_timeout"
            break
        time.sleep(0.005)
    termination_attempted = True
    if failure is not None:
        _terminate_tree(process, total_deadline, job)
        job = None
    elif os.name == "nt":
        _close_job(job, terminate=False)
        job = None
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    for thread in threads:
        thread.join(timeout=max(0.0, total_deadline - time.monotonic()))
    reader_incomplete = {name: thread.is_alive() for name, thread in readers.items()}
    if any(thread.is_alive() for thread in threads):
        _terminate_tree(process, total_deadline, job)
        failure = failure or "worker_timeout"
    elif overflow.is_set():
        failure = failure or "stream_limit_exceeded"
    elif writer_error.is_set() or reader_error.is_set():
        failure = failure or "worker_error"
    if failure is not None:
        raise BoundaryError(
            failure, spawn_count=1,
            containment_established=containment,
            termination_attempted=True,
            worker_exit_confirmed=process.poll() is not None,
            accepted_output_bytes=min(COMBINED_OUTPUT_MAX_BYTES, used),
            stderr_seen=stderr_seen.is_set(),
            stdout_observation_complete=observations_complete["stdout"].is_set() and not reader_incomplete["stdout"],
            stderr_observation_complete=observations_complete["stderr"].is_set() and not reader_incomplete["stderr"],
            output_limit_exceeded=overflow.is_set(),
            stream_read_error_seen=reader_error.is_set(),
        )
    return WorkerRun(
        returncode=int(process.returncode), stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]), containment_established=containment,
        termination_attempted=termination_attempted, worker_exit_confirmed=process.poll() is not None,
        stderr_seen=stderr_seen.is_set(),
        stdout_observation_complete=observations_complete["stdout"].is_set(),
        stderr_observation_complete=observations_complete["stderr"].is_set(),
        output_limit_exceeded=overflow.is_set(), stream_read_error_seen=reader_error.is_set(),
    )


def _validate_response(response: Mapping[str, Any], request: Mapping[str, Any]) -> None:
    Draft202012Validator(_load_schema(PROTOCOL_SCHEMA)).validate(response)
    expected = {
        "invocation_id": request["invocation_id"],
        "manifest_sha256": request["manifest_sha256"],
        "request_sha256": digest_bytes(canonical_bytes(request)),
        "worker_source_sha256": request["manifest"]["worker_source_sha256"],
        "claims": FALSE_CLAIMS,
    }
    if any(response[name] != value for name, value in expected.items()):
        raise BoundaryError("protocol_error")


def _lifecycle_state(
    spawn_count: int, exit_confirmed: bool, containment_established: bool,
) -> str:
    if spawn_count == 0:
        return "not_spawned"
    containment = "contained" if containment_established else "uncontained"
    exit_state = "exited" if exit_confirmed else "exit_unconfirmed"
    return f"spawned_{containment}_{exit_state}"


def _validate_receipt_state_machine(receipt: Mapping[str, Any]) -> None:
    result = receipt["result"]
    process = receipt["process"]
    transport = receipt["transport"]
    boundary = receipt["evidence_boundary"]
    observed = receipt["result"]["status"] == "observed"
    expected_lifecycle = _lifecycle_state(
        process["worker_spawn_count"], process["worker_exit_confirmed"],
        process["process_tree_containment_established"],
    )
    if process["lifecycle_state"] != expected_lifecycle:
        raise BoundaryError("protocol_error")
    if process["worker_spawn_count"] == 0:
        if (
            process["worker_exit_confirmed"]
            or process["process_tree_containment_established"]
            or process["process_tree_termination_attempted"]
            or transport["accepted_output_bytes"] != 0
            or transport["stderr_empty"]
            or transport["stderr_seen"]
            or transport["stdout_observation_complete"]
            or transport["stderr_observation_complete"]
            or transport["output_limit_exceeded"]
            or transport["stream_read_error_seen"]
        ):
            raise BoundaryError("protocol_error")
    elif not process["process_tree_termination_attempted"]:
        raise BoundaryError("protocol_error")
    if observed != (result["outcome"] == "inert_contract_observed"):
        raise BoundaryError("protocol_error")
    if observed != boundary["process_separation_observed"]:
        raise BoundaryError("protocol_error")
    if transport["stderr_empty"] != (
        transport["stderr_observation_complete"] and not transport["stderr_seen"]
    ):
        raise BoundaryError("protocol_error")
    if (
        transport["stdout_canonical"] and not transport["stdout_observation_complete"]
    ) or (
        transport["stream_read_error_seen"]
        and transport["stdout_observation_complete"]
        and transport["stderr_observation_complete"]
    ):
        raise BoundaryError("protocol_error")
    if transport["output_limit_exceeded"] and result["error_class"] not in {
        "stream_limit_exceeded", "manifest_drift",
    }:
        raise BoundaryError("protocol_error")
    if observed:
        expected = (
            result["error_class"] is None
            and process["lifecycle_state"] == "spawned_contained_exited"
            and not process["pre_post_drift_detected"]
            and transport["stdout_canonical"]
            and transport["stderr_empty"]
            and not transport["stderr_seen"]
            and transport["stdout_observation_complete"]
            and transport["stderr_observation_complete"]
            and not transport["output_limit_exceeded"]
            and not transport["stream_read_error_seen"]
            and transport["accepted_output_bytes"] > 0
            and isinstance(transport["response_sha256"], str)
        )
        if not expected:
            raise BoundaryError("protocol_error")
    else:
        error = result["error_class"]
        if (
            result["outcome"] != "boundary_error"
            or not isinstance(error, str)
            or transport["stdout_canonical"]
            or transport["response_sha256"] is not None
            or process["pre_post_drift_detected"] != (error == "manifest_drift")
            or (error == "stream_limit_exceeded" and not transport["output_limit_exceeded"])
        ):
            raise BoundaryError("protocol_error")
        lifecycle = process["lifecycle_state"]
        if error == "input_invalid":
            if lifecycle != "not_spawned" or transport["stderr_empty"]:
                raise BoundaryError("protocol_error")
        elif error in {"protocol_error", "stream_limit_exceeded", "worker_error", "worker_timeout"}:
            if lifecycle not in {"spawned_contained_exited", "spawned_contained_exit_unconfirmed"}:
                raise BoundaryError("protocol_error")
        elif error == "process_setup_error":
            pass
        elif error != "manifest_drift":
            raise BoundaryError("protocol_error")


def validate_receipt(receipt: Mapping[str, Any]) -> None:
    Draft202012Validator(_load_schema(RECEIPT_SCHEMA)).validate(receipt)
    _validate_receipt_state_machine(receipt)
    if receipt["claims"] != FALSE_CLAIMS:
        raise BoundaryError("protocol_error")


def build_receipt(invocation_id: str | None = None) -> dict[str, Any]:
    manifest = build_manifest()
    request = build_request(manifest, invocation_id)
    request_body = canonical_bytes(request)
    payload = request_body + b"\n"
    run: WorkerRun | None = None
    response: dict[str, Any] | None = None
    error_class: str | None = None
    failure: BoundaryError | None = None
    response_sha: str | None = None
    stdout_canonical = False
    try:
        run = _run_worker(payload)
        if run.returncode != 0 or run.stderr or len(run.stdout) > RESPONSE_MAX_BYTES:
            raise BoundaryError(
                "worker_error", spawn_count=1,
                containment_established=run.containment_established,
                termination_attempted=run.termination_attempted,
                worker_exit_confirmed=run.worker_exit_confirmed,
                accepted_output_bytes=min(COMBINED_OUTPUT_MAX_BYTES, len(run.stdout) + len(run.stderr)),
                stderr_seen=run.stderr_seen,
                stdout_observation_complete=run.stdout_observation_complete,
                stderr_observation_complete=run.stderr_observation_complete,
                output_limit_exceeded=run.output_limit_exceeded,
                stream_read_error_seen=run.stream_read_error_seen,
            )
        response = parse_canonical_document(run.stdout, limit=RESPONSE_MAX_BYTES)
        _validate_response(response, request)
        response_sha = digest_bytes(run.stdout[:-1])
        stdout_canonical = True
    except BoundaryError as exc:
        failure = exc
        error_class = exc.category
    try:
        post = _binding_snapshot()
    except BoundaryError:
        post = {}
    drift = any(post.get(name) != manifest[name] for name in MANIFEST_BINDING_NAMES)
    if drift:
        error_class = "manifest_drift"
        response = None
        response_sha = None
        stdout_canonical = False
    observed = response is not None and error_class is None
    accepted_output_bytes = (
        min(COMBINED_OUTPUT_MAX_BYTES, len(run.stdout) + len(run.stderr))
        if run else (failure.accepted_output_bytes if failure else 0)
    )
    stderr_was_seen = run.stderr_seen if run else bool(failure and failure.stderr_seen)
    stdout_complete = (
        run.stdout_observation_complete if run
        else bool(failure and failure.stdout_observation_complete)
    )
    stderr_complete = (
        run.stderr_observation_complete if run
        else bool(failure and failure.stderr_observation_complete)
    )
    output_limit_exceeded = run.output_limit_exceeded if run else bool(failure and failure.output_limit_exceeded)
    stream_read_error_seen = run.stream_read_error_seen if run else bool(failure and failure.stream_read_error_seen)
    bindings = {name: manifest[name] for name in MANIFEST_BINDING_NAMES}
    bindings["manifest_sha256"] = request["manifest_sha256"]
    receipt = {
        "schema": "tamandua.elixir_check_locked.worker_boundary_receipt/v1",
        "evidence_class": "local_offline_inert_worker_process_boundary_contract",
        "workspace_base_head": WORKSPACE_BASE_HEAD,
        "invocation_id": request["invocation_id"],
        "bindings": bindings,
        "evidence_boundary": {
            "adapter_authenticity_verified": False,
            "manifest_canonical": True,
            "parent_is_sole_receipt_emitter": True,
            "process_separation_observed": observed,
            "real_cleanup_verified": False,
            "same_user_replacement_resistance_proven": False,
            "worker_trust": "untrusted_categorical_producer",
        },
        "process": {
            "platform": "windows" if os.name == "nt" else "posix",
            "total_timeout_ms": TOTAL_TIMEOUT_MS,
            "cleanup_reserve_ms": CLEANUP_RESERVE_MS,
            "lifecycle_state": _lifecycle_state(
                1 if run is not None else (failure.spawn_count if failure else 0),
                bool(run.worker_exit_confirmed if run else failure and failure.worker_exit_confirmed),
                bool(run.containment_established if run else failure and failure.containment_established),
            ),
            "worker_spawn_count": 1 if run is not None else (failure.spawn_count if failure else 0),
            "worker_exit_confirmed": bool(run.worker_exit_confirmed if run else failure and failure.worker_exit_confirmed),
            "process_tree_containment_established": bool(run.containment_established if run else failure and failure.containment_established),
            "process_tree_termination_attempted": bool(run.termination_attempted if run else failure and failure.termination_attempted),
            "process_tree_exit_independently_verified": False,
            "pre_post_drift_detected": drift,
        },
        "transport": {
            "stdin_canonical": True,
            "stdout_canonical": stdout_canonical,
            "stdout_observation_complete": stdout_complete,
            "stderr_observation_complete": stderr_complete,
            "stderr_seen": stderr_was_seen,
            "stderr_empty": stderr_complete and not stderr_was_seen,
            "output_limit_exceeded": output_limit_exceeded,
            "stream_read_error_seen": stream_read_error_seen,
            "accepted_output_bytes": accepted_output_bytes,
            "accepted_output_max_bytes": COMBINED_OUTPUT_MAX_BYTES,
            "request_sha256": digest_bytes(request_body),
            "response_sha256": response_sha,
        },
        "result": {
            "status": "observed" if observed else "blocked",
            "outcome": "inert_contract_observed" if observed else "boundary_error",
            "error_class": None if observed else (error_class or "worker_error"),
        },
        "claims": dict(FALSE_CLAIMS),
    }
    validate_receipt(receipt)
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    if list(argv if argv is not None else sys.argv[1:]):
        return 2
    try:
        receipt = build_receipt()
    except Exception:
        return 3
    sys.stdout.buffer.write(canonical_bytes(receipt) + b"\n")
    return 0 if receipt["result"]["status"] == "observed" else 4


if __name__ == "__main__":
    raise SystemExit(main())
