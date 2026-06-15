#!/usr/bin/env python3
"""
Tamandua Detection Validation runner.

This runner wraps external validation tools such as Atomic Red Team, while
normalizing the evidence into Tamandua-specific metrics: endpoint health,
driver state, event coverage, alert coverage, latency, drops, and raw evidence.

The default mode is dry-run. Use --execute to run commands on the target VM.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import dataclasses
import datetime as dt
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    # Fallback for direct execution without root_resolver
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False

# Paths adapt based on standalone vs monorepo mode
if is_standalone():
    DEFAULT_PROFILE = Path(__file__).parent / "profiles" / "windows_atomic_smoke.json"
    DEFAULT_OUTPUT_DIR = RUNS_DIR
    PROFILE_DIR = Path(__file__).parent / "profiles"
else:
    DEFAULT_PROFILE = ROOT / "tools" / "detection_validation" / "profiles" / "windows_atomic_smoke.json"
    DEFAULT_OUTPUT_DIR = RUNS_DIR
    PROFILE_DIR = ROOT / "tools" / "detection_validation" / "profiles"


@dataclasses.dataclass
class CommandResult:
    host: str
    command: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int


class RunnerError(RuntimeError):
    pass


def local_shell_command(command: str, cwd: Path | None = None, timeout: int = 120) -> CommandResult:
    started = time.monotonic()
    proc = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=True,
    )
    return CommandResult(
        host="local",
        command=command,
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def trace_step(message: str) -> None:
    if os.getenv("TAMANDUA_VALIDATION_TRACE"):
        print(f"[validation-trace] {iso(utc_now())} {message}", file=sys.stderr, flush=True)


def deadline_expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def remaining_deadline_seconds(deadline: float | None, default: int, floor: int = 1) -> int:
    if deadline is None:
        return max(floor, default)
    return max(floor, min(default, int(deadline - time.monotonic())))


def execution_infra_blocked_score(
    test: dict[str, Any],
    error: str,
    error_code: str,
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "status": "infra_blocked",
        "gap_category": "runner",
        "error": error,
        "error_code": error_code,
        "expected_telemetry": test.get("expected_telemetry", []),
        "missing_expected_telemetry": test.get("expected_telemetry", []),
        "execution": execution or {},
    }


def classify_execution_failure(execution: dict[str, Any]) -> tuple[str, str, str]:
    error_code = str(execution.get("error_code") or "")
    stderr = " ".join(
        str(execution.get(key) or "")
        for key in ("stderr", "guest_stderr", "error")
    )
    lower = " ".join([error_code, stderr]).lower()
    if "caldera" in lower:
        return "infra_blocked", "runner", error_code or "caldera_execution_channel_failed"
    if "qemu guest agent" in lower or "guest-exec" in lower or "qga" in lower or "timed out" in lower:
        return "infra_blocked", "runner", error_code or "qga_execution_channel_failed"
    if "local command launch failed" in lower:
        return "infra_blocked", "runner", error_code or "local_execution_transport_failed"
    live_response_code = classify_live_response_execution_error(execution)
    if live_response_code:
        return "infra_blocked", "runner", live_response_code
    return "execution_failed", "execution", error_code or "command_execution_failed"


def classify_live_response_execution_error(execution: dict[str, Any]) -> str | None:
    transport = str(execution.get("transport") or "")
    stderr = " ".join(
        str(execution.get(key) or "")
        for key in ("stderr", "guest_stderr", "error")
    )
    lower = " ".join([str(execution.get("error_code") or ""), stderr]).lower()

    if transport != "tamandua_ctl_live_response" and "live response" not in lower and "tamandua-ctl" not in lower:
        return None
    if "invalid or expired token" in lower or "expired token" in lower:
        return "cli_auth_invalid_or_expired"
    if "http error: 403 forbidden" in lower or "http 403" in lower or "forbidden" in lower:
        return "cli_auth_forbidden"
    if "http 401" in lower or "unauthorized" in lower:
        return "cli_auth_unauthorized"
    if "failed to start cli auth" in lower:
        return "cli_auth_start_failed"
    if "agent is not online" in lower or "agent offline" in lower:
        return "live_response_agent_offline"
    if "live response join failed" in lower:
        return "live_response_join_failed"
    if "live_response_shell_unconfirmed" in lower:
        return "live_response_shell_unconfirmed"
    if "live_response_shell_not_ready" in lower:
        return "live_response_shell_not_ready"
    if "live_response_no_output_unconfirmed" in lower:
        return "live_response_no_output_unconfirmed"
    if "shell_start_unconfirmed_dispatch" in lower or "session_started was not received" in lower:
        return "live_response_shell_unconfirmed"
    if "shell_ready=false" in lower or "shell ready false" in lower:
        return "live_response_shell_not_ready"
    if "timed out waiting for agent shell_start" in lower:
        return "live_response_shell_start_timeout"
    if "timed out waiting for agent shell input" in lower:
        return "live_response_shell_input_timeout"
    if "timed out" in lower:
        return "live_response_timeout"
    return "live_response_execution_channel_failed"


def local_command(
    command: list[str],
    cwd: Path | None = None,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> CommandResult:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            host="local",
            command=" ".join(shlex.quote(part) for part in command),
            exit_code=124,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace"),
            stderr=(
                ((exc.stderr or "") if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace"))
                + f"\nlocal command timed out after {timeout}s"
            ).strip(),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except OSError as exc:
        return CommandResult(
            host="local",
            command=" ".join(shlex.quote(part) for part in command),
            exit_code=1,
            stdout="",
            stderr=f"local command launch failed: {type(exc).__name__}: {exc}",
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    return CommandResult(
        host="local",
        command=" ".join(shlex.quote(part) for part in command),
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def tamandua_ctl_env(server: str | None, base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base_env or os.environ)
    if not server:
        return env
    host = urllib.parse.urlparse(server).hostname
    if not host:
        return env

    existing_values: list[str] = []
    for name in ("NO_PROXY", "no_proxy"):
        existing = env.get(name)
        if existing:
            existing_values.extend(item.strip() for item in existing.split(",") if item.strip())

    merged: list[str] = []
    for value in [*existing_values, host]:
        if value and value not in merged:
            merged.append(value)
    no_proxy = ",".join(merged)
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    return env


def require_paramiko():
    try:
        import paramiko  # type: ignore
    except ImportError as exc:
        raise RunnerError("paramiko is required for remote lab execution. Install with: pip install paramiko") from exc
    return paramiko


class SshHost:
    def __init__(self, host: str, username: str, password: str | None, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.client = None

    def __enter__(self):
        self._connect()
        return self

    def _connect(self) -> None:
        paramiko = require_paramiko()
        if self.client is not None:
            with contextlib.suppress(Exception):
                self.client.close()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        trace_step(f"ssh connect start host={self.host} user={self.username} password={'yes' if self.password else 'no'}")
        client.connect(
            self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
            look_for_keys=self.password is None,
            allow_agent=self.password is None,
        )
        trace_step(f"ssh connect ok host={self.host}")
        self.client = client

    def __exit__(self, exc_type, exc, tb):
        if self.client is not None:
            self.client.close()

    def _transport_active(self) -> bool:
        if self.client is None:
            return False
        transport = self.client.get_transport()
        return bool(transport and transport.is_active())

    def run(self, command: str, timeout: int = 120) -> CommandResult:
        if self.client is None:
            raise RunnerError("SSH host is not connected")

        started = time.monotonic()
        trace_step(f"ssh command start host={self.host} timeout={timeout} command={command[:160]}")
        if not self._transport_active():
            trace_step(f"ssh reconnect inactive host={self.host}")
            self._connect()
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        except Exception as exc:
            if "not active" not in str(exc).lower() and "forcibly closed" not in str(exc).lower():
                raise
            trace_step(f"ssh reconnect after exec failure host={self.host} error={exc}")
            self._connect()
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        del stdin
        channel = stdout.channel
        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        deadline = time.monotonic() + max(1, timeout)

        while True:
            while channel.recv_ready():
                out_chunks.append(channel.recv(65536))
            while channel.recv_stderr_ready():
                err_chunks.append(channel.recv_stderr(65536))

            if channel.exit_status_ready():
                code = channel.recv_exit_status()
                break

            if time.monotonic() >= deadline:
                channel.close()
                out = b"".join(out_chunks).decode(errors="replace")
                err = b"".join(err_chunks).decode(errors="replace")
                if err:
                    err += "\n"
                err += f"SSH command timed out after {timeout}s"
                trace_step(f"ssh command timeout host={self.host} stdout={len(out)} stderr={len(err)}")
                return CommandResult(
                    host=self.host,
                    command=command,
                    exit_code=124,
                    stdout=out,
                    stderr=err,
                    duration_ms=int((time.monotonic() - started) * 1000),
                )

            time.sleep(0.1)

        while channel.recv_ready():
            out_chunks.append(channel.recv(65536))
        while channel.recv_stderr_ready():
            err_chunks.append(channel.recv_stderr(65536))

        out = b"".join(out_chunks).decode(errors="replace")
        err = b"".join(err_chunks).decode(errors="replace")
        trace_step(f"ssh command done host={self.host} exit={code} stdout={len(out)} stderr={len(err)}")
        return CommandResult(
            host=self.host,
            command=command,
            exit_code=code,
            stdout=out,
            stderr=err,
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class ProxmoxApiHost:
    """Minimal Proxmox HTTPS API client for QGA command execution."""

    def __init__(self, host: str, username: str, password: str | None, node: str = "Default"):
        self.host = host
        self.username = username if "@" in username else f"{username}@pam"
        self.password = password
        self.node = node
        self.base_url = f"https://{host}:8006/api2/json"
        self.context = ssl._create_unverified_context()
        self.ticket: str | None = None
        self.csrf: str | None = None

    def __enter__(self):
        if not self.password:
            raise RunnerError("--proxmox-api requires --proxmox-password or TAMANDUA_PROXMOX_PASSWORD")
        payload = urllib.parse.urlencode(
            {"username": self.username, "password": self.password}
        ).encode()
        data = self._request("POST", "/access/ticket", payload=payload, auth=False)
        auth = data.get("data") if isinstance(data, dict) else {}
        self.ticket = auth.get("ticket")
        self.csrf = auth.get("CSRFPreventionToken")
        if not self.ticket or not self.csrf:
            raise RunnerError("Proxmox API login did not return ticket/CSRF token")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.ticket = None
        self.csrf = None

    def _request(
        self,
        method: str,
        path: str,
        payload: bytes | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if payload is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if auth:
            if not self.ticket or not self.csrf:
                raise RunnerError("Proxmox API client is not authenticated")
            headers["Cookie"] = f"PVEAuthCookie={self.ticket}"
            headers["CSRFPreventionToken"] = self.csrf
        request = urllib.request.Request(
            self.base_url + path,
            data=payload,
            headers=headers,
            method=method,
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self.context),
        )
        with opener.open(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))

    def guest_exec(self, vmid: int, command: str, timeout: int = 120, retries: int = 3) -> dict[str, Any]:
        started = time.monotonic()
        guest_os = os.getenv("TAMANDUA_QGA_GUEST_OS", "windows").strip().lower()
        if guest_os in {"linux", "bash", "sh"}:
            guest_command = "/bin/bash"
            input_data = command
            command_text = (
                f"proxmox-api guest exec {vmid}: /bin/bash <<'SCRIPT'\n"
                f"{command}\nSCRIPT"
            )
        else:
            # Proxmox API does not reliably split Windows command lines for
            # guest-exec. Launch cmd.exe and feed it the intended command, which
            # matches the qm/input-data path used by the lab scripts.
            guest_command = "cmd.exe"
            input_data = command.rstrip() + "\r\nexit\r\n"
            command_text = (
                f"proxmox-api guest exec {vmid}: cmd.exe <<'SCRIPT'\n"
                f"{command}\nSCRIPT"
            )

        payload = urllib.parse.urlencode(
            {"command": guest_command, "input-data": input_data}
        ).encode()
        start: dict[str, Any] | None = None
        start_error: str | None = None
        for attempt in range(max(0, retries) + 1):
            try:
                start = self._request(
                    "POST",
                    f"/nodes/{urllib.parse.quote(self.node)}/qemu/{vmid}/agent/exec",
                    payload=payload,
                )
                start_error = None
                break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
                error_text = str(exc)
                if isinstance(exc, urllib.error.HTTPError):
                    try:
                        body = exc.read().decode("utf-8", errors="replace")
                    except Exception:
                        body = ""
                    if body:
                        error_text = f"{error_text}: {body}"
                start_error = error_text
                retryable = (
                    "qemu guest agent is not running" in error_text.lower()
                    or "guest agent is not running" in error_text.lower()
                    or "got timeout" in error_text.lower()
                    or "timeout" in error_text.lower()
                )
                if attempt >= max(0, retries) or not retryable:
                    break
                time.sleep(5 * (attempt + 1))
        if start_error is not None or start is None:
            result = CommandResult(
                host=self.host,
                command=command_text,
                exit_code=1,
                stdout="",
                stderr=start_error or "Proxmox API guest exec did not start",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            return {
                "outer_exit_code": 1,
                "stdout": "",
                "stderr": result.stderr,
                "guest_exit_code": None,
                "guest_stdout": "",
                "guest_stderr": result.stderr,
                "transport": "proxmox_api_qga",
                "error_code": "qga_execution_channel_failed",
                "error": result.stderr,
                "command_result": dataclasses.asdict(result),
            }
        pid = ((start.get("data") or {}) if isinstance(start, dict) else {}).get("pid")
        if pid is None:
            return {
                "outer_exit_code": 1,
                "stdout": json.dumps(start),
                "stderr": "Proxmox API guest exec returned no pid",
                "guest_exit_code": None,
                "guest_stdout": "",
                "guest_stderr": "",
                "transport": "proxmox_api_qga",
                "command_result": dataclasses.asdict(
                    CommandResult(
                        host=self.host,
                        command=command_text,
                        exit_code=1,
                        stdout=json.dumps(start),
                        stderr="Proxmox API guest exec returned no pid",
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                ),
            }

        deadline = time.monotonic() + max(5, timeout)
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            time.sleep(1)
            try:
                status = self._request(
                    "GET",
                    f"/nodes/{urllib.parse.quote(self.node)}/qemu/{vmid}/agent/exec-status?"
                    + urllib.parse.urlencode({"pid": pid}),
                )
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
                last = dict(last)
                last["exitcode"] = 124
                last["err-data"] = (last.get("err-data") or "") + f"\nQGA exec-status failed: {exc}"
                time.sleep(2)
                continue
            last = (status.get("data") or {}) if isinstance(status, dict) else {}
            if last.get("exited"):
                break
        else:
            last = dict(last)
            last["exitcode"] = 124
            last["err-data"] = (last.get("err-data") or "") + f"\nQGA command timed out after {timeout}s"

        stdout = str(last.get("out-data") or "")
        stderr = str(last.get("err-data") or "")
        exit_code = last.get("exitcode")
        outer_exit_code = 0 if exit_code == 0 else int(exit_code or 1)
        result = CommandResult(
            host=self.host,
            command=command_text,
            exit_code=outer_exit_code,
            stdout=json.dumps({"data": last}, ensure_ascii=False),
            stderr=stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return {
            "outer_exit_code": outer_exit_code,
            "stdout": result.stdout,
            "stderr": stderr,
            "guest_exit_code": exit_code,
            "guest_stdout": stdout,
            "guest_stderr": stderr,
            "qm_payload": last,
            "transport": "proxmox_api_qga",
            "command_result": dataclasses.asdict(result),
        }


def load_profile(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def discover_profiles() -> list[dict[str, Any]]:
    profiles = []
    for path in sorted(PROFILE_DIR.glob("*.json")):
        profile = load_profile(path)
        profiles.append(
            {
                "profile_id": profile.get("profile_id", path.stem),
                "name": profile.get("name", path.stem),
                "platform": profile.get("platform"),
                "tests": len(profile.get("tests") or []),
                "path": str(path.relative_to(ROOT)),
            }
        )
    return profiles


def select_tests(profile: dict[str, Any], only: list[str] | None) -> list[dict[str, Any]]:
    tests = list(profile.get("tests") or [])
    if not only:
        return tests

    wanted = {item.strip().lower() for item in only if item.strip()}
    selected = [
        test
        for test in tests
        if str(test.get("id", "")).lower() in wanted
        or str(test.get("name", "")).lower() in wanted
        or any(str(tag).lower() in wanted for tag in test.get("tags", []))
    ]
    if not selected:
        raise RunnerError(f"--only matched no tests: {', '.join(sorted(wanted))}")
    return selected


def git_metadata() -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key, command in {
        "commit": ["git", "rev-parse", "HEAD"],
        "commit_short": ["git", "rev-parse", "--short", "HEAD"],
    }.items():
        try:
            result = local_command(command, cwd=ROOT)
            metadata[key] = result.stdout.strip() if result.exit_code == 0 else None
        except Exception:
            metadata[key] = None

    try:
        status = local_command(["git", "status", "--short"], cwd=ROOT)
        metadata["dirty"] = bool(status.stdout.strip())
        metadata["status_short"] = status.stdout.splitlines()
    except Exception:
        metadata["dirty"] = None
        metadata["status_short"] = []
    return metadata


def json_line_block(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def powershell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def powershell_command_line(script: str) -> str:
    escaped = script.replace('"', '\\"')
    return f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{escaped}"'


def qm_guest_exec_command(vmid: int, windows_command: str, timeout_seconds: int = 120) -> str:
    # Do not wrap every benchmark command in PowerShell. The Windows QEMU guest
    # agent is much more reliable when it launches the intended process directly,
    # and the direct command line is the evidence we want the EDR to observe.
    argv = [strip_grouping_quotes(arg) for arg in shlex.split(windows_command, posix=False)]
    return shlex.join(["qm", "guest", "exec", str(vmid), "--timeout", str(timeout_seconds), "--", *argv])


def strip_grouping_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def split_windows_command_line(command: str) -> list[str]:
    if os.name != "nt":
        return [strip_grouping_quotes(arg) for arg in shlex.split(command, posix=True)]

    argc = ctypes.c_int()
    command_line_to_argv = ctypes.windll.shell32.CommandLineToArgvW
    command_line_to_argv.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    command_line_to_argv.restype = ctypes.POINTER(ctypes.c_wchar_p)
    argv = command_line_to_argv(command, ctypes.byref(argc))
    if not argv:
        raise RunnerError("CommandLineToArgvW failed while parsing tamandua-ctl command")
    try:
        return [argv[index] for index in range(argc.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(argv)


def parse_qm_guest_exec(result: CommandResult) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "outer_exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "guest_exit_code": None,
        "guest_stdout": "",
        "guest_stderr": "",
    }
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return parsed

    parsed["qm_payload"] = payload
    parsed["guest_exit_code"] = payload.get("exitcode")
    parsed["guest_stdout"] = payload.get("out-data", "")
    parsed["guest_stderr"] = payload.get("err-data", "")
    return parsed


def guest_command(
    proxmox: SshHost | ProxmoxApiHost,
    vmid: int,
    windows_command: str,
    timeout: int = 180,
    retries: int = 3,
) -> dict[str, Any]:
    if isinstance(proxmox, ProxmoxApiHost):
        return proxmox.guest_exec(vmid, windows_command, timeout=timeout, retries=retries)

    command = qm_guest_exec_command(vmid, windows_command, timeout)
    result = proxmox.run(command, timeout=timeout + 30)
    for attempt in range(max(0, retries)):
        retryable_qga_error = (
            "guest-exec' failed - got timeout" in result.stderr
            or "guest-exec-status' failed - got timeout" in result.stderr
            or "QEMU guest agent is not running" in result.stderr
        )
        if result.exit_code != 255 or not retryable_qga_error:
            break
        time.sleep(5 * (attempt + 1))
        result = proxmox.run(command, timeout=timeout + 30)
    parsed = parse_qm_guest_exec(result)
    if parsed.get("guest_exit_code") is None and isinstance(parsed.get("qm_payload"), dict):
        pid = parsed["qm_payload"].get("pid")
        if pid is not None:
            parsed = poll_guest_exec_status(proxmox, vmid, int(pid), parsed, timeout)
    parsed["command_result"] = dataclasses.asdict(result)
    return parsed


def tamandua_ctl_command(args: argparse.Namespace, command: str, timeout: int) -> dict[str, Any]:
    if not args.agent_id:
        return {
            "outer_exit_code": 1,
            "stdout": "",
            "stderr": "tamandua-ctl target agent_id was not resolved",
            "guest_exit_code": 1,
            "guest_stdout": "",
            "guest_stderr": "tamandua-ctl target agent_id was not resolved",
            "transport": "tamandua_ctl_live_response",
            "error_code": "tamandua_ctl_target_agent_missing",
            "error": "tamandua-ctl target agent_id was not resolved",
        }

    ctl_path = Path(args.tamandua_ctl_path)
    ctl = str(ctl_path if ctl_path.exists() else args.tamandua_ctl_path)
    invocation = [
        ctl,
        "--json",
        "remote",
        "command",
        "--agent-id",
        args.agent_id or "",
        "--overall-timeout",
        str(max(1, timeout)),
        "--idle-timeout",
        str(max(1, args.live_response_idle_timeout_seconds)),
        "--shell-start-timeout",
        str(max(1, min(timeout, args.live_response_shell_start_timeout_seconds))),
    ]
    if args.tamandua_ctl_server:
        invocation.extend(["--server", args.tamandua_ctl_server])
    if args.tamandua_ctl_token:
        invocation.extend(["--token", args.tamandua_ctl_token])
    if args.live_response_supervisor_mode:
        invocation.append("--supervisor-mode")
    # Preserve the benchmark command as a single shell input line. The remote
    # command path writes to the interactive shell PTY; splitting here breaks
    # platform shell quoting such as `sh -lc '...'`.
    invocation.extend(["--", command])

    result = local_command(
        invocation,
        cwd=ROOT,
        timeout=timeout + 10,
        env=tamandua_ctl_env(args.tamandua_ctl_server),
    )
    command_result = dataclasses.asdict(result)
    if args.tamandua_ctl_token:
        command_result["command"] = str(command_result.get("command") or "").replace(
            args.tamandua_ctl_token,
            "<redacted-token>",
        )
    parsed: dict[str, Any] = {
        "outer_exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "guest_exit_code": 0 if result.exit_code == 0 else result.exit_code,
        "guest_stdout": "",
        "guest_stderr": result.stderr,
        "transport": "tamandua_ctl_live_response",
        "command_result": command_result,
    }
    live_response_error = classify_live_response_execution_error(parsed)
    if result.exit_code not in (0, None) and live_response_error:
        parsed["error_code"] = live_response_error
        parsed["error"] = result.stderr or result.stdout or "tamandua-ctl live-response transport failed"
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return parsed
    parsed["tamandua_ctl_payload"] = payload
    parsed["guest_stdout"] = str(payload.get("output") or "")
    parsed["live_response_session_id"] = payload.get("session_id")
    payload_exit_code = payload.get("exit_code", payload.get("exitcode"))
    if isinstance(payload_exit_code, bool):
        payload_exit_code = int(payload_exit_code)
    elif isinstance(payload_exit_code, str):
        try:
            payload_exit_code = int(payload_exit_code.strip())
        except ValueError:
            payload_exit_code = None
    elif not isinstance(payload_exit_code, int):
        payload_exit_code = None
    if payload_exit_code is not None:
        parsed["guest_exit_code"] = payload_exit_code
    parsed["live_response_audit"] = {
        "resource_type": payload.get("audit_resource_type"),
        "resource_id": payload.get("audit_resource_id"),
        "end_reason": payload.get("end_reason"),
        "duration_ms": payload.get("duration_ms"),
    }
    status = str(payload.get("status") or "")
    if result.exit_code == 0:
        shell_ready = payload.get("shell_ready")
        unconfirmed_dispatch = payload.get("unconfirmed_dispatch") is True
        output = str(payload.get("output") or "")
        events = payload.get("events") if isinstance(payload.get("events"), list) else []
        event_types = [
            str(event.get("type") or event.get("event") or "")
            for event in events
            if isinstance(event, dict)
        ]

        if unconfirmed_dispatch:
            parsed["outer_exit_code"] = 1
            parsed["guest_exit_code"] = 1
            parsed["error_code"] = "live_response_shell_unconfirmed"
            parsed["error"] = (
                "tamandua-ctl dispatched command before confirmed shell readiness "
                f"(shell_ready={shell_ready!r}, events={event_types})"
            )
        elif shell_ready is False or status == "shell_not_ready":
            parsed["outer_exit_code"] = 1
            parsed["guest_exit_code"] = 1
            parsed["error_code"] = "live_response_shell_not_ready"
            parsed["error"] = (
                "tamandua-ctl completed without a ready shell "
                f"(shell_ready={shell_ready!r}, events={event_types})"
            )
        elif not output and any(event_type == "shell_start_unconfirmed_dispatch" for event_type in event_types):
            parsed["outer_exit_code"] = 1
            parsed["guest_exit_code"] = 1
            parsed["error_code"] = "live_response_no_output_unconfirmed"
            parsed["error"] = (
                "tamandua-ctl completed with empty output after unconfirmed shell dispatch"
            )
        elif marker := expected_command_marker(command):
            if marker not in output:
                parsed["outer_exit_code"] = 1
                parsed["guest_exit_code"] = 1
                parsed["error_code"] = "live_response_command_marker_missing"
                parsed["error"] = (
                    "tamandua-ctl completed without the expected command marker in output "
                    f"(marker={marker})"
                )
        elif status not in {"completed"}:
            parsed["outer_exit_code"] = 1
            parsed["guest_exit_code"] = 1
            parsed["error_code"] = "live_response_command_not_completed"
            parsed["error"] = f"tamandua-ctl remote command ended with status={status or 'unknown'}"
    return parsed


def endpoint_ssh_command(endpoint: SshHost, command: str, timeout: int) -> dict[str, Any]:
    result = endpoint.run(command, timeout=timeout)
    return {
        "outer_exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "guest_exit_code": result.exit_code,
        "guest_stdout": result.stdout,
        "guest_stderr": result.stderr,
        "transport": "endpoint_ssh",
        "command_result": dataclasses.asdict(result),
    }


def expected_command_marker(command: str) -> str | None:
    match = re.search(r"tamandua-semantic-rewrite-[A-Za-z0-9_.:-]+", command)
    return match.group(0) if match else None


def tamandua_ctl_agent_state(args: argparse.Namespace) -> dict[str, Any]:
    ctl_path = Path(args.tamandua_ctl_path)
    ctl = str(ctl_path if ctl_path.exists() else args.tamandua_ctl_path)
    invocation = [ctl, "--json", "remote", "agents", "list"]
    if args.tamandua_ctl_server:
        invocation.extend(["--server", args.tamandua_ctl_server])
    if args.tamandua_ctl_token:
        invocation.extend(["--token", args.tamandua_ctl_token])

    result = local_command(
        invocation,
        cwd=ROOT,
        timeout=45,
        env=tamandua_ctl_env(args.tamandua_ctl_server),
    )
    state: dict[str, Any] = {
        "transport": "tamandua_ctl_agents_list",
        "command_result": dataclasses.asdict(result),
        "agent": None,
    }
    if result.exit_code != 0:
        state["error"] = result.stderr or result.stdout or "tamandua-ctl agents list failed"
        state["error_code"] = classify_live_response_execution_error(
            {"transport": "tamandua_ctl_live_response", "stderr": state["error"]}
        ) or "tamandua_ctl_agents_list_failed"
        return state

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        state["error"] = f"invalid tamandua-ctl agents list JSON: {exc}"
        state["error_code"] = "tamandua_ctl_agents_list_invalid_json"
        return state

    agents = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(agents, list):
        state["error"] = "tamandua-ctl agents list returned no agent list"
        state["error_code"] = "tamandua_ctl_agents_list_unexpected_shape"
        state["payload"] = payload
        return state

    target_id = str(args.agent_id or "")
    target_hostname = str(args.agent_hostname or "")
    selected = None
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        if target_id and str(agent.get("id") or agent.get("agent_id") or "") == target_id:
            selected = agent
            break
        if target_hostname and str(agent.get("hostname") or "").lower() == target_hostname.lower():
            selected = agent
            break

    state["agent_count"] = len(agents)
    state["agent"] = selected
    if selected is None:
        state["error"] = f"target agent not found in tamandua-ctl agents list: {target_id or target_hostname or '<unset>'}"
        state["error_code"] = "tamandua_ctl_target_agent_missing"
    return state


def evaluate_tamandua_ctl_agent_readiness(
    live_state: dict[str, Any],
    freshness_seconds: int,
) -> dict[str, Any]:
    issues: list[str] = []
    agent = live_state.get("agent")
    if live_state.get("error"):
        issues.append(str(live_state.get("error_code") or "tamandua_ctl_agent_state_error"))
    if not isinstance(agent, dict):
        issues.append("tamandua_ctl_agent_missing")
        return {
            "ready": False,
            "issues": issues,
            "status": None,
            "last_seen_at": None,
            "last_seen_age_seconds": None,
            "freshness_seconds": freshness_seconds,
            "source": "tamandua-ctl",
        }

    status = str(agent.get("status") or "").lower()
    health_status = agent.get("health_status") if isinstance(agent.get("health_status"), dict) else {}
    health_metrics = health_status.get("metrics") if isinstance(health_status.get("metrics"), dict) else {}
    heartbeat_age_ms = health_metrics.get("heartbeat_age_ms")
    heartbeat_last_seen_ms = health_metrics.get("last_seen_at")
    last_seen_value = agent.get("last_seen")
    if heartbeat_last_seen_ms is not None:
        last_seen = parse_agent_timestamp(heartbeat_last_seen_ms)
        last_seen_source = "health_status.metrics.last_seen_at"
    else:
        last_seen = parse_agent_timestamp(last_seen_value)
        last_seen_source = "last_seen"
    age_seconds: float | None = None
    if status != "online":
        issues.append(f"agent_status_{status or 'unknown'}")
    if isinstance(heartbeat_age_ms, (int, float)):
        age_seconds = max(0.0, float(heartbeat_age_ms) / 1000.0)
        if freshness_seconds >= 0 and age_seconds > freshness_seconds:
            issues.append(f"agent_heartbeat_stale_{int(age_seconds)}s")
    elif last_seen is None:
        issues.append("agent_last_seen_missing_or_unparseable")
    else:
        age_seconds = max(0.0, (utc_now() - last_seen).total_seconds())
        if freshness_seconds >= 0 and age_seconds > freshness_seconds:
            issues.append(f"agent_last_seen_stale_{int(age_seconds)}s")

    return {
        "ready": not issues,
        "issues": issues,
        "status": status or None,
        "last_seen_at": last_seen_value,
        "last_seen_source": last_seen_source,
        "last_seen_age_seconds": age_seconds,
        "heartbeat_age_ms": heartbeat_age_ms,
        "freshness_seconds": freshness_seconds,
        "source": "tamandua-ctl",
        "health_status": health_status.get("status"),
    }


def combine_agent_readiness_for_tamandua_ctl(
    db_readiness: dict[str, Any],
    live_readiness: dict[str, Any],
    block_critical_health: bool = False,
) -> dict[str, Any]:
    warnings: list[str] = []
    db_issues = list(db_readiness.get("issues") or [])
    live_health = str(live_readiness.get("health_status") or "").lower()
    if block_critical_health and live_health in {"critical", "unhealthy"}:
        return {
            "ready": False,
            "issues": [f"agent_health_{live_health}"] + list(live_readiness.get("issues") or []) + db_issues,
            "source": "tamandua-ctl-live",
            "live": live_readiness,
            "database": db_readiness,
        }

    if live_readiness.get("ready"):
        if db_issues:
            warnings.append("db_agent_state_stale_or_inconsistent")
        return {
            "ready": True,
            "issues": [],
            "warnings": warnings,
            "source": "tamandua-ctl-live",
            "live": live_readiness,
            "database": db_readiness,
        }

    return {
        "ready": False,
        "issues": list(live_readiness.get("issues") or []) + db_issues,
        "source": "tamandua-ctl-live",
        "live": live_readiness,
        "database": db_readiness,
    }


def poll_guest_exec_status(
    proxmox: SshHost,
    vmid: int,
    pid: int,
    initial: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(5, timeout)
    last_result: CommandResult | None = None
    poll_command = shlex.join(["qm", "guest", "exec-status", str(vmid), str(pid)])

    while time.monotonic() < deadline:
        time.sleep(2)
        last_result = proxmox.run(poll_command, timeout=30)
        parsed = parse_qm_guest_exec(last_result)
        payload = parsed.get("qm_payload")
        if isinstance(payload, dict) and payload.get("exited"):
            parsed["waited_for_pid"] = pid
            parsed["initial_qm_payload"] = initial.get("qm_payload")
            parsed["exec_status_command_result"] = dataclasses.asdict(last_result)
            return parsed

    timed_out = dict(initial)
    timed_out["waited_for_pid"] = pid
    timed_out["exec_status_timed_out"] = True
    if last_result is not None:
        timed_out["exec_status_command_result"] = dataclasses.asdict(last_result)
    return timed_out


def command_exists_on_guest(proxmox: SshHost, vmid: int, command_name: str) -> bool:
    probe = guest_command(
        proxmox,
        vmid,
        powershell_command_line(
            f"if (Get-Command {powershell_single_quote(command_name)} -ErrorAction SilentlyContinue) {{ 'yes' }}"
        ),
        timeout=60,
    )
    return "yes" in (probe.get("guest_stdout") or "")


def ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_atomic_command(test: dict[str, Any], args: argparse.Namespace | None = None) -> str:
    atomic = test.get("atomic") or {}
    technique = atomic.get("technique") or test["id"]
    numbers = atomic.get("test_numbers") or []
    atomics_path = (
        getattr(args, "atomic_path_to_atomics", None)
        if args is not None
        else None
    ) or os.getenv("ATOMIC_PATH_TO_ATOMICS") or os.getenv("ATOMIC_RED_TEAM_PATH")

    invoke_args = [f"Invoke-AtomicTest {technique}"]
    if numbers:
        joined = ",".join(str(number) for number in numbers)
        invoke_args.append(f"-TestNumbers {joined}")
    if atomics_path:
        invoke_args.append(f"-PathToAtomicsFolder {ps_single_quote(atomics_path)}")

    prereq = " ".join([*invoke_args, "-GetPrereqs"])
    run = " ".join(invoke_args)
    command_parts = [
        "if (-not (Get-PSDrive C -ErrorAction SilentlyContinue)) { $root = $env:SystemDrive + '\\'; New-PSDrive -Name C -PSProvider FileSystem -Root $root -Scope Global | Out-Null }",
        "Import-Module Invoke-AtomicRedTeam -ErrorAction Stop",
        "Get-Command Invoke-AtomicTest -ErrorAction Stop | Out-Null",
        prereq,
        run,
    ]

    return powershell_command_line("; ".join(command_parts))


def build_atomic_cleanup_command(test: dict[str, Any], args: argparse.Namespace | None = None) -> str | None:
    atomic = test.get("atomic") or {}
    technique = atomic.get("technique")
    if not technique:
        return None

    numbers = atomic.get("test_numbers") or []
    atomics_path = (
        getattr(args, "atomic_path_to_atomics", None)
        if args is not None
        else None
    ) or os.getenv("ATOMIC_PATH_TO_ATOMICS") or os.getenv("ATOMIC_RED_TEAM_PATH")

    invoke_args = [f"Invoke-AtomicTest {technique}"]
    if numbers:
        joined = ",".join(str(number) for number in numbers)
        invoke_args.append(f"-TestNumbers {joined}")
    if atomics_path:
        invoke_args.append(f"-PathToAtomicsFolder {ps_single_quote(atomics_path)}")

    command_parts = [
        "if (-not (Get-PSDrive C -ErrorAction SilentlyContinue)) { $root = $env:SystemDrive + '\\'; New-PSDrive -Name C -PSProvider FileSystem -Root $root -Scope Global | Out-Null }",
        "Import-Module Invoke-AtomicRedTeam -ErrorAction Stop",
        "Get-Command Invoke-AtomicTest -ErrorAction Stop | Out-Null",
        " ".join([*invoke_args, "-Cleanup"]),
    ]
    return powershell_command_line("; ".join(command_parts))


def normalize_guest_command(command: str) -> str:
    command = command.strip()
    return add_cmd_dwell(command)


def add_cmd_dwell(command: str, seconds: int = 8) -> str:
    """Keep cmd.exe-backed deterministic tests observable by polling collectors."""
    stripped = command.strip()
    lower = stripped.lower()
    if seconds <= 0 or not lower.startswith("cmd.exe ") or " /c " not in lower:
        return stripped

    dwell = f" & ping -n {max(2, seconds + 1)} 127.0.0.1 > nul"
    if stripped.endswith('"'):
        return stripped[:-1] + dwell + '"'
    return stripped + dwell


def resolve_test_command(
    test: dict[str, Any],
    atomic_available: bool,
    args: argparse.Namespace | None = None,
) -> tuple[str, str]:
    executor = test.get("executor", "command")
    if executor == "caldera_operation":
        return "caldera_operation", "caldera_operation"
    if executor == "atomic_or_command" and atomic_available and test.get("atomic"):
        return "atomic_red_team", build_atomic_command(test, args)
    return "command", normalize_guest_command(test.get("fallback_command", ""))


def executor_metadata(
    test: dict[str, Any],
    executor_used: str,
    atomic_available: bool,
    args: argparse.Namespace | None = None,
) -> dict[str, Any]:
    requested = test.get("executor", "command")
    atomic_configured = bool(test.get("atomic"))
    fallback_used = requested == "atomic_or_command" and executor_used == "command"
    if executor_used == "atomic_red_team":
        label = "Atomic Red Team"
    elif executor_used == "caldera_operation":
        label = "CALDERA operation"
    elif fallback_used:
        label = "Deterministic fallback command"
    else:
        label = "Deterministic command"

    fallback_reason = None
    if fallback_used:
        if not atomic_configured:
            fallback_reason = "test has no atomic block"
        elif not atomic_available:
            fallback_reason = "Invoke-AtomicTest was not available on the target"

    if executor_used == "atomic_red_team":
        execution_class = "upstream"
        upstream_tool = "atomic_red_team"
    elif executor_used == "caldera_operation":
        execution_class = "upstream"
        upstream_tool = "caldera"
    elif fallback_used:
        execution_class = "fallback"
        upstream_tool = "atomic_red_team"
    else:
        execution_class = "deterministic"
        upstream_tool = None

    claim_level = claim_level_for_executor(executor_used, fallback_used=fallback_used)
    return {
        "executor_requested": requested,
        "executor_used": executor_used,
        "executor_label": label,
        "claim_level": claim_level,
        "execution_class": execution_class,
        "provenance": {
            "execution_class": execution_class,
            "claim_level": claim_level,
            "upstream_tool": upstream_tool,
            "upstream_backed": executor_used in {"atomic_red_team", "caldera_operation"},
            "fallback_used": bool(fallback_used),
            "fallback_reason": fallback_reason,
        },
        "upstream_available": {
            "atomic_red_team": bool(atomic_available),
        },
        "atomic": {
            "technique": (test.get("atomic") or {}).get("technique"),
            "test_numbers": (test.get("atomic") or {}).get("test_numbers") or [],
            "path_to_atomics": getattr(args, "atomic_path_to_atomics", None) if args is not None else None,
            "cleanup": bool(getattr(args, "atomic_cleanup", False)) if args is not None else False,
        } if requested == "atomic_or_command" or executor_used == "atomic_red_team" else None,
        "upstream_backed": executor_used in {"atomic_red_team", "caldera_operation"},
        "fallback_used": bool(fallback_used),
        "fallback_reason": fallback_reason,
    }


def claim_level_for_executor(executor: str, fallback_used: bool = False) -> str:
    if executor == "atomic_red_team":
        return "atomic_red_team"
    if executor == "caldera_operation":
        return "caldera_operation"
    if fallback_used:
        return "fallback"
    if executor == "command":
        return "deterministic"
    return "unknown"


def evidence_source_counts(event_rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in event_rows:
        source = str(row.get("source_name") or "unknown")
        counts[source] = counts.get(source, 0) + int(row.get("count") or 0)
    return dict(sorted(counts.items()))


def caldera_request(
    args: argparse.Namespace,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    if not args.caldera_url:
        raise RunnerError("--caldera-url is required for caldera_operation tests")

    url = args.caldera_url.rstrip("/") + path
    data = None
    headers = {"Content-Type": "application/json"}
    api_key = args.caldera_api_key or os.getenv("CALDERA_API_KEY")
    if api_key:
        headers["KEY"] = api_key

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    started = time.monotonic()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode(errors="replace")
            parsed = json.loads(body) if body.strip() else {}
            return {
                "url": url,
                "method": method,
                "status": response.status,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "body": parsed,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        return {
            "url": url,
            "method": method,
            "status": exc.code,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": body,
        }
    except Exception as exc:
        return {
            "url": url,
            "method": method,
            "status": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def caldera_operation_from_list(body: Any, operation_id: str | None) -> dict[str, Any]:
    if not operation_id:
        return {}
    if isinstance(body, dict):
        operations = body.get("operations") or body.get("data") or body.get("results") or []
    else:
        operations = body
    if not isinstance(operations, list):
        return {}
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        candidate = operation.get("id") or operation.get("operation_id") or operation.get("uuid")
        if str(candidate or "") == str(operation_id):
            return operation
    return {}


def caldera_agent_like(candidate: dict[str, Any]) -> bool:
    return any(key in candidate for key in ("paw", "host", "host_name")) and any(
        key in candidate for key in ("group", "last_seen", "platform", "pid", "privilege")
    )


def caldera_agents_from_body(body: Any) -> list[dict[str, Any]]:
    """Extract CALDERA agents from common list, wrapper, or paw-keyed shapes."""

    found: list[dict[str, Any]] = []
    seen: set[int] = set()

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
            return
        if not isinstance(value, dict):
            return
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)
        if caldera_agent_like(value):
            found.append(value)
            return
        for key in ("agents", "data", "results", "objects", "paws"):
            if key in value:
                visit(value.get(key), depth + 1)
        for nested in value.values():
            if isinstance(nested, (dict, list)):
                visit(nested, depth + 1)

    visit(body)
    return found


def caldera_agent_snapshot(agent: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(agent, dict):
        return None
    keys = [
        "paw",
        "group",
        "host",
        "host_name",
        "platform",
        "last_seen",
        "sleep_min",
        "sleep_max",
        "pid",
        "ppid",
        "location",
        "server",
        "privilege",
    ]
    return {key: agent.get(key) for key in keys if key in agent}


def preflight_caldera_agent(args: argparse.Namespace) -> dict[str, Any]:
    started_at = utc_now()
    request = caldera_request(args, "GET", "/api/v2/agents", timeout=30)
    proof: dict[str, Any] = {
        "started_at": iso(started_at),
        "ended_at": iso(utc_now()),
        "url": request.get("url"),
        "status": request.get("status"),
        "duration_ms": request.get("duration_ms"),
        "requested_paw": args.caldera_agent_paw,
        "requested_group": args.caldera_group,
        "freshness_seconds": args.caldera_agent_freshness_seconds,
        "ready": False,
        "issues": [],
    }
    if request.get("status") != 200:
        proof["issues"] = ["caldera_agent_preflight_api_error"]
        proof["error"] = request.get("error") or f"HTTP {request.get('status')}"
        return proof

    agents = caldera_agents_from_body(request.get("body"))
    proof["agent_count"] = len(agents)
    agent = next((candidate for candidate in agents if str(candidate.get("paw") or "") == str(args.caldera_agent_paw)), None)
    proof["agent"] = caldera_agent_snapshot(agent)
    if not agent:
        proof["issues"] = ["caldera_agent_paw_not_found"]
        proof["known_paws"] = [
            {
                "paw": candidate.get("paw"),
                "group": candidate.get("group"),
                "host": candidate.get("host") or candidate.get("host_name"),
                "last_seen": candidate.get("last_seen"),
            }
            for candidate in agents[:20]
        ]
        return proof

    group = str(agent.get("group") or "")
    if args.caldera_group and group != str(args.caldera_group):
        proof["issues"].append("caldera_agent_group_mismatch")
        proof["actual_group"] = group

    last_seen = parse_agent_timestamp(agent.get("last_seen"))
    proof["last_seen_at"] = agent.get("last_seen")
    age_seconds: float | None = None
    if last_seen is None:
        proof["issues"].append("caldera_agent_last_seen_missing_or_unparseable")
    else:
        age_seconds = max(0.0, (utc_now() - last_seen).total_seconds())
        proof["last_seen_age_seconds"] = age_seconds
        if args.caldera_agent_freshness_seconds >= 0 and age_seconds > args.caldera_agent_freshness_seconds:
            proof["issues"].append(f"caldera_agent_stale_{int(age_seconds)}s")

    proof["ready"] = not proof["issues"]
    proof["ended_at"] = iso(utc_now())
    return proof


def run_caldera_operation(args: argparse.Namespace, test: dict[str, Any]) -> dict[str, Any]:
    caldera = test.get("caldera") or {}
    adversary_id = caldera.get("adversary_id") or args.caldera_adversary_id
    trace_step(f"caldera operation start test={test.get('id')} adversary={adversary_id}")
    ability_ids = [
        ability.get("ability_id") or ability.get("id")
        for ability in caldera.get("abilities", [])
        if isinstance(ability, dict) and (ability.get("ability_id") or ability.get("id"))
    ]
    proof: dict[str, Any] = {
        "requested_adversary_id": adversary_id,
        "adversary_id": adversary_id,
        "configured_adversary_profile": caldera.get("adversary_profile"),
        "expected_abilities": caldera.get("abilities", []),
        "ability_ids": ability_ids,
        "group": args.caldera_group,
        "paw": args.caldera_agent_paw,
        "operation_id": None,
        "final_state": None,
        "poll_count": 0,
        "started_at": iso(utc_now()),
        "ended_at": None,
        "success": False,
    }
    if not adversary_id:
        return {
            "outer_exit_code": 2,
            "error": "caldera_operation requires caldera.adversary_id in the profile or --caldera-adversary-id",
            "caldera": caldera,
            "caldera_proof": proof,
        }

    agent_preflight = preflight_caldera_agent(args)
    proof["agent_preflight"] = agent_preflight
    if not agent_preflight.get("ready"):
        proof["ended_at"] = iso(utc_now())
        issues = list(agent_preflight.get("issues") or ["caldera_agent_preflight_failed"])
        if "caldera_agent_paw_not_found" in issues:
            error_code = "caldera_agent_paw_not_found"
        elif "caldera_agent_group_mismatch" in issues:
            error_code = "caldera_agent_group_mismatch"
        elif any(str(issue).startswith("caldera_agent_stale_") for issue in issues):
            error_code = "caldera_agent_stale_or_offline"
        elif "caldera_agent_preflight_api_error" in issues:
            error_code = "caldera_agent_preflight_failed"
        else:
            error_code = "caldera_agent_not_ready"
        return {
            "outer_exit_code": 1,
            "error_code": error_code,
            "error": (
                "CALDERA agent preflight failed before operation creation: "
                + ", ".join(str(issue) for issue in issues)
            ),
            "caldera": caldera,
            "caldera_agent_preflight": agent_preflight,
            "caldera_proof": proof,
        }

    operation_payload = {
        "name": f"tamandua-{test.get('id')}-{int(time.time())}",
        "adversary": {"adversary_id": adversary_id},
        "group": args.caldera_group,
        "state": "running",
    }
    if args.caldera_agent_paw:
        operation_payload["paw"] = args.caldera_agent_paw

    create = caldera_request(args, "POST", "/api/v2/operations", operation_payload, timeout=60)
    trace_step(
        "caldera operation create "
        f"test={test.get('id')} status={create.get('status')} duration_ms={create.get('duration_ms')}"
    )
    operation = create.get("body") if isinstance(create.get("body"), dict) else {}
    operation_id = (
        operation.get("id")
        or operation.get("operation_id")
        or operation.get("uuid")
        or operation.get("id".upper())
    )

    result: dict[str, Any] = {
        "outer_exit_code": 0 if create.get("status") in {200, 201, 202} else 1,
        "caldera_operation_payload": operation_payload,
        "caldera_create": create,
        "caldera_operation_id": operation_id,
        "caldera": caldera,
        "caldera_proof": proof,
    }
    proof["operation_id"] = operation_id
    if result["outer_exit_code"] != 0 or not operation_id:
        proof["ended_at"] = iso(utc_now())
        result["error"] = "failed to create CALDERA operation or operation id was missing"
        return result

    deadline = time.monotonic() + max(30, args.caldera_timeout_seconds)
    polls: list[dict[str, Any]] = []
    final_state = None
    terminal_states = {"finished", "complete", "completed", "paused", "stopped"}
    success_states = {"finished", "complete", "completed"}
    while time.monotonic() < deadline:
        # The operation detail endpoint can block while CALDERA is still
        # building a large chain. Poll the operation list for liveness/state and
        # fetch the full chain only after a terminal state.
        poll = caldera_request(args, "GET", "/api/v2/operations", timeout=20)
        polls.append(poll)
        body = caldera_operation_from_list(poll.get("body"), operation_id)
        final_state = body.get("state") or body.get("status")
        trace_step(
            "caldera operation poll "
            f"operation={operation_id} count={len(polls)} state={final_state} "
            f"status={poll.get('status')} duration_ms={poll.get('duration_ms')}"
        )
        if str(final_state).lower() in terminal_states:
            break
        time.sleep(max(2, args.caldera_poll_seconds))

    result["caldera_polls"] = polls[-20:]
    result["caldera_final_state"] = final_state
    final_body = {}
    if str(final_state).lower() in terminal_states:
        detail = caldera_request(args, "GET", f"/api/v2/operations/{operation_id}", timeout=20)
        result["caldera_final_detail"] = detail
        final_body = detail.get("body") if isinstance(detail.get("body"), dict) else {}
        if not final_body:
            final_body = caldera_operation_from_list((polls[-1] or {}).get("body"), operation_id) if polls else {}
    elif polls:
        final_body = caldera_operation_from_list((polls[-1] or {}).get("body"), operation_id)
    chain = final_body.get("chain") if isinstance(final_body, dict) else []
    host_group = final_body.get("host_group") if isinstance(final_body, dict) else []
    proof["chain_count"] = len(chain) if isinstance(chain, list) else 0
    proof["host_count"] = len(host_group) if isinstance(host_group, list) else 0
    proof["executed_link_count"] = 0
    proof["successful_link_count"] = 0
    proof["failed_link_count"] = 0
    expected_ability_ids = {
        str(ability.get("ability_id") or ability.get("id") or "")
        for ability in (caldera.get("abilities") or [])
        if isinstance(ability, dict) and (ability.get("ability_id") or ability.get("id"))
    }
    proof["expected_ability_ids"] = sorted(expected_ability_ids)
    proof["executed_ability_ids"] = []
    proof["missing_ability_ids"] = sorted(expected_ability_ids)
    if isinstance(chain, list):
        target_links = [
            link
            for link in chain
            if isinstance(link, dict) and str(link.get("paw") or "") == str(args.caldera_agent_paw or link.get("paw") or "")
        ]
        primary_links = [link for link in target_links if int(link.get("cleanup") or 0) == 0]
        cleanup_links = [link for link in target_links if int(link.get("cleanup") or 0) != 0]
        proof["cleanup_link_count"] = len(cleanup_links)
        proof["cleanup_failed_link_count"] = len(
            [
                link
                for link in cleanup_links
                if link.get("status") is not None and str(link.get("status")) not in {"0", "-3"}
            ]
        )
        proof["executed_link_count"] = len(primary_links)
        proof["successful_link_count"] = len(
            [link for link in primary_links if str(link.get("status")) == "0"]
        )
        proof["failed_link_count"] = len(
            [
                link
                for link in primary_links
                if link.get("status") is not None and str(link.get("status")) not in {"0", "-3"}
            ]
        )
        executed_ability_ids = set()
        for link in primary_links:
            ability = link.get("ability")
            ability_id = None
            if isinstance(ability, dict):
                ability_id = ability.get("ability_id") or ability.get("id")
            elif ability:
                ability_id = ability
            if not ability_id:
                ability_id = link.get("ability_id") or link.get("ABILITY_ID")
            if not ability_id and isinstance(link.get("ability_metadata"), dict):
                ability_id = link["ability_metadata"].get("ability_id")
            if ability_id:
                executed_ability_ids.add(str(ability_id))
        proof["executed_ability_ids"] = sorted(executed_ability_ids)
        proof["missing_ability_ids"] = sorted(expected_ability_ids - executed_ability_ids)
    proof["final_state"] = final_state
    proof["poll_count"] = len(polls)
    proof["ended_at"] = iso(utc_now())
    if str(final_state).lower() not in terminal_states:
        cleanup = caldera_request(
            args,
            "PATCH",
            f"/api/v2/operations/{operation_id}",
            {"state": "stopped"},
            timeout=20,
        )
        result["caldera_cleanup"] = {
            "strategy": "stop_stuck_operation",
            "request": cleanup,
            "attempted_at": iso(utc_now()),
        }
        trace_step(
            "caldera operation cleanup "
            f"operation={operation_id} status={cleanup.get('status')} error={cleanup.get('error')}"
        )
    proof["success"] = (
        str(final_state).lower() in success_states
        and proof["executed_link_count"] > 0
        and proof["successful_link_count"] > 0
        and not proof["missing_ability_ids"]
        and proof["failed_link_count"] == 0
    )
    trace_step(
        "caldera operation result "
        f"operation={operation_id} state={final_state} success={proof['success']} "
        f"links={proof['successful_link_count']}/{proof['executed_link_count']} "
        f"failed={proof['failed_link_count']} missing={len(proof['missing_ability_ids'])}"
    )
    if not proof["success"]:
        result["outer_exit_code"] = 1
        if str(final_state or "").lower() not in terminal_states:
            result["error_code"] = "caldera_operation_timeout_stopped"
            result["error"] = (
                f"CALDERA operation did not reach a terminal state before timeout: "
                f"state={final_state or 'timeout'} links={proof['executed_link_count']}; "
                "stop cleanup was attempted"
            )
        elif str(final_state).lower() in success_states and proof["executed_link_count"] == 0:
            result["error_code"] = "caldera_no_executed_links_or_stale_paw"
            result["error"] = (
                "CALDERA operation finished without executed links. "
                "This usually means the selected paw is stale/offline or the adversary has no runnable "
                f"abilities for the target: state={final_state} links=0"
            )
        elif proof["failed_link_count"] > 0:
            result["error_code"] = "caldera_link_failures"
            result["error"] = (
                "CALDERA operation finished but one or more links returned a non-zero status: "
                f"state={final_state} executed={proof['executed_link_count']} "
                f"failed={proof['failed_link_count']}"
            )
        elif proof["missing_ability_ids"]:
            result["error_code"] = "caldera_missing_ability_links"
            result["error"] = (
                "CALDERA operation did not execute every expected ability: "
                f"missing={', '.join(proof['missing_ability_ids'])}"
            )
        else:
            result["error_code"] = "caldera_operation_not_completed"
            result["error"] = (
                f"CALDERA operation did not finish with executed links: "
                f"state={final_state or 'timeout'} links={proof['executed_link_count']}"
            )
    return result


def validate_caldera_profile(args: argparse.Namespace, tests: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for test in tests:
        if test.get("executor") != "caldera_operation":
            continue

        caldera = test.get("caldera") or {}
        if not (caldera.get("adversary_id") or args.caldera_adversary_id):
            errors.append(
                f"{test.get('id')}: caldera_operation requires caldera.adversary_id "
                "or --caldera-adversary-id"
            )
        if not args.caldera_url:
            errors.append(f"{test.get('id')}: caldera_operation requires --caldera-url")
        if not (args.caldera_api_key or os.getenv("CALDERA_API_KEY")):
            errors.append(f"{test.get('id')}: caldera_operation requires --caldera-api-key or CALDERA_API_KEY")
        if not args.caldera_agent_paw:
            errors.append(
                f"{test.get('id')}: caldera_operation requires --caldera-agent-paw for audit-safe target binding"
            )
        if caldera.get("adversary_profile") and not caldera.get("adversary_id") and not args.caldera_adversary_id:
            errors.append(
                f"{test.get('id')}: adversary_profile is documentation only; provide a real adversary_id"
            )

    return errors


def collect_guest_preflight(proxmox: SshHost, vmid: int) -> dict[str, Any]:
    # Keep probes separate. Chained cmd.exe commands over QGA are fragile on the
    # Windows lab VM and can make a healthy guest look unavailable.
    probes = {
        "hostname": ("cmd.exe /d /c hostname", 8),
        "agent_service": ("cmd.exe /d /c sc.exe query TamanduaAgent", 10),
        "agent_task": (
            'cmd.exe /d /c schtasks.exe /Query /TN TamanduaAgentForeground /FO LIST',
            10,
        ),
        "agent_process": (
            'cmd.exe /d /c tasklist.exe /FI "IMAGENAME eq tamandua-agent.exe" /FO CSV /NH',
            10,
        ),
        "driver_service": ("cmd.exe /d /c sc.exe query tamandua", 10),
        "driver_filters": ("cmd.exe /d /c fltmc filters", 10),
    }
    results: dict[str, dict[str, Any]] = {}

    for name, (command, timeout) in probes.items():
        try:
            results[name] = guest_command(proxmox, vmid, command, timeout=timeout, retries=0)
        except Exception as exc:
            results[name] = {"error": str(exc), "guest_stdout": "", "guest_stderr": ""}

    hostname_stdout = results["hostname"].get("guest_stdout") or ""
    agent_stdout = results["agent_service"].get("guest_stdout") or ""
    agent_task_stdout = results["agent_task"].get("guest_stdout") or ""
    agent_process_stdout = results["agent_process"].get("guest_stdout") or ""
    driver_stdout = results["driver_service"].get("guest_stdout") or ""
    filters_stdout = results["driver_filters"].get("guest_stdout") or ""

    return {
        "outer_exit_code": max(
            int((result.get("outer_exit_code") or 0) != 0) for result in results.values()
        ),
        "stdout": "\n".join(str(result.get("stdout") or "") for result in results.values()),
        "stderr": "\n".join(str(result.get("stderr") or "") for result in results.values()),
        "guest_stdout": "\n".join(
            str(result.get("guest_stdout") or "") for result in results.values()
        ),
        "guest_stderr": "\n".join(
            str(result.get("guest_stderr") or "") for result in results.values()
        ),
        "probes": results,
        "preflight": {
            "hostname": parse_windows_hostname_output(hostname_stdout),
            "agent_service": parse_sc_state(agent_stdout),
            "agent_task_state": parse_schtasks_state(agent_task_stdout),
            "agent_process_running": "tamandua-agent" in agent_process_stdout.lower(),
            "agent_process_count": count_tasklist_processes(agent_process_stdout, "tamandua-agent"),
            "driver_service": parse_sc_state(driver_stdout),
            "driver_loaded": "tamandua" in filters_stdout.lower(),
            "raw": "\n".join(
                [
                    hostname_stdout,
                    agent_stdout,
                    agent_task_stdout,
                    agent_process_stdout,
                    driver_stdout,
                    filters_stdout,
                ]
            )[-8000:],
        },
    }


def extract_marker_block(text: str, marker: str) -> str:
    start = f"{marker}_BEGIN"
    end = f"{marker}_END"
    if start not in text or end not in text:
        return ""
    return text.split(start, 1)[1].split(end, 1)[0].strip()


def parse_sc_state(text: str) -> str | None:
    match = re.search(r"(?:STATE|ESTADO)\s*:\s*\d+\s+([A-Z_]+)", text, re.IGNORECASE)
    return match.group(1).lower() if match else None


def parse_windows_hostname_output(text: str) -> str | None:
    candidates: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("microsoft windows") or "todos os direitos" in lower:
            continue
        if re.match(r"^[a-z]:\\.*>", lower):
            continue
        if lower in {"exit", "hostname"}:
            continue
        if lower.endswith(">exit") or "hostname" in lower and ">" in lower:
            continue
        candidates.append(line)
    return candidates[-1] if candidates else (text.strip() or None)


def parse_schtasks_state(text: str) -> str | None:
    match = re.search(r"^(?:Status|Estado)\s*:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip().lower() if match else None


def count_tasklist_processes(text: str, image_prefix: str) -> int:
    image = image_prefix.lower()
    return sum(1 for line in text.splitlines() if line.lower().strip().strip('"').startswith(image))


def evaluate_preflight_readiness(preflight_result: dict[str, Any]) -> dict[str, Any]:
    fingerprint = preflight_result.get("preflight") if isinstance(preflight_result, dict) else {}
    if not isinstance(fingerprint, dict):
        fingerprint = {}

    issues: list[str] = []
    service_state = str(fingerprint.get("agent_service") or "").lower()
    task_state = str(fingerprint.get("agent_task_state") or "").lower()
    process_count = fingerprint.get("agent_process_count")
    process_running = process_count == 1
    service_running = service_state == "running"

    # Some Windows lab builds/locales return only the hostname for
    # `sc.exe query TamanduaAgent` over QGA even while the service process is
    # clearly running in session 0. Treat that as a degraded preflight signal,
    # not as a hard infrastructure block for detection benchmarks.
    if service_state and service_state != "running":
        issues.append(f"agent_service_{service_state or 'unknown'}")
    if not process_running and not service_running:
        issues.append(f"agent_process_count_{process_count if process_count is not None else 'unknown'}")
    if "running" in task_state or "execu" in task_state:
        issues.append("foreground_agent_task_running")

    probe_errors = []
    blocking_probe_errors = []
    for name, result in (preflight_result.get("probes") or {}).items():
        if isinstance(result, dict) and result.get("error"):
            error = f"{name}:{result['error']}"
            probe_errors.append(error)
            if name in {"hostname", "agent_service"}:
                blocking_probe_errors.append(error)
    if blocking_probe_errors:
        issues.append("guest_preflight_probe_errors")

    return {
        "ready": not issues,
        "issues": issues,
        "agent_service": service_state or None,
        "agent_service_inferred_from_process": not service_state and process_running,
        "agent_process_inferred_from_service": service_running and not process_running,
        "agent_task_state": task_state or None,
        "agent_process_count": process_count,
        "probe_errors": probe_errors,
        "blocking_probe_errors": blocking_probe_errors,
    }


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def psql_json_query(server: SshHost, sql: str, timeout: int = 120) -> CommandResult:
    escaped_sql = shlex.quote(sql)
    command = (
        "docker exec tamandua-postgres-light sh -lc "
        + shlex.quote(
            "user=${POSTGRES_USER:-tamandua}; "
            "db=${POSTGRES_DB:-tamandua_dev}; "
            "psql -U \"$user\" -d \"$db\" -t -A -F '' -c "
            + escaped_sql
        )
    )
    return server.run(command, timeout=timeout)


_SERVER_UTC_NOW_CACHE: dict[str, dt.datetime] = {}


def server_utc_now(server: SshHost) -> dt.datetime:
    cache_key = f"{server.host}:{server.username}"
    last_error: str | None = None

    for _attempt in range(3):
        result = psql_json_query(
            server,
            "select jsonb_build_object('now', now())::text;",
            timeout=30,
        )
        payload = result.stdout.strip()
        try:
            value = json.loads(payload).get("now")
            parsed = parse_agent_timestamp(value)
            if parsed is None:
                raise ValueError("empty server timestamp")
            _SERVER_UTC_NOW_CACHE[cache_key] = parsed
            return parsed
        except (json.JSONDecodeError, AttributeError, TypeError, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}; payload={payload!r}"
            time.sleep(1)

    cached = _SERVER_UTC_NOW_CACHE.get(cache_key)
    if cached is not None:
        trace_step(f"server_utc_now using cached value after query failure: {last_error}")
        return cached
    raise RunnerError(f"Could not read server DB clock: {last_error}")


def collect_agent_db_state(server: SshHost, agent_id: str | None) -> dict[str, Any]:
    if not agent_id:
        return {"skipped": "agent_id was not provided"}
    sql = f"""
select jsonb_build_object(
  'id', id,
  'hostname', hostname,
  'status', status,
  'last_seen_at', last_seen_at,
  'db_now', now(),
  'agent_version', agent_version,
  'os_type', os_type,
  'os_version', os_version,
  'updated_at', updated_at
)::text
from agents
where id = '{agent_id}'
limit 1;
"""
    result = psql_json_query(server, sql)
    payload = result.stdout.strip()
    try:
        return json.loads(payload) if payload else {"missing": True}
    except json.JSONDecodeError:
        return {"parse_error": payload, "command": dataclasses.asdict(result)}


def parse_agent_timestamp(value: Any) -> dt.datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    text = re.sub(
        r"(\.\d{1,6})(?=Z|[+-]\d{2}:?\d{2}$|$)",
        lambda match: match.group(1).ljust(7, "0"),
        text,
    )
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def parse_report_timestamp(value: Any) -> dt.datetime | None:
    return parse_agent_timestamp(value)


def report_row_has_stale_source_timestamp(
    row: dict[str, Any],
    noise_started_at: dt.datetime | None,
) -> bool:
    """Return true when a DB row was inserted during the run but sourced earlier."""
    if noise_started_at is None:
        return False
    source_timestamp = parse_report_timestamp(row.get("last_source_at") or row.get("source_timestamp"))
    if source_timestamp is None:
        return False
    if source_timestamp < noise_started_at:
        return True
    row_timestamp = parse_report_timestamp(
        row.get("last_at") or row.get("created_at") or row.get("inserted_at") or row.get("updated_at")
    )
    if row_timestamp is not None and source_timestamp < row_timestamp - dt.timedelta(minutes=5):
        return True
    return False


def evaluate_agent_readiness(
    agent_state: dict[str, Any],
    freshness_seconds: int,
    reference_time: dt.datetime | None = None,
) -> dict[str, Any]:
    issues: list[str] = []
    status = str(agent_state.get("status") or "").lower()
    last_seen = parse_agent_timestamp(agent_state.get("last_seen_at"))
    age_seconds: float | None = None

    if agent_state.get("missing"):
        issues.append("agent_db_record_missing")
    if status != "online":
        issues.append(f"agent_status_{status or 'unknown'}")
    if last_seen is None:
        issues.append("agent_last_seen_missing_or_unparseable")
    else:
        reference = reference_time or parse_agent_timestamp(agent_state.get("db_now")) or utc_now()
        age_seconds = max(0.0, (reference - last_seen).total_seconds())
        if freshness_seconds >= 0 and age_seconds > freshness_seconds:
            issues.append(f"agent_last_seen_stale_{int(age_seconds)}s")

    return {
        "ready": not issues,
        "issues": issues,
        "status": status or None,
        "last_seen_at": agent_state.get("last_seen_at"),
        "last_seen_age_seconds": age_seconds,
        "freshness_seconds": freshness_seconds,
        "reference_time": iso(reference) if last_seen is not None else None,
        "reference_time_source": "db_now" if last_seen is not None and agent_state.get("db_now") else "local_utc_now",
    }


def mark_tests_infra_blocked(
    report: dict[str, Any],
    tests: list[dict[str, Any]],
    reason: str,
    details: dict[str, Any],
    atomic_available: bool = False,
    args: argparse.Namespace | None = None,
) -> None:
    for test in tests:
        executor, command = resolve_test_command(test, atomic_available=atomic_available, args=args or argparse.Namespace())
        report["tests"].append(
            {
                "id": test["id"],
                "name": test["name"],
                "risk": test.get("risk"),
                "tags": test.get("tags", []),
                "validation_category": test.get("validation_category"),
                "roadmap_traceability": test.get("roadmap_traceability"),
                "claim_boundary": test.get("claim_boundary"),
                **executor_metadata(test, executor, atomic_available=atomic_available, args=args or argparse.Namespace()),
                "command": command,
                "expected_telemetry": test.get("expected_telemetry", []),
                "status": "infra_blocked",
                "score": {
                    "status": "infra_blocked",
                    "error": reason,
                    "details": details,
                    "expected_telemetry": test.get("expected_telemetry", []),
                },
            }
        )


def resolve_agent_by_hostname(server: SshHost, hostname: str | None) -> dict[str, Any]:
    if not hostname:
        return {"skipped": "hostname was not provided"}

    hostname_literal = sql_literal(hostname)
    sql = f"""
select jsonb_build_object(
  'id', id,
  'hostname', hostname,
  'status', status,
  'last_seen_at', last_seen_at,
  'agent_version', agent_version,
  'os_type', os_type,
  'os_version', os_version,
  'updated_at', updated_at
)::text
from agents
where hostname = {hostname_literal}
order by
  case when status = 'online' then 0 else 1 end,
  last_seen_at desc nulls last,
  updated_at desc nulls last
limit 1;
"""
    result = psql_json_query(server, sql)
    payload = result.stdout.strip()
    try:
        resolved = json.loads(payload) if payload else {"missing": True}
    except json.JSONDecodeError:
        return {"hostname": hostname, "parse_error": payload, "command": dataclasses.asdict(result)}

    return {
        "hostname": hostname,
        "resolved": resolved,
        "command": dataclasses.asdict(result),
    }


def collect_event_summary(
    server: SshHost,
    agent_id: str | None,
    started_at: str,
    ended_at: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    if not agent_id:
        return {"skipped": "agent_id was not provided"}

    upper_bound = (
        f"    and created_at <= ('{ended_at}'::timestamptz + interval '180 seconds')\n"
        if ended_at
        else ""
    )
    sql = f"""
with scoped as (
  select
    event_type,
    severity,
    case
      when event_type = 'system_health' then 'agent_health'
      else coalesce(
        enrichment->>'source',
        enrichment->'metadata'->>'source',
        payload->>'source',
        payload->>'provider',
        case
          when event_type in ('process_create', 'process_terminate', 'module_load') then 'kernel_driver_inferred'
          when event_type like 'registry_%' then 'kernel_driver_inferred'
          when event_type like 'file_%' then 'kernel_driver_inferred'
          when event_type in ('network_connect', 'connection_attempt') then 'endpoint_network_inferred'
          when event_type in ('dns_query', 'dns_response') then 'endpoint_dns_inferred'
          when event_type in ('defense_evasion', 'etw_tamper', 'ntdll_write') then 'endpoint_behavior_inferred'
          when event_type in ('agent_health', 'heartbeat') then 'agent_health_inferred'
          else null
        end,
        'unknown'
      )
    end as source_name,
    timestamp as source_timestamp,
    created_at,
    coalesce(
      detections[1]->>'rule_name',
      detections[1]->>'detection_type',
      detections[1]->>'mitre_technique',
      ''
    ) as detection_name,
    payload->>'process_name' as process_name,
    payload->>'process_path' as process_path,
    payload->>'mem_type_str' as mem_type_str,
    payload->>'new_protection_str' as new_protection_str,
    enrichment->'metadata'->>'operation' as operation,
    payload->>'key_path' as key_path,
    payload->>'value_name' as value_name
  from events
  where agent_id = '{agent_id}'
    and created_at >= '{started_at}'::timestamptz
{upper_bound.rstrip()}
)
select coalesce(jsonb_agg(row_to_json(t)), '[]'::jsonb)::text
from (
  select
    source_name,
    event_type,
    severity,
    detection_name,
    count(*)::int as count,
    max(created_at) as last_at,
    max(source_timestamp) as last_source_at,
    max(process_name) as process_name,
    max(process_path) as process_path,
    max(mem_type_str) as mem_type_str,
    max(new_protection_str) as new_protection_str,
    max(operation) as operation,
    max(key_path) as key_path,
    max(value_name) as value_name
  from scoped
  group by source_name, event_type, severity, detection_name
  order by count desc, source_name, event_type, detection_name
) t;
"""
    result = psql_json_query(server, sql, timeout=timeout)
    payload = result.stdout.strip()
    try:
        return {"rows": json.loads(payload) if payload else [], "command": dataclasses.asdict(result)}
    except json.JSONDecodeError:
        return {"rows": [], "parse_error": payload, "command": dataclasses.asdict(result)}


def collect_event_samples(
    server: SshHost,
    agent_id: str | None,
    started_at: str,
    ended_at: str | None = None,
    limit: int = 200,
    preferred_event_types: list[str] | None = None,
    expected_fields: list[str] | None = None,
    expected_values: list[str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    if not agent_id:
        return {"skipped": "agent_id was not provided"}

    upper_bound = (
        f"    and created_at <= ('{ended_at}'::timestamptz + interval '180 seconds')\n"
        if ended_at
        else ""
    )
    preferred = [str(item).replace("'", "''") for item in (preferred_event_types or [])]
    preferred_order = ""
    preferred_filter = ""
    if preferred:
        preferred_values = ", ".join(f"'{item}'" for item in preferred)
        preferred_order = f"case when event_type in ({preferred_values}) then 0 else 1 end, "
        preferred_filter = f"    and event_type in ({preferred_values})\n"
    field_clauses: list[str] = []
    for field in expected_fields or []:
        aliases = FIELD_ALIASES.get(field, [field])
        alias_checks: list[str] = []
        for alias in aliases:
            escaped = str(alias).replace("'", "''")
            alias_checks.extend(
                [
                    f"payload ? '{escaped}'",
                    f"payload->'metadata' ? '{escaped}'",
                    f"enrichment ? '{escaped}'",
                    f"enrichment->'metadata' ? '{escaped}'",
                ]
            )
        if alias_checks:
            field_clauses.append(f"case when {' or '.join(alias_checks)} then 1 else 0 end")
    field_score_expr = " + ".join(field_clauses) if field_clauses else "0"
    value_clauses: list[str] = []
    for expected_value in expected_values or []:
        escaped = str(expected_value).replace("'", "''")
        if escaped:
            value_clauses.append(
                "case when position(lower('"
                + escaped
                + "') in lower(coalesce(payload::text, '') || ' ' || coalesce(enrichment::text, ''))) > 0 "
                "then 1 else 0 end"
            )
    value_score_expr = " + ".join(value_clauses) if value_clauses else "0"
    sql = f"""
select coalesce(jsonb_agg(row_to_json(t)), '[]'::jsonb)::text
from (
  select
    id::text,
    agent_id::text,
    (select hostname from agents where agents.id = events.agent_id limit 1) as hostname,
    event_type,
    severity,
    timestamp as source_timestamp,
    created_at,
    payload,
    enrichment,
    detections,
    ({field_score_expr}) as evidence_field_score,
    ({value_score_expr}) as evidence_value_score
  from events
  where agent_id = '{agent_id}'
    and created_at >= '{started_at}'::timestamptz
{upper_bound.rstrip()}
{preferred_filter.rstrip()}
  order by {preferred_order}evidence_value_score desc, evidence_field_score desc, created_at desc
  limit {int(limit)}
) t;
"""
    result = psql_json_query(server, sql, timeout=timeout)
    payload = result.stdout.strip()
    try:
        return {"rows": json.loads(payload) if payload else [], "command": dataclasses.asdict(result)}
    except json.JSONDecodeError:
        return {"rows": [], "parse_error": payload, "command": dataclasses.asdict(result)}


def collect_alert_summary(
    server: SshHost,
    agent_id: str | None,
    started_at: str,
    ended_at: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    if not agent_id:
        return {"skipped": "agent_id was not provided"}

    upper_bound = (
        f"    and coalesce(updated_at, inserted_at) <= '{ended_at}'::timestamptz\n" if ended_at else ""
    )
    sql = f"""
select coalesce(jsonb_agg(row_to_json(t)), '[]'::jsonb)::text
from (
  select
    id::text,
    severity,
    status,
    title,
    1::int as count,
    coalesce(updated_at, inserted_at) as last_at,
    event_ids,
    contributing_events,
    process_chain,
    mitre_tactics,
    mitre_techniques,
    storyline_id,
    evidence,
    detection_metadata
  from alerts
  where agent_id = '{agent_id}'
    and coalesce(updated_at, inserted_at) >= '{started_at}'::timestamptz
{upper_bound.rstrip()}
  order by coalesce(updated_at, inserted_at) desc
  limit 250
) t;
"""
    result = psql_json_query(server, sql, timeout=timeout)
    payload = result.stdout.strip()
    try:
        return {"rows": json.loads(payload) if payload else [], "command": dataclasses.asdict(result)}
    except json.JSONDecodeError:
        return {"rows": [], "parse_error": payload, "command": dataclasses.asdict(result)}


def collect_detection_summary(
    server: SshHost,
    agent_id: str | None,
    started_at: str,
    ended_at: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    if not agent_id:
        return {"skipped": "agent_id was not provided"}

    upper_bound = f"    and created_at <= '{ended_at}'::timestamptz\n" if ended_at else ""
    sql = f"""
with scoped as (
  select
    event_type,
    severity,
    timestamp as source_timestamp,
    created_at,
    det as detection
  from events
  cross join lateral unnest(coalesce(detections, ARRAY[]::jsonb[])) as det
  where agent_id = '{agent_id}'
    and created_at >= '{started_at}'::timestamptz
{upper_bound.rstrip()}
),
normalized as (
  select
    event_type,
    severity,
    source_timestamp,
    created_at,
    coalesce(det_obj->>'rule_name', det_obj->>'rule', det_obj->>'name', 'unknown') as rule_name,
    coalesce(det_obj->>'detection_type', det_obj->>'type', 'unknown') as detection_type,
    nullif(coalesce(det_obj->>'mitre_technique', det_obj->>'mitre_techniques'), '') as mitre_technique,
    det_obj as detection
  from (
    select
      event_type,
      severity,
      source_timestamp,
      created_at,
      case
        when jsonb_typeof(detection) = 'object' then detection
        when jsonb_typeof(detection) = 'string' and (detection #>> '{{}}') ~ '^\\s*\\{{' then (detection #>> '{{}}')::jsonb
        else '{{}}'::jsonb
      end as det_obj
    from scoped
  ) parsed
)
select coalesce(jsonb_agg(row_to_json(t)), '[]'::jsonb)::text
from (
  select
    rule_name,
    detection_type,
    mitre_technique,
    event_type,
    severity,
    count(*)::int as count,
    max(created_at) as last_at,
    max(source_timestamp) as last_source_at
  from normalized
  group by rule_name, detection_type, mitre_technique, event_type, severity
  order by count desc, rule_name, event_type
) t;
"""
    result = psql_json_query(server, sql, timeout=timeout)
    payload = result.stdout.strip()
    try:
        return {"rows": json.loads(payload) if payload else [], "command": dataclasses.asdict(result)}
    except json.JSONDecodeError:
        return {"rows": [], "parse_error": payload, "command": dataclasses.asdict(result)}


def collect_driver_health_snapshot(server: SshHost, agent_id: str | None, timeout: int = 120) -> dict[str, Any]:
    if not agent_id:
        return {"skipped": "agent_id was not provided"}

    sql = f"""
select coalesce(row_to_json(t)::jsonb, '{{}}'::jsonb)::text
from (
  select
    created_at,
    payload->'driver_status' as driver_status
  from events
  where agent_id = '{agent_id}'
    and event_type = 'system_health'
    and payload ? 'driver_status'
  order by created_at desc
  limit 1
) t;
"""
    result = psql_json_query(server, sql, timeout=timeout)
    payload = result.stdout.strip()
    try:
        snapshot = json.loads(payload) if payload else {}
        if snapshot:
            return {"snapshot": snapshot, "command": dataclasses.asdict(result), "source": "events_db"}
    except json.JSONDecodeError:
        return {"snapshot": {}, "parse_error": payload, "command": dataclasses.asdict(result), "source": "events_db"}

    # Lightweight deployments log driver health but may filter system_health
    # from durable events. Use the log as a sensor-contract fallback.
    grep_agent = shlex.quote(f"[DriverLab] health agent={agent_id}")
    command = (
        "docker logs --since 20m --tail 2000 tamandua-server-light 2>&1 "
        f"| grep -F {grep_agent} | tail -1"
    )
    log_result = server.run(command, timeout=min(30, max(1, timeout)))
    line = log_result.stdout.strip()
    match = re.search(r"driver_status=(%\{.*\})", line)
    if not match:
        return {
            "snapshot": {},
            "source": "server_log",
            "command": dataclasses.asdict(result),
            "log_command": dataclasses.asdict(log_result),
        }

    elixir_map = match.group(1)
    jsonish = (
        elixir_map.replace("%{", "{")
        .replace(" => ", ": ")
        .replace(": nil", ": null")
    )
    try:
        driver_status = json.loads(jsonish)
    except json.JSONDecodeError as exc:
        return {
            "snapshot": {},
            "source": "server_log",
            "parse_error": str(exc),
            "raw": line,
            "command": dataclasses.asdict(result),
            "log_command": dataclasses.asdict(log_result),
        }

    return {
        "snapshot": {
            "created_at": line.split(" ", 1)[0],
            "driver_status": driver_status,
        },
        "source": "server_log",
        "command": dataclasses.asdict(result),
        "log_command": dataclasses.asdict(log_result),
    }


def counter_delta(before: dict[str, Any], after: dict[str, Any], counter_name: str) -> dict[str, int]:
    before_driver = ((before.get("snapshot") or {}).get("driver_status") or {})
    after_driver = ((after.get("snapshot") or {}).get("driver_status") or {})
    before_counts = before_driver.get(counter_name) or {}
    after_counts = after_driver.get(counter_name) or {}
    keys = set(before_counts) | set(after_counts)
    deltas: dict[str, int] = {}
    for key in sorted(keys):
        try:
            delta = int(after_counts.get(key) or 0) - int(before_counts.get(key) or 0)
        except (TypeError, ValueError):
            delta = 0
        if delta:
            deltas[str(key)] = delta
    return deltas


def collect_server_logs(server: SshHost, agent_id: str | None, since_minutes: int, timeout: int = 30) -> dict[str, Any]:
    if not agent_id:
        return {"skipped": "agent_id was not provided"}
    pattern = shlex.quote(agent_id)
    command = (
        f"docker logs --since {since_minutes}m --tail 1000 tamandua-server-light 2>&1 "
        f"| grep -E {pattern} | tail -n 300"
    )
    result = server.run(command, timeout=timeout)
    return dataclasses.asdict(result)


def collect_baseline(server: SshHost, agent_id: str | None, started_at: str) -> dict[str, Any]:
    ended_at = iso(server_utc_now(server))
    return {
        "started_at": started_at,
        "ended_at": ended_at,
        "event_summary": collect_event_summary(server, agent_id, started_at, ended_at),
        "alert_summary": collect_alert_summary(server, agent_id, started_at, ended_at),
        "detection_summary": collect_detection_summary(server, agent_id, started_at, ended_at),
    }


def verify_endpoint_telemetry_flow(
    proxmox: SshHost,
    server: SshHost,
    vmid: int,
    agent_id: str | None,
    wait_seconds: int = 180,
) -> dict[str, Any]:
    started_at_dt = server_utc_now(server) - dt.timedelta(seconds=10)
    started_at = iso(started_at_dt)
    marker = "tamandua-benchmark-liveness-" + uuid.uuid4().hex[:10]
    execution = guest_command(
        proxmox,
        vmid,
        f'cmd.exe /d /c "echo {marker} & ping -n 6 127.0.0.1 > nul"',
        timeout=60,
    )
    if execution.get("outer_exit_code") not in (0, None) or execution.get("guest_exit_code") not in (0, None):
        return {
            "ready": False,
            "started_at": started_at,
            "ended_at": iso(server_utc_now(server)),
            "marker": marker,
            "wait_seconds": wait_seconds,
            "execution": execution,
            "observed_event_types": [],
            "event_summary": {"rows": []},
            "issue": "liveness_command_execution_failed",
        }
    deadline = time.monotonic() + max(15, wait_seconds)
    summary: dict[str, Any] = {"rows": []}
    observed_types: set[str] = set()
    ready = False
    ended_at = iso(server_utc_now(server))
    while True:
        ended_at = iso(server_utc_now(server) + dt.timedelta(seconds=30))
        summary = collect_event_summary(server, agent_id, started_at, ended_at)
        observed_types = {str(row.get("event_type")) for row in summary.get("rows") or []}
        ready = bool({"process_create", "process_start"} & observed_types)
        if ready or time.monotonic() >= deadline:
            break
        time.sleep(15)
    return {
        "ready": ready,
        "started_at": started_at,
        "ended_at": ended_at,
        "marker": marker,
        "wait_seconds": wait_seconds,
        "execution": execution,
        "observed_event_types": sorted(observed_types),
        "event_summary": summary,
        "issue": None if ready else "no_fresh_process_telemetry_after_liveness_command",
    }


def expected_telemetry_alternatives(test: dict[str, Any]) -> list[list[str]]:
    """Return explicit OR-groups for acceptable telemetry evidence."""
    raw_groups = test.get("expected_telemetry_any") or test.get("expected_telemetry_alternatives") or []
    groups: list[list[str]] = []
    if not isinstance(raw_groups, list):
        return groups
    for group in raw_groups:
        if isinstance(group, str):
            values = [group]
        elif isinstance(group, list):
            values = [str(item) for item in group if item]
        else:
            continue
        values = [value for value in values if value]
        if values:
            groups.append(values)
    return groups


def telemetry_contract_state(test: dict[str, Any], observed_event_types: set[str]) -> dict[str, Any]:
    expected = {str(item) for item in (test.get("expected_telemetry") or [])}
    alternatives = expected_telemetry_alternatives(test)
    strict_missing = sorted(expected - observed_event_types)
    group_results: list[dict[str, Any]] = []
    matched_group: list[str] | None = None

    for group in alternatives:
        group_set = {str(item) for item in group}
        missing = sorted(group_set - observed_event_types)
        result = {
            "group": sorted(group_set),
            "observed": sorted(group_set & observed_event_types),
            "missing": missing,
            "satisfied": not missing,
        }
        group_results.append(result)
        if matched_group is None and not missing:
            matched_group = sorted(group_set)

    satisfied = not strict_missing or matched_group is not None
    if satisfied:
        missing_contract: list[str] = []
    elif expected:
        missing_contract = strict_missing
    elif alternatives:
        missing_contract = [
            "any_of:" + "|".join(result["group"])
            for result in group_results
            if not result["satisfied"]
        ]
    else:
        missing_contract = []

    return {
        "telemetry_contract_satisfied": satisfied,
        "strict_expected_telemetry": sorted(expected),
        "missing_strict_expected_telemetry": strict_missing,
        "expected_telemetry_any": [sorted({str(item) for item in group}) for group in alternatives],
        "telemetry_any_results": group_results,
        "observed_telemetry_alternative": matched_group or [],
        "missing_expected_telemetry": missing_contract,
    }


def preferred_telemetry_event_types(test: dict[str, Any]) -> list[str]:
    values: list[str] = []
    values.extend(str(item) for item in (test.get("expected_telemetry") or []) if item)
    values.extend(str(item) for item in (test.get("optional_telemetry") or []) if item)
    for group in expected_telemetry_alternatives(test):
        values.extend(group)
    return sorted(set(values))


def evidence_readiness(
    server: SshHost,
    agent_id: str | None,
    started_at: str,
    ended_at: str,
    test: dict[str, Any],
) -> dict[str, Any]:
    event_summary = collect_event_summary(server, agent_id, started_at, ended_at)
    detection_summary = collect_detection_summary(server, agent_id, started_at, ended_at)

    expected_telemetry = list(test.get("expected_telemetry") or [])
    expected_detections = list(test.get("expected_detections") or [])
    expected_fields = list(test.get("expected_fields") or [])
    expected_fields_by_event_type = test.get("expected_fields_by_event_type") or {}
    expected_values_by_event_type = test.get("expected_values_by_event_type") or {}
    observed_event_types = {str(row.get("event_type")) for row in event_summary.get("rows") or []}
    telemetry_state = telemetry_contract_state(test, observed_event_types)
    missing_telemetry = telemetry_state["missing_expected_telemetry"]
    observed_detections, missing_detections = matched_expected(
        detection_summary.get("rows") or [],
        expected_detections,
        ["rule_name", "detection_type", "mitre_technique"],
    )
    required_event_types = (
        set(telemetry_state["observed_telemetry_alternative"])
        or set(expected_telemetry)
        or {
            event_type
            for group in expected_telemetry_alternatives(test)
            for event_type in group
        }
    )
    expected_value_fields = [
        str(field)
        for expectations in expected_values_by_event_type.values()
        for field in (expectations or {}).keys()
    ]
    preferred_types = sorted(
        set(preferred_telemetry_event_types(test)) | set(expected_fields_by_event_type.keys()) | set(expected_values_by_event_type.keys())
    )
    event_samples: list[dict[str, Any]] = []
    field_score: dict[str, Any] = {
        "missing_expected_fields": [],
        "missing_expected_fields_by_event_type": {},
    }
    value_score: dict[str, Any] = {
        "missing_expected_values": [],
        "missing_expected_values_by_event_type": {},
    }
    if expected_fields or expected_fields_by_event_type or expected_values_by_event_type:
        samples = collect_event_samples(
            server,
            agent_id,
            started_at,
            ended_at,
            limit=300,
            preferred_event_types=preferred_types,
            expected_fields=sorted(set(expected_fields + expected_value_fields)),
            expected_values=expected_value_needles(test),
        )
        event_samples = samples.get("rows") or []
        if expected_fields_by_event_type:
            field_score = score_expected_fields_by_event_type(
                expected_fields_by_event_type,
                event_samples,
                required_event_types=required_event_types,
            )
        else:
            field_score = score_expected_fields(expected_fields, event_samples)
        value_score = score_expected_values_by_event_type(
            expected_values_by_event_type,
            event_samples,
            required_event_types=required_event_types,
        )

    return {
        "ready": (
            telemetry_state["telemetry_contract_satisfied"]
            and not missing_detections
            and not field_score.get("missing_expected_fields")
            and not value_score.get("missing_expected_values")
        ),
        "checked_at": ended_at,
        "missing_telemetry": missing_telemetry,
        "telemetry_contract": telemetry_state,
        "observed_detections": observed_detections,
        "missing_detections": missing_detections,
        "missing_expected_fields": field_score.get("missing_expected_fields", []),
        "missing_expected_fields_by_event_type": field_score.get("missing_expected_fields_by_event_type", {}),
        "missing_expected_values": value_score.get("missing_expected_values", []),
        "missing_expected_values_by_event_type": value_score.get("missing_expected_values_by_event_type", {}),
        "event_sample_count": len(event_samples),
        "event_row_count": len(event_summary.get("rows") or []),
        "detection_row_count": len(detection_summary.get("rows") or []),
    }


def wait_for_expected_evidence(
    server: SshHost,
    agent_id: str | None,
    started_at: str,
    test: dict[str, Any],
    timeout_seconds: int,
    poll_seconds: int = 15,
) -> dict[str, Any]:
    timeout_seconds = max(0, int(timeout_seconds or 0))
    if timeout_seconds <= 0:
        return {"enabled": False}

    deadline = time.monotonic() + timeout_seconds
    checks: list[dict[str, Any]] = []
    last: dict[str, Any] = {"ready": False}
    while True:
        ended_at = iso(server_utc_now(server) + dt.timedelta(seconds=5))
        last = evidence_readiness(server, agent_id, started_at, ended_at, test)
        checks.append(last)
        if last.get("ready") or time.monotonic() >= deadline:
            break
        time.sleep(max(1, poll_seconds))

    return {
        "enabled": True,
        "timeout_seconds": timeout_seconds,
        "poll_seconds": poll_seconds,
        "ready": bool(last.get("ready")),
        "checks": checks[-10:],
        "final": last,
    }


def contains_expected(value: str, expected: str) -> bool:
    return expected.lower() in value.lower()


def as_text_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(as_text_values(item))
        return values
    if isinstance(value, dict):
        values = []
        for item in value.values():
            values.extend(as_text_values(item))
        return values
    return [str(value)]


def alert_matches_test_context(alert: dict[str, Any], test: dict[str, Any]) -> bool:
    """Treat high/critical alerts for the active technique as expected signal.

    Deterministic benchmark scenarios often do not pin an exact alert title yet.
    A high-severity alert is not noise when it carries the MITRE technique for
    the scenario currently being executed.
    """
    traceability = test.get("roadmap_traceability") or {}
    expected_techniques = {
        str(item).upper()
        for item in [
            test.get("technique"),
            traceability.get("technique"),
            (test.get("atomic") or {}).get("technique"),
            *(test.get("mitre_techniques") or []),
            *(test.get("techniques") or []),
            *[
                str(tag).split(":", 1)[1]
                for tag in (test.get("tags") or [])
                if str(tag).lower().startswith("mitre:")
            ],
        ]
        if item
    }
    if not expected_techniques:
        return False

    haystack_values: list[str] = []
    for field in (
        "mitre_techniques",
        "detection_metadata",
        "evidence",
        "title",
        "contributing_events",
    ):
        haystack_values.extend(as_text_values(alert.get(field)))
    haystack = " ".join(haystack_values).upper()
    return any(technique in haystack for technique in expected_techniques)


BENCHMARK_SETUP_ALERT_PATTERNS = [
    r"d:\\atomicredteam",
    r"c:\\atomicredteam",
    "invoke-atomicredteam",
    "install-atomicredteam",
    "atomic-offline-package",
    "atomic_red_team",
    "atomic red team",
    "sandcat-v1.exe",
    r"d:\\programdata\\tamandua\\caldera",
    r"d:\\programdata\\tamandua\\staging",
    "tamanduaagent",
    "tamanduaenterpriseeval",
    r"\\windows\\temp\\svchost.exe  /c ping -n 5 127.0.0.1",
    r"\\program files\\tamandua\\tamandua-agent.exe",
    "tamandua-agent.exe' -argumentlist 'service",
    'tamandua-agent.exe" -argumentlist "service',
    "puaprotection",
    "windows defender",
    "microsoftedgeupdate.exe",
    "ngen.exe",
    r"\\windows\\microsoft.net\\framework",
    r"\\windows\\microsoft.net\\framework64",
]


def searchable_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def decoded_powershell_payloads(text: str) -> list[str]:
    decoded: list[str] = []
    for match in re.finditer(r"(?i)(?:-|/)encodedcommand\s+([A-Za-z0-9+/=_-]{20,})", text):
        encoded = match.group(1).replace("-", "+").replace("_", "/")
        encoded += "=" * (-len(encoded) % 4)
        try:
            decoded.append(base64.b64decode(encoded).decode("utf-16le", errors="ignore"))
        except (ValueError, UnicodeDecodeError):
            continue
    return decoded


def is_benchmark_setup_alert(alert: dict[str, Any]) -> bool:
    """Return true for alerts caused by the validation harness setup itself.

    These alerts are still real alerts in Tamandua. The benchmark only excludes
    them from the "unexpected high/critical" gate so a CALDERA run is not failed
    by earlier Atomic installation/provisioning commands in the same lab window.
    """
    raw_haystack = " ".join(
        searchable_text(alert.get(field))
        for field in (
            "title",
            "evidence",
            "detection_metadata",
            "process_chain",
            "contributing_events",
            "mitre_techniques",
        )
    )
    haystack = " ".join([raw_haystack, *decoded_powershell_payloads(raw_haystack)]).lower()
    return any(pattern in haystack for pattern in BENCHMARK_SETUP_ALERT_PATTERNS)


def is_benign_edge_update_ntdll_event(row: dict[str, Any]) -> bool:
    if str(row.get("event_type") or "").lower() != "defense_evasion":
        return False
    if str(row.get("detection_name") or "").lower() != "ntdll_write_ntmapviewofsection":
        return False

    haystack = searchable_text(row).lower().replace("\\\\", "\\")
    process_name = str(row.get("process_name") or "").strip().lower()
    stable_edge_update_binary = (
        process_name == "microsoftedgeupdate.exe"
        and "\\program files (x86)\\microsoft\\edgeupdate\\microsoftedgeupdate.exe" in haystack
    )
    edge_update_installer = (
        process_name.startswith("microsoftedgeupdatesetup_")
        and "\\program files (x86)\\microsoft\\edgeupdate\\install\\" in haystack
    )
    edge_update_temp_staging = (
        process_name == "microsoftedgeupdate.exe"
        and "\\program files (x86)\\microsoft\\temp\\" in haystack
        and "\\microsoftedgeupdate.exe" in haystack
    )
    return (
        (stable_edge_update_binary or edge_update_installer or edge_update_temp_staging)
        and "ntmapviewofsection" in haystack
        and "mem_image" in haystack
        and "page_execute_read" in haystack
    )


def is_benign_windows_error_reporting_ntdll_event(row: dict[str, Any]) -> bool:
    """Classify narrow Windows Error Reporting image-map maintenance noise.

    WER can map its own image/text pages while handling process faults. The
    benchmark gate excludes only this low-context self image-map shape; it does
    not suppress wermgr cases with child process, network, credential target,
    explicit write-size, thread execution, or non-Windows binary paths.
    """

    if str(row.get("event_type") or "").lower() != "defense_evasion":
        return False
    if str(row.get("detection_name") or "").lower() != "ntdll_write_ntmapviewofsection":
        return False

    process_name = str(row.get("process_name") or "").strip().lower()
    if process_name != "wermgr.exe":
        return False

    haystack = searchable_text(row).lower().replace("\\\\", "\\")
    expected_path = (
        "\\windows\\system32\\wermgr.exe" in haystack
        or "\\windows\\syswow64\\wermgr.exe" in haystack
        or "\\device\\harddiskvolume" in haystack and "\\windows\\syswow64\\wermgr.exe" in haystack
    )
    if not expected_path:
        return False

    suspicious_terms = {
        "lsass",
        "sam",
        "powershell",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "mshta",
        "wscript",
        "cscript",
        "http://",
        "https://",
        "thread_start",
        "thread_from_unbacked",
        "writeprocessmemory",
        "ntwritevirtualmemory",
        "remote_thread",
        "browser",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
    }

    return (
        "ntmapviewofsection" in haystack
        and "mem_image" in haystack
        and "page_execute_read" in haystack
        and not any(term in haystack for term in suspicious_terms)
    )


def is_benchmark_service_registry_cleanup_event(row: dict[str, Any]) -> bool:
    if str(row.get("event_type") or "").lower() not in {"registry_create", "registry_delete"}:
        return False
    if str(row.get("detection_name") or "").lower() != "registry_t1543_003":
        return False

    haystack = searchable_text(row).lower().replace("\\\\", "\\")
    process_name = str(row.get("process_name") or "").strip().lower()
    return (
        "tamanduabench" in haystack
        and "hklm\\system\\currentcontrolset\\services" in haystack
        and process_name in {"", "unknown", "system"}
    )


def is_benchmark_run_key_persistence_event(row: dict[str, Any]) -> bool:
    if str(row.get("event_type") or "").lower() not in {"registry_create", "registry_set_value", "registry_delete"}:
        return False
    if str(row.get("detection_name") or "").lower() not in {
        "registry_persistence",
        "persistence_t1547_001",
        "registry_t1547_001",
    }:
        return False

    haystack = searchable_text(row).lower().replace("\\\\", "\\")
    run_key = "\\currentversion\\run" in haystack and "\\currentversion\\runonce" not in haystack
    benchmark_marker = "tamanduabench" in haystack or "tamanduaenterpriseeval" in haystack
    return run_key and benchmark_marker


def is_benign_defender_manifest_backup_event(row: dict[str, Any]) -> bool:
    if str(row.get("event_type") or "").lower() not in {"registry_create", "registry_delete"}:
        return False
    if str(row.get("detection_name") or "").lower() != "registry_t1562_001":
        return False

    haystack = searchable_text(row).lower().replace("\\\\", "\\")
    process_name = str(row.get("process_name") or "").strip().lower()
    return (
        "hklm\\software\\microsoft\\windows defender" in haystack
        and "manifestbackup" in haystack
        and process_name in {"", "unknown", "system"}
    )


def is_benign_edge_update_etw_process_event(row: dict[str, Any]) -> bool:
    if str(row.get("event_type") or "").lower() != "process_create":
        return False
    detection_name = str(row.get("detection_name") or "").lower()
    if not detection_name.startswith("etw_"):
        return False

    process_name = str(row.get("process_name") or "").strip().lower()
    haystack = searchable_text(row).lower().replace("\\\\", "\\")
    return process_name == "microsoftedgeupdate.exe" or "microsoftedgeupdate.exe" in haystack


def is_benign_windows_service_etw_process_event(row: dict[str, Any]) -> bool:
    """Classify narrow Windows maintenance-service ETW noise in benchmark gates only."""

    if str(row.get("event_type") or "").lower() != "process_create":
        return False
    if str(row.get("source_name") or "").lower() != "kernel_driver_inferred":
        return False

    detection_name = str(row.get("detection_name") or "").lower()
    if not detection_name.startswith("etw_"):
        return False

    process_name = str(row.get("process_name") or "").strip().lower()
    if process_name not in {"sppsvc.exe"}:
        return False

    haystack = searchable_text(row).lower().replace("\\\\", "\\")
    suspicious_terms = {
        "powershell",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "mshta",
        "wscript",
        "cscript",
        "tamanduabench",
        "encodedcommand",
        "executionpolicy",
        "http://",
        "https://",
    }
    return not any(term in haystack for term in suspicious_terms)


def matched_expected(items: list[dict[str, Any]], expected: list[str], fields: list[str]) -> tuple[list[str], list[str]]:
    observed_values: list[str] = []
    for item in items:
        for field in fields:
            observed_values.extend(as_text_values(item.get(field)))

    observed = []
    missing = []
    for expectation in expected:
        if any(contains_expected(value, expectation) for value in observed_values):
            observed.append(expectation)
        else:
            missing.append(expectation)
    return observed, missing


def matching_items(items: list[dict[str, Any]], expected: list[str], fields: list[str]) -> list[dict[str, Any]]:
    if not expected:
        return []

    matched: list[dict[str, Any]] = []
    for item in items:
        values = []
        for field in fields:
            values.extend(as_text_values(item.get(field)))
        if any(contains_expected(value, expectation) for expectation in expected for value in values):
            matched.append(item)
    return matched


def inline_detection_rows(event_samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample in event_samples:
        detections = sample.get("detections")
        if not isinstance(detections, list):
            continue
        for detection in detections:
            if not isinstance(detection, dict):
                continue
            mitre_techniques = detection.get("mitre_techniques")
            rows.append(
                {
                    "rule_name": detection.get("rule_name"),
                    "detection_type": detection.get("detection_type"),
                    "mitre_technique": " ".join(str(item) for item in mitre_techniques)
                    if isinstance(mitre_techniques, list)
                    else mitre_techniques,
                    "severity": detection.get("severity") or sample.get("severity"),
                    "event_type": sample.get("event_type"),
                    "description": detection.get("description"),
                }
            )
    return rows


def sequence_len(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    return 0


def alert_context_gaps(alerts: list[dict[str, Any]], test: dict[str, Any]) -> list[dict[str, Any]]:
    if not alerts:
        return []

    requires_mitre = bool(tag_values(test, "mitre:"))
    gaps: list[dict[str, Any]] = []
    for alert in alerts:
        missing: list[str] = []
        has_event_linkage = (
            sequence_len(alert.get("event_ids")) > 0
            or sequence_len(alert.get("contributing_events")) > 0
        )

        if not has_event_linkage:
            missing.append("event_ids")
        if requires_mitre and sequence_len(alert.get("mitre_techniques")) == 0:
            missing.append("mitre_techniques")
        if requires_mitre and sequence_len(alert.get("mitre_tactics")) == 0:
            missing.append("mitre_tactics")

        if missing:
            gaps.append(
                {
                    "id": alert.get("id"),
                    "title": alert.get("title"),
                    "missing": missing,
                }
            )
    return gaps


FIELD_ALIASES: dict[str, list[str]] = {
    "agent_id": ["agent_id"],
    "hostname": ["hostname", "host", "computer_name", "device_name"],
    "user": ["user", "username", "user_name", "account_name", "subject_user_name", "process.user"],
    "process_name": ["process_name", "name", "image", "image_name", "process.name"],
    "parent_process_name": ["parent_process_name", "parent_name", "parent_process"],
    "process_id": ["pid", "process_id", "process.pid"],
    "parent_process_id": ["ppid", "parent_pid", "parent_process_id"],
    "command_line": ["command_line", "cmdline", "command", "process_command_line", "process.command_line"],
    "exe_path": ["exe_path", "path", "image_path", "process_path", "process.path"],
    "path": ["path", "file_path", "target_path", "file.path"],
    "file_path": ["file_path", "path", "target_path", "file.path"],
    "module_path": ["module_path", "image_path", "path"],
    "registry_key": ["registry_key", "key_path", "target_object", "target_name", "object_name", "registry_path"],
    "registry_value": ["registry_value", "value_name", "registry_value_name"],
    "remote_ip": [
        "remote_ip",
        "dst_ip",
        "dest_ip",
        "destination_ip",
        "remote_addr",
        "remote_address",
        "network.remote_ip",
    ],
    "remote_port": ["remote_port", "dst_port", "destination_port", "network.remote_port"],
    "domain": ["domain", "query", "dns_query", "hostname", "dns.query"],
}


def lookup_nested(payload: dict[str, Any], key: str) -> Any:
    if key in payload:
        return payload.get(key)
    if "." in key:
        current: Any = payload
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current.get(part)
        if current is not None:
            return current
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and key in metadata:
        return metadata.get(key)
    for value in payload.values():
        if isinstance(value, dict):
            found = lookup_nested(value, key)
            if found is not None:
                return found
    return None


def raw_key_present(value: Any, key: str) -> bool:
    try:
        raw = json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        raw = str(value)
    return (
        re.search(rf'(?i)"{re.escape(key)}"\s*:\s*(?!null\b|""|\[\])', raw) is not None
        or re.search(rf'(?i)(?:^|[\W]){re.escape(key)}(?:[\W]|$)', raw) is not None
    )


def score_expected_fields(
    expected_fields: list[str],
    event_samples: list[dict[str, Any]],
) -> dict[str, Any]:
    observed: dict[str, int] = {}
    missing: list[str] = []

    for field in expected_fields:
        aliases = FIELD_ALIASES.get(field, [field])
        count = 0
        for sample in event_samples:
            sample_payload = sample.get("payload")
            payload = sample_payload if isinstance(sample_payload, dict) else {}
            enrichment = sample.get("enrichment")
            enrich = enrichment if isinstance(enrichment, dict) else {}
            haystacks = [sample, payload, enrich]
            if any(
                lookup_nested(haystack, alias) not in (None, "", [])
                for haystack in haystacks
                for alias in aliases
            ) or any(raw_key_present(haystack, alias) for haystack in haystacks for alias in aliases):
                count += 1
        if count:
            observed[field] = count
        else:
            missing.append(field)

    return {
        "expected_fields": expected_fields,
        "observed_field_counts": observed,
        "missing_expected_fields": missing,
    }


def score_expected_fields_by_event_type(
    expected_fields_by_event_type: dict[str, list[str]],
    event_samples: list[dict[str, Any]],
    required_event_types: set[str] | None = None,
) -> dict[str, Any]:
    observed: dict[str, dict[str, int]] = {}
    missing: dict[str, list[str]] = {}
    skipped_optional: dict[str, list[str]] = {}
    required_event_types = required_event_types or set()

    samples_by_type: dict[str, list[dict[str, Any]]] = {}
    for sample in event_samples:
        samples_by_type.setdefault(str(sample.get("event_type") or ""), []).append(sample)

    for event_type, fields in expected_fields_by_event_type.items():
        if required_event_types and str(event_type) not in required_event_types:
            skipped_optional[str(event_type)] = list(fields or [])
            continue

        event_samples_for_type = samples_by_type.get(str(event_type), [])
        if not event_samples_for_type and str(event_type) not in required_event_types:
            skipped_optional[str(event_type)] = list(fields or [])
            continue

        field_score = score_expected_fields(list(fields or []), event_samples_for_type)
        observed[str(event_type)] = field_score["observed_field_counts"]
        if field_score["missing_expected_fields"]:
            missing[str(event_type)] = field_score["missing_expected_fields"]

    return {
        "expected_fields_by_event_type": expected_fields_by_event_type,
        "observed_field_counts_by_event_type": observed,
        "skipped_optional_fields_by_event_type": skipped_optional,
        "missing_expected_fields_by_event_type": missing,
        "missing_expected_fields": [
            f"{event_type}.{field}"
            for event_type, fields in missing.items()
            for field in fields
        ],
    }


def score_expected_values_by_event_type(
    expected_values_by_event_type: dict[str, dict[str, list[str]]],
    event_samples: list[dict[str, Any]],
    required_event_types: set[str] | None = None,
) -> dict[str, Any]:
    observed: dict[str, dict[str, list[str]]] = {}
    missing: dict[str, dict[str, list[str]]] = {}
    skipped_optional: dict[str, dict[str, list[str]]] = {}
    required_event_types = required_event_types or set()

    samples_by_type: dict[str, list[dict[str, Any]]] = {}
    for sample in event_samples:
        samples_by_type.setdefault(str(sample.get("event_type") or ""), []).append(sample)

    for event_type, field_expectations in expected_values_by_event_type.items():
        if required_event_types and str(event_type) not in required_event_types:
            skipped_optional[str(event_type)] = field_expectations
            continue

        event_samples_for_type = samples_by_type.get(str(event_type), [])
        if not event_samples_for_type and str(event_type) not in required_event_types:
            skipped_optional[str(event_type)] = field_expectations
            continue

        for field, expectations in (field_expectations or {}).items():
            aliases = FIELD_ALIASES.get(field, [field])
            if str(event_type) == "live_response_command_completed" and str(field) == "command":
                aliases = sorted(set([*aliases, "output", "stdout"]))
            values: list[str] = []
            for sample in event_samples_for_type:
                payload = sample.get("payload") if isinstance(sample.get("payload"), dict) else {}
                enrichment = sample.get("enrichment") if isinstance(sample.get("enrichment"), dict) else {}
                for haystack in [sample, payload, enrichment]:
                    for alias in aliases:
                        values.extend(as_text_values(lookup_nested(haystack, alias)))

            for expectation in expectations or []:
                if any(contains_expected(value, str(expectation)) for value in values):
                    observed.setdefault(str(event_type), {}).setdefault(str(field), []).append(str(expectation))
                else:
                    missing.setdefault(str(event_type), {}).setdefault(str(field), []).append(str(expectation))

    return {
        "expected_values_by_event_type": expected_values_by_event_type,
        "observed_expected_values_by_event_type": observed,
        "skipped_optional_values_by_event_type": skipped_optional,
        "missing_expected_values_by_event_type": missing,
        "missing_expected_values": [
            f"{event_type}.{field}~{expectation}"
            for event_type, fields in missing.items()
            for field, expectations in fields.items()
            for expectation in expectations
        ],
    }


def expected_value_needles(test: dict[str, Any]) -> list[str]:
    expected_values_by_event_type = test.get("expected_values_by_event_type") or {}
    return [
        str(expectation)
        for field_expectations in expected_values_by_event_type.values()
        for expectations in (field_expectations or {}).values()
        for expectation in (expectations or [])
        if str(expectation)
    ]


def execution_output_text(item: dict[str, Any]) -> str:
    execution = item.get("execution") if isinstance(item.get("execution"), dict) else {}
    payload = execution.get("tamandua_ctl_payload") if isinstance(execution.get("tamandua_ctl_payload"), dict) else {}
    values = [
        execution.get("guest_stdout"),
        execution.get("stdout"),
        payload.get("output"),
    ]
    return "\n".join(str(value) for value in values if value not in (None, ""))


def execution_output_missing_expected_values(item: dict[str, Any]) -> bool:
    score = item.get("score") or {}
    if not score.get("missing_expected_values"):
        return False
    needles = expected_value_needles(item)
    if not needles:
        return False
    output = execution_output_text(item)
    return not any(contains_expected(output, needle) for needle in needles)


def driver_status_from_health(health: dict[str, Any] | None) -> dict[str, Any]:
    if not health:
        return {}
    snapshot = health.get("snapshot") or {}
    return snapshot.get("driver_status") or {}


def row_text(row: dict[str, Any]) -> str:
    parts = []
    for key in (
        "event_type",
        "title",
        "rule_name",
        "detection_type",
        "mitre_technique",
        "severity",
        "source_name",
    ):
        value = row.get(key)
        if value not in (None, ""):
            parts.append(str(value))
    payload = row.get("payload")
    if isinstance(payload, dict):
        for key in ("process_name", "name", "command_line", "cmdline", "path", "key_path", "remote_ip", "domain"):
            value = payload.get(key)
            if value not in (None, ""):
                parts.append(str(value))
    return " ".join(parts).lower()


CORRELATION_HINTS: dict[str, list[str]] = {
    "credential_access_probe": ["credential", "lsass"],
    "process_sequence": ["process_create"],
    "process_file_sequence": ["process_create", "file_"],
    "suspicious_script_execution": ["powershell_execution_policy_bypass", "encoded", "powershell"],
    "persistence_attempt": ["registry_t1547_001", "registry_set_value", "schtasks", "run key"],
    "file_activity_sequence": ["file_", "del ", "remove-item", "type ", "copy ", "move "],
    "remote_admin_tool_sequence": ["wmi", "winrm", "admin$"],
    "network_process_sequence": ["process_create", "network_connect"],
    "privilege_escalation_attempt": ["privilege", "uac", "scheduled", "service"],
    "service_or_task_sequence": ["service", "schtasks", "scheduled"],
    "network_beacon_sequence": ["beacon", "network_connect", "test-netconnection"],
    "download_execution_sequence": ["download", "curl", "invoke-webrequest"],
    "file_staging_to_network_sequence": ["archive", "staged", "network_connect", "exfil"],
    "archive_then_transfer_sequence": ["archive", "zip", "curl"],
    "remote_management_sequence": ["wmi", "winrm", "psremoting"],
    "dll_search_order_sequence": ["dll", "module_load", "version.dll"],
    "lolbin_proxy_execution_sequence": ["regsvr32", "rundll32", "mshta", "certutil"],
    "defense_evasion_sequence": ["tamper", "defense", "vssadmin", "mppreference"],
}


def score_expected_correlations(
    expected_correlations: list[str],
    event_rows: list[dict[str, Any]],
    alert_rows: list[dict[str, Any]],
    detection_rows: list[dict[str, Any]],
    event_samples: list[dict[str, Any]],
) -> dict[str, Any]:
    if not expected_correlations:
        return {
            "expected_correlations": [],
            "observed_expected_correlations": [],
            "missing_expected_correlations": [],
            "correlation_evidence": {},
        }

    evidence_rows = event_rows + alert_rows + detection_rows + event_samples
    evidence_text = "\n".join(row_text(row) for row in evidence_rows)
    observed: list[str] = []
    evidence: dict[str, list[str]] = {}

    for correlation in expected_correlations:
        hints = CORRELATION_HINTS.get(correlation, [correlation])
        matched = [hint for hint in hints if hint.lower() in evidence_text]
        if matched:
            observed.append(correlation)
            evidence[correlation] = matched

    missing = sorted(set(expected_correlations) - set(observed))
    return {
        "expected_correlations": expected_correlations,
        "observed_expected_correlations": sorted(observed),
        "missing_expected_correlations": missing,
        "correlation_evidence": evidence,
    }


def score_test(
    test: dict[str, Any],
    event_rows: list[dict[str, Any]],
    alert_rows: list[dict[str, Any]],
    detection_rows: list[dict[str, Any]],
    event_samples: list[dict[str, Any]] | None = None,
    driver_health_before: dict[str, Any] | None = None,
    driver_health_after: dict[str, Any] | None = None,
    noise_started_at: dt.datetime | None = None,
) -> dict[str, Any]:
    expected = set(test.get("expected_telemetry") or [])
    optional = set(test.get("optional_telemetry") or [])
    expected_driver_raw = set(test.get("expected_driver_raw_event_types") or [])
    expected_fields = list(test.get("expected_fields") or [])
    expected_fields_by_event_type = test.get("expected_fields_by_event_type") or {}
    expected_values_by_event_type = test.get("expected_values_by_event_type") or {}
    expected_detections = list(test.get("expected_detections") or [])
    expected_alerts = list(test.get("expected_alerts") or [])
    expected_correlations = list(test.get("expected_correlations") or [])
    observed = {str(row.get("event_type")) for row in event_rows}
    fresh_detection_rows = [
        row for row in detection_rows if not report_row_has_stale_source_timestamp(row, noise_started_at)
    ]
    fresh_event_samples = [
        row for row in (event_samples or []) if not report_row_has_stale_source_timestamp(row, noise_started_at)
    ]
    detection_evidence_rows = fresh_detection_rows + inline_detection_rows(fresh_event_samples)
    raw_driver_delta: dict[str, int] = {}
    converted_driver_delta: dict[str, int] = {}
    skipped_driver_delta: dict[str, int] = {}
    missing_driver_raw: list[str] = []
    driver_channel_drops_delta = 0
    driver_kernel_drops_delta = 0

    if driver_health_before is not None and driver_health_after is not None:
        raw_driver_delta = counter_delta(driver_health_before, driver_health_after, "raw_event_type_counts")
        converted_driver_delta = counter_delta(
            driver_health_before,
            driver_health_after,
            "converted_event_type_counts",
        )
        skipped_driver_delta = counter_delta(
            driver_health_before,
            driver_health_after,
            "skipped_event_type_counts",
        )
        missing_driver_raw = sorted(
            event_type for event_type in expected_driver_raw if raw_driver_delta.get(event_type, 0) <= 0
        )
        observed_kernel_driver_events = {
            str(row.get("event_type"))
            for row in event_rows
            if str(row.get("source_name", "")).lower() in {"kernel_driver", "kernel_driver_inferred"}
            and int(row.get("count") or 0) > 0
        }
        missing_driver_raw = [
            event_type for event_type in missing_driver_raw if event_type not in observed_kernel_driver_events
        ]
        before_driver = driver_status_from_health(driver_health_before)
        after_driver = driver_status_from_health(driver_health_after)
        driver_channel_drops_delta = int(after_driver.get("channel_drops") or 0) - int(
            before_driver.get("channel_drops") or 0
        )
        driver_kernel_drops_delta = int(after_driver.get("kernel_events_dropped") or 0) - int(
            before_driver.get("kernel_events_dropped") or 0
        )
    elif expected_driver_raw:
        missing_driver_raw = sorted(expected_driver_raw)

    telemetry_state = telemetry_contract_state(test, observed)
    missing = telemetry_state["missing_expected_telemetry"]
    observed_expected = sorted(expected & observed)
    if telemetry_state["observed_telemetry_alternative"]:
        observed_expected = sorted(set(observed_expected) | set(telemetry_state["observed_telemetry_alternative"]))
    observed_optional = sorted(optional & observed)
    observed_detections, missing_detections = matched_expected(
        detection_evidence_rows,
        expected_detections,
        ["rule_name", "detection_type", "mitre_technique", "description"],
    )
    field_event_samples = event_samples or []
    if expected_fields_by_event_type:
        field_score = score_expected_fields_by_event_type(
            expected_fields_by_event_type,
            field_event_samples,
            required_event_types=set(telemetry_state["observed_telemetry_alternative"])
            or expected
            or {
                event_type
                for group in expected_telemetry_alternatives(test)
                for event_type in group
            },
        )
    else:
        field_score = score_expected_fields(expected_fields, field_event_samples)
    value_score = score_expected_values_by_event_type(
        expected_values_by_event_type,
        fresh_event_samples,
        required_event_types=set(telemetry_state["observed_telemetry_alternative"])
        or expected
        or {
            event_type
            for group in expected_telemetry_alternatives(test)
            for event_type in group
        },
    )
    observed_alerts, missing_alerts = matched_expected(
        alert_rows,
        expected_alerts,
        [
            "title",
            "severity",
            "status",
            "detection_metadata",
            "evidence",
            "mitre_techniques",
            "mitre_tactics",
            "process_chain",
            "contributing_events",
        ],
    )
    matched_alert_rows = matching_items(
        alert_rows,
        expected_alerts,
        [
            "title",
            "severity",
            "status",
            "detection_metadata",
            "evidence",
            "mitre_techniques",
            "mitre_tactics",
            "process_chain",
            "contributing_events",
        ],
    )
    investigable_alert_gaps = alert_context_gaps(matched_alert_rows, test)
    correlation_score = score_expected_correlations(
        expected_correlations,
        event_rows,
        alert_rows,
        fresh_detection_rows,
        fresh_event_samples,
    )

    detection_covered = not missing_detections
    critical_or_high = []
    expected_critical_or_high_alerts = []
    excluded_benchmark_setup_alerts = []
    expected_alert_fragments = expected_alerts + expected_detections
    def row_is_in_measured_noise_window(row: dict[str, Any]) -> bool:
        if noise_started_at is None:
            return True
        row_timestamp = parse_report_timestamp(
            row.get("last_at") or row.get("created_at") or row.get("inserted_at") or row.get("updated_at")
        )
        if row_timestamp is None:
            return True
        return row_timestamp >= noise_started_at

    for row in alert_rows:
        if str(row.get("severity", "")).lower() not in {"high", "critical"}:
            continue
        if not row_is_in_measured_noise_window(row):
            continue

        title = str(row.get("title") or "")
        if (
            detection_covered
            and any(contains_expected(title, fragment) for fragment in expected_alert_fragments)
        ) or alert_matches_test_context(row, test):
            expected_critical_or_high_alerts.append(row)
        elif is_benchmark_setup_alert(row):
            excluded_benchmark_setup_alerts.append(row)
        else:
            critical_or_high.append(row)

    excluded_setup_detection_names = {
        str(
            ((row.get("detection_metadata") or {}).get("rule_name"))
            or ((row.get("evidence") or {}).get("detection") or {}).get("rule_name")
            or row.get("detection_name")
            or ""
        ).lower()
        for row in excluded_benchmark_setup_alerts
    }
    excluded_setup_detection_names.discard("")

    expected_detection_event_keys = {
        (str(row.get("event_type")), str(row.get("severity", "")).lower())
        for row in detection_rows
        if str(row.get("severity", "")).lower() in {"high", "critical"}
    }
    critical_or_high_events = []
    expected_critical_or_high_events = []
    excluded_stale_source_events = []
    for row in event_rows:
        if str(row.get("severity", "")).lower() not in {"high", "critical"}:
            continue
        if not row_is_in_measured_noise_window(row):
            continue

        event_key = (str(row.get("event_type")), str(row.get("severity", "")).lower())
        if detection_covered and event_key in expected_detection_event_keys:
            expected_critical_or_high_events.append(row)
        elif report_row_has_stale_source_timestamp(row, noise_started_at):
            excluded_stale_source_events.append(row)
        elif str(row.get("detection_name") or "").lower() in excluded_setup_detection_names:
            continue
        elif is_benign_edge_update_ntdll_event(row):
            continue
        elif is_benign_windows_error_reporting_ntdll_event(row):
            continue
        elif is_benchmark_service_registry_cleanup_event(row):
            continue
        elif is_benchmark_run_key_persistence_event(row):
            continue
        elif is_benign_defender_manifest_backup_event(row):
            continue
        elif is_benign_edge_update_etw_process_event(row):
            continue
        elif is_benign_windows_service_etw_process_event(row):
            continue
        else:
            critical_or_high_events.append(row)
    unknown_source_events = [
        row
        for row in event_rows
        if str(row.get("source_name", "")).lower() in {"unknown", ""}
        and str(row.get("event_type", "")).lower() != "system_health"
        and str(row.get("detection_name") or "").lower() not in excluded_setup_detection_names
        and not is_benign_edge_update_ntdll_event(row)
        and not is_benign_windows_error_reporting_ntdll_event(row)
        and not is_benchmark_service_registry_cleanup_event(row)
        and not is_benchmark_run_key_persistence_event(row)
        and not is_benign_defender_manifest_backup_event(row)
        and not is_benign_edge_update_etw_process_event(row)
        and not is_benign_windows_service_etw_process_event(row)
        and not report_row_has_stale_source_timestamp(row, noise_started_at)
    ]
    total_events = sum(int(row.get("count") or 0) for row in event_rows)
    unexpected_high_or_critical_event_count = sum(int(row.get("count") or 0) for row in critical_or_high_events)
    unknown_source_event_count = sum(int(row.get("count") or 0) for row in unknown_source_events)
    source_counts = evidence_source_counts(event_rows)

    missing_fields = field_score["missing_expected_fields"]
    missing_values = value_score["missing_expected_values"]
    if (
        missing
        or missing_detections
        or missing_alerts
        or missing_driver_raw
        or missing_fields
        or missing_values
        or correlation_score["missing_expected_correlations"]
        or investigable_alert_gaps
    ):
        status = "partial" if observed_expected else "missed"
    else:
        status = "covered"
    coverage = {
        "telemetry": "ok" if not missing else ("weak" if observed_expected else "missing"),
        "detection": "not_expected" if not expected_detections else ("ok" if not missing_detections else "missing"),
        "alert": "not_expected" if not expected_alerts else ("ok" if not missing_alerts else "missing"),
        "timeline": "ok" if total_events > 0 and observed_expected else "missing",
        "driver_raw": "not_expected" if not expected_driver_raw else ("ok" if not missing_driver_raw else "missing"),
        "fields": "not_expected"
        if not expected_fields and not expected_fields_by_event_type
        else ("ok" if not missing_fields else "missing"),
        "values": "not_expected" if not expected_values_by_event_type else ("ok" if not missing_values else "missing"),
        "correlation": "not_expected"
        if not expected_correlations
        else ("ok" if not correlation_score["missing_expected_correlations"] else "missing"),
    }

    return {
        "status": status,
        "coverage": coverage,
        "expected_telemetry": sorted(expected),
        "expected_telemetry_any": telemetry_state["expected_telemetry_any"],
        "optional_telemetry": sorted(optional),
        "expected_detections": expected_detections,
        "expected_alerts": expected_alerts,
        "expected_correlations": expected_correlations,
        "expected_driver_raw_event_types": sorted(expected_driver_raw),
        "observed_expected_telemetry": observed_expected,
        "observed_telemetry_alternative": telemetry_state["observed_telemetry_alternative"],
        "telemetry_any_results": telemetry_state["telemetry_any_results"],
        "observed_optional_telemetry": observed_optional,
        "driver_raw_event_type_delta": raw_driver_delta,
        "driver_converted_event_type_delta": converted_driver_delta,
        "driver_skipped_event_type_delta": skipped_driver_delta,
        "driver_channel_drops_delta": max(driver_channel_drops_delta, 0),
        "driver_kernel_drops_delta": max(driver_kernel_drops_delta, 0),
        "missing_expected_driver_raw_event_types": missing_driver_raw,
        **field_score,
        **value_score,
        **correlation_score,
        "observed_expected_detections": observed_detections,
        "missing_expected_detections": missing_detections,
        "observed_expected_alerts": observed_alerts,
        "missing_expected_alerts": missing_alerts,
        "investigable_alert_gaps": investigable_alert_gaps,
        "missing_expected_telemetry": missing,
        "missing_strict_expected_telemetry": telemetry_state["missing_strict_expected_telemetry"],
        "expected_high_or_critical_alerts": expected_critical_or_high_alerts,
        "unexpected_high_or_critical_alerts": critical_or_high,
        "excluded_benchmark_setup_alerts": excluded_benchmark_setup_alerts,
        "excluded_stale_source_events": excluded_stale_source_events,
        "expected_high_or_critical_events": expected_critical_or_high_events,
        "unexpected_high_or_critical_events": critical_or_high_events,
        "unexpected_high_or_critical_event_count": unexpected_high_or_critical_event_count,
        "unknown_source_events": unknown_source_events,
        "unknown_source_event_count": unknown_source_event_count,
        "evidence_source_counts": source_counts,
        "evidence_source_status": {
            source: "weak" if source.lower() in {"unknown", ""} else "ok"
            for source in source_counts
        },
        "total_events": total_events,
        "evidence_quality": {
            "source_attribution": "weak" if unknown_source_event_count else "ok",
            "severity_noise": "review" if unexpected_high_or_critical_event_count else "ok",
            "detection_coverage": "weak" if missing_detections else "ok",
            "alert_coverage": "weak" if missing_alerts else "ok",
            "alert_context": "weak" if investigable_alert_gaps else "ok",
            "driver_raw_coverage": "weak" if missing_driver_raw else "ok",
            "field_coverage": "weak" if missing_fields else "ok",
            "value_coverage": "weak" if missing_values else "ok",
            "correlation_coverage": "weak" if correlation_score["missing_expected_correlations"] else "ok",
        },
    }


def score_transport_only_execution(test: dict[str, Any], execution: dict[str, Any]) -> dict[str, Any]:
    expected = set(test.get("expected_telemetry") or [])
    expected_fields = list(test.get("expected_fields") or [])
    expected_fields_by_event_type = test.get("expected_fields_by_event_type") or {}
    expected_values_by_event_type = test.get("expected_values_by_event_type") or {}
    payload = execution.get("tamandua_ctl_payload") if isinstance(execution, dict) else None
    payload = payload if isinstance(payload, dict) else {}
    observed: set[str] = set()

    if str(payload.get("status") or "").lower() == "completed":
        observed.add("live_response_command_completed")

    telemetry_state = telemetry_contract_state(test, observed)
    missing = telemetry_state["missing_expected_telemetry"]
    event_samples = [
        {
            "event_type": event_type,
            "source_name": "live_response_audit",
            "payload": payload,
        }
        for event_type in observed
    ]
    if expected_fields_by_event_type:
        field_score = score_expected_fields_by_event_type(
            expected_fields_by_event_type,
            event_samples,
            required_event_types=set(telemetry_state["observed_telemetry_alternative"]) or observed,
        )
    else:
        field_score = score_expected_fields(expected_fields, event_samples)
    value_score = score_expected_values_by_event_type(
        expected_values_by_event_type,
        event_samples,
        required_event_types=set(telemetry_state["observed_telemetry_alternative"]) or observed,
    )
    missing_fields = field_score["missing_expected_fields"]
    missing_values = value_score["missing_expected_values"]
    status = "covered" if not missing and not missing_fields and not missing_values else ("partial" if observed else "missed")

    return {
        "status": status,
        "coverage": {
            "telemetry": "ok" if not missing else ("weak" if observed else "missing"),
            "detection": "not_expected",
            "alert": "not_expected",
            "timeline": "not_expected",
            "driver_raw": "not_expected",
            "fields": "ok" if not missing_fields else "missing",
            "values": "not_expected" if not expected_values_by_event_type else ("ok" if not missing_values else "missing"),
            "correlation": "not_expected",
        },
        "expected_telemetry": sorted(expected),
        "expected_telemetry_any": telemetry_state["expected_telemetry_any"],
        "observed_expected_telemetry": sorted(expected & observed),
        "observed_telemetry_alternative": telemetry_state["observed_telemetry_alternative"],
        "telemetry_any_results": telemetry_state["telemetry_any_results"],
        "missing_expected_telemetry": missing,
        "missing_strict_expected_telemetry": telemetry_state["missing_strict_expected_telemetry"],
        **field_score,
        **value_score,
        "expected_detections": [],
        "missing_expected_detections": [],
        "expected_alerts": [],
        "missing_expected_alerts": [],
        "expected_correlations": [],
        "missing_expected_correlations": [],
        "expected_driver_raw_event_types": [],
        "missing_expected_driver_raw_event_types": [],
        "investigable_alert_gaps": [],
        "unexpected_high_or_critical_alerts": [],
        "unexpected_high_or_critical_events": [],
        "excluded_benchmark_setup_alerts": [],
        "unknown_source_events": [],
        "driver_channel_drops_delta": 0,
        "driver_kernel_drops_delta": 0,
        "total_events": 0,
        "evidence_source_counts": {},
        "transport_evidence": {
            "status": payload.get("status"),
            "session_id": payload.get("session_id"),
            "hostname": payload.get("hostname"),
            "end_reason": payload.get("end_reason"),
            "duration_ms": payload.get("duration_ms"),
        },
    }


def live_response_execution_evidence(execution: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Expose tamandua-ctl live-response audit as benchmark evidence.

    This is intentionally separate from endpoint telemetry. A completed
    live-response command proves the execution/audit channel, but it should only
    satisfy endpoint detection profiles when the profile explicitly accepts
    `live_response_command_completed` as an alternative signal.
    """
    if not isinstance(execution, dict):
        return []

    payload = execution.get("tamandua_ctl_payload")
    payload = payload if isinstance(payload, dict) else {}
    if str(payload.get("status") or "").lower() != "completed":
        return []
    output = str(payload.get("output") or "")
    shell_name = Path(str(payload.get("shell") or "/bin/sh")).name or "live_response_shell"

    return [
        {
            "event_type": "live_response_command_completed",
            "severity": "info",
            "source_name": "live_response_audit",
            "count": 1,
            "last_at": payload.get("finished_at") or payload.get("ended_at"),
            "agent_id": payload.get("agent_id"),
            "hostname": payload.get("hostname"),
            "process_name": shell_name,
            "command_line": payload.get("command"),
            "user": payload.get("user") or payload.get("operator") or "live_response_operator",
            "payload": {
                "agent_id": payload.get("agent_id"),
                "hostname": payload.get("hostname"),
                "process_name": shell_name,
                "command_line": payload.get("command"),
                "user": payload.get("user") or payload.get("operator") or "live_response_operator",
                "command": payload.get("command"),
                "session_id": payload.get("session_id"),
                "audit_resource_id": payload.get("audit_resource_id"),
                "audit_resource_type": payload.get("audit_resource_type"),
                "duration_ms": payload.get("duration_ms"),
                "end_reason": payload.get("end_reason"),
                "output": output[-4000:] if output else "",
            },
        }
    ]


def evaluate_gates(report: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    summary = report.get("summary") or {}
    lane = str(getattr(args, "benchmark_lane", "stable-regression") or "stable-regression")
    failures = []
    if args.fail_on_missed and int(summary.get("missed") or 0) > 0:
        failures.append("missed_tests")
    if args.fail_on_partial and int(summary.get("partial") or 0) > 0:
        failures.append("partial_tests")
    if int(summary.get("execution_failed") or 0) > 0:
        failures.append("execution_failed_tests")
    if int(summary.get("infra_blocked") or 0) > 0:
        failures.append("infrastructure_blocked_tests")
    if int(summary.get("executed_without_server_evidence") or 0) > 0:
        failures.append("executed_without_server_evidence")
    if int(summary.get("missing_expected_driver_raw_events") or 0) > 0:
        failures.append("missing_expected_driver_raw_events")
    if int(summary.get("missing_expected_fields") or 0) > 0:
        failures.append("missing_expected_fields")
    if int(summary.get("missing_expected_values") or 0) > 0:
        failures.append("missing_expected_values")
    if int(summary.get("investigable_alert_gaps") or 0) > 0:
        failures.append("investigable_alert_gaps")
    if int(summary.get("missing_expected_correlations") or 0) > 0:
        failures.append("missing_expected_correlations")
    if args.max_driver_channel_drops >= 0:
        if int(summary.get("driver_channel_drops") or 0) > args.max_driver_channel_drops:
            failures.append("driver_channel_drops")
    if args.max_driver_kernel_drops >= 0:
        if int(summary.get("driver_kernel_drops") or 0) > args.max_driver_kernel_drops:
            failures.append("driver_kernel_drops")
    if args.max_unexpected_high_critical >= 0:
        noisy = int(summary.get("unexpected_high_or_critical_events") or 0) + int(
            summary.get("unexpected_high_or_critical_alerts") or 0
        )
        if noisy > args.max_unexpected_high_critical:
            failures.append("unexpected_high_or_critical_events_or_alerts")
    if args.max_unknown_source >= 0:
        unknown = int(summary.get("unknown_source_events") or 0)
        if unknown > args.max_unknown_source:
            failures.append("unknown_source_events")
    if getattr(args, "require_upstream", False) and int(summary.get("fallback_command_tests") or 0) > 0:
        failures.append("fallback_used_when_upstream_required")
    if getattr(args, "require_upstream", False) and int(summary.get("upstream_backed_tests") or 0) <= 0:
        failures.append("no_upstream_backed_tests")
    if lane in {"atomic-upstream", "caldera-upstream"}:
        if int(summary.get("deterministic_command_tests") or 0) > 0:
            failures.append("deterministic_tests_in_upstream_lane")
        if int(summary.get("fallback_command_tests") or 0) > 0:
            failures.append("fallback_tests_in_upstream_lane")
    if lane == "atomic-upstream" and int((summary.get("executor_counts") or {}).get("atomic_red_team") or 0) <= 0:
        failures.append("no_atomic_red_team_tests")
    if lane == "caldera-upstream" and int((summary.get("executor_counts") or {}).get("caldera_operation") or 0) <= 0:
        failures.append("no_caldera_operation_tests")
    restore_readiness = report.get("fresh_restore_provenance_readiness")
    if isinstance(restore_readiness, dict) and restore_readiness.get("ready") is False:
        failures.append("fresh_restore_provenance_incomplete")

    return {
        "passed": not failures,
        "failures": failures,
        "gap_category_counts": summary.get("gap_category_counts") or {},
        "actionable_gaps": (
            (
                [
                    {
                        "test_id": "fresh_restore_provenance",
                        "status": "missed",
                        "gap_category": "claim-boundary",
                        "missing_expected_fields": restore_readiness.get("missing_fields") or [],
                        "validation_category": "fresh_restore_provenance",
                    }
                ]
                if isinstance(restore_readiness, dict) and restore_readiness.get("ready") is False
                else []
            )
            + (summary.get("actionable_gaps") or [])
        )[:25],
        "thresholds": {
            "fail_on_missed": args.fail_on_missed,
            "fail_on_partial": args.fail_on_partial,
            "max_unexpected_high_critical": args.max_unexpected_high_critical,
            "max_unknown_source": args.max_unknown_source,
            "max_driver_channel_drops": args.max_driver_channel_drops,
            "max_driver_kernel_drops": args.max_driver_kernel_drops,
            "require_upstream": getattr(args, "require_upstream", False),
            "benchmark_lane": lane,
            "fresh_restore_provenance_required_when_claimed": True,
        },
    }


def apply_benchmark_lane_defaults(args: argparse.Namespace) -> None:
    lane = str(getattr(args, "benchmark_lane", "stable-regression") or "stable-regression")

    if lane in {"atomic-upstream", "caldera-upstream"}:
        args.require_upstream = True
        args.fail_on_partial = True
        args.max_unknown_source = 0 if args.max_unknown_source < 0 else args.max_unknown_source
        args.max_unexpected_high_critical = (
            0 if args.max_unexpected_high_critical < 0 else args.max_unexpected_high_critical
        )

    if lane == "enterprise-eval":
        args.fail_on_partial = True
        args.max_unknown_source = 0 if args.max_unknown_source < 0 else args.max_unknown_source
        args.max_unexpected_high_critical = (
            0 if args.max_unexpected_high_critical < 0 else args.max_unexpected_high_critical
        )
        args.max_driver_channel_drops = 0 if args.max_driver_channel_drops < 0 else args.max_driver_channel_drops
        args.max_driver_kernel_drops = 0 if args.max_driver_kernel_drops < 0 else args.max_driver_kernel_drops


def apply_profile_quality_bar(args: argparse.Namespace, profile: dict[str, Any]) -> None:
    quality_bar = profile.get("quality_bar") or {}
    if args.max_unknown_source < 0 and "max_unknown_source_events" in quality_bar:
        args.max_unknown_source = int(quality_bar["max_unknown_source_events"])
    if args.max_unexpected_high_critical < 0 and "max_unexpected_high_critical" in quality_bar:
        args.max_unexpected_high_critical = int(quality_bar["max_unexpected_high_critical"])
    if args.max_driver_channel_drops < 0 and "max_driver_channel_drops" in quality_bar:
        args.max_driver_channel_drops = int(quality_bar["max_driver_channel_drops"])
    if args.max_driver_kernel_drops < 0 and "max_driver_kernel_drops" in quality_bar:
        args.max_driver_kernel_drops = int(quality_bar["max_driver_kernel_drops"])


def ratio(numerator: int | float, denominator: int | float) -> float:
    if not denominator:
        return 0.0
    return round(float(numerator) / float(denominator), 4)


def benchmark_scorecard(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary") or {}
    min_external_tests = 5
    if not report.get("execute"):
        return {
            "maturity_score": 0,
            "maturity_band": "planned",
            "telemetry_rate": 0.0,
            "covered_rate": 0.0,
            "upstream_rate": 0.0,
            "field_quality": 0.0,
            "analytic_quality": 0.0,
            "context_quality": 0.0,
            "noise_quality": 0.0,
            "driver_quality": 0.0,
            "external_claim_allowed": False,
            "recommended_claim": "dry-run plan only; no detection maturity claim",
            "blocking_gaps": ["not_executed"],
        }

    tests = int(summary.get("tests") or 0)
    covered = int(summary.get("covered") or 0)
    partial = int(summary.get("partial") or 0)
    upstream = int(summary.get("upstream_backed_tests") or 0)
    fallback = int(summary.get("fallback_command_tests") or 0)
    deterministic = int(summary.get("deterministic_command_tests") or 0)
    gate_passed = bool((report.get("quality_gate") or {}).get("passed", True))
    missing_fields = int(summary.get("missing_expected_fields") or 0)
    missing_values = int(summary.get("missing_expected_values") or 0)
    missing_detections = int(summary.get("missing_expected_detections") or 0)
    missing_alerts = int(summary.get("missing_expected_alerts") or 0)
    missing_correlations = int(summary.get("missing_expected_correlations") or 0)
    alert_gaps = int(summary.get("investigable_alert_gaps") or 0)
    noise = int(summary.get("unexpected_high_or_critical_events") or 0) + int(
        summary.get("unexpected_high_or_critical_alerts") or 0
    )
    unknown = int(summary.get("unknown_source_events") or 0)
    driver_drops = int(summary.get("driver_channel_drops") or 0) + int(summary.get("driver_kernel_drops") or 0)
    driver_missing = int(summary.get("missing_expected_driver_raw_events") or 0)
    server_evidence_gap = int(summary.get("executed_without_server_evidence") or 0)

    telemetry_rate = ratio(covered + partial, tests)
    covered_rate = ratio(covered, tests)
    upstream_rate = ratio(upstream, tests)
    field_quality = (
        1.0
        if missing_fields + missing_values == 0
        else max(0.0, 1.0 - ratio(missing_fields + missing_values, max(tests, 1)))
    )
    analytic_quality = 1.0 if (missing_detections + missing_alerts) == 0 else max(
        0.0,
        1.0 - ratio(missing_detections + missing_alerts, max(tests, 1)),
    )
    context_quality = 1.0 if (alert_gaps + missing_correlations) == 0 else max(
        0.0,
        1.0 - ratio(alert_gaps + missing_correlations, max(tests, 1)),
    )
    noise_quality = 1.0 if (noise + unknown) == 0 else 0.0
    driver_quality = 1.0 if (driver_drops + driver_missing) == 0 else 0.0

    maturity_score = round(
        25 * telemetry_rate
        + 20 * covered_rate
        + 15 * field_quality
        + 15 * analytic_quality
        + 10 * context_quality
        + 5 * noise_quality
        + 5 * driver_quality
        + 5 * upstream_rate
    )

    # A clean deterministic run is valuable engineering evidence, but it is not
    # equivalent to Atomic Red Team/CALDERA-backed validation or vendor-grade
    # comparison data. Cap the headline score so the report cannot overclaim.
    if tests > 0 and upstream == 0:
        maturity_score = min(maturity_score, 74)
    elif tests > 0 and upstream < tests:
        maturity_score = min(maturity_score, 84)
    if server_evidence_gap > 0:
        maturity_score = min(maturity_score, 44)

    if maturity_score >= 90 and gate_passed and upstream_rate >= 0.8 and tests >= min_external_tests:
        maturity_band = "external-comparison-ready"
    elif maturity_score >= 80 and gate_passed:
        maturity_band = "release-candidate"
    elif maturity_score >= 65:
        maturity_band = "engineering-validation"
    elif maturity_score >= 45:
        maturity_band = "calibration"
    else:
        maturity_band = "prototype"

    external_claim_allowed = (
        gate_passed
        and tests >= min_external_tests
        and upstream == tests
        and fallback == 0
        and deterministic == 0
        and maturity_score >= 85
    )

    if external_claim_allowed:
        recommended_claim = "upstream-backed benchmark for the selected profile"
    elif upstream > 0 and tests < min_external_tests:
        recommended_claim = (
            f"upstream-backed smoke/regression ({tests} tests); external comparison requires "
            f"at least {min_external_tests} upstream-backed tests"
        )
    elif upstream > 0:
        recommended_claim = "mixed upstream/regression validation; do not use as vendor comparison"
    elif fallback > 0:
        recommended_claim = "Atomic-style fallback regression; not Atomic-backed"
    elif deterministic > 0:
        recommended_claim = "Tamandua deterministic regression; not external-tool-backed"
    else:
        recommended_claim = "planned or incomplete validation"

    return {
        "maturity_score": maturity_score,
        "maturity_band": maturity_band,
        "telemetry_rate": telemetry_rate,
        "covered_rate": covered_rate,
        "upstream_rate": upstream_rate,
        "field_quality": round(field_quality, 4),
        "analytic_quality": round(analytic_quality, 4),
        "context_quality": round(context_quality, 4),
        "noise_quality": round(noise_quality, 4),
        "driver_quality": round(driver_quality, 4),
        "external_claim_allowed": external_claim_allowed,
        "recommended_claim": recommended_claim,
        "blocking_gaps": [
            gap
            for gap, active in [
                ("quality_gate_failed", not gate_passed),
                ("fallback_commands_present", fallback > 0),
                ("deterministic_commands_present", deterministic > 0),
                ("insufficient_upstream_test_count_for_external_claim", upstream > 0 and tests < min_external_tests),
                ("not_all_tests_upstream_backed", tests > 0 and upstream < tests),
                ("missing_expected_fields", missing_fields > 0),
                ("missing_expected_values", missing_values > 0),
                ("missing_expected_detections", missing_detections > 0),
                ("missing_expected_alerts", missing_alerts > 0),
                ("missing_expected_correlations", missing_correlations > 0),
                ("investigable_alert_gaps", alert_gaps > 0),
                ("unexpected_high_critical_or_unknown_noise", noise + unknown > 0),
                ("driver_missing_or_drops", driver_missing + driver_drops > 0),
                ("missing_server_evidence", server_evidence_gap > 0),
            ]
            if active
        ],
    }


def target_fingerprint(report: dict[str, Any]) -> dict[str, Any]:
    preflight = report.get("preflight") or {}
    target = preflight.get("preflight") if isinstance(preflight, dict) else None
    if not isinstance(target, dict):
        return {}
    os_info = target.get("os") if isinstance(target.get("os"), dict) else {}
    return {
        "hostname": target.get("hostname"),
        "agent_service": target.get("agent_service"),
        "driver_service": target.get("driver_service"),
        "driver_loaded": target.get("driver_loaded"),
        "agent_hash": target.get("agent_hash"),
        "driver_hash": target.get("driver_hash"),
        "os_caption": os_info.get("Caption"),
        "os_version": os_info.get("Version"),
        "os_build": os_info.get("BuildNumber"),
    }


def upstream_readiness_checklist(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary") or {}
    quality_gate = report.get("quality_gate") or {}
    lane = str(report.get("benchmark_lane") or "stable-regression")
    selected = report.get("tests") or []
    atomic_capable = [test for test in selected if test.get("executor_requested") == "atomic_or_command"]
    caldera_tests = [test for test in selected if test.get("executor_requested") == "caldera_operation"]
    caldera_proofs = [
        (test.get("execution") or {}).get("caldera_proof") or {}
        for test in caldera_tests
    ]
    atomic = {
        "lane": lane,
        "ready": (
            lane == "atomic-upstream"
            and bool(atomic_capable)
            and int(summary.get("fallback_command_tests") or 0) == 0
            and int((summary.get("executor_counts") or {}).get("atomic_red_team") or 0) == len(atomic_capable)
            and bool(quality_gate.get("passed", False))
        ),
        "items": {
            "atomic_profile_selected": bool(atomic_capable),
            "atomic_upstream_lane": lane == "atomic-upstream",
            "all_atomic_capable_tests_upstream_backed": bool(atomic_capable)
            and int(summary.get("fallback_command_tests") or 0) == 0
            and int((summary.get("executor_counts") or {}).get("atomic_red_team") or 0) == len(atomic_capable),
            "no_fallback_commands": int(summary.get("fallback_command_tests") or 0) == 0,
            "quality_gate_passed": bool(quality_gate.get("passed", False)),
        },
    }
    caldera = {
        "lane": lane,
        "ready": (
            lane == "caldera-upstream"
            and bool(caldera_tests)
            and len(caldera_proofs) == len(caldera_tests)
            and all(proof.get("operation_id") and proof.get("adversary_id") and proof.get("paw") for proof in caldera_proofs)
            and all(proof.get("success") for proof in caldera_proofs)
            and bool(quality_gate.get("passed", False))
        ),
        "items": {
            "caldera_profile_selected": bool(caldera_tests),
            "caldera_upstream_lane": lane == "caldera-upstream",
            "operation_proof_recorded": bool(caldera_tests)
            and len(caldera_proofs) == len(caldera_tests)
            and all(proof.get("operation_id") for proof in caldera_proofs),
            "adversary_group_and_paw_recorded": bool(caldera_tests)
            and all(proof.get("adversary_id") and proof.get("group") and proof.get("paw") for proof in caldera_proofs),
            "operations_succeeded": bool(caldera_tests) and all(proof.get("success") for proof in caldera_proofs),
            "quality_gate_passed": bool(quality_gate.get("passed", False)),
        },
    }
    return {"atomic_red_team": atomic, "caldera": caldera}


def comparison_export(report: dict[str, Any]) -> dict[str, Any]:
    """Stable, low-noise JSON for comparing benchmark runs across builds."""
    tests = []
    for item in sorted(report.get("tests") or [], key=lambda value: str(value.get("id") or "")):
        score = item.get("score") or {}
        tests.append(
            {
                "id": item.get("id"),
                "status": score.get("status") or item.get("status"),
                "claim_level": item.get("claim_level"),
                "execution_class": item.get("execution_class"),
                "validation_category": item.get("validation_category"),
                "roadmap_traceability": item.get("roadmap_traceability"),
                "executor_used": item.get("executor_used"),
                "upstream_backed": bool(item.get("upstream_backed")),
                "fallback_used": bool(item.get("fallback_used")),
                "coverage": score.get("coverage") or {},
                "gap_category": gap_category(item),
                "evidence_source_counts": score.get("evidence_source_counts") or {},
                "missing_expected_telemetry": score.get("missing_expected_telemetry") or [],
                "missing_strict_expected_telemetry": score.get("missing_strict_expected_telemetry") or [],
                "expected_telemetry_any": score.get("expected_telemetry_any") or [],
                "observed_telemetry_alternative": score.get("observed_telemetry_alternative") or [],
                "missing_expected_fields": score.get("missing_expected_fields") or [],
                "missing_expected_detections": score.get("missing_expected_detections") or [],
                "missing_expected_alerts": score.get("missing_expected_alerts") or [],
                "missing_expected_correlations": score.get("missing_expected_correlations") or [],
                "missing_expected_driver_raw_event_types": score.get("missing_expected_driver_raw_event_types") or [],
            }
        )
    return {
        "schema_version": 1,
        "profile_id": (report.get("profile") or {}).get("profile_id"),
        "benchmark_lane": report.get("benchmark_lane"),
        "execute": bool(report.get("execute")),
        "quality_gate": report.get("quality_gate"),
        "scorecard": report.get("scorecard"),
        "summary": {
            key: (report.get("summary") or {}).get(key)
            for key in [
                "tests",
                "covered",
                "partial",
                "missed",
                "planned",
                "execution_failed",
                "executor_counts",
                "execution_class_counts",
                "claim_level_counts",
                "gap_category_counts",
                "actionable_gaps",
                "evidence_source_coverage",
                "tactic_coverage",
                "technique_coverage",
                "category_coverage",
                "upstream_backed_tests",
                "fallback_command_tests",
                "deterministic_command_tests",
                "unknown_source_events",
                "unexpected_high_or_critical_events",
                "unexpected_high_or_critical_alerts",
                "excluded_benchmark_setup_alerts",
                "excluded_stale_source_events",
                "missing_expected_driver_raw_events",
                "missing_expected_fields",
                "missing_expected_values",
                "investigable_alert_gaps",
            ]
        },
        "upstream_readiness": report.get("upstream_readiness"),
        "tests": tests,
    }


def gap_category(item: dict[str, Any]) -> str:
    """Classify the primary gap in a benchmark test for triage routing."""
    score = item.get("score") or {}
    status = str(score.get("status") or item.get("status") or "")
    score_gap = str(score.get("gap_category") or "")
    if status == "covered":
        return "none"
    if status == "infra_blocked":
        return score_gap or "infrastructure"
    if status == "execution_failed":
        return score_gap or "runner"
    if status == "executed_without_server_evidence":
        return "collector"
    if item.get("fallback_used") or item.get("execution_class") == "fallback":
        return "claim-boundary"
    if score.get("missing_expected_driver_raw_event_types"):
        return "collector"
    if score.get("missing_expected_telemetry"):
        return "collector"
    if score.get("missing_expected_values"):
        if execution_output_missing_expected_values(item):
            return "runner"
        return "collector"
    if score.get("missing_expected_fields"):
        return "normalization"
    if is_response_audit_test(item) and (score.get("missing_expected_alerts") or score.get("investigable_alert_gaps")):
        return "response-audit"
    if score.get("missing_expected_detections") or score.get("missing_expected_alerts"):
        return "detector"
    if score.get("missing_expected_correlations") or score.get("investigable_alert_gaps"):
        return "alert-quality"
    if score.get("unknown_source_events") or score.get("unexpected_high_or_critical_events") or score.get(
        "unexpected_high_or_critical_alerts"
    ):
        return "noise"
    return "unknown"


def md_cell(value: Any, max_len: int = 96) -> str:
    if value is None:
        return "-"
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return "-"
    text = text.replace("|", "\\|")
    if len(text) > max_len:
        return text[: max_len - 1].rstrip() + "..."
    return text


def summary_rows(section: Any) -> list[dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    rows = section.get("rows")
    return rows if isinstance(rows, list) else []


def compact_baseline_lines(baseline: dict[str, Any]) -> list[str]:
    event_rows = summary_rows(baseline.get("event_summary"))
    detection_rows = summary_rows(baseline.get("detection_summary"))
    alert_rows = summary_rows(baseline.get("alert_summary"))
    lines = [
        "",
        "## Baseline",
        "",
        f"- Window: `{baseline.get('started_at') or '-'} -> {baseline.get('ended_at') or '-'}`",
        f"- Event groups: `{len(event_rows)}`",
        f"- Detection groups: `{len(detection_rows)}`",
        f"- Alerts: `{len(alert_rows)}`",
        "",
    ]

    if event_rows:
        lines.extend(
            [
                "### Baseline Events",
                "",
                "| Source | Event | Severity | Detection | Count | Last seen |",
                "|--------|-------|----------|-----------|-------|-----------|",
            ]
        )
        for row in event_rows[:12]:
            lines.append(
                f"| `{md_cell(row.get('source_name'))}` | `{md_cell(row.get('event_type'))}` | "
                f"`{md_cell(row.get('severity'))}` | `{md_cell(row.get('detection_name'))}` | "
                f"`{row.get('count') or 0}` | `{md_cell(row.get('last_at'))}` |"
            )
        lines.append("")

    if detection_rows:
        lines.extend(
            [
                "### Baseline Detections",
                "",
                "| Rule | Type | Technique | Event | Severity | Count | Last seen |",
                "|------|------|-----------|-------|----------|-------|-----------|",
            ]
        )
        for row in detection_rows[:12]:
            lines.append(
                f"| `{md_cell(row.get('rule_name'))}` | `{md_cell(row.get('detection_type'))}` | "
                f"`{md_cell(row.get('mitre_technique'))}` | `{md_cell(row.get('event_type'))}` | "
                f"`{md_cell(row.get('severity'))}` | `{row.get('count') or 0}` | `{md_cell(row.get('last_at'))}` |"
            )
        lines.append("")

    if alert_rows:
        lines.extend(
            [
                "### Baseline Alerts",
                "",
                "| Title | Severity | Status | Last seen |",
                "|-------|----------|--------|-----------|",
            ]
        )
        for row in alert_rows[:12]:
            lines.append(
                f"| `{md_cell(row.get('title'), 120)}` | `{md_cell(row.get('severity'))}` | "
                f"`{md_cell(row.get('status'))}` | `{md_cell(row.get('last_at'))}` |"
            )
        lines.append("")
    else:
        lines.extend(["No baseline alerts were observed before the CALDERA run.", ""])

    return lines


def compact_preflight_lines(preflight: Any) -> list[str]:
    if not isinstance(preflight, dict):
        return ["", "## Preflight", "", "No preflight metadata was recorded.", ""]

    nested = preflight.get("preflight") if isinstance(preflight.get("preflight"), dict) else {}
    probes = preflight.get("probes") if isinstance(preflight.get("probes"), dict) else {}
    lines = [
        "",
        "## Preflight",
        "",
        f"- Outer exit code: `{preflight.get('outer_exit_code', '-')}`",
        f"- Guest stdout captured: `{'yes' if preflight.get('guest_stdout') else 'no'}`",
        f"- Guest stderr captured: `{'yes' if preflight.get('guest_stderr') else 'no'}`",
    ]
    if nested:
        lines.extend(
            [
                f"- Agent service: `{nested.get('agent_service') or nested.get('service_status') or '-'}`",
                f"- Driver service: `{nested.get('driver_service') or nested.get('driver_status') or '-'}`",
                f"- Hostname: `{nested.get('hostname') or '-'}`",
            ]
        )
    lines.append("")

    if probes:
        lines.extend(["### Probe Results", "", "| Probe | Result |", "|-------|--------|"])
        for key, value in sorted(probes.items()):
            if isinstance(value, dict):
                status = value.get("status") or value.get("result") or value.get("ok")
                if status is None:
                    guest_exit = value.get("guest_exit_code")
                    outer_exit = value.get("outer_exit_code")
                    status = "ok" if guest_exit == 0 and outer_exit == 0 else f"guest={guest_exit}, outer={outer_exit}"
            else:
                status = value
            lines.append(f"| `{md_cell(key)}` | `{md_cell(status)}` |")
        lines.append("")

    lines.extend(
        [
            "Full command lines, stdout/stderr and raw probe payloads are intentionally kept in the JSON artifact, not in this Markdown report.",
            "",
        ]
    )
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    fingerprint = target_fingerprint(report)
    lines = [
        f"# Tamandua Detection Validation Run {report['run_id']}",
        "",
        f"- Profile: `{report['profile']['profile_id']}`",
        f"- Started: `{report['started_at']}`",
        f"- Finished: `{report['finished_at']}`",
        f"- Mode: `{'execute' if report['execute'] else 'dry-run'}`",
        f"- Benchmark lane: `{report.get('benchmark_lane') or 'stable-regression'}`",
        f"- Target VMID: `{report['target'].get('vmid')}`",
        f"- Agent ID: `{report['target'].get('agent_id') or 'not provided'}`",
        f"- Hostname: `{fingerprint.get('hostname') or 'unknown'}`",
        f"- OS build: `{fingerprint.get('os_build') or 'unknown'}`",
        f"- Agent hash: `{fingerprint.get('agent_hash') or 'unknown'}`",
        f"- Driver hash: `{fingerprint.get('driver_hash') or 'unknown'}`",
        f"- Git commit: `{report['git'].get('commit_short')}`",
        "",
        "## Summary",
        "",
    ]

    totals = report.get("summary", {})
    scorecard = report.get("scorecard") or {}
    executor_counts = totals.get("executor_counts") or {}
    execution_class_counts = totals.get("execution_class_counts") or {}
    lines.extend(
        [
            f"- Maturity score: `{scorecard.get('maturity_score', 0)}/100`",
            f"- Maturity band: `{scorecard.get('maturity_band', 'unknown')}`",
            f"- Recommended claim: `{scorecard.get('recommended_claim', 'unknown')}`",
            f"- External comparison claim allowed: `{scorecard.get('external_claim_allowed', False)}`",
            f"- Tests: `{totals.get('tests', 0)}`",
            f"- Covered: `{totals.get('covered', 0)}`",
            f"- Partial: `{totals.get('partial', 0)}`",
            f"- Missed: `{totals.get('missed', 0)}`",
            f"- Dry-run planned only: `{totals.get('planned', 0)}`",
            f"- Upstream-backed tests: `{totals.get('upstream_backed_tests', 0)}`",
            f"- Fallback-command tests: `{totals.get('fallback_command_tests', 0)}`",
            f"- Deterministic-command tests: `{totals.get('deterministic_command_tests', 0)}`",
            f"- Executor mix: `{', '.join(f'{key}={value}' for key, value in sorted(executor_counts.items())) or '-'}`",
            f"- Execution classes: `{', '.join(f'{key}={value}' for key, value in sorted(execution_class_counts.items())) or '-'}`",
            f"- Claim levels: `{', '.join(f'{key}={value}' for key, value in sorted((totals.get('claim_level_counts') or {}).items())) or '-'}`",
            f"- Gap categories: `{', '.join(f'{key}={value}' for key, value in sorted((totals.get('gap_category_counts') or {}).items())) or '-'}`",
            f"- Unknown source events: `{totals.get('unknown_source_events', 0)}`",
            f"- Unexpected high/critical events: `{totals.get('unexpected_high_or_critical_events', 0)}`",
            f"- Unexpected high/critical alerts: `{totals.get('unexpected_high_or_critical_alerts', 0)}`",
            f"- Excluded benchmark setup alerts: `{totals.get('excluded_benchmark_setup_alerts', 0)}`",
            f"- Excluded stale source-timestamp events: `{totals.get('excluded_stale_source_events', 0)}`",
            f"- Missing driver raw events: `{totals.get('missing_expected_driver_raw_events', 0)}`",
            f"- Driver channel drops: `{totals.get('driver_channel_drops', 0)}`",
            f"- Driver kernel drops: `{totals.get('driver_kernel_drops', 0)}`",
            f"- Missing expected fields: `{totals.get('missing_expected_fields', 0)}`",
            f"- Missing expected values: `{totals.get('missing_expected_values', 0)}`",
            f"- Missing expected correlations: `{totals.get('missing_expected_correlations', 0)}`",
            f"- Investigable alert gaps: `{totals.get('investigable_alert_gaps', 0)}`",
            f"- Gate: `{'pass' if (report.get('quality_gate') or {}).get('passed', True) else 'fail'}`",
            "",
            "## Scorecard",
            "",
            "```json",
            json_line_block(scorecard),
            "```",
            "",
            "## Results",
            "",
            "| Test | Executor | Status | Coverage | Missing telemetry | Missing fields | Missing driver raw | Missing detections | Missing alerts | Missing correlations | Alert context gaps | Driver drops | Unknown source events | Unexpected high/critical events | Unexpected high/critical alerts | Excluded setup alerts |",
            "|------|----------|--------|----------|-------------------|----------------|--------------------|--------------------|----------------|----------------------|--------------------|--------------|-----------------------|---------------------------------|---------------------------------|-----------------------|",
        ]
    )

    for item in report.get("tests", []):
        score = item.get("score") or {}
        missing = ", ".join(score.get("missing_expected_telemetry") or [])
        missing_fields = ", ".join(score.get("missing_expected_fields") or [])
        missing_driver = ", ".join(score.get("missing_expected_driver_raw_event_types") or [])
        missing_detections = ", ".join(score.get("missing_expected_detections") or [])
        missing_alerts = ", ".join(score.get("missing_expected_alerts") or [])
        missing_correlations = ", ".join(score.get("missing_expected_correlations") or [])
        alert_context_gaps = len(score.get("investigable_alert_gaps") or [])
        unknown_events = int(score.get("unknown_source_event_count") or 0)
        noisy_events = int(score.get("unexpected_high_or_critical_event_count") or 0)
        noisy_alerts = len(score.get("unexpected_high_or_critical_alerts") or [])
        excluded_setup_alerts = len(score.get("excluded_benchmark_setup_alerts") or [])
        driver_drops = int(score.get("driver_channel_drops_delta") or 0) + int(
            score.get("driver_kernel_drops_delta") or 0
        )
        coverage = score.get("coverage") or {}
        coverage_label = (
            f"T:{coverage.get('telemetry', '-')}; "
            f"D:{coverage.get('detection', '-')}; "
            f"A:{coverage.get('alert', '-')}; "
            f"L:{coverage.get('timeline', '-')}; "
            f"R:{coverage.get('driver_raw', '-')}; "
            f"F:{coverage.get('fields', '-')}"
        )
        lines.append(
            f"| `{item['id']}` {item['name']} | `{item.get('executor_label') or item.get('executor_used')}` | "
            f"`{score.get('status', item.get('status'))}` | `{coverage_label}` | "
            f"`{missing or '-'}` | "
            f"`{missing_fields or '-'}` | "
            f"`{missing_driver or '-'}` | "
            f"`{missing_detections or '-'}` | `{missing_alerts or '-'}` | "
            f"`{missing_correlations or '-'}` | "
            f"`{alert_context_gaps}` | `{driver_drops}` | `{unknown_events}` | `{noisy_events}` | `{noisy_alerts}` | `{excluded_setup_alerts}` |"
        )

    actionable_gaps = (report.get("summary") or {}).get("actionable_gaps") or []
    if actionable_gaps:
        lines.extend(
            [
                "",
                "## Actionable Gaps",
                "",
                "| Test | Gap category | Status | Validation category | Techniques | Missing signals |",
                "|------|--------------|--------|---------------------|------------|-----------------|",
            ]
        )
        for gap in actionable_gaps[:25]:
            missing_signals = []
            for key in [
                "missing_expected_telemetry",
                "missing_expected_fields",
                "missing_expected_detections",
                "missing_expected_alerts",
                "missing_expected_correlations",
                "missing_expected_driver_raw_event_types",
            ]:
                values = gap.get(key) or []
                if values:
                    missing_signals.append(f"{key}={','.join(str(value) for value in values)}")
            if gap.get("fallback_used"):
                missing_signals.append("fallback_used=true")
            lines.append(
                f"| `{md_cell(gap.get('test_id'))}` | `{md_cell(gap.get('gap_category'))}` | "
                f"`{md_cell(gap.get('status'))}` | `{md_cell(gap.get('validation_category'))}` | "
                f"`{md_cell(', '.join(gap.get('techniques') or []))}` | `{md_cell('; '.join(missing_signals))}` |"
            )

    tactic_coverage = (report.get("summary") or {}).get("tactic_coverage") or {}
    if tactic_coverage:
        lines.extend(
            [
                "",
                "## ATT&CK Tactic Coverage",
                "",
                "| Tactic | Tests | Covered | Partial | Missed | Failed | Upstream-backed |",
                "|--------|-------|---------|---------|--------|--------|-----------------|",
            ]
        )
        for tactic, bucket in sorted(tactic_coverage.items()):
            lines.append(
                f"| `{tactic}` | `{bucket.get('tests', 0)}` | `{bucket.get('covered', 0)}` | "
                f"`{bucket.get('partial', 0)}` | `{bucket.get('missed', 0)}` | "
                f"`{bucket.get('execution_failed', 0)}` | `{bucket.get('upstream_backed_tests', 0)}` |"
            )

    category_coverage = (report.get("summary") or {}).get("category_coverage") or {}
    if category_coverage:
        lines.extend(
            [
                "",
                "## Validation Category Coverage",
                "",
                "| Category | Tests | Covered | Partial | Missed | Failed | Upstream-backed | Gap categories |",
                "|----------|-------|---------|---------|--------|--------|-----------------|----------------|",
            ]
        )
        for category, bucket in sorted(category_coverage.items()):
            gaps = ", ".join(
                f"{name}={count}" for name, count in sorted((bucket.get("gap_category_counts") or {}).items())
            )
            lines.append(
                f"| `{category}` | `{bucket.get('tests', 0)}` | `{bucket.get('covered', 0)}` | "
                f"`{bucket.get('partial', 0)}` | `{bucket.get('missed', 0)}` | "
                f"`{bucket.get('execution_failed', 0)}` | `{bucket.get('upstream_backed_tests', 0)}` | "
                f"`{gaps or '-'}` |"
            )

    technique_coverage = (report.get("summary") or {}).get("technique_coverage") or {}
    if technique_coverage:
        lines.extend(
            [
                "",
                "## ATT&CK Technique Coverage",
                "",
                "| Technique | Tests | Covered | Partial | Missed | Failed | Upstream-backed | Evidence sources |",
                "|-----------|-------|---------|---------|--------|--------|-----------------|------------------|",
            ]
        )
        for technique, bucket in sorted(technique_coverage.items()):
            sources = ", ".join(
                f"{source}={count}"
                for source, count in sorted((bucket.get("evidence_sources") or {}).items())
            )
            lines.append(
                f"| `{technique}` | `{bucket.get('tests', 0)}` | `{bucket.get('covered', 0)}` | "
                f"`{bucket.get('partial', 0)}` | `{bucket.get('missed', 0)}` | "
                f"`{bucket.get('execution_failed', 0)}` | `{bucket.get('upstream_backed_tests', 0)}` | "
                f"`{sources or '-'}` |"
            )

    source_coverage = (report.get("summary") or {}).get("evidence_source_coverage") or {}
    if source_coverage:
        lines.extend(
            [
                "",
                "## Evidence Source Coverage",
                "",
                "| Source | Events | Status |",
                "|--------|--------|--------|",
            ]
        )
        for source, bucket in sorted(source_coverage.items()):
            lines.append(f"| `{source}` | `{bucket.get('events', 0)}` | `{bucket.get('status', 'unknown')}` |")

    if report.get("upstream_readiness"):
        lines.extend(
            [
                "",
                "## Upstream Readiness",
                "",
                "```json",
                json_line_block(report.get("upstream_readiness")),
                "```",
            ]
        )

    caldera_items = [
        item for item in report.get("tests", []) if (item.get("execution") or {}).get("caldera_proof")
    ]
    if caldera_items:
        lines.extend(
            [
                "",
                "## CALDERA Proof",
                "",
                "| Test | Operation | Final state | Group | PAW | Polls | Links ok/fail | Success |",
                "|------|-----------|-------------|-------|-----|-------|---------------|---------|",
            ]
        )
        for item in caldera_items:
            proof = (item.get("execution") or {}).get("caldera_proof") or {}
            lines.append(
                f"| `{item['id']}` | `{proof.get('operation_id') or '-'}` | "
                f"`{proof.get('final_state') or '-'}` | `{proof.get('group') or '-'}` | "
                f"`{proof.get('paw') or '-'}` | `{proof.get('poll_count') or 0}` | "
                f"`{proof.get('successful_link_count') or 0}/{proof.get('failed_link_count') or 0}` | "
                f"`{proof.get('success')}` |"
            )
        preflight_items = [
            (item, ((item.get("execution") or {}).get("caldera_proof") or {}).get("agent_preflight") or {})
            for item in caldera_items
        ]
        preflight_items = [(item, preflight) for item, preflight in preflight_items if preflight]
        if preflight_items:
            lines.extend(
                [
                    "",
                    "### CALDERA Agent Preflight",
                    "",
                    "| Test | Ready | Issues | Host | Platform | Last seen | Age seconds | Agent count |",
                    "|------|-------|--------|------|----------|-----------|-------------|-------------|",
                ]
            )
            for item, preflight in preflight_items:
                agent = preflight.get("agent") if isinstance(preflight.get("agent"), dict) else {}
                issues = ", ".join(str(issue) for issue in (preflight.get("issues") or []))
                age = preflight.get("last_seen_age_seconds")
                age_label = f"{int(age)}" if isinstance(age, (int, float)) else "-"
                lines.append(
                    f"| `{item['id']}` | `{preflight.get('ready')}` | `{md_cell(issues or '-')}` | "
                    f"`{md_cell(agent.get('host') or agent.get('host_name') or '-')}` | "
                    f"`{md_cell(agent.get('platform') or '-')}` | "
                    f"`{md_cell(preflight.get('last_seen_at') or '-')}` | "
                    f"`{age_label}` | `{preflight.get('agent_count', '-')}` |"
                )
        lines.extend(
            [
                "",
                "CALDERA operations are upstream-backed only when a real adversary id, group, and target PAW are recorded. "
                "`expected_correlations` is scored as an investigation-readiness signal using Tamandua telemetry, "
                "detection and alert evidence; it is not inferred from CALDERA execution success alone.",
            ]
        )

    if report.get("baseline"):
        lines.extend(compact_baseline_lines(report.get("baseline") or {}))

    lines.extend(compact_preflight_lines(report.get("preflight")))
    if report.get("quality_gate"):
        lines.extend(["## Quality Gate", "", "```json", json_line_block(report.get("quality_gate")), "```", ""])
    lines.extend(
        [
            "## Notes",
            "",
            "- Raw JSON artifact contains commands, stdout/stderr, event summaries, alert summaries, and server log excerpts.",
            "- Markdown is intentionally concise so it can be reviewed as an executive benchmark artifact.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base = output_dir / report["run_id"]
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    comparison_path = base.with_suffix(".comparison.json")
    json_path.write_text(json_line_block(report) + "\n", encoding="utf-8")
    comparison_path.write_text(json_line_block(comparison_export(report)) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    update_run_index(report, output_dir)
    return json_path, md_path, comparison_path


def update_run_index(report: dict[str, Any], output_dir: Path) -> None:
    index_path = output_dir / "index.json"
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            index = {"schema_version": 1, "runs": []}
    else:
        index = {"schema_version": 1, "runs": []}

    runs = [
        run
        for run in index.get("runs", [])
        if run.get("run_id") != report.get("run_id")
    ]
    fingerprint = target_fingerprint(report)
    runs.append(
        {
            "run_id": report.get("run_id"),
            "started_at": report.get("started_at"),
            "finished_at": report.get("finished_at"),
            "profile_id": (report.get("profile") or {}).get("profile_id"),
            "agent_id": (report.get("target") or {}).get("agent_id"),
            "vmid": (report.get("target") or {}).get("vmid"),
            "git_commit": (report.get("git") or {}).get("commit_short"),
            "git_dirty": (report.get("git") or {}).get("dirty"),
            "hostname": fingerprint.get("hostname"),
            "agent_hash": fingerprint.get("agent_hash"),
            "driver_hash": fingerprint.get("driver_hash"),
            "os_build": fingerprint.get("os_build"),
            "summary": report.get("summary"),
            "scorecard": report.get("scorecard"),
            "quality_gate": report.get("quality_gate"),
            "executor_counts": (report.get("summary") or {}).get("executor_counts"),
            "upstream_backed_tests": (report.get("summary") or {}).get("upstream_backed_tests"),
            "fallback_command_tests": (report.get("summary") or {}).get("fallback_command_tests"),
            "deterministic_command_tests": (report.get("summary") or {}).get("deterministic_command_tests"),
            "execution_class_counts": (report.get("summary") or {}).get("execution_class_counts"),
            "evidence_source_coverage": (report.get("summary") or {}).get("evidence_source_coverage"),
            "tactic_coverage": (report.get("summary") or {}).get("tactic_coverage"),
            "technique_coverage": (report.get("summary") or {}).get("technique_coverage"),
            "upstream_readiness": report.get("upstream_readiness"),
        }
    )
    index["runs"] = sorted(runs, key=lambda run: run.get("started_at") or "")[-200:]
    index_body = json_line_block(index) + "\n"
    tmp_path = index_path.with_name(f"{index_path.name}.{uuid.uuid4().hex}.tmp")
    tmp_path.write_text(index_body, encoding="utf-8")
    for attempt in range(3):
        try:
            tmp_path.replace(index_path)
            break
        except OSError:
            if attempt == 2:
                raise
            time.sleep(0.2 * (attempt + 1))
    if tmp_path.exists():
        with contextlib.suppress(OSError):
            tmp_path.unlink()


def tag_values(test: dict[str, Any], prefix: str) -> list[str]:
    values = []
    for tag in test.get("tags") or []:
        tag_text = str(tag)
        if tag_text.lower().startswith(prefix.lower()):
            values.append(tag_text.split(":", 1)[1])
    return values


def technique_values(test: dict[str, Any]) -> list[str]:
    values = tag_values(test, "mitre:")
    atomic_technique = (test.get("atomic") or {}).get("technique")
    if atomic_technique:
        values.append(str(atomic_technique))
    for ability in (test.get("caldera") or {}).get("abilities") or []:
        mitre = ability.get("mitre")
        if mitre:
            values.append(str(mitre))
    return sorted(set(values))


def is_response_audit_test(item: dict[str, Any]) -> bool:
    tags = [str(tag).lower() for tag in item.get("tags") or []]
    validation_category = str(
        item.get("validation_category") or (item.get("roadmap_traceability") or {}).get("category") or ""
    ).lower()
    claim_boundary = str(item.get("claim_boundary") or "").lower()
    return (
        "response-validation" in tags
        or "response-audit" in tags
        or validation_category in {"response", "response-audit", "response-validation"}
        or "response" in claim_boundary
        or "audit" in claim_boundary
    )


def add_source_counts(bucket: dict[str, Any], source_counts: dict[str, int]) -> None:
    sources = bucket.setdefault("evidence_sources", {})
    for source, count in source_counts.items():
        sources[source] = int(sources.get(source, 0)) + int(count)


def add_summary_source_counts(summary: dict[str, Any], source_counts: dict[str, int]) -> None:
    sources = summary.setdefault("evidence_source_coverage", {})
    for source, count in source_counts.items():
        bucket = sources.setdefault(
            source,
            {
                "events": 0,
                "status": "weak" if source.lower() in {"unknown", ""} else "ok",
            },
        )
        bucket["events"] += int(count)


def summarize_dimension(
    summary: dict[str, Any],
    dimension: str,
    value: str,
    status: str,
    upstream_backed: bool,
    source_counts: dict[str, int],
    gap: str,
) -> None:
    bucket = summary.setdefault(dimension, {}).setdefault(
        value,
        {
            "tests": 0,
            "covered": 0,
            "partial": 0,
            "missed": 0,
            "execution_failed": 0,
            "skipped": 0,
            "planned": 0,
            "upstream_backed_tests": 0,
            "evidence_sources": {},
            "gap_category_counts": {},
        },
    )
    bucket["tests"] += 1
    if status in bucket:
        bucket[status] += 1
    if upstream_backed:
        bucket["upstream_backed_tests"] += 1
    add_source_counts(bucket, source_counts)
    if gap and gap != "none":
        gaps = bucket.setdefault("gap_category_counts", {})
        gaps[gap] = int(gaps.get(gap, 0)) + 1


def summarize_tests(tests: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, Any] = {
        "tests": len(tests),
        "covered": 0,
        "partial": 0,
        "missed": 0,
        "planned": 0,
        "execution_failed": 0,
        "executed_without_server_evidence": 0,
        "infra_blocked": 0,
        "skipped": 0,
        "unknown_source_events": 0,
        "unexpected_high_or_critical_events": 0,
        "unexpected_high_or_critical_alerts": 0,
        "excluded_benchmark_setup_alerts": 0,
        "excluded_stale_source_events": 0,
        "missing_expected_detections": 0,
        "missing_expected_alerts": 0,
        "missing_expected_correlations": 0,
        "investigable_alert_gaps": 0,
        "missing_expected_driver_raw_events": 0,
        "driver_channel_drops": 0,
        "driver_kernel_drops": 0,
        "missing_expected_fields": 0,
        "missing_expected_values": 0,
        "upstream_backed_tests": 0,
        "fallback_command_tests": 0,
        "deterministic_command_tests": 0,
        "executor_counts": {},
        "execution_class_counts": {},
        "claim_level_counts": {},
        "gap_category_counts": {},
        "actionable_gaps": [],
        "evidence_source_coverage": {},
        "tactic_coverage": {},
        "technique_coverage": {},
        "category_coverage": {},
    }
    for test in tests:
        score = test.get("score") or {}
        status = score.get("status") or test.get("status")
        executor = str(test.get("executor_used") or "unknown")
        execution_class = str(test.get("execution_class") or (test.get("provenance") or {}).get("execution_class") or "unknown")
        claim_level = str(test.get("claim_level") or ("planned" if status == "planned" else "unknown"))
        upstream_backed = bool(test.get("upstream_backed"))
        source_counts = score.get("evidence_source_counts") or {}
        gap = gap_category(test)
        summary["executor_counts"][executor] = int(summary["executor_counts"].get(executor, 0)) + 1
        summary["execution_class_counts"][execution_class] = int(summary["execution_class_counts"].get(execution_class, 0)) + 1
        summary["claim_level_counts"][claim_level] = int(summary["claim_level_counts"].get(claim_level, 0)) + 1
        if gap != "none":
            summary["gap_category_counts"][gap] = int(summary["gap_category_counts"].get(gap, 0)) + 1
            summary["actionable_gaps"].append(
                {
                    "test_id": test.get("id"),
                    "status": status,
                    "gap_category": gap,
                    "tactics": tag_values(test, "tactic:"),
                    "techniques": technique_values(test),
                    "validation_category": test.get("validation_category") or (test.get("roadmap_traceability") or {}).get("category"),
                    "missing_expected_telemetry": score.get("missing_expected_telemetry") or [],
                    "missing_expected_fields": score.get("missing_expected_fields") or [],
                    "missing_expected_values": score.get("missing_expected_values") or [],
                    "missing_expected_detections": score.get("missing_expected_detections") or [],
                    "missing_expected_alerts": score.get("missing_expected_alerts") or [],
                    "missing_expected_correlations": score.get("missing_expected_correlations") or [],
                    "missing_expected_driver_raw_event_types": score.get("missing_expected_driver_raw_event_types") or [],
                    "fallback_used": bool(test.get("fallback_used")),
                    "execution_class": execution_class,
                }
            )
        add_summary_source_counts(summary, source_counts)
        if executor in {"atomic_red_team", "caldera_operation"}:
            summary["upstream_backed_tests"] += 1
        if test.get("fallback_used"):
            summary["fallback_command_tests"] += 1
        elif executor == "command":
            summary["deterministic_command_tests"] += 1
        if status in summary:
            summary[status] += 1
        summary["unknown_source_events"] += int(score.get("unknown_source_event_count") or 0)
        summary["unexpected_high_or_critical_events"] += int(score.get("unexpected_high_or_critical_event_count") or 0)
        summary["unexpected_high_or_critical_alerts"] += len(score.get("unexpected_high_or_critical_alerts") or [])
        summary["excluded_benchmark_setup_alerts"] += len(score.get("excluded_benchmark_setup_alerts") or [])
        summary["excluded_stale_source_events"] += len(score.get("excluded_stale_source_events") or [])
        summary["missing_expected_detections"] += len(score.get("missing_expected_detections") or [])
        summary["missing_expected_alerts"] += len(score.get("missing_expected_alerts") or [])
        summary["missing_expected_correlations"] += len(score.get("missing_expected_correlations") or [])
        summary["investigable_alert_gaps"] += len(score.get("investigable_alert_gaps") or [])
        summary["missing_expected_driver_raw_events"] += len(score.get("missing_expected_driver_raw_event_types") or [])
        summary["driver_channel_drops"] += int(score.get("driver_channel_drops_delta") or 0)
        summary["driver_kernel_drops"] += int(score.get("driver_kernel_drops_delta") or 0)
        summary["missing_expected_fields"] += len(score.get("missing_expected_fields") or [])
        summary["missing_expected_values"] += len(score.get("missing_expected_values") or [])
        for tactic in tag_values(test, "tactic:"):
            summarize_dimension(summary, "tactic_coverage", tactic, status, upstream_backed, source_counts, gap)
        for technique in technique_values(test):
            summarize_dimension(summary, "technique_coverage", technique, status, upstream_backed, source_counts, gap)
        for category in tag_values(test, "category:") or [
            str(test.get("validation_category") or (test.get("roadmap_traceability") or {}).get("category") or "")
        ]:
            if category:
                summarize_dimension(summary, "category_coverage", category, status, upstream_backed, source_counts, gap)
    return summary


def fresh_restore_provenance_from_args(args: argparse.Namespace) -> dict[str, Any] | None:
    fields = {
        "fresh_restore": bool(getattr(args, "fresh_restore", False)),
        "restore_started_at": getattr(args, "fresh_restore_started_at", None),
        "restore_finished_at": getattr(args, "fresh_restore_finished_at", None),
        "snapshot_name": getattr(args, "fresh_restore_snapshot_name", None),
        "snapshot_id": getattr(args, "fresh_restore_snapshot_id", None),
        "vmid": getattr(args, "fresh_restore_vmid", None) or getattr(args, "vmid", None),
        "agent_id_after_restore": getattr(args, "fresh_restore_agent_id", None) or getattr(args, "agent_id", None),
        "hostname_after_restore": getattr(args, "fresh_restore_hostname", None) or getattr(args, "agent_hostname", None),
        "source": getattr(args, "fresh_restore_source", None),
        "notes": getattr(args, "fresh_restore_notes", None),
    }
    has_restore_context = fields["fresh_restore"] or any(
        fields.get(key)
        for key in (
            "restore_started_at",
            "restore_finished_at",
            "snapshot_name",
            "snapshot_id",
            "source",
            "notes",
        )
    )
    if not has_restore_context:
        return None
    return {key: value for key, value in fields.items() if value not in (None, "")}


def evaluate_fresh_restore_provenance(provenance: dict[str, Any] | None) -> dict[str, Any]:
    required = [
        "fresh_restore",
        "restore_started_at",
        "restore_finished_at",
        "snapshot_name",
        "snapshot_id",
        "vmid",
        "agent_id_after_restore",
        "hostname_after_restore",
    ]
    if not isinstance(provenance, dict) or not provenance:
        return {"ready": True, "skipped": True, "reason": "no_fresh_restore_claim"}
    missing = [field for field in required if provenance.get(field) in (None, "", [])]
    return {
        "ready": not missing,
        "skipped": False,
        "required_fields": required,
        "missing_fields": missing,
        "claim_boundary": (
            "Fresh-restore benchmark claims require complete restore/snapshot, VM, "
            "post-restore agent, and timing metadata."
        ),
    }


def refresh_fresh_restore_provenance(report: dict[str, Any], args: argparse.Namespace) -> None:
    provenance = report.get("fresh_restore_provenance")
    if not isinstance(provenance, dict):
        return
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    if not provenance.get("vmid") and target.get("vmid"):
        provenance["vmid"] = target["vmid"]
    if not provenance.get("agent_id_after_restore") and (args.agent_id or target.get("agent_id")):
        provenance["agent_id_after_restore"] = args.agent_id or target.get("agent_id")
    if not provenance.get("hostname_after_restore") and (args.agent_hostname or target.get("agent_hostname")):
        provenance["hostname_after_restore"] = args.agent_hostname or target.get("agent_hostname")
    report["fresh_restore_provenance_readiness"] = evaluate_fresh_restore_provenance(provenance)
    metadata = report.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        report["metadata"] = metadata
    metadata["fresh_restore_provenance"] = provenance


def run(args: argparse.Namespace) -> int:
    if args.list_profiles:
        for profile in discover_profiles():
            print(
                f"{profile['profile_id']}\t{profile['platform'] or '-'}\t"
                f"{profile['tests']} tests\t{profile['path']}"
            )
        return 0

    profile = load_profile(args.profile)
    apply_profile_quality_bar(args, profile)
    apply_benchmark_lane_defaults(args)
    selected_tests = select_tests(profile, args.only)
    caldera_errors = validate_caldera_profile(args, selected_tests)
    if args.execute and caldera_errors:
        for error in caldera_errors:
            print(f"caldera_profile_error={error}", file=sys.stderr)
        return 2
    started_at = utc_now()
    run_id = args.run_id or f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{profile['profile_id']}"

    report: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": iso(started_at),
        "finished_at": None,
        "execute": args.execute,
        "benchmark_lane": args.benchmark_lane,
        "profile": {
            "profile_id": profile["profile_id"],
            "name": profile["name"],
            "platform": profile.get("platform"),
            "quality_bar": profile.get("quality_bar"),
        },
        "target": {
            "vmid": args.vmid,
            "agent_id": args.agent_id,
            "agent_hostname": args.agent_hostname,
            "resolve_agent_by_hostname": args.resolve_agent_by_hostname,
            "server_host": args.server_host,
            "proxmox_host": args.proxmox_host,
        },
        "git": git_metadata(),
        "preflight": None,
        "tests": [],
        "selected_tests": [test.get("id") for test in selected_tests],
        "baseline": None,
        "quality_gate": None,
        "scorecard": None,
        "upstream_readiness": None,
        "summary": {},
    }
    restore_provenance = fresh_restore_provenance_from_args(args)
    if restore_provenance:
        report["fresh_restore_provenance"] = restore_provenance
        report["metadata"] = {"fresh_restore_provenance": restore_provenance}

    if not args.execute:
        for test in selected_tests:
            executor, command = resolve_test_command(test, atomic_available=False, args=args)
            report["tests"].append(
                {
                    "id": test["id"],
                    "name": test["name"],
                    "risk": test.get("risk"),
                    "tags": test.get("tags", []),
                    "validation_category": test.get("validation_category"),
                    "roadmap_traceability": test.get("roadmap_traceability"),
                    "claim_boundary": test.get("claim_boundary"),
                    "status": "planned",
                    **executor_metadata(test, executor, atomic_available=False, args=args),
                    "claim_level": "planned",
                    "command": command,
                    "expected_telemetry": test.get("expected_telemetry", []),
                }
            )
        report["finished_at"] = iso(utc_now())
        refresh_fresh_restore_provenance(report, args)
        report["summary"] = summarize_tests(report["tests"])
        report["quality_gate"] = evaluate_gates(report, args)
        report["scorecard"] = benchmark_scorecard(report)
        report["upstream_readiness"] = upstream_readiness_checklist(report)
        json_path, md_path, comparison_path = write_report(report, args.output_dir)
        print(f"dry_run=true json={json_path} markdown={md_path} comparison_json={comparison_path}")
        return 0 if report["quality_gate"]["passed"] or not args.fail_on_gate else 1

    profile_execution = profile.get("execution") if isinstance(profile.get("execution"), dict) else {}
    if profile_execution.get("type") == "local_probe":
        command = str(profile_execution.get("command") or "").strip()
        if not command:
            raise RunnerError("local_probe profile is missing execution.command")
        timeout = int(profile_execution.get("timeout_seconds") or args.test_timeout or 120)
        result = local_shell_command(command, cwd=ROOT, timeout=timeout)
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return int(result.exit_code or 0)

    if args.local_target:
        if str(profile.get("platform") or "").lower() == "windows":
            raise RunnerError("--local-target is only supported for non-Windows profiles")
        for test in selected_tests:
            test_started = utc_now()
            executor, command = resolve_test_command(test, atomic_available=False, args=args)
            item: dict[str, Any] = {
                "id": test["id"],
                "name": test["name"],
                "risk": test.get("risk"),
                "tags": test.get("tags", []),
                "validation_category": test.get("validation_category"),
                "roadmap_traceability": test.get("roadmap_traceability"),
                "claim_boundary": test.get("claim_boundary"),
                "started_at": iso(test_started),
                **executor_metadata(test, executor, atomic_available=False, args=args),
                "command": command,
                "expected_telemetry": test.get("expected_telemetry", []),
                "optional_telemetry": test.get("optional_telemetry", []),
                "expected_detections": test.get("expected_detections", []),
                "expected_alerts": test.get("expected_alerts", []),
            }

            if not command:
                item["status"] = "skipped"
                item["error"] = "no command resolved"
                report["tests"].append(item)
                continue

            result = local_shell_command(command, cwd=ROOT, timeout=args.test_timeout)
            item["execution"] = dataclasses.asdict(result)
            if result.exit_code != 0:
                item["status"] = "execution_failed"
                item["score"] = {
                    "status": "execution_failed",
                    "expected_telemetry": test.get("expected_telemetry", []),
                    "error": result.stderr or result.stdout,
                }
            else:
                item["score"] = {
                    "status": "executed_without_server_evidence",
                    "expected_telemetry": test.get("expected_telemetry", []),
                    "missing_expected_telemetry": test.get("expected_telemetry", []),
                }
            item["finished_at"] = iso(utc_now())
            report["tests"].append(item)

        report["finished_at"] = iso(utc_now())
        refresh_fresh_restore_provenance(report, args)
        report["summary"] = summarize_tests(report["tests"])
        report["quality_gate"] = evaluate_gates(report, args)
        report["scorecard"] = benchmark_scorecard(report)
        report["upstream_readiness"] = upstream_readiness_checklist(report)
        json_path, md_path, comparison_path = write_report(report, args.output_dir)
        print(f"execute=true local_target=true json={json_path} markdown={md_path} comparison_json={comparison_path}")
        return 0 if report["quality_gate"]["passed"] or not args.fail_on_gate else 1

    if (
        args.execution_transport == "tamandua-ctl"
        and args.skip_preflight
        and not args.proxmox_host
        and not args.server_host
    ):
        report["preflight"] = {"skipped": True, "reason": "tamandua_ctl_transport_only"}
        report["preflight_readiness"] = {"ready": True, "skipped": True}
        report["execution_transport_proof"] = {
            "transport": "tamandua-ctl",
            "qga_required": False,
            "proxmox_required": False,
            "purpose": "bounded live-response execution-channel validation",
        }
        if not args.agent_id and args.agent_hostname:
            report["agent_live_before"] = tamandua_ctl_agent_state(args)
            resolved_agent = report["agent_live_before"].get("agent")
            if isinstance(resolved_agent, dict):
                args.agent_id = str(resolved_agent.get("id") or resolved_agent.get("agent_id") or "")
                report["target"]["agent_id"] = args.agent_id
                report["target"]["agent_hostname"] = str(resolved_agent.get("hostname") or args.agent_hostname)
            else:
                report["agent_live_readiness_before"] = evaluate_tamandua_ctl_agent_readiness(
                    report["agent_live_before"],
                    args.agent_freshness_seconds,
                )

        for test in selected_tests:
            test_wall_started = time.monotonic()
            test_deadline = (
                test_wall_started + args.max_test_wall_seconds
                if args.max_test_wall_seconds > 0
                else None
            )
            test_started = utc_now()
            executor, command = resolve_test_command(test, atomic_available=False, args=args)
            item: dict[str, Any] = {
                "id": test["id"],
                "name": test["name"],
                "risk": test.get("risk"),
                "tags": test.get("tags", []),
                "validation_category": test.get("validation_category"),
                "roadmap_traceability": test.get("roadmap_traceability"),
                "claim_boundary": test.get("claim_boundary"),
                "started_at": iso(test_started),
                "evidence_started_at": iso(test_started),
                **executor_metadata(test, executor, atomic_available=False, args=args),
                "command": command,
                "expected_telemetry": test.get("expected_telemetry", []),
                "optional_telemetry": test.get("optional_telemetry", []),
                "expected_detections": test.get("expected_detections", []),
                "expected_alerts": test.get("expected_alerts", []),
            }

            if not command:
                item["status"] = "skipped"
                item["error"] = "no command resolved"
                report["tests"].append(item)
                continue

            try:
                item["execution"] = tamandua_ctl_command(
                    args,
                    command,
                    remaining_deadline_seconds(test_deadline, args.test_timeout),
                )
            except Exception as exc:
                item["execution"] = {
                    "outer_exit_code": 124 if isinstance(exc, TimeoutError) else 1,
                    "transport": "tamandua_ctl_live_response",
                    "error_code": "test_wall_timeout" if isinstance(exc, TimeoutError) else "execution_transport_exception",
                    "error": f"{type(exc).__name__}: {exc}",
                }

            guest_exit_code = item["execution"].get("guest_exit_code")
            if item["execution"].get("outer_exit_code") not in (0, None) or guest_exit_code not in (0, None):
                status, gap, error_code = classify_execution_failure(item["execution"])
                item["status"] = status
                item["score"] = {
                    "status": status,
                    "gap_category": gap,
                    "error_code": error_code,
                    "expected_telemetry": test.get("expected_telemetry", []),
                    "missing_expected_telemetry": test.get("expected_telemetry", []),
                    "error": (
                        item["execution"].get("stderr")
                        or item["execution"].get("guest_stderr")
                        or item["execution"].get("error")
                    ),
                }
            else:
                item["score"] = score_transport_only_execution(test, item["execution"])
            item["finished_at"] = iso(utc_now())
            report["tests"].append(item)

        report["finished_at"] = iso(utc_now())
        refresh_fresh_restore_provenance(report, args)
        report["summary"] = summarize_tests(report["tests"])
        report["quality_gate"] = evaluate_gates(report, args)
        report["scorecard"] = benchmark_scorecard(report)
        report["upstream_readiness"] = upstream_readiness_checklist(report)
        json_path, md_path, comparison_path = write_report(report, args.output_dir)
        print(
            "execute=true tamandua_ctl_transport_only=true "
            f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
        )
        return 0 if report["quality_gate"]["passed"] or not args.fail_on_gate else 1

    remote_exec_with_server_evidence = (
        args.execution_transport in {"tamandua-ctl", "ssh"}
        and bool(args.server_host)
        and bool(args.server_user)
        and not args.proxmox_host
    )

    if not remote_exec_with_server_evidence and (not args.proxmox_host or not args.proxmox_user or not args.vmid):
        raise RunnerError(
            "--execute requires --proxmox-host, --proxmox-user, and --vmid "
            "unless --execution-transport tamandua-ctl/ssh is paired with --server-host"
        )

    if args.execution_transport == "ssh" and (not args.endpoint_host or not args.endpoint_user):
        raise RunnerError("--execution-transport ssh requires --endpoint-host and --endpoint-user")

    proxmox_password = args.proxmox_password or os.getenv("TAMANDUA_PROXMOX_PASSWORD")
    server_password = args.server_password or os.getenv("TAMANDUA_SERVER_PASSWORD")

    proxmox_context = (
        contextlib.nullcontext(None)
        if remote_exec_with_server_evidence
        else (
            ProxmoxApiHost(args.proxmox_host, args.proxmox_user, proxmox_password, args.proxmox_node)
            if args.proxmox_api
            else SshHost(args.proxmox_host, args.proxmox_user, proxmox_password)
        )
    )

    with proxmox_context as proxmox:
        endpoint_cm = None
        endpoint = None
        if args.execution_transport == "ssh":
            endpoint_cm = SshHost(
                args.endpoint_host,
                args.endpoint_user,
                args.endpoint_password or os.getenv("TAMANDUA_ENDPOINT_PASSWORD"),
            )
            endpoint = endpoint_cm.__enter__()
        if args.skip_preflight or proxmox is None:
            report["preflight"] = {
                "skipped": True,
                "reason": "skip_preflight" if args.skip_preflight else "tamandua_ctl_no_qga",
            }
            report["preflight_readiness"] = {"ready": True, "skipped": True}
        else:
            report["preflight"] = collect_guest_preflight(proxmox, args.vmid)
            report["preflight_readiness"] = evaluate_preflight_readiness(report["preflight"])
        needs_atomic_probe = any(
            test.get("executor") == "atomic_or_command" and test.get("atomic")
            for test in selected_tests
        )
        atomic_available = (
            command_exists_on_guest(proxmox, args.vmid, "Invoke-AtomicTest")
            if needs_atomic_probe and proxmox is not None
            else False
        )

        server = None
        server_cm = None
        if args.server_host and args.server_user:
            server_cm = SshHost(args.server_host, args.server_user, server_password)
            server = server_cm.__enter__()

        try:
            if not report["preflight_readiness"].get("ready"):
                mark_tests_infra_blocked(
                    report,
                    selected_tests,
                    "endpoint_preflight_not_ready_for_benchmark",
                    report["preflight_readiness"],
                    atomic_available=atomic_available,
                    args=args,
                )
                report["finished_at"] = iso(utc_now())
                refresh_fresh_restore_provenance(report, args)
                report["summary"] = summarize_tests(report["tests"])
                report["quality_gate"] = evaluate_gates(report, args)
                report["scorecard"] = benchmark_scorecard(report)
                report["upstream_readiness"] = upstream_readiness_checklist(report)
                json_path, md_path, comparison_path = write_report(report, args.output_dir)
                print(
                    "execute=true endpoint_preflight_blocked=true "
                    f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
                )
                return 0 if report["quality_gate"]["passed"] or not args.fail_on_gate else 1

            if server is not None:
                preflight_details = report.get("preflight") or {}
                preflight_fingerprint = (
                    preflight_details.get("preflight") if isinstance(preflight_details, dict) else {}
                )
                resolved_hostname = (
                    args.agent_hostname
                    or (
                        preflight_fingerprint.get("hostname")
                        if isinstance(preflight_fingerprint, dict)
                        else None
                    )
                )
                if args.resolve_agent_by_hostname:
                    report["agent_resolution"] = resolve_agent_by_hostname(server, resolved_hostname)
                    resolved = report["agent_resolution"].get("resolved")
                    if isinstance(resolved, dict) and resolved.get("id"):
                        args.agent_id = str(resolved["id"])
                        report["target"]["agent_id"] = args.agent_id
                        report["target"]["agent_hostname"] = resolved_hostname
                    elif not args.agent_id:
                        raise RunnerError(
                            "--resolve-agent-by-hostname could not find an agent row for "
                            f"hostname={resolved_hostname!r}"
                        )

            if server is not None and not args.skip_server_readiness:
                report["agent_db_before"] = collect_agent_db_state(server, args.agent_id)
                db_readiness = evaluate_agent_readiness(
                    report["agent_db_before"],
                    args.agent_freshness_seconds,
                )
                if args.execution_transport == "tamandua-ctl":
                    report["agent_live_before"] = tamandua_ctl_agent_state(args)
                    report["agent_live_readiness_before"] = evaluate_tamandua_ctl_agent_readiness(
                        report["agent_live_before"],
                        args.agent_freshness_seconds,
                    )
                    report["agent_readiness_before"] = combine_agent_readiness_for_tamandua_ctl(
                        db_readiness,
                        report["agent_live_readiness_before"],
                        args.block_critical_agent_health,
                    )
                else:
                    report["agent_readiness_before"] = db_readiness
                if not report["agent_readiness_before"].get("ready"):
                    mark_tests_infra_blocked(
                        report,
                        selected_tests,
                        "agent_not_ready_for_benchmark",
                        report["agent_readiness_before"],
                        atomic_available=atomic_available,
                        args=args,
                    )
                    report["finished_at"] = iso(utc_now())
                    report["agent_db_after"] = collect_agent_db_state(server, args.agent_id)
                    refresh_fresh_restore_provenance(report, args)
                    report["summary"] = summarize_tests(report["tests"])
                    report["quality_gate"] = evaluate_gates(report, args)
                    report["scorecard"] = benchmark_scorecard(report)
                    report["upstream_readiness"] = upstream_readiness_checklist(report)
                    json_path, md_path, comparison_path = write_report(report, args.output_dir)
                    print(
                        "execute=true infrastructure_blocked=true "
                        f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
                    )
                    return 0 if report["quality_gate"]["passed"] or not args.fail_on_gate else 1
                if args.skip_telemetry_flow_check:
                    report["telemetry_flow_before"] = {
                        "ready": True,
                        "skipped": True,
                        "reason": "skip_telemetry_flow_check",
                    }
                elif proxmox is None and args.execution_transport in {"tamandua-ctl", "ssh"}:
                    report["telemetry_flow_before"] = {
                        "ready": True,
                        "skipped": True,
                        "reason": f"{args.execution_transport}_no_qga_precheck",
                    }
                else:
                    report["telemetry_flow_before"] = verify_endpoint_telemetry_flow(
                        proxmox,
                        server,
                        args.vmid,
                        args.agent_id,
                        wait_seconds=args.telemetry_flow_check_seconds,
                    )
                if not report["telemetry_flow_before"].get("ready"):
                    mark_tests_infra_blocked(
                        report,
                        selected_tests,
                        "endpoint_telemetry_not_flowing",
                        report["telemetry_flow_before"],
                        atomic_available=atomic_available,
                        args=args,
                    )
                    report["finished_at"] = iso(utc_now())
                    report["agent_db_after"] = collect_agent_db_state(server, args.agent_id)
                    refresh_fresh_restore_provenance(report, args)
                    report["summary"] = summarize_tests(report["tests"])
                    report["quality_gate"] = evaluate_gates(report, args)
                    report["scorecard"] = benchmark_scorecard(report)
                    report["upstream_readiness"] = upstream_readiness_checklist(report)
                    json_path, md_path, comparison_path = write_report(report, args.output_dir)
                    print(
                        "execute=true telemetry_flow_blocked=true "
                        f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
                    )
                    return 0 if report["quality_gate"]["passed"] or not args.fail_on_gate else 1
                if args.baseline_seconds > 0:
                    baseline_started = iso(server_utc_now(server) - dt.timedelta(seconds=5))
                    time.sleep(args.baseline_seconds)
                    report["baseline"] = collect_baseline(server, args.agent_id, baseline_started)
            elif server is not None and args.skip_server_readiness:
                report["agent_readiness_before"] = {
                    "ready": True,
                    "skipped": True,
                    "reason": "skip_server_readiness",
                }

            deferred_cleanup: list[dict[str, Any]] = []

            for test_index, test in enumerate(selected_tests):
                if test_index > 0 and args.inter_test_sleep_seconds > 0:
                    time.sleep(args.inter_test_sleep_seconds)

                test_wall_started = time.monotonic()
                test_deadline = (
                    test_wall_started + args.max_test_wall_seconds
                    if args.max_test_wall_seconds > 0
                    else None
                )
                test_started = server_utc_now(server) if server is not None else utc_now()
                evidence_started = test_started - dt.timedelta(seconds=max(0, args.evidence_lookback_seconds))
                executor, command = resolve_test_command(test, atomic_available, args=args)
                item: dict[str, Any] = {
                    "id": test["id"],
                    "name": test["name"],
                    "risk": test.get("risk"),
                    "tags": test.get("tags", []),
                    "validation_category": test.get("validation_category"),
                    "roadmap_traceability": test.get("roadmap_traceability"),
                    "claim_boundary": test.get("claim_boundary"),
                    "started_at": iso(test_started),
                    "evidence_started_at": iso(evidence_started),
                    **executor_metadata(test, executor, atomic_available, args=args),
                    "command": command,
                    "expected_telemetry": test.get("expected_telemetry", []),
                    "optional_telemetry": test.get("optional_telemetry", []),
                    "expected_detections": test.get("expected_detections", []),
                    "expected_alerts": test.get("expected_alerts", []),
                }

                if not command:
                    item["status"] = "skipped"
                    item["error"] = "no command resolved"
                    report["tests"].append(item)
                    continue

                precondition_command = str(test.get("precondition_command") or "").strip()
                if precondition_command:
                    try:
                        if deadline_expired(test_deadline):
                            raise TimeoutError(
                                f"test wall timeout before precondition after {args.max_test_wall_seconds}s"
                            )
                        if args.execution_transport == "tamandua-ctl":
                            precondition = tamandua_ctl_command(
                                args,
                                precondition_command,
                                remaining_deadline_seconds(
                                    test_deadline,
                                    int(test.get("precondition_timeout_seconds") or min(args.test_timeout, 60)),
                                ),
                            )
                        elif args.execution_transport == "ssh":
                            precondition = endpoint_ssh_command(
                                endpoint,
                                precondition_command,
                                remaining_deadline_seconds(
                                    test_deadline,
                                    int(test.get("precondition_timeout_seconds") or min(args.test_timeout, 60)),
                                ),
                            )
                        else:
                            precondition = guest_command(
                                proxmox,
                                args.vmid,
                                precondition_command,
                                timeout=remaining_deadline_seconds(
                                    test_deadline,
                                    int(test.get("precondition_timeout_seconds") or min(args.test_timeout, 60)),
                                ),
                            )
                    except Exception as exc:
                        precondition = {
                            "outer_exit_code": 124 if isinstance(exc, TimeoutError) else 1,
                            "error_code": (
                                "test_wall_timeout_precondition"
                                if isinstance(exc, TimeoutError)
                                else "precondition_transport_exception"
                            ),
                            "error": f"{type(exc).__name__}: {exc}",
                        }

                    item["precondition"] = precondition
                    precondition_guest_exit_code = precondition.get("guest_exit_code")
                    precondition_failed = (
                        precondition.get("outer_exit_code") not in (0, None)
                        or precondition_guest_exit_code not in (0, None)
                    )
                    if precondition_failed:
                        item["status"] = "infra_blocked"
                        item["score"] = execution_infra_blocked_score(
                            test,
                            str(
                                precondition.get("stderr")
                                or precondition.get("guest_stderr")
                                or precondition.get("error")
                                or "scenario precondition failed"
                            ),
                            str(test.get("precondition_error_code") or "scenario_precondition_failed"),
                            precondition,
                        )
                        item["finished_at"] = iso(utc_now())
                        report["tests"].append(item)
                        continue

                if server is not None:
                    item["driver_health_before"] = collect_driver_health_snapshot(
                        server,
                        args.agent_id,
                        timeout=remaining_deadline_seconds(test_deadline, 15, floor=1),
                    )

                try:
                    if deadline_expired(test_deadline):
                        raise TimeoutError(f"test wall timeout before execution after {args.max_test_wall_seconds}s")
                    if executor == "caldera_operation":
                        original_caldera_timeout = args.caldera_timeout_seconds
                        args.caldera_timeout_seconds = remaining_deadline_seconds(
                            test_deadline,
                            args.caldera_timeout_seconds,
                            floor=min(30, max(1, args.caldera_timeout_seconds)),
                        )
                        try:
                            item["execution"] = run_caldera_operation(args, test)
                        finally:
                            args.caldera_timeout_seconds = original_caldera_timeout
                    elif args.execution_transport == "tamandua-ctl":
                        item["execution"] = tamandua_ctl_command(
                            args,
                            command,
                            remaining_deadline_seconds(test_deadline, args.test_timeout),
                        )
                    elif args.execution_transport == "ssh":
                        item["execution"] = endpoint_ssh_command(
                            endpoint,
                            command,
                            remaining_deadline_seconds(test_deadline, args.test_timeout),
                        )
                    else:
                        item["execution"] = guest_command(
                            proxmox,
                            args.vmid,
                            command,
                            timeout=remaining_deadline_seconds(test_deadline, args.test_timeout),
                        )
                except Exception as exc:
                    item["execution"] = {
                        "outer_exit_code": 124 if isinstance(exc, TimeoutError) else 1,
                        "error_code": "test_wall_timeout" if isinstance(exc, TimeoutError) else "execution_transport_exception",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                trace_step(
                    "test execution returned "
                    f"test={test.get('id')} executor={executor} "
                    f"outer_exit_code={item['execution'].get('outer_exit_code')} "
                    f"guest_exit_code={item['execution'].get('guest_exit_code')}"
                )

                post_execution_db_time = server_utc_now(server) if server is not None else utc_now()

                guest_exit_code = item["execution"].get("guest_exit_code")
                if item["execution"].get("outer_exit_code") not in (0, None) or guest_exit_code not in (0, None):
                    status, gap, error_code = classify_execution_failure(item["execution"])
                    item["status"] = status
                    item["score"] = {
                        "status": status,
                        "gap_category": gap,
                        "error_code": error_code,
                        "expected_telemetry": test.get("expected_telemetry", []),
                        "missing_expected_telemetry": test.get("expected_telemetry", []),
                        "error": (
                            item["execution"].get("stderr")
                            or item["execution"].get("guest_stderr")
                            or item["execution"].get("error")
                        ),
                    }
                    item["finished_at"] = iso(utc_now())
                    report["tests"].append(item)
                    continue

                if (
                    item["execution"].get("transport") == "tamandua_ctl_live_response"
                    and not bool((profile.get("quality_bar") or {}).get("requires_persisted_events", True))
                ):
                    item["execution_evidence"] = live_response_execution_evidence(item.get("execution"))
                    item["score"] = score_transport_only_execution(test, item["execution"])
                    item["status"] = item["score"].get("status")
                    item["finished_at"] = iso(utc_now())
                    report["tests"].append(item)
                    continue

                caldera_proof = (item.get("execution") or {}).get("caldera_proof") or {}
                effective_evidence_started = evidence_started
                effective_alert_started = test_started

                if executor == "caldera_operation":
                    proof_started = parse_report_timestamp(caldera_proof.get("started_at"))
                    proof_ended = parse_report_timestamp(caldera_proof.get("ended_at"))

                    caldera_clock_usable = (
                        proof_started is not None
                        and proof_started <= post_execution_db_time + dt.timedelta(minutes=2)
                        and proof_started >= test_started - dt.timedelta(minutes=5)
                    )

                    if proof_started is not None and not caldera_clock_usable:
                        item["caldera_evidence_window_source"] = "db_clock_caldera_clock_skew"
                        item["caldera_clock_skew_seconds"] = round(
                            (proof_started - post_execution_db_time).total_seconds(), 3
                        )

                    if proof_started is not None and caldera_clock_usable:
                        effective_evidence_started = proof_started - dt.timedelta(
                            seconds=max(0, args.evidence_lookback_seconds)
                        )
                        effective_alert_started = proof_started
                        item["evidence_started_at"] = iso(effective_evidence_started)
                        item["caldera_evidence_window_source"] = "caldera_proof"

                    if proof_ended is not None:
                        item["caldera_execution_ended_at"] = iso(proof_ended)

                if deadline_expired(test_deadline):
                    item["status"] = "infra_blocked"
                    item["score"] = execution_infra_blocked_score(
                        test,
                        f"test wall timeout after execution before observation ({args.max_test_wall_seconds}s)",
                        "test_wall_timeout_before_observation",
                        item.get("execution"),
                    )
                    item["finished_at"] = iso(utc_now())
                    report["tests"].append(item)
                    continue

                observation_seconds = (
                    args.observation_seconds
                    if args.observation_seconds is not None
                    else profile.get("default_observation_seconds", 45)
                )
                time.sleep(remaining_deadline_seconds(test_deadline, observation_seconds, floor=0))
                trace_step(f"observation complete test={test.get('id')}")

                if server is not None:
                    if args.evidence_post_seconds > 0:
                        time.sleep(remaining_deadline_seconds(test_deadline, args.evidence_post_seconds, floor=0))
                    if deadline_expired(test_deadline):
                        item["status"] = "infra_blocked"
                        item["score"] = execution_infra_blocked_score(
                            test,
                            f"test wall timeout before evidence collection ({args.max_test_wall_seconds}s)",
                            "test_wall_timeout_before_evidence",
                            item.get("execution"),
                        )
                        item["finished_at"] = iso(utc_now())
                        report["tests"].append(item)
                        continue
                    trace_step(f"evidence collection start test={test.get('id')}")

                    evidence_wait = wait_for_expected_evidence(
                        server,
                        args.agent_id,
                        iso(effective_evidence_started),
                        test,
                        remaining_deadline_seconds(test_deadline, args.evidence_wait_seconds, floor=0),
                        args.evidence_wait_poll_seconds,
                    )
                    if evidence_wait.get("enabled"):
                        item["evidence_wait"] = evidence_wait
                    trace_step(f"evidence wait complete test={test.get('id')} enabled={evidence_wait.get('enabled')}")

                    evidence_ended = server_utc_now(server) + dt.timedelta(seconds=5)
                    if executor == "caldera_operation":
                        proof_ended = parse_report_timestamp(caldera_proof.get("ended_at"))
                        if (
                            proof_ended is not None
                            and proof_ended <= evidence_ended + dt.timedelta(minutes=2)
                            and proof_ended >= effective_evidence_started - dt.timedelta(minutes=5)
                        ):
                            evidence_ended = max(evidence_ended, proof_ended + dt.timedelta(seconds=30))

                    event_summary = collect_event_summary(
                        server,
                        args.agent_id,
                        iso(effective_evidence_started),
                        iso(evidence_ended),
                        timeout=remaining_deadline_seconds(test_deadline, 15, floor=1),
                    )
                    if deadline_expired(test_deadline):
                        item["status"] = "infra_blocked"
                        item["score"] = execution_infra_blocked_score(
                            test,
                            f"test wall timeout during event summary collection ({args.max_test_wall_seconds}s)",
                            "test_wall_timeout_event_summary",
                            item.get("execution"),
                        )
                        item["event_summary"] = event_summary
                        item["finished_at"] = iso(utc_now())
                        report["tests"].append(item)
                        continue
                    expected_sample_fields = (
                        (test.get("expected_fields") or [])
                        + [
                            field
                            for fields in (test.get("expected_fields_by_event_type") or {}).values()
                            for field in fields
                        ]
                        + [
                            field
                            for field_expectations in (test.get("expected_values_by_event_type") or {}).values()
                            for field in (field_expectations or {}).keys()
                        ]
                    )
                    sample_budget = remaining_deadline_seconds(test_deadline, 20, floor=0)
                    if (
                        sample_budget < 10
                        and evidence_wait.get("ready")
                        and not expected_sample_fields
                    ):
                        event_samples = {
                            "rows": [],
                            "skipped": "deadline_low_and_telemetry_contract_already_satisfied",
                            "remaining_seconds": sample_budget,
                        }
                    else:
                        event_samples = collect_event_samples(
                            server,
                            args.agent_id,
                            iso(effective_evidence_started),
                            iso(evidence_ended),
                            args.event_sample_limit,
                            preferred_telemetry_event_types(test),
                            expected_sample_fields,
                            expected_value_needles(test),
                            timeout=max(1, sample_budget),
                        )
                    if deadline_expired(test_deadline):
                        item["status"] = "infra_blocked"
                        item["score"] = execution_infra_blocked_score(
                            test,
                            f"test wall timeout during event sample collection ({args.max_test_wall_seconds}s)",
                            "test_wall_timeout_event_samples",
                            item.get("execution"),
                        )
                        item["event_summary"] = event_summary
                        item["event_samples"] = event_samples
                        item["finished_at"] = iso(utc_now())
                        report["tests"].append(item)
                        continue
                    if test.get("expected_alerts"):
                        alert_summary = collect_alert_summary(
                            server,
                            args.agent_id,
                            iso(effective_alert_started),
                            iso(evidence_ended),
                            timeout=remaining_deadline_seconds(test_deadline, 15, floor=1),
                        )
                    else:
                        alert_summary = {"rows": [], "skipped": "no_expected_alerts"}

                    if test.get("expected_detections"):
                        detection_summary = collect_detection_summary(
                            server,
                            args.agent_id,
                            iso(effective_evidence_started),
                            iso(evidence_ended),
                            timeout=remaining_deadline_seconds(test_deadline, 15, floor=1),
                        )
                    else:
                        detection_summary = {"rows": [], "skipped": "no_expected_detections"}
                    driver_health_after = collect_driver_health_snapshot(
                        server,
                        args.agent_id,
                        timeout=remaining_deadline_seconds(test_deadline, 15, floor=1),
                    )
                    item["evidence_ended_at"] = iso(evidence_ended)
                    item["event_summary"] = event_summary
                    item["event_samples"] = event_samples
                    item["alert_summary"] = alert_summary
                    item["detection_summary"] = detection_summary
                    item["driver_health_after"] = driver_health_after
                    item["server_logs"] = collect_server_logs(
                        server,
                        args.agent_id,
                        max(2, args.observation_seconds // 60 + 2),
                        timeout=remaining_deadline_seconds(test_deadline, 10, floor=1),
                    )
                    execution_evidence_rows = live_response_execution_evidence(item.get("execution"))
                    if execution_evidence_rows:
                        item["execution_evidence"] = execution_evidence_rows
                    item["score"] = score_test(
                        test,
                        (event_summary.get("rows") or []) + execution_evidence_rows,
                        alert_summary.get("rows") or [],
                        detection_summary.get("rows") or [],
                        (event_samples.get("rows") or []) + execution_evidence_rows,
                        item.get("driver_health_before"),
                        driver_health_after,
                        effective_alert_started,
                    )
                    item["status"] = item["score"].get("status")
                else:
                    if item["execution"].get("transport") == "tamandua_ctl_live_response":
                        item["score"] = score_transport_only_execution(test, item["execution"])
                    else:
                        item["score"] = {
                            "status": "executed_without_server_evidence",
                            "expected_telemetry": test.get("expected_telemetry", []),
                        }
                    item["status"] = item["score"]["status"]

                item["finished_at"] = iso(utc_now())
                report["tests"].append(item)
                if executor == "atomic_red_team" and args.atomic_cleanup:
                    cleanup_command = build_atomic_cleanup_command(test, args)
                    if cleanup_command:
                        deferred_cleanup.append(
                            {
                                "test_id": test["id"],
                                "name": test["name"],
                                "command": cleanup_command,
                            }
                        )

            if deferred_cleanup:
                report["atomic_cleanup"] = {
                    "strategy": "deferred_post_scoring",
                    "reason": "cleanup can generate telemetry and alerts; it is intentionally run after all measured evidence windows",
                    "items": [],
                }
                for cleanup_item in deferred_cleanup:
                    cleanup_item["started_at"] = iso(utc_now())
                    cleanup_item["execution"] = guest_command(
                        proxmox,
                        args.vmid,
                        cleanup_item["command"],
                        timeout=args.test_timeout,
                    )
                    cleanup_item["finished_at"] = iso(utc_now())
                    report["atomic_cleanup"]["items"].append(cleanup_item)

            if server is not None:
                report["agent_db_after"] = collect_agent_db_state(server, args.agent_id)
        finally:
            if server_cm is not None:
                server_cm.__exit__(None, None, None)
            if endpoint_cm is not None:
                endpoint_cm.__exit__(None, None, None)

    report["finished_at"] = iso(utc_now())
    refresh_fresh_restore_provenance(report, args)
    report["summary"] = summarize_tests(report["tests"])
    report["quality_gate"] = evaluate_gates(report, args)
    report["scorecard"] = benchmark_scorecard(report)
    report["upstream_readiness"] = upstream_readiness_checklist(report)
    json_path, md_path, comparison_path = write_report(report, args.output_dir)
    print(f"execute=true json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if report["quality_gate"]["passed"] or not args.fail_on_gate else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tamandua Detection Validation runner")
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--list-profiles", action="store_true", help="List available validation profiles")
    parser.add_argument("--only", action="append", help="Run only a test id, test name, or tag. Can be repeated.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--run-id")
    parser.add_argument("--execute", action="store_true", help="Run the profile on the target VM")
    parser.add_argument(
        "--local-target",
        action="store_true",
        help="Run a non-Windows profile on the local host and require server evidence before passing quality gates",
    )
    parser.add_argument(
        "--benchmark-lane",
        choices=[
            "stable-regression",
            "enterprise-eval",
            "atomic-upstream",
            "caldera-upstream",
            "external-coverage-report-only",
            "external-semantic-rewrite-execution",
            "detection-governance",
            "analyst-ux",
            "claim-boundary",
        ],
        default=os.getenv("TAMANDUA_BENCHMARK_LANE", "stable-regression"),
        help=(
            "Controls quality-gate semantics and allowed claims. "
            "stable-regression permits deterministic fallback; enterprise-eval hardens quality gates; "
            "atomic-upstream/caldera-upstream require real upstream execution; external lanes run "
            "report-only external-source-inspired coverage and semantic rewrite prep; analyst-ux "
            "runs non-destructive analyst workflow and API/UX contract probes."
        ),
    )
    parser.add_argument("--vmid", type=int, default=int(os.getenv("TAMANDUA_PROXMOX_VMID", "0") or "0"))
    parser.add_argument(
        "--fresh-restore",
        action="store_true",
        default=os.getenv("TAMANDUA_FRESH_RESTORE", "").lower() in {"1", "true", "yes"},
        help="Mark this run as executed after an explicit fresh VM restore. Requires restore/snapshot metadata for Roadmap B claims.",
    )
    parser.add_argument("--fresh-restore-started-at", default=os.getenv("TAMANDUA_FRESH_RESTORE_STARTED_AT"))
    parser.add_argument("--fresh-restore-finished-at", default=os.getenv("TAMANDUA_FRESH_RESTORE_FINISHED_AT"))
    parser.add_argument("--fresh-restore-snapshot-name", default=os.getenv("TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME"))
    parser.add_argument("--fresh-restore-snapshot-id", default=os.getenv("TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"))
    parser.add_argument(
        "--fresh-restore-vmid",
        type=int,
        default=int(os.getenv("TAMANDUA_FRESH_RESTORE_VMID")) if os.getenv("TAMANDUA_FRESH_RESTORE_VMID") else None,
    )
    parser.add_argument("--fresh-restore-agent-id", default=os.getenv("TAMANDUA_FRESH_RESTORE_AGENT_ID"))
    parser.add_argument("--fresh-restore-hostname", default=os.getenv("TAMANDUA_FRESH_RESTORE_HOSTNAME"))
    parser.add_argument("--fresh-restore-source", default=os.getenv("TAMANDUA_FRESH_RESTORE_SOURCE"))
    parser.add_argument("--fresh-restore-notes", default=os.getenv("TAMANDUA_FRESH_RESTORE_NOTES"))
    parser.add_argument("--agent-id", default=os.getenv("TAMANDUA_AGENT_ID"))
    parser.add_argument(
        "--agent-hostname",
        default=os.getenv("TAMANDUA_AGENT_HOSTNAME"),
        help="Hostname used with --resolve-agent-by-hostname. Defaults to the guest preflight hostname.",
    )
    parser.add_argument(
        "--resolve-agent-by-hostname",
        action="store_true",
        default=os.getenv("TAMANDUA_RESOLVE_AGENT_BY_HOSTNAME", "").lower() in {"1", "true", "yes"},
        help="Resolve the current backend agent id by hostname before server-backed evidence collection.",
    )
    parser.add_argument("--proxmox-host", default=os.getenv("TAMANDUA_PROXMOX_HOST"))
    parser.add_argument("--proxmox-user", default=os.getenv("TAMANDUA_PROXMOX_USER", "root"))
    parser.add_argument("--proxmox-password", default=os.getenv("TAMANDUA_PROXMOX_PASSWORD"))
    parser.add_argument(
        "--proxmox-api",
        action="store_true",
        default=os.getenv("TAMANDUA_PROXMOX_API", "").lower() in {"1", "true", "yes"},
        help="Use the Proxmox HTTPS API for QGA command execution instead of SSHing to qm.",
    )
    parser.add_argument(
        "--proxmox-node",
        default=os.getenv("TAMANDUA_PROXMOX_NODE", "Default"),
        help="Proxmox node name used with --proxmox-api.",
    )
    parser.add_argument("--server-host", default=os.getenv("TAMANDUA_SERVER_HOST"))
    parser.add_argument("--server-user", default=os.getenv("TAMANDUA_SERVER_USER", "root"))
    parser.add_argument("--server-password", default=os.getenv("TAMANDUA_SERVER_PASSWORD"))
    parser.add_argument("--caldera-url", default=os.getenv("CALDERA_URL"))
    parser.add_argument("--caldera-api-key", default=os.getenv("CALDERA_API_KEY"))
    parser.add_argument("--caldera-adversary-id", default=os.getenv("CALDERA_ADVERSARY_ID"))
    parser.add_argument("--caldera-agent-paw", default=os.getenv("CALDERA_AGENT_PAW"))
    parser.add_argument("--caldera-group", default=os.getenv("CALDERA_GROUP", "tamandua-lab"))
    parser.add_argument("--caldera-timeout-seconds", type=int, default=int(os.getenv("CALDERA_TIMEOUT_SECONDS", "900")))
    parser.add_argument("--caldera-poll-seconds", type=int, default=int(os.getenv("CALDERA_POLL_SECONDS", "10")))
    parser.add_argument(
        "--caldera-agent-freshness-seconds",
        type=int,
        default=int(os.getenv("CALDERA_AGENT_FRESHNESS_SECONDS", "300")),
        help=(
            "Abort caldera_operation before creating an operation when the selected PAW last_seen is older "
            "than this many seconds. Use -1 only for explicit stale-agent diagnostics."
        ),
    )
    parser.add_argument(
        "--atomic-path-to-atomics",
        default=os.getenv("ATOMIC_PATH_TO_ATOMICS") or os.getenv("ATOMIC_RED_TEAM_PATH"),
        help="Optional Atomic Red Team atomics folder passed to Invoke-AtomicTest -PathToAtomicsFolder.",
    )
    parser.add_argument(
        "--atomic-cleanup",
        action="store_true",
        default=os.getenv("TAMANDUA_ATOMIC_CLEANUP", "").lower() in {"1", "true", "yes"},
        help="Run Invoke-AtomicTest -Cleanup after each upstream Atomic test.",
    )
    parser.add_argument("--baseline-seconds", type=int, default=0)
    parser.add_argument(
        "--agent-freshness-seconds",
        type=int,
        default=int(os.getenv("TAMANDUA_AGENT_FRESHNESS_SECONDS", "180")),
        help="Fail the run as infrastructure-blocked when the resolved agent is not online or last_seen is older than this many seconds.",
    )
    parser.add_argument(
        "--telemetry-flow-check-seconds",
        type=int,
        default=int(os.getenv("TAMANDUA_TELEMETRY_FLOW_CHECK_SECONDS", "180")),
        help="Maximum seconds to wait for fresh endpoint telemetry during pre-test liveness verification.",
    )
    parser.add_argument(
        "--skip-telemetry-flow-check",
        action="store_true",
        default=os.getenv("TAMANDUA_SKIP_TELEMETRY_FLOW_CHECK", "").lower() in {"1", "true", "yes"},
        help=(
            "Skip the pre-test QGA liveness telemetry check. Use only for runner/transport validation "
            "where the test execution channel itself is being evaluated."
        ),
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        default=os.getenv("TAMANDUA_SKIP_PREFLIGHT", "").lower() in {"1", "true", "yes"},
        help="Skip expensive guest preflight probes for execution-transport proof runs.",
    )
    parser.add_argument(
        "--skip-server-readiness",
        action="store_true",
        default=os.getenv("TAMANDUA_SKIP_SERVER_READINESS", "").lower() in {"1", "true", "yes"},
        help="Skip backend agent freshness and telemetry-flow readiness gates for execution-transport proof runs.",
    )
    parser.add_argument("--observation-seconds", type=int, default=0)
    parser.add_argument(
        "--evidence-lookback-seconds",
        type=int,
        default=120,
        help="Include recently ingested evidence before each test start to account for endpoint batching and clock skew.",
    )
    parser.add_argument(
        "--evidence-post-seconds",
        type=int,
        default=15,
        help="Include a short post-observation evidence grace window.",
    )
    parser.add_argument(
        "--evidence-wait-seconds",
        type=int,
        default=int(os.getenv("TAMANDUA_EVIDENCE_WAIT_SECONDS", "0")),
        help="Poll server evidence until expected telemetry/detections arrive, useful for delayed endpoint flushes.",
    )
    parser.add_argument(
        "--evidence-wait-poll-seconds",
        type=int,
        default=int(os.getenv("TAMANDUA_EVIDENCE_WAIT_POLL_SECONDS", "15")),
        help="Polling interval for --evidence-wait-seconds.",
    )
    parser.add_argument("--test-timeout", type=int, default=180)
    parser.add_argument(
        "--execution-transport",
        choices=["qga", "tamandua-ctl", "ssh"],
        default=os.getenv("TAMANDUA_EXECUTION_TRANSPORT", "qga"),
        help="Execution channel for command/Atomic tests. CALDERA tests still use the CALDERA API.",
    )
    parser.add_argument(
        "--endpoint-host",
        default=os.getenv("TAMANDUA_ENDPOINT_HOST"),
        help="Endpoint SSH host used when --execution-transport ssh.",
    )
    parser.add_argument(
        "--endpoint-user",
        default=os.getenv("TAMANDUA_ENDPOINT_USER"),
        help="Endpoint SSH username used when --execution-transport ssh.",
    )
    parser.add_argument(
        "--endpoint-password",
        default=os.getenv("TAMANDUA_ENDPOINT_PASSWORD"),
        help="Endpoint SSH password used when --execution-transport ssh.",
    )
    parser.add_argument(
        "--tamandua-ctl-path",
        default=os.getenv(
            "TAMANDUA_CTL_PATH",
            str(ROOT / "apps" / "tamandua_ctl" / "target" / "release" / "tamandua-ctl.exe"),
        ),
        help="tamandua-ctl binary used when --execution-transport tamandua-ctl.",
    )
    parser.add_argument(
        "--tamandua-ctl-server",
        default=os.getenv("TAMANDUA_CTL_SERVER") or os.getenv("TAMANDUA_SERVER"),
        help="Tamandua server URL passed to tamandua-ctl remote command.",
    )
    parser.add_argument(
        "--tamandua-ctl-token",
        default=os.getenv("TAMANDUA_CTL_TOKEN") or os.getenv("TAMANDUA_TOKEN"),
        help="Operator token passed to tamandua-ctl remote command. If omitted, tamandua-ctl uses its saved login.",
    )
    parser.add_argument(
        "--live-response-idle-timeout-seconds",
        type=int,
        default=int(os.getenv("TAMANDUA_LIVE_RESPONSE_IDLE_TIMEOUT_SECONDS", "2")),
        help="Idle timeout passed to tamandua-ctl remote command.",
    )
    parser.add_argument(
        "--live-response-shell-start-timeout-seconds",
        type=int,
        default=int(os.getenv("TAMANDUA_LIVE_RESPONSE_SHELL_START_TIMEOUT_SECONDS", "45")),
        help="Shell startup timeout passed to tamandua-ctl remote command.",
    )
    parser.add_argument(
        "--live-response-supervisor-mode",
        action="store_true",
        default=os.getenv("TAMANDUA_LIVE_RESPONSE_SUPERVISOR_MODE", "").lower() in {"1", "true", "yes"},
        help="Pass --supervisor-mode to tamandua-ctl remote command.",
    )
    parser.add_argument(
        "--max-test-wall-seconds",
        type=int,
        default=int(os.getenv("TAMANDUA_MAX_TEST_WALL_SECONDS", "900")),
        help=(
            "Hard per-test wall clock budget. When exceeded, the runner records an infra/runner gap "
            "and still writes benchmark artifacts instead of waiting indefinitely."
        ),
    )
    parser.add_argument("--event-sample-limit", type=int, default=200)
    parser.add_argument(
        "--inter-test-sleep-seconds",
        type=int,
        default=int(os.getenv("TAMANDUA_INTER_TEST_SLEEP_SECONDS", "0")),
        help=(
            "Sleep between tests to avoid overdriving endpoint collectors during long sequential "
            "profiles. Use this for signal-quality validation; use reliability profiles for stress."
        ),
    )
    parser.add_argument(
        "--block-critical-agent-health",
        action="store_true",
        default=os.getenv("TAMANDUA_BLOCK_CRITICAL_AGENT_HEALTH", "").lower() in {"1", "true", "yes"},
        help=(
            "Fail readiness when tamandua-ctl reports critical/unhealthy agent health. "
            "Use for long signal-quality profiles; stress/reliability profiles should leave this off."
        ),
    )
    parser.add_argument("--fail-on-gate", action="store_true", help="Exit non-zero when quality gate fails")
    parser.add_argument("--fail-on-missed", action="store_true", default=True)
    parser.add_argument("--allow-missed", action="store_false", dest="fail_on_missed")
    parser.add_argument("--fail-on-partial", action="store_true")
    parser.add_argument("--max-unexpected-high-critical", type=int, default=0)
    parser.add_argument("--max-unknown-source", type=int, default=-1)
    parser.add_argument("--max-driver-channel-drops", type=int, default=-1)
    parser.add_argument("--max-driver-kernel-drops", type=int, default=-1)
    parser.add_argument(
        "--require-upstream",
        action="store_true",
        help="Fail the quality gate if an upstream-capable test falls back to a deterministic command.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        return run(parse_args(argv))
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
