#!/usr/bin/env python3
"""Start the Windows agent in foreground via QGA for lab validation."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "tools" / "detection_validation"))
import windows_proxmox_qga_readiness_probe as qga  # noqa: E402
from windows_qga_agent_service_probe import guest_exec  # noqa: E402


DEFAULT_AGENT_ID = "717f4ffc-d373-4bb4-b021-36d7c51838f0"
DEFAULT_SERVER_HOST = "192.168.12.146"
DEFAULT_OUTPUT = ROOT / "docs" / "benchmarks" / "runs"
DEFAULT_REMOTE_CONFIG = Path.home() / "AppData" / "Roaming" / "Tamandua" / "tamandua-ctl" / "remote.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compact_stamp(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace(".", "")[:15] + "Z"


def resolve_proxmox_args(args: argparse.Namespace) -> None:
    qga.load_dotenv()
    if not args.proxmox_host:
        args.proxmox_host = qga.os.environ.get("TAMANDUA_PROXMOX_HOST", "192.168.12.149")
    if not args.proxmox_user:
        args.proxmox_user = qga.os.environ.get("TAMANDUA_PROXMOX_USER", "root@pam")
    if not args.proxmox_password:
        args.proxmox_password = qga.os.environ.get("TAMANDUA_PROXMOX_PASSWORD", "")
    if not args.proxmox_node:
        args.proxmox_node = qga.os.environ.get("TAMANDUA_PROXMOX_NODE", "Default")
    if not args.vmid:
        args.vmid = qga.os.environ.get("TAMANDUA_WINDOWS_VMID", "1521")


def load_ctl_bearer(remote_config: Path) -> str:
    data = json.loads(remote_config.read_text(encoding="utf-8"))
    token = data.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"tamandua-ctl remote config has no token: {remote_config}")
    return token


def create_installation_token(args: argparse.Namespace) -> str:
    if args.installation_token:
        return args.installation_token

    remote_config = Path(args.remote_config)
    bearer = load_ctl_bearer(remote_config)
    body = json.dumps(
        {
            "name": f"WIN-TEMPLATE QGA lab bootstrap {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "max_uses": 1,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"http://{args.server_host}:4000/api/v1/admin/installation-tokens",
        data=body,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=args.http_timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"installation token creation failed: HTTP {error.code}: {details}") from error

    token = payload.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("installation token creation response did not include a cleartext token")
    return token


def build_guest_script(args: argparse.Namespace) -> str:
    server_ws = f"ws://{args.server_host}:4000/socket/agent"
    agent_url = f"http://{args.server_host}:4000/downloads/agents/tamandua-agent-windows-x64.exe"
    auth_token = f"dev-win-template-{args.agent_id}"
    # Keep this as plain cmd.exe input. Long PowerShell -EncodedCommand payloads
    # are brittle through QGA/cmd command-line limits on this lab VM.
    lines = [
        "@echo off",
        "set ROOT=D:\\ProgramData\\Tamandua\\qga-foreground",
        "set EXE=%ROOT%\\tamandua-agent.exe",
        "set CFG=%ROOT%\\agent.toml",
        "set OUT=%ROOT%\\agent.out.log",
        "set ERR=%ROOT%\\agent.err.log",
        "mkdir \"%ROOT%\" 2>nul",
        "for /f \"tokens=2\" %p in ('tasklist /fi \"imagename eq tamandua-agent.exe\" /fo list ^| findstr /b \"PID:\"') do taskkill /pid %p /f >nul 2>nul",
        f"curl.exe -L --max-time 90 -o \"%EXE%\" \"{agent_url}\"",
        "if not exist \"%EXE%\" echo download_failed & exit /b 2",
        f"> \"%CFG%\" echo agent_id = \"{args.agent_id}\"",
        f">> \"%CFG%\" echo server_url = \"{server_ws}\"",
        f">> \"%CFG%\" echo auth_token = \"{auth_token}\"",
        ">> \"%CFG%\" echo heartbeat_interval_seconds = 10",
        ">> \"%CFG%\" echo batch_size = 25",
        ">> \"%CFG%\" echo batch_timeout_seconds = 5",
        ">> \"%CFG%\" echo reconnect_delay_seconds = 5",
        ">> \"%CFG%\" echo max_reconnect_attempts = 0",
        ">> \"%CFG%\" echo connection_timeout_seconds = 30",
        ">> \"%CFG%\" echo yara_enabled = false",
        ">> \"%CFG%\" echo entropy_check_enabled = true",
        ">> \"%CFG%\" echo entropy_threshold = 7.2",
        ">> \"%CFG%\" echo honeyfiles_enabled = false",
        ">> \"%CFG%\" echo monitored_file_patterns = [\"*.exe\", \"*.dll\", \"*.ps1\", \"*.bat\", \"*.cmd\"]",
        ">> \"%CFG%\" echo excluded_paths = [\"C:\\\\Windows\\\\WinSxS\", \"C:\\\\Windows\\\\Installer\"]",
        ">> \"%CFG%\" echo excluded_processes = [\"System\", \"svchost.exe\"]",
        ">> \"%CFG%\" echo.",
        ">> \"%CFG%\" echo [transport]",
        ">> \"%CFG%\" echo backup_servers = []",
        ">> \"%CFG%\" echo cert_pins = []",
        ">> \"%CFG%\" echo.",
        ">> \"%CFG%\" echo [tls]",
        ">> \"%CFG%\" echo enabled = false",
        ">> \"%CFG%\" echo skip_verify = true",
        "del \"%OUT%\" \"%ERR%\" 2>nul",
        "start \"TamanduaAgentForeground\" /MIN cmd.exe /c \"\"%EXE%\" --config \"%CFG%\" --foreground --profile lightweight --log-level info 1>>\"%OUT%\" 2>>\"%ERR%\"\"",
        "ping -n 16 127.0.0.1 >nul",
        "for /f \"tokens=2\" %p in ('tasklist /fi \"imagename eq tamandua-agent.exe\" /fo list ^| findstr /b \"PID:\"') do set AGENTPID=%p",
        "echo {\"running\":true,\"pid\":\"%AGENTPID%\",\"exe\":\"%EXE%\",\"config\":\"%CFG%\"}",
        "exit /b 0",
    ]
    return "\r\n".join(lines) + "\r\n"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    resolve_proxmox_args(args)
    started_at = utc_now()
    session, auth = qga.login(args)
    if session is None:
        return {
            "api_version": "tamandua.io/windows-qga-start-foreground-agent/v1",
            "kind": "WindowsQgaStartForegroundAgent",
            "metadata": {"started_at": started_at, "finished_at": utc_now()},
            "passed": False,
            "auth": {key: value for key, value in auth.items() if "password" not in key.lower()},
        }
    server_ws = f"ws://{args.server_host}:4000/socket/agent"
    enrollment_url = f"http://{args.server_host}:4000"
    agent_url = f"http://{args.server_host}:4000/downloads/agents/tamandua-agent-windows-x64.exe"
    issued_installation_token = None
    try:
        installation_token = create_installation_token(args)
        issued_installation_token = args.installation_token is None
    except Exception as error:
        return {
            "api_version": "tamandua.io/windows-qga-start-foreground-agent/v1",
            "kind": "WindowsQgaStartForegroundAgent",
            "metadata": {"started_at": started_at, "finished_at": utc_now()},
            "passed": False,
            "target": {
                "proxmox_host": args.proxmox_host,
                "proxmox_node": args.proxmox_node,
                "vmid": str(args.vmid),
                "server_host": args.server_host,
            },
            "token_source": "provided" if args.installation_token else "tamandua_ctl_remote_config",
            "raw_guest_exec_error": str(error),
        }
    root = "D:\\ProgramData\\Tamandua\\qga-foreground"
    exe = f"{root}\\tamandua-agent.exe"
    out_log = f"{root}\\agent.out.log"
    err_log = f"{root}\\agent.err.log"

    def run_step(name: str, raw_input: str) -> dict[str, Any]:
        result = guest_exec(session, args, "@echo off\r\n" + raw_input + "\r\nexit /b 0\r\n")
        return {
            "name": name,
            "ok": bool(result.get("ok")),
            "error": result.get("error"),
            "stdout_tail": str(result.get("stdout", ""))[-2000:],
            "stderr_tail": str(result.get("stderr", ""))[-2000:],
        }

    steps = [
        run_step(
            "prepare",
            "\r\n".join(
                [
                    f'mkdir "{root}" 2>nul',
                    'sc stop TamanduaAgent >nul 2>nul',
                    'taskkill /IM tamandua-agent.exe /T /F >nul 2>nul',
                    'ping -n 6 127.0.0.1 >nul',
                    'sc delete TamanduaAgent >nul 2>nul',
                    f'attrib -R "{exe}" >nul 2>nul',
                    f'del "{exe}" >nul 2>nul',
                    f'del "{out_log}" "{err_log}" 2>nul',
                ]
            ),
        ),
        run_step(
            "download",
            "\r\n".join(
                [
                    f'curl.exe -f -L --max-time 90 -o "{exe}" "{agent_url}"',
                    "if errorlevel 1 exit /b 23",
                    f'if not exist "{exe}" exit /b 2',
                ]
            ),
        ),
        run_step(
            "install",
            "\r\n".join(
                [
                    f'"{exe}" install --token "{installation_token}" --server "{server_ws}" --enrollment-url "{enrollment_url}" --no-driver >"{out_log}" 2>"{err_log}"',
                ]
            ),
        ),
        run_step(
            "start",
            f'"{exe}" start >"{out_log}" 2>"{err_log}"\r\nping -n 12 127.0.0.1 >nul',
        ),
        run_step(
            "inspect",
            f'sc query TamanduaAgent\r\ntasklist /FI "IMAGENAME eq tamandua-agent.exe" /FO LIST\r\nif exist "{err_log}" type "{err_log}"\r\nif exist "{out_log}" type "{out_log}"',
        ),
    ]
    inspect = steps[-1]
    running = "RUNNING" in inspect.get("stdout_tail", "") or "tamandua-agent.exe" in inspect.get("stdout_tail", "")
    parsed = {"exe": exe, "pid": None, "stdout_tail": inspect.get("stdout_tail", ""), "stderr_tail": inspect.get("stderr_tail", "")}
    for line in inspect.get("stdout_tail", "").splitlines():
        if line.strip().startswith("PID:"):
            parsed["pid"] = line.split(":", 1)[1].strip()
            break
    return {
        "api_version": "tamandua.io/windows-qga-start-foreground-agent/v1",
        "kind": "WindowsQgaStartForegroundAgent",
        "metadata": {
            "started_at": started_at,
            "finished_at": utc_now(),
            "claim_boundary": (
                "Installs and starts the Windows agent service for lab validation. "
                "When no token is provided it creates a one-use installation token from tamandua-ctl credentials. "
                "Does not execute ML detection workloads by itself."
            ),
        },
        "target": {
            "proxmox_host": args.proxmox_host,
            "proxmox_node": args.proxmox_node,
            "vmid": str(args.vmid),
            "agent_id": args.agent_id,
            "server_host": args.server_host,
        },
        "runtime_effect": "qga_guest_exec_starts_foreground_agent_process",
        "passed": bool(all(step.get("ok") for step in steps) and running),
        "foreground_agent": {
            "running": running,
            "pid": parsed.get("pid"),
            "exe": parsed.get("exe"),
            "stdout_tail": parsed.get("stdout_tail", "")[-2000:],
            "stderr_tail": parsed.get("stderr_tail", "")[-2000:],
        },
        "token_source": "provided" if args.installation_token else "tamandua_ctl_remote_config",
        "installation_token_created": issued_installation_token,
        "steps": [
            {
                **step,
                "stdout_tail": step["stdout_tail"].replace(installation_token, "<redacted-installation-token>"),
                "stderr_tail": step["stderr_tail"].replace(installation_token, "<redacted-installation-token>"),
            }
            for step in steps
        ],
        "raw_guest_exec_ok": all(step.get("ok") for step in steps),
        "raw_guest_exec_error": next((step.get("error") for step in steps if step.get("error")), None),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start foreground Windows agent via Proxmox QGA")
    parser.add_argument("--agent-id", default=DEFAULT_AGENT_ID)
    parser.add_argument("--server-host", default=DEFAULT_SERVER_HOST)
    parser.add_argument("--installation-token")
    parser.add_argument("--remote-config", default=str(DEFAULT_REMOTE_CONFIG))
    parser.add_argument("--proxmox-host")
    parser.add_argument("--proxmox-user")
    parser.add_argument("--proxmox-password")
    parser.add_argument("--proxmox-node")
    parser.add_argument("--vmid")
    parser.add_argument("--http-timeout-seconds", type=int, default=30)
    parser.add_argument("--guest-exec-timeout-seconds", type=int, default=90)
    parser.add_argument("--qga-retry-attempts", type=int, default=3)
    parser.add_argument("--qga-exec-start-attempts", type=int, default=3)
    parser.add_argument("--qga-retry-sleep-seconds", type=float, default=2.0)
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)
    run_id = compact_stamp(report["metadata"]["started_at"]) + "-windows-qga-start-foreground-agent"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{run_id}.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"windows_qga_start_foreground_agent={'ok' if report['passed'] else 'gaps'} json={output_path}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
