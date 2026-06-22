#!/usr/bin/env python3
"""Read-only QGA probe for the Windows Tamandua agent service."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "tools" / "detection_validation"))
import windows_proxmox_qga_readiness_probe as qga  # noqa: E402


DEFAULT_OUTPUT = ROOT / "docs" / "benchmarks" / "runs"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compact_stamp(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace(".", "")[:15] + "Z"


def guest_exec(session: Any, args: argparse.Namespace, raw_input: str) -> dict[str, Any]:
    start = qga.request_json_retry(
        session,
        args,
        "POST",
        f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/exec",
        max_attempts_override=args.qga_exec_start_attempts,
        data={"command": "cmd.exe", "input-data": raw_input},
    )
    pid = (((start.get("body") or {}).get("data") or {}) if isinstance(start.get("body"), dict) else {}).get("pid")
    result: dict[str, Any] = {"start": start, "transport": "proxmox_api_qga_guest_exec"}
    if not start.get("ok") or pid is None:
        result.update({"ok": False, "error": "guest_exec_start_failed"})
        return result

    deadline = time.monotonic() + max(5, args.guest_exec_timeout_seconds)
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        time.sleep(1)
        poll = qga.request_json(
            session,
            args,
            "GET",
            f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/exec-status",
            params={"pid": pid},
        )
        last = poll
        data = ((poll.get("body") or {}).get("data") or {}) if isinstance(poll.get("body"), dict) else {}
        if data.get("exited"):
            stdout = qga.decode_qga(data.get("out-data"))
            stderr = qga.decode_qga(data.get("err-data"))
            result.update(
                {
                    "ok": data.get("exitcode") == 0,
                    "exitcode": data.get("exitcode"),
                    "stdout": stdout,
                    "stderr": stderr,
                    "poll": poll,
                }
            )
            return result

    result.update({"ok": False, "error": "guest_exec_status_timeout", "last_poll": last})
    return result


def parse_service_state(stdout: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("STATE"):
            parsed["state"] = stripped
        elif stripped.startswith("WIN32_EXIT_CODE"):
            parsed["win32_exit_code"] = stripped
        elif stripped.startswith("SERVICE_EXIT_CODE"):
            parsed["service_exit_code"] = stripped
    return parsed


def tasklist_agent_process_seen(stdout: str) -> bool:
    for line in stdout.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("tamandua-agent.exe"):
            return True
    return False


def tamandua_agent_service_running(stdout: str) -> bool:
    marker = "D:\\Windows\\System32>sc query TamanduaAgent"
    if marker not in stdout:
        return False
    section = stdout.split(marker, 1)[1].split("D:\\Windows\\System32>sc queryex TamanduaAgent", 1)[0]
    return "RUNNING" in section


def redact_sensitive(value: str) -> str:
    value = re.sub(r'(?im)^(auth_token\s*=\s*")[^"]+(")', r"\1<redacted>\2", value)
    value = re.sub(r'(?im)^(jwt\s*=\s*")[^"]+(")', r"\1<redacted>\2", value)
    value = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1<redacted>", value)
    return value


def build_report(args: argparse.Namespace) -> dict[str, Any]:
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

    session, auth = qga.login(args)
    started_at = utc_now()
    if session is None:
        return {
            "api_version": "tamandua.io/windows-qga-agent-service-probe/v1",
            "kind": "WindowsQgaAgentServiceProbe",
            "metadata": {"started_at": started_at, "finished_at": utc_now()},
            "runtime_effect": "read_only_qga_guest_exec",
            "passed": False,
            "auth": {key: value for key, value in auth.items() if "password" not in key.lower()},
            "service": {"reachable": False},
        }

    raw_input = (
        "hostname\r\n"
        "whoami\r\n"
        "sc query TamanduaAgent\r\n"
        "sc queryex TamanduaAgent\r\n"
        "sc qc TamanduaAgent\r\n"
        "sc query tamandua-agent\r\n"
        "sc query tamandua\r\n"
        'tasklist /FI "IMAGENAME eq tamandua-agent.exe"\r\n'
        "where /R D:\\ProgramData\\Tamandua tamandua-agent.exe 2>nul\r\n"
        "dir /s /b D:\\ProgramData\\Tamandua\\*.toml 2>nul\r\n"
        "for /R D:\\ProgramData\\Tamandua %f in (*.toml) do @echo ---CONFIG:%f--- & @type \"%f\"\r\n"
        "exit /b 0\r\n"
    )
    exec_result = guest_exec(session, args, raw_input)
    stdout = redact_sensitive(str(exec_result.get("stdout", "")))
    stderr = redact_sensitive(str(exec_result.get("stderr", "")))
    service_state = parse_service_state(stdout)
    service_running = tamandua_agent_service_running(stdout)
    process_seen = tasklist_agent_process_seen(stdout)
    running = service_running or process_seen
    return {
        "api_version": "tamandua.io/windows-qga-agent-service-probe/v1",
        "kind": "WindowsQgaAgentServiceProbe",
        "metadata": {
            "started_at": started_at,
            "finished_at": utc_now(),
            "claim_boundary": (
                "Read-only QGA guest command for Windows Tamandua agent service diagnostics. "
                "Does not execute detection workloads or prove ML detection coverage."
            ),
        },
        "target": {
            "proxmox_host": args.proxmox_host,
            "proxmox_node": args.proxmox_node,
            "vmid": str(args.vmid),
        },
        "runtime_effect": "read_only_qga_guest_exec",
        "passed": bool(exec_result.get("ok") and running and process_seen),
        "service": {
            "query_ok": bool(exec_result.get("ok")),
            "running": running,
            "service_running": service_running,
            "process_seen": process_seen,
            "state": service_state,
        },
        "next_action": (
            "Agent service appears running; rerun Windows lab readiness and then the agent-bound validation."
            if running and process_seen
            else "Agent service/process is not running or not discoverable; start or reinstall the Windows agent before agent-bound ML validation."
        ),
        "exec_error": exec_result.get("error"),
        "exec_exitcode": exec_result.get("exitcode"),
        "diagnostic_stdout_tail": stdout[-20000:],
        "diagnostic_stderr_tail": stderr[-2000:],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only Windows agent service diagnostic via Proxmox QGA")
    parser.add_argument("--proxmox-host")
    parser.add_argument("--proxmox-user")
    parser.add_argument("--proxmox-password")
    parser.add_argument("--proxmox-node")
    parser.add_argument("--vmid")
    parser.add_argument("--http-timeout-seconds", type=int, default=20)
    parser.add_argument("--guest-exec-timeout-seconds", type=int, default=45)
    parser.add_argument("--qga-retry-attempts", type=int, default=3)
    parser.add_argument("--qga-exec-start-attempts", type=int, default=3)
    parser.add_argument("--qga-retry-sleep-seconds", type=float, default=2.0)
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)
    run_id = compact_stamp(report["metadata"]["started_at"]) + "-windows-qga-agent-service-probe"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{run_id}.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"windows_qga_agent_service_probe={'ok' if report['passed'] else 'gaps'} json={output_path}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
