#!/usr/bin/env python3
"""Power-cycle the Windows lab VM through Proxmox API."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
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


def resolve_args(args: argparse.Namespace) -> None:
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


def vm_status(session: Any, args: argparse.Namespace) -> dict[str, Any]:
    return qga.request_json(
        session,
        args,
        "GET",
        f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/status/current",
    )


def task_status(session: Any, args: argparse.Namespace, task: dict[str, Any] | None) -> dict[str, Any] | None:
    if not task or not task.get("ok"):
        return None
    upid = ((task.get("body") or {}).get("data") or "") if isinstance(task.get("body"), dict) else ""
    if not isinstance(upid, str) or not upid:
        return None
    return qga.request_json(
        session,
        args,
        "GET",
        f"/nodes/{args.proxmox_node}/tasks/{urllib.parse.quote(upid, safe='')}/status",
    )


def wait_for_status(session: Any, args: argparse.Namespace, expected: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = vm_status(session, args)
        data = ((last.get("body") or {}).get("data") or {}) if isinstance(last.get("body"), dict) else {}
        if data.get("status") == expected:
            return last
        time.sleep(5)
    return last


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    resolve_args(args)
    started_at = utc_now()
    session, auth = qga.login(args)
    if session is None:
        return {
            "api_version": "tamandua.io/windows-proxmox-powercycle/v1",
            "kind": "WindowsProxmoxPowercycle",
            "metadata": {"started_at": started_at, "finished_at": utc_now()},
            "passed": False,
            "auth": {key: value for key, value in auth.items() if "password" not in key.lower()},
        }

    before = vm_status(session, args)
    before_data = ((before.get("body") or {}).get("data") or {}) if isinstance(before.get("body"), dict) else {}
    stop = qga.request_json(
        session,
        args,
        "POST",
        f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/status/stop",
        data={"skiplock": "1", "timeout": str(args.stop_timeout_seconds)},
    )
    stopped = wait_for_status(session, args, "stopped", args.wait_stopped_seconds)
    stopped_data = ((stopped.get("body") or {}).get("data") or {}) if isinstance(stopped.get("body"), dict) else {}
    reset: dict[str, Any] | None = None
    if stopped_data.get("status") == "stopped":
        start = qga.request_json(
            session,
            args,
            "POST",
            f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/status/start",
            data={"skiplock": "1"},
        )
    else:
        reset = qga.request_json(
            session,
            args,
            "POST",
            f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/status/reset",
            data={"skiplock": "1"},
        )
        start = {"ok": True, "skipped": "reset_fallback_used"}
    stop_task_status = task_status(session, args, stop)
    reset_task_status = task_status(session, args, reset)
    start_task_status = task_status(session, args, start)
    time.sleep(args.boot_wait_seconds)
    after = vm_status(session, args)
    after_data = ((after.get("body") or {}).get("data") or {}) if isinstance(after.get("body"), dict) else {}
    reboot_observed = (
        after_data.get("status") == "running"
        and (
            after_data.get("pid") != before_data.get("pid")
            or int(after_data.get("uptime") or 0) < int(before_data.get("uptime") or 0)
        )
    )
    return {
        "api_version": "tamandua.io/windows-proxmox-powercycle/v1",
        "kind": "WindowsProxmoxPowercycle",
        "metadata": {
            "started_at": started_at,
            "finished_at": utc_now(),
            "claim_boundary": "Power-cycles the configured Windows lab VM only; does not execute detection workloads.",
        },
        "target": {
            "proxmox_host": args.proxmox_host,
            "proxmox_node": args.proxmox_node,
            "vmid": str(args.vmid),
        },
        "steps": {
            "before": before,
            "stop": stop,
            "stop_task_status": stop_task_status,
            "stopped": stopped,
            "reset": reset,
            "reset_task_status": reset_task_status,
            "start": start,
            "start_task_status": start_task_status,
            "after": after,
        },
        "passed": bool((stop.get("ok") or (reset or {}).get("ok")) and start.get("ok") and reboot_observed),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Power-cycle Windows lab VM through Proxmox")
    parser.add_argument("--proxmox-host")
    parser.add_argument("--proxmox-user")
    parser.add_argument("--proxmox-password")
    parser.add_argument("--proxmox-node")
    parser.add_argument("--vmid")
    parser.add_argument("--http-timeout-seconds", type=int, default=30)
    parser.add_argument("--qga-retry-attempts", type=int, default=3)
    parser.add_argument("--qga-retry-sleep-seconds", type=float, default=2.0)
    parser.add_argument("--stop-timeout-seconds", type=int, default=1)
    parser.add_argument("--wait-stopped-seconds", type=int, default=90)
    parser.add_argument("--boot-wait-seconds", type=int, default=120)
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)
    run_id = compact_stamp(report["metadata"]["started_at"]) + "-windows-proxmox-powercycle"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{run_id}.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"windows_proxmox_powercycle={'ok' if report['passed'] else 'gaps'} json={output_path}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
