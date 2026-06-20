#!/usr/bin/env python3
"""Short read-only-ish QGA network probe from WIN-TEMPLATE to Tamandua server."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from root_resolver import ROOT
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "tools" / "detection_validation"))
import windows_proxmox_qga_readiness_probe as qga  # noqa: E402
from windows_qga_agent_service_probe import guest_exec  # noqa: E402
from windows_qga_start_foreground_agent import resolve_proxmox_args  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-host", default="192.168.12.146")
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
    args = parser.parse_args()
    resolve_proxmox_args(args)
    session, auth = qga.login(args)
    if session is None:
        print(json.dumps({"ok": False, "auth": {k: v for k, v in auth.items() if "password" not in k.lower()}}, indent=2))
        return 2
    raw = (
        "hostname\r\n"
        f"curl.exe -I --max-time 10 http://{args.server_host}:4000/\r\n"
        f"curl.exe -I --max-time 20 http://{args.server_host}:4000/downloads/agents/tamandua-agent-windows-x64.exe\r\n"
        "exit /b 0\r\n"
    )
    result = guest_exec(session, args, raw)
    payload = {
        "api_version": "tamandua.io/windows-qga-network-probe/v1",
        "kind": "WindowsQgaNetworkProbe",
        "metadata": {"generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")},
        "server_host": args.server_host,
        "ok": bool(result.get("ok")),
        "stdout": str(result.get("stdout", ""))[-4000:],
        "stderr": str(result.get("stderr", ""))[-2000:],
        "error": result.get("error"),
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
