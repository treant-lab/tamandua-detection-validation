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


DEFAULT_OUTPUT = ROOT / "docs" / "benchmarks" / "runs"


def compact_stamp(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace(".", "")[:15] + "Z"


def write_markdown(path: Path, payload: dict) -> None:
    status = "PASS" if payload.get("passed") else "FAIL"
    lines = [
        f"# Windows QGA Network Probe: {status}",
        "",
        f"- Server host: `{payload.get('server_host')}`",
        f"- Runtime effect: `{payload.get('runtime_effect')}`",
        f"- Backend reachable: `{payload.get('backend_reachable')}`",
        f"- Agent download reachable: `{payload.get('agent_download_reachable')}`",
        f"- Next action: {payload.get('next_action')}",
        "",
        "## stderr tail",
        "",
        "```text",
        str(payload.get("stderr", ""))[-2000:],
        "```",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    resolve_proxmox_args(args)
    session, auth = qga.login(args)
    if session is None:
        print(json.dumps({"ok": False, "auth": {k: v for k, v in auth.items() if "password" not in k.lower()}}, indent=2))
        return 2
    raw = (
        "hostname\r\n"
        "echo ===TAMANDUA_BACKEND_ROOT===\r\n"
        f"curl.exe -I --max-time 10 http://{args.server_host}:4000/health/live\r\n"
        "echo ===TAMANDUA_AGENT_DOWNLOAD===\r\n"
        f"curl.exe -I --max-time 20 http://{args.server_host}:4000/downloads/agents/tamandua-agent-windows-x64.exe\r\n"
        "exit /b 0\r\n"
    )
    result = guest_exec(session, args, raw)
    stdout = str(result.get("stdout", ""))
    stderr = str(result.get("stderr", ""))
    backend_section = stdout.split("===TAMANDUA_BACKEND_ROOT===", 1)[-1].split("===TAMANDUA_AGENT_DOWNLOAD===", 1)[0]
    agent_download_section = stdout.split("===TAMANDUA_AGENT_DOWNLOAD===", 1)[-1]
    backend_reachable = "HTTP/" in backend_section
    agent_download_reachable = "HTTP/" in agent_download_section
    passed = bool(result.get("ok") and backend_reachable and agent_download_reachable)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "api_version": "tamandua.io/windows-qga-network-probe/v1",
        "kind": "WindowsQgaNetworkProbe",
        "metadata": {
            "generated_at": generated_at,
            "claim_boundary": (
                "QGA network reachability probe from WIN-TEMPLATE to the Tamandua server. "
                "Does not execute detection workloads or prove ML detection coverage."
            ),
        },
        "server_host": args.server_host,
        "runtime_effect": "read_only_qga_guest_exec_network_probe",
        "ok": passed,
        "passed": passed,
        "backend_reachable": backend_reachable,
        "agent_download_reachable": agent_download_reachable,
        "stdout": stdout[-4000:],
        "stderr": stderr[-2000:],
        "error": result.get("error"),
        "next_action": (
            "Run the agent-bound validation."
            if passed
            else (
                "Recover tamandua-server-light on the lab host and rerun this probe before "
                "attempting agent-bound ML validation."
            )
        ),
    }
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = compact_stamp(generated_at) + "-windows-qga-network-probe"
    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(md_path, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"windows_qga_network_probe={'ok' if payload['passed'] else 'gaps'} json={json_path} md={md_path}")
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
