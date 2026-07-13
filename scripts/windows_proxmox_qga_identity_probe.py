#!/usr/bin/env python3
"""Read-only Windows guest identity probe through Proxmox QGA GET endpoints."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3


urllib3.disable_warnings()

try:
    from root_resolver import ROOT, RUNS_DIR
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"

PROFILE_ID = "windows-proxmox-qga-identity-probe"
PROFILE_NAME = "Windows Proxmox QGA Identity Probe"


def load_dotenv(path: Path = ROOT / ".env") -> None:
    if os.getenv("TAMANDUA_SKIP_DOTENV") or not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
            value = value[1:-1]
        os.environ[key] = value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            ).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--short"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def request_json(session: requests.Session, base: str, path: str, timeout: int) -> dict[str, Any]:
    try:
        response = session.get(base + path, timeout=timeout)
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text[:1000]
        return {"ok": response.ok, "status": response.status_code, "body": body}
    except Exception as exc:
        return {"ok": False, "status": None, "error": f"{type(exc).__name__}: {exc}"}


def response_data(response: dict[str, Any]) -> Any:
    body = response.get("body")
    return body.get("data") if isinstance(body, dict) else None


def login(args: argparse.Namespace) -> tuple[requests.Session | None, dict[str, Any]]:
    session = requests.Session()
    session.verify = False
    session.trust_env = False
    base = f"https://{args.proxmox_host}:8006/api2/json"
    if not args.proxmox_password:
        return None, {
            "authenticated": False,
            "error": "missing_proxmox_password",
            "required_env": "TAMANDUA_PROXMOX_PASSWORD",
        }
    try:
        response = session.post(
            f"{base}/access/ticket",
            data={"username": args.proxmox_user, "password": args.proxmox_password},
            timeout=args.http_timeout_seconds,
        )
        if not response.ok:
            return None, {"authenticated": False, "status": response.status_code, "error": response.text[:1000]}
        auth = response.json().get("data") or {}
        if not auth.get("ticket") or not auth.get("CSRFPreventionToken"):
            return None, {"authenticated": False, "status": response.status_code, "error": "missing_ticket_or_csrf"}
        session.cookies.set("PVEAuthCookie", auth["ticket"])
        session.headers.update({"CSRFPreventionToken": auth["CSRFPreventionToken"]})
        return session, {"authenticated": True, "status": response.status_code}
    except Exception as exc:
        return None, {"authenticated": False, "error": f"{type(exc).__name__}: {exc}"}


def summarize_network(data: Any) -> list[dict[str, Any]]:
    result = data.get("result") if isinstance(data, dict) else data
    interfaces = result if isinstance(result, list) else []
    summary = []
    for interface in interfaces:
        ips = [
            {
                "ip_address": item.get("ip-address"),
                "type": item.get("ip-address-type"),
                "prefix": item.get("prefix"),
            }
            for item in interface.get("ip-addresses", [])
            if isinstance(item, dict)
        ]
        summary.append(
            {
                "name": interface.get("name"),
                "hardware_address": interface.get("hardware-address"),
                "ip_addresses": ips,
            }
        )
    return summary


def probe_vm(session: requests.Session, args: argparse.Namespace, vmid: str) -> dict[str, Any]:
    base = f"https://{args.proxmox_host}:8006/api2/json"
    endpoints = {
        "status": f"/nodes/{args.proxmox_node}/qemu/{vmid}/status/current",
        "qga_info": f"/nodes/{args.proxmox_node}/qemu/{vmid}/agent/info",
        "hostname": f"/nodes/{args.proxmox_node}/qemu/{vmid}/agent/get-host-name",
        "osinfo": f"/nodes/{args.proxmox_node}/qemu/{vmid}/agent/get-osinfo",
        "network": f"/nodes/{args.proxmox_node}/qemu/{vmid}/agent/network-get-interfaces",
    }
    responses = {
        name: request_json(session, base, path, args.http_timeout_seconds)
        for name, path in endpoints.items()
    }
    hostname_data = response_data(responses["hostname"])
    hostname_result = hostname_data.get("result") if isinstance(hostname_data, dict) else {}
    status_data = response_data(responses["status"])
    return {
        "vmid": vmid,
        "proxmox_name": status_data.get("name") if isinstance(status_data, dict) else None,
        "power_status": status_data.get("status") if isinstance(status_data, dict) else None,
        "qga_agent_enabled": status_data.get("agent") if isinstance(status_data, dict) else None,
        "guest_hostname": hostname_result.get("host-name") if isinstance(hostname_result, dict) else None,
        "network": summarize_network(response_data(responses["network"])),
        "responses": {
            name: {
                "ok": response.get("ok"),
                "status": response.get("status"),
                "error": response.get("error"),
            }
            for name, response in responses.items()
        },
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now()
    session, auth = login(args)
    vms: list[dict[str, Any]] = []
    if session is not None:
        vms = [probe_vm(session, args, vmid.strip()) for vmid in args.vmids.split(",") if vmid.strip()]
    qga_readonly_any = any(vm["responses"].get("hostname", {}).get("ok") or vm["responses"].get("network", {}).get("ok") for vm in vms)
    all_expected_hostnames = {
        item.strip().upper()
        for item in (args.expected_hostnames or "").split(",")
        if item.strip()
    }
    observed_hostnames = {str(vm.get("guest_hostname") or "").upper() for vm in vms if vm.get("guest_hostname")}
    expected_missing = sorted(all_expected_hostnames - observed_hostnames)
    passed = bool(auth.get("authenticated")) and qga_readonly_any and not expected_missing
    return {
        "schema_version": 1,
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}",
        "profile_id": PROFILE_ID,
        "profile_name": PROFILE_NAME,
        "started_at": started,
        "finished_at": utc_now(),
        "runtime_effect": "read_only_proxmox_qga_get",
        "claim_boundary": (
            "Read-only Proxmox QGA identity evidence only. This does not execute guest commands, "
            "mutate Windows state, prove agent enrollment, or prove detection readiness."
        ),
        "git": git_snapshot(),
        "auth": auth,
        "vmids": vms,
        "quality_gate": {
            "passed": passed,
            "status": "pass" if passed else "fail",
            "blocking_gaps": ([] if passed else (["missing_expected_hostname"] if expected_missing else ["qga_readonly_identity_gap"])),
        },
        "summary": {
            "vm_count": len(vms),
            "qga_readonly_any": qga_readonly_any,
            "expected_hostnames": sorted(all_expected_hostnames),
            "observed_hostnames": sorted(observed_hostnames),
            "missing_expected_hostnames": expected_missing,
        },
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Runtime effect: `{report['runtime_effect']}`",
        "",
        "| VMID | Proxmox Name | Guest Hostname | Power | QGA Hostname | QGA Network |",
        "|------|--------------|----------------|-------|--------------|-------------|",
    ]
    for vm in report["vmids"]:
        responses = vm.get("responses", {})
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                vm.get("vmid"),
                vm.get("proxmox_name") or "",
                vm.get("guest_hostname") or "",
                vm.get("power_status") or "",
                "ok" if responses.get("hostname", {}).get("ok") else "gap",
                "ok" if responses.get("network", {}).get("ok") else "gap",
            )
        )
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"], ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    load_dotenv()
    parser = argparse.ArgumentParser(description=PROFILE_NAME)
    parser.add_argument("--proxmox-host", default=os.getenv("TAMANDUA_PROXMOX_HOST", "192.168.12.149"))
    parser.add_argument("--proxmox-user", default=os.getenv("TAMANDUA_PROXMOX_USER", "root@pam"))
    parser.add_argument("--proxmox-password", default=os.getenv("TAMANDUA_PROXMOX_PASSWORD"))
    parser.add_argument("--proxmox-node", default=os.getenv("TAMANDUA_PROXMOX_NODE", "Default"))
    parser.add_argument("--vmids", default="1520,1521")
    parser.add_argument("--expected-hostnames", default="")
    parser.add_argument("--http-timeout-seconds", type=int, default=int(os.getenv("TAMANDUA_PROXMOX_HTTP_TIMEOUT_SECONDS", "20")))
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{report['run_id']}.json"
    md_path = output_dir / f"{report['run_id']}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(report, md_path)
    print(
        "windows_proxmox_qga_identity="
        f"{'ok' if report['quality_gate']['passed'] else 'gaps'} json={json_path} markdown={md_path}"
    )
    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
