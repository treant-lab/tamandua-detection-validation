#!/usr/bin/env python3
"""Read-only Windows guest identity probe through Proxmox QGA GET endpoints."""

from __future__ import annotations

import argparse
import json
import os
import re
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


def _trusted_windows_root() -> Path | None:
    if os.name != "nt":
        return None
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    except (AttributeError, OSError):
        return None
    if length == 0 or length >= len(buffer):
        return None
    return Path(buffer.value)


def _canonical_system_curl() -> Path | None:
    configured_root = os.environ.get("SystemRoot")
    trusted_root = _trusted_windows_root()
    if not configured_root or trusted_root is None:
        return None
    try:
        configured = Path(configured_root).resolve(strict=True)
        trusted = trusted_root.resolve(strict=True)
        candidate = (configured / "System32" / "curl.exe").resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    same_path = lambda left, right: os.path.normcase(str(left)) == os.path.normcase(str(right))
    expected = trusted / "System32" / "curl.exe"
    if not same_path(configured, trusted) or not same_path(candidate, expected) or not candidate.is_file():
        return None
    return candidate


def _curl_environment(curl_path: Path) -> dict[str, str]:
    windows_root = str(curl_path.parents[1])
    return {"SystemRoot": windows_root, "WINDIR": windows_root}


def _redact_text(value: Any, secrets: tuple[str, ...]) -> str:
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text[:1000]


def _curl_config_value(value: Any) -> str:
    text = str(value)
    if any(character in text for character in ("\r", "\n", "\0")):
        raise ValueError("curl config values cannot contain control characters")
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _curl_config_line(name: str, value: Any) -> str:
    return f'{name} = "{_curl_config_value(value)}"'


def _curl_timeout(timeout: int) -> int:
    return max(1, int(timeout))


def _run_curl(config: str, timeout: int, secrets: tuple[str, ...]) -> dict[str, Any]:
    bounded_timeout = _curl_timeout(timeout)
    curl_path = _canonical_system_curl()
    if curl_path is None:
        return {
            "ok": False,
            "status": None,
            "error": "curl_transport_unavailable: canonical_system_curl_missing_or_untrusted",
        }
    argv = [str(curl_path), "--disable", "--config", "-"]
    try:
        completed = subprocess.run(
            argv,
            input=config,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=bounded_timeout + 2,
            check=False,
            shell=False,
            env=_curl_environment(curl_path),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "status": None, "error": "curl_transport_timeout"}
    except OSError as exc:
        return {
            "ok": False,
            "status": None,
            "error": f"curl_transport_unavailable: {type(exc).__name__}",
        }

    if completed.returncode != 0:
        return {
            "ok": False,
            "status": None,
            "error": f"curl_transport_error: exit_{completed.returncode}",
        }

    body_text, separator, status_text = completed.stdout.rpartition("\n")
    if not separator or not re.fullmatch(r"\d{3}", status_text.strip()):
        return {"ok": False, "status": None, "error": "curl_transport_invalid_response"}
    status = int(status_text.strip())
    try:
        body: Any = json.loads(body_text)
    except ValueError:
        body = _redact_text(body_text, secrets)
    return {"ok": 200 <= status < 300, "status": status, "body": body}


def _curl_base_config(url: str, timeout: int) -> list[str]:
    bounded_timeout = _curl_timeout(timeout)
    return [
        "silent",
        "show-error",
        "insecure",
        _curl_config_line("url", url),
        f"connect-timeout = {bounded_timeout}",
        f"max-time = {bounded_timeout}",
        _curl_config_line("write-out", "\\n%{http_code}"),
    ]


class CurlReadOnlyTransport:
    """curl-backed GET transport whose authentication material never enters argv."""

    def __init__(self, ticket: str):
        self._ticket = ticket

    def __repr__(self) -> str:
        return "CurlReadOnlyTransport(ticket=<redacted>)"

    def get_json(self, base: str, path: str, timeout: int) -> dict[str, Any]:
        config = _curl_base_config(base + path, timeout)
        config.append(_curl_config_line("header", f"Cookie: PVEAuthCookie={self._ticket}"))
        return _run_curl("\n".join(config) + "\n", timeout, (self._ticket,))


def _windows_curl_fallback_enabled() -> bool:
    return os.name == "nt"


def _is_windows_transport_failure(exc: BaseException) -> bool:
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, (requests.ConnectionError, requests.exceptions.SSLError, FileNotFoundError)):
            return True
        current = current.__cause__ or current.__context__
    return False


def _curl_login(args: argparse.Namespace, base: str) -> tuple[CurlReadOnlyTransport | None, dict[str, Any]]:
    password = str(args.proxmox_password or "")
    try:
        config = _curl_base_config(f"{base}/access/ticket", args.http_timeout_seconds)
        config.extend(
            [
                _curl_config_line("request", "POST"),
                _curl_config_line("data-urlencode", f"username={args.proxmox_user}"),
                _curl_config_line("data-urlencode", f"password={password}"),
            ]
        )
    except ValueError as exc:
        return None, {"authenticated": False, "error": _redact_text(exc, (password,))}

    response = _run_curl("\n".join(config) + "\n", args.http_timeout_seconds, (password,))
    if not response.get("ok"):
        result = {"authenticated": False, "status": response.get("status")}
        result["error"] = str(response.get("error") or "curl_login_http_error")
        return None, result
    body = response.get("body")
    auth = body.get("data") if isinstance(body, dict) else None
    auth = auth if isinstance(auth, dict) else {}
    ticket = str(auth.get("ticket") or "")
    csrf = str(auth.get("CSRFPreventionToken") or "")
    if not ticket or not csrf:
        return None, {
            "authenticated": False,
            "status": response.get("status"),
            "error": "missing_ticket_or_csrf",
        }
    return CurlReadOnlyTransport(ticket), {"authenticated": True, "status": response.get("status")}


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


def request_json(session: requests.Session | CurlReadOnlyTransport, base: str, path: str, timeout: int) -> dict[str, Any]:
    if isinstance(session, CurlReadOnlyTransport):
        return session.get_json(base, path, timeout)
    try:
        response = session.get(base + path, timeout=timeout)
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text[:1000]
        return {"ok": response.ok, "status": response.status_code, "body": body}
    except Exception as exc:
        return {"ok": False, "status": None, "error": f"{type(exc).__name__}: request_get_failed"}


def response_data(response: dict[str, Any]) -> Any:
    body = response.get("body")
    return body.get("data") if isinstance(body, dict) else None


def login(args: argparse.Namespace) -> tuple[requests.Session | CurlReadOnlyTransport | None, dict[str, Any]]:
    base = f"https://{args.proxmox_host}:8006/api2/json"
    if not args.proxmox_password:
        return None, {
            "authenticated": False,
            "error": "missing_proxmox_password",
            "required_env": "TAMANDUA_PROXMOX_PASSWORD",
        }
    try:
        session = requests.Session()
        session.verify = False
        session.trust_env = False
        response = session.post(
            f"{base}/access/ticket",
            data={"username": args.proxmox_user, "password": args.proxmox_password},
            timeout=args.http_timeout_seconds,
        )
        if not response.ok:
            return None, {
                "authenticated": False,
                "status": response.status_code,
                "error": "proxmox_login_rejected",
            }
        auth = response.json().get("data") or {}
        if not auth.get("ticket") or not auth.get("CSRFPreventionToken"):
            return None, {"authenticated": False, "status": response.status_code, "error": "missing_ticket_or_csrf"}
        session.cookies.set("PVEAuthCookie", auth["ticket"])
        session.headers.update({"CSRFPreventionToken": auth["CSRFPreventionToken"]})
        return session, {"authenticated": True, "status": response.status_code}
    except Exception as exc:
        if _windows_curl_fallback_enabled() and _is_windows_transport_failure(exc):
            return _curl_login(args, base)
        return None, {"authenticated": False, "error": f"{type(exc).__name__}: request_login_failed"}


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


def probe_vm(session: requests.Session | CurlReadOnlyTransport, args: argparse.Namespace, vmid: str) -> dict[str, Any]:
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
