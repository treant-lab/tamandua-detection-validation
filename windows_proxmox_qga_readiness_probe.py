#!/usr/bin/env python3
"""Roadmap A Proxmox/QGA execution readiness probe.

This probe checks whether the WIN-TEMPLATE lab VM can be used as a bounded
execution transport. It does not restart the VM, mutate Tamandua server state,
or run attack workloads. The only guest command is a short `cmd.exe` echo.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3


urllib3.disable_warnings()

try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "windows-proxmox-qga-readiness-probe"
PROFILE_NAME = "Windows Proxmox QGA Readiness Probe"


def load_dotenv(path: Path = ROOT / ".env") -> None:
    if not path.exists():
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
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
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


def decode_qga(value: str | None) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value).decode(errors="replace")
    except Exception:
        return str(value)


def login(args: argparse.Namespace) -> tuple[requests.Session | None, dict[str, Any]]:
    session = requests.Session()
    session.verify = False
    session.trust_env = False
    base = f"https://{args.proxmox_host}:8006/api2/json"
    if not args.proxmox_password:
        return None, {
            "url": f"{base}/access/ticket",
            "status": None,
            "duration_ms": 0,
            "authenticated": False,
            "error": "missing_proxmox_password",
            "password_supplied": False,
            "required_env": "TAMANDUA_PROXMOX_PASSWORD",
        }
    started = time.monotonic()
    try:
        response = session.post(
            f"{base}/access/ticket",
            data={"username": args.proxmox_user, "password": args.proxmox_password},
            timeout=args.http_timeout_seconds,
        )
        evidence = {
            "url": f"{base}/access/ticket",
            "status": response.status_code,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        if not response.ok:
            evidence["error"] = response.text[:1000]
            return None, evidence
        auth = response.json().get("data") or {}
        if not auth.get("ticket") or not auth.get("CSRFPreventionToken"):
            evidence["error"] = "missing_ticket_or_csrf"
            return None, evidence
        session.cookies.set("PVEAuthCookie", auth["ticket"])
        session.headers.update({"CSRFPreventionToken": auth["CSRFPreventionToken"]})
        evidence["authenticated"] = True
        return session, evidence
    except Exception as exc:
        return None, {
            "url": f"{base}/access/ticket",
            "status": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def request_json(session: requests.Session, args: argparse.Namespace, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    base = f"https://{args.proxmox_host}:8006/api2/json"
    started = time.monotonic()
    try:
        if method == "POST":
            response = session.post(base + path, timeout=args.http_timeout_seconds, **kwargs)
        else:
            response = session.get(base + path, timeout=args.http_timeout_seconds, **kwargs)
        body: Any = {}
        try:
            body = response.json()
        except ValueError:
            body = response.text[:1000]
        return {
            "method": method,
            "path": path,
            "status": response.status_code,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "body": body,
            "ok": response.ok,
        }
    except Exception as exc:
        return {
            "method": method,
            "path": path,
            "status": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
            "ok": False,
        }


def request_json_retry(
    session: requests.Session,
    args: argparse.Namespace,
    method: str,
    path: str,
    max_attempts_override: int | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    max_attempts = max(1, max_attempts_override or args.qga_retry_attempts)
    for attempt in range(1, max_attempts + 1):
        result = request_json(session, args, method, path, **kwargs)
        result["attempt"] = attempt
        attempts.append(result)
        status = result.get("status")
        if result.get("ok") or (isinstance(status, int) and status < 500):
            break
        if attempt < max_attempts:
            time.sleep(max(0.0, args.qga_retry_sleep_seconds))

    final = dict(attempts[-1])
    final["attempts"] = attempts
    final["attempt_count"] = len(attempts)
    final["retried"] = len(attempts) > 1
    return final


def qga_start_variants() -> list[tuple[str, Any]]:
    marker = "tamandua-qga-ready"
    raw_input = f"echo {marker}\r\nexit /b 0\r\n"
    return [
        (
            "stdin_raw_cmd",
            {
                "command": "cmd.exe",
                "input-data": raw_input,
            },
        ),
        (
            "args_repeated_cmd",
            [
                ("command", "cmd.exe"),
                ("command", "/d"),
                ("command", "/c"),
                ("command", f"echo {marker}"),
            ],
        ),
    ]


def qga_guest_exec(session: requests.Session, args: argparse.Namespace) -> dict[str, Any]:
    variants: list[dict[str, Any]] = []
    chosen: dict[str, Any] | None = None
    pid: Any = None
    for index, (variant_name, data) in enumerate(qga_start_variants()):
        start = request_json_retry(
            session,
            args,
            "POST",
            f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/exec",
            max_attempts_override=args.qga_exec_start_attempts if index == 0 else 1,
            data=data,
        )
        variant = {"variant": variant_name, "start": start}
        variants.append(variant)
        pid = (((start.get("body") or {}).get("data") or {}) if isinstance(start.get("body"), dict) else {}).get("pid")
        if start.get("ok") and pid is not None:
            chosen = variant
            break

    result: dict[str, Any] = {
        "start": chosen["start"] if chosen else (variants[-1]["start"] if variants else {}),
        "start_variants": variants,
        "successful_start_variant": chosen["variant"] if chosen else None,
        "transport": "proxmox_api_qga",
    }
    if chosen is None or pid is None:
        result["ready"] = False
        result["error"] = "guest_exec_start_failed"
        return result

    deadline = time.monotonic() + max(5, args.guest_exec_timeout_seconds)
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        time.sleep(1)
        poll = request_json(
            session,
            args,
            "GET",
            f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/exec-status",
            params={"pid": pid},
        )
        last = poll
        data = ((poll.get("body") or {}).get("data") or {}) if isinstance(poll.get("body"), dict) else {}
        if data.get("exited"):
            stdout = decode_qga(data.get("out-data"))
            stderr = decode_qga(data.get("err-data"))
            ready = data.get("exitcode") == 0
            if stdout:
                ready = ready and "tamandua-qga-ready" in stdout
            result.update(
                {
                    "ready": ready,
                    "exitcode": data.get("exitcode"),
                    "stdout": stdout[-1000:],
                    "stderr": stderr[-1000:],
                    "stdout_required": bool(stdout),
                    "poll": poll,
                }
            )
            return result

    result.update({"ready": False, "error": "guest_exec_status_timeout", "last_poll": last})
    return result


def has_permission(permissions: dict[str, Any], permission: str, paths: list[str]) -> bool:
    data = permissions.get("body", {}).get("data") if isinstance(permissions.get("body"), dict) else {}
    if not isinstance(data, dict):
        return False
    for path in paths:
        values = data.get(path)
        if isinstance(values, dict) and int(values.get(permission) or 0) == 1:
            return True
    return False


def make_result(test_id: str, name: str, passed: bool, gap: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else gap,
        "validation_category": "windows_proxmox_qga_readiness",
        "execution_class": "proxmox_api_readiness_probe",
        "claim_level": "windows_qga_readiness_claim_boundary",
        "executor_used": PROFILE_ID,
        "fallback_used": False,
        "upstream_backed": False,
        "evidence": evidence,
        "missing_expected_fields": [] if passed else [gap],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def next_action_hint(args: argparse.Namespace, tests: list[dict[str, Any]], passed: bool) -> dict[str, Any]:
    missed = [test for test in tests if test.get("status") != "covered"]
    missing_readiness = []
    blockers = sorted({str(test.get("gap_category")) for test in missed if test.get("gap_category") not in (None, "none")})
    required_env: list[str] = []
    auth_evidence = tests[0].get("evidence") if tests and isinstance(tests[0].get("evidence"), dict) else {}

    if passed:
        return {
            "host": args.proxmox_host,
            "node": args.proxmox_node,
            "vmid": args.vmid,
            "missing_readiness": [],
            "required_env": [],
            "blockers": [],
            "rerun_commands": [
                "python tools/detection_validation/windows_proxmox_qga_readiness_probe.py --output-dir <out>",
                "python tools/detection_validation/windows_proxmox_qga_file_diagnostics_probe.py --output-dir <out>",
            ],
            "action": "QGA readiness is green; keep the file diagnostics probe current before using QGA as a broad Windows execution transport.",
        }

    for test in missed:
        test_id = str(test.get("id") or "")
        if test_id == "proxmox-api-authenticated":
            missing_readiness.append("proxmox_api_auth")
        elif test_id == "proxmox-api-vm-monitor-permission":
            missing_readiness.append("vm_monitor_permission")
        elif test_id == "proxmox-vm-running":
            missing_readiness.append("vm_running_with_qga_enabled")
        elif test_id == "proxmox-qga-ping":
            missing_readiness.append("qga_ping")
        elif test_id == "proxmox-qga-readonly-hostname":
            missing_readiness.append("qga_readonly_hostname")
        elif test_id == "proxmox-qga-guest-exec-supported":
            missing_readiness.append("guest_exec_supported")
        elif test_id == "proxmox-qga-bounded-guest-exec":
            missing_readiness.append("bounded_guest_exec")

    if auth_evidence.get("error") == "missing_proxmox_password":
        required_env.append("TAMANDUA_PROXMOX_PASSWORD")
        action = (
            "Set TAMANDUA_PROXMOX_PASSWORD in the execution shell, verify the Proxmox API endpoint is reachable, "
            "then rerun QGA readiness and QGA file diagnostics before scheduling Windows broad or P1/P2 reruns."
        )
    elif "proxmox_api_auth" in missing_readiness:
        action = (
            f"Verify Proxmox API reachability at https://{args.proxmox_host}:8006 and the credentials for "
            f"{args.proxmox_user}, then rerun QGA readiness and QGA file diagnostics."
        )
    else:
        action = (
            f"Restore QGA readiness for VM {args.vmid} on node {args.proxmox_node}, then rerun readiness and file "
            "diagnostics until guest-exec and the bounded execution marker are green."
        )

    return {
        "host": args.proxmox_host,
        "node": args.proxmox_node,
        "vmid": args.vmid,
        "missing_readiness": missing_readiness,
        "required_env": required_env,
        "blockers": blockers,
        "auth_error": auth_evidence.get("error"),
        "api_url": auth_evidence.get("url") or f"https://{args.proxmox_host}:8006/api2/json/access/ticket",
        "rerun_commands": [
            "python tools/detection_validation/windows_proxmox_qga_readiness_probe.py --output-dir <out>",
            "python tools/detection_validation/windows_proxmox_qga_file_diagnostics_probe.py --output-dir <out>",
        ],
        "action": action,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now()
    session, auth = login(args)
    tests: list[dict[str, Any]] = [
        make_result(
            "proxmox-api-authenticated",
            "Proxmox API accepts configured credentials",
            session is not None and bool(auth.get("authenticated")),
            "infra",
            auth,
        )
    ]

    vm_status: dict[str, Any] = {}
    permissions: dict[str, Any] = {}
    qga_ping: dict[str, Any] = {}
    qga_hostname: dict[str, Any] = {}
    qga_info: dict[str, Any] = {}
    qga_exec: dict[str, Any] = {}
    if session is not None:
        permissions = request_json_retry(session, args, "GET", "/access/permissions")
        tests.append(
            make_result(
                "proxmox-api-vm-monitor-permission",
                "Configured Proxmox user has VM.Monitor permission for agent commands",
                bool(permissions.get("ok")) and has_permission(permissions, "VM.Monitor", ["/vms", "/", f"/vms/{args.vmid}"]),
                "infra",
                {
                    "permission": "VM.Monitor",
                    "paths_checked": ["/vms", "/", f"/vms/{args.vmid}"],
                    "status": permissions.get("status"),
                    "ok": permissions.get("ok"),
                    "present": has_permission(permissions, "VM.Monitor", ["/vms", "/", f"/vms/{args.vmid}"]),
                },
            )
        )
        vm_status = request_json_retry(session, args, "GET", f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/status/current")
        vm_data = (vm_status.get("body") or {}).get("data") if isinstance(vm_status.get("body"), dict) else {}
        tests.append(
            make_result(
                "proxmox-vm-running",
                "WIN-TEMPLATE VM is running and has QGA enabled",
                vm_status.get("ok") and vm_data.get("status") == "running" and int(vm_data.get("agent") or 0) == 1,
                "infra",
                {"vmid": args.vmid, "status_response": vm_status},
            )
        )
        qga_ping = request_json_retry(session, args, "POST", f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/ping")
        tests.append(
            make_result(
                "proxmox-qga-ping",
                "QEMU Guest Agent ping succeeds",
                bool(qga_ping.get("ok")),
                "runner",
                qga_ping,
            )
        )
        qga_hostname = request_json_retry(session, args, "GET", f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/get-host-name")
        hostname = ""
        if qga_hostname.get("ok") and isinstance(qga_hostname.get("body"), dict):
            data = (qga_hostname.get("body") or {}).get("data") or {}
            result = data.get("result") if isinstance(data, dict) else {}
            if isinstance(result, dict):
                hostname = str(result.get("host-name") or result.get("hostname") or "")
        tests.append(
            make_result(
                "proxmox-qga-readonly-hostname",
                "QEMU Guest Agent can answer a read-only hostname query",
                bool(qga_hostname.get("ok")) and bool(hostname),
                "runner",
                {"hostname_response": qga_hostname, "hostname": hostname},
            )
        )
        qga_info = request_json_retry(session, args, "GET", f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/info")
        commands = []
        if qga_info.get("ok") and isinstance(qga_info.get("body"), dict):
            result = (((qga_info.get("body") or {}).get("data") or {}).get("result") or {})
            commands = [item.get("name") for item in result.get("supported_commands") or [] if isinstance(item, dict)]
        tests.append(
            make_result(
                "proxmox-qga-guest-exec-supported",
                "QEMU Guest Agent reports guest-exec support",
                qga_info.get("ok") and "guest-exec" in commands,
                "runner",
                {"info_response": qga_info, "supported_command_count": len(commands), "guest_exec_supported": "guest-exec" in commands},
            )
        )
        qga_exec = qga_guest_exec(session, args)
        tests.append(
            make_result(
                "proxmox-qga-bounded-guest-exec",
                "QGA can execute a bounded benign command",
                bool(qga_exec.get("ready")),
                "runner",
                qga_exec,
            )
        )

    passed = all(item["status"] == "covered" for item in tests)
    covered = sum(1 for item in tests if item["status"] == "covered")
    missed = len(tests) - covered
    finished = utc_now()
    run_id_value = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"
    return {
        "schema_version": 1,
        "run_id": run_id_value,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "name": PROFILE_NAME,
        "mode": "execute",
        "benchmark_lane": "claim-boundary",
        "started_at": started,
        "finished_at": finished,
        "git": git_snapshot(),
        "summary": {
            "tests": len(tests),
            "covered": covered,
            "missed": missed,
            "partial": 0,
            "execution_failed": 0,
            "unknown_source_events": 0,
            "unexpected_high_or_critical_events": 0,
            "unexpected_high_or_critical_alerts": 0,
            "missing_expected_fields": sum(len(item.get("missing_expected_fields") or []) for item in tests),
            "gap_category_counts": {
                category: sum(1 for item in tests if item["gap_category"] == category)
                for category in sorted({item["gap_category"] for item in tests if item["gap_category"] != "none"})
            },
            "executor_counts": {PROFILE_ID: len(tests)},
            "claim_level_counts": {"windows_qga_readiness_claim_boundary": len(tests)},
            "category_coverage": {"windows_proxmox_qga_readiness": {"covered": covered, "missed": missed}},
            "roadmap_coverage": {"A": {"covered": covered, "missed": missed}},
        },
        "quality_gate": {
            "passed": passed,
            "status": "pass" if passed else "fail",
            "failures": [] if passed else ["windows_proxmox_qga_readiness_gaps"],
            "actionable_gaps": [item for item in tests if item["status"] != "covered"],
        },
        "scorecard": {
            "maturity_score": 100 if passed else max(20, int((covered / max(1, len(tests))) * 80)),
            "maturity_band": "windows-qga-ready" if passed else "windows-qga-blocked",
            "recommended_claim": (
                "WIN-TEMPLATE QGA can execute bounded commands"
                if passed
                else "WIN-TEMPLATE QGA is not ready for benchmark execution"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else ["windows_proxmox_qga_readiness_missing"],
            "covered_rate": covered / max(1, len(tests)),
            "telemetry_rate": 1.0,
            "field_quality": 1.0 if passed else 0.0,
            "context_quality": 1.0 if passed else 0.0,
            "analytic_quality": 1.0,
            "noise_quality": 1.0,
            "driver_quality": 1.0,
            "upstream_rate": 0.0,
        },
        "proxmox_qga_readiness": {
            "ready_for_bounded_execution": passed,
            "vmid": args.vmid,
            "host": args.proxmox_host,
            "node": args.proxmox_node,
            "next_action": next_action_hint(args, tests, passed),
            "permissions": permissions,
            "vm_status": vm_status,
            "qga_ping": qga_ping,
            "qga_hostname": qga_hostname,
            "qga_info": qga_info,
            "qga_exec": qga_exec,
        },
        "tests": tests,
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    action = report["proxmox_qga_readiness"].get("next_action") or {}
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Ready for bounded execution: `{str(report['proxmox_qga_readiness']['ready_for_bounded_execution']).lower()}`",
        "",
        "## Results",
        "",
        "| Test | Status | Gap |",
        "|------|--------|-----|",
    ]
    for item in report["tests"]:
        lines.append(f"| `{item['id']}` | `{item['status']}` | `{item.get('gap_category') or 'none'}` |")
    if action:
        lines.extend(
            [
                "",
                "## Next Action",
                "",
                f"- Target: `{action.get('host')}` node `{action.get('node')}` VM `{action.get('vmid')}`",
                "- Missing readiness: `" + ", ".join(action.get("missing_readiness") or []) + "`",
                "- Required env: `" + (", ".join(action.get("required_env") or []) or "-") + "`",
                f"- Action: {action.get('action')}",
            ]
        )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact proves only Proxmox/QGA readiness for bounded lab execution. "
            "It does not run attack workloads, does not restart the VM, does not mutate the Tamandua server, "
            "and does not prove detection coverage.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    load_dotenv()
    parser = argparse.ArgumentParser(description=PROFILE_NAME)
    parser.add_argument("--proxmox-host", default=os.getenv("TAMANDUA_PROXMOX_HOST", "192.168.12.149"))
    parser.add_argument("--proxmox-user", default=os.getenv("TAMANDUA_PROXMOX_USER", "root@pam"))
    parser.add_argument("--proxmox-password", default=os.getenv("TAMANDUA_PROXMOX_PASSWORD"))
    parser.add_argument("--proxmox-node", default=os.getenv("TAMANDUA_PROXMOX_NODE", "Default"))
    parser.add_argument("--vmid", type=int, default=int(os.getenv("TAMANDUA_WINDOWS_VMID", "1521")))
    parser.add_argument("--http-timeout-seconds", type=int, default=int(os.getenv("TAMANDUA_PROXMOX_HTTP_TIMEOUT_SECONDS", "20")))
    parser.add_argument("--guest-exec-timeout-seconds", type=int, default=int(os.getenv("TAMANDUA_QGA_GUEST_EXEC_TIMEOUT_SECONDS", "30")))
    parser.add_argument("--qga-retry-attempts", type=int, default=int(os.getenv("TAMANDUA_QGA_RETRY_ATTEMPTS", "2")))
    parser.add_argument(
        "--qga-exec-start-attempts",
        type=int,
        default=int(os.getenv("TAMANDUA_QGA_EXEC_START_ATTEMPTS", "5")),
    )
    parser.add_argument(
        "--qga-retry-sleep-seconds",
        type=float,
        default=float(os.getenv("TAMANDUA_QGA_RETRY_SLEEP_SECONDS", "2")),
    )
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id_value = report["run_id"]
    json_path = output_dir / f"{run_id_value}.json"
    comparison_path = output_dir / f"{run_id_value}.comparison.json"
    md_path = output_dir / f"{run_id_value}.md"
    payload = json.dumps(report, indent=2, sort_keys=True)
    json_path.write_text(payload, encoding="utf-8")
    comparison_path.write_text(payload, encoding="utf-8")
    write_markdown(report, md_path)
    print(f"windows_proxmox_qga_readiness={'ok' if report['quality_gate']['passed'] else 'gaps'} json={json_path} markdown={md_path}")
    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
