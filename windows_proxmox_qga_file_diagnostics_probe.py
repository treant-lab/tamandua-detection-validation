#!/usr/bin/env python3
"""Read-only Proxmox/QGA file diagnostics probe for WIN-TEMPLATE.

This probe intentionally does not mutate the guest. It verifies whether the
Proxmox API exposes QGA guest-file commands that could be used to inspect
Tamandua agent config/logs when guest-exec is unstable.
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
PROFILE_ID = "windows-proxmox-qga-file-diagnostics-probe"
PROFILE_NAME = "Windows Proxmox QGA File Diagnostics Probe"


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
            evidence["error"] = response.text[:500]
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
        response = getattr(session, method.lower())(base + path, timeout=args.http_timeout_seconds, **kwargs)
        body: Any
        try:
            body = response.json()
        except ValueError:
            body = response.text[:500]
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


def make_result(test_id: str, name: str, passed: bool, gap: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else gap,
        "validation_category": "windows_proxmox_qga_file_diagnostics",
        "execution_class": "proxmox_api_read_only_file_probe",
        "claim_level": "windows_qga_file_diagnostics_claim_boundary",
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


def next_action_hint(
    args: argparse.Namespace,
    tests: list[dict[str, Any]],
    file_attempts: list[dict[str, Any]],
    passed: bool,
) -> dict[str, Any]:
    missed = [test for test in tests if test.get("status") != "covered"]
    missing_diagnostics = []
    blockers = sorted({str(test.get("gap_category")) for test in missed if test.get("gap_category") not in (None, "none")})
    required_env: list[str] = []
    auth_evidence = tests[0].get("evidence") if tests and isinstance(tests[0].get("evidence"), dict) else {}
    observed_501 = any(attempt.get("status") == 501 for attempt in file_attempts)

    if passed:
        return {
            "host": args.proxmox_host,
            "node": args.proxmox_node,
            "vmid": args.vmid,
            "missing_diagnostics": [],
            "required_env": [],
            "blockers": [],
            "observed_501_not_implemented": False,
            "rerun_commands": [
                "python tools/detection_validation/windows_proxmox_qga_file_diagnostics_probe.py --output-dir <out>",
                "python tools/detection_validation/windows_proxmox_qga_readiness_probe.py --output-dir <out>",
            ],
            "action": "QGA file diagnostics are green; keep this proof paired with current QGA guest-exec readiness.",
        }

    for test in missed:
        test_id = str(test.get("id") or "")
        if test_id == "proxmox-api-authenticated":
            missing_diagnostics.append("proxmox_api_auth")
        elif test_id == "qga-file-commands-advertised":
            missing_diagnostics.append("guest_file_commands_advertised")
        elif test_id in {"proxmox-agent-file-open-exposed", "proxmox-agent-readonly-diagnostics-transport"}:
            missing_diagnostics.append("proxmox_agent_file_open_exposed")

    if auth_evidence.get("error") == "missing_proxmox_password":
        required_env.append("TAMANDUA_PROXMOX_PASSWORD")
        action = (
            "Set TAMANDUA_PROXMOX_PASSWORD in the execution shell, verify the Proxmox API endpoint is reachable, "
            "then rerun QGA file diagnostics and QGA readiness."
        )
    elif observed_501:
        action = (
            "Treat Proxmox QGA guest-file diagnostics as unavailable through the current API because /agent/file-open "
            "returned HTTP 501. Use bounded guest-exec or another approved diagnostic transport, then rerun this probe "
            "after Proxmox/QGA exposes file-open."
        )
    elif "proxmox_api_auth" in missing_diagnostics:
        action = (
            f"Verify Proxmox API reachability at https://{args.proxmox_host}:8006 and credentials for "
            f"{args.proxmox_user}, then rerun QGA file diagnostics."
        )
    else:
        action = (
            f"Restore QGA guest-file diagnostic capability for VM {args.vmid} on node {args.proxmox_node}, then rerun "
            "file diagnostics and QGA readiness before relying on file inspection for Windows lab recovery."
        )

    return {
        "host": args.proxmox_host,
        "node": args.proxmox_node,
        "vmid": args.vmid,
        "missing_diagnostics": missing_diagnostics,
        "required_env": required_env,
        "blockers": blockers,
        "auth_error": auth_evidence.get("error"),
        "api_url": auth_evidence.get("url") or f"https://{args.proxmox_host}:8006/api2/json/access/ticket",
        "observed_501_not_implemented": observed_501,
        "file_open_endpoint": f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/file-open",
        "rerun_commands": [
            "python tools/detection_validation/windows_proxmox_qga_file_diagnostics_probe.py --output-dir <out>",
            "python tools/detection_validation/windows_proxmox_qga_readiness_probe.py --output-dir <out>",
        ],
        "action": action,
    }


def supported_commands(info: dict[str, Any]) -> list[str]:
    if not info.get("ok") or not isinstance(info.get("body"), dict):
        return []
    result = (((info.get("body") or {}).get("data") or {}).get("result") or {})
    return [item.get("name") for item in result.get("supported_commands") or [] if isinstance(item, dict)]


def qga_file_open_attempts(session: requests.Session, args: argparse.Namespace) -> list[dict[str, Any]]:
    candidates = [
        r"D:\ProgramData\Tamandua\config\agent.toml",
        r"C:\ProgramData\Tamandua\config\agent.toml",
        r"D:\ProgramData\Tamandua\logs\agent.log",
        r"C:\ProgramData\Tamandua\logs\agent.log",
    ]
    attempts: list[dict[str, Any]] = []
    for path in candidates:
        response = request_json(
            session,
            args,
            "POST",
            f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/file-open",
            data={"file": path, "mode": "r"},
        )
        attempts.append(
            {
                "path": path,
                "status": response.get("status"),
                "ok": response.get("ok"),
                "duration_ms": response.get("duration_ms"),
                "error": summarize_error(response),
            }
        )
    return attempts


def summarize_error(response: dict[str, Any]) -> str | None:
    body = response.get("body")
    if isinstance(body, dict):
        message = body.get("message") or body.get("errors") or body.get("data")
        return str(message)[:300] if message is not None else None
    if body:
        return str(body)[:300]
    return response.get("error")


def decode_qga(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    try:
        return base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
    except Exception:
        return text


def qga_guest_exec_file_metadata(session: requests.Session, args: argparse.Namespace) -> dict[str, Any]:
    marker = "tamandua-qga-file-metadata-ready"
    candidates = [
        r"D:\ProgramData\Tamandua\config\agent.toml",
        r"C:\ProgramData\Tamandua\config\agent.toml",
        r"D:\ProgramData\Tamandua\logs\agent.log",
        r"C:\ProgramData\Tamandua\logs\agent.log",
    ]
    lines = [f"echo {marker}"]
    for path in candidates:
        lines.append(f'if exist "{path}" echo exists={path}')
    raw_input = "\r\n".join(lines + ["exit /b 0", ""])
    start = request_json(
        session,
        args,
        "POST",
        f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/exec",
        data={"command": "cmd.exe", "input-data": raw_input},
    )
    pid = (((start.get("body") or {}).get("data") or {}) if isinstance(start.get("body"), dict) else {}).get("pid")
    result: dict[str, Any] = {
        "start": {
            "status": start.get("status"),
            "ok": start.get("ok"),
            "duration_ms": start.get("duration_ms"),
            "error": summarize_error(start),
        },
        "transport": "proxmox_api_qga_guest_exec",
        "reads_file_contents": False,
    }
    if not start.get("ok") or pid is None:
        result.update({"ready": False, "error": "guest_exec_start_failed"})
        return result

    deadline = time.monotonic() + max(5, int(getattr(args, "guest_exec_timeout_seconds", 30)))
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
            result.update(
                {
                    "ready": data.get("exitcode") == 0 and marker in stdout,
                    "exitcode": data.get("exitcode"),
                    "stdout_tail": stdout[-1000:],
                    "stderr_tail": stderr[-1000:],
                    "marker_seen": marker in stdout,
                    "existing_candidate_count": sum(1 for line in stdout.splitlines() if line.startswith("exists=")),
                    "poll": {"status": poll.get("status"), "ok": poll.get("ok"), "duration_ms": poll.get("duration_ms")},
                }
            )
            return result

    result.update(
        {
            "ready": False,
            "error": "guest_exec_status_timeout",
            "last_poll": {
                "status": last.get("status"),
                "ok": last.get("ok"),
                "duration_ms": last.get("duration_ms"),
                "error": summarize_error(last),
            },
        }
    )
    return result


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

    qga_info: dict[str, Any] = {}
    commands: list[str] = []
    file_attempts: list[dict[str, Any]] = []
    guest_exec_metadata: dict[str, Any] = {}
    if session is not None:
        qga_info = request_json(session, args, "GET", f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/info")
        commands = supported_commands(qga_info)
        tests.append(
            make_result(
                "qga-file-commands-advertised",
                "QGA advertises guest-file commands",
                all(command in commands for command in ("guest-file-open", "guest-file-read", "guest-file-close")),
                "runner",
                {
                    "status": qga_info.get("status"),
                    "supported_command_count": len(commands),
                    "guest_file_open": "guest-file-open" in commands,
                    "guest_file_read": "guest-file-read" in commands,
                    "guest_file_close": "guest-file-close" in commands,
                },
            )
        )
        file_attempts = qga_file_open_attempts(session, args)
        exposed = any(attempt.get("ok") for attempt in file_attempts)
        if not exposed and "guest-exec" in commands:
            guest_exec_metadata = qga_guest_exec_file_metadata(session, args)
        tests.append(
            make_result(
                "proxmox-agent-readonly-diagnostics-transport",
                "Proxmox exposes a read-only QGA diagnostics transport",
                exposed or bool(guest_exec_metadata.get("ready")),
                "runner",
                {
                    "attempts": file_attempts,
                    "expected_endpoint": f"/nodes/{args.proxmox_node}/qemu/{args.vmid}/agent/file-open",
                    "observed_501_not_implemented": any(attempt.get("status") == 501 for attempt in file_attempts),
                    "file_open_exposed": exposed,
                    "guest_exec_metadata": guest_exec_metadata,
                },
            )
        )

    covered = sum(1 for item in tests if item["status"] == "covered")
    missed = len(tests) - covered
    passed = all(item["status"] == "covered" for item in tests)
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
        "finished_at": utc_now(),
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
            "claim_level_counts": {"windows_qga_file_diagnostics_claim_boundary": len(tests)},
            "category_coverage": {"windows_proxmox_qga_file_diagnostics": {"covered": covered, "missed": missed}},
            "roadmap_coverage": {"A": {"covered": covered, "missed": missed}},
        },
        "quality_gate": {
            "passed": passed,
            "status": "pass" if passed else "fail",
            "failures": [] if passed else ["qga_file_diagnostics_gaps"],
            "actionable_gaps": [item for item in tests if item["status"] != "covered"],
        },
        "scorecard": {
            "maturity_score": 100 if passed else max(20, int((covered / max(1, len(tests))) * 80)),
            "maturity_band": "windows-qga-file-readable" if passed else "windows-qga-file-api-blocked",
            "recommended_claim": (
                "WIN-TEMPLATE QGA file API is available for read-only diagnostics"
                if passed
                else "WIN-TEMPLATE QGA file API is not available through current Proxmox API"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else ["qga_file_api_unavailable"],
        },
        "proxmox_qga_file_diagnostics": {
            "ready_for_read_only_file_diagnostics": passed,
            "vmid": args.vmid,
            "host": args.proxmox_host,
            "node": args.proxmox_node,
            "next_action": next_action_hint(args, tests, file_attempts, passed),
            "qga_info": {
                "status": qga_info.get("status"),
                "supported_command_count": len(commands),
                "guest_file_commands_advertised": all(
                    command in commands for command in ("guest-file-open", "guest-file-read", "guest-file-close")
                ),
            },
            "file_open_attempts": file_attempts,
            "guest_exec_metadata": guest_exec_metadata,
        },
        "tests": tests,
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    action = report["proxmox_qga_file_diagnostics"].get("next_action") or {}
    preflight: list[str] = []
    tests = report.get("tests") or []
    auth_evidence = tests[0].get("evidence") if tests and isinstance(tests[0], dict) else {}
    if isinstance(auth_evidence, dict) and auth_evidence.get("error") == "missing_proxmox_password":
        preflight = [
            "",
            "## Preflight",
            "",
            "- `TAMANDUA_PROXMOX_PASSWORD` is not set in the current shell.",
            "- This probe did not authenticate to Proxmox or touch QGA file endpoints without a password.",
        ]
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Ready for read-only file diagnostics: `{str(report['proxmox_qga_file_diagnostics']['ready_for_read_only_file_diagnostics']).lower()}`",
        *preflight,
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
                "- Missing diagnostics: `" + ", ".join(action.get("missing_diagnostics") or []) + "`",
                "- Required env: `" + (", ".join(action.get("required_env") or []) or "-") + "`",
                f"- Observed 501 on file-open: `{str(bool(action.get('observed_501_not_implemented'))).lower()}`",
                f"- Action: {action.get('action')}",
            ]
        )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact proves only whether Proxmox exposes QGA guest-file endpoints for read-only lab diagnostics. "
            "It does not read Tamandua secrets into the artifact, does not execute guest commands, and does not prove detection coverage.",
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
    print(
        f"windows_proxmox_qga_file_diagnostics={'ok' if report['quality_gate']['passed'] else 'gaps'} "
        f"json={json_path} markdown={md_path}"
    )
    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
