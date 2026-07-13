#!/usr/bin/env python3
"""Parallel lab reestablishment probe launcher.

This launcher fans out independent, bounded probes and writes one coordination
artifact. It is intentionally conservative: Windows QGA guest execution is
opt-in because a wedged guest-exec channel should not be hammered repeatedly.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "lab-reestablishment-parallel-probe"


def load_dotenv(path: Path = ROOT / ".env") -> None:
    if os.getenv("TAMANDUA_SKIP_DOTENV"):
        return
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


def isolate_lab_network_env() -> None:
    hosts = [
        "127.0.0.1",
        "localhost",
        "192.168.12.146",
        "192.168.12.149",
        os.getenv("TAMANDUA_PROXMOX_HOST", ""),
    ]
    existing = []
    for name in ("NO_PROXY", "no_proxy"):
        value = os.environ.get(name)
        if value:
            existing.extend(item.strip() for item in value.split(",") if item.strip())
    merged = []
    for value in [*existing, *hosts]:
        if value and value not in merged:
            merged.append(value)
    no_proxy = ",".join(merged)
    os.environ["NO_PROXY"] = no_proxy
    os.environ["no_proxy"] = no_proxy


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compact_stamp(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace(".", "")[:15] + "Z"


def run_command(name: str, command: list[str], timeout_seconds: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=os.environ.copy(),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "name": name,
            "command": command,
            "exit_code": completed.returncode,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
            "ok": completed.returncode == 0,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "command": command,
            "exit_code": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "stdout_tail": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
            "stderr_tail": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
            "ok": False,
            "error": "timeout",
        }
    except OSError as exc:
        return {
            "name": name,
            "command": command,
            "exit_code": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "stdout_tail": "",
            "stderr_tail": "",
            "ok": False,
            "error": str(exc),
        }


def build_jobs(args: argparse.Namespace) -> list[tuple[str, list[str], int]]:
    python = sys.executable
    jobs: list[tuple[str, list[str], int]] = [
        (
            "proxmox_host_readiness",
            [
                python,
                "tools/detection_validation/scripts/proxmox_virtualization_host_readiness_probe.py",
                "--output-dir",
                str(args.output_dir / "proxmox_host_readiness"),
            ],
            args.host_timeout_seconds,
        ),
        (
            "windows_proxmox_readiness_matrix",
            [
                python,
                "tools/detection_validation/scripts/lab_windows_proxmox_readiness_matrix_probe.py",
                "--server",
                args.server,
                "--vmids",
                *[str(vmid) for vmid in args.windows_vmids],
                "--expected-hostnames",
                *args.windows_target_hostnames,
                "--output-dir",
                str(args.output_dir / "windows_proxmox_readiness_matrix"),
            ],
            args.matrix_timeout_seconds,
        ),
        (
            "linux_ebpf_readiness",
            [
                python,
                "tools/detection_validation/scripts/linux_ebpf_readiness_probe.py",
                "--output-dir",
                str(args.output_dir / "linux_ebpf_readiness"),
            ],
            args.linux_timeout_seconds,
        ),
    ]
    for hostname in args.windows_target_hostnames:
        jobs.append(
            (
                f"windows_backend_readiness_{hostname.lower()}",
                [
                    python,
                    "tools/detection_validation/scripts/windows_lab_execution_readiness_probe.py",
                    "--server",
                    args.server,
                    "--target-hostname",
                    hostname,
                    "--output-dir",
                    str(args.output_dir / f"windows_backend_readiness_{hostname.lower()}"),
                ],
                args.backend_timeout_seconds,
            )
        )
    if args.include_windows_qga_exec:
        for vmid in args.windows_vmids:
            jobs.append(
                (
                    f"windows_qga_exec_{vmid}",
                    [
                        python,
                        "tools/detection_validation/scripts/windows_proxmox_qga_readiness_probe.py",
                        "--vmid",
                        str(vmid),
                        "--qga-retry-attempts",
                        "1",
                        "--qga-exec-start-attempts",
                        "1",
                        "--guest-exec-timeout-seconds",
                        str(args.qga_guest_exec_timeout_seconds),
                        "--output-dir",
                        str(args.output_dir / f"windows_qga_exec_{vmid}"),
                    ],
                    args.qga_probe_timeout_seconds,
                )
            )
    return jobs


def parse_args() -> argparse.Namespace:
    load_dotenv()
    isolate_lab_network_env()
    parser = argparse.ArgumentParser(description="Parallel lab reestablishment probe launcher")
    parser.add_argument("--server", default=os.getenv("TAMANDUA_SERVER_URL", "http://192.168.12.146:4000"))
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--host-timeout-seconds", type=int, default=120)
    parser.add_argument("--backend-timeout-seconds", type=int, default=90)
    parser.add_argument("--linux-timeout-seconds", type=int, default=60)
    parser.add_argument("--qga-probe-timeout-seconds", type=int, default=90)
    parser.add_argument("--matrix-timeout-seconds", type=int, default=180)
    parser.add_argument("--qga-guest-exec-timeout-seconds", type=int, default=10)
    parser.add_argument("--windows-vmids", type=int, nargs="+", default=[1520, 1521])
    parser.add_argument("--windows-target-hostnames", nargs="+", default=["LAB-DC01", "LAB-WS01"])
    parser.add_argument(
        "--include-windows-qga-exec",
        action="store_true",
        help="Opt in to bounded Windows QGA guest-exec probes. Avoid this when guest-exec is already wedged.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    jobs = build_jobs(args)
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(run_command, name, command, timeout): name
            for name, command, timeout in jobs
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    finished_at = utc_now()
    results.sort(key=lambda item: item["name"])
    report = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "run_id": f"{compact_stamp(started_at)}-{PROFILE_ID}",
        "started_at": started_at,
        "finished_at": finished_at,
        "claim_boundary": "Lab coordination artifact only. It fans out readiness probes and does not prove product readiness.",
        "include_windows_qga_exec": bool(args.include_windows_qga_exec),
        "results": results,
        "ok": all(item["ok"] for item in results),
    }
    json_path = args.output_dir / f"{report['run_id']}.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"lab_reestablishment_parallel_probe={'ok' if report['ok'] else 'blocked'} json={json_path}")
    for item in results:
        status = "ok" if item["ok"] else "blocked"
        print(f"{item['name']}={status} exit_code={item['exit_code']} duration_ms={item['duration_ms']}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
