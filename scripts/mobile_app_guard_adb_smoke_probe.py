#!/usr/bin/env python3
"""Collect read-only Mobile App Guard smoke evidence from an installed APK.

This probe uses ADB only for low-impact observation: installed package metadata,
process/service state, current UI text, and optional bounded logcat grep. It
does not install, launch, stop, mutate app data, trigger attacks, or claim
shielding efficacy.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence


CommandRunner = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]

DEFAULT_UI_STRINGS = (
    "Tamandua",
    "App Guard",
    "Protected",
    "Shield",
    "Risk",
    "Device",
)

PRIVACY_EXCLUDED_FIELDS = (
    "raw_payload",
    "raw_body",
    "request_body",
    "response_body",
    "dom_snapshot",
    "page_content",
)


def run_command(args: Sequence[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )


def adb_prefix(adb: str, serial: str | None) -> list[str]:
    prefix = [adb]
    if serial:
        prefix.extend(["-s", serial])
    return prefix


def call_adb(
    runner: CommandRunner,
    adb: str,
    serial: str | None,
    command: Sequence[str],
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    return runner([*adb_prefix(adb, serial), *command], timeout_seconds)


def find_first(output: str, pattern: str) -> str | None:
    match = re.search(pattern, output)
    return match.group(1).strip() if match else None


def parse_package_dump(output: str, package_name: str) -> dict[str, object]:
    version_name = find_first(output, r"versionName=([^\s]+)")
    version_code = find_first(output, r"versionCode=(\d+)")
    first_install = find_first(output, r"firstInstallTime=([^\n\r]+)")
    last_update = find_first(output, r"lastUpdateTime=([^\n\r]+)")
    apk_paths = sorted(set(re.findall(r"(?:codePath|resourcePath)=([^\s]+)", output)))
    package_seen = f"Package [{package_name}]" in output or re.search(rf"\bpackageName={re.escape(package_name)}\b", output)

    return {
        "installed": bool(package_seen or version_name or version_code),
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "first_install_time": first_install,
        "last_update_time": last_update,
        "apk_paths": apk_paths,
    }


def parse_service_state(output: str, package_name: str) -> dict[str, object]:
    lines = [line.strip() for line in output.splitlines() if package_name in line or "foreground" in line.lower()]
    foreground_lines = [line for line in lines if "foreground=true" in line.lower() or "isforeground=true" in line.lower()]
    service_lines = [line for line in lines if "ServiceRecord" in line or package_name in line]
    return {
        "queried": True,
        "foreground_service_observed": bool(foreground_lines),
        "matching_lines": service_lines[:20],
        "foreground_lines": foreground_lines[:20],
    }


def parse_ui_dump(output: str, key_strings: Sequence[str]) -> dict[str, object]:
    matches: dict[str, int] = {}
    lowered = output.lower()
    for value in key_strings:
        count = lowered.count(value.lower())
        if count:
            matches[value] = count
    return {
        "collected": bool(output.strip()),
        "key_strings": list(key_strings),
        "matched_strings": matches,
        "contains_package_text": bool(matches),
        "bytes": len(output.encode("utf-8")),
    }


def grep_logcat(output: str, patterns: Sequence[str]) -> dict[str, object]:
    matched: list[dict[str, str]] = []
    for line in output.splitlines():
        for pattern in patterns:
            if pattern.lower() in line.lower():
                matched.append({"pattern": pattern, "line": line[:500]})
                break
        if len(matched) >= 50:
            break
    return {
        "collected": True,
        "patterns": list(patterns),
        "line_count_scanned": len(output.splitlines()),
        "matches": matched,
    }


def command_record(name: str, completed: subprocess.CompletedProcess[str]) -> dict[str, object]:
    return {
        "name": name,
        "returncode": completed.returncode,
        "stdout_bytes": len((completed.stdout or "").encode("utf-8")),
        "stderr_bytes": len((completed.stderr or "").encode("utf-8")),
    }


def collect_smoke_evidence(
    package_name: str,
    *,
    adb: str = "adb",
    serial: str | None = None,
    device_id: str | None = None,
    app_build_id: str | None = None,
    sdk_build_id: str | None = None,
    event_ids: Sequence[str] = (),
    server_request_ids: Sequence[str] = (),
    ui_strings: Sequence[str] = DEFAULT_UI_STRINGS,
    logcat_grep: Sequence[str] = (),
    timeout_seconds: int = 10,
    runner: CommandRunner = run_command,
) -> tuple[int, dict[str, object]]:
    commands: list[dict[str, object]] = []
    errors: list[str] = []

    package_dump = call_adb(runner, adb, serial, ["shell", "dumpsys", "package", package_name], timeout_seconds)
    commands.append(command_record("dumpsys_package", package_dump))
    package = parse_package_dump(package_dump.stdout or "", package_name)
    if package_dump.returncode != 0:
        errors.append(f"dumpsys package failed with exit {package_dump.returncode}")
    if not package["installed"]:
        errors.append(f"package {package_name} was not observed as installed")

    pidof = call_adb(runner, adb, serial, ["shell", "pidof", package_name], timeout_seconds)
    commands.append(command_record("pidof", pidof))
    process = {
        "running": pidof.returncode == 0 and bool((pidof.stdout or "").strip()),
        "pids": (pidof.stdout or "").split(),
    }

    services_dump = call_adb(runner, adb, serial, ["shell", "dumpsys", "activity", "services", package_name], timeout_seconds)
    commands.append(command_record("dumpsys_activity_services", services_dump))
    service_state = parse_service_state(services_dump.stdout or "", package_name)
    if services_dump.returncode != 0:
        errors.append(f"dumpsys activity services failed with exit {services_dump.returncode}")

    ui_dump_path = "/sdcard/tamandua_app_guard_smoke.xml"
    ui_dump = call_adb(runner, adb, serial, ["shell", "uiautomator", "dump", ui_dump_path], timeout_seconds)
    commands.append(command_record("uiautomator_dump", ui_dump))
    ui_dump_cat = call_adb(runner, adb, serial, ["shell", "cat", ui_dump_path], timeout_seconds)
    commands.append(command_record("uiautomator_dump_cat", ui_dump_cat))
    ui_state = parse_ui_dump(ui_dump_cat.stdout or "", ui_strings)
    if ui_dump.returncode != 0:
        errors.append(f"uiautomator dump failed with exit {ui_dump.returncode}")
    if ui_dump_cat.returncode != 0:
        errors.append(f"uiautomator dump cat failed with exit {ui_dump_cat.returncode}")

    logcat: dict[str, object] = {"collected": False, "patterns": list(logcat_grep), "matches": []}
    if logcat_grep:
        logcat_dump = call_adb(runner, adb, serial, ["logcat", "-d", "-t", "500"], timeout_seconds)
        commands.append(command_record("logcat_tail_grep", logcat_dump))
        if logcat_dump.returncode == 0:
            logcat = grep_logcat(logcat_dump.stdout or "", logcat_grep)
        else:
            errors.append(f"logcat grep failed with exit {logcat_dump.returncode}")

    report: dict[str, object] = {
        "evidence_class": "physical_device_smoke",
        "claim_status": "physical_device_smoke",
        "collected_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "read_only_low_impact": True,
        "package_name": package_name,
        "adb_serial": serial,
        "device_id": device_id,
        "app_build_id": app_build_id,
        "sdk_build_id": sdk_build_id,
        "event_ids": list(event_ids),
        "server_request_ids": list(server_request_ids),
        "package": package,
        "process": process,
        "foreground_service_state": service_state,
        "ui_dump_key_strings": ui_state,
        "logcat_grep": logcat,
        "commands": commands,
        "errors": errors,
        "failure_reasons": list(errors),
        "rollback": {
            "required": False,
            "performed": False,
            "reason": "read-only ADB smoke probe does not mutate app, device, or server state",
        },
        "privacy_boundary": {
            "metadata_only": True,
            "contains_pii": False,
            "excluded_fields": list(PRIVACY_EXCLUDED_FIELDS),
            "operator_review_required_before_external_sharing": True,
        },
        "evidence_buckets": {
            "implemented_contract": "synthetic fixture gate: mobile_app_guard_benchmark_gate.py",
            "physical_device_smoke": "this ADB probe: installed APK and passive device state only",
            "roadmap_device_evidence_required": "root/hook/repack/pinning attack evidence still requires a governed device lab run",
        },
        "limitations": [
            "Does not install, launch, stop, or mutate the application.",
            "Does not execute Magisk, Frida, hook, repack, pinning-bypass, exfiltration, or spyware simulations.",
            "Does not prove SDK shielding efficacy, malware accuracy, backend ingestion, or frontend rendering.",
            "UI dump and logcat grep may contain operator-visible text; keep reports internal unless reviewed.",
        ],
    }
    return (0 if not errors else 1), report


def write_report(report: dict[str, object], output: Path | None) -> None:
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if output:
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="Installed Android package name to observe.")
    parser.add_argument("--adb", default="adb", help="ADB executable path. Defaults to adb on PATH.")
    parser.add_argument("--serial", help="Optional adb device serial.")
    parser.add_argument("--device-id", help="Sanitized physical device/lab inventory id.")
    parser.add_argument("--app-build-id", help="Protected app build id associated with this smoke observation.")
    parser.add_argument("--sdk-build-id", help="Mobile SDK build id associated with this smoke observation.")
    parser.add_argument("--event-id", action="append", default=[], help="Optional App Guard event id observed outside this probe.")
    parser.add_argument(
        "--server-request-id",
        action="append",
        default=[],
        help="Optional backend request id observed outside this probe.",
    )
    parser.add_argument("--ui-string", action="append", dest="ui_strings", help="Expected UI string to count in uiautomator dump.")
    parser.add_argument(
        "--logcat-grep",
        action="append",
        default=[],
        help="Optional case-insensitive logcat substring to collect from the last 500 lines.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument("--output", type=Path, help="Optional JSON report path.")
    args = parser.parse_args()

    ui_strings = args.ui_strings if args.ui_strings else list(DEFAULT_UI_STRINGS)
    exit_code, report = collect_smoke_evidence(
        args.package,
        adb=args.adb,
        serial=args.serial,
        device_id=args.device_id,
        app_build_id=args.app_build_id,
        sdk_build_id=args.sdk_build_id,
        event_ids=args.event_id,
        server_request_ids=args.server_request_id,
        ui_strings=ui_strings,
        logcat_grep=args.logcat_grep,
        timeout_seconds=args.timeout_seconds,
    )
    write_report(report, args.output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
