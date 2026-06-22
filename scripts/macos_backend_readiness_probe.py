#!/usr/bin/env python3
"""Roadmap E macOS backend-readiness probe.

This probe is non-destructive. It uses tamandua-ctl inventory JSON to determine
whether a macOS agent is backend-connected and ready for the server-backed P0
sensor smoke profile. By default it does not run endpoint commands or inspect
live alerts. With --live-response-diagnostics it also records read-only live
response diagnostics for the selected macOS agent.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "macos-backend-readiness-probe"
PROFILE_NAME = "macOS Backend Readiness Probe"
DEFAULT_CTL = ROOT / "apps" / "tamandua_ctl" / "target" / "release" / "tamandua-ctl.exe"
FRESHNESS_SECONDS = int(os.getenv("TAMANDUA_MACOS_READINESS_FRESHNESS_SECONDS", "300"))
LIVE_RESPONSE_REMOTE_TIMEOUT_SECONDS = int(os.getenv("TAMANDUA_MACOS_LIVE_RESPONSE_REMOTE_TIMEOUT_SECONDS", "45"))
LIVE_RESPONSE_PROCESS_TIMEOUT_SECONDS = int(os.getenv("TAMANDUA_MACOS_LIVE_RESPONSE_PROCESS_TIMEOUT_SECONDS", "55"))
LIVE_RESPONSE_TOTAL_TIMEOUT_SECONDS = int(os.getenv("TAMANDUA_MACOS_LIVE_RESPONSE_TOTAL_TIMEOUT_SECONDS", "180"))
BOOTSTRAP_READINESS_FRESHNESS_SECONDS = int(
    os.getenv("TAMANDUA_MACOS_BOOTSTRAP_READINESS_FRESHNESS_SECONDS", "900")
)
BOOTSTRAP_READINESS_BOOLEAN_FIELDS = [
    "agent_architecture_matches_host",
    "app_bundle_present",
    "system_extension_architecture_matches_host",
    "launchd_service_present",
    "developer_id_signature_present",
    "not_adhoc_signed",
    "endpoint_security_entitlement_present",
    "system_extension_install_entitlement_present",
    "gatekeeper_assessment_accepted",
    "tamandua_system_extension_listed",
    "system_tcc_db_readable",
    "full_disk_access_tamandua_entry_present",
]
BOOTSTRAP_READINESS_STRING_FIELDS = [
    "generated_at",
    "agent_binary",
    "host_architecture",
    "agent_architecture",
    "app_bundle_path",
    "system_extension_architecture",
    "gatekeeper_assessment_detail",
    "tamandua_system_extension_line",
    "system_tcc_db_detail",
    "full_disk_access_tamandua_entry_detail",
    "next_action",
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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


def ctl_path() -> Path:
    return Path(os.getenv("TAMANDUA_CTL_PATH") or DEFAULT_CTL)


def tamandua_ctl_env(server: str | None, base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base_env or os.environ)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(name, None)
    if not server:
        return env
    host = urlparse(server).hostname
    if not host:
        return env
    existing_values = []
    for name in ("NO_PROXY", "no_proxy"):
        existing = env.get(name)
        if existing:
            existing_values.extend(item.strip() for item in existing.split(",") if item.strip())
    merged = []
    for value in [*existing_values, host]:
        if value and value not in merged:
            merged.append(value)
    no_proxy = ",".join(merged)
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    return env


def remote_config_path() -> Path | None:
    if os.name == "nt":
        appdata = os.getenv("APPDATA")
        if not appdata:
            return None
        return Path(appdata) / "Tamandua" / "tamandua-ctl" / "remote.json"
    config_home = os.getenv("XDG_CONFIG_HOME")
    if config_home:
        base = Path(config_home)
    else:
        home = os.getenv("HOME")
        if not home:
            return None
        base = Path(home) / ".config"
    return base / "tamandua" / "tamandua-ctl" / "remote.json"


def remote_config_metadata(target_server: str | None = None) -> dict[str, Any]:
    path = remote_config_path()
    metadata: dict[str, Any] = {
        "path": str(path) if path else None,
        "exists": False,
        "server": None,
        "has_token": False,
        "expires_at": None,
        "target_server": target_server,
        "server_matches_target": None,
    }
    if path is None:
        metadata["error"] = "remote_config_path_unavailable"
        return metadata
    if not path.exists():
        return metadata
    metadata["exists"] = True
    try:
        stat = path.stat()
        metadata["last_modified"] = iso(datetime.fromtimestamp(stat.st_mtime, timezone.utc))
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        metadata["error"] = type(exc).__name__
        return metadata
    if not isinstance(body, dict):
        metadata["error"] = "remote_config_not_object"
        return metadata
    saved_server = body.get("server")
    metadata["server"] = saved_server if isinstance(saved_server, str) else None
    metadata["has_token"] = bool(body.get("token"))
    expires_at = body.get("expires_at")
    metadata["expires_at"] = expires_at if isinstance(expires_at, str) else None
    if target_server and metadata["server"]:
        metadata["server_matches_target"] = str(metadata["server"]).rstrip("/") == str(target_server).rstrip("/")
    return metadata


def load_agents(server: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    command = [str(ctl_path()), "remote", "agents", "list", "--json"]
    if server:
        command.extend(["--server", server])
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=tamandua_ctl_env(server),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    evidence = {
        "command": " ".join(command),
        "exit_code": result.returncode,
        "stderr": result.stderr[-2000:],
        "remote_config": remote_config_metadata(server),
    }
    if result.returncode != 0:
        evidence["stdout"] = result.stdout[-2000:]
        return [], evidence
    try:
        body = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        evidence["json_error"] = str(exc)
        evidence["stdout"] = result.stdout[-2000:]
        return [], evidence
    agents = body.get("data") if isinstance(body, dict) else body
    if not isinstance(agents, list):
        evidence["shape_error"] = "agents response is not a list"
        return [], evidence
    return [agent for agent in agents if isinstance(agent, dict)], evidence


def inventory_auth_missing(inventory: dict[str, Any]) -> bool:
    text = f"{inventory.get('stderr') or ''}\n{inventory.get('stdout') or ''}".lower()
    return int(inventory.get("exit_code") or 0) != 0 and (
        "401 unauthorized" in text or "invalid or expired token" in text
    )


def macos_live_response_diagnostic_script(agent_binary_path: str = "/opt/tamandua/tamandua-agent") -> str:
    quoted_agent = agent_binary_path.replace("'", "'\"'\"'")
    sections = [
        ("HOSTNAME", "hostname"),
        ("LAUNCHCTL", "launchctl list"),
        ("SYSTEMEXTENSIONSCTL", "systemextensionsctl list"),
        ("CODESIGN", f"codesign -d --entitlements :- '{quoted_agent}'"),
        ("SPCTL", f"spctl --assess --type execute --verbose=4 '{quoted_agent}'"),
    ]
    parts = []
    for section, command in sections:
        parts.extend(
            [
                f"printf '\\n__TAMANDUA_DIAG_{section}_BEGIN__\\n'",
                f"{command} 2>&1",
                "status=\"$?\"",
                f"printf '\\n__TAMANDUA_DIAG_{section}_EXIT__:%s\\n' \"$status\"",
                f"printf '__TAMANDUA_DIAG_{section}_END__\\n'",
            ]
        )
    return "; ".join(parts)


def live_response_diagnostic_commands(agent_binary_path: str = "/opt/tamandua/tamandua-agent") -> list[list[str]]:
    # Read-only command markers preserved for status consistency checks:
    # ["systemextensionsctl", "list"]
    # ["codesign", "-d", "--entitlements", ":-", agent_binary_path]
    # ["spctl", "--assess", "--type", "execute", "--verbose=4", agent_binary_path]
    return [
        ["systemextensionsctl", "list"],
        ["codesign", "-d", "--entitlements", ":-", agent_binary_path],
        ["spctl", "--assess", "--type", "execute", "--verbose=4", agent_binary_path],
    ]


def run_live_response_command(
    server: str | None,
    agent_id: str,
    command: list[str],
    process_timeout_seconds: int | None = None,
    remote_timeout_seconds: int | None = None,
) -> dict[str, Any]:
    process_timeout = process_timeout_seconds or LIVE_RESPONSE_PROCESS_TIMEOUT_SECONDS
    remote_timeout = remote_timeout_seconds or LIVE_RESPONSE_REMOTE_TIMEOUT_SECONDS
    shell_start_timeout = remote_timeout if remote_timeout <= 2 else max(1, min(remote_timeout - 1, 10))
    ctl_command = [
        str(ctl_path()),
        "remote",
        "command",
        "--json",
        "--agent-id",
        agent_id,
        "--overall-timeout",
        str(remote_timeout),
        "--shell-start-timeout",
        str(shell_start_timeout),
        "--idle-timeout",
        "2",
    ]
    if server:
        ctl_command.extend(["--server", server])
    ctl_command.append("--")
    ctl_command.extend(command)
    try:
        result = subprocess.run(
            ctl_command,
            cwd=ROOT,
            env=tamandua_ctl_env(server),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=process_timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "command": command,
            "ok": False,
            "error": type(exc).__name__,
            "detail": str(exc)[-2000:],
            "process_timeout_seconds": process_timeout,
            "remote_timeout_seconds": remote_timeout,
        }

    evidence: dict[str, Any] = {
        "command": command,
        "exit_code": result.returncode,
        "stderr_tail": result.stderr[-2000:],
        "ok": result.returncode == 0,
        "process_timeout_seconds": process_timeout,
        "remote_timeout_seconds": remote_timeout,
    }
    if is_combined_live_response_diagnostic_command(command):
        evidence["label"] = "combined macOS readiness diagnostics"
    try:
        body = json.loads(result.stdout)
    except json.JSONDecodeError:
        evidence["stdout_tail"] = result.stdout[-2000:]
        return evidence
    if isinstance(body, dict):
        evidence["status"] = body.get("status")
        evidence["command_confirmed"] = body.get("command_confirmed")
        evidence["end_reason"] = body.get("end_reason")
        evidence["remote_exit_code"] = body.get("exit_code")
        output = body.get("output")
        if isinstance(output, str):
            evidence["output_tail"] = output[-4000:]
    else:
        evidence["stdout_shape"] = type(body).__name__
    return evidence


def live_response_command(commands: list[dict[str, Any]], executable: str) -> dict[str, Any] | None:
    for item in commands:
        if not isinstance(item, dict):
            continue
        command = item.get("command")
        if isinstance(command, list) and command and command[0] == executable:
            return item
    return None


def live_response_command_reliable(item: dict[str, Any] | None) -> bool:
    if not item:
        return False
    if item.get("ok") is False:
        return False
    if item.get("command_confirmed") is False:
        return False
    if item.get("status") == "not_dispatched":
        return False
    if item.get("error") == "diagnostic_budget_exhausted":
        return False
    return True


def is_combined_live_response_diagnostic_command(command: Any) -> bool:
    return (
        isinstance(command, list)
        and len(command) == 1
        and isinstance(command[0], str)
        and "__TAMANDUA_DIAG_SYSTEMEXTENSIONSCTL_BEGIN__" in command[0]
        and "__TAMANDUA_DIAG_CODESIGN_BEGIN__" in command[0]
        and "__TAMANDUA_DIAG_SPCTL_BEGIN__" in command[0]
    )


def live_response_output(commands: list[dict[str, Any]], executable: str) -> str:
    item = live_response_command(commands, executable)
    if not live_response_command_reliable(item):
        section = {
            "hostname": "HOSTNAME",
            "launchctl": "LAUNCHCTL",
            "systemextensionsctl": "SYSTEMEXTENSIONSCTL",
            "codesign": "CODESIGN",
            "spctl": "SPCTL",
        }.get(executable)
        return live_response_section_output(commands, section) if section else ""
    return str(item.get("output_tail") or item.get("stdout_tail") or "")


def live_response_section_output(commands: list[dict[str, Any]], section: str | None) -> str:
    if not section:
        return ""
    pattern = re.compile(
        rf"__TAMANDUA_DIAG_{re.escape(section)}_BEGIN__\r?\n"
        rf"(?P<body>.*?)"
        rf"\r?\n__TAMANDUA_DIAG_{re.escape(section)}_EXIT__:(?P<exit_code>\d+)",
        re.DOTALL,
    )
    for item in commands:
        if not live_response_command_reliable(item):
            continue
        command = item.get("command")
        if not is_combined_live_response_diagnostic_command(command):
            continue
        output = str(item.get("output_tail") or item.get("stdout_tail") or "")
        match = pattern.search(output)
        if match:
            return match.group("body").strip()
    return ""


def systemextensionsctl_evidence_lines(output: str) -> list[str]:
    lines = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if "tamandua shell ready" in lower:
            continue
        if "__tamandua_ctl_done_" in lower:
            continue
        if "systemextensionsctl list" in lower:
            continue
        if line.startswith("sh-") or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def summarize_live_response_diagnostics(commands: list[dict[str, Any]]) -> dict[str, Any]:
    sysext_command = live_response_command(commands, "systemextensionsctl")
    entitlement_command = live_response_command(commands, "codesign")
    spctl_command = live_response_command(commands, "spctl")
    combined_command = next(
        (
            item
            for item in commands
            if isinstance(item, dict)
            and is_combined_live_response_diagnostic_command(item.get("command"))
        ),
        None,
    )
    sysext_output = live_response_output(commands, "systemextensionsctl")
    entitlement_output = live_response_output(commands, "codesign")
    spctl_output = live_response_output(commands, "spctl")
    sysext_lower = "\n".join(systemextensionsctl_evidence_lines(sysext_output)).lower()
    entitlement_lower = entitlement_output.lower()
    spctl_lower = spctl_output.lower()

    findings = []
    inconclusive_commands = []
    for executable, item in [
        ("systemextensionsctl", sysext_command),
        ("codesign", entitlement_command),
        ("spctl", spctl_command),
    ]:
        if item is not None and not live_response_command_reliable(item):
            inconclusive_commands.append(executable)
        elif item is None and not live_response_command_reliable(combined_command):
            inconclusive_commands.append(executable)

    tamandua_system_extension_present = None
    endpoint_security_entitlement_present = None
    system_extension_install_entitlement_present = None
    gatekeeper_accepted = None
    gatekeeper_rejected = None
    if live_response_command_reliable(sysext_command) or (
        live_response_command_reliable(combined_command) and sysext_output
    ):
        tamandua_system_extension_present = "tamandua" in sysext_lower
    if live_response_command_reliable(entitlement_command) or (
        live_response_command_reliable(combined_command) and entitlement_output
    ):
        endpoint_security_entitlement_present = "com.apple.developer.endpoint-security.client" in entitlement_lower
        system_extension_install_entitlement_present = (
            "com.apple.developer.system-extension.install" in entitlement_lower
        )
    if live_response_command_reliable(spctl_command) or (
        live_response_command_reliable(combined_command) and spctl_output
    ):
        gatekeeper_accepted = "accepted" in spctl_lower and "rejected" not in spctl_lower
        gatekeeper_rejected = "rejected" in spctl_lower

    if sysext_output and tamandua_system_extension_present is False:
        findings.append("tamandua_system_extension_missing")
    if entitlement_output and endpoint_security_entitlement_present is False:
        findings.append("endpoint_security_entitlement_missing")
    if entitlement_output and system_extension_install_entitlement_present is False:
        findings.append("system_extension_install_entitlement_missing")
    if gatekeeper_rejected:
        findings.append("gatekeeper_rejected_agent_binary")

    return {
        "tamandua_system_extension_present": tamandua_system_extension_present,
        "endpoint_security_entitlement_present": endpoint_security_entitlement_present,
        "system_extension_install_entitlement_present": system_extension_install_entitlement_present,
        "gatekeeper_accepted": gatekeeper_accepted,
        "gatekeeper_rejected": gatekeeper_rejected,
        "inconclusive_commands": inconclusive_commands,
        "diagnostics_conclusive": not inconclusive_commands,
        "findings": findings,
    }


def collect_live_response_diagnostics(
    server: str | None,
    best_candidate: dict[str, Any] | None,
    enabled: bool = False,
) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {
        "enabled": enabled,
        "claim_boundary": "read-only live response diagnostics; not a smoke execution",
        "commands": [],
    }
    if not enabled:
        return diagnostics
    if not best_candidate:
        diagnostics["error"] = "no_macos_candidate"
        return diagnostics
    agent_id = best_candidate.get("id")
    if not isinstance(agent_id, str) or not agent_id:
        diagnostics["error"] = "candidate_missing_agent_id"
        return diagnostics
    if str(best_candidate.get("status") or "").lower() != "online":
        diagnostics["error"] = "candidate_not_online"
        return diagnostics
    diagnostics["target_agent_id"] = agent_id
    diagnostics["target_hostname"] = best_candidate.get("hostname")
    diagnostics["total_timeout_seconds"] = LIVE_RESPONSE_TOTAL_TIMEOUT_SECONDS
    start = time.monotonic()
    commands = []
    for command in live_response_diagnostic_commands():
        elapsed = time.monotonic() - start
        remaining = LIVE_RESPONSE_TOTAL_TIMEOUT_SECONDS - elapsed
        if remaining <= 5:
            commands.append(
                {
                    "command": command,
                    "ok": False,
                    "error": "diagnostic_budget_exhausted",
                    "detail": "Skipped to keep read-only live response diagnostics bounded.",
                }
            )
            continue
        process_timeout = max(5, min(LIVE_RESPONSE_PROCESS_TIMEOUT_SECONDS, int(remaining)))
        commands.append(run_live_response_command(server, agent_id, command, process_timeout_seconds=process_timeout))
    diagnostics["commands"] = commands
    diagnostics["diagnostic_findings"] = summarize_live_response_diagnostics(diagnostics["commands"])
    return diagnostics


def load_bootstrap_readiness_report(path_value: str | None) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "enabled": bool(path_value),
        "path": str(path_value or ""),
        "claim_boundary": "local bootstrap readiness report only; does not replace backend health evidence",
        "report_exists": False,
        "valid_shape": False,
        "ready_for_backend_probe": False,
        "missing_fields": [],
        "wrong_type_fields": [],
        "false_readiness_fields": [],
        "unknown_fields": [],
        "generated_at_parseable": False,
        "generated_at_age_seconds": None,
        "stale_report": False,
        "freshness_seconds": BOOTSTRAP_READINESS_FRESHNESS_SECONDS,
    }
    if not path_value:
        return evidence

    path = Path(path_value)
    evidence["path"] = str(path)
    if not path.exists():
        evidence["error"] = "report_not_found"
        return evidence
    evidence["report_exists"] = True

    try:
        report = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        evidence["error"] = "report_invalid_json"
        evidence["error_detail"] = str(exc)[-500:]
        return evidence
    if not isinstance(report, dict):
        evidence["error"] = "report_not_object"
        return evidence

    required_fields = BOOTSTRAP_READINESS_BOOLEAN_FIELDS + BOOTSTRAP_READINESS_STRING_FIELDS
    for field in required_fields:
        if field not in report:
            evidence["missing_fields"].append(field)
    for field in BOOTSTRAP_READINESS_BOOLEAN_FIELDS:
        if field in report and not isinstance(report.get(field), bool):
            evidence["wrong_type_fields"].append(field)
    for field in BOOTSTRAP_READINESS_STRING_FIELDS:
        if field in report and not isinstance(report.get(field), str):
            evidence["wrong_type_fields"].append(field)
    for field in report:
        if field not in required_fields:
            evidence["unknown_fields"].append(str(field))
    for field in BOOTSTRAP_READINESS_BOOLEAN_FIELDS:
        if report.get(field) is False:
            evidence["false_readiness_fields"].append(field)
    generated_at = parse_time(report.get("generated_at"))
    if generated_at is None:
        evidence["stale_report"] = True
    else:
        generated_at_age_seconds = max(0, int((utc_now() - generated_at).total_seconds()))
        evidence["generated_at_parseable"] = True
        evidence["generated_at_age_seconds"] = generated_at_age_seconds
        evidence["stale_report"] = generated_at_age_seconds > BOOTSTRAP_READINESS_FRESHNESS_SECONDS

    evidence["valid_shape"] = not (
        evidence["missing_fields"]
        or evidence["wrong_type_fields"]
        or evidence["unknown_fields"]
        or not evidence["generated_at_parseable"]
    )
    evidence["ready_for_backend_probe"] = bool(
        evidence["valid_shape"]
        and not evidence["false_readiness_fields"]
        and not evidence["stale_report"]
    )
    evidence["summary"] = {
        "generated_at": report.get("generated_at"),
        "generated_at_age_seconds": evidence["generated_at_age_seconds"],
        "agent_binary": report.get("agent_binary"),
        "next_action": report.get("next_action"),
    }
    return evidence


def macos_agent_summary(agent: dict[str, Any]) -> dict[str, Any]:
    health = agent.get("health_status") if isinstance(agent.get("health_status"), dict) else {}
    health_metrics = health.get("metrics") if isinstance(health.get("metrics"), dict) else {}
    capabilities = agent.get("platform_capabilities") if isinstance(agent.get("platform_capabilities"), list) else []
    last_seen = parse_time(agent.get("last_seen"))
    age_seconds = None if last_seen is None else max(0, int((utc_now() - last_seen).total_seconds()))
    heartbeat_age_ms = health_metrics.get("heartbeat_age_ms")
    return {
        "id": agent.get("id"),
        "hostname": agent.get("hostname"),
        "os_type": agent.get("os_type"),
        "os_version": agent.get("os_version"),
        "status": agent.get("status"),
        "health": health.get("status"),
        "health_reasons": health.get("reasons") if isinstance(health.get("reasons"), list) else [],
        "driver_state": health_metrics.get("driver_state"),
        "driver_last_error": health_metrics.get("driver_last_error"),
        "heartbeat_age_ms": heartbeat_age_ms if isinstance(heartbeat_age_ms, int | float) else None,
        "platform_coverage": health_metrics.get("platform_coverage"),
        "last_seen": agent.get("last_seen"),
        "last_seen_age_seconds": age_seconds,
        "capabilities": [
            {
                "id": item.get("id"),
                "status": item.get("status"),
                "maturity": item.get("maturity"),
                "observed": item.get("observed"),
            }
            for item in capabilities
            if isinstance(item, dict)
        ],
    }


def has_fresh_heartbeat(agent: dict[str, Any]) -> bool:
    heartbeat_age_ms = agent.get("heartbeat_age_ms")
    if isinstance(heartbeat_age_ms, int | float):
        return heartbeat_age_ms <= FRESHNESS_SECONDS * 1000
    return (
        isinstance(agent.get("last_seen_age_seconds"), int)
        and agent["last_seen_age_seconds"] <= FRESHNESS_SECONDS
    )


def macos_candidate_missing(agent: dict[str, Any]) -> list[str]:
    missing = []
    if str(agent.get("status") or "").lower() != "online":
        missing.append("status_online")
    if str(agent.get("health") or "").lower() != "healthy":
        missing.append("health_healthy")
    if not has_fresh_heartbeat(agent):
        missing.append("fresh_heartbeat")
    if not any(
        item.get("id") == "endpoint_telemetry"
        and item.get("status") not in {"unavailable", "unknown"}
        for item in agent.get("capabilities") or []
    ):
        missing.append("endpoint_telemetry_capability")
    return missing


def best_macos_candidate(summaries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not summaries:
        return None

    def sort_key(agent: dict[str, Any]) -> tuple[int, int, int, int]:
        missing = macos_candidate_missing(agent)
        online = int(str(agent.get("status") or "").lower() == "online")
        healthy = int(str(agent.get("health") or "").lower() == "healthy")
        age = agent.get("last_seen_age_seconds")
        freshness_score = -int(age) if isinstance(age, int) else -10**9
        return (-len(missing), online, healthy, freshness_score)

    candidate = sorted(summaries, key=sort_key, reverse=True)[0]
    return {**candidate, "missing_readiness": macos_candidate_missing(candidate)}


def macos_next_action(best_candidate: dict[str, Any] | None, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    if inventory and inventory_auth_missing(inventory):
        remote_config = inventory.get("remote_config") if isinstance(inventory.get("remote_config"), dict) else {}
        target_server = remote_config.get("target_server") or None
        saved_server = remote_config.get("server") or None
        if target_server and saved_server and remote_config.get("server_matches_target") is False:
            return {
                "target_agent_id": None,
                "target_hostname": None,
                "missing_readiness": ["tamandua_ctl_auth"],
                "action": (
                    "Run tamandua-ctl remote login for the target server "
                    f"{target_server} because the saved remote login is for {saved_server}; "
                    "then rerun macos_backend_readiness_probe.py before diagnosing macOS agent enrollment."
                ),
                "login_command": f"tamandua-ctl remote login --server {target_server} --no-browser",
                "token_env": "TAMANDUA_TOKEN",
                "token_login_command": f"tamandua-ctl remote login --server {target_server} --token $env:TAMANDUA_TOKEN",
                "saved_server": saved_server,
                "target_server": target_server,
            }
        return {
            "target_agent_id": None,
            "target_hostname": None,
            "missing_readiness": ["tamandua_ctl_auth"],
            "action": "Refresh tamandua-ctl authentication for the target server, then rerun macos_backend_readiness_probe.py before diagnosing macOS agent enrollment.",
            "token_env": "TAMANDUA_TOKEN",
        }
    if best_candidate is None:
        return {
            "target_agent_id": None,
            "target_hostname": None,
            "missing_readiness": ["macos_agent_row"],
            "action": "Enroll or reconnect a macOS lab agent, then rerun macos_backend_readiness_probe.py.",
        }
    missing = [str(value) for value in best_candidate.get("missing_readiness") or []]
    if not missing:
        action = "Run deploy/scripts/proxmox/run-macos-p0-smoke.ps1 against the ready macOS agent."
    elif missing == ["health_healthy"]:
        driver_error = str(best_candidate.get("driver_last_error") or "")
        driver_state = str(best_candidate.get("driver_state") or "")
        if "EndpointSecurity" in driver_error or driver_state == "not_loaded":
            action = (
                "Resolve the selected macOS agent health degradation before smoke execution. "
                "Deploy a Developer ID signed/notarized agent with "
                "com.apple.developer.endpoint-security.client and "
                "com.apple.developer.system-extension.install, confirm the Tamandua system extension "
                "is active and Full Disk Access is approved on the Mac, then rerun macos_backend_readiness_probe.py."
            )
        else:
            action = (
                "Resolve the selected macOS agent health degradation before smoke execution. "
                "Check EndpointSecurity/system extension and Full Disk Access approval on the Mac, "
                "then rerun macos_backend_readiness_probe.py."
            )
    else:
        action = (
            "Reconnect the selected macOS agent, wait for a fresh healthy heartbeat, "
            "verify endpoint_telemetry capability, then rerun macos_backend_readiness_probe.py."
        )
    return {
        "target_agent_id": best_candidate.get("id"),
        "target_hostname": best_candidate.get("hostname"),
        "missing_readiness": missing,
        "action": action,
    }


def refine_next_action_with_diagnostics(
    next_action: dict[str, Any],
    diagnostics: dict[str, Any],
) -> dict[str, Any]:
    findings_payload = diagnostics.get("diagnostic_findings") if isinstance(diagnostics, dict) else {}
    if not isinstance(findings_payload, dict):
        return next_action
    findings = [str(value) for value in findings_payload.get("findings") or []]
    if not findings:
        return next_action

    refined = dict(next_action)
    refined["diagnostic_findings"] = findings
    if (
        "endpoint_security_entitlement_missing" in findings
        or "system_extension_install_entitlement_missing" in findings
        or "gatekeeper_rejected_agent_binary" in findings
    ):
        refined["action"] = (
            "Deploy a Developer ID signed/notarized agent binary for macOS that Gatekeeper accepts "
            "and that includes com.apple.developer.endpoint-security.client and "
            "com.apple.developer.system-extension.install, confirm Full Disk Access remains approved, "
            "then rerun macos_backend_readiness_probe.py before smoke execution."
        )
    elif "tamandua_system_extension_missing" in findings:
        refined["action"] = (
            "Approve or reinstall the Tamandua system extension on the Mac, confirm Full Disk Access, "
            "then rerun macos_backend_readiness_probe.py before smoke execution."
        )
    return refined


def make_result(test_id: str, name: str, passed: bool, category: str, evidence: dict[str, Any], missing: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else category,
        "execution_class": "backend_readiness_probe",
        "claim_level": "macos_backend_readiness",
        "executor_used": PROFILE_ID,
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": "macos_backend_readiness",
        "coverage": {
            "telemetry": "not_expected",
            "fields": "ok" if passed else "missing",
            "detection": "not_expected",
            "alert": "not_expected",
            "correlation": "not_expected",
            "driver_raw": "not_expected",
            "timeline": "not_expected",
            "values": "ok" if passed else "missing",
        },
        "evidence": evidence,
        "missing_expected_fields": missing or [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [],
    }


def build_tests(
    server: str | None = None,
    live_response_diagnostics: bool = False,
    bootstrap_readiness_report: str | None = None,
) -> list[dict[str, Any]]:
    agents, inventory = load_agents(server)
    auth_missing = inventory_auth_missing(inventory)
    macs = [agent for agent in agents if str(agent.get("os_type") or "").lower() == "macos"]
    summaries = [macos_agent_summary(agent) for agent in macs]
    online = [agent for agent in summaries if str(agent.get("status") or "").lower() == "online"]
    healthy = [agent for agent in online if str(agent.get("health") or "").lower() == "healthy"]
    fresh = [agent for agent in online if has_fresh_heartbeat(agent)]
    endpoint_ready = [
        agent
        for agent in fresh
        if any(
            item.get("id") == "endpoint_telemetry"
            and item.get("status") not in {"unavailable", "unknown"}
            for item in agent.get("capabilities") or []
        )
    ]
    best_candidate = best_macos_candidate(summaries)
    live_response_evidence = collect_live_response_diagnostics(
        server,
        best_candidate,
        enabled=live_response_diagnostics,
    )
    next_action = refine_next_action_with_diagnostics(
        macos_next_action(best_candidate, inventory),
        live_response_evidence,
    )
    bootstrap_evidence = load_bootstrap_readiness_report(bootstrap_readiness_report)

    evidence = {
        "inventory": inventory,
        "macos_agents": summaries,
        "best_candidate": best_candidate,
        "next_action": next_action,
        "freshness_seconds": FRESHNESS_SECONDS,
        "live_response_diagnostics": live_response_evidence,
        "bootstrap_readiness_report": bootstrap_evidence,
    }
    row_missing = ["tamandua_ctl_auth"] if auth_missing else ["macos_agent_row"]
    tests = [
        make_result(
            "macos-backend-agent-row-present",
            "At least one macOS agent row exists in backend inventory",
            bool(macs),
            "infrastructure",
            evidence,
            [] if macs else row_missing,
        ),
        make_result(
            "macos-backend-agent-online-healthy",
            "At least one macOS agent is online and healthy",
            bool(healthy),
            "infrastructure",
            evidence,
            [] if healthy else ["online_healthy_macos_agent"],
        ),
        make_result(
            "macos-backend-agent-fresh",
            "At least one macOS agent has a fresh heartbeat",
            bool(fresh),
            "infrastructure",
            evidence,
            [] if fresh else ["fresh_macos_heartbeat"],
        ),
        make_result(
            "macos-backend-endpoint-telemetry-capability",
            "At least one fresh macOS agent advertises endpoint telemetry capability",
            bool(endpoint_ready),
            "collector",
            evidence,
            [] if endpoint_ready else ["macos_endpoint_telemetry_capability"],
        ),
    ]
    if bootstrap_evidence.get("enabled"):
        bootstrap_missing = []
        if not bootstrap_evidence.get("report_exists"):
            bootstrap_missing.append("macos_bootstrap_readiness_report")
        if not bootstrap_evidence.get("valid_shape"):
            bootstrap_missing.append("valid_macos_bootstrap_readiness_shape")
        if bootstrap_evidence.get("stale_report"):
            bootstrap_missing.append("fresh_macos_bootstrap_readiness_report")
        for field in bootstrap_evidence.get("false_readiness_fields") or []:
            bootstrap_missing.append(str(field))
        tests.append(
            make_result(
                "macos-backend-bootstrap-readiness-report",
                "Provided macOS bootstrap readiness report is valid and ready for backend probe",
                bool(bootstrap_evidence.get("ready_for_backend_probe")),
                "infrastructure",
                evidence,
                bootstrap_missing,
            )
        )
    return tests


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        "",
        "## Results",
        "",
        "| Test | Status | Gap | Missing |",
        "|------|--------|-----|---------|",
    ]
    for test in report["tests"]:
        missing = ", ".join(test.get("missing_expected_fields") or []) or "-"
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['gap_category']}` | `{missing}` |")
    first_evidence = (report["tests"][0].get("evidence") if report.get("tests") else {}) or {}
    best_candidate = first_evidence.get("best_candidate") if isinstance(first_evidence.get("best_candidate"), dict) else None
    next_action = first_evidence.get("next_action") if isinstance(first_evidence.get("next_action"), dict) else {}
    lines.extend(
        [
            "",
            "## Best Candidate",
            "",
            "| Hostname | Agent ID | Status | Health | Last seen age | Missing readiness |",
            "|----------|----------|--------|--------|---------------|-------------------|",
        ]
    )
    if best_candidate:
        missing = ", ".join(str(value) for value in best_candidate.get("missing_readiness") or []) or "-"
        lines.append(
            f"| `{best_candidate.get('hostname') or '-'}` | `{best_candidate.get('id') or '-'}` | "
            f"`{best_candidate.get('status') or '-'}` | `{best_candidate.get('health') or '-'}` | "
            f"`{best_candidate.get('last_seen_age_seconds')}` | `{missing}` |"
        )
        health_reasons = ", ".join(str(value) for value in best_candidate.get("health_reasons") or []) or "-"
        lines.extend(
            [
                "",
                "## Health Details",
                "",
                f"- Heartbeat age ms: `{best_candidate.get('heartbeat_age_ms')}`",
                f"- Driver state: `{best_candidate.get('driver_state') or '-'}`",
                f"- Driver last error: `{best_candidate.get('driver_last_error') or '-'}`",
                f"- Health reasons: `{health_reasons}`",
                f"- Platform coverage: `{best_candidate.get('platform_coverage')}`",
            ]
        )
    else:
        missing = ", ".join(str(value) for value in next_action.get("missing_readiness") or []) or "macos_agent_row"
        lines.append(f"| `-` | `-` | `-` | `-` | `-` | `{missing}` |")
    lines.extend(
        [
            "",
            "## Next Action",
            "",
            f"- Target: `{next_action.get('target_hostname') or '-'}` / `{next_action.get('target_agent_id') or '-'}`",
            f"- Missing: `{', '.join(next_action.get('missing_readiness') or []) or '-'}`",
            f"- Action: {next_action.get('action') or '-'}",
        ]
    )
    diagnostics = first_evidence.get("live_response_diagnostics")
    if isinstance(diagnostics, dict):
        lines.extend(["", "## Live Response Diagnostics", ""])
        lines.append(f"- Enabled: `{str(bool(diagnostics.get('enabled'))).lower()}`")
        if diagnostics.get("target_hostname") or diagnostics.get("target_agent_id"):
            lines.append(
                f"- Target: `{diagnostics.get('target_hostname') or '-'}` / `{diagnostics.get('target_agent_id') or '-'}`"
            )
        if diagnostics.get("error"):
            lines.append(f"- Error: `{diagnostics.get('error')}`")
        commands = diagnostics.get("commands") if isinstance(diagnostics.get("commands"), list) else []
        if commands:
            lines.extend(
                [
                    "",
                    "| Command | Exit | Remote Exit | Status | Confirmed |",
                    "|---------|------|-------------|--------|-----------|",
                ]
            )
            for item in commands:
                if not isinstance(item, dict):
                    continue
                command = str(item.get("label") or " ".join(str(value) for value in item.get("command") or []))
                lines.append(
                    f"| `{command}` | `{item.get('exit_code')}` | `{item.get('remote_exit_code')}` | "
                    f"`{item.get('status') or '-'}` | `{item.get('command_confirmed')}` |"
                )
        diagnostic_findings = diagnostics.get("diagnostic_findings")
        if isinstance(diagnostic_findings, dict):
            findings = diagnostic_findings.get("findings") if isinstance(diagnostic_findings.get("findings"), list) else []
            inconclusive = (
                diagnostic_findings.get("inconclusive_commands")
                if isinstance(diagnostic_findings.get("inconclusive_commands"), list)
                else []
            )

            def tri_state(value: Any) -> str:
                if value is None:
                    return "unknown"
                return str(bool(value)).lower()

            lines.extend(
                [
                    "",
                    "### Diagnostic Findings",
                    "",
                    f"- Diagnostics conclusive: `{str(bool(diagnostic_findings.get('diagnostics_conclusive'))).lower()}`",
                    f"- Inconclusive commands: `{', '.join(str(value) for value in inconclusive) if inconclusive else '-'}`",
                    f"- Tamandua system extension present: `{tri_state(diagnostic_findings.get('tamandua_system_extension_present'))}`",
                    f"- EndpointSecurity entitlement present: `{tri_state(diagnostic_findings.get('endpoint_security_entitlement_present'))}`",
                    f"- System Extension install entitlement present: `{tri_state(diagnostic_findings.get('system_extension_install_entitlement_present'))}`",
                    f"- Gatekeeper accepted agent binary: `{tri_state(diagnostic_findings.get('gatekeeper_accepted'))}`",
                    f"- Gatekeeper rejected agent binary: `{tri_state(diagnostic_findings.get('gatekeeper_rejected'))}`",
                    f"- Findings: `{', '.join(str(value) for value in findings) if findings else '-'}`",
                ]
            )
    bootstrap_report = first_evidence.get("bootstrap_readiness_report")
    if isinstance(bootstrap_report, dict):
        lines.extend(["", "## Bootstrap Readiness Report", ""])
        lines.append(f"- Enabled: `{str(bool(bootstrap_report.get('enabled'))).lower()}`")
        if bootstrap_report.get("path"):
            lines.append(f"- Path: `{bootstrap_report.get('path')}`")
        lines.append(f"- Report exists: `{str(bool(bootstrap_report.get('report_exists'))).lower()}`")
        lines.append(f"- Valid shape: `{str(bool(bootstrap_report.get('valid_shape'))).lower()}`")
        lines.append(
            f"- Ready for backend probe: `{str(bool(bootstrap_report.get('ready_for_backend_probe'))).lower()}`"
        )
        for key, label in [
            ("missing_fields", "Missing fields"),
            ("wrong_type_fields", "Wrong type fields"),
            ("unknown_fields", "Unknown fields"),
            ("false_readiness_fields", "False readiness fields"),
        ]:
            values = bootstrap_report.get(key) if isinstance(bootstrap_report.get(key), list) else []
            if values:
                lines.append(f"- {label}: `{', '.join(str(value) for value in values)}`")
        summary = bootstrap_report.get("summary") if isinstance(bootstrap_report.get("summary"), dict) else {}
        if summary.get("agent_binary"):
            lines.append(f"- Agent binary: `{summary.get('agent_binary')}`")
        if summary.get("next_action"):
            lines.append(f"- Local next action: {summary.get('next_action')}")
        if bootstrap_report.get("error"):
            lines.append(f"- Error: `{bootstrap_report.get('error')}`")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact proves macOS backend readiness only. It does not execute the macOS P0 sensor smoke profile and does not prove collector coverage.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    parser.add_argument("--server")
    parser.add_argument(
        "--live-response-diagnostics",
        action="store_true",
        help="Collect read-only live response diagnostics from the selected online macOS agent.",
    )
    parser.add_argument(
        "--bootstrap-readiness-report",
        help="Attach a copied /var/log/tamandua/macos-bootstrap-readiness.json report to evidence.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = iso(utc_now())
    tests = build_tests(
        args.server,
        live_response_diagnostics=args.live_response_diagnostics,
        bootstrap_readiness_report=args.bootstrap_readiness_report,
    )
    finished = iso(utc_now())
    passed = all(test["status"] == "covered" for test in tests)
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"

    report = {
        "schema_version": 1,
        "run_id": run_id,
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
            "missing_expected_fields": sum(len(test.get("missing_expected_fields") or []) for test in tests),
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "executor_counts": {PROFILE_ID: len(tests)},
            "claim_level_counts": {"macos_backend_readiness": len(tests)},
            "category_coverage": {"macos_backend_readiness": {"covered": covered, "missed": missed}},
        },
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["macos_backend_readiness_gaps"],
            "actionable_gaps": [
                {
                    "test_id": test["id"],
                    "gap_category": test["gap_category"],
                    "missing": test.get("missing_expected_fields") or [],
                    "evidence": test.get("evidence") or {},
                }
                for test in tests
                if test["status"] != "covered"
            ],
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "thresholds": {"freshness_seconds": FRESHNESS_SECONDS},
        },
        "scorecard": {
            "maturity_score": 100 if passed else 45,
            "maturity_band": "macos-backend-ready" if passed else "macos-backend-readiness-gaps",
            "recommended_claim": (
                "macOS backend readiness is sufficient to run P0 sensor smoke"
                if passed
                else "macOS backend-backed P0 sensor smoke is blocked by agent readiness"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else ["macos_backend_readiness_missing"],
            "covered_rate": covered / len(tests) if tests else 0,
            "telemetry_rate": 1.0,
            "field_quality": 1.0 if passed else 0.0,
            "context_quality": 1.0 if passed else 0.0,
            "analytic_quality": 1.0,
            "noise_quality": 1.0,
            "driver_quality": 1.0,
            "upstream_rate": 0.0,
        },
        "tests": tests,
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    md_path = output_dir / f"{run_id}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    comparison_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"macos_backend_readiness={'ok' if passed else 'gaps'} json={json_path} markdown={md_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
