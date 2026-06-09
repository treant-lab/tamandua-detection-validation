#!/usr/bin/env python3
"""Offline telemetry replay executor for sanitized FP/severity fixtures.

This is the first executable Roadmap P replay step. It consumes sanitized
fixture inputs, applies Tamandua-authored severity calibration logic that
mirrors the structured false-positive rules in `TamanduaServer.Alerts`, and
emits benchmark artifacts. It is intentionally report-only: no database access,
no live alert mutation, and no endpoint execution.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
from typing import Any

from validate_replay_fixtures import validate_fixture_file


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
FIXTURE_DIR = ROOT / "tools" / "detection_validation" / "fixtures"
PROFILE_ID = "telemetry-replay-offline-fp-severity-v1"
PROFILE_NAME = "Telemetry Replay Offline FP/Severity V1"


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
    return {"commit": commit, "commit_short": commit[:8] if commit else "", "dirty": bool(status), "status_short": status}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True).lower()
    return str(value).lower()


def basename(value: Any) -> str:
    return text(value).replace("\\", "/").rstrip("/").split("/")[-1]


def get_path(data: dict[str, Any], path: list[str]) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def first(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", []):
            return value
    return None


def fixture_context(item: dict[str, Any]) -> dict[str, Any]:
    input_data = item.get("input") or {}
    evidence = input_data.get("evidence") or {}
    raw_event = input_data.get("raw_event") or {}
    return {
        "title": text(input_data.get("title")),
        "severity": text(input_data.get("severity") or "info"),
        "evidence": evidence,
        "raw_event": raw_event,
        "process": evidence.get("process") or raw_event,
        "detection": evidence.get("detection") or {},
    }


def detection_name(ctx: dict[str, Any]) -> str:
    return text(first(ctx["detection"].get("rule_name"), ctx["detection"].get("name")))


def mitre_technique(ctx: dict[str, Any]) -> str:
    return text(first(ctx["detection"].get("mitre_technique"), ctx["detection"].get("mitre_techniques"), ctx["raw_event"].get("mitre_technique")))


def process_name(ctx: dict[str, Any]) -> str:
    return basename(first(ctx["process"].get("name"), ctx["process"].get("process_name"), ctx["raw_event"].get("process_name")))


def parent_name(ctx: dict[str, Any]) -> str:
    return basename(first(ctx["process"].get("parent_name"), ctx["raw_event"].get("parent_name")))


def process_path(ctx: dict[str, Any]) -> str:
    return text(first(ctx["process"].get("path"), ctx["process"].get("image_path"), ctx["raw_event"].get("path"), ctx["raw_event"].get("image_path")))


def parent_path(ctx: dict[str, Any]) -> str:
    return text(first(ctx["process"].get("parent_path"), ctx["raw_event"].get("parent_path")))


def command_line(ctx: dict[str, Any]) -> str:
    return text(first(ctx["process"].get("command_line"), ctx["process"].get("cmdline"), ctx["raw_event"].get("command_line"), ctx["raw_event"].get("cmdline")))


def registry_key(ctx: dict[str, Any]) -> str:
    registry = ctx["evidence"].get("registry") or {}
    return text(first(registry.get("key"), ctx["raw_event"].get("registry_key"), ctx["raw_event"].get("key"))).replace("/", "\\")


def registry_value(ctx: dict[str, Any]) -> str:
    registry = ctx["evidence"].get("registry") or {}
    return text(first(registry.get("value"), ctx["raw_event"].get("registry_value"), ctx["raw_event"].get("value")))


def registry_data(ctx: dict[str, Any]) -> str:
    registry = ctx["evidence"].get("registry") or {}
    return text(first(registry.get("data"), ctx["raw_event"].get("registry_data"), ctx["raw_event"].get("data"))).replace("/", "\\")


def network_remote_ip(ctx: dict[str, Any]) -> str:
    network = ctx["evidence"].get("network") or {}
    return text(first(network.get("remote_ip"), network.get("ip"), network.get("value"), ctx["raw_event"].get("remote_ip")))


def blank(value: Any) -> bool:
    return value in (None, "", [])


def truthy(value: Any) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    return str(value).strip().lower() in ("true", "1")


def falsy(value: Any) -> bool:
    if value is False:
        return True
    if value is True or value is None:
        return False
    return str(value).strip().lower() in ("false", "0")


def first_ctx(ctx: dict[str, Any], paths: list[list[str]]) -> Any:
    for path in paths:
        value = get_path(ctx, path)
        if value not in (None, "", []):
            return value
    return None


def contextless_ntdll_write(ctx: dict[str, Any]) -> bool:
    rule = detection_name(ctx)
    if rule not in {"ntdll_write_writeprocessmemory", "ntdll_write_ntwritevirtualmemory", "ntdll_write_ntmapviewofsection"}:
        return False
    target_fields = [
        get_path(ctx, ["raw_event", "target_pid"]),
        get_path(ctx, ["raw_event", "target_process"]),
        get_path(ctx, ["raw_event", "target_process_name"]),
        get_path(ctx, ["raw_event", "target_image"]),
        get_path(ctx, ["raw_event", "target_module"]),
        get_path(ctx, ["raw_event", "target_address"]),
        get_path(ctx, ["raw_event", "write_size"]),
        get_path(ctx, ["raw_event", "bytes_written"]),
        get_path(ctx, ["raw_event", "call_stack"]),
        get_path(ctx, ["process", "target_pid"]),
        get_path(ctx, ["process", "target_process"]),
        get_path(ctx, ["process", "target_process_name"]),
    ]
    return all(blank(value) for value in target_fields)


NTDLL_WRITE_RULES = {
    "ntdll_write_writeprocessmemory",
    "ntdll_write_ntwritevirtualmemory",
    "ntdll_write_ntmapviewofsection",
}

NTDLL_KNOWN_TOOL_BASENAMES = {
    "windbg.exe",
    "windbgx.exe",
    "cdb.exe",
    "ntsd.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "devenv.exe",
    "vsdebugconsole.exe",
    "easyanticheat.exe",
    "beservice.exe",
    "vgc.exe",
    "vgtray.exe",
    "msmpeng.exe",
    "tamandua-agent.exe",
    "tamandua_agent.exe",
}

NTDLL_KNOWN_TOOL_PATH_MARKERS = (
    "\\windows kits\\",
    "\\microsoft visual studio\\",
    "\\debuggers\\",
)


def ntdll_write_detection(ctx: dict[str, Any]) -> bool:
    if detection_name(ctx) in NTDLL_WRITE_RULES:
        return True
    return ctx["title"].startswith("agent detection: ntdll_write_")


def ntdll_region_class(ctx: dict[str, Any]) -> str:
    return text(first_ctx(ctx, [
        ["raw_event", "region_class"],
        ["raw_event", "metadata", "region_class"],
        ["raw_event", "enrichment", "region_class"],
        ["raw_event", "enrichment", "metadata", "region_class"],
        ["detection", "region_class"],
    ]))


def ntdll_target_function(ctx: dict[str, Any]) -> str:
    return text(first_ctx(ctx, [
        ["raw_event", "target_function"],
        ["raw_event", "metadata", "target_function"],
        ["raw_event", "enrichment", "target_function"],
        ["raw_event", "enrichment", "metadata", "target_function"],
        ["raw_event", "target_module"],
        ["raw_event", "enrichment", "metadata", "target_module"],
    ]))


def ntdll_export_table_target(ctx: dict[str, Any]) -> bool:
    region = ntdll_region_class(ctx)
    func = ntdll_target_function(ctx)
    return region == "export_table" or "export" in func or "eat" in func


def ntdll_rwx_protection(ctx: dict[str, Any]) -> bool:
    new_protection = text(first_ctx(ctx, [
        ["raw_event", "new_protection_str"],
        ["raw_event", "metadata", "new_protection_str"],
        ["raw_event", "enrichment", "new_protection_str"],
        ["raw_event", "enrichment", "metadata", "new_protection_str"],
        ["raw_event", "new_protection"],
        ["raw_event", "enrichment", "metadata", "new_protection"],
    ]))
    return new_protection in ("page_execute_readwrite", "page_execute_writecopy", "0x40", "0x80")


def ntdll_rwx_region(ctx: dict[str, Any]) -> bool:
    region = ntdll_region_class(ctx)
    if region == "rwx":
        return True
    if region in ("text", "data", "export_table"):
        return False
    return ntdll_rwx_protection(ctx)


def ntdll_thread_execution_context(ctx: dict[str, Any]) -> bool:
    thread_from_unbacked = first_ctx(ctx, [
        ["raw_event", "thread_from_unbacked"],
        ["raw_event", "metadata", "thread_from_unbacked"],
        ["raw_event", "enrichment", "thread_from_unbacked"],
        ["raw_event", "enrichment", "metadata", "thread_from_unbacked"],
    ])
    thread_start = first_ctx(ctx, [
        ["raw_event", "thread_start_address"],
        ["raw_event", "metadata", "thread_start_address"],
        ["raw_event", "enrichment", "thread_start_address"],
        ["raw_event", "enrichment", "metadata", "thread_start_address"],
    ])
    return truthy(thread_from_unbacked) or not blank(thread_start)


def ntdll_credential_target(ctx: dict[str, Any]) -> bool:
    target = text(first_ctx(ctx, [
        ["raw_event", "target_process"],
        ["raw_event", "target_process_name"],
        ["raw_event", "metadata", "target_process"],
        ["raw_event", "metadata", "target_process_name"],
        ["raw_event", "enrichment", "target_process"],
        ["raw_event", "enrichment", "target_process_name"],
        ["raw_event", "enrichment", "metadata", "target_process"],
        ["raw_event", "enrichment", "metadata", "target_process_name"],
    ]))
    return "lsass" in target or "sam" in target


def ntdll_source_pid(ctx: dict[str, Any]) -> Any:
    return first_ctx(ctx, [
        ["raw_event", "source_pid"],
        ["raw_event", "metadata", "source_pid"],
        ["raw_event", "enrichment", "source_pid"],
        ["raw_event", "enrichment", "metadata", "source_pid"],
        ["raw_event", "pid"],
        ["process", "pid"],
    ])


def ntdll_target_pid(ctx: dict[str, Any]) -> Any:
    return first_ctx(ctx, [
        ["raw_event", "target_pid"],
        ["raw_event", "metadata", "target_pid"],
        ["raw_event", "enrichment", "target_pid"],
        ["raw_event", "enrichment", "metadata", "target_pid"],
        ["process", "target_pid"],
    ])


def ntdll_cross_process_target(ctx: dict[str, Any]) -> bool:
    flag = first_ctx(ctx, [
        ["raw_event", "cross_process"],
        ["raw_event", "metadata", "cross_process"],
        ["raw_event", "enrichment", "cross_process"],
        ["raw_event", "enrichment", "metadata", "cross_process"],
        ["detection", "cross_process"],
    ])
    if truthy(flag):
        return True
    if falsy(flag):
        return False
    source_pid = ntdll_source_pid(ctx)
    target_pid = ntdll_target_pid(ctx)
    return not blank(source_pid) and not blank(target_pid) and str(source_pid) != str(target_pid)


def ntdll_source_signed(ctx: dict[str, Any]) -> bool:
    return truthy(first_ctx(ctx, [
        ["raw_event", "source_is_signed"],
        ["raw_event", "metadata", "source_is_signed"],
        ["raw_event", "enrichment", "source_is_signed"],
        ["raw_event", "enrichment", "metadata", "source_is_signed"],
        ["detection", "source_is_signed"],
    ]))


def ntdll_known_tool_source(ctx: dict[str, Any]) -> bool:
    source_name = basename(first(
        get_path(ctx, ["raw_event", "source_process"]),
        get_path(ctx, ["raw_event", "metadata", "source_process"]),
        get_path(ctx, ["raw_event", "source_process_name"]),
        get_path(ctx, ["process", "name"]),
    ))
    source_path = text(first(
        get_path(ctx, ["raw_event", "source_path"]),
        get_path(ctx, ["raw_event", "metadata", "source_path"]),
        get_path(ctx, ["process", "path"]),
        get_path(ctx, ["process", "image_path"]),
    )).replace("/", "\\")
    return source_name in NTDLL_KNOWN_TOOL_BASENAMES or any(
        marker in source_path for marker in NTDLL_KNOWN_TOOL_PATH_MARKERS
    )


def ntdll_cross_process_legitimacy(ctx: dict[str, Any]) -> bool:
    return (
        ntdll_write_detection(ctx)
        and ntdll_cross_process_target(ctx)
        and not ntdll_credential_target(ctx)
        and not ntdll_export_table_target(ctx)
        and not ntdll_rwx_region(ctx)
        and not ntdll_thread_execution_context(ctx)
        and (ntdll_source_signed(ctx) or ntdll_known_tool_source(ctx))
    )


def ntdll_cross_process_legitimacy_reason(ctx: dict[str, Any]) -> str:
    if ntdll_source_signed(ctx):
        return "cross_process_ntdll_write_legitimate_signed_source"
    return "cross_process_ntdll_write_legitimate_known_tool"


def ntdll_self_write_no_permission_transition(ctx: dict[str, Any]) -> bool:
    source_pid = ntdll_source_pid(ctx)
    target_pid = ntdll_target_pid(ctx)
    old_protection = text(first_ctx(ctx, [["raw_event", "old_protection_str"], ["raw_event", "old_protection"]]))
    new_protection = text(first_ctx(ctx, [["raw_event", "new_protection_str"], ["raw_event", "new_protection"]]))
    return (
        ntdll_write_detection(ctx)
        and not blank(source_pid)
        and str(source_pid) == str(target_pid)
        and "ntdll" in ntdll_target_function(ctx)
        and ".text" in ntdll_target_function(ctx)
        and old_protection == "page_execute_read"
        and new_protection == "page_execute_read"
    )


def dotnet_ngen_runtime_maintenance(ctx: dict[str, Any]) -> bool:
    path = process_path(ctx).replace("/", "\\")
    return (
        ntdll_write_detection(ctx)
        and process_name(ctx) == "ngentask.exe"
        and parent_name(ctx) == "taskhostw.exe"
        and "\\windows\\microsoft.net\\framework\\" in path
        and "\\ngentask.exe" in path
        and "/runtimewide" in command_line(ctx)
    )


def dotnet_ngen_masquerade(ctx: dict[str, Any]) -> bool:
    path = process_path(ctx).replace("/", "\\")
    return ntdll_write_detection(ctx) and process_name(ctx) == "ngentask.exe" and "\\users\\" in path and "\\temp\\" in path


def edge_update_etw_patch(ctx: dict[str, Any]) -> bool:
    rule = detection_name(ctx)
    etw_tamper_rule = rule.startswith("etw_") or "t1562.006" in mitre_technique(ctx)
    cmdline = command_line(ctx)
    benign_cmd = cmdline.endswith("microsoftedgeupdate.exe /c") or (
        "microsoftedgeupdate.exe" in cmdline
        and " /ua " in cmdline
        and ("/installsource scheduler" in cmdline or "/installsource core" in cmdline)
    )
    return (
        etw_tamper_rule
        and process_name(ctx) == "microsoftedgeupdate.exe"
        and parent_name(ctx) in {"", "svchost.exe", "microsoftedgeupdate.exe"}
        and "\\program files (x86)\\microsoft\\edgeupdate\\microsoftedgeupdate.exe" in process_path(ctx).replace("/", "\\")
        and benign_cmd
    )


def contextless_etw_tamper(ctx: dict[str, Any]) -> bool:
    if not detection_name(ctx).startswith("etw_") or "t1562.006" not in mitre_technique(ctx):
        return False
    context_values = [
        ctx["process"].get("name"),
        ctx["process"].get("process_name"),
        ctx["process"].get("path"),
        ctx["process"].get("image_path"),
        ctx["process"].get("command_line"),
        ctx["process"].get("cmdline"),
        ctx["raw_event"].get("process_name"),
        ctx["raw_event"].get("path"),
        ctx["raw_event"].get("image_path"),
        ctx["raw_event"].get("command_line"),
        ctx["raw_event"].get("provider_name"),
        ctx["raw_event"].get("session_name"),
        ctx["raw_event"].get("operation"),
        ctx["raw_event"].get("target_provider"),
        ctx["raw_event"].get("target_session"),
    ]
    return all(blank(value) for value in context_values)


def lsass_self_event(ctx: dict[str, Any]) -> bool:
    normalized_path = process_path(ctx).replace("/", "\\")
    return (
        process_name(ctx) == "lsass.exe"
        and parent_name(ctx) == "wininit.exe"
        and "\\windows\\system32\\lsass.exe" in normalized_path
    )


def trusted_macos_operator_parent(ctx: dict[str, Any]) -> bool:
    parent = parent_name(ctx)
    ppath = parent_path(ctx)
    return parent in {"tamandua edr", "tamandua-agent", "zsh", "bash", "sh", "codex"} or "/tamandua" in ppath or "/.codex/" in ppath


def macos_launchctl_tamandua_command(cmdline: str) -> bool:
    return "launchctl" in cmdline and "com.tamandua." in cmdline and any(
        token in cmdline for token in [" print ", " bootstrap ", " bootout ", " kickstart ", " enable "]
    )


def macos_diagnostic_command(proc: str, cmdline: str) -> bool:
    return (
        (proc == "lsof" and ("-i" in cmdline or "-n" in cmdline))
        or (proc == "netstat" and ("-an" in cmdline or "-anv" in cmdline))
        or (proc == "scutil" and ("--dns" in cmdline or "--proxy" in cmdline))
        or (proc == "plutil" and "-lint" in cmdline)
        or proc == "sw_vers"
    )


def macos_operational_high_risk(ctx: dict[str, Any]) -> bool:
    proc = process_name(ctx)
    path = process_path(ctx)
    cmdline = command_line(ctx)
    trusted = trusted_macos_operator_parent(ctx)
    if proc == "osascript":
        return path == "/usr/bin/osascript" and trusted and "do shell script" in cmdline and "with administrator privileges" in cmdline and "tamandua" in cmdline
    if proc == "launchctl":
        return path in {"/bin/launchctl", "/usr/bin/launchctl"} and trusted and macos_launchctl_tamandua_command(cmdline)
    if proc in {"lsof", "netstat", "scutil", "plutil", "sw_vers"}:
        return path.startswith("/usr/") and trusted and macos_diagnostic_command(proc, cmdline)
    return False


def macos_benign_unusual_time(ctx: dict[str, Any]) -> bool:
    proc = process_name(ctx)
    path = process_path(ctx)
    cmdline = command_line(ctx)
    return proc in {"launchctl", "lsof", "netstat", "plutil", "sw_vers", "scutil"} and path.startswith("/") and (
        macos_launchctl_tamandua_command(cmdline) or macos_diagnostic_command(proc, cmdline)
    )


def behavioral_score_only_unusual_time(ctx: dict[str, Any]) -> bool:
    if detection_name(ctx) != "behavioral_high_risk_score":
        return False
    factors = ctx["raw_event"].get("factors") or []
    if not isinstance(factors, list) or len(factors) != 1 or not isinstance(factors[0], dict):
        return False
    return text(factors[0].get("name")) == "unusual_time"


def windows_trusted_operator_parent(ctx: dict[str, Any]) -> bool:
    parent = parent_name(ctx)
    ppath = parent_path(ctx).replace("/", "\\")
    return parent in {"codex.exe", "tamandua-agent.exe", "tamandua_agent.exe", "powershell.exe", "pwsh.exe", "cmd.exe"} or "\\@openai\\codex\\" in ppath or "\\tamandua\\" in ppath


def windows_operational_high_risk(ctx: dict[str, Any]) -> bool:
    proc = process_name(ctx)
    cmdline = command_line(ctx)
    return (
        detection_name(ctx) == "behavioral_high_risk_score"
        and proc in {"pwsh.exe", "powershell.exe", "cmd.exe"}
        and windows_trusted_operator_parent(ctx)
        and any(token in cmdline for token in ("get-ciminstance", "get-process", "tasklist", "sc.exe", "reg query"))
    )


def windows_benign_unusual_time(ctx: dict[str, Any]) -> bool:
    if detection_name(ctx) != "behavioral_unusual_execution_time":
        return False
    path = process_path(ctx).replace("/", "\\")
    return process_name(ctx) in {"searchprotocolhost.exe", "searchfilterhost.exe", "trustedinstaller.exe"} and "\\windows\\system32\\" in path


def benchmark_persistence_setup(ctx: dict[str, Any]) -> bool:
    return (
        detection_name(ctx) == "registry_persistence"
        and "\\software\\microsoft\\windows\\currentversion\\run" in registry_key(ctx)
        and registry_value(ctx) == "tamanduabenchrun"
        and "tamandua-bench" in registry_data(ctx)
    )


def edge_webview_runonce_cleanup(ctx: dict[str, Any]) -> bool:
    return (
        detection_name(ctx) == "registry_t1547_001"
        and "\\software\\microsoft\\windows\\currentversion\\runonce" in registry_key(ctx)
        and "msedgewebview" in registry_value(ctx)
        and "\\microsoft\\edgewebview\\" in registry_data(ctx)
        and "--delete-old-versions" in registry_data(ctx)
    )


def nvidia_rundll32_rxdiag(ctx: dict[str, Any]) -> bool:
    parent_signer = text(first(ctx["process"].get("parent_signer"), ctx["raw_event"].get("parent_signer")))
    parent = parent_path(ctx).replace("/", "\\")
    cmdline = command_line(ctx).replace("/", "\\")
    return (
        detection_name(ctx) == "behavioral_rundll32_network"
        and process_name(ctx) == "rundll32.exe"
        and parent_name(ctx) == "nvcontainer.exe"
        and "\\program files\\nvidia corporation\\nvcontainer\\" in parent
        and "nvidia" in parent_signer
        and "\\windows\\system32\\rxdiag.dll,rxentry" in cmdline
    )


def rfc1918_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip.version == 4
        and (
            str(ip).startswith("10.")
            or str(ip).startswith("192.168.")
            or any(str(ip).startswith(f"172.{octet}.") for octet in range(16, 32))
        )
    )


def benign_rapid_internal_connection(ctx: dict[str, Any]) -> bool:
    signer = text(first(ctx["process"].get("signer"), ctx["raw_event"].get("signer")))
    return (
        detection_name(ctx) == "ndr_rapid_internal_connections"
        and process_name(ctx) == "synergy-core"
        and "synergy" in signer
        and rfc1918_ip(network_remote_ip(ctx))
    )


def invalid_ioc_zero(ctx: dict[str, Any]) -> bool:
    return detection_name(ctx) == "retroactive_ioc_match" and network_remote_ip(ctx) == "0.0.0.0"


def kernel_memory_without_process_context(ctx: dict[str, Any]) -> bool:
    return detection_name(ctx).startswith("kernel_") and not ctx["evidence"].get("process") and blank(ctx["raw_event"].get("source_pid"))


def service_registry_missing_process_context(ctx: dict[str, Any]) -> bool:
    return (
        detection_name(ctx) == "registry_t1543_003"
        and "\\system\\currentcontrolset\\services\\" in registry_key(ctx)
        and not ctx["evidence"].get("process")
    )


def windows_core_service_chain(ctx: dict[str, Any]) -> bool:
    path = process_path(ctx).replace("/", "\\")
    cmdline = command_line(ctx).replace("/", "\\")
    return (
        detection_name(ctx) == "system file execution location anomaly"
        and process_name(ctx) == "services.exe"
        and parent_name(ctx) == "wininit.exe"
        and "\\windows\\system32\\lsass.exe" in path
        and "powershell" not in cmdline
        and " -enc " not in cmdline
    )


def replay_decision(item: dict[str, Any]) -> dict[str, Any]:
    ctx = fixture_context(item)
    severity = ctx["severity"] or "info"
    title = ctx["title"]
    reason: str | None = None
    new_severity = severity
    severity_adjusted: bool | None = None

    if invalid_ioc_zero(ctx):
        new_severity, reason = None, "invalid_ioc_0_0_0_0"
        severity_adjusted = False
    elif dotnet_ngen_runtime_maintenance(ctx):
        new_severity, reason = "info", "benign_dotnet_ngen_runtime_maintenance_structured"
    elif dotnet_ngen_masquerade(ctx):
        pass
    elif ntdll_self_write_no_permission_transition(ctx):
        new_severity, reason = "medium", "ntdll_self_write_no_permission_transition_structured"
    elif contextless_ntdll_write(ctx):
        new_severity, reason = "medium", "ntdll_write_missing_target_context"
    elif ntdll_cross_process_legitimacy(ctx):
        new_severity, reason = "medium", ntdll_cross_process_legitimacy_reason(ctx)
    elif edge_update_etw_patch(ctx):
        new_severity, reason = "medium", "edge_update_etw_patch_without_actionable_context"
    elif contextless_etw_tamper(ctx):
        new_severity, reason = "medium", "etw_tamper_missing_actionable_context"
    elif title == "agent detection: behavioral_lsass_access" and lsass_self_event(ctx):
        new_severity, reason = "info", "lsass_self_process_event_structured"
    elif title == "agent detection: behavioral_high_risk_score" and macos_operational_high_risk(ctx):
        new_severity, reason = "medium", "macos_behavioral_score_only_operational_tool_context"
    elif title == "agent detection: behavioral_unusual_execution_time" and macos_benign_unusual_time(ctx):
        new_severity, reason = "info", "macos_benign_unusual_execution_time_structured"
    elif behavioral_score_only_unusual_time(ctx):
        new_severity, reason = "low", "behavioral_score_only_unusual_time_structured"
    elif windows_operational_high_risk(ctx):
        new_severity, reason = "medium", "behavioral_score_only_operational_tool_context"
    elif windows_benign_unusual_time(ctx):
        new_severity, reason = "info", "benign_unusual_execution_time_structured"
    elif benchmark_persistence_setup(ctx):
        new_severity, reason = "info", "benign_benchmark_persistence_setup_structured"
    elif edge_webview_runonce_cleanup(ctx):
        new_severity, reason = "info", "benign_edge_webview_runonce_cleanup_structured"
    elif nvidia_rundll32_rxdiag(ctx):
        new_severity, reason = "low", "benign_nvidia_rundll32_rxdiag_structured"
    elif benign_rapid_internal_connection(ctx):
        new_severity, reason = "low", "benign_rapid_internal_connection_structured"
    elif kernel_memory_without_process_context(ctx):
        new_severity, reason = "medium", "kernel_memory_detection_without_process_context"
    elif service_registry_missing_process_context(ctx):
        new_severity, reason = "medium", "service_registry_change_missing_process_context"
    elif windows_core_service_chain(ctx):
        new_severity, reason = "info", "windows_core_service_process_chain_structured"

    return {
        "alert_severity": new_severity,
        "severity_adjusted": severity_adjusted if severity_adjusted is not None else reason is not None,
        "fp_reason": reason,
        "original_severity": severity,
        "decision_source": "offline_replay_structured_fp_policy",
        "source_parity_reference": "apps/tamandua_server/lib/tamandua_server/alerts.ex obvious_false_positive_reason/1",
    }


def make_result(fixture_file: Path, item: dict[str, Any]) -> dict[str, Any]:
    expected = item.get("expected") or {}
    observed = replay_decision(item)
    mismatches = []
    for key in ["alert_severity", "severity_adjusted", "fp_reason"]:
        if observed.get(key) != expected.get(key):
            mismatches.append({"field": key, "expected": expected.get(key), "observed": observed.get(key)})
    passed = not mismatches
    return {
        "id": f"offline-replay-{fixture_file.stem.replace('_', '-')}-{item.get('id')}",
        "name": f"Offline replay decision: {item.get('id')}",
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else "detector",
        "execution_class": "offline_replay",
        "claim_level": "replay_decision_report_only",
        "executor_used": "telemetry_replay_executor",
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": "severity_policy",
        "coverage": {
            "telemetry": "ok",
            "fields": "ok" if passed else "mismatch",
            "detection": "ok",
            "alert": "ok" if passed else "mismatch",
            "correlation": "not_expected",
            "driver_raw": "not_expected",
            "timeline": "not_expected",
            "values": "ok" if passed else "mismatch",
        },
        "evidence": {
            "fixture_file": str(fixture_file.relative_to(ROOT)).replace("\\", "/"),
            "fixture_id": item.get("id"),
            "event_type": item.get("event_type"),
            "observed": observed,
            "expected": expected,
            "mismatches": mismatches,
            "live_alert_mutation": False,
            "db_access": False,
        },
        "missing_expected_fields": [m["field"] for m in mismatches],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [] if passed else ["severity_policy_mismatch"],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [],
    }


def load_tests(fixture_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    tests: list[dict[str, Any]] = []
    fixture_errors: list[str] = []
    for path in sorted(fixture_dir.glob("*_false_positive_replay_v1.json")):
        errors = validate_fixture_file(path)
        fixture_errors.extend(errors)
        if errors:
            continue
        data = load_json(path)
        for item in data.get("fixtures", []):
            tests.append(make_result(path, item))
    return tests, fixture_errors


def build_summary(tests: list[dict[str, Any]], fixture_errors: list[str]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered + len(fixture_errors)
    gaps = []
    gap_counts: dict[str, int] = {}
    for test in tests:
        if test["status"] == "covered":
            continue
        gaps.append({
            "test_id": test["id"],
            "status": test["status"],
            "gap_category": test["gap_category"],
            "validation_category": test.get("validation_category"),
            "missing_expected_fields": test.get("missing_expected_fields", []),
            "missing_expected_telemetry": [],
            "missing_expected_detections": [],
            "missing_expected_alerts": test.get("missing_expected_alerts", []),
            "missing_expected_correlations": [],
            "missing_expected_driver_raw_event_types": [],
            "execution_class": test.get("execution_class"),
            "fallback_used": False,
            "tactics": [],
            "techniques": [],
        })
        gap_counts[test["gap_category"]] = gap_counts.get(test["gap_category"], 0) + 1
    if fixture_errors:
        gap_counts["fixture-schema"] = len(fixture_errors)
        gaps.append({
            "test_id": "fixture-schema",
            "status": "missed",
            "gap_category": "fixture-schema",
            "validation_category": "fixture_schema",
            "missing_expected_fields": fixture_errors,
            "missing_expected_telemetry": [],
            "missing_expected_detections": [],
            "missing_expected_alerts": [],
            "missing_expected_correlations": [],
            "missing_expected_driver_raw_event_types": [],
            "execution_class": "fixture_schema_probe",
            "fallback_used": False,
            "tactics": [],
            "techniques": [],
        })
    return {
        "tests": len(tests),
        "covered": covered,
        "partial": 0,
        "missed": missed,
        "planned": 0,
        "execution_failed": 0,
        "unknown_source_events": 0,
        "unexpected_high_or_critical_events": 0,
        "unexpected_high_or_critical_alerts": 0,
        "missing_expected_fields": missed,
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"telemetry_replay_executor": len(tests)},
        "execution_class_counts": {"offline_replay": len(tests)},
        "claim_level_counts": {"replay_decision_report_only": len(tests)},
        "category_coverage": {"severity_policy": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": gap_counts,
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 78 if passed else int(55 * covered_rate),
        "maturity_band": "offline-replay-decision-validation" if passed else "offline-replay-decision-gaps",
        "recommended_claim": (
            "Offline sanitized FP/severity replay decisions are validated; no historical DB replay or live alert mutation claim"
            if passed
            else "Offline replay decision mismatches exist; do not use replay as a release gate"
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if passed else covered_rate,
        "context_quality": 1.0 if passed else covered_rate,
        "analytic_quality": 1.0 if passed else covered_rate,
        "noise_quality": 1.0 if passed else covered_rate,
        "driver_quality": 1.0,
        "upstream_rate": 0.0,
        "blocking_gaps": [] if passed else sorted(summary["gap_category_counts"].keys()),
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- Scope: offline sanitized replay only; no DB access, live alert mutation, or endpoint execution.",
        "",
        "| Test | Status | Observed Severity | FP Reason |",
        "|------|--------|-------------------|-----------|",
    ]
    for test in report["tests"]:
        observed = test["evidence"]["observed"]
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{observed['alert_severity']}` | `{observed['fp_reason'] or '-'}` |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=FIXTURE_DIR)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests, fixture_errors = load_tests(args.fixture_dir)
    summary = build_summary(tests, fixture_errors)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "telemetry-replay",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "telemetry_replay_offline_fp_severity",
                "requires_persisted_events": False,
                "requires_driver_health": False,
                "max_unknown_source_events": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
            },
        },
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["offline_replay_decision_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "telemetry-replay",
                "fail_on_missed": True,
                "fail_on_partial": False,
                "max_unknown_source": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
                "require_upstream": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Validates sanitized offline FP/severity decisions only. It does not execute historical DB replay, "
            "persist retrospective results, mutate live alerts, or prove endpoint collection."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "telemetry-replay",
        "summary": summary,
        "quality_gate": report["quality_gate"],
        "scorecard": report["scorecard"],
        "tests": tests,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{run_id}.json"
    comparison_path = args.output_dir / f"{run_id}.comparison.json"
    md_path = args.output_dir / f"{run_id}.md"
    write_json(json_path, report)
    write_json(comparison_path, comparison)
    write_markdown(md_path, report)
    print(f"json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
