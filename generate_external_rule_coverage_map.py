#!/usr/bin/env python3
"""Generate report-only benchmark coverage from external rule metadata.

This intentionally does not copy external detection queries, Sigma/Wazuh rule
bodies, notes, or rule logic. The output is a Tamandua coverage backlog derived
from factual metadata: platform, rule id, severity, risk score, ATT&CK tactic,
and ATT&CK technique.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
ROADMAP_DIR = ROOT / "tools" / "detection_validation" / "roadmaps"
PROFILE_DIR = ROOT / "tools" / "detection_validation" / "profiles"
DOC_DIR = ROOT / "docs" / "benchmarks"

PLATFORM_DIRS = ("windows", "linux", "macos")
LICENSE_NAME = "Elastic License v2"
SIGMAHQ_LICENSE = "Detection Rule License 1.1"
WAZUH_LICENSE = "Wazuh ruleset upstream license; metadata-only use, verify before direct reuse"
LOLBAS_LICENSE = "GPL-3.0; metadata-only use, verify before direct reuse"
GTFOBINS_LICENSE = "GPL-3.0; metadata-only use, verify before direct reuse"
SPLUNK_SECURITY_CONTENT_LICENSE = "Apache-2.0"
AZURE_SENTINEL_LICENSE = "MIT"
DEFAULT_ELASTIC_ROOT = Path("D:/treant/external/elastic-detection-rules")
DEFAULT_SIGMAHQ_ROOT = Path("D:/treant/external/sigmahq-sigma")
DEFAULT_WAZUH_ROOT = Path("D:/treant/external/wazuh-ruleset")
DEFAULT_LOLBAS_ROOT = Path("D:/treant/external/lolbas")
DEFAULT_GTFOBINS_ROOT = Path("D:/treant/external/gtfobins")
DEFAULT_SPLUNK_ROOT = Path("D:/treant/external/splunk-security-content")
DEFAULT_SENTINEL_ROOT = Path("D:/treant/external/azure-sentinel")

TACTIC_SLUGS = {
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}

PLATFORM_COMMANDS = {
    "windows": 'cmd.exe /d /c "echo tamandua-external-coverage-%TEST_ID%"',
    "linux": "sh -lc 'echo tamandua-external-coverage-%TEST_ID%'",
    "macos": "sh -lc 'echo tamandua-external-coverage-%TEST_ID%'",
}

SEMANTIC_EXECUTION_BATCH_SIZE = 50
LIVE_RESPONSE_AUDIT_TELEMETRY = "live_response_command_completed"
LIVE_RESPONSE_AUDIT_REQUIRED_FIELDS = ["agent_id", "hostname", "command", "session_id"]
PROCESS_REQUIRED_FIELDS_BY_PLATFORM = {
    "windows": ["agent_id", "hostname", "process_name", "command_line", "parent_process_name"],
    "linux": ["agent_id", "hostname", "process_name", "command_line", "user"],
    "macos": ["agent_id", "hostname", "process_name", "command_line", "user"],
}
SEMANTIC_EXECUTION_COMMANDS = {
    "windows": 'cmd.exe /d /c "echo tamandua-semantic-rewrite-%TEST_ID% & whoami & hostname & ver"',
    "linux": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; hostname; uname -a'",
    "macos": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; hostname; sw_vers 2>/dev/null || uname -a'",
}
# Linux/macOS semantic rewrite probes rely on polling-based process telemetry
# until auditd/eBPF/EndpointSecurity are wired as event-driven collectors. Keep
# marker-bearing shell processes alive across throttled collector intervals.
PROCESS_POLLING_DWELL_SECONDS = 75

SEMANTIC_TECHNIQUE_COMMANDS = {
    "windows": {
        "T1003": "powershell.exe -NoProfile -Command \"Get-Process lsass -ErrorAction SilentlyContinue | Select-Object -First 1 Id,ProcessName | Out-Null; Write-Output 'tamandua-semantic-rewrite-%TEST_ID%'\"",
        "T1021": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & net use 2>nul & qwinsta 2>nul || whoami\"",
        "T1027": "powershell.exe -NoProfile -Command \"[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('tamandua-semantic-rewrite-%TEST_ID%')) | Out-Null\"",
        "T1036": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID%>%TEMP%\\svch0st-tamandua-%TEST_ID%.txt & type %TEMP%\\svch0st-tamandua-%TEST_ID%.txt >nul & del /f /q %TEMP%\\svch0st-tamandua-%TEST_ID%.txt\"",
        "T1047": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & tasklist.exe /FI \"\"IMAGENAME eq powershell.exe\"\" 2>nul || whoami\"",
        "T1053": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & schtasks.exe /Query /FO LIST /TN \\Microsoft\\Windows\\Defrag\\ScheduledDefrag 2>nul || schtasks.exe /Query /FO LIST | more\"",
        "T1053.005": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & schtasks.exe /Query /FO LIST /TN \\Microsoft\\Windows\\Defrag\\ScheduledDefrag 2>nul || schtasks.exe /Query /FO LIST | more\"",
        "T1055": "powershell.exe -NoProfile -Command \"Get-Process | Select-Object -First 3 Id,ProcessName | Out-Null; Write-Output 'tamandua-semantic-rewrite-%TEST_ID%'\"",
        "T1059": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & whoami & hostname\"",
        "T1059.001": "powershell.exe -NoProfile -Command \"Write-Output 'tamandua-semantic-rewrite-%TEST_ID%'; Get-ExecutionPolicy | Out-Null\"",
        "T1059.003": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & set COMSPEC\"",
        "T1071": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & nslookup localhost 2>nul || ping -n 1 127.0.0.1\"",
        "T1078": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & whoami /user & whoami /groups\"",
        "T1083": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & dir %TEMP%\"",
        "T1098": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & net user %USERNAME% 2>nul || whoami /user\"",
        "T1105": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & echo tamandua>%TEMP%\\tamandua-transfer-src-%TEST_ID%.txt & copy /Y %TEMP%\\tamandua-transfer-src-%TEST_ID%.txt %TEMP%\\tamandua-transfer-dst-%TEST_ID%.txt >nul & del /f /q %TEMP%\\tamandua-transfer-src-%TEST_ID%.txt %TEMP%\\tamandua-transfer-dst-%TEST_ID%.txt\"",
        "T1110": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & net accounts 2>nul || whoami\"",
        "T1112": "cmd.exe /d /c \"reg add HKCU\\Software\\TamanduaBench /v SemanticRewrite /t REG_SZ /d tamandua-semantic-rewrite-%TEST_ID% /f & reg query HKCU\\Software\\TamanduaBench /v SemanticRewrite & reg delete HKCU\\Software\\TamanduaBench /f\"",
        "T1114": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & dir %USERPROFILE% 2>nul\"",
        "T1127": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & where csc.exe 2>nul || where msbuild.exe 2>nul || ver\"",
        "T1133": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & qwinsta 2>nul || query user 2>nul || whoami\"",
        "T1190": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & curl.exe -I http://127.0.0.1/ 2>nul || ver\"",
        "T1204": "cmd.exe /d /c \"echo @echo tamandua-semantic-rewrite-%TEST_ID%>%TEMP%\\tamandua-user-exec.bat & call %TEMP%\\tamandua-user-exec.bat & del /f /q %TEMP%\\tamandua-user-exec.bat\"",
        "T1566.001": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID%>%TEMP%\\tamandua-attachment.txt & type %TEMP%\\tamandua-attachment.txt >nul & del /f /q %TEMP%\\tamandua-attachment.txt\"",
        "T1218": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & where rundll32.exe & where regsvr32.exe\"",
        "T1484": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & gpresult /R 2>nul || whoami /groups\"",
        "T1485": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID%>%TEMP%\\tamandua-delete-safe.txt & type %TEMP%\\tamandua-delete-safe.txt >nul & del /f /q %TEMP%\\tamandua-delete-safe.txt\"",
        "T1489": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & sc.exe query Spooler 2>nul || sc.exe query\"",
        "T1499": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & tasklist | findstr /I cmd\"",
        "T1543": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & sc.exe query Spooler 2>nul || sc.exe query\"",
        "T1546": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & schtasks.exe /Query /FO LIST /TN \\Microsoft\\Windows\\Defrag\\ScheduledDefrag 2>nul || schtasks.exe /Query /FO LIST | more\"",
        "T1548": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & whoami /priv\"",
        "T1552": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & set USERPROFILE & dir %APPDATA% 2>nul\"",
        "T1562": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & sc.exe query WinDefend 2>nul || netsh advfirewall show allprofiles\"",
        "T1574": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & where cmd.exe & where powershell.exe\"",
        "T1685": "cmd.exe /d /c \"echo tamandua-semantic-rewrite-%TEST_ID% & echo prompt-injection-canary>%TEMP%\\tamandua-ai-guardrail.txt & type %TEMP%\\tamandua-ai-guardrail.txt >nul & del /f /q %TEMP%\\tamandua-ai-guardrail.txt\"",
    },
    "linux": {
        "T1003": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; test -r /etc/passwd && head -n 1 /etc/passwd >/dev/null; id'",
        "T1021": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; getent hosts localhost >/dev/null || true; id'",
        "T1027": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID% | base64 >/tmp/tamandua-semantic-%TEST_ID%.b64; rm -f /tmp/tamandua-semantic-%TEST_ID%.b64'",
        "T1036": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; p=/tmp/.systemd-tamandua-%TEST_ID%; echo tamandua > \"$p\"; ls -la \"$p\" >/dev/null; rm -f \"$p\"'",
        "T1059": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; uname -a'",
        "T1059.004": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; printf tamandua-shell >/dev/null'",
        "T1059.006": "sh -lc 'python3 -c \"print(\\\"tamandua-semantic-rewrite-%TEST_ID%\\\")\" 2>/dev/null || python -c \"print(\\\"tamandua-semantic-rewrite-%TEST_ID%\\\")\" 2>/dev/null || echo tamandua-semantic-rewrite-%TEST_ID%'",
        "T1068": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; uname -a; id; find /usr/bin -perm -4000 -maxdepth 1 -type f 2>/dev/null | head -n 3 >/dev/null || true'",
        "T1071": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; getent hosts localhost >/dev/null 2>&1 || printf localhost >/dev/null'",
        "T1078": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; whoami; last -n 1 2>/dev/null || true'",
        "T1083": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; find /tmp -maxdepth 1 -type f 2>/dev/null | head -n 3 >/dev/null || true'",
        "T1098": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; getent passwd \"$USER\" >/dev/null 2>&1 || true'",
        "T1105": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; src=/tmp/tamandua-transfer-src-%TEST_ID%; dst=/tmp/tamandua-transfer-dst-%TEST_ID%; printf tamandua > \"$src\"; cp \"$src\" \"$dst\"; rm -f \"$src\" \"$dst\"'",
        "T1110": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; lastb -n 1 2>/dev/null || true; id'",
        "T1133": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; ss -tn 2>/dev/null | head -n 3 >/dev/null || netstat -tn 2>/dev/null | head -n 3 >/dev/null || true'",
        "T1190": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; curl -I http://127.0.0.1/ >/dev/null 2>&1 || true'",
        "T1204": "sh -lc 'p=/tmp/tamandua-user-exec-%TEST_ID%.sh; printf \"#!/bin/sh\\necho tamandua-semantic-rewrite-%TEST_ID%\\n\" > \"$p\"; sh \"$p\"; rm -f \"$p\"'",
        "T1499": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; ps -eo pid,comm | head -n 5 >/dev/null'",
        "T1543": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; systemctl list-units --type=service --no-pager 2>/dev/null | head -n 3 >/dev/null || service --status-all 2>/dev/null | head -n 3 >/dev/null || true'",
        "T1546": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; crontab -l 2>/dev/null || true; ls /etc/cron* >/dev/null 2>&1 || true'",
        "T1548": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; find /usr/bin -perm -4000 -maxdepth 1 -type f 2>/dev/null | head -n 3 >/dev/null || true'",
        "T1552": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; env | head -n 3 >/dev/null; test -r ~/.bash_history && tail -n 1 ~/.bash_history >/dev/null || true'",
        "T1562": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; systemctl status auditd >/dev/null 2>&1 || true; ps -eo comm | grep -Ei \"audit|falco|osquery\" >/dev/null 2>&1 || true'",
        "T1574": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; printf tamandua >/tmp/libtamandua-%TEST_ID%.so; ls /tmp/libtamandua-%TEST_ID%.so >/dev/null; rm -f /tmp/libtamandua-%TEST_ID%.so'",
    },
    "macos": {
        "T1003": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; dscl . -list /Users 2>/dev/null | head -n 3 >/dev/null || id'",
        "T1021": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; dscacheutil -q host -a name localhost >/dev/null 2>&1 || true; id'",
        "T1027": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID% | base64 >/tmp/tamandua-semantic-%TEST_ID%.b64; rm -f /tmp/tamandua-semantic-%TEST_ID%.b64'",
        "T1036": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; p=/tmp/.launchd-tamandua-%TEST_ID%; echo tamandua > \"$p\"; ls -la \"$p\" >/dev/null; rm -f \"$p\"'",
        "T1059": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; sw_vers 2>/dev/null || uname -a'",
        "T1059.004": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; printf tamandua-shell >/dev/null'",
        "T1059.006": "sh -lc 'python3 -c \"print(\\\"tamandua-semantic-rewrite-%TEST_ID%\\\")\" 2>/dev/null || python -c \"print(\\\"tamandua-semantic-rewrite-%TEST_ID%\\\")\" 2>/dev/null || echo tamandua-semantic-rewrite-%TEST_ID%'",
        "T1071": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; dscacheutil -q host -a name localhost >/dev/null 2>&1 || printf localhost >/dev/null'",
        "T1078": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; whoami; last -1 2>/dev/null || true'",
        "T1083": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; find /tmp -maxdepth 1 -type f 2>/dev/null | head -n 3 >/dev/null || true'",
        "T1110": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; last -1 2>/dev/null || true; id'",
        "T1133": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; netstat -an 2>/dev/null | head -n 3 >/dev/null || true'",
        "T1190": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; curl -I http://127.0.0.1/ >/dev/null 2>&1 || true'",
        "T1204": "sh -lc 'p=/tmp/tamandua-user-exec-%TEST_ID%.sh; printf \"#!/bin/sh\\necho tamandua-semantic-rewrite-%TEST_ID%\\n\" > \"$p\"; sh \"$p\"; rm -f \"$p\"'",
        "T1543": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; launchctl list 2>/dev/null | head -n 3 >/dev/null || true'",
        "T1546": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; ls ~/Library/LaunchAgents /Library/LaunchAgents >/dev/null 2>&1 || true'",
        "T1548": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; id; sudo -n -l >/dev/null 2>&1 || true'",
        "T1552": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; env | head -n 3 >/dev/null; security list-keychains >/dev/null 2>&1 || true'",
        "T1562": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; spctl --status >/dev/null 2>&1 || true; ps -axo comm | grep -Ei \"xprotect|osquery|falco\" >/dev/null 2>&1 || true'",
        "T1574": "sh -lc 'echo tamandua-semantic-rewrite-%TEST_ID%; printf tamandua >/tmp/libtamandua-%TEST_ID%.dylib; ls /tmp/libtamandua-%TEST_ID%.dylib >/dev/null; rm -f /tmp/libtamandua-%TEST_ID%.dylib'",
    },
}

TECHNIQUE_INTENTS = {
    "T1003": "credential material access against OS secrets, memory, or authentication stores",
    "T1021": "remote services used for lateral movement or administrative pivoting",
    "T1027": "obfuscated command, script, payload, or artifact execution",
    "T1036": "masquerading through misleading process, file, path, service, or account naming",
    "T1047": "WMI or equivalent management interface execution and discovery",
    "T1055": "process injection or suspicious cross-process memory/thread activity",
    "T1059": "command and scripting interpreter execution",
    "T1059.001": "PowerShell execution patterns with suspicious arguments or encoded content",
    "T1059.003": "Windows command shell execution patterns",
    "T1059.004": "Unix shell execution patterns",
    "T1059.006": "Python interpreter execution patterns",
    "T1068": "local privilege escalation exploit indicators",
    "T1071": "application-layer command and control over common protocols",
    "T1078": "valid account activity that deviates from expected host, time, or privilege context",
    "T1083": "file and directory discovery behavior",
    "T1098": "account manipulation, permission changes, or credential material changes",
    "T1110": "brute force or repeated authentication attempts",
    "T1112": "registry or configuration modification for evasion or persistence",
    "T1114": "email collection or mailbox access behavior",
    "T1133": "external remote service access patterns",
    "T1190": "public-facing application exploitation indicators",
    "T1204": "user execution of suspicious downloaded, scripted, or attachment-backed content",
    "T1218": "signed binary proxy execution",
    "T1484": "domain or group policy modification",
    "T1499": "endpoint, service, or network resource exhaustion indicators",
    "T1543": "service or daemon creation and modification for persistence",
    "T1546": "event-triggered persistence or execution hook creation",
    "T1548": "abuse of elevation control mechanisms",
    "T1552": "credential or secret discovery in files, environment, config, or history",
    "T1562": "impair defenses through logging, security tool, or policy modification",
    "T1574": "hijack execution flow through search order, library, or path manipulation",
}

PLATFORM_TELEMETRY_BASE = {
    "windows": ["process_create", "file_create", "file_modify", "registry_modify"],
    "linux": ["process_create", "file_create", "file_modify", "auth_event"],
    "macos": ["process_create", "file_create", "file_modify", "auth_event"],
}

INVENTORY: list[dict[str, Any]] = []

TECHNIQUE_TELEMETRY = {
    "T1003": ["process_access", "file_read", "security_event"],
    "T1021": ["network_connect", "auth_event", "process_create"],
    "T1047": ["process_create", "wmi_event"],
    "T1055": ["process_access", "memory_event", "process_create"],
    "T1071": ["network_connect", "dns_query", "process_create"],
    "T1078": ["auth_event", "session_start", "privilege_change"],
    "T1098": ["account_change", "privilege_change", "auth_event"],
    "T1110": ["auth_event", "failed_login", "rate_window"],
    "T1112": ["registry_modify", "process_create"],
    "T1114": ["mail_access", "network_connect", "auth_event"],
    "T1133": ["auth_event", "network_connect", "session_start"],
    "T1190": ["web_request", "process_create", "file_create"],
    "T1218": ["process_create", "image_load"],
    "T1484": ["directory_change", "registry_modify", "auth_event"],
    "T1499": ["resource_usage", "network_connect", "service_health"],
    "T1543": ["service_create", "file_create", "process_create"],
    "T1546": ["file_create", "registry_modify", "scheduled_event"],
    "T1548": ["privilege_change", "process_create", "auth_event"],
    "T1552": ["file_read", "process_create", "secret_scan"],
    "T1562": ["service_modify", "registry_modify", "process_create"],
    "T1574": ["image_load", "file_create", "process_create"],
}

TECHNIQUE_FIELD_HINTS = {
    "T1003": ["target_process", "access_mask", "file_path", "user"],
    "T1021": ["remote_address", "remote_port", "protocol", "user"],
    "T1047": ["process_name", "command_line", "parent_process_name", "user"],
    "T1055": ["source_process", "target_process", "access_mask", "call_trace"],
    "T1059": ["process_name", "command_line", "parent_process_name", "script_path"],
    "T1059.001": ["process_name", "command_line", "parent_process_name", "script_block_hash"],
    "T1059.003": ["process_name", "command_line", "parent_process_name", "working_directory"],
    "T1059.004": ["process_name", "command_line", "parent_process_name", "tty"],
    "T1059.006": ["process_name", "command_line", "parent_process_name", "script_path"],
    "T1071": ["process_name", "remote_domain", "remote_address", "protocol"],
    "T1078": ["user", "source_address", "logon_type", "host_role"],
    "T1110": ["user", "source_address", "failure_count", "time_window"],
    "T1112": ["registry_key", "registry_value", "process_name", "user"],
    "T1218": ["process_name", "command_line", "parent_process_name", "signed_status"],
    "T1484": ["policy_object", "actor_user", "change_type", "target_domain"],
    "T1543": ["service_name", "service_path", "actor_process", "user"],
    "T1546": ["trigger_path", "trigger_type", "actor_process", "user"],
    "T1562": ["security_product", "service_name", "policy_key", "actor_process"],
}


def parse_scalar(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}\s*=\s*\"([^\"]*)\"", text)
    return match.group(1) if match else None


def parse_int(text: str, key: str) -> int | None:
    match = re.search(rf"(?m)^{re.escape(key)}\s*=\s*(\d+)", text)
    return int(match.group(1)) if match else None


def parse_array(text: str, key: str) -> list[str]:
    match = re.search(rf"(?ms)^{re.escape(key)}\s*=\s*\[(.*?)\]", text)
    if not match:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def parse_yaml_scalar(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}\s*:\s*['\"]?([^'\"\n#]+)", text)
    return match.group(1).strip() if match else None


def technique_ids_from_text(text: str) -> list[str]:
    return sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)))


def infer_platforms_from_text(path: Path, text: str) -> list[str]:
    haystack = f"{path.as_posix()} {text[:6000]}".lower()
    platforms = []
    if any(token in haystack for token in ("windows", "winlog", "powershell", "sysmon", "microsoft-windows")):
        platforms.append("windows")
    if any(token in haystack for token in ("linux", "syslog", "auditd", "journald", "/etc/", "unix")):
        platforms.append("linux")
    if any(token in haystack for token in ("macos", "mac os", "darwin", "launchagent", "launchdaemon")):
        platforms.append("macos")
    if platforms:
        return platforms
    if any(token in haystack for token in ("identity", "authentication", "signin", "dns", "network", "endpoint")):
        return list(PLATFORM_DIRS)
    return []


def inventory_add(
    *,
    source: str,
    path: Path,
    root: Path,
    included: bool,
    skip_reason: str | None = None,
    rule_id: str | None = None,
    platform: str | None = None,
    techniques: list[str] | None = None,
    license_name: str | None = None,
) -> None:
    INVENTORY.append(
        {
            "source": source,
            "source_license": license_name,
            "source_rule_id": rule_id,
            "source_relative_path": path.relative_to(root).as_posix(),
            "included": included,
            "skip_reason": skip_reason,
            "platform": platform,
            "techniques": techniques or [],
        }
    )


def parse_rule(path: Path, platform: str, root: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rule_id = parse_scalar(text, "rule_id")
    name = parse_scalar(text, "name")
    if not rule_id or not name:
        inventory_add(
            source="elastic_detection_rules",
            path=path,
            root=root,
            included=False,
            skip_reason="missing_rule_id_or_name",
            rule_id=rule_id,
            platform=platform,
            license_name=LICENSE_NAME,
        )
        return None

    technique_ids = sorted(set(re.findall(r'id\s*=\s*"(T\d+(?:\.\d+)?)"', text)))
    tactic_names = sorted(set(re.findall(r"(?ms)\[rule\.threat\.tactic\].*?name\s*=\s*\"([^\"]+)\"", text)))
    tactic_slugs = sorted({TACTIC_SLUGS.get(name, name.lower().replace(" ", "-")) for name in tactic_names})

    tags = parse_array(text, "tags")
    data_sources = sorted(
        {
            tag.split(":", 1)[1].strip()
            for tag in tags
            if tag.lower().startswith("data source:")
        }
    )

    record = {
        "source": "elastic_detection_rules",
        "source_license": LICENSE_NAME,
        "source_rule_id": rule_id,
        "source_rule_name": name,
        "source_relative_path": path.relative_to(root).as_posix(),
        "source_platform": platform,
        "language": parse_scalar(text, "language"),
        "type": parse_scalar(text, "type"),
        "severity": parse_scalar(text, "severity"),
        "risk_score": parse_int(text, "risk_score"),
        "maturity": parse_scalar(text, "maturity"),
        "integrations": parse_array(text, "integration"),
        "tactics": tactic_slugs,
        "techniques": technique_ids,
        "data_sources": data_sources,
    }
    inventory_add(
        source="elastic_detection_rules",
        path=path,
        root=root,
        included=True,
        rule_id=rule_id,
        platform=platform,
        techniques=technique_ids,
        license_name=LICENSE_NAME,
    )
    return record


def infer_sigma_platform(path: Path) -> str | None:
    parts = {part.lower() for part in path.parts}
    if "windows" in parts:
        return "windows"
    if "linux" in parts:
        return "linux"
    if "macos" in parts or "mac" in parts:
        return "macos"
    return None


def parse_sigma_rule(path: Path, root: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rule_id = parse_scalar(text, "id") or path.stem
    name = parse_scalar(text, "title") or path.stem.replace("_", " ").title()
    tags = parse_array(text, "tags")
    technique_ids = sorted(
        {
            tag.split(".", 1)[1].upper()
            for tag in tags
            if re.fullmatch(r"attack\.t\d+(?:\.\d+)?", tag.lower())
        }
    )
    tactic_slugs = sorted(
        {
            tag.split(".", 1)[1].replace("_", "-")
            for tag in tags
            if tag.lower().startswith("attack.") and not re.fullmatch(r"attack\.t\d+(?:\.\d+)?", tag.lower())
        }
    )
    platform = infer_sigma_platform(path)
    if platform is None:
        inventory_add(
            source="sigmahq_community_rules",
            path=path,
            root=root,
            included=False,
            skip_reason="platform_not_windows_linux_macos",
            rule_id=rule_id,
            techniques=technique_ids,
            license_name=SIGMAHQ_LICENSE,
        )
        return None
    record = {
        "source": "sigmahq_community_rules",
        "source_license": SIGMAHQ_LICENSE,
        "source_rule_id": rule_id,
        "source_rule_name": name,
        "source_relative_path": path.relative_to(root).as_posix(),
        "source_platform": platform,
        "language": "sigma",
        "type": "sigma",
        "severity": parse_scalar(text, "level"),
        "risk_score": None,
        "maturity": parse_scalar(text, "status"),
        "integrations": [],
        "tactics": tactic_slugs,
        "techniques": technique_ids,
        "data_sources": [],
    }
    inventory_add(
        source="sigmahq_community_rules",
        path=path,
        root=root,
        included=True,
        rule_id=rule_id,
        platform=platform,
        techniques=technique_ids,
        license_name=SIGMAHQ_LICENSE,
    )
    return record


def infer_wazuh_platform(text: str, path: Path) -> str:
    haystack = f"{path.as_posix()} {text[:4000]}".lower()
    if any(token in haystack for token in ("windows", "win-", "sysmon", "powershell", "winlog")):
        return "windows"
    if any(token in haystack for token in ("macos", "mac os", "darwin", "apple")):
        return "macos"
    return "linux"


def parse_wazuh_rules(path: Path, root: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    platform = infer_wazuh_platform(text, path)
    records: list[dict[str, Any]] = []
    for match in re.finditer(r"(?ms)<rule\s+([^>]*)>(.*?)</rule>", text):
        attrs, body = match.groups()
        rule_id = re.search(r'id="([^"]+)"', attrs)
        level = re.search(r'level="([^"]+)"', attrs)
        if not rule_id:
            inventory_add(
                source="wazuh_ruleset",
                path=path,
                root=root,
                included=False,
                skip_reason="missing_rule_id",
                platform=platform,
                license_name=WAZUH_LICENSE,
            )
            continue
        description = re.search(r"(?ms)<description>(.*?)</description>", body)
        groups = re.findall(r"(?ms)<group>(.*?)</group>", body)
        mitre_ids = sorted(set(re.findall(r"(?ms)<id>(T\d+(?:\.\d+)?)</id>", body)))
        tags = []
        for group in groups:
            tags.extend(item.strip() for item in group.split(",") if item.strip())
        if not mitre_ids and not tags:
            inventory_add(
                source="wazuh_ruleset",
                path=path,
                root=root,
                included=False,
                skip_reason="missing_mitre_id_and_group_tags",
                rule_id=rule_id.group(1),
                platform=platform,
                license_name=WAZUH_LICENSE,
            )
            continue
        record = {
            "source": "wazuh_ruleset",
            "source_license": WAZUH_LICENSE,
            "source_rule_id": rule_id.group(1),
            "source_rule_name": re.sub(r"\s+", " ", description.group(1)).strip()
            if description
            else f"Wazuh rule {rule_id.group(1)}",
            "source_relative_path": path.relative_to(root).as_posix(),
            "source_platform": platform,
            "language": "wazuh-xml",
            "type": "wazuh_rule",
            "severity": None,
            "risk_score": int(level.group(1)) if level else None,
            "maturity": "community",
            "integrations": [],
            "tactics": [],
            "techniques": mitre_ids,
            "data_sources": sorted(set(tags)),
        }
        records.append(record)
        inventory_add(
            source="wazuh_ruleset",
            path=path,
            root=root,
            included=True,
            rule_id=rule_id.group(1),
            platform=platform,
            techniques=mitre_ids,
            license_name=WAZUH_LICENSE,
        )
    return records


def load_elastic_metadata(elastic_root: Path) -> list[dict[str, Any]]:
    rules_root = elastic_root / "rules"
    if not rules_root.exists():
        raise SystemExit(f"Elastic rules directory not found: {rules_root}")

    records: list[dict[str, Any]] = []
    for platform in PLATFORM_DIRS:
        for path in sorted((rules_root / platform).glob("*.toml")):
            parsed = parse_rule(path, platform, elastic_root)
            if parsed:
                records.append(parsed)
    for path in sorted((rules_root / "cross-platform").glob("*.toml")):
        parsed = parse_rule(path, "cross-platform", elastic_root)
        if parsed:
            for platform in PLATFORM_DIRS:
                clone = dict(parsed)
                clone["source_platform"] = platform
                clone["source_relative_path"] = parsed["source_relative_path"]
                records.append(clone)
    return records


def load_sigmahq_metadata(sigmahq_root: Path) -> list[dict[str, Any]]:
    rules_root = sigmahq_root / "rules"
    if not rules_root.exists():
        return []
    records = []
    for path in sorted(rules_root.rglob("*.yml")) + sorted(rules_root.rglob("*.yaml")):
        parsed = parse_sigma_rule(path, sigmahq_root)
        if parsed:
            records.append(parsed)
    return records


def load_wazuh_metadata(wazuh_root: Path) -> list[dict[str, Any]]:
    rules_root = wazuh_root / "rules"
    if not rules_root.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(rules_root.rglob("*.xml")):
        if "/translated/" in path.as_posix().lower():
            continue
        records.extend(parse_wazuh_rules(path, wazuh_root))
    return records


def generic_record(
    *,
    source: str,
    license_name: str,
    rule_id: str,
    name: str,
    path: Path,
    root: Path,
    platform: str,
    language: str,
    severity: str | None,
    maturity: str | None,
    techniques: list[str],
    data_sources: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "source": source,
        "source_license": license_name,
        "source_rule_id": rule_id,
        "source_rule_name": name,
        "source_relative_path": path.relative_to(root).as_posix(),
        "source_platform": platform,
        "language": language,
        "type": "external_metadata",
        "severity": severity,
        "risk_score": None,
        "maturity": maturity,
        "integrations": [],
        "tactics": [],
        "techniques": techniques,
        "data_sources": data_sources or [],
    }


def parse_detection_yaml_records(
    root: Path,
    glob: str,
    *,
    source: str,
    license_name: str,
    language: str,
) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(root.glob(glob)):
        text = path.read_text(encoding="utf-8", errors="ignore")
        techniques = technique_ids_from_text(text)
        rule_id = parse_yaml_scalar(text, "id") or path.stem
        name = parse_yaml_scalar(text, "name") or parse_yaml_scalar(text, "title") or path.stem.replace("_", " ")
        platforms = infer_platforms_from_text(path, text)
        if not techniques or not platforms:
            inventory_add(
                source=source,
                path=path,
                root=root,
                included=False,
                skip_reason="missing_technique_or_supported_platform",
                rule_id=rule_id,
                techniques=techniques,
                license_name=license_name,
            )
            continue
        for platform in platforms:
            records.append(
                generic_record(
                    source=source,
                    license_name=license_name,
                    rule_id=rule_id,
                    name=name,
                    path=path,
                    root=root,
                    platform=platform,
                    language=language,
                    severity=parse_yaml_scalar(text, "severity"),
                    maturity=parse_yaml_scalar(text, "status") or parse_yaml_scalar(text, "kind"),
                    techniques=techniques,
                    data_sources=re.findall(r"(?m)^\s*-\s*([A-Za-z0-9 _:/.-]+)$", text[:3000])[:8],
                )
            )
            inventory_add(
                source=source,
                path=path,
                root=root,
                included=True,
                rule_id=rule_id,
                platform=platform,
                techniques=techniques,
                license_name=license_name,
            )
    return records


def load_lolbas_metadata(lolbas_root: Path) -> list[dict[str, Any]]:
    if not lolbas_root.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted((lolbas_root / "yml").rglob("*.yml")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        techniques = technique_ids_from_text(text)
        name = parse_yaml_scalar(text, "Name") or path.stem
        if not techniques:
            inventory_add(
                source="lolbas",
                path=path,
                root=lolbas_root,
                included=False,
                skip_reason="missing_mitre_id",
                rule_id=name,
                platform="windows",
                license_name=LOLBAS_LICENSE,
            )
            continue
        records.append(
            generic_record(
                source="lolbas",
                license_name=LOLBAS_LICENSE,
                rule_id=name,
                name=name,
                path=path,
                root=lolbas_root,
                platform="windows",
                language="lolbas-yaml",
                severity=None,
                maturity="community",
                techniques=techniques,
                data_sources=["process_create", "network_connect", "file_modify"],
            )
        )
        inventory_add(
            source="lolbas",
            path=path,
            root=lolbas_root,
            included=True,
            rule_id=name,
            platform="windows",
            techniques=techniques,
            license_name=LOLBAS_LICENSE,
        )
    return records


def load_gtfobins_metadata(gtfobins_root: Path) -> list[dict[str, Any]]:
    functions = gtfobins_root / "_data" / "functions.yml"
    if not functions.exists():
        return []
    text = functions.read_text(encoding="utf-8", errors="ignore")
    records: list[dict[str, Any]] = []
    for match in re.finditer(r"(?ms)^([a-z0-9-]+):\n.*?(?=^[a-z0-9-]+:\n|\Z)", text):
        function_name = match.group(1)
        block = match.group(0)
        techniques = technique_ids_from_text(block)
        if not techniques:
            continue
        for platform in ("linux", "macos"):
            records.append(
                generic_record(
                    source="gtfobins",
                    license_name=GTFOBINS_LICENSE,
                    rule_id=function_name,
                    name=f"GTFOBins {function_name}",
                    path=functions,
                    root=gtfobins_root,
                    platform=platform,
                    language="gtfobins-yaml",
                    severity=None,
                    maturity="community",
                    techniques=techniques,
                    data_sources=["process_create", "file_read", "file_modify", "network_connect"],
                )
            )
            inventory_add(
                source="gtfobins",
                path=functions,
                root=gtfobins_root,
                included=True,
                rule_id=function_name,
                platform=platform,
                techniques=techniques,
                license_name=GTFOBINS_LICENSE,
            )
    return records


def roadmap_lookup(platform: str) -> dict[str, list[dict[str, Any]]]:
    path = ROADMAP_DIR / f"{platform}_detection_roadmap_300.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    lookup: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for scenario in data.get("scenarios") or []:
        lookup[str(scenario.get("technique_id"))].append(scenario)
    return lookup


def technique_base_id(technique: str) -> str:
    return technique.split(".", 1)[0]


def technique_intent(technique: str) -> str:
    return TECHNIQUE_INTENTS.get(technique) or TECHNIQUE_INTENTS.get(
        technique_base_id(technique),
        "externally observed detection behavior that needs a Tamandua-authored semantic rewrite",
    )


def merge_unique(values: list[str]) -> list[str]:
    seen = set()
    merged = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            merged.append(value)
    return merged


def telemetry_contract(platform: str, technique: str) -> list[str]:
    base = PLATFORM_TELEMETRY_BASE.get(platform, ["process_create"])
    exact = TECHNIQUE_TELEMETRY.get(technique, [])
    family = TECHNIQUE_TELEMETRY.get(technique_base_id(technique), [])
    return merge_unique(exact + family + base)[:8]


def required_fields(platform: str, technique: str) -> list[str]:
    defaults = ["agent_id", "hostname", "timestamp", "event_type"]
    exact = TECHNIQUE_FIELD_HINTS.get(technique, [])
    family = TECHNIQUE_FIELD_HINTS.get(technique_base_id(technique), [])
    platform_fields = {
        "windows": ["process_guid", "integrity_level"],
        "linux": ["pid", "uid"],
        "macos": ["pid", "uid", "signing_id"],
    }.get(platform, [])
    return merge_unique(defaults + exact + family + platform_fields)


def rewrite_priority(source_count: int, roadmap_matches: int) -> str:
    if source_count >= 80 and roadmap_matches == 0:
        return "p0-gap"
    if source_count >= 40:
        return "p1-high-signal"
    if roadmap_matches > 0:
        return "p2-roadmap-hardening"
    return "p3-backlog"


def source_mix_for_technique(records: list[dict[str, Any]], platform: str, technique: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in records:
        if item["source_platform"] != platform:
            continue
        if technique in (item.get("techniques") or []):
            counter[str(item.get("source") or "unknown")] += 1
    return dict(counter.most_common())


def records_for_technique(records: list[dict[str, Any]], platform: str, technique: str) -> list[dict[str, Any]]:
    return [
        item
        for item in records
        if item["source_platform"] == platform and technique in (item.get("techniques") or [])
    ]


def dominant_values(
    records: list[dict[str, Any]],
    key: str,
    fallback: str = "unknown",
    limit: int = 8,
) -> list[str]:
    counter: Counter[str] = Counter()
    for item in records:
        values = item.get(key) or []
        if not values:
            values = [fallback]
        for value in values:
            normalized = str(value).strip()
            if not normalized or normalized.startswith(("http://", "https://")):
                continue
            counter[normalized] += 1
    if not counter:
        counter[fallback] += 1
    return [value for value, _count in counter.most_common(limit)]


def execution_command(platform: str, technique: str) -> tuple[str, str]:
    platform_commands = SEMANTIC_TECHNIQUE_COMMANDS.get(platform, {})
    command = platform_commands.get(technique)
    if command:
        return ensure_process_observation_dwell(platform, command), "technique-specific"
    base = technique_base_id(technique)
    command = platform_commands.get(base)
    if command:
        return ensure_process_observation_dwell(platform, command), "technique-family"
    return ensure_process_observation_dwell(platform, SEMANTIC_EXECUTION_COMMANDS[platform]), "platform-generic"


def ensure_process_observation_dwell(platform: str, command: str) -> str:
    """Keep Unix probes observable by polling-based process collectors."""
    if platform not in {"linux", "macos"}:
        return command
    if f"sleep {PROCESS_POLLING_DWELL_SECONDS}" in command:
        return command

    prefix = "sh -lc '"
    if command.startswith(prefix) and command.endswith("'"):
        inner = command[len(prefix) : -1]
        return f"{prefix}{inner}; sleep {PROCESS_POLLING_DWELL_SECONDS}'"
    return f"sh -lc {json.dumps(command + f'; sleep {PROCESS_POLLING_DWELL_SECONDS}')}"


def candidate_from_summary(
    records: list[dict[str, Any]],
    platform: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    technique = str(item["technique_id"])
    source_count = int(item["source_rule_count"])
    roadmap_matches = int(item["tamandua_roadmap_matches"])
    technique_records = records_for_technique(records, platform, technique)
    fields = required_fields(platform, technique)
    telemetry = telemetry_contract(platform, technique)
    return {
        "id": f"semantic-rewrite-{platform}-{technique.lower().replace('.', '-')}",
        "platform": platform,
        "technique_id": technique,
        "priority": rewrite_priority(source_count, roadmap_matches),
        "source_rule_count": source_count,
        "source_mix": source_mix_for_technique(records, platform, technique),
        "source_reference_ids": item["representative_source_rule_ids"],
        "dominant_tactics": dominant_values(technique_records, "tactics"),
        "dominant_data_sources": dominant_values(technique_records, "data_sources", fallback="endpoint telemetry"),
        "tamandua_roadmap_matches": roadmap_matches,
        "tamandua_scenario_ids": item["tamandua_scenario_ids"],
        "rewrite_mode": "tamandua-authored semantic rewrite",
        "behavior_intent": technique_intent(technique),
        "collector_contract": {
            "required_events": telemetry,
            "required_fields": fields,
            "normalization_target": "tamandua.events.v1",
        },
        "detection_shape": {
            "rule_authoring_boundary": (
                "Use external implementation as practical inspiration, but write Tamandua-native "
                "conditions, thresholds, field names, descriptions, and tests."
            ),
            "positive_signal": (
                f"Correlate {technique} behavior intent with platform-specific process, file, "
                "identity, configuration, or network telemetry as available."
            ),
            "benign_contrast": (
                "Add allowlisted administrative and installer patterns observed in Tamandua fixtures "
                "before promoting to alerting mode."
            ),
            "minimum_output": ["rule_candidate", "benign_fixture", "suspicious_fixture", "benchmark_case"],
        },
        "validation_plan": {
            "first_benchmark": f"external-{platform}-{technique.lower().replace('.', '-')}",
            "needs_live_fixture": True,
            "assertions": [
                "required telemetry exists with normalized fields",
                "benign contrast does not fire high-severity detection",
                "suspicious fixture produces explainable rule evidence",
                "provenance records external sources without copied rule body",
            ],
        },
        "license_review": "required before direct textual or logic reuse",
    }


def semantic_rewrite_candidates(records: list[dict[str, Any]], mapping: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for platform, summary in mapping["platforms"].items():
        for item in summary["top_techniques"]:
            candidates.append(candidate_from_summary(records, platform, item))
    priority_order = {"p0-gap": 0, "p1-high-signal": 1, "p2-roadmap-hardening": 2, "p3-backlog": 3}
    return sorted(
        candidates,
        key=lambda item: (
            priority_order.get(str(item["priority"]), 9),
            str(item["platform"]),
            -int(item["source_rule_count"]),
            str(item["technique_id"]),
        ),
    )


def write_semantic_candidates(records: list[dict[str, Any]], mapping: dict[str, Any]) -> Path:
    payload = {
        "schema_version": 1,
        "generated_from": mapping["generated_from"],
        "purpose": (
            "Practical acquisition queue for Tamandua-authored semantic rewrites inspired by "
            "external detection implementations."
        ),
        "guardrail": {
            "allowed": [
                "derive behavior intent",
                "derive collector and field requirements",
                "derive benchmark and fixture backlog",
                "record source ids as provenance",
            ],
            "requires_review": [
                "copying or closely adapting query expressions",
                "copying Sigma condition trees",
                "copying Wazuh XML rules",
                "copying prose descriptions, notes, setup, or guides",
            ],
        },
        "candidates": semantic_rewrite_candidates(records, mapping),
    }
    path = ROADMAP_DIR / "external_rule_semantic_rewrite_candidates.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def semantic_execution_test(
    candidate: dict[str, Any],
    *,
    generated_from: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    platform = str(candidate["platform"])
    technique = str(candidate["technique_id"])
    candidate_id = str(candidate["id"])
    test_id = candidate_id.replace("semantic-rewrite-", "semantic-exec-", 1)
    required_events = candidate.get("collector_contract", {}).get("required_events") or []
    optional = merge_unique([str(item) for item in required_events if item != "process_create"])
    command_template, command_coverage = execution_command(platform, technique)
    command = command_template.replace("%TEST_ID%", test_id)
    marker = f"tamandua-semantic-rewrite-{test_id}"
    process_required_fields = PROCESS_REQUIRED_FIELDS_BY_PLATFORM.get(
        platform,
        ["agent_id", "hostname", "process_name", "command_line"],
    )
    return {
        "id": test_id,
        "name": f"External semantic rewrite execution prep: {platform} {technique}",
        "executor": "command",
        "fallback_command": command,
        "validation_category": "external-rule-semantic-rewrite-execution-smoke",
        "source_executor": "external_rule_semantic_rewrite",
        "source_benchmark_lane": "external-semantic-rewrite-execution",
        "claim_boundary": (
            "safe execution prep for Tamandua-authored semantic rewrite; validates runner, "
            "process telemetry, and candidate traceability, not external source rule behavior"
        ),
        "expected_telemetry": ["process_create"],
        "expected_telemetry_any": [[LIVE_RESPONSE_AUDIT_TELEMETRY]],
        "optional_telemetry": optional,
        "expected_fields_by_event_type": {
            "process_create": process_required_fields,
            LIVE_RESPONSE_AUDIT_TELEMETRY: LIVE_RESPONSE_AUDIT_REQUIRED_FIELDS,
        },
        "expected_values_by_event_type": {
            "process_create": {"command_line": [marker]},
            LIVE_RESPONSE_AUDIT_TELEMETRY: {"command": [marker]},
        },
        "telemetry_contract_notes": [
            "process_create remains the strict endpoint telemetry expectation for semantic rewrite promotion",
            "process_create command_line must include the probe marker before a candidate is counted as traceable endpoint telemetry",
            (
                "linux/macos probes keep the shell process alive briefly so polling-based "
                "process collectors can observe them until auditd/eBPF/EndpointSecurity "
                "event-driven collection is production-wired"
            ),
            (
                f"{LIVE_RESPONSE_AUDIT_TELEMETRY} is accepted only as bounded "
                "tamandua-ctl/live-response audit evidence for execution-prep smoke runs"
            ),
            "planned event contracts remain report-only until collector/schema evidence exists",
        ],
        "semantic_rewrite_candidate": {
            "id": candidate_id,
            "priority": candidate["priority"],
            "technique_id": technique,
            "source_rule_count": candidate["source_rule_count"],
            "source_mix": candidate["source_mix"],
            "source_reference_ids": candidate.get("source_reference_ids") or [],
            "license_review": candidate.get("license_review"),
            "generated_from": generated_from or [],
            "clean_room_boundary": (
                "metadata and behavior-intent only; no copied external rule body, "
                "query, XML, condition tree, prose, or investigation guide"
            ),
            "dominant_tactics": candidate.get("dominant_tactics") or [],
            "dominant_data_sources": candidate.get("dominant_data_sources") or [],
            "execution_command_coverage": command_coverage,
            "process_observation_dwell_seconds": (
                PROCESS_POLLING_DWELL_SECONDS if platform in {"linux", "macos"} else 0
            ),
            "collector_contract": candidate["collector_contract"],
            "validation_plan": candidate["validation_plan"],
        },
        "tags": [
            f"{platform}-external-semantic-rewrite",
            f"priority:{candidate['priority']}",
            f"mitre:{technique}",
            "source:external-rule-semantic-rewrite",
            "lane:external-semantic-rewrite-execution",
        ],
        "risk": "low",
    }


def semantic_execution_profile(
    *,
    platform: str,
    profile_id: str,
    name: str,
    description: str,
    candidates: list[dict[str, Any]],
    selection: dict[str, Any],
    generated_from: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    tests = [
        semantic_execution_test(candidate, generated_from=generated_from)
        for candidate in candidates
    ]
    return {
        "schema_version": 1,
        "profile_id": profile_id,
        "name": name,
        "description": description,
        "platform": platform,
        "default_observation_seconds": 60,
        "benchmark_lane": "external-semantic-rewrite-execution",
        "quality_bar": {
            "purpose": profile_id.replace("-", "_"),
            "requires_persisted_events": True,
            "max_unknown_source_events": 0,
            "max_unexpected_high_critical": 0,
            "report_only": True,
        },
        "semantic_rewrite_selection": selection,
        "tests": tests,
    }


def write_semantic_execution_profiles(candidates_path: Path) -> list[Path]:
    payload = json.loads(candidates_path.read_text(encoding="utf-8"))
    candidates = payload.get("candidates") or []
    generated_from = payload.get("generated_from") or []
    paths: list[Path] = []
    for platform in PLATFORM_DIRS:
        platform_candidates = [
            item for item in candidates if item.get("platform") == platform
        ]
        immediate = [
            item
            for item in platform_candidates
            if item.get("priority") in {"p0-gap", "p1-high-signal"}
        ]
        if immediate:
            profile = semantic_execution_profile(
                platform=platform,
                profile_id=f"{platform}-external-semantic-rewrite-p0-p1-execution",
                name=f"{platform.title()} External Semantic Rewrite P0/P1 Execution",
                description=(
                    "Safe execution-prep profile for high-priority external-rule-inspired "
                    "Tamandua semantic rewrite candidates."
                ),
                candidates=immediate,
                selection={
                    "source": candidates_path.relative_to(ROOT).as_posix(),
                    "priority": ["p0-gap", "p1-high-signal"],
                    "candidate_count": len(immediate),
                    "generated_from": generated_from,
                    "clean_room_boundary": (
                        "execution probes are Tamandua-authored and carry provenance "
                        "without copying external detection logic"
                    ),
                },
                generated_from=generated_from,
            )
            path = PROFILE_DIR / f"{profile['profile_id'].replace('-', '_')}.json"
            path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
            paths.append(path)

        for batch_index, start in enumerate(
            range(0, len(platform_candidates), SEMANTIC_EXECUTION_BATCH_SIZE),
            start=1,
        ):
            batch = platform_candidates[start : start + SEMANTIC_EXECUTION_BATCH_SIZE]
            if not batch:
                continue
            profile = semantic_execution_profile(
                platform=platform,
                profile_id=f"{platform}-external-semantic-rewrite-all-batch-{batch_index:02d}",
                name=f"{platform.title()} External Semantic Rewrite All Batch {batch_index:02d}",
                description=(
                    "Safe batch profile for external-rule-inspired Tamandua semantic rewrite "
                    "execution prep across all mapped candidates."
                ),
                candidates=batch,
                selection={
                    "source": candidates_path.relative_to(ROOT).as_posix(),
                    "priority": "all",
                    "batch_size": SEMANTIC_EXECUTION_BATCH_SIZE,
                    "batch_index": batch_index,
                    "candidate_count": len(batch),
                    "generated_from": generated_from,
                    "clean_room_boundary": (
                        "execution probes are Tamandua-authored and carry provenance "
                        "without copying external detection logic"
                    ),
                },
                generated_from=generated_from,
            )
            path = PROFILE_DIR / f"{profile['profile_id'].replace('-', '_')}.json"
            path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
            paths.append(path)
    return paths


def improvement_domains(candidate: dict[str, Any]) -> list[str]:
    events = set(candidate.get("collector_contract", {}).get("required_events") or [])
    domains = {"detection_engine", "benchmark_fixtures", "provenance"}
    if "process_create" in events:
        domains.add("agent_process_collector")
    if events & {"file_read"}:
        domains.add("agent_file_read_collector")
    if events & {"file_create", "file_modify"} and candidate.get("priority") in {"p0-gap", "p1-high-signal"}:
        domains.add("agent_file_collector")
    if events & {"network_connect", "dns_query", "web_request"}:
        domains.add("agent_network_collector")
    if events & {"registry_modify", "registry_set_value", "directory_change"}:
        domains.add("windows_registry_directory_collector")
    if events & {"auth_event", "failed_login", "session_start", "account_change", "privilege_change"}:
        domains.add("identity_auth_collector")
    if events & {"service_create", "service_modify", "scheduled_event"}:
        domains.add("service_persistence_collector")
    if events & {"process_access", "memory_event", "image_load"}:
        domains.add("deep_endpoint_sensor")
    if events & {"mail_access", "secret_scan", "resource_usage", "service_health"}:
        domains.add("specialized_context_collectors")
    return sorted(domains)


def implementation_steps(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    technique = str(candidate["technique_id"])
    platform = str(candidate["platform"])
    fields = candidate.get("collector_contract", {}).get("required_fields") or []
    events = candidate.get("collector_contract", {}).get("required_events") or []
    steps = [
        {
            "area": "collector_contract",
            "action": "ensure required events and fields are emitted in normalized Tamandua schema",
            "required_events": events,
            "required_fields": fields,
        },
        {
            "area": "agent_or_sensor",
            "action": f"verify {platform} agent can collect the behavior intent for {technique}",
            "domains": improvement_domains(candidate),
        },
        {
            "area": "detection_engine",
            "action": "author Tamandua-native D&R candidate with benign allowlist and explainable evidence",
            "rule_authoring_boundary": "no copied upstream rule body, query, XML, condition tree, or prose",
        },
        {
            "area": "validation",
            "action": "add benign fixture, suspicious fixture, and promoted benchmark beyond execution-prep probe",
            "first_execution_profile": candidate.get("validation_plan", {}).get("first_benchmark"),
        },
        {
            "area": "documentation",
            "action": "record source provenance, expected telemetry, fixture coverage, and claim boundary",
        },
    ]
    return steps


def global_improvement_items(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority_order = {"p0-gap": 0, "p1-high-signal": 1, "p2-roadmap-hardening": 2, "p3-backlog": 3}
    items = []
    for candidate in candidates:
        domains = improvement_domains(candidate)
        items.append(
            {
                "id": candidate["id"].replace("semantic-rewrite-", "global-improvement-", 1),
                "source_candidate_id": candidate["id"],
                "platform": candidate["platform"],
                "technique_id": candidate["technique_id"],
                "priority": candidate["priority"],
                "source_rule_count": candidate["source_rule_count"],
                "source_mix": candidate["source_mix"],
                "dominant_tactics": candidate.get("dominant_tactics") or [],
                "dominant_data_sources": candidate.get("dominant_data_sources") or [],
                "owner_areas": domains,
                "collector_contract": candidate["collector_contract"],
                "execution_probe": {
                    "profile_hint": (
                        f"{candidate['platform']}_external_semantic_rewrite_p0_p1_execution.json"
                        if candidate["priority"] in {"p0-gap", "p1-high-signal"}
                        else f"{candidate['platform']}_external_semantic_rewrite_all_batch_*.json"
                    ),
                    "first_benchmark": candidate.get("validation_plan", {}).get("first_benchmark"),
                },
                "implementation_steps": implementation_steps(candidate),
                "promotion_gate": [
                    "execution-prep probe passes with normalized process telemetry",
                    "collector contract emits required event family or documented not-supported gap",
                    "Tamandua-authored D&R rule candidate exists",
                    "benign and suspicious fixtures exist",
                    "source provenance and license class are recorded",
                ],
            }
        )
    return sorted(
        items,
        key=lambda item: (
            priority_order.get(str(item["priority"]), 9),
            str(item["platform"]),
            -int(item["source_rule_count"]),
            str(item["technique_id"]),
        ),
    )


def write_global_improvement_roadmap(candidates_path: Path) -> Path:
    payload = json.loads(candidates_path.read_text(encoding="utf-8"))
    candidates = payload.get("candidates") or []
    items = global_improvement_items(candidates)
    summary = {
        "item_count": len(items),
        "by_priority": counter_to_dict(Counter(str(item["priority"]) for item in items)),
        "by_platform": counter_to_dict(Counter(str(item["platform"]) for item in items)),
        "by_owner_area": counter_to_dict(
            Counter(area for item in items for area in item.get("owner_areas") or [])
        ),
    }
    out = {
        "schema_version": 1,
        "purpose": (
            "Global implementation roadmap derived from external-rule semantic rewrite candidates. "
            "Use this to schedule agent, collector, schema, D&R, validation, and documentation work."
        ),
        "source": candidates_path.relative_to(ROOT).as_posix(),
        "summary": summary,
        "items": items,
    }
    path = ROADMAP_DIR / "external_rule_global_improvement_roadmap.json"
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return path


def counter_to_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(counter.most_common())


def inventory_summary() -> dict[str, Any]:
    total = len(INVENTORY)
    included = [item for item in INVENTORY if item["included"]]
    skipped = [item for item in INVENTORY if not item["included"]]
    return {
        "total_inventory_items": total,
        "included_items": len(included),
        "skipped_items": len(skipped),
        "included_by_source": counter_to_dict(Counter(str(item["source"]) for item in included)),
        "skipped_by_source": counter_to_dict(Counter(str(item["source"]) for item in skipped)),
        "included_by_platform": counter_to_dict(Counter(str(item["platform"]) for item in included)),
        "skipped_by_reason": counter_to_dict(Counter(str(item["skip_reason"]) for item in skipped)),
    }


def write_inventory(mapping: dict[str, Any]) -> Path:
    payload = {
        "schema_version": 1,
        "generated_from": mapping["generated_from"],
        "purpose": (
            "One-row-per-source-rule audit inventory for external rule acquisition. "
            "Included rows feed coverage and semantic rewrite candidates; skipped rows document why."
        ),
        "summary": inventory_summary(),
        "items": INVENTORY,
    }
    path = ROADMAP_DIR / "external_rule_inventory.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def platform_summary(records: list[dict[str, Any]], platform: str) -> dict[str, Any]:
    platform_records = [item for item in records if item["source_platform"] == platform]
    tactic_counter: Counter[str] = Counter()
    technique_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()
    data_source_counter: Counter[str] = Counter()
    source_counter: Counter[str] = Counter()
    by_technique: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for item in platform_records:
        source_counter[str(item.get("source") or "unknown")] += 1
        severity_counter[str(item.get("severity") or "unknown")] += 1
        for tactic in item.get("tactics") or ["unknown"]:
            tactic_counter[str(tactic)] += 1
        for technique in item.get("techniques") or ["unmapped"]:
            technique_counter[str(technique)] += 1
            by_technique[str(technique)].append(item)
        for data_source in item.get("data_sources") or []:
            data_source_counter[str(data_source)] += 1

    roadmaps = roadmap_lookup(platform)
    top_techniques = []
    for technique, count in technique_counter.most_common():
        if technique == "unmapped":
            continue
        roadmap_matches = roadmaps.get(technique, [])
        top_techniques.append(
            {
                "technique_id": technique,
                "source_rule_count": count,
                "tamandua_roadmap_matches": len(roadmap_matches),
                "tamandua_scenario_ids": [str(item.get("id")) for item in roadmap_matches[:8]],
                "representative_source_rule_ids": [
                    f"{item['source']}:{item['source_rule_id']}" for item in by_technique[technique][:5]
                ],
            }
        )

    mapped = sum(1 for item in top_techniques if item["tamandua_roadmap_matches"] > 0)
    return {
        "platform": platform,
        "source_rule_count": len(platform_records),
        "source_counts": dict(source_counter.most_common()),
        "tactic_counts": dict(tactic_counter.most_common()),
        "technique_counts": dict(technique_counter.most_common()),
        "severity_counts": dict(severity_counter.most_common()),
        "data_source_counts": dict(data_source_counter.most_common()),
        "top_techniques": top_techniques,
        "top_techniques_with_tamandua_roadmap_match": mapped,
    }


def write_mapping(records: list[dict[str, Any]], commits: dict[str, str]) -> dict[str, Any]:
    summaries = {platform: platform_summary(records, platform) for platform in PLATFORM_DIRS}
    payload = {
        "schema_version": 1,
        "generated_from": {
            "sources": [
                {
                    "source": "elastic/detection-rules",
                    "commit": commits.get("elastic_detection_rules", "unknown"),
                    "license": LICENSE_NAME,
                },
                {
                    "source": "SigmaHQ/sigma",
                    "commit": commits.get("sigmahq_community_rules", "unknown"),
                    "license": SIGMAHQ_LICENSE,
                },
                {
                    "source": "wazuh/wazuh-ruleset",
                    "commit": commits.get("wazuh_ruleset", "unknown"),
                    "license": WAZUH_LICENSE,
                },
                {
                    "source": "LOLBAS-Project/LOLBAS",
                    "commit": commits.get("lolbas", "unknown"),
                    "license": LOLBAS_LICENSE,
                },
                {
                    "source": "GTFOBins/GTFOBins.github.io",
                    "commit": commits.get("gtfobins", "unknown"),
                    "license": GTFOBINS_LICENSE,
                },
                {
                    "source": "splunk/security_content",
                    "commit": commits.get("splunk_security_content", "unknown"),
                    "license": SPLUNK_SECURITY_CONTENT_LICENSE,
                },
                {
                    "source": "Azure/Azure-Sentinel",
                    "commit": commits.get("azure_sentinel", "unknown"),
                    "license": AZURE_SENTINEL_LICENSE,
                },
            ],
            "local_clone_required": False,
        },
        "license_guardrail": {
            "mode": "metadata-only coverage mapping",
            "do_not_copy": [
                "query",
                "eql",
                "kql",
                "sigma rule body",
                "wazuh xml rule body",
                "rule logic",
                "investigation guide text",
                "setup text",
            ],
            "allowed_use": [
                "ATT&CK coverage gap analysis",
                "platform/data-source prioritization",
                "Tamandua-authored benchmark intent",
                "Tamandua-authored rule candidates",
            ],
        },
        "platforms": summaries,
    }
    out = ROADMAP_DIR / "external_rule_coverage_map.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def profile_tests(platform: str, summary: dict[str, Any], limit: int = 24) -> list[dict[str, Any]]:
    tests = []
    command_template = PLATFORM_COMMANDS[platform]
    for item in summary["top_techniques"]:
        if len(tests) >= limit:
            break
        technique = str(item["technique_id"])
        test_id = f"external-{platform}-{technique.lower().replace('.', '-')}"
        if item["tamandua_roadmap_matches"] == 0:
            category = "external-rule-coverage-gap"
        else:
            category = "external-rule-roadmap-overlap"
        tests.append(
            {
                "id": test_id,
                "name": f"External rule coverage mapping: {technique}",
                "executor": "command",
                "fallback_command": command_template.replace("%TEST_ID%", test_id),
                "validation_category": category,
                "source_executor": "external_rule_metadata",
                "source_benchmark_lane": "external-coverage-report-only",
                "claim_boundary": (
                    "metadata-only external rule coverage mapping; validates Tamandua telemetry "
                    "and backlog traceability, not external source rule behavior"
                ),
                "expected_telemetry": ["process_create"],
                "optional_telemetry": ["file_create", "file_modify", "network_connect", "dns_query"],
                "expected_fields": ["agent_id", "hostname", "process_name", "command_line"],
                "external_rule_mapping": {
                    "source": "mixed external rule metadata",
                    "source_license": "mixed external metadata sources; see generated map",
                    "license_guardrail": (
                        "Do not copy external query, EQL/KQL, Sigma body, Wazuh XML body, "
                        "notes, setup, or rule logic."
                    ),
                    "technique_id": technique,
                    "source_rule_count": item["source_rule_count"],
                    "tamandua_roadmap_matches": item["tamandua_roadmap_matches"],
                    "tamandua_scenario_ids": item["tamandua_scenario_ids"],
                    "representative_source_rule_ids": item["representative_source_rule_ids"],
                },
                "tags": [
                    f"{platform}-external-rule-coverage",
                    "source:external-rule-metadata",
                    "license:metadata-only",
                    f"mitre:{technique}",
                    f"category:{category}",
                    "lane:external-coverage-report-only",
                ],
                "risk": "low",
            }
        )
    return tests


def write_profiles(mapping: dict[str, Any]) -> list[Path]:
    paths = []
    for platform, summary in mapping["platforms"].items():
        tests = profile_tests(platform, summary)
        payload = {
            "schema_version": 1,
            "profile_id": f"{platform}-external-rule-coverage-map",
            "name": f"{platform.title()} External Rule Coverage Map",
            "description": (
                "Report-only benchmark profile mapping high-signal external detection-rule "
                "coverage into Tamandua-authored validation backlog."
            ),
            "platform": platform,
            "default_observation_seconds": 45,
            "benchmark_lane": "external-coverage-report-only",
            "quality_bar": {
                "purpose": f"{platform}_external_rule_coverage_map",
                "requires_persisted_events": True,
                "max_unknown_source_events": 0,
                "max_unexpected_high_critical": 0,
                "report_only": True,
            },
            "external_rule_mapping": {
                "sources": mapping["generated_from"]["sources"],
                "guardrail": mapping["license_guardrail"],
            },
            "tests": tests,
        }
        path = PROFILE_DIR / f"{platform}_external_rule_coverage_map.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


def write_doc(
    mapping: dict[str, Any],
    semantic_candidates_path: Path | None = None,
    inventory_path: Path | None = None,
    semantic_execution_paths: list[Path] | None = None,
    global_improvement_path: Path | None = None,
) -> Path:
    semantic_candidate_count = sum(
        len(summary["top_techniques"]) for summary in mapping["platforms"].values()
    )
    inventory = inventory_summary()
    lines = [
        "# External Rule Coverage Mapping",
        "",
        "Status: report-only benchmark backlog",
        "Last updated: 2026-05-28",
        "",
        "This document maps external detection-rule metadata into Tamandua benchmark coverage intent.",
        "It is intentionally metadata-only. Do not copy external queries, EQL/KQL, Sigma",
        "rule bodies, Wazuh XML rule bodies, investigation guides, setup text, or rule",
        "logic into Tamandua rules or public docs.",
        "",
        "Source snapshot:",
        "",
    ]
    for source in mapping["generated_from"]["sources"]:
        lines.append(
            f"- `{source['source']}` at `{source['commit']}`; license: `{source['license']}`"
        )
    lines.extend(
        [
        "- Use in Tamandua: ATT&CK/data-source coverage planning and Tamandua-authored benchmark intent only.",
        "",
        "## Platform Summary",
        "",
        "| Platform | Source rules | Source mix | Top mapped techniques with roadmap overlap | Top tactics |",
        "| --- | ---: | --- | ---: | --- |",
        ]
    )
    for platform, summary in mapping["platforms"].items():
        tactics = ", ".join(f"{k}={v}" for k, v in list(summary["tactic_counts"].items())[:4])
        source_mix = ", ".join(f"{k}={v}" for k, v in summary["source_counts"].items())
        lines.append(
            f"| `{platform}` | {summary['source_rule_count']} | "
            f"{source_mix} | "
            f"{summary['top_techniques_with_tamandua_roadmap_match']} | {tactics} |"
        )

    lines.extend(
        [
            "",
            "## Next Benchmark Profiles",
            "",
            "- `tools/detection_validation/profiles/windows_external_rule_coverage_map.json`",
            "- `tools/detection_validation/profiles/linux_external_rule_coverage_map.json`",
            "- `tools/detection_validation/profiles/macos_external_rule_coverage_map.json`",
            "",
            "These profiles are safe deterministic probes that prove Tamandua can attach",
            "external coverage intent to platform telemetry. A passing run is not a claim",
            "that Tamandua implements the corresponding external source rule.",
            "",
            "## Semantic Rewrite Queue",
            "",
            "The practical acquisition output is generated at:",
            "",
            f"- `{semantic_candidates_path.relative_to(ROOT).as_posix() if semantic_candidates_path else 'tools/detection_validation/roadmaps/external_rule_semantic_rewrite_candidates.json'}`",
            "",
            "Execution runbook:",
            "",
            "- `docs/benchmarks/EXTERNAL_RULE_EXECUTION_PLAN.md`",
            "",
            "Use it to pick high-signal external implementations and rewrite them as",
            "Tamandua-native collector contracts, D&R candidates, fixtures, and benchmark",
            "cases. The queue intentionally records behavior intent, telemetry needs,",
            "field contracts, source mix, and source ids instead of copying rule bodies.",
            f"Current queue size: `{semantic_candidate_count}` platform-technique candidates.",
            "",
            "Global implementation roadmap:",
            "",
            f"- `{global_improvement_path.relative_to(ROOT).as_posix() if global_improvement_path else 'tools/detection_validation/roadmaps/external_rule_global_improvement_roadmap.json'}`",
            "- `tools/detection_validation/roadmaps/external_rule_implementation_backlog.json`",
            "- `tools/detection_validation/roadmaps/external_rule_event_contracts.json`",
            "- `docs/benchmarks/EXTERNAL_RULE_IMPLEMENTATION_BACKLOG.md`",
            "- `docs/benchmarks/EXTERNAL_RULE_EVENT_CONTRACTS.md`",
            "",
            "Execution-prep profiles generated from the queue:",
            "",
        ]
    )
    for path in semantic_execution_paths or []:
        lines.append(f"- `{path.relative_to(ROOT).as_posix()}`")
    lines.extend(
        [
            "",
            "Run the immediate high-priority profiles first, then the `all-batch` profiles.",
            "Example command shape:",
            "",
            "```powershell",
            "python tools\\detection_validation\\tamandua_detection_validation.py --execute --profile tools\\detection_validation\\profiles\\windows_external_semantic_rewrite_p0_p1_execution.json --benchmark-lane external-semantic-rewrite-execution --fail-on-gate",
            "```",
            "",
            "## Source Rule Inventory",
            "",
            "The source-rule audit inventory is generated at:",
            "",
            f"- `{inventory_path.relative_to(ROOT).as_posix() if inventory_path else 'tools/detection_validation/roadmaps/external_rule_inventory.json'}`",
            "",
            f"Inventory rows: `{inventory['total_inventory_items']}`; included: `{inventory['included_items']}`; skipped: `{inventory['skipped_items']}`.",
            "",
            "Included by source:",
            "",
        ]
    )
    for source, count in inventory["included_by_source"].items():
        lines.append(f"- `{source}`: `{count}`")
    lines.extend(
        [
            "",
            "Skipped by reason:",
            "",
        ]
    )
    for reason, count in inventory["skipped_by_reason"].items():
        lines.append(f"- `{reason}`: `{count}`")
    lines.extend(
        [
            "",
            "## High-Signal Coverage Backlog",
            "",
        ]
    )
    for platform, summary in mapping["platforms"].items():
        lines.extend(
            [
                f"### {platform.title()}",
                "",
            "| Technique | Source rule count | Tamandua roadmap matches | Representative source rule ids |",
                "| --- | ---: | ---: | --- |",
            ]
        )
        for item in summary["top_techniques"][:16]:
            ids = ", ".join(f"`{rule_id}`" for rule_id in item["representative_source_rule_ids"][:4])
            lines.append(
                f"| `{item['technique_id']}` | {item['source_rule_count']} | "
                f"{item['tamandua_roadmap_matches']} | {ids} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Promotion Rules",
            "",
            "1. Use external implementations as practical inspiration, then rewrite in Tamandua-native form.",
            "2. Treat SigmaHQ and Wazuh as separately licensed community sources; verify license before direct reuse.",
            "3. Promote only Tamandua-authored rule logic into D&R Engine candidates.",
            "4. Pair every promoted candidate with a benign contrast and a platform-specific collector contract.",
            "5. Record source inspiration as provenance, not as copied rule content.",
            "6. Direct textual or logic reuse is not the default. Only reuse content after explicit license, attribution, and clean-room review; prefer Tamandua-authored rewrites.",
            "",
        ]
    )
    path = DOC_DIR / "EXTERNAL_RULE_COVERAGE_MAPPING.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--elastic-root",
        type=Path,
        default=DEFAULT_ELASTIC_ROOT,
        help="Local clone of elastic/detection-rules",
    )
    parser.add_argument("--sigmahq-root", type=Path, default=DEFAULT_SIGMAHQ_ROOT)
    parser.add_argument("--wazuh-root", type=Path, default=DEFAULT_WAZUH_ROOT)
    parser.add_argument("--lolbas-root", type=Path, default=DEFAULT_LOLBAS_ROOT)
    parser.add_argument("--gtfobins-root", type=Path, default=DEFAULT_GTFOBINS_ROOT)
    parser.add_argument("--splunk-root", type=Path, default=DEFAULT_SPLUNK_ROOT)
    parser.add_argument("--sentinel-root", type=Path, default=DEFAULT_SENTINEL_ROOT)
    parser.add_argument("--elastic-commit", default=None)
    parser.add_argument("--sigmahq-commit", default=None)
    parser.add_argument("--wazuh-commit", default=None)
    parser.add_argument("--lolbas-commit", default=None)
    parser.add_argument("--gtfobins-commit", default=None)
    parser.add_argument("--splunk-commit", default=None)
    parser.add_argument("--sentinel-commit", default=None)
    args = parser.parse_args()

    records = []
    records.extend(load_elastic_metadata(args.elastic_root))
    records.extend(load_sigmahq_metadata(args.sigmahq_root))
    records.extend(load_wazuh_metadata(args.wazuh_root))
    records.extend(load_lolbas_metadata(args.lolbas_root))
    records.extend(load_gtfobins_metadata(args.gtfobins_root))
    records.extend(
        parse_detection_yaml_records(
            args.splunk_root,
            "detections/**/*.yml",
            source="splunk_security_content",
            license_name=SPLUNK_SECURITY_CONTENT_LICENSE,
            language="splunk-yaml",
        )
    )
    records.extend(
        parse_detection_yaml_records(
            args.sentinel_root,
            "Detections/**/*.yaml",
            source="azure_sentinel",
            license_name=AZURE_SENTINEL_LICENSE,
            language="sentinel-kql-yaml",
        )
    )
    commits = {
        "elastic_detection_rules": args.elastic_commit or "unknown",
        "sigmahq_community_rules": args.sigmahq_commit or "unknown",
        "wazuh_ruleset": args.wazuh_commit or "unknown",
        "lolbas": args.lolbas_commit or "unknown",
        "gtfobins": args.gtfobins_commit or "unknown",
        "splunk_security_content": args.splunk_commit or "unknown",
        "azure_sentinel": args.sentinel_commit or "unknown",
    }
    mapping = write_mapping(records, commits)
    semantic_candidates = write_semantic_candidates(records, mapping)
    global_improvement = write_global_improvement_roadmap(semantic_candidates)
    semantic_execution_profiles = write_semantic_execution_profiles(semantic_candidates)
    inventory = write_inventory(mapping)
    profiles = write_profiles(mapping)
    doc = write_doc(mapping, semantic_candidates, inventory, semantic_execution_profiles, global_improvement)
    print(
        "external_rule_coverage=ok "
        f"records={len(records)} doc={doc} inventory={inventory} "
        f"semantic_candidates={semantic_candidates} "
        f"global_improvement={global_improvement} "
        f"semantic_execution_profiles={','.join(str(path) for path in semantic_execution_profiles)} "
        f"profiles={','.join(str(path) for path in profiles)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
