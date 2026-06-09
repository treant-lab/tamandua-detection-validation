#!/usr/bin/env python3
"""Generate Linux and macOS detection roadmaps with 300 scenarios each."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROADMAP_DIR = ROOT / "tools" / "detection_validation" / "roadmaps"
DOC_DIR = ROOT / "docs" / "benchmarks"

TACTIC_COUNTS = [
    ("initial-access", 15),
    ("execution", 30),
    ("persistence", 30),
    ("privilege-escalation", 25),
    ("defense-evasion", 40),
    ("credential-access", 30),
    ("discovery", 30),
    ("lateral-movement", 25),
    ("collection", 20),
    ("command-and-control", 25),
    ("exfiltration", 15),
    ("impact", 15),
]

VARIANTS = [
    ("telemetry-contract", "sensor_contract", "Validate raw event and canonical fields."),
    ("atomic-safe", "atomic_or_command", "Run upstream Atomic test or deterministic safe fallback."),
    ("caldera-chain", "caldera_operation", "Validate multi-step adversary-emulation evidence."),
    ("correlation-storyline", "correlation", "Validate storyline grouping and causal edge reason."),
    ("alert-quality", "alert_quality", "Validate rule title, severity, MITRE, evidence and analyst context."),
    ("benign-contrast", "benign_baseline", "Validate benign analogue does not create high/critical noise."),
    ("response-readiness", "response_harness", "Validate suggested safe response and audit trail."),
    ("kernel-backed", "kernel_contract", "Validate kernel/audit/eBPF/EndpointSecurity source when applicable."),
]

PLATFORMS = {
    "linux": {
        "display": "Linux",
        "roadmap_id": "linux-detection-roadmap-300",
        "sensor_note": "auditd for broad compatibility, eBPF for higher-fidelity process/file/network/kernel events, plus systemd/journald/container/Kubernetes context.",
        "techniques": {
            "initial-access": [
                ("T1190", "Exploit Public-Facing Application"),
                ("T1133", "External Remote Services"),
                ("T1566.002", "Spearphishing Link"),
                ("T1091", "Replication Through Removable Media"),
                ("T1078", "Valid Accounts"),
            ],
            "execution": [
                ("T1059.004", "Unix Shell"),
                ("T1059.006", "Python"),
                ("T1059.007", "JavaScript"),
                ("T1204.002", "Malicious File"),
                ("T1106", "Native API"),
                ("T1569.002", "Service Execution"),
                ("T1047", "WMI-equivalent Remote Management"),
                ("T1129", "Shared Modules"),
            ],
            "persistence": [
                ("T1053.003", "Cron"),
                ("T1543.002", "Systemd Service"),
                ("T1546.004", "Unix Shell Configuration Modification"),
                ("T1098.004", "SSH Authorized Keys"),
                ("T1574.006", "Dynamic Linker Hijacking"),
                ("T1505.003", "Web Shell"),
                ("T1037.004", "RC Scripts"),
            ],
            "privilege-escalation": [
                ("T1548.003", "Sudo and Sudo Caching"),
                ("T1068", "Exploitation for Privilege Escalation"),
                ("T1574.006", "Dynamic Linker Hijacking"),
                ("T1611", "Escape to Host"),
                ("T1543.002", "Systemd Service"),
                ("T1055", "Process Injection"),
            ],
            "defense-evasion": [
                ("T1027", "Obfuscated Files or Information"),
                ("T1562.001", "Disable or Modify Tools"),
                ("T1070.002", "Clear Linux or Mac System Logs"),
                ("T1070.004", "File Deletion"),
                ("T1036", "Masquerading"),
                ("T1222.002", "Linux and Mac File and Directory Permissions Modification"),
                ("T1564.001", "Hidden Files and Directories"),
                ("T1497", "Virtualization/Sandbox Evasion"),
                ("T1140", "Deobfuscate/Decode Files"),
            ],
            "credential-access": [
                ("T1003.008", "/etc/passwd and /etc/shadow"),
                ("T1552.004", "Private Keys"),
                ("T1552.001", "Credentials In Files"),
                ("T1056.001", "Keylogging"),
                ("T1555", "Credentials from Password Stores"),
                ("T1110.001", "Password Guessing"),
            ],
            "discovery": [
                ("T1082", "System Information Discovery"),
                ("T1057", "Process Discovery"),
                ("T1016", "System Network Configuration Discovery"),
                ("T1049", "System Network Connections Discovery"),
                ("T1033", "System Owner/User Discovery"),
                ("T1083", "File and Directory Discovery"),
                ("T1135", "Network Share Discovery"),
                ("T1069.001", "Local Groups"),
            ],
            "lateral-movement": [
                ("T1021.004", "SSH"),
                ("T1021.002", "SMB/Windows Admin Shares from Linux"),
                ("T1570", "Lateral Tool Transfer"),
                ("T1550.002", "Pass the Hash"),
                ("T1091", "Removable Media"),
            ],
            "collection": [
                ("T1005", "Data from Local System"),
                ("T1115", "Clipboard Data"),
                ("T1560.001", "Archive via Utility"),
                ("T1213", "Data from Information Repositories"),
                ("T1119", "Automated Collection"),
            ],
            "command-and-control": [
                ("T1071.001", "Web Protocols"),
                ("T1105", "Ingress Tool Transfer"),
                ("T1095", "Non-Application Layer Protocol"),
                ("T1573", "Encrypted Channel"),
                ("T1090", "Proxy"),
                ("T1132", "Data Encoding"),
            ],
            "exfiltration": [
                ("T1041", "Exfiltration Over C2 Channel"),
                ("T1020", "Automated Exfiltration"),
                ("T1567.002", "Exfiltration to Cloud Storage"),
                ("T1052.001", "Exfiltration over USB"),
            ],
            "impact": [
                ("T1486", "Data Encrypted for Impact"),
                ("T1490", "Inhibit System Recovery"),
                ("T1485", "Data Destruction"),
                ("T1529", "System Shutdown/Reboot"),
            ],
        },
        "data_sources": {
            "initial-access": ["process", "file", "dns", "network", "auth", "journald"],
            "execution": ["process", "command_line", "auditd_execve", "eBPF_exec"],
            "persistence": ["process", "file", "systemd", "cron", "ssh", "auditd"],
            "privilege-escalation": ["process", "auditd", "sudo", "capabilities", "container"],
            "defense-evasion": ["process", "file", "auditd", "journald", "eBPF"],
            "credential-access": ["process", "file", "auditd", "ssh", "pam"],
            "discovery": ["process", "command_line", "network", "auditd"],
            "lateral-movement": ["process", "network", "dns", "ssh", "smb"],
            "collection": ["process", "file", "clipboard", "archive"],
            "command-and-control": ["process", "network", "dns", "tls", "http"],
            "exfiltration": ["process", "file", "network", "dns", "cloud"],
            "impact": ["process", "file", "auditd", "volume", "systemd"],
        },
        "telemetry": {
            "default": ["process_create", "file_create", "network_connect"],
            "persistence": ["process_create", "file_modify", "service_change"],
            "credential-access": ["process_create", "file_read"],
            "defense-evasion": ["process_create", "file_delete", "log_clear"],
            "lateral-movement": ["process_create", "network_connect", "auth_event"],
        },
    },
    "macos": {
        "display": "macOS",
        "roadmap_id": "macos-detection-roadmap-300",
        "sensor_note": "EndpointSecurity for high-fidelity process/file/auth events, launchd/TCC/XPC/FSEvents for platform-specific persistence and privacy abuse, plus network/DNS/browser context.",
        "techniques": {
            "initial-access": [
                ("T1566.001", "Spearphishing Attachment"),
                ("T1566.002", "Spearphishing Link"),
                ("T1195.002", "Compromise Software Supply Chain"),
                ("T1091", "Replication Through Removable Media"),
                ("T1078", "Valid Accounts"),
            ],
            "execution": [
                ("T1059.004", "Unix Shell"),
                ("T1059.006", "Python"),
                ("T1204.002", "Malicious File"),
                ("T1106", "Native API"),
                ("T1569.001", "Launchctl"),
                ("T1129", "Shared Modules"),
                ("T1059.002", "AppleScript/JXA"),
            ],
            "persistence": [
                ("T1543.001", "Launch Agent"),
                ("T1543.004", "Launch Daemon"),
                ("T1547.011", "Plist Modification"),
                ("T1037.002", "Login Hook"),
                ("T1546.004", "Unix Shell Configuration Modification"),
                ("T1574.006", "Dynamic Linker Hijacking"),
                ("T1505.003", "Web Shell"),
            ],
            "privilege-escalation": [
                ("T1548.003", "Sudo and Sudo Caching"),
                ("T1068", "Exploitation for Privilege Escalation"),
                ("T1548.001", "Setuid and Setgid"),
                ("T1574.006", "Dynamic Linker Hijacking"),
                ("T1055", "Process Injection"),
            ],
            "defense-evasion": [
                ("T1027", "Obfuscated Files or Information"),
                ("T1562.001", "Disable or Modify Tools"),
                ("T1070.002", "Clear Linux or Mac System Logs"),
                ("T1070.004", "File Deletion"),
                ("T1036", "Masquerading"),
                ("T1222.002", "File and Directory Permissions Modification"),
                ("T1564.001", "Hidden Files and Directories"),
                ("T1553.001", "Gatekeeper Bypass"),
                ("T1140", "Deobfuscate/Decode Files"),
            ],
            "credential-access": [
                ("T1555.001", "Keychain"),
                ("T1552.004", "Private Keys"),
                ("T1552.001", "Credentials In Files"),
                ("T1056.001", "Keylogging"),
                ("T1110.001", "Password Guessing"),
                ("T1003", "OS Credential Dumping Safe Simulation"),
            ],
            "discovery": [
                ("T1082", "System Information Discovery"),
                ("T1057", "Process Discovery"),
                ("T1016", "System Network Configuration Discovery"),
                ("T1049", "System Network Connections Discovery"),
                ("T1033", "System Owner/User Discovery"),
                ("T1083", "File and Directory Discovery"),
                ("T1518.001", "Security Software Discovery"),
                ("T1124", "System Time Discovery"),
            ],
            "lateral-movement": [
                ("T1021.004", "SSH"),
                ("T1021.002", "SMB/Admin Shares"),
                ("T1570", "Lateral Tool Transfer"),
                ("T1021.005", "VNC"),
                ("T1091", "Removable Media"),
            ],
            "collection": [
                ("T1005", "Data from Local System"),
                ("T1115", "Clipboard Data"),
                ("T1560.001", "Archive via Utility"),
                ("T1113", "Screen Capture"),
                ("T1123", "Audio Capture"),
            ],
            "command-and-control": [
                ("T1071.001", "Web Protocols"),
                ("T1105", "Ingress Tool Transfer"),
                ("T1095", "Non-Application Layer Protocol"),
                ("T1573", "Encrypted Channel"),
                ("T1090", "Proxy"),
                ("T1132", "Data Encoding"),
            ],
            "exfiltration": [
                ("T1041", "Exfiltration Over C2 Channel"),
                ("T1020", "Automated Exfiltration"),
                ("T1567.002", "Exfiltration to Cloud Storage"),
                ("T1052.001", "Exfiltration over USB"),
            ],
            "impact": [
                ("T1486", "Data Encrypted for Impact"),
                ("T1490", "Inhibit System Recovery"),
                ("T1485", "Data Destruction"),
                ("T1529", "System Shutdown/Reboot"),
            ],
        },
        "data_sources": {
            "initial-access": ["EndpointSecurity", "process", "file", "dns", "network", "browser"],
            "execution": ["EndpointSecurity", "process", "command_line", "script", "xpc"],
            "persistence": ["EndpointSecurity", "launchd", "plist", "file", "tcc", "xpc"],
            "privilege-escalation": ["EndpointSecurity", "auth", "sudo", "setuid", "tcc"],
            "defense-evasion": ["EndpointSecurity", "file", "log", "gatekeeper", "quarantine"],
            "credential-access": ["EndpointSecurity", "keychain", "file", "tcc", "browser"],
            "discovery": ["process", "command_line", "network", "system_profiler"],
            "lateral-movement": ["process", "network", "dns", "ssh", "smb", "vnc"],
            "collection": ["process", "file", "clipboard", "screen", "microphone", "tcc"],
            "command-and-control": ["process", "network", "dns", "tls", "http"],
            "exfiltration": ["process", "file", "network", "dns", "cloud"],
            "impact": ["process", "file", "EndpointSecurity", "volume"],
        },
        "telemetry": {
            "default": ["process_create", "file_create", "network_connect"],
            "persistence": ["process_create", "file_modify", "launchd_plist"],
            "credential-access": ["process_create", "file_read", "tcc_access"],
            "defense-evasion": ["process_create", "file_delete", "log_clear"],
            "lateral-movement": ["process_create", "network_connect", "auth_event"],
        },
    },
}


def priority_for(tactic: str, ordinal: int) -> str:
    if tactic in {"execution", "defense-evasion", "credential-access", "lateral-movement", "command-and-control"}:
        return "P0" if ordinal <= 12 else ("P1" if ordinal <= 24 else "P2")
    if tactic in {"persistence", "privilege-escalation", "impact", "exfiltration"}:
        return "P0" if ordinal <= 8 else ("P1" if ordinal <= 18 else "P2")
    return "P0" if ordinal <= 5 else ("P1" if ordinal <= 12 else "P2")


def safe_level(tactic: str, variant: str) -> str:
    if variant in {"benign-contrast", "telemetry-contract"}:
        return "safe"
    if tactic in {"credential-access", "impact", "privilege-escalation"}:
        return "simulated-safe"
    if variant in {"kernel-backed", "response-readiness"}:
        return "lab-only-safe"
    return "safe"


def expected_telemetry(config: dict[str, object], tactic: str) -> list[str]:
    telemetry = config["telemetry"]
    assert isinstance(telemetry, dict)
    return list(telemetry.get(tactic) or telemetry["default"])


def build(platform: str, config: dict[str, object]) -> list[dict[str, object]]:
    techniques = config["techniques"]
    data_sources = config["data_sources"]
    assert isinstance(techniques, dict)
    assert isinstance(data_sources, dict)
    scenarios: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    for tactic, target in TACTIC_COUNTS:
        tactic_techniques = techniques[tactic]
        while counts[tactic] < target:
            ordinal = counts[tactic] + 1
            technique_id, technique_name = tactic_techniques[(ordinal - 1) % len(tactic_techniques)]
            variant, executor, goal = VARIANTS[(ordinal - 1) % len(VARIANTS)]
            counts[tactic] += 1
            scenario_id = f"{platform[:3]}-{tactic.replace('-', '')}-{ordinal:03d}"
            scenarios.append(
                {
                    "id": scenario_id,
                    "platform": platform,
                    "tactic": tactic,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "variant": variant,
                    "name": f"{technique_name}: {variant.replace('-', ' ')}",
                    "priority": priority_for(tactic, ordinal),
                    "status": "planned",
                    "executor": executor,
                    "safe_level": safe_level(tactic, variant),
                    "expected_telemetry": expected_telemetry(config, tactic),
                    "expected_fields": [
                        "agent_id",
                        "hostname",
                        "process_name",
                        "command_line",
                        "parent_process_name",
                        "user",
                    ],
                    "expected_data_sources": data_sources[tactic],
                    "detection_goal": goal,
                    "alert_goal": "Generate detection/alert according to variant, with MITRE, evidence and storyline context.",
                    "storyline_goal": "Attach process, file/registry/network/auth context and edge reason when related events exist.",
                    "false_positive_guard": "Pair with benign workload before promotion to release gate.",
                    "product_gap_to_close": "Needs runnable profile implementation and lab evidence.",
                }
            )
    assert len(scenarios) == 300
    assert len({item["id"] for item in scenarios}) == 300
    return scenarios


def write_json(platform: str, config: dict[str, object], scenarios: list[dict[str, object]]) -> Path:
    ROADMAP_DIR.mkdir(parents=True, exist_ok=True)
    path = ROADMAP_DIR / f"{platform}_detection_roadmap_300.json"
    payload = {
        "schema_version": 1,
        "roadmap_id": config["roadmap_id"],
        "platform": platform,
        "scenario_count": len(scenarios),
        "sensor_note": config["sensor_note"],
        "scenario_status_counts": dict(Counter(str(s["status"]) for s in scenarios)),
        "priority_counts": dict(Counter(str(s["priority"]) for s in scenarios)),
        "tactic_counts": dict(Counter(str(s["tactic"]) for s in scenarios)),
        "executor_counts": dict(Counter(str(s["executor"]) for s in scenarios)),
        "scenarios": scenarios,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def write_md(platform: str, config: dict[str, object], scenarios: list[dict[str, object]]) -> Path:
    DOC_DIR.mkdir(parents=True, exist_ok=True)
    path = DOC_DIR / f"{platform.upper()}_DETECTION_ROADMAP_300.md"
    by_tactic: dict[str, list[dict[str, object]]] = defaultdict(list)
    for scenario in scenarios:
        by_tactic[str(scenario["tactic"])].append(scenario)
    lines = [
        f"# {config['display']} Detection Roadmap 300",
        "",
        f"This roadmap maps 300 {config['display']} EDR validation scenarios for Tamandua. It is a backlog and coverage model, not a current product claim.",
        "",
        f"Sensor model: {config['sensor_note']}",
        "",
        "## Summary",
        "",
        f"- Total scenarios: `{len(scenarios)}`",
        f"- Status counts: `{dict(Counter(str(s['status']) for s in scenarios))}`",
        f"- Priority counts: `{dict(Counter(str(s['priority']) for s in scenarios))}`",
        f"- Executor counts: `{dict(Counter(str(s['executor']) for s in scenarios))}`",
        "",
        "## Promotion Rules",
        "",
        "- `P0`: required for credible platform support.",
        "- `P1`: required for enterprise validation and public benchmark snapshots.",
        "- `P2`: advanced variants, stress cases and edge cases.",
        "",
    ]
    for tactic, _count in TACTIC_COUNTS:
        items = by_tactic[tactic]
        lines.extend(
            [
                f"## {tactic.replace('-', ' ').title()} ({len(items)})",
                "",
                "| ID | Priority | Status | Technique | Variant | Executor | Safe Level | Data Sources |",
                "|----|----------|--------|-----------|---------|----------|------------|--------------|",
            ]
        )
        for item in items:
            sources = ", ".join(item["expected_data_sources"])
            lines.append(
                f"| `{item['id']}` | `{item['priority']}` | `{item['status']}` | "
                f"`{item['technique_id']}` {item['technique_name']} | `{item['variant']}` | "
                f"`{item['executor']}` | `{item['safe_level']}` | `{sources}` |"
            )
        lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> int:
    for platform, config in PLATFORMS.items():
        scenarios = build(platform, config)
        json_path = write_json(platform, config, scenarios)
        md_path = write_md(platform, config, scenarios)
        print(f"{platform}: scenarios={len(scenarios)} json={json_path} md={md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
