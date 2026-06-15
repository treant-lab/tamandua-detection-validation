#!/usr/bin/env python3
"""Generate the Windows detection roadmap with 300 benchmark scenarios.

The output is intentionally product-oriented rather than a runnable profile.
Each scenario is a backlog item that can later become an Atomic, CALDERA,
deterministic command, sensor contract, or manual validation test.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
PROFILE_DIR = ROOT / "tools" / "detection_validation" / "profiles"
JSON_OUT = ROOT / "tools" / "detection_validation" / "roadmaps" / "windows_detection_roadmap_300.json"
MD_OUT = ROOT / "docs" / "benchmarks" / "WINDOWS_DETECTION_ROADMAP_300.md"


TACTICS = [
    ("initial-access", 15),
    ("execution", 30),
    ("persistence", 25),
    ("privilege-escalation", 25),
    ("defense-evasion", 40),
    ("credential-access", 30),
    ("discovery", 30),
    ("lateral-movement", 25),
    ("collection", 20),
    ("command-and-control", 25),
    ("exfiltration", 15),
    ("impact", 20),
]


TECHNIQUES = {
    "initial-access": [
        ("T1566.001", "Spearphishing Attachment"),
        ("T1566.002", "Spearphishing Link"),
        ("T1190", "Exploit Public-Facing Application"),
        ("T1133", "External Remote Services"),
        ("T1091", "Replication Through Removable Media"),
    ],
    "execution": [
        ("T1059.001", "PowerShell"),
        ("T1059.003", "Windows Command Shell"),
        ("T1047", "Windows Management Instrumentation"),
        ("T1204.002", "Malicious File"),
        ("T1053.005", "Scheduled Task"),
        ("T1106", "Native API"),
        ("T1129", "Shared Modules"),
        ("T1569.002", "Service Execution"),
    ],
    "persistence": [
        ("T1547.001", "Registry Run Keys / Startup Folder"),
        ("T1053.005", "Scheduled Task"),
        ("T1543.003", "Windows Service"),
        ("T1136.001", "Local Account"),
        ("T1505.003", "Web Shell"),
        ("T1574.001", "DLL Search Order Hijacking"),
        ("T1546.003", "WMI Event Subscription"),
    ],
    "privilege-escalation": [
        ("T1548.002", "Bypass User Account Control"),
        ("T1055", "Process Injection"),
        ("T1134", "Access Token Manipulation"),
        ("T1068", "Exploitation for Privilege Escalation"),
        ("T1574.011", "Services Registry Permissions Weakness"),
        ("T1543.003", "Windows Service"),
    ],
    "defense-evasion": [
        ("T1027", "Obfuscated Files or Information"),
        ("T1562.001", "Disable or Modify Tools"),
        ("T1070.004", "File Deletion"),
        ("T1112", "Modify Registry"),
        ("T1218.010", "Regsvr32"),
        ("T1218.011", "Rundll32"),
        ("T1218.005", "Mshta"),
        ("T1140", "Deobfuscate/Decode Files"),
        ("T1036", "Masquerading"),
        ("T1564.001", "Hidden Files and Directories"),
        ("T1497", "Virtualization/Sandbox Evasion"),
    ],
    "credential-access": [
        ("T1003.001", "LSASS Memory"),
        ("T1552.001", "Credentials In Files"),
        ("T1555.003", "Credentials From Web Browsers"),
        ("T1110.001", "Password Guessing"),
        ("T1558.003", "Kerberoasting"),
        ("T1552.006", "Group Policy Preferences"),
        ("T1056.001", "Keylogging"),
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
        ("T1124", "System Time Discovery"),
        ("T1518.001", "Security Software Discovery"),
    ],
    "lateral-movement": [
        ("T1021.002", "SMB/Windows Admin Shares"),
        ("T1021.006", "Windows Remote Management"),
        ("T1047", "Windows Management Instrumentation"),
        ("T1570", "Lateral Tool Transfer"),
        ("T1563.002", "RDP Hijacking"),
        ("T1550.002", "Pass the Hash"),
    ],
    "collection": [
        ("T1005", "Data from Local System"),
        ("T1115", "Clipboard Data"),
        ("T1560.001", "Archive via Utility"),
        ("T1113", "Screen Capture"),
        ("T1056.001", "Keylogging"),
        ("T1213", "Data from Information Repositories"),
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
        ("T1030", "Data Transfer Size Limits"),
    ],
    "impact": [
        ("T1486", "Data Encrypted for Impact"),
        ("T1490", "Inhibit System Recovery"),
        ("T1485", "Data Destruction"),
        ("T1491.001", "Internal Defacement"),
        ("T1529", "System Shutdown/Reboot"),
        ("T1565.001", "Stored Data Manipulation"),
    ],
}


VARIANTS = [
    ("telemetry-contract", "sensor_contract", "telemetry", "enterprise-eval", "Validate raw event and canonical fields."),
    (
        "atomic-safe",
        "atomic_or_command",
        "atomic-upstream-candidate",
        "enterprise-eval",
        "Run upstream Atomic test or deterministic safe fallback.",
    ),
    (
        "caldera-chain",
        "caldera_operation",
        "caldera-upstream-candidate",
        "caldera-upstream",
        "Validate multi-step adversary-emulation evidence.",
    ),
    ("correlation-storyline", "correlation", "correlation", "enterprise-eval", "Validate storyline grouping and causal edge reason."),
    ("alert-quality", "alert_quality", "alert-quality", "enterprise-eval", "Validate rule title, severity, MITRE, evidence and analyst context."),
    ("benign-contrast", "benign_baseline", "benign-baseline", "enterprise-eval", "Validate benign analogue does not create high/critical noise."),
    ("response-readiness", "response_harness", "response", "enterprise-eval", "Validate suggested safe response and audit trail."),
    ("driver-backed", "driver_contract", "driver", "enterprise-eval", "Validate kernel/driver source when applicable."),
]


TACTIC_DATA_SOURCES = {
    "initial-access": ["process", "file", "dns", "network", "browser"],
    "execution": ["process", "command_line", "parent_process", "script"],
    "persistence": ["process", "registry", "file", "scheduled_task", "service"],
    "privilege-escalation": ["process", "registry", "token", "service", "driver"],
    "defense-evasion": ["process", "file", "registry", "module_load", "driver"],
    "credential-access": ["process", "file", "registry", "browser", "memory", "driver"],
    "discovery": ["process", "command_line", "network", "registry"],
    "lateral-movement": ["process", "network", "dns", "wmi", "winrm"],
    "collection": ["process", "file", "clipboard", "screen", "archive"],
    "command-and-control": ["process", "network", "dns", "tls", "http"],
    "exfiltration": ["process", "file", "network", "dns", "cloud"],
    "impact": ["process", "file", "registry", "driver", "volume_shadow"],
}


TACTIC_TELEMETRY = {
    "initial-access": ["process_create", "file_create", "dns_query", "network_connect"],
    "execution": ["process_create"],
    "persistence": ["process_create", "registry_set_value", "file_create"],
    "privilege-escalation": ["process_create", "registry_set_value", "process_access"],
    "defense-evasion": ["process_create", "file_modify", "registry_set_value", "module_load"],
    "credential-access": ["process_create", "file_read", "process_access"],
    "discovery": ["process_create"],
    "lateral-movement": ["process_create", "network_connect", "dns_query"],
    "collection": ["process_create", "file_create", "file_read"],
    "command-and-control": ["process_create", "network_connect", "dns_query"],
    "exfiltration": ["process_create", "file_read", "network_connect"],
    "impact": ["process_create", "file_modify", "file_delete", "registry_set_value"],
}


def existing_profile_index() -> dict[str, list[str]]:
    index: dict[str, list[str]] = defaultdict(list)
    for path in sorted(PROFILE_DIR.glob("*.json")):
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        profile_id = profile.get("profile_id") or path.stem
        if profile.get("platform") not in {None, "windows"}:
            continue
        if str(profile_id).startswith("windows-roadmap-300-batch-"):
            continue
        for test in profile.get("tests") or []:
            for tag in test.get("tags") or []:
                if isinstance(tag, str) and tag.startswith("mitre:"):
                    index[tag.removeprefix("mitre:")].append(profile_id)
            atomic = test.get("atomic") or {}
            if atomic.get("technique"):
                index[str(atomic["technique"])].append(profile_id)
            caldera = test.get("caldera") or {}
            for ability in caldera.get("abilities") or []:
                if ability.get("mitre"):
                    index[str(ability["mitre"])].append(profile_id)
    return {key: sorted(set(values)) for key, values in index.items()}


def priority_for(tactic: str, ordinal: int) -> str:
    if tactic in {"execution", "defense-evasion", "credential-access", "lateral-movement", "command-and-control"}:
        return "P0" if ordinal <= 12 else ("P1" if ordinal <= 24 else "P2")
    if tactic in {"persistence", "privilege-escalation", "impact", "exfiltration"}:
        return "P0" if ordinal <= 8 else ("P1" if ordinal <= 18 else "P2")
    return "P0" if ordinal <= 5 else ("P1" if ordinal <= 12 else "P2")


def safe_level_for(tactic: str, variant_slug: str) -> str:
    if variant_slug in {"benign-contrast", "telemetry-contract"}:
        return "safe"
    if tactic in {"credential-access", "impact", "privilege-escalation"}:
        return "simulated-safe"
    if variant_slug in {"driver-backed", "response-readiness"}:
        return "lab-only-safe"
    return "safe"


def scenario_name(tactic: str, technique_name: str, variant_label: str) -> str:
    return f"{technique_name}: {variant_label}"


def build_scenarios() -> list[dict[str, object]]:
    profile_index = existing_profile_index()
    scenarios: list[dict[str, object]] = []
    tactic_counts: Counter[str] = Counter()

    for tactic, target_count in TACTICS:
        techniques = TECHNIQUES[tactic]
        cursor = 0
        while tactic_counts[tactic] < target_count:
            technique_id, technique_name = techniques[cursor % len(techniques)]
            tactic_counts[tactic] += 1
            ordinal = tactic_counts[tactic]
            variant_slug, executor, validation_category, benchmark_lane, variant_goal = VARIANTS[(ordinal - 1) % len(VARIANTS)]
            scenario_id = f"win-{tactic.replace('-', '')}-{ordinal:03d}"
            refs = profile_index.get(technique_id, [])
            priority = priority_for(tactic, ordinal)
            status = "covered-by-existing-profile" if refs else "planned"
            upstream_target_lane = None
            if executor == "atomic_or_command":
                upstream_target_lane = "atomic-upstream"
            elif executor == "caldera_operation":
                upstream_target_lane = "caldera-upstream"
            scenarios.append(
                {
                    "id": scenario_id,
                    "platform": "windows",
                    "tactic": tactic,
                    "category": validation_category,
                    "validation_category": validation_category,
                    "benchmark_lane": benchmark_lane,
                    "upstream_target_lane": upstream_target_lane,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "variant": variant_slug,
                    "name": scenario_name(tactic, technique_name, variant_slug.replace("-", " ")),
                    "priority": priority,
                    "status": status,
                    "executor": executor,
                    "safe_level": safe_level_for(tactic, variant_slug),
                    "existing_profile_refs": refs,
                    "traceability": {
                        "technique": technique_id,
                        "technique_name": technique_name,
                        "tactic": tactic,
                        "category": validation_category,
                        "lane": benchmark_lane,
                        "executor": executor,
                        "upstream_target_lane": upstream_target_lane,
                        "existing_profile_refs": refs,
                    },
                    "expected_telemetry": TACTIC_TELEMETRY[tactic],
                    "expected_fields": [
                        "agent_id",
                        "hostname",
                        "process_name",
                        "command_line",
                        "parent_process_name",
                        "user",
                    ],
                    "expected_data_sources": TACTIC_DATA_SOURCES[tactic],
                    "detection_goal": variant_goal,
                    "alert_goal": (
                        "Generate an actionable alert with MITRE, rule reason, evidence fields and storyline link."
                        if variant_slug in {"alert-quality", "caldera-chain", "correlation-storyline"}
                        else "Generate detection or explicit no-alert baseline according to variant."
                    ),
                    "storyline_goal": "Attach process, file/registry/network context and edge reason when related events exist.",
                    "false_positive_guard": "Include a benign contrast or baseline window before promotion to P0 release gate.",
                    "product_gap_to_close": (
                        "Needs runnable profile implementation and lab evidence."
                        if not refs
                        else "Existing profile coverage exists; verify quality gate and enrich evidence if weak."
                    ),
                }
            )
            cursor += 1

    assert len(scenarios) == 300, len(scenarios)
    assert len({scenario["id"] for scenario in scenarios}) == 300
    return scenarios


def write_json(scenarios: list[dict[str, object]]) -> None:
    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "schema_version": 1,
        "roadmap_id": "windows-detection-roadmap-300",
        "platform": "windows",
        "scenario_count": len(scenarios),
        "purpose": "Roadmap for evolving Tamandua Windows EDR detection validation toward broad enterprise coverage.",
        "promotion_model": {
            "P0": "Must become runnable and stable before beta claims.",
            "P1": "Needed for strong enterprise evaluation and public validation.",
            "P2": "Advanced coverage, deeper variants, and edge cases.",
        },
        "scenario_status_counts": dict(Counter(str(s["status"]) for s in scenarios)),
        "priority_counts": dict(Counter(str(s["priority"]) for s in scenarios)),
        "tactic_counts": dict(Counter(str(s["tactic"]) for s in scenarios)),
        "category_counts": dict(Counter(str(s["validation_category"]) for s in scenarios)),
        "benchmark_lane_counts": dict(Counter(str(s["benchmark_lane"]) for s in scenarios)),
        "executor_counts": dict(Counter(str(s["executor"]) for s in scenarios)),
        "scenarios": scenarios,
    }
    JSON_OUT.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def write_markdown(scenarios: list[dict[str, object]]) -> None:
    MD_OUT.parent.mkdir(parents=True, exist_ok=True)
    by_tactic: dict[str, list[dict[str, object]]] = defaultdict(list)
    for scenario in scenarios:
        by_tactic[str(scenario["tactic"])].append(scenario)

    lines = [
        "# Windows Detection Roadmap 300",
        "",
        "This roadmap maps 300 Windows EDR validation scenarios for Tamandua. It is not a claim that all scenarios are currently implemented. It is the execution backlog for turning current Atomic/CALDERA/profile coverage into a broad, measurable detection program.",
        "",
        "## Summary",
        "",
        f"- Total scenarios: `{len(scenarios)}`",
        f"- Status counts: `{dict(Counter(str(s['status']) for s in scenarios))}`",
        f"- Priority counts: `{dict(Counter(str(s['priority']) for s in scenarios))}`",
        f"- Category counts: `{dict(Counter(str(s['validation_category']) for s in scenarios))}`",
        f"- Benchmark lane counts: `{dict(Counter(str(s['benchmark_lane']) for s in scenarios))}`",
        f"- Executor counts: `{dict(Counter(str(s['executor']) for s in scenarios))}`",
        "",
        "## Promotion Rules",
        "",
        "- `P0`: must be runnable, low-noise, and backed by persisted events before beta claims.",
        "- `P1`: should be runnable for strong enterprise evaluation and public validation snapshots.",
        "- `P2`: advanced variants and edge cases; useful for maturity but not required for first beta.",
        "",
        "A scenario is not complete until it has event evidence, detection/alert expectations when applicable, false-positive guardrails, and a reproducible run artifact.",
        "",
    ]

    for tactic, _target in TACTICS:
        items = by_tactic[tactic]
        lines.extend(
            [
                f"## {tactic.replace('-', ' ').title()} ({len(items)})",
                "",
                "| ID | Priority | Status | Technique | Category | Lane | Variant | Executor | Safe Level | Existing refs |",
                "|----|----------|--------|-----------|----------|------|---------|----------|------------|---------------|",
            ]
        )
        for item in items:
            refs = ", ".join(item["existing_profile_refs"]) if item["existing_profile_refs"] else "-"
            lines.append(
                f"| `{item['id']}` | `{item['priority']}` | `{item['status']}` | "
                f"`{item['technique_id']}` {item['technique_name']} | `{item['validation_category']}` | "
                f"`{item['benchmark_lane']}` | `{item['variant']}` | "
                f"`{item['executor']}` | `{item['safe_level']}` | `{refs}` |"
            )
        lines.append("")

    MD_OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    scenarios = build_scenarios()
    write_json(scenarios)
    write_markdown(scenarios)
    print(f"wrote {JSON_OUT}")
    print(f"wrote {MD_OUT}")
    print(f"scenarios={len(scenarios)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
