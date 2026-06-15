#!/usr/bin/env python3
"""Generate focused validation batches from the 900-scenario roadmaps."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from generate_windows_p0_roadmap_profile import COMMANDS as WINDOWS_COMMANDS


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
ROADMAP_DIR = ROOT / "tools" / "detection_validation" / "roadmaps"
PROFILE_DIR = ROOT / "tools" / "detection_validation" / "profiles"


WINDOWS_REQUIRED_FIELDS = ["agent_id", "hostname", "process_name", "command_line", "parent_process_name"]
UNIX_REQUIRED_FIELDS = ["agent_id", "hostname", "process_name", "command_line", "user"]
LIVE_RESPONSE_AUDIT_REQUIRED_FIELDS = ["agent_id", "hostname", "command", "session_id"]
LIVE_RESPONSE_AUDIT_TELEMETRY = "live_response_command_completed"
OPTIONAL_TELEMETRY = [
    "file_create",
    "file_modify",
    "file_delete",
    "network_connect",
    "dns_query",
    "registry_set_value",
]

WINDOWS_TECHNIQUE_TELEMETRY = {
    "T1547.001": ["process_create", "registry_set_value"],
    "T1505.003": ["process_create", "file_create"],
}
WINDOWS_TECHNIQUE_TELEMETRY_ANY = {
    "T1505.003": [
        ["process_create", "file_create"],
        ["process_create", "file_modify"],
        ["process_create", "file_delete"],
    ],
}


UNIX_COMMANDS_BY_TACTIC = {
    "initial-access": "sh -lc 'echo tamandua-initial-access > /tmp/tamandua-initial-access.txt; cat /tmp/tamandua-initial-access.txt >/dev/null; rm -f /tmp/tamandua-initial-access.txt'",
    "execution": "sh -lc 'id >/dev/null; uname -a >/dev/null; echo tamandua-execution'",
    "persistence": "sh -lc 'mkdir -p /tmp/tamandua-persistence; echo tamandua >/tmp/tamandua-persistence/marker; ls /tmp/tamandua-persistence >/dev/null; rm -rf /tmp/tamandua-persistence'",
    "privilege-escalation": "sh -lc 'id; groups; whoami'",
    "defense-evasion": "sh -lc 'mktemp /tmp/tamandua-hidden.XXXXXX >/tmp/tamandua-path.txt; p=$(cat /tmp/tamandua-path.txt); mv \"$p\" \"${p}.renamed\"; rm -f \"${p}.renamed\" /tmp/tamandua-path.txt'",
    "credential-access": "sh -lc 'test -r /etc/passwd && head -n 1 /etc/passwd >/dev/null; id >/dev/null'",
    "discovery": "sh -lc 'whoami; hostname; uname -a; ps -eo pid,comm | head'",
    "lateral-movement": "sh -lc 'hostname; id; getent hosts localhost || true'",
    "collection": "sh -lc 'mkdir -p /tmp/tamandua-collection; echo sample >/tmp/tamandua-collection/sample.txt; tar -cf /tmp/tamandua-collection.tar -C /tmp/tamandua-collection sample.txt; rm -rf /tmp/tamandua-collection /tmp/tamandua-collection.tar'",
    "command-and-control": "sh -lc 'getent hosts example.com >/dev/null || nslookup example.com >/dev/null 2>&1 || true'",
    "exfiltration": "sh -lc 'printf tamandua | base64 >/tmp/tamandua-exfil.txt; rm -f /tmp/tamandua-exfil.txt'",
    "impact": "sh -lc 'echo before >/tmp/tamandua-impact.txt; echo after >>/tmp/tamandua-impact.txt; rm -f /tmp/tamandua-impact.txt'",
}

MACOS_COMMANDS_BY_TACTIC = {
    "initial-access": "sh -lc 'echo tamandua-initial-access > /tmp/tamandua-initial-access.txt; cat /tmp/tamandua-initial-access.txt >/dev/null; rm -f /tmp/tamandua-initial-access.txt'",
    "execution": "sh -lc 'id >/dev/null; sw_vers >/dev/null 2>&1 || uname -a >/dev/null; echo tamandua-execution'",
    "persistence": "sh -lc 'mkdir -p /tmp/tamandua-persistence; cat > /tmp/tamandua-persistence/com.tamandua.benchmark.plist <<EOF\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>com.tamandua.benchmark</string></dict></plist>\nEOF\nplutil -lint /tmp/tamandua-persistence/com.tamandua.benchmark.plist >/dev/null 2>&1 || true; rm -rf /tmp/tamandua-persistence'",
    "privilege-escalation": "sh -lc 'id; groups; whoami; find /usr/bin -perm -4000 -maxdepth 1 -type f 2>/dev/null | head -n 5'",
    "defense-evasion": "sh -lc 'p=$(mktemp /tmp/tamandua-hidden.XXXXXX); mv \"$p\" \"$(dirname \"$p\")/.tamandua-hidden\"; chmod 600 \"$(dirname \"$p\")/.tamandua-hidden\"; rm -f \"$(dirname \"$p\")/.tamandua-hidden\"'",
    "credential-access": "sh -lc 'test -r /etc/passwd && head -n 1 /etc/passwd >/dev/null; security list-keychains >/dev/null 2>&1 || true; id >/dev/null'",
    "discovery": "sh -lc 'whoami; hostname; sw_vers 2>/dev/null || uname -a; ps -axo pid,comm | head'",
    "lateral-movement": "sh -lc 'hostname; id; dscacheutil -q host -a name localhost >/dev/null 2>&1 || true; smbutil statshares -a >/dev/null 2>&1 || true'",
    "collection": "sh -lc 'mkdir -p /tmp/tamandua-collection; echo sample >/tmp/tamandua-collection/sample.txt; tar -cf /tmp/tamandua-collection.tar -C /tmp/tamandua-collection sample.txt; rm -rf /tmp/tamandua-collection /tmp/tamandua-collection.tar'",
    "command-and-control": "sh -lc 'dscacheutil -q host -a name example.com >/dev/null 2>&1 || nslookup example.com >/dev/null 2>&1 || true'",
    "exfiltration": "sh -lc 'printf tamandua | base64 >/tmp/tamandua-exfil.txt; rm -f /tmp/tamandua-exfil.txt'",
    "impact": "sh -lc 'echo before >/tmp/tamandua-impact.txt; echo after >>/tmp/tamandua-impact.txt; rm -f /tmp/tamandua-impact.txt'",
}

WINDOWS_COMMANDS_BY_TACTIC = {
    "initial-access": "cmd.exe /d /c \"echo tamandua-initial-access>%TEMP%\\tamandua-initial-access.txt & type %TEMP%\\tamandua-initial-access.txt > nul & del /f /q %TEMP%\\tamandua-initial-access.txt\"",
    "execution": "cmd.exe /d /c \"whoami & hostname & ver\"",
    "persistence": "cmd.exe /d /c \"schtasks.exe /Query /TN \\Microsoft\\Windows\\Defrag\\ScheduledDefrag 2>nul || schtasks.exe /Query /FO CSV /NH\"",
    "privilege-escalation": "cmd.exe /d /c \"whoami /groups & whoami /priv\"",
    "defense-evasion": "cmd.exe /d /c \"echo tamandua>%TEMP%\\tamandua-evasion.txt & attrib +h %TEMP%\\tamandua-evasion.txt & attrib -h %TEMP%\\tamandua-evasion.txt & del /f /q %TEMP%\\tamandua-evasion.txt\"",
    "credential-access": "cmd.exe /d /c \"whoami /user & cmdkey /list 2>nul\"",
    "discovery": "cmd.exe /d /c \"whoami & hostname & ipconfig /all\"",
    "lateral-movement": "cmd.exe /d /c \"net view \\\\localhost 2>nul || whoami\"",
    "collection": "cmd.exe /d /c \"mkdir %TEMP%\\tamandua-collection 2>nul & echo sample>%TEMP%\\tamandua-collection\\sample.txt & tar.exe -a -c -f %TEMP%\\tamandua-collection.zip -C %TEMP%\\tamandua-collection sample.txt & del /f /q %TEMP%\\tamandua-collection.zip & rmdir /s /q %TEMP%\\tamandua-collection\"",
    "command-and-control": "cmd.exe /d /c \"nslookup example.com & curl.exe -I https://example.com/\"",
    "exfiltration": "cmd.exe /d /c \"echo tamandua-exfil>%TEMP%\\tamandua-exfil.txt & type %TEMP%\\tamandua-exfil.txt > nul & del /f /q %TEMP%\\tamandua-exfil.txt\"",
    "impact": "cmd.exe /d /c \"echo before>%TEMP%\\tamandua-impact.txt & echo after>>%TEMP%\\tamandua-impact.txt & del /f /q %TEMP%\\tamandua-impact.txt\"",
}


def load_roadmap(platform: str) -> dict[str, Any]:
    path = ROADMAP_DIR / f"{platform}_detection_roadmap_300.json"
    return json.loads(path.read_text(encoding="utf-8"))


def scenario_command(platform: str, scenario: dict[str, Any]) -> str | None:
    if platform == "windows":
        return WINDOWS_COMMANDS.get(str(scenario["technique_id"])) or WINDOWS_COMMANDS_BY_TACTIC.get(
            str(scenario["tactic"])
        )
    if platform == "macos":
        return MACOS_COMMANDS_BY_TACTIC.get(str(scenario["tactic"]))
    return UNIX_COMMANDS_BY_TACTIC.get(str(scenario["tactic"]))


def profile_test(platform: str, scenario: dict[str, Any]) -> dict[str, Any] | None:
    command = scenario_command(platform, scenario)
    if not command:
        return None

    tactic = str(scenario["tactic"])
    technique = str(scenario["technique_id"])
    scenario_id = str(scenario["id"])
    category = str(scenario.get("validation_category") or scenario.get("category") or scenario.get("executor"))
    lane = str(scenario.get("benchmark_lane") or "enterprise-eval")
    traceability = scenario.get("traceability") or {
        "technique": technique,
        "technique_name": scenario.get("technique_name"),
        "tactic": tactic,
        "category": category,
        "lane": lane,
        "executor": scenario.get("executor"),
        "upstream_target_lane": scenario.get("upstream_target_lane"),
        "existing_profile_refs": scenario.get("existing_profile_refs") or [],
    }
    expected_telemetry = (
        WINDOWS_TECHNIQUE_TELEMETRY.get(technique, ["process_create"])
        if platform == "windows"
        else ["process_create"]
    )
    test = {
        "id": f"roadmap-{scenario_id}-{technique.lower().replace('.', '-')}",
        "name": scenario["name"],
        "executor": "command",
        "fallback_command": command,
        "roadmap_traceability": traceability,
        "validation_category": category,
        "source_executor": scenario.get("executor"),
        "source_benchmark_lane": lane,
        "claim_boundary": (
            "deterministic fallback evidence for an Atomic candidate; not Atomic upstream proof"
            if scenario.get("executor") == "atomic_or_command"
            else "deterministic roadmap evidence; upstream claims require matching upstream lane artifacts"
        ),
        "expected_telemetry": expected_telemetry,
        "optional_telemetry": OPTIONAL_TELEMETRY,
        "tags": [
            f"{platform}-roadmap-batch",
            f"roadmap:{scenario_id}",
            f"tactic:{tactic}",
            f"mitre:{technique}",
            f"category:{category}",
            f"lane:{lane}",
            f"variant:{scenario['variant']}",
            f"executor:{scenario['executor']}",
            f"status:{scenario['status']}",
        ],
        "risk": "low" if scenario.get("safe_level") == "safe" else "medium",
    }
    if platform == "windows":
        telemetry_any = list(WINDOWS_TECHNIQUE_TELEMETRY_ANY.get(technique, []))
        telemetry_any.append([LIVE_RESPONSE_AUDIT_TELEMETRY])
        test.update(
            {
                "expected_telemetry_any": telemetry_any,
                "expected_fields_by_event_type": {
                    "process_create": WINDOWS_REQUIRED_FIELDS,
                    LIVE_RESPONSE_AUDIT_TELEMETRY: LIVE_RESPONSE_AUDIT_REQUIRED_FIELDS,
                },
                "telemetry_contract_notes": [
                    "process_create remains the strict endpoint telemetry expectation",
                    (
                        "T1505.003 accepts file_modify/file_delete as Windows file-system "
                        "evidence when the create edge is coalesced or missed"
                    )
                    if technique == "T1505.003"
                    else "",
                    (
                        f"{LIVE_RESPONSE_AUDIT_TELEMETRY} is accepted only as tamandua-ctl "
                        "live-response audit evidence when endpoint collection is unavailable or not_loaded"
                    ),
                ],
            }
        )
        test["telemetry_contract_notes"] = [note for note in test["telemetry_contract_notes"] if note]
    else:
        test["expected_fields"] = UNIX_REQUIRED_FIELDS
    return test


def unique_tests(scenarios: list[dict[str, Any]], platform: str, limit: int) -> list[dict[str, Any]]:
    tests = []
    seen: set[str] = set()
    for scenario in scenarios:
        test = profile_test(platform, scenario)
        if not test:
            continue
        key = str(test["id"])
        if key in seen:
            continue
        seen.add(key)
        tests.append(test)
        if limit and len(tests) >= limit:
            break
    return tests


def make_profile(
    platform: str,
    profile_id: str,
    name: str,
    description: str,
    purpose: str,
    scenarios: list[dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    tests = unique_tests(scenarios, platform, limit)
    quality_bar: dict[str, Any] = {
        "purpose": purpose,
        "requires_persisted_events": True,
        "max_unknown_source_events": 0,
        "max_unexpected_high_critical": 0,
    }
    if platform == "windows":
        quality_bar.update(
            {
                "requires_driver_health": True,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
            }
        )
    return {
        "schema_version": 1,
        "profile_id": profile_id,
        "name": name,
        "description": description,
        "platform": platform,
        "default_observation_seconds": 75,
        "benchmark_lane": "enterprise-eval",
        "quality_bar": quality_bar,
        "roadmap_selection": {
            "source": f"tools/detection_validation/roadmaps/{platform}_detection_roadmap_300.json",
            "selected_scenarios": len(scenarios),
            "generated_tests": len(tests),
            "limit": limit,
        },
        "tests": tests,
    }


def write_profile(profile: dict[str, Any]) -> Path:
    path = PROFILE_DIR / f"{profile['profile_id'].replace('-', '_')}.json"
    path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    return path


def build_profiles(limit: int) -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    windows = load_roadmap("windows")["scenarios"]
    windows_p0_existing = [
        scenario
        for scenario in windows
        if scenario["priority"] == "P0" and scenario["status"] == "covered-by-existing-profile"
    ]
    for executor in ["sensor_contract", "benign_baseline", "driver_contract"]:
        selected = [scenario for scenario in windows_p0_existing if scenario["executor"] == executor]
        profiles.append(
            make_profile(
                "windows",
                f"windows-roadmap-p0-existing-{executor.replace('_', '-')}",
                f"Windows Roadmap P0 Existing {executor.replace('_', ' ').title()}",
                "Focused batch that promotes Windows P0 scenarios already mapped to existing profiles into fresh evidence.",
                f"windows_p0_existing_{executor}",
                selected,
                limit,
            )
        )

    for platform in ["linux", "macos"]:
        scenarios = [
            scenario
            for scenario in load_roadmap(platform)["scenarios"]
            if scenario["priority"] == "P0" and scenario["executor"] == "sensor_contract"
        ]
        profiles.append(
            make_profile(
                platform,
                f"{platform}-roadmap-p0-sensor-contract-smoke",
                f"{platform.title()} Roadmap P0 Sensor Contract Smoke",
                "First P0 sensor-contract batch to move this platform out of planned-only state.",
                f"{platform}_p0_sensor_contract_smoke",
                scenarios,
                limit,
            )
        )
    return profiles


def build_roadmap_chunks(platform: str, chunk_size: int, priority: str | None) -> list[dict[str, Any]]:
    scenarios = load_roadmap(platform)["scenarios"]
    selected = [
        scenario
        for scenario in scenarios
        if priority is None or str(scenario.get("priority")) == priority
    ]
    profiles: list[dict[str, Any]] = []
    for index in range(0, len(selected), chunk_size):
        chunk = selected[index : index + chunk_size]
        chunk_no = index // chunk_size + 1
        suffix = f"{priority.lower()}-" if priority else ""
        display = "macOS" if platform == "macos" else platform.title()
        profiles.append(
            make_profile(
                platform,
                f"{platform}-roadmap-300-{suffix}batch-{chunk_no:02d}",
                f"{display} Roadmap 300 {priority + ' ' if priority else ''}Batch {chunk_no:02d}",
                f"Executable batch generated directly from the {display} 300-scenario roadmap.",
                f"{platform}_roadmap_300_{priority.lower() + '_' if priority else ''}batch_{chunk_no:02d}",
                chunk,
                0,
            )
        )
    return profiles


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=12, help="Maximum generated tests per profile")
    parser.add_argument(
        "--windows-roadmap-chunks",
        action="store_true",
        help="Generate executable Windows roadmap batches from all selected roadmap scenarios.",
    )
    parser.add_argument(
        "--roadmap-chunks",
        choices=["windows", "linux", "macos"],
        help="Generate executable roadmap batches for the selected platform.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=50,
        help="Number of tests per generated Windows roadmap chunk.",
    )
    parser.add_argument(
        "--priority",
        choices=["P0", "P1", "P2"],
        help="Limit generated Windows roadmap chunks to one priority.",
    )
    args = parser.parse_args()
    if args.chunk_size <= 0:
        parser.error("--chunk-size must be greater than zero")

    written = []
    chunk_platform = "windows" if args.windows_roadmap_chunks else args.roadmap_chunks
    profiles = build_roadmap_chunks(chunk_platform, args.chunk_size, args.priority) if chunk_platform else build_profiles(args.limit)
    for profile in profiles:
        path = write_profile(profile)
        written.append((path, len(profile["tests"])))

    for path, count in written:
        print(f"wrote {path.relative_to(ROOT)} tests={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
