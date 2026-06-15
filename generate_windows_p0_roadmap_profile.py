#!/usr/bin/env python3
"""Generate an executable profile for currently planned Windows P0 roadmap items."""

from __future__ import annotations

import json
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
ROADMAP = ROOT / "tools" / "detection_validation" / "roadmaps" / "windows_detection_roadmap_300.json"
OUT = ROOT / "tools" / "detection_validation" / "profiles" / "windows_roadmap_p0_safe_expansion.json"


COMMANDS = {
    "T1566.001": (
        "cmd.exe /d /c \"echo tamandua-phishing-attachment > %TEMP%\\tamandua-phishing-attachment.txt & "
        "type %TEMP%\\tamandua-phishing-attachment.txt & del /f /q %TEMP%\\tamandua-phishing-attachment.txt\""
    ),
    "T1566.002": "cmd.exe /d /c \"curl.exe -I https://example.com/\"",
    "T1190": "cmd.exe /d /c \"curl.exe -I http://127.0.0.1/ 2>nul || ver\"",
    "T1133": "cmd.exe /d /c \"qwinsta 2>nul || query user 2>nul || whoami\"",
    "T1091": (
        "cmd.exe /d /c \"mkdir %TEMP%\\tamandua-usb-sim 2>nul & "
        "echo autorun-canary>%TEMP%\\tamandua-usb-sim\\autorun.inf & "
        "dir %TEMP%\\tamandua-usb-sim & rmdir /s /q %TEMP%\\tamandua-usb-sim\""
    ),
    "T1204.002": (
        "cmd.exe /d /c \"echo @echo tamandua-user-execution>%TEMP%\\tamandua-clickme.bat & "
        "call %TEMP%\\tamandua-clickme.bat & del /f /q %TEMP%\\tamandua-clickme.bat\""
    ),
    "T1053.005": (
        "cmd.exe /d /c \"schtasks.exe /Create /TN TamanduaBenchTask /SC ONCE /ST 23:59 "
        "/TR %ComSpec% /RU SYSTEM /F > nul & "
        "schtasks.exe /Query /TN TamanduaBenchTask & schtasks.exe /Delete /TN TamanduaBenchTask /F > nul\""
    ),
    "T1106": (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
        "JABzAHIAYwAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzADsADQAKAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABjAGwAYQBzAHMAIABUAGEAbQBhAG4AZAB1AGEATgBhAHQAaQB2AGUAQQBwAGkAUAByAG8AYgBlACAAewAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIAKQBdACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAdQBpAG4AdAAgAEcAZQB0AFQAaQBjAGsAQwBvAHUAbgB0ACgAKQA7ACAAfQANAAoAIgBAADsAIABBAGQAZAAtAFQAeQBwAGUAIAAtAFQAeQBwAGUARABlAGYAaQBuAGkAdABpAG8AbgAgACQAcwByAGMAOwAgAFsAVABhAG0AYQBuAGQAdQBhAE4AYQB0AGkAdgBlAEEAcABpAFAAcgBvAGIAZQBdADoAOgBHAGUAdABUAGkAYwBrAEMAbwB1AG4AdAAoACkAIAB8ACAATwB1AHQALQBOAHUAbABsADsAIABTAHQAYQByAHQALQBTAGwAZQBlAHAAIAAtAFMAZQBjAG8AbgBkAHMAIAAzAA=="
    ),
    "T1129": "cmd.exe /d /c \"where kernel32.dll & where user32.dll\"",
    "T1574.011": (
        "cmd.exe /d /c \"sc.exe sdshow Spooler > nul 2>&1 & "
        "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler /v ImagePath\""
    ),
    "T1547.001": (
        "cmd.exe /d /c \"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        "/v TamanduaBenchRun /t REG_SZ /d tamandua-bench-run /f & "
        "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v TamanduaBenchRun & "
        "ping -n 8 127.0.0.1 > nul & "
        "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v TamanduaBenchRun /f\""
    ),
    "T1543.003": (
        "cmd.exe /d /c \"sc.exe create TamanduaBenchSvc binPath= %ComSpec% "
        "start= demand > nul & sc.exe query TamanduaBenchSvc & sc.exe delete TamanduaBenchSvc > nul\""
    ),
    "T1136.001": (
        "cmd.exe /d /c \"net user tamandua_bench P@ssw0rd123! /add & "
        "net user tamandua_bench & net user tamandua_bench /delete\""
    ),
    "T1505.003": (
        "cmd.exe /d /c \"echo ^<%% tamandua webshell canary %%^> > "
        "%TEMP%\\tamandua-webshell.aspx & type %TEMP%\\tamandua-webshell.aspx & "
        "ping -n 9 127.0.0.1 > nul & "
        "del /f /q %TEMP%\\tamandua-webshell.aspx\""
    ),
    "T1003.001": "cmd.exe /d /c \"tasklist.exe /FI \\\"IMAGENAME eq lsass.exe\\\" /NH > nul\"",
    "T1555.003": (
        "powershell.exe -NoProfile -Command \"$p=Join-Path $env:LOCALAPPDATA "
        "'Google\\Chrome\\User Data\\Default\\Login Data'; "
        "if (Test-Path -LiteralPath $p) { Get-Item -LiteralPath $p | Out-Null }\""
    ),
    "T1558.003": "cmd.exe /d /c \"setspn -Q */* 2>nul || whoami /user\"",
    "T1552.006": "cmd.exe /d /c \"dir \\\\localhost\\SYSVOL 2>nul || whoami\"",
    "T1056.001": "cmd.exe /d /c \"tasklist.exe /V /FI \\\"STATUS eq running\\\" /NH > nul\"",
    "T1570": (
        "cmd.exe /d /c \"echo tamandua-lateral-tool>%TEMP%\\tamandua-tool.exe & "
        "copy %TEMP%\\tamandua-tool.exe %TEMP%\\tamandua-tool-copy.exe > nul & "
        "del /f /q %TEMP%\\tamandua-tool.exe %TEMP%\\tamandua-tool-copy.exe\""
    ),
    "T1563.002": "cmd.exe /d /c \"query session 2>nul || qwinsta 2>nul || whoami\"",
    "T1550.002": "cmd.exe /d /c \"klist 2>nul || whoami /groups\"",
    "T1090": "cmd.exe /d /c \"netsh winhttp show proxy\"",
    "T1132": "powershell.exe -NoProfile -Command \"[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('tamandua-c2-encoding')) | Out-Null\"",
    "T1567.002": "cmd.exe /d /c \"curl.exe -I https://example.com/upload 2>nul || ver & ping -n 5 127.0.0.1 > nul\"",
    "T1052.001": "cmd.exe /d /c \"fsutil fsinfo drives 2>nul || dir %SystemDrive%\\ & ping -n 5 127.0.0.1 > nul\"",
    "T1485": (
        "cmd.exe /d /c \"echo tamandua-delete-safe>%TEMP%\\tamandua-delete-safe.txt & "
        "del /f /q %TEMP%\\tamandua-delete-safe.txt\""
    ),
    "T1491.001": (
        "powershell.exe -NoProfile -Command \"$p=Join-Path $env:TEMP 'tamandua-deface.html'; "
        "Set-Content -Path $p -Value '<html>tamandua</html>'; Remove-Item $p -Force\""
    ),
    "T1529": "cmd.exe /d /c \"shutdown.exe /a 2>nul || ver\"",
    "T1565.001": (
        "powershell.exe -NoProfile -Command \"$p=Join-Path $env:TEMP 'tamandua-data.txt'; "
        "Set-Content $p 'before'; Add-Content $p 'after'; Remove-Item $p -Force\""
    ),
}


# This expansion profile is a telemetry closure lane. The commands are deliberately
# benign/read-only or self-cleaning, so requiring threat detections here would train
# the product toward false positives. Real detection assertions stay in Atomic and
# CALDERA profiles where the behavior is intentionally suspicious.
DETECTION_HINTS: dict[str, list[str]] = {}


def make_test(scenario: dict[str, object]) -> dict[str, object] | None:
    technique = str(scenario["technique_id"])
    command = COMMANDS.get(technique)
    if not command:
        return None

    tactic = str(scenario["tactic"])
    scenario_id = str(scenario["id"])
    test = {
        "id": f"roadmap-{scenario_id}-{technique.lower().replace('.', '-')}",
        "name": scenario["name"],
        "executor": "command",
        "fallback_command": command,
        "expected_telemetry": ["process_create"],
        "optional_telemetry": ["file_create", "file_modify", "file_delete", "network_connect", "dns_query", "registry_set_value"],
        "expected_fields": ["agent_id", "hostname", "process_name", "command_line", "parent_process_name"],
        "tags": [
            "windows-roadmap-p0-safe",
            f"roadmap:{scenario_id}",
            f"tactic:{tactic}",
            f"mitre:{technique}",
            f"variant:{scenario['variant']}",
        ],
        "risk": "low" if scenario["safe_level"] == "safe" else "medium",
    }
    hints = DETECTION_HINTS.get(technique)
    if hints and scenario["variant"] in {"alert-quality", "correlation-storyline", "caldera-chain", "atomic-safe"}:
        test["expected_detections"] = hints
    return test


def main() -> int:
    roadmap = json.loads(ROADMAP.read_text(encoding="utf-8"))
    selected = [
        scenario
        for scenario in roadmap["scenarios"]
        if scenario["priority"] == "P0" and scenario["status"] == "planned"
    ]
    tests = []
    seen = set()
    for scenario in selected:
        test = make_test(scenario)
        if not test:
            continue
        key = (test["tags"][2], test["tags"][3], test["tags"][4])
        if key in seen:
            continue
        seen.add(key)
        tests.append(test)

    profile = {
        "schema_version": 1,
        "profile_id": "windows-roadmap-p0-safe-expansion",
        "name": "Windows Roadmap P0 Safe Expansion",
        "description": "Executable safe telemetry profile generated from planned P0 Windows detection roadmap items. It closes roadmap coverage using deterministic commands before promoting selected cases to Atomic/CALDERA upstream lanes with real detection assertions.",
        "platform": "windows",
        "default_observation_seconds": 75,
        "benchmark_lane": "enterprise-eval",
        "quality_bar": {
            "purpose": "roadmap_p0_safe_expansion",
            "requires_driver_health": True,
            "requires_persisted_events": True,
            "max_unknown_source_events": 0,
            "max_unexpected_high_critical": 0,
            "max_driver_channel_drops": 0,
            "max_driver_kernel_drops": 0,
        },
        "tests": tests,
    }
    OUT.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    print(f"tests={len(tests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
