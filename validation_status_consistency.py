#!/usr/bin/env python3
"""Audit consistency between the validation scorecard and manual status docs.

This report-only tool checks that the operational benchmark documents point to
the latest closure gate, execution preflight, and offline replay artifacts from
the generated validation roadmap scorecard. It does not execute benchmarks,
contact services, inspect live alerts, or mutate endpoint/server state.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
SCORECARD_JSON = GENERATED_DIR / "validation_roadmap_scorecard.json"
OUTPUT_STEM = "validation_status_consistency"
PROFILE_ID = "validation-status-consistency-probe"
PROFILE_NAME = "Validation Status Consistency Probe"
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-validation-status-consistency-probe$")

PROFILE_CLOSURE = "roadmap-closure-gate-probe"
PROFILE_PREFLIGHT = "validation-execution-preflight-probe"
PROFILE_REPLAY = "telemetry-replay-offline-fp-severity-v1"
PROFILE_FRESH_RESTORE = "fresh-restore-provenance-probe"
PROFILE_DISPATCH_RESULTS = "validation-dispatch-results-probe"
PROFILE_CALDERA_REPEATABILITY = "caldera-repeatability-probe"
PROFILE_WINDOWS_LAB_READINESS = "windows-lab-execution-readiness-probe"
PROFILE_WINDOWS_CONNECTION_STABILITY = "windows-agent-connection-stability-probe"
PROFILE_MACOS_BACKEND_READINESS = "macos-backend-readiness-probe"
PROFILE_ATOMIC_T1047_CAPABILITY = "atomic-t1047-lab-capability-probe"
PROFILE_WINDOWS_QGA_READINESS = "windows-proxmox-qga-readiness-probe"
PROFILE_LINUX_EBPF_READINESS = "linux-ebpf-readiness-probe"
MIN_SCORECARD_CONSISTENCY_CHECKS = 165
EXPECTED_WINDOWS_LAB_RUN = "20260604T073101Z-windows-lab-execution-readiness-probe"
EXPECTED_WINDOWS_CONNECTION_STABILITY_RUN = "20260604T010012Z-windows-agent-connection-stability-probe"
EXPECTED_MACOS_BACKEND_RUN = "20260604T073101Z-macos-backend-readiness-probe"
EXPECTED_ATOMIC_T1047_RUN = "20260603T170349Z-atomic-t1047-lab-capability-probe"
EXPECTED_WINDOWS_QGA_AGGREGATE_PASS_RUN = "20260603T131556Z-windows-proxmox-qga-readiness-probe"
EXPECTED_WINDOWS_QGA_LATEST_RAW_FAIL_RUN = "20260603T223403Z-windows-proxmox-qga-readiness-probe"
EXPECTED_LINUX_EBPF_RUN = "20260603T180022Z-linux-ebpf-readiness-probe"
EXPECTED_DISPATCH_AGENT_EXCERPTS = {
    "wave-1-provide-required-preflight-env": {
        "missing_package": [
            "validation-execution-preflight-probe",
        ],
        "required_env": [
            "CALDERA_AGENT_PAW",
            "CALDERA_API_KEY",
            "CALDERA_GROUP",
            "TAMANDUA_FRESH_RESTORE",
            "TAMANDUA_FRESH_RESTORE_AGENT_ID",
            "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
            "TAMANDUA_FRESH_RESTORE_HOSTNAME",
            "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
            "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
            "TAMANDUA_FRESH_RESTORE_STARTED_AT",
            "TAMANDUA_FRESH_RESTORE_VMID",
            "TAMANDUA_SERVER_PASSWORD",
        ]
    },
    "wave-1-restore-macos-backend-readiness": {
        "hostname": "Victors-MacBook-Pro.local",
        "status": "offline",
    },
    "wave-1-restore-windows-backend-readiness": {
        "missing_package": [
            "windows-lab-execution-readiness-probe",
            "windows-agent-connection-stability-probe",
        ],
        "required_env": ["TAMANDUA_SERVER_PASSWORD"],
    },
    "wave-1-restore-windows-qga-readiness": {
        "missing_package": [
            "windows-proxmox-qga-readiness-probe",
            "windows-proxmox-qga-file-diagnostics-probe",
        ],
        "required_env": ["TAMANDUA_PROXMOX_PASSWORD"],
    },
    "wave-2-restore-caldera-readiness-repeatability": {
        "missing_package": [
            "caldera-api-shape-probe",
            "caldera-paw-readiness-probe",
            "caldera-repeatability-probe",
        ],
        "required_env": ["CALDERA_AGENT_PAW", "CALDERA_API_KEY", "CALDERA_GROUP"],
    },
    "wave-3-rerun-preflight-and-closure-gate": {
        "missing": ["roadmap_status_pass"]
    },
}
EXPECTED_DISPATCH_WINDOWS_CONNECTION_HANDOFF = {
    "package_id": "wave-1-restore-windows-backend-readiness",
    "profile_id": PROFILE_WINDOWS_CONNECTION_STABILITY,
    "required_env": ["TAMANDUA_SERVER_PASSWORD"],
    "missing_package": True,
}
EXPECTED_DISPATCH_MACOS_AUTH_HANDOFF = {
    "package_id": "wave-1-restore-macos-backend-readiness",
    "profile_id": PROFILE_MACOS_BACKEND_READINESS,
    "missing_readiness": ["tamandua_ctl_auth"],
    "login_command": "tamandua-ctl remote login --server http://192.168.12.146:4000 --no-browser",
    "token_env": "TAMANDUA_TOKEN",
    "token_login_command": "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN",
    "target_server": "http://192.168.12.146:4000",
    "has_action": True,
}
EXPECTED_CLOSURE_NEXT_ACTION_ROADMAPS = ["A", "B", "D", "E", "M"]
EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS = {
    "B": [
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "TAMANDUA_FRESH_RESTORE_HOSTNAME",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "TAMANDUA_FRESH_RESTORE_VMID",
    ],
    "D": ["CALDERA_AGENT_PAW", "CALDERA_API_KEY", "CALDERA_GROUP"],
}
EXPECTED_PREFLIGHT_PACKAGE_REQUIRED_ENVS = {
    "wave-2-capture-fresh-restore-provenance": [
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "TAMANDUA_FRESH_RESTORE_HOSTNAME",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "TAMANDUA_FRESH_RESTORE_VMID",
    ],
    "wave-1-restore-windows-qga-readiness": ["TAMANDUA_PROXMOX_PASSWORD"],
}
EXPECTED_CALDERA_REPEATABILITY_RESET_REASONS = {
    "windows-caldera-smoke": "quality_gate_failed",
    "windows-caldera-enterprise-safe": (
        "quality_gate_failed:caldera_agent_stale_1021008s,caldera_agent_stale_or_offline"
    ),
}
EXPECTED_CALDERA_REPEATABILITY_NEXT_ACTIONS = {
    "windows-caldera-smoke": {
        "passes_needed": 2,
        "profile_file": "tools/detection_validation/profiles/windows_caldera_smoke.json",
        "has_command_hint": True,
        "required_env": ["CALDERA_API_KEY", "CALDERA_GROUP", "CALDERA_AGENT_PAW"],
    },
    "windows-caldera-enterprise-safe": {
        "passes_needed": 3,
        "profile_file": "tools/detection_validation/profiles/windows_caldera_enterprise_safe.json",
        "has_command_hint": True,
        "required_env": ["CALDERA_API_KEY", "CALDERA_GROUP", "CALDERA_AGENT_PAW"],
    },
}
EXPECTED_PREFLIGHT_REQUIRED_ENVS = [
    "CALDERA_API_KEY",
    "CALDERA_AGENT_PAW",
    "CALDERA_GROUP",
    "TAMANDUA_FRESH_RESTORE",
    "TAMANDUA_FRESH_RESTORE_AGENT_ID",
    "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
    "TAMANDUA_FRESH_RESTORE_HOSTNAME",
    "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
    "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
    "TAMANDUA_FRESH_RESTORE_STARTED_AT",
    "TAMANDUA_FRESH_RESTORE_VMID",
    "TAMANDUA_SERVER_PASSWORD",
]
EXPECTED_ROADMAP_B_NOTE_MARKERS = [
    "executed",
    "non-planned",
    "fresh_restore=true",
    "valid restore timing order",
    "hostname fields",
]
EXPECTED_BLOCKED_RUN_CLASS_ROADMAPS = {
    "macos-server-backed-smoke": ["E"],
    "windows-atomic-extended": ["M"],
    "windows-broad": ["A", "B", "M"],
    "windows-caldera-enterprise": ["D", "M"],
    "windows-p1-p2-rerun": ["A"],
}
EXPECTED_BLOCKED_RUN_CLASS_MISSING_ENVS = {
    "macos-server-backed-smoke": [],
    "windows-atomic-extended": [],
    "windows-broad": [
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "TAMANDUA_FRESH_RESTORE_HOSTNAME",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "TAMANDUA_FRESH_RESTORE_VMID",
        "TAMANDUA_SERVER_PASSWORD",
    ],
    "windows-caldera-enterprise": ["CALDERA_AGENT_PAW", "CALDERA_API_KEY", "CALDERA_GROUP"],
    "windows-p1-p2-rerun": ["TAMANDUA_SERVER_PASSWORD"],
}
EXPECTED_UNBLOCK_SEQUENCE = [
    "provide-required-preflight-env",
    "restore-windows-backend-readiness",
    "restore-windows-qga-readiness",
    "capture-fresh-restore-provenance",
    "restore-caldera-readiness-repeatability",
    "resolve-atomic-extended-preconditions",
    "restore-macos-backend-readiness",
    "rerun-preflight-and-closure-gate",
]
EXPECTED_UNBLOCK_SEQUENCE_PRIORITIES = [10, 20, 25, 30, 40, 50, 60, 90]
EXPECTED_PARALLEL_UNBLOCK_WAVES = [
    {
        "wave": 1,
        "parallelizable": True,
        "step_ids": [
            "provide-required-preflight-env",
            "restore-windows-backend-readiness",
            "restore-windows-qga-readiness",
            "resolve-atomic-extended-preconditions",
            "restore-macos-backend-readiness",
        ],
        "depends_on_waves": [],
    },
    {
        "wave": 2,
        "parallelizable": True,
        "step_ids": [
            "capture-fresh-restore-provenance",
            "restore-caldera-readiness-repeatability",
        ],
        "depends_on_waves": [1],
    },
    {
        "wave": 3,
        "parallelizable": False,
        "step_ids": ["rerun-preflight-and-closure-gate"],
        "depends_on_waves": [1, 2],
    },
]
EXPECTED_PREFLIGHT_SAFE_COMMAND_MARKERS = [
    "windows_lab_execution_readiness_probe.py --server http://192.168.12.146:4000 --output-dir",
    "caldera_repeatability_probe.py --output-dir",
    "macos_backend_readiness_probe.py --server http://192.168.12.146:4000 --output-dir",
    "roadmap_closure_gate_probe.py --output-dir",
]

STATUS_DOCS = [
    ROOT / "docs" / "benchmarks" / "NEXT_VALIDATION_WORK_QUEUE.md",
    ROOT / "docs" / "benchmarks" / "PARALLEL_EXECUTION_BOARD.md",
    ROOT / "docs" / "benchmarks" / "REMAINING_VALIDATION_BLOCKERS.md",
]
FRESH_RESTORE_STATUS_DOCS = STATUS_DOCS + [
    ROOT / "docs" / "benchmarks" / "FRESH_RESTORE_PROVENANCE_RUNBOOK.md",
]


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            ).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--porcelain"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def normalize_artifact_ref(value: Any) -> str:
    return str(value or "").replace("\\", "/")


def env_template_placeholder(name: str) -> str:
    upper = name.upper()
    suffix = "-secret" if any(marker in upper for marker in ("KEY", "PASSWORD", "TOKEN", "SECRET")) else ""
    return f"<set-{name.lower().replace('_', '-')}{suffix}>"


def compact_stamp(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace(".", "")[:15] + "Z"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"error: missing JSON artifact: {rel(path)}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"error: expected JSON object: {rel(path)}")
    return data


def load_text(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"error: missing document: {rel(path)}")
    return path.read_text(encoding="utf-8")


def latest_profile(scorecard: dict[str, Any], profile_id: str) -> dict[str, Any]:
    entry = profile_entry(scorecard, profile_id)
    latest = entry.get("latest") if isinstance(entry.get("latest"), dict) else {}
    if not latest:
        raise SystemExit(f"error: scorecard profile has no latest artifact: {profile_id}")
    return latest


def profile_entry(scorecard: dict[str, Any], profile_id: str) -> dict[str, Any]:
    for entry in scorecard.get("profiles") or []:
        if isinstance(entry, dict) and entry.get("profile_id") == profile_id:
            return entry
    raise SystemExit(f"error: scorecard missing profile: {profile_id}")


def artifact_path(latest: dict[str, Any]) -> Path:
    path_value = latest.get("path")
    if not path_value:
        raise SystemExit(f"error: latest artifact has no path for {latest.get('profile_id')}")
    path = Path(str(path_value))
    return path if path.is_absolute() else ROOT / path


def check(checks: list[dict[str, Any]], name: str, actual: Any, expected: Any, sources: list[str]) -> None:
    checks.append(
        {
            "name": name,
            "status": "PASS" if actual == expected else "FAIL",
            "actual": actual,
            "expected": expected,
            "source_files": sources,
        }
    )


def check_contains(
    checks: list[dict[str, Any]], name: str, text: str, needle: str, source: Path
) -> None:
    check(checks, name, needle in text, True, [rel(source)])


def line_contains_all(text: str, needles: list[str]) -> bool:
    return any(all(needle in line for needle in needles) for line in text.splitlines())


def collect_nested_values(value: Any, key: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        current = value.get(key)
        if isinstance(current, list):
            found.extend(str(item) for item in current if item not in (None, ""))
        elif current not in (None, ""):
            found.append(str(current))
        for nested in value.values():
            found.extend(collect_nested_values(nested, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(collect_nested_values(item, key))
    return found


def sorted_unique_strings(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return sorted({str(value) for value in values if value not in (None, "")})


def roadmap_note(scorecard: dict[str, Any], roadmap_key: str) -> str:
    for item in scorecard.get("roadmaps") or []:
        if isinstance(item, dict) and item.get("key") == roadmap_key:
            return str(item.get("note") or "")
    return ""


def closure_open_roadmaps(closure_artifact: dict[str, Any]) -> list[str]:
    roadmaps = sorted_unique_strings(closure_artifact.get("gated_roadmaps"))
    if roadmaps:
        return roadmaps
    found = []
    for test in closure_artifact.get("tests") or []:
        if not isinstance(test, dict):
            continue
        if test.get("status") == "covered":
            continue
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        roadmap = evidence.get("roadmap_key")
        if roadmap:
            found.append(str(roadmap))
    return sorted(set(found))


def closure_next_action_summary(closure_artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    actions: dict[str, dict[str, Any]] = {}
    for item in closure_artifact.get("roadmap_next_actions") or []:
        if not isinstance(item, dict):
            continue
        roadmap = str(item.get("roadmap") or "")
        if not roadmap:
            continue
        actions[roadmap] = {
            "blocking_profiles": sorted_unique_strings(item.get("blocking_profiles")),
            "required_env": sorted_unique_strings(item.get("required_env")),
            "has_action": bool(item.get("action")),
        }
    return dict(sorted(actions.items()))


def closure_next_actions_valid(closure_artifact: dict[str, Any]) -> bool:
    actions = closure_next_action_summary(closure_artifact)
    if sorted(actions) != EXPECTED_CLOSURE_NEXT_ACTION_ROADMAPS:
        return False
    for roadmap in EXPECTED_CLOSURE_NEXT_ACTION_ROADMAPS:
        action = actions.get(roadmap) or {}
        if not action.get("has_action"):
            return False
        if not action.get("blocking_profiles"):
            return False
        missing_env = missing_expected_values(
            action.get("required_env") or [],
            EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS.get(roadmap, []),
        )
        if missing_env:
            return False
    return True


def preflight_roadmap_next_actions_valid(preflight_artifact: dict[str, Any]) -> bool:
    actions = closure_next_action_summary(preflight_artifact)
    if not actions:
        raw_actions = preflight_artifact.get("roadmap_next_actions") or []
        actions = closure_next_action_summary({"roadmap_next_actions": raw_actions})
    if sorted(actions) != EXPECTED_CLOSURE_NEXT_ACTION_ROADMAPS:
        return False
    for roadmap, expected_env in EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS.items():
        action = actions.get(roadmap) or {}
        if missing_expected_values(action.get("required_env") or [], expected_env):
            return False
    return all((actions.get(roadmap) or {}).get("has_action") for roadmap in actions)


def blocked_run_classes(preflight_artifact: dict[str, Any]) -> list[str]:
    blocked = []
    for item in preflight_artifact.get("run_class_readiness") or []:
        if isinstance(item, dict) and item.get("allowed") is False and item.get("run_class"):
            blocked.append(str(item["run_class"]))
    return sorted(set(blocked))


def blocked_run_class_roadmaps(preflight_artifact: dict[str, Any]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for item in preflight_artifact.get("run_class_readiness") or []:
        if not isinstance(item, dict) or item.get("allowed") is not False or not item.get("run_class"):
            continue
        mapping[str(item["run_class"])] = sorted_unique_strings(item.get("open_roadmaps"))
    return dict(sorted(mapping.items()))


def blocked_run_class_missing_envs(preflight_artifact: dict[str, Any]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for item in preflight_artifact.get("run_class_readiness") or []:
        if not isinstance(item, dict) or item.get("allowed") is not False or not item.get("run_class"):
            continue
        mapping[str(item["run_class"])] = sorted_unique_strings(item.get("missing_env"))
    return dict(sorted(mapping.items()))


def unblock_sequence_ids(preflight_artifact: dict[str, Any]) -> list[str]:
    steps = []
    for item in preflight_artifact.get("unblock_sequence") or []:
        if isinstance(item, dict) and item.get("step_id"):
            steps.append(str(item["step_id"]))
    return steps


def unblock_sequence_priorities(preflight_artifact: dict[str, Any]) -> list[int]:
    priorities: list[int] = []
    for item in preflight_artifact.get("unblock_sequence") or []:
        if not isinstance(item, dict):
            continue
        try:
            priorities.append(int(item.get("priority")))
        except (TypeError, ValueError):
            continue
    return priorities


def parallel_unblock_wave_shape(preflight_artifact: dict[str, Any]) -> list[dict[str, Any]]:
    waves = []
    for item in preflight_artifact.get("parallel_unblock_waves") or []:
        if not isinstance(item, dict):
            continue
        try:
            wave = int(item.get("wave"))
        except (TypeError, ValueError):
            continue
        waves.append(
            {
                "wave": wave,
                "parallelizable": bool(item.get("parallelizable")),
                "step_ids": [str(value) for value in item.get("step_ids") or [] if value],
                "depends_on_waves": [
                    int(value)
                    for value in item.get("depends_on_waves") or []
                    if str(value).isdigit()
                ],
            }
        )
    return sorted(waves, key=lambda item: item["wave"])


def dispatch_agent_excerpts(dispatch_artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict) or not package.get("package_id"):
            continue
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        agent = evidence.get("agent") if isinstance(evidence.get("agent"), dict) else {}
        if agent:
            mapping[str(package["package_id"])] = {
                "hostname": agent.get("hostname"),
                "status": agent.get("status"),
            }
            continue
        missing = evidence.get("missing") if isinstance(evidence.get("missing"), list) else []
        if missing:
            mapping[str(package["package_id"])] = {"missing": [str(value) for value in missing]}
            continue
        missing_package = (
            evidence.get("missing_package")
            if isinstance(evidence.get("missing_package"), dict)
            else {}
        )
        if missing_package:
            mapping[str(package["package_id"])] = {
                "missing_package": [
                    str(value) for value in missing_package.get("missing_expected_profiles") or []
                ],
                "required_env": [
                    str(value) for value in missing_package.get("required_env") or []
                ],
            }
            continue
        gap_category = evidence.get("gap_category")
        if gap_category:
            mapping[str(package["package_id"])] = {"gap_category": str(gap_category)}
    return dict(sorted(mapping.items()))


def dispatch_missing_package_evidence_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False
    expected_by_package = {
        str(package.get("package_id")): [
            str(value) for value in package.get("expected_profile_ids") or []
        ]
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    }
    checked = 0
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        if not package_id or package_id not in expected_by_package:
            return False
        artifact_paths = [str(value) for value in package.get("artifact_paths") or []]
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        missing_package = (
            evidence.get("missing_package")
            if isinstance(evidence.get("missing_package"), dict)
            else {}
        )
        if artifact_paths:
            if missing_package:
                return False
            checked += 1
            continue
        missing_profiles = [
            str(value) for value in missing_package.get("missing_expected_profiles") or []
        ]
        if missing_profiles != expected_by_package[package_id]:
            return False
        checked += 1
    return checked == len(expected_by_package) and checked > 0


def dispatch_windows_connection_next_action(dispatch_artifact: dict[str, Any]) -> dict[str, Any]:
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_id = str(profile_result.get("profile_id") or "")
            if profile_id != PROFILE_WINDOWS_CONNECTION_STABILITY:
                continue
            evidence = (
                profile_result.get("evidence_excerpt")
                if isinstance(profile_result.get("evidence_excerpt"), dict)
                else {}
            )
            action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
            if not action:
                continue
            return {
                "package_id": package_id,
                "profile_id": profile_id,
                "missing_stability": [str(value) for value in action.get("missing_stability") or []],
                "has_action": bool(action.get("action")),
            }
    return {}


def dispatch_windows_connection_handoff(dispatch_artifact: dict[str, Any]) -> dict[str, Any]:
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        expected_profiles = [str(value) for value in package.get("expected_profile_ids") or []]
        if PROFILE_WINDOWS_CONNECTION_STABILITY not in expected_profiles:
            continue
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        missing_package = (
            evidence.get("missing_package")
            if isinstance(evidence.get("missing_package"), dict)
            else {}
        )
        missing_profiles = [
            str(value) for value in missing_package.get("missing_expected_profiles") or []
        ]
        required_env = [
            str(value) for value in missing_package.get("required_env") or []
        ]
        return {
            "package_id": str(package.get("package_id") or ""),
            "profile_id": PROFILE_WINDOWS_CONNECTION_STABILITY,
            "required_env": sorted(required_env),
            "missing_package": PROFILE_WINDOWS_CONNECTION_STABILITY in missing_profiles,
        }
    return {}


def dispatch_macos_auth_handoff(dispatch_artifact: dict[str, Any]) -> dict[str, Any]:
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        expected_profiles = [str(value) for value in package.get("expected_profile_ids") or []]
        if PROFILE_MACOS_BACKEND_READINESS not in expected_profiles:
            continue
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        if not action:
            for profile_result in package.get("profile_results") or []:
                if not isinstance(profile_result, dict):
                    continue
                if profile_result.get("profile_id") != PROFILE_MACOS_BACKEND_READINESS:
                    continue
                profile_evidence = (
                    profile_result.get("evidence_excerpt")
                    if isinstance(profile_result.get("evidence_excerpt"), dict)
                    else {}
                )
                action = (
                    profile_evidence.get("next_action")
                    if isinstance(profile_evidence.get("next_action"), dict)
                    else {}
                )
                break
        return {
            "package_id": str(package.get("package_id") or ""),
            "profile_id": PROFILE_MACOS_BACKEND_READINESS,
            "missing_readiness": [str(value) for value in action.get("missing_readiness") or []],
            "login_command": str(action.get("login_command") or ""),
            "token_env": str(action.get("token_env") or ""),
            "token_login_command": str(action.get("token_login_command") or ""),
            "target_server": str(action.get("target_server") or ""),
            "has_action": bool(action.get("action")),
        }
    return {}


def dispatch_claim_macos_auth_handoff(dispatch_artifact: dict[str, Any]) -> dict[str, Any]:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return {}
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return {}
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return {}
    claim_sources = [
        normalize_artifact_ref(manifest.get("agent_claims_json_path")),
        normalize_artifact_ref(manifest.get("claim_status_report_json_path")),
    ]
    summaries = []
    for source in claim_sources:
        if not source:
            return {}
        source_path = ROOT / source
        if not source_path.exists():
            return {}
        try:
            payload = load_json(source_path)
        except json.JSONDecodeError:
            return {}
        claim = next(
            (
                item
                for item in payload.get("claims") or []
                if isinstance(item, dict)
                and item.get("package_id") == "wave-1-restore-macos-backend-readiness"
            ),
            {},
        )
        action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        summaries.append(
            {
                "source": source,
                "missing_readiness": [str(value) for value in action.get("missing_readiness") or []],
                "login_command": str(action.get("login_command") or ""),
                "token_env": str(action.get("token_env") or ""),
                "token_login_command": str(action.get("token_login_command") or ""),
                "target_server": str(action.get("target_server") or ""),
            }
        )
    return {"summaries": summaries}


def render_current_next_action_summary(action: object) -> str:
    if not isinstance(action, dict) or not action:
        return "-"
    missing_values = (
        action.get("missing_stability")
        or action.get("missing_readiness")
        or action.get("missing_diagnostics")
        or action.get("missing_endpoints")
        or action.get("missing_profiles")
        or []
    )
    parts = []
    if missing_values:
        parts.append("missing=" + ",".join(str(value) for value in missing_values))
    if action.get("login_command"):
        parts.append("login_command=" + str(action.get("login_command")))
    if action.get("token_login_command"):
        parts.append("token_login_command=" + str(action.get("token_login_command")))
    elif action.get("action"):
        parts.append("action=" + str(action.get("action")))
    return "; ".join(parts) or "-"


def find_first_nested_dict(value: object, key: str) -> dict[str, Any]:
    if isinstance(value, dict):
        nested = value.get(key)
        if isinstance(nested, dict) and nested:
            return nested
        for item in value.values():
            found = find_first_nested_dict(item, key)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = find_first_nested_dict(item, key)
            if found:
                return found
    return {}


def expected_dispatch_claim_macos_auth_handoff(dispatch_run: str) -> dict[str, Any]:
    base = f"docs/benchmarks/runs/{dispatch_run}.package-artifacts"
    common = {
        "missing_readiness": ["tamandua_ctl_auth"],
        "login_command": "tamandua-ctl remote login --server http://192.168.12.146:4000 --no-browser",
        "token_env": "TAMANDUA_TOKEN",
        "token_login_command": "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN",
        "target_server": "http://192.168.12.146:4000",
    }
    return {
        "summaries": [
            {"source": f"{base}/agent_claims.json", **common},
            {"source": f"{base}/claim_status_report.json", **common},
        ]
    }


def dispatch_macos_prompt_exposes_token_env(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        if package.get("package_id") != "wave-1-restore-macos-backend-readiness":
            continue
        prompt_path = normalize_artifact_ref(package.get("prompt_path"))
        if not prompt_path:
            return False
        prompt_full_path = ROOT / prompt_path
        if not prompt_full_path.exists():
            return False
        text = prompt_full_path.read_text(encoding="utf-8")
        return (
            "Next-action env: TAMANDUA_TOKEN" in text
            and "Effective env checklist: TAMANDUA_TOKEN" in text
            and "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN" in text
        )
    return False


def dispatch_package_artifact_paths(dispatch_artifact: dict[str, Any]) -> list[str]:
    paths = []
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        output_dir = package.get("output_dir")
        if output_dir:
            paths.append(normalize_artifact_ref(output_dir))
        status_path = package.get("agent_status_path")
        if status_path:
            paths.append(normalize_artifact_ref(status_path))
        artifact_path = package.get("artifact_path")
        if artifact_path:
            paths.append(normalize_artifact_ref(artifact_path))
        for artifact_path in package.get("artifact_paths") or []:
            paths.append(normalize_artifact_ref(artifact_path))
        for agent_artifact in package.get("agent_artifacts") or []:
            paths.append(normalize_artifact_ref(agent_artifact))
        for archived_path in package.get("archived_artifacts") or []:
            paths.append(normalize_artifact_ref(archived_path))
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_artifact = profile_result.get("artifact_path")
            if profile_artifact:
                paths.append(normalize_artifact_ref(profile_artifact))
    return sorted(set(paths))


def dispatch_official_metadata_matches_profile(dispatch_artifact: dict[str, Any]) -> bool:
    return (
        dispatch_artifact.get("profile_id") == PROFILE_DISPATCH_RESULTS
        and dispatch_artifact.get("profile") == PROFILE_DISPATCH_RESULTS
        and dispatch_artifact.get("benchmark_lane") == "claim-boundary"
        and "does not promote package artifacts" in str(dispatch_artifact.get("claim_boundary") or "")
    )


def dispatch_official_paths_are_self_contained(dispatch_artifact: dict[str, Any], dispatch_run: str) -> bool:
    expected_prefix = f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/"
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    canonical_paths = dispatch_package_artifact_paths(dispatch_artifact)
    if not manifest_path.startswith(expected_prefix):
        return False
    if not canonical_paths:
        return False
    return all(path.startswith(expected_prefix) for path in canonical_paths)


def dispatch_official_paths_exist(dispatch_artifact: dict[str, Any]) -> bool:
    official_paths = dispatch_package_artifact_paths(dispatch_artifact)
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if manifest_path:
        official_paths.append(manifest_path)
    if not official_paths:
        return False
    return all((ROOT / path).exists() for path in official_paths)


def dispatch_official_payload_has_no_tmp(dispatch_artifact: dict[str, Any]) -> bool:
    official_values: list[str] = []
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if source_preflight:
        official_values.append(source_preflight)
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if manifest_path:
        official_values.append(manifest_path)
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for field_name in ("artifact_path", "output_dir"):
            field_value = package.get(field_name)
            if field_value:
                official_values.append(normalize_artifact_ref(field_value))
        for artifact_path in package.get("artifact_paths") or []:
            official_values.append(normalize_artifact_ref(artifact_path))
        for agent_artifact in package.get("agent_artifacts") or []:
            official_values.append(normalize_artifact_ref(agent_artifact))
        for archived_path in package.get("archived_artifacts") or []:
            official_values.append(normalize_artifact_ref(archived_path))
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_artifact = profile_result.get("artifact_path")
            if profile_artifact:
                official_values.append(normalize_artifact_ref(profile_artifact))
    return all(
        "/tmp/" not in value.lower()
        and not value.lower().startswith("tmp/")
        and not re.match(r"^[A-Za-z]:/", value)
        and not value.startswith("/")
        for value in official_values
    )


def dispatch_official_comparison_matches_payload(dispatch_artifact: dict[str, Any]) -> bool:
    run_id = str(dispatch_artifact.get("run_id") or "")
    if not run_id:
        return False
    comparison_path = ROOT / "docs" / "benchmarks" / "runs" / f"{run_id}.comparison.json"
    if not comparison_path.exists():
        return False
    try:
        comparison = load_json(comparison_path)
    except json.JSONDecodeError:
        return False
    if comparison.get("schema_version") != 1:
        return False
    for key in ("profile_id", "benchmark_lane", "claim_boundary", "quality_gate"):
        if comparison.get(key) != dispatch_artifact.get(key):
            return False
    if comparison.get("packages") != dispatch_artifact.get("packages"):
        return False
    if comparison.get("tests") != dispatch_artifact.get("tests"):
        return False
    summary = comparison.get("summary") if isinstance(comparison.get("summary"), dict) else {}
    artifact_summary = (
        dispatch_artifact.get("summary")
        if isinstance(dispatch_artifact.get("summary"), dict)
        else {}
    )
    expected_summary = {
        "passed_count": dispatch_artifact.get("passed_count"),
        "failed_count": dispatch_artifact.get("failed_count"),
        "status_counts": dispatch_artifact.get("status_counts"),
        "blocked_count": dispatch_artifact.get("blocked_count"),
        "failed_status_count": dispatch_artifact.get("failed_status_count"),
        "missing_count": dispatch_artifact.get("missing_count"),
        "invalid_count": dispatch_artifact.get("invalid_count"),
        "dispatch_manifest": dispatch_artifact.get("dispatch_manifest"),
        "source_preflight": dispatch_artifact.get("source_preflight"),
        "missing_required_env": dispatch_artifact.get("missing_required_env"),
        "required_env_blockers": dispatch_artifact.get("required_env_blockers"),
        "owner_handoff": dispatch_artifact.get("owner_handoff"),
        "covered": artifact_summary.get("covered"),
        "tests": artifact_summary.get("tests"),
    }
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            return False
    comparison_dispatch = {
        "run_id": run_id,
        "dispatch_manifest": summary.get("dispatch_manifest"),
        "source_preflight": summary.get("source_preflight"),
        "packages": comparison.get("packages") or [],
    }
    return (
        dispatch_official_paths_are_self_contained(comparison_dispatch, run_id)
        and dispatch_official_paths_exist(comparison_dispatch)
        and dispatch_official_payload_has_no_tmp(comparison_dispatch)
    )


def dispatch_archived_summary_has_self_contained_paths(dispatch_artifact: dict[str, Any]) -> bool:
    run_id = str(dispatch_artifact.get("run_id") or "")
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not run_id or not manifest_path:
        return False
    archive_root = (ROOT / manifest_path).parent
    json_path = archive_root / "dispatch_results.json"
    markdown_path = archive_root / "dispatch_results.md"
    if not json_path.exists() or not markdown_path.exists():
        return False
    try:
        summary = load_json(json_path)
    except json.JSONDecodeError:
        return False
    for key in (
        "passed_count",
        "failed_count",
        "blocked_count",
        "failed_status_count",
        "missing_count",
        "invalid_count",
    ):
        if summary.get(key) != dispatch_artifact.get(key):
            return False
    summary_dispatch = {
        "run_id": run_id,
        "dispatch_manifest": summary.get("dispatch_manifest"),
        "source_preflight": summary.get("source_preflight"),
        "packages": summary.get("packages") or [],
    }
    if not (
        dispatch_official_paths_are_self_contained(summary_dispatch, run_id)
        and dispatch_official_paths_exist(summary_dispatch)
        and dispatch_official_payload_has_no_tmp(summary_dispatch)
    ):
        return False
    markdown = markdown_path.read_text(encoding="utf-8")
    forbidden_patterns = ("/tmp/", "tmp/", "D:/", "D:\\", "\\tmp\\")
    if any(pattern.lower() in markdown.lower() for pattern in forbidden_patterns):
        return False
    artifact_paths = [
        normalize_artifact_ref(package.get("artifact_path"))
        for package in summary.get("packages") or []
        if isinstance(package, dict) and package.get("artifact_path")
    ]
    return all(path in markdown for path in artifact_paths)


def dispatch_archived_manifest_has_no_tmp(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    manifest_values: list[str] = []
    for field_name in (
        "source_preflight",
        "output_dir",
        "agent_roster_path",
        "env_checklist_path",
        "env_template_path",
        "owner_launch_plan_path",
        "owner_launch_plan_json_path",
        "execution_matrix_path",
        "execution_matrix_json_path",
        "agent_claims_path",
        "agent_claims_json_path",
        "agent_spawn_plan_path",
        "agent_spawn_plan_json_path",
        "agent_spawn_launcher_path",
        "claim_status_report_path",
        "claim_status_report_json_path",
        "claim_lock_helper_path",
        "env_unblock_queue_path",
        "env_unblock_queue_json_path",
        "ready_claims_launcher_path",
        "ready_claims_parallel_launcher_path",
        "env_bundle_ready_claims_launcher_path",
        "dispatch_prelaunch_validation_path",
        "dispatch_brief_path",
        "dispatch_runner_path",
    ):
        field_value = manifest.get(field_name)
        if field_value:
            manifest_values.append(normalize_artifact_ref(field_value))
    for launcher_path in manifest.get("launcher_paths") or []:
        manifest_values.append(normalize_artifact_ref(launcher_path))
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for field_name in ("artifact_path", "output_dir", "prompt_path", "script_path"):
            field_value = package.get(field_name)
            if field_value:
                manifest_values.append(normalize_artifact_ref(field_value))

    return bool(manifest_values) and all(
        "/tmp/" not in value.lower()
        and not value.lower().startswith("tmp/")
        and not re.match(r"^[A-Za-z]:/", value)
        and not value.startswith("/")
        for value in manifest_values
    )


def dispatch_archived_manifest_handoff_paths_exist(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    required_file_paths: list[str] = []
    roster_path = normalize_artifact_ref(manifest.get("agent_roster_path"))
    if roster_path:
        required_file_paths.append(roster_path)
    env_checklist_path = normalize_artifact_ref(manifest.get("env_checklist_path"))
    if env_checklist_path:
        required_file_paths.append(env_checklist_path)
    env_template_path = normalize_artifact_ref(manifest.get("env_template_path"))
    if env_template_path:
        required_file_paths.append(env_template_path)
    owner_launch_plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_path"))
    if owner_launch_plan_path:
        required_file_paths.append(owner_launch_plan_path)
    owner_launch_plan_json_path = normalize_artifact_ref(manifest.get("owner_launch_plan_json_path"))
    if owner_launch_plan_json_path:
        required_file_paths.append(owner_launch_plan_json_path)
    execution_matrix_path = normalize_artifact_ref(manifest.get("execution_matrix_path"))
    if execution_matrix_path:
        required_file_paths.append(execution_matrix_path)
    execution_matrix_json_path = normalize_artifact_ref(manifest.get("execution_matrix_json_path"))
    if execution_matrix_json_path:
        required_file_paths.append(execution_matrix_json_path)
    agent_claims_path = normalize_artifact_ref(manifest.get("agent_claims_path"))
    if agent_claims_path:
        required_file_paths.append(agent_claims_path)
    agent_claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if agent_claims_json_path:
        required_file_paths.append(agent_claims_json_path)
    agent_spawn_plan_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_path"))
    if agent_spawn_plan_path:
        required_file_paths.append(agent_spawn_plan_path)
    agent_spawn_plan_json_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path"))
    if agent_spawn_plan_json_path:
        required_file_paths.append(agent_spawn_plan_json_path)
    agent_spawn_launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    if agent_spawn_launcher_path:
        required_file_paths.append(agent_spawn_launcher_path)
    claim_status_report_path = normalize_artifact_ref(manifest.get("claim_status_report_path"))
    if claim_status_report_path:
        required_file_paths.append(claim_status_report_path)
    claim_status_report_json_path = normalize_artifact_ref(manifest.get("claim_status_report_json_path"))
    if claim_status_report_json_path:
        required_file_paths.append(claim_status_report_json_path)
    claim_lock_helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if claim_lock_helper_path:
        required_file_paths.append(claim_lock_helper_path)
    env_unblock_queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    if env_unblock_queue_path:
        required_file_paths.append(env_unblock_queue_path)
    env_unblock_queue_json_path = normalize_artifact_ref(manifest.get("env_unblock_queue_json_path"))
    if env_unblock_queue_json_path:
        required_file_paths.append(env_unblock_queue_json_path)
    ready_claims_launcher_path = normalize_artifact_ref(manifest.get("ready_claims_launcher_path"))
    if ready_claims_launcher_path:
        required_file_paths.append(ready_claims_launcher_path)
    ready_claims_parallel_launcher_path = normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path"))
    if ready_claims_parallel_launcher_path:
        required_file_paths.append(ready_claims_parallel_launcher_path)
    env_bundle_ready_claims_launcher_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    if env_bundle_ready_claims_launcher_path:
        required_file_paths.append(env_bundle_ready_claims_launcher_path)
    dispatch_prelaunch_validation_path = normalize_artifact_ref(manifest.get("dispatch_prelaunch_validation_path"))
    if dispatch_prelaunch_validation_path:
        required_file_paths.append(dispatch_prelaunch_validation_path)
    dispatch_brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    if dispatch_brief_path:
        required_file_paths.append(dispatch_brief_path)
    dispatch_runner_path = normalize_artifact_ref(manifest.get("dispatch_runner_path"))
    if dispatch_runner_path:
        required_file_paths.append(dispatch_runner_path)
    for launcher_path in manifest.get("launcher_paths") or []:
        required_file_paths.append(normalize_artifact_ref(launcher_path))
    for launcher_path in manifest.get("staged_launcher_paths") or []:
        required_file_paths.append(normalize_artifact_ref(launcher_path))
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for field_name in ("prompt_path", "script_path"):
            field_value = package.get(field_name)
            if field_value:
                required_file_paths.append(normalize_artifact_ref(field_value))
    return bool(required_file_paths) and all((ROOT / path).is_file() for path in required_file_paths)


def dispatch_archived_handoff_contents_are_self_contained(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    dispatch_run = str(dispatch_artifact.get("run_id") or "")
    if not manifest_path or not dispatch_run:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    packages = [package for package in manifest.get("packages") or [] if isinstance(package, dict)]

    expected_prefix = f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/"
    launcher_paths = [normalize_artifact_ref(path) for path in manifest.get("launcher_paths") or []]
    launcher_paths.extend(normalize_artifact_ref(path) for path in manifest.get("staged_launcher_paths") or [])
    package_script_paths: list[str] = []
    files_to_scan = list(launcher_paths)
    roster_path = normalize_artifact_ref(manifest.get("agent_roster_path"))
    if roster_path:
        files_to_scan.append(roster_path)
    env_checklist_path = normalize_artifact_ref(manifest.get("env_checklist_path"))
    if env_checklist_path:
        files_to_scan.append(env_checklist_path)
    env_template_path = normalize_artifact_ref(manifest.get("env_template_path"))
    if env_template_path:
        files_to_scan.append(env_template_path)
    owner_launch_plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_path"))
    if owner_launch_plan_path:
        files_to_scan.append(owner_launch_plan_path)
    owner_launch_plan_json_path = normalize_artifact_ref(manifest.get("owner_launch_plan_json_path"))
    if owner_launch_plan_json_path:
        files_to_scan.append(owner_launch_plan_json_path)
    execution_matrix_path = normalize_artifact_ref(manifest.get("execution_matrix_path"))
    if execution_matrix_path:
        files_to_scan.append(execution_matrix_path)
    execution_matrix_json_path = normalize_artifact_ref(manifest.get("execution_matrix_json_path"))
    if execution_matrix_json_path:
        files_to_scan.append(execution_matrix_json_path)
    agent_claims_path = normalize_artifact_ref(manifest.get("agent_claims_path"))
    if agent_claims_path:
        files_to_scan.append(agent_claims_path)
    agent_claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if agent_claims_json_path:
        files_to_scan.append(agent_claims_json_path)
    agent_spawn_plan_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_path"))
    if agent_spawn_plan_path:
        files_to_scan.append(agent_spawn_plan_path)
    agent_spawn_plan_json_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path"))
    if agent_spawn_plan_json_path:
        files_to_scan.append(agent_spawn_plan_json_path)
    agent_spawn_launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    if agent_spawn_launcher_path:
        files_to_scan.append(agent_spawn_launcher_path)
    claim_status_report_path = normalize_artifact_ref(manifest.get("claim_status_report_path"))
    if claim_status_report_path:
        files_to_scan.append(claim_status_report_path)
    claim_status_report_json_path = normalize_artifact_ref(manifest.get("claim_status_report_json_path"))
    if claim_status_report_json_path:
        files_to_scan.append(claim_status_report_json_path)
    claim_lock_helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if claim_lock_helper_path:
        files_to_scan.append(claim_lock_helper_path)
    env_unblock_queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    if env_unblock_queue_path:
        files_to_scan.append(env_unblock_queue_path)
    env_unblock_queue_json_path = normalize_artifact_ref(manifest.get("env_unblock_queue_json_path"))
    if env_unblock_queue_json_path:
        files_to_scan.append(env_unblock_queue_json_path)
    ready_claims_launcher_path = normalize_artifact_ref(manifest.get("ready_claims_launcher_path"))
    if ready_claims_launcher_path:
        files_to_scan.append(ready_claims_launcher_path)
    ready_claims_parallel_launcher_path = normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path"))
    if ready_claims_parallel_launcher_path:
        files_to_scan.append(ready_claims_parallel_launcher_path)
    env_bundle_ready_claims_launcher_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    if env_bundle_ready_claims_launcher_path:
        files_to_scan.append(env_bundle_ready_claims_launcher_path)
    dispatch_prelaunch_validation_path = normalize_artifact_ref(manifest.get("dispatch_prelaunch_validation_path"))
    if dispatch_prelaunch_validation_path:
        files_to_scan.append(dispatch_prelaunch_validation_path)
    dispatch_brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    if dispatch_brief_path:
        files_to_scan.append(dispatch_brief_path)
    dispatch_runner_path = normalize_artifact_ref(manifest.get("dispatch_runner_path"))
    if dispatch_runner_path:
        files_to_scan.append(dispatch_runner_path)
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        script_path = normalize_artifact_ref(package.get("script_path"))
        prompt_path = normalize_artifact_ref(package.get("prompt_path"))
        status_path = normalize_artifact_ref(package.get("status_path"))
        if not script_path or not script_path.startswith(expected_prefix):
            return False
        package_script_paths.append(script_path)
        files_to_scan.append(script_path)
        if not status_path or not status_path.startswith(expected_prefix):
            return False
        if prompt_path:
            files_to_scan.append(prompt_path)
            prompt_full_path = ROOT / prompt_path
            if not prompt_full_path.exists():
                return False
            prompt_text = prompt_full_path.read_text(encoding="utf-8")
            if script_path not in prompt_text:
                return False
            if status_path not in prompt_text:
                return False

    if not files_to_scan or not package_script_paths:
        return False
    launcher_text = ""
    for launcher_path in launcher_paths:
        if not launcher_path.startswith(expected_prefix):
            return False
        launcher_full_path = ROOT / launcher_path
        if not launcher_full_path.exists():
            return False
        launcher_text += "\n" + launcher_full_path.read_text(encoding="utf-8")
    for package in packages:
        if not isinstance(package, dict):
            continue
        if package.get("launcher_selected") is not True and package.get("staged_launcher_selected") is not True:
            continue
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not script_path or script_path not in launcher_text:
            return False

    for file_path in files_to_scan:
        if not file_path.startswith(expected_prefix):
            return False
        content_path = ROOT / file_path
        if not content_path.exists():
            return False
        normalized_content = content_path.read_text(encoding="utf-8").replace("\\", "/").lower()
        if "/tmp/" in normalized_content or "tmp/dispatch-" in normalized_content:
            return False
        if re.search(r"\b[a-z]:/", normalized_content):
            return False
    return True


def dispatch_archived_handoff_execution_guards_present(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_paths = [normalize_artifact_ref(path) for path in manifest.get("launcher_paths") or []]
    if launcher_paths:
        for launcher_path in launcher_paths:
            launcher_full_path = ROOT / launcher_path
            if not launcher_full_path.exists():
                return False
            launcher_text = launcher_full_path.read_text(encoding="utf-8")
            if "exit $LASTEXITCODE" not in launcher_text:
                return False

    guarded_packages = 0
    status_guarded_packages = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        required_env = [
            str(value)
            for value in package.get("effective_required_env") or package.get("required_env") or []
        ]
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not script_path:
            return False
        script_full_path = ROOT / script_path
        if not script_full_path.exists():
            return False
        script_text = script_full_path.read_text(encoding="utf-8")
        status_markers = [
            "$StatusPath",
            "function Write-AgentStatus",
            "package_id = $PackageId",
            "claim_id = $ClaimId",
            "agent_id = $AgentId",
            "status = $Status",
            "artifacts = @($Artifacts)",
            "blocker_cleared = [bool]$BlockerCleared",
            "notes = @($Notes)",
            "$ProfileIdProperty = $Payload.PSObject.Properties['profile_id']",
            "$QualityGateProperty = $Payload.PSObject.Properties['quality_gate']",
            "$PassedProperty = $QualityGateProperty.Value.PSObject.Properties['passed']",
        ]
        if not all(marker in script_text for marker in status_markers):
            return False
        if "$Payload.profile_id" in script_text or "$Payload.quality_gate" in script_text:
            return False
        status_guarded_packages += 1
        if not required_env:
            continue
        if "Missing effective env for package" not in script_text:
            return False
        if "missing_effective_env:" not in script_text:
            return False
        if "Write-AgentStatus 'blocked'" not in script_text:
            return False
        for env_name in required_env:
            if env_name not in script_text:
                return False
        guarded_packages += 1
    return guarded_packages > 0 and status_guarded_packages > 0


def dispatch_archived_dependent_launcher_evidence_guards_present(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    dependent_waves = sorted(
        {
            int(package.get("wave") or 0)
            for package in manifest.get("packages") or []
            if isinstance(package, dict)
            and package.get("parallelizable_in_wave")
            and package.get("depends_on_waves")
        }
    )
    if not dependent_waves:
        return True

    launcher_text_by_wave: dict[int, str] = {}
    for launcher_path in [*(manifest.get("launcher_paths") or []), *(manifest.get("staged_launcher_paths") or [])]:
        launcher_ref = normalize_artifact_ref(launcher_path)
        launcher_full_path = ROOT / launcher_ref
        if not launcher_ref or not launcher_full_path.exists():
            return False
        launcher_text = launcher_full_path.read_text(encoding="utf-8")
        match = re.search(r"(?m)^# Wave: (\d+)\s*$", launcher_text)
        if match:
            launcher_text_by_wave[int(match.group(1))] = launcher_text

    required_markers = [
        "TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH",
        "dispatch_manifest.json",
        "Dependent wave evidence missing",
        "missing_json_output",
        "expected_profile_ids",
        "quality_gate_not_passed",
        "staged_launcher_selected",
        "missing_dependency_packages",
        "Split-Path -Parent $LauncherDir",
    ]
    for wave in dependent_waves:
        launcher_text = launcher_text_by_wave.get(wave)
        if not launcher_text:
            return False
        if not all(marker in launcher_text for marker in required_markers):
            return False
    return True


def dispatch_archived_one_shot_runner_guard_present(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    runner_path = normalize_artifact_ref(manifest.get("dispatch_runner_path"))
    if not runner_path:
        return False
    runner_full_path = ROOT / runner_path
    if not runner_full_path.exists():
        return False
    runner_text = runner_full_path.read_text(encoding="utf-8")
    required_markers = [
        "TAMANDUA_ALLOW_ONE_SHOT_DISPATCH",
        "TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH",
        "TAMANDUA_DISPATCH_AGENT_ID",
        "ClaimLockHelperPath",
        "Missing claim lock helper",
        "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
        "$env:TAMANDUA_AGENT_ID = $script:DispatchAgentId",
        "-File $script:ClaimLockHelperPath -ClaimId $ClaimId -AgentId $script:DispatchAgentId",
        "claim lock exit",
        "DispatchFailures",
        "FailedWaves",
        "Write-DispatchBlockedPackageStatus",
        "Write-DispatchBlockedWaveStatuses",
        "claim_id = 'claim-' + [string]$Package.package_id",
        "agent_id = $script:DispatchAgentId",
        "status = 'blocked'",
        "exit_code = 2",
        "missing_profiles = $ExpectedProfiles",
        "Test-DispatchWaveDependencies",
        "skipped because dependency wave failed",
        "skipped because dependency evidence missing",
        "Invoke-DispatchCommand",
        "Dispatch one-shot completed with failures",
        "--summarize-dispatch",
        "--promote-dispatch-results",
        "generate_validation_scorecard.py",
        "validation_status_consistency.py",
    ]
    if not all(marker in runner_text for marker in required_markers):
        return False
    staged_paths = [normalize_artifact_ref(path) for path in manifest.get("staged_launcher_paths") or []]
    if staged_paths and not any(path in runner_text for path in staged_paths):
        return False
    staged_required_markers = [
        "StageFailures",
        "Failed package jobs across staged wave",
        "stage ",
    ]
    for staged_path in staged_paths:
        staged_full_path = ROOT / staged_path
        if not staged_path or not staged_full_path.exists():
            return False
        staged_text = staged_full_path.read_text(encoding="utf-8")
        if not all(marker in staged_text for marker in staged_required_markers):
            return False
    return True


def dispatch_archived_env_checklist_includes_operator_input_details(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    checklist_path = normalize_artifact_ref(manifest.get("env_checklist_path"))
    if not checklist_path:
        return False
    checklist_full_path = ROOT / checklist_path
    if not checklist_full_path.exists():
        return False
    checklist_text = checklist_full_path.read_text(encoding="utf-8")
    if "| Flag | Description |" not in checklist_text:
        return False

    rows: dict[tuple[str, str], dict[str, str]] = {}
    for line in checklist_text.splitlines():
        if not line.startswith("|") or "`" not in line:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 9:
            continue
        package_id = cells[1].strip("`")
        env_name = cells[2].strip("`")
        rows[(package_id, env_name)] = {
            "flag": cells[6].strip("`"),
            "description": cells[7].strip(),
        }

    checked = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        env_details = package.get("env_details") if isinstance(package.get("env_details"), dict) else {}
        for item in package.get("operator_inputs") or []:
            if not isinstance(item, dict) or not item.get("env"):
                continue
            env_name = str(item.get("env"))
            row = rows.get((package_id, env_name))
            if not row:
                return False
            expected_flag = str(item.get("flag") or "-")
            expected_description = str(item.get("description") or "-")
            if row["flag"] != expected_flag:
                return False
            if row["description"] != expected_description:
                return False
            manifest_detail = env_details.get(env_name)
            if not isinstance(manifest_detail, dict):
                return False
            if str(manifest_detail.get("name") or "") != str(item.get("name") or ""):
                return False
            if str(manifest_detail.get("flag") or "") != str(item.get("flag") or ""):
                return False
            if str(manifest_detail.get("description") or "") != str(item.get("description") or ""):
                return False
            checked += 1
    return checked > 0


def dispatch_archived_env_template_is_redacted_and_complete(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    template_path = normalize_artifact_ref(manifest.get("env_template_path"))
    if not template_path:
        return False
    template_full_path = ROOT / template_path
    if not template_full_path.exists():
        return False
    template_text = template_full_path.read_text(encoding="utf-8")
    if "# Validation env handoff template" not in template_text:
        return False
    if "placeholder values only" not in template_text:
        return False
    if "<set-" not in template_text:
        return False

    expected_env: set[str] = set()
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for env_name in package.get("effective_required_env") or []:
            if isinstance(env_name, str) and env_name.strip():
                expected_env.add(env_name)
    if not expected_env:
        return False

    for env_name in expected_env:
        marker = f"$env:{env_name} = '<set-{env_name.lower().replace('_', '-')}"
        if marker not in template_text:
            return False
    assignment_values = re.findall(r"(?m)^\$env:[A-Z0-9_]+\s*=\s*'([^']*)'", template_text)
    return bool(assignment_values) and all(value.startswith("<set-") and value.endswith(">") for value in assignment_values)


def dispatch_archived_owner_launch_plan_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_path"))
    if not plan_path:
        return False
    plan_full_path = ROOT / plan_path
    if not plan_full_path.exists():
        return False
    plan_text = plan_full_path.read_text(encoding="utf-8")
    if "# Validation Owner Launch Plan" not in plan_text:
        return False
    if "| Wave | Stage | Package | Launch mode | Depends | Missing env | Command | Prompt |" not in plan_text:
        return False
    if manifest.get("env_checklist_path") and normalize_artifact_ref(manifest.get("env_checklist_path")) not in plan_text:
        return False
    if manifest.get("env_template_path") and normalize_artifact_ref(manifest.get("env_template_path")) not in plan_text:
        return False

    checked = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        owner = str(package.get("recommended_owner_role") or "unassigned")
        script_path = normalize_artifact_ref(package.get("script_path"))
        prompt_path = normalize_artifact_ref(package.get("prompt_path"))
        if not package_id or not owner or not script_path:
            return False
        if f"## Owner: {owner}" not in plan_text:
            return False
        if f"`{package_id}`" not in plan_text:
            return False
        if f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_path}'" not in plan_text:
            return False
        if prompt_path and prompt_path not in plan_text:
            return False
        for env_name in package.get("effective_required_env") or []:
            if isinstance(env_name, str) and env_name.strip() and env_name not in plan_text:
                return False
        checked += 1
    return checked > 0


def dispatch_archived_owner_launch_plan_json_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_json_path"))
    if not plan_path:
        return False
    plan_full_path = ROOT / plan_path
    if not plan_full_path.exists():
        return False
    try:
        plan = load_json(plan_full_path)
    except json.JSONDecodeError:
        return False
    if plan.get("schema_version") != 1 or plan.get("artifact") != "validation-owner-launch-plan":
        return False
    packages = [package for package in manifest.get("packages") or [] if isinstance(package, dict)]
    owners = [owner for owner in plan.get("owners") or [] if isinstance(owner, dict)]
    if plan.get("package_count") != len(packages):
        return False
    if plan.get("owner_count") != len(owners):
        return False
    if manifest.get("env_checklist_path") and normalize_artifact_ref(manifest.get("env_checklist_path")) != normalize_artifact_ref(plan.get("env_checklist_path")):
        return False
    if manifest.get("env_template_path") and normalize_artifact_ref(manifest.get("env_template_path")) != normalize_artifact_ref(plan.get("env_template_path")):
        return False

    plan_packages: dict[str, dict[str, Any]] = {}
    launchable_package_count = 0
    blocked_package_count = 0
    for owner in owners:
        owner_name = str(owner.get("owner") or "")
        owner_packages = [package for package in owner.get("packages") or [] if isinstance(package, dict)]
        if owner.get("package_count") != len(owner_packages):
            return False
        owner_launchable_count = sum(1 for package in owner_packages if package.get("ready_to_launch") is True)
        if owner.get("launchable_package_count") != owner_launchable_count:
            return False
        if owner.get("blocked_package_count") != len(owner_packages) - owner_launchable_count:
            return False
        launchable_package_count += owner_launchable_count
        blocked_package_count += len(owner_packages) - owner_launchable_count
        for package in owner_packages:
            package_id = str(package.get("package_id") or "")
            if not package_id or package_id in plan_packages:
                return False
            if owner_name != str(package.get("owner") or owner_name):
                package["owner"] = owner_name
            plan_packages[package_id] = package

    if set(plan_packages) != {str(package.get("package_id") or "") for package in packages}:
        return False
    for manifest_package in packages:
        package_id = str(manifest_package.get("package_id") or "")
        plan_package = plan_packages.get(package_id)
        if not plan_package:
            return False
        script_path = normalize_artifact_ref(manifest_package.get("script_path"))
        prompt_path = normalize_artifact_ref(manifest_package.get("prompt_path"))
        status_path = normalize_artifact_ref(manifest_package.get("status_path"))
        if normalize_artifact_ref(plan_package.get("script_path")) != script_path:
            return False
        if prompt_path and normalize_artifact_ref(plan_package.get("prompt_path")) != prompt_path:
            return False
        if status_path and normalize_artifact_ref(plan_package.get("status_path")) != status_path:
            return False
        status_full_path = ROOT / status_path if status_path else None
        if status_full_path and status_full_path.exists():
            try:
                status_payload = load_json(status_full_path)
            except json.JSONDecodeError:
                return False
            if str(plan_package.get("current_status") or "") != str(status_payload.get("status") or ""):
                return False
            if plan_package.get("current_exit_code") != status_payload.get("exit_code"):
                return False
            if [str(value) for value in plan_package.get("current_notes") or []] != [
                str(value) for value in status_payload.get("notes") or []
            ]:
                return False
            if [str(value) for value in plan_package.get("current_missing_profiles") or []] != [
                str(value) for value in status_payload.get("missing_profiles") or []
            ]:
                return False
            if plan_package.get("current_blocker_cleared") != status_payload.get("blocker_cleared"):
                return False
            expected_artifacts = [normalize_artifact_ref(value) for value in status_payload.get("artifacts") or []]
            if [normalize_artifact_ref(value) for value in plan_package.get("current_artifacts") or []] != expected_artifacts:
                return False
        else:
            if str(plan_package.get("current_status") or "") != "not_run":
                return False
            if plan_package.get("current_artifacts") not in (None, []):
                return False
        current_next_action = plan_package.get("current_next_action") if isinstance(plan_package.get("current_next_action"), dict) else {}
        current_next_action_env = [str(value) for value in current_next_action.get("required_env") or [] if str(value)]
        token_env = str(current_next_action.get("token_env") or "")
        if token_env and token_env not in current_next_action_env:
            current_next_action_env.append(token_env)
        expected_next_action_env = []
        for value in [str(value) for value in manifest_package.get("next_action_required_env") or []] + current_next_action_env:
            if value and value not in expected_next_action_env:
                expected_next_action_env.append(value)
        manifest_effective_env = [str(value) for value in manifest_package.get("effective_required_env") or []]
        manifest_required_env = [str(value) for value in manifest_package.get("required_env") or []]
        expected_effective_env = []
        for value in (manifest_effective_env or manifest_required_env) + expected_next_action_env:
            if value and value not in expected_effective_env:
                expected_effective_env.append(value)
        if "current_next_action_required_env" in plan_package and [
            str(value) for value in plan_package.get("current_next_action_required_env") or []
        ] != current_next_action_env:
            return False
        if "next_action_required_env" in plan_package and [
            str(value) for value in plan_package.get("next_action_required_env") or []
        ] != expected_next_action_env:
            return False
        if "effective_required_env" in plan_package and [
            str(value) for value in plan_package.get("effective_required_env") or []
        ] != expected_effective_env:
            return False
        if str(plan_package.get("command") or "") != f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_path}'":
            return False
        if not set(str(value) for value in plan_package.get("missing_effective_env") or []).issubset(
            set(expected_effective_env)
        ):
            return False
        if [int(value) for value in plan_package.get("depends_on_waves") or []] != [
            int(value) for value in manifest_package.get("depends_on_waves") or []
        ]:
            return False
        expected_reasons = []
        if plan_package.get("missing_effective_env"):
            expected_reasons.append("missing_effective_env")
        if manifest_package.get("depends_on_waves"):
            expected_reasons.append("depends_on_prior_waves")
        if manifest_package.get("launcher_selected") is False:
            expected_reasons.append("manual_launch_required")
        if [str(value) for value in plan_package.get("blocked_reasons") or []] != expected_reasons:
            return False
        if bool(plan_package.get("ready_to_launch")) != (not expected_reasons):
            return False
    if plan.get("launchable_package_count") != launchable_package_count:
        return False
    if plan.get("blocked_package_count") != blocked_package_count:
        return False
    return True


def dispatch_archived_execution_matrix_matches_owner_plan(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    matrix_path = normalize_artifact_ref(manifest.get("execution_matrix_path"))
    matrix_json_path = normalize_artifact_ref(manifest.get("execution_matrix_json_path"))
    if not matrix_path and not matrix_json_path:
        return True
    if not matrix_path or not matrix_json_path:
        return False
    matrix_full_path = ROOT / matrix_path
    matrix_json_full_path = ROOT / matrix_json_path
    if not matrix_full_path.exists() or not matrix_json_full_path.exists():
        return False
    matrix_text = matrix_full_path.read_text(encoding="utf-8")
    if "# Validation Execution Matrix" not in matrix_text:
        return False
    if "| Wave | Stage | Owner | Package | Current | Ready | Blockers | Missing env | Artifacts | Next action | Command |" not in matrix_text:
        return False

    plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_json_path"))
    if not plan_path:
        return False
    try:
        plan = load_json(ROOT / plan_path)
        matrix = load_json(matrix_json_full_path)
    except json.JSONDecodeError:
        return False
    if matrix.get("schema_version") != 1 or matrix.get("artifact") != "validation-execution-matrix":
        return False
    rows = [row for row in matrix.get("rows") or [] if isinstance(row, dict)]
    plan_rows = []
    for owner in plan.get("owners") or []:
        if not isinstance(owner, dict):
            continue
        owner_name = str(owner.get("owner") or "unassigned")
        for package in owner.get("packages") or []:
            if not isinstance(package, dict):
                continue
            plan_rows.append(
                {
                    "package_id": str(package.get("package_id") or ""),
                    "owner": owner_name,
                    "wave": int(package.get("wave") or 0),
                    "stage": package.get("stage"),
                    "current_status": str(package.get("current_status") or "not_run"),
                    "current_exit_code": package.get("current_exit_code"),
                    "ready_to_launch": bool(package.get("ready_to_launch")),
                    "blocked_reasons": [str(value) for value in package.get("blocked_reasons") or []],
                    "missing_effective_env": [str(value) for value in package.get("missing_effective_env") or []],
                    "depends_on_waves": [int(value) for value in package.get("depends_on_waves") or []],
                    "resource_tags": [str(value) for value in package.get("resource_tags") or []],
                    "launcher_selected": package.get("launcher_selected"),
                    "manual_reason": package.get("manual_reason"),
                    "current_artifacts": [str(value) for value in package.get("current_artifacts") or []],
                    "current_next_action": package.get("current_next_action") if isinstance(package.get("current_next_action"), dict) else {},
                    "command": str(package.get("command") or ""),
                    "script_path": str(package.get("script_path") or ""),
                    "prompt_path": package.get("prompt_path"),
                    "status_path": str(package.get("status_path") or ""),
                }
            )
    plan_rows.sort(
        key=lambda item: (
            int(item.get("wave") or 0),
            int(item.get("stage") or 999),
            str(item.get("owner") or ""),
            str(item.get("package_id") or ""),
        )
    )
    if rows != plan_rows:
        return False
    if matrix.get("package_count") != len(plan_rows):
        return False
    if matrix.get("ready_to_launch_count") != sum(1 for row in plan_rows if row.get("ready_to_launch") is True):
        return False
    if matrix.get("blocked_count") != sum(1 for row in plan_rows if row.get("ready_to_launch") is not True):
        return False
    for row in plan_rows:
        package_id = str(row.get("package_id") or "")
        if f"`{package_id}`" not in matrix_text:
            return False
        command = str(row.get("command") or "")
        if command and command not in matrix_text:
            return False
    return True


def dispatch_archived_agent_claims_match_execution_matrix(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    claims_path = normalize_artifact_ref(manifest.get("agent_claims_path"))
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_path and not claims_json_path:
        return True
    if not claims_path or not claims_json_path:
        return False
    claims_full_path = ROOT / claims_path
    claims_json_full_path = ROOT / claims_json_path
    if not claims_full_path.exists() or not claims_json_full_path.exists():
        return False
    claims_text = claims_full_path.read_text(encoding="utf-8")
    if "# Validation Agent Claims" not in claims_text:
        return False
    if "| Claim | Wave | Stage | Owner | Package | State | Current | Blockers | Missing env | Next action | Command |" not in claims_text:
        return False

    matrix_json_path = normalize_artifact_ref(manifest.get("execution_matrix_json_path"))
    if not matrix_json_path:
        return False
    try:
        matrix = load_json(ROOT / matrix_json_path)
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    if claims_payload.get("schema_version") != 1 or claims_payload.get("artifact") != "validation-agent-claims":
        return False
    expected_claims = []
    for row in matrix.get("rows") or []:
        if not isinstance(row, dict):
            continue
        package_id = str(row.get("package_id") or "")
        blocked_reasons = [str(value) for value in row.get("blocked_reasons") or []]
        blocked_reason_set = set(blocked_reasons)
        current_status = str(row.get("current_status") or "")
        if row.get("ready_to_launch") is True:
            claim_state = "ready_to_claim"
        elif "missing_effective_env" in blocked_reason_set:
            claim_state = "blocked_missing_env"
        elif "depends_on_prior_waves" in blocked_reason_set:
            claim_state = "blocked_dependency_wave"
        elif "manual_launch_required" in blocked_reason_set:
            claim_state = "manual_claim_required"
        elif current_status in {"pass", "fail", "blocked"}:
            claim_state = f"has_current_{current_status}_evidence"
        else:
            claim_state = "not_ready"
        expected_claims.append(
            {
                "claim_id": f"claim-{package_id}",
                "package_id": package_id,
                "owner": str(row.get("owner") or "unassigned"),
                "wave": int(row.get("wave") or 0),
                "stage": row.get("stage"),
                "claim_state": claim_state,
                "ready_to_launch": bool(row.get("ready_to_launch")),
                "current_status": str(row.get("current_status") or "not_run"),
                "blocked_reasons": blocked_reasons,
                "missing_effective_env": [str(value) for value in row.get("missing_effective_env") or []],
                "depends_on_waves": [int(value) for value in row.get("depends_on_waves") or []],
                "resource_tags": [str(value) for value in row.get("resource_tags") or []],
                "current_artifacts": [str(value) for value in row.get("current_artifacts") or []],
                "current_next_action": row.get("current_next_action") if isinstance(row.get("current_next_action"), dict) else {},
                "command": str(row.get("command") or ""),
                "script_path": str(row.get("script_path") or ""),
                "prompt_path": row.get("prompt_path"),
                "status_path": str(row.get("status_path") or ""),
                "claim_output": {
                    "status_file": "agent_status.json",
                    "allowed_status": ["pass", "fail", "blocked"],
                    "must_update_current_status": True,
                },
            }
        )
    expected_claims.sort(key=lambda item: (int(item.get("wave") or 0), int(item.get("stage") or 999), str(item.get("claim_id") or "")))
    actual_claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    if actual_claims != expected_claims:
        return False
    if claims_payload.get("claim_count") != len(expected_claims):
        return False
    if claims_payload.get("ready_to_claim_count") != sum(1 for claim in expected_claims if claim.get("claim_state") == "ready_to_claim"):
        return False
    if claims_payload.get("blocked_claim_count") != sum(1 for claim in expected_claims if str(claim.get("claim_state") or "").startswith("blocked_")):
        return False
    if claims_payload.get("manual_claim_count") != sum(1 for claim in expected_claims if claim.get("claim_state") == "manual_claim_required"):
        return False
    for claim in expected_claims:
        claim_id = str(claim.get("claim_id") or "")
        if f"`{claim_id}`" not in claims_text:
            return False
        command = str(claim.get("command") or "")
        if command and command not in claims_text:
            return False
    return True


def dispatch_archived_agent_spawn_plan_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    plan_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_path"))
    plan_json_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path"))
    if not plan_path and not plan_json_path:
        return True
    if not plan_path or not plan_json_path:
        return False
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    claim_lock_helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if not claims_json_path or not claim_lock_helper_path:
        return False
    plan_full_path = ROOT / plan_path
    plan_json_full_path = ROOT / plan_json_path
    claims_json_full_path = ROOT / claims_json_path
    if not plan_full_path.exists() or not plan_json_full_path.exists() or not claims_json_full_path.exists():
        return False
    plan_text = plan_full_path.read_text(encoding="utf-8")
    if "# Validation Agent Spawn Plan" not in plan_text:
        return False
    try:
        plan = load_json(plan_json_full_path)
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    if plan.get("schema_version") != 1 or plan.get("artifact") != "validation-agent-spawn-plan":
        return False
    claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    ready_claims = [claim for claim in claims if claim.get("claim_state") == "ready_to_claim"]
    blocked_or_manual_claims = [claim for claim in claims if claim.get("claim_state") != "ready_to_claim"]
    env_bundle_ready_claims = [
        claim
        for claim in claims
        if [str(value) for value in claim.get("missing_effective_env") or []]
        and {str(value) for value in claim.get("blocked_reasons") or []} <= {"missing_effective_env"}
    ]
    env_bundle_still_blocked_claims = [
        claim
        for claim in claims
        if [str(value) for value in claim.get("missing_effective_env") or []]
        and {str(value) for value in claim.get("blocked_reasons") or []} > {"missing_effective_env"}
    ]
    spawn_claims = [
        claim
        for batch in plan.get("batches") or []
        if isinstance(batch, dict)
        for claim in batch.get("claims") or []
        if isinstance(claim, dict)
    ]
    env_bundle_spawn_claims = [
        claim
        for batch in plan.get("env_bundle_ready_batches") or []
        if isinstance(batch, dict)
        for claim in batch.get("claims") or []
        if isinstance(claim, dict)
    ]
    if plan.get("ready_claim_count") != len(ready_claims):
        return False
    if (
        ready_claims
        and "| Claim | Owner | Package | Resources | Next action | Prompt | Codex template | Claude template | Lock command | Run command | Status |"
        not in plan_text
    ):
        return False
    if plan.get("blocked_or_manual_claim_count") != len(blocked_or_manual_claims):
        return False
    if plan.get("env_bundle_ready_claim_count") != len(env_bundle_ready_claims):
        return False
    if plan.get("env_bundle_ready_batch_count") != len(plan.get("env_bundle_ready_batches") or []):
        return False
    if plan.get("env_bundle_still_blocked_claim_count") != len(env_bundle_still_blocked_claims):
        return False
    if len(env_bundle_spawn_claims) != len(env_bundle_ready_claims):
        return False
    if env_bundle_ready_claims and "## Ready After Env Bundle" not in plan_text:
        return False
    if env_bundle_ready_claims and "### Copy/Paste Env-Bundle Spawn Prompts" not in plan_text:
        return False
    if env_bundle_still_blocked_claims and "## Still Blocked After Env Bundle" not in plan_text:
        return False
    if len(spawn_claims) != len(ready_claims):
        return False
    if plan.get("ready_batch_count") != len(plan.get("batches") or []):
        return False
    if len(ready_claims) < 2 and plan.get("not_multi_agent_actionable_reason") != "fewer than two ready claims":
        return False
    if len(ready_claims) >= 2 and plan.get("not_multi_agent_actionable_reason"):
        return False
    if normalize_artifact_ref(plan.get("claim_lock_helper_path")) != claim_lock_helper_path:
        return False
    if "--refresh-claim-status-report" not in str(plan.get("refresh_command") or ""):
        return False
    ready_by_id = {str(claim.get("claim_id") or ""): claim for claim in ready_claims}
    seen_ready_ids = set()
    for spawn_claim in spawn_claims:
        claim_id = str(spawn_claim.get("claim_id") or "")
        source_claim = ready_by_id.get(claim_id)
        if not source_claim:
            return False
        seen_ready_ids.add(claim_id)
        for field in ("package_id", "owner", "prompt_path", "script_path", "status_path"):
            if normalize_artifact_ref(spawn_claim.get(field)) != normalize_artifact_ref(source_claim.get(field)):
                return False
        if [str(value) for value in spawn_claim.get("resource_tags") or []] != [
            str(value) for value in source_claim.get("resource_tags") or []
        ]:
            return False
        if spawn_claim.get("current_next_action") != (
            source_claim.get("current_next_action") if isinstance(source_claim.get("current_next_action"), dict) else {}
        ):
            return False
        action_summary = render_current_next_action_summary(spawn_claim.get("current_next_action"))
        if action_summary != "-" and action_summary not in plan_text:
            return False
        if claim_id not in str(spawn_claim.get("lock_command") or ""):
            return False
        if claim_lock_helper_path not in str(spawn_claim.get("lock_command") or ""):
            return False
        if str(source_claim.get("command") or "") != str(spawn_claim.get("run_command") or ""):
            return False
        if spawn_claim.get("cwd") != ".":
            return False
        if spawn_claim.get("claim_id_env") != f"TAMANDUA_AGENT_CLAIM_ID={claim_id}":
            return False
        if spawn_claim.get("agent_id_env") != "TAMANDUA_AGENT_ID=<agent-id>":
            return False
        templates = spawn_claim.get("agent_spawn_command_templates") or {}
        for provider in ("codex", "claude"):
            template = str(templates.get(provider) or "")
            if provider not in template or claim_id not in template:
                return False
            if str(spawn_claim.get("prompt_path") or "") not in template:
                return False
            if claim_lock_helper_path not in template or "-ClaimId" not in template or "-AgentId" not in template:
                return False
            if "exit $LASTEXITCODE" not in template:
                return False
        prompt_text = str(spawn_claim.get("prompt_text") or "")
        copy_paste_prompt = str(spawn_claim.get("copy_paste_prompt") or "")
        if not prompt_text.strip() or not copy_paste_prompt.strip():
            return False
        for required_text in [
            claim_id,
            str(spawn_claim.get("package_id") or ""),
            str(spawn_claim.get("prompt_path") or ""),
            f"Working directory: {spawn_claim.get('cwd')}",
            str(spawn_claim.get("claim_id_env") or ""),
            str(spawn_claim.get("agent_id_env") or ""),
            str(spawn_claim.get("lock_command") or ""),
            str(spawn_claim.get("run_command") or ""),
            str(templates.get("codex") or ""),
            str(templates.get("claude") or ""),
            prompt_text,
        ]:
            if required_text and required_text not in copy_paste_prompt:
                return False
        if "### Copy/Paste Spawn Prompts" not in plan_text:
            return False
        if copy_paste_prompt not in plan_text:
            return False
        if f"`{claim_id}`" not in plan_text:
            return False
    if seen_ready_ids != set(ready_by_id):
        return False
    env_ready_by_id = {str(claim.get("claim_id") or ""): claim for claim in env_bundle_ready_claims}
    seen_env_ready_ids = set()
    for spawn_claim in env_bundle_spawn_claims:
        claim_id = str(spawn_claim.get("claim_id") or "")
        source_claim = env_ready_by_id.get(claim_id)
        if not source_claim:
            return False
        seen_env_ready_ids.add(claim_id)
        for field in ("package_id", "owner", "prompt_path", "script_path", "status_path"):
            if normalize_artifact_ref(spawn_claim.get(field)) != normalize_artifact_ref(source_claim.get(field)):
                return False
        if [str(value) for value in spawn_claim.get("resource_tags") or []] != [
            str(value) for value in source_claim.get("resource_tags") or []
        ]:
            return False
        if spawn_claim.get("current_next_action") != (
            source_claim.get("current_next_action") if isinstance(source_claim.get("current_next_action"), dict) else {}
        ):
            return False
        action_summary = render_current_next_action_summary(spawn_claim.get("current_next_action"))
        if action_summary != "-" and action_summary not in plan_text:
            return False
        if claim_id not in str(spawn_claim.get("lock_command") or ""):
            return False
        if claim_lock_helper_path not in str(spawn_claim.get("lock_command") or ""):
            return False
        if str(source_claim.get("command") or "") != str(spawn_claim.get("run_command") or ""):
            return False
        if spawn_claim.get("cwd") != ".":
            return False
        if spawn_claim.get("claim_id_env") != f"TAMANDUA_AGENT_CLAIM_ID={claim_id}":
            return False
        if spawn_claim.get("agent_id_env") != "TAMANDUA_AGENT_ID=<agent-id>":
            return False
        templates = spawn_claim.get("agent_spawn_command_templates") or {}
        for provider in ("codex", "claude"):
            template = str(templates.get(provider) or "")
            if provider not in template or claim_id not in template:
                return False
            if str(spawn_claim.get("prompt_path") or "") not in template:
                return False
            if claim_lock_helper_path not in template or "-ClaimId" not in template or "-AgentId" not in template:
                return False
            if "exit $LASTEXITCODE" not in template:
                return False
        prompt_text = str(spawn_claim.get("prompt_text") or "")
        copy_paste_prompt = str(spawn_claim.get("copy_paste_prompt") or "")
        if not prompt_text.strip() or not copy_paste_prompt.strip() or copy_paste_prompt not in plan_text:
            return False
        for required_text in [
            claim_id,
            str(spawn_claim.get("package_id") or ""),
            str(spawn_claim.get("prompt_path") or ""),
            f"Working directory: {spawn_claim.get('cwd')}",
            str(spawn_claim.get("claim_id_env") or ""),
            str(spawn_claim.get("agent_id_env") or ""),
            str(spawn_claim.get("lock_command") or ""),
            str(spawn_claim.get("run_command") or ""),
            str(templates.get("codex") or ""),
            str(templates.get("claude") or ""),
            prompt_text,
        ]:
            if required_text and required_text not in copy_paste_prompt:
                return False
    if seen_env_ready_ids != set(env_ready_by_id):
        return False
    env_still_ids = {str(claim.get("claim_id") or "") for claim in env_bundle_still_blocked_claims}
    plan_env_still_ids = {
        str(claim.get("claim_id") or "")
        for claim in plan.get("env_bundle_still_blocked_claims") or []
        if isinstance(claim, dict)
    }
    if plan_env_still_ids != env_still_ids:
        return False
    for source_claim in env_bundle_still_blocked_claims:
        claim_id = str(source_claim.get("claim_id") or "")
        plan_claim = next(
            (
                claim
                for claim in plan.get("env_bundle_still_blocked_claims") or []
                if isinstance(claim, dict) and str(claim.get("claim_id") or "") == claim_id
            ),
            {},
        )
        if plan_claim.get("current_next_action") != (
            source_claim.get("current_next_action") if isinstance(source_claim.get("current_next_action"), dict) else {}
        ):
            return False
    blocked_ids = {str(claim.get("claim_id") or "") for claim in blocked_or_manual_claims}
    plan_blocked_ids = {
        str(claim.get("claim_id") or "")
        for claim in plan.get("blocked_or_manual_claims") or []
        if isinstance(claim, dict)
    }
    if plan_blocked_ids != blocked_ids:
        return False
    for source_claim in blocked_or_manual_claims:
        claim_id = str(source_claim.get("claim_id") or "")
        plan_claim = next(
            (
                claim
                for claim in plan.get("blocked_or_manual_claims") or []
                if isinstance(claim, dict) and str(claim.get("claim_id") or "") == claim_id
            ),
            {},
        )
        if plan_claim.get("current_next_action") != (
            source_claim.get("current_next_action") if isinstance(source_claim.get("current_next_action"), dict) else {}
        ):
            return False
    return True


def dispatch_archived_agent_spawn_launcher_matches_spawn_plan(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    plan_json_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path"))
    if not launcher_path and not plan_json_path:
        return True
    if not launcher_path or not plan_json_path:
        return False
    launcher_full_path = ROOT / launcher_path
    plan_json_full_path = ROOT / plan_json_path
    if not launcher_full_path.exists() or not plan_json_full_path.exists():
        return False
    launcher_text = launcher_full_path.read_text(encoding="utf-8")
    try:
        plan = load_json(plan_json_full_path)
    except json.JSONDecodeError:
        return False
    execute_policy = plan.get("execute_policy") or {}
    if execute_policy.get("one_provider_per_claim") is not True:
        return False
    if execute_policy.get("override_switch") != "-AllowDuplicateProviderPerClaim":
        return False
    if execute_policy.get("override_env") != "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM":
        return False
    if execute_policy.get("parallel_switch") != "-Parallel":
        return False
    for required_text in [
        "# Validation Agent Spawn Launcher",
        "[ValidateSet('codex','claude','all')]",
        "[ValidateSet('ready','env-bundle','all')]",
        "[switch]$ShowBlocked",
        "[switch]$AllowDuplicateProviderPerClaim",
        "[switch]$Parallel",
        "Group-Object claim_id",
        "Refusing to execute multiple providers for the same claim",
        "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM",
        "Refusing duplicate provider execution without TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1",
        "[duplicate-provider-override]",
        "Start-Job -Name ($Row.provider + '-' + $Row.claim_id)",
        "Remove-Job -Job $Job -Force",
        "Agent spawn parallel execution failed",
        "AgentId may only contain letters",
        "$SawResult = $false",
        "produced no result",
        "Agent spawn sequential execution failed",
        "Show-BlockedClaims",
        "$Plan.blocked_or_manual_claims",
        "Format-NextAction",
        "next_action=",
        "[blocked][",
        "TAMANDUA_SPAWN_AGENT_ID",
        "TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH",
        "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH",
        "Refusing to execute env-bundle spawn commands without TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH=1",
        "Dry run only",
        "Invoke-Expression $Row.command",
        "if ($Phase -in @('ready','all')) { Add-SpawnRows @($Plan.batches) 'ready' }",
        "if ($Phase -in @('env-bundle','all')) { Add-SpawnRows @($Plan.env_bundle_ready_batches) 'env-bundle' }",
        plan_json_path,
    ]:
        if required_text not in launcher_text:
            return False
    for batch_key, phase_name in (("batches", "ready"), ("env_bundle_ready_batches", "env-bundle")):
        for batch in plan.get(batch_key) or []:
            if not isinstance(batch, dict):
                continue
            for claim in batch.get("claims") or []:
                if not isinstance(claim, dict):
                    continue
                claim_id = str(claim.get("claim_id") or "")
                if not claim_id:
                    return False
                templates = claim.get("agent_spawn_command_templates") or {}
                for provider in ("codex", "claude"):
                    template = str(templates.get(provider) or "")
                    if not template or provider not in template or claim_id not in template:
                        return False
                if phase_name not in launcher_text:
                    return False
    return True


def dispatch_archived_claim_status_report_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    report_path = normalize_artifact_ref(manifest.get("claim_status_report_path"))
    report_json_path = normalize_artifact_ref(manifest.get("claim_status_report_json_path"))
    if not report_path and not report_json_path:
        return True
    if not report_path or not report_json_path:
        return False
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    report_full_path = ROOT / report_path
    report_json_full_path = ROOT / report_json_path
    claims_json_full_path = ROOT / claims_json_path
    if not report_full_path.exists() or not report_json_full_path.exists() or not claims_json_full_path.exists():
        return False
    report_text = report_full_path.read_text(encoding="utf-8")
    if "# Validation Claim Status Report" not in report_text:
        return False
    if "| Claim | Wave | Stage | Owner | Package | State | Agent status | Agent claim | Agent id | Lock | Lock agent | Locked at | Exit | Missing env | Missing profiles | Artifacts | Next action | Command |" not in report_text:
        return False
    try:
        claims_payload = load_json(claims_json_full_path)
        report = load_json(report_json_full_path)
    except json.JSONDecodeError:
        return False
    if report.get("schema_version") != 1 or report.get("artifact") != "validation-claim-status-report":
        return False
    claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    report_claims = [claim for claim in report.get("claims") or [] if isinstance(claim, dict)]
    if report.get("claim_count") != len(claims):
        return False
    if report.get("ready_to_claim_count") != sum(1 for claim in claims if claim.get("claim_state") == "ready_to_claim"):
        return False
    if report.get("blocked_claim_count") != sum(1 for claim in claims if str(claim.get("claim_state") or "").startswith("blocked_")):
        return False
    if report.get("manual_claim_count") != sum(1 for claim in claims if claim.get("claim_state") == "manual_claim_required"):
        return False
    if report.get("locked_claim_count") != sum(
        1 for claim in report_claims if claim.get("lock_state") == "locked"
    ):
        return False
    if report.get("invalid_lock_count") != sum(
        1 for claim in report_claims if claim.get("lock_state") == "invalid"
    ):
        return False
    for required_text in [
        f"- Claims: `{report.get('claim_count')}`",
        f"- Ready to claim: `{report.get('ready_to_claim_count')}`",
        f"- Blocked: `{report.get('blocked_claim_count')}`",
        f"- Manual: `{report.get('manual_claim_count')}`",
        f"- Locked claims: `{report.get('locked_claim_count')}`",
        f"- Invalid locks: `{report.get('invalid_lock_count')}`",
        "- Status counts:",
    ]:
        if required_text not in report_text:
            return False
    claim_by_id = {str(claim.get("claim_id") or ""): claim for claim in claims}
    report_by_id = {str(claim.get("claim_id") or ""): claim for claim in report_claims}
    if set(claim_by_id) != set(report_by_id):
        return False
    status_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for claim_id, claim in claim_by_id.items():
        report_claim = report_by_id[claim_id]
        for field in [
            "package_id",
            "owner",
            "wave",
            "stage",
            "claim_state",
            "ready_to_launch",
            "script_path",
            "prompt_path",
            "status_path",
            "command",
            "current_next_action",
        ]:
            if report_claim.get(field) != claim.get(field):
                return False
        if [str(value) for value in report_claim.get("missing_effective_env") or []] != [
            str(value) for value in claim.get("missing_effective_env") or []
        ]:
            return False
        if [str(value) for value in report_claim.get("blocked_reasons") or []] != [
            str(value) for value in claim.get("blocked_reasons") or []
        ]:
            return False
        if [str(value) for value in report_claim.get("resource_tags") or []] != [
            str(value) for value in claim.get("resource_tags") or []
        ]:
            return False
        lock_state = str(report_claim.get("lock_state") or "")
        if lock_state not in {"unlocked", "locked", "invalid"}:
            return False
        lock_path = normalize_artifact_ref(report_claim.get("lock_path"))
        expected_lock_suffix = f"claim_locks/{claim_id}.claim-lock.json"
        if not lock_path or not lock_path.replace("\\", "/").endswith(expected_lock_suffix):
            return False
        if lock_state == "locked" and (
            not str(report_claim.get("lock_agent_id") or "") or not str(report_claim.get("locked_at") or "")
        ):
            return False
        if lock_state == "unlocked" and (
            str(report_claim.get("lock_agent_id") or "") or str(report_claim.get("locked_at") or "")
        ):
            return False
        current_status = str(claim.get("current_status") or "not_run")
        if str(report_claim.get("agent_status") or "") not in {current_status, "pass", "fail", "blocked", "invalid"}:
            return False
        status_path = normalize_artifact_ref(claim.get("status_path"))
        if status_path:
            status_full_path = ROOT / status_path
            if not status_full_path.exists():
                return False
            try:
                status_payload = load_json(status_full_path)
            except json.JSONDecodeError:
                expected_agent_claim_id = ""
                expected_agent_id = ""
            else:
                expected_agent_claim_id = str(status_payload.get("claim_id") or f"claim-{claim.get('package_id') or ''}")
                expected_agent_id = str(status_payload.get("agent_id") or "unknown-agent")
            if str(report_claim.get("agent_claim_id") or "") != expected_agent_claim_id:
                return False
            if str(report_claim.get("agent_id") or "") != expected_agent_id:
                return False
        elif str(report_claim.get("agent_claim_id") or "") or str(report_claim.get("agent_id") or ""):
            return False
        status = str(report_claim.get("agent_status") or "unknown")
        state = str(report_claim.get("claim_state") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        state_counts[state] = state_counts.get(state, 0) + 1
        if f"`{claim_id}`" not in report_text:
            return False
        agent_claim_id = str(report_claim.get("agent_claim_id") or "")
        if agent_claim_id and f"`{agent_claim_id}`" not in report_text:
            return False
        agent_id = str(report_claim.get("agent_id") or "")
        if agent_id and agent_id not in report_text:
            return False
    if report.get("status_counts") != dict(sorted(status_counts.items())):
        return False
    if report.get("claim_state_counts") != dict(sorted(state_counts.items())):
        return False
    return True


def dispatch_archived_claim_lock_helper_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if not helper_path:
        return True
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    helper_full_path = ROOT / helper_path
    claims_json_full_path = ROOT / claims_json_path
    if not helper_full_path.exists() or not claims_json_full_path.exists():
        return False
    helper_text = helper_full_path.read_text(encoding="utf-8")
    for required_text in [
        "# Validation Claim Lock Helper",
        "CreateNew",
        "claim_locks",
        "Unknown validation claim",
        "Claim already locked",
        "ConvertTo-Json",
        "[switch]$List",
        "[string]$ResetClaimId",
        "[switch]$ResetAll",
        "Refusing to reset claim lock without -Force",
        "Refusing to reset all claim locks without -Force",
    ]:
        if required_text not in helper_text:
            return False
    try:
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        claim_id = str(claim.get("claim_id") or "")
        if claim_id and claim_id not in helper_text:
            return False
    return True


def dispatch_archived_env_unblock_queue_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    queue_json_path = normalize_artifact_ref(manifest.get("env_unblock_queue_json_path"))
    if not queue_path and not queue_json_path:
        return True
    if not queue_path or not queue_json_path:
        return False
    queue_full_path = ROOT / queue_path
    queue_json_full_path = ROOT / queue_json_path
    if not queue_full_path.exists() or not queue_json_full_path.exists():
        return False
    queue_text = queue_full_path.read_text(encoding="utf-8")
    if "# Validation Env Unblock Queue" not in queue_text:
        return False
    if "| Env | Owners | Claims | Single-env ready | Single-env still blocked | Immediate | Dependency | Manual | Set command | Claim IDs |" not in queue_text:
        return False

    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    try:
        claims_payload = load_json(ROOT / claims_json_path)
        queue = load_json(queue_json_full_path)
    except json.JSONDecodeError:
        return False
    if queue.get("schema_version") != 1 or queue.get("artifact") != "validation-env-unblock-queue":
        return False
    env_entries: dict[str, dict[str, Any]] = {}
    next_action_env_entries: dict[str, dict[str, Any]] = {}
    claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        next_action_env = [str(value) for value in next_action.get("required_env") or [] if str(value)]
        token_env = str(next_action.get("token_env") or "")
        if token_env:
            next_action_env.append(token_env)
        seen_next_action_env = set()
        for env_name in next_action_env:
            if env_name in seen_next_action_env:
                continue
            seen_next_action_env.add(env_name)
            entry = next_action_env_entries.setdefault(
                env_name,
                {
                    "env": env_name,
                    "owners": set(),
                    "claim_ids": [],
                    "package_ids": [],
                    "waves": set(),
                    "token_login_commands": set(),
                    "actions": [],
                },
            )
            entry["owners"].add(str(claim.get("owner") or "unassigned"))
            entry["claim_ids"].append(str(claim.get("claim_id") or ""))
            entry["package_ids"].append(str(claim.get("package_id") or ""))
            entry["waves"].add(int(claim.get("wave") or 0))
            if next_action.get("token_login_command"):
                entry["token_login_commands"].add(str(next_action.get("token_login_command")))
            if next_action.get("action"):
                entry["actions"].append(str(next_action.get("action")))
        for env_name in [str(value) for value in claim.get("missing_effective_env") or []]:
            entry = env_entries.setdefault(
                env_name,
                {
                    "env": env_name,
                    "owners": set(),
                    "claim_ids": [],
                    "package_ids": [],
                    "waves": set(),
                    "immediate_claim_ids": [],
                    "dependency_claim_ids": [],
                    "manual_claim_ids": [],
                },
            )
            entry["owners"].add(str(claim.get("owner") or "unassigned"))
            entry["claim_ids"].append(str(claim.get("claim_id") or ""))
            entry["package_ids"].append(str(claim.get("package_id") or ""))
            entry["waves"].add(int(claim.get("wave") or 0))
            blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
            if "depends_on_prior_waves" in blocked_reasons:
                entry["dependency_claim_ids"].append(str(claim.get("claim_id") or ""))
            elif "manual_launch_required" in blocked_reasons:
                entry["manual_claim_ids"].append(str(claim.get("claim_id") or ""))
            else:
                entry["immediate_claim_ids"].append(str(claim.get("claim_id") or ""))
    expected_entries = []
    for entry in env_entries.values():
        claim_ids = sorted(set(value for value in entry["claim_ids"] if value))
        immediate_claim_ids = sorted(set(value for value in entry["immediate_claim_ids"] if value))
        dependency_claim_ids = sorted(set(value for value in entry["dependency_claim_ids"] if value))
        manual_claim_ids = sorted(set(value for value in entry["manual_claim_ids"] if value))
        env_name = str(entry["env"])
        single_env_ready_claim_ids = []
        single_env_still_blocked_claim_ids = []
        remaining_env_after_setting: dict[str, list[str]] = {}
        for claim in claims:
            claim_id = str(claim.get("claim_id") or "")
            missing_env = [str(value) for value in claim.get("missing_effective_env") or []]
            if env_name not in missing_env:
                continue
            remaining_env = sorted(value for value in missing_env if value != env_name)
            remaining_env_after_setting[claim_id] = remaining_env
            blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
            if not remaining_env and blocked_reasons <= {"missing_effective_env"}:
                single_env_ready_claim_ids.append(claim_id)
            else:
                single_env_still_blocked_claim_ids.append(claim_id)
        expected_entries.append(
            {
                "env": env_name,
                "owners": sorted(entry["owners"]),
                "claim_ids": claim_ids,
                "package_ids": sorted(set(value for value in entry["package_ids"] if value)),
                "waves": sorted(entry["waves"]),
                "claim_count": len(claim_ids),
                "immediate_claim_count": len(immediate_claim_ids),
                "dependency_claim_count": len(dependency_claim_ids),
                "manual_claim_count": len(manual_claim_ids),
                "immediate_claim_ids": immediate_claim_ids,
                "dependency_claim_ids": dependency_claim_ids,
                "manual_claim_ids": manual_claim_ids,
                "single_env_ready_claim_ids": sorted(single_env_ready_claim_ids),
                "single_env_still_blocked_claim_ids": sorted(single_env_still_blocked_claim_ids),
                "remaining_env_after_setting": remaining_env_after_setting,
            }
        )
    expected_entries.sort(
        key=lambda item: (
            -int(item.get("immediate_claim_count") or 0),
            -int(item.get("claim_count") or 0),
            str(item.get("env") or ""),
        )
    )
    expected_next_action_entries = []
    for entry in next_action_env_entries.values():
        claim_ids = sorted(set(value for value in entry["claim_ids"] if value))
        env_name = str(entry["env"])
        expected_next_action_entries.append(
            {
                "env": env_name,
                "owners": sorted(entry["owners"]),
                "claim_ids": claim_ids,
                "package_ids": sorted(set(value for value in entry["package_ids"] if value)),
                "waves": sorted(entry["waves"]),
                "claim_count": len(claim_ids),
                "token_login_commands": sorted(entry["token_login_commands"]),
                "actions": sorted(set(value for value in entry["actions"] if value)),
            }
        )
    expected_next_action_entries.sort(
        key=lambda item: (
            -int(item.get("claim_count") or 0),
            str(item.get("env") or ""),
        )
    )
    queue_entries = [entry for entry in queue.get("entries") or [] if isinstance(entry, dict)]
    comparable_queue_entries = [
        {
            key: value
            for key, value in entry.items()
            if key not in ("placeholder", "powershell_set_command", "copy_paste_unblock_prompt")
        }
        for entry in queue_entries
    ]
    if comparable_queue_entries != expected_entries:
        return False
    queue_next_action_entries = [
        entry for entry in queue.get("next_action_entries") or [] if isinstance(entry, dict)
    ]
    comparable_queue_next_action_entries = [
        {
            key: value
            for key, value in entry.items()
            if key not in ("placeholder", "powershell_set_command")
        }
        for entry in queue_next_action_entries
    ]
    if comparable_queue_next_action_entries != expected_next_action_entries:
        return False
    if queue.get("env_count") != len(expected_entries):
        return False
    if queue.get("next_action_env_count") != len(expected_next_action_entries):
        return False
    if queue.get("blocked_claim_count") != int(claims_payload.get("blocked_claim_count") or 0):
        return False
    all_env_names = {str(entry.get("env") or "") for entry in expected_entries}
    expected_ready_after_all = []
    expected_still_blocked_after_all = []
    for claim in claims:
        claim_id = str(claim.get("claim_id") or "")
        missing_env = {str(value) for value in claim.get("missing_effective_env") or []}
        if not missing_env:
            continue
        remaining_env = missing_env - all_env_names
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
        if not remaining_env and blocked_reasons <= {"missing_effective_env"}:
            expected_ready_after_all.append(claim_id)
        else:
            expected_still_blocked_after_all.append(claim_id)
    expected_all_env_commands = [
        f"$env:{entry.get('env')} = '{env_template_placeholder(str(entry.get('env') or ''))}'"
        for entry in expected_entries
    ]
    expected_next_action_env_commands = [
        f"$env:{entry.get('env')} = '{env_template_placeholder(str(entry.get('env') or ''))}'"
        for entry in expected_next_action_entries
    ]
    if queue.get("all_env_powershell_set_commands") != expected_all_env_commands:
        return False
    if queue.get("next_action_env_powershell_set_commands") != expected_next_action_env_commands:
        return False
    env_bundle_launcher_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    expected_post_env_bundle_launcher_commands = []
    expected_env_bundle_validation_command = ""
    if expected_ready_after_all:
        if not env_bundle_launcher_path:
            return False
        expected_env_bundle_validation_command = (
            f"powershell -NoProfile -ExecutionPolicy Bypass -File '{env_bundle_launcher_path}' -ValidateOnly"
        )
        expected_post_env_bundle_launcher_commands = [
            "$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
            f"powershell -NoProfile -ExecutionPolicy Bypass -File '{env_bundle_launcher_path}'",
        ]
    if queue.get("env_bundle_validation_command") != expected_env_bundle_validation_command:
        return False
    if queue.get("post_env_bundle_launcher_commands") != expected_post_env_bundle_launcher_commands:
        return False
    if queue.get("ready_after_all_env_claim_ids") != sorted(expected_ready_after_all):
        return False
    if queue.get("still_blocked_after_all_env_claim_ids") != sorted(expected_still_blocked_after_all):
        return False
    if "## Copy/Paste Complete Env Bundle" not in queue_text:
        return False
    for command in expected_all_env_commands:
        if command not in queue_text:
            return False
    if expected_next_action_env_commands:
        if "## Copy/Paste Next-Action Env Commands" not in queue_text:
            return False
        if "## Next-Action Env Follow-Ups" not in queue_text:
            return False
        for command in expected_next_action_env_commands:
            if command not in queue_text:
                return False
        for entry in expected_next_action_entries:
            env_name = str(entry.get("env") or "")
            if f"`{env_name}`" not in queue_text:
                return False
            queue_entry = next(
                (item for item in queue_next_action_entries if str(item.get("env") or "") == env_name),
                {},
            )
            placeholder = str(queue_entry.get("placeholder") or "")
            set_command = str(queue_entry.get("powershell_set_command") or "")
            if not placeholder.startswith("<set-") or not placeholder.endswith(">"):
                return False
            if set_command != f"$env:{env_name} = '{placeholder}'":
                return False
            for claim_id in entry.get("claim_ids") or []:
                if str(claim_id) not in queue_text:
                    return False
            for package_id in entry.get("package_ids") or []:
                if str(package_id) not in queue_text:
                    return False
            for command in entry.get("token_login_commands") or []:
                if str(command) not in queue_text:
                    return False
    if expected_post_env_bundle_launcher_commands:
        if "## Copy/Paste Env-Bundle Validation" not in queue_text:
            return False
        if expected_env_bundle_validation_command not in queue_text:
            return False
        if "## Copy/Paste Post-Env-Bundle Launcher" not in queue_text:
            return False
        for command in expected_post_env_bundle_launcher_commands:
            if command not in queue_text:
                return False
    for entry in expected_entries:
        env_name = str(entry.get("env") or "")
        if f"`{env_name}`" not in queue_text:
            return False
        queue_entry = next((item for item in queue_entries if str(item.get("env") or "") == env_name), {})
        placeholder = str(queue_entry.get("placeholder") or "")
        set_command = str(queue_entry.get("powershell_set_command") or "")
        unblock_prompt = str(queue_entry.get("copy_paste_unblock_prompt") or "")
        if not placeholder.startswith("<set-") or not placeholder.endswith(">"):
            return False
        if set_command != f"$env:{env_name} = '{placeholder}'":
            return False
        if set_command not in queue_text or set_command not in unblock_prompt:
            return False
        if "## Copy/Paste Env Unblock Commands" not in queue_text:
            return False
        if f"Env: {env_name}" not in unblock_prompt:
            return False
        if "Claims ready after setting only this env:" not in unblock_prompt:
            return False
        if "Claims still blocked after setting only this env:" not in unblock_prompt:
            return False
        if "Dependency-gated claims also needing this env:" not in unblock_prompt:
            return False
        if "Manual claims also needing this env:" not in unblock_prompt:
            return False
        if "All affected packages:" not in unblock_prompt:
            return False
        for claim_id in entry.get("single_env_ready_claim_ids") or []:
            if str(claim_id) not in unblock_prompt or str(claim_id) not in queue_text:
                return False
        for claim_id in entry.get("single_env_still_blocked_claim_ids") or []:
            if str(claim_id) not in unblock_prompt or str(claim_id) not in queue_text:
                return False
        for claim_id in entry.get("immediate_claim_ids") or []:
            if str(claim_id) not in unblock_prompt:
                return False
        for claim_id in entry.get("dependency_claim_ids") or []:
            if str(claim_id) not in unblock_prompt:
                return False
        for claim_id in entry.get("manual_claim_ids") or []:
            if str(claim_id) not in unblock_prompt:
                return False
        for package_id in entry.get("package_ids") or []:
            if str(package_id) not in unblock_prompt:
                return False
        for claim_id in entry.get("claim_ids") or []:
            if str(claim_id) not in queue_text:
                return False
    return True


def dispatch_archived_ready_claims_launcher_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_path = normalize_artifact_ref(manifest.get("ready_claims_launcher_path"))
    if not launcher_path:
        return True
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    launcher_full_path = ROOT / launcher_path
    claims_json_full_path = ROOT / claims_json_path
    if not launcher_full_path.exists() or not claims_json_full_path.exists():
        return False
    launcher_text = launcher_full_path.read_text(encoding="utf-8")
    if "# Validation Ready Claims Launcher" not in launcher_text:
        return False
    if "TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH" not in launcher_text:
        return False
    for required_text in [
        "[switch]$ValidateOnly",
        "Ready claims validation passed. Ready claims:",
        "claim_lock_helper.ps1",
        "TAMANDUA_READY_CLAIMS_AGENT_ID",
        "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
        "$env:TAMANDUA_AGENT_ID = $script:ReadyClaimAgentId",
        "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
        "dispatch_manifest.json",
        "--refresh-claim-status-report",
        "Invoke-ClaimStatusRefresh",
        "ready_to_claim",
    ]:
        if required_text not in launcher_text:
            return False
    try:
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    lock_position = launcher_text.find(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ClaimLockHelperPath "
        "-ClaimId $ClaimId -AgentId $script:ReadyClaimAgentId"
    )
    claim_env_position = launcher_text.find("$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId")
    agent_env_position = launcher_text.find("$env:TAMANDUA_AGENT_ID = $script:ReadyClaimAgentId")
    script_position = launcher_text.find("powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath")
    if (
        lock_position < 0
        or claim_env_position < 0
        or agent_env_position < 0
        or script_position < 0
        or claim_env_position > lock_position
        or agent_env_position > lock_position
        or lock_position > script_position
    ):
        return False
    ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") == "ready_to_claim"
    ]
    non_ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") != "ready_to_claim"
    ]
    executable_lines = [
        line.strip() for line in launcher_text.splitlines() if line.strip().startswith("Invoke-ReadyClaim ")
    ]
    if len(executable_lines) != len(ready_claims):
        return False
    for claim in ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if not claim_id or not package_id or not script_path:
            return False
        if f"# Claim: {claim_id}" not in launcher_text:
            return False
        if f"# Package: {package_id}" not in launcher_text:
            return False
        if script_path not in launcher_text:
            return False
        expected_invocation = f"Invoke-ReadyClaim '{claim_id}' '{package_id}' '{script_path}'"
        if expected_invocation not in executable_lines:
            return False
    for claim in non_ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if claim_id and f"# Claim: {claim_id}" in launcher_text:
            return False
        if package_id and f"# Package: {package_id}" in launcher_text:
            return False
        for line in executable_lines:
            if (claim_id and claim_id in line) or (script_path and script_path in line):
                return False
    return True


def dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_path = normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path"))
    if not launcher_path:
        return True
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    launcher_full_path = ROOT / launcher_path
    claims_json_full_path = ROOT / claims_json_path
    if not launcher_full_path.exists() or not claims_json_full_path.exists():
        return False
    launcher_text = launcher_full_path.read_text(encoding="utf-8")
    if "# Validation Ready Claims Parallel Launcher" not in launcher_text:
        return False
    for required_text in [
        "[switch]$ValidateOnly",
        "Ready claims validation passed. Ready claims:",
        "TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH",
        "claim_lock_helper.ps1",
        "TAMANDUA_READY_CLAIMS_AGENT_ID",
        "dispatch_manifest.json",
        "--refresh-claim-status-report",
        "Invoke-ClaimStatusRefresh",
        "Start-Job",
        "Wait-ReadyClaimBatch",
        "Phase = 'auth-env'",
        "Phase = 'auth-login'",
        "$InnerTokenLoginCommand",
        "ExitCode",
        "$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId",
        "$env:TAMANDUA_AGENT_ID = $InnerAgentId",
        "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
        "ready_to_claim",
    ]:
        if required_text not in launcher_text:
            return False
    lock_invocation = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerClaimLockHelperPath "
        "-ClaimId $InnerClaimId -AgentId $InnerAgentId"
    )
    lock_position = launcher_text.find(lock_invocation)
    claim_env_position = launcher_text.find("$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId")
    agent_env_position = launcher_text.find("$env:TAMANDUA_AGENT_ID = $InnerAgentId")
    script_position = launcher_text.find("powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerScriptPath")
    if (
        lock_position < 0
        or claim_env_position < 0
        or agent_env_position < 0
        or script_position < 0
        or claim_env_position > lock_position
        or agent_env_position > lock_position
        or lock_position > script_position
    ):
        return False
    if "Phase = 'lock'" not in launcher_text or "Phase = 'run'" not in launcher_text:
        return False
    try:
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") == "ready_to_claim"
    ]
    non_ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") != "ready_to_claim"
    ]
    executable_lines = [
        line.strip()
        for line in launcher_text.splitlines()
        if line.strip().startswith("$ReadyClaimJobs += Start-ReadyClaimJob ")
    ]
    if len(executable_lines) != len(ready_claims):
        return False
    for claim in ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if not claim_id or not package_id or not script_path:
            return False
        if f"# Claim: {claim_id}" not in launcher_text:
            return False
        if f"# Package: {package_id}" not in launcher_text:
            return False
        if script_path not in launcher_text:
            return False
        resources = ", ".join(str(value) for value in claim.get("resource_tags") or []) or "-"
        if f"# Resources: {resources}" not in launcher_text:
            return False
        next_action = render_current_next_action_summary(claim.get("current_next_action"))
        if f"# Next action: {next_action}" not in launcher_text:
            return False
        current_next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        token_env = str(current_next_action.get("token_env") or "")
        token_login_command = str(current_next_action.get("token_login_command") or "")
        expected_invocation = (
            f"$ReadyClaimJobs += Start-ReadyClaimJob '{claim_id}' '{package_id}' '{script_path}' "
            f"'{token_env}' '{token_login_command}'"
        )
        if expected_invocation not in executable_lines:
            return False
    for claim in non_ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if claim_id and f"# Claim: {claim_id}" in launcher_text:
            return False
        if package_id and f"# Package: {package_id}" in launcher_text:
            return False
        for line in executable_lines:
            if (claim_id and claim_id in line) or (script_path and script_path in line):
                return False
    return True


def dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    if not launcher_path:
        return True
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    launcher_full_path = ROOT / launcher_path
    claims_json_full_path = ROOT / claims_json_path
    if not launcher_full_path.exists() or not claims_json_full_path.exists():
        return False
    launcher_text = launcher_full_path.read_text(encoding="utf-8")
    for required_text in [
        "# Validation Env-Bundle Ready Claims Launcher",
        "[switch]$ValidateOnly",
        "Env bundle validation passed. Ready claims:",
        "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH",
        "TAMANDUA_ENV_BUNDLE_CLAIMS_AGENT_ID",
        "env_unblock_queue.json",
        "claim_lock_helper.ps1",
        "dispatch_manifest.json",
        "--refresh-claim-status-report",
        "Invoke-ClaimStatusRefresh",
        "Start-Job",
        "Wait-EnvBundleClaimBatch",
        "Phase = 'auth-env'",
        "Phase = 'auth-login'",
        "$InnerTokenLoginCommand",
        "Missing env bundle values",
        "Placeholder env bundle values must be replaced before launch",
        "$PlaceholderEnv",
        "^<set-.+>$",
        "ExitCode",
        "$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId",
        "$env:TAMANDUA_AGENT_ID = $InnerAgentId",
        "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
    ]:
        if required_text not in launcher_text:
            return False
    lock_invocation = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerClaimLockHelperPath "
        "-ClaimId $InnerClaimId -AgentId $InnerAgentId"
    )
    lock_position = launcher_text.find(lock_invocation)
    claim_env_position = launcher_text.find("$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId")
    agent_env_position = launcher_text.find("$env:TAMANDUA_AGENT_ID = $InnerAgentId")
    script_position = launcher_text.find("powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerScriptPath")
    if (
        lock_position < 0
        or claim_env_position < 0
        or agent_env_position < 0
        or script_position < 0
        or claim_env_position > lock_position
        or agent_env_position > lock_position
        or lock_position > script_position
    ):
        return False
    if "Phase = 'lock'" not in launcher_text or "Phase = 'run'" not in launcher_text:
        return False
    try:
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    queue_json_path = normalize_artifact_ref(manifest.get("env_unblock_queue_json_path"))
    expected_env_bundle_ids: set[str] | None = None
    if queue_json_path:
        queue_json_full_path = ROOT / queue_json_path
        if not queue_json_full_path.exists():
            return False
        try:
            queue_payload = load_json(queue_json_full_path)
        except json.JSONDecodeError:
            return False
        expected_env_bundle_ids = {
            str(value) for value in queue_payload.get("ready_after_all_env_claim_ids") or [] if str(value)
        }
    env_bundle_ready_claims = []
    non_env_bundle_ready_claims = []
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        missing_env = [str(value) for value in claim.get("missing_effective_env") or [] if str(value)]
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or [] if str(value)}
        claim_id = str(claim.get("claim_id") or "")
        if expected_env_bundle_ids is not None:
            is_env_bundle_ready = claim_id in expected_env_bundle_ids
        else:
            is_env_bundle_ready = bool(missing_env and blocked_reasons <= {"missing_effective_env"})
        if is_env_bundle_ready:
            env_bundle_ready_claims.append(claim)
        else:
            non_env_bundle_ready_claims.append(claim)
    executable_lines = [
        line.strip()
        for line in launcher_text.splitlines()
        if line.strip().startswith("$EnvBundleClaimJobs += Start-EnvBundleClaimJob ")
    ]
    if len(executable_lines) != len(env_bundle_ready_claims):
        return False
    for claim in env_bundle_ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if not claim_id or not package_id or not script_path:
            return False
        if f"# Claim: {claim_id}" not in launcher_text:
            return False
        if f"# Package: {package_id}" not in launcher_text:
            return False
        if script_path not in launcher_text:
            return False
        resources = ", ".join(str(value) for value in claim.get("resource_tags") or []) or "-"
        if f"# Resources: {resources}" not in launcher_text:
            return False
        next_action = render_current_next_action_summary(claim.get("current_next_action"))
        if f"# Next action: {next_action}" not in launcher_text:
            return False
        current_next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        token_env = str(current_next_action.get("token_env") or "")
        token_login_command = str(current_next_action.get("token_login_command") or "")
        expected_invocation = (
            f"$EnvBundleClaimJobs += Start-EnvBundleClaimJob '{claim_id}' '{package_id}' '{script_path}' "
            f"'{token_env}' '{token_login_command}'"
        )
        if expected_invocation not in executable_lines:
            return False
    for claim in non_env_bundle_ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if claim_id and f"# Claim: {claim_id}" in launcher_text:
            return False
        if package_id and f"# Package: {package_id}" in launcher_text:
            return False
        for line in executable_lines:
            if (claim_id and claim_id in line) or (script_path and script_path in line):
                return False
    return True


def dispatch_archived_prelaunch_validation_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    prelaunch_path = normalize_artifact_ref(manifest.get("dispatch_prelaunch_validation_path"))
    if not prelaunch_path:
        return False
    prelaunch_full_path = ROOT / prelaunch_path
    if not prelaunch_full_path.exists():
        return False
    prelaunch_text = prelaunch_full_path.read_text(encoding="utf-8")
    expected_paths = [
        normalize_artifact_ref(manifest.get("agent_spawn_launcher_path")),
        normalize_artifact_ref(manifest.get("ready_claims_launcher_path")),
        normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path")),
        normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path")),
        normalize_artifact_ref(manifest.get("claim_lock_helper_path")),
    ]
    if not all(expected_paths):
        return False
    required_fragments = [
        "# Validation Dispatch Prelaunch Validation",
        "[switch]$ValidateEnvBundle",
        "$PrelaunchFailures = @()",
        "function Invoke-PrelaunchStep",
        "Invoke-PrelaunchStep 'agent spawn dry run'",
        str(expected_paths[0]),
        "-Provider', 'all', '-Phase', 'all', '-ShowBlocked'",
        "Invoke-PrelaunchStep 'ready claims sequential validate-only'",
        str(expected_paths[1]),
        "Invoke-PrelaunchStep 'ready claims parallel validate-only'",
        str(expected_paths[2]),
        "Invoke-PrelaunchStep 'claim lock list'",
        str(expected_paths[4]),
        "if ($ValidateEnvBundle)",
        "Invoke-PrelaunchStep 'env bundle validate-only'",
        str(expected_paths[3]),
        "env bundle validate-only skipped",
        "Dispatch prelaunch validation failed:",
        "Dispatch prelaunch validation passed.",
    ]
    return all(fragment in prelaunch_text for fragment in required_fragments)


def dispatch_archived_launcher_membership_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_text = ""
    launcher_waves: set[int] = set()
    for launcher_path in manifest.get("launcher_paths") or []:
        launcher_ref = normalize_artifact_ref(launcher_path)
        launcher_full_path = ROOT / launcher_ref
        if not launcher_ref or not launcher_full_path.exists():
            return False
        text = launcher_full_path.read_text(encoding="utf-8")
        if not all(
            marker in text
            for marker in [
                "TAMANDUA_WAVE_LAUNCHER_AGENT_ID",
                "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
                "$env:TAMANDUA_AGENT_ID = $AgentId",
                "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
            ]
        ):
            return False
        launcher_text += "\n" + text
        match = re.search(r"(?m)^# Wave: (\d+)\s*$", text)
        if match:
            launcher_waves.add(int(match.group(1)))

    selected_count = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        if not package.get("parallelizable_in_wave"):
            continue
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not script_path:
            return False
        selected = package.get("launcher_selected")
        in_launcher = script_path in launcher_text
        if selected is True:
            selected_count += 1
            if not in_launcher:
                return False
        elif selected is False:
            if in_launcher or not package.get("manual_reason"):
                return False
        else:
            return False
    return selected_count > 0


def dispatch_archived_manifest_launcher_decisions_are_replayable(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    packages = [package for package in manifest.get("packages") or [] if isinstance(package, dict)]
    if not packages:
        return False

    selected_count = 0
    waves = sorted({int(package.get("wave") or 0) for package in packages})
    for wave in waves:
        wave_packages = [
            package
            for package in packages
            if int(package.get("wave") or 0) == wave and package.get("parallelizable_in_wave")
        ]
        used_resources: set[str] = set()
        expected_selected: dict[str, bool] = {}
        expected_reason: dict[str, str | None] = {}
        ordered_packages = sorted(
            wave_packages,
            key=lambda package: (
                -int(package.get("impact_score") or 0),
                str(package.get("package_id") or ""),
            ),
        )
        for package in ordered_packages:
            package_id = str(package.get("package_id") or "")
            resources = {str(value) for value in package.get("resource_tags") or []}
            overlap = sorted(used_resources & resources)
            if overlap:
                expected_selected[package_id] = False
                expected_reason[package_id] = f"resource overlap: {', '.join(overlap)}"
                continue
            expected_selected[package_id] = True
            expected_reason[package_id] = None
            used_resources.update(resources)
        if sum(1 for value in expected_selected.values() if value is True) < 2:
            for package_id, value in list(expected_selected.items()):
                if value is True:
                    expected_selected[package_id] = False
                    expected_reason[package_id] = "parallel launcher not emitted: fewer than two non-overlapping packages"
        for package in ordered_packages:
            package_id = str(package.get("package_id") or "")
            if package.get("launcher_selected") is not expected_selected.get(package_id):
                return False
            if package.get("manual_reason") != expected_reason.get(package_id):
                return False
            if expected_selected.get(package_id) is True:
                selected_count += 1
                continue

    for package in packages:
        if package.get("parallelizable_in_wave"):
            continue
        if package.get("launcher_selected") is not None or package.get("manual_reason") is not None:
            return False
    return selected_count > 0


def dispatch_archived_launcher_manual_reasons_match_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_text = ""
    launcher_waves: set[int] = set()
    for launcher_path in manifest.get("launcher_paths") or []:
        launcher_ref = normalize_artifact_ref(launcher_path)
        launcher_full_path = ROOT / launcher_ref
        if not launcher_ref or not launcher_full_path.exists():
            return False
        text = launcher_full_path.read_text(encoding="utf-8")
        launcher_text += "\n" + text
        match = re.search(r"(?m)^# Wave: (\d+)\s*$", text)
        if match:
            launcher_waves.add(int(match.group(1)))
    if not launcher_text:
        return False
    if not launcher_waves:
        return False

    manual_count = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        if not package_id:
            return False
        manual_line = f"# - {package_id}: {package.get('manual_reason')}"
        if package.get("launcher_selected") is False:
            manual_reason = str(package.get("manual_reason") or "")
            if not manual_reason:
                return False
            wave = int(package.get("wave") or 0)
            if wave not in launcher_waves:
                manual_count += 1
                continue
            if (
                not manual_reason.startswith("parallel launcher not emitted:")
                and manual_line not in launcher_text
            ):
                return False
            manual_count += 1
        elif package.get("launcher_selected") is True:
            if f"# - {package_id}:" in launcher_text:
                return False
    return manual_count > 0


def dispatch_archived_launcher_selected_metadata_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_text = ""
    for launcher_path in manifest.get("launcher_paths") or []:
        launcher_ref = normalize_artifact_ref(launcher_path)
        launcher_full_path = ROOT / launcher_ref
        if not launcher_ref or not launcher_full_path.exists():
            return False
        launcher_text += "\n" + launcher_full_path.read_text(encoding="utf-8")
    if not launcher_text:
        return False

    selected_count = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        script_path = normalize_artifact_ref(package.get("script_path"))
        resources = ", ".join(str(value) for value in package.get("resource_tags") or [])
        if not package_id or not script_path:
            return False
        if package.get("launcher_selected") is True:
            expected_lines = [
                f"# Package: {package_id} resources={resources}",
                f"$jobs += Start-Job -Name '{package_id}'",
                f"-ArgumentList '{script_path}', 'claim-{package_id}', $script:ClaimLockHelperPath",
                "ClaimLockHelperPath",
                "Missing claim lock helper",
                "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
                "$env:TAMANDUA_AGENT_ID = $AgentId",
                "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
                "-File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId",
            ]
            for expected in expected_lines:
                if expected not in launcher_text:
                    return False
            selected_count += 1
        elif package.get("launcher_selected") is False:
            if f"$jobs += Start-Job -Name '{package_id}'" in launcher_text:
                return False
    return selected_count > 0


def dispatch_archived_staged_launcher_stage_membership_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    staged_paths = [normalize_artifact_ref(path) for path in manifest.get("staged_launcher_paths") or []]
    staged_packages = [
        package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("staged_launcher_selected") is True
    ]
    if not staged_paths:
        return not staged_packages
    if not staged_packages:
        return False

    observed: dict[str, dict[str, object]] = {}
    for staged_path in staged_paths:
        staged_full_path = ROOT / staged_path
        if not staged_path or not staged_full_path.exists():
            return False
        text = staged_full_path.read_text(encoding="utf-8")
        if not all(
            marker in text
            for marker in [
                "TAMANDUA_STAGED_LAUNCHER_AGENT_ID",
                "ClaimLockHelperPath",
                "Missing claim lock helper",
                "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
                "$env:TAMANDUA_AGENT_ID = $AgentId",
                "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
                "-File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId",
            ]
        ):
            return False
        wave_match = re.search(r"(?m)^# Wave: (\d+)\s*$", text)
        if not wave_match:
            return False
        current_stage: int | None = None
        current_package: str | None = None
        for line in text.splitlines():
            stage_match = re.match(r"# Stage (\d+)$", line)
            if stage_match:
                current_stage = int(stage_match.group(1))
                current_package = None
                continue
            package_match = re.match(r"# Package: ([^ ]+) resources=(.*)$", line)
            if package_match:
                if current_stage is None:
                    return False
                current_package = package_match.group(1)
                if current_package in observed:
                    return False
                observed[current_package] = {
                    "stage": current_stage,
                    "resources": package_match.group(2),
                    "path": staged_path,
                    "has_start_job": False,
                    "has_argument": False,
                }
                continue
            if current_package and f"$jobs += Start-Job -Name '{current_package}'" in line:
                observed[current_package]["has_start_job"] = True
            if current_package and " -ArgumentList '" in line:
                observed[current_package]["has_argument"] = True

    staged_by_id = {str(package.get("package_id") or ""): package for package in staged_packages}
    if set(observed) != set(staged_by_id):
        return False
    for package_id, package in staged_by_id.items():
        staged = observed.get(package_id) or {}
        if staged.get("stage") != package.get("staged_stage"):
            return False
        resources = ", ".join(str(value) for value in package.get("resource_tags") or [])
        if staged.get("resources") != resources:
            return False
        if not staged.get("has_start_job") or not staged.get("has_argument"):
            return False
        launcher_wave = re.search(r"/wave-(\d+)-staged-launcher\.ps1$", str(staged.get("path") or "").replace("\\", "/"))
        if launcher_wave and int(launcher_wave.group(1)) != int(package.get("wave") or 0):
            return False
    return True


def dispatch_archived_manifest_source_matches_artifact(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if not manifest_path or not source_preflight:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    return normalize_artifact_ref(manifest.get("source_preflight")) == source_preflight


def dispatch_archived_manifest_packages_match_artifact(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    manifest_packages = {
        str(package.get("package_id")): package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    }
    artifact_packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not manifest_packages or len(manifest_packages) != len(artifact_packages):
        return False
    for package in artifact_packages:
        package_id = str(package.get("package_id"))
        manifest_package = manifest_packages.get(package_id)
        if not manifest_package:
            return False
        for key in ("wave", "launcher_selected", "manual_reason", "staged_launcher_selected", "staged_stage"):
            if manifest_package.get(key) != package.get(key):
                return False
        for key in ("resource_tags", "required_env"):
            if [str(value) for value in manifest_package.get(key) or []] != [
                str(value) for value in package.get(key) or []
            ]:
                return False
    return True


def dispatch_archived_manifest_handoff_notes_are_actionable(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    packages = [package for package in manifest.get("packages") or [] if isinstance(package, dict)]
    if not packages:
        return False
    for package in packages:
        notes = [str(value) for value in package.get("handoff_notes") or []]
        if not notes:
            return False
        if package.get("parallelizable_in_wave"):
            if "parallelizable" not in notes:
                return False
        elif "parallelizable_in_wave" in package and "serial-only" not in notes:
            return False
        launcher_selected = package.get("launcher_selected")
        manual_reason = package.get("manual_reason")
        if launcher_selected is True and "parallel-launcher:auto" not in notes:
            return False
        if launcher_selected is False and manual_reason:
            if f"parallel-launcher:manual:{manual_reason}" not in notes:
                return False
        staged_stage = package.get("staged_stage")
        if staged_stage is not None and f"staged-launcher:stage-{staged_stage}" not in notes:
            return False
        depends_on_waves = [str(value) for value in package.get("depends_on_waves") or []]
        if depends_on_waves and "depends-on-waves:" + ",".join(depends_on_waves) not in notes:
            return False
        effective_env = {str(value) for value in package.get("effective_required_env") or []}
        env_notes = [note for note in notes if note.startswith("env-blocked:")]
        for env_note in env_notes:
            env_values = [value for value in env_note.removeprefix("env-blocked:").split(",") if value]
            if not env_values or not set(env_values).issubset(effective_env):
                return False

    brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    if brief_path:
        brief_full_path = ROOT / brief_path
        if not brief_full_path.exists():
            return False
        brief = brief_full_path.read_text(encoding="utf-8")
        if "Handoff notes" not in brief:
            return False
        for package in packages:
            for note in package.get("handoff_notes") or []:
                if f"`{note}`" not in brief:
                    return False
    return True


def dispatch_archived_brief_recommended_launch_sequence_matches_manifest(
    dispatch_artifact: dict[str, Any],
) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    agent_spawn_launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    ready_parallel_path = normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path"))
    env_queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    env_bundle_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    prelaunch_path = normalize_artifact_ref(manifest.get("dispatch_prelaunch_validation_path"))
    required_paths = [brief_path, agent_spawn_launcher_path, ready_parallel_path, env_queue_path, env_bundle_path, prelaunch_path]
    if not all(required_paths):
        return False
    brief_full_path = ROOT / str(brief_path)
    if not brief_full_path.exists():
        return False
    brief = brief_full_path.read_text(encoding="utf-8")
    section_start = brief.find("## Recommended Launch Sequence")
    if section_start < 0:
        return False
    next_section = brief.find("\n## ", section_start + len("## Recommended Launch Sequence"))
    launch_sequence = brief[section_start:] if next_section < 0 else brief[section_start:next_section]
    expected_fragments = [
        "## Recommended Launch Sequence",
        "1. Dispatch prelaunch validation:",
        f"-File '{prelaunch_path}'",
        "This runs no-execution checks",
        "Wrapped agent spawn dry run:",
        f"-File '{agent_spawn_launcher_path}'",
        "-Provider all -Phase all -ShowBlocked",
        "This prints Codex/Claude spawn commands",
        "1a. Optional Codex parallel agent execution:",
        "TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'",
        "-Provider codex -Phase ready -Execute -Parallel",
        "1b. Optional Claude parallel agent execution:",
        "-Provider claude -Phase ready -Execute -Parallel",
        "1c. Optional env-bundle prelaunch validation after env fill:",
        f"-File '{prelaunch_path}' -ValidateEnvBundle",
        "Use one provider per claim",
        "Duplicate-provider execution requires both `-AllowDuplicateProviderPerClaim`",
        "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1",
        "[duplicate-provider-override]",
        "2. Ready package claims:",
        "$env:TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH = '1'",
        f"-File '{ready_parallel_path}'",
        f"-File '{ready_parallel_path}' -ValidateOnly",
        "This launcher runs package scripts directly",
        "3. Fill env bundle:",
        str(env_queue_path),
        "4. Post-env-bundle package claims:",
        "$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
        f"-File '{env_bundle_path}'",
        f"-File '{env_bundle_path}' -ValidateOnly",
        "5. Refresh claim status:",
        "--refresh-claim-status-report",
        str(manifest_path),
    ]
    positions = []
    for fragment in expected_fragments:
        position = launch_sequence.find(fragment)
        if position < 0:
            return False
        positions.append(position)
    if positions != sorted(positions):
        return False

    staged_paths = [normalize_artifact_ref(path) for path in manifest.get("staged_launcher_paths") or []]
    staged_by_wave: dict[int, str] = {}
    for path in staged_paths:
        if not path:
            continue
        name_parts = Path(path).name.split("-")
        if len(name_parts) < 3 or name_parts[0] != "wave":
            continue
        try:
            staged_by_wave[int(name_parts[1])] = str(path)
        except ValueError:
            continue
    packages = manifest.get("packages") or []
    wave3_scripts = [
        normalize_artifact_ref(package.get("script_path"))
        for package in packages
        if int(package.get("wave") or 0) == 3
    ]
    if not (staged_by_wave.get(1) and staged_by_wave.get(2) and wave3_scripts):
        return True
    continuation_start = brief.find("## Dependency-Gated Continuation")
    if continuation_start < 0:
        return False
    next_section = brief.find("\n## ", continuation_start + len("## Dependency-Gated Continuation"))
    continuation = brief[continuation_start:] if next_section < 0 else brief[continuation_start:next_section]
    continuation_fragments = [
        "## Dependency-Gated Continuation",
        "Run this after the recommended launch sequence and claim-status refresh",
        "Wave 1 staged continuation:",
        staged_by_wave.get(1, ""),
        "Wave 2 staged continuation:",
        "$env:TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH = '1'",
        staged_by_wave.get(2, ""),
        "Requires waves `1` evidence to be green before launch.",
        "Wave 3 closure handoff:",
        str(wave3_scripts[0] or "") if wave3_scripts else "",
        "Requires waves `1`, `2` evidence to be green before launch.",
    ]
    continuation_positions = []
    for fragment in continuation_fragments:
        if not fragment:
            return False
        position = continuation.find(fragment)
        if position < 0:
            return False
        continuation_positions.append(position)
    return continuation_positions == sorted(continuation_positions)


def prompt_list(values: Any) -> str:
    items = [str(value) for value in values or []]
    return ", ".join(items) if items else "-"


def dispatch_archived_prompts_match_manifest_metadata(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if not manifest_path or not source_preflight:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    claim_lock_helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if not claim_lock_helper_path:
        return False

    checked_prompts = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        prompt_path = normalize_artifact_ref(package.get("prompt_path"))
        script_path = normalize_artifact_ref(package.get("script_path"))
        status_path = normalize_artifact_ref(package.get("status_path"))
        if not package_id or not prompt_path or not script_path or not status_path:
            return False
        prompt_full_path = ROOT / prompt_path
        if not prompt_full_path.exists():
            return False
        prompt_text = prompt_full_path.read_text(encoding="utf-8")
        expected_lines = [
            f"# {package_id}",
            f"Claim ID: claim-{package_id}",
            f"Title: {package.get('title') or ''}",
            f"Wave: {int(package.get('wave') or 0)}",
            f"Owner role: {package.get('recommended_owner_role') or ''}",
            f"Roadmaps: {prompt_list(package.get('roadmaps'))}",
            f"Required env: {prompt_list(package.get('required_env'))}",
            f"Depends on waves: {prompt_list(package.get('depends_on_waves'))}",
            f"Resource tags: {prompt_list(package.get('resource_tags'))}",
            f"Blocking profiles: {prompt_list(package.get('blocking_profiles'))}",
            f"Source preflight: {source_preflight}",
            f"Script: {script_path}",
            f"Status path: {status_path}",
            f"Claim lock helper: {claim_lock_helper_path}",
            (
                "Claim lock command: powershell -NoProfile -ExecutionPolicy Bypass "
                f"-File '{claim_lock_helper_path}' -ClaimId claim-{package_id} -AgentId <agent-id>"
            ),
            f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_path}'",
        ]
        contract = package.get("claim_output_contract") or {}
        if not isinstance(contract, dict):
            return False
        expected_lines.append(f"Expected JSON profiles: {prompt_list(contract.get('required_json_profile_ids'))}")
        expected_lines.append(
            f"Status JSON required fields: {prompt_list(contract.get('status_required_fields'))}"
        )
        expected_lines.append(
            f"Status JSON allowed status values: {prompt_list(contract.get('status_allowed_values'))}"
        )
        status_full_path = ROOT / status_path
        if status_full_path.exists():
            try:
                status_payload = load_json(status_full_path)
            except json.JSONDecodeError:
                return False
            current_artifacts = [normalize_artifact_ref(value) for value in status_payload.get("artifacts") or []]
            current_missing_profiles = [str(value) for value in status_payload.get("missing_profiles") or []]
            current_exit_code = status_payload.get("exit_code")
            expected_lines.extend(
                [
                    f"Current status: {str(status_payload.get('status') or 'not_run')}",
                    f"Current exit code: {current_exit_code if current_exit_code is not None else '-'}",
                    f"Current artifacts: {prompt_list(current_artifacts)}",
                    f"Current missing profiles: {prompt_list(current_missing_profiles)}",
                ]
            )
        else:
            expected_lines.extend(
                [
                    "Current status: not_run",
                    "Current exit code: -",
                    "Current artifacts: -",
                    "Current missing profiles: -",
                ]
            )
        current_next_action = {}
        if status_full_path.exists():
            try:
                status_payload = load_json(status_full_path)
            except json.JSONDecodeError:
                status_payload = {}
            artifacts = [normalize_artifact_ref(value) for value in status_payload.get("artifacts") or []]
            for artifact in reversed([value for value in artifacts if value.endswith(".json")]):
                artifact_path = ROOT / artifact
                if not artifact_path.exists():
                    continue
                try:
                    artifact_payload = load_json(artifact_path)
                except json.JSONDecodeError:
                    continue
                action = find_first_nested_dict(artifact_payload, "next_action")
                if action:
                    current_next_action = action
                    break
        if not current_next_action and isinstance(package.get("current_next_action"), dict):
            current_next_action = package.get("current_next_action") or {}
        current_next_action_env = [str(value) for value in current_next_action.get("required_env") or [] if str(value)]
        token_env = str(current_next_action.get("token_env") or "")
        if token_env and token_env not in current_next_action_env:
            current_next_action_env.append(token_env)
        expected_next_action_env = []
        for value in [str(value) for value in package.get("next_action_required_env") or []] + current_next_action_env:
            if value and value not in expected_next_action_env:
                expected_next_action_env.append(value)
        expected_effective_env = []
        for value in [str(value) for value in package.get("effective_required_env") or []] + current_next_action_env:
            if value and value not in expected_effective_env:
                expected_effective_env.append(value)
        static_next_action_env_line = f"Next-action env: {prompt_list(package.get('next_action_required_env'))}"
        current_next_action_env_line = f"Next-action env: {prompt_list(expected_next_action_env)}"
        static_effective_env_line = f"Effective env checklist: {prompt_list(package.get('effective_required_env'))}"
        current_effective_env_line = f"Effective env checklist: {prompt_list(expected_effective_env)}"
        for expected in expected_lines:
            if expected not in prompt_text:
                return False
        if "Next-action env:" not in prompt_text:
            return False
        if "Effective env checklist:" not in prompt_text:
            return False
        checked_prompts += 1
    return checked_prompts > 0


def dispatch_archived_agent_roster_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False

    roster_path = normalize_artifact_ref(manifest.get("agent_roster_path"))
    if not roster_path:
        return False
    roster_full_path = ROOT / roster_path
    if not roster_full_path.exists():
        return False
    roster_text = roster_full_path.read_text(encoding="utf-8")
    if "# Validation Agent Roster" not in roster_text:
        return False
    expected_header = (
        "| Wave | Package | Owner | Launcher | Resources | Required env | "
        "Next-action env | Depends | Script | Prompt | Status | Output contract |"
    )
    if expected_header not in roster_text.splitlines():
        return False

    roster_rows: dict[str, list[str]] = {}
    for line in roster_text.splitlines():
        if not line.startswith("|") or "`" not in line:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 12:
            continue
        cells = ["-" if cell == "`-`" else cell for cell in cells]
        package_id = cells[1].strip("`")
        if not package_id or package_id in roster_rows:
            return False
        roster_rows[package_id] = cells

    manifest_packages = [
        package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    manifest_ids = {str(package.get("package_id")) for package in manifest_packages}
    if set(roster_rows) != manifest_ids:
        return False

    for package in manifest_packages:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        if not package_id:
            return False
        selected = package.get("launcher_selected")
        selected_text = "-" if selected is None else ("auto" if selected else f"manual: {package.get('manual_reason')}")
        def roster_code_list(values: Any) -> str:
            items = [str(value) for value in values or []]
            return ", ".join(f"`{value}`" for value in items) if items else "-"

        script_path = normalize_artifact_ref(package.get("script_path"))
        prompt_path = normalize_artifact_ref(package.get("prompt_path")) or "-"
        status_path = normalize_artifact_ref(package.get("status_path"))
        contract = package.get("claim_output_contract") or {}
        if not isinstance(contract, dict):
            return False
        expected_cells = [
            str(int(package.get("wave") or 0)),
            f"`{package_id}`",
            str(package.get("recommended_owner_role") or "-"),
            selected_text,
            roster_code_list(package.get("resource_tags")),
            roster_code_list(package.get("required_env")),
            roster_code_list(package.get("next_action_required_env")),
            roster_code_list(package.get("depends_on_waves")),
            f"`{script_path}`",
            f"`{prompt_path}`",
            f"`{status_path}`",
            roster_code_list(contract.get("required_json_profile_ids")),
        ]
        if not script_path or not status_path:
            return False
        if roster_rows.get(package_id) != expected_cells:
            return False
    return bool(manifest_packages)


def dispatch_archived_current_action_env_guards_match_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False

    template_path = normalize_artifact_ref(manifest.get("env_template_path"))
    roster_path = normalize_artifact_ref(manifest.get("agent_roster_path"))
    if not template_path or not roster_path:
        return False
    template_full_path = ROOT / template_path
    roster_full_path = ROOT / roster_path
    if not template_full_path.exists() or not roster_full_path.exists():
        return False
    template_text = template_full_path.read_text(encoding="utf-8")
    roster_text = roster_full_path.read_text(encoding="utf-8")

    checked = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not package_id or not script_path:
            return False
        env_names = []
        current_action = package.get("current_next_action") if isinstance(package.get("current_next_action"), dict) else {}
        for value in current_action.get("required_env") or []:
            env_name = str(value)
            if env_name and env_name not in env_names:
                env_names.append(env_name)
        token_env = str(current_action.get("token_env") or "")
        if token_env and token_env not in env_names:
            env_names.append(token_env)
        for value in package.get("current_next_action_required_env") or []:
            env_name = str(value)
            if env_name and env_name not in env_names:
                env_names.append(env_name)
        if not env_names:
            continue

        script_full_path = ROOT / script_path
        if not script_full_path.exists():
            return False
        script_text = script_full_path.read_text(encoding="utf-8")
        checked += 1
        for env_name in env_names:
            if f"$env:{env_name} = '{env_template_placeholder(env_name)}'" not in template_text:
                return False
            if f"`{env_name}`" not in roster_text:
                return False
            if f"'{env_name}'" not in script_text:
                return False
            if "$RequiredEnv" not in script_text or "Missing effective env for package" not in script_text:
                return False
    return checked > 0


def dispatch_archived_manifest_matches_source_preflight_packages(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if not manifest_path or not source_preflight:
        return False
    manifest_full_path = ROOT / manifest_path
    preflight_full_path = ROOT / source_preflight
    if not manifest_full_path.exists() or not preflight_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
        preflight = load_json(preflight_full_path)
    except json.JSONDecodeError:
        return False

    manifest_packages = [
        package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not manifest_packages:
        return False
    manifest_waves = sorted({int(package.get("wave") or 0) for package in manifest_packages})
    expected_waves = sorted(int(value) for value in manifest.get("expected_waves") or [])
    if expected_waves and expected_waves != manifest_waves:
        return False
    expected_package_ids = sorted(str(value) for value in manifest.get("expected_package_ids") or [])
    if expected_package_ids and expected_package_ids != sorted(str(package.get("package_id")) for package in manifest_packages):
        return False
    selection_mode = str(manifest.get("selection_mode") or "")
    if selection_mode == "all":
        allowed_waves = sorted(
            {
                int(package.get("wave") or 0)
                for package in preflight.get("parallel_work_packages") or []
                if isinstance(package, dict) and package.get("package_id")
            }
        )
    elif selection_mode == "wave":
        try:
            selected_wave = int(manifest.get("selected_wave"))
        except (TypeError, ValueError):
            return False
        allowed_waves = [selected_wave]
        if manifest_waves != allowed_waves:
            return False
    else:
        allowed_waves = manifest_waves
    source_packages = [
        package
        for package in preflight.get("parallel_work_packages") or []
        if isinstance(package, dict)
        and package.get("package_id")
        and int(package.get("wave") or 0) in allowed_waves
    ]
    source_by_id = {str(package.get("package_id")): package for package in source_packages}
    manifest_by_id = {str(package.get("package_id")): package for package in manifest_packages}
    if set(source_by_id) != set(manifest_by_id):
        return False

    for package_id, manifest_package in manifest_by_id.items():
        source_package = source_by_id[package_id]
        scalar_fields = (
            "title",
            "wave",
            "recommended_owner_role",
            "parallelizable_in_wave",
            "continue_on_failure",
        )
        for field_name in scalar_fields:
            if manifest_package.get(field_name) != source_package.get(field_name):
                return False
        list_fields = (
            "blocked_run_classes",
            "blocking_profiles",
            "depends_on_waves",
            "expected_profile_ids",
            "manual_prerequisites",
            "required_env",
            "roadmaps",
        )
        for field_name in list_fields:
            if [str(value) for value in manifest_package.get(field_name) or []] != [
                str(value) for value in source_package.get(field_name) or []
            ]:
                return False
        action_fields = ("roadmap", "roadmap_status", "blocking_profiles", "required_env", "action")
        source_actions = [
            {
                field: (
                    [str(value) for value in item.get(field) or []]
                    if field in {"blocking_profiles", "required_env"}
                    else str(item.get(field) or "")
                )
                for field in action_fields
            }
            for item in source_package.get("roadmap_next_actions") or []
            if isinstance(item, dict)
        ]
        manifest_actions = [
            {
                field: (
                    [str(value) for value in item.get(field) or []]
                    if field in {"blocking_profiles", "required_env"}
                    else str(item.get(field) or "")
                )
                for field in action_fields
            }
            for item in manifest_package.get("roadmap_next_actions") or []
            if isinstance(item, dict)
        ]
        if manifest_actions != source_actions:
            return False
        source_inputs = [
            {
                "name": str(item.get("name") or ""),
                "flag": str(item.get("flag") or ""),
                "env": str(item.get("env") or ""),
                "description": str(item.get("description") or ""),
            }
            for item in source_package.get("operator_inputs") or []
            if isinstance(item, dict)
        ]
        manifest_inputs = [
            {
                "name": str(item.get("name") or ""),
                "flag": str(item.get("flag") or ""),
                "env": str(item.get("env") or ""),
                "description": str(item.get("description") or ""),
            }
            for item in manifest_package.get("operator_inputs") or []
            if isinstance(item, dict)
        ]
        if manifest_inputs != source_inputs:
            return False
        if [str(value) for value in manifest_package.get("safe_commands") or []] != [
            str(value) for value in source_package.get("safe_commands") or []
        ]:
            return False
        status_path = normalize_artifact_ref(manifest_package.get("status_path"))
        output_dir = normalize_artifact_ref(manifest_package.get("output_dir"))
        if not status_path or not output_dir or not status_path.endswith("/agent_status.json"):
            return False
        if status_path != f"{output_dir}/agent_status.json":
            return False
        contract = manifest_package.get("claim_output_contract") or {}
        if not isinstance(contract, dict):
            return False
        if str(contract.get("status_file") or "") != "agent_status.json":
            return False
        if str(contract.get("output_dir") or "") != "package output directory":
            return False
        if [str(value) for value in contract.get("status_required_fields") or []] != [
            "package_id",
            "claim_id",
            "agent_id",
            "status",
            "artifacts",
            "blocker_cleared",
            "notes",
            "exit_code",
            "expected_profiles",
            "missing_profiles",
        ]:
            return False
        if [str(value) for value in contract.get("status_allowed_values") or []] != [
            "pass",
            "fail",
            "blocked",
        ]:
            return False
        if [str(value) for value in contract.get("required_json_profile_ids") or []] != [
            str(value) for value in source_package.get("expected_profile_ids") or []
        ]:
            return False
    return True


def preflight_package_required_env(preflight_artifact: dict[str, Any]) -> dict[str, list[str]]:
    packages = preflight_artifact.get("parallel_work_packages") or []
    return {
        str(package.get("package_id")): [str(value) for value in package.get("required_env") or []]
        for package in packages
        if isinstance(package, dict) and package.get("package_id")
    }


def dispatch_archived_handoff_scripts_match_source_commands(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if not manifest_path or not source_preflight:
        return False
    manifest_full_path = ROOT / manifest_path
    preflight_full_path = ROOT / source_preflight
    if not manifest_full_path.exists() or not preflight_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
        preflight = load_json(preflight_full_path)
    except json.JSONDecodeError:
        return False

    source_by_id = {
        str(package.get("package_id")): package
        for package in preflight.get("parallel_work_packages") or []
        if isinstance(package, dict) and package.get("package_id")
    }
    checked = 0
    for manifest_package in manifest.get("packages") or []:
        if not isinstance(manifest_package, dict) or not manifest_package.get("package_id"):
            continue
        package_id = str(manifest_package.get("package_id"))
        source_package = source_by_id.get(package_id)
        script_path = normalize_artifact_ref(manifest_package.get("script_path"))
        if not source_package or not script_path:
            return False
        script_full_path = ROOT / script_path
        if not script_full_path.exists():
            return False
        script_text = script_full_path.read_text(encoding="utf-8")
        source_commands = [
            str(command).strip()
            for command in source_package.get("safe_commands") or []
            if str(command).strip() and not str(command).strip().startswith("$Out = ")
        ]
        if not source_commands:
            return False
        for command in source_commands:
            if command not in script_text:
                return False
        checked += 1
    return checked > 0


def dispatch_package_summaries_match_artifacts(dispatch_artifact: dict[str, Any]) -> bool:
    packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not packages:
        return False
    checked = 0
    for package in packages:
        artifact_path = normalize_artifact_ref(package.get("artifact_path"))
        if not artifact_path:
            package_status = str(package.get("status") or "")
            package_failures = [str(value) for value in package.get("failures") or []]
            if package_status != "missing" and not (
                package_status in {"blocked", "invalid"} and "missing_package_artifact" in package_failures
            ):
                return False
            if "missing_expected_profile_artifact" not in package_failures:
                return False
            checked += 1
            continue
        full_path = ROOT / artifact_path
        if not full_path.exists():
            return False
        try:
            package_artifact = load_json(full_path)
        except json.JSONDecodeError:
            return False
        quality_gate = package_artifact.get("quality_gate") if isinstance(package_artifact.get("quality_gate"), dict) else {}
        profile_id = str(package_artifact.get("profile_id") or package_artifact.get("profile") or "")
        run_id = str(package_artifact.get("run_id") or full_path.stem)
        status = str(quality_gate.get("status") or ("pass" if quality_gate.get("passed") else "fail"))
        blocking_gaps = [str(value) for value in quality_gate.get("blocking_gaps") or []]
        failures = [str(value) for value in quality_gate.get("failures") or []]
        if profile_id != str(package.get("profile_id") or ""):
            return False
        if run_id != str(package.get("run_id") or ""):
            return False
        if str(package.get("status") or "") == "missing":
            package_failures = [str(value) for value in package.get("failures") or []]
            if "missing_expected_profile_artifact" not in package_failures:
                return False
            continue
        if status != str(package.get("status") or ""):
            return False
        if bool(quality_gate.get("passed")) != bool(package.get("passed")):
            return False
        if blocking_gaps != [str(value) for value in package.get("blocking_gaps") or []]:
            return False
        package_failures = [str(value) for value in package.get("failures") or []]
        if not set(failures).issubset(set(package_failures)):
            return False
        checked += 1
    return checked == len(packages)


def dispatch_package_summaries_reject_unexpected_profile_artifacts(dispatch_artifact: dict[str, Any]) -> bool:
    checked = 0
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        expected_profiles = [str(value) for value in package.get("expected_profile_ids") or []]
        artifact_paths = [normalize_artifact_ref(path) for path in package.get("artifact_paths") or []]
        if not expected_profiles:
            continue
        if not artifact_paths:
            if [str(value) for value in package.get("unexpected_profile_ids") or []]:
                return False
            checked += 1
            continue
        expected_set = set(expected_profiles)
        unexpected_profiles = []
        for artifact_path in artifact_paths:
            full_path = ROOT / artifact_path
            if not full_path.exists():
                return False
            try:
                payload = load_json(full_path)
            except json.JSONDecodeError:
                return False
            profile_id = str(payload.get("profile_id") or payload.get("profile") or "")
            if profile_id and profile_id not in expected_set:
                unexpected_profiles.append(profile_id)
        recorded_unexpected = [str(value) for value in package.get("unexpected_profile_ids") or []]
        if unexpected_profiles != recorded_unexpected:
            return False
        if unexpected_profiles:
            failures = [str(value) for value in package.get("failures") or []]
            if package.get("passed") is not False or "unexpected_profile_artifact" not in failures:
                return False
        checked += 1
    return checked > 0


def dispatch_package_archived_artifacts_include_companions(dispatch_artifact: dict[str, Any]) -> bool:
    packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not packages:
        return False
    checked = 0
    for package in packages:
        artifact_path = normalize_artifact_ref(package.get("artifact_path"))
        if not artifact_path:
            status = str(package.get("status") or "")
            failures = {str(value) for value in package.get("failures") or []}
            if status != "missing" and not (
                status in {"blocked", "invalid"} and "missing_package_artifact" in failures
            ):
                return False
            checked += 1
            continue
        full_path = ROOT / artifact_path
        if not full_path.exists() or full_path.suffix != ".json":
            return False
        archived = {normalize_artifact_ref(path) for path in package.get("archived_artifacts") or []}
        if artifact_path not in archived:
            return False
        expected_existing = {artifact_path}
        for suffix in (".md", ".comparison.json"):
            companion = full_path.with_suffix(suffix)
            if companion.exists():
                expected_existing.add(rel(companion))
        if not expected_existing.issubset(archived):
            return False
        for archived_path in archived:
            archived_full_path = ROOT / archived_path
            if not archived_path.startswith(str(Path(artifact_path).parent).replace("\\", "/")):
                return False
            if not archived_full_path.exists():
                return False
        checked += 1
    return checked > 0


def dispatch_tests_match_package_summaries(dispatch_artifact: dict[str, Any]) -> bool:
    packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    tests = [
        test
        for test in dispatch_artifact.get("tests") or []
        if isinstance(test, dict) and str(test.get("id") or "").startswith("dispatch-package-")
    ]
    if not packages or len(packages) != len(tests):
        return False
    tests_by_package: dict[str, dict[str, Any]] = {}
    for test in tests:
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        package_id = str(evidence.get("package_id") or "")
        if not package_id or package_id in tests_by_package:
            return False
        if test.get("id") != f"dispatch-package-{package_id}":
            return False
        tests_by_package[package_id] = test

    for package in packages:
        package_id = str(package.get("package_id") or "")
        test = tests_by_package.get(package_id)
        if not test:
            return False
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        for key in ("artifact_path", "profile_id", "run_id", "status"):
            if normalize_artifact_ref(evidence.get(key)) != normalize_artifact_ref(package.get(key)):
                return False
        first_gap = package.get("first_gap") if isinstance(package.get("first_gap"), dict) else None
        evidence_first_gap = evidence.get("first_gap") if isinstance(evidence.get("first_gap"), dict) else None
        if first_gap != evidence_first_gap:
            return False
        expected_status = "covered" if package.get("passed") else "missed"
        expected_gap_category = None if package.get("passed") else "dispatch-results"
        if test.get("status") != expected_status:
            return False
        if test.get("gap_category") != expected_gap_category:
            return False
    return True


def dispatch_summary_and_gate_match_packages(dispatch_artifact: dict[str, Any]) -> bool:
    packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not packages:
        return False
    passed_ids = [str(package.get("package_id")) for package in packages if package.get("passed")]
    failed_ids = [str(package.get("package_id")) for package in packages if not package.get("passed")]
    summary = dispatch_artifact.get("summary") if isinstance(dispatch_artifact.get("summary"), dict) else {}
    category = summary.get("category_coverage") if isinstance(summary.get("category_coverage"), dict) else {}
    dispatch_category = (
        category.get("validation_dispatch_results")
        if isinstance(category.get("validation_dispatch_results"), dict)
        else {}
    )
    quality_gate = (
        dispatch_artifact.get("quality_gate") if isinstance(dispatch_artifact.get("quality_gate"), dict) else {}
    )

    try:
        passed_count = int(dispatch_artifact.get("passed_count"))
        failed_count = int(dispatch_artifact.get("failed_count"))
    except (TypeError, ValueError):
        return False
    if passed_count != len(passed_ids) or failed_count != len(failed_ids):
        return False
    expected_status_counts = {
        "pass": 0,
        "fail": 0,
        "blocked": 0,
        "missing": 0,
        "invalid": 0,
        "unknown": 0,
    }
    for package in packages:
        status = str(package.get("status") or "").strip().lower()
        if status not in expected_status_counts:
            status = "unknown"
        expected_status_counts[status] += 1
    status_counts = (
        dispatch_artifact.get("status_counts")
        if isinstance(dispatch_artifact.get("status_counts"), dict)
        else {}
    )
    for key, expected in expected_status_counts.items():
        if int(status_counts.get(key) or 0) != expected:
            return False
    expected_status_totals = {
        "blocked_count": expected_status_counts["blocked"],
        "failed_status_count": expected_status_counts["fail"],
        "missing_count": expected_status_counts["missing"],
        "invalid_count": expected_status_counts["invalid"],
    }
    for key, expected in expected_status_totals.items():
        if int(dispatch_artifact.get(key) or 0) != expected:
            return False
    expected_missing_env = sorted(
        {
            str(value)
            for package in packages
            for value in package.get("agent_missing_required_env") or []
        }
    )
    if sorted(str(value) for value in dispatch_artifact.get("missing_required_env") or []) != expected_missing_env:
        return False
    expected_env_blockers = [
        {
            "package_id": package.get("package_id"),
            "wave": package.get("wave"),
            "title": package.get("title"),
            "recommended_owner_role": package.get("recommended_owner_role"),
            "status": package.get("status"),
            "roadmaps": [str(value) for value in package.get("roadmaps") or []],
            "blocking_profiles": [str(value) for value in package.get("blocking_profiles") or []],
            "blocked_run_classes": [str(value) for value in package.get("blocked_run_classes") or []],
            "missing_required_env": [str(value) for value in package.get("agent_missing_required_env") or []],
            "declared_required_env": [
                str(value)
                for value in package.get("effective_required_env") or package.get("required_env") or []
            ],
        }
        for package in packages
        if package.get("agent_missing_required_env")
    ]
    if dispatch_artifact.get("required_env_blockers") != expected_env_blockers:
        return False
    expected_owner_handoff: dict[str, dict[str, Any]] = {}
    for package in packages:
        owner = str(package.get("recommended_owner_role") or "unassigned")
        entry = expected_owner_handoff.setdefault(
            owner,
            {
                "owner": owner,
                "package_count": 0,
                "passed_count": 0,
                "blocked_count": 0,
                "failed_status_count": 0,
                "missing_count": 0,
                "invalid_count": 0,
                "packages": [],
                "missing_required_env": [],
                "roadmaps": [],
            },
        )
        status = str(package.get("status") or "").strip().lower()
        entry["package_count"] += 1
        if bool(package.get("passed")):
            entry["passed_count"] += 1
        if status == "blocked":
            entry["blocked_count"] += 1
        elif status == "fail":
            entry["failed_status_count"] += 1
        elif status == "missing":
            entry["missing_count"] += 1
        elif status == "invalid":
            entry["invalid_count"] += 1
        entry["packages"].append(
            {
                "package_id": package.get("package_id"),
                "wave": package.get("wave"),
                "status": package.get("status"),
                "title": package.get("title"),
                "parallelizable_in_wave": package.get("parallelizable_in_wave"),
                "depends_on_waves": package.get("depends_on_waves") or [],
                "handoff_notes": package.get("handoff_notes") or [],
            }
        )
        for env_name in package.get("agent_missing_required_env") or []:
            value = str(env_name)
            if value not in entry["missing_required_env"]:
                entry["missing_required_env"].append(value)
        for roadmap in package.get("roadmaps") or []:
            value = str(roadmap)
            if value not in entry["roadmaps"]:
                entry["roadmaps"].append(value)
    expected_owner_handoff_list = []
    for entry in expected_owner_handoff.values():
        entry["missing_required_env"] = sorted(entry["missing_required_env"])
        entry["roadmaps"] = sorted(entry["roadmaps"])
        expected_owner_handoff_list.append(entry)
    expected_owner_handoff_list = sorted(expected_owner_handoff_list, key=lambda item: item["owner"])
    if dispatch_artifact.get("owner_handoff") != expected_owner_handoff_list:
        return False
    expected_summary = {
        "covered": len(passed_ids),
        "missed": len(failed_ids),
        "tests": len(packages),
        "total": len(packages),
        "partial": 0,
        "planned": 0,
        "skipped": 0,
        "execution_failed": 0,
    }
    for key, expected in expected_summary.items():
        if int(summary.get(key) or 0) != expected:
            return False
    if int(dispatch_category.get("covered") or 0) != len(passed_ids):
        return False
    if int(dispatch_category.get("missed") or 0) != len(failed_ids):
        return False
    expected_gate_passed = not failed_ids
    if bool(quality_gate.get("passed")) != expected_gate_passed:
        return False
    if str(quality_gate.get("status") or "") != ("pass" if expected_gate_passed else "fail"):
        return False
    if sorted(str(value) for value in quality_gate.get("blocking_gaps") or []) != sorted(failed_ids):
        return False
    expected_failures = [] if expected_gate_passed else ["dispatch_results_incomplete"]
    if [str(value) for value in quality_gate.get("failures") or []] != expected_failures:
        return False
    return True


def dispatch_markdown_matches_package_summaries(dispatch_artifact: dict[str, Any]) -> bool:
    def expected_agent_evidence_line(agent: dict[str, Any]) -> str:
        agent_bits = []
        for key in (
            "hostname",
            "status",
            "health",
            "last_seen",
            "last_seen_age_seconds",
            "endpoint_telemetry",
            "live_response",
        ):
            if agent.get(key) not in (None, "", []):
                agent_bits.append(f"{key}={agent[key]}")
        return "; ".join(agent_bits)

    run_id = str(dispatch_artifact.get("run_id") or "")
    if not run_id:
        return False
    markdown_path = ROOT / "docs" / "benchmarks" / "runs" / f"{run_id}.md"
    if not markdown_path.exists():
        return False
    markdown = markdown_path.read_text(encoding="utf-8")
    forbidden_patterns = ("/tmp/", "tmp/dispatch", "D:/", "D:\\", "\\tmp\\")
    if any(pattern.lower() in markdown.lower() for pattern in forbidden_patterns):
        return False
    expected_header_lines = [
        f"- Source preflight: `{normalize_artifact_ref(dispatch_artifact.get('source_preflight'))}`",
        f"- Passed packages: `{dispatch_artifact.get('passed_count')}`",
        f"- Failed/missing packages: `{dispatch_artifact.get('failed_count')}`",
        f"- Blocked packages: `{dispatch_artifact.get('blocked_count', 0)}`",
        f"- Failed packages with artifacts: `{dispatch_artifact.get('failed_status_count', 0)}`",
        f"- Missing packages: `{dispatch_artifact.get('missing_count', 0)}`",
        f"- Invalid packages: `{dispatch_artifact.get('invalid_count', 0)}`",
        f"- Missing required env: `{', '.join(str(value) for value in dispatch_artifact.get('missing_required_env') or []) or '-'}`",
    ]
    for expected in expected_header_lines:
        if expected not in markdown:
            return False
    required_env_blockers = dispatch_artifact.get("required_env_blockers") or []
    owner_handoff = dispatch_artifact.get("owner_handoff") or []
    if owner_handoff:
        owner_table_header = "| Owner | Packages | Passed | Blocked | Failed | Missing env | Roadmaps |"
        if "## Owner Handoff" not in markdown or owner_table_header not in markdown:
            return False
        owner_package_table_header = "| Owner | Package | Wave | Status | Title | Depends on waves | Parallel in wave | Handoff notes |"
        if "## Owner Package Queue" not in markdown or owner_package_table_header not in markdown:
            return False
        for owner in owner_handoff:
            owner_needles = [
                f"`{owner.get('owner')}`",
                f"| {owner.get('package_count')} |",
                f"| {owner.get('passed_count')} |",
                f"| {owner.get('blocked_count')} |",
                f"| {owner.get('failed_status_count')} |",
                *[f"`{value}`" for value in owner.get("missing_required_env") or []],
                *[f"`{value}`" for value in owner.get("roadmaps") or []],
            ]
            for expected in owner_needles:
                if expected not in markdown:
                    return False
            for package in owner.get("packages") or []:
                package_needles = [
                    f"`{owner.get('owner')}`",
                    f"`{package.get('package_id')}`",
                    f"`{package.get('status')}`",
                    str(package.get("title") or "-"),
                    str(bool(package.get("parallelizable_in_wave"))).lower(),
                    *[f"`{value}`" for value in package.get("handoff_notes") or []],
                ]
                for expected in package_needles:
                    if expected not in markdown:
                        return False
    if required_env_blockers:
        required_table_header = "| Package | Wave | Owner | Roadmaps | Missing env | Blocking profiles |"
        if "## Required Env Blockers" not in markdown or required_table_header not in markdown:
            return False
        for blocker in required_env_blockers:
            blocker_needles = [
                f"`{blocker.get('package_id')}`",
                f"| {blocker.get('wave') or '-'} |",
                f"`{blocker.get('recommended_owner_role') or '-'}`",
                *[f"`{value}`" for value in blocker.get("roadmaps") or []],
                *[f"`{value}`" for value in blocker.get("missing_required_env") or []],
                *[f"`{value}`" for value in blocker.get("blocking_profiles") or []],
            ]
            for expected in blocker_needles:
                if expected not in markdown:
                    return False
    checked = 0
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        artifact_path = normalize_artifact_ref(package.get("artifact_path"))
        if not package_id:
            return False
        artifact_cell = artifact_path or "-"
        selected = package.get("launcher_selected")
        selected_text = "-" if selected is None else str(bool(selected)).lower()
        first_gap = package.get("first_gap") if isinstance(package.get("first_gap"), dict) else {}
        first_gap_text = first_gap.get("test_id") or "-"
        expected_cells = [
            f"`{package_id}`",
            f"| {package.get('wave') or '-'} |",
            f"| {selected_text} |",
            f"`{package.get('status')}`",
            f"`{artifact_cell}`",
            f"`{first_gap_text}`",
        ]
        for expected in expected_cells:
            if expected not in markdown:
                return False
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        agent = evidence.get("agent") if isinstance(evidence.get("agent"), dict) else {}
        if agent:
            expected_agent_line = expected_agent_evidence_line(agent)
            if not expected_agent_line or f"`{expected_agent_line}`" not in markdown:
                return False
        missing = [str(value) for value in evidence.get("missing") or []]
        if missing and f"`{', '.join(missing)}`" not in markdown:
            return False
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_evidence = (
                profile_result.get("evidence_excerpt")
                if isinstance(profile_result.get("evidence_excerpt"), dict)
                else {}
            )
            action = (
                profile_evidence.get("next_action")
                if isinstance(profile_evidence.get("next_action"), dict)
                else {}
            )
            if not action:
                continue
            profile_id = str(profile_result.get("profile_id") or "-")
            missing_values = (
                action.get("missing_stability")
                or action.get("missing_readiness")
                or action.get("missing_diagnostics")
                or action.get("missing_endpoints")
                or action.get("missing_profiles")
                or []
            )
            missing_text = ", ".join(str(value) for value in missing_values) or "-"
            action_text = str(action.get("action") or "-")
            action_details = [f"{missing_text}; {action_text}"]
            if action.get("login_command"):
                action_details.append("login_command=" + str(action.get("login_command")))
            if action.get("token_login_command"):
                action_details.append("token_login_command=" + str(action.get("token_login_command")))
            if f"`{profile_id}` next action" not in markdown:
                return False
            if f"`{'; '.join(action_details)}`" not in markdown:
                return False
        checked += 1
    return checked > 0


def dispatch_package_evidence_excerpt_is_actionable(dispatch_artifact: dict[str, Any]) -> bool:
    checked = 0
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        if package.get("passed") is True:
            continue
        first_gap = package.get("first_gap") if isinstance(package.get("first_gap"), dict) else {}
        expected_missing = [str(value) for value in first_gap.get("missing") or []]
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        if not expected_missing and isinstance(evidence.get("missing_package"), dict) and evidence.get("missing_package"):
            checked += 1
            continue
        if not expected_missing:
            return False
        actual_missing = [str(value) for value in evidence.get("missing") or []]
        if actual_missing:
            if actual_missing != expected_missing:
                return False
            checked += 1
            continue
        agent = evidence.get("agent") if isinstance(evidence.get("agent"), dict) else {}
        if agent:
            checked += 1
            continue
        if isinstance(evidence.get("next_action"), dict) and evidence.get("next_action"):
            checked += 1
            continue
        if isinstance(evidence.get("missing_package"), dict) and evidence.get("missing_package"):
            checked += 1
            continue
        if actual_missing != expected_missing:
            return False
        checked += 1
    failed_packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("passed") is not True
    ]
    return checked == len(failed_packages) and checked > 0


def caldera_repeatability_reset_reasons(artifact: dict[str, Any]) -> dict[str, str]:
    reasons: dict[str, str] = {}
    for gap in (artifact.get("quality_gate") or {}).get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        profile = str(evidence.get("profile_id") or "")
        reset = evidence.get("latest_streak_reset") if isinstance(evidence.get("latest_streak_reset"), dict) else {}
        reason = str(reset.get("reason") or "")
        if profile and reason:
            reasons[profile] = reason
    return reasons


def caldera_repeatability_recent_history_profiles(artifact: dict[str, Any]) -> list[str]:
    profiles: set[str] = set()
    for gap in (artifact.get("quality_gate") or {}).get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        profile = str(evidence.get("profile_id") or "")
        history = evidence.get("recent_history")
        if profile and isinstance(history, list) and history:
            profiles.add(profile)
    return sorted(profiles)


def caldera_repeatability_next_actions(artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    actions: dict[str, dict[str, Any]] = {}
    for gap in (artifact.get("quality_gate") or {}).get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        profile = str(evidence.get("profile_id") or "")
        action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        command = str(action.get("next_command_hint") or "")
        required_env = [str(value) for value in action.get("required_env") or []]
        if not profile or not action:
            continue
        actions[profile] = {
            "passes_needed": int(action.get("passes_needed") or 0),
            "profile_file": str(action.get("profile_file") or ""),
            "has_command_hint": "tamandua_detection_validation.py" in command,
            "required_env": required_env,
        }
    return dict(sorted(actions.items()))


def macos_backend_best_candidate_action(artifact: dict[str, Any]) -> dict[str, Any]:
    for gap in (artifact.get("quality_gate") or {}).get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        candidate = evidence.get("best_candidate") if isinstance(evidence.get("best_candidate"), dict) else {}
        action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        if candidate and action:
            return {
                "hostname": candidate.get("hostname"),
                "status": candidate.get("status"),
                "health": candidate.get("health"),
                "missing_readiness": [str(value) for value in candidate.get("missing_readiness") or []],
                "target_hostname": action.get("target_hostname"),
                "has_action": bool(action.get("action")),
            }
        if action:
            return {
                "hostname": None,
                "status": None,
                "health": None,
                "missing_readiness": [str(value) for value in action.get("missing_readiness") or []],
                "target_hostname": action.get("target_hostname"),
                "has_action": bool(action.get("action")),
            }
    return {}


def windows_lab_next_action(artifact: dict[str, Any]) -> dict[str, Any]:
    readiness = artifact.get("windows_lab_readiness") if isinstance(artifact.get("windows_lab_readiness"), dict) else {}
    action = readiness.get("next_action") if isinstance(readiness.get("next_action"), dict) else {}
    target = readiness.get("target") if isinstance(readiness.get("target"), dict) else {}
    if not action:
        return {}
    return {
        "hostname": target.get("hostname"),
        "status": target.get("status"),
        "health": target.get("health"),
        "missing_readiness": [str(value) for value in action.get("missing_readiness") or []],
        "target_hostname": action.get("target_hostname"),
        "has_action": bool(action.get("action")),
    }


def windows_connection_stability_next_action(artifact: dict[str, Any]) -> dict[str, Any]:
    stability = (
        artifact.get("connection_stability")
        if isinstance(artifact.get("connection_stability"), dict)
        else {}
    )
    action = stability.get("next_action") if isinstance(stability.get("next_action"), dict) else {}
    if not action:
        return {}
    return {
        "agent_id": action.get("agent_id"),
        "missing_stability": [str(value) for value in action.get("missing_stability") or []],
        "blockers": [str(value) for value in action.get("blockers") or []],
        "min_stable_session_seconds": action.get("min_stable_session_seconds"),
        "has_action": bool(action.get("action")),
    }


def missing_expected_values(actual: list[str], expected: list[str]) -> list[str]:
    actual_set = set(actual)
    return [value for value in expected if value not in actual_set]


def scorecard_consistency_latest_meets_minimum(latest: dict[str, Any]) -> bool:
    try:
        covered = int(latest.get("covered") or 0)
        tests = int(latest.get("tests") or latest.get("expected_profile_tests") or 0)
    except (TypeError, ValueError):
        return False
    return covered >= MIN_SCORECARD_CONSISTENCY_CHECKS and tests >= MIN_SCORECARD_CONSISTENCY_CHECKS


def consistency_artifact_self_indexes_run(artifact: dict[str, Any], run_id: str) -> bool:
    latest = artifact.get("latest") if isinstance(artifact.get("latest"), dict) else {}
    entry = latest.get(PROFILE_ID) if isinstance(latest.get(PROFILE_ID), dict) else {}
    return str(artifact.get("run_id") or "") == run_id and str(entry.get("run_id") or "") == run_id


def dispatch_artifact_self_indexes_run(artifact: dict[str, Any], run_id: str) -> bool:
    return str(artifact.get("run_id") or "") == run_id


def dispatch_official_timestamps_are_parseable(artifact: dict[str, Any]) -> bool:
    parsed: dict[str, datetime] = {}
    for field_name in ("generated_at", "summarized_at"):
        value = str(artifact.get(field_name) or "")
        if not value:
            return False
        try:
            parsed[field_name] = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
    return parsed["generated_at"] >= parsed["summarized_at"]


def run_id_timestamp(run_id: str) -> str:
    if not run_id or "-" not in run_id:
        return ""
    return run_id.split("-", 1)[0]


def run_id_is_at_least(run_id: str, other_run_id: str) -> bool:
    stamp = run_id_timestamp(run_id)
    other_stamp = run_id_timestamp(other_run_id)
    return bool(stamp and other_stamp and stamp >= other_stamp)


def scorecard_coverage_string(latest: dict[str, Any]) -> str:
    covered = latest.get("covered")
    tests = latest.get("tests") or latest.get("expected_profile_tests")
    if covered in (None, "") or tests in (None, ""):
        return ""
    return f"{covered}/{tests}"


def build_payload(
    scorecard_path: Path,
    status_docs: list[Path],
    expected_consistency_run_id: str | None = None,
) -> dict[str, Any]:
    scorecard = load_json(scorecard_path)
    scorecard_md_path = scorecard_path.with_suffix(".md")
    scorecard_md_text = load_text(scorecard_md_path)
    closure_latest = latest_profile(scorecard, PROFILE_CLOSURE)
    preflight_latest = latest_profile(scorecard, PROFILE_PREFLIGHT)
    replay_latest = latest_profile(scorecard, PROFILE_REPLAY)
    fresh_restore_latest = latest_profile(scorecard, PROFILE_FRESH_RESTORE)
    dispatch_latest = latest_profile(scorecard, PROFILE_DISPATCH_RESULTS)
    caldera_repeatability_latest = latest_profile(scorecard, PROFILE_CALDERA_REPEATABILITY)
    consistency_latest = latest_profile(scorecard, PROFILE_ID)
    consistency_entry = profile_entry(scorecard, PROFILE_ID)
    consistency_latest_fail = (
        consistency_entry.get("latest_fail") if isinstance(consistency_entry.get("latest_fail"), dict) else {}
    )
    windows_lab_latest = latest_profile(scorecard, PROFILE_WINDOWS_LAB_READINESS)
    windows_connection_latest = latest_profile(scorecard, PROFILE_WINDOWS_CONNECTION_STABILITY)
    macos_backend_latest = latest_profile(scorecard, PROFILE_MACOS_BACKEND_READINESS)
    atomic_t1047_latest = latest_profile(scorecard, PROFILE_ATOMIC_T1047_CAPABILITY)
    linux_ebpf_latest = latest_profile(scorecard, PROFILE_LINUX_EBPF_READINESS)
    windows_qga_entry = profile_entry(scorecard, PROFILE_WINDOWS_QGA_READINESS)
    windows_qga_latest = windows_qga_entry.get("latest") if isinstance(windows_qga_entry.get("latest"), dict) else {}
    windows_qga_aggregate = (
        windows_qga_entry.get("aggregate") if isinstance(windows_qga_entry.get("aggregate"), dict) else {}
    )
    windows_qga_aggregate_source = (
        windows_qga_aggregate.get("latest_raw_gate_pass")
        if isinstance(windows_qga_aggregate.get("latest_raw_gate_pass"), dict)
        else {}
    )

    closure_run = str(closure_latest.get("run_id") or "")
    preflight_run = str(preflight_latest.get("run_id") or "")
    replay_run = str(replay_latest.get("run_id") or "")
    fresh_restore_run = str(fresh_restore_latest.get("run_id") or "")
    dispatch_run = str(dispatch_latest.get("run_id") or "")
    caldera_repeatability_run = str(caldera_repeatability_latest.get("run_id") or "")
    indexed_consistency_run = str(consistency_latest.get("run_id") or "")
    consistency_run = (
        validate_run_id(expected_consistency_run_id)
        if expected_consistency_run_id
        else indexed_consistency_run
    )
    windows_lab_run = str(windows_lab_latest.get("run_id") or "")
    windows_connection_run = str(windows_connection_latest.get("run_id") or "")
    macos_backend_run = str(macos_backend_latest.get("run_id") or "")
    atomic_t1047_run = str(atomic_t1047_latest.get("run_id") or "")
    linux_ebpf_run = str(linux_ebpf_latest.get("run_id") or "")
    windows_qga_latest_run = str(windows_qga_latest.get("run_id") or "")
    windows_qga_aggregate_run = str(windows_qga_aggregate_source.get("run_id") or "")
    closure_coverage = scorecard_coverage_string(closure_latest)
    preflight_coverage = scorecard_coverage_string(preflight_latest)
    fresh_restore_coverage = scorecard_coverage_string(fresh_restore_latest)
    dispatch_coverage = scorecard_coverage_string(dispatch_latest)
    caldera_repeatability_coverage = scorecard_coverage_string(caldera_repeatability_latest)
    windows_lab_coverage = scorecard_coverage_string(windows_lab_latest)
    windows_connection_coverage = scorecard_coverage_string(windows_connection_latest)
    macos_backend_coverage = scorecard_coverage_string(macos_backend_latest)
    atomic_t1047_coverage = scorecard_coverage_string(atomic_t1047_latest)
    linux_ebpf_coverage = scorecard_coverage_string(linux_ebpf_latest)

    closure_path = artifact_path(closure_latest)
    preflight_path = artifact_path(preflight_latest)
    replay_path = artifact_path(replay_latest)
    fresh_restore_path = artifact_path(fresh_restore_latest)
    dispatch_path = artifact_path(dispatch_latest)
    caldera_repeatability_path = artifact_path(caldera_repeatability_latest)
    windows_lab_path = artifact_path(windows_lab_latest)
    windows_connection_path = artifact_path(windows_connection_latest)
    macos_backend_path = artifact_path(macos_backend_latest)
    indexed_consistency_path = artifact_path(consistency_latest)
    prospective_consistency_path = RUNS_DIR / f"{consistency_run}.json"
    consistency_path = (
        prospective_consistency_path
        if expected_consistency_run_id and prospective_consistency_path.exists()
        else indexed_consistency_path
    )
    consistency_artifact_run = consistency_run if consistency_path == prospective_consistency_path else indexed_consistency_run

    closure_artifact = load_json(closure_path)
    preflight_artifact = load_json(preflight_path)
    replay_artifact = load_json(replay_path)
    fresh_restore_artifact = load_json(fresh_restore_path)
    dispatch_artifact = load_json(dispatch_path)
    caldera_repeatability_artifact = load_json(caldera_repeatability_path)
    windows_lab_artifact = load_json(windows_lab_path)
    windows_connection_artifact = load_json(windows_connection_path)
    macos_backend_artifact = load_json(macos_backend_path)
    consistency_artifact = load_json(consistency_path)
    roadmap_b_note = roadmap_note(scorecard, "B")
    open_roadmaps = closure_open_roadmaps(closure_artifact)
    blocked_classes = blocked_run_classes(preflight_artifact)
    blocked_class_roadmaps = blocked_run_class_roadmaps(preflight_artifact)
    blocked_class_missing_envs = blocked_run_class_missing_envs(preflight_artifact)
    unblock_steps = unblock_sequence_ids(preflight_artifact)
    unblock_priorities = unblock_sequence_priorities(preflight_artifact)
    parallel_wave_shape = parallel_unblock_wave_shape(preflight_artifact)

    checks: list[dict[str, Any]] = []
    scorecard_source = rel(scorecard_path)
    scorecard_md_source = rel(scorecard_md_path)
    closure_source = rel(closure_path)
    preflight_source = rel(preflight_path)
    replay_source = rel(replay_path)
    fresh_restore_source = rel(fresh_restore_path)
    dispatch_source = rel(dispatch_path)
    caldera_repeatability_source = rel(caldera_repeatability_path)
    windows_lab_source = rel(windows_lab_path)
    windows_connection_source = rel(windows_connection_path)
    macos_backend_source = rel(macos_backend_path)
    consistency_source = rel(consistency_path)
    preflight_work_package_path = ROOT / "tools" / "detection_validation" / "run_preflight_work_package.py"
    preflight_work_package_text = load_text(preflight_work_package_path)

    check(checks, "closure latest run_id present", bool(closure_run), True, [scorecard_source])
    check(checks, "preflight latest run_id present", bool(preflight_run), True, [scorecard_source])
    check(checks, "replay latest run_id present", bool(replay_run), True, [scorecard_source])
    check(checks, "fresh restore latest run_id present", bool(fresh_restore_run), True, [scorecard_source])
    check(checks, "dispatch results latest run_id present", bool(dispatch_run), True, [scorecard_source])
    check(
        checks,
        "CALDERA repeatability latest run_id present",
        bool(caldera_repeatability_run),
        True,
        [scorecard_source],
    )
    check(checks, "windows lab readiness latest run_id present", bool(windows_lab_run), True, [scorecard_source])
    check(
        checks,
        "windows connection stability latest run_id present",
        bool(windows_connection_run),
        True,
        [scorecard_source],
    )
    check(checks, "macOS backend readiness latest run_id present", bool(macos_backend_run), True, [scorecard_source])
    check(checks, "Atomic T1047 capability latest run_id present", bool(atomic_t1047_run), True, [scorecard_source])
    check(checks, "Linux eBPF readiness latest run_id present", bool(linux_ebpf_run), True, [scorecard_source])
    check(checks, "closure artifact path exists", closure_path.exists(), True, [scorecard_source, closure_source])
    check(checks, "preflight artifact path exists", preflight_path.exists(), True, [scorecard_source, preflight_source])
    check(checks, "replay artifact path exists", replay_path.exists(), True, [scorecard_source, replay_source])
    check(
        checks,
        "fresh restore artifact path exists",
        fresh_restore_path.exists(),
        True,
        [scorecard_source, fresh_restore_source],
    )
    check(
        checks,
        "dispatch results artifact path exists",
        dispatch_path.exists(),
        True,
        [scorecard_source, dispatch_source],
    )
    check(
        checks,
        "dispatch results official artifact self-indexes its run_id",
        dispatch_artifact_self_indexes_run(dispatch_artifact, dispatch_run),
        True,
        [scorecard_source, dispatch_source],
    )
    check(
        checks,
        "dispatch results official timestamps are parseable",
        dispatch_official_timestamps_are_parseable(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact path exists",
        caldera_repeatability_path.exists(),
        True,
        [scorecard_source, caldera_repeatability_source],
    )
    check(
        checks,
        "consistency latest artifact path exists",
        consistency_path.exists(),
        True,
        [scorecard_source, consistency_source],
    )
    check(
        checks,
        "consistency latest artifact self-indexes its run_id",
        consistency_artifact_self_indexes_run(consistency_artifact, consistency_artifact_run),
        True,
        [scorecard_source, consistency_source],
    )
    check(
        checks,
        "dispatch results official metadata matches dispatch profile",
        dispatch_official_metadata_matches_profile(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results official paths are self-contained package artifacts",
        dispatch_official_paths_are_self_contained(dispatch_artifact, dispatch_run),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results official package artifacts exist",
        dispatch_official_paths_exist(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results official payload omits temp and absolute output paths",
        dispatch_official_payload_has_no_tmp(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results official comparison matches payload paths",
        dispatch_official_comparison_matches_payload(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived summary paths are self-contained",
        dispatch_archived_summary_has_self_contained_paths(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest source preflight matches official artifact",
        dispatch_archived_manifest_source_matches_artifact(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest omits temp and absolute output paths",
        dispatch_archived_manifest_has_no_tmp(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest handoff paths exist",
        dispatch_archived_manifest_handoff_paths_exist(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived handoff contents are self-contained",
        dispatch_archived_handoff_contents_are_self_contained(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived handoff execution guards are present",
        dispatch_archived_handoff_execution_guards_present(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived dependent launcher evidence guards are present",
        dispatch_archived_dependent_launcher_evidence_guards_present(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived one-shot runner guard is present",
        dispatch_archived_one_shot_runner_guard_present(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived env checklist includes operator input details",
        dispatch_archived_env_checklist_includes_operator_input_details(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived env template is redacted and complete",
        dispatch_archived_env_template_is_redacted_and_complete(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived owner launch plan matches manifest",
        dispatch_archived_owner_launch_plan_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived owner launch plan JSON matches manifest",
        dispatch_archived_owner_launch_plan_json_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived execution matrix matches owner launch plan",
        dispatch_archived_execution_matrix_matches_owner_plan(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived agent claims match execution matrix",
        dispatch_archived_agent_claims_match_execution_matrix(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived agent spawn plan matches agent claims",
        dispatch_archived_agent_spawn_plan_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived agent spawn launcher matches spawn plan",
        dispatch_archived_agent_spawn_launcher_matches_spawn_plan(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived claim status report matches agent claims",
        dispatch_archived_claim_status_report_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived claim lock helper matches agent claims",
        dispatch_archived_claim_lock_helper_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived env unblock queue matches agent claims",
        dispatch_archived_env_unblock_queue_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived ready claims launcher matches agent claims",
        dispatch_archived_ready_claims_launcher_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived ready claims parallel launcher matches agent claims",
        dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived env-bundle ready claims launcher matches agent claims",
        dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived prelaunch validation matches manifest",
        dispatch_archived_prelaunch_validation_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived brief recommended launch sequence matches manifest",
        dispatch_archived_brief_recommended_launch_sequence_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived launcher membership matches manifest",
        dispatch_archived_launcher_membership_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived staged launcher stage membership matches manifest",
        dispatch_archived_staged_launcher_stage_membership_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest launcher decisions are replayable",
        dispatch_archived_manifest_launcher_decisions_are_replayable(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived launcher manual reasons match manifest",
        dispatch_archived_launcher_manual_reasons_match_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived launcher selected metadata matches manifest",
        dispatch_archived_launcher_selected_metadata_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest package metadata matches official artifact",
        dispatch_archived_manifest_packages_match_artifact(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest handoff notes are actionable",
        dispatch_archived_manifest_handoff_notes_are_actionable(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived prompts match manifest metadata",
        dispatch_archived_prompts_match_manifest_metadata(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived agent roster matches manifest metadata",
        dispatch_archived_agent_roster_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived current-action env guards match manifest",
        dispatch_archived_current_action_env_guards_match_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest package set matches source preflight wave",
        dispatch_archived_manifest_matches_source_preflight_packages(dispatch_artifact),
        True,
        [dispatch_source, preflight_source],
    )
    check(
        checks,
        "dispatch archived handoff scripts match source safe commands",
        dispatch_archived_handoff_scripts_match_source_commands(dispatch_artifact),
        True,
        [dispatch_source, preflight_source],
    )
    check(
        checks,
        "dispatch package summaries match archived artifacts",
        dispatch_package_summaries_match_artifacts(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch package summaries reject unexpected profile artifacts",
        dispatch_package_summaries_reject_unexpected_profile_artifacts(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch package archived artifacts include companions",
        dispatch_package_archived_artifacts_include_companions(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch tests match package summaries",
        dispatch_tests_match_package_summaries(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch summary and gate match packages",
        dispatch_summary_and_gate_match_packages(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch markdown matches package summaries",
        dispatch_markdown_matches_package_summaries(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch package evidence excerpt is actionable",
        dispatch_package_evidence_excerpt_is_actionable(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped blocker_cleared",
        preflight_work_package_text,
        'not isinstance(blocker_cleared_value, bool)',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch records blocker_cleared type violation",
        preflight_work_package_text,
        '"blocker_cleared_not_bool"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-string artifact list entries",
        preflight_work_package_text,
        '"artifacts_not_string_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects blank artifact list entries",
        preflight_work_package_text,
        '"artifacts_has_blank_entry"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-string notes entries",
        preflight_work_package_text,
        '"notes_not_string_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects blank notes entries",
        preflight_work_package_text,
        '"notes_has_blank_entry"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped exit_code",
        preflight_work_package_text,
        '"exit_code_not_int"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent status package mismatch",
        preflight_work_package_text,
        '"agent_status_package_id_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent status claim mismatch",
        preflight_work_package_text,
        '"agent_status_claim_id_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped expected_profiles",
        preflight_work_package_text,
        '"expected_profiles_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-string expected profile entries",
        preflight_work_package_text,
        '"expected_profiles_not_string_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects blank expected profile entries",
        preflight_work_package_text,
        '"expected_profiles_has_blank_entry"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects expected profile mismatch",
        preflight_work_package_text,
        '"agent_status_expected_profiles_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects unknown agent status artifact",
        preflight_work_package_text,
        '"agent_status_unknown_artifact"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects missing agent status artifact",
        preflight_work_package_text,
        '"agent_status_missing_artifact"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent-declared missing profiles as pass",
        preflight_work_package_text,
        '"agent_status_missing_profiles"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects unexpected agent missing profile",
        preflight_work_package_text,
        '"agent_status_unexpected_missing_profile"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-string missing profile entries",
        preflight_work_package_text,
        '"missing_profiles_not_string_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects blank missing profile entries",
        preflight_work_package_text,
        '"missing_profiles_has_blank_entry"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects unexpected agent status path",
        preflight_work_package_text,
        '"agent_status_path_unexpected"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects missing declared agent status",
        preflight_work_package_text,
        '"agent_status_missing"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects output dirs outside manifest workdir",
        preflight_work_package_text,
        '"dispatch_output_dir_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects missing package id",
        preflight_work_package_text,
        '"dispatch_package_id_missing"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped expected profiles",
        preflight_work_package_text,
        '"dispatch_expected_profiles_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid expected profile entries",
        preflight_work_package_text,
        '"dispatch_expected_profiles_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped resource tags",
        preflight_work_package_text,
        '"dispatch_resource_tags_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects empty resource tags",
        preflight_work_package_text,
        '"dispatch_resource_tags_empty"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid resource tag entries",
        preflight_work_package_text,
        '"dispatch_resource_tags_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped required env",
        preflight_work_package_text,
        '"dispatch_required_env_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid required env entries",
        preflight_work_package_text,
        '"dispatch_required_env_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped launcher selection",
        preflight_work_package_text,
        '"dispatch_launcher_selected_not_bool"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects manual selection without reason",
        preflight_work_package_text,
        '"dispatch_manual_reason_missing"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects automatic selection with manual reason",
        preflight_work_package_text,
        '"dispatch_manual_reason_unexpected"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped staged launcher selection",
        preflight_work_package_text,
        '"dispatch_staged_launcher_selected_not_bool"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid staged launcher stage",
        preflight_work_package_text,
        '"dispatch_staged_stage_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid package wave",
        preflight_work_package_text,
        '"dispatch_wave_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped dependency waves",
        preflight_work_package_text,
        '"dispatch_depends_on_waves_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid dependency wave entries",
        preflight_work_package_text,
        '"dispatch_depends_on_waves_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-prior dependency waves",
        preflight_work_package_text,
        '"dispatch_depends_on_waves_not_prior"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped safe commands",
        preflight_work_package_text,
        '"dispatch_safe_commands_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid safe command entries",
        preflight_work_package_text,
        '"dispatch_safe_commands_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects unsupported safe commands",
        preflight_work_package_text,
        '"dispatch_safe_commands_unsupported"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped claim output contract",
        preflight_work_package_text,
        '"dispatch_claim_contract_not_dict"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim output profiles",
        preflight_work_package_text,
        '"dispatch_claim_contract_profiles_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mismatched claim output profiles",
        preflight_work_package_text,
        '"dispatch_claim_contract_profiles_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim status fields",
        preflight_work_package_text,
        '"dispatch_claim_contract_status_fields_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim status values",
        preflight_work_package_text,
        '"dispatch_claim_contract_status_values_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped manual prerequisites",
        preflight_work_package_text,
        '"dispatch_manual_prerequisites_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid manual prerequisites",
        preflight_work_package_text,
        '"dispatch_manual_prerequisites_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped operator inputs",
        preflight_work_package_text,
        '"dispatch_operator_inputs_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid operator inputs",
        preflight_work_package_text,
        '"dispatch_operator_inputs_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped roadmap next actions",
        preflight_work_package_text,
        '"dispatch_roadmap_next_actions_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid roadmap next actions",
        preflight_work_package_text,
        '"dispatch_roadmap_next_actions_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped roadmaps",
        preflight_work_package_text,
        '"dispatch_roadmaps_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid roadmaps",
        preflight_work_package_text,
        '"dispatch_roadmaps_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped blocking profiles",
        preflight_work_package_text,
        '"dispatch_blocking_profiles_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid blocking profiles",
        preflight_work_package_text,
        '"dispatch_blocking_profiles_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped blocked run classes",
        preflight_work_package_text,
        '"dispatch_blocked_run_classes_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid blocked run classes",
        preflight_work_package_text,
        '"dispatch_blocked_run_classes_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid recommended owner role",
        preflight_work_package_text,
        '"dispatch_recommended_owner_role_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped continue-on-failure flag",
        preflight_work_package_text,
        '"dispatch_continue_on_failure_not_bool"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid manifest profile id",
        preflight_work_package_text,
        '"dispatch_manifest_profile_id_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects missing manifest source preflight",
        preflight_work_package_text,
        '"dispatch_manifest_source_preflight_missing"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped manifest packages",
        preflight_work_package_text,
        '"dispatch_manifest_packages_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid manifest packages",
        preflight_work_package_text,
        '"dispatch_manifest_packages_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped expected waves",
        preflight_work_package_text,
        '"dispatch_manifest_expected_waves_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid expected waves",
        preflight_work_package_text,
        '"dispatch_manifest_expected_waves_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mismatched expected waves",
        preflight_work_package_text,
        '"dispatch_manifest_expected_waves_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped expected package ids",
        preflight_work_package_text,
        '"dispatch_manifest_expected_package_ids_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid expected package ids",
        preflight_work_package_text,
        '"dispatch_manifest_expected_package_ids_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mismatched expected package ids",
        preflight_work_package_text,
        '"dispatch_manifest_expected_package_ids_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid selected wave",
        preflight_work_package_text,
        '"dispatch_manifest_selected_wave_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid selection mode",
        preflight_work_package_text,
        '"dispatch_manifest_selection_mode_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped launcher paths",
        preflight_work_package_text,
        '"dispatch_manifest_launcher_paths_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid launcher paths",
        preflight_work_package_text,
        '"dispatch_manifest_launcher_paths_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects launcher paths outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_launcher_paths_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped staged launcher paths",
        preflight_work_package_text,
        '"dispatch_manifest_staged_launcher_paths_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid staged launcher paths",
        preflight_work_package_text,
        '"dispatch_manifest_staged_launcher_paths_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects staged launcher paths outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_staged_launcher_paths_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid agent roster path",
        preflight_work_package_text,
        '"dispatch_manifest_agent_roster_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent roster path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_agent_roster_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid env checklist path",
        preflight_work_package_text,
        '"dispatch_manifest_env_checklist_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects env checklist path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_env_checklist_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid env template path",
        preflight_work_package_text,
        '"dispatch_manifest_env_template_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects env template path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_env_template_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid owner launch plan path",
        preflight_work_package_text,
        '"dispatch_manifest_owner_launch_plan_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects owner launch plan path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_owner_launch_plan_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid owner launch plan JSON path",
        preflight_work_package_text,
        '"dispatch_manifest_owner_launch_plan_json_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects owner launch plan JSON path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_owner_launch_plan_json_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid agent spawn launcher path",
        preflight_work_package_text,
        '"dispatch_manifest_agent_spawn_launcher_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent spawn launcher path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_agent_spawn_launcher_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim status report path",
        preflight_work_package_text,
        '"dispatch_manifest_claim_status_report_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects claim status report path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_claim_status_report_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim status report JSON path",
        preflight_work_package_text,
        '"dispatch_manifest_claim_status_report_json_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects claim status report JSON path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_claim_status_report_json_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim lock helper path",
        preflight_work_package_text,
        '"dispatch_manifest_claim_lock_helper_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects claim lock helper path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_claim_lock_helper_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid ready claims launcher path",
        preflight_work_package_text,
        '"dispatch_manifest_ready_claims_launcher_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects ready claims launcher path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_ready_claims_launcher_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid ready claims parallel launcher path",
        preflight_work_package_text,
        '"dispatch_manifest_ready_claims_parallel_launcher_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects ready claims parallel launcher path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_ready_claims_parallel_launcher_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid env-bundle ready claims launcher path",
        preflight_work_package_text,
        '"dispatch_manifest_env_bundle_ready_claims_launcher_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects env-bundle ready claims launcher path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_env_bundle_ready_claims_launcher_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid dispatch prelaunch validation path",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_prelaunch_validation_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects dispatch prelaunch validation path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_prelaunch_validation_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid dispatch brief path",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_brief_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects dispatch brief path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_brief_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid dispatch runner path",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_runner_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects dispatch runner path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_runner_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects pass status with nonzero exit code",
        preflight_work_package_text,
        '"agent_status_pass_exit_code_nonzero"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch records failure status with zero exit code",
        preflight_work_package_text,
        '"agent_status_failure_exit_code_zero"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch records failure status with empty notes",
        preflight_work_package_text,
        '"agent_status_failure_notes_empty"',
        preflight_work_package_path,
    )
    check(
        checks,
        "preflight references latest closure gate",
        preflight_artifact.get("closure_gate_run_id"),
        closure_run,
        [preflight_source, closure_source],
    )
    check(
        checks,
        "preflight broad runs remain blocked when gate failed",
        bool((preflight_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [preflight_source],
    )
    check(
        checks,
        "preflight scorecard blocks external execution claims",
        bool((preflight_artifact.get("scorecard") or {}).get("external_claim_allowed")),
        False,
        [preflight_source],
    )
    check(
        checks,
        "preflight records broad-runs-allowed blocker",
        missing_expected_values(
            collect_nested_values(preflight_artifact.get("quality_gate") or {}, "blocking_gaps"),
            ["execution-preflight-broad-runs-allowed"],
        ),
        [],
        [preflight_source],
    )
    check(
        checks,
        "closure gate is still failed for open roadmaps",
        bool((closure_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [closure_source],
    )
    check(
        checks,
        "closure gate exposes open roadmap list",
        open_roadmaps,
        ["A", "B", "D", "E", "M"],
        [closure_source],
    )
    check(
        checks,
        "closure gate exposes actionable roadmap next actions",
        closure_next_actions_valid(closure_artifact),
        True,
        [closure_source],
    )
    check(
        checks,
        "scorecard indexes latest official Windows readiness artifact",
        windows_lab_run,
        EXPECTED_WINDOWS_LAB_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard Windows readiness remains fail 0/6",
        f"{windows_lab_latest.get('raw_quality_gate_passed')} {windows_lab_coverage}",
        "False 0/6",
        [scorecard_source],
    )
    check(
        checks,
        "Windows readiness artifact exposes target next action",
        windows_lab_next_action(windows_lab_artifact),
        {
            "hostname": None,
            "status": None,
            "health": None,
            "missing_readiness": [
                "target_inventory_row",
            ],
            "target_hostname": "WIN-TEMPLATE",
            "has_action": True,
        },
        [windows_lab_source],
    )
    check(
        checks,
        "scorecard indexes latest official Windows connection stability artifact",
        windows_connection_run,
        EXPECTED_WINDOWS_CONNECTION_STABILITY_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard Windows connection stability remains fail 0/5",
        f"{windows_connection_latest.get('raw_quality_gate_passed')} {windows_connection_coverage}",
        "False 0/5",
        [scorecard_source],
    )
    check(
        checks,
        "Windows connection stability artifact exposes server-log next action",
        windows_connection_stability_next_action(windows_connection_artifact),
        {
            "agent_id": "cb145360-8ba8-475a-bfd6-2bc16d5281d7",
            "missing_stability": [
                "server_log_access",
                "recent_agent_connection",
                "stable_session_300s",
                "active_session",
                "telemetry_batches",
            ],
            "blockers": ["agent-health", "collector", "infra", "runner"],
            "min_stable_session_seconds": 300,
            "has_action": True,
        },
        [windows_connection_source],
    )
    check(
        checks,
        "scorecard indexes latest official macOS backend readiness artifact",
        macos_backend_run,
        EXPECTED_MACOS_BACKEND_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard macOS backend readiness remains fail 0/4",
        f"{macos_backend_latest.get('raw_quality_gate_passed')} {macos_backend_coverage}",
        "False 0/4",
        [scorecard_source],
    )
    check(
        checks,
        "macOS backend artifact exposes best candidate next action",
        macos_backend_best_candidate_action(macos_backend_artifact),
        {
            "hostname": None,
            "status": None,
            "health": None,
            "missing_readiness": ["tamandua_ctl_auth"],
            "target_hostname": None,
            "has_action": True,
        },
        [macos_backend_source],
    )
    check(
        checks,
        "scorecard indexes latest official Atomic T1047 capability artifact",
        atomic_t1047_run,
        EXPECTED_ATOMIC_T1047_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard Atomic T1047 capability remains pass 4/4 boundary evidence",
        f"{atomic_t1047_latest.get('raw_quality_gate_passed')} {atomic_t1047_coverage}",
        "True 4/4",
        [scorecard_source],
    )
    check(
        checks,
        "scorecard indexes latest official Linux eBPF readiness artifact",
        linux_ebpf_run,
        EXPECTED_LINUX_EBPF_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard Linux eBPF readiness remains partial-scope 1/1",
        f"{linux_ebpf_latest.get('raw_quality_gate_passed')} {linux_ebpf_coverage}",
        "True 1/1",
        [scorecard_source],
    )
    check(
        checks,
        "scorecard QGA aggregate source remains latest green execution proof",
        windows_qga_aggregate_run,
        EXPECTED_WINDOWS_QGA_AGGREGATE_PASS_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard QGA latest raw artifact remains failed diagnostic",
        windows_qga_latest_run,
        EXPECTED_WINDOWS_QGA_LATEST_RAW_FAIL_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard markdown displays QGA aggregate-pass on aggregate source line",
        line_contains_all(
            scorecard_md_text,
            [
                PROFILE_WINDOWS_QGA_READINESS,
                EXPECTED_WINDOWS_QGA_AGGREGATE_PASS_RUN,
                "aggregate-pass",
                "7/7",
            ],
        ),
        True,
        [scorecard_md_source],
    )
    check(
        checks,
        "scorecard roadmap row preserves QGA latest raw fail context",
        line_contains_all(
            scorecard_md_text,
            [
                PROFILE_WINDOWS_QGA_READINESS,
                EXPECTED_WINDOWS_QGA_AGGREGATE_PASS_RUN,
                f"latest `{EXPECTED_WINDOWS_QGA_LATEST_RAW_FAIL_RUN}` fail",
            ],
        ),
        True,
        [scorecard_md_source],
    )
    check(
        checks,
        "preflight exposes blocked run class list",
        blocked_classes,
        [
            "macos-server-backed-smoke",
            "windows-atomic-extended",
            "windows-broad",
            "windows-caldera-enterprise",
            "windows-p1-p2-rerun",
        ],
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes expected blocked run class roadmap mapping",
        blocked_class_roadmaps,
        EXPECTED_BLOCKED_RUN_CLASS_ROADMAPS,
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes expected blocked run class missing env mapping",
        blocked_class_missing_envs,
        EXPECTED_BLOCKED_RUN_CLASS_MISSING_ENVS,
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes expected unblock sequence order",
        unblock_steps,
        EXPECTED_UNBLOCK_SEQUENCE,
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes expected unblock sequence priorities",
        unblock_priorities,
        EXPECTED_UNBLOCK_SEQUENCE_PRIORITIES,
        [preflight_source],
    )
    check(
        checks,
        "preflight propagates closure roadmap next actions",
        preflight_roadmap_next_actions_valid(preflight_artifact),
        True,
        [preflight_source, closure_source],
    )
    check(
        checks,
        "preflight exposes expected parallel unblock wave shape",
        parallel_wave_shape,
        EXPECTED_PARALLEL_UNBLOCK_WAVES,
        [preflight_source],
    )
    check(
        checks,
        "preflight Windows QGA package requires Proxmox auth env",
        {
            package_id: preflight_package_required_env(preflight_artifact).get(package_id)
            for package_id in EXPECTED_PREFLIGHT_PACKAGE_REQUIRED_ENVS
        },
        EXPECTED_PREFLIGHT_PACKAGE_REQUIRED_ENVS,
        [preflight_source],
    )
    check(
        checks,
        "offline replay latest pass is 43/43",
        f"{(replay_artifact.get('summary') or {}).get('covered')}/{(replay_artifact.get('summary') or {}).get('tests')}",
        "43/43",
        [replay_source],
    )
    check(
        checks,
        "fresh restore latest remains blocked at 2/5 until real restore evidence exists",
        fresh_restore_coverage,
        "2/5",
        [fresh_restore_source],
    )
    check(
        checks,
        "fresh restore artifact blocks fresh restore claims",
        bool((fresh_restore_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [fresh_restore_source],
    )
    check(
        checks,
        "CALDERA repeatability latest remains blocked at 0/2 until three consecutive passes exist",
        caldera_repeatability_coverage,
        "0/2",
        [caldera_repeatability_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact blocks repeatability claims",
        bool((caldera_repeatability_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [caldera_repeatability_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact exposes expected latest reset reasons",
        caldera_repeatability_reset_reasons(caldera_repeatability_artifact),
        EXPECTED_CALDERA_REPEATABILITY_RESET_REASONS,
        [caldera_repeatability_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact exposes recent history for both profiles",
        caldera_repeatability_recent_history_profiles(caldera_repeatability_artifact),
        sorted(EXPECTED_CALDERA_REPEATABILITY_RESET_REASONS),
        [caldera_repeatability_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact exposes next action hints for both profiles",
        caldera_repeatability_next_actions(caldera_repeatability_artifact),
        EXPECTED_CALDERA_REPEATABILITY_NEXT_ACTIONS,
        [caldera_repeatability_source],
    )
    check(
        checks,
        "scorecard Roadmap B note preserves fresh restore claim boundary markers",
        missing_expected_values([marker for marker in EXPECTED_ROADMAP_B_NOTE_MARKERS if marker in roadmap_b_note], EXPECTED_ROADMAP_B_NOTE_MARKERS),
        [],
        [scorecard_source],
    )
    check(
        checks,
        "dispatch results remain coordination-only",
        "does not promote package artifacts" in str(dispatch_artifact.get("claim_boundary") or ""),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results reference latest preflight artifact",
        normalize_artifact_ref(dispatch_artifact.get("source_preflight")),
        preflight_source,
        [dispatch_source, preflight_source],
    )
    check(
        checks,
        "dispatch results gate remains failed while wave 1 has open blockers",
        bool((dispatch_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results record one passed package",
        int(dispatch_artifact.get("passed_count") or 0),
        1,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results latest coverage is 1/8",
        dispatch_coverage,
        "1/8",
        [scorecard_source, dispatch_source],
    )
    check(
        checks,
        "dispatch results record seven failed packages",
        int(dispatch_artifact.get("failed_count") or 0),
        7,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch missing-package evidence matches manifest expected profiles",
        dispatch_missing_package_evidence_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results expose Windows connection stability handoff env",
        dispatch_windows_connection_handoff(dispatch_artifact),
        EXPECTED_DISPATCH_WINDOWS_CONNECTION_HANDOFF,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results expose macOS auth handoff command",
        dispatch_macos_auth_handoff(dispatch_artifact),
        EXPECTED_DISPATCH_MACOS_AUTH_HANDOFF,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch claim handoffs expose macOS auth command",
        dispatch_claim_macos_auth_handoff(dispatch_artifact),
        expected_dispatch_claim_macos_auth_handoff(dispatch_run),
        [dispatch_source],
    )
    check(
        checks,
        "dispatch macOS prompt exposes token next-action env",
        dispatch_macos_prompt_exposes_token_env(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "consistency latest run_id present",
        bool(consistency_run),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "consistency latest run_id is at least latest closure preflight and dispatch",
        all(
            run_id_is_at_least(consistency_run, run_id)
            for run_id in (closure_run, preflight_run, dispatch_run)
        ),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "consistency latest pass supersedes latest consistency fail",
        not consistency_latest_fail
        or run_id_is_at_least(consistency_run, str(consistency_latest_fail.get("run_id") or "")),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard manual claim review exposes dispatch manual claims",
        any(
            isinstance(item, dict)
            and item.get("kind") == "dispatch-claim"
            and item.get("polarity") == "manual"
            for item in scorecard.get("manual_claim_review") or []
        ),
        True,
        [scorecard_source],
    )
    check(
        checks,
        f"scorecard indexes consistency artifact with at least {MIN_SCORECARD_CONSISTENCY_CHECKS} checks",
        bool(expected_consistency_run_id) or scorecard_consistency_latest_meets_minimum(consistency_latest),
        True,
        [scorecard_source],
    )
    closure_required_env = collect_nested_values(closure_artifact, "required_env")
    required_env = collect_nested_values(preflight_artifact, "required_env")
    check(
        checks,
        "closure gate exposes all expected required env inputs",
        missing_expected_values(closure_required_env, EXPECTED_PREFLIGHT_REQUIRED_ENVS),
        [],
        [closure_source],
    )
    check(
        checks,
        "preflight exposes fresh-restore required env inputs",
        any(value.startswith("TAMANDUA_FRESH_RESTORE_") for value in required_env),
        True,
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes all expected required env inputs",
        missing_expected_values(required_env, EXPECTED_PREFLIGHT_REQUIRED_ENVS),
        [],
        [preflight_source],
    )

    preflight_md = preflight_path.with_suffix(".md")
    preflight_md_text = load_text(preflight_md)
    for section in (
        "## Roadmap Blockers",
        "## Run Class Readiness",
        "## Unblock Sequence",
        "## Parallel Unblock Waves",
        "## Parallel Work Packages",
    ):
        check_contains(
            checks,
            f"preflight markdown contains {section}",
            preflight_md_text,
            section,
            preflight_md,
        )
    for marker in EXPECTED_PREFLIGHT_SAFE_COMMAND_MARKERS:
        check_contains(
            checks,
            f"preflight markdown contains safe command marker {marker}",
            preflight_md_text,
            marker,
            preflight_md,
        )

    for doc in status_docs:
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest closure gate", text, closure_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest closure gate coverage on same line",
            line_contains_all(text, [closure_run, closure_coverage]),
            True,
            [rel(doc)],
        )
        check_contains(checks, f"{rel(doc)} references latest preflight", text, preflight_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest preflight coverage on same line",
            line_contains_all(text, [preflight_run, preflight_coverage]),
            True,
            [rel(doc)],
        )
        check(
            checks,
            f"{rel(doc)} references all open roadmaps",
            [roadmap for roadmap in open_roadmaps if roadmap not in text],
            [],
            [rel(doc), closure_source],
        )
        check(
            checks,
            f"{rel(doc)} references all blocked run classes",
            [run_class for run_class in blocked_classes if run_class not in text],
            [],
            [rel(doc), preflight_source],
        )
        check_contains(checks, f"{rel(doc)} references CALDERA API env input", text, "CALDERA_API_KEY", doc)
        check_contains(
            checks,
            f"{rel(doc)} references macOS token auth command",
            text,
            "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN",
            doc,
        )
        for marker in (
            "AgentId may only contain letters",
            "produced no result",
            "Agent spawn sequential execution failed",
            "-ValidateOnly",
            "auth-env",
            "auth-login",
            "Placeholder env bundle values must be replaced before launch",
        ):
            check_contains(
                checks,
                f"{rel(doc)} references dispatch guard marker {marker}",
                text,
                marker,
                doc,
            )
        check_contains(
            checks,
            f"{rel(doc)} references latest CALDERA repeatability",
            text,
            caldera_repeatability_run,
            doc,
        )
        check(
            checks,
            f"{rel(doc)} references latest CALDERA repeatability coverage on same line",
            line_contains_all(text, [caldera_repeatability_run, caldera_repeatability_coverage]),
            True,
            [rel(doc)],
        )
        for reason in EXPECTED_CALDERA_REPEATABILITY_RESET_REASONS.values():
            check_contains(
                checks,
                f"{rel(doc)} references CALDERA repeatability reset reason {reason}",
                text,
                reason,
                doc,
            )
        check_contains(
            checks,
            f"{rel(doc)} references fresh-restore env input prefix",
            text,
            "TAMANDUA_FRESH_RESTORE_",
            doc,
        )
        check_contains(
            checks,
            f"{rel(doc)} references multi-agent roster emission",
            text,
            "--emit-agent-roster",
            doc,
        )
        check_contains(
            checks,
            f"{rel(doc)} references dependent-wave launcher acknowledgement",
            text,
            "TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH",
            doc,
        )
        check_contains(
            checks,
            f"{rel(doc)} references latest consistency run",
            text,
            consistency_run,
            doc,
        )
        if consistency_latest_fail:
            check_contains(
                checks,
                f"{rel(doc)} references latest superseded consistency fail",
                text,
                str(consistency_latest_fail.get("run_id") or ""),
                doc,
            )
        check_contains(checks, f"{rel(doc)} references latest Windows readiness", text, windows_lab_run, doc)
        check_contains(checks, f"{rel(doc)} references latest macOS backend readiness", text, macos_backend_run, doc)
        if doc.name in {"PARALLEL_EXECUTION_BOARD.md", "REMAINING_VALIDATION_BLOCKERS.md"}:
            check_contains(checks, f"{rel(doc)} references latest Linux eBPF readiness", text, linux_ebpf_run, doc)
    for doc in status_docs[:2]:
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest dispatch results", text, dispatch_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest dispatch coverage on same line",
            line_contains_all(text, [dispatch_run, dispatch_coverage]),
            True,
            [rel(doc)],
        )
        check_contains(checks, f"{rel(doc)} references dispatch coordination boundary", text, "coordination-only", doc)
    for doc in status_docs[:2]:
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest replay", text, replay_run, doc)
    for doc in (status_docs[0], status_docs[2]):
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest Atomic T1047 boundary artifact", text, atomic_t1047_run, doc)
    for doc in FRESH_RESTORE_STATUS_DOCS:
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest fresh restore provenance", text, fresh_restore_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest fresh restore coverage on same line",
            line_contains_all(text, [fresh_restore_run, fresh_restore_coverage]),
            True,
            [rel(doc)],
        )

    failed = sum(1 for item in checks if item["status"] == "FAIL")
    passed = sum(1 for item in checks if item["status"] == "PASS")
    return {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "profile_name": PROFILE_NAME,
        "benchmark_lane": "claim-boundary",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "git": git_snapshot(),
        "external_claim_allowed": False,
        "claim_boundary": (
            "offline consistency audit of validation status docs and generated scorecard; "
            "no endpoint, service, database, live alert, CALDERA, or Proxmox access"
        ),
        "latest": {
            PROFILE_CLOSURE: {"run_id": closure_run, "path": closure_source},
            PROFILE_PREFLIGHT: {"run_id": preflight_run, "path": preflight_source},
            PROFILE_REPLAY: {"run_id": replay_run, "path": replay_source},
            PROFILE_FRESH_RESTORE: {"run_id": fresh_restore_run, "path": fresh_restore_source},
            PROFILE_DISPATCH_RESULTS: {"run_id": dispatch_run, "path": dispatch_source},
            PROFILE_CALDERA_REPEATABILITY: {
                "run_id": caldera_repeatability_run,
                "path": caldera_repeatability_source,
            },
            PROFILE_ID: {"run_id": consistency_run, "path": rel(RUNS_DIR / f"{consistency_run}.json")},
        },
        "summary": {
            "total_checks": len(checks),
            "passed": passed,
            "failed": failed,
        },
        "checks": checks,
    }


def test_id(name: str) -> str:
    cleaned = []
    last_dash = False
    for char in name.lower():
        if char.isalnum():
            cleaned.append(char)
            last_dash = False
        elif not last_dash:
            cleaned.append("-")
            last_dash = True
    return "status-consistency-" + "".join(cleaned).strip("-")


def tests_from_checks(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for item in checks:
        passed = item.get("status") == "PASS"
        tests.append(
            {
                "id": test_id(str(item.get("name") or "check")),
                "name": item.get("name") or "status consistency check",
                "status": "covered" if passed else "missed",
                "gap_category": None if passed else "status-consistency",
                "validation_category": "validation_status_consistency",
                "execution_class": "local_read_only_status_audit",
                "fallback_used": False,
                "claim_level": "status_consistency_claim_boundary",
                "tactics": [],
                "techniques": [],
                "evidence": {
                    "actual": item.get("actual"),
                    "expected": item.get("expected"),
                    "source_files": item.get("source_files") or [],
                },
                "missing_expected_fields": [] if passed else [str(item.get("name") or "check")],
                "missing_expected_telemetry": [],
                "missing_expected_detections": [],
                "missing_expected_alerts": [],
                "missing_expected_correlations": [],
                "missing_expected_driver_raw_event_types": [],
            }
        )
    return tests


def summarize_tests(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for item in tests if item.get("status") == "covered")
    missed = len(tests) - covered
    return {
        "tests": len(tests),
        "total": len(tests),
        "covered": covered,
        "missed": missed,
        "partial": 0,
        "execution_failed": 0,
        "category_coverage": {
            "validation_status_consistency": {"covered": covered, "missed": missed}
        },
    }


def quality_gate(tests: list[dict[str, Any]]) -> dict[str, Any]:
    blocking = [item["id"] for item in tests if item.get("status") != "covered"]
    return {
        "passed": not blocking,
        "status": "pass" if not blocking else "fail",
        "failures": [] if not blocking else ["validation_status_consistency_gaps"],
        "blocking_gaps": blocking,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Validation Status Consistency",
        "",
        "Status: generated (offline audit)",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Git commit: `{payload['git'].get('commit_short') or 'unknown'}`"
        + (" (dirty)" if payload["git"].get("dirty") else ""),
        f"- Checks: {summary['passed']}/{summary['total_checks']} passed; {summary['failed']} failed",
        "- external_claim_allowed: false",
        "",
        "## Latest Artifacts",
        "",
        "| Profile | Run ID | Path |",
        "|---------|--------|------|",
    ]
    for profile_id, latest in payload["latest"].items():
        lines.append(f"| `{profile_id}` | `{latest['run_id']}` | `{latest['path']}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            payload["claim_boundary"],
            "",
            "## Checks",
            "",
            "| Status | Check | Actual | Expected | Sources |",
            "|--------|-------|--------|----------|---------|",
        ]
    )
    for item in payload["checks"]:
        sources = ", ".join(f"`{source}`" for source in item.get("source_files") or [])
        lines.append(
            f"| `{item['status']}` | {item['name']} | `{item.get('actual')}` | "
            f"`{item.get('expected')}` | {sources} |"
        )
    return "\n".join(lines) + "\n"


def render_run_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Validation Status Consistency Probe",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Checks: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- external_claim_allowed: false",
        "",
        "## Latest Artifacts",
        "",
        "| Profile | Run ID | Path |",
        "|---------|--------|------|",
    ]
    for profile_id, latest in report["latest"].items():
        lines.append(f"| `{profile_id}` | `{latest['run_id']}` | `{latest['path']}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            report["claim_boundary"],
            "",
            "## Results",
            "",
            "| Status | Check | Actual | Expected | Sources |",
            "|--------|-------|--------|----------|---------|",
        ]
    )
    for check_item in report["checks"]:
        sources = ", ".join(f"`{source}`" for source in check_item.get("source_files") or [])
        lines.append(
            f"| `{check_item['status']}` | {check_item['name']} | `{check_item.get('actual')}` | "
            f"`{check_item.get('expected')}` | {sources} |"
        )
    return "\n".join(lines) + "\n"


def write_outputs(payload: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{OUTPUT_STEM}.json"
    md_path = output_dir / f"{OUTPUT_STEM}.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    return json_path, md_path


def validate_run_id(run_id: str) -> str:
    if not RUN_ID_RE.match(run_id):
        raise ValueError(f"run_id must match YYYYMMDDTHHMMSSZ-{PROFILE_ID}")
    return run_id


def started_at_from_run_id(run_id: str) -> str:
    stamp = run_id.split("-", 1)[0]
    return datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def resolve_run_id(run_id: str | None = None) -> tuple[str, str]:
    if run_id:
        run_id = validate_run_id(run_id)
        return run_id, started_at_from_run_id(run_id)
    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return f"{compact_stamp(started)}-{PROFILE_ID}", started


def comparison(run_id: str, report: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "status": report["quality_gate"]["status"],
        "quality_gate": {
            "passed": report["quality_gate"]["passed"],
            "status": report["quality_gate"]["status"],
        },
        "score": 90 if report["quality_gate"]["passed"] else 35,
        "summary": report["summary"],
        "category_coverage": report["summary"]["category_coverage"],
        "failures": report["quality_gate"]["failures"],
    }


def write_run_artifacts(payload: dict[str, Any], output_dir: Path, run_id: str | None = None) -> tuple[Path, Path, Path]:
    run_id, started = resolve_run_id(run_id)
    tests = tests_from_checks(payload["checks"])
    gate = quality_gate(tests)
    summary = summarize_tests(tests)
    finished = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    latest = dict(payload.get("latest") or {})
    latest[PROFILE_ID] = {"run_id": run_id, "path": rel(output_dir / f"{run_id}.json")}
    report = {
        **payload,
        "run_id": run_id,
        "started_at": started,
        "finished_at": finished,
        "runtime_effect": "local_read_only_status_audit",
        "tests": tests,
        "latest": latest,
        "summary": summary,
        "quality_gate": gate,
        "scorecard": {
            "score": 90 if gate["passed"] else 35,
            "status": gate["status"],
            "external_claim_allowed": False,
            "recommended_claim": (
                "Validation status docs are aligned with latest generated evidence"
                if gate["passed"]
                else "Validation status docs are stale or inconsistent with latest generated evidence"
            ),
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_run_markdown(report), encoding="utf-8")
    comparison_path.write_text(
        json.dumps(comparison(run_id, report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return json_path, md_path, comparison_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scorecard-json", default=str(SCORECARD_JSON))
    parser.add_argument("--output-dir", default=str(GENERATED_DIR))
    parser.add_argument("--run-output-dir", default=str(RUNS_DIR))
    parser.add_argument("--run-id", help=f"explicit run id matching YYYYMMDDTHHMMSSZ-{PROFILE_ID}")
    parser.add_argument("--skip-run-artifact", action="store_true")
    parser.add_argument("--status-doc", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    status_docs = [Path(path) for path in args.status_doc] if args.status_doc else STATUS_DOCS
    expected_run_id = args.run_id
    if not args.skip_run_artifact:
        expected_run_id, _started = resolve_run_id(args.run_id)
    payload = build_payload(Path(args.scorecard_json), status_docs, expected_run_id)
    json_path, md_path = write_outputs(payload, Path(args.output_dir))
    run_outputs: tuple[Path, Path, Path] | None = None
    if not args.skip_run_artifact:
        run_outputs = write_run_artifacts(payload, Path(args.run_output_dir), expected_run_id)
        payload = build_payload(Path(args.scorecard_json), status_docs, expected_run_id)
        json_path, md_path = write_outputs(payload, Path(args.output_dir))
        run_outputs = write_run_artifacts(payload, Path(args.run_output_dir), expected_run_id)
    summary = payload["summary"]
    run_text = ""
    if run_outputs:
        run_text = " run_artifacts=" + ",".join(rel(path) for path in run_outputs)
    print(
        f"validation_status_consistency={summary['failed'] == 0} "
        f"checks={summary['passed']}/{summary['total_checks']} "
        f"written={rel(json_path)},{rel(md_path)}"
        f"{run_text}"
    )
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
