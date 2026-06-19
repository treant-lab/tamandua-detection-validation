#!/usr/bin/env python3
"""Report-only execution preflight for broad validation runs.

This probe answers a narrow scheduling question: is the current shell/state
ready to run broad Windows, Atomic extended, or CALDERA validation profiles?
It reads the latest roadmap closure gate, extracts required environment inputs,
checks whether they are present, and emits a claim-boundary artifact. It never
prints secret values and never contacts endpoints, Proxmox, CALDERA, or the
Tamandua server.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fresh_restore_provenance_probe import REQUIRED_RESTORE_FIELDS, RESTORE_FIELD_INPUTS

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional local convenience
    def load_dotenv(*_args: Any, **_kwargs: Any) -> bool:
        return False


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
SCORECARD_JSON = ROOT / "docs" / "benchmarks" / "generated" / "validation_roadmap_scorecard.json"
PROFILE_ID = "validation-execution-preflight-probe"
PROFILE_NAME = "Validation Execution Preflight Probe"
DEFAULT_TAMANDUA_SERVER = "http://192.168.12.146:4000"
WINDOWS_300_BATCH_PROFILES = [f"windows-roadmap-300-batch-{idx:02d}" for idx in range(1, 7)]

BROAD_RUN_CLASSES = [
    "windows-broad",
    "windows-p1-p2-rerun",
    "windows-atomic-extended",
    "windows-caldera-enterprise",
    "macos-server-backed-smoke",
]

RUN_CLASS_ROADMAPS = {
    "windows-broad": ["A", "B", "M"],
    "windows-p1-p2-rerun": ["A"],
    "windows-atomic-extended": ["M"],
    "windows-caldera-enterprise": ["D", "M"],
    "macos-server-backed-smoke": ["E"],
}

RUN_CLASS_RELEVANT_PROFILES = {
    "windows-broad": None,
    "windows-p1-p2-rerun": {
        "windows-lab-execution-readiness-probe",
        "windows-agent-connection-stability-probe",
        "windows-proxmox-qga-readiness-probe",
        "windows-proxmox-qga-file-diagnostics-probe",
    },
    "windows-atomic-extended": {
        "windows-lab-execution-readiness-probe",
        "windows-agent-connection-stability-probe",
        "windows-atomic-extended-safe",
    },
    "windows-caldera-enterprise": {
        "caldera-api-shape-probe",
        "caldera-paw-readiness-probe",
        "caldera-repeatability-probe",
        "windows-caldera-enterprise-safe",
    },
    "macos-server-backed-smoke": {
        "macos-backend-readiness-probe",
        "macos-roadmap-p0-sensor-contract-smoke",
    },
}

STEP_COMMAND_REQUIRED_ENV = {
    "restore-windows-qga-readiness": ["TAMANDUA_PROXMOX_PASSWORD"],
}
STEP_CONTINUE_ON_FAILURE = {
    "restore-windows-backend-readiness": True,
    "restore-windows-qga-readiness": True,
}

SERVER_PASSWORD_INPUT = {
    "name": "server_password",
    "flag": "--server-password",
    "env": "TAMANDUA_SERVER_PASSWORD",
    "description": "Tamandua backend password used by server-backed Windows readiness and connection-stability probes",
}
MACOS_BOOTSTRAP_READINESS_REPORT_PREREQUISITE = (
    "Copy /var/log/tamandua/macos-bootstrap-readiness.json from the signed/notarized "
    "macOS agent bootstrap and set TAMANDUA_MACOS_BOOTSTRAP_READINESS_REPORT to that local "
    "file before running macOS backend readiness or P0 smoke."
)
MACOS_SIGNED_RELEASE_PREREQUISITE = (
    "Produce and deploy a macOS release app/DMG from the signed/notarized release workflow; "
    "the artifact preflight must pass with a bundled Contents/Library/SystemExtensions/*.systemextension "
    "and the workflow must have Apple signing/notarization secrets configured."
)
MACOS_ENDPOINT_APPROVAL_PREREQUISITE = (
    "On the approved Mac access path, install the signed/notarized app and confirm the Tamandua "
    "System Extension plus Full Disk Access approvals before rerunning backend readiness or P0 smoke."
)
MACOS_NON_PROXMOX_PREREQUISITE = (
    "macOS lane is not a Proxmox VMID/QGA flow; use the approved Mac SSH/local access path "
    "and do not attempt qm/VMID remediation for this blocker."
)
PROXMOX_PASSWORD_INPUT = {
    "name": "proxmox_password",
    "flag": "",
    "env": "TAMANDUA_PROXMOX_PASSWORD",
    "description": "Proxmox API password for QGA readiness and file-diagnostics probes against the disposable Windows VM",
}
CALDERA_OPERATOR_INPUTS = [
    {
        "name": "caldera_api_key",
        "flag": "",
        "env": "CALDERA_API_KEY",
        "description": "CALDERA API key with read access to agents, operations, abilities, and adversaries",
    },
    {
        "name": "caldera_group",
        "flag": "--caldera-group",
        "env": "CALDERA_GROUP",
        "description": "expected lab group for fresh PAW readiness; set to tamandua-lab",
    },
    {
        "name": "caldera_agent_paw",
        "flag": "--caldera-agent-paw",
        "env": "CALDERA_AGENT_PAW",
        "description": "fresh target PAW/sandcat id bound to the disposable lab Windows VM",
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compact_stamp(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace(".", "")[:15] + "Z"


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
    status = run(["git", "status", "--short"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} root must be an object")
    return data


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def latest_closure_gate_from_scorecard(scorecard_path: Path) -> Path | None:
    if not scorecard_path.exists():
        return None
    scorecard = load_json(scorecard_path)
    for profile in scorecard.get("profiles") or []:
        if not isinstance(profile, dict) or profile.get("profile_id") != "roadmap-closure-gate-probe":
            continue
        latest = profile.get("latest") if isinstance(profile.get("latest"), dict) else {}
        path_value = latest.get("path")
        if not path_value:
            return None
        path = Path(str(path_value))
        return path if path.is_absolute() else ROOT / path
    return None


def latest_closure_gate_from_runs(runs_dir: Path) -> Path | None:
    latest: tuple[str, Path] | None = None
    for path in runs_dir.glob("*-roadmap-closure-gate-probe.json"):
        try:
            payload = load_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if payload.get("profile_id") != "roadmap-closure-gate-probe":
            continue
        run_id = str(payload.get("run_id") or path.stem)
        if latest is None or run_id > latest[0]:
            latest = (run_id, path)
    return latest[1] if latest else None


def latest_closure_gate(scorecard_path: Path, runs_dir: Path) -> Path | None:
    candidates = [
        path
        for path in (
            latest_closure_gate_from_scorecard(scorecard_path),
            latest_closure_gate_from_runs(runs_dir),
        )
        if path is not None
    ]
    if not candidates:
        return None

    def run_id_for(path: Path) -> str:
        try:
            return str(load_json(path).get("run_id") or path.stem)
        except (OSError, ValueError, json.JSONDecodeError):
            return path.stem

    return max(candidates, key=run_id_for)


def clean_text(value: Any) -> str:
    return " ".join(str(value).replace("|", "/").split())


def collect_required_env(closure_gate: dict[str, Any]) -> dict[str, list[str]]:
    by_roadmap: dict[str, set[str]] = {}
    for test in closure_gate.get("tests") or []:
        if not isinstance(test, dict):
            continue
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        roadmap = clean_text(evidence.get("roadmap_key") or "unknown")
        by_roadmap.setdefault(roadmap, set())
        for blocker in evidence.get("blocking_profiles") or []:
            if not isinstance(blocker, dict):
                continue
            by_roadmap[roadmap].update(clean_text(env) for env in blocker.get("required_env") or [])
    return {key: sorted(value) for key, value in sorted(by_roadmap.items())}


def collect_roadmap_blockers(closure_gate: dict[str, Any]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    for test in closure_gate.get("tests") or []:
        if not isinstance(test, dict):
            continue
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        roadmap = clean_text(evidence.get("roadmap_key") or "unknown")
        roadmap_status = clean_text(evidence.get("roadmap_status") or "unknown")
        for blocker in evidence.get("blocking_profiles") or []:
            if not isinstance(blocker, dict):
                continue
            blockers.append(
                {
                    "roadmap": roadmap,
                    "roadmap_status": roadmap_status,
                    "profile_id": clean_text(blocker.get("profile_id") or "unknown"),
                    "status": clean_text(blocker.get("status") or "unknown"),
                    "latest_run_id": clean_text(blocker.get("latest_run_id") or "-"),
                    "latest_path": clean_text(blocker.get("latest_path") or "-"),
                    "covered": blocker.get("covered"),
                    "expected": blocker.get("expected"),
                    "required_env": [clean_text(env) for env in blocker.get("required_env") or []],
                    "blocking_gaps": [clean_text(gap) for gap in blocker.get("blocking_gaps") or []],
                    "errors": [clean_text(error) for error in blocker.get("errors") or []],
                    "actionable_gap_ids": [
                        clean_text(action) for action in blocker.get("actionable_gap_ids") or []
                    ],
                }
            )
    return blockers


def collect_roadmap_next_actions(closure_gate: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for action in closure_gate.get("roadmap_next_actions") or []:
        if not isinstance(action, dict) or not action.get("roadmap"):
            continue
        actions.append(
            {
                "roadmap": clean_text(action.get("roadmap")),
                "roadmap_status": clean_text(action.get("roadmap_status") or ""),
                "blocking_profiles": sorted(
                    {clean_text(value) for value in action.get("blocking_profiles") or []}
                ),
                "required_env": sorted(
                    {clean_text(value) for value in action.get("required_env") or []}
                ),
                "errors": sorted({clean_text(value) for value in action.get("errors") or []}),
                "actionable_gap_ids": sorted(
                    {clean_text(value) for value in action.get("actionable_gap_ids") or []}
                ),
                "action": clean_text(action.get("action") or ""),
            }
        )
    return sorted(actions, key=lambda item: str(item.get("roadmap") or ""))


def collect_excluded_roadmaps(closure_gate: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in closure_gate.get("excluded_roadmaps") or []:
        if not isinstance(item, dict):
            continue
        row = {
            "roadmap": clean_text(item.get("roadmap") or ""),
            "title": clean_text(item.get("title") or ""),
            "status": clean_text(item.get("status") or ""),
            "reason": clean_text(item.get("reason") or ""),
        }
        if row["roadmap"] and row["status"] and row["reason"]:
            rows.append(row)
    return sorted(rows, key=lambda item: str(item.get("roadmap") or ""))


def classify_run_classes(
    closure_gate: dict[str, Any],
    required_by_roadmap: dict[str, list[str]],
    missing_env: list[str],
    roadmap_blockers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    open_roadmaps = {
        clean_text(item.get("evidence", {}).get("roadmap_key") or "unknown")
        for item in closure_gate.get("tests") or []
        if isinstance(item, dict) and item.get("status") != "covered"
    }
    missing_env_set = set(missing_env)
    by_roadmap: dict[str, list[dict[str, Any]]] = {}
    for blocker in roadmap_blockers:
        by_roadmap.setdefault(str(blocker.get("roadmap") or "unknown"), []).append(blocker)

    readiness: list[dict[str, Any]] = []
    for run_class in BROAD_RUN_CLASSES:
        roadmaps = RUN_CLASS_ROADMAPS.get(run_class, [])
        relevant_profiles = RUN_CLASS_RELEVANT_PROFILES.get(run_class)
        candidate_blockers = [
            blocker
            for roadmap in roadmaps
            for blocker in by_roadmap.get(roadmap, [])
        ]
        blockers = [
            blocker
            for blocker in candidate_blockers
            if relevant_profiles is None
            or str(blocker.get("profile_id") or "unknown") in relevant_profiles
        ]
        class_open_roadmaps = sorted(
            {
                str(blocker.get("roadmap") or "unknown")
                for blocker in blockers
                if str(blocker.get("roadmap") or "unknown") in open_roadmaps
            }
        )
        class_required_env = sorted(
            {env for blocker in blockers for env in blocker.get("required_env") or []}
        )
        class_missing_env = [env for env in class_required_env if env in missing_env_set]
        readiness.append(
            {
                "run_class": run_class,
                "allowed": not blockers and not class_missing_env,
                "roadmaps": roadmaps,
                "open_roadmaps": class_open_roadmaps,
                "required_env": class_required_env,
                "missing_env": class_missing_env,
                "blocking_profiles": sorted(
                    {str(blocker.get("profile_id") or "unknown") for blocker in blockers}
                ),
                "relevant_profiles": (
                    sorted(relevant_profiles) if relevant_profiles is not None else "all"
                ),
                "blocking_profile_count": len(blockers),
            }
        )
    return readiness


def blockers_for_profiles(
    roadmap_blockers: list[dict[str, Any]], profile_ids: set[str]
) -> list[dict[str, Any]]:
    return [
        blocker
        for blocker in roadmap_blockers
        if str(blocker.get("profile_id") or "") in profile_ids
    ]


def run_classes_for_env(run_class_readiness: list[dict[str, Any]], env_names: set[str]) -> list[str]:
    return sorted(
        str(item.get("run_class"))
        for item in run_class_readiness
        if env_names.intersection(set(item.get("missing_env") or []))
    )


def run_classes_for_profiles(
    run_class_readiness: list[dict[str, Any]], profile_ids: set[str]
) -> list[str]:
    return sorted(
        str(item.get("run_class"))
        for item in run_class_readiness
        if profile_ids.intersection(set(item.get("blocking_profiles") or []))
    )


def summarize_blockers(blockers: list[dict[str, Any]]) -> dict[str, list[str]]:
    return {
        "roadmaps": sorted({str(item.get("roadmap") or "unknown") for item in blockers}),
        "profiles": sorted({str(item.get("profile_id") or "unknown") for item in blockers}),
        "latest_runs": sorted({str(item.get("latest_run_id") or "-") for item in blockers}),
        "errors": sorted(
            {
                str(error)
                for item in blockers
                for error in (item.get("errors") or [])
            }
        ),
        "gaps": sorted(
            {
                str(gap)
                for item in blockers
                for gap in (item.get("blocking_gaps") or [])
            }
        ),
    }


def derive_unblock_sequence(
    required_by_roadmap: dict[str, list[str]],
    missing_env: list[str],
    roadmap_blockers: list[dict[str, Any]],
    run_class_readiness: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []

    def add_step(
        priority: int,
        step_id: str,
        title: str,
        action: str,
        blocked_run_classes: list[str],
        roadmaps: list[str],
        required_env: list[str],
        blockers: list[dict[str, Any]],
    ) -> None:
        summary = summarize_blockers(blockers)
        command_required_env = STEP_COMMAND_REQUIRED_ENV.get(step_id, [])
        steps.append(
            {
                "priority": priority,
                "step_id": step_id,
                "title": title,
                "action": action,
                "blocked_run_classes": sorted(set(blocked_run_classes)),
                "roadmaps": sorted(set(roadmaps or summary["roadmaps"])),
                "required_env": sorted(set(required_env).union(command_required_env)),
                "blocking_profiles": summary["profiles"],
                "latest_runs": summary["latest_runs"],
                "errors": summary["errors"],
                "gaps": summary["gaps"],
                "runtime_effect": "operator_input_or_readiness_work",
            }
        )

    missing_env_set = set(missing_env)
    if missing_env_set:
        env_roadmaps = sorted(
            roadmap
            for roadmap, envs in required_by_roadmap.items()
            if missing_env_set.intersection(set(envs))
        )
        add_step(
            10,
            "provide-required-preflight-env",
            "Provide required preflight environment inputs",
            "Set the missing env vars in the execution shell, then rerun the read-only preflight before any broad shard.",
            run_classes_for_env(run_class_readiness, missing_env_set),
            env_roadmaps,
            sorted(missing_env_set),
            [
                blocker
                for blocker in roadmap_blockers
                if missing_env_set.intersection(set(blocker.get("required_env") or []))
            ],
        )

    windows_backend_profiles = {
        "windows-lab-execution-readiness-probe",
        "windows-agent-connection-stability-probe",
    }
    windows_backend_blockers = blockers_for_profiles(roadmap_blockers, windows_backend_profiles)
    if windows_backend_blockers:
        add_step(
            20,
            "restore-windows-backend-readiness",
            "Restore Windows backend readiness",
            "Prove WIN-TEMPLATE/backend readiness and server-log connection stability before Windows broad or P1/P2 reruns.",
            run_classes_for_profiles(run_class_readiness, windows_backend_profiles),
            ["A"],
            sorted(
                {
                    env
                    for blocker in windows_backend_blockers
                    for env in (blocker.get("required_env") or [])
                }
            ),
            windows_backend_blockers,
        )

    windows_qga_profiles = {
        "windows-proxmox-qga-readiness-probe",
        "windows-proxmox-qga-file-diagnostics-probe",
    }
    windows_qga_blockers = blockers_for_profiles(roadmap_blockers, windows_qga_profiles)
    if windows_qga_blockers:
        add_step(
            25,
            "restore-windows-qga-readiness",
            "Restore Windows Proxmox QGA readiness",
            "Provide Proxmox auth and prove QGA guest-exec or another bounded transport before Windows broad or P1/P2 reruns.",
            run_classes_for_profiles(run_class_readiness, windows_qga_profiles),
            ["A"],
            sorted(
                {
                    env
                    for blocker in windows_qga_blockers
                    for env in (blocker.get("required_env") or [])
                }
            ),
            windows_qga_blockers,
        )

    fresh_restore_profiles = {"fresh-restore-provenance-probe"}
    fresh_restore_blockers = blockers_for_profiles(roadmap_blockers, fresh_restore_profiles)
    if fresh_restore_blockers:
        add_step(
            30,
            "capture-fresh-restore-provenance",
            "Capture Windows fresh-restore provenance",
            "Rerun all six Windows 300 batches after a real VM restore with snapshot, VM, restore timing, agent, and hostname metadata on the batch runner, then run the provenance probe to validate the artifact set before claiming Windows 300 fresh-restore evidence.",
            run_classes_for_profiles(run_class_readiness, fresh_restore_profiles),
            ["B"],
            sorted(
                {
                    str(details["env"])
                    for details in RESTORE_FIELD_INPUTS.values()
                    if details.get("env")
                }
            ),
            fresh_restore_blockers,
        )

    caldera_profiles = {
        "caldera-api-shape-probe",
        "caldera-paw-readiness-probe",
        "caldera-repeatability-probe",
        "windows-caldera-enterprise-safe",
    }
    caldera_blockers = blockers_for_profiles(roadmap_blockers, caldera_profiles)
    if caldera_blockers:
        add_step(
            40,
            "restore-caldera-readiness-repeatability",
            "Restore CALDERA API, PAW, and repeatability readiness",
            "Provide a valid CALDERA API key, verify a fresh PAW, then gather the required consecutive passing CALDERA artifacts before enterprise C2 claims.",
            run_classes_for_profiles(run_class_readiness, caldera_profiles),
            ["D", "M"],
            sorted(
                {
                    env
                    for blocker in caldera_blockers
                    for env in (blocker.get("required_env") or [])
                }
            ),
            caldera_blockers,
        )

    atomic_profiles = {"windows-atomic-extended-safe"}
    atomic_blockers = blockers_for_profiles(roadmap_blockers, atomic_profiles)
    if atomic_blockers:
        add_step(
            50,
            "resolve-atomic-extended-preconditions",
            "Resolve Atomic extended preconditions",
            "Use a WMI-capable disposable target or narrow the claim boundary for T1047 before rerunning Atomic extended.",
            run_classes_for_profiles(run_class_readiness, atomic_profiles),
            ["M"],
            [],
            atomic_blockers,
        )

    macos_profiles = {
        "macos-backend-readiness-probe",
        "macos-roadmap-p0-sensor-contract-smoke",
    }
    macos_blockers = blockers_for_profiles(roadmap_blockers, macos_profiles)
    if macos_blockers:
        add_step(
            60,
            "restore-macos-backend-readiness",
            "Restore macOS backend-backed readiness",
            (
                "Deploy a Developer ID signed/notarized macOS agent that Gatekeeper accepts "
                "and that includes com.apple.developer.endpoint-security.client and "
                "com.apple.developer.system-extension.install, approve the Tamandua System "
                "Extension and Full Disk Access on the Mac, prove backend readiness, then "
                "rerun server-backed macOS P0 sensor smoke."
            ),
            run_classes_for_profiles(run_class_readiness, macos_profiles),
            ["E"],
            [],
            macos_blockers,
        )

    blocked_classes = [
        str(item.get("run_class"))
        for item in run_class_readiness
        if not item.get("allowed")
    ]
    if blocked_classes:
        add_step(
            90,
            "rerun-preflight-and-closure-gate",
            "Rerun preflight, scorecard, and closure gate",
            "After the blocking inputs and readiness probes are green, regenerate the scorecard and rerun the closure gate before scheduling broad validation.",
            blocked_classes,
            sorted({roadmap for item in run_class_readiness for roadmap in item.get("open_roadmaps") or []}),
            [],
            roadmap_blockers,
        )

    return sorted(steps, key=lambda item: (item["priority"], item["step_id"]))


def derive_parallel_unblock_waves(unblock_sequence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group unblock steps into coarse waves that can be assigned independently."""

    wave_by_step = {
        "provide-required-preflight-env": 1,
        "restore-windows-backend-readiness": 1,
        "restore-windows-qga-readiness": 1,
        "resolve-atomic-extended-preconditions": 1,
        "restore-macos-backend-readiness": 1,
        "capture-fresh-restore-provenance": 2,
        "restore-caldera-readiness-repeatability": 2,
        "rerun-preflight-and-closure-gate": 3,
    }
    wave_titles = {
        1: "parallel prerequisite recovery",
        2: "evidence capture after required inputs",
        3: "final local gates after blockers are cleared",
    }
    waves: dict[int, list[dict[str, Any]]] = {}
    for step in unblock_sequence:
        step_id = str(step.get("step_id") or "")
        wave = wave_by_step.get(step_id, 2)
        waves.setdefault(wave, []).append(step)

    result: list[dict[str, Any]] = []
    for wave, steps in sorted(waves.items()):
        result.append(
            {
                "wave": wave,
                "title": wave_titles.get(wave, "parallel unblock work"),
                "parallelizable": len(steps) > 1,
                "step_ids": [str(item.get("step_id")) for item in steps if item.get("step_id")],
                "roadmaps": sorted(
                    {
                        str(roadmap)
                        for item in steps
                        for roadmap in (item.get("roadmaps") or [])
                    }
                ),
                "blocked_run_classes": sorted(
                    {
                        str(run_class)
                        for item in steps
                        for run_class in (item.get("blocked_run_classes") or [])
                    }
                ),
                "depends_on_waves": [prior for prior in sorted(waves) if prior < wave],
            }
        )
    return result


def safe_commands_for_step(step_id: str) -> list[str]:
    fresh_restore_flags = (
        "--fresh-restore "
        "--fresh-restore-started-at $env:TAMANDUA_FRESH_RESTORE_STARTED_AT "
        "--fresh-restore-finished-at $env:TAMANDUA_FRESH_RESTORE_FINISHED_AT "
        "--fresh-restore-snapshot-name $env:TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME "
        "--fresh-restore-snapshot-id $env:TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID "
        "--fresh-restore-vmid $env:TAMANDUA_FRESH_RESTORE_VMID "
        "--fresh-restore-agent-id $env:TAMANDUA_FRESH_RESTORE_AGENT_ID "
        "--fresh-restore-hostname $env:TAMANDUA_FRESH_RESTORE_HOSTNAME"
    )
    windows_300_batch_commands = [
        (
            "python tools/detection_validation/tamandua_detection_validation.py "
            f"--profile tools/detection_validation/profiles/{profile_id.replace('-', '_')}.json "
            "--execute --benchmark-lane enterprise-eval --output-dir $Out "
            f"{fresh_restore_flags} --fail-on-gate"
        )
        for profile_id in WINDOWS_300_BATCH_PROFILES
    ]
    commands = {
        "provide-required-preflight-env": [
            "$Out = Join-Path $env:TEMP 'tamandua-preflight-check'",
            "python tools/detection_validation/validation_execution_preflight_probe.py --output-dir $Out",
        ],
        "restore-windows-backend-readiness": [
            "$Out = Join-Path $env:TEMP 'tamandua-windows-backend-readiness'",
            (
                "python tools/detection_validation/windows_lab_execution_readiness_probe.py "
                f"--server {DEFAULT_TAMANDUA_SERVER} --output-dir $Out"
            ),
            "python tools/detection_validation/windows_agent_connection_stability_probe.py --output-dir $Out",
        ],
        "restore-windows-qga-readiness": [
            "$Out = Join-Path $env:TEMP 'tamandua-windows-qga-readiness'",
            "python tools/detection_validation/windows_proxmox_qga_readiness_probe.py --output-dir $Out",
            "python tools/detection_validation/windows_proxmox_qga_file_diagnostics_probe.py --output-dir $Out",
        ],
        "capture-fresh-restore-provenance": [
            "$Out = Join-Path $env:TEMP 'tamandua-fresh-restore-provenance'",
            *windows_300_batch_commands,
            "python tools/detection_validation/fresh_restore_provenance_probe.py --output-dir $Out",
        ],
        "restore-caldera-readiness-repeatability": [
            "$Out = Join-Path $env:TEMP 'tamandua-caldera-readiness'",
            "python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out",
            "python tools/detection_validation/caldera_paw_readiness_probe.py --output-dir $Out",
            "python tools/detection_validation/caldera_repeatability_probe.py --output-dir $Out",
        ],
        "resolve-atomic-extended-preconditions": [
            "$Out = Join-Path $env:TEMP 'tamandua-atomic-t1047-boundary'",
            "python tools/detection_validation/atomic_t1047_lab_capability_probe.py --output-dir $Out",
        ],
        "restore-macos-backend-readiness": [
            "$Out = Join-Path $env:TEMP 'tamandua-macos-readiness'",
            "$BootstrapReadinessReport = $env:TAMANDUA_MACOS_BOOTSTRAP_READINESS_REPORT",
            (
                "if (-not $BootstrapReadinessReport) { throw "
                "'Set TAMANDUA_MACOS_BOOTSTRAP_READINESS_REPORT to the copied "
                "/var/log/tamandua/macos-bootstrap-readiness.json before macOS P0 smoke.' }"
            ),
            (
                "python tools/detection_validation/macos_backend_readiness_probe.py "
                f"--server {DEFAULT_TAMANDUA_SERVER} --output-dir $Out "
                "--bootstrap-readiness-report $BootstrapReadinessReport"
            ),
            (
                "powershell -File deploy/scripts/proxmox/run-macos-p0-smoke.ps1 "
                "-OutputDir $Out -BootstrapReadinessReport $BootstrapReadinessReport -NoFailOnGate"
            ),
        ],
        "rerun-preflight-and-closure-gate": [
            "$Out = Join-Path $env:TEMP 'tamandua-final-local-gates'",
            "python tools/detection_validation/generate_validation_scorecard.py",
            "python tools/detection_validation/roadmap_closure_gate_probe.py --output-dir $Out",
            "python tools/detection_validation/validation_execution_preflight_probe.py --output-dir $Out",
        ],
    }
    return commands.get(step_id, [])


def expected_profile_ids_for_step(step_id: str) -> list[str]:
    expected_profiles = {
        "provide-required-preflight-env": [
            "validation-execution-preflight-probe",
        ],
        "restore-windows-backend-readiness": [
            "windows-lab-execution-readiness-probe",
            "windows-agent-connection-stability-probe",
        ],
        "restore-windows-qga-readiness": [
            "windows-proxmox-qga-readiness-probe",
            "windows-proxmox-qga-file-diagnostics-probe",
        ],
        "capture-fresh-restore-provenance": [
            "fresh-restore-provenance-probe",
        ],
        "restore-caldera-readiness-repeatability": [
            "caldera-api-shape-probe",
            "caldera-paw-readiness-probe",
            "caldera-repeatability-probe",
        ],
        "resolve-atomic-extended-preconditions": [
            "atomic-t1047-lab-capability-probe",
        ],
        "restore-macos-backend-readiness": [
            "macos-backend-readiness-probe",
        ],
        "rerun-preflight-and-closure-gate": [
            "roadmap-closure-gate-probe",
            "validation-execution-preflight-probe",
        ],
    }
    return expected_profiles.get(step_id, [])


def operator_inputs_for_step(step_id: str) -> list[dict[str, str]]:
    fresh_restore_inputs = [
        {
            "name": field,
            "flag": str(RESTORE_FIELD_INPUTS[field]["flag"]),
            "env": str(RESTORE_FIELD_INPUTS[field]["env"]),
            "description": str(RESTORE_FIELD_INPUTS[field]["description"]),
        }
        for field in REQUIRED_RESTORE_FIELDS
    ]
    if step_id == "capture-fresh-restore-provenance":
        return fresh_restore_inputs
    if step_id == "restore-caldera-readiness-repeatability":
        return CALDERA_OPERATOR_INPUTS
    if step_id == "restore-windows-backend-readiness":
        return [SERVER_PASSWORD_INPUT]
    if step_id == "restore-windows-qga-readiness":
        return [PROXMOX_PASSWORD_INPUT, SERVER_PASSWORD_INPUT]
    if step_id in {"provide-required-preflight-env", "rerun-preflight-and-closure-gate"}:
        return [
            *CALDERA_OPERATOR_INPUTS,
            *fresh_restore_inputs,
            SERVER_PASSWORD_INPUT,
            PROXMOX_PASSWORD_INPUT,
        ]
    return []


def manual_prerequisites_for_step(step_id: str) -> list[str]:
    prerequisites = {
        "capture-fresh-restore-provenance": [
            "Restore or snapshot WIN-TEMPLATE before rerunning the six Windows 300 batch profiles.",
            "Pass the same fresh-restore metadata to every Windows 300 batch runner invocation.",
            "Do not run the six Windows 300 batches in parallel on the single restored target.",
            "Run fresh_restore_provenance_probe.py after the six batch artifacts exist.",
        ],
        "restore-caldera-readiness-repeatability": [
            "Use only a disposable lab Windows VM, not an operator workstation.",
            "Start a fresh sandcat/PAW in CALDERA group tamandua-lab.",
            "Set CALDERA_API_KEY, CALDERA_GROUP=tamandua-lab, and CALDERA_AGENT_PAW before readiness or enterprise runs.",
            "Require three consecutive passing artifacts before claiming repeatability.",
        ],
        "restore-macos-backend-readiness": [
            MACOS_SIGNED_RELEASE_PREREQUISITE,
            MACOS_ENDPOINT_APPROVAL_PREREQUISITE,
            MACOS_BOOTSTRAP_READINESS_REPORT_PREREQUISITE,
            MACOS_NON_PROXMOX_PREREQUISITE,
        ],
    }
    return prerequisites.get(step_id, [])


def derive_parallel_work_packages(
    unblock_sequence: list[dict[str, Any]],
    parallel_unblock_waves: list[dict[str, Any]],
    roadmap_next_actions: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Create concrete handoff packages for independent agents/operators."""

    roadmap_next_actions = roadmap_next_actions or []
    actions_by_roadmap = {
        str(action.get("roadmap")): action
        for action in roadmap_next_actions
        if isinstance(action, dict) and action.get("roadmap")
    }
    wave_by_step: dict[str, dict[str, Any]] = {}
    for wave in parallel_unblock_waves:
        for step_id in wave.get("step_ids") or []:
            wave_by_step[str(step_id)] = wave

    packages: list[dict[str, Any]] = []
    for step in unblock_sequence:
        step_id = str(step.get("step_id") or "")
        if not step_id:
            continue
        wave = wave_by_step.get(step_id, {})
        package_roadmaps = sorted({str(item) for item in step.get("roadmaps") or []})
        packages.append(
            {
                "package_id": f"wave-{wave.get('wave', 0)}-{step_id}",
                "wave": wave.get("wave"),
                "title": step.get("title") or step_id,
                "step_id": step_id,
                "roadmaps": package_roadmaps,
                "roadmap_next_actions": [
                    actions_by_roadmap[roadmap]
                    for roadmap in package_roadmaps
                    if roadmap in actions_by_roadmap
                ],
                "blocked_run_classes": sorted(
                    {str(item) for item in step.get("blocked_run_classes") or []}
                ),
                "required_env": sorted({str(item) for item in step.get("required_env") or []}),
                "blocking_profiles": sorted(
                    {str(item) for item in step.get("blocking_profiles") or []}
                ),
                "depends_on_waves": wave.get("depends_on_waves") or [],
                "parallelizable_in_wave": bool(wave.get("parallelizable")),
                "continue_on_failure": bool(STEP_CONTINUE_ON_FAILURE.get(step_id)),
                "recommended_owner_role": (
                    "operator-or-secret-holder"
                    if step.get("required_env")
                    else "validation-agent"
                ),
                "expected_profile_ids": expected_profile_ids_for_step(step_id),
                "operator_inputs": operator_inputs_for_step(step_id),
                "manual_prerequisites": manual_prerequisites_for_step(step_id),
                "safe_commands": safe_commands_for_step(step_id),
                "action": step.get("action") or "",
                "runtime_effect": step.get("runtime_effect") or "operator_input_or_readiness_work",
            }
        )
    return sorted(packages, key=lambda item: (item.get("wave") or 0, str(item.get("step_id"))))


def env_present(name: str) -> bool:
    return bool(os.environ.get(name))


def test_row(
    test_id: str,
    name: str,
    status: str,
    evidence: dict[str, Any],
    missing_fields: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": status,
        "gap_category": None if status == "covered" else "preflight",
        "validation_category": "validation_execution_preflight",
        "execution_class": "local_read_only_preflight",
        "fallback_used": False,
        "claim_level": "execution_scheduling_claim_boundary",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": missing_fields or [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def build_tests(closure_path: Path | None, closure_gate: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not closure_path or not closure_gate:
        return [
            test_row(
                "execution-preflight-closure-gate-present",
                "Latest roadmap closure gate artifact is available",
                "missed",
                {"closure_gate_path": rel(closure_path) if closure_path else None},
                ["roadmap_closure_gate_artifact"],
            )
        ]

    gate_passed = bool((closure_gate.get("quality_gate") or {}).get("passed"))
    required_by_roadmap = collect_required_env(closure_gate)
    roadmap_blockers = collect_roadmap_blockers(closure_gate)
    roadmap_next_actions = collect_roadmap_next_actions(closure_gate)
    unique_required = sorted({env for envs in required_by_roadmap.values() for env in envs})
    missing_env = [name for name in unique_required if not env_present(name)]
    present_env = [name for name in unique_required if env_present(name)]
    run_class_readiness = classify_run_classes(
        closure_gate, required_by_roadmap, missing_env, roadmap_blockers
    )
    unblock_sequence = derive_unblock_sequence(
        required_by_roadmap, missing_env, roadmap_blockers, run_class_readiness
    )
    parallel_unblock_waves = derive_parallel_unblock_waves(unblock_sequence)
    parallel_work_packages = derive_parallel_work_packages(
        unblock_sequence, parallel_unblock_waves, roadmap_next_actions
    )
    open_roadmaps = [
        str(item.get("evidence", {}).get("roadmap_key"))
        for item in closure_gate.get("tests") or []
        if isinstance(item, dict) and item.get("status") != "covered"
    ]

    tests = [
        test_row(
            "execution-preflight-closure-gate-present",
            "Latest roadmap closure gate artifact is available",
            "covered",
            {
                "closure_gate_path": rel(closure_path),
                "closure_gate_run_id": closure_gate.get("run_id"),
                "closure_gate_passed": gate_passed,
            },
        ),
        test_row(
            "execution-preflight-required-env-present",
            "Required preflight environment variables are present in this shell",
            "covered" if not missing_env else "missed",
            {
                "required_env_by_roadmap": required_by_roadmap,
                "required_env_present": present_env,
                "required_env_missing": missing_env,
                "secret_values_exposed": False,
            },
            missing_env,
        ),
        test_row(
            "execution-preflight-closure-gate-green",
            "Roadmap closure gate is green before broad execution",
            "covered" if gate_passed else "missed",
            {
                "closure_gate_run_id": closure_gate.get("run_id"),
                "closure_gate_passed": gate_passed,
                "open_roadmaps": sorted(set(open_roadmaps)),
                "blocking_gaps": (closure_gate.get("quality_gate") or {}).get("blocking_gaps") or [],
            },
            [] if gate_passed else ["roadmap_closure_gate_passed"],
        ),
        test_row(
            "execution-preflight-roadmap-blockers-summarized",
            "Roadmap blocker profiles are summarized for scheduling triage",
            "covered",
            {
                "closure_gate_run_id": closure_gate.get("run_id"),
                "roadmap_blockers": roadmap_blockers,
                "roadmap_blocker_count": len(roadmap_blockers),
                "secret_values_exposed": False,
            },
        ),
        test_row(
            "execution-preflight-run-class-readiness-summarized",
            "Run class readiness is summarized before broad scheduling",
            "covered",
            {
                "run_class_readiness": run_class_readiness,
                "blocked_run_classes": [
                    item["run_class"] for item in run_class_readiness if not item.get("allowed")
                ],
                "allowed_run_classes": [
                    item["run_class"] for item in run_class_readiness if item.get("allowed")
                ],
                "secret_values_exposed": False,
            },
        ),
        test_row(
            "execution-preflight-unblock-sequence-summarized",
            "Unblock sequence is summarized before broad scheduling",
            "covered",
            {
                "unblock_sequence": unblock_sequence,
                "roadmap_next_actions": roadmap_next_actions,
                "unblock_step_count": len(unblock_sequence),
                "secret_values_exposed": False,
            },
        ),
        test_row(
            "execution-preflight-parallel-unblock-waves-summarized",
            "Parallel unblock waves are summarized for multi-agent scheduling",
            "covered",
            {
                "parallel_unblock_waves": parallel_unblock_waves,
                "parallel_work_packages": parallel_work_packages,
                "parallel_wave_count": len(parallel_unblock_waves),
                "parallel_work_package_count": len(parallel_work_packages),
                "parallelizable_wave_count": sum(
                    1 for item in parallel_unblock_waves if item.get("parallelizable")
                ),
                "secret_values_exposed": False,
            },
        ),
    ]
    blocked_run_classes = [
        item["run_class"] for item in run_class_readiness if not item.get("allowed")
    ]
    allowed = gate_passed and not missing_env and not blocked_run_classes
    tests.append(
        test_row(
            "execution-preflight-broad-runs-allowed",
            "Broad validation runs are allowed from this shell",
            "covered" if allowed else "missed",
            {
                "allowed": allowed,
                "blocked_run_classes": blocked_run_classes,
                "allowed_run_classes": [
                    item["run_class"] for item in run_class_readiness if item.get("allowed")
                ],
                "reason": "ready" if allowed else "closure_gate_or_required_env_not_ready",
            },
            [] if allowed else ["broad_execution_preflight_green"],
        )
    )
    return tests


def summarize(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for item in tests if item.get("status") == "covered")
    missed = sum(1 for item in tests if item.get("status") != "covered")
    return {
        "tests": len(tests),
        "total": len(tests),
        "covered": covered,
        "missed": missed,
        "partial": 0,
        "execution_failed": 0,
        "category_coverage": {
            "validation_execution_preflight": {"covered": covered, "missed": missed}
        },
    }


def quality_gate(tests: list[dict[str, Any]]) -> dict[str, Any]:
    missed = [item["id"] for item in tests if item.get("status") != "covered"]
    return {
        "passed": not missed,
        "status": "pass" if not missed else "fail",
        "failures": [] if not missed else ["validation_execution_preflight_gaps"],
        "blocking_gaps": missed,
    }


def comparison(run_id: str, tests: list[dict[str, Any]], gate: dict[str, Any]) -> dict[str, Any]:
    summary = summarize(tests)
    return {
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "status": gate["status"],
        "quality_gate": {"passed": gate["passed"], "status": gate["status"]},
        "score": 90 if gate["passed"] else 35,
        "summary": summary,
        "category_coverage": summary["category_coverage"],
        "failures": gate["failures"],
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    env_test = next((item for item in report["tests"] if item["id"] == "execution-preflight-required-env-present"), {})
    env_evidence = env_test.get("evidence") or {}
    gate_test = next((item for item in report["tests"] if item["id"] == "execution-preflight-closure-gate-green"), {})
    gate_evidence = gate_test.get("evidence") or {}
    allow_test = next((item for item in report["tests"] if item["id"] == "execution-preflight-broad-runs-allowed"), {})
    allow_evidence = allow_test.get("evidence") or {}
    blockers_test = next(
        (item for item in report["tests"] if item["id"] == "execution-preflight-roadmap-blockers-summarized"),
        {},
    )
    blockers_evidence = blockers_test.get("evidence") or {}
    class_test = next(
        (item for item in report["tests"] if item["id"] == "execution-preflight-run-class-readiness-summarized"),
        {},
    )
    class_evidence = class_test.get("evidence") or {}
    sequence_test = next(
        (item for item in report["tests"] if item["id"] == "execution-preflight-unblock-sequence-summarized"),
        {},
    )
    sequence_evidence = sequence_test.get("evidence") or {}
    parallel_test = next(
        (item for item in report["tests"] if item["id"] == "execution-preflight-parallel-unblock-waves-summarized"),
        {},
    )
    parallel_evidence = parallel_test.get("evidence") or {}
    lines = [
        "# Validation Execution Preflight Probe",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Closure gate: `{report.get('closure_gate_run_id') or '-'}`",
        f"- Broad runs allowed: `{str(allow_evidence.get('allowed', False)).lower()}`",
        "",
        "## Required Inputs",
        "",
        "| Env var | Present | Roadmaps |",
        "|---------|---------|----------|",
    ]
    by_roadmap = env_evidence.get("required_env_by_roadmap") or {}
    env_to_roadmaps: dict[str, list[str]] = {}
    for roadmap, envs in by_roadmap.items():
        for env in envs:
            env_to_roadmaps.setdefault(env, []).append(roadmap)
    for env in sorted(env_to_roadmaps):
        present = "yes" if env in (env_evidence.get("required_env_present") or []) else "no"
        roadmaps = ", ".join(f"`{roadmap}`" for roadmap in sorted(env_to_roadmaps[env]))
        lines.append(f"| `{env}` | `{present}` | {roadmaps} |")
    if not env_to_roadmaps:
        lines.append("| - | - | - |")
    lines.extend(
        [
            "",
            "## Closure Gate",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Closure gate passed | `{str(gate_evidence.get('closure_gate_passed', False)).lower()}` |",
            "| Open roadmaps | "
            + (
                ", ".join(f"`{roadmap}`" for roadmap in gate_evidence.get("open_roadmaps") or [])
                or "-"
            )
            + " |",
            "| Blocking gaps | "
            + (
                ", ".join(f"`{gap}`" for gap in gate_evidence.get("blocking_gaps") or [])
                or "-"
            )
            + " |",
        ]
    )
    excluded = [item for item in report.get("excluded_roadmaps") or [] if isinstance(item, dict)]
    if excluded:
        lines.extend(
            [
                "",
                "## Excluded Roadmaps",
                "",
                "| Roadmap | Status | Reason |",
                "|---------|--------|--------|",
            ]
        )
        for item in excluded:
            lines.append(
                f"| `{clean_text(item.get('roadmap') or '-')}` | "
                f"`{clean_text(item.get('status') or '-')}` | "
                f"{clean_text(item.get('reason') or '-')} |"
            )
    lines.extend(
        [
            "",
            "## Results",
            "",
            "| Status | Test | Missing fields |",
            "|--------|------|----------------|",
        ]
    )
    for item in report["tests"]:
        missing = ", ".join(f"`{field}`" for field in item.get("missing_expected_fields") or [])
        lines.append(f"| `{item['status']}` | {item['name']} | {missing or '-'} |")
    lines.extend(
        [
            "",
            "## Roadmap Next Actions",
            "",
            "| Roadmap | Blocking profiles | Required env | Action |",
            "|---------|-------------------|--------------|--------|",
        ]
    )
    for action in sequence_evidence.get("roadmap_next_actions") or report.get("roadmap_next_actions") or []:
        blockers = ", ".join(f"`{value}`" for value in action.get("blocking_profiles") or []) or "-"
        envs = ", ".join(f"`{value}`" for value in action.get("required_env") or []) or "-"
        lines.append(
            f"| `{action.get('roadmap')}` | {blockers} | {envs} | {clean_text(action.get('action') or '-')} |"
        )
    if not (sequence_evidence.get("roadmap_next_actions") or report.get("roadmap_next_actions")):
        lines.append("| - | - | - | - |")
    lines.extend(
        [
            "",
            "## Roadmap Blockers",
            "",
            "| Roadmap | Profile | Status | Latest run | Coverage | Required env | Gaps | Errors | Actions |",
            "|---------|---------|--------|------------|----------|--------------|------|--------|---------|",
        ]
    )
    for blocker in blockers_evidence.get("roadmap_blockers") or []:
        covered = blocker.get("covered")
        expected = blocker.get("expected")
        coverage = f"`{covered}/{expected}`" if covered is not None and expected is not None else "-"
        envs = ", ".join(f"`{env}`" for env in blocker.get("required_env") or []) or "-"
        gaps = ", ".join(f"`{gap}`" for gap in blocker.get("blocking_gaps") or []) or "-"
        errors = ", ".join(f"`{error}`" for error in blocker.get("errors") or []) or "-"
        actions = ", ".join(f"`{action}`" for action in blocker.get("actionable_gap_ids") or []) or "-"
        lines.append(
            f"| `{blocker.get('roadmap')}` | `{blocker.get('profile_id')}` | "
            f"`{blocker.get('status')}` | `{blocker.get('latest_run_id')}` | "
            f"{coverage} | {envs} | {gaps} | {errors} | {actions} |"
        )
    if not blockers_evidence.get("roadmap_blockers"):
        lines.append("| - | - | - | - | - | - | - | - | - |")
    lines.extend(
        [
            "",
            "## Run Class Readiness",
            "",
            "| Run class | Allowed | Roadmaps | Open roadmaps | Missing env | Blocking profiles |",
            "|-----------|---------|----------|---------------|-------------|-------------------|",
        ]
    )
    for item in class_evidence.get("run_class_readiness") or []:
        roadmaps = ", ".join(f"`{roadmap}`" for roadmap in item.get("roadmaps") or []) or "-"
        open_roadmaps = ", ".join(f"`{roadmap}`" for roadmap in item.get("open_roadmaps") or []) or "-"
        missing_env = ", ".join(f"`{env}`" for env in item.get("missing_env") or []) or "-"
        profiles = ", ".join(f"`{profile}`" for profile in item.get("blocking_profiles") or []) or "-"
        lines.append(
            f"| `{item.get('run_class')}` | `{str(item.get('allowed', False)).lower()}` | "
            f"{roadmaps} | {open_roadmaps} | {missing_env} | {profiles} |"
        )
    if not class_evidence.get("run_class_readiness"):
        lines.append("| - | - | - | - | - | - |")
    lines.extend(
        [
            "",
            "## Unblock Sequence",
            "",
            "| Priority | Step | Blocked classes | Roadmaps | Required env | Blocking profiles | Action |",
            "|----------|------|-----------------|----------|--------------|-------------------|--------|",
        ]
    )
    for item in sequence_evidence.get("unblock_sequence") or []:
        classes = ", ".join(f"`{value}`" for value in item.get("blocked_run_classes") or []) or "-"
        roadmaps = ", ".join(f"`{value}`" for value in item.get("roadmaps") or []) or "-"
        envs = ", ".join(f"`{value}`" for value in item.get("required_env") or []) or "-"
        profiles = ", ".join(f"`{value}`" for value in item.get("blocking_profiles") or []) or "-"
        lines.append(
            f"| `{item.get('priority')}` | `{item.get('step_id')}` | {classes} | "
            f"{roadmaps} | {envs} | {profiles} | {clean_text(item.get('action') or '-')} |"
        )
    if not sequence_evidence.get("unblock_sequence"):
        lines.append("| - | - | - | - | - | - | - |")
    lines.extend(
        [
            "",
            "## Parallel Unblock Waves",
            "",
            "| Wave | Parallelizable | Steps | Roadmaps | Blocked classes | Depends on |",
            "|------|----------------|-------|----------|-----------------|------------|",
        ]
    )
    for item in parallel_evidence.get("parallel_unblock_waves") or report.get("parallel_unblock_waves") or []:
        steps = ", ".join(f"`{value}`" for value in item.get("step_ids") or []) or "-"
        roadmaps = ", ".join(f"`{value}`" for value in item.get("roadmaps") or []) or "-"
        classes = ", ".join(f"`{value}`" for value in item.get("blocked_run_classes") or []) or "-"
        depends = ", ".join(f"`{value}`" for value in item.get("depends_on_waves") or []) or "-"
        lines.append(
            f"| `{item.get('wave')}` | `{str(item.get('parallelizable', False)).lower()}` | "
            f"{steps} | {roadmaps} | {classes} | {depends} |"
        )
    if not (parallel_evidence.get("parallel_unblock_waves") or report.get("parallel_unblock_waves")):
        lines.append("| - | - | - | - | - | - |")
    work_packages = (
        parallel_evidence.get("parallel_work_packages")
        or report.get("parallel_work_packages")
        or []
    )
    lines.extend(
        [
            "",
            "## Parallel Work Packages",
            "",
            "| Package | Wave | Owner role | Roadmaps | Blocked classes | Required env | Depends on | Safe commands | Action |",
            "|---------|------|------------|----------|-----------------|--------------|------------|---------------|--------|",
        ]
    )
    for item in work_packages:
        roadmaps = ", ".join(f"`{value}`" for value in item.get("roadmaps") or []) or "-"
        classes = ", ".join(f"`{value}`" for value in item.get("blocked_run_classes") or []) or "-"
        envs = ", ".join(f"`{value}`" for value in item.get("required_env") or []) or "-"
        depends = ", ".join(f"`{value}`" for value in item.get("depends_on_waves") or []) or "-"
        commands = "<br>".join(
            f"`{clean_text(value)}`" for value in item.get("safe_commands") or []
        ) or "-"
        lines.append(
            f"| `{item.get('package_id')}` | `{item.get('wave')}` | "
            f"`{item.get('recommended_owner_role')}` | {roadmaps} | {classes} | "
            f"{envs} | {depends} | {commands} | {clean_text(item.get('action') or '-')} |"
        )
    if not work_packages:
        lines.append("| - | - | - | - | - | - | - | - | - |")
    blocked = allow_evidence.get("blocked_run_classes") or []
    lines.extend(
        [
            "",
            "## Blocked Run Classes",
            "",
            ", ".join(f"`{item}`" for item in blocked) if blocked else "-",
            "",
            "## Claim Boundary",
            "",
            report["claim_boundary"],
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    load_dotenv(ROOT / ".env")

    parser = argparse.ArgumentParser()
    parser.add_argument("--scorecard-json", default=str(SCORECARD_JSON))
    parser.add_argument("--closure-gate-json", default="")
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    parser.add_argument("--run-id", default="", help="Optional explicit run id for regenerating an existing artifact.")
    args = parser.parse_args()

    started = utc_now()
    run_id = args.run_id or f"{compact_stamp(started)}-{PROFILE_ID}"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    closure_path = (
        Path(args.closure_gate_json)
        if args.closure_gate_json
        else latest_closure_gate(Path(args.scorecard_json), RUNS_DIR)
    )
    if closure_path and not closure_path.is_absolute():
        closure_path = ROOT / closure_path
    closure_gate = load_json(closure_path) if closure_path and closure_path.exists() else None
    tests = build_tests(closure_path, closure_gate)
    gate = quality_gate(tests)
    finished = utc_now()

    required_by_roadmap = collect_required_env(closure_gate) if closure_gate else {}
    roadmap_blockers = collect_roadmap_blockers(closure_gate) if closure_gate else []
    roadmap_next_actions = collect_roadmap_next_actions(closure_gate) if closure_gate else []
    excluded_roadmaps = collect_excluded_roadmaps(closure_gate) if closure_gate else []
    missing_env = [
        env
        for env in sorted({env for envs in required_by_roadmap.values() for env in envs})
        if not env_present(env)
    ]
    run_class_readiness = (
        classify_run_classes(closure_gate, required_by_roadmap, missing_env, roadmap_blockers)
        if closure_gate
        else []
    )
    unblock_sequence = derive_unblock_sequence(
        required_by_roadmap, missing_env, roadmap_blockers, run_class_readiness
    )
    parallel_unblock_waves = derive_parallel_unblock_waves(unblock_sequence)
    parallel_work_packages = derive_parallel_work_packages(
        unblock_sequence, parallel_unblock_waves, roadmap_next_actions
    )

    report: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "profile_name": PROFILE_NAME,
        "benchmark_lane": "claim-boundary",
        "started_at": started,
        "finished_at": finished,
        "generated_at": finished,
        "runtime_effect": "local_read_only_preflight",
        "metadata": {"git": git_snapshot()},
        "closure_gate_path": rel(closure_path) if closure_path else None,
        "closure_gate_run_id": closure_gate.get("run_id") if closure_gate else None,
        "excluded_roadmaps": excluded_roadmaps,
        "roadmap_next_actions": roadmap_next_actions,
        "roadmap_blockers": roadmap_blockers,
        "run_class_readiness": run_class_readiness,
        "unblock_sequence": unblock_sequence,
        "parallel_unblock_waves": parallel_unblock_waves,
        "parallel_work_packages": parallel_work_packages,
        "tests": tests,
        "summary": summarize(tests),
        "quality_gate": gate,
        "scorecard": {
            "score": 90 if gate["passed"] else 35,
            "status": gate["status"],
            "external_claim_allowed": False,
            "recommended_claim": (
                "Broad validation execution preflight is green"
                if gate["passed"]
                else "Broad validation execution remains blocked by closure gate and/or missing preflight inputs"
            ),
        },
        "claim_boundary": (
            "Local read-only scheduling preflight only. This artifact checks whether "
            "the latest closure gate is green and whether required environment inputs "
            "are present in this shell. It does not expose secret values, run endpoint "
            "commands, create CALDERA operations, query live alerts, or mutate server state."
        ),
    }

    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    comparison_path.write_text(
        json.dumps(comparison(run_id, tests, gate), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"validation_execution_preflight={'ok' if gate['passed'] else 'blocked'} "
        f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
    )
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
