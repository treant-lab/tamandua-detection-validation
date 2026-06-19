#!/usr/bin/env python3
"""Consolidated closure gate for the active validation roadmaps.

This probe reads the generated validation scorecard and emits a single
claim-boundary artifact for the roadmaps that still gate product validation.
It does not execute endpoints, contact CALDERA, query live alerts, or mutate
server state.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
SCORECARD_JSON = ROOT / "docs" / "benchmarks" / "generated" / "validation_roadmap_scorecard.json"
PROFILE_ID = "roadmap-closure-gate-probe"
PROFILE_NAME = "Roadmap Closure Gate Probe"
ROADMAP_ACTION_TITLES = {
    "A": "Windows P0 segmented and lab readiness",
    "B": "Windows 300 fresh-restore provenance",
    "C": "Atomic upstream smoke",
    "D": "CALDERA repeatability",
    "E": "Linux/macOS P0 sensor smoke",
    "M": "Expanded upstream Atomic/CALDERA",
}
EXCLUDED_ROADMAP_KEYS = {
    "O": "generated_scorecard_automation_not_product_gate",
}


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


def load_optional_artifact(path_value: Any) -> dict[str, Any] | None:
    if not path_value:
        return None
    path = Path(str(path_value))
    if not path.is_absolute():
        path = ROOT / path
    try:
        return load_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def collect_nested_values(value: Any, key: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        current = value.get(key)
        if isinstance(current, list):
            found.extend(clean_text(item) for item in current if item not in (None, "", []))
        elif current:
            found.append(clean_text(current))
        for nested in value.values():
            found.extend(collect_nested_values(nested, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(collect_nested_values(item, key))
    return found


def collect_required_input_envs(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        required_inputs = value.get("required_inputs")
        if isinstance(required_inputs, dict):
            for item in required_inputs.values():
                if isinstance(item, dict) and item.get("env"):
                    found.append(clean_text(item["env"]))
        for nested in value.values():
            found.extend(collect_required_input_envs(nested))
    elif isinstance(value, list):
        for item in value:
            found.extend(collect_required_input_envs(item))
    return found


def clean_text(value: Any) -> str:
    return " ".join(str(value).replace("|", "/").split())


def artifact_gap_summary(artifact: dict[str, Any] | None) -> dict[str, Any]:
    if not artifact:
        return {"required_env": [], "errors": [], "actionable_gap_ids": [], "missing_values": []}

    actionable = []
    quality_gate = artifact.get("quality_gate") if isinstance(artifact.get("quality_gate"), dict) else {}
    for item in quality_gate.get("actionable_gaps") or []:
        if isinstance(item, dict):
            actionable.append(str(item.get("id") or item.get("test_id") or item.get("name") or "unknown"))

    required_env = collect_nested_values(artifact, "required_env")
    errors = collect_nested_values(artifact, "error")
    missing_values = collect_nested_values(artifact, "missing")
    missing_values.extend(collect_nested_values(artifact, "missing_expected_fields"))
    required_env.extend(collect_required_input_envs(artifact))

    return {
        "required_env": sorted(set(required_env)),
        "errors": sorted(set(errors)),
        "actionable_gap_ids": sorted(set(actionable)),
        "missing_values": sorted(set(missing_values)),
    }


def roadmap_list(scorecard: dict[str, Any]) -> list[dict[str, Any]]:
    value = scorecard.get("roadmaps") or scorecard.get("roadmap_status") or []
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def roadmap_key(item: dict[str, Any]) -> str:
    return str(item.get("key") or item.get("roadmap") or "").strip()


def roadmap_title(item: dict[str, Any]) -> str:
    key = roadmap_key(item)
    return str(
        item.get("title")
        or item.get("owner_area")
        or ROADMAP_ACTION_TITLES.get(key)
        or f"Roadmap {key}"
    )


def gated_roadmap_items(scorecard: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    rows = []
    for item in roadmap_list(scorecard):
        key = roadmap_key(item)
        if not key:
            continue
        status = str(item.get("status") or "")
        if key in EXCLUDED_ROADMAP_KEYS:
            continue
        if status == "pass":
            continue
        rows.append((key, roadmap_title(item), item))
    return rows


def excluded_roadmap_items(scorecard: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in roadmap_list(scorecard):
        key = roadmap_key(item)
        if key not in EXCLUDED_ROADMAP_KEYS:
            continue
        rows.append(
            {
                "roadmap": key,
                "title": roadmap_title(item),
                "status": clean_text(item.get("status") or "missing"),
                "reason": EXCLUDED_ROADMAP_KEYS[key],
            }
        )
    return rows


def profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    latest = profile.get("latest") if isinstance(profile.get("latest"), dict) else {}
    aggregate = profile.get("aggregate") if isinstance(profile.get("aggregate"), dict) else {}
    artifact_summary = artifact_gap_summary(load_optional_artifact(latest.get("path")))
    return {
        "profile_id": profile.get("profile_id"),
        "status": profile.get("status"),
        "latest_run_id": latest.get("run_id"),
        "latest_path": latest.get("path"),
        "latest_quality_gate_passed": latest.get("quality_gate_passed"),
        "covered": latest.get("covered"),
        "expected": latest.get("tests") or latest.get("expected_profile_tests"),
        "aggregate_covered": aggregate.get("covered"),
        "aggregate_expected": aggregate.get("expected"),
        "blocking_gaps": latest.get("blocking_gaps") or [],
        "gap_category_counts": latest.get("gap_category_counts") or {},
        "required_env": artifact_summary["required_env"],
        "errors": artifact_summary["errors"],
        "actionable_gap_ids": artifact_summary["actionable_gap_ids"],
        "missing_values": artifact_summary["missing_values"],
    }


def blocking_profiles(roadmap: dict[str, Any]) -> list[dict[str, Any]]:
    profiles = roadmap.get("profiles") or []
    rows: list[dict[str, Any]] = []
    for profile in profiles if isinstance(profiles, list) else []:
        if not isinstance(profile, dict):
            continue
        status = str(profile.get("status") or "")
        if status not in {"pass", "generated"}:
            rows.append(profile_summary(profile))
    return rows


def roadmap_action_text(key: str, blockers: list[dict[str, Any]], required_env: list[str]) -> str:
    if key == "A":
        return (
            "Restore Windows backend readiness and connection stability, verify WIN-TEMPLATE stays online with "
            "live response and endpoint telemetry, then rerun the focused P0 shard before broad Windows execution."
        )
    if key == "B":
        return (
            "Restore the Windows VM, run all six Windows 300 batches with fresh_restore provenance metadata, "
            "then rerun the fresh-restore provenance probe."
        )
    if key == "C":
        return (
            "Install and validate Invoke-AtomicTest plus the Atomics folder on WIN-TEMPLATE, rerun "
            "windows-atomic-upstream-smoke with --require-upstream, and reject fallback-backed evidence."
        )
    if key == "D":
        return (
            "Provide CALDERA_API_KEY and a fresh CALDERA_AGENT_PAW, rerun API shape and PAW readiness, "
            "then collect three consecutive repeatability passes."
        )
    if key == "E":
        if any("tamandua_ctl_auth" in (blocker.get("missing_values") or []) for blocker in blockers):
            return (
                "Refresh tamandua-ctl authentication for the target server, rerun macOS backend readiness, "
                "then reconnect or re-enroll the macOS agent only if readiness still shows agent gaps before "
                "running the server-backed macOS P0 sensor smoke."
            )
        return (
            "Deploy a Developer ID signed/notarized macOS agent that Gatekeeper accepts and that includes "
            "com.apple.developer.endpoint-security.client and com.apple.developer.system-extension.install, "
            "approve the Tamandua System Extension and Full Disk Access, rerun macOS backend readiness, then "
            "run the server-backed macOS P0 sensor smoke."
        )
    if key == "M":
        return (
            "Close Atomic extended with an authoritative green artifact and rerun CALDERA enterprise only after "
            "CALDERA API, PAW readiness, and repeatability are ready."
        )
    if required_env:
        return "Provide required environment inputs, rerun the blocking profiles, then rerun this closure gate."
    if blockers:
        return "Rerun the listed blocking profiles after their local prerequisites are green, then rerun this closure gate."
    return "No roadmap-specific action is required."


def roadmap_next_action(key: str, roadmap: dict[str, Any] | None, blockers: list[dict[str, Any]]) -> dict[str, Any]:
    required_env = sorted(
        {
            clean_text(env)
            for blocker in blockers
            for env in blocker.get("required_env") or []
            if env
        }
    )
    errors = sorted(
        {
            clean_text(error)
            for blocker in blockers
            for error in blocker.get("errors") or []
            if error
        }
    )
    blocking_profile_ids = [
        clean_text(blocker.get("profile_id") or "unknown") for blocker in blockers
    ]
    return {
        "roadmap": key,
        "roadmap_status": clean_text((roadmap or {}).get("status") or "missing"),
        "blocking_profiles": blocking_profile_ids,
        "required_env": required_env,
        "errors": errors,
        "actionable_gap_ids": sorted(
            {
                clean_text(action)
                for blocker in blockers
                for action in blocker.get("actionable_gap_ids") or []
                if action
            }
        ),
        "action": roadmap_action_text(key, blockers, required_env),
    }


def test_result(key: str, title: str, roadmap: dict[str, Any] | None) -> dict[str, Any]:
    if not roadmap:
        passed = False
        status = "missing"
        blockers = [{"profile_id": None, "status": "missing_scorecard_roadmap"}]
    else:
        status = str(roadmap.get("status") or "")
        passed = status == "pass"
        blockers = blocking_profiles(roadmap)
    action = roadmap_next_action(key, roadmap, blockers)

    return {
        "id": f"roadmap-{key.lower()}-closure-gate",
        "name": title,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else "claim-boundary",
        "validation_category": "roadmap_closure_gate",
        "execution_class": "scorecard_read_only_probe",
        "fallback_used": False,
        "claim_level": "roadmap_closure_claim_boundary",
        "tactics": [],
        "techniques": [],
        "evidence": {
            "roadmap_key": key,
            "roadmap_title": roadmap.get("title") if roadmap else title,
            "roadmap_status": status,
            "blocking_profiles": blockers,
            "note": roadmap.get("note") if roadmap else None,
            "next_action": action,
        },
        "missing_expected_fields": [] if passed else ["roadmap_status_pass"],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def summary(tests: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "tests": len(tests),
        "total": len(tests),
        "covered": sum(1 for item in tests if item.get("status") == "covered"),
        "missed": sum(1 for item in tests if item.get("status") == "missed"),
        "partial": 0,
        "execution_failed": 0,
    }


def quality_gate(tests: list[dict[str, Any]]) -> dict[str, Any]:
    missed = [item["id"] for item in tests if item.get("status") != "covered"]
    return {
        "passed": not missed,
        "status": "pass" if not missed else "fail",
        "failures": [] if not missed else ["roadmap_closure_gate_open_items"],
        "blocking_gaps": missed,
    }


def comparison(run_id: str, tests: list[dict[str, Any]], passed: bool) -> dict[str, Any]:
    covered = sum(1 for item in tests if item.get("status") == "covered")
    missed = sum(1 for item in tests if item.get("status") != "covered")
    return {
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "status": "pass" if passed else "fail",
        "quality_gate": {"passed": passed, "status": "pass" if passed else "fail"},
        "score": 90 if passed else 45,
        "summary": {"tests": len(tests), "total": len(tests), "covered": covered, "missed": missed},
        "category_coverage": {"roadmap_closure_gate": {"covered": covered, "missed": missed}},
        "failures": [] if passed else ["roadmap_closure_gate_open_items"],
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    def blocker_text(blocker: dict[str, Any]) -> str:
        profile = clean_text(blocker.get("profile_id") or "unknown")
        status = clean_text(blocker.get("status") or "unknown")
        run_id = clean_text(blocker.get("latest_run_id") or "-")
        covered = blocker.get("covered")
        expected = blocker.get("expected")
        coverage = f" {covered}/{expected}" if covered is not None and expected is not None else ""
        gaps = blocker.get("blocking_gaps") or []
        gap_text = f" gaps:{'/'.join(clean_text(gap) for gap in gaps[:3])}" if gaps else ""
        required_env = blocker.get("required_env") or []
        env_text = f" env:{'/'.join(clean_text(env) for env in required_env[:3])}" if required_env else ""
        errors = blocker.get("errors") or []
        error_text = f" errors:{'/'.join(clean_text(error) for error in errors[:2])}" if errors else ""
        actionable = blocker.get("actionable_gap_ids") or []
        action_text = f" actions:{'/'.join(clean_text(item) for item in actionable[:2])}" if actionable else ""
        return f"{profile}={status}{coverage} @{run_id}{gap_text}{env_text}{error_text}{action_text}"

    required_by_roadmap: dict[str, set[str]] = {}
    errors_by_roadmap: dict[str, set[str]] = {}
    for item in report["tests"]:
        key = str(item.get("evidence", {}).get("roadmap_key") or "")
        required_by_roadmap.setdefault(key, set())
        errors_by_roadmap.setdefault(key, set())
        for blocker in item.get("evidence", {}).get("blocking_profiles") or []:
            if not isinstance(blocker, dict):
                continue
            required_by_roadmap[key].update(clean_text(env) for env in blocker.get("required_env") or [])
            errors_by_roadmap[key].update(clean_text(error) for error in blocker.get("errors") or [])

    lines = [
        "# Roadmap Closure Gate Probe",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Scorecard generated at: `{report['scorecard_generated_at']}`",
        "",
        "## Results",
        "",
        "| Roadmap | Status | Blocking profiles |",
        "|---------|--------|-------------------|",
    ]
    for item in report["tests"]:
        evidence = item["evidence"]
        blockers = evidence.get("blocking_profiles") or []
        blocking_text = ", ".join(
            blocker_text(blocker) for blocker in blockers if isinstance(blocker, dict)
        )
        lines.append(
            f"| `{evidence.get('roadmap_key')}` | `{evidence.get('roadmap_status')}` | `{blocking_text or 'none'}` |"
        )
    lines.extend(
        [
            "",
            "## Immediate Inputs",
            "",
            "| Roadmap | Required env | Preflight errors |",
            "|---------|--------------|------------------|",
        ]
    )
    for key in report.get("gated_roadmaps") or []:
        envs = ", ".join(f"`{env}`" for env in sorted(required_by_roadmap.get(key) or []))
        errors = ", ".join(f"`{error}`" for error in sorted(errors_by_roadmap.get(key) or []))
        lines.append(f"| `{key}` | {envs or '-'} | {errors or '-'} |")
    lines.extend(
        [
            "",
            "## Next Actions",
            "",
            "| Roadmap | Blocking profiles | Required env | Action |",
            "|---------|-------------------|--------------|--------|",
        ]
    )
    for action in report.get("roadmap_next_actions") or []:
        if not isinstance(action, dict):
            continue
        blockers = ", ".join(f"`{clean_text(value)}`" for value in action.get("blocking_profiles") or [])
        envs = ", ".join(f"`{clean_text(value)}`" for value in action.get("required_env") or [])
        lines.append(
            f"| `{clean_text(action.get('roadmap') or '-')}` | {blockers or '-'} | "
            f"{envs or '-'} | {clean_text(action.get('action') or '-')} |"
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
            "## Claim Boundary",
            "",
            "This artifact proves only whether existing generated scorecard evidence satisfies the closure gates. It does not run endpoint commands, does not create CALDERA operations, and does not inspect live alerts.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scorecard-json", default=str(SCORECARD_JSON))
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    args = parser.parse_args()

    started = utc_now()
    run_id = f"{compact_stamp(started)}-{PROFILE_ID}"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scorecard = load_json(Path(args.scorecard_json))
    roadmaps = {roadmap_key(item): item for item in roadmap_list(scorecard)}
    tests = [test_result(key, title, roadmap) for key, title, roadmap in gated_roadmap_items(scorecard)]
    excluded_roadmaps = excluded_roadmap_items(scorecard)
    gate = quality_gate(tests)
    finished = utc_now()

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
        "runtime_effect": "read_only_scorecard",
        "metadata": {"git": git_snapshot()},
        "scorecard_path": str(Path(args.scorecard_json).relative_to(ROOT)),
        "scorecard_generated_at": scorecard.get("generated_at") or scorecard.get("generated"),
        "gated_roadmaps": [item["evidence"]["roadmap_key"] for item in tests],
        "excluded_roadmaps": excluded_roadmaps,
        "roadmap_next_actions": [
            item["evidence"]["next_action"]
            for item in tests
            if item.get("status") != "covered"
        ],
        "tests": tests,
        "summary": summary(tests),
        "quality_gate": gate,
        "scorecard": {"score": 90 if gate["passed"] else 45, "status": gate["status"]},
        "claim_boundary": "Read-only generated-scorecard closure gate; no endpoint/server mutation and no live alert dependency.",
    }

    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    comparison_path.write_text(json.dumps(comparison(run_id, tests, gate["passed"]), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"roadmap_closure_gate={'ok' if gate['passed'] else 'open'} "
        f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
    )
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
