#!/usr/bin/env python3
"""Read-only Windows lab execution readiness probe.

This probe records whether the dedicated Windows validation target is ready
for broad Windows, Atomic extended, or CALDERA enterprise execution. It uses
authenticated `tamandua-ctl remote agents list --json` only; it does not run
endpoint commands and does not inspect live alerts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
DEFAULT_CTL = ROOT / "apps" / "tamandua_ctl" / "target" / "release" / "tamandua-ctl.exe"
PROFILE_ID = "windows-lab-execution-readiness-probe"
PROFILE_NAME = "Windows Lab Execution Readiness Probe"


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


def run_ctl(ctl_path: Path, server: str | None) -> dict[str, Any]:
    cmd = [str(ctl_path), "remote", "agents", "list", "--json"]
    if server:
        cmd.extend(["--server", server])
    try:
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc), "command": " ".join(cmd)}

    payload: dict[str, Any] | None = None
    if completed.returncode == 0:
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            return {
                "ok": False,
                "exit_code": completed.returncode,
                "stdout_tail": completed.stdout[-2000:],
                "stderr_tail": completed.stderr[-2000:],
                "error": f"invalid_json: {exc}",
                "command": " ".join(cmd),
            }

    return {
        "ok": completed.returncode == 0 and isinstance(payload, dict),
        "exit_code": completed.returncode,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
        "payload": payload,
        "command": " ".join(cmd),
    }


def agents_from_ctl(ctl: dict[str, Any]) -> list[dict[str, Any]]:
    payload = ctl.get("payload") if isinstance(ctl.get("payload"), dict) else {}
    agents = payload.get("data") if isinstance(payload, dict) else []
    return [item for item in agents if isinstance(item, dict)] if isinstance(agents, list) else []


def agent_id(agent: dict[str, Any]) -> str:
    return str(agent.get("id") or agent.get("agent_id") or "")


def hostname(agent: dict[str, Any]) -> str:
    return str(agent.get("hostname") or agent.get("name") or agent_id(agent) or "unknown")


def status(agent: dict[str, Any]) -> str:
    return str(agent.get("status") or "").lower()


def health(agent: dict[str, Any]) -> str:
    value = agent.get("health_status") or {}
    if isinstance(value, dict):
        return str(value.get("status") or "").lower()
    return str(value).lower()


def metrics(agent: dict[str, Any]) -> dict[str, Any]:
    value = agent.get("health_status") or {}
    if isinstance(value, dict) and isinstance(value.get("metrics"), dict):
        return value["metrics"]
    return {}


def reasons(agent: dict[str, Any]) -> list[str]:
    value = agent.get("health_status") or {}
    raw = value.get("reasons") if isinstance(value, dict) else []
    return [str(item) for item in raw] if isinstance(raw, list) else []


def capability_observed(agent: dict[str, Any], capability_id: str) -> str:
    value = agent.get("platform_capabilities") or []
    if not isinstance(value, list):
        return ""
    for item in value:
        if isinstance(item, dict) and item.get("id") == capability_id:
            return str(item.get("observed") or "").lower()
    return ""


def target_agent(agents: list[dict[str, Any]], expected_hostname: str, expected_agent_id: str | None) -> dict[str, Any] | None:
    if expected_agent_id:
        for agent in agents:
            if agent_id(agent) == expected_agent_id:
                return agent
    for agent in agents:
        if hostname(agent).lower() == expected_hostname.lower():
            return agent
    return None


def test_result(test_id: str, name: str, passed: bool, evidence: dict[str, Any], gap: str) -> dict[str, Any]:
    missing = [] if passed else [gap]
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else gap,
        "validation_category": "windows_lab_execution_readiness",
        "execution_class": "authenticated_read_only_api_probe",
        "fallback_used": False,
        "claim_level": "windows_lab_readiness_claim_boundary",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": missing,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def build_tests(ctl: dict[str, Any], expected_hostname: str, expected_agent_id: str | None, max_cpu: float) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    agents = agents_from_ctl(ctl)
    target = target_agent(agents, expected_hostname, expected_agent_id)
    target_summary = summarize_agent(target) if target else None

    live_ready = False
    if target:
        live_ready = (
            status(target) == "online"
            and health(target) in {"healthy", "degraded"}
            and capability_observed(target, "live_response") == "reported"
        )

    endpoint_ready = False
    if target:
        endpoint_ready = (
            status(target) == "online"
            and health(target) in {"healthy", "degraded"}
            and capability_observed(target, "endpoint_telemetry") in {"reported", "observed"}
        )

    cpu_ready = False
    driver_not_loaded = False
    if target:
        cpu = metrics(target).get("cpu_usage")
        try:
            cpu_ready = float(cpu) <= max_cpu
        except (TypeError, ValueError):
            cpu_ready = health(target) != "critical"
        driver_not_loaded = str(metrics(target).get("driver_state") or "").lower() == "not_loaded"

    tests = [
        test_result(
            "windows-lab-target-present",
            "WIN-TEMPLATE target is present in authenticated inventory",
            target is not None,
            {
                "ctl_ok": bool(ctl.get("ok")),
                "agent_count": len(agents),
                "expected_hostname": expected_hostname,
                "expected_agent_id": expected_agent_id,
                "target": target_summary,
                "stderr_tail": ctl.get("stderr_tail"),
            },
            "infra",
        ),
        test_result(
            "windows-lab-target-online",
            "WIN-TEMPLATE target is online with a fresh backend state",
            bool(target) and status(target) == "online",
            {"target": target_summary},
            "infra",
        ),
        test_result(
            "windows-lab-target-health-acceptable",
            "WIN-TEMPLATE target health is healthy or degraded, not critical/offline",
            bool(target) and health(target) in {"healthy", "degraded"},
            {"target": target_summary},
            "agent-health",
        ),
        test_result(
            "windows-lab-target-live-response-ready",
            "WIN-TEMPLATE target reports live response runtime readiness",
            live_ready,
            {"target": target_summary},
            "runner",
        ),
        test_result(
            "windows-lab-target-endpoint-telemetry-ready",
            "WIN-TEMPLATE target reports endpoint telemetry runtime readiness",
            endpoint_ready,
            {"target": target_summary},
            "collector",
        ),
        test_result(
            "windows-lab-target-load-safe-for-broad-runs",
            "WIN-TEMPLATE target load is safe for broad shards",
            bool(target) and cpu_ready and not driver_not_loaded,
            {"target": target_summary, "max_cpu": max_cpu, "driver_not_loaded": driver_not_loaded},
            "agent-health",
        ),
    ]

    readiness = {
        "ready_for_windows_broad_runs": all(item["status"] == "covered" for item in tests),
        "target": target_summary,
        "blockers": sorted({item["gap_category"] for item in tests if item["status"] != "covered"}),
    }
    readiness["next_action"] = windows_next_action(
        target_summary,
        [str(value) for value in readiness["blockers"]],
        expected_hostname,
    )
    return tests, readiness


def summarize_agent(agent: dict[str, Any] | None) -> dict[str, Any] | None:
    if not agent:
        return None
    return {
        "agent_id": agent_id(agent),
        "hostname": hostname(agent),
        "status": status(agent),
        "health": health(agent),
        "last_seen": agent.get("last_seen"),
        "os_type": agent.get("os_type"),
        "os_version": agent.get("os_version"),
        "reasons": reasons(agent),
        "metrics": metrics(agent),
        "endpoint_telemetry": capability_observed(agent, "endpoint_telemetry"),
        "live_response": capability_observed(agent, "live_response"),
        "kernel_sensor": capability_observed(agent, "kernel_sensor"),
    }


def windows_next_action(target: dict[str, Any] | None, blockers: list[str], expected_hostname: str) -> dict[str, Any]:
    if target is None:
        return {
            "target_hostname": expected_hostname,
            "target_agent_id": None,
            "missing_readiness": ["target_inventory_row"],
            "action": "Reconnect or enroll WIN-TEMPLATE so it appears in authenticated backend inventory, then rerun the readiness probe.",
        }
    missing = []
    if "infra" in blockers:
        missing.append("status_online")
    if "agent-health" in blockers:
        missing.append("health_or_load_safe")
    if "runner" in blockers:
        missing.append("live_response_reported")
    if "collector" in blockers:
        missing.append("endpoint_telemetry_reported")
    if missing:
        action = (
            "Bring WIN-TEMPLATE online, wait for a fresh healthy/degraded heartbeat, "
            "verify live_response and endpoint_telemetry capabilities, then rerun the readiness and connection-stability probes."
        )
    else:
        action = "Run the next bounded Windows validation shard; readiness is green."
    return {
        "target_hostname": target.get("hostname") or expected_hostname,
        "target_agent_id": target.get("agent_id"),
        "missing_readiness": missing,
        "action": action,
    }


def summary(tests: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "tests": len(tests),
        "total": len(tests),
        "covered": sum(1 for item in tests if item.get("status") == "covered"),
        "missed": sum(1 for item in tests if item.get("status") == "missed"),
        "partial": sum(1 for item in tests if item.get("status") == "partial"),
        "execution_failed": sum(1 for item in tests if item.get("status") == "execution_failed"),
    }


def quality_gate(tests: list[dict[str, Any]]) -> dict[str, Any]:
    missed = [item["id"] for item in tests if item.get("status") != "covered"]
    return {
        "passed": not missed,
        "status": "pass" if not missed else "fail",
        "failures": [] if not missed else ["windows_lab_execution_readiness_gaps"],
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
        "score": 80 if passed else 45,
        "summary": {"covered": covered, "missed": missed, "total": len(tests)},
        "category_coverage": {"windows_lab_execution_readiness": {"covered": covered, "missed": missed}},
        "failures": [] if passed else ["windows_lab_execution_readiness_gaps"],
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Windows Lab Execution Readiness Probe",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Target hostname: `{report['target_hostname']}`",
        f"- Ready for broad Windows runs: `{str(report['windows_lab_readiness']['ready_for_windows_broad_runs']).lower()}`",
        "",
        "## Results",
        "",
        "| Test | Status | Gap |",
        "|------|--------|-----|",
    ]
    for item in report["tests"]:
        lines.append(f"| `{item['id']}` | `{item['status']}` | `{item.get('gap_category') or 'none'}` |")
    lines.extend(
        [
            "",
            "## Target",
            "",
            "```json",
            json.dumps(report["windows_lab_readiness"].get("target"), indent=2, sort_keys=True),
            "```",
            "",
            "## Next Action",
            "",
            f"- Target: `{(report['windows_lab_readiness'].get('next_action') or {}).get('target_hostname') or '-'}` / `{(report['windows_lab_readiness'].get('next_action') or {}).get('target_agent_id') or '-'}`",
            f"- Missing: `{', '.join((report['windows_lab_readiness'].get('next_action') or {}).get('missing_readiness') or []) or '-'}`",
            f"- Action: {(report['windows_lab_readiness'].get('next_action') or {}).get('action') or '-'}",
            "",
            "## Claim Boundary",
            "",
            "Read-only lab readiness proof only. It does not execute endpoint commands, does not mutate server state, and does not prove detection coverage.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ctl-path", default=str(DEFAULT_CTL))
    parser.add_argument("--server")
    parser.add_argument("--target-hostname", default="WIN-TEMPLATE")
    parser.add_argument("--target-agent-id")
    parser.add_argument("--max-cpu", type=float, default=90.0)
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    args = parser.parse_args()

    started = utc_now()
    run_id = f"{compact_stamp(started)}-{PROFILE_ID}"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ctl = run_ctl(Path(args.ctl_path), args.server)
    tests, readiness = build_tests(ctl, args.target_hostname, args.target_agent_id, args.max_cpu)
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
        "target_hostname": args.target_hostname,
        "target_agent_id": args.target_agent_id,
        "runtime_effect": "read_only_api",
        "metadata": {"git": git_snapshot()},
        "tamandua_ctl": {key: value for key, value in ctl.items() if key != "payload"},
        "windows_lab_readiness": readiness,
        "tests": tests,
        "summary": summary(tests),
        "quality_gate": gate,
        "scorecard": {"score": 80 if gate["passed"] else 45, "status": gate["status"]},
        "claim_boundary": "Read-only lab readiness proof; no endpoint command execution and no alert dependency.",
    }

    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    comparison_path.write_text(json.dumps(comparison(run_id, tests, gate["passed"]), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"windows_lab_execution_readiness={'ok' if gate['passed'] else 'gaps'} "
        f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
    )
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
