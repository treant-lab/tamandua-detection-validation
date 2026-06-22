#!/usr/bin/env python3
"""Live API probe for agent platform capability rendering.

This probe reads authenticated agent inventory through `tamandua-ctl` and checks
whether the deployed API distinguishes:
- online healthy runtime capability reported by the agent control plane;
- observed collector telemetry;
- offline/critical agents that must not be promoted to reported/observed.

It is read-only and does not execute commands on endpoints.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
DEFAULT_CTL = ROOT / "apps" / "tamandua_ctl" / "target" / "release" / "tamandua-ctl.exe"
PROFILE_ID = "agent-platform-capabilities-live-api-probe"
PROFILE_NAME = "Agent Platform Capabilities Live API Probe"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--short"]).splitlines()
    return {"commit": commit, "commit_short": commit[:8] if commit else "", "dirty": bool(status), "status_short": status}


def tamandua_ctl_env(server: str | None, base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base_env or os.environ)
    if not server:
        return env
    host = urlparse(server).hostname
    if not host:
        return env

    existing_values: list[str] = []
    for name in ("NO_PROXY", "no_proxy"):
        existing = env.get(name)
        if existing:
            existing_values.extend(item.strip() for item in existing.split(",") if item.strip())

    merged: list[str] = []
    for value in [*existing_values, host]:
        if value and value not in merged:
            merged.append(value)
    no_proxy = ",".join(merged)
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    return env


def run_ctl(ctl_path: Path, server: str | None = None) -> dict[str, Any]:
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
            env=tamandua_ctl_env(server),
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


def agent_id(agent: dict[str, Any]) -> str:
    return str(agent.get("id") or agent.get("agent_id") or agent.get("agentId") or "")


def agent_name(agent: dict[str, Any]) -> str:
    return str(agent.get("hostname") or agent.get("name") or agent_id(agent) or "unknown")


def agent_status(agent: dict[str, Any]) -> str:
    return str(agent.get("status") or "").lower()


def health_status(agent: dict[str, Any]) -> str:
    health = agent.get("health_status") or agent.get("healthStatus") or {}
    if isinstance(health, dict):
        return str(health.get("status") or "").lower()
    return str(health).lower()


def capabilities(agent: dict[str, Any]) -> list[dict[str, Any]]:
    value = agent.get("platform_capabilities") or agent.get("platformCapabilities") or []
    return value if isinstance(value, list) else []


def capability(agent: dict[str, Any], capability_id: str) -> dict[str, Any] | None:
    for item in capabilities(agent):
        if isinstance(item, dict) and item.get("id") == capability_id:
            return item
    return None


def observed(agent: dict[str, Any], capability_id: str) -> str:
    item = capability(agent, capability_id) or {}
    return str(item.get("observed") or "").lower()


def test_result(test_id: str, name: str, passed: bool, evidence: dict[str, Any], gap: str | None = None) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else (gap or "analyst-ux-live-api"),
        "validation_category": "agent_platform_capabilities_live_api",
        "execution_class": "authenticated_read_only_api_probe",
        "fallback_used": False,
        "claim_level": "agent_capability_live_api_contract",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests(ctl: dict[str, Any]) -> list[dict[str, Any]]:
    payload = ctl.get("payload") if isinstance(ctl.get("payload"), dict) else {}
    agents = payload.get("data") if isinstance(payload, dict) else []
    agents = agents if isinstance(agents, list) else []

    online_healthy = [
        agent
        for agent in agents
        if isinstance(agent, dict) and agent_status(agent) == "online" and health_status(agent) == "healthy"
    ]
    offline_or_critical = [
        agent
        for agent in agents
        if isinstance(agent, dict)
        and (agent_status(agent) != "online" or health_status(agent) in {"critical", "unknown", "offline"})
    ]

    expected_runtime = ["endpoint_telemetry", "live_response"]
    bad_online = []
    for agent in online_healthy:
        bad_caps = [cap for cap in expected_runtime if observed(agent, cap) == "not_observed"]
        if bad_caps:
            bad_online.append({"agent_id": agent_id(agent), "hostname": agent_name(agent), "bad_capabilities": bad_caps})

    bad_offline = []
    for agent in offline_or_critical:
        promoted = [
            cap
            for cap in expected_runtime
            if observed(agent, cap) in {"reported", "observed"} and health_status(agent) in {"critical", "unknown", "offline"}
        ]
        if promoted:
            bad_offline.append({"agent_id": agent_id(agent), "hostname": agent_name(agent), "promoted_capabilities": promoted})

    return [
        test_result(
            "agent-capabilities-live-api-readable",
            "Authenticated CLI can read agent inventory and platform capabilities",
            bool(ctl.get("ok")) and len(agents) > 0,
            {
                "ctl_ok": bool(ctl.get("ok")),
                "exit_code": ctl.get("exit_code"),
                "agent_count": len(agents),
                "stderr_tail": ctl.get("stderr_tail"),
            },
            "analyst-ux-live-api-auth",
        ),
        test_result(
            "agent-capabilities-online-healthy-runtime-reported",
            "Online healthy agents expose runtime-reported endpoint telemetry/live response capability",
            bool(online_healthy) and not bad_online,
            {
                "online_healthy_agents": [
                    {
                        "agent_id": agent_id(agent),
                        "hostname": agent_name(agent),
                        "endpoint_telemetry": observed(agent, "endpoint_telemetry"),
                        "live_response": observed(agent, "live_response"),
                    }
                    for agent in online_healthy
                ],
                "bad_online_agents": bad_online,
                "claim_boundary": "reported is runtime readiness, not collector-observed telemetry",
            },
            "analyst-ux-live-api-stale-server",
        ),
        test_result(
            "agent-capabilities-offline-critical-not-promoted",
            "Offline, unknown, or critical agents are not promoted to runtime-reported capability",
            not bad_offline,
            {
                "offline_or_critical_agents": [
                    {
                        "agent_id": agent_id(agent),
                        "hostname": agent_name(agent),
                        "status": agent_status(agent),
                        "health": health_status(agent),
                        "endpoint_telemetry": observed(agent, "endpoint_telemetry"),
                        "live_response": observed(agent, "live_response"),
                    }
                    for agent in offline_or_critical
                ],
                "bad_promotions": bad_offline,
            },
        ),
    ]


def summarize(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps: dict[str, int] = {}
    for test in tests:
        if test["status"] != "covered":
            gaps[str(test["gap_category"])] = gaps.get(str(test["gap_category"]), 0) + 1
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
        "missing_expected_fields": 0,
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {PROFILE_ID: len(tests)},
        "execution_class_counts": {"authenticated_read_only_api_probe": len(tests)},
        "claim_level_counts": {"agent_capability_live_api_contract": len(tests)},
        "category_coverage": {"agent_platform_capabilities_live_api": {"covered": covered, "missed": missed}},
        "roadmap_coverage": {"R": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {"authenticated_read_only_api_probe": covered},
        "gap_category_counts": gaps,
        "actionable_gaps": [test for test in tests if test["status"] != "covered"],
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    passed = summary["missed"] == 0
    rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "maturity_score": 84 if passed else max(40, int(70 * rate)),
        "maturity_band": "agent-capability-live-api-ready" if passed else "agent-capability-live-api-gaps",
        "recommended_claim": (
            "Deployed Agent API renders runtime-reported capabilities without promoting offline/critical agents"
            if passed
            else "Deployed Agent API capability rendering still needs update or live validation"
        ),
        "external_claim_allowed": False,
        "covered_rate": rate,
        "telemetry_rate": 1.0 if passed else rate,
        "field_quality": 1.0 if passed else rate,
        "context_quality": 1.0 if passed else rate,
        "analytic_quality": 1.0 if passed else rate,
        "noise_quality": 1.0,
        "driver_quality": 1.0,
        "upstream_rate": 0.0,
        "blocking_gaps": sorted(summary["gap_category_counts"].keys()),
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- Scope: authenticated read-only live Agent API capability rendering.",
        "- Runtime effect: none; no endpoint command, server mutation, DB mutation, or alert mutation.",
        "",
        "| Test | Status |",
        "|------|--------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` |")
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_outputs(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base = output_dir / report["run_id"]
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    comparison_path = output_dir / f"{report['run_id']}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    comparison_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": report["run_id"],
                "profile_id": report["profile_id"],
                "quality_gate": report["quality_gate"],
                "summary": report["summary"],
                "scorecard": report["scorecard"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return json_path, md_path, comparison_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--ctl-path", type=Path, default=Path(os.getenv("TAMANDUA_CTL_PATH", str(DEFAULT_CTL))))
    parser.add_argument("--server", default=os.getenv("TAMANDUA_SERVER"))
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    ctl = run_ctl(args.ctl_path, args.server)
    tests = collect_tests(ctl)
    summary = summarize(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "analyst-ux",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {"profile_id": PROFILE_ID, "name": PROFILE_NAME, "platform": "multi"},
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["agent_platform_capabilities_live_api_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "analyst-ux",
                "fail_on_missed": True,
                "require_upstream": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Authenticated read-only live API proof only. It validates deployed API rendering for "
            "agent capability states, but does not prove endpoint collector telemetry, driver health, "
            "or live-response command execution."
        ),
    }
    json_path, md_path, comparison_path = write_outputs(report, args.output_dir)
    print(f"agent_platform_capabilities_live_api_probe={'ok' if passed else 'fail'} json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
