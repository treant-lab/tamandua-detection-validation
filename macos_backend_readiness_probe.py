#!/usr/bin/env python3
"""Roadmap E macOS backend-readiness probe.

This probe is non-destructive. It uses tamandua-ctl inventory JSON to determine
whether a macOS agent is backend-connected and ready for the server-backed P0
sensor smoke profile. It does not run endpoint commands or inspect live alerts.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "macos-backend-readiness-probe"
PROFILE_NAME = "macOS Backend Readiness Probe"
DEFAULT_CTL = ROOT / "apps" / "tamandua_ctl" / "target" / "release" / "tamandua-ctl.exe"
FRESHNESS_SECONDS = int(os.getenv("TAMANDUA_MACOS_READINESS_FRESHNESS_SECONDS", "300"))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
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


def ctl_path() -> Path:
    return Path(os.getenv("TAMANDUA_CTL_PATH") or DEFAULT_CTL)


def remote_config_path() -> Path | None:
    if os.name == "nt":
        appdata = os.getenv("APPDATA")
        if not appdata:
            return None
        return Path(appdata) / "Tamandua" / "tamandua-ctl" / "remote.json"
    config_home = os.getenv("XDG_CONFIG_HOME")
    if config_home:
        base = Path(config_home)
    else:
        home = os.getenv("HOME")
        if not home:
            return None
        base = Path(home) / ".config"
    return base / "tamandua" / "tamandua-ctl" / "remote.json"


def remote_config_metadata(target_server: str | None = None) -> dict[str, Any]:
    path = remote_config_path()
    metadata: dict[str, Any] = {
        "path": str(path) if path else None,
        "exists": False,
        "server": None,
        "has_token": False,
        "expires_at": None,
        "target_server": target_server,
        "server_matches_target": None,
    }
    if path is None:
        metadata["error"] = "remote_config_path_unavailable"
        return metadata
    if not path.exists():
        return metadata
    metadata["exists"] = True
    try:
        stat = path.stat()
        metadata["last_modified"] = iso(datetime.fromtimestamp(stat.st_mtime, timezone.utc))
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        metadata["error"] = type(exc).__name__
        return metadata
    if not isinstance(body, dict):
        metadata["error"] = "remote_config_not_object"
        return metadata
    saved_server = body.get("server")
    metadata["server"] = saved_server if isinstance(saved_server, str) else None
    metadata["has_token"] = bool(body.get("token"))
    expires_at = body.get("expires_at")
    metadata["expires_at"] = expires_at if isinstance(expires_at, str) else None
    if target_server and metadata["server"]:
        metadata["server_matches_target"] = str(metadata["server"]).rstrip("/") == str(target_server).rstrip("/")
    return metadata


def load_agents(server: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    command = [str(ctl_path()), "remote", "agents", "list", "--json"]
    if server:
        command.extend(["--server", server])
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    evidence = {
        "command": " ".join(command),
        "exit_code": result.returncode,
        "stderr": result.stderr[-2000:],
        "remote_config": remote_config_metadata(server),
    }
    if result.returncode != 0:
        evidence["stdout"] = result.stdout[-2000:]
        return [], evidence
    try:
        body = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        evidence["json_error"] = str(exc)
        evidence["stdout"] = result.stdout[-2000:]
        return [], evidence
    agents = body.get("data") if isinstance(body, dict) else body
    if not isinstance(agents, list):
        evidence["shape_error"] = "agents response is not a list"
        return [], evidence
    return [agent for agent in agents if isinstance(agent, dict)], evidence


def inventory_auth_missing(inventory: dict[str, Any]) -> bool:
    text = f"{inventory.get('stderr') or ''}\n{inventory.get('stdout') or ''}".lower()
    return int(inventory.get("exit_code") or 0) != 0 and (
        "401 unauthorized" in text or "invalid or expired token" in text
    )


def macos_agent_summary(agent: dict[str, Any]) -> dict[str, Any]:
    health = agent.get("health_status") if isinstance(agent.get("health_status"), dict) else {}
    capabilities = agent.get("platform_capabilities") if isinstance(agent.get("platform_capabilities"), list) else []
    last_seen = parse_time(agent.get("last_seen"))
    age_seconds = None if last_seen is None else max(0, int((utc_now() - last_seen).total_seconds()))
    return {
        "id": agent.get("id"),
        "hostname": agent.get("hostname"),
        "os_type": agent.get("os_type"),
        "os_version": agent.get("os_version"),
        "status": agent.get("status"),
        "health": health.get("status"),
        "last_seen": agent.get("last_seen"),
        "last_seen_age_seconds": age_seconds,
        "capabilities": [
            {
                "id": item.get("id"),
                "status": item.get("status"),
                "maturity": item.get("maturity"),
                "observed": item.get("observed"),
            }
            for item in capabilities
            if isinstance(item, dict)
        ],
    }


def macos_candidate_missing(agent: dict[str, Any]) -> list[str]:
    missing = []
    if str(agent.get("status") or "").lower() != "online":
        missing.append("status_online")
    if str(agent.get("health") or "").lower() != "healthy":
        missing.append("health_healthy")
    if not (
        isinstance(agent.get("last_seen_age_seconds"), int)
        and agent["last_seen_age_seconds"] <= FRESHNESS_SECONDS
    ):
        missing.append("fresh_heartbeat")
    if not any(
        item.get("id") == "endpoint_telemetry"
        and item.get("status") not in {"unavailable", "unknown"}
        for item in agent.get("capabilities") or []
    ):
        missing.append("endpoint_telemetry_capability")
    return missing


def best_macos_candidate(summaries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not summaries:
        return None

    def sort_key(agent: dict[str, Any]) -> tuple[int, int, int, int]:
        missing = macos_candidate_missing(agent)
        online = int(str(agent.get("status") or "").lower() == "online")
        healthy = int(str(agent.get("health") or "").lower() == "healthy")
        age = agent.get("last_seen_age_seconds")
        freshness_score = -int(age) if isinstance(age, int) else -10**9
        return (-len(missing), online, healthy, freshness_score)

    candidate = sorted(summaries, key=sort_key, reverse=True)[0]
    return {**candidate, "missing_readiness": macos_candidate_missing(candidate)}


def macos_next_action(best_candidate: dict[str, Any] | None, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    if inventory and inventory_auth_missing(inventory):
        remote_config = inventory.get("remote_config") if isinstance(inventory.get("remote_config"), dict) else {}
        target_server = remote_config.get("target_server") or None
        saved_server = remote_config.get("server") or None
        if target_server and saved_server and remote_config.get("server_matches_target") is False:
            return {
                "target_agent_id": None,
                "target_hostname": None,
                "missing_readiness": ["tamandua_ctl_auth"],
                "action": (
                    "Run tamandua-ctl remote login for the target server "
                    f"{target_server} because the saved remote login is for {saved_server}; "
                    "then rerun macos_backend_readiness_probe.py before diagnosing macOS agent enrollment."
                ),
                "login_command": f"tamandua-ctl remote login --server {target_server} --no-browser",
                "token_env": "TAMANDUA_TOKEN",
                "token_login_command": f"tamandua-ctl remote login --server {target_server} --token $env:TAMANDUA_TOKEN",
                "saved_server": saved_server,
                "target_server": target_server,
            }
        return {
            "target_agent_id": None,
            "target_hostname": None,
            "missing_readiness": ["tamandua_ctl_auth"],
            "action": "Refresh tamandua-ctl authentication for the target server, then rerun macos_backend_readiness_probe.py before diagnosing macOS agent enrollment.",
            "token_env": "TAMANDUA_TOKEN",
        }
    if best_candidate is None:
        return {
            "target_agent_id": None,
            "target_hostname": None,
            "missing_readiness": ["macos_agent_row"],
            "action": "Enroll or reconnect a macOS lab agent, then rerun macos_backend_readiness_probe.py.",
        }
    missing = [str(value) for value in best_candidate.get("missing_readiness") or []]
    if not missing:
        action = "Run deploy/scripts/proxmox/run-macos-p0-smoke.ps1 against the ready macOS agent."
    else:
        action = (
            "Reconnect the selected macOS agent, wait for a fresh healthy heartbeat, "
            "verify endpoint_telemetry capability, then rerun macos_backend_readiness_probe.py."
        )
    return {
        "target_agent_id": best_candidate.get("id"),
        "target_hostname": best_candidate.get("hostname"),
        "missing_readiness": missing,
        "action": action,
    }


def make_result(test_id: str, name: str, passed: bool, category: str, evidence: dict[str, Any], missing: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else category,
        "execution_class": "backend_readiness_probe",
        "claim_level": "macos_backend_readiness",
        "executor_used": PROFILE_ID,
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": "macos_backend_readiness",
        "coverage": {
            "telemetry": "not_expected",
            "fields": "ok" if passed else "missing",
            "detection": "not_expected",
            "alert": "not_expected",
            "correlation": "not_expected",
            "driver_raw": "not_expected",
            "timeline": "not_expected",
            "values": "ok" if passed else "missing",
        },
        "evidence": evidence,
        "missing_expected_fields": missing or [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [],
    }


def build_tests(server: str | None = None) -> list[dict[str, Any]]:
    agents, inventory = load_agents(server)
    auth_missing = inventory_auth_missing(inventory)
    macs = [agent for agent in agents if str(agent.get("os_type") or "").lower() == "macos"]
    summaries = [macos_agent_summary(agent) for agent in macs]
    online = [agent for agent in summaries if str(agent.get("status") or "").lower() == "online"]
    healthy = [agent for agent in online if str(agent.get("health") or "").lower() == "healthy"]
    fresh = [
        agent
        for agent in healthy
        if isinstance(agent.get("last_seen_age_seconds"), int) and agent["last_seen_age_seconds"] <= FRESHNESS_SECONDS
    ]
    endpoint_ready = [
        agent
        for agent in fresh
        if any(
            item.get("id") == "endpoint_telemetry"
            and item.get("status") not in {"unavailable", "unknown"}
            for item in agent.get("capabilities") or []
        )
    ]
    best_candidate = best_macos_candidate(summaries)

    evidence = {
        "inventory": inventory,
        "macos_agents": summaries,
        "best_candidate": best_candidate,
        "next_action": macos_next_action(best_candidate, inventory),
        "freshness_seconds": FRESHNESS_SECONDS,
    }
    row_missing = ["tamandua_ctl_auth"] if auth_missing else ["macos_agent_row"]
    return [
        make_result(
            "macos-backend-agent-row-present",
            "At least one macOS agent row exists in backend inventory",
            bool(macs),
            "infrastructure",
            evidence,
            [] if macs else row_missing,
        ),
        make_result(
            "macos-backend-agent-online-healthy",
            "At least one macOS agent is online and healthy",
            bool(healthy),
            "infrastructure",
            evidence,
            [] if healthy else ["online_healthy_macos_agent"],
        ),
        make_result(
            "macos-backend-agent-fresh",
            "At least one macOS agent has a fresh heartbeat",
            bool(fresh),
            "infrastructure",
            evidence,
            [] if fresh else ["fresh_macos_heartbeat"],
        ),
        make_result(
            "macos-backend-endpoint-telemetry-capability",
            "At least one fresh macOS agent advertises endpoint telemetry capability",
            bool(endpoint_ready),
            "collector",
            evidence,
            [] if endpoint_ready else ["macos_endpoint_telemetry_capability"],
        ),
    ]


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        "",
        "## Results",
        "",
        "| Test | Status | Gap | Missing |",
        "|------|--------|-----|---------|",
    ]
    for test in report["tests"]:
        missing = ", ".join(test.get("missing_expected_fields") or []) or "-"
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['gap_category']}` | `{missing}` |")
    first_evidence = (report["tests"][0].get("evidence") if report.get("tests") else {}) or {}
    best_candidate = first_evidence.get("best_candidate") if isinstance(first_evidence.get("best_candidate"), dict) else None
    next_action = first_evidence.get("next_action") if isinstance(first_evidence.get("next_action"), dict) else {}
    lines.extend(
        [
            "",
            "## Best Candidate",
            "",
            "| Hostname | Agent ID | Status | Health | Last seen age | Missing readiness |",
            "|----------|----------|--------|--------|---------------|-------------------|",
        ]
    )
    if best_candidate:
        missing = ", ".join(str(value) for value in best_candidate.get("missing_readiness") or []) or "-"
        lines.append(
            f"| `{best_candidate.get('hostname') or '-'}` | `{best_candidate.get('id') or '-'}` | "
            f"`{best_candidate.get('status') or '-'}` | `{best_candidate.get('health') or '-'}` | "
            f"`{best_candidate.get('last_seen_age_seconds')}` | `{missing}` |"
        )
    else:
        missing = ", ".join(str(value) for value in next_action.get("missing_readiness") or []) or "macos_agent_row"
        lines.append(f"| `-` | `-` | `-` | `-` | `-` | `{missing}` |")
    lines.extend(
        [
            "",
            "## Next Action",
            "",
            f"- Target: `{next_action.get('target_hostname') or '-'}` / `{next_action.get('target_agent_id') or '-'}`",
            f"- Missing: `{', '.join(next_action.get('missing_readiness') or []) or '-'}`",
            f"- Action: {next_action.get('action') or '-'}",
        ]
    )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This artifact proves macOS backend readiness only. It does not execute the macOS P0 sensor smoke profile and does not prove collector coverage.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    parser.add_argument("--server")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = iso(utc_now())
    tests = build_tests(args.server)
    finished = iso(utc_now())
    passed = all(test["status"] == "covered" for test in tests)
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"

    report = {
        "schema_version": 1,
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "name": PROFILE_NAME,
        "mode": "execute",
        "benchmark_lane": "claim-boundary",
        "started_at": started,
        "finished_at": finished,
        "git": git_snapshot(),
        "summary": {
            "tests": len(tests),
            "covered": covered,
            "missed": missed,
            "partial": 0,
            "execution_failed": 0,
            "unknown_source_events": 0,
            "unexpected_high_or_critical_events": 0,
            "unexpected_high_or_critical_alerts": 0,
            "missing_expected_fields": sum(len(test.get("missing_expected_fields") or []) for test in tests),
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "executor_counts": {PROFILE_ID: len(tests)},
            "claim_level_counts": {"macos_backend_readiness": len(tests)},
            "category_coverage": {"macos_backend_readiness": {"covered": covered, "missed": missed}},
        },
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["macos_backend_readiness_gaps"],
            "actionable_gaps": [
                {
                    "test_id": test["id"],
                    "gap_category": test["gap_category"],
                    "missing": test.get("missing_expected_fields") or [],
                    "evidence": test.get("evidence") or {},
                }
                for test in tests
                if test["status"] != "covered"
            ],
            "gap_category_counts": {
                category: sum(1 for test in tests if test["gap_category"] == category)
                for category in sorted({test["gap_category"] for test in tests if test["gap_category"] != "none"})
            },
            "thresholds": {"freshness_seconds": FRESHNESS_SECONDS},
        },
        "scorecard": {
            "maturity_score": 100 if passed else 45,
            "maturity_band": "macos-backend-ready" if passed else "macos-backend-readiness-gaps",
            "recommended_claim": (
                "macOS backend readiness is sufficient to run P0 sensor smoke"
                if passed
                else "macOS backend-backed P0 sensor smoke is blocked by agent readiness"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else ["macos_backend_readiness_missing"],
            "covered_rate": covered / len(tests) if tests else 0,
            "telemetry_rate": 1.0,
            "field_quality": 1.0 if passed else 0.0,
            "context_quality": 1.0 if passed else 0.0,
            "analytic_quality": 1.0,
            "noise_quality": 1.0,
            "driver_quality": 1.0,
            "upstream_rate": 0.0,
        },
        "tests": tests,
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    md_path = output_dir / f"{run_id}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    comparison_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"macos_backend_readiness={'ok' if passed else 'gaps'} json={json_path} markdown={md_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
