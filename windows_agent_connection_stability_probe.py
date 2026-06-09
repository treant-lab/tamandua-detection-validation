#!/usr/bin/env python3
"""Read-only Windows agent connection stability probe.

The probe connects to the lab server over SSH and reads recent Phoenix logs to
determine whether the WIN-TEMPLATE agent connection is stable enough to run
Windows shards, Atomic extended, or CALDERA enterprise profiles. It does not
execute endpoint commands and does not mutate server state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "windows-agent-connection-stability-probe"
PROFILE_NAME = "Windows Agent Connection Stability Probe"
DEFAULT_AGENT_ID = "cb145360-8ba8-475a-bfd6-2bc16d5281d7"

TIMESTAMP_RE = re.compile(r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\.(?P<millis>\d{3})")
TELEMETRY_RE = re.compile(r"Received telemetry batch with (?P<count>\d+) events")


@dataclass
class Session:
    connected_at: str | None = None
    registered_at: str | None = None
    joined_at: str | None = None
    first_telemetry_at: str | None = None
    last_telemetry_at: str | None = None
    disconnected_at: str | None = None
    disconnect_reason: str | None = None
    telemetry_batches: int = 0
    telemetry_events: int = 0

    def duration_seconds(self) -> float | None:
        start = self.connected_at or self.registered_at or self.joined_at or self.first_telemetry_at
        end = self.disconnected_at
        if not start or not end:
            return None
        try:
            return (parse_iso(end) - parse_iso(start)).total_seconds()
        except ValueError:
            return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "connected_at": self.connected_at,
            "registered_at": self.registered_at,
            "joined_at": self.joined_at,
            "first_telemetry_at": self.first_telemetry_at,
            "last_telemetry_at": self.last_telemetry_at,
            "disconnected_at": self.disconnected_at,
            "disconnect_reason": self.disconnect_reason,
            "duration_seconds": self.duration_seconds(),
            "telemetry_batches": self.telemetry_batches,
            "telemetry_events": self.telemetry_events,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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


def log_timestamp(line: str, day: datetime) -> str | None:
    match = TIMESTAMP_RE.search(line)
    if not match:
        return None
    value = day.replace(
        hour=int(match.group("hour")),
        minute=int(match.group("minute")),
        second=int(match.group("second")),
        microsecond=int(match.group("millis")) * 1000,
    )
    return value.isoformat().replace("+00:00", "Z")


def fetch_logs(args: argparse.Namespace) -> dict[str, Any]:
    try:
        import paramiko  # type: ignore
    except ImportError as exc:
        return {"ok": False, "error": f"paramiko_missing: {exc}"}

    password = args.server_password or os.environ.get("TAMANDUA_SERVER_PASSWORD")
    if not password:
        return {
            "ok": False,
            "error": "missing_server_password",
            "required_env": "TAMANDUA_SERVER_PASSWORD",
            "password_supplied": False,
        }

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(args.server_host, username=args.server_user, password=password, timeout=20)
        grep_pattern = f"{args.agent_id}|{args.agent_hostname}|Agent connected|Agent registered|Worker started|JOINED agent:{args.agent_id}|Agent channel terminated|Socket disconnected|Agent unregistered|Worker terminating|Received telemetry batch"
        cmd = (
            "docker logs "
            + shell_quote(args.container)
            + " --since "
            + shell_quote(args.since)
            + " 2>&1 | grep -Ei "
            + shell_quote(grep_pattern)
            + " | tail -"
            + str(max(args.tail_lines, 1))
            + " || true"
        )
        _, stdout, stderr = ssh.exec_command(cmd, timeout=120)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        return {"ok": code == 0, "stdout": out, "stderr": err, "command": cmd, "exit_code": code}
    except Exception as exc:  # noqa: BLE001 - probe must produce an artifact instead of crashing on infra.
        return {"ok": False, "error": str(exc)}
    finally:
        ssh.close()


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def parse_sessions(log_text: str, agent_id: str, now: datetime) -> list[Session]:
    sessions: list[Session] = []
    current: Session | None = None
    for raw_line in log_text.splitlines():
        if agent_id not in raw_line:
            continue
        ts = log_timestamp(raw_line, now)
        if "Agent connected:" in raw_line:
            if current and (current.registered_at or current.joined_at or current.first_telemetry_at) and not current.disconnected_at:
                sessions.append(current)
            current = Session(connected_at=ts)
            continue
        if "Certificate validated for agent" in raw_line:
            continue
        if current is None:
            current = Session()
        if "Agent registered:" in raw_line:
            current.registered_at = ts
        elif "Worker started for agent" in raw_line:
            current.registered_at = current.registered_at or ts
        elif f"JOINED agent:{agent_id}" in raw_line:
            current.joined_at = ts
        elif "Received telemetry batch" in raw_line:
            current.first_telemetry_at = current.first_telemetry_at or ts
            current.last_telemetry_at = ts
            current.telemetry_batches += 1
            match = TELEMETRY_RE.search(raw_line)
            if match:
                current.telemetry_events += int(match.group("count"))
        elif "Agent channel terminated:" in raw_line or "Socket disconnected for agent" in raw_line:
            current.disconnected_at = ts
            current.disconnect_reason = raw_line[-220:]
        elif "Agent unregistered:" in raw_line or "Worker terminating for agent" in raw_line:
            current.disconnected_at = current.disconnected_at or ts
            current.disconnect_reason = current.disconnect_reason or raw_line[-220:]
            sessions.append(current)
            current = None
    if current:
        sessions.append(current)
    return sessions


def test_result(test_id: str, name: str, passed: bool, evidence: dict[str, Any], gap: str) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else gap,
        "validation_category": "windows_agent_connection_stability",
        "execution_class": "server_log_read_only_probe",
        "fallback_used": False,
        "claim_level": "windows_agent_connection_stability_claim_boundary",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": [] if passed else [gap],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def build_tests(fetch: dict[str, Any], sessions: list[Session], min_duration: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    session_dicts = [session.as_dict() for session in sessions]
    connected = [
        session
        for session in sessions
        if session.connected_at or session.registered_at or session.joined_at or session.first_telemetry_at
    ]
    stable_sessions = [
        session for session in connected if session.duration_seconds() is not None and session.duration_seconds() >= min_duration
    ]
    active_sessions = [session for session in connected if not session.disconnected_at]
    latest = session_dicts[-1] if session_dicts else None
    total_telemetry = sum(session.telemetry_events for session in sessions)
    recent_disconnects = [session for session in sessions if session.disconnected_at]

    tests = [
        test_result(
            "windows-agent-server-log-readable",
            "146 server logs are readable for WIN-TEMPLATE",
            bool(fetch.get("ok")),
            {
                "ok": fetch.get("ok"),
                "exit_code": fetch.get("exit_code"),
                "error": fetch.get("error"),
                "required_env": fetch.get("required_env"),
                "password_supplied": fetch.get("password_supplied"),
                "stderr_tail": str(fetch.get("stderr") or "")[-1000:],
            },
            "infra",
        ),
        test_result(
            "windows-agent-recent-connection-observed",
            "Recent WIN-TEMPLATE connection or join is visible in server logs",
            bool(connected),
            {"session_count": len(sessions), "sessions": session_dicts[-5:]},
            "infra",
        ),
        test_result(
            "windows-agent-stable-session-duration",
            f"At least one recent WIN-TEMPLATE session lasted {min_duration}s or more",
            bool(stable_sessions),
            {"min_duration_seconds": min_duration, "sessions": session_dicts[-5:]},
            "agent-health",
        ),
        test_result(
            "windows-agent-not-currently-disconnected",
            "Latest observed WIN-TEMPLATE session is still active or did not end in channel close",
            bool(active_sessions) and latest is not None and not latest.get("disconnected_at"),
            {"latest_session": latest, "recent_disconnect_count": len(recent_disconnects)},
            "runner",
        ),
        test_result(
            "windows-agent-telemetry-flow-observed",
            "WIN-TEMPLATE sent telemetry batches during the recent log window",
            total_telemetry > 0,
            {"telemetry_events": total_telemetry, "sessions": session_dicts[-5:]},
            "collector",
        ),
    ]
    stability = {
        "ready_for_windows_broad_runs": all(item["status"] == "covered" for item in tests),
        "session_count": len(sessions),
        "stable_session_count": len(stable_sessions),
        "active_session_count": len(active_sessions),
        "telemetry_events": total_telemetry,
        "latest_session": latest,
        "blockers": sorted({item["gap_category"] for item in tests if item["status"] != "covered"}),
    }
    stability["next_action"] = connection_next_action(
        fetch,
        stability,
        min_duration,
    )
    return tests, stability


def connection_next_action(fetch: dict[str, Any], stability: dict[str, Any], min_duration: int) -> dict[str, Any]:
    blockers = [str(value) for value in stability.get("blockers") or []]
    missing = []
    if not fetch.get("ok"):
        missing.append("server_log_access")
    if stability.get("session_count", 0) <= 0:
        missing.append("recent_agent_connection")
    if stability.get("stable_session_count", 0) <= 0:
        missing.append(f"stable_session_{min_duration}s")
    if stability.get("active_session_count", 0) <= 0:
        missing.append("active_session")
    if stability.get("telemetry_events", 0) <= 0:
        missing.append("telemetry_batches")
    if missing:
        if "server_log_access" in missing:
            action = "Set TAMANDUA_SERVER_PASSWORD or provide --server-password, then rerun the connection-stability probe."
        else:
            action = (
                "Bring WIN-TEMPLATE online, keep the agent connected long enough to exceed the stable-session threshold, "
                "wait for telemetry batches, then rerun the connection-stability probe."
            )
    else:
        action = "Connection stability is ready; proceed only after Windows readiness and QGA readiness are also green."
    return {
        "agent_id": DEFAULT_AGENT_ID,
        "missing_stability": missing,
        "blockers": blockers,
        "min_stable_session_seconds": min_duration,
        "action": action,
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
        "failures": [] if not missed else ["windows_agent_connection_stability_gaps"],
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
        "summary": {"tests": len(tests), "total": len(tests), "covered": covered, "missed": missed},
        "category_coverage": {"windows_agent_connection_stability": {"covered": covered, "missed": missed}},
        "failures": [] if passed else ["windows_agent_connection_stability_gaps"],
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    preflight: list[str] = []
    server_probe = report.get("server_log_probe") or {}
    if server_probe.get("error") == "missing_server_password":
        preflight = [
            "",
            "## Preflight",
            "",
            "- `TAMANDUA_SERVER_PASSWORD` is not set in the current shell.",
            "- This probe did not connect to the server over SSH without a password.",
        ]
    lines = [
        "# Windows Agent Connection Stability Probe",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Agent ID: `{report['agent_id']}`",
        f"- Ready for broad Windows runs: `{str(report['connection_stability']['ready_for_windows_broad_runs']).lower()}`",
        *preflight,
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
            "## Stability Summary",
            "",
            "```json",
            json.dumps(report["connection_stability"], indent=2, sort_keys=True),
            "```",
            "",
            "## Next Action",
            "",
            f"- Missing: `{', '.join((report['connection_stability'].get('next_action') or {}).get('missing_stability') or []) or '-'}`",
            f"- Action: {(report['connection_stability'].get('next_action') or {}).get('action') or '-'}",
            "",
            "## Claim Boundary",
            "",
            "Server-log readiness proof only. It does not execute endpoint commands, does not mutate the server, and does not inspect live alerts.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-host", default="192.168.12.146")
    parser.add_argument("--server-user", default="root")
    parser.add_argument("--server-password")
    parser.add_argument("--container", default="tamandua-server-light")
    parser.add_argument("--agent-id", default=DEFAULT_AGENT_ID)
    parser.add_argument("--agent-hostname", default="WIN-TEMPLATE")
    parser.add_argument("--since", default="45m")
    parser.add_argument("--tail-lines", type=int, default=500)
    parser.add_argument("--min-stable-session-seconds", type=int, default=300)
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    args = parser.parse_args()

    started = utc_now()
    run_id = f"{compact_stamp(started)}-{PROFILE_ID}"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    fetched = fetch_logs(args)
    sessions = parse_sessions(str(fetched.get("stdout") or ""), args.agent_id, now)
    tests, stability = build_tests(fetched, sessions, args.min_stable_session_seconds)
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
        "agent_id": args.agent_id,
        "agent_hostname": args.agent_hostname,
        "runtime_effect": "server_log_read_only",
        "metadata": {"git": git_snapshot()},
        "server_log_probe": {key: value for key, value in fetched.items() if key != "stdout"},
        "connection_stability": stability,
        "tests": tests,
        "summary": summary(tests),
        "quality_gate": gate,
        "scorecard": {"score": 80 if gate["passed"] else 45, "status": gate["status"]},
        "claim_boundary": "Read-only server-log stability proof; no endpoint command execution and no alert dependency.",
    }

    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    comparison_path.write_text(json.dumps(comparison(run_id, tests, gate["passed"]), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"windows_agent_connection_stability={'ok' if gate['passed'] else 'gaps'} "
        f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
    )
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
