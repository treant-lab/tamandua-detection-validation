#!/usr/bin/env python3
"""Read-only probe for the lab server release-image build lane.

This probe uses SSH and Docker/journal read commands only. It does not build,
retag, pull, push, deploy, stop, restart, kill, exec into containers, or create
temporary containers.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]


PROFILE_ID = "server-release-build-readonly-probe"
PROFILE_NAME = "Server Release Build Read-Only Probe"
DEFAULT_OUTPUT_DIR = ROOT / ".tmp" / PROFILE_ID
KILL_PATTERNS = ("137", "signal=9", "sigkill", "killed", "oom", "out of memory")
BUILD_PATTERNS = ("docker build", "buildx", "buildkit", "mix deps.", "mix deps.compile", "product-lab")
BUILD_KILL_PATTERNS = KILL_PATTERNS + ("mix deps.compile", "product-lab", "docker build", "buildkit")


def classify(status: str, *, present: bool, evidence: list[str] | None = None, detail: str = "") -> dict[str, Any]:
    return {
        "status": status,
        "present": present,
        "detail": detail,
        "evidence": evidence or [],
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(args: list[str], *, timeout: int = 30) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "args": args,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except FileNotFoundError as exc:
        return {"args": args, "returncode": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {
            "args": args,
            "returncode": 124,
            "stdout": stdout.strip(),
            "stderr": f"timeout after {timeout}s\n{stderr}".strip(),
        }


def ssh(args: argparse.Namespace, tail: list[str], *, timeout: int = 30) -> dict[str, Any]:
    return run(
        [
            args.ssh_bin,
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={args.connect_timeout}",
            args.ssh_target,
            *tail,
        ],
        timeout=timeout,
    )


def git_snapshot() -> dict[str, Any]:
    commit = run(["git", "rev-parse", "HEAD"], timeout=10)["stdout"]
    status = run(["git", "status", "--short"], timeout=10)["stdout"].splitlines()
    return {"commit": commit, "commit_short": commit[:8], "dirty": bool(status), "status_short": status}


def filter_lines(text: str, patterns: tuple[str, ...]) -> list[str]:
    matches = []
    for line in text.splitlines():
        lower = line.lower()
        if any(pattern.lower() in lower for pattern in patterns):
            matches.append(line)
    return matches


def has_pattern(line: str, patterns: tuple[str, ...]) -> bool:
    lower = line.lower()
    return any(pattern.lower() in lower for pattern in patterns)


def build_kill_evidence(lines: list[str]) -> list[str]:
    """Return lines that make a failed release build plausibly memory/kill related."""
    matches = []
    for line in lines:
        kill_related = has_pattern(line, KILL_PATTERNS)
        build_related = has_pattern(line, BUILD_PATTERNS)
        if kill_related and (build_related or "beam.smp" in line.lower() or "docker" in line.lower()):
            matches.append(line)
    return matches


def recommend_next_action(
    *,
    candidate_ready: list[str],
    active_build_detected: bool,
    build_dead_by_137: bool,
    source_runtime: bool,
    health_ok: bool,
    listeners_ok: bool,
) -> str:
    if candidate_ready:
        return (
            "candidate_image_present_run_release_image_probe_or_smoke_before_any_promotion"
        )
    if active_build_detected:
        return "build_active_wait_or_monitor_do_not_retry_or_retag_concurrently"
    if build_dead_by_137:
        return "move_build_to_clean_runner_or_more_memory_before_retrying_local_host"
    if source_runtime and health_ok and listeners_ok:
        return "no_candidate_but_source_runtime_healthy_start_release_build_on_clean_runner"
    if source_runtime:
        return "source_runtime_detected_but_health_or_listeners_degraded_fix_runtime_before_release_retry"
    return "inspect_docker_ssh_health_prerequisites_before_release_retry"


def relative_delta(value: str) -> timedelta | None:
    if value.startswith("-") and value.endswith("h") and value[1:-1].isdigit():
        return timedelta(hours=int(value[1:-1]))
    if value.startswith("-") and value.endswith("m") and value[1:-1].isdigit():
        return timedelta(minutes=int(value[1:-1]))
    return None


def tcp_probe(host: str, port: int, timeout: int) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"host": host, "port": port, "open": True}
    except OSError as exc:
        return {"host": host, "port": port, "open": False, "error": str(exc)}


def health_probe(url: str, timeout: int) -> dict[str, Any]:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": PROFILE_ID})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {"url": url, "status_code": response.status, "ok": 200 <= response.status < 300}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status_code": exc.code, "ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - transport evidence
        return {"url": url, "ok": False, "error": str(exc)}


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    active_build_lines = report["active_build_processes"]
    candidate_results = report["candidate_images"]
    candidate_ready = [tag for tag, result in candidate_results.items() if result["id"]["returncode"] == 0]
    live_container = report["live_container"]
    docker_ps = report["docker_ps"]["stdout"]
    kill_lines = (
        report["recent_kill_evidence"]["docker_journal_matches"]
        + report["recent_kill_evidence"]["kernel_journal_matches"]
        + report["recent_kill_evidence"]["docker_event_matches"]
    )
    build_kill_lines = build_kill_evidence(kill_lines)
    health_ok = report["health"].get("ok") is True
    listeners_ok = all(item.get("open") for item in report["listeners"])
    source_runtime = "tamandua-server-light" in docker_ps and "mix phx.server" in docker_ps
    source_runtime_healthy = source_runtime and health_ok and listeners_ok
    active_build_detected = bool(active_build_lines)
    no_candidate_image = not candidate_ready
    build_dead_by_137 = no_candidate_image and not active_build_detected and bool(build_kill_lines)
    classifications = {
        "candidate_present": classify(
            "ok" if candidate_ready else "blocked",
            present=bool(candidate_ready),
            evidence=candidate_ready,
            detail=(
                "requested candidate release image tag exists"
                if candidate_ready
                else "no requested candidate release image tag is present"
            ),
        ),
        "active_build": classify(
            "blocked" if active_build_detected else "ok",
            present=active_build_detected,
            evidence=active_build_lines[:20],
            detail=(
                "release build process appears active; do not start a concurrent retry"
                if active_build_detected
                else "no active release build process was detected"
            ),
        ),
        "source_runtime_healthy": classify(
            "degraded" if source_runtime_healthy else "blocked",
            present=source_runtime_healthy,
            evidence=[live_container["image"]["stdout"], live_container["state"]["stdout"]],
            detail=(
                "live lab container is source-runtime and health/listeners are up; this is not release-image evidence"
                if source_runtime_healthy
                else "source-runtime health was not established from container, health, and listener evidence"
            ),
        ),
        "release_build_dead_by_137_or_sigkill": classify(
            "blocked" if build_dead_by_137 else "ok",
            present=build_dead_by_137,
            evidence=build_kill_lines[:20],
            detail=(
                "no candidate image or active build is visible, and recent build kill/OOM/SIGKILL evidence exists"
                if build_dead_by_137
                else "no read-only evidence that the release build died by 137/SIGKILL"
            ),
        ),
    }
    next_action = recommend_next_action(
        candidate_ready=candidate_ready,
        active_build_detected=active_build_detected,
        build_dead_by_137=build_dead_by_137,
        source_runtime=source_runtime,
        health_ok=health_ok,
        listeners_ok=listeners_ok,
    )
    blockers = [
        "candidate_release_image_not_present" if no_candidate_image else None,
        "active_release_build_still_running" if active_build_detected else None,
        "release_build_dead_by_137_or_sigkill" if build_dead_by_137 else None,
        "live_container_is_source_runtime" if source_runtime else None,
        "live_source_runtime_unhealthy" if source_runtime and not health_ok else None,
        "live_listener_missing" if source_runtime and not listeners_ok else None,
    ]
    return {
        "overall_status": "blocked",
        "candidate_release_images_ready": candidate_ready,
        "candidate_release_image_missing": no_candidate_image,
        "active_build_detected": active_build_detected,
        "release_build_dead_by_137": build_dead_by_137,
        "recent_kill_evidence_count": len(kill_lines),
        "recent_build_kill_evidence_count": len(build_kill_lines),
        "recent_build_kill_evidence": build_kill_lines[:20],
        "live_health_ok": health_ok,
        "listeners_ok": listeners_ok,
        "live_container_source_runtime": source_runtime,
        "live_container_source_runtime_healthy": source_runtime_healthy,
        "live_container_image": live_container["image"]["stdout"],
        "live_container_state": live_container["state"]["stdout"],
        "live_container_oom_killed": live_container["oom_killed"]["stdout"],
        "classifications": classifications,
        "next_action": next_action,
        "retry_local_recommended": next_action
        not in {
            "build_active_wait_or_monitor_do_not_retry_or_retag_concurrently",
            "move_build_to_clean_runner_or_more_memory_before_retrying_local_host",
        },
        "clean_runner_recommended": next_action
        in {
            "move_build_to_clean_runner_or_more_memory_before_retrying_local_host",
            "no_candidate_but_source_runtime_healthy_start_release_build_on_clean_runner",
        },
        "blockers": [blocker for blocker in blockers if blocker],
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    summary = report["summary"]
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Host: `{report['inputs']['ssh_target']}`",
        f"- Overall status: `{summary['overall_status']}`",
        f"- Candidate release images ready: `{', '.join(summary['candidate_release_images_ready']) or 'none'}`",
        f"- Active build detected: `{summary['active_build_detected']}`",
        f"- Recent kill evidence lines: `{summary['recent_kill_evidence_count']}`",
        f"- Recent build kill evidence lines: `{summary['recent_build_kill_evidence_count']}`",
        f"- Release build dead by 137/SIGKILL: `{summary['release_build_dead_by_137']}`",
        f"- Live health OK: `{summary['live_health_ok']}`",
        f"- Live listeners OK: `{summary['listeners_ok']}`",
        f"- Live container source-runtime: `{summary['live_container_source_runtime']}`",
        f"- Live source-runtime healthy: `{summary['live_container_source_runtime_healthy']}`",
        f"- Next action: `{summary['next_action']}`",
        "",
        "## Classifications",
        "",
    ]
    for name, classification in summary["classifications"].items():
        lines.append(
            f"- `{name}`: `{classification['status']}`; present=`{classification['present']}`; {classification['detail']}"
        )
    lines.extend(
        [
            "",
        "## Active Build Lines",
        "",
        ]
    )
    if report["active_build_processes"]:
        lines.extend(f"- `{line}`" for line in report["active_build_processes"])
    else:
        lines.append("- None detected.")
    lines.extend(["", "## Build Kill Evidence", ""])
    if summary["recent_build_kill_evidence"]:
        lines.extend(f"- `{line}`" for line in summary["recent_build_kill_evidence"])
    else:
        lines.append("- None detected.")
    lines.extend(["", "## Blockers", ""])
    for blocker in summary["blockers"]:
        if blocker:
            lines.append(f"- `{blocker}`")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            report["claim_boundary"],
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    started_at = utc_now()
    host_time = ssh(args, ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], timeout=args.command_timeout)
    host_epoch = ssh(args, ["date", "+%s"], timeout=args.command_timeout)
    delta = relative_delta(args.since)
    if delta and host_epoch["returncode"] == 0 and host_epoch["stdout"].strip().isdigit():
        remote_now = datetime.fromtimestamp(int(host_epoch["stdout"].strip()), timezone.utc)
        event_since = (remote_now - delta).isoformat().replace("+00:00", "Z")
        event_until = remote_now.isoformat().replace("+00:00", "Z")
    else:
        event_since = args.since
        event_until = host_time["stdout"] or started_at
    docker_ps = ssh(args, ["docker", "ps", "--no-trunc"], timeout=args.command_timeout)
    docker_images = ssh(args, ["docker", "image", "ls", "docker_server", "--no-trunc"], timeout=args.command_timeout)
    live_container = {
        "image": ssh(args, ["docker", "inspect", "--format={{.Config.Image}}", args.container_name], timeout=args.command_timeout),
        "state": ssh(args, ["docker", "inspect", "--format={{.State.Status}}", args.container_name], timeout=args.command_timeout),
        "oom_killed": ssh(args, ["docker", "inspect", "--format={{.State.OOMKilled}}", args.container_name], timeout=args.command_timeout),
    }
    pgrep_docker = ssh(args, ["pgrep", "-af", "docker"], timeout=args.command_timeout)
    pgrep_mix = ssh(args, ["pgrep", "-af", "mix"], timeout=args.command_timeout)
    docker_journal = ssh(args, ["journalctl", "-u", "docker", "-S", args.since, "--no-pager"], timeout=args.journal_timeout)
    kernel_journal = ssh(args, ["journalctl", "-k", "-S", args.since, "--no-pager"], timeout=args.journal_timeout)
    docker_events = ssh(
        args,
        ["docker", "events", "--since", event_since, "--until", event_until, "--filter", "event=die", "--filter", "event=kill"],
        timeout=args.events_timeout,
    )
    candidate_images = {
        tag: {
            "id": ssh(args, ["docker", "image", "inspect", "--format={{.Id}}", f"docker_server:{tag}"], timeout=args.command_timeout),
            "created": ssh(args, ["docker", "image", "inspect", "--format={{.Created}}", f"docker_server:{tag}"], timeout=args.command_timeout),
        }
        for tag in args.candidate_tag
    }
    report = {
        "schema_version": 1,
        "run_id": f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{PROFILE_ID}",
        "started_at": started_at,
        "finished_at": utc_now(),
        "profile": {"profile_id": PROFILE_ID, "name": PROFILE_NAME, "platform": "server"},
        "benchmark_lane": "server-release-readiness",
        "git": git_snapshot(),
        "inputs": {
            "ssh_target": args.ssh_target,
            "container_name": args.container_name,
            "candidate_tags": args.candidate_tag,
            "since": args.since,
            "event_since": event_since,
            "event_until": event_until,
            "health_url": args.health_url,
            "tcp_host": args.tcp_host,
        },
        "host_time": host_time,
        "host_epoch": host_epoch,
        "docker_ps": docker_ps,
        "docker_images": docker_images,
        "live_container": live_container,
        "candidate_images": candidate_images,
        "active_build_processes": filter_lines(pgrep_docker["stdout"] + "\n" + pgrep_mix["stdout"], BUILD_PATTERNS),
        "recent_kill_evidence": {
            "docker_journal_matches": filter_lines(docker_journal["stdout"], KILL_PATTERNS + ("product-lab",)),
            "kernel_journal_matches": filter_lines(kernel_journal["stdout"], KILL_PATTERNS),
            "docker_event_matches": filter_lines(docker_events["stdout"], KILL_PATTERNS + ("product-lab",)),
            "docker_journal_returncode": docker_journal["returncode"],
            "kernel_journal_returncode": kernel_journal["returncode"],
            "docker_events_returncode": docker_events["returncode"],
            "docker_events_stderr": docker_events["stderr"][-1000:],
        },
        "health": health_probe(args.health_url, args.http_timeout) if args.health_url else {"skipped": "no health URL"},
        "listeners": [tcp_probe(args.tcp_host, port, args.http_timeout) for port in args.tcp_port] if args.tcp_host else [],
        "claim_boundary": (
            "Read-only lab evidence only. The probe does not build, retag, pull, push, deploy, "
            "stop, restart, kill, docker exec, docker run, or create temporary containers."
        ),
    }
    report["summary"] = summarize(report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-target", default="root@192.168.12.146")
    parser.add_argument("--ssh-bin", default="ssh")
    parser.add_argument("--connect-timeout", type=int, default=5)
    parser.add_argument("--command-timeout", type=int, default=30)
    parser.add_argument("--journal-timeout", type=int, default=30)
    parser.add_argument("--events-timeout", type=int, default=30)
    parser.add_argument("--container-name", default="tamandua-server-light")
    parser.add_argument("--candidate-tag", action="append", default=[])
    parser.add_argument("--since", default="-2h")
    parser.add_argument("--health-url", default="http://192.168.12.146:4000/api/v1/health")
    parser.add_argument("--tcp-host", default="192.168.12.146")
    parser.add_argument("--tcp-port", action="append", type=int, default=[4000, 8443])
    parser.add_argument("--http-timeout", type=int, default=5)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.candidate_tag:
        args.candidate_tag = ["product-lab-cec17805-20260707", "product-lab-db9030a0-20260707"]

    report = build_report(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{report['run_id']}.json"
    md_path = args.output_dir / f"{report['run_id']}.md"
    write_json(json_path, report)
    write_markdown(md_path, report)
    print(f"server_release_build_readonly_probe={report['summary']['overall_status']} json={json_path} markdown={md_path}")
    return 2 if report["summary"]["overall_status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
