#!/usr/bin/env python3
"""Server release image preflight probe.

Verifies a Tamandua server release image without retagging, pushing, promoting,
or replacing a deployment. By default the probe only inspects a named Docker
image and optional live container/URL evidence. A short-lived smoke container is
available behind --smoke-run for release labs that provide the required env.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"


PROFILE_ID = "server-release-image-probe"
PROFILE_NAME = "Server Release Image Probe"
DEFAULT_HEALTH_PATH = "/api/v1/health"
SECRET_MARKERS = ("SECRET", "TOKEN", "PASSWORD", "KEY", "DATABASE_URL")
MTLS_ENV_KEYS = {
    "AGENT_MTLS_ENABLED",
    "AGENT_MTLS_PORT",
    "AGENT_MTLS_CERTFILE",
    "AGENT_MTLS_KEYFILE",
    "AGENT_MTLS_CLIENT_CA_CERTFILE",
    "CA_CERT_PATH",
    "MTLS_REQUIRED",
}


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(args: list[str], *, timeout: int = 30) -> CommandResult:
    try:
        completed = subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return CommandResult(args, completed.returncode, completed.stdout.strip(), completed.stderr.strip())
    except FileNotFoundError as exc:
        return CommandResult(args, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return CommandResult(args, 124, stdout.strip(), f"timeout after {timeout}s\n{stderr}".strip())


def git_snapshot() -> dict[str, Any]:
    def git(args: list[str]) -> str:
        try:
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
        except OSError:
            return ""

    commit = git(["git", "rev-parse", "HEAD"])
    status = git(["git", "status", "--short"]).splitlines()
    return {"commit": commit, "commit_short": commit[:8] if commit else "", "dirty": bool(status), "status_short": status}


def status_rank(status: str) -> int:
    return {"ok": 0, "degraded": 1, "blocked": 2}.get(status, 2)


def redact(value: str) -> str:
    redacted = value
    for marker in SECRET_MARKERS:
        if marker in redacted.upper():
            return "<redacted>"
    return redacted


def docker_base(args: argparse.Namespace) -> list[str]:
    base = [args.docker_bin]
    if args.docker_context:
        base.extend(["--context", args.docker_context])
    if args.docker_host:
        base.extend(["-H", args.docker_host])
    return base


def docker(args: argparse.Namespace, tail: list[str], *, timeout: int = 30) -> CommandResult:
    return run(docker_base(args) + tail, timeout=timeout)


def check(check_id: str, name: str, status: str, evidence: dict[str, Any], blocker: str | None = None) -> dict[str, Any]:
    return {
        "id": check_id,
        "name": name,
        "status": status,
        "blocker": blocker,
        "evidence": evidence,
    }


def parse_json(text: str, fallback: Any) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return fallback


def inspect_image(args: argparse.Namespace) -> tuple[dict[str, Any], bool]:
    result = docker(args, ["image", "inspect", args.image], timeout=args.docker_timeout)
    exists = result.returncode == 0
    evidence: dict[str, Any] = {
        "image": args.image,
        "docker_context": args.docker_context,
        "docker_host_set": bool(args.docker_host),
        "returncode": result.returncode,
    }
    if exists:
        data = parse_json(result.stdout, [])
        image_info = data[0] if isinstance(data, list) and data else {}
        config = image_info.get("Config") or {}
        evidence.update(
            {
                "id": image_info.get("Id"),
                "repo_tags": image_info.get("RepoTags") or [],
                "created": image_info.get("Created"),
                "entrypoint": config.get("Entrypoint") or [],
                "cmd": config.get("Cmd") or [],
                "labels": config.get("Labels") or {},
            }
        )
        return check("image-exists", "Docker release image exists locally/in selected context", "ok", evidence), True

    evidence["stderr"] = result.stderr[-800:]
    return check("image-exists", "Docker release image exists locally/in selected context", "blocked", evidence, "image_not_found_or_docker_unavailable"), False


def inspect_release_binary(args: argparse.Namespace, image_exists: bool) -> dict[str, Any]:
    if not image_exists:
        return check("release-binary", "Image contains executable /app/bin/tamandua_server", "blocked", {"skipped": "image missing"}, "image_missing")

    command = "test -x /app/bin/tamandua_server && printf 'present\\n' && /app/bin/tamandua_server version 2>/dev/null || true"
    result = docker(
        args,
        ["run", "--rm", "--entrypoint", "/bin/sh", args.image, "-lc", command],
        timeout=args.docker_timeout,
    )
    evidence = {
        "returncode": result.returncode,
        "stdout": result.stdout[-1000:],
        "stderr": result.stderr[-1000:],
        "command_effect": "short-lived docker run --rm; no ports, no deploy, no tag changes",
    }
    if result.returncode == 0 and result.stdout.strip():
        return check("release-binary", "Image contains executable /app/bin/tamandua_server", "ok", evidence)
    return check("release-binary", "Image contains executable /app/bin/tamandua_server", "blocked", evidence, "release_binary_missing_or_not_executable")


def inspect_image_command(args: argparse.Namespace, image_exists: bool) -> dict[str, Any]:
    if not image_exists:
        return check("release-command", "Image command starts the compiled release", "blocked", {"skipped": "image missing"}, "image_missing")
    result = docker(args, ["image", "inspect", args.image], timeout=args.docker_timeout)
    data = parse_json(result.stdout, [])
    image_info = data[0] if isinstance(data, list) and data else {}
    config = image_info.get("Config") or {}
    entrypoint = config.get("Entrypoint") or []
    cmd = config.get("Cmd") or []
    combined = " ".join(str(part) for part in entrypoint + cmd)
    status = "ok" if "bin/tamandua_server" in combined else "degraded"
    blocker = None if status == "ok" else "release_start_command_not_explicit"
    return check("release-command", "Image command starts the compiled release", status, {"entrypoint": entrypoint, "cmd": cmd}, blocker)


def http_health(url: str, timeout: int) -> dict[str, Any]:
    started = utc_now()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "tamandua-server-release-image-probe"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
            return {
                "started_at": started,
                "status_code": response.status,
                "body_prefix": body[:500],
                "ok": 200 <= response.status < 300,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(1024).decode("utf-8", errors="replace")
        return {"started_at": started, "status_code": exc.code, "body_prefix": body[:500], "ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - report transport failure as evidence
        return {"started_at": started, "ok": False, "error": str(exc)}


def inspect_container_health(args: argparse.Namespace, container_name: str) -> dict[str, Any]:
    result = docker(args, ["inspect", container_name], timeout=args.docker_timeout)
    evidence: dict[str, Any] = {"container": container_name, "inspect_returncode": result.returncode}
    if result.returncode != 0:
        evidence["stderr"] = result.stderr[-800:]
        return check("health-endpoint", "Server health endpoint responds", "blocked", evidence, "container_not_found")

    data = parse_json(result.stdout, [])
    container = data[0] if isinstance(data, list) and data else {}
    state = container.get("State") or {}
    health = state.get("Health") or {}
    evidence.update({"running": state.get("Running"), "container_health": health.get("Status")})

    curl = docker(
        args,
        ["exec", container_name, "sh", "-lc", f"curl -fsS http://127.0.0.1:4000{DEFAULT_HEALTH_PATH}"],
        timeout=args.docker_timeout,
    )
    evidence.update({"curl_returncode": curl.returncode, "curl_stdout": curl.stdout[:500], "curl_stderr": curl.stderr[-500:]})
    if curl.returncode == 0:
        return check("health-endpoint", "Server health endpoint responds", "ok", evidence)
    if health.get("Status") == "healthy":
        return check("health-endpoint", "Server health endpoint responds", "degraded", evidence, "container_health_ok_but_direct_health_probe_failed")
    return check("health-endpoint", "Server health endpoint responds", "blocked", evidence, "health_endpoint_failed")


def check_health(args: argparse.Namespace, smoke_container: str | None) -> dict[str, Any]:
    if args.health_url:
        evidence = http_health(args.health_url, args.http_timeout)
        status = "ok" if evidence["ok"] else "blocked"
        return check("health-endpoint", "Server health endpoint responds", status, {"url": args.health_url, **evidence}, None if status == "ok" else "health_endpoint_failed")
    container_name = smoke_container or args.container_name
    if container_name:
        return inspect_container_health(args, container_name)
    return check("health-endpoint", "Server health endpoint responds", "blocked", {"missing_inputs": ["--health-url", "--container-name", "or --smoke-run"]}, "health_target_missing")


def tcp_probe(host: str, port: int, timeout: int) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"host": host, "port": port, "open": True}
    except OSError as exc:
        return {"host": host, "port": port, "open": False, "error": str(exc)}


def check_listeners(args: argparse.Namespace, smoke_container: str | None) -> dict[str, Any]:
    ports = [args.http_port]
    if args.expect_mtls:
        ports.append(args.mtls_port)
    if args.tcp_host:
        probes = [tcp_probe(args.tcp_host, port, args.http_timeout) for port in ports]
        blocked = [probe for probe in probes if not probe["open"]]
        status = "ok" if not blocked else "blocked"
        return check("listeners", "HTTP and mTLS listener ports are open", status, {"tcp_probes": probes}, None if status == "ok" else "listener_port_closed")

    container_name = smoke_container or args.container_name
    if not container_name:
        return check("listeners", "HTTP and mTLS listener ports are open", "blocked", {"missing_inputs": ["--tcp-host", "--container-name", "or --smoke-run"]}, "listener_target_missing")

    script = "ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6"
    result = docker(args, ["exec", container_name, "sh", "-lc", script], timeout=args.docker_timeout)
    output = result.stdout
    hits = {
        str(args.http_port): (f":{args.http_port} " in output or f":{args.http_port}\n" in output or f":{args.http_port}," in output or ":0FA0" in output.upper()),
        str(args.mtls_port): (f":{args.mtls_port} " in output or f":{args.mtls_port}\n" in output or f":{args.mtls_port}," in output or ":20FB" in output.upper()),
    }
    required = [str(args.http_port)] + ([str(args.mtls_port)] if args.expect_mtls else [])
    missing = [port for port in required if not hits.get(port)]
    status = "ok" if result.returncode == 0 and not missing else "blocked"
    return check(
        "listeners",
        "HTTP and mTLS listener ports are open",
        status,
        {"container": container_name, "returncode": result.returncode, "required_ports": required, "port_hits": hits, "output_prefix": output[:1200], "stderr": result.stderr[-500:]},
        None if status == "ok" else "listener_port_missing",
    )


def container_mtls_env(args: argparse.Namespace, container_name: str) -> dict[str, str]:
    result = docker(args, ["inspect", container_name], timeout=args.docker_timeout)
    if result.returncode != 0:
        return {}
    data = parse_json(result.stdout, [])
    container = data[0] if isinstance(data, list) and data else {}
    env_items = ((container.get("Config") or {}).get("Env") or [])
    values: dict[str, str] = {}
    for item in env_items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key in MTLS_ENV_KEYS:
            values[key] = value
    return values


def check_mtls(args: argparse.Namespace, smoke_container: str | None) -> dict[str, Any]:
    container_name = smoke_container or args.container_name
    if not container_name:
        return check("mtls-cert-chain", "mTLS cert/key/CA paths and server certificate chain verify", "blocked", {"missing_inputs": ["--container-name", "or --smoke-run"]}, "mtls_container_target_missing")

    env = container_mtls_env(args, container_name)
    mtls_enabled = env.get("AGENT_MTLS_ENABLED", "").lower() == "true"
    evidence: dict[str, Any] = {"container": container_name, "mtls_env": {key: redact(value) for key, value in env.items()}, "mtls_enabled": mtls_enabled}
    if args.expect_mtls and not mtls_enabled:
        return check("mtls-cert-chain", "mTLS cert/key/CA paths and server certificate chain verify", "blocked", evidence, "agent_mtls_not_enabled")

    certfile = env.get("AGENT_MTLS_CERTFILE")
    keyfile = env.get("AGENT_MTLS_KEYFILE")
    cafile = env.get("AGENT_MTLS_CLIENT_CA_CERTFILE") or env.get("CA_CERT_PATH")
    missing_paths = [name for name, value in [("AGENT_MTLS_CERTFILE", certfile), ("AGENT_MTLS_KEYFILE", keyfile), ("AGENT_MTLS_CLIENT_CA_CERTFILE/CA_CERT_PATH", cafile)] if not value]
    if missing_paths:
        evidence["missing_env_paths"] = missing_paths
        status = "blocked" if args.expect_mtls else "degraded"
        return check("mtls-cert-chain", "mTLS cert/key/CA paths and server certificate chain verify", status, evidence, "mtls_path_env_missing")

    path_script = f"test -r {certfile!r} && test -r {keyfile!r} && test -r {cafile!r}"
    readable = docker(args, ["exec", container_name, "sh", "-lc", path_script], timeout=args.docker_timeout)
    cert = docker(args, ["exec", container_name, "sh", "-lc", f"openssl x509 -in {certfile!r} -noout -subject -issuer -dates"], timeout=args.docker_timeout)
    ca = docker(args, ["exec", container_name, "sh", "-lc", f"openssl x509 -in {cafile!r} -noout -subject -issuer -dates"], timeout=args.docker_timeout)
    verify = docker(args, ["exec", container_name, "sh", "-lc", f"openssl verify -CAfile {cafile!r} {certfile!r}"], timeout=args.docker_timeout)
    evidence.update(
        {
            "paths_readable_returncode": readable.returncode,
            "server_cert": cert.stdout,
            "ca_cert": ca.stdout,
            "verify_stdout": verify.stdout,
            "verify_stderr": verify.stderr[-500:],
            "verify_returncode": verify.returncode,
        }
    )
    if readable.returncode == 0 and cert.returncode == 0 and ca.returncode == 0 and verify.returncode == 0:
        return check("mtls-cert-chain", "mTLS cert/key/CA paths and server certificate chain verify", "ok", evidence)
    return check("mtls-cert-chain", "mTLS cert/key/CA paths and server certificate chain verify", "blocked", evidence, "mtls_cert_chain_failed")


def check_rollback_notes() -> dict[str, Any]:
    paths = [
        ROOT / "docs" / "operations" / "SERVER_RELEASE_IMAGE_RUNBOOK.md",
        ROOT / "docs" / "operations" / "UPGRADE_PROCEDURES.md",
        ROOT / "docs" / "benchmarks" / "LAB_REESTABLISHMENT_PARALLEL_BOARD_20260706.md",
    ]
    required_terms = ["rollback", "previous image", "health", "mTLS", "tamandua_server"]
    found: dict[str, list[str]] = {}
    for path in paths:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        found[str(path.relative_to(ROOT))] = [term for term in required_terms if term.lower() in text]
    all_terms = {term for terms in found.values() for term in terms}
    missing = [term for term in required_terms if term not in all_terms]
    status = "ok" if not missing else "degraded"
    return check("rollback-notes", "Rollback notes exist for release-image smoke failures", status, {"checked_paths": list(found.keys()), "missing_terms": missing}, None if status == "ok" else "rollback_notes_incomplete")


def start_smoke_container(args: argparse.Namespace, image_exists: bool) -> tuple[str | None, dict[str, Any] | None]:
    if not args.smoke_run:
        return None, None
    if not image_exists:
        return None, {"status": "blocked", "blocker": "image_missing", "evidence": {"skipped": "image missing"}}

    name = args.smoke_name or f"tamandua-server-release-probe-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    env_args: list[str] = []
    if args.env_file:
        env_args.extend(["--env-file", str(args.env_file)])
    for env in args.env:
        env_args.extend(["-e", env])
    publish = []
    if args.smoke_publish:
        publish.extend(["-p", f"{args.http_port}:4000"])
        if args.expect_mtls:
            publish.extend(["-p", f"{args.mtls_port}:{args.mtls_port}"])
    result = docker(args, ["run", "-d", "--rm", "--name", name, *publish, *env_args, args.image], timeout=args.docker_timeout)
    if result.returncode != 0:
        return None, {"status": "blocked", "blocker": "smoke_container_start_failed", "evidence": {"returncode": result.returncode, "stderr": result.stderr[-1000:]}}
    return name, {"status": "ok", "evidence": {"container": name, "command_effect": "short-lived docker run --rm for smoke only; no tag or deployment promotion"}}


def stop_smoke_container(args: argparse.Namespace, name: str | None) -> dict[str, Any] | None:
    if not name:
        return None
    result = docker(args, ["stop", name], timeout=args.docker_timeout)
    return {"container": name, "returncode": result.returncode, "stdout": result.stdout[-500:], "stderr": result.stderr[-500:]}


def summarize(checks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"ok": 0, "degraded": 0, "blocked": 0}
    for item in checks:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    overall = "blocked" if counts["blocked"] else "degraded" if counts["degraded"] else "ok"
    return {
        "checks": len(checks),
        "ok": counts["ok"],
        "degraded": counts["degraded"],
        "blocked": counts["blocked"],
        "overall_status": overall,
        "blockers": [item for item in checks if item["status"] == "blocked"],
        "degraded_checks": [item for item in checks if item["status"] == "degraded"],
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Overall status: `{report['summary']['overall_status']}`",
        f"- Image: `{report['inputs']['image']}`",
        "- Runtime effect: no retag, push, pull, deploy promotion, compose update, or Kubernetes rollout.",
        "",
        "| Check | Status | Blocker |",
        "|-------|--------|---------|",
    ]
    for item in report["checks"]:
        lines.append(f"| `{item['id']}` | `{item['status']}` | `{item.get('blocker') or '-'}` |")
    lines.extend(["", "## Blockers", ""])
    if report["summary"]["blockers"]:
        for item in report["summary"]["blockers"]:
            lines.append(f"- `{item['id']}`: {item.get('blocker')}")
    else:
        lines.append("- None.")
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"], ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def build_report(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    started_at = utc_now()
    image_check, image_exists = inspect_image(args)
    smoke_container = None
    smoke_start: dict[str, Any] | None = None
    smoke_stop: dict[str, Any] | None = None
    try:
        smoke_container, smoke_start = start_smoke_container(args, image_exists)
        checks = [
            image_check,
            inspect_release_binary(args, image_exists),
            inspect_image_command(args, image_exists),
            check_health(args, smoke_container),
            check_listeners(args, smoke_container),
            check_mtls(args, smoke_container),
            check_rollback_notes(),
        ]
    finally:
        smoke_stop = stop_smoke_container(args, smoke_container)

    summary = summarize(checks)
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{PROFILE_ID}"
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": utc_now(),
        "profile_id": PROFILE_ID,
        "profile": {"profile_id": PROFILE_ID, "name": PROFILE_NAME, "platform": "server"},
        "benchmark_lane": "server-release-readiness",
        "git": git_snapshot(),
        "inputs": {
            "image": args.image,
            "container_name": args.container_name,
            "health_url": args.health_url,
            "tcp_host": args.tcp_host,
            "expect_mtls": args.expect_mtls,
            "smoke_run": args.smoke_run,
            "smoke_publish": args.smoke_publish,
        },
        "smoke_container": {"start": smoke_start, "stop": smoke_stop},
        "checks": checks,
        "summary": summary,
        "quality_gate": {
            "passed": summary["overall_status"] == "ok" or (summary["overall_status"] == "degraded" and not args.fail_on_degraded),
            "failures": [item["blocker"] for item in summary["blockers"] if item.get("blocker")],
            "thresholds": {"fail_on_blocked": True, "fail_on_degraded": args.fail_on_degraded},
        },
        "claim_boundary": (
            "This probe verifies release-image and optional live/smoke runtime evidence only. "
            "It does not pull images, retag, push, update compose/Helm manifests, promote a "
            "deployment, run migrations, rotate certificates, or prove production readiness."
        ),
    }
    exit_code = 2 if summary["blocked"] else 1 if args.fail_on_degraded and summary["degraded"] else 0
    return report, exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Docker image tag/digest to inspect, for example docker_server:product-lab-20260707")
    parser.add_argument("--container-name", help="Existing live/smoke container to inspect; no restart is performed")
    parser.add_argument("--health-url", help="External health URL to probe, for example http://192.168.12.146:4000/api/v1/health")
    parser.add_argument("--tcp-host", help="Host/IP for external listener checks")
    parser.add_argument("--http-port", type=int, default=4000)
    parser.add_argument("--mtls-port", type=int, default=8443)
    parser.add_argument("--expect-mtls", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--docker-bin", default="docker")
    parser.add_argument("--docker-context")
    parser.add_argument("--docker-host")
    parser.add_argument("--docker-timeout", type=int, default=30)
    parser.add_argument("--http-timeout", type=int, default=5)
    parser.add_argument("--smoke-run", action="store_true", help="Start a short-lived docker run --rm container for runtime checks")
    parser.add_argument("--smoke-name")
    parser.add_argument("--smoke-publish", action="store_true", help="Publish smoke ports to the host; only valid with --smoke-run")
    parser.add_argument("--env-file", type=Path, help="Env file for --smoke-run")
    parser.add_argument("-e", "--env", action="append", default=[], help="Env var for --smoke-run, KEY=VALUE")
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--fail-on-degraded", action="store_true")
    args = parser.parse_args()

    report, exit_code = build_report(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{report['run_id']}.json"
    md_path = args.output_dir / f"{report['run_id']}.md"
    write_json(json_path, report)
    write_markdown(md_path, report)
    print(f"server_release_image_probe={report['summary']['overall_status']} json={json_path} markdown={md_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
