#!/usr/bin/env python3
"""Read-only Windows/Linux+Proxmox lab readiness matrix probe.

This probe consolidates separate readiness layers without executing guest
commands. QGA guest-exec state is inferred only from prior artifacts or marked
as blocked/not-retested so a wedged guest-exec channel is not hammered.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "lab-windows-proxmox-readiness-matrix-probe"
PROFILE_NAME = "Lab Windows/Linux+Proxmox Readiness Matrix Probe"


def load_dotenv(path: Path = ROOT / ".env") -> None:
    if os.getenv("TAMANDUA_SKIP_DOTENV") or not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
            value = value[1:-1]
        os.environ[key] = value


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


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def import_script_module(name: str) -> Any:
    scripts_dir = str(Path(__file__).resolve().parent)
    if scripts_dir not in os.sys.path:
        os.sys.path.insert(0, scripts_dir)
    module = __import__(name)
    if hasattr(module, "ROOT"):
        module.ROOT = ROOT
    if hasattr(module, "RUNS_DIR"):
        module.RUNS_DIR = RUNS_DIR
    return module


def redact_command(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("<redacted>" if "password" in key.lower() or "token" in key.lower() else redact_command(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_command(item) for item in value]
    return value


def latest_profile_artifact(output_dir: Path, profile_id: str) -> Path | None:
    candidates = [
        path
        for path in output_dir.glob(f"*{profile_id}.json")
        if not path.name.endswith(".comparison.json")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def load_json(path: Path | None) -> dict[str, Any] | None:
    if not path or not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def agent_id(agent: dict[str, Any]) -> str:
    return str(agent.get("id") or agent.get("agent_id") or "")


def hostname(agent: dict[str, Any]) -> str:
    return str(agent.get("hostname") or agent.get("name") or agent_id(agent) or "")


def agent_status(agent: dict[str, Any]) -> str:
    return str(agent.get("status") or "").lower()


def agent_health(agent: dict[str, Any] | None) -> str:
    if not agent:
        return ""
    health = agent.get("health_status") or {}
    if isinstance(health, dict):
        return str(health.get("status") or "").lower()
    return str(health).lower()


def summarize_agent(agent: dict[str, Any] | None) -> dict[str, Any] | None:
    if not agent:
        return None
    health = agent.get("health_status") or {}
    metrics = health.get("metrics") if isinstance(health, dict) else {}
    return {
        "agent_id": agent_id(agent),
        "hostname": hostname(agent),
        "status": agent_status(agent),
        "health": str(health.get("status") or "").lower() if isinstance(health, dict) else str(health).lower(),
        "last_seen": agent.get("last_seen"),
        "os_type": agent.get("os_type"),
        "os_version": agent.get("os_version"),
        "metrics": metrics if isinstance(metrics, dict) else {},
    }


def find_backend_agent(agents: list[dict[str, Any]], expected_hostname: str, expected_agent_id: str | None) -> dict[str, Any] | None:
    if expected_agent_id:
        for agent in agents:
            if agent_id(agent) == expected_agent_id:
                return agent
    for agent in agents:
        if hostname(agent).lower() == expected_hostname.lower():
            return agent
    return None


def collect_backend_inventory(args: argparse.Namespace) -> dict[str, Any]:
    windows_backend = import_script_module("windows_lab_execution_readiness_probe")
    ctl = windows_backend.run_ctl(Path(args.ctl_path), args.server)
    agents = windows_backend.agents_from_ctl(ctl)
    expected_ids = dict(zip(args.expected_hostnames, args.expected_agent_ids or []))
    if any(find_backend_agent(agents, host, expected_ids.get(host)) is None for host in args.expected_hostnames):
        fallback = windows_backend.admin_web_agents(args.server)
        fallback_agents = windows_backend.agents_from_ctl(fallback)
        if fallback.get("ok") and len(fallback_agents) >= len(agents):
            return {
                "ok": True,
                "source": "admin_web_fallback",
                "ctl": {key: value for key, value in ctl.items() if key != "payload"},
                "admin_web_fallback": {key: value for key, value in fallback.items() if key != "payload"},
                "agents": fallback_agents,
            }
    return {
        "ok": bool(ctl.get("ok")),
        "source": "tamandua_ctl",
        "ctl": {key: value for key, value in ctl.items() if key != "payload"},
        "agents": agents,
    }


def collect_proxmox_host(args: argparse.Namespace) -> dict[str, Any]:
    proxmox_probe = import_script_module("proxmox_virtualization_host_readiness_probe")
    prox_args = argparse.Namespace(
        proxmox_host=args.proxmox_host,
        proxmox_user=args.proxmox_user,
        proxmox_password=args.proxmox_password,
        http_timeout_seconds=args.http_timeout_seconds,
        output_dir=str(args.output_dir),
    )
    report = proxmox_probe.build_report(prox_args)
    return {
        "ok": bool(report.get("quality_gate", {}).get("passed")),
        "run_id": report.get("run_id"),
        "quality_gate": report.get("quality_gate"),
        "summary": report.get("summary"),
        "resource_summary": (report.get("virtualization_host_inventory") or {}).get("resource_summary"),
    }


def collect_qga_identity(args: argparse.Namespace) -> dict[str, Any]:
    qga_identity = import_script_module("windows_proxmox_qga_identity_probe")
    qga_args = argparse.Namespace(
        proxmox_host=args.proxmox_host,
        proxmox_user=args.proxmox_user,
        proxmox_password=args.proxmox_password,
        proxmox_node=args.proxmox_node,
        vmids=",".join(str(item) for item in args.vmids),
        expected_hostnames=",".join(args.expected_hostnames),
        http_timeout_seconds=args.http_timeout_seconds,
        output_dir=str(args.output_dir),
    )
    report = qga_identity.build_report(qga_args)
    return {
        "ok": bool(report.get("quality_gate", {}).get("passed")),
        "run_id": report.get("run_id"),
        "quality_gate": report.get("quality_gate"),
        "summary": report.get("summary"),
        "vmids": report.get("vmids") or [],
    }


def exec_evidence_for_vmid(evidence: dict[str, Any] | None, vmid: str) -> dict[str, Any]:
    if not evidence:
        return {
            "status": "blocked_not_retested",
            "source": "readonly_probe_policy",
            "reason": "No fresh QGA guest-exec was run by this matrix probe.",
        }
    qga = evidence.get("proxmox_qga_readiness") if isinstance(evidence.get("proxmox_qga_readiness"), dict) else {}
    evidence_vmid = str(qga.get("vmid") or "")
    if evidence_vmid and evidence_vmid != str(vmid):
        return {
            "status": "blocked_not_retested",
            "source_run_id": evidence.get("run_id"),
            "reason": f"Latest guest-exec artifact is for VM {evidence_vmid}, not VM {vmid}.",
        }
    ready = bool(qga.get("ready_for_bounded_execution"))
    qga_exec = qga.get("qga_exec") if isinstance(qga.get("qga_exec"), dict) else {}
    return {
        "status": "ready_prior_evidence" if ready else "blocked_prior_evidence",
        "source_run_id": evidence.get("run_id"),
        "source_profile_id": evidence.get("profile_id"),
        "ready": ready,
        "error": qga_exec.get("error"),
        "start_status": ((qga_exec.get("start") or {}) if isinstance(qga_exec.get("start"), dict) else {}).get("status"),
        "runtime_effect": "artifact_read_only_no_guest_exec_rerun",
    }


def qga_readonly_status(vm: dict[str, Any]) -> str:
    responses = vm.get("responses") if isinstance(vm.get("responses"), dict) else {}
    if responses.get("hostname", {}).get("ok") and responses.get("network", {}).get("ok"):
        return "ready"
    if responses.get("hostname", {}).get("ok") or responses.get("network", {}).get("ok") or responses.get("qga_info", {}).get("ok"):
        return "partial"
    return "blocked"


def target_next_action(row: dict[str, Any], host_ready: bool) -> str:
    expected = row["expected_hostname"]
    if not host_ready:
        return "Restore Proxmox API/host inventory readiness, then rerun this read-only matrix."
    if row["power_status"] != "running":
        return f"Start VM {row['vmid']} for {expected}, then rerun the read-only matrix."
    if row["qga_readonly"] == "blocked":
        return f"Restore QGA read-only GETs for VM {row['vmid']} before any execution transport probe."
    if row["hostname_mismatch"]:
        return f"Fix guest identity for VM {row['vmid']} so expected hostname {expected} is visible through QGA read-only identity."
    if row["qga_readonly"] == "partial":
        return f"Restore complete QGA read-only identity for VM {row['vmid']} before any execution transport probe."
    if row["backend_inventory_status"] != "online":
        return f"Reconnect or re-enroll the {expected} Windows agent so the authoritative backend shows a fresh online row."
    if str(row["qga_exec_status"]).startswith("blocked"):
        return f"Plan one bounded execution-transport recovery for VM {row['vmid']}; do not stack guest-exec attempts."
    return "Readiness layers are aligned; proceed only with the next bounded Windows validation shard."


def linux_local_gate_status() -> dict[str, Any]:
    host_platform = platform.system().lower()
    if host_platform != "linux":
        return {
            "status": "skipped_non_linux_runner",
            "runner_platform": host_platform,
            "claim_boundary": (
                "The eBPF/LSM local host gate must run on the Linux lab host or a comparable Linux runner. "
                "This matrix records backend readiness only when executed from Windows."
            ),
        }
    return {
        "status": "local_linux_runner_available",
        "runner_platform": host_platform,
        "claim_boundary": (
            "Run linux_ebpf_readiness_probe.py for kernel/BTF/LSM/bpffs/capability evidence. "
            "This matrix does not load BPF programs."
        ),
    }


def linux_next_action(row: dict[str, Any]) -> str:
    expected = row["expected_hostname"]
    if row["backend_inventory_status"] != "online":
        return f"Reconnect or re-enroll {expected} through the supported Linux enrollment/token rotation path."
    if row["backend_health"] not in {"healthy", "degraded"}:
        return f"Restore {expected} health to healthy/degraded before treating Linux lab telemetry as stable."
    if row["local_ebpf_gate_status"] == "skipped_non_linux_runner":
        return f"Run linux_ebpf_readiness_probe.py on {expected} or a comparable Linux runner for kernel sensor gating."
    return "Linux backend identity is online; pair it with fresh Linux eBPF/LSM gate evidence before stronger sensor claims."


def build_linux_rows(args: argparse.Namespace, backend: dict[str, Any]) -> list[dict[str, Any]]:
    agents = backend.get("agents") if isinstance(backend.get("agents"), list) else []
    local_gate = linux_local_gate_status()
    rows = []
    for expected in args.linux_hostnames:
        backend_agent = find_backend_agent(agents, expected, None)
        row = {
            "expected_hostname": expected,
            "backend_inventory_source": backend.get("source"),
            "backend_inventory_present": backend_agent is not None,
            "backend_inventory_status": agent_status(backend_agent) if backend_agent else "missing",
            "backend_health": agent_health(backend_agent) if backend_agent else "missing",
            "backend_agent": summarize_agent(backend_agent),
            "local_ebpf_gate_status": local_gate["status"],
            "local_ebpf_gate": local_gate,
        }
        row["next_action"] = linux_next_action(row)
        rows.append(row)
    return rows


def build_matrix(args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now()
    host = collect_proxmox_host(args)
    backend = collect_backend_inventory(args)
    qga = collect_qga_identity(args)
    host_guests = {
        str(item.get("vmid")): item
        for item in (((host.get("resource_summary") or {}).get("guest_inventory") or []))
        if isinstance(item, dict)
    }
    evidence_path = Path(args.qga_exec_evidence) if args.qga_exec_evidence else latest_profile_artifact(
        RUNS_DIR,
        "windows-proxmox-qga-readiness-probe",
    )
    exec_evidence = load_json(evidence_path)
    expected_ids = dict(zip(args.expected_hostnames, args.expected_agent_ids or []))
    agents = backend.get("agents") if isinstance(backend.get("agents"), list) else []
    qga_by_vmid = {str(vm.get("vmid")): vm for vm in qga.get("vmids") or [] if isinstance(vm, dict)}
    rows: list[dict[str, Any]] = []

    for index, vmid in enumerate(args.vmids):
        expected = args.expected_hostnames[index] if index < len(args.expected_hostnames) else ""
        expected_id = expected_ids.get(expected)
        vm = qga_by_vmid.get(str(vmid), {})
        host_guest = host_guests.get(str(vmid), {})
        backend_agent = find_backend_agent(agents, expected, expected_id)
        guest_hostname = str(vm.get("guest_hostname") or "")
        backend_summary = summarize_agent(backend_agent)
        backend_hostname_mismatch = bool(backend_agent and expected and hostname(backend_agent).lower() != expected.lower())
        guest_hostname_mismatch = bool(expected and guest_hostname.lower() != expected.lower())
        missing_expected_guest_hostname = bool(expected and not guest_hostname)
        exec_state = exec_evidence_for_vmid(exec_evidence, str(vmid))
        row = {
            "vmid": str(vmid),
            "expected_hostname": expected,
            "expected_agent_id": expected_id,
            "proxmox_name": vm.get("proxmox_name") or host_guest.get("name"),
            "power_status": vm.get("power_status") or host_guest.get("status"),
            "qga_agent_enabled": vm.get("qga_agent_enabled"),
            "guest_hostname": guest_hostname or None,
            "qga_readonly": qga_readonly_status(vm),
            "qga_exec_status": exec_state["status"],
            "qga_exec_evidence": exec_state,
            "backend_inventory_source": backend.get("source"),
            "backend_inventory_present": backend_agent is not None,
            "backend_inventory_status": agent_status(backend_agent) if backend_agent else "missing",
            "backend_agent": backend_summary,
            "hostname_mismatch": guest_hostname_mismatch or backend_hostname_mismatch,
            "missing_expected_guest_hostname": missing_expected_guest_hostname,
            "guest_hostname_mismatch": guest_hostname_mismatch,
            "backend_hostname_mismatch": backend_hostname_mismatch,
            "network": vm.get("network") or [],
        }
        row["next_action"] = target_next_action(row, bool(host.get("ok")))
        rows.append(row)

    linux_rows = build_linux_rows(args, backend)
    blockers = []
    if not host.get("ok"):
        blockers.append("proxmox_host_readiness")
    if not backend.get("ok"):
        blockers.append("backend_inventory")
    for row in rows:
        if row["qga_readonly"] != "ready":
            blockers.append(f"{row['expected_hostname']}:qga_readonly_{row['qga_readonly']}")
        if str(row["qga_exec_status"]).startswith("blocked"):
            blockers.append(f"{row['expected_hostname']}:qga_exec_blocked")
        if row["missing_expected_guest_hostname"]:
            blockers.append(f"{row['expected_hostname']}:missing_expected_guest_hostname")
        if row["hostname_mismatch"]:
            blockers.append(f"{row['expected_hostname']}:expected_hostname_mismatch")
        if row["backend_inventory_status"] != "online":
            blockers.append(f"{row['expected_hostname']}:backend_inventory_{row['backend_inventory_status']}")
    for row in linux_rows:
        if row["backend_inventory_status"] != "online":
            blockers.append(f"{row['expected_hostname']}:backend_inventory_{row['backend_inventory_status']}")
        if row["backend_health"] not in {"healthy", "degraded"}:
            blockers.append(f"{row['expected_hostname']}:backend_health_{row['backend_health']}")
        if row["local_ebpf_gate_status"] == "skipped_non_linux_runner":
            blockers.append(f"{row['expected_hostname']}:linux_ebpf_gate_not_run_on_linux_runner")

    finished = utc_now()
    passed = not blockers
    return {
        "schema_version": 1,
        "run_id": f"{compact_stamp(started)}-{PROFILE_ID}",
        "profile_id": PROFILE_ID,
        "profile_name": PROFILE_NAME,
        "started_at": started,
        "finished_at": finished,
        "generated_at": finished,
        "benchmark_lane": "claim-boundary",
        "runtime_effect": "read_only_api_and_artifact_matrix",
        "claim_boundary": (
            "Read-only lab readiness matrix only. It reads Proxmox/QGA GET endpoints, authenticated backend inventory, "
            "and optional prior QGA exec artifacts. It does not execute guest commands, mutate guests, restart VMs, "
            "or prove detection coverage."
        ),
        "git": git_snapshot(),
        "inputs": {
            "server": args.server,
            "proxmox_host": args.proxmox_host,
            "proxmox_node": args.proxmox_node,
            "vmids": [str(item) for item in args.vmids],
            "expected_hostnames": args.expected_hostnames,
            "linux_hostnames": args.linux_hostnames,
            "qga_exec_evidence": str(evidence_path) if evidence_path else None,
        },
        "proxmox_host_readiness": redact_command(host),
        "qga_readonly_identity": redact_command(qga),
        "backend_inventory": {
            "ok": backend.get("ok"),
            "source": backend.get("source"),
            "agent_count": len(agents),
            "ctl": redact_command(backend.get("ctl")),
            "admin_web_fallback": redact_command(backend.get("admin_web_fallback")),
        },
        "matrix": rows,
        "linux_matrix": linux_rows,
        "summary": {
            "windows_target_count": len(rows),
            "linux_target_count": len(linux_rows),
            "ready_windows_targets": sum(1 for row in rows if row["next_action"].startswith("Readiness layers are aligned")),
            "linux_backend_online_targets": sum(1 for row in linux_rows if row["backend_inventory_status"] == "online"),
            "blockers": sorted(set(blockers)),
        },
        "quality_gate": {
            "passed": passed,
            "status": "pass" if passed else "fail",
            "failures": [] if passed else ["lab_windows_proxmox_readiness_matrix_gaps"],
            "blocking_gaps": sorted(set(blockers)),
        },
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Runtime effect: `{report['runtime_effect']}`",
        "",
        "| VMID | Expected | QGA Hostname | Power | QGA Read-only | QGA Exec | Backend | Hostname Mismatch | Next Action |",
        "|------|----------|--------------|-------|---------------|----------|---------|-------------------|-------------|",
    ]
    for row in report["matrix"]:
        lines.append(
            "| `{vmid}` | `{expected}` | `{guest}` | `{power}` | `{qga}` | `{exec_status}` | `{backend}` | `{mismatch}` | {action} |".format(
                vmid=row["vmid"],
                expected=row["expected_hostname"],
                guest=row.get("guest_hostname") or "-",
                power=row.get("power_status") or "-",
                qga=row["qga_readonly"],
                exec_status=row["qga_exec_status"],
                backend=row["backend_inventory_status"],
                mismatch=str(row["hostname_mismatch"]).lower(),
                action=row["next_action"],
            )
        )
    lines.extend(
        [
            "",
            "## Linux Backend Matrix",
            "",
            "| Expected | Backend | Health | eBPF Gate | Next Action |",
            "|----------|---------|--------|-----------|-------------|",
        ]
    )
    for row in report.get("linux_matrix") or []:
        lines.append(
            "| `{expected}` | `{backend}` | `{health}` | `{ebpf}` | {action} |".format(
                expected=row["expected_hostname"],
                backend=row["backend_inventory_status"],
                health=row["backend_health"],
                ebpf=row["local_ebpf_gate_status"],
                action=row["next_action"],
            )
        )
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


def parse_args() -> argparse.Namespace:
    load_dotenv()
    parser = argparse.ArgumentParser(description=PROFILE_NAME)
    parser.add_argument("--server", default=os.getenv("TAMANDUA_SERVER_URL", "http://192.168.12.146:4000"))
    parser.add_argument("--ctl-path", default=str(ROOT / "apps" / "tamandua_ctl" / "target" / "release" / "tamandua-ctl.exe"))
    parser.add_argument("--proxmox-host", default=os.getenv("TAMANDUA_PROXMOX_HOST", "192.168.12.149"))
    parser.add_argument("--proxmox-user", default=os.getenv("TAMANDUA_PROXMOX_USER", "root@pam"))
    parser.add_argument("--proxmox-password", default=os.getenv("TAMANDUA_PROXMOX_PASSWORD"))
    parser.add_argument("--proxmox-node", default=os.getenv("TAMANDUA_PROXMOX_NODE", "Default"))
    parser.add_argument("--http-timeout-seconds", type=int, default=int(os.getenv("TAMANDUA_PROXMOX_HTTP_TIMEOUT_SECONDS", "20")))
    parser.add_argument("--vmids", type=int, nargs="+", default=[1520, 1521])
    parser.add_argument("--expected-hostnames", nargs="+", default=["LAB-DC01", "LAB-WS01"])
    parser.add_argument("--expected-agent-ids", nargs="*", default=[])
    parser.add_argument("--linux-hostnames", nargs="+", default=["lab-linux01"])
    parser.add_argument("--qga-exec-evidence", default="")
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = build_matrix(args)
    json_path = args.output_dir / f"{report['run_id']}.json"
    md_path = args.output_dir / f"{report['run_id']}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(report, md_path)
    print(
        f"lab_windows_proxmox_readiness_matrix={'ok' if report['quality_gate']['passed'] else 'gaps'} "
        f"json={json_path} markdown={md_path}"
    )
    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
