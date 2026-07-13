#!/usr/bin/env python3
"""Read-only Proxmox virtualization host readiness probe."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3


urllib3.disable_warnings()

try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False

PROFILE_ID = "proxmox-virtualization-host-readiness-probe"
PROFILE_NAME = "Proxmox Virtualization Host Readiness Probe"
COLLECTOR_NAME = "proxmox"
CAPABILITY_ID = "virtualization_host"
EVENT_TYPE = "virtualization_host_inventory"


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


def login(args: argparse.Namespace) -> tuple[requests.Session | None, dict[str, Any]]:
    session = requests.Session()
    session.verify = False
    session.trust_env = False
    base = f"https://{args.proxmox_host}:8006/api2/json"
    if not args.proxmox_password:
        return None, {
            "url": f"{base}/access/ticket",
            "status": None,
            "duration_ms": 0,
            "authenticated": False,
            "error": "missing_proxmox_password",
            "password_supplied": False,
            "required_env": "TAMANDUA_PROXMOX_PASSWORD",
        }

    started = time.monotonic()
    try:
        response = session.post(
            f"{base}/access/ticket",
            data={"username": args.proxmox_user, "password": args.proxmox_password},
            timeout=args.http_timeout_seconds,
        )
        evidence: dict[str, Any] = {
            "url": f"{base}/access/ticket",
            "status": response.status_code,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "authenticated": False,
        }
        if not response.ok:
            evidence["error"] = response.text[:1000]
            return None, evidence
        auth = response.json().get("data") or {}
        if not auth.get("ticket") or not auth.get("CSRFPreventionToken"):
            evidence["error"] = "missing_ticket_or_csrf"
            return None, evidence
        session.cookies.set("PVEAuthCookie", auth["ticket"])
        session.headers.update({"CSRFPreventionToken": auth["CSRFPreventionToken"]})
        evidence["authenticated"] = True
        return session, evidence
    except Exception as exc:
        return None, {
            "url": f"{base}/access/ticket",
            "status": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "authenticated": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def request_json(session: requests.Session, args: argparse.Namespace, path: str) -> dict[str, Any]:
    base = f"https://{args.proxmox_host}:8006/api2/json"
    started = time.monotonic()
    try:
        response = session.get(base + path, timeout=args.http_timeout_seconds)
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text[:1000]
        return {
            "method": "GET",
            "path": path,
            "status": response.status_code,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "ok": response.ok,
            "body": body,
        }
    except Exception as exc:
        return {
            "method": "GET",
            "path": path,
            "status": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def data_list(response: dict[str, Any]) -> list[dict[str, Any]]:
    body = response.get("body")
    data = body.get("data") if isinstance(body, dict) else None
    return data if isinstance(data, list) else []


def node_data(response: dict[str, Any]) -> dict[str, Any]:
    body = response.get("body")
    data = body.get("data") if isinstance(body, dict) else None
    return data if isinstance(data, dict) else {}


def make_result(
    test_id: str,
    name: str,
    passed: bool,
    category: str,
    evidence: dict[str, Any],
    fallback_used: bool = False,
) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": "none" if passed else category,
        "execution_class": "remote_api_probe",
        "claim_level": "proxmox_virtualization_host_readiness",
        "collector": COLLECTOR_NAME,
        "capability": CAPABILITY_ID,
        "event_type": EVENT_TYPE,
        "executor_used": PROFILE_ID,
        "fallback_used": fallback_used,
        "upstream_backed": False,
        "validation_category": category,
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
        "missing_expected_fields": [] if passed else ["required_proxmox_inventory_field"],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [EVENT_TYPE],
    }


def summarize_resources(resources: list[dict[str, Any]]) -> dict[str, Any]:
    qemu = [item for item in resources if item.get("type") == "qemu"]
    lxc = [item for item in resources if item.get("type") == "lxc"]
    nodes = [item for item in resources if item.get("type") == "node"]
    storage = [item for item in resources if item.get("type") == "storage"]
    return {
        "resource_count": len(resources),
        "node_count": len(nodes),
        "qemu_count": len(qemu),
        "lxc_count": len(lxc),
        "storage_count": len(storage),
        "running_guest_count": sum(1 for item in [*qemu, *lxc] if item.get("status") == "running"),
        "guest_inventory": [
            {
                "vmid": item.get("vmid"),
                "name": item.get("name"),
                "type": item.get("type"),
                "node": item.get("node"),
                "status": item.get("status"),
            }
            for item in [*qemu, *lxc]
        ],
    }


def nodes_from_cluster_resources(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "node": item.get("node"),
            "status": item.get("status"),
            "cpu": item.get("cpu"),
            "mem": item.get("mem"),
            "maxmem": item.get("maxmem"),
            "uptime": item.get("uptime"),
            "source": "cluster/resources",
        }
        for item in resources
        if item.get("type") == "node" and item.get("node")
    ]


def node_status_from_cluster_resource(node: dict[str, Any]) -> dict[str, Any]:
    status: dict[str, Any] = {}
    if node.get("cpu") is not None:
        status["cpu"] = node.get("cpu")
    if node.get("mem") is not None or node.get("maxmem") is not None:
        status["memory"] = {
            "used": node.get("mem"),
            "total": node.get("maxmem"),
        }
    if node.get("uptime") is not None:
        status["uptime"] = node.get("uptime")
    if node.get("status") is not None:
        status["status"] = node.get("status")
    if status:
        status["source"] = "cluster/resources"
    return status


def storage_from_cluster_resources(resources: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    storage_by_node: dict[str, list[dict[str, Any]]] = {}
    for item in resources:
        if item.get("type") != "storage":
            continue
        node = str(item.get("node") or "")
        if not node:
            continue
        storage_by_node.setdefault(node, []).append(
            {
                "storage": item.get("storage"),
                "status": item.get("status"),
                "content": item.get("content"),
                "disk": item.get("disk"),
                "maxdisk": item.get("maxdisk"),
                "plugintype": item.get("plugintype"),
                "source": "cluster/resources",
            }
        )
    return storage_by_node


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now()
    session, auth = login(args)
    tests = [
        make_result(
            "proxmox-api-authenticated",
            "Proxmox API accepts configured credentials",
            bool(auth.get("authenticated")),
            "auth",
            auth,
        )
    ]
    responses: dict[str, Any] = {"auth": auth}
    resources: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    node_status: dict[str, Any] = {}
    node_storage: dict[str, Any] = {}

    if session is not None:
        resources_response = request_json(session, args, "/cluster/resources")
        nodes_response = request_json(session, args, "/nodes")
        responses["cluster_resources"] = resources_response
        responses["nodes"] = nodes_response
        resources = data_list(resources_response)
        nodes = data_list(nodes_response)
        node_inventory_fallback = False
        if not nodes:
            nodes = nodes_from_cluster_resources(resources)
            node_inventory_fallback = bool(nodes)
        for node in nodes:
            node_name = str(node.get("node") or "")
            if not node_name:
                continue
            node_status[node_name] = request_json(session, args, f"/nodes/{node_name}/status")
            node_storage[node_name] = request_json(session, args, f"/nodes/{node_name}/storage")
        responses["node_status"] = node_status
        responses["node_storage"] = node_storage

        resource_summary = summarize_resources(resources)
        online_nodes = [item for item in nodes if str(item.get("status") or "").lower() == "online"]
        status_data = {node: node_data(response) for node, response in node_status.items()}
        resource_node_by_name = {
            str(item.get("node") or ""): item
            for item in nodes_from_cluster_resources(resources)
            if item.get("node")
        }
        node_status_fallback = False
        for item in online_nodes:
            node_name = str(item.get("node") or "")
            if not node_name:
                continue
            if not status_data.get(node_name):
                fallback_status = node_status_from_cluster_resource(resource_node_by_name.get(node_name, item))
                if fallback_status:
                    status_data[node_name] = fallback_status
                    node_status_fallback = True
        storage_items = {
            node: data_list(response)
            for node, response in node_storage.items()
            if bool(response.get("ok"))
        }
        storage_fallback = False
        if not storage_items:
            storage_items = storage_from_cluster_resources(resources)
            storage_fallback = bool(storage_items)
        tests.extend(
            [
                make_result(
                    "proxmox-cluster-resources-readable",
                    "Cluster resource inventory is readable",
                    bool(resources_response.get("ok")) and bool(resources),
                    "inventory",
                    resource_summary | {"status": resources_response.get("status")},
                ),
                make_result(
                    "proxmox-node-inventory-readable",
                    "Node inventory exposes at least one online node",
                    (bool(nodes_response.get("ok")) or node_inventory_fallback) and bool(online_nodes),
                    "node-inventory",
                    {
                        "status": nodes_response.get("status"),
                        "source": "nodes" if bool(nodes_response.get("ok")) else "cluster/resources",
                        "node_count": len(nodes),
                        "online_node_count": len(online_nodes),
                        "nodes": [
                            {
                                "node": item.get("node"),
                                "status": item.get("status"),
                                "cpu": item.get("cpu"),
                                "mem": item.get("mem"),
                                "maxmem": item.get("maxmem"),
                            }
                            for item in nodes
                        ],
                    },
                    fallback_used=node_inventory_fallback,
                ),
                make_result(
                    "proxmox-node-status-readable",
                    "Online node status exposes CPU, memory, and uptime fields",
                    bool(online_nodes)
                    and all(
                        {"cpu", "memory", "uptime"}.issubset(status_data.get(str(item.get("node") or ""), {}).keys())
                        for item in online_nodes
                    ),
                    "node-status",
                    {
                        "node_status": status_data,
                        "source": "node-status" if not node_status_fallback else "cluster/resources",
                    },
                    fallback_used=node_status_fallback,
                ),
                make_result(
                    "proxmox-guest-inventory-readable",
                    "Virtual machine or container inventory is readable",
                    bool(resources_response.get("ok")) and (resource_summary["qemu_count"] + resource_summary["lxc_count"] > 0),
                    "guest-inventory",
                    resource_summary,
                ),
                make_result(
                    "proxmox-storage-inventory-readable",
                    "Storage inventory is readable for discovered nodes",
                    bool(storage_items) and all(len(items) > 0 for items in storage_items.values()),
                    "storage-inventory",
                    {
                        "storage": storage_items,
                        "source": "node-storage" if not storage_fallback else "cluster/resources",
                    },
                    fallback_used=storage_fallback,
                ),
            ]
        )

    covered = sum(1 for item in tests if item["status"] == "covered")
    missed = len(tests) - covered
    passed = missed == 0
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"
    gap_counts = {
        category: sum(1 for item in tests if item["gap_category"] == category)
        for category in sorted({item["gap_category"] for item in tests if item["gap_category"] != "none"})
    }
    return {
        "schema_version": 1,
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "name": PROFILE_NAME,
        "collector": COLLECTOR_NAME,
        "capability": CAPABILITY_ID,
        "event_type": EVENT_TYPE,
        "mode": "execute",
        "benchmark_lane": "claim-boundary",
        "started_at": started,
        "finished_at": utc_now(),
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
            "missing_expected_fields": sum(len(item.get("missing_expected_fields") or []) for item in tests),
            "gap_category_counts": gap_counts,
            "executor_counts": {PROFILE_ID: len(tests)},
            "claim_level_counts": {"proxmox_virtualization_host_readiness": len(tests)},
            "category_coverage": {"proxmox_virtualization_host_readiness": {"covered": covered, "missed": missed}},
        },
        "quality_gate": {
            "passed": passed,
            "status": "pass" if passed else "fail",
            "failures": [] if passed else ["proxmox_virtualization_host_readiness_gaps"],
            "actionable_gaps": [item for item in tests if item["status"] != "covered"],
        },
        "scorecard": {
            "maturity_score": 100 if passed else max(20, int((covered / max(1, len(tests))) * 80)),
            "maturity_band": "proxmox-lab-inventory-readable" if passed else "proxmox-lab-inventory-blocked",
            "recommended_claim": (
                "Read-only Proxmox API inventory is readable for bounded lab readiness; not production validated"
                if passed
                else "Read-only Proxmox API inventory readiness has gaps; do not claim host readiness"
            ),
            "external_claim_allowed": False,
            "blocking_gaps": [] if passed else sorted(gap_counts),
            "covered_rate": covered / max(1, len(tests)),
            "telemetry_rate": 1.0,
            "field_quality": 1.0 if passed else covered / max(1, len(tests)),
            "context_quality": 1.0 if passed else covered / max(1, len(tests)),
            "analytic_quality": 1.0,
            "noise_quality": 1.0,
            "driver_quality": 1.0,
            "upstream_rate": 0.0,
        },
        EVENT_TYPE: {
            "host": args.proxmox_host,
            "collector": COLLECTOR_NAME,
            "capability": CAPABILITY_ID,
            "resource_summary": summarize_resources(resources),
            "responses": responses,
            "claim_boundary": (
                "Read-only Proxmox API inventory readiness only. This does not mutate guests, execute QGA commands, "
                "prove endpoint telemetry, prove detection coverage, or establish production virtualization posture. "
                "It is not production validated."
            ),
        },
        "tests": tests,
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    inventory = report[EVENT_TYPE]["resource_summary"]
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Nodes: `{inventory['node_count']}`",
        f"- QEMU guests: `{inventory['qemu_count']}`",
        f"- LXC guests: `{inventory['lxc_count']}`",
        "",
        "| Test | Status | Gap |",
        "|------|--------|-----|",
    ]
    for item in report["tests"]:
        lines.append(f"| `{item['id']}` | `{item['status']}` | `{item.get('gap_category') or 'none'}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            report[EVENT_TYPE]["claim_boundary"],
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    load_dotenv()
    parser = argparse.ArgumentParser(description=PROFILE_NAME)
    parser.add_argument("--proxmox-host", default=os.getenv("TAMANDUA_PROXMOX_HOST", "192.168.12.149"))
    parser.add_argument("--proxmox-user", default=os.getenv("TAMANDUA_PROXMOX_USER", "root@pam"))
    parser.add_argument("--proxmox-password", default=os.getenv("TAMANDUA_PROXMOX_PASSWORD"))
    parser.add_argument("--http-timeout-seconds", type=int, default=int(os.getenv("TAMANDUA_PROXMOX_HTTP_TIMEOUT_SECONDS", "20")))
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{report['run_id']}.json"
    comparison_path = output_dir / f"{report['run_id']}.comparison.json"
    md_path = output_dir / f"{report['run_id']}.md"
    payload = json.dumps(report, indent=2, sort_keys=True)
    json_path.write_text(payload + "\n", encoding="utf-8")
    comparison_path.write_text(payload + "\n", encoding="utf-8")
    write_markdown(report, md_path)
    print(
        "proxmox_virtualization_host_readiness="
        f"{'ok' if report['quality_gate']['passed'] else 'gaps'} json={json_path} markdown={md_path}"
    )
    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
