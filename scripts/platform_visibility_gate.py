#!/usr/bin/env python3
"""Run platform visibility readiness gates as one claim-boundary check."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from platform_endpoint_health_bundle_probe import build_bundle


PLATFORMS = ("linux", "windows", "macos", "mobile")
LIVE_ENDPOINT_EVIDENCE_CLASS = "live_endpoint_health"
SYNTHETIC_EVIDENCE_CLASSES = {
    "synthetic",
    "synthetic_contract",
    "synthetic_parity",
    "readiness_fixture",
}
ENDPOINT_HEALTH_REQUIRED_FIELDS = (
    "endpoint_id",
    "platform",
    "collected_at",
    "source",
    "health",
)
ENDPOINT_HEALTH_REQUIRED_CHECKS = (
    "agent_running",
    "telemetry_recent",
    "clock_synchronized",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_json(value: str) -> dict[str, Any]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("gate output must be a JSON object")
    return parsed


def load_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        parsed = json.load(handle)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return parsed


def validate_endpoint_health_bundle(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "status": "not_provided",
            "evidence_class": "none",
            "checked_endpoints": 0,
            "failed_endpoints": [],
            "claim_boundary": (
                "No live endpoint health bundle was supplied. Platform results are "
                "readiness or fixture evidence only and must not be promoted to live "
                "endpoint evidence."
            ),
        }

    payload = load_json_file(path)
    errors: list[str] = []
    evidence_class = str(payload.get("evidence_class") or "")
    if evidence_class != LIVE_ENDPOINT_EVIDENCE_CLASS:
        errors.append(
            f"evidence_class must be {LIVE_ENDPOINT_EVIDENCE_CLASS!r}, got {evidence_class!r}"
        )
    if evidence_class in SYNTHETIC_EVIDENCE_CLASSES:
        errors.append("synthetic readiness evidence cannot satisfy live endpoint health")

    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        errors.append("endpoints must be a non-empty list")
        endpoints = []

    endpoint_results: list[dict[str, Any]] = []
    for index, endpoint in enumerate(endpoints):
        endpoint_errors: list[str] = []
        if not isinstance(endpoint, dict):
            endpoint_results.append(
                {
                    "index": index,
                    "endpoint_id": "<invalid>",
                    "platform": "<invalid>",
                    "status": "fail",
                    "errors": ["endpoint entry must be an object"],
                }
            )
            continue

        missing = [field for field in ENDPOINT_HEALTH_REQUIRED_FIELDS if field not in endpoint]
        if missing:
            endpoint_errors.append(f"missing required fields: {', '.join(missing)}")

        platform = str(endpoint.get("platform") or "")
        if platform not in PLATFORMS:
            endpoint_errors.append(f"platform must be one of {', '.join(PLATFORMS)}")

        source = str(endpoint.get("source") or "")
        if source not in {"agent_health_api", "agent_cli_health", "tamandua_ctl_health"}:
            endpoint_errors.append("source must identify a live agent health collection path")

        health = endpoint.get("health")
        if not isinstance(health, dict):
            endpoint_errors.append("health must be an object")
            health = {}
        missing_checks = [field for field in ENDPOINT_HEALTH_REQUIRED_CHECKS if field not in health]
        if missing_checks:
            endpoint_errors.append(f"missing health checks: {', '.join(missing_checks)}")
        false_checks = [
            field
            for field in ENDPOINT_HEALTH_REQUIRED_CHECKS
            if field in health and health.get(field) is not True
        ]
        if false_checks:
            endpoint_errors.append(f"health checks are not passing: {', '.join(false_checks)}")

        endpoint_results.append(
            {
                "index": index,
                "endpoint_id": str(endpoint.get("endpoint_id") or "<missing-endpoint-id>"),
                "platform": platform or "<missing-platform>",
                "status": "fail" if endpoint_errors else "pass",
                "errors": endpoint_errors,
                "health_checks": {
                    field: health.get(field) is True
                    for field in ENDPOINT_HEALTH_REQUIRED_CHECKS
                },
            }
        )

    failed_endpoints = [
        result["endpoint_id"] for result in endpoint_results if result["status"] != "pass"
    ]
    status = "fail" if errors or failed_endpoints else "pass"
    return {
        "status": status,
        "bundle": str(path),
        "bundle_id": payload.get("bundle_id"),
        "evidence_class": evidence_class or "missing",
        "checked_endpoints": len(endpoint_results),
        "failed_endpoints": failed_endpoints,
        "errors": errors,
        "claim_boundary": (
            "Live endpoint health means a supplied bundle reports recent agent health from "
            "a live collection path. It confirms agent-health presence for the listed "
            "endpoints only; it does not prove production detection efficacy, packet "
            "fidelity, or endpoint-wide prevention."
        ),
        "results": endpoint_results,
    }


def validate_endpoint_health_export(path: Path, temp_dir: Path) -> dict[str, Any]:
    try:
        payload = load_json_file(path)
        bundle, build_errors = build_bundle(payload)
    except Exception as exc:  # noqa: BLE001 - surface export parsing as gate JSON.
        return {
            "status": "fail",
            "source_export": str(path),
            "evidence_class": "missing",
            "checked_endpoints": 0,
            "failed_endpoints": [],
            "errors": [f"failed to build endpoint health bundle: {exc}"],
            "claim_boundary": (
                "Live endpoint health export must be Agent API JSON with live health "
                "signals. Readiness or synthetic exports cannot satisfy this gate."
            ),
        }

    if build_errors:
        return {
            "status": "fail",
            "source_export": str(path),
            "evidence_class": bundle.get("evidence_class", "missing"),
            "checked_endpoints": len(bundle.get("endpoints") or []),
            "failed_endpoints": [
                str(endpoint.get("endpoint_id") or "<missing-endpoint-id>")
                for endpoint in bundle.get("endpoints") or []
            ],
            "errors": build_errors,
            "claim_boundary": bundle.get("claim_boundary"),
            "generated_bundle": bundle,
        }

    bundle_path = temp_dir / "platform-endpoint-health-bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = validate_endpoint_health_bundle(bundle_path)
    result["source_export"] = str(path)
    result["generated_bundle"] = bundle
    return result


def default_linux_snapshot(temp_dir: Path) -> tuple[Path, Path]:
    snapshot = temp_dir / "linux-kernel-visibility-snapshot.json"
    config = temp_dir / "linux-kernel-visibility-config.json"
    snapshot.write_text(
        json.dumps(
            {
                "kernel": {"release": "6.8.0"},
                "btf": {"available": True},
                "capabilities": {"is_root": True},
                "auditd": {"active": True},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    config.write_text(
        json.dumps(
            {
                "feature_flags": {"ebpf": True, "auditd": True},
                "collectors": {"ebpf_enabled": True, "auditd_enabled": True},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return snapshot, config


def gate_command(
    root: Path,
    platform: str,
    args: argparse.Namespace,
    temp_dir: Path,
) -> list[str]:
    scripts = root / "tools" / "detection_validation" / "scripts"
    fixtures = root / "tools" / "detection_validation" / "fixtures"

    if platform == "linux":
        snapshot = args.linux_snapshot
        config = args.linux_config
        if snapshot is None:
            generated_snapshot, generated_config = default_linux_snapshot(temp_dir)
            snapshot = generated_snapshot
            config = config or generated_config
        command = [
            sys.executable,
            str(scripts / "linux_kernel_visibility_gate.py"),
            "--snapshot",
            str(snapshot),
        ]
        if config is not None:
            command.extend(["--config", str(config)])
        return command

    if platform == "windows":
        return [
            sys.executable,
            str(scripts / "windows_kernel_visibility_gate.py"),
            str(args.windows_fixture or fixtures / "windows_kernel_visibility_readiness_v1.json"),
        ]

    if platform == "macos":
        return [
            sys.executable,
            str(scripts / "macos_platform_visibility_gate.py"),
            str(args.macos_fixture or fixtures / "macos_platform_visibility_readiness_v1.json"),
        ]

    if platform == "mobile":
        return [
            sys.executable,
            str(scripts / "mobile_network_visibility_gate.py"),
            str(args.mobile_fixture or fixtures / "mobile_network_visibility_readiness_v1.json"),
        ]

    raise ValueError(f"unsupported platform {platform!r}")


def result_status(platform: str, payload: dict[str, Any], returncode: int) -> tuple[bool, str]:
    if platform == "linux":
        verdict = str(payload.get("verdict") or "")
        return returncode == 0 and verdict == "active", verdict or "fail"
    if returncode != 0:
        return False, str(payload.get("status") or "fail")
    status = str(payload.get("status") or "")
    return status == "pass", status or "unknown"


def run_gate(root: Path, platform: str, args: argparse.Namespace, temp_dir: Path) -> dict[str, Any]:
    command = gate_command(root, platform, args, temp_dir)
    completed = subprocess.run(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    payload: dict[str, Any]
    parse_error = None
    try:
        payload = load_json(completed.stdout)
    except Exception as exc:  # noqa: BLE001 - report parse failure in JSON summary.
        payload = {}
        parse_error = str(exc)

    ok, status = result_status(platform, payload, completed.returncode)
    return {
        "platform": platform,
        "status": status,
        "ok": ok,
        "returncode": completed.returncode,
        "kind": payload.get("kind") or payload.get("profile_id"),
        "payload": payload,
        "stderr": completed.stderr.strip(),
        "parse_error": parse_error,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        action="append",
        choices=PLATFORMS,
        help="Platform gate to run. Repeatable; defaults to all platforms.",
    )
    parser.add_argument("--linux-snapshot", type=Path)
    parser.add_argument("--linux-config", type=Path)
    parser.add_argument("--windows-fixture", type=Path)
    parser.add_argument("--macos-fixture", type=Path)
    parser.add_argument("--mobile-fixture", type=Path)
    parser.add_argument(
        "--endpoint-health-bundle",
        type=Path,
        help=(
            "Optional live endpoint health bundle. Defaults remain synthetic/readiness "
            "only when omitted."
        ),
    )
    parser.add_argument(
        "--endpoint-health-export",
        type=Path,
        help=(
            "Optional exported JSON from /api/v1/agents/data-sources/health or agent detail. "
            "The gate builds and validates a live endpoint health bundle from it."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.endpoint_health_bundle and args.endpoint_health_export:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "PlatformVisibilityGate",
                    "status": "fail",
                    "errors": [
                        "--endpoint-health-bundle and --endpoint-health-export are mutually exclusive"
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1

    platforms = args.platform or list(PLATFORMS)
    root = repo_root()
    with tempfile.TemporaryDirectory(prefix="tamandua-platform-visibility-") as raw_temp_dir:
        temp_dir = Path(raw_temp_dir)
        results = [run_gate(root, platform, args, temp_dir) for platform in platforms]
        if args.endpoint_health_export:
            endpoint_health = validate_endpoint_health_export(args.endpoint_health_export, temp_dir)
        else:
            endpoint_health = validate_endpoint_health_bundle(args.endpoint_health_bundle)

    failed = [result for result in results if not result["ok"]]
    endpoint_health_failed = endpoint_health["status"] == "fail"
    report = {
        "schema_version": 1,
        "kind": "PlatformVisibilityGate",
        "status": "fail" if failed or endpoint_health_failed else "pass",
        "checked_platforms": platforms,
        "failed_platforms": [result["platform"] for result in failed],
        "claim_boundary": (
            "Runs platform readiness gates for Linux, Windows, macOS, and mobile. "
            "Passing means fixtures or supplied snapshots satisfy claim-boundary "
            "contracts; it does not prove live production collection unless a separate "
            "live endpoint health bundle is supplied and passes."
        ),
        "endpoint_health_evidence": endpoint_health,
        "results": results,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failed or endpoint_health_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
