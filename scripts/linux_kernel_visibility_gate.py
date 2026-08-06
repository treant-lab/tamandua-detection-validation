#!/usr/bin/env python3
"""Classify Linux kernel visibility readiness from a capability snapshot.

The gate is deliberately snapshot-driven: it does not inspect the local host
and does not load eBPF programs. It answers whether a supplied fixture/config
is sufficient to claim active, degraded, or unavailable eBPF/auditd/kernel
visibility.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


MIN_KERNEL = (5, 8)
CAP_BPF_BIT = 39
CAP_PERFMON_BIT = 38


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def parse_kernel(value: Any) -> tuple[int, int, int] | None:
    if isinstance(value, list | tuple) and len(value) >= 2:
        try:
            major = int(value[0])
            minor = int(value[1])
            patch = int(value[2]) if len(value) > 2 else 0
            return major, minor, patch
        except (TypeError, ValueError):
            return None
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", str(value or ""))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def get_nested(data: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def truthy(data: dict[str, Any], *paths: str) -> bool:
    return any(bool(get_nested(data, path)) for path in paths)


def has_cap_bit(cap_eff: Any, bit: int) -> bool:
    if cap_eff in (None, ""):
        return False
    try:
        return bool(int(str(cap_eff), 16) & (1 << bit))
    except ValueError:
        return False


def capability_present(snapshot: dict[str, Any], name: str, bit: int) -> bool:
    caps = snapshot.get("capabilities", {})
    if not isinstance(caps, dict):
        caps = {}
    normalized = name.lower()
    values = {
        key.lower(): value
        for key, value in caps.items()
        if isinstance(key, str)
    }
    if bool(values.get(normalized)):
        return True
    if bool(values.get(normalized.replace("cap_", ""))):
        return True
    if bool(values.get(normalized.upper())):
        return True
    return has_cap_bit(values.get("capeff") or values.get("cap_eff"), bit)


def merged_config(snapshot: dict[str, Any], explicit: dict[str, Any] | None) -> dict[str, Any]:
    embedded = snapshot.get("config")
    base = embedded if isinstance(embedded, dict) else {}
    if not explicit:
        return dict(base)
    merged = dict(base)
    merged.update(explicit)
    return merged


def classify(snapshot: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = merged_config(snapshot, config)
    kernel_value = (
        get_nested(snapshot, "kernel.release")
        or get_nested(snapshot, "kernel.version")
        or snapshot.get("kernel_release")
        or snapshot.get("kernel")
    )
    parsed = parse_kernel(kernel_value)
    kernel_ok = bool(parsed and (parsed[0], parsed[1]) >= MIN_KERNEL)
    btf_ok = truthy(snapshot, "btf.available", "btf", "kernel.btf")
    is_root = bool(get_nested(snapshot, "capabilities.is_root") or snapshot.get("is_root"))
    cap_bpf = capability_present(snapshot, "cap_bpf", CAP_BPF_BIT)
    cap_perfmon = capability_present(snapshot, "cap_perfmon", CAP_PERFMON_BIT)
    privilege_ok = is_root or (cap_bpf and cap_perfmon)
    ebpf_flag = truthy(cfg, "feature_flags.ebpf", "features.ebpf", "ebpf")
    ebpf_config = truthy(cfg, "collectors.ebpf_enabled", "collectors.ebpf.enabled", "ebpf_enabled")
    auditd_config = truthy(cfg, "feature_flags.auditd", "collectors.auditd_enabled", "collectors.auditd.enabled")
    auditd_available = truthy(snapshot, "auditd.active", "auditd.available", "services.auditd.active")

    checks = {
        "kernel_minimum_5_8": kernel_ok,
        "btf_available": btf_ok,
        "ebpf_feature_flag": ebpf_flag,
        "ebpf_config_enabled": ebpf_config,
        "cap_bpf_and_cap_perfmon_or_root": privilege_ok,
        "auditd_configured": auditd_config,
        "auditd_available": auditd_available,
    }
    required = (
        "kernel_minimum_5_8",
        "btf_available",
        "ebpf_feature_flag",
        "ebpf_config_enabled",
        "cap_bpf_and_cap_perfmon_or_root",
    )
    missing_required = [name for name in required if not checks[name]]
    missing_optional = [
        name for name in ("auditd_configured", "auditd_available") if not checks[name]
    ]

    if not missing_required:
        verdict = "active" if not missing_optional else "degraded"
    elif kernel_ok and btf_ok and (ebpf_flag or ebpf_config):
        verdict = "degraded"
    else:
        verdict = "unavailable"

    return {
        "profile_id": "linux-kernel-visibility-readiness",
        "verdict": verdict,
        "kernel": {
            "release": kernel_value,
            "parsed": list(parsed) if parsed else None,
            "minimum_required": list(MIN_KERNEL),
        },
        "checks": checks,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "claim_boundary": (
            "Snapshot/config readiness only; this does not prove that eBPF "
            "programs are loaded or producing production telemetry."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)

    snapshot = load_json(args.snapshot)
    config = load_json(args.config) if args.config else None
    result = classify(snapshot, config)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "active" else 1


if __name__ == "__main__":
    raise SystemExit(main())
