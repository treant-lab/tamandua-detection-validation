#!/usr/bin/env python3
"""Local read-only eBPF/LSM readiness probe for Linux hosts.

This probe records whether the current Linux host is ready to load eBPF and
eBPF-LSM programs for sensor-grade telemetry. It only inspects local kernel,
filesystem, and capability state; it does not load any BPF program, does not
contact the Tamandua server, and does not mutate the host.

On non-Linux platforms the probe exits with verdict ``skipped`` so it can be
scheduled in cross-platform pipelines without failing the gate.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "linux-ebpf-readiness-probe"
PROFILE_NAME = "Linux eBPF/LSM Readiness Probe"

MIN_KERNEL = (5, 7)
REQUIRED_KERNEL_CONFIGS = ("CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_LSM")
REQUIRED_CAPABILITIES = ("cap_bpf", "cap_sys_admin")
BTF_PATH = "/sys/kernel/btf/vmlinux"
LSM_PATH = "/sys/kernel/security/lsm"
BPF_FS_PATH = "/sys/fs/bpf"
PROC_CONFIG_GZ = "/proc/config.gz"


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


def parse_kernel_release(release: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", release or "")
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3) or 0)
    return (major, minor, patch)


def detect_kernel() -> dict[str, Any]:
    release = ""
    try:
        release = os.uname().release  # type: ignore[attr-defined]
    except AttributeError:
        release = platform.release()
    parsed = parse_kernel_release(release)
    meets_min = bool(parsed and (parsed[0], parsed[1]) >= MIN_KERNEL)
    return {
        "release": release,
        "parsed": list(parsed) if parsed else None,
        "minimum_required": list(MIN_KERNEL),
        "meets_minimum": meets_min,
    }


def read_btf() -> dict[str, Any]:
    path = Path(BTF_PATH)
    exists = path.exists()
    size = 0
    if exists:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
    return {"path": BTF_PATH, "available": bool(exists and size > 0), "size_bytes": size}


def read_kernel_config_text(release: str) -> tuple[str | None, str]:
    proc_path = Path(PROC_CONFIG_GZ)
    if proc_path.exists():
        try:
            with gzip.open(proc_path, "rt", encoding="utf-8", errors="replace") as handle:
                return handle.read(), PROC_CONFIG_GZ
        except OSError:
            pass
    if release:
        boot_path = Path(f"/boot/config-{release}")
        if boot_path.exists():
            try:
                return boot_path.read_text(encoding="utf-8", errors="replace"), str(boot_path)
            except OSError:
                pass
    return None, ""


def evaluate_kernel_configs(text: str | None) -> dict[str, str]:
    if not text:
        return {name: "unknown" for name in REQUIRED_KERNEL_CONFIGS}
    results: dict[str, str] = {}
    for name in REQUIRED_KERNEL_CONFIGS:
        pattern = re.compile(rf"^{name}=([ymn])\b", re.MULTILINE)
        not_set = re.compile(rf"^# {name} is not set\b", re.MULTILINE)
        match = pattern.search(text)
        if match:
            value = match.group(1).lower()
            results[name] = {"y": "enabled", "m": "module", "n": "disabled"}.get(value, value)
        elif not_set.search(text):
            results[name] = "disabled"
        else:
            results[name] = "absent"
    return results


def detect_kernel_config(release: str) -> dict[str, Any]:
    text, source = read_kernel_config_text(release)
    configs = evaluate_kernel_configs(text)
    required_ok = all(value in {"enabled", "module"} for value in configs.values())
    return {
        "source": source or None,
        "flags": configs,
        "required_flags_satisfied": required_ok,
    }


def detect_lsm() -> dict[str, Any]:
    path = Path(LSM_PATH)
    raw = ""
    available = False
    if path.exists():
        try:
            raw = path.read_text(encoding="utf-8", errors="replace").strip()
            available = True
        except OSError:
            raw = ""
            available = False
    entries = [item.strip() for item in raw.split(",") if item.strip()] if raw else []
    return {
        "path": LSM_PATH,
        "available": available,
        "raw": raw,
        "entries": entries,
        "bpf_enabled": "bpf" in entries,
    }


def detect_bpf_fs() -> dict[str, Any]:
    path = Path(BPF_FS_PATH)
    exists = path.exists()
    mounted = False
    fs_type = ""
    try:
        mounts = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == BPF_FS_PATH:
                mounted = True
                fs_type = parts[2]
                break
    except OSError:
        mounts = ""
    return {
        "path": BPF_FS_PATH,
        "exists": exists,
        "mounted": mounted,
        "fs_type": fs_type,
    }


def read_proc_status_caps() -> dict[str, str]:
    try:
        text = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    keys = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    found: dict[str, str] = {}
    for line in text.splitlines():
        for key in keys:
            if line.startswith(f"{key}:"):
                found[key] = line.split(":", 1)[1].strip()
    return found


# Linux capability bit numbers.
CAP_SYS_ADMIN_BIT = 21
CAP_BPF_BIT = 39


def has_capability(cap_mask_hex: str, bit: int) -> bool:
    try:
        mask = int(cap_mask_hex, 16)
    except (TypeError, ValueError):
        return False
    return bool(mask & (1 << bit))


def detect_capabilities() -> dict[str, Any]:
    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    caps = read_proc_status_caps()
    effective = caps.get("CapEff", "")
    cap_bpf = has_capability(effective, CAP_BPF_BIT)
    cap_sys_admin = has_capability(effective, CAP_SYS_ADMIN_BIT)
    return {
        "euid": euid,
        "is_root": euid == 0,
        "cap_eff": effective,
        "cap_bnd": caps.get("CapBnd", ""),
        "cap_bpf": cap_bpf,
        "cap_sys_admin": cap_sys_admin,
        "load_capable": cap_bpf or cap_sys_admin or euid == 0,
    }


def derive_verdict(
    kernel: dict[str, Any],
    btf: dict[str, Any],
    kconfig: dict[str, Any],
    lsm: dict[str, Any],
    bpf_fs: dict[str, Any],
    caps: dict[str, Any],
) -> tuple[str, list[str], list[str], list[str]]:
    passed: list[str] = []
    missing: list[str] = []
    recommendations: list[str] = []

    if kernel.get("meets_minimum"):
        passed.append(f"kernel {kernel.get('release')} >= {'.'.join(str(x) for x in MIN_KERNEL)}")
    else:
        missing.append(f"kernel<{'.'.join(str(x) for x in MIN_KERNEL)}")
        recommendations.append(
            f"Upgrade the kernel to {'.'.join(str(x) for x in MIN_KERNEL)} or newer for eBPF/LSM support."
        )

    if btf.get("available"):
        passed.append("btf_vmlinux_available")
    else:
        missing.append("btf_vmlinux")
        recommendations.append(
            "Install a kernel built with CONFIG_DEBUG_INFO_BTF=y or expose vmlinux BTF at /sys/kernel/btf/vmlinux."
        )

    for name in REQUIRED_KERNEL_CONFIGS:
        state = kconfig.get("flags", {}).get(name)
        if state in {"enabled", "module"}:
            passed.append(f"{name}={state}")
        else:
            missing.append(f"{name}:{state or 'unknown'}")
            recommendations.append(
                f"Enable {name}=y (or =m) in the running kernel configuration."
            )

    if lsm.get("available") and lsm.get("bpf_enabled"):
        passed.append("lsm_bpf_enabled")
    elif lsm.get("available") and not lsm.get("bpf_enabled"):
        missing.append("lsm_bpf_not_enabled")
        recommendations.append(
            "Add 'bpf' to the kernel cmdline lsm= list (or CONFIG_LSM) and reboot."
        )
    else:
        missing.append("lsm_sysfs_unavailable")
        recommendations.append(
            "Mount securityfs and verify /sys/kernel/security/lsm exposes the active LSMs."
        )

    if bpf_fs.get("mounted"):
        passed.append("bpf_fs_mounted")
    elif bpf_fs.get("exists"):
        missing.append("bpf_fs_not_mounted")
        recommendations.append("Mount the bpf filesystem: mount -t bpf bpffs /sys/fs/bpf")
    else:
        missing.append("bpf_fs_absent")
        recommendations.append(
            "Create /sys/fs/bpf and mount bpffs (mount -t bpf bpffs /sys/fs/bpf)."
        )

    if caps.get("load_capable"):
        if caps.get("cap_bpf"):
            passed.append("cap_bpf_present")
        elif caps.get("cap_sys_admin"):
            passed.append("cap_sys_admin_present")
        elif caps.get("is_root"):
            passed.append("euid_root")
    else:
        missing.append("missing_cap_bpf_or_cap_sys_admin")
        recommendations.append(
            "Run the agent with CAP_BPF (preferred on kernels >= 5.8) or CAP_SYS_ADMIN."
        )

    if not missing:
        verdict = "active"
    elif (
        kernel.get("meets_minimum")
        and btf.get("available")
        and kconfig.get("flags", {}).get("CONFIG_BPF") in {"enabled", "module"}
        and kconfig.get("flags", {}).get("CONFIG_BPF_SYSCALL") in {"enabled", "module"}
    ):
        verdict = "degraded"
    else:
        verdict = "unavailable"
    return verdict, passed, missing, recommendations


def test_row(
    test_id: str,
    name: str,
    status: str,
    evidence: dict[str, Any],
    gap: str,
) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": status,
        "gap_category": None if status == "covered" else gap,
        "validation_category": "linux_ebpf_readiness",
        "execution_class": "local_read_only_host_probe",
        "fallback_used": False,
        "claim_level": "sensor_capability_claim_boundary",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": [] if status == "covered" else [gap],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def build_tests_linux(
    kernel: dict[str, Any],
    btf: dict[str, Any],
    kconfig: dict[str, Any],
    lsm: dict[str, Any],
    bpf_fs: dict[str, Any],
    caps: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        test_row(
            "linux-ebpf-kernel-version",
            "Kernel version meets eBPF/LSM minimum (>= 5.7)",
            "covered" if kernel.get("meets_minimum") else "missed",
            {"kernel": kernel},
            "kernel_version_too_old",
        ),
        test_row(
            "linux-ebpf-btf-available",
            "BTF information is available at /sys/kernel/btf/vmlinux",
            "covered" if btf.get("available") else "missed",
            {"btf": btf},
            "btf_unavailable",
        ),
        test_row(
            "linux-ebpf-kernel-config",
            "CONFIG_BPF, CONFIG_BPF_SYSCALL, and CONFIG_BPF_LSM are enabled",
            "covered" if kconfig.get("required_flags_satisfied") else "missed",
            {"kernel_config": kconfig},
            "missing_kernel_config",
        ),
        test_row(
            "linux-ebpf-lsm-bpf",
            "Active LSM list at /sys/kernel/security/lsm contains 'bpf'",
            "covered" if lsm.get("bpf_enabled") else "missed",
            {"lsm": lsm},
            "bpf_lsm_not_active",
        ),
        test_row(
            "linux-ebpf-bpffs-mounted",
            "bpf filesystem is mounted at /sys/fs/bpf",
            "covered" if bpf_fs.get("mounted") else "missed",
            {"bpf_fs": bpf_fs},
            "bpf_fs_not_mounted",
        ),
        test_row(
            "linux-ebpf-capabilities",
            "Process has CAP_BPF or CAP_SYS_ADMIN to load eBPF programs",
            "covered" if caps.get("load_capable") else "missed",
            {"capabilities": caps},
            "missing_bpf_capability",
        ),
    ]


def build_tests_skipped(reason: str, host_platform: str) -> list[dict[str, Any]]:
    return [
        test_row(
            "linux-ebpf-platform-applicable",
            "Probe is running on a Linux host",
            "covered",
            {"platform": host_platform, "reason": reason, "skipped": True},
            "non_linux_platform",
        )
    ]


def summarize(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for item in tests if item.get("status") == "covered")
    missed = sum(1 for item in tests if item.get("status") not in {"covered", "skipped"})
    return {
        "tests": len(tests),
        "total": len(tests),
        "covered": covered,
        "missed": missed,
        "partial": 0,
        "execution_failed": 0,
        "category_coverage": {
            "linux_ebpf_readiness": {"covered": covered, "missed": missed}
        },
    }


def quality_gate(tests: list[dict[str, Any]], verdict: str) -> dict[str, Any]:
    if verdict == "skipped":
        return {
            "passed": True,
            "status": "pass",
            "failures": [],
            "blocking_gaps": [],
        }
    missed = [item["id"] for item in tests if item.get("status") != "covered"]
    return {
        "passed": not missed,
        "status": "pass" if not missed else "fail",
        "failures": [] if not missed else ["linux_ebpf_readiness_gaps"],
        "blocking_gaps": missed,
    }


def comparison(run_id: str, tests: list[dict[str, Any]], gate: dict[str, Any], verdict: str) -> dict[str, Any]:
    summary = summarize(tests)
    if verdict == "skipped":
        score = 50
    elif gate["passed"]:
        score = 90
    elif verdict == "degraded":
        score = 45
    else:
        score = 25
    return {
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "status": gate["status"],
        "quality_gate": {"passed": gate["passed"], "status": gate["status"]},
        "score": score,
        "summary": summary,
        "category_coverage": summary["category_coverage"],
        "failures": gate["failures"],
        "verdict": verdict,
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    verdict = report.get("verdict") or "unknown"
    lines = [
        "# Linux eBPF/LSM Readiness Probe",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Verdict: `{verdict}`",
        f"- Platform: `{report.get('host', {}).get('platform') or '-'}`",
        f"- Kernel: `{report.get('host', {}).get('kernel_release') or '-'}`",
        "",
        "## Results",
        "",
        "| Test | Status | Gap |",
        "|------|--------|-----|",
    ]
    for item in report["tests"]:
        lines.append(
            f"| `{item['id']}` | `{item['status']}` | `{item.get('gap_category') or 'none'}` |"
        )
    lines.extend(
        [
            "",
            "## Passed Checks",
            "",
        ]
    )
    passed = report.get("ebpf_readiness", {}).get("passed_checks") or []
    if passed:
        lines.extend([f"- `{item}`" for item in passed])
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Missing Prerequisites",
            "",
        ]
    )
    missing = report.get("ebpf_readiness", {}).get("missing_prerequisites") or []
    if missing:
        lines.extend([f"- `{item}`" for item in missing])
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Recommendations",
            "",
        ]
    )
    recs = report.get("ebpf_readiness", {}).get("recommendations") or []
    if recs:
        lines.extend([f"- {item}" for item in recs])
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            report["claim_boundary"],
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default=str(RUNS_DIR))
    args = parser.parse_args()

    started = utc_now()
    run_id = f"{compact_stamp(started)}-{PROFILE_ID}"
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    host_platform = platform.system().lower()
    kernel_release = ""
    try:
        kernel_release = os.uname().release  # type: ignore[attr-defined]
    except AttributeError:
        kernel_release = platform.release()

    host_info = {
        "platform": host_platform,
        "kernel_release": kernel_release,
        "machine": platform.machine(),
    }

    if host_platform != "linux":
        verdict = "skipped"
        tests = build_tests_skipped("non-linux platform", host_platform)
        gate = quality_gate(tests, verdict)
        readiness = {
            "verdict": verdict,
            "reason": "non-linux platform",
            "passed_checks": [],
            "missing_prerequisites": [],
            "recommendations": [],
        }
        details: dict[str, Any] = {}
    else:
        kernel = detect_kernel()
        btf = read_btf()
        kconfig = detect_kernel_config(kernel.get("release") or "")
        lsm = detect_lsm()
        bpf_fs = detect_bpf_fs()
        caps = detect_capabilities()
        verdict, passed_checks, missing, recommendations = derive_verdict(
            kernel, btf, kconfig, lsm, bpf_fs, caps
        )
        tests = build_tests_linux(kernel, btf, kconfig, lsm, bpf_fs, caps)
        gate = quality_gate(tests, verdict)
        readiness = {
            "verdict": verdict,
            "reason": "ready" if verdict == "active" else "missing_prerequisites",
            "passed_checks": passed_checks,
            "missing_prerequisites": missing,
            "recommendations": recommendations,
        }
        details = {
            "kernel": kernel,
            "btf": btf,
            "kernel_config": kconfig,
            "lsm": lsm,
            "bpf_fs": bpf_fs,
            "capabilities": caps,
        }

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
        "runtime_effect": "local_read_only_host_probe",
        "verdict": readiness["verdict"],
        "host": host_info,
        "metadata": {"git": git_snapshot()},
        "ebpf_readiness": readiness,
        "details": details,
        "tests": tests,
        "summary": summarize(tests),
        "quality_gate": gate,
        "scorecard": {
            "score": (
                50
                if readiness["verdict"] == "skipped"
                else 90
                if gate["passed"]
                else 45
                if readiness["verdict"] == "degraded"
                else 25
            ),
            "status": gate["status"],
            "external_claim_allowed": False,
            "recommended_claim": (
                "Linux eBPF/LSM sensor stack is ready for deployment"
                if gate["passed"] and readiness["verdict"] == "active"
                else "Linux eBPF/LSM readiness probe skipped (non-linux host)"
                if readiness["verdict"] == "skipped"
                else "Linux eBPF/LSM sensor stack is not ready; resolve the listed prerequisites"
            ),
        },
        "claim_boundary": (
            "Local read-only host readiness proof. This probe inspects kernel version, "
            "BTF availability, kernel BPF configuration flags, capability bits, the LSM "
            "list, and the bpffs mount. It does not load any BPF program, does not "
            "contact the Tamandua server, and does not prove end-to-end sensor coverage."
        ),
    }

    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    comparison_path.write_text(
        json.dumps(comparison(run_id, tests, gate, readiness["verdict"]), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        f"linux_ebpf_readiness={readiness['verdict']} "
        f"gate={'ok' if gate['passed'] else 'gaps'} "
        f"json={json_path} markdown={md_path} comparison_json={comparison_path}"
    )
    if readiness["verdict"] == "skipped":
        return 0
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
