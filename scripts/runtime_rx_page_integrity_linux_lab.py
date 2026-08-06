#!/usr/bin/env python3
"""Run and strictly validate the isolated Linux RX self-page lab."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SOURCE = (
    ROOT
    / "tools"
    / "detection_validation"
    / "labs"
    / "runtime_rx_page_integrity_linux_v1.rs"
)
SCENARIOS = (
    "clean_no_relocation",
    "rx_restored_drift",
    "jit_no_baseline",
    "execute_only_unreadable",
)
RAW_KEYS = {
    "schema",
    "scenario",
    "state",
    "page_size_bytes",
    "initial_protection",
    "final_protection",
    "baseline_hex",
    "current_hex",
    "drift_offsets",
    "limitations",
    "observed_permissions",
    "mapped_pages",
    "compared_bytes",
    "comparison_duration_ns",
    "cleanup",
}
REPORT_KEYS = {
    "schema",
    "evidence_class",
    "external_claim_allowed",
    "production_ready",
    "vendor_parity",
    "provenance",
    "safety",
    "cost",
    "cases",
    "cleanup_confirmed",
    "repeatability",
}
PROVENANCE_KEYS = {
    "source_sha256",
    "binary_sha256",
    "kernel",
    "architecture",
    "rustc_version",
    "page_size_bytes",
}
SAFETY_KEYS = {
    "self_owned_anonymous_mapping_only",
    "writable_executable_used",
    "mapped_bytes_executed",
    "ptrace_used",
    "raw_page_bytes_retained",
}
COST_KEYS = {
    "mapped_pages",
    "compared_pages",
    "compared_bytes",
    "max_mapped_pages",
    "max_compared_bytes",
    "max_comparison_duration_ns",
}
CASE_KEYS = {
    "scenario",
    "state",
    "outcome",
    "page_size_bytes",
    "initial_protection",
    "final_protection",
    "observed_permissions",
    "baseline_sha256",
    "current_sha256",
    "drift_offsets",
    "limitations",
    "compared_bytes",
    "comparison_duration_ns",
    "cleanup",
}
REPEAT_KEYS = {"runs", "normalized_equal"}
DRIFT_OFFSET = 137
MAX_COMPARISON_DURATION_NS = 100_000_000


class LabError(ValueError):
    """Raised when capability, execution, or evidence violates the lab contract."""


def _run(command: list[str], timeout: float = 10.0, text: bool = True):
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=text,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LabError(f"command failed safely: {command[0]}: {error}") from error


def _wsl(*arguments: str, timeout: float = 10.0):
    return _run(["wsl.exe", "-e", *arguments], timeout=timeout)


def _require_success(completed, label: str) -> str:
    if completed.returncode != 0:
        raise LabError(f"{label} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def preflight() -> dict[str, Any]:
    result = {
        "schema": "tamandua.runtime-rx-page-integrity-linux-preflight/v1",
        "evidence_class": "local_wsl_lab_preflight",
        "external_claim_allowed": False,
        "production_ready": False,
        "vendor_parity": False,
        "capable": False,
        "reasons": [],
    }
    if shutil.which("wsl.exe") is None:
        result["reasons"].append("wsl_executable_unavailable")
        return result
    try:
        kernel = _require_success(_wsl("uname", "-sr"), "kernel probe")
        architecture = _require_success(_wsl("uname", "-m"), "architecture probe")
        rustc = _require_success(_wsl("rustc", "--version"), "rustc probe")
        _require_success(_wsl("timeout", "--version"), "GNU timeout probe")
        page_size = _require_success(_wsl("getconf", "PAGESIZE"), "page-size probe")
        uid = _require_success(_wsl("id", "-u"), "uid probe")
    except LabError as error:
        result["reasons"].append(str(error))
        return result
    if architecture != "x86_64":
        result["reasons"].append("wsl_architecture_not_x86_64")
    if not re.match(r"^rustc 1\.(?:7[5-9]|[89]\d|\d{3,})\.", rustc):
        result["reasons"].append("rustc_1_75_or_newer_required")
    if page_size != "4096":
        result["reasons"].append("page_size_4096_required")
    if uid == "0":
        result["reasons"].append("root_execution_forbidden")
    result.update(
        {
            "kernel": kernel,
            "architecture": architecture,
            "rustc_version": rustc,
            "page_size_bytes": int(page_size) if page_size.isdigit() else None,
            "capable": not result["reasons"],
        }
    )
    return result


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LabError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _canonical_page(value: Any, page_size: int, label: str) -> bytes:
    if not isinstance(value, str) or value != value.lower() or len(value) != page_size * 2:
        raise LabError(f"{label} must be canonical full-page lowercase hex")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise LabError(f"{label} is invalid hex") from error
    if len(decoded) != page_size:
        raise LabError(f"{label} does not match the page size")
    return decoded


def _permissions_are(record: dict[str, Any], readable: bool, executable: bool) -> None:
    permissions = record["observed_permissions"]
    if not isinstance(permissions, str) or len(permissions) < 3:
        raise LabError("mapping permissions are malformed")
    if (permissions[0] == "r") != readable or permissions[1] == "w":
        raise LabError("mapping permissions violate the expected W^X state")
    if (permissions[2] == "x") != executable:
        raise LabError("mapping executable permission is inconsistent")


def validate_raw_case(value: Any, scenario: str, page_size: int) -> dict[str, Any]:
    record = _exact(value, RAW_KEYS, f"raw case {scenario}")
    if record["schema"] != "tamandua.runtime-rx-page-integrity-linux-raw/v1":
        raise LabError("raw schema is unsupported")
    if record["scenario"] != scenario or record["page_size_bytes"] != page_size:
        raise LabError("raw case provenance does not match its invocation")
    if record["initial_protection"] != "rw" or record["mapped_pages"] != 1:
        raise LabError("each child must own exactly one initially-RW page")
    if record["cleanup"] != "unmapped":
        raise LabError("child did not report successful unmap cleanup")
    if not isinstance(record["drift_offsets"], list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in record["drift_offsets"]
    ):
        raise LabError("drift offsets are malformed")

    if scenario in {"clean_no_relocation", "rx_restored_drift"}:
        if record["state"] != "supported" or record["final_protection"] != "rx":
            raise LabError("supported cases must finish RX")
        _permissions_are(record, readable=True, executable=True)
        baseline = _canonical_page(record["baseline_hex"], page_size, "baseline_hex")
        current = _canonical_page(record["current_hex"], page_size, "current_hex")
        offsets = [
            index for index, (before, after) in enumerate(zip(baseline, current)) if before != after
        ]
        expected = [] if scenario == "clean_no_relocation" else [DRIFT_OFFSET]
        if offsets != expected or record["drift_offsets"] != expected:
            raise LabError("computed drift does not match the fixed scenario")
        duration = record["comparison_duration_ns"]
        if (
            isinstance(duration, bool)
            or not isinstance(duration, int)
            or duration < 0
            or duration > MAX_COMPARISON_DURATION_NS
        ):
            raise LabError("comparison duration exceeds the lab runaway bound")
        if record["compared_bytes"] != page_size or record["limitations"] != []:
            raise LabError("supported comparison accounting is invalid")
        return {
            "scenario": scenario,
            "state": "supported",
            "outcome": "clean" if not expected else "finding",
            "page_size_bytes": page_size,
            "initial_protection": "rw",
            "final_protection": "rx",
            "observed_permissions": record["observed_permissions"],
            "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
            "current_sha256": hashlib.sha256(current).hexdigest(),
            "drift_offsets": expected,
            "limitations": [],
            "compared_bytes": page_size,
            "comparison_duration_ns": duration,
            "cleanup": "unmapped",
        }

    expected = {
        "jit_no_baseline": (
            "unsupported",
            "rx",
            "jit_region_has_no_stable_baseline",
            True,
        ),
        "execute_only_unreadable": (
            "degraded",
            "x",
            "execute_only_policy_refused_dereference",
            False,
        ),
    }[scenario]
    state, protection, limitation, readable = expected
    if record["state"] != state or record["final_protection"] != protection:
        raise LabError("unavailable case state is inconsistent")
    _permissions_are(record, readable=readable, executable=True)
    if (
        record["baseline_hex"] is not None
        or record["current_hex"] is not None
        or record["drift_offsets"] != []
        or record["limitations"] != [limitation]
        or record["compared_bytes"] != 0
        or record["comparison_duration_ns"] is not None
    ):
        raise LabError("unavailable case must not claim a page comparison")
    return {
        "scenario": scenario,
        "state": state,
        "outcome": state,
        "page_size_bytes": page_size,
        "initial_protection": "rw",
        "final_protection": protection,
        "observed_permissions": record["observed_permissions"],
        "baseline_sha256": None,
        "current_sha256": None,
        "drift_offsets": [],
        "limitations": [limitation],
        "compared_bytes": 0,
        "comparison_duration_ns": None,
        "cleanup": "unmapped",
    }


def _source_wsl_path() -> str:
    windows_path = str(SOURCE.resolve())
    command = f"wslpath -a {shlex.quote(windows_path)}"
    return _require_success(_wsl("bash", "-lc", command), "source path conversion")


def _safe_temp_path(path: str) -> str:
    if not re.fullmatch(r"/tmp/tamandua-rx-lab\.[A-Za-z0-9]+", path):
        raise LabError("temporary path escaped the dedicated WSL namespace")
    return path


def _binary_sha256(path: str) -> str:
    output = _require_success(_wsl("sha256sum", path), "binary hash")
    digest = output.split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise LabError("binary SHA-256 is malformed")
    return digest


def _run_once(capability: dict[str, Any]) -> dict[str, Any]:
    if capability.get("capable") is not True:
        raise LabError("explicit WSL capability preflight did not pass")
    temp_path = _safe_temp_path(
        _require_success(
            _wsl("mktemp", "-d", "-t", "tamandua-rx-lab.XXXXXXXX"), "temporary directory"
        )
    )
    cleanup_confirmed = False
    report: dict[str, Any] | None = None
    try:
        source_copy = f"{temp_path}/lab.rs"
        binary = f"{temp_path}/lab"
        _require_success(_wsl("cp", "--", _source_wsl_path(), source_copy), "source isolation")
        _require_success(
            _wsl(
                "timeout",
                "--kill-after=1s",
                "25s",
                "rustc",
                "--edition",
                "2021",
                "-D",
                "warnings",
                "-C",
                "opt-level=1",
                source_copy,
                "-o",
                binary,
                timeout=30.0,
            ),
            "standalone Rust compile",
        )
        cases = []
        for scenario in SCENARIOS:
            raw_output = _require_success(
                _wsl(
                    "timeout",
                    "--kill-after=1s",
                    "1s",
                    binary,
                    scenario,
                    timeout=3.0,
                ),
                f"scenario {scenario}",
            )
            try:
                raw = json.loads(raw_output)
            except json.JSONDecodeError as error:
                raise LabError(f"scenario {scenario} emitted malformed JSON") from error
            cases.append(validate_raw_case(raw, scenario, capability["page_size_bytes"]))

        source_sha = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        binary_sha = _binary_sha256(binary)
        report = {
            "schema": "tamandua.runtime-rx-page-integrity-linux-lab/v1",
            "evidence_class": "local_wsl_lab",
            "external_claim_allowed": False,
            "production_ready": False,
            "vendor_parity": False,
            "provenance": {
                "source_sha256": source_sha,
                "binary_sha256": binary_sha,
                "kernel": capability["kernel"],
                "architecture": capability["architecture"],
                "rustc_version": capability["rustc_version"],
                "page_size_bytes": capability["page_size_bytes"],
            },
            "safety": {
                "self_owned_anonymous_mapping_only": True,
                "writable_executable_used": False,
                "mapped_bytes_executed": False,
                "ptrace_used": False,
                "raw_page_bytes_retained": False,
            },
            "cost": {
                "mapped_pages": len(cases),
                "compared_pages": 2,
                "compared_bytes": sum(item["compared_bytes"] for item in cases),
                "max_mapped_pages": 4,
                "max_compared_bytes": 8192,
                "max_comparison_duration_ns": MAX_COMPARISON_DURATION_NS,
            },
            "cases": cases,
            "cleanup_confirmed": False,
            "repeatability": {"runs": 1, "normalized_equal": True},
        }
    finally:
        if temp_path.startswith("/tmp/tamandua-rx-lab."):
            _wsl("rm", "-rf", "--", temp_path)
            cleanup_confirmed = _wsl("test", "!", "-e", temp_path).returncode == 0
        if not cleanup_confirmed:
            raise LabError("isolated WSL temporary directory cleanup failed")
    if report is None:
        raise LabError("WSL lab did not produce a report")
    report["cleanup_confirmed"] = True
    return report


def normalized_report(report: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(report)
    normalized["repeatability"] = {"runs": 1, "normalized_equal": True}
    for case in normalized["cases"]:
        case["comparison_duration_ns"] = None
    return normalized


def validate_report(value: Any) -> dict[str, Any]:
    report = _exact(value, REPORT_KEYS, "report")
    if (
        report["schema"] != "tamandua.runtime-rx-page-integrity-linux-lab/v1"
        or report["evidence_class"] != "local_wsl_lab"
        or report["external_claim_allowed"] is not False
        or report["production_ready"] is not False
        or report["vendor_parity"] is not False
    ):
        raise LabError("report claim boundary was elevated or relabeled")
    provenance = _exact(report["provenance"], PROVENANCE_KEYS, "provenance")
    if not all(
        isinstance(provenance[key], str) and provenance[key]
        for key in ("source_sha256", "binary_sha256", "kernel", "architecture", "rustc_version")
    ):
        raise LabError("report provenance is incomplete")
    if not re.fullmatch(r"[0-9a-f]{64}", provenance["source_sha256"]) or not re.fullmatch(
        r"[0-9a-f]{64}", provenance["binary_sha256"]
    ):
        raise LabError("report provenance hashes are malformed")
    if provenance["architecture"] != "x86_64" or provenance["page_size_bytes"] != 4096:
        raise LabError("report platform provenance is outside the supported lab lane")
    safety = _exact(report["safety"], SAFETY_KEYS, "safety")
    if safety != {
        "self_owned_anonymous_mapping_only": True,
        "writable_executable_used": False,
        "mapped_bytes_executed": False,
        "ptrace_used": False,
        "raw_page_bytes_retained": False,
    }:
        raise LabError("report safety boundary is invalid")
    cost = _exact(report["cost"], COST_KEYS, "cost")
    if cost["mapped_pages"] != 4 or cost["compared_pages"] != 2:
        raise LabError("report page accounting is invalid")
    if cost["compared_bytes"] != 8192 or cost["max_compared_bytes"] != 8192:
        raise LabError("report byte accounting is invalid")
    if cost["max_mapped_pages"] != 4:
        raise LabError("report page budget is invalid")
    if cost["max_comparison_duration_ns"] != MAX_COMPARISON_DURATION_NS:
        raise LabError("report comparison budget is invalid")
    if not isinstance(report["cases"], list) or len(report["cases"]) != 4:
        raise LabError("report must contain exactly four cases")
    expected_cases = {
        "clean_no_relocation": ("supported", "clean", "rx", "r-xp", [], 4096),
        "rx_restored_drift": (
            "supported",
            "finding",
            "rx",
            "r-xp",
            [DRIFT_OFFSET],
            4096,
        ),
        "jit_no_baseline": (
            "unsupported",
            "unsupported",
            "rx",
            "r-xp",
            ["jit_region_has_no_stable_baseline"],
            0,
        ),
        "execute_only_unreadable": (
            "degraded",
            "degraded",
            "x",
            "--xp",
            ["execute_only_policy_refused_dereference"],
            0,
        ),
    }
    for scenario, item in zip(SCENARIOS, report["cases"]):
        _exact(item, CASE_KEYS, "report case")
        state, outcome, protection, permissions, detail, compared_bytes = expected_cases[scenario]
        if (
            item["scenario"] != scenario
            or item["state"] != state
            or item["outcome"] != outcome
            or item["page_size_bytes"] != 4096
            or item["initial_protection"] != "rw"
            or item["final_protection"] != protection
            or item["observed_permissions"] != permissions
            or item["compared_bytes"] != compared_bytes
        ):
            raise LabError("report case semantics are inconsistent")
        if "baseline_hex" in item or "current_hex" in item:
            raise LabError("raw page bytes must not survive report projection")
        if item["initial_protection"] == "rwx" or item["final_protection"] == "rwx":
            raise LabError("report contains a writable+executable transition")
        if item["cleanup"] != "unmapped":
            raise LabError("report case cleanup is incomplete")
        if scenario in {"clean_no_relocation", "rx_restored_drift"}:
            if (
                not re.fullmatch(r"[0-9a-f]{64}", item["baseline_sha256"] or "")
                or not re.fullmatch(r"[0-9a-f]{64}", item["current_sha256"] or "")
                or item["drift_offsets"] != detail
                or item["limitations"] != []
                or isinstance(item["comparison_duration_ns"], bool)
                or not isinstance(item["comparison_duration_ns"], int)
                or not 0 <= item["comparison_duration_ns"] <= MAX_COMPARISON_DURATION_NS
            ):
                raise LabError("supported report case evidence is malformed")
            if scenario == "clean_no_relocation" and (
                item["baseline_sha256"] != item["current_sha256"]
            ):
                raise LabError("clean report case hashes disagree")
            if scenario == "rx_restored_drift" and (
                item["baseline_sha256"] == item["current_sha256"]
            ):
                raise LabError("drift report case hashes agree")
        elif (
            item["baseline_sha256"] is not None
            or item["current_sha256"] is not None
            or item["drift_offsets"] != []
            or item["limitations"] != detail
            or item["comparison_duration_ns"] is not None
        ):
            raise LabError("unavailable report case claims comparison evidence")
    if report["cleanup_confirmed"] is not True:
        raise LabError("report cleanup was not confirmed")
    repeatability = _exact(report["repeatability"], REPEAT_KEYS, "repeatability")
    if repeatability["runs"] not in {1, 2} or repeatability["normalized_equal"] is not True:
        raise LabError("repeatability gate is not satisfied")
    return report


def run_lab(repeat: int = 1) -> dict[str, Any]:
    if repeat not in {1, 2}:
        raise LabError("repeat must be one or two")
    capability = preflight()
    if capability["capable"] is not True:
        raise LabError(f"WSL capability preflight failed: {capability['reasons']}")
    runs = [_run_once(capability) for _ in range(repeat)]
    normalized_equal = all(
        normalized_report(item) == normalized_report(runs[0]) for item in runs[1:]
    )
    report = runs[0]
    report["repeatability"] = {"runs": repeat, "normalized_equal": normalized_equal}
    return validate_report(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--run", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = preflight() if args.preflight else run_lab(args.repeat)
    except LabError as error:
        print(json.dumps({"status": "fail", "error": str(error)}, sort_keys=True))
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    if args.json or not args.output:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
