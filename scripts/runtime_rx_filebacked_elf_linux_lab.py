#!/usr/bin/env python3
"""Run the bounded Linux file-backed ELF RX self-text integrity lab."""

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
    / "runtime_rx_filebacked_elf_linux_v1.rs"
)
CONTRACT = (
    ROOT
    / "tools"
    / "detection_validation"
    / "fixtures"
    / "runtime_rx_filebacked_elf_linux_v1.json"
)
SYMBOL = "tamandua_probe_page"
SCENARIOS = (
    "clean_file_backed_rx",
    "file_backed_rw_to_rx_drift",
    "deleted_backing",
    "replaced_backing",
    "anonymous_jit_no_baseline",
    "execute_only_file_backed",
)
RAW_KEYS = {
    "schema",
    "scenario",
    "state",
    "outcome",
    "backing_state",
    "page_size_bytes",
    "initial_protection",
    "final_protection",
    "observed_permissions",
    "mapping_file_offset",
    "probe_file_offset",
    "load_bias",
    "mapping_inode",
    "backing_inode",
    "baseline_sha256",
    "current_sha256",
    "drift_offsets",
    "limitations",
    "compared_bytes",
    "comparison_pipeline_duration_ns",
    "writable_executable_used",
    "mapped_bytes_executed",
    "absolute_paths_emitted",
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
    "contract_sha256",
    "binary_sha256",
    "build_id",
    "kernel",
    "architecture",
    "rustc_version",
    "elf_class",
    "elf_machine",
    "page_size_bytes",
    "load_bias",
    "relocation_policy",
    "probe_relocation_count",
    "case_binary_hashes_verified",
}
SAFETY_KEYS = {
    "self_owned_compiled_elf_only",
    "writable_executable_used",
    "mapped_bytes_executed",
    "ptrace_used",
    "raw_page_bytes_retained",
    "absolute_paths_retained",
    "runtime_addresses_retained",
    "inode_values_retained",
}
COST_KEYS = {
    "cases",
    "compared_pages",
    "compared_bytes",
    "max_cases",
    "max_compared_pages",
    "max_compared_bytes",
    "max_case_duration_ms",
    "max_comparison_pipeline_duration_ns",
}
CASE_KEYS = {
    "scenario",
    "state",
    "outcome",
    "backing_state",
    "page_size_bytes",
    "initial_protection",
    "final_protection",
    "observed_permissions",
    "baseline_sha256",
    "current_sha256",
    "drift_offsets",
    "limitations",
    "compared_bytes",
    "comparison_pipeline_duration_ns",
    "load_bias",
    "mapping_identity",
    "backing_identity",
    "executed_binary_identity",
    "cleanup",
}
CONTRACT_KEYS = {
    "schema",
    "evidence_class",
    "external_claim_allowed",
    "production_ready",
    "vendor_parity",
    "page_size_bytes",
    "drift_offset",
    "relocation_policy",
    "cost_budget",
    "cases",
}
CONTRACT_COST_KEYS = {
    "max_cases",
    "max_compared_pages",
    "max_compared_bytes",
    "max_case_duration_ms",
    "max_comparison_pipeline_duration_ns",
}
CONTRACT_CASE_KEYS = {
    "scenario",
    "state",
    "outcome",
    "backing_state",
    "limitations",
    "cleanup",
}
REPEAT_KEYS = {"runs", "normalized_equal"}
MAX_COMPARISON_PIPELINE_DURATION_NS = 100_000_000

RELOCATION_WIDTHS = {
    "R_X86_64_64": 8,
    "R_X86_64_PC32": 4,
    "R_X86_64_GOT32": 4,
    "R_X86_64_PLT32": 4,
    "R_X86_64_COPY": None,
    "R_X86_64_GLOB_DAT": 8,
    "R_X86_64_JUMP_SLOT": 8,
    "R_X86_64_RELATIVE": 8,
    "R_X86_64_GOTPCREL": 4,
    "R_X86_64_32": 4,
    "R_X86_64_32S": 4,
    "R_X86_64_16": 2,
    "R_X86_64_PC16": 2,
    "R_X86_64_8": 1,
    "R_X86_64_PC8": 1,
    "R_X86_64_DTPMOD64": 8,
    "R_X86_64_DTPOFF64": 8,
    "R_X86_64_TPOFF64": 8,
    "R_X86_64_IRELATIVE": 8,
    "R_X86_64_GOTPCRELX": 4,
    "R_X86_64_REX_GOTPCRELX": 4,
}


class LabError(ValueError):
    """Raised when the isolated lab violates its capability or evidence contract."""


def _run(command: list[str], timeout: float = 10.0):
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
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


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LabError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LabError(f"{label} must be a positive integer")
    return value


def load_contract() -> dict[str, Any]:
    try:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LabError(f"contract fixture is unavailable: {error}") from error
    value = _exact(value, CONTRACT_KEYS, "contract")
    if (
        value["schema"] != "tamandua.runtime-rx-filebacked-elf-linux-contract/v1"
        or value["evidence_class"] != "local_wsl_lab_contract"
        or value["external_claim_allowed"] is not False
        or value["production_ready"] is not False
        or value["vendor_parity"] is not False
    ):
        raise LabError("contract claim boundary was elevated or relabeled")
    if value["page_size_bytes"] != 4096 or value["drift_offset"] != 137:
        raise LabError("contract page identity is unsupported")
    if value["relocation_policy"] != "reject_probe_overlap":
        raise LabError("contract relocation policy is unsupported")
    cost = _exact(value["cost_budget"], CONTRACT_COST_KEYS, "contract cost")
    expected_cost = {
        "max_cases": 6,
        "max_compared_pages": 2,
        "max_compared_bytes": 8192,
        "max_case_duration_ms": 1000,
        "max_comparison_pipeline_duration_ns": MAX_COMPARISON_PIPELINE_DURATION_NS,
    }
    if cost != expected_cost:
        raise LabError("contract cost budget changed")
    if not isinstance(value["cases"], list) or len(value["cases"]) != len(SCENARIOS):
        raise LabError("contract must contain exactly six cases")
    expected = {
        "clean_file_backed_rx": (
            "supported",
            "clean",
            "original",
            [],
            "process_exit_discards_private_mapping",
        ),
        "file_backed_rw_to_rx_drift": (
            "supported",
            "finding",
            "original",
            [],
            "process_exit_discards_private_mapping",
        ),
        "deleted_backing": (
            "degraded",
            "degraded",
            "deleted",
            ["file_backing_deleted"],
            "case_binary_unlinked",
        ),
        "replaced_backing": (
            "degraded",
            "degraded",
            "replaced",
            ["file_backing_identity_changed"],
            "replacement_removed",
        ),
        "anonymous_jit_no_baseline": (
            "unsupported",
            "unsupported",
            "anonymous",
            ["anonymous_executable_has_no_file_baseline"],
            "anonymous_mapping_unmapped",
        ),
        "execute_only_file_backed": (
            "degraded",
            "degraded",
            "original",
            ["execute_only_policy_refused_dereference"],
            "probe_permissions_restored_rx",
        ),
    }
    for scenario, raw_case in zip(SCENARIOS, value["cases"], strict=True):
        case = _exact(raw_case, CONTRACT_CASE_KEYS, f"contract case {scenario}")
        state, outcome, backing, limitations, cleanup = expected[scenario]
        if case != {
            "scenario": scenario,
            "state": state,
            "outcome": outcome,
            "backing_state": backing,
            "limitations": limitations,
            "cleanup": cleanup,
        }:
            raise LabError(f"contract case {scenario} changed semantics")
    return value


def preflight() -> dict[str, Any]:
    result = {
        "schema": "tamandua.runtime-rx-filebacked-elf-linux-preflight/v1",
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
        _require_success(_wsl("readelf", "--version"), "readelf probe")
        _require_success(_wsl("timeout", "--version"), "timeout probe")
        page_size = _require_success(_wsl("getconf", "PAGESIZE"), "page-size probe")
        uid = _require_success(_wsl("id", "-u"), "uid probe")
    except LabError as error:
        result["reasons"].append(str(error))
        return result
    if architecture != "x86_64":
        result["reasons"].append("wsl_architecture_not_x86_64")
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


def _host_to_wsl(path: Path) -> str:
    command = f"wslpath -a {shlex.quote(str(path.resolve()))}"
    return _require_success(_wsl("bash", "-lc", command), "path conversion")


def _safe_temp_path(path: str) -> str:
    if not re.fullmatch(r"/tmp/tamandua-rx-elf-lab\.[A-Za-z0-9]+", path):
        raise LabError("temporary path escaped the dedicated WSL namespace")
    return path


def _sha256_file_wsl(path: str) -> str:
    output = _require_success(_wsl("sha256sum", path), "binary hash")
    digest = output.split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise LabError("binary SHA-256 is malformed")
    return digest


def _require_hash_match(actual: str, expected: str, label: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", actual) or actual != expected:
        raise LabError(f"{label} differs from master provenance")


def _sha256_file_range_wsl(path: str, offset: int, length: int) -> str:
    if offset < 0 or length <= 0:
        raise LabError("bounded file range is invalid")
    command = (
        f"dd if={shlex.quote(path)} bs=1 skip={offset} count={length} status=none "
        "| sha256sum"
    )
    output = _require_success(_wsl("bash", "-lc", command), "bounded page hash")
    digest = output.split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise LabError("bounded page SHA-256 is malformed")
    return digest


def _relocation_intervals(output: str) -> list[tuple[int, int, str]]:
    lowered = output.lower()
    if "relr" in lowered or "packed relocation" in lowered or "android.rela" in lowered:
        raise LabError("packed or relative relocation encoding is unsupported")
    intervals = []
    for line in output.splitlines():
        columns = line.split()
        if not columns or not re.fullmatch(r"[0-9a-fA-F]+", columns[0]):
            continue
        if len(columns) < 3:
            raise LabError("relocation entry is truncated")
        relocation_type = columns[2]
        if relocation_type not in RELOCATION_WIDTHS:
            raise LabError(f"relocation type is unsupported: {relocation_type}")
        width = RELOCATION_WIDTHS[relocation_type]
        if width is None:
            raise LabError(f"relocation width is unsupported: {relocation_type}")
        start = int(columns[0], 16)
        intervals.append((start, start + width, relocation_type))
    return intervals


def _probe_relocation_overlaps(
    intervals: list[tuple[int, int, str]], probe_start: int, probe_size: int
) -> list[tuple[int, int, str]]:
    probe_end = probe_start + probe_size
    return [
        (start, end, relocation_type)
        for start, end, relocation_type in intervals
        if start < probe_end and end > probe_start
    ]


def _validate_pinned_elf_identity(elf_class: str, machine: str) -> None:
    if elf_class != "ELF64" or machine != "Advanced Micro Devices X86-64":
        raise LabError("ELF class or machine is outside the pinned lab contract")


def _elf_provenance(binary: str, page_size: int) -> dict[str, Any]:
    header = _require_success(_wsl("readelf", "-hW", binary), "ELF header")
    elf_class = re.search(r"^\s*Class:\s*(\S+)", header, re.MULTILINE)
    machine = re.search(r"^\s*Machine:\s*(.+)$", header, re.MULTILINE)
    if not elf_class or not machine:
        raise LabError("ELF header provenance is incomplete")
    pinned_class = elf_class.group(1)
    pinned_machine = machine.group(1).strip()
    _validate_pinned_elf_identity(pinned_class, pinned_machine)
    notes = _require_success(_wsl("readelf", "-nW", binary), "ELF notes")
    build_id_match = re.search(r"Build ID:\s*([0-9a-f]+)", notes)
    if not build_id_match or len(build_id_match.group(1)) < 16:
        raise LabError("ELF build identity is unavailable")
    symbols = _require_success(_wsl("readelf", "-sW", binary), "ELF symbols")
    symbol_matches = []
    for line in symbols.splitlines():
        columns = line.split()
        if len(columns) >= 8 and columns[-1] == SYMBOL:
            try:
                symbol_matches.append((int(columns[1], 16), int(columns[2])))
            except ValueError as error:
                raise LabError("probe symbol is malformed") from error
    symbol_matches = list(dict.fromkeys(symbol_matches))
    if len(symbol_matches) != 1 or symbol_matches[0][1] != page_size:
        raise LabError("probe symbol must be unique and exactly one page")
    symbol_vaddr, symbol_size = symbol_matches[0]
    if symbol_vaddr % page_size != 0 or symbol_size != page_size:
        raise LabError("probe symbol is not page-aligned")
    relocations = _require_success(_wsl("readelf", "-rW", binary), "ELF relocations")
    relocation_intervals = _relocation_intervals(relocations)
    overlaps = _probe_relocation_overlaps(
        relocation_intervals, symbol_vaddr, symbol_size
    )
    if overlaps:
        raise LabError("probe page contains runtime relocations and is unsupported")
    return {
        "binary_sha256": _sha256_file_wsl(binary),
        "build_id": build_id_match.group(1),
        "elf_class": pinned_class,
        "elf_machine": pinned_machine,
        "probe_relocation_count": 0,
    }


def _permissions(value: Any, readable: bool, executable: bool) -> str:
    if not isinstance(value, str) or len(value) < 4:
        raise LabError("mapping permissions are malformed")
    if (
        (value[0] == "r") != readable
        or value[1] == "w"
        or (value[2] == "x") != executable
    ):
        raise LabError("mapping permissions violate the expected W^X state")
    return value


def validate_raw_case(
    value: Any, expected: dict[str, Any], page_size: int, drift_offset: int
) -> dict[str, Any]:
    raw = _exact(value, RAW_KEYS, f"raw case {expected['scenario']}")
    if raw["schema"] != "tamandua.runtime-rx-filebacked-elf-linux-raw/v1":
        raise LabError("raw schema is unsupported")
    for field in ("scenario", "state", "outcome", "backing_state", "limitations"):
        if raw[field] != expected[field]:
            raise LabError(f"raw case {expected['scenario']} changed {field}")
    if raw["cleanup"] != expected["cleanup"]:
        raise LabError(f"raw case {expected['scenario']} changed cleanup semantics")
    if raw["page_size_bytes"] != page_size or raw["initial_protection"] != "rx":
        raise LabError("raw page identity is inconsistent")
    if (
        raw["writable_executable_used"] is not False
        or raw["mapped_bytes_executed"] is not False
        or raw["absolute_paths_emitted"] is not False
    ):
        raise LabError("raw safety boundary was violated")
    for field in (
        "mapping_file_offset",
        "probe_file_offset",
        "load_bias",
        "mapping_inode",
    ):
        if (
            isinstance(raw[field], bool)
            or not isinstance(raw[field], int)
            or raw[field] < 0
        ):
            raise LabError(f"raw {field} is malformed")
    if raw["load_bias"] % page_size != 0:
        raise LabError("runtime load bias is not page-aligned")
    if raw["mapping_inode"] <= 0 and raw["backing_state"] != "anonymous":
        raise LabError("file-backed mapping identity is unavailable")
    backing_inode = raw["backing_inode"]
    if backing_inode is not None and (
        isinstance(backing_inode, bool)
        or not isinstance(backing_inode, int)
        or backing_inode <= 0
    ):
        raise LabError("raw backing_inode is malformed")

    scenario = expected["scenario"]
    if scenario in {"clean_file_backed_rx", "file_backed_rw_to_rx_drift"}:
        _permissions(raw["observed_permissions"], readable=True, executable=True)
        if raw["final_protection"] != "rx" or backing_inode != raw["mapping_inode"]:
            raise LabError("supported file backing identity is inconsistent")
        wanted = [] if scenario == "clean_file_backed_rx" else [drift_offset]
        if raw["drift_offsets"] != wanted:
            raise LabError("file-backed page drift does not match the fixed scenario")
        duration = raw["comparison_pipeline_duration_ns"]
        if (
            isinstance(duration, bool)
            or not isinstance(duration, int)
            or not 0 <= duration <= MAX_COMPARISON_PIPELINE_DURATION_NS
        ):
            raise LabError("comparison pipeline duration exceeds the runaway bound")
        if raw["compared_bytes"] != page_size:
            raise LabError("supported comparison accounting is invalid")
        baseline_sha = raw["baseline_sha256"]
        current_sha = raw["current_sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", baseline_sha or "") or not re.fullmatch(
            r"[0-9a-f]{64}", current_sha or ""
        ):
            raise LabError("comparison pipeline digest is malformed")
        if (baseline_sha == current_sha) != (scenario == "clean_file_backed_rx"):
            raise LabError("comparison pipeline digest contradicts the scenario")
    else:
        if scenario == "anonymous_jit_no_baseline":
            _permissions(raw["observed_permissions"], readable=True, executable=True)
        elif scenario == "execute_only_file_backed":
            _permissions(raw["observed_permissions"], readable=False, executable=True)
        else:
            _permissions(raw["observed_permissions"], readable=True, executable=True)
        if (
            raw["baseline_sha256"] is not None
            or raw["current_sha256"] is not None
            or raw["drift_offsets"] != []
            or raw["compared_bytes"] != 0
            or raw["comparison_pipeline_duration_ns"] is not None
        ):
            raise LabError("unavailable case must not claim a comparison")
        protection, backing_must_be_none, backing_must_equal, mapping_must_be_zero = {
            "deleted_backing": ("rx", True, False, False),
            "replaced_backing": ("rx", False, False, False),
            "anonymous_jit_no_baseline": ("rx", True, False, True),
            "execute_only_file_backed": ("x", False, True, False),
        }[scenario]
        if raw["final_protection"] != protection:
            raise LabError(f"{scenario} final protection is inconsistent")
        if (raw["mapping_inode"] == 0) != mapping_must_be_zero:
            raise LabError(f"{scenario} mapping identity is inconsistent")
        if (backing_inode is None) != backing_must_be_none:
            raise LabError(f"{scenario} backing identity is inconsistent")
        if backing_must_equal and backing_inode != raw["mapping_inode"]:
            raise LabError(f"{scenario} backing identity is inconsistent")
        if scenario == "replaced_backing" and backing_inode == raw["mapping_inode"]:
            raise LabError("replaced backing identity was not changed")
        baseline_sha = None
        current_sha = None

    return {
        "scenario": scenario,
        "state": raw["state"],
        "outcome": raw["outcome"],
        "backing_state": raw["backing_state"],
        "page_size_bytes": page_size,
        "initial_protection": "rx",
        "final_protection": raw["final_protection"],
        "observed_permissions": raw["observed_permissions"],
        "baseline_sha256": baseline_sha,
        "current_sha256": current_sha,
        "drift_offsets": raw["drift_offsets"],
        "limitations": raw["limitations"],
        "compared_bytes": raw["compared_bytes"],
        "comparison_pipeline_duration_ns": raw["comparison_pipeline_duration_ns"],
        "load_bias": "verified_redacted",
        "mapping_identity": "verified_redacted",
        "backing_identity": (
            "unavailable_deleted"
            if scenario == "deleted_backing"
            else "verified_changed_redacted"
            if scenario == "replaced_backing"
            else "not_applicable_anonymous"
            if scenario == "anonymous_jit_no_baseline"
            else "verified_matching_redacted"
        ),
        "executed_binary_identity": "master_sha256_verified_redacted",
        "cleanup": raw["cleanup"],
    }


def _run_matrix(
    temp_path: str,
    master_binary: str,
    contract: dict[str, Any],
    provenance: dict[str, Any],
    capability: dict[str, Any],
) -> dict[str, Any]:
    cases = []
    verified_case_hashes = 0
    for index, expected in enumerate(contract["cases"]):
        case_binary = f"{temp_path}/case-{index}"
        _require_success(
            _wsl("cp", "--", master_binary, case_binary), "case binary copy"
        )
        _require_hash_match(
            _sha256_file_wsl(case_binary),
            provenance["binary_sha256"],
            f"scenario {expected['scenario']} binary",
        )
        verified_case_hashes += 1
        completed = _wsl(
            "timeout",
            "--kill-after=1s",
            "1s",
            "env",
            f"TAMANDUA_CASE_BINARY_PATH={case_binary}",
            case_binary,
            expected["scenario"],
            timeout=3.0,
        )
        output = _require_success(completed, f"scenario {expected['scenario']}")
        try:
            raw = json.loads(output)
        except json.JSONDecodeError as error:
            raise LabError(
                f"scenario {expected['scenario']} emitted malformed JSON"
            ) from error
        projected = validate_raw_case(
            raw,
            expected,
            contract["page_size_bytes"],
            contract["drift_offset"],
        )
        if expected["state"] == "supported":
            bounded_baseline = _sha256_file_range_wsl(
                case_binary,
                raw["probe_file_offset"],
                contract["page_size_bytes"],
            )
            if bounded_baseline != raw["baseline_sha256"]:
                raise LabError(
                    f"scenario {expected['scenario']} baseline digest is not provenance-bound"
                )
        if expected["scenario"] not in {"deleted_backing", "replaced_backing"}:
            _require_hash_match(
                _sha256_file_wsl(case_binary),
                provenance["binary_sha256"],
                f"scenario {expected['scenario']} post-execution binary",
            )
        cases.append(projected)
    return {
        "schema": "tamandua.runtime-rx-filebacked-elf-linux-lab/v1",
        "evidence_class": "local_wsl_filebacked_elf_lab",
        "external_claim_allowed": False,
        "production_ready": False,
        "vendor_parity": False,
        "provenance": {
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "contract_sha256": hashlib.sha256(CONTRACT.read_bytes()).hexdigest(),
            **provenance,
            "case_binary_hashes_verified": verified_case_hashes,
            "kernel": capability["kernel"],
            "architecture": capability["architecture"],
            "rustc_version": capability["rustc_version"],
            "page_size_bytes": capability["page_size_bytes"],
            "load_bias": "verified_redacted",
            "relocation_policy": contract["relocation_policy"],
        },
        "safety": {
            "self_owned_compiled_elf_only": True,
            "writable_executable_used": False,
            "mapped_bytes_executed": False,
            "ptrace_used": False,
            "raw_page_bytes_retained": False,
            "absolute_paths_retained": False,
            "runtime_addresses_retained": False,
            "inode_values_retained": False,
        },
        "cost": {
            "cases": len(cases),
            "compared_pages": 2,
            "compared_bytes": sum(case["compared_bytes"] for case in cases),
            **contract["cost_budget"],
        },
        "cases": cases,
        "cleanup_confirmed": False,
        "repeatability": {"runs": 1, "normalized_equal": True},
    }


def normalized_report(report: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(report)
    normalized["repeatability"] = {"runs": 1, "normalized_equal": True}
    for case in normalized["cases"]:
        case["comparison_pipeline_duration_ns"] = None
    return normalized


def validate_report(value: Any) -> dict[str, Any]:
    report = _exact(value, REPORT_KEYS, "report")
    if (
        report["schema"] != "tamandua.runtime-rx-filebacked-elf-linux-lab/v1"
        or report["evidence_class"] != "local_wsl_filebacked_elf_lab"
        or report["external_claim_allowed"] is not False
        or report["production_ready"] is not False
        or report["vendor_parity"] is not False
    ):
        raise LabError("report claim boundary was elevated or relabeled")
    provenance = _exact(report["provenance"], PROVENANCE_KEYS, "provenance")
    for key in ("source_sha256", "contract_sha256", "binary_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", provenance[key] or ""):
            raise LabError(f"provenance {key} is malformed")
    if (
        not re.fullmatch(r"[0-9a-f]{16,}", provenance["build_id"] or "")
        or provenance["architecture"] != "x86_64"
        or provenance["page_size_bytes"] != 4096
        or provenance["load_bias"] != "verified_redacted"
        or provenance["relocation_policy"] != "reject_probe_overlap"
        or provenance["probe_relocation_count"] != 0
        or provenance["case_binary_hashes_verified"] != 6
    ):
        raise LabError("ELF provenance is incomplete or unsupported")
    _validate_pinned_elf_identity(provenance["elf_class"], provenance["elf_machine"])
    safety = _exact(report["safety"], SAFETY_KEYS, "safety")
    if safety != {
        "self_owned_compiled_elf_only": True,
        "writable_executable_used": False,
        "mapped_bytes_executed": False,
        "ptrace_used": False,
        "raw_page_bytes_retained": False,
        "absolute_paths_retained": False,
        "runtime_addresses_retained": False,
        "inode_values_retained": False,
    }:
        raise LabError("report safety boundary is invalid")
    cost = _exact(report["cost"], COST_KEYS, "cost")
    if cost != {
        "cases": 6,
        "compared_pages": 2,
        "compared_bytes": 8192,
        "max_cases": 6,
        "max_compared_pages": 2,
        "max_compared_bytes": 8192,
        "max_case_duration_ms": 1000,
        "max_comparison_pipeline_duration_ns": MAX_COMPARISON_PIPELINE_DURATION_NS,
    }:
        raise LabError("report cost accounting is invalid")
    if not isinstance(report["cases"], list) or len(report["cases"]) != 6:
        raise LabError("report must contain exactly six cases")
    contract = load_contract()
    for expected, case in zip(contract["cases"], report["cases"], strict=True):
        _exact(case, CASE_KEYS, f"report case {expected['scenario']}")
        for field in (
            "scenario",
            "state",
            "outcome",
            "backing_state",
            "limitations",
            "cleanup",
        ):
            if case[field] != expected[field]:
                raise LabError(f"report case {expected['scenario']} changed {field}")
        if "hex" in " ".join(case) or any("/" in str(item) for item in case.values()):
            raise LabError("report retained raw page bytes or absolute paths")
        if (
            case["load_bias"] != "verified_redacted"
            or case["mapping_identity"] != "verified_redacted"
        ):
            raise LabError("report identity redaction is incomplete")
        if case["executed_binary_identity"] != "master_sha256_verified_redacted":
            raise LabError("report executed-binary provenance is incomplete")
    if report["cleanup_confirmed"] is not True:
        raise LabError("lab cleanup was not confirmed")
    repeatability = _exact(report["repeatability"], REPEAT_KEYS, "repeatability")
    if (
        repeatability["runs"] not in {1, 2}
        or repeatability["normalized_equal"] is not True
    ):
        raise LabError("repeatability gate is not satisfied")
    return report


def run_lab(repeat: int = 1) -> dict[str, Any]:
    if repeat not in {1, 2}:
        raise LabError("repeat must be one or two")
    contract = load_contract()
    capability = preflight()
    if capability.get("capable") is not True:
        raise LabError(
            f"explicit WSL capability preflight failed: {capability['reasons']}"
        )
    temp_path = _safe_temp_path(
        _require_success(
            _wsl("mktemp", "-d", "-t", "tamandua-rx-elf-lab.XXXXXXXX"),
            "temporary directory",
        )
    )
    cleanup_confirmed = False
    report: dict[str, Any] | None = None
    try:
        source_copy = f"{temp_path}/lab.rs"
        master_binary = f"{temp_path}/lab"
        _require_success(
            _wsl("cp", "--", _host_to_wsl(SOURCE), source_copy), "source isolation"
        )
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
                "-C",
                "link-arg=-Wl,--build-id=sha1",
                source_copy,
                "-o",
                master_binary,
                timeout=30.0,
            ),
            "standalone Rust compile",
        )
        provenance = _elf_provenance(master_binary, contract["page_size_bytes"])
        runs = [
            _run_matrix(temp_path, master_binary, contract, provenance, capability)
            for _ in range(repeat)
        ]
        normalized_equal = all(
            normalized_report(item) == normalized_report(runs[0]) for item in runs[1:]
        )
        report = runs[0]
        report["repeatability"] = {"runs": repeat, "normalized_equal": normalized_equal}
    finally:
        if temp_path.startswith("/tmp/tamandua-rx-elf-lab."):
            _wsl("rm", "-rf", "--", temp_path)
            cleanup_confirmed = _wsl("test", "!", "-e", temp_path).returncode == 0
        if not cleanup_confirmed:
            raise LabError("isolated WSL temporary directory cleanup failed")
    if report is None:
        raise LabError("WSL lab did not produce a report")
    report["cleanup_confirmed"] = True
    return validate_report(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--run", action="store_true")
    action.add_argument("--validate-contract", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.preflight:
            result = preflight()
        elif args.validate_contract:
            result = load_contract()
        else:
            result = run_lab(args.repeat)
    except LabError as error:
        print(json.dumps({"status": "fail", "error": str(error)}, sort_keys=True))
        return 1
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
