#!/usr/bin/env python3
"""Validate a sanitized Windows live self-image comparison lab receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

MAX_INPUT = 64 * 1024 * 1024
MAX_PAGES = 8192
PAGE = 4096
SCHEMA_VERSION = "tamandua.runtime_self_image_live_compare_receipt/v1"
BUILD_COMMAND_ID = "cargo-test-release-nodefault-windows-x86_64-msvc-live-lab-v1"
CANONICAL_BUILD_COMMAND = "cargo test --locked --manifest-path apps/tamandua_agent/Cargo.toml --target x86_64-pc-windows-msvc --release --no-default-features --lib --no-run --message-format=json-render-diagnostics"
PROVENANCE_PATHS = (
    "apps/tamandua_agent/Cargo.lock",
    "apps/tamandua_agent/src/collectors/runtime_integrity/page_content.rs",
    "apps/tamandua_agent/src/collectors/runtime_integrity/page_content/windows_live_lab.rs",
    "schemas/runtime_self_image_live_compare_receipt_v1.schema.json",
    "tools/detection_validation/scripts/runtime_self_image_live_compare_gate.py",
    "tools/detection_validation/tests/test_runtime_self_image_live_compare_gate.py",
)
ROOT_KEYS = {
    "actions", "artifact_sha256_after", "artifact_sha256_before", "artifact_size",
    "build_command_id", "build_command_sha256", "cargo_lock_sha256", "claims",
    "cost", "counts", "degraded_reason", "dirty_patch_sha256", "evidence_class",
    "harness_sha256", "identity", "measurement_boundary", "page_size", "planner_source_sha256", "receipt_encoding_and_write_measured",
    "post_restore_counts", "post_restore_state", "scenario", "schema_version",
    "source_commit", "state", "target", "toolchain_id",
}
ACTION_KEYS = {"current_main_modified", "disposable_mapping_restored", "disposable_sec_image_used", "live_memory_compared"}
CLAIM_KEYS = {"external_claim_allowed", "production_ready", "release_authority", "runtime_detection_proven", "telemetry_emitted", "verimatrix_parity"}
COUNT_KEYS = {"clean_pages", "compared_pages", "mismatch_pages", "planned_pages", "relocation_excluded_pages", "unstable_pages"}
COST_KEYS = {"budget_state", "cpu_time_ms", "elapsed_ms", "query_count", "read_attempt_count", "read_bytes", "working_set_after", "working_set_before", "working_set_delta_bytes", "working_set_peak_delta_bytes"}
IDENTITY_KEYS = {"anchor_within_main_image", "anchor_module_matches_main", "artifact_matches_main_exe", "disposable_mapping_disjoint_from_main", "file_id_stable", "locked_read_handle", "mapped_file_object_identity_proven", "mapped_name_matches_locked_artifact", "module_size_matches_pe", "native_amd64_process", "page_size_matches"}
FORBIDDEN = ("path", "offset", "address", "raw", "page_hash", "per_page", "pid", "device", "guid", "serial", "user", "hostname", "module_name")


class GateError(ValueError):
    pass


class PeMetrics(NamedTuple):
    eligible_pages: int
    relocation_excluded_pages: int


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise GateError(f"{name} must have exact keys")
    return value


def _integer(value: Any, name: str, minimum: int = 0, maximum: int = MAX_PAGES) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GateError(f"{name} is not a bounded integer")
    return value


def _digest(value: Any, name: str, size: int = 64) -> str:
    if type(value) is not str or len(value) != size or any(c not in "0123456789abcdef" for c in value):
        raise GateError(f"{name} is not normalized hex identity")
    return value


def _privacy(value: Any, location: str = "receipt") -> None:
    if isinstance(value, list):
        raise GateError(f"arrays are forbidden at {location}")
    if isinstance(value, dict):
        for key, child in value.items():
            if any(part in key.lower() for part in FORBIDDEN):
                raise GateError(f"privacy-risk field is forbidden at {location}.{key}")
            _privacy(child, f"{location}.{key}")


def _file_digest(path: Path, maximum: int | None = None) -> tuple[str, int]:
    before = path.stat()
    if not path.is_file() or (maximum is not None and before.st_size > maximum):
        raise GateError("identity input is not a bounded regular file")
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise GateError("identity input changed while read")
    return hashlib.sha256(data).hexdigest(), len(data)


def _run_identity(command: list[str], root: Path) -> bytes:
    try:
        result = subprocess.run(command, cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as error:
        raise GateError(f"provenance command failed: {command[0]}") from error
    return result.stdout


def _resolve_executable(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved: raise GateError(f"required provenance executable is absent: {name}")
    return str(Path(resolved).resolve())


def _bundle_digest(root: Path, git_executable: str | None = None) -> str:
    git_executable = git_executable or _resolve_executable("git")
    digest = hashlib.sha256(b"tamandua-scoped-dirty-bundle-v1\0")
    for relative in PROVENANCE_PATHS:
        path = root / relative
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode): raise GateError(f"provenance input is not an exact regular file: {relative}")
        content = path.read_bytes()
        after = path.lstat()
        metadata = lambda value: (value.st_mode,value.st_size,value.st_mtime_ns,value.st_dev,value.st_ino)
        if metadata(before) != metadata(after) or len(content) != before.st_size: raise GateError(f"provenance input drifted while read: {relative}")
        stage = _run_identity([git_executable, "ls-files", "--stage", "--", relative], root).decode("utf-8", "strict").strip()
        tracked_mode = stage.split(" ", 1)[0] if stage else "untracked"
        for label, value in ((b"path", relative.encode("utf-8")), (b"mode", f"{before.st_mode:o}".encode("ascii")), (b"tracked-mode", tracked_mode.encode("ascii")), (b"size", len(content).to_bytes(8, "big")), (b"content", content)):
            digest.update(label + b"\0" + len(value).to_bytes(8, "big") + value)
    return digest.hexdigest()


def derive_provenance(root: Path) -> dict[str, str]:
    root = root.resolve()
    git_executable, rustc_executable = _resolve_executable("git"), _resolve_executable("rustc")
    commit = _run_identity([git_executable, "rev-parse", "--verify", "HEAD"], root).decode("ascii", "strict").strip()
    _digest(commit, "derived git HEAD", 40)
    rustc_vv = _run_identity([rustc_executable, "-Vv"], root).replace(b"\r\n", b"\n").rstrip(b"\n") + b"\n"
    toolchain_digest = hashlib.sha256(b"tamandua-rustc-vv-v1\0" + rustc_vv).hexdigest()
    return {
        "source_commit": commit,
        "dirty_patch_sha256": _bundle_digest(root, git_executable),
        "toolchain_id": "rustc-vv-sha256-" + toolchain_digest,
        "build_command_sha256": hashlib.sha256(CANONICAL_BUILD_COMMAND.encode("ascii")).hexdigest(),
    }


def _u16(data: bytes, at: int) -> int:
    if at < 0 or at + 2 > len(data): raise GateError("truncated PE")
    return int.from_bytes(data[at:at + 2], "little")


def _u32(data: bytes, at: int) -> int:
    if at < 0 or at + 4 > len(data): raise GateError("truncated PE")
    return int.from_bytes(data[at:at + 4], "little")


def _pe_metrics(path: Path) -> PeMetrics:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ": raise GateError("artifact is not PE")
    pe = _u32(data, 0x3C)
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0": raise GateError("PE signature is invalid")
    sections_n, optional_size = _u16(data, pe + 6), _u16(data, pe + 20)
    characteristics, optional = _u16(data, pe + 22), pe + 24
    if _u16(data, pe + 4) != 0x8664 or _u16(data, optional) != 0x20B: raise GateError("artifact is not PE64 AMD64")
    if not characteristics & 0x0002 or characteristics & 0x2000: raise GateError("PE is not an executable main image")
    if optional_size < 240 or optional + optional_size > len(data): raise GateError("optional header is incomplete")
    section_alignment, file_alignment = _u32(data, optional + 32), _u32(data, optional + 36)
    size_image, size_headers = _u32(data, optional + 56), _u32(data, optional + 60)
    if section_alignment != PAGE or file_alignment < 512 or file_alignment > PAGE or file_alignment & (file_alignment - 1):
        raise GateError("unsupported PE alignment")
    if size_image == 0 or size_image % PAGE or size_headers == 0 or size_headers % file_alignment:
        raise GateError("unsupported PE image geometry")
    table = optional + optional_size
    if not 1 <= sections_n <= 96 or table + sections_n * 40 > len(data): raise GateError("section table is invalid")
    sections: list[tuple[int, int, int, int, int]] = []
    for i in range(sections_n):
        at = table + i * 40
        virtual_size, rva, raw_size, raw_at, flags = _u32(data, at + 8), _u32(data, at + 12), _u32(data, at + 16), _u32(data, at + 20), _u32(data, at + 36)
        mapped = max(virtual_size, raw_size)
        if not mapped or rva % PAGE or raw_at % file_alignment or raw_size % file_alignment or raw_at + raw_size > len(data) or rva + mapped > size_image:
            raise GateError("section geometry is invalid")
        sections.append((rva, mapped, raw_at, raw_size, flags))
    ordered = sorted(sections)
    if any(a[0] + a[1] > b[0] for a, b in zip(ordered, ordered[1:])): raise GateError("sections overlap")

    def rva_file(rva: int, size: int) -> int:
        for srva, _, raw_at, raw_size, _ in sections:
            if rva >= srva and rva + size <= srva + raw_size: return raw_at + rva - srva
        raise GateError("directory is not wholly file-backed")

    candidates: set[int] = set()
    for rva, mapped, raw_at, raw_size, flags in sections:
        if flags & 0x40000000 and flags & 0x20000000 and not flags & 0x80000000:
            backed = min(mapped, raw_size)
            for delta in range(0, backed, PAGE):
                if delta + PAGE <= backed and raw_at + delta >= size_headers:
                    candidates.add(rva + delta)
    if not candidates or len(candidates) > MAX_PAGES: raise GateError("no bounded RX page plan")

    directories = _u32(data, optional + 108)
    if directories > (optional_size - 112) // 8: raise GateError("directory table exceeds optional header")
    def directory(index: int) -> tuple[int, int]:
        if index >= directories: return 0, 0
        at = optional + 112 + index * 8
        if at + 8 > optional + optional_size: raise GateError("directory table is truncated")
        return _u32(data, at), _u32(data, at + 4)

    excluded: set[int] = set()
    reloc_rva, reloc_size = directory(5)
    if bool(reloc_rva) != bool(reloc_size): raise GateError("partial relocation metadata")
    if reloc_size:
        if reloc_size < 8: raise GateError("relocation directory is malformed")
        pos, end, last = rva_file(reloc_rva, reloc_size), rva_file(reloc_rva, reloc_size) + reloc_size, -1
        while pos < end:
            page_rva, block_size = _u32(data, pos), _u32(data, pos + 4)
            if page_rva % PAGE or block_size < 8 or block_size % 2 or pos + block_size > end or page_rva <= last: raise GateError("relocation blocks are ambiguous")
            last = page_rva
            for at in range(pos + 8, pos + block_size, 2):
                entry = _u16(data, at); kind, within = entry >> 12, entry & 0xFFF
                if kind == 0: continue
                if kind != 10: raise GateError("unsupported relocation type")
                touched = page_rva + within
                if touched + 8 > size_image: raise GateError("relocation target exceeds image")
                excluded.add(touched // PAGE * PAGE); excluded.add((touched + 7) // PAGE * PAGE)
            pos += block_size

    iat_rva, iat_size = directory(12)
    import_rva, import_size = directory(1)
    delay_rva, delay_size = directory(13)
    if delay_rva or delay_size: raise GateError("delay imports are unsupported")
    if bool(iat_rva) != bool(iat_size) or bool(import_rva) != bool(import_size): raise GateError("partial import metadata")
    if iat_rva:
        if iat_rva % 8 or iat_size % 8: raise GateError("IAT is unaligned")
        rva_file(iat_rva, iat_size)
        for page in candidates:
            if page < iat_rva + iat_size and page + PAGE > iat_rva: excluded.add(page)
    if import_rva:
        if not iat_rva: raise GateError("imports require a validated IAT")
        imp = rva_file(import_rva, import_size)
        if import_size < 20 or import_size % 20: raise GateError("import directory is ambiguous")
        def name(rva: int) -> None:
            start = rva_file(rva, 1)
            available = next((srva + raw_size - rva for srva, _, _, raw_size, _ in sections if srva <= rva < srva + raw_size), 0)
            if not available or b"\0" not in data[start:start + min(available, 4096)]: raise GateError("import name is not bounded and terminated")
        terminated = False
        thunk_ranges: list[tuple[int,int]] = []
        for at in range(imp, imp + import_size, 20):
            words = [_u32(data, at + x) for x in (0, 4, 8, 12, 16)]
            if not any(words):
                if any(data[at + 20:imp + import_size]): raise GateError("data follows import terminator")
                terminated = True; break
            original, _, _, name_rva, first_thunk = words
            if not name_rva or not first_thunk: raise GateError("import descriptor is incomplete")
            name(name_rva)
            lookup = original or first_thunk; count = 0
            while True:
                thunk_rva = lookup + count * 8; thunk = int.from_bytes(data[rva_file(thunk_rva, 8):rva_file(thunk_rva, 8)+8], "little"); count += 1
                if count > 1_000_000: raise GateError("import thunk count exceeds bound")
                if not thunk: break
                if not thunk & 0x8000000000000000:
                    target = thunk & 0x7fffffffffffffff
                    if target > 0xffffffff: raise GateError("import-by-name RVA exceeds format")
                    rva_file(target, 2); name(target + 2)
            width = count * 8; rva_file(first_thunk, width)
            if not (iat_rva <= first_thunk and first_thunk + width <= iat_rva + iat_size): raise GateError("FirstThunk range escapes IAT")
            thunk_ranges.append((first_thunk, first_thunk + width))
        if not terminated: raise GateError("import descriptors lack terminator")
        thunk_ranges.sort()
        if any(a[1] > b[0] for a,b in zip(thunk_ranges, thunk_ranges[1:])): raise GateError("FirstThunk ranges overlap")
    removed = candidates & excluded
    eligible = candidates - excluded
    if not eligible: raise GateError("exclusions removed every RX page")
    return PeMetrics(len(eligible), len(removed))


def _schema_contract(schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" or schema.get("additionalProperties") is not False:
        raise GateError("schema root is not closed Draft 2020-12")
    if set(schema.get("required", [])) != ROOT_KEYS or set(schema.get("properties", {})) != ROOT_KEYS:
        raise GateError("schema root differs from gate contract")


def preflight_artifact(path: Path) -> dict[str, int]:
    metrics = _pe_metrics(path)
    if not 1 <= metrics.eligible_pages <= MAX_PAGES or metrics.relocation_excluded_pages < 1:
        raise GateError("artifact lacks bounded eligible RX pages or positive relocation exclusion")
    return {"eligible_pages": metrics.eligible_pages, "relocation_excluded_pages": metrics.relocation_excluded_pages}


def _counts(value: Any, name: str) -> tuple[dict[str, Any], int, int, int, int, int, int]:
    v = _exact(value, COUNT_KEYS, name)
    planned = _integer(v["planned_pages"], f"{name}.planned_pages", 0)
    compared = _integer(v["compared_pages"], f"{name}.compared_pages")
    clean = _integer(v["clean_pages"], f"{name}.clean_pages")
    mismatch = _integer(v["mismatch_pages"], f"{name}.mismatch_pages")
    unstable = _integer(v["unstable_pages"], f"{name}.unstable_pages")
    excluded = _integer(v["relocation_excluded_pages"], f"{name}.relocation_excluded_pages", 0, 16384)
    if compared != clean + mismatch or planned != compared + unstable: raise GateError(f"{name} accounting is inconsistent")
    return v, planned, compared, clean, mismatch, unstable, excluded


def validate(receipt_path: Path, artifact_path: Path, planner_source_path: Path, harness_path: Path,
             cargo_lock_path: Path, schema_path: Path, repo_root: Path | None = None,
             derived_provenance: dict[str, str] | None = None) -> dict[str, Any]:
    _schema_contract(schema_path)
    raw = receipt_path.read_text(encoding="utf-8"); receipt = json.loads(raw)
    if raw != json.dumps(receipt, ensure_ascii=False, separators=(",", ":"), sort_keys=True): raise GateError("receipt is not compact canonical key-sorted JSON")
    _privacy(receipt); receipt = _exact(receipt, ROOT_KEYS, "receipt")
    actions = _exact(receipt["actions"], ACTION_KEYS, "actions")
    claims = _exact(receipt["claims"], CLAIM_KEYS, "claims")
    identity = _exact(receipt["identity"], IDENTITY_KEYS, "identity")
    cost = _exact(receipt["cost"], COST_KEYS, "cost")
    _, planned, compared, _, mismatch, unstable, excluded = _counts(receipt["counts"], "counts")
    _, post_planned, post_compared, post_clean, post_mismatch, post_unstable, post_excluded = _counts(receipt["post_restore_counts"], "post_restore_counts")
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["evidence_class"] != "windows-live-compare-lab" or receipt["target"] != "x86_64-pc-windows-msvc" or receipt["page_size"] != PAGE:
        raise GateError("receipt identity is unsupported")
    if receipt["measurement_boundary"] != "pre_receipt_serialization" or receipt["receipt_encoding_and_write_measured"] is not False: raise GateError("measurement boundary limitation is not exact")
    if receipt["build_command_id"] != BUILD_COMMAND_ID: raise GateError("build command identity is unsupported")
    if any(type(v) is not bool or v for v in claims.values()): raise GateError("all claims must be exact boolean false")
    if any(type(v) is not bool for v in actions.values()) or any(type(v) is not bool for v in identity.values()) or actions["current_main_modified"]:
        raise GateError("actions/identity are invalid")
    metrics = _pe_metrics(artifact_path)
    if planned != metrics.eligible_pages or excluded != metrics.relocation_excluded_pages: raise GateError("receipt plan differs from independently derived PE plan")

    for field in ("cpu_time_ms","elapsed_ms"): _integer(cost[field], f"cost.{field}", 0, 300000)
    for field in ("query_count","read_attempt_count"): _integer(cost[field], f"cost.{field}", 0, 49152)
    _integer(cost["read_bytes"], "cost.read_bytes", 0, 134217728)
    for field in ("working_set_before","working_set_after"): _integer(cost[field], f"cost.{field}", 1, 1 << 50)
    if type(cost["working_set_delta_bytes"]) is not int or not -(1 << 50) <= cost["working_set_delta_bytes"] <= (1 << 50): raise GateError("working-set delta is not bounded")
    if cost["working_set_delta_bytes"] != cost["working_set_after"] - cost["working_set_before"]: raise GateError("working-set delta is stale")
    _integer(cost["working_set_peak_delta_bytes"], "cost.working_set_peak_delta_bytes", 0, 1 << 50)
    if cost["working_set_peak_delta_bytes"] < abs(cost["working_set_delta_bytes"]): raise GateError("working-set peak delta under-reports final delta")
    total_planned, total_compared = planned + post_planned, compared + post_compared
    if not total_compared * 3 <= cost["query_count"] <= total_planned * 3: raise GateError("attempted query counter contradicts comparison work")
    if not total_compared * 2 <= cost["read_attempt_count"] <= total_planned * 2 or cost["read_attempt_count"] > cost["query_count"]: raise GateError("attempted read counter contradicts comparison work")
    if not total_compared * 2 * PAGE <= cost["read_bytes"] <= cost["read_attempt_count"] * PAGE: raise GateError("read-byte counter contradicts attempted reads")
    if cost["read_bytes"] == cost["read_attempt_count"] * PAGE and cost["query_count"] < cost["read_attempt_count"] + (cost["read_attempt_count"] + 1) // 2: raise GateError("query attempts under-report completed read sequence")
    exceeded = cost["elapsed_ms"] > 30000 or cost["cpu_time_ms"] > 30000 or cost["read_bytes"] > 128 * 1024 * 1024 or cost["query_count"] > 49152 or cost["working_set_peak_delta_bytes"] > 512 * 1024 * 1024
    if cost["budget_state"] != ("exceeded" if exceeded else "within_budget"): raise GateError("cost budget state is stale")

    scenario, live, reason, state = receipt["scenario"], actions["live_memory_compared"], receipt["degraded_reason"], receipt["state"]
    if identity["mapped_file_object_identity_proven"]: raise GateError("mapped object identity is an explicit unproven limitation")
    base_identity = {k: v for k, v in identity.items() if k not in {"disposable_mapping_disjoint_from_main", "mapped_file_object_identity_proven"}}
    if not all(base_identity.values()): raise GateError("exact live identity checks are incomplete")
    if scenario == "current-main-observe":
        if actions["disposable_sec_image_used"] or actions["disposable_mapping_restored"] or identity["disposable_mapping_disjoint_from_main"]: raise GateError("current-main scenario claims disposable actions")
        if receipt["post_restore_state"] != "not_applicable" or any((post_planned, post_compared, post_clean, post_mismatch, post_unstable, post_excluded)): raise GateError("current-main post-restore fields must be zero/not-applicable")
        if not live:
            expected_reason = "cost_budget_exceeded" if exceeded else "relocation_exclusion_not_positive"
            if excluded != 0 or state != "degraded" or reason != expected_reason or compared or unstable != planned: raise GateError("missing relocation proof must follow exact cost-first non-live degradation")
        else:
            if excluded < 1: raise GateError("live comparison lacks artifact-proven relocation exclusion")
            expected = "degraded" if exceeded else "unstable" if unstable else "mismatch" if mismatch else "clean"
            expected_reason = "cost_budget_exceeded" if exceeded else "none"
            if state != expected or reason != expected_reason: raise GateError("current-main state precedence is not exact")
    elif scenario == "disposable-sec-image-controlled-drift":
        if excluded < 1: raise GateError("controlled comparison lacks artifact-proven relocation exclusion")
        if not all((live, actions["disposable_sec_image_used"], actions["disposable_mapping_restored"], identity["disposable_mapping_disjoint_from_main"])): raise GateError("controlled scenario prerequisites are incomplete")
        if unstable or mismatch < 1 or state != "controlled_mismatch_detected" or reason != "none" or exceeded: raise GateError("controlled mismatch state is not exact")
        if receipt["post_restore_state"] != "clean" or (post_planned, post_compared, post_clean, post_excluded) != (metrics.eligible_pages, metrics.eligible_pages, metrics.eligible_pages, metrics.relocation_excluded_pages) or post_mismatch or post_unstable:
            raise GateError("controlled post-restore proof is not exact clean")
    else: raise GateError("scenario is unsupported")

    artifact_sha, artifact_size = _file_digest(artifact_path, MAX_INPUT)
    if receipt["artifact_size"] != artifact_size or _digest(receipt["artifact_sha256_before"], "artifact before") != artifact_sha or _digest(receipt["artifact_sha256_after"], "artifact after") != artifact_sha: raise GateError("artifact identity is stale")
    for field, path in (("planner_source_sha256", planner_source_path), ("harness_sha256", harness_path), ("cargo_lock_sha256", cargo_lock_path)):
        actual, _ = _file_digest(path)
        if _digest(receipt[field], field) != actual: raise GateError(f"{field} is stale")
    provenance = derived_provenance if derived_provenance is not None else derive_provenance(repo_root or Path(__file__).resolve().parents[3])
    if set(provenance) != {"source_commit","dirty_patch_sha256","toolchain_id","build_command_sha256"}: raise GateError("derived provenance contract is incomplete")
    if _digest(receipt["source_commit"], "source_commit", 40) != provenance["source_commit"]: raise GateError("source commit is stale")
    if _digest(receipt["dirty_patch_sha256"], "dirty_patch_sha256") != provenance["dirty_patch_sha256"]: raise GateError("dirty patch is stale")
    if receipt["toolchain_id"] != provenance["toolchain_id"]: raise GateError("toolchain identity is stale")
    if _digest(receipt["build_command_sha256"], "build_command_sha256") != provenance["build_command_sha256"]: raise GateError("build command hash is stale")
    return receipt


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[3]; p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--print-derived-provenance", action="store_true")
    p.add_argument("--preflight-artifact", action="store_true")
    for name in ("receipt", "artifact", "planner-source", "harness"): p.add_argument(f"--{name}", type=Path)
    p.add_argument("--cargo-lock", default=root / "apps/tamandua_agent/Cargo.lock", type=Path); p.add_argument("--schema", default=root / "schemas/runtime_self_image_live_compare_receipt_v1.schema.json", type=Path)
    a = p.parse_args(argv)
    try:
        if a.print_derived_provenance:
            print(json.dumps(derive_provenance(root), separators=(",",":"), sort_keys=True)); return 0
        if a.preflight_artifact:
            if a.artifact is None: raise GateError("--preflight-artifact requires --artifact")
            print(json.dumps(preflight_artifact(a.artifact), separators=(",",":"), sort_keys=True)); return 0
        if any(value is None for value in (a.receipt,a.artifact,a.planner_source,a.harness)): raise GateError("receipt/artifact/planner-source/harness are required")
        validate(a.receipt, a.artifact, a.planner_source, a.harness, a.cargo_lock, a.schema, root)
    except (GateError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"runtime self-image live compare gate: FAIL: {error}", file=sys.stderr); return 1
    print("runtime self-image live compare gate: PASS (Windows test-only live lab; all claims false)"); return 0


if __name__ == "__main__": raise SystemExit(main())
