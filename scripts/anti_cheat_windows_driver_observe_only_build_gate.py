#!/usr/bin/env python3
"""Local consistency gate for the Windows observe-only driver candidate.

This tool may compile and link an unsigned ``.sys``.  It never installs, signs,
loads, opens, or communicates with a driver.  Runtime and efficacy claims are
therefore permanently false in its receipt.  A locally observed zero-exit build
and parsed artifact remain unbound observations: this importable gate never
authenticates build or link execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as python_platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable, Sequence

from jsonschema import Draft202012Validator


SCHEMA_VERSION = "tamandua.anti_cheat_windows_driver_observe_only_build_receipt/v1"
SCHEMA_VERSION_V2 = "tamandua.anti_cheat_windows_driver_observe_only_build_receipt/v2"
AUTHORITY_SCHEMA_VERSION = "tamandua.anti_cheat_windows_driver_observe_only_build_authority/v1"
V1_SCHEMA_SHA256 = "03b0c22a2b95a6b703af58fc9d8c5e99b5751cfd02e93bdbce5cb578c5a29bd9"
AUTHORITY_FALSE_CLAIMS = {"build_executed": False, "build_validated": False, "link_validated": False}
MAX_LOG_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
PROJECT_ITEM_TAGS = frozenset({
    "ClCompile", "ClInclude", "Inf", "ResourceCompile", "CustomBuild",
    "MessageCompile", "MessageCompiler",
})
ALLOWED_DIRECT_IMPORTS = frozenset({
    r"$(VCTargetsPath)\Microsoft.Cpp.Default.props",
    r"$(VCTargetsPath)\Microsoft.Cpp.props",
    r"$(VCTargetsPath)\Microsoft.Cpp.targets",
})
RUNTIME_FALSE_CLAIMS = {
    "signed": False,
    "installed": False,
    "loaded": False,
    "driver_communication_validated": False,
    "runtime_validated": False,
    "efficacy_validated": False,
    "production_ready": False,
    "external_claim_allowed": False,
}
ARTIFACT_OBSERVED_BLOCKERS = [
    "build_execution_authenticity_unbound", "link_execution_authenticity_unbound",
    "signature_not_validated", "install_not_validated", "load_not_validated",
    "driver_communication_not_validated", "runtime_not_validated", "efficacy_not_validated",
]
LOCAL_RECEIPT_STATUSES = frozenset({
    "artifact_observed_unbound", "toolchain_unavailable", "project_preflight_failed",
    "timed_out", "build_failed", "artifact_missing", "artifact_invalid", "input_drift",
    "internal_error", "artifact_observed_provenance_bound", "provenance_drift",
})
ALL_CLAIM_KEYS = frozenset({"build_validated", "link_validated", *RUNTIME_FALSE_CLAIMS})
PROVENANCE_ROLE_NAMES = (
    "gate_entrypoint", "receipt_schema_v2", "focused_tests", "python_executable",
)
INTERNAL_BLOCKERS = frozenset({
    "internal_gate_error", "unsafe_output_topology", "invalid_project_contract",
    "toolchain_inventory_unavailable", "receipt_validation_failed",
})
class ReceiptValidationError(ValueError):
    """Raised when an emitted receipt is not derivable from its evidence."""


@dataclass
class _LocalConsistencyContext:
    project: Path
    source_before: list[dict[str, object]]
    stage: Path
    msbuild: Path
    wdk: str
    toolchain_before: list[dict[str, object]] | None = None
    imports_before: list[dict[str, object]] | None = None
    preprocess_path: Path | None = None
    allowed_import_roots: tuple[Path, ...] = ()
    artifact_path: Path | None = None
    binding_sha256: str | None = None
    preprocess_evidence: "ProcessEvidence | None" = None
    process_evidence: "ProcessEvidence | None" = None
    authority_path: Path | None = None
    authority_snapshot: dict[str, object] | None = None
    authority_sha256: str | None = None
    provenance_before: list[dict[str, object]] | None = None
    invocation_args: argparse.Namespace | None = None


def _sha256_file(path: Path, *, max_bytes: int | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"file_too_large:{path}")
            digest.update(chunk)
    return digest.hexdigest()


def _repo_root() -> Path:
    return Path(__file__).resolve(strict=True).parents[3]


def _schema_path(version: str) -> Path:
    names = {
        SCHEMA_VERSION: "anti_cheat_windows_driver_observe_only_build_receipt_v1.schema.json",
        SCHEMA_VERSION_V2: "anti_cheat_windows_driver_observe_only_build_receipt_v2.schema.json",
        AUTHORITY_SCHEMA_VERSION: "anti_cheat_windows_driver_observe_only_build_authority_v1.schema.json",
    }
    try:
        return _repo_root() / "schemas" / names[version]
    except KeyError as exc:
        raise ReceiptValidationError("schema_version_unsupported") from exc


def _path_token(path: Path) -> str:
    return hashlib.sha256(os.path.normcase(str(path)).encode("utf-8")).hexdigest()


def _reject_unsafe_windows_spelling(path: Path) -> None:
    text = str(path)
    if text.startswith(("\\\\", "\\?\\", "\\.\\")):
        raise ValueError("unsafe_path_spelling")
    drive, tail = os.path.splitdrive(text)
    if ":" in tail or any(part.endswith((" ", ".")) for part in Path(tail).parts):
        raise ValueError("unsafe_path_spelling")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if any(part.split(".", 1)[0].casefold() in reserved for part in Path(tail).parts):
        raise ValueError("unsafe_path_spelling")
    if os.name == "nt" and (not drive or not re.fullmatch(r"[A-Za-z]:", drive)):
        raise ValueError("unsafe_path_spelling")


def _reject_reparse_chain(path: Path, *, include_leaf: bool) -> None:
    current = path if include_leaf else path.parent
    checked: set[str] = set()
    while True:
        key = os.path.normcase(str(current))
        if key in checked:
            raise ValueError("path_ancestor_cycle")
        checked.add(key)
        info = os.lstat(current)
        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(info.st_mode) or attributes & reparse_flag:
            raise ValueError("reparse_path_forbidden")
        if current.parent == current:
            break
        current = current.parent


def _strict_regular_file(path: Path) -> Path:
    if not path.is_absolute():
        path = Path(os.path.abspath(path))
    _reject_unsafe_windows_spelling(path)
    _reject_reparse_chain(path, include_leaf=True)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_nlink", 1) != 1:
        raise ValueError("regular_single_link_file_required")
    resolved = path.resolve(strict=True)
    if os.path.normcase(str(resolved)) != os.path.normcase(str(path)):
        raise ValueError("path_alias_forbidden")
    return resolved


def _snapshot_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _read_strict_regular_bytes(path: Path, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> tuple[Path, bytes]:
    resolved = _strict_regular_file(path)
    before = os.stat(resolved, follow_symlinks=False)
    with resolved.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if _snapshot_identity(before) != _snapshot_identity(opened):
            raise ValueError("file_identity_changed_before_read")
        data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("file_too_large")
        after_handle = os.fstat(handle.fileno())
        if _snapshot_identity(opened) != _snapshot_identity(after_handle):
            raise ValueError("file_identity_changed_during_read")
    after_path = os.stat(resolved, follow_symlinks=False)
    if _snapshot_identity(after_handle) != _snapshot_identity(after_path):
        raise ValueError("file_identity_changed_after_read")
    return resolved, data


def _strict_future_path(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("future_path_must_be_absolute")
    absolute = Path(os.path.abspath(path))
    _reject_unsafe_windows_spelling(absolute)
    if absolute.exists() or absolute.is_symlink():
        raise ValueError("future_path_not_fresh")
    _reject_reparse_chain(absolute, include_leaf=False)
    parent = absolute.parent.resolve(strict=True)
    canonical = parent / absolute.name
    if os.path.normcase(str(canonical)) != os.path.normcase(str(absolute)):
        raise ValueError("path_alias_forbidden")
    return canonical


def _provenance_identity(path: Path, role: str) -> dict[str, object]:
    resolved, data = _read_strict_regular_bytes(path)
    return {
        "role": role,
        "basename": resolved.name,
        "path_token": _path_token(resolved),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _canonical_json_bytes(value: object) -> bytes:
    _require_exact_json_value(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _load_exact_json_bytes(data: bytes) -> dict[str, object]:
    if data.startswith(b"\xef\xbb\xbf") or not data or data != data.strip():
        raise ReceiptValidationError("authority_not_canonical")
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=lambda pairs: _object_from_unique_pairs(pairs),
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError("float_forbidden")),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant_forbidden")),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ReceiptValidationError("authority_not_canonical") from exc
    if type(value) is not dict or _canonical_json_bytes(value) != data:
        raise ReceiptValidationError("authority_not_canonical")
    return value


def _object_from_unique_pairs(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("duplicate_or_non_string_key")
        result[key] = value
    return result


def _provenance_role_paths() -> list[tuple[str, Path]]:
    root = _repo_root()
    return [
        ("gate_entrypoint", Path(__file__)),
        ("receipt_schema_v2", _schema_path(SCHEMA_VERSION_V2)),
        ("focused_tests", root / "tools/detection_validation/tests/anti_cheat_windows_driver_observe_only_build_test.py"),
        ("python_executable", Path(sys.executable)),
    ]


def _provenance_inventory() -> list[dict[str, object]]:
    entries = [_provenance_identity(path, role) for role, path in _provenance_role_paths()]
    if tuple(entry["role"] for entry in entries) != PROVENANCE_ROLE_NAMES:
        raise ValueError("provenance_role_order_invalid")
    tokens = [str(entry["path_token"]) for entry in entries]
    if len(tokens) != len(set(tokens)):
        raise ValueError("provenance_role_alias")
    paths = [_strict_regular_file(path) for _role, path in _provenance_role_paths()]
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            if os.path.samefile(left, right):
                raise ValueError("provenance_role_alias")
    return entries


def _future_path_identity(path: Path) -> dict[str, str]:
    future = _strict_future_path(path)
    return {"basename": future.name, "path_token": _path_token(future), "parent_token": _path_token(future.parent)}


def _invocation_contract(args: argparse.Namespace, authority_path: Path) -> dict[str, object]:
    if args.configuration != "Release" or args.platform != "x64" or args.observe_only != "1":
        raise ValueError("authority_invocation_policy_invalid")
    if args.wdk != "10.0.26100.0" or not 1 <= args.timeout_seconds <= 3600:
        raise ValueError("authority_invocation_policy_invalid")
    project = _strict_regular_file(Path(args.project))
    msbuild = _strict_regular_file(Path(args.msbuild))
    if project != (_repo_root() / "apps/tamandua_driver/tamandua_driver.vcxproj").resolve(strict=True):
        raise ValueError("authority_project_substitution")
    output = _strict_future_path(Path(args.output))
    receipt = _strict_future_path(Path(args.receipt))
    authority = Path(os.path.abspath(authority_path))
    if len({_path_token(output), _path_token(receipt), _path_token(authority)}) != 3:
        raise ValueError("authority_path_collision")
    for candidate in (output, receipt, authority):
        try:
            candidate.relative_to(_repo_root())
        except ValueError:
            pass
        else:
            raise ValueError("authority_output_inside_source")
    try:
        receipt.relative_to(output)
    except ValueError:
        pass
    else:
        raise ValueError("authority_path_collision")
    symbolic_argv = [
        _path_token(_strict_regular_file(Path(sys.executable))),
        _path_token(_strict_regular_file(Path(__file__))),
        "--authority", _path_token(authority), "--project", _path_token(project),
        "--configuration", "Release", "--platform", "x64", "--observe-only", "1",
        "--msbuild", _path_token(msbuild), "--wdk", "10.0.26100.0",
        "--output", _path_token(output), "--receipt", _path_token(receipt),
        "--timeout-seconds", str(args.timeout_seconds),
    ]
    return {
        "authority_path_token": _path_token(authority), "configuration": "Release", "platform": "x64",
        "observe_only": "1", "wdk_version": "10.0.26100.0", "timeout_seconds": args.timeout_seconds,
        "project": _provenance_identity(project, "project"),
        "msbuild": _provenance_identity(msbuild, "msbuild"),
        "output": _future_path_identity(output), "receipt": _future_path_identity(receipt),
        "argv_contract_sha256": hashlib.sha256(_canonical_json_bytes(symbolic_argv)).hexdigest(),
    }


def _authority_document(args: argparse.Namespace, authority_path: Path) -> dict[str, object]:
    roles = _provenance_inventory()
    return {
        "schema_version": AUTHORITY_SCHEMA_VERSION, "created_at": _utc_now(),
        "evidence_class": "detached_canonical_freeze_authority",
        "roles": roles, "roles_sha256": _inventory_digest(roles),
        "python": {
            "implementation": python_platform.python_implementation(),
            "version": sys.version,
            "version_info": list(sys.version_info[:3]),
        },
        "invocation": _invocation_contract(args, authority_path),
        "claims": {**AUTHORITY_FALSE_CLAIMS, **RUNTIME_FALSE_CLAIMS},
    }


def _validate_authority_claims(authority: dict[str, object]) -> None:
    claims = authority.get("claims")
    expected_claim_keys = {*AUTHORITY_FALSE_CLAIMS, *RUNTIME_FALSE_CLAIMS}
    if type(claims) is not dict or set(claims) != expected_claim_keys or any(
        type(value) is not bool or value is not False for value in claims.values()
    ):
        raise ReceiptValidationError("authority_claims_invalid")


def _validate_authority_document(
    authority: dict[str, object], args: argparse.Namespace, authority_path: Path
) -> dict[str, object]:
    frozen = _freeze_receipt(authority)
    _schema_file, schema_bytes = _read_strict_regular_bytes(_schema_path(AUTHORITY_SCHEMA_VERSION))
    schema = json.loads(schema_bytes.decode("utf-8"))
    if list(Draft202012Validator(schema).iter_errors(frozen)):
        raise ReceiptValidationError("authority_schema_invalid")
    _validate_authority_claims(frozen)
    roles = _provenance_inventory()
    if frozen.get("roles") != roles or frozen.get("roles_sha256") != _inventory_digest(roles):
        raise ReceiptValidationError("authority_role_mismatch")
    expected_python = {
        "implementation": python_platform.python_implementation(), "version": sys.version,
        "version_info": list(sys.version_info[:3]),
    }
    if frozen.get("python") != expected_python:
        raise ReceiptValidationError("authority_python_mismatch")
    if frozen.get("invocation") != _invocation_contract(args, authority_path):
        raise ReceiptValidationError("authority_invocation_mismatch")
    return frozen


def _load_authority(path: Path, args: argparse.Namespace) -> tuple[dict[str, object], str]:
    authority_path, data = _read_strict_regular_bytes(path)
    authority = _load_exact_json_bytes(data)
    validated = _validate_authority_document(authority, args, authority_path)
    return validated, hashlib.sha256(data).hexdigest()


def _freeze_authority(args: argparse.Namespace, destination: Path) -> tuple[dict[str, object], str]:
    output = _strict_future_path(destination)
    document = _authority_document(args, output)
    _validate_authority_document(document, args, output)
    encoded = _canonical_json_bytes(document)
    with output.open("xb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    persisted = _strict_regular_file(output).read_bytes()
    if persisted != encoded:
        raise ReceiptValidationError("authority_persistence_mismatch")
    _load_authority(output, args)
    return document, hashlib.sha256(encoded).hexdigest()


def _canonical_source_inventory(project: Path) -> list[dict[str, object]]:
    project = _strict_regular_file(project)
    root = project.parent.resolve(strict=True)
    tree = ET.parse(project)
    paths = {project}
    for element in tree.getroot().iter():
        tag = element.tag.rsplit("}", 1)[-1]
        include = element.attrib.get("Include")
        if tag not in PROJECT_ITEM_TAGS or not include or "$" in include or "*" in include:
            continue
        candidate = _strict_regular_file(root / include.replace("\\", os.sep))
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"input_outside_project:{include}") from exc
        paths.add(candidate)
    entries: list[dict[str, object]] = []
    for path in sorted(paths, key=lambda item: item.as_posix().casefold()):
        entries.append(
            {
                "path": path.relative_to(root).as_posix() if path != project else project.name,
                "size": path.stat().st_size,
                "sha256": _sha256_file(path, max_bytes=MAX_ARTIFACT_BYTES),
            }
        )
    return entries


def _project_contract(project: Path) -> dict[str, object]:
    tree = ET.parse(project)
    root = tree.getroot()
    imports: list[str] = []
    user_imports: list[str] = []
    custom_builds: list[dict[str, str]] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "Import":
            value = element.attrib.get("Project", "")
            if "$(UserRootDir)" in value:
                user_imports.append(value)
            elif value not in ALLOWED_DIRECT_IMPORTS:
                raise ValueError(f"unapproved_direct_import:{value}")
            else:
                imports.append(value)
        if tag in {"CustomBuild", "MessageCompile", "MessageCompiler"}:
            command = next(
                (child.text or "" for child in element if child.tag.rsplit("}", 1)[-1] == "Command"), ""
            ).strip()
            custom_builds.append({"kind": tag, "include": element.attrib.get("Include", ""), "command": command})
    expected_command = 'mc.exe -U "%(FullPath)" -h "$(ProjectDir)src" -r "$(ProjectDir)src"'
    if custom_builds != [{"kind": "CustomBuild", "include": r"src\TamanduaEvents.mc", "command": expected_command}]:
        raise ValueError("unapproved_custom_build_contract")
    if tuple(imports) != (
        r"$(VCTargetsPath)\Microsoft.Cpp.Default.props",
        r"$(VCTargetsPath)\Microsoft.Cpp.props",
        r"$(VCTargetsPath)\Microsoft.Cpp.targets",
    ):
        raise ValueError("direct_import_order_mismatch")
    if user_imports != [r"$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props"]:
        raise ValueError("unexpected_user_import_contract")
    return {"imports": imports, "disabled_user_imports": user_imports, "custom_builds": custom_builds}


def _stage_project(project: Path, stage: Path) -> Path:
    inventory = _canonical_source_inventory(project)
    root = project.parent.resolve(strict=True)
    for entry in inventory:
        relative = Path(str(entry["path"]))
        source = root / relative
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target, follow_symlinks=False)
    staged_project = stage / project.name
    staged_text = staged_project.read_text(encoding="utf-8")
    user_import = (
        '    <Import Project="$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props"\n'
        '            Condition="exists(\'$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\')"\n'
        '            Label="LocalAppDataPlatform" />\n'
    )
    if staged_text.count(user_import) != 1:
        raise ValueError("user_import_stage_rewrite_mismatch")
    staged_project.write_text(staged_text.replace(user_import, ""), encoding="utf-8")
    return staged_project


def _redact_text(value: str, paths: Sequence[Path]) -> str:
    result = value
    for path in sorted((str(item) for item in paths), key=len, reverse=True):
        result = re.sub(re.escape(path), "<isolated>", result, flags=re.IGNORECASE)
        result = re.sub(re.escape(path.replace("\\", "/")), "<isolated>", result, flags=re.IGNORECASE)
    system_roots = (
        (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft Visual Studio", "<vs-root>"),
        (Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits", "<wdk-root>"),
        (Path(os.environ.get("SystemRoot", r"C:\Windows")), "<windows-root>"),
    )
    for root, token in system_roots:
        result = re.sub(re.escape(str(root)), token, result, flags=re.IGNORECASE)
        result = re.sub(re.escape(str(root).replace("\\", "/")), token, result, flags=re.IGNORECASE)
    result = re.sub(r"(?i)[A-Z]:[\\/]+Users[\\/]+[^\\/\s\r\n]+", "<user-home>", result)
    result = re.sub(
        r"(?i)\b((?:Authorization|Proxy-Authorization)\s*:\s*(?:Basic|Bearer)\s+|(?:X-Api-Key|X-Auth-Token|Cookie|Set-Cookie)\s*:\s*)[^\s,;]+",
        r"\1<redacted>", result,
    )
    result = re.sub(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{6,}", r"\1<redacted>", result)
    result = re.sub(
        r"(?i)\b(token|password|passwd|secret|api[_-]?key|x[_-]?api[_-]?key|aws_(?:access_key_id|secret_access_key|session_token))\s*[:=]\s*[^\s,;]+",
        r"\1=<redacted>", result,
    )
    assignment = re.compile(
        r"(?i)(^|[\s;,\{\[])([\"']?)([a-z][a-z0-9_.-]{1,95})([\"']?)(\s*[:=]\s*)([^\s,;\}\]]+)"
    )

    def redact_named_secret(match: re.Match[str]) -> str:
        if not _secret_name(match.group(3)):
            return match.group(0)
        retained_value = match.group(6)
        quote = retained_value[0] if retained_value[:1] in ("\"", "'") else ""
        replacement = f"{quote}<redacted>{quote}"
        return "".join(match.group(index) for index in range(1, 6)) + replacement

    result = assignment.sub(redact_named_secret, result)
    return result


def _canonical_fresh_locations(project: Path, output_value: str, receipt_value: str) -> tuple[Path, Path]:
    project_root = project.parent.resolve(strict=True)
    requested: list[tuple[str, Path]] = [("output", Path(output_value)), ("receipt", Path(receipt_value))]
    resolved: dict[str, Path] = {}
    for label, raw in requested:
        if not raw.is_absolute():
            raise ValueError("unsafe_output_topology")
        if not raw.parent.is_dir():
            raise ValueError("unsafe_output_topology")
        absolute = Path(os.path.abspath(raw))
        canonical = raw.resolve(strict=False)
        if os.path.normcase(str(absolute)) != os.path.normcase(str(canonical)):
            raise ValueError("unsafe_output_topology")
        ancestor = raw.parent
        while True:
            if ancestor.exists() and ancestor.is_symlink():
                raise ValueError("unsafe_output_topology")
            if ancestor.parent == ancestor:
                break
            ancestor = ancestor.parent
        if raw.exists() or raw.is_symlink():
            raise ValueError("unsafe_output_topology")
        try:
            canonical.relative_to(project_root)
        except ValueError:
            pass
        else:
            raise ValueError("unsafe_output_topology")
        resolved[label] = canonical
    output = resolved["output"]
    receipt = resolved["receipt"]
    try:
        receipt.relative_to(output)
    except ValueError:
        pass
    else:
        raise ValueError("unsafe_output_topology")
    if receipt.parent == output or output == receipt:
        raise ValueError("unsafe_output_topology")
    return output, receipt


def _path_identity(path: Path, role: str) -> dict[str, object]:
    resolved, data = _read_strict_regular_bytes(path)
    return {
        "role": role,
        "basename": resolved.name,
        "path_token": hashlib.sha256(str(resolved).casefold().encode()).hexdigest(),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _toolchain_inventory(msbuild: Path, wdk: str) -> tuple[list[dict[str, object]], list[Path]]:
    vs_root = msbuild.parents[3]
    msvc_roots = sorted((vs_root / "VC/Tools/MSVC").glob("*"), reverse=True)
    if not msvc_roots:
        raise ValueError("msvc_tools_unavailable")
    vc_bin = msvc_roots[0] / "bin/Hostx64/x64"
    kits = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits/10"
    kit_bin = kits / "bin" / wdk / "x64"
    kit_x86_bin = kits / "bin" / wdk / "x86"
    candidates = [
        (msbuild, "msbuild"), (vc_bin / "cl.exe", "compiler"), (vc_bin / "link.exe", "linker"),
        (kit_bin / "mc.exe", "message_compiler"), (kit_bin / "rc.exe", "resource_compiler"),
        (kit_bin / "stampinf.exe", "stampinf"), (kit_x86_bin / "Inf2Cat.exe", "inf2cat"),
    ]
    missing = [role for path, role in candidates if not path.is_file()]
    if missing:
        raise ValueError("toolchain_binary_unavailable:" + ",".join(missing))
    return [_path_identity(path, role) for path, role in candidates], [vc_bin, kit_bin, msbuild.parent]


def _stage_inventory(stage: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(stage.rglob("*"), key=lambda item: item.as_posix().casefold()):
        info = os.lstat(path)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & reparse_flag:
            raise ValueError("stage_contains_symlink")
        if path.is_file():
            regular = _strict_regular_file(path)
            entries.append({
                "path": path.relative_to(stage).as_posix(), "size": regular.stat().st_size,
                "sha256": _sha256_file(regular, max_bytes=MAX_ARTIFACT_BYTES),
            })
    return entries


def _authoritative_stage_inventory(
    stage: Path, expected: Sequence[dict[str, object]]
) -> list[dict[str, object]]:
    """Re-open exactly the captured staged inputs; generated outputs are excluded."""
    root = stage.resolve(strict=True)
    expected_paths = [str(entry["path"]) for entry in expected]
    if len(expected_paths) != len(set(expected_paths)):
        raise ValueError("stage_authority_duplicate_path")
    observed: list[dict[str, object]] = []
    for relative_text in expected_paths:
        relative = Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("stage_authority_invalid_path")
        candidate = root / relative
        try:
            resolved = _strict_regular_file(candidate)
        except (OSError, ValueError) as exc:
            raise ValueError("stage_authority_missing_or_non_regular") from exc
        if root not in resolved.parents:
            raise ValueError("stage_authority_outside_root")
        observed.append({
            "path": relative.as_posix(),
            "size": resolved.stat().st_size,
            "sha256": _sha256_file(resolved, max_bytes=MAX_ARTIFACT_BYTES),
        })
    return observed


def _assert_authoritative_stage_unchanged(
    stage: Path, expected: Sequence[dict[str, object]]
) -> list[dict[str, object]]:
    observed = _authoritative_stage_inventory(stage, expected)
    if list(expected) != observed:
        raise ValueError("stage_authoritative_input_drift")
    return observed


def _inventory_digest(entries: Sequence[dict[str, object]]) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _process_document(evidence: "ProcessEvidence", redaction_paths: Sequence[Path]) -> dict[str, object]:
    retained = _redact_text(evidence.retained_output, redaction_paths)
    raw_digest = hashlib.sha256(evidence.retained_raw).hexdigest()
    return {
        "exit_code": evidence.exit_code,
        "timed_out": evidence.timed_out,
        "duration_ms": evidence.duration_ms,
        "output_sha256": evidence.output_sha256,
        "output_bytes": evidence.output_bytes,
        "retained_output": retained,
        "retained_output_sha256": hashlib.sha256(retained.encode("utf-8")).hexdigest(),
        "retained_raw_sha256": raw_digest,
        "retained_raw_bytes": len(evidence.retained_raw),
        "redaction_applied": retained != evidence.retained_output,
        "retained_truncated": evidence.retained_truncated,
        "job_containment": evidence.job_containment,
    }


@dataclass(frozen=True)
class ProcessEvidence:
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    output_sha256: str
    output_bytes: int
    retained_output: str
    retained_raw: bytes
    retained_truncated: bool
    job_containment: str


class _BoundedCapture:
    def __init__(self, limit: int = MAX_LOG_BYTES) -> None:
        self.limit = limit
        self.digest = hashlib.sha256()
        self.total = 0
        self.retained = bytearray()

    def consume(self, stream: BinaryIO) -> None:
        while chunk := stream.read(64 * 1024):
            self.digest.update(chunk)
            self.total += len(chunk)
            remaining = self.limit - len(self.retained)
            if remaining > 0:
                self.retained.extend(chunk[:remaining])


if os.name == "nt":
    import _winapi
    import ctypes
    import msvcrt
    from ctypes import wintypes

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class _BASIC_LIMIT(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _EXTENDED_LIMIT(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BASIC_LIMIT),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    def _create_kill_job(process_handle: int) -> int:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW")
        info = _EXTENDED_LIMIT()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
        ):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(job)
            raise OSError(error, "SetInformationJobObject")
        if not kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(process_handle)):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(job)
            raise OSError(error, "AssignProcessToJobObject")
        return int(job)

    def _terminate_job(job: int) -> None:
        ctypes.WinDLL("kernel32", use_last_error=True).TerminateJobObject(wintypes.HANDLE(job), 124)

    def _close_job(job: int) -> None:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(wintypes.HANDLE(job))


def _run_bounded_windows(
    argv: Sequence[str], cwd: Path, env: dict[str, str], timeout_seconds: int
) -> ProcessEvidence:
    start = time.monotonic()
    absolute_deadline = start + timeout_seconds
    execution_deadline = absolute_deadline - min(5.0, timeout_seconds / 4)
    read_handle, write_handle = _winapi.CreatePipe(None, 0)  # type: ignore[name-defined]
    os.set_handle_inheritable(int(read_handle), False)
    os.set_handle_inheritable(int(write_handle), True)
    null_fd = os.open(os.devnull, os.O_RDONLY)
    null_handle = msvcrt.get_osfhandle(null_fd)  # type: ignore[name-defined]
    os.set_handle_inheritable(null_handle, True)
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESTDHANDLES
    startup.hStdInput = null_handle
    startup.hStdOutput = write_handle
    startup.hStdError = write_handle
    process_handle = thread_handle = None
    job: int | None = None
    capture = _BoundedCapture()
    reader: threading.Thread | None = None
    stream = None
    timed_out = False
    exit_code: int | None = None
    try:
        process_handle, thread_handle, _pid, _tid = _winapi.CreateProcess(  # type: ignore[name-defined]
            str(argv[0]), subprocess.list2cmdline(list(argv)), None, None, True,
            CREATE_SUSPENDED | subprocess.CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            env, str(cwd), startup,
        )
        _winapi.CloseHandle(write_handle)  # type: ignore[name-defined]
        write_handle = None
        job = _create_kill_job(int(process_handle))
        resumed = ctypes.WinDLL("kernel32", use_last_error=True).ResumeThread(  # type: ignore[name-defined]
            wintypes.HANDLE(int(thread_handle))  # type: ignore[name-defined]
        )
        if resumed == 0xFFFFFFFF:
            raise OSError(ctypes.get_last_error(), "ResumeThread")  # type: ignore[name-defined]
        _winapi.CloseHandle(thread_handle)  # type: ignore[name-defined]
        thread_handle = None
        fd = msvcrt.open_osfhandle(int(read_handle), os.O_RDONLY)  # type: ignore[name-defined]
        read_handle = None
        stream = os.fdopen(fd, "rb", closefd=True)
        reader = threading.Thread(target=capture.consume, args=(stream,), daemon=True)
        reader.start()
        wait_ms = max(1, int((execution_deadline - time.monotonic()) * 1000))
        result = _winapi.WaitForSingleObject(process_handle, wait_ms)  # type: ignore[name-defined]
        if result == _winapi.WAIT_TIMEOUT:  # type: ignore[name-defined]
            timed_out = True
            _terminate_job(job)
            remaining_ms = max(1, int((absolute_deadline - time.monotonic()) * 1000))
            _winapi.WaitForSingleObject(process_handle, remaining_ms)  # type: ignore[name-defined]
        exit_code = _winapi.GetExitCodeProcess(process_handle)  # type: ignore[name-defined]
    except Exception:
        if job is not None:
            _terminate_job(job)
        elif process_handle is not None:
            _winapi.TerminateProcess(process_handle, 125)  # type: ignore[name-defined]
        raise
    finally:
        if write_handle is not None:
            _winapi.CloseHandle(write_handle)  # type: ignore[name-defined]
        if thread_handle is not None:
            _winapi.CloseHandle(thread_handle)  # type: ignore[name-defined]
        if reader is not None:
            reader.join(timeout=max(0.001, absolute_deadline - time.monotonic()))
            if reader.is_alive():
                if job is not None:
                    _terminate_job(job)
                raise RuntimeError("output_reader_did_not_finish")
        if stream is not None:
            stream.close()
        elif read_handle is not None:
            _winapi.CloseHandle(read_handle)  # type: ignore[name-defined]
        if job is not None:
            _close_job(job)
        if process_handle is not None:
            _winapi.CloseHandle(process_handle)  # type: ignore[name-defined]
        os.close(null_fd)
    return ProcessEvidence(
        exit_code=exit_code, timed_out=timed_out,
        duration_ms=max(0, round((time.monotonic() - start) * 1000)),
        output_sha256=capture.digest.hexdigest(), output_bytes=capture.total,
        retained_output=bytes(capture.retained).decode("utf-8", errors="replace"),
        retained_raw=bytes(capture.retained),
        retained_truncated=capture.total > len(capture.retained),
        job_containment="windows_job_kill_on_close",
    )


def _run_bounded(argv: Sequence[str], cwd: Path, env: dict[str, str], timeout_seconds: int) -> ProcessEvidence:
    if not argv or timeout_seconds < 1:
        raise ValueError("invalid_process_contract")
    if os.name == "nt":
        return _run_bounded_windows(argv, cwd, env, timeout_seconds)
    start = time.monotonic()
    absolute_deadline = start + timeout_seconds
    cleanup_reserve = min(5.0, timeout_seconds / 4)
    execution_deadline = absolute_deadline - cleanup_reserve
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        list(argv), cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False,
        creationflags=creationflags,
    )
    job: int | None = None
    containment = "process_only"
    assert process.stdout is not None
    capture = _BoundedCapture()
    reader = threading.Thread(target=capture.consume, args=(process.stdout,), daemon=True)
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=max(0.001, execution_deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        if job is not None:
            _terminate_job(job)
        else:
            process.kill()
        process.wait(timeout=max(0.001, absolute_deadline - time.monotonic()))
    finally:
        reader.join(timeout=max(0.001, absolute_deadline - time.monotonic()))
        if reader.is_alive():
            raise RuntimeError("output_reader_did_not_finish")
        if job is not None:
            _close_job(job)
    duration_ms = max(0, round((time.monotonic() - start) * 1000))
    return ProcessEvidence(
        exit_code=process.returncode,
        timed_out=timed_out,
        duration_ms=duration_ms,
        output_sha256=capture.digest.hexdigest(),
        output_bytes=capture.total,
        retained_output=bytes(capture.retained).decode("utf-8", errors="replace"),
        retained_raw=bytes(capture.retained),
        retained_truncated=capture.total > len(capture.retained),
        job_containment=containment,
    )


def _rva_to_offset(data: bytes, rva: int, section_offset: int, section_count: int) -> int:
    for index in range(section_count):
        offset = section_offset + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            result = raw_offset + (rva - virtual_address)
            if result >= len(data):
                break
            return result
    raise ValueError("pe_rva_out_of_bounds")


def _parse_pe(path: Path) -> dict[str, object]:
    path, data = _read_strict_regular_bytes(path)
    if len(data) < 0x100 or len(data) > MAX_ARTIFACT_BYTES or data[:2] != b"MZ":
        raise ValueError("invalid_dos_header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid_pe_signature")
    machine, section_count, _timestamp, _symbols, _symbol_count, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    optional_offset = pe_offset + 24
    if machine != 0x8664:
        raise ValueError(f"unexpected_machine:{machine:#x}")
    if optional_size < 128 or optional_offset + optional_size > len(data):
        raise ValueError("invalid_optional_header")
    if struct.unpack_from("<H", data, optional_offset)[0] != 0x20B:
        raise ValueError("not_pe32_plus")
    directories = optional_offset + 112
    import_rva, import_size = struct.unpack_from("<II", data, directories + 8)
    certificate_offset, certificate_size = struct.unpack_from("<II", data, directories + 32)
    section_offset = optional_offset + optional_size
    if section_offset + section_count * 40 > len(data):
        raise ValueError("invalid_sections")
    imports: list[str] = []
    if import_rva and import_size:
        descriptor = _rva_to_offset(data, import_rva, section_offset, section_count)
        for _ in range(256):
            if descriptor + 20 > len(data):
                raise ValueError("invalid_import_descriptor")
            values = struct.unpack_from("<IIIII", data, descriptor)
            if values == (0, 0, 0, 0, 0):
                break
            name_offset = _rva_to_offset(data, values[3], section_offset, section_count)
            end = data.find(b"\0", name_offset, min(len(data), name_offset + 260))
            if end < 0:
                raise ValueError("invalid_import_name")
            imports.append(data[name_offset:end].decode("ascii").lower())
            descriptor += 20
        else:
            raise ValueError("too_many_import_descriptors")
    if certificate_size and certificate_offset + certificate_size > len(data):
        raise ValueError("invalid_certificate_table")
    return {
        "path": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": "amd64",
        "characteristics": characteristics,
        "imports": sorted(set(imports)),
        "certificate_table_present": certificate_size > 0,
    }


def _build_argv(args: argparse.Namespace, project: Path, output: Path) -> list[str]:
    out_dir = str((output / "bin").resolve()) + os.sep
    int_dir = str((output / "obj").resolve()) + os.sep
    return [
        str(Path(args.msbuild).resolve()), str(project), "/nologo", "/m:1", "/nr:false",
        "/t:Rebuild", f"/p:Configuration={args.configuration}", f"/p:Platform={args.platform}",
        "/p:TamanduaDriverObserveOnly=1", f"/p:WindowsTargetPlatformVersion={args.wdk}",
        f"/p:OutDir={out_dir}", f"/p:IntDir={int_dir}", "/p:DriverSign=Off",
        "/p:SignMode=Off", "/p:EnableInf2cat=false", "/p:SupportsPackaging=false",
        "/p:PostBuildEventUseInBuild=false", "/p:VCLibPackagePath=", "/p:VcpkgEnabled=false",
        "/verbosity:minimal",
    ]


def _minimal_child_env(tool_dirs: Sequence[Path], temporary: Path) -> dict[str, str]:
    required = ("SystemRoot", "WINDIR", "ComSpec", "SystemDrive", "PROCESSOR_ARCHITECTURE")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise ValueError("required_child_environment_missing:" + ",".join(missing))
    env = {name: os.environ[name] for name in required}
    env.update({
        "PATH": os.pathsep.join(str(path) for path in (*tool_dirs, Path(env["SystemRoot"]) / "System32")),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD", "TMP": str(temporary), "TEMP": str(temporary),
        "MSBUILDDISABLENODEREUSE": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "NUGET_XMLDOC_MODE": "skip", "VSCMD_SKIP_SENDTELEMETRY": "1",
    })
    return env


def _preprocess_argv(build_argv: Sequence[str], destination: Path) -> list[str]:
    ignored = {"/t:rebuild", "/verbosity:minimal"}
    result = [item for item in build_argv if item.casefold() not in ignored]
    result.extend([f"/pp:{destination}", "/verbosity:quiet"])
    return result


def _property_argv(build_argv: Sequence[str], name: str) -> list[str]:
    ignored_prefixes = ("/t:", "/verbosity:")
    result = [item for item in build_argv if not item.casefold().startswith(ignored_prefixes)]
    result.extend([f"/getProperty:{name}", "/verbosity:quiet"])
    return result


def _capture_effective_properties(
    build_argv: Sequence[str], cwd: Path, env: dict[str, str], deadline_seconds: int,
    checkpoint: Callable[[], None] | None = None,
) -> dict[str, str]:
    expected = {
        "TamanduaDriverObserveOnly": "1", "DriverSign": "Off", "SignMode": "Off",
        "EnableInf2cat": "false", "SupportsPackaging": "false", "PostBuildEventUseInBuild": "false",
        "VcpkgEnabled": "false",
    }
    observed: dict[str, str] = {}
    for name, wanted in expected.items():
        if checkpoint is not None:
            checkpoint()
        result = _run_bounded(_property_argv(build_argv, name), cwd, env, deadline_seconds)
        if result.timed_out or result.exit_code != 0:
            raise ValueError(f"effective_property_query_failed:{name}")
        lines = [line.strip() for line in result.retained_output.splitlines() if line.strip()]
        if not lines:
            raise ValueError(f"effective_property_empty:{name}")
        value = lines[-1]
        if value.casefold() != wanted.casefold():
            raise ValueError(f"effective_property_mismatch:{name}")
        observed[name] = value
    return observed


def _identities_unchanged(before: Sequence[dict[str, object]], after: Sequence[dict[str, object]]) -> bool:
    return list(before) == list(after)


def _import_inventory(preprocessed: Path, allowed_roots: Sequence[Path]) -> list[dict[str, object]]:
    text = preprocessed.read_text(encoding="utf-8-sig", errors="strict")
    matches = set(re.findall(r"(?im)^\s*([A-Z]:\\[^\r\n<>]+\.(?:props|targets))\s*$", text))
    entries: list[dict[str, object]] = []
    roots = [root.resolve(strict=True) for root in allowed_roots]
    for raw in sorted(matches, key=str.casefold):
        if re.match(r"(?i)^[A-Z]:\\Users\\", raw):
            raise ValueError("user_local_import_observed")
        path = Path(raw).resolve(strict=True)
        if not any(path == root or root in path.parents for root in roots):
            raise ValueError("import_outside_allowed_closure:" + path.name)
        entries.append(_path_identity(path, "imported_project"))
    if not entries:
        raise ValueError("preprocessed_import_closure_empty")
    return entries


def _rehash_import_inventory(
    before: Sequence[dict[str, object]], preprocessed: Path, allowed_roots: Sequence[Path]
) -> tuple[list[dict[str, object]], bool]:
    after = _import_inventory(preprocessed, allowed_roots)
    return after, _identities_unchanged(before, after)


def _classify_build_failure(output: str) -> str:
    normalized = output.casefold()
    if "msb8040" in normalized and "spectre" in normalized:
        return "spectre_mitigated_libraries_unavailable"
    if "msb8020" in normalized or "windowskernelmodedriver" in normalized and "cannot be found" in normalized:
        return "wdk_platform_toolset_unavailable"
    if "msb8036" in normalized and "sdk version" in normalized:
        return "requested_wdk_version_unavailable"
    return "msbuild_nonzero_exit"


def _derive_status_and_blockers(receipt: dict[str, object]) -> tuple[str, list[str]]:
    source = receipt.get("source")
    toolchain = receipt.get("toolchain")
    execution = receipt.get("execution")
    process = receipt.get("process")
    artifact = receipt.get("artifact")
    artifact_check = receipt.get("artifact_check")
    if not isinstance(source, dict) or not isinstance(toolchain, dict) or not isinstance(execution, dict):
        raise ReceiptValidationError("receipt_evidence_incomplete")
    if source.get("original_unchanged") is not True:
        return "input_drift", ["source_or_toolchain_changed_during_build"]
    if not toolchain.get("files"):
        return "toolchain_unavailable", ["msbuild_not_found"]
    preprocess = execution.get("preprocess")
    if isinstance(preprocess, dict) and (
        preprocess.get("timed_out") is True or preprocess.get("exit_code") != 0
    ):
        return "project_preflight_failed", ["msbuild_preprocess_failed"]
    if not isinstance(process, dict):
        raise ReceiptValidationError("receipt_process_evidence_incomplete")
    if toolchain.get("unchanged") is not True:
        return "input_drift", ["source_or_toolchain_changed_during_build"]
    if process.get("timed_out") is True:
        return "timed_out", ["msbuild_deadline_exceeded"]
    exit_code = process.get("exit_code")
    if type(exit_code) is not int:
        raise ReceiptValidationError("receipt_process_exit_invalid")
    if exit_code != 0:
        return "build_failed", [_classify_build_failure(str(process.get("retained_output", "")))]
    if not isinstance(artifact_check, dict):
        raise ReceiptValidationError("receipt_artifact_evidence_incomplete")
    artifact_state = artifact_check.get("state")
    if artifact_state == "missing_or_ambiguous":
        return "artifact_missing", ["expected_exactly_one_sys_artifact"]
    if artifact_state == "invalid":
        return "artifact_invalid", ["invalid_pe_artifact"]
    if artifact_state != "valid" or not isinstance(artifact, dict):
        raise ReceiptValidationError("receipt_artifact_evidence_incoherent")
    if artifact.get("certificate_table_present") is not False:
        return "artifact_invalid", ["unexpected_signed_artifact"]
    return "artifact_observed_unbound", list(ARTIFACT_OBSERVED_BLOCKERS)


def _evidence_binding(receipt: dict[str, object]) -> str:
    payload = {key: receipt.get(key) for key in (
        "source", "toolchain", "policy", "execution", "process", "artifact", "artifact_check",
    )}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _provenance_document(
    authority: dict[str, object], authority_sha256: str,
    before: Sequence[dict[str, object]], after: Sequence[dict[str, object]],
) -> dict[str, object]:
    return {
        "authority_snapshot": _freeze_receipt(authority), "authority_sha256": authority_sha256,
        "authority_post_sha256": authority_sha256,
        "role_inventory_pre": list(before), "role_inventory_pre_sha256": _inventory_digest(before),
        "role_inventory_post": list(after), "role_inventory_post_sha256": _inventory_digest(after),
        "unchanged": list(before) == list(after) == authority.get("roles"),
    }


def _convert_to_v2(
    receipt: dict[str, object], authority: dict[str, object], authority_sha256: str,
    before: Sequence[dict[str, object]], after: Sequence[dict[str, object]],
) -> dict[str, object]:
    value = _freeze_receipt(receipt)
    value["schema_version"] = SCHEMA_VERSION_V2
    value["evidence_class"] = "local_unsigned_build_provenance_bound"
    value["provenance"] = _provenance_document(authority, authority_sha256, before, after)
    if value.get("status") == "artifact_observed_unbound":
        value["status"] = "artifact_observed_provenance_bound"
    if value["provenance"]["unchanged"] is not True:  # type: ignore[index]
        value["status"] = "provenance_drift"
        value["blockers"] = ["authority_or_provenance_changed"]
        value["claims"] = {"build_validated": False, "link_validated": False, **RUNTIME_FALSE_CLAIMS}
    return value


def _validate_inventory_binding(entries: object, digest: object, label: str) -> None:
    if not isinstance(entries, list) or not isinstance(digest, str) or _inventory_digest(entries) != digest:
        raise ReceiptValidationError(f"receipt_{label}_digest_invalid")


def _validate_process_binding(process: object) -> None:
    if process is None:
        return
    if not isinstance(process, dict):
        raise ReceiptValidationError("receipt_process_evidence_incomplete")
    retained = process.get("retained_output")
    retained_digest = process.get("retained_output_sha256")
    if not isinstance(retained, str) or retained_digest != hashlib.sha256(retained.encode("utf-8")).hexdigest():
        raise ReceiptValidationError("receipt_retained_output_digest_invalid")
    output_bytes = process.get("output_bytes")
    if type(output_bytes) is not int or output_bytes < 0:
        raise ReceiptValidationError("receipt_output_size_invalid")
    if process.get("retained_truncated") is True and output_bytes <= len(retained.encode("utf-8")):
        raise ReceiptValidationError("receipt_output_truncation_invalid")
    raw_bytes = process.get("retained_raw_bytes")
    raw_digest = process.get("retained_raw_sha256")
    if type(raw_bytes) is not int or raw_bytes < 0 or not isinstance(raw_digest, str):
        raise ReceiptValidationError("receipt_raw_capture_invalid")
    if raw_bytes > output_bytes:
        raise ReceiptValidationError("receipt_raw_capture_size_invalid")
    if process.get("retained_truncated") is False:
        if raw_bytes != output_bytes or raw_digest != process.get("output_sha256"):
            raise ReceiptValidationError("receipt_full_output_binding_invalid")
    if process.get("redaction_applied") is False:
        encoded = retained.encode("utf-8")
        if raw_bytes != len(encoded) or raw_digest != hashlib.sha256(encoded).hexdigest():
            raise ReceiptValidationError("receipt_unredacted_output_binding_invalid")


def _validate_evidence_relations(receipt: dict[str, object]) -> None:
    source = receipt.get("source")
    if isinstance(source, dict):
        _validate_inventory_binding(source.get("inventory"), source.get("inventory_sha256"), "source")
        _validate_inventory_binding(source.get("stage_input_inventory"), source.get("stage_input_sha256"), "stage_input")
        for entries_key, digest_key, label in (
            ("post_inventory", "post_inventory_sha256", "source_post"),
            ("stage_post_inventory", "stage_post_sha256", "stage_post"),
            ("isolated_post_inventory", "isolated_post_sha256", "isolated_post"),
        ):
            entries, digest = source.get(entries_key), source.get(digest_key)
            if digest is not None:
                _validate_inventory_binding(entries, digest, label)
        if source.get("original_unchanged") is True and source.get("post_inventory") != source.get("inventory"):
            raise ReceiptValidationError("receipt_source_identity_invalid")
        stage_input = source.get("stage_input_inventory")
        stage_post = source.get("stage_post_inventory")
        if isinstance(stage_input, list) and isinstance(stage_post, list):
            post_by_path = {entry.get("path"): entry for entry in stage_post if isinstance(entry, dict)}
            if len(post_by_path) != len(stage_post) or any(
                post_by_path.get(entry.get("path")) != entry
                for entry in stage_input
                if isinstance(entry, dict)
            ):
                raise ReceiptValidationError("receipt_stage_authority_invalid")
    toolchain = receipt.get("toolchain")
    if isinstance(toolchain, dict):
        post_files, post_sha = toolchain.get("post_files"), toolchain.get("post_sha256")
        post_imports, imports_sha = toolchain.get("post_imports"), toolchain.get("imports_post_sha256")
        if post_sha is not None:
            _validate_inventory_binding(post_files, post_sha, "toolchain_post")
        if imports_sha is not None:
            _validate_inventory_binding(post_imports, imports_sha, "imports_post")
        if toolchain.get("unchanged") is True and toolchain.get("files") != post_files:
            raise ReceiptValidationError("receipt_toolchain_identity_invalid")
        if toolchain.get("imports_unchanged") is True and toolchain.get("imports") != post_imports:
            raise ReceiptValidationError("receipt_import_identity_invalid")
    execution = receipt.get("execution")
    if isinstance(execution, dict):
        _validate_process_binding(execution.get("preprocess"))
    _validate_process_binding(receipt.get("process"))


def _finalize_receipt_integrity(
    receipt: dict[str, object], proof: _LocalConsistencyContext
) -> dict[str, object]:
    receipt = _reject_local_promotion(receipt)
    source = receipt.get("source")
    toolchain = receipt.get("toolchain")
    if not isinstance(source, dict) or not isinstance(toolchain, dict):
        proof.binding_sha256 = _evidence_binding(receipt)
        return _validate_receipt_document(receipt)
    source_after = _canonical_source_inventory(proof.project)
    source["post_inventory"] = source_after
    source["post_inventory_sha256"] = _inventory_digest(source_after)
    source["original_unchanged"] = _identities_unchanged(proof.source_before, source_after)
    stage_input = source.get("stage_input_inventory")
    if not isinstance(stage_input, list):
        raise ReceiptValidationError("receipt_stage_authority_missing")
    _assert_authoritative_stage_unchanged(proof.stage, stage_input)
    stage_after = _stage_inventory(proof.stage)
    source["stage_post_inventory"] = stage_after
    source["stage_post_sha256"] = _inventory_digest(stage_after)
    isolated_after = _stage_inventory(proof.stage.parent)
    source["isolated_post_inventory"] = isolated_after
    source["isolated_post_sha256"] = _inventory_digest(isolated_after)
    toolchain_unchanged = True
    if proof.toolchain_before is not None:
        post_files, _ = _toolchain_inventory(proof.msbuild, proof.wdk)
        toolchain["post_files"] = post_files
        toolchain["post_sha256"] = _inventory_digest(post_files)
        toolchain_unchanged = _identities_unchanged(proof.toolchain_before, post_files)
    if proof.imports_before is not None and proof.preprocess_path is not None:
        post_imports, imports_unchanged = _rehash_import_inventory(
            proof.imports_before, proof.preprocess_path, proof.allowed_import_roots
        )
        toolchain["post_imports"] = post_imports
        toolchain["imports_post_sha256"] = _inventory_digest(post_imports)
        toolchain["imports_unchanged"] = imports_unchanged
        toolchain_unchanged = toolchain_unchanged and imports_unchanged
    toolchain["unchanged"] = toolchain_unchanged if proof.toolchain_before is not None else False
    redaction_paths = (proof.stage.parent, proof.stage, proof.project.parent, Path.home())
    if proof.preprocess_evidence is not None:
        execution = receipt.get("execution")
        if isinstance(execution, dict):
            execution["preprocess"] = _process_document(proof.preprocess_evidence, redaction_paths)
    if proof.process_evidence is not None:
        receipt["process"] = _process_document(proof.process_evidence, redaction_paths)
    if receipt.get("status") == "artifact_observed_unbound":
        artifact = receipt.get("artifact")
        if proof.artifact_path is None or not isinstance(artifact, dict):
            raise ReceiptValidationError("receipt_artifact_execution_evidence_missing")
        actual = _parse_pe(proof.artifact_path)
        if actual != artifact:
            raise ReceiptValidationError("receipt_artifact_execution_evidence_invalid")
    if receipt.get("status") != "provenance_drift" and (source.get("original_unchanged") is not True or (
        proof.toolchain_before is not None and toolchain.get("unchanged") is not True
    )):
        receipt["status"] = "input_drift"
        receipt["claims"] = {"build_validated": False, "link_validated": False, **RUNTIME_FALSE_CLAIMS}
        receipt["blockers"] = ["source_or_toolchain_changed_during_build"]
    proof.binding_sha256 = _evidence_binding(receipt)
    return _validate_receipt_document(receipt)


def _require_exact_json_value(value: object) -> None:
    value_type = type(value)
    if value is None or value_type in (str, int, float, bool):
        return
    if value_type is list:
        for member in value:
            _require_exact_json_value(member)
        return
    if value_type is dict:
        for key, member in value.items():
            if type(key) is not str:
                raise ReceiptValidationError("receipt_not_canonical_json")
            _require_exact_json_value(member)
        return
    raise ReceiptValidationError("receipt_not_canonical_json")


def _freeze_receipt(receipt: object) -> dict[str, object]:
    _require_exact_json_value(receipt)
    try:
        encoded = json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        frozen = json.loads(encoded)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ReceiptValidationError("receipt_not_canonical_json") from exc
    if type(frozen) is not dict:
        raise ReceiptValidationError("receipt_not_canonical_json")
    return frozen


def _reject_local_promotion(receipt: dict[str, object]) -> dict[str, object]:
    frozen = _freeze_receipt(receipt)
    status = frozen.get("status")
    claims = frozen.get("claims")
    if type(status) is not str or status == "success":
        raise ReceiptValidationError("receipt_local_promotion_forbidden")
    if status not in LOCAL_RECEIPT_STATUSES:
        raise ReceiptValidationError("receipt_status_invalid")
    if type(claims) is not dict or set(claims) != ALL_CLAIM_KEYS or any(
        type(value) is not bool or value is not False for value in claims.values()
    ):
        raise ReceiptValidationError("receipt_local_promotion_forbidden")
    return frozen


def _normalized_secret_name(value: str) -> str:
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", camel_split.casefold()).strip("_")


def _secret_name(value: str) -> bool:
    normalized = _normalized_secret_name(value)
    compact = normalized.replace("_", "")
    parts = set(normalized.split("_"))
    return (
        bool(parts & {"password", "passwd", "secret", "token", "credential", "credentials"})
        or normalized.endswith(("_private_key", "_api_key", "_auth_key", "_access_key"))
        or compact in {
            "awsaccesskeyid", "awssecretaccesskey", "awssessiontoken", "secretkey",
            "privatekey", "apikey", "authtoken", "accesstoken", "refreshtoken",
        }
    )


def _privacy_invalid(value: object) -> bool:
    if type(value) is dict:
        # Receipt field names are closed by the schema and include safe digest
        # identifiers such as cwd_token and project_path_token. Inspect retained
        # values here; assignment-like secret names inside those values are
        # handled below without misclassifying the schema's own field names.
        return any(_privacy_invalid(member) for member in value.values())
    if type(value) is list:
        return any(_privacy_invalid(member) for member in value)
    if type(value) is not str:
        return False
    if re.search(
        r"(?i)[A-Z]:[\\/]+Users[\\/]+|(?:Authorization|Proxy-Authorization)\s*:\s*(?:Basic|Bearer)\s+(?!<redacted>)|(?:X-Api-Key|X-Auth-Token|Cookie|Set-Cookie)\s*:\s*(?!<redacted>)|Bearer\s+(?!<redacted>)[A-Za-z0-9._~+/=-]{6,}",
        value,
    ):
        return True
    assignments = re.finditer(
        r"(?i)(?:^|[\s;,\{\[])[\"']?([a-z][a-z0-9_.-]{1,95})[\"']?\s*[:=]",
        value,
    )
    return any(_secret_name(match.group(1)) for match in assignments)


def _validate_receipt_structure(receipt: dict[str, object]) -> dict[str, object]:
    receipt = _reject_local_promotion(receipt)
    schema_path, schema_bytes = _read_strict_regular_bytes(_schema_path(SCHEMA_VERSION))
    if hashlib.sha256(schema_bytes).hexdigest() != V1_SCHEMA_SHA256:
        raise ReceiptValidationError("historical_v1_schema_drift")
    schema = json.loads(schema_bytes.decode("utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(receipt))
    if errors:
        raise ReceiptValidationError("receipt_schema_invalid")
    _validate_evidence_relations(receipt)
    status = receipt.get("status")
    blockers = receipt.get("blockers")
    if status == "internal_error":
        if blockers != [next(iter(blockers), None)] or blockers[0] not in INTERNAL_BLOCKERS:  # type: ignore[index]
            raise ReceiptValidationError("internal_receipt_category_invalid")
    else:
        derived_status, derived_blockers = _derive_status_and_blockers(receipt)
        if status != derived_status or blockers != derived_blockers:
            raise ReceiptValidationError("receipt_status_not_derived")
    claims = receipt.get("claims")
    if not isinstance(claims, dict) or claims.get("build_validated") is not False or claims.get("link_validated") is not False:
        raise ReceiptValidationError("receipt_claims_not_derived")
    if _privacy_invalid(receipt):
        raise ReceiptValidationError("receipt_privacy_invalid")
    return receipt


def _validate_receipt_v2(receipt: dict[str, object]) -> dict[str, object]:
    value = _reject_local_promotion(receipt)
    _schema_file, schema_bytes = _read_strict_regular_bytes(_schema_path(SCHEMA_VERSION_V2))
    schema = json.loads(schema_bytes.decode("utf-8"))
    if list(Draft202012Validator(schema).iter_errors(value)):
        raise ReceiptValidationError("receipt_v2_schema_invalid")
    provenance = value.get("provenance")
    if type(provenance) is not dict:
        raise ReceiptValidationError("receipt_provenance_missing")
    authority = provenance.get("authority_snapshot")
    if type(authority) is not dict:
        raise ReceiptValidationError("receipt_authority_snapshot_invalid")
    authority_bytes = _canonical_json_bytes(authority)
    _authority_schema_file, authority_schema_bytes = _read_strict_regular_bytes(
        _schema_path(AUTHORITY_SCHEMA_VERSION)
    )
    authority_schema = json.loads(authority_schema_bytes.decode("utf-8"))
    if list(Draft202012Validator(authority_schema).iter_errors(authority)):
        raise ReceiptValidationError("receipt_authority_snapshot_invalid")
    _validate_authority_claims(authority)
    if authority.get("roles_sha256") != _inventory_digest(authority.get("roles", [])):
        raise ReceiptValidationError("receipt_authority_roles_invalid")
    if provenance.get("authority_sha256") != hashlib.sha256(authority_bytes).hexdigest():
        raise ReceiptValidationError("receipt_authority_digest_invalid")
    pre, post = provenance.get("role_inventory_pre"), provenance.get("role_inventory_post")
    _validate_inventory_binding(pre, provenance.get("role_inventory_pre_sha256"), "provenance_pre")
    _validate_inventory_binding(post, provenance.get("role_inventory_post_sha256"), "provenance_post")
    if pre != authority.get("roles"):
        raise ReceiptValidationError("receipt_authority_roles_invalid")
    unchanged = (
        pre == post == authority.get("roles")
        and provenance.get("authority_post_sha256") == provenance.get("authority_sha256")
    )
    if provenance.get("unchanged") is not unchanged:
        raise ReceiptValidationError("receipt_provenance_state_invalid")
    claims = value.get("claims")
    if type(claims) is not dict or set(claims) != ALL_CLAIM_KEYS or any(
        type(item) is not bool or item is not False for item in claims.values()
    ):
        raise ReceiptValidationError("receipt_local_promotion_forbidden")
    status, blockers = value.get("status"), value.get("blockers")
    if not unchanged:
        if status != "provenance_drift" or blockers != ["authority_or_provenance_changed"]:
            raise ReceiptValidationError("receipt_provenance_precedence_invalid")
    elif status == "provenance_drift":
        raise ReceiptValidationError("receipt_provenance_state_invalid")
    elif status == "internal_error":
        if blockers != [next(iter(blockers), None)] or blockers[0] not in INTERNAL_BLOCKERS:  # type: ignore[index]
            raise ReceiptValidationError("internal_receipt_category_invalid")
    else:
        derived_status, derived_blockers = _derive_status_and_blockers(value)
        if derived_status == "artifact_observed_unbound":
            derived_status = "artifact_observed_provenance_bound"
        if status != derived_status or blockers != derived_blockers:
            raise ReceiptValidationError("receipt_status_not_derived")
    if unchanged:
        historical = _freeze_receipt(value)
        historical.pop("provenance")
        historical["schema_version"] = SCHEMA_VERSION
        historical["evidence_class"] = "local_unsigned_build"
        if historical.get("status") == "artifact_observed_provenance_bound":
            historical["status"] = "artifact_observed_unbound"
        _validate_receipt_structure(historical)
    _validate_evidence_relations(value)
    if _privacy_invalid(value):
        raise ReceiptValidationError("receipt_privacy_invalid")
    return value


def _validate_receipt_document(receipt: dict[str, object]) -> dict[str, object]:
    """Validate a v1 historical or v2 provenance-bound local receipt."""
    frozen = _freeze_receipt(receipt)
    if frozen.get("schema_version") == SCHEMA_VERSION:
        return _validate_receipt_structure(frozen)
    if frozen.get("schema_version") == SCHEMA_VERSION_V2:
        return _validate_receipt_v2(frozen)
    raise ReceiptValidationError("schema_version_unsupported")


def _exception_blocker(error: Exception) -> str:
    message = str(error).casefold()
    if "unsafe_output_topology" in message:
        return "unsafe_output_topology"
    if any(token in message for token in ("project", "import", "custom_build", "user_import", "input_")):
        return "invalid_project_contract"
    if any(token in message for token in ("toolchain", "msvc", "compiler", "inf2cat", "stampinf")):
        return "toolchain_inventory_unavailable"
    if isinstance(error, ReceiptValidationError):
        return "receipt_validation_failed"
    return "internal_gate_error"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _finish_execution(
    receipt: dict[str, object], exit_code: int, proof: _LocalConsistencyContext
) -> tuple[dict[str, object], int, _LocalConsistencyContext]:
    receipt = _reject_local_promotion(receipt)
    proof.binding_sha256 = _evidence_binding(receipt)
    return receipt, exit_code, proof


def execute(args: argparse.Namespace) -> tuple[dict[str, object], int, _LocalConsistencyContext]:
    observed_at = _utc_now()
    project = Path(args.project).resolve(strict=True)
    output, _receipt_path = _canonical_fresh_locations(project, args.output, args.receipt)
    original_before = _canonical_source_inventory(project)
    project_contract = _project_contract(project)
    output.mkdir(parents=True, exist_ok=False)
    (output / "bin").mkdir()
    (output / "obj").mkdir()
    (output / "tmp").mkdir()
    stage = output / "stage"
    stage.mkdir()
    staged_project = _stage_project(project, stage)
    staged_before = _stage_inventory(stage)
    msbuild = Path(args.msbuild).resolve()
    proof = _LocalConsistencyContext(project, original_before, stage, msbuild, args.wdk)
    argv = _build_argv(args, staged_project, output)
    redaction_paths = (output, stage, project.parent, Path.home())
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "observed_at": observed_at,
        "evidence_class": "local_unsigned_build",
        "status": "internal_error",
        "source": {
            "project_basename": project.name,
            "project_path_token": hashlib.sha256(str(project).casefold().encode()).hexdigest(),
            "inventory": original_before, "inventory_sha256": _inventory_digest(original_before),
            "post_inventory": [], "post_inventory_sha256": None, "original_unchanged": False,
            "stage_input_inventory": staged_before, "stage_input_sha256": _inventory_digest(staged_before),
            "stage_post_inventory": [], "stage_post_sha256": None,
            "isolated_post_inventory": [], "isolated_post_sha256": None,
            "project_contract": project_contract,
        },
        "toolchain": {
            "wdk_version_requested": args.wdk, "files": [], "post_files": [], "post_sha256": None,
            "unchanged": False, "imports": [], "post_imports": [], "imports_post_sha256": None,
            "imports_unchanged": False,
        },
        "policy": {
            "observe_only": "1", "driver_sign": "Off", "sign_mode": "Off",
            "inf2cat": "false", "packaging": "false", "post_build": "false",
            "vcpkg_enabled": "false", "custom_build_stage_only": True, "user_props_loaded": False,
        },
        "execution": {
            "argv": [_redact_text(item, redaction_paths) for item in argv], "cwd_token": hashlib.sha256(str(stage).casefold().encode()).hexdigest(),
            "timeout_seconds": args.timeout_seconds, "environment_keys": [], "preprocess": None,
            "effective_properties": {},
        },
        "process": None,
        "artifact": None,
        "artifact_check": {"candidate_count": 0, "state": "not_evaluated", "failure": None},
        "claims": {"build_validated": False, "link_validated": False, **RUNTIME_FALSE_CLAIMS},
        "blockers": [],
    }
    if not msbuild.is_file():
        base["status"] = "toolchain_unavailable"
        base["blockers"] = ["msbuild_not_found"]
        return _finish_execution(base, 2, proof)
    toolchain_before, tool_dirs = _toolchain_inventory(msbuild, args.wdk)
    proof.toolchain_before = toolchain_before
    base["toolchain"]["files"] = toolchain_before  # type: ignore[index]
    env = _minimal_child_env(tool_dirs, output / "tmp")
    base["execution"]["environment_keys"] = sorted(env)  # type: ignore[index]
    preprocess_path = output / "preprocessed.xml"
    checkpoint = getattr(args, "_provenance_checkpoint", None)
    if checkpoint is not None:
        checkpoint()
    preprocess = _run_bounded(_preprocess_argv(argv, preprocess_path), stage, env, min(args.timeout_seconds, 120))
    proof.preprocess_evidence = preprocess
    preprocess_dict = _process_document(preprocess, redaction_paths)
    base["execution"]["preprocess"] = preprocess_dict  # type: ignore[index]
    if preprocess.timed_out or preprocess.exit_code != 0 or not preprocess_path.is_file():
        base["status"] = "project_preflight_failed"
        base["blockers"] = ["msbuild_preprocess_failed"]
        return _finish_execution(base, 8, proof)
    _assert_authoritative_stage_unchanged(stage, staged_before)
    allowed_import_roots = (
        msbuild.parents[3],
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits/10",
        Path(os.environ["SystemRoot"]) / "Microsoft.NET/Framework/v4.0.30319",
    )
    imports_before = _import_inventory(preprocess_path, allowed_import_roots)
    proof.imports_before = imports_before
    proof.preprocess_path = preprocess_path
    proof.allowed_import_roots = tuple(allowed_import_roots)
    base["toolchain"]["imports"] = imports_before  # type: ignore[index]
    base["execution"]["effective_properties"] = _capture_effective_properties(  # type: ignore[index]
        argv, stage, env, min(args.timeout_seconds, 60), checkpoint
    )
    _assert_authoritative_stage_unchanged(stage, staged_before)
    if checkpoint is not None:
        checkpoint()
    result = _run_bounded(argv, stage, env, args.timeout_seconds)
    proof.process_evidence = result
    _assert_authoritative_stage_unchanged(stage, staged_before)
    process_dict = _process_document(result, redaction_paths)
    base["process"] = process_dict
    original_after = _canonical_source_inventory(project)
    source_unchanged = _identities_unchanged(original_before, original_after)
    base["source"]["post_inventory"] = original_after  # type: ignore[index]
    base["source"]["post_inventory_sha256"] = _inventory_digest(original_after)  # type: ignore[index]
    base["source"]["original_unchanged"] = source_unchanged  # type: ignore[index]
    stage_post = _stage_inventory(stage)
    base["source"]["stage_post_inventory"] = stage_post  # type: ignore[index]
    base["source"]["stage_post_sha256"] = _inventory_digest(stage_post)  # type: ignore[index]
    isolated_post = _stage_inventory(output)
    base["source"]["isolated_post_inventory"] = isolated_post  # type: ignore[index]
    base["source"]["isolated_post_sha256"] = _inventory_digest(isolated_post)  # type: ignore[index]
    toolchain_after, _ = _toolchain_inventory(msbuild, args.wdk)
    imports_after, imports_unchanged = _rehash_import_inventory(
        imports_before, preprocess_path, allowed_import_roots
    )
    toolchain_unchanged = _identities_unchanged(toolchain_before, toolchain_after) and imports_unchanged
    base["toolchain"]["post_files"] = toolchain_after  # type: ignore[index]
    base["toolchain"]["post_sha256"] = _inventory_digest(toolchain_after)  # type: ignore[index]
    base["toolchain"]["unchanged"] = toolchain_unchanged  # type: ignore[index]
    base["toolchain"]["post_imports"] = imports_after  # type: ignore[index]
    base["toolchain"]["imports_post_sha256"] = _inventory_digest(imports_after)  # type: ignore[index]
    base["toolchain"]["imports_unchanged"] = imports_unchanged  # type: ignore[index]
    if not source_unchanged or not toolchain_unchanged:
        base["status"] = "input_drift"
        base["blockers"] = ["source_or_toolchain_changed_during_build"]
        return _finish_execution(base, 9, proof)
    if result.timed_out:
        base["status"] = "timed_out"
        base["blockers"] = ["msbuild_deadline_exceeded"]
        return _finish_execution(base, 3, proof)
    if result.exit_code != 0:
        base["status"] = "build_failed"
        base["blockers"] = [_classify_build_failure(result.retained_output)]
        return _finish_execution(base, 4, proof)
    artifacts = list((output / "bin").rglob("*.sys"))
    base["artifact_check"]["candidate_count"] = len(artifacts)  # type: ignore[index]
    if len(artifacts) != 1:
        base["artifact_check"]["state"] = "missing_or_ambiguous"  # type: ignore[index]
        base["artifact_check"]["failure"] = "expected_exactly_one_sys_artifact"  # type: ignore[index]
        base["status"] = "artifact_missing"
        base["blockers"] = ["expected_exactly_one_sys_artifact"]
        return _finish_execution(base, 5, proof)
    try:
        artifact = _parse_pe(artifacts[0])
    except (OSError, ValueError):
        base["artifact_check"]["state"] = "invalid"  # type: ignore[index]
        base["artifact_check"]["failure"] = "invalid_pe_artifact"  # type: ignore[index]
        base["status"] = "artifact_invalid"
        base["blockers"] = ["invalid_pe_artifact"]
        return _finish_execution(base, 6, proof)
    base["artifact"] = artifact
    base["artifact_check"]["state"] = "valid"  # type: ignore[index]
    if artifact["certificate_table_present"]:
        base["artifact_check"]["failure"] = "unexpected_signed_artifact"  # type: ignore[index]
        base["status"] = "artifact_invalid"
        base["blockers"] = ["unexpected_signed_artifact"]
        return _finish_execution(base, 6, proof)
    base["status"] = "artifact_observed_unbound"
    base["blockers"] = list(ARTIFACT_OBSERVED_BLOCKERS)
    proof.artifact_path = artifacts[0]
    return _finish_execution(base, 0, proof)


def _execute_v2(
    args: argparse.Namespace, authority_path: Path
) -> tuple[dict[str, object], int, _LocalConsistencyContext]:
    authority, authority_sha256 = _load_authority(authority_path, args)
    before = _provenance_inventory()
    if before != authority.get("roles"):
        raise ReceiptValidationError("authority_role_mismatch")
    def checkpoint() -> None:
        current_authority, current_sha256 = _load_authority(authority_path, args)
        if current_sha256 != authority_sha256 or current_authority != authority:
            raise ReceiptValidationError("authority_checkpoint_drift")

    setattr(args, "_provenance_checkpoint", checkpoint)
    receipt, exit_code, proof = execute(args)
    after = _provenance_inventory()
    proof.authority_path = _strict_regular_file(authority_path)
    proof.authority_snapshot = authority
    proof.authority_sha256 = authority_sha256
    proof.provenance_before = before
    proof.invocation_args = args
    return _convert_to_v2(receipt, authority, authority_sha256, before, after), exit_code, proof


def _refresh_v2_provenance(receipt: dict[str, object], proof: _LocalConsistencyContext) -> None:
    if (
        proof.authority_path is None or proof.authority_snapshot is None
        or proof.authority_sha256 is None or proof.provenance_before is None
    ):
        raise ReceiptValidationError("receipt_provenance_context_missing")
    _authority_path, authority_bytes = _read_strict_regular_bytes(proof.authority_path)
    authority_post_sha256 = hashlib.sha256(authority_bytes).hexdigest()
    after = _provenance_inventory()
    provenance = _provenance_document(
        proof.authority_snapshot, proof.authority_sha256, proof.provenance_before, after
    )
    provenance["authority_post_sha256"] = authority_post_sha256
    provenance["unchanged"] = (
        provenance["unchanged"] is True and authority_post_sha256 == proof.authority_sha256
    )
    receipt["provenance"] = provenance
    if provenance["unchanged"] is not True:
        receipt["status"] = "provenance_drift"
        receipt["blockers"] = ["authority_or_provenance_changed"]
        receipt["claims"] = {"build_validated": False, "link_validated": False, **RUNTIME_FALSE_CLAIMS}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze-authority")
    mode.add_argument("--validate-authority")
    mode.add_argument("--authority")
    parser.add_argument("--project", required=True)
    parser.add_argument("--configuration", default="Release", choices=("Release",))
    parser.add_argument("--platform", default="x64", choices=("x64",))
    parser.add_argument("--observe-only", required=True, choices=("1",))
    parser.add_argument("--msbuild", required=True)
    parser.add_argument("--wdk", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    return parser.parse_args(argv)


def _write_receipt_exclusive(
    receipt_path: Path,
    receipt: dict[str, object],
    proof: _LocalConsistencyContext,
    before_final_check: Callable[[], None] | None = None,
) -> None:
    receipt = _reject_local_promotion(receipt)
    if before_final_check is not None:
        before_final_check()
    if receipt.get("schema_version") == SCHEMA_VERSION_V2:
        _refresh_v2_provenance(receipt, proof)
    receipt = _finalize_receipt_integrity(receipt, proof)
    if receipt.get("schema_version") == SCHEMA_VERSION_V2:
        _refresh_v2_provenance(receipt, proof)
    receipt = _validate_receipt_document(receipt)
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    _validate_receipt_document(json.loads(encoded))
    with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    receipt_path: Path | None = None
    proof: _LocalConsistencyContext | None = None
    try:
        if args.freeze_authority:
            authority, digest = _freeze_authority(args, Path(args.freeze_authority))
            print(json.dumps({"ok": True, "authority_sha256": digest, "authority": authority}, sort_keys=True))
            return 0
        if args.validate_authority:
            authority, digest = _load_authority(Path(args.validate_authority), args)
            print(json.dumps({"ok": True, "authority_sha256": digest, "authority": authority}, sort_keys=True))
            return 0
        project = Path(args.project).resolve(strict=True)
        _output_path, receipt_path = _canonical_fresh_locations(project, args.output, args.receipt)
        receipt, exit_code, proof = _execute_v2(args, Path(args.authority))
        _write_receipt_exclusive(receipt_path, receipt, proof)
    except Exception as exc:
        receipt = {"ok": False, "status": "provenance_preflight_failed", "blocker": _exception_blocker(exc),
                   "claims": {"build_validated": False, "link_validated": False, **RUNTIME_FALSE_CLAIMS}}
        exit_code = 7
    print(json.dumps(receipt, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
