#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUST_PATH = "apps/tamandua_agent/ebpf-programs/src/main.rs"
C_PATH = "apps/tamandua_agent/bpf/lsm_hooks.bpf.c"
SCHEMA_PATH = "schemas/anti_cheat_linux_ebpf_lsm_observe_only_source_v1.schema.json"
FIXTURE_PATH = "tools/detection_validation/fixtures/anti_cheat_linux_ebpf_lsm_observe_only_source_degraded.json"
SCRIPT_PATH = "tools/detection_validation/scripts/anti_cheat_linux_ebpf_lsm_observe_only_static_gate.py"
TEST_PATH = "tools/detection_validation/tests/anti_cheat_linux_ebpf_lsm_observe_only_static_test.py"
CONTRACT_FILES = {SCHEMA_PATH, FIXTURE_PATH, SCRIPT_PATH, TEST_PATH}
ALL_FILES = CONTRACT_FILES | {RUST_PATH, C_PATH}
RUST_SHA256 = "2a387e9c66cf1e5c64c9304f655fa068a7339420a939d22f085e8b3df345b812"
C_SHA256 = "d60f1773f39961268eee325991885ca383e3793100fccaf09b2b376e9d9d3590"
RUST_HOOKS = {"bprm_check_security", "file_open", "file_permission", "mmap_file", "socket_bind", "socket_connect", "task_kill"}
C_HOOKS = RUST_HOOKS | {"ptrace_access_check", "sb_mount"}
BLOCKERS = ["prior_lsm_decision_not_preserved", "decisive_behavior_not_formally_proven"]
TOP = {"schema_version", "evidence_class", "observed_at", "capability_state", "sources", "assessment", "lifecycle", "claims", "blockers"}
SOURCE_FIELDS = {"path", "sha256", "hooks"}
ASSESSMENT_FIELDS = {"prior_lsm_decision_preserved", "decisive_behavior_assessment"}
LIFECYCLE_FIELDS = {"runtime_state", "load_requested", "load_authorized", "attach_requested", "attach_authorized", "enforcement_requested", "enforcement_authorized"}
CLAIM_FIELDS = {"build_validated", "load_validated", "kernel_compatibility_validated", "efficacy_validated", "production_ready", "external_claim_allowed"}


class DuplicateKey(ValueError):
    pass


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKey(f"duplicate key: {key}")
        value[key] = item
    return value


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _closed(value, fields, label, errors):
    if not isinstance(value, dict) or set(value) != fields:
        errors.append(f"{label}:closed_fields")
        return False
    return True


def validate_paths(root: Path) -> list[str]:
    errors = []
    root_resolved = root.resolve(strict=True)
    reparse_flag = 0x400
    for relative in sorted(ALL_FILES):
        candidate = root / relative
        try:
            metadata = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            confined = resolved == root_resolved or root_resolved in resolved.parents
            attributes = metadata.st_file_attributes if "st_file_attributes" in dir(metadata) else 0
            reparse = bool(attributes & reparse_flag)
            if candidate.is_symlink() or reparse or not confined or not candidate.is_file():
                errors.append(f"path:{relative}:regular_confined_required")
        except OSError:
            errors.append(f"path:{relative}:regular_confined_required")
    return errors


def inventories(root: Path) -> tuple[list[str], list[str]]:
    rust = (root / RUST_PATH).read_text(encoding="utf-8")
    c = (root / C_PATH).read_text(encoding="utf-8")
    rust_hooks = re.findall(r'#\[lsm\s*\(\s*hook\s*=\s*"([^"]+)"\s*\)\s*\]\s*pub\s+fn\s+\w+', rust)
    c_hooks = re.findall(r'SEC\s*\(\s*"lsm/([^"]+)"\s*\)\s*int\s+BPF_PROG\s*\(', c)
    return rust_hooks, c_hooks


def validate_sources(root: Path) -> list[str]:
    errors = []
    if sha256(root / RUST_PATH) != RUST_SHA256:
        errors.append("source:rust:sha256")
    if sha256(root / C_PATH) != C_SHA256:
        errors.append("source:c:sha256")
    rust_hooks, c_hooks = inventories(root)
    if len(rust_hooks) != len(RUST_HOOKS) or set(rust_hooks) != RUST_HOOKS:
        errors.append("source:rust:inventory")
    if len(c_hooks) != len(C_HOOKS) or set(c_hooks) != C_HOOKS:
        errors.append("source:c:inventory")
    return errors


def validate_gate_policy(root: Path) -> list[str]:
    errors = []
    actual = set()
    for directory in ("schemas", "tools/detection_validation/fixtures", "tools/detection_validation/scripts", "tools/detection_validation/tests"):
        for path in (root / directory).rglob("anti_cheat_linux_ebpf_lsm_observe_only*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                actual.add(path.relative_to(root).as_posix())
    if actual != CONTRACT_FILES:
        errors.append("contract:file_set")
    source = (root / SCRIPT_PATH).read_text(encoding="utf-8")
    tree = ast.parse(source)
    allowed_imports = {"__future__", "argparse", "ast", "hashlib", "json", "re", "datetime", "pathlib"}
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    }
    if not imports <= allowed_imports:
        errors.append("contract:dependencies")
    forbidden_names = {
        "__import__", "open", "eval", "exec", "compile", "getattr", "setattr",
        "delattr", "vars", "globals", "locals", "input", "breakpoint",
        "system", "popen", "run", "Popen", "import_module",
    }
    forbidden_attrs = {
        "open", "write_text", "write_bytes", "unlink", "replace", "rename",
        "touch", "mkdir", "rmdir", "chmod", "symlink_to", "hardlink_to",
        "system", "popen", "run", "Popen", "call", "import_module",
    }
    allowed_dunder_names = {"__file__", "__name__"}
    dunder_reference = any(
        (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and (node.id.startswith("__") or node.id.endswith("__"))
            and node.id not in allowed_dunder_names
        )
        or (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and (node.attr.startswith("__") or node.attr.endswith("__"))
        )
        for node in ast.walk(tree)
    )
    if dunder_reference:
        errors.append("contract:dunder_reference")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in forbidden_names:
            errors.append("contract:dynamic_or_write_reference")
            break
        if isinstance(node, ast.Attribute) and node.attr in forbidden_attrs:
            errors.append("contract:dynamic_or_write_reference")
            break
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, (ast.Name, ast.Attribute)):
            errors.append("contract:dynamic_or_write_call")
            break
        if isinstance(node.func, ast.Name) and node.func.id in forbidden_names:
            errors.append("contract:dynamic_or_write_call")
            break
    return errors


def validate_schema(root: Path) -> list[str]:
    errors = []
    schema = load_json(root / SCHEMA_PATH)
    if set(schema.get("required", [])) != TOP or set(schema.get("properties", {})) != TOP or schema.get("additionalProperties") is not False:
        errors.append("schema:top")
        return errors
    properties = schema["properties"]
    constants = {
        "schema_version": 1,
        "evidence_class": "static_source_inventory",
        "capability_state": "degraded_unproven",
        "blockers": BLOCKERS,
    }
    if any(properties.get(key, {}).get("const") != value for key, value in constants.items()):
        errors.append("schema:constants")
    nested = {
        "sources": ({"rust", "c"}, None),
        "assessment": (ASSESSMENT_FIELDS, {"prior_lsm_decision_preserved": False, "decisive_behavior_assessment": "not_formally_proven"}),
        "lifecycle": (LIFECYCLE_FIELDS, {"runtime_state": "not_executed", **{key: False for key in LIFECYCLE_FIELDS if key != "runtime_state"}}),
        "claims": (CLAIM_FIELDS, {key: False for key in CLAIM_FIELDS}),
    }
    for name, (fields, expected) in nested.items():
        value = properties.get(name, {})
        if value.get("additionalProperties") is not False or set(value.get("required", [])) != fields or set(value.get("properties", {})) != fields:
            errors.append(f"schema:{name}:closed")
        if expected and any(value.get("properties", {}).get(key, {}).get("const") != item for key, item in expected.items()):
            errors.append(f"schema:{name}:constants")
    source = schema.get("$defs", {}).get("source", {})
    if source.get("additionalProperties") is not False or set(source.get("required", [])) != SOURCE_FIELDS or set(source.get("properties", {})) != SOURCE_FIELDS:
        errors.append("schema:source:closed")
    source_expectations = {
        "rust": {"path": RUST_PATH, "sha256": RUST_SHA256, "hooks": sorted(RUST_HOOKS)},
        "c": {"path": C_PATH, "sha256": C_SHA256, "hooks": sorted(C_HOOKS)},
    }
    for label, expected in source_expectations.items():
        all_of = properties.get("sources", {}).get("properties", {}).get(label, {}).get("allOf", [])
        if len(all_of) != 2 or all_of[0] != {"$ref": "#/$defs/source"}:
            errors.append(f"schema:source:{label}:binding")
            continue
        bound = all_of[1].get("properties", {})
        if set(bound) != SOURCE_FIELDS or any(bound.get(key, {}).get("const") != value for key, value in expected.items()):
            errors.append(f"schema:source:{label}:binding")
    return errors


def validate_receipt(receipt) -> list[str]:
    errors = []
    if not _closed(receipt, TOP, "receipt", errors):
        return errors
    try:
        datetime.strptime(receipt["observed_at"], "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        errors.append("observed_at")
    expected_scalars = {
        "schema_version": 1,
        "evidence_class": "static_source_inventory",
        "capability_state": "degraded_unproven",
        "blockers": BLOCKERS,
    }
    if any(receipt[key] != value for key, value in expected_scalars.items()):
        errors.append("receipt:immutable_constants")
    expected_sources = {
        "rust": {"path": RUST_PATH, "sha256": RUST_SHA256, "hooks": sorted(RUST_HOOKS)},
        "c": {"path": C_PATH, "sha256": C_SHA256, "hooks": sorted(C_HOOKS)},
    }
    if receipt["sources"] != expected_sources:
        errors.append("receipt:sources")
    if receipt["assessment"] != {"prior_lsm_decision_preserved": False, "decisive_behavior_assessment": "not_formally_proven"}:
        errors.append("receipt:assessment")
    expected_lifecycle = {"runtime_state": "not_executed", **{key: False for key in LIFECYCLE_FIELDS if key != "runtime_state"}}
    if receipt["lifecycle"] != expected_lifecycle:
        errors.append("receipt:lifecycle")
    if receipt["claims"] != {key: False for key in CLAIM_FIELDS}:
        errors.append("receipt:claims")
    return errors


def run_gate(root: Path = ROOT) -> dict:
    failures = {}
    path_errors = validate_paths(root)
    if path_errors:
        failures["paths"] = path_errors
    else:
        for label, errors in (
            ("sources", validate_sources(root)),
            ("contract", validate_gate_policy(root)),
            ("schema", validate_schema(root)),
            ("fixture", validate_receipt(load_json(root / FIXTURE_PATH))),
        ):
            if errors:
                failures[label] = errors
    return {"ok": not failures, "evidence_class": "static_source_inventory", "failures": failures, "blockers": BLOCKERS}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    result = run_gate()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
