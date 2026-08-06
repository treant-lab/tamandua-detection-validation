#!/usr/bin/env python3

import sys

if sys.platform == "win32":
    import nt as _bootstrap_fs
else:
    import posix as _bootstrap_fs


def _bootstrap_realpath(entry):
    if sys.platform == "win32":
        return _bootstrap_fs._getfinalpathname(_bootstrap_fs._getfullpathname(entry)).lower()
    pending = entry if entry.startswith("/") else _bootstrap_fs.getcwd() + "/" + entry
    resolved = []
    links = 0
    while pending:
        components = pending.split("/")
        pending = ""
        for offset, component in enumerate(components):
            if not component or component == ".":
                continue
            if component == "..":
                if resolved:
                    resolved.pop()
                continue
            candidate = "/" + "/".join(resolved + [component])
            try:
                target = _bootstrap_fs.readlink(candidate)
            except OSError:
                resolved.append(component)
                continue
            links += 1
            if links > 40:
                raise OSError("too many symbolic links")
            if target.startswith("/"):
                resolved = []
            remaining = components[offset + 1:]
            pending = target + ("/" + "/".join(remaining) if remaining else "")
            break
    return "/" + "/".join(resolved)


if __name__ == "__main__":
    _base = sys.base_prefix.rstrip("\\/")
    _stdlib = _base + "\\Lib" if sys.platform == "win32" else _base + "/lib/python" + str(sys.version_info.major) + "." + str(sys.version_info.minor)
    _expected_paths = [_stdlib]
    _expected_paths.append(_base + "\\DLLs" if sys.platform == "win32" else _stdlib + "/lib-dynload")
    _expected_realpaths = set()
    for _expected in _expected_paths:
        try:
            _expected_realpaths.add(_bootstrap_realpath(_expected))
        except OSError:
            pass
    _trusted_sys_path = []
    for _entry in tuple(sys.path):
        if not _entry:
            continue
        try:
            _real_entry = _bootstrap_realpath(_entry)
        except OSError:
            continue
        if _real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path:
            _trusted_sys_path.append(_real_entry)
    sys.path[:] = _trusted_sys_path

import ast
import hashlib
import json
import pathlib
import re
import stat
import typing


Path = pathlib.Path
OBSERVED_AT = "2026-07-18T01:00:00Z"
STDLIB_MODULES = {"sys", "ast", "hashlib", "json", "pathlib", "re", "stat", "typing"}
SHADOW_MODULES = STDLIB_MODULES | {"nt", "posix"}


ROOT = Path(__file__).resolve().parents[3]
RUST_PATH = "apps/tamandua_agent/ebpf-programs/src/main.rs"
C_PATH = "apps/tamandua_agent/bpf/lsm_hooks.bpf.c"
SCHEMA_PATH = "schemas/anti_cheat_linux_bpf_lsm_prior_ret_source_v2.schema.json"
FIXTURE_PATH = "tools/detection_validation/fixtures/anti_cheat_linux_bpf_lsm_prior_ret_source_v2.json"
SCRIPT_PATH = "tools/detection_validation/scripts/anti_cheat_linux_bpf_lsm_prior_ret_source_v2_gate.py"
TEST_PATH = "tools/detection_validation/tests/anti_cheat_linux_bpf_lsm_prior_ret_source_v2_test.py"
V1_FIXTURE_PATH = "tools/detection_validation/fixtures/anti_cheat_linux_ebpf_lsm_observe_only_source_degraded.json"
CONTRACT_FILES = {SCHEMA_PATH, FIXTURE_PATH, SCRIPT_PATH, TEST_PATH}
ALL_FILES = CONTRACT_FILES | {RUST_PATH, C_PATH, V1_FIXTURE_PATH}
RUST_SHA256 = "dc4b896d991b1c733c79a41689712e63b64efd8c3aeb3ad4e3e934b16f1f1271"
C_SHA256 = "d2d80206e03be012f28ee753c8608d4c708b32a2da8e3e5dda0be947bdb81a0a"
V1_SHA256 = "bc85bdfb8be0eabe49db795d9afe36f3b55c4b245e4ae9295486577e7d07aa68"
RUST_INDICES = {"bprm_check_security": 1, "file_open": 1, "file_permission": 2, "socket_connect": 3, "socket_bind": 3, "task_kill": 4, "mmap_file": 4}
C_HOOKS = set(RUST_INDICES) | {"ptrace_access_check", "sb_mount"}
RUST_EVENT_RET_HOOKS = {"bprm_check_security", "socket_connect", "socket_bind", "task_kill"}
C_EVENT_RET_HOOKS = {"bprm_check_security", "socket_connect", "socket_bind", "task_kill", "ptrace_access_check"}
BLOCKERS = ["build_not_validated", "verifier_not_validated", "btf_abi_not_validated", "load_not_validated", "attach_not_validated", "runtime_prior_decision_preservation_not_validated", "telemetry_not_validated", "kernel_compatibility_not_validated", "efficacy_not_validated", "performance_not_validated", "rollback_not_validated", "decision_gate_not_approved"]
LIFECYCLE = {"runtime_state": "not_executed", "build_requested": False, "build_authorized": False, "load_requested": False, "load_authorized": False, "attach_requested": False, "attach_authorized": False, "enforcement_requested": False, "enforcement_authorized": False}
CLAIM_NAMES = {"build_validated", "verifier_validated", "btf_abi_validated", "load_validated", "attach_validated", "runtime_prior_decision_preservation_validated", "telemetry_validated", "kernel_compatibility_validated", "efficacy_validated", "performance_validated", "rollback_validated", "production_ready", "external_claim_allowed"}
TOP = {"schema_version", "evidence_class", "observed_at", "capability_state", "sources", "historical_v1", "assessment", "lifecycle", "claims", "blockers"}
SOURCE_FIELDS = {"path", "sha256", "hooks"}
HISTORICAL_FIELDS = {"fixture_path", "fixture_sha256", "rust_source_sha256", "c_source_sha256", "relation"}
ASSESSMENT_FIELDS = {"prior_lsm_decision_preserved", "new_denial_introduced"}


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


def _body(text: str, start: int) -> str:
    opening = text.find("{", start)
    if opening < 0:
        return ""
    depth = 0
    for index in range(opening, len(text)):
        depth += (text[index] == "{") - (text[index] == "}")
        if depth == 0:
            return text[opening + 1:index]
    return ""


def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\r\n]*", "", text)


def validate_paths(root: Path) -> list[str]:
    errors = []
    root_resolved = root.resolve(strict=True)
    for relative in sorted(ALL_FILES):
        candidate = root / relative
        try:
            metadata = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            attributes = metadata.st_file_attributes if "st_file_attributes" in dir(metadata) else 0
            if candidate.is_symlink() or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT or root_resolved not in resolved.parents or not candidate.is_file():
                errors.append(f"path:{relative}")
        except OSError:
            errors.append(f"path:{relative}")
    return errors


def validate_rust_shape(text: str) -> list[str]:
    errors = []
    inventory = re.findall(r'#\[lsm\s*\(\s*hook\s*=\s*"([^"]+)"\s*\)\s*\]\s*pub\s+fn\s+(\w+)', text)
    if len(inventory) != len(RUST_INDICES) or {hook for hook, _ in inventory} != set(RUST_INDICES):
        errors.append("rust:inventory")
    for hook, index in RUST_INDICES.items():
        name = f"lsm_{hook}"
        wrapper_match = re.search(rf"\bpub\s+fn\s+{name}\s*\(\s*ctx\s*:\s*LsmContext\s*\)\s*->\s*i32", text)
        helper_match = re.search(rf"\bfn\s+try_lsm_{hook}\s*\(\s*[^,]+,\s*prior_ret\s*:\s*i32\s*\)\s*->\s*Result\s*<\s*i32\s*,\s*i64\s*>", text)
        if not wrapper_match or not helper_match:
            errors.append(f"rust:{hook}:signature")
            continue
        wrapper = _code(_body(text, wrapper_match.start()))
        helper = _code(_body(text, helper_match.start()))
        extraction = rf"let\s+prior_ret\s*:\s*i32\s*=\s*unsafe\s*\{{\s*ctx\.arg\s*\(\s*{index}\s*\)\s*\}}\s*;"
        extraction_matches = list(re.finditer(extraction, wrapper))
        guard = re.search(r"if\s+prior_ret\s*!=\s*0\s*\{\s*return\s+prior_ret\s*;\s*\}", wrapper)
        call = re.search(rf"try_lsm_{hook}\s*\(\s*&ctx\s*,\s*prior_ret\s*\)", wrapper)
        if len(extraction_matches) != 1 or not guard or not call or not (extraction_matches[0].start() < guard.start() < call.start()):
            errors.append(f"rust:{hook}:wrapper")
        if len(re.findall(r"\bctx\.arg\s*\(", wrapper)) != 1 or re.search(r"Err\s*\([^)]*\)\s*=>\s*prior_ret", wrapper) is None:
            errors.append(f"rust:{hook}:error_path")
        wrapper_without_extraction = re.sub(extraction, "", wrapper, count=1)
        if re.search(r"\blet\s+(?:mut\s+)?prior_ret\b|\bprior_ret\s*[-+*/%&|^]?=", wrapper_without_extraction):
            errors.append(f"rust:{hook}:ret_mutation")
        ok_values = re.findall(r"(?:return\s+)?Ok\s*\(([^)]*)\)", helper)
        if not ok_values or any(value.strip() != "prior_ret" for value in ok_values):
            errors.append(f"rust:{hook}:helper_exit")
        if re.search(r"\blet\s+(?:mut\s+)?prior_ret\b|\bprior_ret\s*[-+*/]?=", helper):
            errors.append(f"rust:{hook}:ret_mutation")
        event_values = re.findall(r"\(\*event\)\.ret\s*=\s*([^;]+);", helper)
        expected_event_count = 1 if hook in RUST_EVENT_RET_HOOKS else 0
        if len(event_values) != expected_event_count or any(value.strip() != "prior_ret" for value in event_values):
            errors.append(f"rust:{hook}:event_ret")
    return errors


def validate_c_shape(text: str) -> list[str]:
    errors = []
    inventory = re.findall(r'SEC\s*\(\s*"lsm/([^"]+)"\s*\)\s*int\s+BPF_PROG\s*\(\s*(\w+)', text)
    if len(inventory) != len(C_HOOKS) or {hook for hook, _ in inventory} != C_HOOKS:
        errors.append("c:inventory")
    for hook in C_HOOKS:
        match = re.search(rf'SEC\s*\(\s*"lsm/{hook}"\s*\)\s*int\s+BPF_PROG\s*\(\s*\w+[^)]*\bint\s+ret\s*\)', text)
        if not match:
            errors.append(f"c:{hook}:signature")
            continue
        body = _code(_body(text, match.start()))
        compact = re.sub(r"\s+", "", body)
        if not compact.startswith("if(ret!=0)returnret;"):
            errors.append(f"c:{hook}:guard")
        returns = re.findall(r"\breturn\s+([^;]+);", body)
        if not returns or any(value.strip() != "ret" for value in returns):
            errors.append(f"c:{hook}:return")
        if re.search(r"\b(?:int|long|short|signed|unsigned)\s+ret\b|(?<!->)\bret\s*(?:<<|>>|[-+*/%&|^])?=|(?:\+\+|--)\s*ret\b|\bret\s*(?:\+\+|--)", body):
            errors.append(f"c:{hook}:ret_mutation")
        event_values = re.findall(r"\bevent->ret\s*=\s*([^;]+);", body)
        expected_event_count = 1 if hook in C_EVENT_RET_HOOKS else 0
        if len(event_values) != expected_event_count or any(value.strip() != "ret" for value in event_values):
            errors.append(f"c:{hook}:event_ret")
    return errors


def validate_policy(root: Path) -> list[str]:
    errors = []
    actual = set()
    for directory in ("schemas", "tools/detection_validation/fixtures", "tools/detection_validation/scripts", "tools/detection_validation/tests"):
        for path in (root / directory).rglob("anti_cheat_linux_bpf_lsm_prior_ret_source_v2*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                actual.add(path.relative_to(root).as_posix())
    if actual != CONTRACT_FILES:
        errors.append("contract:file_set")
    script_source = (root / SCRIPT_PATH).read_text(encoding="utf-8")
    tree = ast.parse(script_source)
    allowed = SHADOW_MODULES
    imports = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    if not imports <= allowed:
        errors.append("contract:dependencies")
    import_nodes = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    first_import = tree.body[0] if tree.body else None
    bootstrap_candidates = [
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Eq)
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "__main__"
    ]
    bootstrap = bootstrap_candidates[0] if bootstrap_candidates else None
    post_bootstrap_imports = [
        node
        for node in import_nodes
        if not (
            isinstance(node, ast.Import)
            and all(alias.name in {"sys", "nt", "posix"} for alias in node.names)
        )
    ]
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    shape = lambda node: ast.dump(node, include_attributes=False)
    realpath_functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_bootstrap_realpath"]
    realpath_function = realpath_functions[0] if len(realpath_functions) == 1 else None
    expected_windows_branch = ast.parse(
        "if sys.platform == 'win32':\n"
        "    return _bootstrap_fs._getfinalpathname(_bootstrap_fs._getfullpathname(entry)).lower()\n"
    ).body[0]
    windows_branch_is_bound = (
        realpath_function is not None
        and bool(realpath_function.body)
        and shape(realpath_function.body[0]) == shape(expected_windows_branch)
    )
    expected_readlink_try = ast.parse(
        "try:\n"
        "    target = _bootstrap_fs.readlink(candidate)\n"
        "except OSError:\n"
        "    resolved.append(component)\n"
        "    continue\n"
    ).body[0]
    readlink_tries = [
        node
        for node in (ast.walk(realpath_function) if realpath_function is not None else ())
        if isinstance(node, ast.Try) and shape(node) == shape(expected_readlink_try)
    ]
    readlink_try = readlink_tries[0] if len(readlink_tries) == 1 else None
    readlink_for = parents.get(readlink_try)
    readlink_while = parents.get(readlink_for)
    readlink_shape_is_bound = (
        isinstance(readlink_for, ast.For)
        and isinstance(readlink_while, ast.While)
        and parents.get(readlink_while) is realpath_function
    )
    expected_paths_loop = ast.parse(
        "for _expected in _expected_paths:\n"
        "    try:\n"
        "        _expected_realpaths.add(_bootstrap_realpath(_expected))\n"
        "    except OSError:\n"
        "        pass\n"
    ).body[0]
    expected_paths_loops = [
        node
        for node in (bootstrap.body if bootstrap is not None else ())
        if isinstance(node, ast.For) and shape(node) == shape(expected_paths_loop)
    ]
    expected_paths_loop_is_bound = len(expected_paths_loops) == 1
    expected_append = ast.parse("_trusted_sys_path.append(_real_entry)").body[0]
    append_statements = [node for node in ast.walk(tree) if isinstance(node, ast.Expr) and shape(node) == shape(expected_append)]
    append_statement = append_statements[0] if len(append_statements) == 1 else None
    append_guard = parents.get(append_statement)
    entry_loop = parents.get(append_guard)
    expected_append_condition = ast.parse(
        "_real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path",
        mode="eval",
    ).body
    expected_entry_try = ast.parse(
        "try:\n"
        "    _real_entry = _bootstrap_realpath(_entry)\n"
        "except OSError:\n"
        "    continue\n"
    ).body[0]
    entry_tries = [
        node
        for node in (entry_loop.body if isinstance(entry_loop, ast.For) else ())
        if isinstance(node, ast.Try) and shape(node) == shape(expected_entry_try)
    ]
    expected_entry_header = ast.parse("for _entry in tuple(sys.path):\n    pass\n").body[0]
    expected_empty_entry_guard = ast.parse("if not _entry:\n    continue\n").body[0]
    append_guard_is_bound = (
        isinstance(append_guard, ast.If)
        and shape(append_guard.test) == shape(expected_append_condition)
        and append_guard.body == [append_statement]
        and not append_guard.orelse
        and isinstance(entry_loop, ast.For)
        and shape(entry_loop.target) == shape(expected_entry_header.target)
        and shape(entry_loop.iter) == shape(expected_entry_header.iter)
        and not entry_loop.orelse
        and parents.get(entry_loop) is bootstrap
        and entry_loop in bootstrap.body
        and len(entry_loop.body) == 3
        and shape(entry_loop.body[0]) == shape(expected_empty_entry_guard)
        and len(entry_tries) == 1
        and entry_loop.body[1] is entry_tries[0]
        and entry_loop.body[-1] is append_guard
    )
    path_writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.ctx, ast.Store)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "sys"
        and node.value.attr == "path"
    ]
    path_write = path_writes[0] if len(path_writes) == 1 else None
    final_bootstrap_statement = bootstrap.body[-1] if bootstrap and bootstrap.body else None
    store_is_final_bootstrap_action = (
        path_write is not None
        and isinstance(path_write.slice, ast.Slice)
        and path_write.slice.lower is None
        and path_write.slice.upper is None
        and path_write.slice.step is None
        and isinstance(final_bootstrap_statement, ast.Assign)
        and len(final_bootstrap_statement.targets) == 1
        and final_bootstrap_statement.targets[0] is path_write
        and isinstance(final_bootstrap_statement.value, ast.Name)
        and final_bootstrap_statement.value.id == "_trusted_sys_path"
        and all(node.lineno > final_bootstrap_statement.end_lineno for node in post_bootstrap_imports)
    )
    if (
        not isinstance(first_import, ast.Import)
        or [alias.name for alias in first_import.names] != ["sys"]
        or bootstrap is None
        or not windows_branch_is_bound
        or not readlink_shape_is_bound
        or not expected_paths_loop_is_bound
        or not append_guard_is_bound
        or not store_is_final_bootstrap_action
    ):
        errors.append("contract:bootstrap")
    if len([node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr == "__spec__"]) != 1:
        errors.append("contract:provenance_shape")
    names = {"__import__", "open", "eval", "exec", "compile", "getattr", "setattr", "delattr", "vars", "globals", "locals", "input", "breakpoint", "system", "popen", "run", "Popen", "import_module"}
    attrs = {"open", "write_text", "write_bytes", "unlink", "replace", "rename", "touch", "mkdir", "rmdir", "chmod", "symlink_to", "hardlink_to", "system", "popen", "run", "Popen", "call", "import_module"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and (node.id in names or ((node.id.startswith("__") or node.id.endswith("__")) and node.id not in {"__file__", "__name__"})):
            errors.append("contract:dynamic_reference")
            break
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and (node.attr in attrs or ((node.attr.startswith("__") or node.attr.endswith("__")) and node.attr != "__spec__")):
            errors.append("contract:dynamic_reference")
            break
        if isinstance(node, ast.Call) and not isinstance(node.func, (ast.Name, ast.Attribute)):
            errors.append("contract:dynamic_call")
            break
    return errors


def validate_import_provenance() -> list[str]:
    errors = []
    base = _bootstrap_realpath(sys.base_prefix).rstrip("\\/")
    separator = "\\" if sys.platform == "win32" else "/"
    provenance_modules = STDLIB_MODULES | ({"nt"} if sys.platform == "win32" else {"posix"})
    for module_name in sorted(provenance_modules):
        module = sys.modules[module_name]
        spec = module.__spec__
        origin = spec.origin if spec else None
        if origin in {"built-in", "frozen"}:
            continue
        if not isinstance(origin, str):
            errors.append(f"provenance:{module_name}")
            continue
        resolved = _bootstrap_realpath(origin)
        lowered = resolved.lower()
        if (resolved != base and not resolved.startswith(base + separator)) or "site-packages" in lowered or "dist-packages" in lowered:
            errors.append(f"provenance:{module_name}")
    return errors


def validate_shadow_modules(root: Path) -> list[str]:
    errors = []
    script_directory = root / "tools/detection_validation/scripts"
    for module_name in sorted(SHADOW_MODULES):
        module_files = list(script_directory.rglob(f"{module_name}.py"))
        package_files = list(script_directory.rglob(f"{module_name}/__init__.py"))
        if module_files or package_files:
            errors.append(f"shadow:{module_name}")
    return errors


def expected_receipt() -> dict:
    return {
        "schema_version": 2, "evidence_class": "static_source_contract", "observed_at": OBSERVED_AT, "capability_state": "source_observe_only_v2",
        "sources": {
            "rust": {"path": RUST_PATH, "sha256": RUST_SHA256, "hooks": sorted(RUST_INDICES)},
            "c": {"path": C_PATH, "sha256": C_SHA256, "hooks": sorted(C_HOOKS)},
            "rust_prior_ret_indices": RUST_INDICES,
        },
        "historical_v1": {"fixture_path": V1_FIXTURE_PATH, "fixture_sha256": V1_SHA256, "rust_source_sha256": "2a387e9c66cf1e5c64c9304f655fa068a7339420a939d22f085e8b3df345b812", "c_source_sha256": "d60f1773f39961268eee325991885ca383e3793100fccaf09b2b376e9d9d3590", "relation": "supersedes_assessment_only"},
        "assessment": {"prior_lsm_decision_preserved": True, "new_denial_introduced": False},
        "lifecycle": LIFECYCLE,
        "claims": {key: False for key in CLAIM_NAMES},
        "blockers": BLOCKERS,
    }


def validate_receipt(receipt: dict) -> list[str]:
    errors = []
    if not isinstance(receipt, dict) or set(receipt) != TOP:
        return ["receipt:closed"]
    expected = expected_receipt()
    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"receipt:{key}")
    return errors


def validate_schema(root: Path) -> list[str]:
    schema = load_json(root / SCHEMA_PATH)
    errors = []
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" or schema.get("$id") != "https://tamandua.local/schemas/anti_cheat_linux_bpf_lsm_prior_ret_source_v2.schema.json" or schema.get("type") != "object":
        errors.append("schema:identity")
    if schema.get("additionalProperties") is not False or set(schema.get("required", [])) != TOP or set(schema.get("properties", {})) != TOP:
        errors.append("schema:closed")
    properties = schema.get("properties", {})
    constants = {"schema_version": 2, "evidence_class": "static_source_contract", "capability_state": "source_observe_only_v2", "blockers": BLOCKERS}
    if any(properties.get(key, {}).get("const") != value for key, value in constants.items()):
        errors.append("schema:constants")
    observed = properties.get("observed_at", {})
    if observed != {"const": OBSERVED_AT}:
        errors.append("schema:observed_at")
    if properties.get("sources") != {"$ref": "#/$defs/sources"}:
        errors.append("schema:sources:reference")
    if properties.get("historical_v1") != {"$ref": "#/$defs/historical"}:
        errors.append("schema:historical:reference")

    expected_nested = {
        "assessment": (ASSESSMENT_FIELDS, {"prior_lsm_decision_preserved": True, "new_denial_introduced": False}),
        "lifecycle": (set(LIFECYCLE), LIFECYCLE),
        "claims": (CLAIM_NAMES, {key: False for key in CLAIM_NAMES}),
    }
    for label, (fields, expected) in expected_nested.items():
        value = properties.get(label, {})
        nested_properties = value.get("properties", {})
        if value.get("additionalProperties") is not False or set(value.get("required", [])) != fields or set(nested_properties) != fields:
            errors.append(f"schema:{label}:closed")
        if any(nested_properties.get(key, {}).get("const") != item for key, item in expected.items()):
            errors.append(f"schema:{label}:constants")

    source_def = schema.get("$defs", {}).get("source", {})
    if source_def.get("additionalProperties") is not False or set(source_def.get("required", [])) != SOURCE_FIELDS or set(source_def.get("properties", {})) != SOURCE_FIELDS:
        errors.append("schema:source:closed")
    expected_sources = expected_receipt()["sources"]
    sources = schema.get("$defs", {}).get("sources", {})
    source_properties = sources.get("properties", {})
    if sources.get("additionalProperties") is not False or set(sources.get("required", [])) != {"rust", "c", "rust_prior_ret_indices"} or set(source_properties) != {"rust", "c", "rust_prior_ret_indices"}:
        errors.append("schema:sources:closed")
    for label in ("rust", "c"):
        all_of = source_properties.get(label, {}).get("allOf", [])
        if len(all_of) != 2 or all_of[0] != {"$ref": "#/$defs/source"}:
            errors.append(f"schema:source:{label}:binding")
            continue
        bound = all_of[1].get("properties", {})
        expected = expected_sources[label]
        if set(bound) != SOURCE_FIELDS or any(bound.get(key, {}).get("const") != value for key, value in expected.items()):
            errors.append(f"schema:source:{label}:binding")
    index_schema = source_properties.get("rust_prior_ret_indices", {})
    index_properties = index_schema.get("properties", {})
    if index_schema.get("additionalProperties") is not False or set(index_schema.get("required", [])) != set(RUST_INDICES) or set(index_properties) != set(RUST_INDICES) or any(index_properties.get(key, {}).get("const") != value for key, value in RUST_INDICES.items()):
        errors.append("schema:sources:indices")

    historical = schema.get("$defs", {}).get("historical", {})
    historical_properties = historical.get("properties", {})
    expected_historical = expected_receipt()["historical_v1"]
    if historical.get("additionalProperties") is not False or set(historical.get("required", [])) != HISTORICAL_FIELDS or set(historical_properties) != HISTORICAL_FIELDS:
        errors.append("schema:historical:closed")
    if any(historical_properties.get(key, {}).get("const") != value for key, value in expected_historical.items()):
        errors.append("schema:historical:constants")
    return errors


def run_gate(root: Path = ROOT) -> dict:
    failures = {}
    paths = validate_paths(root)
    if paths:
        failures["paths"] = paths
    else:
        rust = (root / RUST_PATH).read_text(encoding="utf-8")
        c = (root / C_PATH).read_text(encoding="utf-8")
        checks = {
            "hashes": [label for label, path, expected in (("rust", RUST_PATH, RUST_SHA256), ("c", C_PATH, C_SHA256), ("v1", V1_FIXTURE_PATH, V1_SHA256)) if sha256(root / path) != expected],
            "rust_shape": validate_rust_shape(rust),
            "c_shape": validate_c_shape(c),
            "contract": validate_policy(root),
            "provenance": validate_import_provenance(),
            "shadows": validate_shadow_modules(root),
            "schema": validate_schema(root),
            "fixture": validate_receipt(load_json(root / FIXTURE_PATH)),
        }
        failures = {key: value for key, value in checks.items() if value}
    return {"ok": not failures, "evidence_class": "static_source_contract", "failures": failures, "blockers": BLOCKERS}


def main() -> int:
    result = run_gate()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
