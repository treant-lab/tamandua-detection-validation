#!/usr/bin/env python3
"""Fail-closed static authority for the macOS host lifecycle source slice."""

import sys


def _trusted_cli_path(entry):
    if not isinstance(entry, str) or not entry:
        return False
    normalized = entry.replace("\\", "/").rstrip("/").casefold()
    base = sys.base_prefix.replace("\\", "/").rstrip("/").casefold()
    return (
        (normalized == base or normalized.startswith(base + "/"))
        and "/site-packages" not in normalized
        and "/dist-packages" not in normalized
    )


if __name__ == "__main__":
    sys.path[:] = [entry for entry in sys.path if _trusted_cli_path(entry)]

import ast
import hashlib
import json
import pathlib
import plistlib
import re
import stat

ROOT = pathlib.Path(__file__).resolve().parents[3]
STEM = "anti_cheat_macos_system_extension_lifecycle_source_v3"
SCHEMA = f"schemas/{STEM}.schema.json"
FIXTURE = f"tools/detection_validation/fixtures/{STEM}.json"
SCRIPT = f"tools/detection_validation/scripts/{STEM}_gate.py"
TEST = f"tools/detection_validation/tests/test_{STEM}_gate.py"
FILES = {SCHEMA, FIXTURE, SCRIPT, TEST}
SCHEMA_SHA256 = "2c978d459a064a320eb30413aa93e9bd4fcf21a2d0b2971063c8b787505030fc"
SOURCES = {
    "apps/tamandua_gui/src-tauri/build.rs": "macos_target_gated_native_build",
    "apps/tamandua_gui/src-tauri/Cargo.toml": "host_manifest_native_build_dependency",
    "apps/tamandua_gui/src-tauri/tauri.conf.json": "host_identity_and_macos_floor",
    "apps/tamandua_gui/src-tauri/Info.plist": "host_system_extension_usage_intent",
    "apps/tamandua_gui/src-tauri/src/main.rs": "explicit_tauri_command_registration",
    "apps/tamandua_gui/src-tauri/src/commands.rs": "confirmed_fixed_lifecycle_commands",
    "apps/tamandua_gui/src-tauri/src/macos/mod.rs": "macos_lifecycle_module_boundary",
    "apps/tamandua_gui/src-tauri/src/macos/system_extension_lifecycle.rs": "fixed_abi_fail_closed_rust_boundary",
    "apps/tamandua_gui/src-tauri/src/macos/system_extension_bridge.m": "single_flight_systemextensions_bridge",
    "deploy/installers/macos/entitlements.plist": "host_install_entitlement_intent",
    "docs/architecture/adr/ADR-0003-macos-system-extension-lifecycle.md": "source_only_lifecycle_decision",
}
BLOCKERS = [
    "xcode_systemextension_target_absent", "host_embed_phase_absent",
    "swift_compile_not_validated", "xpc_api_availability_not_validated",
    "signed_peer_identifier_unobserved", "objc_compile_not_validated",
    "systemextensions_framework_link_not_validated", "native_callback_runtime_not_validated",
    "host_bundle_merge_not_validated", "extension_embedding_not_validated",
    "signed_entitlements_unobserved", "provisioning_unobserved", "sign_not_validated",
    "notarization_gatekeeper_not_validated", "install_not_validated",
    "activation_not_executed", "deactivation_not_executed", "user_approval_not_observed",
    "reboot_completion_not_observed", "apple_es_grant_unobserved", "fda_unobserved",
    "xpc_runtime_not_validated", "es_runtime_not_validated", "telemetry_not_validated",
    "update_rollback_not_rehearsed", "release_decision_not_approved",
]
LIFECYCLE = {key: False for key in (
    "native_compile", "framework_link", "bundle_merge", "embed", "sign", "install",
    "activate", "deactivate", "callback_runtime", "telemetry",
)}
CLAIMS = {"runtime_proven": False, "product_ready": False,
          "production_ready": False, "external_claim_allowed": False}
CONTRACT = {"host_id": "com.tamandua.edr",
            "extension_id": "com.tamandua.agent.sysext.filemonitor", "abi_version": 1,
            "minimum_macos": "14.0", "explicit_confirmation": True,
            "single_flight": True, "replacement": "strictly_newer_only",
            "completion_implies_runtime": False}
STDLIB = ("ast", "hashlib", "json", "pathlib", "plistlib", "re", "stat")


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)


def load_plist(path):
    raw = path.read_bytes()
    keys = re.findall(br"<key>\s*([^<]+?)\s*</key>", raw)
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate plist key")
    return plistlib.loads(raw)


def schema_errors(value, schema, location="$"):
    """Validate the deliberately small Draft 2020-12 schema vocabulary used here."""
    errors = []
    if "const" in schema and value != schema["const"]:
        errors.append(location + ":const")
    expected_type = schema.get("type")
    type_ok = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
    }.get(expected_type, True)
    if not type_ok:
        return errors + [location + ":type"]
    if isinstance(value, dict):
        required = schema.get("required", [])
        errors.extend(location + ":required:" + key for key in required if key not in value)
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errors.extend(location + ":additional:" + key for key in value if key not in properties)
        for key, item in value.items():
            if key in properties:
                errors.extend(schema_errors(item, properties[key], location + "." + key))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(location + ":minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(location + ":maxItems")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(schema_errors(item, schema["items"], f"{location}[{index}]"))
    if isinstance(value, str) and "pattern" in schema:
        if re.fullmatch(schema["pattern"], value) is None:
            errors.append(location + ":pattern")
    return errors


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_file(root, relative):
    path = root / relative
    try:
        mode = path.lstat().st_mode
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    return path if stat.S_ISREG(mode) and not path.is_symlink() else None


def source_rows(root):
    return [{"path": path, "role": role, "sha256": digest(root / path)}
            for path, role in SOURCES.items()]


def inventory_digest(rows):
    payload = "\n".join(f"{row['role']}|{row['path']}|{row['sha256']}" for row in rows)
    return hashlib.sha256(payload.encode()).hexdigest()


def _provenance_errors():
    errors = []
    base = pathlib.Path(sys.base_prefix).resolve()
    for name in STDLIB:
        origin = getattr(sys.modules.get(name), "__file__", None)
        if origin is None:
            continue
        try:
            resolved = pathlib.Path(origin).resolve(strict=True)
            resolved.relative_to(base)
        except (OSError, ValueError):
            errors.append(f"import_provenance:{name}")
            continue
        folded = str(resolved).replace("\\", "/").casefold()
        if "/site-packages/" in folded or "/dist-packages/" in folded:
            errors.append(f"import_provenance:{name}")
    return errors


def _shadow_errors(root):
    errors = []
    scripts = root / "tools/detection_validation/scripts"
    if not scripts.is_dir():
        return ["shadow_scan_root"]
    for path in scripts.rglob("*"):
        if path.name.casefold() in {name + ".py" for name in STDLIB} | set(STDLIB):
            errors.append(str(path.relative_to(root)).replace("\\", "/"))
    return sorted(set(errors))


def _policy_errors(root):
    try:
        policy_source = (root / SCRIPT).read_text(encoding="utf-8")
        tree = ast.parse(policy_source)
    except (OSError, SyntaxError) as error:
        return [f"parse:{error}"]
    errors, imports, path_writes, guards, declared_forbidden = [], [], 0, 0, None
    forbidden = {"eval", "exec", "compile", "open", "__import__", "setattr", "delattr",
                 "write_text", "write_bytes", "unlink", "rename", "mkdir", "rmdir"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            errors.append("import_from")
        elif isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else "")
            if name in forbidden:
                errors.append("dynamic_call:" + name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if (isinstance(target, ast.Name) and target.id == "forbidden"
                        and isinstance(node, ast.Assign) and isinstance(node.value, ast.Set)
                        and all(isinstance(item, ast.Constant) and isinstance(item.value, str)
                                for item in node.value.elts)):
                    declared_forbidden = {item.value for item in node.value.elts}
                if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute)
                        and isinstance(target.value.value, ast.Name)
                        and target.value.value.id == "sys" and target.value.attr == "path"):
                    path_writes += 1
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == "__main__"):
            guards += 1
    if imports != ["sys", *STDLIB]:
        errors.append("imports")
    if path_writes != 1:
        errors.append("sys_path_write")
    if guards != 2:
        errors.append("main_guards")
    expected_forbidden = {"eval", "exec", "compile", "open", "__import__", "setattr", "delattr",
                          "write_text", "write_bytes", "unlink", "rename", "mkdir", "rmdir"}
    if declared_forbidden != expected_forbidden:
        errors.append("bootstrap_policy")
    for token in ('sys.path[:] = [entry for entry in sys.path if _trusted_cli_path(entry)]',):
        if token not in policy_source:
            errors.append("bootstrap_policy")
    return sorted(set(errors))


def shapes(root=ROOT):
    read = lambda path: (root / path).read_text(encoding="utf-8")
    errors = []
    build, manifest = read(next(iter(SOURCES))), read("apps/tamandua_gui/src-tauri/Cargo.toml")
    config = load_json(root / "apps/tamandua_gui/src-tauri/tauri.conf.json")
    main = read("apps/tamandua_gui/src-tauri/src/main.rs")
    commands = read("apps/tamandua_gui/src-tauri/src/commands.rs")
    module = read("apps/tamandua_gui/src-tauri/src/macos/mod.rs")
    rust = read("apps/tamandua_gui/src-tauri/src/macos/system_extension_lifecycle.rs")
    objc = read("apps/tamandua_gui/src-tauri/src/macos/system_extension_bridge.m")
    adr = read("docs/architecture/adr/ADR-0003-macos-system-extension-lifecycle.md")
    host_info = load_plist(root / "apps/tamandua_gui/src-tauri/Info.plist")
    host_entitlements = load_plist(root / "deploy/installers/macos/entitlements.plist")
    bundle = config.get("tauri", {}).get("bundle", {})
    if (bundle.get("identifier"), bundle.get("macOS", {}).get("minimumSystemVersion")) != ("com.tamandua.edr", "14.0"):
        errors.append("shape:host_identity_macos14")
    if (build.count("CARGO_CFG_TARGET_OS") != 1 or 'Ok("macos")' not in build
            or build.count("framework=SystemExtensions") != 1 or "system_extension_bridge.m" not in build):
        errors.append("shape:target_gated_link")
    if 'cc = "1.0"' not in manifest:
        errors.append("shape:native_build_dependency")
    if set(host_info) != {"NSSystemExtensionUsageDescription"}:
        errors.append("shape:host_usage_description")
    if host_entitlements != {"com.apple.developer.system-extension.install": True}:
        errors.append("shape:host_install_entitlement")
    if module.strip() != "pub mod system_extension_lifecycle;":
        errors.append("shape:module_boundary")
    for name in ("get_macos_system_extension_lifecycle", "activate_macos_system_extension", "deactivate_macos_system_extension"):
        if main.count(f"commands::{name}") != 1 or commands.count(f"fn {name}") != 1:
            errors.append("shape:explicit_commands_only")
    if commands.count("confirmed: bool") != 2 or "bundle_id:" in commands[:3000]:
        errors.append("shape:explicit_commands_only")
    status_body = commands[commands.find("pub fn get_macos_system_extension_lifecycle"):
                           commands.find("#[command]", commands.find("pub fn get_macos_system_extension_lifecycle"))]
    if (status_body.count("system_extension_lifecycle::snapshot()") != 1
            or "request_activation" in status_body or "request_deactivation" in status_body):
        errors.append("shape:no_status_mutation")
    if 'SYSTEM_EXTENSION_ID: &str = "com.tamandua.agent.sysext.filemonitor"' not in rust or "ABI_VERSION: u32 = 1" not in rust:
        errors.append("shape:fixed_rust_id_abi")
    for token in ("return_code != 0", "raw.abi_version != ABI_VERSION", "_ => return None",
                  "InvalidSnapshot", "size_of::<NativeSnapshot>() == 216",
                  "align_of::<NativeSnapshot>() == 8", "offset_of!(NativeSnapshot, detail) == 24",
                  "position(|byte| *byte == 0)?", "from_utf8(&raw.detail[..end]).ok()?",
                  "valid_relation"):
        if token not in rust:
            errors.append("shape:rust_fail_closed_decode:" + token)
    if rust.count("runtime_proven: false") < 2 or rust.count("telemetry_proven: false") < 2:
        errors.append("shape:false_runtime_claims")
    if "#[cfg(target_os = \"macos\")]" not in rust or "#[cfg(not(target_os = \"macos\"))]" not in rust or "unsupported_platform" not in rust:
        errors.append("shape:platform_boundary")
    for token in ("TMD_EXTENSION_ID", "TMD_HOST_ID", "TMD_EXTENSION_RELATIVE_PATH",
                  "TMD_ABI_VERSION", "DISPATCH_QUEUE_SERIAL", "dispatch_once",
                  "[self inFlight]", "TMD_IN_FLIGHT", "NSOrderedDescending",
                  "_Static_assert(sizeof(tmd_sysext_snapshot_t) == 216",
                  "_Static_assert(_Alignof(tmd_sysext_snapshot_t) == 8",
                  "offsetof(tmd_sysext_snapshot_t, detail) == 24",
                  "request == self.request", "output->error = TMD_IN_FLIGHT",
                  "_snapshot.state != TMD_SUBMITTED",
                  "OSSystemExtensionRequestCompleted", "unknown_finish_result",
                  "scanUnsignedLongLong", "OSSystemExtensionErrorMissingEntitlement",
                  "OSSystemExtensionErrorAuthorizationRequired"):
        if token not in objc:
            errors.append("shape:objc:" + token)
    if "_snapshot.error=TMD_IN_FLIGHT" in objc.replace(" ", ""):
        errors.append("shape:single_flight_mutates_active_snapshot")
    if re.search(r"case\s+\d+\s*:\s*return\s+TMD_", objc):
        errors.append("shape:magic_error_codes")
    if objc.count("dispatch_async") != 0 or objc.count("dispatch_sync") != 2:
        errors.append("shape:serial_queue_ownership")
    if objc.count("if (![self isCurrentRequest:request])") < 3:
        errors.append("shape:stale_callback_guard")
    if "result == OSSystemExtensionRequestCompleted" not in objc or "else {" not in objc:
        errors.append("shape:finish_result_closed")
    if objc.count("submitRequest:") != 1 or "OSSystemExtensionErrorDomain" not in objc:
        errors.append("shape:single_submit_categorical_errors")
    if "NSOrderedDescending" not in objc or "OSSystemExtensionReplacementActionReplace" not in objc or objc.count("OSSystemExtensionReplacementActionCancel") < 2:
        errors.append("shape:strictly_newer_replacement")
    lifecycle_surface = commands[:commands.find("// ===")] + rust + objc
    if any(token in lifecycle_surface for token in ("systemextensionsctl", "openSystemSettings",
                                                     "sudo ", "osascript", "std::process::Command",
                                                     "relaunch", "retry", "restart", "helper")):
        errors.append("shape:no_lifecycle_helper_shell_settings")
    setup = main[main.find(".setup("):]
    if any(token in setup for token in ("request_activation", "request_deactivation", "activate_macos_system_extension", "deactivate_macos_system_extension")):
        errors.append("shape:no_setup_lifecycle_invocation")
    normalized_adr = " ".join(adr.split())
    for phrase in ("source-only lifecycle contract", "fixed extension identifier", "one request at a time",
                   "Completion means only", "runtime remains HOLD", "stale callbacks",
                   "ABI layout", "unknown callback results"):
        if phrase not in normalized_adr:
            errors.append("shape:adr:" + phrase)
    return sorted(set(errors))


def run_gate(root=ROOT):
    root = pathlib.Path(root)
    failures = {}
    for relative in FILES | set(SOURCES):
        if safe_file(root, relative) is None:
            failures.setdefault("paths", []).append(relative)
    if failures:
        failures["paths"].sort()
        return {"ok": False, "failures": failures, "blockers": BLOCKERS}
    expected_set = FILES
    unexpected = []
    for directory in (root / "schemas", root / "tools/detection_validation/fixtures",
                      root / "tools/detection_validation/scripts", root / "tools/detection_validation/tests"):
        for path in directory.rglob("*"):
            relative = str(path.relative_to(root)).replace("\\", "/")
            if STEM in path.name and "__pycache__" not in path.parts and relative not in expected_set:
                unexpected.append(relative)
    if unexpected:
        failures["file_set"] = sorted(set(unexpected))
    if _shadow_errors(root):
        failures["import_shadow"] = _shadow_errors(root)
    if _provenance_errors():
        failures["import_provenance"] = _provenance_errors()
    if _policy_errors(root):
        failures["gate_policy"] = _policy_errors(root)
    try:
        receipt, schema = load_json(root / FIXTURE), load_json(root / SCHEMA)
        shape_errors = shapes(root)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError,
            plistlib.InvalidFileException) as error:
        failures["document"] = [str(error)]
        return {"ok": False, "failures": failures, "blockers": BLOCKERS}
    if schema.get("properties", {}).get("schema_version", {}).get("const") != 3:
        failures["schema"] = ["unexpected_schema"]
    if digest(root / SCHEMA) != SCHEMA_SHA256:
        failures["schema"] = ["sha256_drift"]
    validation_errors = schema_errors(receipt, schema)
    if validation_errors:
        failures["schema_validation"] = validation_errors
    rows = source_rows(root)
    if receipt.get("sources") != rows:
        failures["source_hashes"] = [row["path"] for row in rows
                                      if row not in receipt.get("sources", [])] or ["receipt_drift"]
    if receipt.get("inventory_digest") != inventory_digest(rows):
        failures["inventory_digest"] = ["drift"]
    exact = {"schema_version": 3, "evidence_class": "static_source_host_lifecycle_inventory",
             "capability_state": "source_lifecycle_present_native_unvalidated",
             "runtime_state": "not_executed", "contract": CONTRACT,
             "lifecycle": LIFECYCLE, "claims": CLAIMS, "blockers": BLOCKERS}
    if set(receipt) != set(exact) | {"sources", "inventory_digest", "gate_authority"} or any(receipt.get(k) != v for k, v in exact.items()):
        failures["contract"] = ["closed_state_drift"]
    authority = {"path": SCRIPT, "sha256": digest(root / SCRIPT), "external_review_required": True}
    if receipt.get("gate_authority") != authority:
        failures["gate_authority"] = ["drift"]
    if shape_errors:
        failures["source_shapes"] = shape_errors
    return {"ok": not failures, "evidence_class": exact["evidence_class"],
            "capability_state": exact["capability_state"], "runtime_state": "not_executed",
            "blockers": BLOCKERS, "failures": failures}


if __name__ == "__main__":
    result = run_gate()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["ok"] else 1)
