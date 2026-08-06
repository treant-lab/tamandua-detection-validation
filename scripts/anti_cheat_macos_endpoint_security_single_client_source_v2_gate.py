#!/usr/bin/env python3
"""Fail-closed source authority. It never attests build, signing, or runtime."""

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
    # Remove cwd, the script directory, PYTHONPATH and third-party paths before
    # importing any module that can be shadowed by workspace content.
    sys.path[:] = [entry for entry in sys.path if _trusted_cli_path(entry)]

import ast
import hashlib
import json
import pathlib
import plistlib
import re
import stat

ROOT = pathlib.Path(__file__).resolve().parents[3]
STEM = "anti_cheat_macos_endpoint_security_single_client_source_v2"
SCHEMA_PATH = f"schemas/{STEM}.schema.json"
FIXTURE_PATH = f"tools/detection_validation/fixtures/{STEM}.json"
SCRIPT_PATH = f"tools/detection_validation/scripts/{STEM}_gate.py"
TEST_PATH = f"tools/detection_validation/tests/test_{STEM}_gate.py"
CONTRACT_FILES = {SCHEMA_PATH, FIXTURE_PATH, SCRIPT_PATH, TEST_PATH}
SCHEMA_SHA256 = "f6bca86f852d2c0ac38684f2163e3918f5b0ceba2424700d7ea6d0fe58a1a159"
SOURCE_HASHES = {
    "apps/tamandua_agent/build.rs": "d55e6fc281a89e2ba933d062aacbd50e257afb58dec28324979aa1c286c83df4",
    "apps/tamandua_agent/SystemExtension/Package.swift": "ef5a99e1c4c4a1d2dbdf2e18e20a67efa78b580ebf21a9e903cc347399063ba3",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift": "e122f227532d9bb1f1d1942752a08c238c5360a4bbc0773578145c34ce05bdb1",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/TamanduaFileMonitor.swift": "fd63ffd4c012884906f7dc8ace9a0a7ff4299a5b011cae8deab6541640b1dcc7",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift": "b8812fa33bddf0ad4b1dd1408c2a3a1e2207a174a7d80b933bde28f868df9445",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist": "29d6c34c9cee8ccf9f8dcc4c10b5c6af29cb80b1de35fc2cd543f3583539b74e",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist": "b7294df000248b8b2081e041832afa16a3fa5fa7727a8391a1275bface1f705f",
    "apps/tamandua_agent/SystemExtension/Tests/ESClientTests.swift": "63f3e00a8021279a696a773a356f629f6ccf0c7a12b9152ea71f90e9d58e6493",
    "apps/tamandua_agent/SystemExtension/Tests/XPCServerTests.swift": "31aec75ba1083a06cc01e884e8a1da516b29f4e07850c6b5389d61fd94a5205c",
    "apps/tamandua_agent/src/collectors/mod.rs": "7d8aaaa7f6877a24f60a8889683ad8b3c8cedba235af71e168184b7df03001cb",
    "apps/tamandua_agent/src/collectors/sysext_bridge.rs": "625427ae23c214dcb79b386e216c756290fe64068b503b4b73dea8b51c722072",
    "apps/tamandua_agent/src/collectors/endpoint_security.rs": "96d95313d3cf2d84de59dcb90f77610ba14eee6de5ab764727cdf06595adb93d",
    "apps/tamandua_agent/tests/unit/collectors/endpoint_security.rs": "6b7bef4e5943c8d05f75eb30407c91c1a194125801cac79a271cbe0abbbfd76b",
    "apps/tamandua_agent/src/collectors/macos/capabilities.rs": "51ef78f8d008590aa699ca0905b788cd877573cbd550603eee76837716438b9e",
    "apps/tamandua_agent/src/collectors/status.rs": "f3922b176bb19105d7f174cb80aac34e0050c410fc634a78f8e3141cdd72a473",
    "apps/tamandua_agent/src/config/mod.rs": "f2ad43d3f68374a7bcc9e9fca440866a9bc74d361c9b9a594ffc9c52de31aa33",
    "apps/tamandua_agent/src/collectors/health.rs": "19d798d623326776a02eee336dc74b5f21a693cc3abee05870336b9bdbe90372",
    "apps/tamandua_agent/tests/macos_endpoint_health_tests.rs": "6b2c82ec80f4c8bd06844dbfe205c81efed1faffcd46d6422c5413025bb04337",
    "apps/tamandua_gui/src-tauri/Info.plist": "a829d6b813a036684ddc7a70f707fa2d1ee30e91a57f25b47d1093c82d92e8fd",
    "apps/tamandua_gui/src-tauri/tauri.conf.json": "d9f735f877120e55d8f79e791febaecd2bc2057cf886c3238ac832b1e30fd987",
    "apps/tamandua_agent/src/collectors/catalog.rs": "552d2202ff0a34b4d6d786668671f19442e6c01a30da82982c403b66c6225696",
    "deploy/installers/macos/entitlements.plist": "d275d432077dd645887f85bb9d038650029136d931be7ad8b1f9764a67c33873",
    "deploy/installers/macos/create-dmg.sh": "322a20cd3073e59a39668b973f8e3df9ca33971e6fcbba3217d7a25a038360b2",
    "docs/architecture/adr/ADR-0002-macos-endpoint-security-single-client.md": "590fbaad17e8b475f7fbc100985a55edccdf59297f3a29c30ad18bb8f0611b81",
}
ROLES = {
    "apps/tamandua_agent/build.rs": "rust_build_topology",
    "apps/tamandua_agent/SystemExtension/Package.swift": "swiftpm_harness",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift": "sole_es_client",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/TamanduaFileMonitor.swift": "sysext_entrypoint",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift": "read_only_xpc_server",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist": "sysext_info_intent",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist": "sysext_entitlements_intent",
    "apps/tamandua_agent/SystemExtension/Tests/ESClientTests.swift": "swift_es_source_tests",
    "apps/tamandua_agent/SystemExtension/Tests/XPCServerTests.swift": "swift_xpc_source_tests",
    "apps/tamandua_agent/src/collectors/mod.rs": "rust_collector_registry",
    "apps/tamandua_agent/src/collectors/sysext_bridge.rs": "rust_read_only_bridge",
    "apps/tamandua_agent/src/collectors/endpoint_security.rs": "dormant_direct_es_source",
    "apps/tamandua_agent/tests/unit/collectors/endpoint_security.rs": "direct_es_import_regression",
    "apps/tamandua_agent/src/collectors/macos/capabilities.rs": "macos_fail_closed_capabilities",
    "apps/tamandua_agent/src/collectors/status.rs": "collector_fail_closed_status",
    "apps/tamandua_agent/src/config/mod.rs": "collector_compatibility_config",
    "apps/tamandua_agent/src/collectors/health.rs": "macos_fail_closed_health",
    "apps/tamandua_agent/tests/macos_endpoint_health_tests.rs": "macos_health_status_regression",
    "apps/tamandua_gui/src-tauri/Info.plist": "host_usage_metadata_intent",
    "apps/tamandua_gui/src-tauri/tauri.conf.json": "host_tauri_bundle_config",
    "apps/tamandua_agent/src/collectors/catalog.rs": "catalog_non_operational_maturity",
    "deploy/installers/macos/entitlements.plist": "host_entitlements_intent",
    "deploy/installers/macos/create-dmg.sh": "bundle_topology_verifier",
    "docs/architecture/adr/ADR-0002-macos-endpoint-security-single-client.md": "architecture_decision",
}
BLOCKERS = [
    "xcode_systemextension_target_absent", "host_embed_phase_absent", "host_activation_api_absent",
    "host_deactivation_api_absent", "host_macos_minimum_below_sysext_requirement",
    "swift_compile_not_validated", "xpc_api_availability_not_validated",
    "signed_peer_identifier_unobserved", "signed_entitlements_unobserved", "apple_es_grant_unobserved",
    "provisioning_unobserved", "fda_unobserved", "sign_not_validated",
    "notarization_gatekeeper_not_validated", "install_activate_not_validated", "xpc_runtime_not_validated",
    "es_runtime_not_validated", "telemetry_not_validated", "performance_efficacy_not_validated",
    "update_rollback_not_rehearsed", "release_decision_not_approved",
]
LIFECYCLE_KEYS = ("build", "sign", "notarize", "package", "install", "activate", "connect", "subscribe", "fda", "runtime", "telemetry", "performance_efficacy", "update_rollback")
CLAIM_KEYS = ("capability_proven", "observe_only_proven", "product_ready", "production_ready", "external_claim_allowed")
NOTIFY_NAMES = ("OPEN", "CREATE", "EXEC", "WRITE", "CLOSE", "RENAME", "UNLINK")
STDLIB_MODULES = ("ast", "hashlib", "json", "pathlib", "plistlib", "re", "stat")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)


def load_plist_unique(path):
    raw = path.read_bytes()
    # plistlib silently accepts duplicate keys, so reject them before parsing.
    keys = re.findall(br"<key>\s*([^<]+?)\s*</key>", raw)
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate plist key")
    return plistlib.loads(raw)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory_digest(sources):
    text = "\n".join(f"{item['role']}|{item['path']}|{item['sha256']}" for item in sources)
    return hashlib.sha256(text.encode()).hexdigest()


def safe_file(root, relative):
    path = root / relative
    try:
        mode = path.lstat().st_mode
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    return path if stat.S_ISREG(mode) and not path.is_symlink() else None


def expected_sources():
    return [{"path": path, "role": ROLES[path], "sha256": SOURCE_HASHES[path]} for path in SOURCE_HASHES]


def executable_text(text):
    """Mask Swift/Rust/C comments and strings while preserving token spacing."""
    out = []
    index = 0
    block_depth = 0
    length = len(text)
    while index < length:
        if block_depth:
            if text.startswith("/*", index):
                block_depth += 1; out.extend("  "); index += 2
            elif text.startswith("*/", index):
                block_depth -= 1; out.extend("  "); index += 2
            else:
                out.append("\n" if text[index] == "\n" else " "); index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end < 0 else end
            out.extend(" " * (end - index)); index = end; continue
        if text.startswith("/*", index):
            block_depth = 1; out.extend("  "); index += 2; continue
        raw = re.match(r'#+"""|#+"|"""|"', text[index:])
        if raw:
            opener = raw.group(0)
            hashes = opener.count("#")
            triple = '"""' in opener
            closer = ('"""' if triple else '"') + ("#" * hashes)
            out.extend(" " * len(opener)); index += len(opener)
            while index < length:
                if text.startswith(closer, index):
                    out.extend(" " * len(closer)); index += len(closer); break
                if not hashes and not triple and text[index] == "\\" and index + 1 < length:
                    out.extend("  "); index += 2; continue
                out.append("\n" if text[index] == "\n" else " "); index += 1
            continue
        out.append(text[index]); index += 1
    if block_depth:
        raise ValueError("unterminated block comment")
    return "".join(out)


def _stdlib_provenance_errors():
    errors = []
    base = pathlib.Path(sys.base_prefix).resolve()
    for name in STDLIB_MODULES:
        module = sys.modules.get(name)
        origin = getattr(module, "__file__", None)
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
    scripts = root / "tools/detection_validation/scripts"
    errors = []
    if not scripts.is_dir():
        return ["shadow_scan_root"]
    for path in scripts.rglob("*"):
        name = path.name.casefold()
        for module in STDLIB_MODULES:
            if name in {module + ".py", module}:
                errors.append(str(path.relative_to(root)).replace("\\", "/"))
    return sorted(set(errors))


def _gate_policy_errors(root):
    errors = []
    try:
        tree = ast.parse((root / SCRIPT_PATH).read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as error:
        return [f"parse:{error}"]
    imports = []
    path_writes = 0
    forbidden_calls = {"eval", "exec", "compile", "open", "__import__", "setattr", "delattr", "breakpoint"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            errors.append("import_from")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
            errors.append("dynamic_call:" + node.func.id)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute) and isinstance(target.value.value, ast.Name) and target.value.value.id == "sys" and target.value.attr == "path":
                    path_writes += 1
    if imports != ["sys", *STDLIB_MODULES]: errors.append("imports")
    if path_writes != 1: errors.append("sys_path_write")
    main_guards = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__" and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Eq) and len(node.test.comparators) == 1 and isinstance(node.test.comparators[0], ast.Constant) and node.test.comparators[0].value == "__main__":
            main_guards += 1
    if main_guards != 2: errors.append("main_guards")
    top_import_lines = [node.lineno for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    path_write_lines = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute) and target.value.attr == "path" for target in node.targets)]
    if not top_import_lines or not path_write_lines or not (top_import_lines[0] < path_write_lines[0] < top_import_lines[1]):
        errors.append("bootstrap_order")
    return sorted(set(errors))


def validate_shapes(root):
    errors = []
    read = lambda rel: (root / rel).read_text(encoding="utf-8")
    build_raw = read("apps/tamandua_agent/build.rs")
    build = executable_text(build_raw)
    registry = executable_text(read("apps/tamandua_agent/src/collectors/mod.rs"))
    bridge = executable_text(read("apps/tamandua_agent/src/collectors/sysext_bridge.rs"))
    es_raw = read("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift")
    es = executable_text(es_raw)
    entry = executable_text(read("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/TamanduaFileMonitor.swift"))
    xpc_raw = read("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift")
    xpc = executable_text(xpc_raw)
    package_raw = read("apps/tamandua_agent/SystemExtension/Package.swift")
    package = executable_text(package_raw)
    deploy_raw = read("deploy/installers/macos/create-dmg.sh")
    direct_test = executable_text(read("apps/tamandua_agent/tests/unit/collectors/endpoint_security.rs"))
    capabilities_raw = read("apps/tamandua_agent/src/collectors/macos/capabilities.rs")
    status_raw = read("apps/tamandua_agent/src/collectors/status.rs")
    config_raw = read("apps/tamandua_agent/src/config/mod.rs")
    health_raw = read("apps/tamandua_agent/src/collectors/health.rs")
    catalog_raw = read("apps/tamandua_agent/src/collectors/catalog.rs")
    adr = read("docs/architecture/adr/ADR-0002-macos-endpoint-security-single-client.md")

    if any(es.count(f"ES_EVENT_TYPE_NOTIFY_{name}") != 2 for name in NOTIFY_NAMES):
        errors.append("shape:notify_exact_seven")
    forbidden_es = ("ES_EVENT_TYPE_AUTH_", "es_respond", "es_mute", "es_unmute", "es_clear_cache", "es_invert_muting", "es_mute_path", "es_mute_process")
    if any(token in es + entry + xpc for token in forbidden_es):
        errors.append("shape:no_auth_respond_or_mutator")
    if any(token in es + entry + xpc for token in ("blockingEnabled", "setBlocking", "setMuted", "dequeueAll", "isAuth", "allowed")):
        errors.append("shape:notify_wire_only")
    if len(re.findall(r"\bes_subscribe\s*\(", es)) != 1 or len(re.findall(r"\bes_new_client\s*\(", es)) != 1 or len(re.findall(r"\bes_delete_client\s*\(", es)) != 2:
        errors.append("shape:es_lifecycle_source")
    if "catch { eventQueue.recordDrop() }" not in xpc_raw or "stats.droppedEvents + eventQueue.droppedCount" not in xpc_raw:
        errors.append("shape:queue_drop_accounting")
    if "guard (1...256).contains(limit) else" not in xpc_raw or xpc.index("guard (1...256).contains(limit) else") > xpc.index("eventQueue.dequeue(limit: limit)"):
        errors.append("shape:limit_before_dequeue")

    methods = ("func getEvents(limit:", "func getStats(reply:", "func getHealth(reply:", "func ping(reply:")
    if any(xpc_raw.count(method) != 2 for method in methods):
        errors.append("shape:xpc_exact_read_only_surface")
    if any(token in xpc for token in ("func set", "func mutate", "func block", "func respond", "func configure")):
        errors.append("shape:xpc_mutator_surface")
    prefix = 'identifier \\"com.tamandua.agent\\" and anchor apple generic and certificate leaf[subject.OU] = \\"'
    if xpc_raw.count(prefix) != 1 or "team.count == 10" not in xpc_raw or "requirement == expected ? expected : nil" not in xpc_raw:
        errors.append("shape:exact_peer_requirement")
    ordered = ("exactPeerRequirement()", "setCodeSigningRequirement(requirement)", "exportedInterface =", "exportedObject = self", "newConnection.resume()")
    try:
        positions = [xpc_raw.index(token, xpc_raw.index("shouldAcceptNewConnection")) for token in ordered]
        if positions != sorted(positions): errors.append("shape:peer_gate_order")
    except ValueError:
        errors.append("shape:peer_gate_order")

    info = load_plist_unique(root / "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist")
    sysext = load_plist_unique(root / "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist")
    host = load_plist_unique(root / "deploy/installers/macos/entitlements.plist")
    host_info = load_plist_unique(root / "apps/tamandua_gui/src-tauri/Info.plist")
    tauri = load_json(root / "apps/tamandua_gui/src-tauri/tauri.conf.json")
    if sysext != {"com.apple.developer.endpoint-security.client": True}:
        errors.append("shape:sysext_minimal_entitlements")
    if host != {"com.apple.developer.system-extension.install": True}:
        errors.append("shape:host_minimal_entitlements")
    usage = host_info.get("NSSystemExtensionUsageDescription")
    if set(host_info) != {"NSSystemExtensionUsageDescription"} or not isinstance(usage, str) or not usage.strip():
        errors.append("shape:host_usage_description_intent")
    bundle = tauri.get("tauri", {}).get("bundle", {})
    if bundle.get("identifier") != "com.tamandua.edr" or bundle.get("macOS", {}).get("minimumSystemVersion") != "10.15":
        errors.append("shape:host_identity_and_minimum_mismatch_bound")
    if info.get("CFBundleIdentifier") != "com.tamandua.agent.sysext.filemonitor" or info.get("LSMinimumSystemVersion") != "14.0":
        errors.append("shape:sysext_identity_macos14")
    if info.get("NSExtension", {}).get("NSExtensionPointIdentifier") != "com.apple.system-extension.endpoint-security" or "NSEndpointSecurityEarlyBoot" in read("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist"):
        errors.append("shape:extension_point_no_early_boot")
    if info.get("TamanduaAllowedClientCodeSigningRequirement") != 'identifier "com.tamandua.agent" and anchor apple generic and certificate leaf[subject.OU] = "$(DEVELOPMENT_TEAM)"':
        errors.append("shape:peer_requirement_build_intent")

    if '.macOS("14.0")' not in package_raw or "EndpointSecurity" not in package_raw or "SystemExtensions" in package:
        errors.append("shape:swiftpm_macos14_harness")
    if "framework=EndpointSecurity" in build_raw or re.search(r"\b(?:mod|pub\s+mod|pub\s+use)\s+endpoint_security\b", registry) or "endpoint_security" in direct_test:
        errors.append("shape:rust_direct_es_reachability")
    if any(token in bridge for token in ("fallback", "Connected", "set_muted", "set_blocking", "is_auth", "allowed")):
        errors.append("shape:bridge_no_fallback_or_mutator")
    if bridge.count("TransportNotImplemented") < 6 or "MAX_EVENTS_PER_REQUEST: usize = 256" not in bridge or "Ok(Vec::new())" in bridge or "unwrap_or_default" in bridge:
        errors.append("shape:bridge_fail_closed")
    if any(token in capabilities_raw for token in ("no_endpoint_security", "EndpointSecurity framework is linked", "privileged_process", "geteuid")):
        errors.append("shape:capability_no_direct_es_inference")
    if "supported_by_build: false" not in capabilities_raw or "state: CapabilityState::Unavailable" not in capabilities_raw or 'name: "read_only_xpc_transport"' not in capabilities_raw or 'detail: "transport_not_implemented"' not in capabilities_raw:
        errors.append("shape:capability_transport_fail_closed")
    if 'name: "endpoint_security",\n            enabled: endpoint_security_enabled,\n            supported: false' not in status_raw or "fn endpoint_security_enabled(_config: &CollectorConfig) -> bool" not in status_raw:
        errors.append("shape:status_direct_es_unsupported")
    if 'name: "sysext_bridge",\n            enabled: sysext_bridge_enabled,\n            supported: false' not in status_raw or 'code: "transport_not_implemented"' not in status_raw or "status.state = CollectorState::Degraded" not in status_raw:
        errors.append("shape:status_bridge_fail_closed")
    if config_raw.count("endpoint_security_enabled: false") != 1 or config_raw.count("sysext_bridge_enabled: false") != 1:
        errors.append("shape:config_macos_default_off")
    if any(token in health_raw for token in ("ES_FRAMEWORK_PATH", "macos_service_state", "framework_available", 'Command::new("launchctl")')):
        errors.append("shape:health_no_framework_or_service_inference")
    for token in ('supported: false', 'loaded: false', 'connected: false', 'state: "unavailable"', 'entitlement_status: Some("unobserved"', 'feature_level: "source_single_client_observe_only_unproven"', 'last_error: Some("transport_not_implemented"'):
        if token not in health_raw: errors.append("shape:health_fail_closed:" + token)
    trivia = r'(?:\s|//[^\n]*(?:\n|$))*'
    endpoint_catalog = rf'platform_collector{trivia}\({trivia}"endpoint_security"{trivia},{trivia}CollectorPlatform::Macos{trivia},{trivia}CollectorCategory::Platform{trivia},{trivia}CollectorMaturity::Experimental{trivia},?{trivia}\)'
    bridge_catalog = rf'platform_collector{trivia}\({trivia}"sysext_bridge"{trivia},{trivia}CollectorPlatform::Macos{trivia},{trivia}CollectorCategory::ResponseReadiness{trivia},{trivia}CollectorMaturity::Experimental{trivia},?{trivia}\)'
    if not re.search(endpoint_catalog, catalog_raw) or not re.search(bridge_catalog, catalog_raw):
        errors.append("shape:catalog_non_operational_maturity")
    deploy_lines = [line.strip() for line in deploy_raw.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if deploy_lines.count('BUNDLE_ID="com.tamandua.edr"') != 1 or deploy_lines.count('if [[ "${sysext_bundle_identifier}" != "com.tamandua.agent.sysext.filemonitor" ]]; then') != 1:
        errors.append("shape:bundle_identity_verifier")
    if deploy_lines.count('if echo "${executable_entitlements}" | grep -q "com.apple.developer.endpoint-security.client"; then') != 1 or deploy_lines.count('if echo "${sysext_entitlements}" | grep -q "com.apple.developer.system-extension.install"; then') != 1:
        errors.append("shape:bundle_entitlement_verifier")
    if deploy_lines.count('if [[ "${found_sysext}" != "true" ]]; then') != 1 or deploy_lines.count('error "No .systemextension bundle found under ${sysext_root}"') != 1:
        errors.append("shape:bundle_embedding_required")
    for phrase in ("sole Endpoint Security", "read-only XPC consumer", "source-only", "runtime and release remain HOLD", "no ES muting"):
        if phrase not in adr: errors.append("shape:adr:" + phrase)
    return errors


def run_gate(root=ROOT):
    root = pathlib.Path(root)
    failures = {}
    for relative in CONTRACT_FILES | set(SOURCE_HASHES):
        if safe_file(root, relative) is None:
            failures.setdefault("paths", []).append(relative)
    if failures:
        failures["paths"].sort()
        return {"ok": False, "failures": failures, "blockers": BLOCKERS}

    unexpected = []
    for directory in (root / "schemas", root / "tools/detection_validation/fixtures", root / "tools/detection_validation/scripts", root / "tools/detection_validation/tests"):
        for path in directory.rglob("*"):
            relative = str(path.relative_to(root)).replace("\\", "/")
            if STEM in path.name and path.suffix in {".py", ".json"} and relative not in CONTRACT_FILES:
                unexpected.append(relative)
    if unexpected: failures["file_set"] = sorted(set(unexpected))
    shadows = _shadow_errors(root)
    if shadows: failures["import_shadow"] = shadows
    provenance = _stdlib_provenance_errors()
    if provenance: failures["import_provenance"] = provenance
    policy = _gate_policy_errors(root)
    if policy: failures["gate_policy"] = policy

    try:
        receipt = load_json(root / FIXTURE_PATH)
        load_json(root / SCHEMA_PATH)
        shapes = validate_shapes(root)
    except (OSError, ValueError, json.JSONDecodeError, plistlib.InvalidFileException) as error:
        failures["document"] = [str(error)]
        return {"ok": False, "failures": failures, "blockers": BLOCKERS}
    if digest(root / SCHEMA_PATH) != SCHEMA_SHA256:
        failures["schema_authority"] = ["sha256_drift"]
    sources = expected_sources()
    drift = [path for path, value in SOURCE_HASHES.items() if digest(root / path) != value]
    if receipt.get("sources") != sources or drift:
        failures["source_hashes"] = drift or ["receipt_drift"]
    if receipt.get("inventory_digest") != inventory_digest(sources):
        failures["inventory_digest"] = ["drift"]
    exact = {
        "schema_version": 2, "evidence_class": "static_source_single_client_inventory",
        "capability_state": "source_single_client_observe_only_unproven", "runtime_state": "not_executed",
        "topology": {"host_bundle_id": "com.tamandua.edr", "sysext_bundle_id": "com.tamandua.agent.sysext.filemonitor", "daemon_bundle_id": "com.tamandua.agent", "sole_es_client": "system_extension", "daemon_transport": "transport_not_implemented"},
        "lifecycle": {key: False for key in LIFECYCLE_KEYS}, "claims": {key: False for key in CLAIM_KEYS}, "blockers": BLOCKERS,
    }
    expected_keys = set(exact) | {"sources", "inventory_digest", "gate_authority"}
    if set(receipt) != expected_keys or any(receipt.get(key) != value for key, value in exact.items()):
        failures["contract"] = ["closed_state_drift"]
    authority = receipt.get("gate_authority", {})
    expected_authority = {"path": SCRIPT_PATH, "sha256": digest(root / SCRIPT_PATH), "trust_model": "detached_fixture_test_vcs_review_external_root_cli_not_self_authenticating", "cli_autonomously_authenticates": False, "coordinated_change_requires_external_review": True}
    if authority != expected_authority: failures["gate_authority"] = ["drift"]
    if shapes: failures["source_shapes"] = shapes
    return {"ok": not failures, "evidence_class": exact["evidence_class"], "capability_state": exact["capability_state"], "runtime_state": "not_executed", "blockers": BLOCKERS, "failures": failures}


if __name__ == "__main__":
    result = run_gate()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["ok"] else 1)
