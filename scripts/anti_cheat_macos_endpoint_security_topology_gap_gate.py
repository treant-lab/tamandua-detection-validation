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
import plistlib
import re
import stat
import xml.etree.ElementTree


Path = pathlib.Path
PurePosixPath = pathlib.PurePosixPath
ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = "schemas/anti_cheat_macos_endpoint_security_topology_gap_v1.schema.json"
FIXTURE_PATH = "tools/detection_validation/fixtures/anti_cheat_macos_endpoint_security_topology_gap_degraded.json"
SCRIPT_PATH = "tools/detection_validation/scripts/anti_cheat_macos_endpoint_security_topology_gap_gate.py"
TEST_PATH = "tools/detection_validation/tests/anti_cheat_macos_endpoint_security_topology_gap_test.py"
CONTRACT_FILES = {SCHEMA_PATH, FIXTURE_PATH, SCRIPT_PATH, TEST_PATH}
SOURCE_ROLES = {
    "apps/tamandua_agent/SystemExtension/Package.swift": "swiftpm_manifest",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift": "sysext_es_client",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist": "sysext_info_intent",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/TamanduaFileMonitor.swift": "sysext_entrypoint",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift": "sysext_xpc_server",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist": "sysext_entitlements_intent",
    "apps/tamandua_agent/src/collectors/endpoint_security.rs": "rust_direct_es_client",
    "apps/tamandua_agent/src/collectors/health.rs": "rust_macos_health",
    "apps/tamandua_agent/src/collectors/sysext_bridge.rs": "rust_sysext_bridge",
    "deploy/installers/macos/create-dmg.sh": "deploy_bundle_verifier",
    "deploy/installers/macos/entitlements.plist": "deploy_host_entitlements_intent",
}
SOURCE_HASHES = {
    "apps/tamandua_agent/SystemExtension/Package.swift": "845253566207a93259a2519ae812049201f430a81355cda4ab04994a91cd9518",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift": "c507ab2daeec26a581259aca4b9b37259bfeb9090c761c19e5a3d86d7a4bc3d7",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist": "b06f930da38c2b3c6051949c52fbc067e115dfc67e77b591757e0f13b9a0f11d",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/TamanduaFileMonitor.swift": "b468e807348550f2a84eed831114bb8376ec23ff860042082e3d86a846a5094d",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift": "97ffa3fc73a3e5f52c414a7b4d51aa7bbc745bf362fc06e28ea0df168e4d2501",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist": "d12ac4c9e85dcd80b9737b0fb8ff2f53b1f7395302e2cea4aae146b2c0d74cbd",
    "apps/tamandua_agent/src/collectors/endpoint_security.rs": "96d95313d3cf2d84de59dcb90f77610ba14eee6de5ab764727cdf06595adb93d",
    "apps/tamandua_agent/src/collectors/health.rs": "54c6c4c0d0e5f8c12d203c767ae794496256c71cea9daef8fe1675ea6a43e2a6",
    "apps/tamandua_agent/src/collectors/sysext_bridge.rs": "16ae26c72fb551ba5e9775de44446017d0c9275bea8bbd6b7b92295311180694",
    "deploy/installers/macos/create-dmg.sh": "e44c13539e492f82c9c1c257c094478df3b2a8f38077b20db45d24b54f01e777",
    "deploy/installers/macos/entitlements.plist": "ffe4f61b4c4de2079cb9063dc5a686e352bfe81440af258fc2a99a3484525f30",
}
INVENTORY_DIGEST = "cddba70bb16e7eb56d777ef773690216363ea6ae96c1d19c11468c659366d6f1"
BLOCKERS = ["host_app_bundle_topology_unbound", "swiftpm_executable_not_proven_systemextension", "package_embedding_not_validated", "entitlement_placement_unproven", "signed_entitlements_unobserved", "apple_endpoint_security_grant_unobserved", "observe_only_source_not_established", "auth_event_subscriptions_present", "auth_response_surface_present", "xpc_mutation_surface_present", "xpc_client_identity_validation_absent", "direct_es_and_sysext_architecture_unresolved", "sysext_bridge_transport_stub", "early_boot_policy_unjustified", "build_not_validated", "macos_host_not_observed", "activation_not_validated", "runtime_not_validated", "rollback_not_rehearsed"]
TOPOLOGY = {"host_app_bundle": "unbound", "extension_product": "swiftpm_executable_not_proven_systemextension", "extension_point_declared": True, "package_embedding_validated": False, "activation_api_present": False, "direct_es_client_present": True, "sysext_client_present": True, "single_privileged_architecture_selected": False, "xpc_transport_state": "stub_no_connection"}
ENTITLEMENT_INTENT = {"source_declared": True, "signed_artifact_observed": False, "provisioning_observed": False, "apple_grant_observed": False, "placement_assessment": "unproven"}
OBSERVE_XPC = {"observe_only_source_established": False, "auth_subscriptions_present": True, "auth_response_api_present": True, "blocking_control_present": True, "xpc_mutators_present": True, "xpc_client_identity_validation_present": False, "early_boot_policy_justified": False}
LIFECYCLE = {key: False for key in ("build", "sign", "notarize", "package", "install", "activate", "connect", "subscribe", "fda_mutation", "runtime", "telemetry", "efficacy", "rollback")}
CLAIMS = {key: False for key in ("capability_proven", "observe_only_proven", "product_ready", "production_ready", "external_claim_allowed")}
STDLIB_MODULES = (ast, hashlib, json, pathlib, plistlib, re, stat, xml, xml.etree.ElementTree)
RUN_GATE_AST_SHA256 = "6cc72e47fd8a76a8e7459cabda9c606903ffac2456a788b17c38394edd06c767"
GATE_TRUST_MODEL = "detached_fixture_test_vcs_review_external_root_cli_not_self_authenticating"


def reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory_digest(sources):
    canonical = "\n".join(f"{item['role']}|{item['path']}|{item['sha256']}" for item in sources)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_stdlib_provenance():
    errors = []
    base = _bootstrap_realpath(sys.base_prefix)
    separator = "\\" if sys.platform == "win32" else "/"
    for module in STDLIB_MODULES:
        origin = module.__file__
        if not origin:
            continue
        try:
            resolved = _bootstrap_realpath(origin)
        except OSError:
            errors.append("policy:stdlib_provenance")
            continue
        if resolved != base and not resolved.startswith(base + separator):
            errors.append("policy:stdlib_provenance")
        parts = resolved.split(separator)
        if any(part.lower() in {"site-packages", "dist-packages"} for part in parts):
            errors.append("policy:stdlib_provenance")
    return errors


def validate_regular_confined(root, relative):
    errors = []
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative:
        return [f"path:{relative}:lexical"]
    root_real = root.resolve(strict=True)
    candidate = root.joinpath(*pure.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return [f"path:{relative}:missing"]
    if resolved != root_real and root_real not in resolved.parents:
        errors.append(f"path:{relative}:confined")
    current = root
    for component in pure.parts:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError:
            errors.append(f"path:{relative}:missing")
            break
        attributes = metadata.st_file_attributes if sys.platform == "win32" else 0
        reparse_flag = stat.FILE_ATTRIBUTE_REPARSE_POINT if sys.platform == "win32" else 0
        if stat.S_ISLNK(metadata.st_mode) or attributes & reparse_flag:
            errors.append(f"path:{relative}:link")
            break
    try:
        mode = candidate.lstat().st_mode
        if not stat.S_ISREG(mode):
            errors.append(f"path:{relative}:regular")
    except OSError:
        pass
    return errors


def load_plist_unique(path):
    raw = path.read_bytes()
    tree = xml.etree.ElementTree.fromstring(raw)
    for dictionary in tree.iter("dict"):
        children = list(dictionary)
        keys = [children[index].text for index in range(0, len(children), 2) if children[index].tag == "key"]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate plist key")
    return plistlib.loads(raw)


def strip_noncode(source, preserve_strings=False):
    output = []
    index = 0
    length = len(source)
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = length if end < 0 else end
            continue
        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            index = end
            continue
        if source[index] == "#" and (index == 0 or source[index - 1] == "\n"):
            end = source.find("\n", index)
            index = length if end < 0 else end
            continue
        raw_match = re.match(r'(?:br|r)?(#+)?("""|")', source[index:])
        if raw_match:
            hashes = raw_match.group(1) or ""
            quote = raw_match.group(2)
            terminator = quote + hashes
            end = source.find(terminator, index + len(raw_match.group(0)))
            value = source[index:(length if end < 0 else end + len(terminator))]
            output.append(value if preserve_strings else '""')
            index += len(value)
            continue
        if source[index] in {'"', "'"}:
            quote = source[index]
            end = index + 1
            while end < length:
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            output.append(source[index:end] if preserve_strings else quote + quote)
            index = end
            continue
        output.append(source[index])
        index += 1
    return "".join(output)


def strip_shell_comments(source):
    output = []
    quote = ""
    index = 0
    while index < len(source):
        character = source[index]
        if character == "\\" and quote != "'":
            output.append(character)
            if index + 1 < len(source):
                output.append(source[index + 1])
                index += 2
                continue
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                quote = ""
            output.append(character)
            index += 1
            continue
        if character == "#" and not quote and (index == 0 or source[index - 1].isspace() or source[index - 1] in ";&|()"):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
            continue
        output.append(character)
        index += 1
    return "".join(output)


def strip_shell_heredocs(source):
    output = []
    pending = []
    pattern = re.compile(r"(?:^|[\s;&|()])<<(-)?\s*(?:'([^']+)'|\"([^\"]+)\"|\\([A-Za-z0-9_]+)|([A-Za-z0-9_]+))")
    for line in source.splitlines(keepends=True):
        if pending:
            delimiter, strip_tabs = pending[0]
            candidate = line.rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate == delimiter:
                pending.pop(0)
            output.append("\n" if line.endswith("\n") else "")
            continue
        executable = strip_shell_comments(line)
        for match in pattern.finditer(executable):
            delimiter = next(value for value in match.groups()[1:] if value is not None)
            pending.append((delimiter, match.group(1) == "-"))
        output.append(line)
    return "".join(output)


def validate_source_shapes(root):
    errors = []
    texts = {path: (root / path).read_text(encoding="utf-8") for path in SOURCE_ROLES if not path.endswith(".plist")}
    package = strip_noncode(texts["apps/tamandua_agent/SystemExtension/Package.swift"], True)
    if package.count(".executableTarget(") != 1 or not re.search(r'exclude\s*:\s*\[\s*"Info\.plist"\s*,\s*"entitlements\.plist"\s*\]', package):
        errors.append("shape:swiftpm_executable_and_excluded_plists")
    info = load_plist_unique(root / "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist")
    extension = info.get("NSExtension", {})
    if extension.get("NSExtensionPointIdentifier") != "com.apple.system-extension.endpoint-security" or info.get("NSEndpointSecurityEarlyBoot") is not True:
        errors.append("shape:extension_point_intent")
    for relative in ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist", "deploy/installers/macos/entitlements.plist"):
        entitlement = load_plist_unique(root / relative)
        if entitlement.get("com.apple.developer.endpoint-security.client") is not True or entitlement.get("com.apple.developer.system-extension.install") is not True:
            errors.append(f"shape:entitlement_intent:{relative}")
    entry = strip_noncode(texts["apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/TamanduaFileMonitor.swift"])
    for token in ("ESClient(eventHandler:", "XPCServer()", "onSetMutedPaths", "onSetBlockingEnabled"):
        if token not in entry:
            errors.append(f"shape:entrypoint:{token}")
    es_client = strip_noncode(texts["apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift"])
    for token in ("ES_EVENT_TYPE_AUTH_OPEN", "ES_EVENT_TYPE_AUTH_CREATE", "ES_EVENT_TYPE_AUTH_EXEC", "es_subscribe(", "es_respond_auth_result(", "ES_AUTH_RESULT_ALLOW", "setBlockingEnabled("):
        if token not in es_client:
            errors.append(f"shape:swift_es:{token}")
    xpc = strip_noncode(texts["apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift"])
    for token in ("shouldAcceptNewConnection", "setMutedPaths(", "setBlockingEnabled(", "newConnection.resume()", "return true"):
        if token not in xpc:
            errors.append(f"shape:xpc:{token}")
    if any(token in xpc for token in ("auditToken", "SecCode", "codeSigningRequirement", "effectiveUserIdentifier")):
        errors.append("shape:xpc_identity_validation_unexpected")
    direct = strip_noncode(texts["apps/tamandua_agent/src/collectors/endpoint_security.rs"])
    for label, token in (("es_new_client(", "let result = unsafe { es_new_client("), ("es_subscribe(", "let result = unsafe { es_subscribe("), ("es_respond_auth_result(", "es_respond_auth_result(client, message")):
        if token not in direct:
            errors.append(f"shape:direct_es:{label}")
    bridge = strip_noncode(texts["apps/tamandua_agent/src/collectors/sysext_bridge.rs"], True)
    if "async fn fetch_events_from_xpc" not in bridge or "Ok(Vec::new())" not in bridge or "NSXPCConnection" in strip_noncode(texts["apps/tamandua_agent/src/collectors/sysext_bridge.rs"]):
        errors.append("shape:sysext_bridge_stub")
    health = strip_noncode(texts["apps/tamandua_agent/src/collectors/health.rs"], True)
    if "EndpointSecurity.framework" not in health or "endpoint_security_sysext" not in health:
        errors.append("shape:dual_health_topology")
    deploy = strip_shell_comments(strip_shell_heredocs(texts["deploy/installers/macos/create-dmg.sh"]))
    for token in ("Contents/Library/SystemExtensions", "com.apple.developer.endpoint-security.client", "com.apple.developer.system-extension.install"):
        if token not in deploy:
            errors.append(f"shape:deploy_verifier:{token}")
    expected_find = 'done < <(find "${sysext_root}" -maxdepth 1 -type d -name "*.systemextension" -print0)'
    if deploy.count(expected_find) != 1:
        errors.append("shape:deploy_verifier:systemextension_find")
    executable_code = "\n".join(strip_noncode(value) for value in texts.values())
    if "OSSystemExtensionRequest" in executable_code or "activationRequest" in executable_code:
        errors.append("shape:activation_api_unexpected")
    return errors


def validate_schema_value(instance, schema, location="$"):
    errors = []
    if "const" in schema and (type(instance) is not type(schema["const"]) or instance != schema["const"]):
        errors.append(f"schema:{location}:const")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"schema:{location}:enum")
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(instance, dict):
            return errors + [f"schema:{location}:type"]
        required = schema.get("required", [])
        if any(key not in instance for key in required):
            errors.append(f"schema:{location}:required")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and any(key not in properties for key in instance):
            errors.append(f"schema:{location}:closed")
        for key, value in instance.items():
            if key in properties:
                errors.extend(validate_schema_value(value, properties[key], location + "." + key))
    elif kind == "array":
        if not isinstance(instance, list):
            return errors + [f"schema:{location}:type"]
        if len(instance) < schema.get("minItems", 0) or len(instance) > schema.get("maxItems", len(instance)):
            errors.append(f"schema:{location}:length")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in instance}) != len(instance):
            errors.append(f"schema:{location}:unique")
        for index, value in enumerate(instance):
            errors.extend(validate_schema_value(value, schema.get("items", {}), f"{location}[{index}]"))
    elif kind == "string":
        if not isinstance(instance, str):
            errors.append(f"schema:{location}:type")
        elif "pattern" in schema and not re.fullmatch(schema["pattern"], instance):
            errors.append(f"schema:{location}:pattern")
    return errors


def validate_schema_authority(schema):
    errors = []
    expected_root_keys = {"schema_version", "evidence_class", "capability_state", "runtime_state", "sources", "inventory_digest", "gate_authority", "topology", "entitlement_intent", "observe_xpc", "lifecycle", "claims", "blockers"}
    properties = schema.get("properties", {})
    expected_schema_keys = {"$schema", "$id", "title", "type", "additionalProperties", "required", "properties"}
    if set(schema) != expected_schema_keys or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" or schema.get("$id") != "https://tamandua.local/schemas/anti_cheat_macos_endpoint_security_topology_gap_v1.schema.json" or schema.get("title") != "Tamandua macOS Endpoint Security topology gap inventory v1" or schema.get("type") != "object" or schema.get("additionalProperties") is not False or set(schema.get("required", [])) != expected_root_keys or set(properties) != expected_root_keys:
        errors.append("schema_authority:root")
    expected_fixed = {"schema_version": 1, "evidence_class": "static_source_topology_inventory", "capability_state": "degraded_topology_unproven", "runtime_state": "not_executed", "topology": TOPOLOGY, "entitlement_intent": ENTITLEMENT_INTENT, "observe_xpc": OBSERVE_XPC, "lifecycle": LIFECYCLE, "claims": CLAIMS, "blockers": BLOCKERS}

    def check_fixed(value, node, location):
        if isinstance(value, dict):
            if set(node) != {"type", "additionalProperties", "required", "properties"} or node.get("type") != "object" or node.get("additionalProperties") is not False or set(node.get("required", [])) != set(value) or set(node.get("properties", {})) != set(value):
                errors.append(f"schema_authority:{location}:closed")
                return
            for key, child in value.items():
                check_fixed(child, node["properties"][key], location + "." + key)
        elif set(node) != {"const"} or type(node.get("const")) is not type(value) or node.get("const") != value:
            errors.append(f"schema_authority:{location}:const")

    for key, value in expected_fixed.items():
        check_fixed(value, properties.get(key, {}), key)
    sources = properties.get("sources", {})
    item = sources.get("items", {})
    item_properties = item.get("properties", {})
    expected_path = {"type": "string", "pattern": "^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$"}
    expected_role = {"enum": list(item_properties.get("role", {}).get("enum", []))}
    expected_sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    expected_digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    if set(sources) != {"type", "minItems", "maxItems", "uniqueItems", "items"} or sources.get("type") != "array" or sources.get("minItems") != 11 or sources.get("maxItems") != 11 or sources.get("uniqueItems") is not True or set(item) != {"type", "additionalProperties", "required", "properties"} or item.get("type") != "object" or item.get("additionalProperties") is not False or set(item.get("required", [])) != {"path", "role", "sha256"} or set(item_properties) != {"path", "role", "sha256"} or item_properties.get("path") != expected_path or set(item_properties.get("role", {})) != {"enum"} or set(expected_role["enum"]) != set(SOURCE_ROLES.values()) or len(expected_role["enum"]) != 11 or item_properties.get("sha256") != expected_sha or properties.get("inventory_digest") != expected_digest:
        errors.append("schema_authority:sources")
    gate_authority = properties.get("gate_authority", {})
    gate_properties = gate_authority.get("properties", {})
    expected_gate_keys = {"path", "sha256", "trust_model", "cli_autonomously_authenticates", "coordinated_change_requires_external_review"}
    if gate_authority.get("type") != "object" or gate_authority.get("additionalProperties") is not False or set(gate_authority.get("required", [])) != expected_gate_keys or set(gate_properties) != expected_gate_keys or gate_properties.get("path", {}).get("const") != SCRIPT_PATH or gate_properties.get("sha256") != expected_sha or gate_properties.get("trust_model", {}).get("const") != GATE_TRUST_MODEL or gate_properties.get("cli_autonomously_authenticates", {}).get("const") is not False or gate_properties.get("coordinated_change_requires_external_review", {}).get("const") is not True:
        errors.append("schema_authority:gate_authority")
    return errors


def validate_policy(root):
    errors = []
    actual = set()
    for directory in ("schemas", "tools/detection_validation/fixtures", "tools/detection_validation/scripts", "tools/detection_validation/tests"):
        for path in (root / directory).rglob("anti_cheat_macos_endpoint_security_topology_gap*"):
            if "__pycache__" not in path.parts and path.suffix != ".pyc":
                actual.add(path.relative_to(root).as_posix())
    if actual != CONTRACT_FILES:
        errors.append("policy:file_set")
    source = (root / SCRIPT_PATH).read_text(encoding="utf-8")
    tree = ast.parse(source)
    allowed = {"sys", "nt", "posix", "ast", "hashlib", "json", "pathlib", "plistlib", "re", "stat", "xml"}
    import_nodes = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    imports = {alias.name.split(".")[0] for node in import_nodes if isinstance(node, ast.Import) for alias in node.names} | {node.module.split(".")[0] for node in import_nodes if isinstance(node, ast.ImportFrom) and node.module}
    import_records = [(alias.name, alias.asname) for node in import_nodes if isinstance(node, ast.Import) for alias in node.names]
    expected_import_records = [("sys", None), ("nt", "_bootstrap_fs"), ("posix", "_bootstrap_fs"), ("ast", None), ("hashlib", None), ("json", None), ("pathlib", None), ("plistlib", None), ("re", None), ("stat", None), ("xml.etree.ElementTree", None)]
    if not imports <= allowed or any(isinstance(node, ast.ImportFrom) for node in import_nodes) or sorted(import_records) != sorted(expected_import_records):
        errors.append("policy:dependencies")
    first_import = tree.body[0] if tree.body else None
    expected_bootstrap = ast.parse(
        "if __name__ == '__main__':\n"
        "    _base = sys.base_prefix.rstrip('\\\\/')\n"
        "    _stdlib = _base + '\\\\Lib' if sys.platform == 'win32' else _base + '/lib/python' + str(sys.version_info.major) + '.' + str(sys.version_info.minor)\n"
        "    _expected_paths = [_stdlib]\n"
        "    _expected_paths.append(_base + '\\\\DLLs' if sys.platform == 'win32' else _stdlib + '/lib-dynload')\n"
        "    _expected_realpaths = set()\n"
        "    for _expected in _expected_paths:\n"
        "        try:\n"
        "            _expected_realpaths.add(_bootstrap_realpath(_expected))\n"
        "        except OSError:\n"
        "            pass\n"
        "    _trusted_sys_path = []\n"
        "    for _entry in tuple(sys.path):\n"
        "        if not _entry:\n"
        "            continue\n"
        "        try:\n"
        "            _real_entry = _bootstrap_realpath(_entry)\n"
        "        except OSError:\n"
        "            continue\n"
        "        if _real_entry in _expected_realpaths and _real_entry not in _trusted_sys_path:\n"
        "            _trusted_sys_path.append(_real_entry)\n"
        "    sys.path[:] = _trusted_sys_path\n"
    ).body[0]
    nonbootstrap_imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots = {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots = {node.module.split(".")[0]}
        else:
            continue
        if not roots <= {"sys", "nt", "posix"}:
            nonbootstrap_imports.append(node)
    first_nonbootstrap_import_line = min(node.lineno for node in nonbootstrap_imports)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    sys_path_alias_bindings = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
        else:
            continue
        if parents.get(node) is not tree and node.lineno >= first_nonbootstrap_import_line:
            continue
        references_path = any(isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == "sys" and child.attr == "path" for child in ast.walk(value))
        references_module = any(isinstance(child, ast.Name) and child.id == "sys" and not isinstance(parents.get(child), ast.Attribute) for child in ast.walk(value))
        if references_path or references_module:
            sys_path_alias_bindings.append(node)
    if sys_path_alias_bindings:
        errors.append("policy:sys_path_alias")
    bootstrap_candidates = [node for node in tree.body if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__" and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Eq) and len(node.test.comparators) == 1 and isinstance(node.test.comparators[0], ast.Constant) and node.test.comparators[0].value == "__main__"]
    bootstrap = bootstrap_candidates[0] if bootstrap_candidates else None
    sys_path_subscript_mutations = [node for node in ast.walk(tree) if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == "sys" and node.value.attr == "path"]
    sys_path_attribute_mutations = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr == "path"]
    sys_path_mutator_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse"} and isinstance(node.func.value, ast.Attribute) and isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "sys" and node.func.value.attr == "path"]
    trusted_name_mutations = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == "_trusted_sys_path"]
    trusted_subscript_mutations = [node for node in ast.walk(tree) if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name) and node.value.id == "_trusted_sys_path"]
    trusted_mutator_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse"} and isinstance(node.func.value, ast.Name) and node.func.value.id == "_trusted_sys_path"]
    final_bootstrap_statement = bootstrap.body[-1] if bootstrap and bootstrap.body else None
    bootstrap_is_canonical = (
        isinstance(first_import, ast.Import)
        and [alias.name for alias in first_import.names] == ["sys"]
        and len(tree.body) > 3
        and tree.body[3] is bootstrap
        and ast.dump(bootstrap, include_attributes=False) == ast.dump(expected_bootstrap, include_attributes=False)
        and len(sys_path_subscript_mutations) == 1
        and not sys_path_attribute_mutations
        and not sys_path_mutator_calls
        and len(trusted_name_mutations) == 1
        and not trusted_subscript_mutations
        and len(trusted_mutator_calls) == 1
        and all(node.lineno > final_bootstrap_statement.end_lineno for node in nonbootstrap_imports)
    )
    if not bootstrap_is_canonical:
        errors.append("policy:bootstrap_order")
    run_gate_functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_gate"]
    run_gate_function = run_gate_functions[0] if len(run_gate_functions) == 1 else None
    expected_failures_assign = ast.parse("failures = {}").body[0]
    expected_provenance_assign = ast.parse("provenance_errors = validate_stdlib_provenance()").body[0]
    expected_provenance_check = ast.parse("if provenance_errors:\n    failures['policy'] = provenance_errors\n").body[0]
    expected_policy_assign = ast.parse("policy_errors = validate_policy(root)").body[0]
    expected_policy_check = ast.parse("if policy_errors:\n    failures.setdefault('policy', []).extend(policy_errors)\n").body[0]
    expected_success_return = ast.parse("return {'ok': not failures, 'evidence_class': 'static_source_topology_inventory', 'blockers': BLOCKERS, 'failures': failures}").body[0]
    provenance_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "validate_stdlib_provenance"]
    policy_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "validate_policy"]
    run_gate_returns = [node for node in ast.walk(run_gate_function) if isinstance(node, ast.Return)] if run_gate_function is not None else []
    final_run_gate_return = run_gate_function.body[-1] if run_gate_function is not None and run_gate_function.body else None
    early_success_returns = []
    for return_node in run_gate_returns:
        if return_node is final_run_gate_return:
            continue
        value = return_node.value
        keys = value.keys if isinstance(value, ast.Dict) else []
        values = value.values if isinstance(value, ast.Dict) else []
        ok_values = [item for key, item in zip(keys, values) if isinstance(key, ast.Constant) and key.value == "ok"]
        if len(ok_values) != 1 or not isinstance(ok_values[0], ast.Constant) or ok_values[0].value is not False:
            early_success_returns.append(return_node)
    run_gate_digest = hashlib.sha256(ast.dump(run_gate_function, include_attributes=False).encode("utf-8")).hexdigest() if run_gate_function is not None else ""
    provenance_flow_is_canonical = (
        run_gate_function is not None
        and len(run_gate_function.body) == 24
        and ast.dump(run_gate_function.body[0], include_attributes=False) == ast.dump(expected_failures_assign, include_attributes=False)
        and ast.dump(run_gate_function.body[1], include_attributes=False) == ast.dump(expected_provenance_assign, include_attributes=False)
        and ast.dump(run_gate_function.body[2], include_attributes=False) == ast.dump(expected_provenance_check, include_attributes=False)
        and ast.dump(run_gate_function.body[-3], include_attributes=False) == ast.dump(expected_policy_assign, include_attributes=False)
        and ast.dump(run_gate_function.body[-2], include_attributes=False) == ast.dump(expected_policy_check, include_attributes=False)
        and ast.dump(run_gate_function.body[-1], include_attributes=False) == ast.dump(expected_success_return, include_attributes=False)
        and len(provenance_calls) == 1
        and isinstance(run_gate_function.body[1], ast.Assign)
        and isinstance(run_gate_function.body[1].value, ast.Call)
        and run_gate_function.body[1].value is provenance_calls[0]
        and len(policy_calls) == 1
        and isinstance(run_gate_function.body[-3], ast.Assign)
        and isinstance(run_gate_function.body[-3].value, ast.Call)
        and run_gate_function.body[-3].value is policy_calls[0]
        and not early_success_returns
        and not any(isinstance(node, ast.Raise) for node in ast.walk(run_gate_function))
        and run_gate_digest == RUN_GATE_AST_SHA256
    )
    if not provenance_flow_is_canonical:
        errors.append("policy:stdlib_provenance")
    banned_names = {"__import__", "eval", "exec", "compile", "getattr", "setattr", "delattr", "vars", "globals", "locals", "open", "input", "breakpoint", "system", "popen", "run", "Popen", "import_module"}
    banned_attrs = {"write_text", "write_bytes", "unlink", "replace", "rename", "touch", "mkdir", "rmdir", "chmod", "symlink_to", "hardlink_to", "system", "popen", "run", "Popen", "call", "import_module"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in banned_names:
            errors.append("policy:dynamic_or_write")
            break
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and (node.attr in banned_attrs or ((node.attr.startswith("__") or node.attr.endswith("__")) and node.attr != "__file__")):
            errors.append("policy:dynamic_or_write")
            break
        if isinstance(node, ast.Call) and not isinstance(node.func, (ast.Name, ast.Attribute)):
            errors.append("policy:dynamic_call")
            break
    return errors


def run_gate(root=ROOT):
    failures = {}
    provenance_errors = validate_stdlib_provenance()
    if provenance_errors:
        failures["policy"] = provenance_errors
    path_errors = []
    for relative in sorted(CONTRACT_FILES | set(SOURCE_ROLES)):
        path_errors.extend(validate_regular_confined(root, relative))
    if path_errors:
        return {"ok": False, "evidence_class": "static_source_topology_inventory", "blockers": BLOCKERS, "failures": {"paths": path_errors}}
    try:
        schema = load_json(root / SCHEMA_PATH)
        fixture = load_json(root / FIXTURE_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {"ok": False, "evidence_class": "static_source_topology_inventory", "blockers": BLOCKERS, "failures": {"document": ["invalid_json_document"]}}
    gate_authority = fixture.get("gate_authority")
    expected_gate_authority = {"path": SCRIPT_PATH, "sha256": sha256(root / SCRIPT_PATH), "trust_model": GATE_TRUST_MODEL, "cli_autonomously_authenticates": False, "coordinated_change_requires_external_review": True}
    if gate_authority != expected_gate_authority:
        failures["gate_authority"] = ["detached_gate_source_sha256_or_trust_model"]
    expected_sources = [{"path": path, "role": SOURCE_ROLES[path], "sha256": SOURCE_HASHES[path]} for path in sorted(SOURCE_ROLES)]
    if fixture.get("sources") != expected_sources or inventory_digest(expected_sources) != INVENTORY_DIGEST or fixture.get("inventory_digest") != INVENTORY_DIGEST:
        failures["inventory"] = ["exact_order_role_hash_digest"]
    hash_errors = [path for path in sorted(SOURCE_HASHES) if sha256(root / path) != SOURCE_HASHES[path]]
    if hash_errors:
        failures["hashes"] = hash_errors
    expected_fields = {"schema_version": 1, "evidence_class": "static_source_topology_inventory", "capability_state": "degraded_topology_unproven", "runtime_state": "not_executed", "topology": TOPOLOGY, "entitlement_intent": ENTITLEMENT_INTENT, "observe_xpc": OBSERVE_XPC, "lifecycle": LIFECYCLE, "claims": CLAIMS, "blockers": BLOCKERS}
    parity_errors = [key for key, value in expected_fields.items() if json.dumps(fixture.get(key), sort_keys=True) != json.dumps(value, sort_keys=True)]
    parity_errors.extend(validate_schema_value(fixture, schema))
    parity_errors.extend(validate_schema_authority(schema))
    if parity_errors:
        failures["contract"] = parity_errors
    try:
        shape_errors = validate_source_shapes(root)
    except (OSError, ValueError, plistlib.InvalidFileException, xml.etree.ElementTree.ParseError) as error:
        shape_errors = ["parse:invalid_source_document"]
    if shape_errors:
        failures["shapes"] = shape_errors
    policy_errors = validate_policy(root)
    if policy_errors:
        failures.setdefault("policy", []).extend(policy_errors)
    return {"ok": not failures, "evidence_class": "static_source_topology_inventory", "blockers": BLOCKERS, "failures": failures}


def main():
    result = run_gate(ROOT)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
