"""Adversarial source-only tests. No Swift, XPC, ES client, or agent is run."""

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_macos_endpoint_security_single_client_source_v2_gate.py"
EXPECTED_GATE_SHA256 = "2e1630880d8dd9480a23c00699db40085f5c997df53e99690a155adda74d0acb"
assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest() == EXPECTED_GATE_SHA256
SPEC = importlib.util.spec_from_file_location("macos_single_client_v2_gate", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(GATE)


def copy_scope(tmp_path):
    for relative in GATE.CONTRACT_FILES | set(GATE.SOURCE_HASHES):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def write_receipt(root, mutate):
    path = root / GATE.FIXTURE_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def mutate_text(root, relative, old, new):
    path = root / relative
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def shape_fail(tmp_path, relative, old, new, expected):
    copy_scope(tmp_path)
    mutate_text(tmp_path, relative, old, new)
    errors = GATE.validate_shapes(tmp_path)
    assert expected in errors


def test_detached_gate_authority_is_checked_before_import():
    text = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert text.index("hashlib.sha256(SCRIPT.read_bytes())") < text.index("spec_from_file_location")
    assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest() == EXPECTED_GATE_SHA256


def test_current_source_receipt_passes_but_never_claims_runtime():
    result = GATE.run_gate(ROOT)
    assert result == {
        "ok": True,
        "evidence_class": "static_source_single_client_inventory",
        "capability_state": "source_single_client_observe_only_unproven",
        "runtime_state": "not_executed",
        "blockers": GATE.BLOCKERS,
        "failures": {},
    }
    assert len(result["blockers"]) == 21


def test_exact_source_order_roles_hashes_and_inventory_digest():
    receipt = GATE.load_json(ROOT / GATE.FIXTURE_PATH)
    assert receipt["sources"] == GATE.expected_sources()
    assert receipt["inventory_digest"] == GATE.inventory_digest(receipt["sources"])
    assert list(GATE.SOURCE_HASHES) == list(GATE.ROLES)


@pytest.mark.parametrize("relative", list(GATE.SOURCE_HASHES))
def test_every_bound_source_byte_drift_fails_closed(tmp_path, relative):
    copy_scope(tmp_path)
    path = tmp_path / relative
    path.write_bytes(path.read_bytes() + b"\n")
    assert relative in GATE.run_gate(tmp_path)["failures"]["source_hashes"]


@pytest.mark.parametrize("field", ["schema_version", "evidence_class", "capability_state", "runtime_state", "blockers", "topology"])
def test_closed_receipt_contract_drift_fails(tmp_path, field):
    copy_scope(tmp_path)
    write_receipt(tmp_path, lambda value: value.__setitem__(field, "drift"))
    assert "contract" in GATE.run_gate(tmp_path)["failures"]


@pytest.mark.parametrize("section,key", [("lifecycle", key) for key in GATE.LIFECYCLE_KEYS] + [("claims", key) for key in GATE.CLAIM_KEYS])
def test_no_lifecycle_or_claim_can_be_promoted(tmp_path, section, key):
    copy_scope(tmp_path)
    write_receipt(tmp_path, lambda value: value[section].__setitem__(key, True))
    assert "contract" in GATE.run_gate(tmp_path)["failures"]


@pytest.mark.parametrize("mutation", ["path", "role", "hash", "order", "digest"])
def test_inventory_mutation_fails(tmp_path, mutation):
    copy_scope(tmp_path)
    def change(value):
        if mutation == "path": value["sources"][0]["path"] += ".escape"
        elif mutation == "role": value["sources"][0]["role"] = "spoof"
        elif mutation == "hash": value["sources"][0]["sha256"] = "0" * 64
        elif mutation == "order": value["sources"].reverse()
        else: value["inventory_digest"] = "0" * 64
    write_receipt(tmp_path, change)
    failures = GATE.run_gate(tmp_path)["failures"]
    assert "source_hashes" in failures or "inventory_digest" in failures


def test_schema_relaxation_and_duplicate_schema_keys_fail(tmp_path):
    copy_scope(tmp_path)
    mutate_text(tmp_path, GATE.SCHEMA_PATH, '"additionalProperties": false', '"additionalProperties": true')
    assert "schema_authority" in GATE.run_gate(tmp_path)["failures"]
    copy_scope(tmp_path)
    path = tmp_path / GATE.SCHEMA_PATH
    path.write_text(path.read_text(encoding="utf-8").replace("{", '{"$schema":"duplicate",', 1), encoding="utf-8")
    assert "document" in GATE.run_gate(tmp_path)["failures"]


def test_duplicate_fixture_key_and_extra_property_fail(tmp_path):
    copy_scope(tmp_path)
    path = tmp_path / GATE.FIXTURE_PATH
    path.write_text(path.read_text(encoding="utf-8").replace("{", '{"schema_version":2,', 1), encoding="utf-8")
    assert "document" in GATE.run_gate(tmp_path)["failures"]
    copy_scope(tmp_path)
    write_receipt(tmp_path, lambda value: value.__setitem__("extra", False))
    assert "contract" in GATE.run_gate(tmp_path)["failures"]


@pytest.mark.parametrize("relative", [
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist",
    "deploy/installers/macos/entitlements.plist",
    "apps/tamandua_gui/src-tauri/Info.plist",
])
def test_duplicate_plist_keys_fail(tmp_path, relative):
    copy_scope(tmp_path)
    path = tmp_path / relative
    text = path.read_text(encoding="utf-8")
    key = next(iter(GATE.load_plist_unique(path)))
    path.write_text(text.replace("</dict>", f"<key>{key}</key><string>spoof</string></dict>", 1), encoding="utf-8")
    assert "document" in GATE.run_gate(tmp_path)["failures"]


@pytest.mark.parametrize("kind", ["hidden", "nested", "alternate_suffix"])
def test_recursive_contract_file_set_is_closed(tmp_path, kind):
    copy_scope(tmp_path)
    scripts = tmp_path / "tools/detection_validation/scripts"
    if kind == "hidden": path = scripts / ("." + GATE.STEM + ".py")
    elif kind == "nested": path = scripts / "nested" / (GATE.STEM + "_helper.py")
    else: path = scripts / (GATE.STEM + ".json")
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text("", encoding="utf-8")
    assert "file_set" in GATE.run_gate(tmp_path)["failures"]


def test_symlink_and_path_escape_are_rejected(tmp_path):
    copy_scope(tmp_path)
    target = tmp_path / GATE.SCHEMA_PATH
    outside = tmp_path.parent / (tmp_path.name + "-outside.json")
    shutil.copy2(target, outside); target.unlink()
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert GATE.SCHEMA_PATH in GATE.run_gate(tmp_path)["failures"]["paths"]


@pytest.mark.parametrize("name", ["ast.py", "json.py", "hashlib.py", "pathlib.py", "plistlib.py", "re.py", "stat.py"])
def test_recursive_sibling_stdlib_module_shadow_is_rejected(tmp_path, name):
    copy_scope(tmp_path)
    path = tmp_path / "tools/detection_validation/scripts/nested" / name
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text("MARKER=True", encoding="utf-8")
    assert "import_shadow" in GATE.run_gate(tmp_path)["failures"]


def test_recursive_package_shadow_is_rejected(tmp_path):
    copy_scope(tmp_path)
    path = tmp_path / "tools/detection_validation/scripts/json/__init__.py"
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text("MARKER=True", encoding="utf-8")
    assert "import_shadow" in GATE.run_gate(tmp_path)["failures"]


def test_cli_sanitizes_pythonpath_before_shadowable_imports(tmp_path):
    shadow = tmp_path / "shadow"; shadow.mkdir()
    marker = tmp_path / "executed"
    (shadow / "json.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n", encoding="utf-8")
    environment = dict(os.environ); environment["PYTHONPATH"] = str(shadow)
    completed = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=20)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not marker.exists()


def test_import_provenance_drift_fails(monkeypatch):
    monkeypatch.setattr(GATE.json, "__file__", str(ROOT / "json.py"))
    assert "import_provenance:json" in GATE._stdlib_provenance_errors()


@pytest.mark.parametrize("old,new", [
    ('import sys', 'import sys\nimport os'),
    ('sys.path[:] = [entry for entry in sys.path if _trusted_cli_path(entry)]', 'pass'),
    ('if __name__ == "__main__":', 'if False:'),
])
def test_gate_bootstrap_self_policy_rejects_mutation(tmp_path, old, new):
    copy_scope(tmp_path)
    mutate_text(tmp_path, GATE.SCRIPT_PATH, old, new)
    assert "gate_policy" in GATE.run_gate(tmp_path)["failures"]


def test_comment_string_raw_string_and_nested_comment_tokens_are_ignored():
    sample = '''// es_respond_auth_result ES_EVENT_TYPE_AUTH_OPEN\n/* outer /* nested es_mute_path */ done */\nlet a = "allowed isAuth"\nlet b = #"setBlocking es_respond"#\nlet c = """fallback Connected"""\nES_EVENT_TYPE_NOTIFY_OPEN\n'''
    clean = GATE.executable_text(sample)
    assert "AUTH" not in clean and "es_mute" not in clean and "fallback" not in clean
    assert clean.count("ES_EVENT_TYPE_NOTIFY_OPEN") == 1


@pytest.mark.parametrize("path,old,new,error", [
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift", "ES_EVENT_TYPE_NOTIFY_OPEN,", "ES_EVENT_TYPE_AUTH_OPEN,", "shape:notify_exact_seven"),
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift", "isRunning = true", "_ = es_mute_path_literal(client!, \"/\")\nisRunning = true", "shape:no_auth_respond_or_mutator"),
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift", "isRunning = true", "es_respond_auth_result(client!, nil, ES_AUTH_RESULT_ALLOW, false)\nisRunning = true", "shape:no_auth_respond_or_mutator"),
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift", "func ping(reply:", "func setBlocking(reply:", "shape:xpc_exact_read_only_surface"),
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift", "guard (1...256).contains(limit) else", "guard (0...999).contains(limit) else", "shape:limit_before_dequeue"),
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift", "newConnection.setCodeSigningRequirement(requirement)", "newConnection.resume()\nnewConnection.setCodeSigningRequirement(requirement)", "shape:peer_gate_order"),
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift", "requirement == expected ? expected : nil", "requirement", "shape:exact_peer_requirement"),
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift", "eventQueue.recordDrop()", "_ = error", "shape:queue_drop_accounting"),
    ("apps/tamandua_agent/src/collectors/mod.rs", "pub mod sysext_bridge;", "pub mod endpoint_security;\npub mod sysext_bridge;", "shape:rust_direct_es_reachability"),
    ("apps/tamandua_agent/src/collectors/sysext_bridge.rs", "Err(SysExtBridgeError::TransportNotImplemented)", "Ok(())", "shape:bridge_fail_closed"),
    ("apps/tamandua_agent/src/collectors/sysext_bridge.rs", "TransportNotImplemented", "Connected", "shape:bridge_no_fallback_or_mutator"),
    ("apps/tamandua_agent/build.rs", "framework=Security", "framework=EndpointSecurity", "shape:rust_direct_es_reachability"),
    ("deploy/installers/macos/create-dmg.sh", 'BUNDLE_ID="com.tamandua.edr"', 'BUNDLE_ID="com.tamandua.agent"', "shape:bundle_identity_verifier"),
    ("deploy/installers/macos/create-dmg.sh", 'error "No .systemextension bundle found under ${sysext_root}"', 'log "No .systemextension bundle found under ${sysext_root}"', "shape:bundle_embedding_required"),
    ("apps/tamandua_agent/src/collectors/macos/capabilities.rs", "state: CapabilityState::Unavailable", "state: CapabilityState::Ready", "shape:capability_transport_fail_closed"),
    ("apps/tamandua_agent/src/collectors/status.rs", 'code: "transport_not_implemented"', 'code: "connected"', "shape:status_bridge_fail_closed"),
    ("apps/tamandua_agent/src/config/mod.rs", "sysext_bridge_enabled: false", "sysext_bridge_enabled: true", "shape:config_macos_default_off"),
    ("apps/tamandua_agent/src/collectors/health.rs", 'connected: false', 'connected: true', "shape:health_fail_closed:connected: false"),
    ("apps/tamandua_gui/src-tauri/Info.plist", "NSSystemExtensionUsageDescription", "UnrelatedDescription", "shape:host_usage_description_intent"),
    ("apps/tamandua_gui/src-tauri/tauri.conf.json", '"minimumSystemVersion": "10.15"', '"minimumSystemVersion": "14.0"', "shape:host_identity_and_minimum_mismatch_bound"),
    ("apps/tamandua_agent/src/collectors/catalog.rs", "// Retired direct-daemon path retained as non-operational metadata.\n        CollectorMaturity::Experimental", "// Retired direct-daemon path retained as non-operational metadata.\n        CollectorMaturity::Stable", "shape:catalog_non_operational_maturity"),
])
def test_executable_source_mutations_fail_shape(tmp_path, path, old, new, error):
    shape_fail(tmp_path, path, old, new, error)


def test_peer_requirement_rejects_wildcard_extra_clause_and_wrong_team_shape():
    raw = (ROOT / "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift").read_text(encoding="utf-8")
    assert '!requirement.contains("*")' in raw
    assert "team.count == 10" in raw
    assert "requirement == expected ? expected : nil" in raw
    assert "setCodeSigningRequirement(requirement)" in raw


@pytest.mark.parametrize("replacement", [
    'identifier "com.tamandua.agent" and anchor apple generic and certificate leaf[subject.OU] = "*"',
    'identifier "com.tamandua.agent" and anchor apple generic and certificate leaf[subject.OU] = "ABCDEFGHIJ" or true',
    'identifier "com.tamandua.agent" and anchor apple generic and certificate leaf[subject.OU] = "SHORT"',
])
def test_peer_requirement_intent_rejects_wildcard_extra_clause_or_bad_team(tmp_path, replacement):
    copy_scope(tmp_path)
    path = tmp_path / "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist"
    text = path.read_text(encoding="utf-8")
    original = 'identifier "com.tamandua.agent" and anchor apple generic and certificate leaf[subject.OU] = "$(DEVELOPMENT_TEAM)"'
    path.write_text(text.replace(original, replacement), encoding="utf-8")
    assert "shape:peer_requirement_build_intent" in GATE.validate_shapes(tmp_path)


def test_shell_comment_and_inert_string_cannot_spoof_bundle_identity(tmp_path):
    copy_scope(tmp_path)
    path = tmp_path / "deploy/installers/macos/create-dmg.sh"
    text = path.read_text(encoding="utf-8")
    text = text.replace('BUNDLE_ID="com.tamandua.edr"', '# BUNDLE_ID="com.tamandua.edr"\nSPOOF=\'BUNDLE_ID="com.tamandua.edr"\'')
    path.write_text(text, encoding="utf-8")
    assert "shape:bundle_identity_verifier" in GATE.validate_shapes(tmp_path)


@pytest.mark.parametrize("relative,key", [
    ("deploy/installers/macos/entitlements.plist", "com.apple.developer.endpoint-security.client"),
    ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist", "com.apple.developer.system-extension.install"),
])
def test_entitlement_cross_placement_or_extra_key_fails(tmp_path, relative, key):
    copy_scope(tmp_path)
    path = tmp_path / relative
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("</dict>", f"<key>{key}</key><true/></dict>"), encoding="utf-8")
    assert any("entitlements" in item for item in GATE.validate_shapes(tmp_path))


def test_early_boot_intent_fails(tmp_path):
    copy_scope(tmp_path)
    path = tmp_path / "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("</dict>", "<key>NSEndpointSecurityEarlyBoot</key><true/></dict>", 1), encoding="utf-8")
    assert "shape:extension_point_no_early_boot" in GATE.validate_shapes(tmp_path)


def test_v1_authority_files_are_not_part_of_v2_write_surface():
    assert not any("topology_gap" in path for path in GATE.CONTRACT_FILES | set(GATE.SOURCE_HASHES))
