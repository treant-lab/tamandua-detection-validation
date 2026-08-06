import hashlib,importlib.util,json,pathlib,shutil
import sys
import pytest
ROOT=pathlib.Path(__file__).resolve().parents[3]
SCRIPT=ROOT/"tools/detection_validation/scripts/anti_cheat_macos_system_extension_lifecycle_source_v3_gate.py"
EXPECTED="d9a56f4c4c85b13955e3084b893e770306fd2738b76b702bff4d4b007b936ef0"
assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest()==EXPECTED
spec=importlib.util.spec_from_file_location("v3gate",SCRIPT);G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
def copy(tmp):
 for p in G.FILES|set(G.SOURCES):
  q=tmp/p;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/p,q)
def test_current_is_source_only_hold():
 r=G.run_gate();assert r["ok"] and r["runtime_state"]=="not_executed" and len(r["blockers"])==26
def test_every_source_is_immutable(tmp_path):
 copy(tmp_path)
 for p in G.SOURCES:
  q=tmp_path/p;original=q.read_bytes();q.write_bytes(original+b"\n")
  assert p in G.run_gate(tmp_path)["failures"]["source_hashes"];q.write_bytes(original)
@pytest.mark.parametrize("path,old,new,error",[
("apps/tamandua_gui/src-tauri/build.rs","CARGO_CFG_TARGET_OS","HOST","shape:target_gated_link"),
("apps/tamandua_gui/src-tauri/tauri.conf.json",'"14.0"','"10.15"',"shape:host_identity_macos14"),
("apps/tamandua_gui/src-tauri/src/commands.rs","confirmed: bool","bundle_id: String","shape:explicit_commands_only"),
("apps/tamandua_gui/src-tauri/src/macos/system_extension_bridge.m","NSOrderedDescending","NSOrderedSame","shape:objc:NSOrderedDescending"),
("apps/tamandua_gui/src-tauri/src/macos/system_extension_bridge.m","DISPATCH_QUEUE_SERIAL","DISPATCH_QUEUE_CONCURRENT","shape:objc:DISPATCH_QUEUE_SERIAL")])
def test_adversarial_shapes(tmp_path,path,old,new,error):
 copy(tmp_path);q=tmp_path/path;text=q.read_text();assert old in text;q.write_text(text.replace(old,new));assert error in G.shapes(tmp_path)
def test_claim_promotion_fails(tmp_path):
 copy(tmp_path);p=tmp_path/G.FIXTURE;d=json.loads(p.read_text());d["claims"]["runtime_proven"]=True;p.write_text(json.dumps(d));assert "contract" in G.run_gate(tmp_path)["failures"]

def test_schema_authority_is_pinned(tmp_path):
 copy(tmp_path);p=tmp_path/G.SCHEMA;p.write_bytes(p.read_bytes()+b"\n");assert "schema" in G.run_gate(tmp_path)["failures"]

def test_duplicate_json_is_rejected(tmp_path):
 copy(tmp_path);p=tmp_path/G.FIXTURE;text=p.read_text();p.write_text(text.replace('"schema_version": 3,','"schema_version": 3, "schema_version": 3,',1));assert "document" in G.run_gate(tmp_path)["failures"]

def test_recursive_contract_file_set_is_closed(tmp_path):
 copy(tmp_path);p=tmp_path/"tools/detection_validation/scripts/nested"/(G.STEM+"_shadow.py");p.parent.mkdir();p.write_text("pass");assert "file_set" in G.run_gate(tmp_path)["failures"]

def test_recursive_contract_file_set_rejects_non_json_python_suffix(tmp_path):
 copy(tmp_path);p=tmp_path/"schemas/nested"/(G.STEM+".txt");p.parent.mkdir();p.write_text("shadow");assert "file_set" in G.run_gate(tmp_path)["failures"]

def test_symlinked_source_is_rejected(tmp_path):
 copy(tmp_path);source=next(iter(G.SOURCES));p=tmp_path/source;backup=tmp_path/"outside";backup.write_bytes(p.read_bytes());p.unlink()
 try:p.symlink_to(backup)
 except OSError:pytest.skip("symlink creation unavailable")
 assert source in G.run_gate(tmp_path)["failures"]["paths"]

def test_detached_hash_precedes_import_and_import_preserves_path():
 text=pathlib.Path(__file__).read_text();assert text.index("assert hashlib.sha256") < text.index("exec_module(G)")
 before=list(sys.path);spec=importlib.util.spec_from_file_location("v3gate_again",SCRIPT);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);assert sys.path==before

def test_schema_is_applied_to_receipt_not_only_pinned(tmp_path):
 copy(tmp_path);p=tmp_path/G.FIXTURE;value=json.loads(p.read_text());value["unexpected"]=False;p.write_text(json.dumps(value));assert "schema_validation" in G.run_gate(tmp_path)["failures"]

@pytest.mark.parametrize("relative", [
 "apps/tamandua_gui/src-tauri/Info.plist",
 "deploy/installers/macos/entitlements.plist",
])
def test_duplicate_plist_keys_are_rejected(tmp_path,relative):
 copy(tmp_path);p=tmp_path/relative;text=p.read_text();key="NSSystemExtensionUsageDescription" if "Info.plist" in relative else "com.apple.developer.system-extension.install";p.write_text(text.replace("<dict>",f"<dict><key>{key}</key><true/>",1));assert "document" in G.run_gate(tmp_path)["failures"]

@pytest.mark.parametrize("old,new,error", [
 ("sizeof(tmd_sysext_snapshot_t) == 216", "sizeof(tmd_sysext_snapshot_t) == 208", "shape:objc:_Static_assert(sizeof(tmd_sysext_snapshot_t) == 216"),
 ("_Alignof(tmd_sysext_snapshot_t) == 8", "_Alignof(tmd_sysext_snapshot_t) == 4", "shape:objc:_Static_assert(_Alignof(tmd_sysext_snapshot_t) == 8"),
 ("offsetof(tmd_sysext_snapshot_t, detail) == 24", "offsetof(tmd_sysext_snapshot_t, detail) == 20", "shape:objc:offsetof(tmd_sysext_snapshot_t, detail) == 24"),
 ("request == self.request", "request != self.request", "shape:objc:request == self.request"),
 ("_snapshot.state != TMD_SUBMITTED", "_snapshot.state == TMD_SUBMITTED", "shape:objc:_snapshot.state != TMD_SUBMITTED"),
 ("output->error = TMD_IN_FLIGHT", "_snapshot.error = TMD_IN_FLIGHT", "shape:objc:output->error = TMD_IN_FLIGHT"),
 ("result == OSSystemExtensionRequestCompleted", "result != OSSystemExtensionRequestCompleted", "shape:finish_result_closed"),
 ("scanUnsignedLongLong", "scanDouble", "shape:objc:scanUnsignedLongLong"),
 ("OSSystemExtensionErrorMissingEntitlement", "2", "shape:objc:OSSystemExtensionErrorMissingEntitlement"),
])
def test_objc_abi_lifecycle_mutations_fail(tmp_path,old,new,error):
 copy(tmp_path);p=tmp_path/"apps/tamandua_gui/src-tauri/src/macos/system_extension_bridge.m";text=p.read_text();assert old in text;p.write_text(text.replace(old,new,1));assert error in G.shapes(tmp_path)

@pytest.mark.parametrize("old,new,error", [
 ("size_of::<NativeSnapshot>() == 216", "size_of::<NativeSnapshot>() == 208", "shape:rust_fail_closed_decode:size_of::<NativeSnapshot>() == 216"),
 ("align_of::<NativeSnapshot>() == 8", "align_of::<NativeSnapshot>() == 4", "shape:rust_fail_closed_decode:align_of::<NativeSnapshot>() == 8"),
 ("position(|byte| *byte == 0)?", "position(|byte| *byte == 0).unwrap_or(raw.detail.len())", "shape:rust_fail_closed_decode:position(|byte| *byte == 0)?"),
 ("from_utf8(&raw.detail[..end]).ok()?", "from_utf8_lossy(&raw.detail[..end])", "shape:rust_fail_closed_decode:from_utf8(&raw.detail[..end]).ok()?"),
 ("valid_relation", "unchecked_relation", "shape:rust_fail_closed_decode:valid_relation"),
])
def test_rust_abi_decode_mutations_fail(tmp_path,old,new,error):
 copy(tmp_path);p=tmp_path/"apps/tamandua_gui/src-tauri/src/macos/system_extension_lifecycle.rs";text=p.read_text();assert old in text;p.write_text(text.replace(old,new));assert error in G.shapes(tmp_path)

def test_magic_error_code_mapping_fails(tmp_path):
 copy(tmp_path);p=tmp_path/"apps/tamandua_gui/src-tauri/src/macos/system_extension_bridge.m";text=p.read_text();text=text.replace("case OSSystemExtensionErrorMissingEntitlement:","case 2:",1);p.write_text(text);assert "shape:magic_error_codes" in G.shapes(tmp_path)

def test_active_snapshot_mutation_on_second_request_fails(tmp_path):
 copy(tmp_path);p=tmp_path/"apps/tamandua_gui/src-tauri/src/macos/system_extension_bridge.m";text=p.read_text().replace("output->error = TMD_IN_FLIGHT;","_snapshot.error=TMD_IN_FLIGHT;",1);p.write_text(text);assert "shape:single_flight_mutates_active_snapshot" in G.shapes(tmp_path)

@pytest.mark.parametrize("token", ["systemextensionsctl", "openSystemSettings", "sudo ", "osascript", "std::process::Command", "retry", "restart", "helper"])
def test_lifecycle_helper_auto_retry_settings_paths_fail(tmp_path,token):
 copy(tmp_path);p=tmp_path/"apps/tamandua_gui/src-tauri/src/macos/system_extension_lifecycle.rs";p.write_text(p.read_text()+"\n// "+token);assert "shape:no_lifecycle_helper_shell_settings" in G.shapes(tmp_path)

def test_status_command_cannot_submit(tmp_path):
 copy(tmp_path);p=tmp_path/"apps/tamandua_gui/src-tauri/src/commands.rs";text=p.read_text();text=text.replace("system_extension_lifecycle::snapshot()","system_extension_lifecycle::request_activation(true).unwrap()",1);p.write_text(text);assert "shape:no_status_mutation" in G.shapes(tmp_path)

@pytest.mark.parametrize("old,new", [
 ('sys.path[:] = [entry for entry in sys.path if _trusted_cli_path(entry)]','pass'),
 ('forbidden = {"eval"','forbidden = {"safe_eval"'),
])
def test_gate_self_policy_mutations_fail(tmp_path,old,new):
 copy(tmp_path);p=tmp_path/G.SCRIPT;text=p.read_text();assert old in text;p.write_text(text.replace(old,new,1));assert "gate_policy" in G.run_gate(tmp_path)["failures"]
