import copy
import json
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from tools.detection_validation.scripts import macos_signing_topology_preflight as gate

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((ROOT / "schemas/macos_signing_topology_preflight_v1.schema.json").read_text())
FILES = (
    "apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh",
    ".github/workflows/macos-notarize.yml",
    "apps/tamandua_agent/scripts/notarize.sh",
    "apps/tamandua_agent/SystemExtension/TamanduaSystemExtensionHost/Info.plist",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist",
    "apps/tamandua_agent/SystemExtension/TamanduaSystemExtensionHost/entitlements.plist",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist",
    f"docs/benchmarks/runs/{gate.RECEIPT_FILENAME}",
)


def fixture_root(tmp_path: Path) -> Path:
    for relative in FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    return tmp_path


def test_current_report_is_strict_privacy_safe_hold():
    report = gate.build_report(ROOT, current_source_sha="a" * 40)
    jsonschema.validate(report, SCHEMA)
    assert report["evidence_class"] == "static_source_contract"
    assert report["status"] == "hold"
    assert report["mismatches"] == ["current_source_not_receipt_source"]
    assert report["prerequisites"] == {
        "developer_id_application": "not_evaluated",
        "macos_capability_profile": "not_evaluated",
        "signing_authorized": False,
    }
    assert set(report["claims"].values()) == {False}
    rendered = json.dumps(report)
    for forbidden in (
        "com.tamandua", "Developer ID Application:", "TeamIdentifier",
        "APPLE_ID", "NOTARYTOOL_APP_PASSWORD", "Contents/", str(ROOT),
    ):
        assert forbidden not in rendered


def test_selected_least_privilege_topology_removes_only_role_mismatches(tmp_path):
    root = fixture_root(tmp_path)
    (root / ".github/workflows/macos-notarize.yml").write_text(
        f"jobs:\n  release:\n    steps:\n      - run: {gate.WORKFLOW_PACKAGER_COMMAND}\n"
    )
    for relative, value in (
        ("apps/tamandua_agent/SystemExtension/TamanduaSystemExtensionHost/entitlements.plist", {gate.INSTALL: True}),
        ("apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist", {gate.ES: True}),
    ):
        (root / relative).write_bytes(plistlib.dumps(value))
    report = gate.build_report(root, current_source_sha=gate.RECEIPT_SOURCE_SHA)
    assert report["mismatches"] == []
    assert report["status"] == "hold"
    assert report["prerequisites"]["signing_authorized"] is False


def test_current_entitlements_assign_privileges_to_exact_owners():
    host_path = ROOT / "apps/tamandua_agent/SystemExtension/TamanduaSystemExtensionHost/entitlements.plist"
    extension_path = ROOT / "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist"
    host = plistlib.loads(host_path.read_bytes())
    extension = plistlib.loads(extension_path.read_bytes())

    assert host.get(gate.INSTALL) is True
    assert gate.ES not in host
    assert extension.get(gate.ES) is True
    assert gate.INSTALL not in extension


@pytest.mark.parametrize("role,key", (("TamanduaSystemExtensionHost", gate.ES), ("TamanduaFileMonitor", gate.INSTALL)))
def test_privileged_entitlement_on_wrong_role_fails(tmp_path, role, key):
    root = fixture_root(tmp_path)
    path = root / f"apps/tamandua_agent/SystemExtension/{role}/entitlements.plist"
    path.write_bytes(plistlib.dumps({key: True}))
    report = gate.build_report(root, current_source_sha=gate.RECEIPT_SOURCE_SHA)
    assert "entitlement_role_mismatch" in report["mismatches"]


def test_receipt_traversal_symlink_and_tamper_fail_closed(tmp_path):
    root = fixture_root(tmp_path)
    with pytest.raises(ValueError, match="receipt_filename_rejected"):
        gate.build_report(root, current_source_sha="a" * 40, receipt_filename="../receipt.json")
    receipt = root / f"docs/benchmarks/runs/{gate.RECEIPT_FILENAME}"
    outside = tmp_path / "outside.json"; outside.write_text("{}")
    receipt.unlink(); receipt.symlink_to(outside)
    with pytest.raises(ValueError, match="receipt_file_rejected"):
        gate.build_report(root, current_source_sha="a" * 40)
    receipt.unlink(); shutil.copyfile(ROOT / f"docs/benchmarks/runs/{gate.RECEIPT_FILENAME}", receipt)
    receipt.write_text(receipt.read_text() + " ")
    report = gate.build_report(root, current_source_sha="a" * 40)
    assert "governed_receipt_mismatch" in report["mismatches"]


def test_required_source_symlink_is_rejected(tmp_path):
    root = fixture_root(tmp_path)
    workflow = root / ".github/workflows/macos-notarize.yml"
    outside = tmp_path / "outside-workflow"; outside.write_text("legacy")
    workflow.unlink(); workflow.symlink_to(outside)
    with pytest.raises(ValueError, match="required_source_invalid"):
        gate.build_report(root, current_source_sha="a" * 40)


def test_required_source_intermediate_symlink_is_rejected(tmp_path):
    root = fixture_root(tmp_path)
    source = root / "apps/tamandua_agent/SystemExtension"
    outside = tmp_path / "outside-tree"
    source.rename(outside)
    source.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="required_source_invalid"):
        gate.build_report(root, current_source_sha="a" * 40)


def test_comments_cannot_spoof_workflow_or_notary_contract(tmp_path):
    root = fixture_root(tmp_path)
    (root / ".github/workflows/macos-notarize.yml").write_text(
        "# package_macos_system_extension_candidate.sh\n"
    )
    (root / "apps/tamandua_agent/scripts/notarize.sh").write_text(
        "# ACTIVATION_HOST=x\n# ENDPOINT_SECURITY_EXTENSION=y\n"
    )
    report = gate.build_report(root, current_source_sha=gate.RECEIPT_SOURCE_SHA)
    assert "workflow_topology_mismatch" in report["mismatches"]
    assert "notary_role_validation_mismatch" in report["mismatches"]


def test_echo_cannot_spoof_workflow_packager_adoption(tmp_path):
    root = fixture_root(tmp_path)
    source = "echo apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh\n"
    assert gate.workflow_invokes_packager(source) is False


@pytest.mark.parametrize("replacement", (
    'echo install -m 0755 "$HOST" "$APP_CONTENTS/MacOS/TamanduaSystemExtensionHost"',
    'printf install -m 0755 "$HOST" "$APP_CONTENTS/MacOS/TamanduaSystemExtensionHost"',
    'install -m 0755 "$HOST" "$APP_CONTENTS/MacOS/TamanduaSystemExtensionHost" && true',
    'install -m 0755 "$HOST" "$APP_CONTENTS/MacOS/TamanduaSystemExtensionHost"; true',
    'install -m 0755 "$HOST" "$APP_CONTENTS/MacOS/TamanduaSystemExtensionHost',
))
def test_packager_rejects_spoof_chaining_and_malformed_quotes(replacement):
    source = (ROOT / FILES[0]).read_text()
    exact = 'install -m 0755 "$HOST" "$APP_CONTENTS/MacOS/TamanduaSystemExtensionHost"'
    assert gate.exact_packager_install_contract(source.replace(exact,replacement)) is False


def test_packager_full_source_seal_rejects_if_false_wrapper():
    source=(ROOT/FILES[0]).read_text()
    wrapped="if false; then\n"+source+"\nfi\n"
    assert gate.bash_syntax_valid(wrapped) is True
    assert gate.exact_packager_install_contract(wrapped) is False


def test_packager_full_source_seal_rejects_function_wrapper():
    source=(ROOT/FILES[0]).read_text()
    wrapped="never_called() {\n"+source+"\n}\n"
    assert gate.bash_syntax_valid(wrapped) is True
    assert gate.exact_packager_install_contract(wrapped) is False


@pytest.mark.parametrize("source", (
    'jobs:\n  release:\n    steps:\n      - run: echo apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh',
    'jobs:\n  release:\n    steps:\n      - run: |\n          if false; then\n            apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh --host "$HOST" --extension "$EXTENSION" --rust-helper "$RUST_HELPER" --output "$APP_PATH"\n          fi',
    'jobs:\n  release:\n    steps:\n      - run: |\n          cat <<EOF\n          apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh --host "$HOST" --extension "$EXTENSION" --rust-helper "$RUST_HELPER" --output "$APP_PATH"\n          EOF',
    'jobs:\n  release:\n    steps:\n      - run: apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh --host "$HOST" --extension "$EXTENSION" --rust-helper "$RUST_HELPER" --output "$APP_PATH" && true',
    'jobs:\n  release:\n    steps:\n      - run: "apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh',
))
def test_workflow_rejects_non_single_command_spoofs(source):
    assert gate.workflow_invokes_packager(source) is False


def test_workflow_accepts_one_exact_yaml_single_command():
    assert gate.workflow_invokes_packager(
        f"jobs:\n  release:\n    steps:\n      - run: {gate.WORKFLOW_PACKAGER_COMMAND}\n"
    ) is True


def test_current_workflow_packages_canonical_inputs_and_holds_secret_jobs():
    source = (ROOT / ".github/workflows/macos-notarize.yml").read_text()
    document = gate.yaml.safe_load(source)
    jobs = document["jobs"]

    assert gate.workflow_invokes_packager(source) is True
    create = jobs["create-app-bundle"]
    create_runs = [step.get("run", "") for step in create["steps"]]
    assert gate.WORKFLOW_PACKAGER_COMMAND in create_runs
    assert all("CFBundleExecutable" not in run for run in create_runs)
    assert all("cp artifacts/agent/tamandua-agent" not in run for run in create_runs)

    verify = next(run for run in create_runs if "lipo -archs artifacts/agent/tamandua-agent" in run)
    for executable in (
        "artifacts/swift-products/TamanduaSystemExtensionHost",
        "artifacts/swift-products/TamanduaFileMonitor",
        "artifacts/agent/tamandua-agent",
    ):
        assert f"chmod +x {executable}" in verify
        assert f"test -x {executable}" in verify
        assert f"lipo -archs {executable}" in verify

    build_upload = next(step for step in jobs["build-sysext"]["steps"] if step.get("uses") == "actions/upload-artifact@v4")
    create_download = next(step for step in create["steps"] if step.get("uses") == "actions/download-artifact@v4" and "swift-products" in step["with"]["path"])
    assert build_upload["with"]["name"] == create_download["with"]["name"] == "canonical-swift-products-${{ matrix.arch }}"

    assert jobs["sign-and-notarize"]["if"] == "${{ false }}"
    assert jobs["create-release"]["needs"] == "sign-and-notarize"
    assert "secrets." not in json.dumps(jobs["build-sysext"])
    assert "secrets." not in json.dumps(jobs["build-agent"])
    assert "secrets." not in json.dumps(create)

    report = gate.build_report(ROOT, current_source_sha="a" * 40)
    assert report["mismatches"] == ["current_source_not_receipt_source"]


def test_workflow_rejects_allowed_run_duplicated_in_env_scalar():
    source=(
        f"env:\n  run: {gate.WORKFLOW_PACKAGER_COMMAND}\n"
        f"jobs:\n  release:\n    steps:\n      - run: {gate.WORKFLOW_PACKAGER_COMMAND}\n"
    )
    assert gate.workflow_invokes_packager(source) is False


@pytest.mark.parametrize("source", (
    "run: {command}\njobs: {{}}",
    "env:\n  run: {command}\njobs: {{}}",
    "jobs:\n  release:\n    outputs:\n      run: {command}\n    steps: []",
    "jobs:\n  release:\n    strategy:\n      run: {command}\n    steps: []",
))
def test_workflow_ignores_spoof_run_outside_job_steps(source):
    assert gate.workflow_invokes_packager(source.format(command=gate.WORKFLOW_PACKAGER_COMMAND)) is False


@pytest.mark.parametrize("source", (
    "jobs: []",
    "jobs:\n  release: []",
    "jobs:\n  release:\n    steps: {}",
    "jobs:\n  release:\n    steps:\n      - text",
    "jobs:\n  release:\n    steps:\n      - run: []",
))
def test_workflow_rejects_invalid_container_types(source):
    assert gate.workflow_invokes_packager(source) is False


def test_notary_requires_real_role_validation_flow():
    valid=(ROOT / "apps/tamandua_agent/scripts/notarize.sh").read_text(encoding="utf-8")
    assert gate.notarize_has_concrete_role_validation(valid) is True
    role_call = gate.NOTARY_ROLE_CALLS[0]
    spoofs=(
        valid.replace("verify_signed_artifact_role_topology\n    if", "if"),
        valid.replace("validate_notarization_credentials\n    create_zip", "create_zip\n    validate_notarization_credentials"),
        valid.replace(gate.NOTARY_ROLE_CALLS[0], "echo role validated"),
        valid.replace("/usr/bin/plutil -extract", "grep"),
        valid.replace(
            "    verify_signed_artifact_role_topology\n    if",
            "    echo topology skipped\n    if",
        ).replace(
            "main() {",
            "never_called_gate() {\n    verify_signed_artifact_role_topology\n    if [[ \"${VALIDATE_ONLY}\" == \"true\" ]]; then\n        return 0\n    fi\n    validate_notarization_credentials\n    create_zip\n    submit_for_notarization\n}\n\nmain() {",
        ),
        "if false; then\n" + valid.replace('\nmain "$@"', '\nfi\nmain "$@"'),
        valid.replace(
            "    verify_signed_artifact_role_topology\n    if",
            "    return 0\n    verify_signed_artifact_role_topology\n    if",
        ),
        valid.replace(role_call, f"{role_call}\n    {role_call}"),
        valid.replace("main() {", "outer() {\nmain() {").replace('\nmain "$@"', '\n}\nmain "$@"'),
        valid + "\necho trailing\n",
    )
    assert all(gate.notarize_has_concrete_role_validation(source) is False for source in spoofs)


def test_validate_only_is_offline_secretless_and_artifact_immutable(tmp_path):
    app = tmp_path / "candidate.app"
    for relative in (
        "Contents/MacOS/TamanduaSystemExtensionHost",
        "Contents/Helpers/TamanduaAgentHelper.bundle",
        "Contents/Library/SystemExtensions/TamanduaFileMonitor.systemextension",
    ):
        (app / relative).mkdir(parents=True)
    tools = tmp_path / "tools"
    tools.mkdir()
    trace = tmp_path / "trace"
    inherited_zip = tmp_path / "must-survive.zip"
    inherited_zip.write_text("preserve")
    codesign = tools / "codesign"
    codesign.write_text("""#!/bin/bash
printf 'codesign %s\\n' "$*" >>"$TRACE"
if [[ "$1" != "-d" ]]; then exit 0; fi
target="${*: -1}"
case "$target" in
  *TamanduaSystemExtensionHost) key=com.apple.developer.system-extension.install ;;
  *TamanduaFileMonitor.systemextension) key=com.apple.developer.endpoint-security.client ;;
  *) key=none ;;
esac
if [[ "${MOCK_VARIANT:-}" == host_forbidden && "$target" == *TamanduaSystemExtensionHost ]]; then
  printf '%s' '<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.developer.system-extension.install</key><true/><key>com.apple.developer.endpoint-security.client</key><false/></dict></plist>'
  exit 0
fi
if [[ "${MOCK_VARIANT:-}" == extension_required_string && "$target" == *TamanduaFileMonitor.systemextension ]]; then
  printf '%s' '<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.developer.endpoint-security.client</key><string>true</string></dict></plist>'
  exit 0
fi
if [[ "$key" == none ]]; then
  printf '%s' '<?xml version="1.0"?><plist version="1.0"><dict/></plist>'
else
  printf '%s' "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>$key</key><true/></dict></plist>"
fi
""")
    codesign.chmod(0o755)
    for name in ("xcrun", "ditto", "spctl"):
        poison = tools / name
        poison.write_text(f'#!/bin/bash\nprintf "FORBIDDEN {name}\\n" >>"$TRACE"\nexit 99\n')
        poison.chmod(0o755)
    before = sorted((str(path.relative_to(app)), path.stat().st_mtime_ns) for path in app.rglob("*"))
    result = subprocess.run(
        ["bash", str(ROOT / "apps/tamandua_agent/scripts/notarize.sh"),
         "--validate-only", str(app), "test.invalid"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": f"{tools}:/usr/bin:/bin", "TRACE": str(trace),
             "ZIP_PATH": str(inherited_zip), "APPLE_ID": "must-not-be-read",
             "NOTARYTOOL_APP_PASSWORD": "must-not-be-read",
             "APPLE_DEVELOPER_TEAM_ID": "must-not-be-read"}, check=False,
    )
    after = sorted((str(path.relative_to(app)), path.stat().st_mtime_ns) for path in app.rglob("*"))
    assert result.returncode == 0, result.stderr
    assert before == after
    assert "FORBIDDEN" not in trace.read_text()
    assert not Path(f"{app}.zip").exists()
    assert inherited_zip.read_text() == "preserve"

    trace.write_text("")
    normal = subprocess.run(
        ["bash", str(ROOT / "apps/tamandua_agent/scripts/notarize.sh"),
         str(app), "test.invalid"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": f"{tools}:/usr/bin:/bin", "TRACE": str(trace),
             "ZIP_PATH": str(inherited_zip)}, check=False,
    )
    assert normal.returncode == 1
    assert "Missing required environment variables" in normal.stderr
    assert "codesign" in trace.read_text()
    assert "FORBIDDEN" not in trace.read_text()
    assert inherited_zip.read_text() == "preserve"
    assert before == sorted((str(path.relative_to(app)), path.stat().st_mtime_ns) for path in app.rglob("*"))

    usage_result = subprocess.run(
        ["bash", str(ROOT / "apps/tamandua_agent/scripts/notarize.sh")],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": f"{tools}:/usr/bin:/bin", "TRACE": str(trace),
             "ZIP_PATH": str(inherited_zip)}, check=False,
    )
    assert usage_result.returncode == 1
    assert inherited_zip.read_text() == "preserve"

    app_sidecar = Path(f"{app}.zip")
    app_sidecar.write_text("preexisting")
    zip_temp = tmp_path / "zip-temp"
    zip_temp.mkdir()
    (tools / "ditto").write_text(
        '#!/bin/bash\nprintf "ditto %s\\n" "$*" >>"$TRACE"\ntouch "${*: -1}"\n'
    )
    trace.write_text("")
    attempted = subprocess.run(
        ["bash", str(ROOT / "apps/tamandua_agent/scripts/notarize.sh"),
         str(app), "test.invalid"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": f"{tools}:/usr/bin:/bin", "TRACE": str(trace),
             "TMPDIR": str(zip_temp), "ZIP_PATH": str(inherited_zip),
             "APPLE_ID": "test", "NOTARYTOOL_APP_PASSWORD": "test",
             "APPLE_DEVELOPER_TEAM_ID": "test"}, check=False,
    )
    assert attempted.returncode == 1
    assert app_sidecar.read_text() == "preexisting"
    assert inherited_zip.read_text() == "preserve"
    assert not list(zip_temp.glob("tamandua-notarize.*"))

    for variant in ("host_forbidden", "extension_required_string"):
        rejected = subprocess.run(
            ["bash", str(ROOT / "apps/tamandua_agent/scripts/notarize.sh"),
             "--validate-only", str(app), "test.invalid"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": f"{tools}:/usr/bin:/bin", "TRACE": str(trace), "MOCK_VARIANT": variant},
            check=False,
        )
        assert rejected.returncode == 1


@pytest.mark.parametrize("suffix", (
    "\nif true; then\n",
    "\nbroken() {\n",
    "\ncat <<EOF\nunterminated\n",
    "\necho \"unterminated\n",
))
def test_packager_fails_closed_on_global_bash_syntax_error(suffix):
    source=(ROOT/FILES[0]).read_text()+suffix
    assert gate.exact_packager_install_contract(source) is False


@pytest.mark.parametrize("prefix", (
    "if true; then\n",
    "broken() {\n",
    "cat <<EOF\nunterminated\n",
    "echo \"unterminated\n",
))
def test_notary_fails_closed_on_global_bash_syntax_error(prefix):
    valid=(ROOT / "apps/tamandua_agent/scripts/notarize.sh").read_text(encoding="utf-8")
    assert gate.notarize_has_concrete_role_validation(prefix+valid) is False


def test_cli_emits_hold_once_without_overwrite(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["preflight", "--output", str(output)])
    assert gate.main() == 1
    value = json.loads(output.read_text())
    assert value["status"] == "hold"
    original = output.read_bytes()
    assert gate.main() == 2
    assert output.read_bytes() == original


def test_schema_rejects_claim_promotion_and_raw_mismatch():
    report = gate.build_report(ROOT, current_source_sha="a" * 40)
    promoted = copy.deepcopy(report); promoted["claims"]["signed"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(promoted, SCHEMA)
    raw = copy.deepcopy(report); raw["mismatches"].append("raw-secret-or-path")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(raw, SCHEMA)
    invalid_receipt = copy.deepcopy(report)
    invalid_receipt["source"]["governed_unsigned_receipt"]["valid"] = False
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(invalid_receipt, SCHEMA)
