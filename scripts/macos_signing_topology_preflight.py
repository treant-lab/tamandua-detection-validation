#!/usr/bin/env python3
"""Static, privacy-safe preflight for the canonical macOS signing topology."""

from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import re
import shlex
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
RECEIPT_FILENAME = "20260718T073047Z-macos-canonical-swift-scratch-v6.json"
RECEIPT_SHA256 = "24ca8f6215255dbfe1491f2b27403b283996c33dbdf6c2ec92f3445f92a3dbfb"
RECEIPT_SOURCE_SHA = "d79e1213ba382b3313f9d97a77c687d8164f72c1"
ES = "com.apple.developer.endpoint-security.client"
INSTALL = "com.apple.developer.system-extension.install"
CANONICAL_PACKAGER_SOURCE_SHA256 = "d415175d2d4196ee2e620ea791d61635db56cd69cb60d6dfd221dba4940f2625"
CANONICAL_NOTARIZE_SOURCE_SHA256 = "49f364ae56aa7dcc0856620c13a45430dff45f1ea89fbbb39ff38146fcfb93ef"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required_file(root: Path, relative: str) -> Path:
    root = root.resolve(strict=True)
    path = root / relative
    current = root
    try:
        for part in Path(relative).parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("required_source_invalid")
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        raise ValueError("required_source_invalid") from None
    if not resolved.is_file():
        raise ValueError("required_source_invalid")
    return resolved


def read_text(root: Path, relative: str) -> str:
    return required_file(root, relative).read_text(encoding="utf-8")


def read_plist(root: Path, relative: str) -> dict:
    value = plistlib.loads(required_file(root, relative).read_bytes())
    if not isinstance(value, dict):
        raise ValueError("required_plist_invalid")
    return value


def git_sha(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
    )
    value = result.stdout.strip().lower()
    if len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("source_sha_invalid")
    return value


def receipt_contract(root: Path, filename: str) -> dict:
    if filename != Path(filename).name or filename != RECEIPT_FILENAME:
        raise ValueError("receipt_filename_rejected")
    try:
        path = required_file(root, f"docs/benchmarks/runs/{filename}")
    except ValueError:
        raise ValueError("receipt_file_rejected") from None
    value = json.loads(path.read_text(encoding="utf-8"))
    receipt_sha256 = digest(path)
    valid = (
        receipt_sha256 == RECEIPT_SHA256
        and value.get("schema_version") == "tamandua.macos_source_bundle_evidence/v6"
        and value.get("state") == "pass"
        and value.get("source", {}).get("commit") == RECEIPT_SOURCE_SHA
        and value.get("source", {}).get("dirty") is False
    )
    return {"filename": filename, "sha256": receipt_sha256, "source_sha": RECEIPT_SOURCE_SHA, "valid": valid}


def active_lines(source: str) -> list[str]:
    return [line.strip() for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def shell_function_body(lines: list[str], name: str) -> list[str] | None:
    declaration = f"{name}() {{"
    starts = [index for index, line in enumerate(lines) if line == declaration]
    if len(starts) != 1:
        return None
    for index in range(starts[0] + 1, len(lines)):
        if lines[index] == "}":
            return lines[starts[0] + 1:index]
    return None


def has_shell_assignment(lines: list[str], name: str, value: str) -> bool:
    pattern = re.compile(rf'{re.escape(name)}="{re.escape(value)}"')
    return any(pattern.fullmatch(line) for line in lines)


PACKAGER_INSTALL_COMMANDS = {
    ("install", "-m", "0755", "$HOST", "$APP_CONTENTS/MacOS/TamanduaSystemExtensionHost"),
    ("install", "-m", "0755", "$RUST_HELPER", "$HELPER/MacOS/tamandua-agent"),
    ("install", "-m", "0644", "$SOURCE_ROOT/TamanduaSystemExtensionHost/Info.plist", "$APP_CONTENTS/Info.plist"),
    ("install", "-m", "0755", "$EXTENSION", "$SYSEXT/MacOS/TamanduaFileMonitor"),
    ("install", "-m", "0644", "$SOURCE_ROOT/TamanduaFileMonitor/Info.plist", "$SYSEXT/Info.plist"),
}
PACKAGER_DIRECTORY_COMMAND = (
    "install", "-d", "-m", "0755", "$APP_CONTENTS/MacOS", "$HELPER/MacOS", "$SYSEXT/MacOS"
)
WORKFLOW_PACKAGER_COMMAND = (
    'apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh '
    '--host "$HOST" --extension "$EXTENSION" --rust-helper "$RUST_HELPER" --output "$APP_PATH"'
)
NOTARY_ROLE_CALLS = (
    'validate_signing_role activation_host "${APP_PATH}/Contents/MacOS/TamanduaSystemExtensionHost" "${SYSTEM_EXTENSION_INSTALL_ENTITLEMENT}" "${ENDPOINT_SECURITY_ENTITLEMENT}" || return 1',
    'validate_signing_role rust_helper "${APP_PATH}/Contents/Helpers/TamanduaAgentHelper.bundle" none "${SYSTEM_EXTENSION_INSTALL_ENTITLEMENT}" "${ENDPOINT_SECURITY_ENTITLEMENT}" || return 1',
    'validate_signing_role endpoint_security_extension "${APP_PATH}/Contents/Library/SystemExtensions/TamanduaFileMonitor.systemextension" "${ENDPOINT_SECURITY_ENTITLEMENT}" "${SYSTEM_EXTENSION_INSTALL_ENTITLEMENT}" || return 1',
)


def exact_packager_install_contract(source: str) -> bool:
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != CANONICAL_PACKAGER_SOURCE_SHA256:
        return False
    if not bash_syntax_valid(source):
        return False
    observed = []
    for line in active_lines(source):
        if not line.startswith("install"):
            continue
        try:
            tokens = tuple(shlex.split(line))
        except ValueError:
            return False
        observed.append(tokens)
    return len(observed) == 6 and set(observed) == {
        *PACKAGER_INSTALL_COMMANDS, PACKAGER_DIRECTORY_COMMAND
    }


def workflow_invokes_packager(source: str) -> bool:
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError:
        return False
    if not isinstance(document, dict):
        return False
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return False
    found = []
    scalar_occurrences = 0
    def count_scalars(value):
        nonlocal scalar_occurrences
        if isinstance(value, dict):
            for child in value.values():
                count_scalars(child)
        elif isinstance(value, list):
            for child in value:
                count_scalars(child)
        elif isinstance(value, str):
            scalar_occurrences += value.count(WORKFLOW_PACKAGER_COMMAND)
    count_scalars(document)
    for job in jobs.values():
        if not isinstance(job, dict):
            return False
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            return False
        for step in steps:
            if not isinstance(step, dict):
                return False
            if "run" in step:
                if not isinstance(step["run"], str):
                    return False
                found.append(step["run"])
    return scalar_occurrences == 1 and found.count(WORKFLOW_PACKAGER_COMMAND) == 1


def bash_syntax_valid(source: str) -> bool:
    try:
        # Feed raw UTF-8 bytes: text=True would use the locale encoding
        # (cp1252 on Windows, which cannot encode all script characters) and
        # would translate "\n" to "\r\n" on the stdin pipe, corrupting the
        # bash source under test.
        result = subprocess.run(
            ["bash", "-n"], input=source.encode("utf-8"),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and not result.stderr and heredocs_closed(source)


def heredocs_closed(source: str) -> bool:
    lines = source.splitlines()
    index = 0
    pattern = re.compile(r"<<(-)?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
    while index < len(lines):
        match = pattern.search(lines[index])
        if match is None:
            index += 1
            continue
        delimiter = match.group(3)
        strip_tabs = match.group(1) == "-"
        index += 1
        while index < len(lines):
            candidate = lines[index].lstrip("\t") if strip_tabs else lines[index]
            if candidate == delimiter:
                break
            index += 1
        if index == len(lines):
            return False
        index += 1
    return True


def notarize_has_concrete_role_validation(source: str) -> bool:
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != CANONICAL_NOTARIZE_SOURCE_SHA256:
        return False
    if not bash_syntax_valid(source):
        return False
    lines = active_lines(source)
    structural = (
        "entitlement_state() {",
        "validate_signing_role() {",
        "verify_signed_artifact_role_topology() {",
        *NOTARY_ROLE_CALLS,
        'plist_key="${entitlement//./\\\\.}"',
        'if ! printf \'%s\' "${entitlements}" | /usr/bin/plutil -lint - >/dev/null 2>&1; then',
        'if value=$(printf \'%s\' "${entitlements}" | /usr/bin/plutil -extract "${plist_key}" xml1 -o - -- - 2>/dev/null); then',
    )
    if not all(item in lines for item in structural):
        return False
    topology_body = shell_function_body(lines, "verify_signed_artifact_role_topology")
    main_body = shell_function_body(lines, "main")
    if topology_body is None or main_body is None:
        return False
    if not all(call in topology_body for call in NOTARY_ROLE_CALLS):
        return False
    try:
        topology_call = main_body.index("verify_signed_artifact_role_topology")
        validate_only_branch = main_body.index('if [[ "${VALIDATE_ONLY}" == "true" ]]; then', topology_call)
        credential_call = main_body.index("validate_notarization_credentials", validate_only_branch)
        create_call = main_body.index("create_zip", credential_call)
        submit_call = main_body.index("submit_for_notarization", create_call)
    except ValueError:
        return False
    return (
        topology_call < validate_only_branch < credential_call < create_call < submit_call
        and validate_only_branch == topology_call + 1
        and lines[-1] == 'main "$@"'
        and not any("grep" in line and "entitlement" in line.lower() for line in lines)
    )


def build_report(root: Path = ROOT, *, current_source_sha: str | None = None,
                 receipt_filename: str = RECEIPT_FILENAME) -> dict:
    source_sha = (current_source_sha or git_sha(root)).lower()
    if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
        raise ValueError("source_sha_invalid")
    receipt = receipt_contract(root, receipt_filename)
    packager = read_text(root, "apps/tamandua_agent/scripts/package_macos_system_extension_candidate.sh")
    workflow = read_text(root, ".github/workflows/macos-notarize.yml")
    notarize = read_text(root, "apps/tamandua_agent/scripts/notarize.sh")
    host_info = read_plist(root, "apps/tamandua_agent/SystemExtension/TamanduaSystemExtensionHost/Info.plist")
    ext_info = read_plist(root, "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist")
    host_ent = read_plist(root, "apps/tamandua_agent/SystemExtension/TamanduaSystemExtensionHost/entitlements.plist")
    ext_ent = read_plist(root, "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist")

    packager_lines = active_lines(packager)
    canonical = all((
        has_shell_assignment(packager_lines, "APP_CONTENTS", "$OUTPUT/Contents"),
        has_shell_assignment(packager_lines, "HELPER", "$APP_CONTENTS/Helpers/TamanduaAgentHelper.bundle/Contents"),
        has_shell_assignment(packager_lines, "SYSEXT", "$APP_CONTENTS/Library/SystemExtensions/TamanduaFileMonitor.systemextension/Contents"),
        exact_packager_install_contract(packager),
    )) and host_info.get("CFBundleExecutable") == "TamanduaSystemExtensionHost" \
        and ext_info.get("CFBundleExecutable") == "TamanduaFileMonitor"
    workflow_matches = workflow_invokes_packager(workflow)
    least_privilege = (
        host_ent.get(INSTALL) is True and host_ent.get(ES) is not True
        and ext_ent.get(ES) is True and ext_ent.get(INSTALL) is not True
    )
    notarize_role_aware = notarize_has_concrete_role_validation(notarize)

    mismatches = []
    if not canonical:
        mismatches.append("canonical_packager_topology_mismatch")
    if not workflow_matches:
        mismatches.append("workflow_topology_mismatch")
    if not least_privilege:
        mismatches.append("entitlement_role_mismatch")
    if not notarize_role_aware:
        mismatches.append("notary_role_validation_mismatch")
    if source_sha != receipt["source_sha"]:
        mismatches.append("current_source_not_receipt_source")
    if not receipt["valid"]:
        mismatches.append("governed_receipt_mismatch")

    return {
        "schema_version": "tamandua.macos_signing_topology_preflight/v1",
        "evidence_class": "static_source_contract",
        "status": "hold",
        "source": {"current_sha": source_sha, "governed_unsigned_receipt": receipt},
        "roles": ["activation_host", "rust_helper", "endpoint_security_extension"],
        "signing_order": [
            "rust_helper_executable", "rust_helper_bundle",
            "endpoint_security_extension_executable", "endpoint_security_extension_bundle",
            "activation_host_executable", "carrier_app_bundle",
        ],
        "mismatches": mismatches,
        "prerequisites": {
            "developer_id_application": "not_evaluated",
            "macos_capability_profile": "not_evaluated",
            "signing_authorized": False,
        },
        "claims": {
            "signed": False, "notarized": False, "installed": False,
            "activated": False, "full_disk_access": False,
            "backend_ready": False, "release_ready": False,
            "external_claim_allowed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--receipt-filename", default=RECEIPT_FILENAME)
    args = parser.parse_args()
    try:
        report = build_report(receipt_filename=args.receipt_filename)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as output:
                output.write(rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError, json.JSONDecodeError, plistlib.InvalidFileException):
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
