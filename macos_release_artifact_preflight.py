#!/usr/bin/env python3
"""Offline macOS release artifact preflight.

This checker is intentionally static: it reads hashes and ZIP indexes only. It
does not mount DMGs, execute binaries, invoke macOS signing tools, or contact a
lab endpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import re
import struct
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"


ARTIFACT_NAME = "macos-release-artifact-preflight"
PROFILE_ID = ARTIFACT_NAME
PROFILE_NAME = "macOS Release Artifact Preflight"
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-macos-release-artifact-preflight$")
EXPECTED_SYSEXT_EXTENSION_POINT = "com.apple.system-extension.endpoint-security"
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
MACHO_CPU_ARCHES = {
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM64: "arm64",
}
MACHO_MAGIC_ENDIAN = {
    b"\xfe\xed\xfa\xce": ">",
    b"\xce\xfa\xed\xfe": "<",
    b"\xfe\xed\xfa\xcf": ">",
    b"\xcf\xfa\xed\xfe": "<",
}
FAT_MAGIC_ENDIAN = {
    b"\xca\xfe\xba\xbe": ">",
    b"\xbe\xba\xfe\xca": "<",
}
FAT64_MAGIC_ENDIAN = {
    b"\xca\xfe\xba\xbf": ">",
    b"\xbf\xba\xfe\xca": "<",
}
CLAIM_BOUNDARY = (
    "Offline macOS release artifact structure/hash check only. Passing this "
    "preflight does not prove Developer ID signing, notarization, stapling, "
    "EndpointSecurity entitlement validity, system-extension approval, Full "
    "Disk Access, install success, backend health, or P0 smoke evidence."
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            ).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--short"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha256sums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, filename = parts
        filename = filename.lstrip("*").strip()
        if len(digest) == 64:
            normalized = filename.replace("\\", "/")
            checksums[filename] = digest.lower()
            checksums[normalized] = digest.lower()
            checksums[Path(normalized).name] = digest.lower()
    return checksums


def checksum_status(path: Path, expected_hashes: dict[str, str] | None) -> dict[str, Any]:
    actual = sha256_file(path)
    expected = None
    if expected_hashes is not None:
        expected = (
            expected_hashes.get(str(path))
            or expected_hashes.get(str(path).replace("\\", "/"))
            or expected_hashes.get(path.name)
        )
    return {
        "path": str(path),
        "name": path.name,
        "exists": path.exists(),
        "sha256": actual,
        "expected_sha256": expected,
        "checksum_present": expected is not None,
        "checksum_matches": expected == actual if expected is not None else None,
    }


def expected_arch_from_name(name: str) -> str:
    lowered = name.lower()
    if "aarch64" in lowered or "arm64" in lowered:
        return "arm64"
    if "x86_64" in lowered or "amd64" in lowered:
        return "x86_64"
    return ""


def macho_arches(raw: bytes) -> list[str]:
    if len(raw) < 8:
        return []
    magic = raw[:4]
    if magic in MACHO_MAGIC_ENDIAN:
        endian = MACHO_MAGIC_ENDIAN[magic]
        cputype = struct.unpack(f"{endian}I", raw[4:8])[0]
        arch = MACHO_CPU_ARCHES.get(cputype)
        return [arch] if arch else []
    if magic in FAT_MAGIC_ENDIAN or magic in FAT64_MAGIC_ENDIAN:
        endian = (FAT_MAGIC_ENDIAN | FAT64_MAGIC_ENDIAN)[magic]
        if len(raw) < 8:
            return []
        nfat_arch = struct.unpack(f"{endian}I", raw[4:8])[0]
        arches: list[str] = []
        offset = 8
        record_size = 32 if magic in FAT64_MAGIC_ENDIAN else 20
        for _ in range(min(nfat_arch, 32)):
            if len(raw) < offset + record_size:
                break
            cputype = struct.unpack(f"{endian}I", raw[offset : offset + 4])[0]
            arch = MACHO_CPU_ARCHES.get(cputype)
            if arch and arch not in arches:
                arches.append(arch)
            offset += record_size
        return arches
    return []


def inspect_app_zip(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        entries_by_normalized = {name.replace("\\", "/"): name for name in names}

    normalized = [name.replace("\\", "/") for name in names]
    app_prefixes = sorted(
        {
            name.split(".app/", 1)[0] + ".app"
            for name in normalized
            if ".app/" in name and name.split(".app/", 1)[0]
        }
    )

    def plist_metadata(entry: str) -> dict[str, Any]:
        try:
            with zipfile.ZipFile(path) as archive:
                raw_info_plist = archive.read(entries_by_normalized[entry])
            parsed_info = plistlib.loads(raw_info_plist)
            valid = isinstance(parsed_info, dict)
            parsed = parsed_info if valid else {}
            cf_bundle_executable_value = parsed.get("CFBundleExecutable")
            executable = cf_bundle_executable_value.strip() if isinstance(cf_bundle_executable_value, str) else ""
            cf_bundle_identifier_value = parsed.get("CFBundleIdentifier")
            bundle_id = cf_bundle_identifier_value.strip() if isinstance(cf_bundle_identifier_value, str) else ""
            extension = parsed.get("NSExtension")
            extension_point_value = extension.get("NSExtensionPointIdentifier") if isinstance(extension, dict) else None
            extension_point = extension_point_value.strip() if isinstance(extension_point_value, str) else ""
            error = ""
            if not executable:
                error = "CFBundleExecutable missing or empty"
            return {
                "valid": valid,
                "error": error,
                "cf_bundle_executable": executable,
                "cf_bundle_identifier": bundle_id,
                "extension_point_identifier": extension_point,
            }
        except Exception as exc:
            return {
                "valid": False,
                "error": f"{type(exc).__name__}: {exc}",
                "cf_bundle_executable": "",
                "cf_bundle_identifier": "",
                "extension_point_identifier": "",
            }

    info_plists = [name for name in normalized if name.endswith(".app/Contents/Info.plist")]
    app_info_plist_valid = False
    app_info_plist_error = ""
    cf_bundle_executable = ""
    app_cf_bundle_identifier = ""
    declared_macos_executable_entry = ""
    if info_plists:
        info_plist = info_plists[0]
        app_bundle = info_plist.rsplit("/Contents/Info.plist", 1)[0]
        app_metadata = plist_metadata(info_plist)
        app_info_plist_valid = bool(app_metadata["valid"])
        app_info_plist_error = str(app_metadata["error"])
        cf_bundle_executable = str(app_metadata["cf_bundle_executable"])
        app_cf_bundle_identifier = str(app_metadata["cf_bundle_identifier"])
        if cf_bundle_executable:
            declared_macos_executable_entry = f"{app_bundle}/Contents/MacOS/{cf_bundle_executable}"
    macos_entries = [
        name
        for name in normalized
        if ".app/Contents/MacOS/" in name and not name.endswith("/")
    ]
    has_declared_macos_executable = bool(
        declared_macos_executable_entry and declared_macos_executable_entry in normalized
    )
    sysext_entries = [
        name
        for name in normalized
        if ".app/Contents/Library/SystemExtensions/" in name
        and ".systemextension/" in name
        and "/Contents/MacOS/" in name
        and not name.endswith("/")
    ]
    sysext_info_plists = [
        name
        for name in normalized
        if ".app/Contents/Library/SystemExtensions/" in name
        and ".systemextension/Contents/Info.plist" in name
    ]
    sysext_info_plist_valid = False
    sysext_info_plist_error = ""
    sysext_cf_bundle_executable = ""
    sysext_cf_bundle_identifier = ""
    sysext_extension_point_identifier = ""
    declared_system_extension_executable_entry = ""
    if sysext_info_plists:
        sysext_info_plist = sysext_info_plists[0]
        sysext_bundle = sysext_info_plist.rsplit("/Contents/Info.plist", 1)[0]
        sysext_metadata = plist_metadata(sysext_info_plist)
        sysext_info_plist_valid = bool(sysext_metadata["valid"])
        sysext_info_plist_error = str(sysext_metadata["error"])
        sysext_cf_bundle_executable = str(sysext_metadata["cf_bundle_executable"])
        sysext_cf_bundle_identifier = str(sysext_metadata["cf_bundle_identifier"])
        sysext_extension_point_identifier = str(sysext_metadata["extension_point_identifier"])
        if sysext_cf_bundle_executable:
            declared_system_extension_executable_entry = (
                f"{sysext_bundle}/Contents/MacOS/{sysext_cf_bundle_executable}"
            )
    has_declared_system_extension_executable = bool(
        declared_system_extension_executable_entry
        and declared_system_extension_executable_entry in normalized
    )
    has_system_extension_bundle_id = bool(sysext_cf_bundle_identifier)
    system_extension_contained_by_app_bundle_id = bool(
        app_cf_bundle_identifier
        and sysext_cf_bundle_identifier.startswith(f"{app_cf_bundle_identifier}.")
    )
    has_endpoint_security_extension_point = (
        sysext_extension_point_identifier == EXPECTED_SYSEXT_EXTENSION_POINT
    )
    tamandua_agent_entries = [
        name
        for name in normalized
        if (
            ".app/Contents/Resources/tamandua-agent/" in name
            or name.endswith(".app/Contents/MacOS/tamandua-agent")
        )
        and not name.endswith("/")
    ]
    expected_arch = expected_arch_from_name(path.name)

    def entry_arches(entry: str) -> list[str]:
        if not entry:
            return []
        try:
            with zipfile.ZipFile(path) as archive:
                raw = archive.read(entries_by_normalized[entry])[:4096]
            return macho_arches(raw)
        except Exception:
            return []

    declared_macos_executable_arches = entry_arches(declared_macos_executable_entry)
    declared_system_extension_executable_arches = entry_arches(
        declared_system_extension_executable_entry
    )
    tamandua_agent_resource_entry = tamandua_agent_entries[0] if tamandua_agent_entries else ""
    tamandua_agent_resource_arches = entry_arches(tamandua_agent_resource_entry)
    architecture_checks_supported = bool(expected_arch)
    architecture_matches_expected = bool(
        not architecture_checks_supported
        or (
            expected_arch in declared_macos_executable_arches
            and (
                not declared_system_extension_executable_entry
                or expected_arch in declared_system_extension_executable_arches
            )
            and (
                not tamandua_agent_resource_entry
                or expected_arch in tamandua_agent_resource_arches
            )
        )
    )

    return {
        "entry_count": len(normalized),
        "app_bundles": app_prefixes,
        "has_app_bundle": bool(app_prefixes),
        "has_info_plist": bool(info_plists),
        "has_macos_executable": bool(macos_entries),
        "has_declared_macos_executable": has_declared_macos_executable,
        "app_info_plist_valid": app_info_plist_valid,
        "app_info_plist_error": app_info_plist_error,
        "cf_bundle_executable": cf_bundle_executable,
        "app_cf_bundle_identifier": app_cf_bundle_identifier,
        "declared_macos_executable_entry": declared_macos_executable_entry,
        "expected_architecture": expected_arch,
        "architecture_checks_supported": architecture_checks_supported,
        "architecture_matches_expected": architecture_matches_expected,
        "declared_macos_executable_arches": declared_macos_executable_arches,
        "declared_system_extension_executable_arches": declared_system_extension_executable_arches,
        "tamandua_agent_resource_entry": tamandua_agent_resource_entry,
        "tamandua_agent_resource_arches": tamandua_agent_resource_arches,
        "has_system_extension": bool(
            sysext_info_plists
            and has_declared_system_extension_executable
            and has_system_extension_bundle_id
            and system_extension_contained_by_app_bundle_id
            and has_endpoint_security_extension_point
        ),
        "has_system_extension_executable": bool(sysext_entries),
        "has_declared_system_extension_executable": has_declared_system_extension_executable,
        "has_system_extension_info_plist": bool(sysext_info_plists),
        "system_extension_info_plist_valid": sysext_info_plist_valid,
        "system_extension_info_plist_error": sysext_info_plist_error,
        "system_extension_cf_bundle_executable": sysext_cf_bundle_executable,
        "system_extension_cf_bundle_identifier": sysext_cf_bundle_identifier,
        "system_extension_extension_point_identifier": sysext_extension_point_identifier,
        "has_system_extension_bundle_id": has_system_extension_bundle_id,
        "system_extension_contained_by_app_bundle_id": system_extension_contained_by_app_bundle_id,
        "has_endpoint_security_extension_point": has_endpoint_security_extension_point,
        "declared_system_extension_executable_entry": declared_system_extension_executable_entry,
        "has_tamandua_agent_resource": bool(tamandua_agent_entries),
        "info_plist_entries": info_plists[:10],
        "macos_executable_entries": macos_entries[:10],
        "system_extension_entries": sysext_entries[:10],
        "system_extension_info_plist_entries": sysext_info_plists[:10],
        "tamandua_agent_entries": tamandua_agent_entries[:10],
    }


def check_result(check_id: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"id": check_id, "passed": passed, "detail": detail}


def build_payload(
    *,
    app_zip: Path | None,
    dmg: Path | None,
    checksums: Path | None,
    run_id: str | None = None,
    require_system_extension: bool = True,
    allow_missing_checksum: bool = False,
) -> dict[str, Any]:
    started = utc_now()
    expected_hashes = parse_sha256sums(checksums) if checksums else None
    checks: list[dict[str, Any]] = []
    payload: dict[str, Any] = {
        "schema_version": 1,
        "artifact": ARTIFACT_NAME,
        "run_id": "",
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "name": PROFILE_NAME,
        "mode": "execute",
        "execute": True,
        "started_at": iso(started),
        "finished_at": "",
        "git": git_snapshot(),
        "benchmark_lane": "release-readiness",
        "claim_boundary": CLAIM_BOUNDARY,
        "deployable": False,
        "checksums": {
            "path": str(checksums) if checksums else None,
            "provided": checksums is not None,
            "entry_count": len(expected_hashes or {}),
        },
        "app_zip": None,
        "dmg": None,
        "checks": checks,
    }

    if app_zip is None:
        checks.append(check_result("app_zip_provided", False, "--app-zip is required"))
    elif not app_zip.exists():
        checks.append(check_result("app_zip_exists", False, f"{app_zip} does not exist"))
    else:
        zip_status = checksum_status(app_zip, expected_hashes)
        zip_status["structure"] = inspect_app_zip(app_zip)
        payload["app_zip"] = zip_status
        structure = zip_status["structure"]

        def system_extension_gap_detail() -> str:
            if not structure["has_system_extension_info_plist"]:
                return "missing system extension"
            if structure.get("system_extension_info_plist_error"):
                return str(structure["system_extension_info_plist_error"])
            if not structure["has_declared_system_extension_executable"]:
                return str(structure.get("system_extension_cf_bundle_executable") or "missing declared executable")
            if not structure["has_system_extension_bundle_id"]:
                return "CFBundleIdentifier missing or empty"
            if not structure["system_extension_contained_by_app_bundle_id"]:
                return (
                    "System Extension CFBundleIdentifier must be prefixed by app "
                    "CFBundleIdentifier: "
                    f"app={structure.get('app_cf_bundle_identifier') or 'missing'} "
                    f"sysext={structure.get('system_extension_cf_bundle_identifier') or 'missing'}"
                )
            if not structure["has_endpoint_security_extension_point"]:
                return (
                    "NSExtensionPointIdentifier is not "
                    f"{EXPECTED_SYSEXT_EXTENSION_POINT}: "
                    f"{structure.get('system_extension_extension_point_identifier') or 'missing'}"
                )
            return "incomplete system extension"

        checks.append(check_result("app_zip_exists", True, str(app_zip)))
        checks.append(
            check_result(
                "app_zip_checksum",
                bool(zip_status["checksum_matches"])
                or (allow_missing_checksum and zip_status["checksum_matches"] is None),
                "checksum matches published SHA256SUMS"
                if zip_status["checksum_matches"]
                else "checksum missing but allowed"
                if allow_missing_checksum and zip_status["checksum_matches"] is None
                else "checksum missing or mismatch",
            )
        )
        checks.append(
            check_result(
                "app_bundle_present",
                bool(structure["has_app_bundle"]),
                "ZIP contains a .app bundle" if structure["has_app_bundle"] else "ZIP has no .app bundle",
            )
        )
        checks.append(
            check_result(
                "info_plist_present",
                bool(structure["has_info_plist"]),
                "ZIP contains Contents/Info.plist"
                if structure["has_info_plist"]
                else "ZIP is missing Contents/Info.plist",
            )
        )
        checks.append(
            check_result(
                "macos_executable_present",
                bool(structure["has_declared_macos_executable"]),
                "ZIP contains the CFBundleExecutable entry under Contents/MacOS"
                if structure["has_declared_macos_executable"]
                else f"ZIP is missing declared CFBundleExecutable under Contents/MacOS: {structure.get('app_info_plist_error') or structure.get('cf_bundle_executable') or 'unknown'}",
            )
        )
        checks.append(
            check_result(
                "system_extension_present",
                bool(structure["has_system_extension"]) or not require_system_extension,
                "ZIP contains Contents/Library/SystemExtensions/*.systemextension with Info.plist and declared Contents/MacOS executable"
                if structure["has_system_extension"]
                else "system extension not required by CLI"
                if not require_system_extension
                else (
                    "ZIP is missing a complete Contents/Library/SystemExtensions/*.systemextension "
                    f"bundle: {system_extension_gap_detail()}"
                ),
            )
        )
        checks.append(
            check_result(
                "tamandua_agent_resource_present",
                bool(structure["has_tamandua_agent_resource"]),
                "ZIP contains a tamandua-agent helper/resource"
                if structure["has_tamandua_agent_resource"]
                else "ZIP is missing tamandua-agent helper/resource",
            )
        )
        checks.append(
            check_result(
                "mach_o_architecture_matches_artifact",
                bool(structure["architecture_matches_expected"]),
                (
                    "app executable, tamandua-agent helper, and System Extension include "
                    f"{structure['expected_architecture']}"
                )
                if structure["architecture_matches_expected"]
                else (
                    "Mach-O architecture mismatch or unreadable binaries for "
                    f"{structure.get('expected_architecture') or 'unknown'}: "
                    f"app={structure.get('declared_macos_executable_arches')}, "
                    f"agent={structure.get('tamandua_agent_resource_arches')}, "
                    f"sysext={structure.get('declared_system_extension_executable_arches')}"
                ),
            )
        )

    if dmg is not None:
        if not dmg.exists():
            checks.append(check_result("dmg_exists", False, f"{dmg} does not exist"))
        else:
            dmg_status = checksum_status(dmg, expected_hashes)
            payload["dmg"] = dmg_status
            checks.append(check_result("dmg_exists", True, str(dmg)))
            checks.append(
                check_result(
                    "dmg_checksum",
                    bool(dmg_status["checksum_matches"])
                    or (allow_missing_checksum and dmg_status["checksum_matches"] is None),
                    "checksum matches published SHA256SUMS"
                    if dmg_status["checksum_matches"]
                    else "checksum missing but allowed"
                    if allow_missing_checksum and dmg_status["checksum_matches"] is None
                    else "checksum missing or mismatch",
                )
            )

    covered = sum(1 for check in checks if check["passed"])
    missed = len(checks) - covered
    finished = utc_now()
    if run_id and not RUN_ID_RE.match(run_id):
        raise ValueError(f"run_id must match YYYYMMDDTHHMMSSZ-{PROFILE_ID}")
    run_id_value = run_id or finished.strftime("%Y%m%dT%H%M%SZ") + f"-{PROFILE_ID}"
    payload["deployable"] = all(check["passed"] for check in checks)
    payload["run_id"] = run_id_value
    payload["finished_at"] = iso(finished)
    payload["summary"] = {
        "tests": len(checks),
        "covered": covered,
        "partial": 0,
        "missed": missed,
        "planned": 0,
        "skipped": 0,
        "execution_failed": 0,
        "unknown_source_events": 0,
        "unexpected_high_or_critical_events": 0,
        "upstream_backed_tests": 0,
        "fallback_command_tests": 0,
        "gap_category_counts": {"release-artifact": missed} if missed else {},
        "actionable_gaps": [
            {
                "check_id": check["id"],
                "detail": check["detail"],
                "validation_category": "release-artifact",
            }
            for check in checks
            if not check["passed"]
        ],
    }
    payload["quality_gate"] = {
        "passed": payload["deployable"],
        "failures": [check["id"] for check in checks if not check["passed"]],
        "gap_category_counts": payload["summary"]["gap_category_counts"],
        "actionable_gaps": payload["summary"]["actionable_gaps"],
        "thresholds": {
            "benchmark_lane": "release-readiness",
            "require_app_zip": True,
            "require_checksum_match": not allow_missing_checksum,
            "require_system_extension": require_system_extension,
        },
    }
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# macOS Release Artifact Preflight",
        "",
        f"- Deployable: `{str(payload['deployable']).lower()}`",
        f"- Claim boundary: {payload['claim_boundary']}",
        "",
        "## Checks",
        "",
        "| Check | Result | Detail |",
        "| --- | --- | --- |",
    ]
    for check in payload["checks"]:
        result = "pass" if check["passed"] else "fail"
        lines.append(f"| `{check['id']}` | `{result}` | {check['detail']} |")
    return "\n".join(lines) + "\n"


def write_optional(path: str | None, content: str) -> None:
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-zip", type=Path, help="macOS .app ZIP artifact to inspect")
    parser.add_argument("--dmg", type=Path, help="Optional DMG artifact for checksum verification")
    parser.add_argument("--checksums", type=Path, help="Optional macos-SHA256SUMS file")
    parser.add_argument("--output-json", help="Optional JSON output path")
    parser.add_argument("--output-md", help="Optional Markdown output path")
    parser.add_argument(
        "--run-id",
        help="Optional explicit run id matching YYYYMMDDTHHMMSSZ-macos-release-artifact-preflight",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional benchmark runs directory; writes <run_id>.json and <run_id>.md",
    )
    parser.add_argument(
        "--allow-missing-checksum",
        action="store_true",
        help="Do not fail artifacts missing from the provided SHA256SUMS file",
    )
    parser.add_argument(
        "--no-require-system-extension",
        action="store_true",
        help="Do not require Contents/Library/SystemExtensions/*.systemextension in the app ZIP",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = build_payload(
        app_zip=args.app_zip,
        dmg=args.dmg,
        checksums=args.checksums,
        run_id=args.run_id,
        require_system_extension=not args.no_require_system_extension,
        allow_missing_checksum=args.allow_missing_checksum,
    )
    json_payload = json.dumps(payload, indent=2, sort_keys=True)
    write_optional(args.output_json, json_payload + "\n")
    write_optional(args.output_md, render_markdown(payload))
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / f"{payload['run_id']}.json").write_text(json_payload + "\n", encoding="utf-8")
        (output_dir / f"{payload['run_id']}.md").write_text(render_markdown(payload), encoding="utf-8")
    print(json_payload)
    return 0 if payload["deployable"] else 2


if __name__ == "__main__":
    sys.exit(main())
