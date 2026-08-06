#!/usr/bin/env python3
"""Validate the synthetic Runtime Trust profile/platform capability ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "schemas" / "runtime_trust_capability_matrix_v1.schema.json"
MATRIX_PATH = ROOT / "sdk" / "runtime-trust" / "capabilities" / "runtime_trust_matrix.json"
MAX_JSON_BYTES = 256 * 1024
EXPECTED_PAIRS = {
    ("mobile_app_guard", "android"), ("mobile_app_guard", "ios"),
    ("desktop_app_guard", "windows"), ("desktop_app_guard", "linux"), ("desktop_app_guard", "macos"),
    ("web_guard", "web"),
    ("anti_cheat", "android"), ("anti_cheat", "ios"), ("anti_cheat", "windows"),
    ("anti_cheat", "linux"), ("anti_cheat", "macos"),
}
EXPECTED_ENTRY_INVARIANTS = {
    ("mobile_app_guard", "android"): ("embedded_mobile_app", "degraded", "source_validated"),
    ("mobile_app_guard", "ios"): ("embedded_mobile_app", "degraded", "source_validated"),
    ("desktop_app_guard", "windows"): ("embedded_desktop_app", "unsupported", "unsupported"),
    ("desktop_app_guard", "linux"): ("embedded_desktop_app", "unsupported", "unsupported"),
    ("desktop_app_guard", "macos"): ("embedded_desktop_app", "unsupported", "unsupported"),
    ("web_guard", "web"): ("web_session", "degraded", "source_validated"),
    ("anti_cheat", "android"): ("game_client", "unsupported", "unsupported"),
    ("anti_cheat", "ios"): ("game_client", "unsupported", "unsupported"),
    ("anti_cheat", "windows"): ("game_client", "unsupported", "unsupported"),
    ("anti_cheat", "linux"): ("game_client", "unsupported", "unsupported"),
    ("anti_cheat", "macos"): ("game_client", "unsupported", "unsupported"),
}
REQUIRED_BOUNDARIES = {
    "desktop_app_guard": {"existing_runtime_integrity_protects_agent_not_embedded_third_party_app"},
    "web_guard": {"client_controlled_javascript_is_removable", "browser_extension_foundation_is_not_embedded_sdk_parity"},
    "anti_cheat": {"anti_cheat_product_not_implemented"},
}
SOURCE_PREFIXES = {
    ("mobile_app_guard", "android"): ("sdk/mobile/android/", "sdk/mobile/rust-core/"),
    ("mobile_app_guard", "ios"): ("sdk/mobile/ios/", "sdk/mobile/rust-core/"),
    ("desktop_app_guard", "windows"): ("apps/tamandua_agent/",),
    ("desktop_app_guard", "linux"): ("apps/tamandua_agent/",),
    ("desktop_app_guard", "macos"): ("apps/tamandua_agent/",),
    ("web_guard", "web"): ("apps/tamandua_browser_extension/",),
    ("anti_cheat", "android"): ("docs/strategy/",),
    ("anti_cheat", "ios"): ("docs/strategy/",),
    ("anti_cheat", "windows"): ("docs/strategy/",),
    ("anti_cheat", "linux"): ("docs/strategy/",),
    ("anti_cheat", "macos"): ("docs/strategy/",),
}
REQUIRED_SOURCE_PREFIX_GROUPS = {
    ("mobile_app_guard", "android"): (("sdk/mobile/android/",), ("sdk/mobile/rust-core/",)),
    ("mobile_app_guard", "ios"): (("sdk/mobile/ios/",), ("sdk/mobile/rust-core/",)),
}


class CapabilityMatrixError(ValueError):
    pass


def _reject_non_finite(value: str) -> None:
    raise CapabilityMatrixError(f"non-finite JSON constant rejected: {value}")


def load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise CapabilityMatrixError(f"JSON document exceeds {MAX_JSON_BYTES} bytes: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_non_finite)
    if not isinstance(value, dict):
        raise CapabilityMatrixError(f"expected JSON object: {path}")
    return value


def canonical_sha256(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def bundle_contract_digest(entry: dict[str, Any]) -> str:
    bundle = entry["detector_bundle"]
    return canonical_sha256({
        "bundle_id": bundle["bundle_id"],
        "bundle_version": bundle["bundle_version"],
        "profile": entry["profile"],
        "platform": entry["platform"],
        "target_scope": entry["target_scope"],
        "state": entry["state"],
        "evidence_status": entry["evidence_status"],
        "required_signal_ids": sorted(entry["required_signal_ids"]),
        "limitations": sorted(entry["limitations"]),
        "source_paths": sorted(entry["source_paths"]),
    })


def derive_signal_completeness(entry: dict[str, Any], observed_signal_ids: list[str]) -> dict[str, Any]:
    if entry["state"] in {"unsupported", "not_applicable"} or "detector_bundle" not in entry:
        return {"signal_completeness": "unknown", "missing_signal_ids": []}
    required = set(entry["required_signal_ids"])
    missing = sorted(required - set(observed_signal_ids))
    return {
        "signal_completeness": "missing_required" if missing else "complete",
        "missing_signal_ids": missing,
    }


def schema_errors(value: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    return [f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors]


def semantic_errors(matrix: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    entries = matrix.get("entries") or []
    pairs = [(entry.get("profile"), entry.get("platform")) for entry in entries if isinstance(entry, dict)]
    if len(pairs) != len(set(pairs)):
        errors.append("profile/platform pairs must be unique")
    if set(pairs) != EXPECTED_PAIRS:
        errors.append(f"profile/platform coverage mismatch: {sorted(set(pairs) ^ EXPECTED_PAIRS)}")
    tracked = {
        path
        for path in subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
        ).stdout.decode("utf-8").split("\0")
        if path
    }
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        label = f"{entry.get('profile')}/{entry.get('platform')}"
        pair = (entry.get("profile"), entry.get("platform"))
        state = entry.get("state")
        expected = EXPECTED_ENTRY_INVARIANTS.get(pair)
        actual = (entry.get("target_scope"), state, entry.get("evidence_status"))
        if expected is not None and actual != expected:
            errors.append(f"{label}: category invariant mismatch: expected {expected}, got {actual}")
        required_boundaries = REQUIRED_BOUNDARIES.get(entry.get("profile"), set())
        missing_boundaries = sorted(required_boundaries - set(entry.get("limitations") or []))
        if missing_boundaries:
            errors.append(f"{label}: missing required category boundaries: {missing_boundaries}")
        source_paths = entry.get("source_paths") or []
        for prefix_group in REQUIRED_SOURCE_PREFIX_GROUPS.get(pair, ()):
            if not any(path.startswith(prefix_group) for path in source_paths):
                errors.append(f"{label}: missing required source prefix group: {prefix_group}")
        if state in {"degraded", "supported"}:
            if not entry.get("required_signal_ids"):
                errors.append(f"{label}: active state requires required_signal_ids")
            if "detector_bundle" not in entry:
                errors.append(f"{label}: active state requires detector_bundle")
            elif entry["detector_bundle"].get("contract_digest") != bundle_contract_digest(entry):
                errors.append(f"{label}: detector bundle contract digest mismatch")
        if state in {"unsupported", "not_applicable"}:
            if entry.get("required_signal_ids"):
                errors.append(f"{label}: unsupported/not_applicable cannot assert required signals")
            if "detector_bundle" in entry:
                errors.append(f"{label}: unsupported/not_applicable cannot assert detector bundle")
        for source_path in source_paths:
            parts = PurePosixPath(source_path).parts
            if "." in parts or ".." in parts or PurePosixPath(source_path).is_absolute():
                errors.append(f"{label}: source path must be normalized repo-relative POSIX: {source_path}")
                continue
            resolved = (ROOT / source_path).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"{label}: source path escapes repository root: {source_path}")
                continue
            if source_path not in tracked:
                errors.append(f"{label}: source path must be git-tracked: {source_path}")
            if not any(source_path.startswith(prefix) for prefix in SOURCE_PREFIXES.get(pair, ())):
                errors.append(f"{label}: source path violates category source family: {source_path}")
            if not resolved.is_file():
                errors.append(f"{label}: source path does not exist: {source_path}")
    return errors


def validate(strict: bool = False) -> dict[str, Any]:
    schema = load_json(SCHEMA_PATH)
    matrix = load_json(MATRIX_PATH)
    errors = schema_errors(matrix, schema)
    errors.extend(semantic_errors(matrix))
    if strict and any(entry.get("state") == "supported" for entry in matrix.get("entries") or []):
        errors.append("strict source-review matrix cannot claim supported state")
    return {
        "schema": "tamandua.runtime_trust.capability_matrix_validation/v1",
        "ok": not errors,
        "evidence_class": "synthetic_contract",
        "external_claim_allowed": False,
        "entries": len(matrix.get("entries") or []),
        "errors": errors,
        "non_claims": ["runtime_derivation_enabled", "platform_coverage", "efficacy", "parity", "production_readiness"]
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate(strict=args.strict)
    except (OSError, json.JSONDecodeError, CapabilityMatrixError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
