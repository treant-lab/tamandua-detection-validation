"""Offline, non-executing readiness gate for the local-model sidecar package.

This validates immutable package inputs and governance contracts.  It does not
start the service, import a provider runtime, or deserialize a model artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[3]
ML_ROOT = REPO_ROOT / "apps" / "tamandua_ml"
if str(ML_ROOT) not in sys.path:
    sys.path.insert(0, str(ML_ROOT))

from src.local_model_service.registry import load_registry
from src.ai_security.lightgbm_guard import LightGBMGuard, LightGBMGuardPolicy
from src.local_model_service.feature_contracts import HIST256_CONTRACT_SHA256


API_VERSION = "tamandua.io/local-model-sidecar-readiness-gate/v1"
KIND = "LocalModelSidecarReadinessGateReport"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CLAIM_BOUNDARY = (
    "Synthetic offline package-readiness smoke only. Passing validates pinned files, "
    "default-off service templates, loopback and ACL contract markers, provider registry "
    "governance, and an eligible static promotion report; it does not execute a model, "
    "prove malware efficacy, validate a live OS installation, or authorize deployment."
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: dict[str, Any]) -> str:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_regular_once(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size > maximum:
        raise ValueError("candidate bundle file is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    chunks: list[bytes] = []
    total = 0
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("candidate bundle file changed while opening")
        while True:
            chunk = os.read(fd, min(1024 * 1024, maximum - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ValueError("candidate bundle file exceeds its byte cap")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    current = path.stat()
    identities = {(item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns) for item in (before, opened, after, current)}
    data = b"".join(chunks)
    if len(identities) != 1 or len(data) != before.st_size:
        raise ValueError("candidate bundle file changed during guarded read")
    return data


def _safe_repo_file(repo_root: Path, relative_value: Any) -> Path:
    if not isinstance(relative_value, str) or not relative_value:
        raise ValueError("manifest path must be a non-empty repo-relative string")
    relative = Path(relative_value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("manifest paths must be safe and repo-relative")
    root = repo_root.resolve(strict=True)
    current = root
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for part in relative.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & reparse_flag:
            raise ValueError("manifest paths may not contain links or reparse points")
    path = current.resolve(strict=True)
    path.relative_to(root)
    if not path.is_file() or path.is_symlink():
        raise ValueError("manifest path must identify a regular non-symlink file")
    return path


def _check(checks: list[dict[str, Any]], check_id: str, passed: bool, detail: str) -> None:
    checks.append({"id": check_id, "status": "pass" if passed else "fail", "detail": detail[:500]})


def _load_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _load_bytes_object(data: bytes, label: str) -> dict[str, Any]:
    value = json.loads(data.decode("utf-8", errors="strict"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def build_report(
    repo_root: Path,
    manifest_path: Path,
    registry_path: Path,
    promotion_report_path: Path,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    blockers: list[str] = []

    manifest = _load_object(manifest_path, "package manifest")
    manifest_ok = (
        manifest.get("schema_version") == "tamandua.local_model_sidecar_package.v1"
        and manifest.get("evidence_class") == "synthetic_parity"
        and manifest.get("execution_allowed") is False
        and manifest.get("service_enabled_default") is False
        and manifest.get("agent_enabled_default") is False
        and manifest.get("loopback_only") is True
    )
    _check(checks, "manifest_policy", manifest_ok, "manifest must be synthetic, default-off, loopback-only, and non-executing")
    if not manifest_ok:
        blockers.append("manifest_policy_invalid")

    entries = manifest.get("files")
    hashes_ok = isinstance(entries, list) and len(entries) >= 7
    resolved: dict[str, Path] = {}
    if hashes_ok:
        seen: set[str] = set()
        for entry in entries:
            try:
                if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                    raise ValueError("invalid file entry")
                value = entry["path"]
                expected = entry["sha256"]
                if value in seen or not isinstance(expected, str) or not SHA256.fullmatch(expected):
                    raise ValueError("duplicate path or invalid SHA-256")
                path = _safe_repo_file(repo_root, value)
                if _sha256(path) != expected:
                    raise ValueError("hash mismatch")
                seen.add(value)
                resolved[value] = path
            except (OSError, ValueError, KeyError):
                hashes_ok = False
                break
    _check(checks, "pinned_package_hashes", hashes_ok, "all required package files must be confined and SHA-256 pinned")
    if not hashes_ok:
        blockers.append("package_hash_validation_failed")

    candidate_bundle = manifest.get("candidate_bundle")
    candidate_bundle_value = candidate_bundle if isinstance(candidate_bundle, dict) else {}
    freeze_pin = candidate_bundle_value.get("freeze_manifest") if isinstance(candidate_bundle_value.get("freeze_manifest"), dict) else {}
    holdout_pin = candidate_bundle_value.get("holdout_evidence") if isinstance(candidate_bundle_value.get("holdout_evidence"), dict) else {}
    bundle_files: dict[str, Path] = {}
    bundle_bytes: dict[str, bytes] = {}
    bundle_pins_ok = isinstance(candidate_bundle, dict) and set(candidate_bundle) == {
        "artifact", "feature_contract", "freeze_manifest", "holdout_evidence"
    }
    if bundle_pins_ok:
        for name, pin in candidate_bundle.items():
            try:
                if not isinstance(pin, dict) or set(pin) != {"path", "sha256"}:
                    raise ValueError("candidate bundle pin must contain path and sha256")
                expected = pin["sha256"]
                if not isinstance(expected, str) or SHA256.fullmatch(expected) is None:
                    raise ValueError("candidate bundle SHA-256 is invalid")
                path = _safe_repo_file(repo_root, pin["path"])
                maximum = 50_000_000 if name == "artifact" else 16 * 1024 * 1024
                pinned_bytes = _read_regular_once(path, maximum)
                if hashlib.sha256(pinned_bytes).hexdigest() != expected:
                    raise ValueError("candidate bundle hash mismatch")
                bundle_files[name] = path
                bundle_bytes[name] = pinned_bytes
            except (OSError, ValueError, KeyError, TypeError):
                bundle_pins_ok = False
                break
    _check(checks, "pinned_hist256_candidate_bundle", bundle_pins_ok, "artifact, feature contract, pre-holdout freeze, and governed holdout evidence must be repo-confined and SHA-256 pinned")
    if not bundle_pins_ok:
        blockers.append("hist256_candidate_bundle_missing_or_unpinned")

    def content(suffix: str) -> str:
        match = next((path for name, path in resolved.items() if name.endswith(suffix)), None)
        return match.read_text(encoding="utf-8") if match else ""

    linux_env = content("linux/local-model-sidecar.env.example")
    linux_dropin = content("linux/tamandua-agent-local-model.conf.example")
    linux_unit = content("linux/tamandua-local-model-sidecar.service")
    windows = content("windows/install-local-model-sidecar.ps1")
    default_off_ok = (
        "TAMANDUA_LOCAL_MODEL_SERVICE_ENABLED=false" in linux_env
        and "TAMANDUA_LOCAL_MODEL_SERVICE_ENABLED=false" in linux_dropin
        and "TAMANDUA_LOCAL_MODEL_SERVICE_HOST=127.0.0.1" in linux_env
        and "WantedBy=multi-user.target" in linux_unit
        and "[switch] $Enable" in windows
        and "if (-not $Enable)" in windows
        and "start= demand" in windows
    )
    _check(checks, "default_off_contract", default_off_ok, "Linux and Windows templates require explicit opt-in")
    if not default_off_ok:
        blockers.append("default_off_contract_invalid")

    acl_ok = all(
        marker in linux_unit
        for marker in ("User=tamandua-model", "NoNewPrivileges=true", "CapabilityBoundingSet=", "IPAddressDeny=any", "IPAddressAllow=localhost", "ReadOnlyPaths=/var/lib/tamandua/model-scan-input")
    ) and all(
        marker in windows
        for marker in ("NT AUTHORITY\\LocalService", "SidecarRights = 'Read'", "SetAccessRuleProtection($true, $false)", "ReparsePoint", "Get-FileHash")
    )
    _check(checks, "acl_isolation_contract", acl_ok, "least-privilege identities, read-only handoff, reparse rejection, and loopback isolation are required")
    if not acl_ok:
        blockers.append("acl_isolation_contract_invalid")

    mac_ok = False
    mac_path = next((path for name, path in resolved.items() if name.endswith("macos/com.tamandua.local-model-sidecar.plist")), None)
    if mac_path:
        try:
            with mac_path.open("rb") as handle:
                plist = plistlib.load(handle)
            env = plist.get("EnvironmentVariables", {})
            mac_ok = (
                plist.get("Disabled") is True
                and plist.get("RunAtLoad") is False
                and plist.get("UserName") == "_tamanduamodel"
                and env.get("TAMANDUA_LOCAL_MODEL_SERVICE_ENABLED") == "false"
                and env.get("TAMANDUA_LOCAL_MODEL_SERVICE_HOST") == "127.0.0.1"
            )
        except (OSError, plistlib.InvalidFileException):
            pass
    _check(checks, "macos_default_off_contract", mac_ok, "launchd template must remain disabled, loopback, and unprivileged")
    if not mac_ok:
        blockers.append("macos_default_off_contract_invalid")

    registry_ok = False
    registry_hash = _sha256(registry_path) if registry_path.is_file() else None
    try:
        registry = load_registry(registry_path)
        registry_ok = (
            registry.policy.get("enabled_default") is False
            and registry.policy.get("remote_bind_allowed") is False
            and registry.policy.get("remote_download_allowed") is False
            and registry.policy.get("enforcement_allowed") is False
            and not registry.enabled_providers()
        )
    except (OSError, ValueError, json.JSONDecodeError):
        registry = None
    expected_registry = manifest.get("provider_registry")
    try:
        registry_pin_ok = bool(
            registry_hash
            and isinstance(expected_registry, dict)
            and set(expected_registry) == {"path", "sha256"}
            and expected_registry.get("sha256") == registry_hash
            and SHA256.fullmatch(str(expected_registry.get("sha256") or "")) is not None
            and _safe_repo_file(repo_root, expected_registry.get("path"))
            == registry_path.resolve(strict=True)
        )
    except (OSError, ValueError):
        registry_pin_ok = False
    registry_ok = registry_ok and registry_pin_ok
    _check(checks, "provider_registry", registry_ok, "registry must be pinned, valid, default-off, local-only, and non-enforcing")
    if not registry_ok:
        blockers.append("provider_registry_invalid_or_unpinned")

    promotion = _load_object(promotion_report_path, "promotion report")
    promotion_hash = _sha256(promotion_report_path)
    try:
        promotion_schema = _load_object(
            repo_root / "schemas" / "external_model_promotion_gate_v1.schema.json",
            "external model promotion schema",
        )
        promotion_schema_ok = not list(
            jsonschema.Draft202012Validator(promotion_schema).iter_errors(promotion)
        )
    except (OSError, ValueError, json.JSONDecodeError, jsonschema.SchemaError):
        promotion_schema_ok = False
    expected_promotion = manifest.get("promotion_report")
    try:
        promotion_pin_ok = (
            isinstance(expected_promotion, dict)
            and set(expected_promotion) == {"path", "sha256"}
            and expected_promotion.get("sha256") == promotion_hash
            and SHA256.fullmatch(str(expected_promotion.get("sha256") or "")) is not None
            and _safe_repo_file(repo_root, expected_promotion.get("path"))
            == promotion_report_path.resolve(strict=True)
        )
    except (OSError, ValueError):
        promotion_pin_ok = False
    candidate = promotion.get("candidate") if isinstance(promotion.get("candidate"), dict) else {}
    artifact_hash = candidate.get("artifact_sha256")
    matching_providers = [
        provider
        for provider in (registry.providers if registry and isinstance(artifact_hash, str) and SHA256.fullmatch(artifact_hash) else ())
        if provider.implementation == "lightgbm_local" and provider.artifact_sha256 == artifact_hash
    ]
    evidence = promotion.get("benchmark_evidence") if isinstance(promotion.get("benchmark_evidence"), dict) else {}
    scans = promotion.get("static_scans")
    freeze: dict[str, Any] = {}
    holdout: dict[str, Any] = {}
    feature_contract: dict[str, Any] = {}
    bundle_schema_ok = False
    artifact_guard_ok = False
    bundle_schema_detail = "freeze, governed holdout, and feature contract must validate against their v1 schemas"
    if bundle_pins_ok:
        try:
            freeze = _load_bytes_object(bundle_bytes["freeze_manifest"], "hist256 freeze manifest")
            holdout = _load_bytes_object(bundle_bytes["holdout_evidence"], "hist256 holdout evidence")
            feature_contract = _load_bytes_object(bundle_bytes["feature_contract"], "hist256 feature contract")
            freeze_schema = _load_object(repo_root / "schemas" / "hist256_candidate_freeze_v1.schema.json", "hist256 freeze schema")
            holdout_schema = _load_object(repo_root / "schemas" / "hist256_holdout_evaluation_v1.schema.json", "hist256 holdout schema")
            feature_schema = _load_object(repo_root / "schemas" / "hist256_feature_contract_v1.schema.json", "hist256 feature contract schema")
            jsonschema.Draft202012Validator(freeze_schema).validate(freeze)
            jsonschema.Draft202012Validator(holdout_schema).validate(holdout)
            jsonschema.Draft202012Validator(feature_schema).validate(feature_contract)
            freeze_seal = dict(freeze)
            declared_freeze_seal = freeze_seal.pop("freeze_payload_sha256")
            contract_seal = dict(feature_contract)
            declared_contract_seal = contract_seal.pop("contract_sha256")
            if _canonical_sha256(freeze_seal) != declared_freeze_seal:
                raise ValueError("freeze payload seal mismatch")
            if _canonical_sha256(contract_seal) != declared_contract_seal:
                raise ValueError("feature contract payload seal mismatch")
            if declared_contract_seal != HIST256_CONTRACT_SHA256:
                raise ValueError("feature contract differs from built-in runtime contract")
            bundle_schema_ok = True

            artifact_bytes = bundle_bytes["artifact"]
            artifact_guard_ok = LightGBMGuard(
                LightGBMGuardPolicy(
                    expected_feature_dim=256,
                    allowed_versions=("v4",),
                    max_bytes=len(artifact_bytes),
                )
            ).scan_bytes(artifact_bytes).clean
        except (OSError, ValueError, KeyError, json.JSONDecodeError, jsonschema.ValidationError, jsonschema.SchemaError) as exc:
            bundle_schema_ok = False
            artifact_guard_ok = False
            bundle_schema_detail = f"hist256 bundle validation failed: {type(exc).__name__}: {exc}"
    _check(checks, "hist256_bundle_schemas", bundle_schema_ok, bundle_schema_detail)
    _check(checks, "lightgbm_artifact_guard", artifact_guard_ok, "the exact pinned artifact bytes must pass LightGBM Guard as a 256-feature v4 model")
    if not bundle_schema_ok:
        blockers.append("hist256_candidate_bundle_schema_invalid")
    if not artifact_guard_ok:
        blockers.append("lightgbm_artifact_guard_not_clean")

    freeze_artifact = freeze.get("artifact") if isinstance(freeze.get("artifact"), dict) else {}
    freeze_contract = freeze.get("feature_contract") if isinstance(freeze.get("feature_contract"), dict) else {}
    freeze_decision = freeze.get("decision") if isinstance(freeze.get("decision"), dict) else {}
    provider = matching_providers[0] if len(matching_providers) == 1 else None
    cross_contract_ok = bool(
        bundle_pins_ok
        and bundle_schema_ok
        and provider
        and provider.implementation == "lightgbm_local"
        and provider.enabled is False
        and provider.decision_mode == "decision_only"
        and provider.feature_contract_id == "tamandua.byte-histogram-256.v1"
        and provider.feature_dimension == 256
        and provider.artifact_format == "lightgbm-text-v4"
        and provider.artifact_sha256 == candidate_bundle["artifact"]["sha256"]
        and provider.artifact_size_bytes == bundle_files["artifact"].stat().st_size
        and provider.artifact_path is not None
        and provider.artifact_path.resolve() == bundle_files["artifact"].resolve(strict=True)
        and freeze_artifact.get("sha256") == provider.artifact_sha256
        and freeze_artifact.get("size_bytes") == provider.artifact_size_bytes
        and freeze_contract.get("id") == provider.feature_contract_id
        and freeze_contract.get("feature_count") == provider.feature_dimension
        and freeze_contract.get("sha256") == feature_contract.get("contract_sha256")
        and freeze_decision.get("threshold") == provider.threshold == holdout.get("threshold")
        and freeze_decision.get("calibration_id") == provider.calibration_id == holdout.get("calibration_id")
        and freeze_decision.get("score_orientation") == provider.score_orientation == "higher_is_more_malicious"
        and freeze_decision.get("initial_lane") == "endpoint_shadow"
        and freeze_decision.get("may_enforce") is False
        and holdout.get("freeze_manifest_sha256") == candidate_bundle["freeze_manifest"]["sha256"]
        and holdout.get("artifact_sha256") == provider.artifact_sha256
        and holdout.get("feature_contract_id") == provider.feature_contract_id
        and holdout.get("evidence_class") == "governed_holdout"
        and holdout.get("metrics", {}).get("sample_gate_met") is True
        and holdout.get("may_promote") is False
        and holdout.get("may_enforce") is False
    )
    _check(checks, "hist256_cross_contract", cross_contract_ok, "artifact SHA/size, contract digest, threshold, calibration, lineage evidence, score orientation, and endpoint_shadow lane must agree")
    if not cross_contract_ok:
        blockers.append("hist256_cross_contract_mismatch")
    promotion_ok = (
        promotion_schema_ok
        and promotion_pin_ok
        and promotion.get("api_version") == "tamandua.io/external-model-promotion-gate/v1"
        and promotion.get("kind") == "ExternalModelPromotionGateReport"
        and promotion.get("mode") == "offline_static_no_execution"
        and promotion.get("target") == "endpoint_shadow"
        and promotion.get("decision") == "eligible_for_manual_review"
        and promotion.get("may_execute_model") is False
        and promotion.get("may_publish_claim") is False
        and promotion.get("promotion_blockers") == []
        and candidate.get("status") in {"intake_approved", "shadow", "benchmark_approved"}
        and isinstance(artifact_hash, str)
        and SHA256.fullmatch(artifact_hash) is not None
        and len(matching_providers) == 1
        and matching_providers[0].evidence_class == "governed_holdout"
        and evidence.get("class") in {"governed_holdout", "production_telemetry"}
        and evidence.get("artifact_sha256") == artifact_hash
        and evidence.get("path") == holdout_pin.get("path")
        and isinstance(scans, list)
        and len(scans) >= 2
        and all(isinstance(scan, dict) and scan.get("status") == "clean" for scan in scans)
        and cross_contract_ok
        and artifact_guard_ok
    )
    _check(checks, "eligible_promotion_report", promotion_ok, "eligible static report and candidate hash must match a governed provider")
    if not promotion_ok:
        blockers.append("promotion_report_not_eligible_or_provider_mismatch")

    blockers = sorted(set(blockers))
    return {
        "api_version": API_VERSION,
        "kind": KIND,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "mode": "offline_static_no_execution",
        "evidence": {"class": "synthetic_parity", "scope": "package_readiness_smoke"},
        "decision": "eligible_for_manual_review" if not blockers else "blocked",
        "may_start_service": False,
        "may_execute_model": False,
        "may_publish_efficacy_claim": False,
        "inputs": {
            "manifest_sha256": _sha256(manifest_path),
            "provider_registry_sha256": registry_hash,
            "promotion_report_sha256": promotion_hash,
            "candidate_artifact_sha256": artifact_hash if isinstance(artifact_hash, str) else None,
            "feature_contract_sha256": freeze_contract.get("sha256") if bundle_schema_ok else None,
            "freeze_manifest_sha256": freeze_pin.get("sha256"),
            "holdout_evidence_sha256": holdout_pin.get("sha256"),
            "holdout_lineage_sha256": holdout.get("holdout_lineage_sha256") if bundle_schema_ok else None,
            "threshold": freeze_decision.get("threshold") if bundle_schema_ok else None,
            "calibration_id": freeze_decision.get("calibration_id") if bundle_schema_ok else None,
            "initial_lane": freeze_decision.get("initial_lane") if bundle_schema_ok else None,
            "decision_mode": provider.decision_mode if provider else None,
        },
        "checks": checks,
        "promotion_blockers": blockers,
        "claim_boundary": CLAIM_BOUNDARY,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--promotion-report", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = build_report(args.repo_root, args.manifest, args.registry, args.promotion_report)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if report["decision"] == "eligible_for_manual_review" else 2


if __name__ == "__main__":
    raise SystemExit(main())
