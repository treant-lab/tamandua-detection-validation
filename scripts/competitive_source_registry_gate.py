#!/usr/bin/env python3
"""Offline structural and governed-readiness gates for source registries."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


ALLOWED_CLASSES = {"normative", "vendor_declared", "measured"}
ALLOWED_LICENSE_STATES = {"pending", "approved", "restricted", "prohibited"}
ALLOWED_CATEGORIES = {
    "mobile_app_shielding", "mobile_device_mtd", "siem_integration", "security_schema",
    "cnapp", "endpoint_edr", "platform_instrumentation",
}
EXPECTED_SOURCE_IDS = {
    "SRC-GSQ-DEX-001", "SRC-GSQ-IXG-001", "SRC-GSQ-VIRT-001", "SRC-GSQ-RASP-001",
    "SRC-ZIM-ZDEF-001", "SRC-ZIM-MTD-001", "SRC-LOOK-MES-001",
    "SRC-GOOG-ING-001", "SRC-GOOG-LEG-001", "SRC-GOOG-LIFE-001", "SRC-MS-LOG-001", "SRC-MS-MIG-001",
    "SRC-MS-ASIM-001", "SRC-EL-ECS-001", "SRC-EL-INT-001", "SRC-OCSF-001",
    "SRC-WIZ-CLOUD-001", "SRC-WIZ-DSPM-001", "SRC-PRIS-CSPM-001", "SRC-PRIS-CNAPP-001",
    "SRC-CS-FALCON-001", "SRC-CS-ENDPOINT-001", "SRC-S1-XDR-001", "SRC-S1-ENDPOINT-001",
    "SRC-MS-MDE-001", "SRC-MS-XDR-001", "SRC-PAN-XDR-001", "SRC-PAN-XQL-001",
    "SRC-APPDOME-SUITE-001", "SRC-APPDOME-OBF-001", "SRC-VMX-XTD-001",
    "SRC-ANDROID-PROF-001", "SRC-ANDROID-POWER-001", "SRC-APPLE-XCT-001",
    "SRC-APPLE-METRICKIT-001",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_ID_RE = re.compile(r"^SRC-(?:[A-Z0-9]+-)+[0-9]{3}$")
PROTOCOL_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*-v[1-9][0-9]*$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
MAX_REGISTRY_BYTES = 1_048_576
MAX_SOURCES = 256
MAX_REVIEW_WINDOW_DAYS = 92
MAX_TEXT_LENGTHS = {"product": 200, "scope": 2_000, "canonical_url": 2_048}


def _parse_date(value: Any, field: str, errors: list[str]) -> date | None:
    if not isinstance(value, str):
        errors.append(f"{field}: expected ISO date")
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        errors.append(f"{field}: invalid ISO date {value!r}")
        return None
    if parsed.isoformat() != value:
        errors.append(f"{field}: date must use YYYY-MM-DD")
        return None
    return parsed


def _valid_https_url(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > MAX_TEXT_LENGTHS["canonical_url"]:
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme == "https"
        and hostname
        and HOST_RE.fullmatch(hostname)
        and parsed.path
        and parsed.username is None
        and parsed.password is None
        and not any(character.isspace() for character in value)
    )


def validate_registry(payload: Any, *, as_of: date, strict: bool) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["registry: expected object"]
    if payload.get("schema_version") != "competitive_source_registry_v1":
        errors.append("schema_version: expected competitive_source_registry_v1")
    if (
        not isinstance(payload.get("registry_id"), str)
        or not payload["registry_id"].strip()
        or len(payload["registry_id"]) > 200
    ):
        errors.append("registry_id: non-empty string required")
    if strict:
        extra_top = sorted(set(payload) - {"schema_version", "registry_id", "sources"})
        if extra_top:
            errors.append(f"registry: unexpected fields {extra_top}")
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        return errors + ["sources: expected non-empty array"]
    if len(sources) > MAX_SOURCES:
        errors.append(f"sources: maximum {MAX_SOURCES} entries exceeded")

    seen: set[str] = set()
    actual_ids: set[str] = set()
    required = {
        "source_id", "class", "canonical_url", "product", "scope", "retrieved_at",
        "version", "revision", "snapshot", "license_review", "permitted_use", "measurement_origin",
        "comparison_category", "protocol_id", "covers_source_ids", "measurement_scope",
        "independent_measurement_source_ids", "next_review_at",
    }
    for index, source in enumerate(sources):
        prefix = f"sources[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{prefix}: expected object")
            continue
        missing = sorted(required - source.keys())
        if missing:
            errors.append(f"{prefix}: missing required fields {missing}")
        if strict:
            extra = sorted(set(source) - required)
            if extra:
                errors.append(f"{prefix}: unexpected fields {extra}")
        source_id = source.get("source_id")
        if not isinstance(source_id, str) or not SOURCE_ID_RE.fullmatch(source_id):
            errors.append(f"{prefix}.source_id: invalid source ID")
        elif source_id in seen:
            errors.append(f"{prefix}.source_id: duplicate {source_id}")
        else:
            seen.add(source_id)
            actual_ids.add(source_id)

        source_class = source.get("class")
        if source_class not in ALLOWED_CLASSES:
            errors.append(f"{prefix}.class: invalid class {source_class!r}")
        category = source.get("comparison_category")
        if category not in ALLOWED_CATEGORIES:
            errors.append(f"{prefix}.comparison_category: invalid category {category!r}")
        protocol_id = source.get("protocol_id")
        if not isinstance(protocol_id, str) or not PROTOCOL_ID_RE.fullmatch(protocol_id):
            errors.append(f"{prefix}.protocol_id: invalid versioned protocol ID")
        url = source.get("canonical_url")
        if not _valid_https_url(url):
            errors.append(f"{prefix}.canonical_url: valid HTTPS URL with public host and path required")
        elif "latest" in url.lower() and not (source.get("version") or source.get("revision")):
            errors.append(f"{prefix}: URL containing latest requires pinned version or revision")
        for field in ("product", "scope"):
            if not isinstance(source.get(field), str) or not source[field].strip():
                errors.append(f"{prefix}.{field}: non-empty string required")
            elif len(source[field]) > MAX_TEXT_LENGTHS[field]:
                errors.append(f"{prefix}.{field}: exceeds {MAX_TEXT_LENGTHS[field]} characters")
        for field in ("version", "revision"):
            value = source.get(field)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                errors.append(f"{prefix}.{field}: expected explicit null or non-empty string")
            elif isinstance(value, str) and len(value) > 200:
                errors.append(f"{prefix}.{field}: exceeds 200 characters")
            if isinstance(value, str) and value.strip().lower() == "latest":
                errors.append(f"{prefix}.{field}: latest is not an immutable pin")

        retrieved_at = _parse_date(source.get("retrieved_at"), f"{prefix}.retrieved_at", errors)
        review_at = _parse_date(source.get("next_review_at"), f"{prefix}.next_review_at", errors)
        if retrieved_at and retrieved_at > as_of:
            errors.append(f"{prefix}.retrieved_at: cannot be in the future")
        if review_at and review_at <= as_of:
            errors.append(f"{prefix}.next_review_at: review is due or expired")
        if retrieved_at and review_at:
            review_window_days = (review_at - retrieved_at).days
            if review_window_days <= 0 or review_window_days > MAX_REVIEW_WINDOW_DAYS:
                errors.append(
                    f"{prefix}.next_review_at: review window must be 1-{MAX_REVIEW_WINDOW_DAYS} days"
                )

        snapshot = source.get("snapshot")
        if not isinstance(snapshot, dict):
            errors.append(f"{prefix}.snapshot: expected object")
            snapshot = {}
        snapshot_fields = {"status", "required_before_governed_comparison", "immutable_uri", "sha256"}
        missing_snapshot = sorted(snapshot_fields - snapshot.keys())
        if missing_snapshot:
            errors.append(f"{prefix}.snapshot: missing required fields {missing_snapshot}")
        if strict:
            extra_snapshot = sorted(set(snapshot) - snapshot_fields)
            if extra_snapshot:
                errors.append(f"{prefix}.snapshot: unexpected fields {extra_snapshot}")
        status = snapshot.get("status")
        digest = snapshot.get("sha256")
        immutable_uri = snapshot.get("immutable_uri")
        if status not in {"live", "archived"}:
            errors.append(f"{prefix}.snapshot.status: expected live or archived")
        if snapshot.get("required_before_governed_comparison") is not True:
            errors.append(f"{prefix}.snapshot: immutable snapshot must be required before governed comparison")
        digest_required = status == "archived" or source_class == "measured"
        if digest_required and (not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)):
            errors.append(f"{prefix}.snapshot.sha256: digest required for archived/measured evidence")
        elif digest is not None and (not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)):
            errors.append(f"{prefix}.snapshot.sha256: invalid SHA-256")
        if status == "archived" and (not isinstance(immutable_uri, str) or not immutable_uri.strip()):
            errors.append(f"{prefix}.snapshot.immutable_uri: required for archived evidence")

        license_review = source.get("license_review")
        if not isinstance(license_review, dict):
            errors.append(f"{prefix}.license_review: expected object")
        else:
            license_fields = {"state", "reviewed_at", "notes"}
            missing_license = sorted(license_fields - license_review.keys())
            if missing_license:
                errors.append(f"{prefix}.license_review: missing required fields {missing_license}")
            if strict:
                extra_license = sorted(set(license_review) - license_fields)
                if extra_license:
                    errors.append(f"{prefix}.license_review: unexpected fields {extra_license}")
            license_state = license_review.get("state")
            if license_state not in ALLOWED_LICENSE_STATES:
                errors.append(f"{prefix}.license_review.state: invalid review state")
            reviewed_at_value = license_review.get("reviewed_at")
            reviewed_at = None
            if reviewed_at_value is not None:
                reviewed_at = _parse_date(
                    reviewed_at_value, f"{prefix}.license_review.reviewed_at", errors
                )
            if reviewed_at and reviewed_at > as_of:
                errors.append(f"{prefix}.license_review.reviewed_at: cannot be in the future")
            if license_state != "pending" and reviewed_at_value is None:
                errors.append(f"{prefix}.license_review.reviewed_at: required after review")

        permitted_use = source.get("permitted_use")
        if source_class == "vendor_declared" and permitted_use != "comparison_dimension":
            errors.append(f"{prefix}: vendor_declared source cannot be treated as measured evidence")
        if source_class == "normative" and permitted_use != "normative_contract":
            errors.append(f"{prefix}: normative source must use normative_contract")
        if source_class == "measured" and permitted_use != "measurement":
            errors.append(f"{prefix}: measured source must use measurement")
        measurement_origin = source.get("measurement_origin")
        if source_class == "measured" and measurement_origin not in {"internal", "independent"}:
            errors.append(f"{prefix}: measured source requires internal or independent origin")
        if source_class in {"vendor_declared", "normative"} and measurement_origin != "not_applicable":
            errors.append(f"{prefix}: declared/normative source must use not_applicable measurement origin")

        covers = source.get("covers_source_ids")
        if not isinstance(covers, list):
            errors.append(f"{prefix}.covers_source_ids: expected array")
            covers = []
        else:
            covers_seen: set[str] = set()
            if len(covers) > 8:
                errors.append(f"{prefix}.covers_source_ids: maximum 8 entries exceeded")
            for covered_id in covers:
                if not isinstance(covered_id, str) or not SOURCE_ID_RE.fullmatch(covered_id):
                    errors.append(f"{prefix}.covers_source_ids: invalid source ID {covered_id!r}")
                elif covered_id in covers_seen:
                    errors.append(f"{prefix}.covers_source_ids: duplicate {covered_id}")
                else:
                    covers_seen.add(covered_id)

        measurement_scope = source.get("measurement_scope")
        if source_class == "measured":
            if not covers:
                errors.append(f"{prefix}: measured source must cover at least one declared/normative source")
            if not isinstance(measurement_scope, dict):
                errors.append(f"{prefix}.measurement_scope: measured source requires structured scope")
                measurement_scope = {}
        elif measurement_scope is not None:
            errors.append(f"{prefix}.measurement_scope: only measured sources may declare measurement scope")
        if source_class in {"vendor_declared", "normative"} and covers:
            errors.append(f"{prefix}.covers_source_ids: declared/normative source must not cover sources")

        if isinstance(measurement_scope, dict):
            scope_fields = {"category", "protocol_id", "artifact_digests"}
            missing_scope = sorted(scope_fields - measurement_scope.keys())
            if missing_scope:
                errors.append(f"{prefix}.measurement_scope: missing required fields {missing_scope}")
            if strict:
                extra_scope = sorted(set(measurement_scope) - scope_fields)
                if extra_scope:
                    errors.append(f"{prefix}.measurement_scope: unexpected fields {extra_scope}")
            scope_category = measurement_scope.get("category")
            scope_protocol = measurement_scope.get("protocol_id")
            if scope_category not in ALLOWED_CATEGORIES:
                errors.append(f"{prefix}.measurement_scope.category: invalid category")
            if not isinstance(scope_protocol, str) or not PROTOCOL_ID_RE.fullmatch(scope_protocol):
                errors.append(f"{prefix}.measurement_scope.protocol_id: invalid versioned protocol ID")
            if source_class == "measured" and (
                scope_category != category or scope_protocol != protocol_id
            ):
                errors.append(f"{prefix}: measurement scope category/protocol must match source record")
            artifact_digests = measurement_scope.get("artifact_digests")
            if not isinstance(artifact_digests, list) or not artifact_digests:
                errors.append(f"{prefix}.measurement_scope.artifact_digests: non-empty array required")
            else:
                if len(artifact_digests) > 16:
                    errors.append(
                        f"{prefix}.measurement_scope.artifact_digests: maximum 16 entries exceeded"
                    )
                if len(set(artifact_digests)) != len(artifact_digests):
                    errors.append(f"{prefix}.measurement_scope.artifact_digests: duplicates forbidden")
                for artifact_digest in artifact_digests:
                    if not isinstance(artifact_digest, str) or not SHA256_RE.fullmatch(artifact_digest):
                        errors.append(
                            f"{prefix}.measurement_scope.artifact_digests: invalid SHA-256"
                        )

        measurement_refs = source.get("independent_measurement_source_ids")
        if not isinstance(measurement_refs, list):
            errors.append(f"{prefix}.independent_measurement_source_ids: expected array")
        else:
            ref_seen: set[str] = set()
            if len(measurement_refs) > 64:
                errors.append(f"{prefix}.independent_measurement_source_ids: maximum 64 entries exceeded")
            for ref in measurement_refs:
                if not isinstance(ref, str) or not SOURCE_ID_RE.fullmatch(ref):
                    errors.append(f"{prefix}.independent_measurement_source_ids: invalid source ID {ref!r}")
                elif ref in ref_seen:
                    errors.append(f"{prefix}.independent_measurement_source_ids: duplicate {ref}")
                else:
                    ref_seen.add(ref)

    if strict and not EXPECTED_SOURCE_IDS <= actual_ids:
        missing = sorted(EXPECTED_SOURCE_IDS - actual_ids)
        errors.append(f"strict official source set mismatch: missing={missing}")
    by_id = {
        source.get("source_id"): source
        for source in sources
        if isinstance(source, dict) and isinstance(source.get("source_id"), str)
    }
    if strict:
        unexpected_declared = sorted(
            source_id
            for source_id, source in by_id.items()
            if source_id not in EXPECTED_SOURCE_IDS and source.get("class") != "measured"
        )
        if unexpected_declared:
            errors.append(f"strict registry has unrecognized declared sources {unexpected_declared}")
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            continue
        source_id = source.get("source_id")
        source_class = source.get("class")
        refs = source.get("independent_measurement_source_ids", [])
        if source_class != "vendor_declared" and refs:
            errors.append(
                f"sources[{index}].independent_measurement_source_ids: only vendor_declared sources may reference measurements"
            )
        for ref in refs:
            target = by_id.get(ref)
            if target is None:
                errors.append(f"sources[{index}]: measurement reference {ref} is missing")
            elif target.get("class") != "measured":
                errors.append(f"sources[{index}]: measurement reference {ref} is not class measured")
            else:
                if source_id not in target.get("covers_source_ids", []):
                    errors.append(
                        f"sources[{index}]: measurement reference {ref} does not cover {source_id}"
                    )
                scope = target.get("measurement_scope")
                if isinstance(scope, dict) and (
                    scope.get("category") != source.get("comparison_category")
                    or scope.get("protocol_id") != source.get("protocol_id")
                ):
                    errors.append(
                        f"sources[{index}]: measurement reference {ref} category/protocol mismatch"
                    )
        if source_class == "measured":
            scope = source.get("measurement_scope")
            for covered_id in source.get("covers_source_ids", []):
                if covered_id == source_id:
                    errors.append(f"sources[{index}].covers_source_ids: measured source cannot cover itself")
                    continue
                covered = by_id.get(covered_id)
                if covered is None:
                    errors.append(f"sources[{index}].covers_source_ids: source {covered_id} is missing")
                elif covered.get("class") not in {"vendor_declared", "normative"}:
                    errors.append(
                        f"sources[{index}].covers_source_ids: source {covered_id} must be vendor_declared or normative"
                    )
                elif isinstance(scope, dict) and (
                    scope.get("category") != covered.get("comparison_category")
                    or scope.get("protocol_id") != covered.get("protocol_id")
                ):
                    errors.append(
                        f"sources[{index}].covers_source_ids: source {covered_id} category/protocol mismatch"
                    )
    return errors


def validate_governed_readiness(payload: Any) -> list[str]:
    """Return readiness blockers after structural validation has succeeded."""
    blockers: list[str] = []
    sources = payload["sources"]
    by_id = {source["source_id"]: source for source in sources}
    ref_users: dict[str, set[str]] = {}
    for source in sources:
        if source["class"] == "vendor_declared":
            for ref in source["independent_measurement_source_ids"]:
                ref_users.setdefault(ref, set()).add(source["source_id"])
    for index, source in enumerate(sources):
        prefix = f"sources[{index}]({source['source_id']})"
        if not (source["version"] or source["revision"]):
            blockers.append(f"{prefix}: pinned version or revision required")
        license_review = source["license_review"]
        if license_review["state"] != "approved":
            blockers.append(f"{prefix}: license/EULA review must be approved")
        snapshot = source["snapshot"]
        if snapshot["status"] != "archived":
            blockers.append(f"{prefix}: immutable archived snapshot required")
        if not snapshot["immutable_uri"]:
            blockers.append(f"{prefix}: immutable snapshot URI required")
        if not isinstance(snapshot["sha256"], str) or not SHA256_RE.fullmatch(snapshot["sha256"]):
            blockers.append(f"{prefix}: immutable snapshot SHA-256 required")
        if source["class"] == "vendor_declared":
            refs = source["independent_measurement_source_ids"]
            valid_refs = [
                ref
                for ref in refs
                if ref in by_id
                and by_id[ref]["class"] == "measured"
                and by_id[ref]["measurement_origin"] == "independent"
                and by_id[ref]["license_review"]["state"] == "approved"
                and by_id[ref]["snapshot"]["status"] == "archived"
                and bool(by_id[ref]["snapshot"]["immutable_uri"])
                and isinstance(by_id[ref]["snapshot"]["sha256"], str)
                and SHA256_RE.fullmatch(by_id[ref]["snapshot"]["sha256"])
                and source["source_id"] in by_id[ref]["covers_source_ids"]
                and by_id[ref]["measurement_scope"]["category"] == source["comparison_category"]
                and by_id[ref]["measurement_scope"]["protocol_id"] == source["protocol_id"]
                and bool(by_id[ref]["measurement_scope"]["artifact_digests"])
                and len(ref_users.get(ref, set())) == 1
            ]
            if not valid_refs:
                blockers.append(f"{prefix}: independent measured evidence required")
            for ref in refs:
                if len(ref_users.get(ref, set())) > 1:
                    blockers.append(
                        f"{prefix}: measurement reference {ref} reused across vendor sources"
                    )
    return blockers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "registry",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "fixtures/competitive_source_registry_v1.json",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--governed-ready",
        action="store_true",
        help="require approved licenses, immutable snapshots, and independent measurements",
    )
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    args = parser.parse_args(argv)
    try:
        raw = args.registry.read_bytes()
        if len(raw) > MAX_REGISTRY_BYTES:
            print(
                f"competitive source registry: STRUCTURAL FAIL: file exceeds {MAX_REGISTRY_BYTES} bytes",
                file=sys.stderr,
            )
            return 2
        payload = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"competitive source registry: FAIL: {exc}", file=sys.stderr)
        return 2
    errors = validate_registry(
        payload, as_of=args.as_of, strict=args.strict or args.governed_ready
    )
    if errors:
        print("competitive source registry: STRUCTURAL FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    if args.governed_ready:
        blockers = validate_governed_readiness(payload)
        if blockers:
            print("competitive source registry: GOVERNED NOT READY", file=sys.stderr)
            for blocker in blockers:
                print(f"- {blocker}", file=sys.stderr)
            return 3
        print(f"competitive source registry: GOVERNED READY ({len(payload['sources'])} sources)")
        return 0
    print(
        f"competitive source registry: STRUCTURAL PASS ({len(payload['sources'])} sources); "
        "not a governed-comparison readiness claim"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
