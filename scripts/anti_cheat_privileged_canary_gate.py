#!/usr/bin/env python3
"""Validate a bounded, synthetic-only privileged anti-cheat A/B packet.

Version 1 validates sanitized observe/shadow contract data. It cannot accept
live evidence, supported capability, server corroboration, or enforcement and
never installs, loads, or executes a privileged component.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Any


MAX_FILE_BYTES = 256 * 1024
MAX_DEPTH = 32
MAX_NODES = 4096
MAX_STRING_LENGTH = 2048
MAX_LIST_ITEMS = 64

PLATFORMS = {
    "windows": "windows_kernel_driver",
    "linux": "ebpf_lsm",
    "macos": "endpoint_security_system_extension",
}
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{7,64}$")
OPAQUE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
CATEGORICAL_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_]{0,127}$")
EMAIL = re.compile(r"(?i)(?:^|[^a-z0-9._%+-])[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}(?:$|[^a-z0-9.-])")
URI = re.compile(r"(?i)(?:https?|ftp|file)://|\bwww\.")
FORBIDDEN_ACTION_VALUES = {
    "enforce", "block", "kick", "ban", "permanent_ban", "kill_session", "sanction"
}

TOP_KEYS = {
    "schema_version", "evidence_class", "mode", "decision",
    "durable_sanctions_allowed", "privacy_mode", "identity", "platforms",
}
IDENTITY_KEYS = {"source_sha", "artifact_digest", "build_id", "session_id", "protected_target_id"}
PLATFORM_KEYS = {
    "platform", "capability_state", "reasons", "limitations", "baseline",
    "privileged", "server_authoritative_corroboration",
}
BASELINE_KEYS = {"synthetic_identity", "clean_controls"}
PRIVILEGED_KEYS = {
    "backend", "evidence_state", "synthetic_identity", "independent_of_baseline",
    "detector_metrics", "clean_controls", "performance", "rollback", "uninstall",
}
SYNTHETIC_IDENTITY_KEYS = {"source_id", "artifact_digest", "component_version", "preregistration_id"}
CONTROL_KEYS = {"state", "count"}
METRIC_KEYS = {
    "detector_family", "attempts", "baseline_detected", "privileged_detected",
    "incremental_detected",
}
PERFORMANCE_KEYS = {"state", "metrics"}
PERFORMANCE_METRIC_KEYS = {
    "frame_time_p95_delta_ms", "cpu_median_percent", "rss_delta_mib", "startup_p95_delta_ms"
}
LIFECYCLE_KEYS = {"available", "state", "procedure_id"}
CORROBORATION_KEYS = {"state", "reason"}


def _closed_object(value: Any, allowed: set[str], prefix: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{prefix}: object is required")
        return {}
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        errors.append(f"{prefix}: unknown fields {unknown}")
    return value


def _scan_structure(value: Any) -> list[str]:
    """Bound arbitrary in-memory input iteratively, without recursive descent."""
    errors: list[str] = []
    stack: list[tuple[Any, str, int]] = [(value, "$", 0)]
    seen_containers: set[int] = set()
    nodes = 0
    while stack:
        current, path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            errors.append(f"$: structure exceeds {MAX_NODES} nodes")
            break
        if depth > MAX_DEPTH:
            errors.append(f"{path}: nesting exceeds maximum depth {MAX_DEPTH}")
            continue
        if isinstance(current, str):
            if len(current) > MAX_STRING_LENGTH:
                errors.append(f"{path}: string exceeds {MAX_STRING_LENGTH} characters")
            if any(ord(character) < 32 or ord(character) == 127 for character in current):
                errors.append(f"{path}: control characters are forbidden")
            if EMAIL.search(current):
                errors.append(f"{path}: email-like data is forbidden")
            if URI.search(current):
                errors.append(f"{path}: URI-like data is forbidden")
            if current.strip().lower() in FORBIDDEN_ACTION_VALUES:
                errors.append(
                    f"{path}: enforcement or durable sanction value {current!r} is forbidden"
                )
        elif isinstance(current, dict):
            if id(current) in seen_containers:
                errors.append(f"{path}: cyclic or reused container is not valid JSON structure")
                continue
            seen_containers.add(id(current))
            if len(current) > MAX_LIST_ITEMS:
                errors.append(f"{path}: object exceeds {MAX_LIST_ITEMS} fields")
            for key, child in current.items():
                key_text = str(key)
                if len(key_text) > MAX_STRING_LENGTH:
                    errors.append(f"{path}: key exceeds {MAX_STRING_LENGTH} characters")
                stack.append((child, f"{path}.{key_text}", depth + 1))
        elif isinstance(current, list):
            if id(current) in seen_containers:
                errors.append(f"{path}: cyclic or reused container is not valid JSON structure")
                continue
            seen_containers.add(id(current))
            if len(current) > MAX_LIST_ITEMS:
                errors.append(f"{path}: array exceeds {MAX_LIST_ITEMS} items")
            for index, child in enumerate(current):
                stack.append((child, f"{path}[{index}]", depth + 1))
        elif isinstance(current, float) and not math.isfinite(current):
            errors.append(f"{path}: NaN and Infinity are forbidden")
    return errors


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds maximum size {MAX_FILE_BYTES} bytes")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds maximum size {MAX_FILE_BYTES} bytes")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as exc:
        raise ValueError(f"JSON nesting exceeds parser limit: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("top-level JSON must be an object")
    return value


def _opaque_id(value: Any) -> bool:
    return isinstance(value, str) and bool(OPAQUE_ID.fullmatch(value))


def _categorical_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and 0 < len(value) <= 16
        and all(isinstance(item, str) and bool(CATEGORICAL_TOKEN.fullmatch(item)) for item in value)
    )


def _require_identity(value: Any, errors: list[str]) -> None:
    identity = _closed_object(value, IDENTITY_KEYS, "$.identity", errors)
    for key in ("build_id", "session_id", "protected_target_id"):
        if not _opaque_id(identity.get(key)):
            errors.append(f"$.identity.{key}: strict opaque identifier is required")
    if not isinstance(identity.get("source_sha"), str) or not SOURCE_SHA.fullmatch(identity["source_sha"]):
        errors.append("$.identity.source_sha: must be a 7-64 character lowercase git SHA")
    if not isinstance(identity.get("artifact_digest"), str) or not SHA256.fullmatch(identity["artifact_digest"]):
        errors.append("$.identity.artifact_digest: must be sha256:<64 lowercase hex>")


def _synthetic_identity(value: Any, prefix: str, errors: list[str]) -> dict[str, Any]:
    identity = _closed_object(value, SYNTHETIC_IDENTITY_KEYS, prefix, errors)
    for key in ("source_id", "component_version", "preregistration_id"):
        if not _opaque_id(identity.get(key)):
            errors.append(f"{prefix}.{key}: strict opaque identifier is required")
    digest = identity.get("artifact_digest")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        errors.append(f"{prefix}.artifact_digest: must be sha256:<64 lowercase hex>")
    return identity


def _controls(value: Any, prefix: str, evidence_state: str, errors: list[str]) -> None:
    controls = _closed_object(value, CONTROL_KEYS, prefix, errors)
    state, count = controls.get("state"), controls.get("count")
    if state not in {"passed", "failed", "not_executed"}:
        errors.append(f"{prefix}.state: invalid clean-control state")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        errors.append(f"{prefix}.count: must be a non-negative integer")
    if evidence_state == "synthetic" and (state != "passed" or not isinstance(count, int) or count < 1):
        errors.append(f"{prefix}: synthetic evidence requires at least one passing clean control")
    if evidence_state == "not_executed" and (state != "not_executed" or count != 0):
        errors.append(f"{prefix}: not_executed evidence requires state=not_executed and count=0")


def _performance(value: Any, prefix: str, evidence_state: str, errors: list[str]) -> None:
    performance = _closed_object(value, PERFORMANCE_KEYS, prefix, errors)
    state, metrics_value = performance.get("state"), performance.get("metrics")
    expected_state = "synthetic_estimate" if evidence_state == "synthetic" else "not_executed"
    if state != expected_state:
        errors.append(f"{prefix}.state: evidence_state={evidence_state} requires state={expected_state}")
    metrics = _closed_object(metrics_value, PERFORMANCE_METRIC_KEYS, f"{prefix}.metrics", errors)
    if evidence_state == "synthetic":
        for key in sorted(PERFORMANCE_METRIC_KEYS):
            number = metrics.get(key)
            if (
                not isinstance(number, (int, float))
                or isinstance(number, bool)
                or not math.isfinite(number)
                or number < 0
            ):
                errors.append(f"{prefix}.metrics.{key}: finite non-negative number is required")
    elif metrics:
        errors.append(f"{prefix}: not_executed evidence cannot contain performance metrics")


def _metrics(value: Any, prefix: str, evidence_state: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{prefix}: detector_metrics must be an array")
        return []
    if evidence_state == "synthetic" and not value:
        errors.append(f"{prefix}: synthetic evidence requires detector-family metrics")
    if evidence_state == "not_executed" and value:
        errors.append(f"{prefix}: not_executed evidence cannot contain detector metrics")
    families: list[str] = []
    for index, raw_metric in enumerate(value[:MAX_LIST_ITEMS]):
        item_prefix = f"{prefix}[{index}]"
        metric = _closed_object(raw_metric, METRIC_KEYS, item_prefix, errors)
        family = metric.get("detector_family")
        if not _opaque_id(family):
            errors.append(f"{item_prefix}.detector_family: strict categorical identifier is required")
        else:
            families.append(family)
        values = {key: metric.get(key) for key in METRIC_KEYS - {"detector_family"}}
        for key, number in values.items():
            if not isinstance(number, int) or isinstance(number, bool) or number < 0:
                errors.append(f"{item_prefix}.{key}: non-negative integer is required")
        attempts = values["attempts"]
        baseline = values["baseline_detected"]
        privileged = values["privileged_detected"]
        incremental = values["incremental_detected"]
        if all(isinstance(number, int) and not isinstance(number, bool) for number in values.values()):
            if evidence_state == "synthetic" and attempts <= 0:
                errors.append(f"{item_prefix}.attempts: synthetic metric requires attempts > 0")
            if baseline > attempts or privileged > attempts:
                errors.append(f"{item_prefix}: detections cannot exceed attempts")
            if incremental != privileged - baseline or incremental < 0:
                errors.append(
                    f"{item_prefix}.incremental_detected: must equal privileged_detected - "
                    "baseline_detected and be non-negative"
                )
    if len(families) != len(set(families)):
        errors.append(f"{prefix}: detector_family values must be unique")
    return families


def _lifecycle(value: Any, prefix: str, evidence_state: str, errors: list[str]) -> None:
    control = _closed_object(value, LIFECYCLE_KEYS, prefix, errors)
    available, state, procedure = control.get("available"), control.get("state"), control.get("procedure_id")
    if evidence_state == "synthetic":
        if available is not True or state != "not_executed" or not _opaque_id(procedure) or procedure == "not_applicable":
            errors.append(f"{prefix}: synthetic candidate requires an available, named, not_executed procedure")
    else:
        if available is not False or state != "not_executed" or procedure != "not_applicable":
            errors.append(f"{prefix}: unsupported lane requires available=false, state=not_executed, procedure_id=not_applicable")


def validate_document(data: Any) -> tuple[list[str], dict[str, Any]]:
    errors = _scan_structure(data)
    if not isinstance(data, dict):
        errors.append("$: top-level value must be an object")
        return errors, _report(errors, {})
    top = _closed_object(data, TOP_KEYS, "$", errors)
    if top.get("schema_version") != "tamandua.anti_cheat_privileged_canary/v1":
        errors.append("$.schema_version: unsupported or missing schema version")
    if top.get("evidence_class") != "synthetic_observe_shadow":
        errors.append("$.evidence_class: v1 is strictly synthetic_observe_shadow")
    if top.get("mode") != "observe_shadow":
        errors.append("$.mode: only observe_shadow is allowed")
    if top.get("decision") != "observe":
        errors.append("$.decision: only observe is allowed")
    if top.get("durable_sanctions_allowed") is not False:
        errors.append("$.durable_sanctions_allowed: must be false")
    if top.get("privacy_mode") != "metadata_only":
        errors.append("$.privacy_mode: must be metadata_only")
    _require_identity(top.get("identity"), errors)

    entries = top.get("platforms")
    if not isinstance(entries, list):
        errors.append("$.platforms: must be an array")
        entries = []
    seen: set[str] = set()
    summary: dict[str, Any] = {}
    for index, raw_entry in enumerate(entries[:MAX_LIST_ITEMS]):
        prefix = f"$.platforms[{index}]"
        entry = _closed_object(raw_entry, PLATFORM_KEYS, prefix, errors)
        platform = entry.get("platform")
        if platform not in PLATFORMS:
            errors.append(f"{prefix}.platform: must be one of {sorted(PLATFORMS)}")
            continue
        if platform in seen:
            errors.append(f"{prefix}.platform: duplicate {platform}")
        seen.add(platform)
        capability = entry.get("capability_state")
        if capability not in {"degraded", "unsupported"}:
            errors.append(f"{prefix}.capability_state: v1 allows only degraded or unsupported")
        if not _categorical_list(entry.get("reasons")):
            errors.append(f"{prefix}.reasons: categorical safe-token array is required")
        if not _categorical_list(entry.get("limitations")):
            errors.append(f"{prefix}.limitations: categorical safe-token array is required")

        baseline = _closed_object(entry.get("baseline"), BASELINE_KEYS, f"{prefix}.baseline", errors)
        baseline_identity = _synthetic_identity(
            baseline.get("synthetic_identity"), f"{prefix}.baseline.synthetic_identity", errors
        )
        _controls(baseline.get("clean_controls"), f"{prefix}.baseline.clean_controls", "synthetic", errors)

        privileged = _closed_object(entry.get("privileged"), PRIVILEGED_KEYS, f"{prefix}.privileged", errors)
        expected_backend = PLATFORMS[platform]
        backend = privileged.get("backend")
        if backend != expected_backend:
            errors.append(f"{prefix}.privileged.backend: {platform} requires exactly {expected_backend!r}")
        evidence_state = privileged.get("evidence_state")
        if evidence_state not in {"synthetic", "not_executed"}:
            errors.append(f"{prefix}.privileged.evidence_state: v1 rejects live and allows only synthetic or not_executed")
            evidence_state = "not_executed"
        if evidence_state == "synthetic" and capability != "degraded":
            errors.append(f"{prefix}: synthetic evidence requires capability_state=degraded")
        if evidence_state == "not_executed" and capability != "unsupported":
            errors.append(f"{prefix}: not_executed evidence requires capability_state=unsupported")
        privileged_identity = _synthetic_identity(
            privileged.get("synthetic_identity"), f"{prefix}.privileged.synthetic_identity", errors
        )
        if privileged.get("independent_of_baseline") is not True:
            errors.append(f"{prefix}.privileged.independent_of_baseline: must be true")
        if privileged_identity.get("source_id") == baseline_identity.get("source_id"):
            errors.append(f"{prefix}: privileged source_id must differ from baseline source_id")
        if privileged_identity.get("artifact_digest") == baseline_identity.get("artifact_digest"):
            errors.append(f"{prefix}: privileged artifact_digest must differ from baseline artifact_digest")
        if privileged_identity.get("preregistration_id") != baseline_identity.get("preregistration_id"):
            errors.append(f"{prefix}: baseline and privileged preregistration_id must match")

        families = _metrics(
            privileged.get("detector_metrics"), f"{prefix}.privileged.detector_metrics", evidence_state, errors
        )
        _controls(privileged.get("clean_controls"), f"{prefix}.privileged.clean_controls", evidence_state, errors)
        _performance(privileged.get("performance"), f"{prefix}.privileged.performance", evidence_state, errors)
        _lifecycle(privileged.get("rollback"), f"{prefix}.privileged.rollback", evidence_state, errors)
        _lifecycle(privileged.get("uninstall"), f"{prefix}.privileged.uninstall", evidence_state, errors)

        corroboration = _closed_object(
            entry.get("server_authoritative_corroboration"), CORROBORATION_KEYS,
            f"{prefix}.server_authoritative_corroboration", errors,
        )
        corroboration_state = corroboration.get("state")
        if corroboration_state != "not_executed":
            errors.append(f"{prefix}.server_authoritative_corroboration.state: v1 requires not_executed")
        reason = corroboration.get("reason")
        if not isinstance(reason, str) or not CATEGORICAL_TOKEN.fullmatch(reason):
            errors.append(f"{prefix}.server_authoritative_corroboration.reason: categorical safe token is required")

        summary[platform] = {
            "capability_state": capability,
            "backend": backend,
            "privileged_evidence_state": evidence_state,
            "detector_families": sorted(families),
            "server_authoritative_corroboration": corroboration_state,
        }

    missing = sorted(set(PLATFORMS) - seen)
    if missing:
        errors.append(f"$.platforms: missing required platforms {missing}")
    return errors, _report(errors, summary)


def _report(errors: list[str], platforms: dict[str, Any]) -> dict[str, Any]:
    return {
        "gate": "anti_cheat_privileged_canary",
        "passed": not errors,
        "verdict": "contract_valid" if not errors else "contract_rejected",
        "errors": errors,
        "platforms": platforms,
        "evidence_class": "synthetic_contract_only",
        "claim_boundary": (
            "Synthetic lab evidence-contract validation only; counts and estimates are not efficacy, "
            "FPR, live driver, server corroboration, production readiness, or external anti-cheat claims."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        data = load_json(args.fixture)
        errors, report = validate_document(data)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        errors = [f"{args.fixture}: {exc}"]
        report = _report(errors, {})
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
