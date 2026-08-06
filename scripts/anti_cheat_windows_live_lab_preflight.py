#!/usr/bin/env python3
"""Read-only preflight for a Windows privileged anti-cheat lab packet.

The validator reads JSON only. It contains no command runner, driver loader,
VM client, or deployment path, and it never authorizes execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


MAX_BYTES = 512 * 1024
MAX_DEPTH = 40
MAX_NODES = 8192
MAX_ITEMS = 128
MAX_STRING = 2048
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EMAIL = re.compile(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
URI = re.compile(r"(?i)(?:https?|ftp|file)://|\bwww\.")
MUTABLE = re.compile(r"(?i)(?:^|[/\\:_-])(?:latest|mutable)(?:$|[/\\:_-])")
FORBIDDEN_VALUES = {"enforce", "block", "kick", "ban", "kill", "kill_session", "sanction"}
SENSITIVE_KEYS = {
    "password", "secret", "token", "api_key", "private_key", "email", "home_address",
    "raw_payload", "memory_dump", "keystrokes", "authorization", "cookie",
}

TOP_KEYS = {
    "schema_version", "packet_state", "execution_requested", "evidence_class",
    "current_driver", "sealed_candidate", "claims",
}
CURRENT_KEYS = {
    "status", "neutralization_receipt_digest",
    "observe_only", "active_controls", "process_control", "file_control",
    "lsass_protection", "self_protection", "agent_auto_load", "scan_port",
    "local_digests", "digest_evidence_state",
}
CLAIM_KEYS = {"effectiveness", "fpr", "external"}
CANDIDATE_KEYS = {
    "source", "artifacts", "build", "safety", "signing", "lab", "guest", "lease",
    "ab_design", "performance", "crash_monitoring", "rollback",
}
SOURCE_KEYS = {"source_sha", "clean_worktree_receipt"}
RECEIPT_KEYS = {"state", "receipt_digest"}
ARTIFACT_ROLE_KEYS = {"driver", "inf", "cat", "agent", "game", "harness", "policy", "scripts"}
ARTIFACT_KEYS = ARTIFACT_ROLE_KEYS | {"manifest_digest"}
BUILD_KEYS = {"toolchain_id", "toolchain_digest", "build_flags"}
SAFETY_KEYS = {
    "observe_only", "active_controls", "lsass_protection", "process_control",
    "file_control", "self_protection", "scan_port", "agent_auto_load",
    "orchestrator_only_load",
}
SIGNING_KEYS = {
    "state", "driver_signed", "inf_cat_verified", "signer_identity_digest",
    "verification_receipt_digest",
}
LAB_KEYS = {
    "provider", "vm_id", "disposable", "snapshot_id", "recovery_receipt_digest",
    "qga_ready", "isolated_network", "network_id",
}
GUEST_KEYS = {
    "windows_build", "kernel_build", "secure_boot", "testsigning", "vbs", "hvci", "wdac",
}
LEASE_KEYS = {
    "owner", "target", "surface", "source_sha", "artifact_digest", "heartbeat_at",
    "validated_at", "expires_at", "previous_fencing_token", "fencing_token",
}
AB_KEYS = {
    "same_build", "same_policy", "same_seed", "restore_before_each_arm", "baseline",
    "privileged", "ordering", "clean_families", "positive_families",
    "paired_attempts_per_family", "experiment_id", "pair_group_id", "build_id",
    "policy_id", "seed_id", "workload_digest",
}
ARM_KEYS = {"arm_id", "session_id", "pair_id"}
PERFORMANCE_KEYS = {
    "measurement_source", "legacy_stub", "pairs_per_scene", "duration_minutes",
    "frames_per_scene", "cold_starts", "scenes",
}
CRASH_KEYS = {"external_heartbeat", "bsod_detection", "heartbeat_receipt_digest"}
ROLLBACK_KEYS = {"steps", "cycles_required", "cycles_completed", "receipt_digest"}

REQUIRED_FLAGS = {"observe_only", "no_active_controls", "orchestrator_only_load"}
REQUIRED_ROLLBACK_STEPS = {"disable", "unload", "uninstall", "reboot", "snapshot_restore"}


def _duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"file exceeds {MAX_BYTES} bytes")
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError(f"file exceeds {MAX_BYTES} bytes")
    try:
        value = json.loads(raw, object_pairs_hook=_duplicate_object)
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds parser limit") from exc
    if not isinstance(value, dict):
        raise ValueError("top-level JSON must be an object")
    return value


def _scan(value: Any) -> list[str]:
    errors: list[str] = []
    stack = [(value, "$", 0)]
    seen: set[int] = set()
    nodes = 0
    while stack:
        current, path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            errors.append(f"$: structure exceeds {MAX_NODES} nodes")
            break
        if depth > MAX_DEPTH:
            errors.append(f"{path}: nesting exceeds {MAX_DEPTH}")
            continue
        if isinstance(current, (dict, list)):
            if id(current) in seen:
                errors.append(f"{path}: cyclic or reused container is forbidden")
                continue
            seen.add(id(current))
            if len(current) > MAX_ITEMS:
                errors.append(f"{path}: container exceeds {MAX_ITEMS} items")
        if isinstance(current, dict):
            for key, child in current.items():
                key_text = str(key)
                if key_text.strip().lower() in SENSITIVE_KEYS:
                    errors.append(f"{path}.{key_text}: sensitive/raw field is forbidden")
                stack.append((child, f"{path}.{key_text}", depth + 1))
        elif isinstance(current, list):
            stack.extend((child, f"{path}[{index}]", depth + 1) for index, child in enumerate(current))
        elif isinstance(current, str):
            normalized = current.strip().lower()
            if len(current) > MAX_STRING:
                errors.append(f"{path}: string exceeds {MAX_STRING} characters")
            if any(ord(character) < 32 or ord(character) == 127 for character in current):
                errors.append(f"{path}: control characters are forbidden")
            if EMAIL.search(current) or URI.search(current):
                errors.append(f"{path}: PII/URI-like string is forbidden")
            if MUTABLE.search(current):
                errors.append(f"{path}: mutable/latest reference is forbidden")
            if normalized in FORBIDDEN_VALUES:
                errors.append(f"{path}: enforcement or sanction value is forbidden")
        elif isinstance(current, float) and not math.isfinite(current):
            errors.append(f"{path}: NaN and Infinity are forbidden")
    return errors


def _obj(value: Any, allowed: set[str], path: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path}: object is required")
        return {}
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        errors.append(f"{path}: unknown fields {unknown}")
    return value


def _token(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        errors.append(f"{path}: strict opaque token is required")


def _digest(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        errors.append(f"{path}: sha256:<64 lowercase hex> is required")


def _bool(value: Any, expected: bool, path: str, errors: list[str]) -> None:
    if value is not expected:
        errors.append(f"{path}: must be {str(expected).lower()}")


def _positive_int(value: Any, minimum: int, path: str, errors: list[str]) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        errors.append(f"{path}: integer >= {minimum} is required")


def _token_list(value: Any, path: str, errors: list[str], *, exact_count: int | None = None) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{path}: non-empty token array is required")
        return []
    items = [item for item in value if isinstance(item, str) and TOKEN.fullmatch(item)]
    if len(items) != len(value) or len(set(items)) != len(items):
        errors.append(f"{path}: values must be unique strict tokens")
    if exact_count is not None and len(value) != exact_count:
        errors.append(f"{path}: exactly {exact_count} values are required")
    return items


def _receipt(value: Any, path: str, errors: list[str]) -> None:
    receipt = _obj(value, RECEIPT_KEYS, path, errors)
    if receipt.get("state") != "verified":
        errors.append(f"{path}.state: must be verified")
    _digest(receipt.get("receipt_digest"), f"{path}.receipt_digest", errors)


def artifact_manifest_digest(artifacts: dict[str, Any]) -> str:
    role_map = {name: artifacts.get(name) for name in sorted(ARTIFACT_ROLE_KEYS)}
    encoded = json.dumps(role_map, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _parse_utc(value: Any, path: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str) or not TIME.fullmatch(value):
        errors.append(f"{path}: UTC second timestamp is required")
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{path}: valid UTC calendar timestamp is required")
        return None


def _current_driver(value: Any, packet_state: Any, errors: list[str]) -> list[str]:
    current = _obj(value, CURRENT_KEYS, "$.current_driver", errors)
    blockers: list[str] = []
    digests = _obj(current.get("local_digests"), ARTIFACT_ROLE_KEYS, "$.current_driver.local_digests", errors)

    if packet_state == "sealed_candidate":
        if current.get("status") != "neutralized_or_absent":
            errors.append("$.current_driver.status: sealed_candidate requires neutralized_or_absent")
        if current.get("active_controls") != []:
            errors.append("$.current_driver.active_controls: must be [] after neutralization")
        _bool(current.get("observe_only"), False, "$.current_driver.observe_only", errors)
        for field in (
            "process_control", "file_control", "lsass_protection", "self_protection",
            "agent_auto_load", "scan_port",
        ):
            _bool(current.get(field), False, f"$.current_driver.{field}", errors)
        if digests:
            errors.append("$.current_driver.local_digests: must be empty after neutralization")
        if current.get("digest_evidence_state") != "not_applicable_removed":
            errors.append("$.current_driver.digest_evidence_state: must be not_applicable_removed")
        _digest(
            current.get("neutralization_receipt_digest"),
            "$.current_driver.neutralization_receipt_digest",
            errors,
        )
        return blockers

    if current.get("status") != "ineligible_active":
        errors.append("$.current_driver.status: preregistered HOLD requires ineligible_active")
    if current.get("neutralization_receipt_digest") is not None:
        errors.append("$.current_driver.neutralization_receipt_digest: must be null before neutralization")
    expected_controls = {"process_control", "file_control", "lsass_protection", "self_protection"}
    controls = current.get("active_controls")
    if (
        not isinstance(controls, list)
        or not all(isinstance(item, str) for item in controls)
        or set(controls) != expected_controls
        or len(controls) != 4
    ):
        errors.append("$.current_driver.active_controls: exact current active-control set is required")
    if isinstance(controls, list) and controls:
        blockers.append("active_controls_enabled")
    _bool(current.get("observe_only"), False, "$.current_driver.observe_only", errors)
    if current.get("observe_only") is False:
        blockers.append("current_driver_not_observe_only")
    expected = {
        "process_control": True,
        "file_control": True,
        "lsass_protection": True,
        "self_protection": True,
        "agent_auto_load": True,
        "scan_port": True,
    }
    for field, field_value in expected.items():
        _bool(current.get(field), field_value, f"$.current_driver.{field}", errors)
        if current.get(field) is True:
            blockers.append(f"{field}_enabled")
    if digests:
        errors.append("$.current_driver.local_digests: must be empty until digest receipts are collected")
    if current.get("digest_evidence_state") != "not_collected":
        errors.append("$.current_driver.digest_evidence_state: must be not_collected")
    if not digests:
        blockers.append("current_driver_digest_receipts_missing")
    return blockers


def _validate_candidate(value: Any, errors: list[str]) -> None:
    candidate = _obj(value, CANDIDATE_KEYS, "$.sealed_candidate", errors)
    source = _obj(candidate.get("source"), SOURCE_KEYS, "$.sealed_candidate.source", errors)
    source_sha = source.get("source_sha")
    if not isinstance(source_sha, str) or not SOURCE_SHA.fullmatch(source_sha):
        errors.append("$.sealed_candidate.source.source_sha: exact 40-char lowercase SHA is required")
    _receipt(source.get("clean_worktree_receipt"), "$.sealed_candidate.source.clean_worktree_receipt", errors)

    artifacts = _obj(candidate.get("artifacts"), ARTIFACT_KEYS, "$.sealed_candidate.artifacts", errors)
    for name in sorted(ARTIFACT_ROLE_KEYS):
        _digest(artifacts.get(name), f"$.sealed_candidate.artifacts.{name}", errors)
    role_digests = [artifacts.get(name) for name in sorted(ARTIFACT_ROLE_KEYS)]
    if len(set(role_digests)) != len(ARTIFACT_ROLE_KEYS):
        errors.append("$.sealed_candidate.artifacts: each artifact role must have a distinct digest")
    expected_manifest_digest = artifact_manifest_digest(artifacts)
    if artifacts.get("manifest_digest") != expected_manifest_digest:
        errors.append("$.sealed_candidate.artifacts.manifest_digest: must bind the canonical role map")

    build = _obj(candidate.get("build"), BUILD_KEYS, "$.sealed_candidate.build", errors)
    _token(build.get("toolchain_id"), "$.sealed_candidate.build.toolchain_id", errors)
    _digest(build.get("toolchain_digest"), "$.sealed_candidate.build.toolchain_digest", errors)
    flags = set(_token_list(build.get("build_flags"), "$.sealed_candidate.build.build_flags", errors))
    if not REQUIRED_FLAGS.issubset(flags):
        errors.append(f"$.sealed_candidate.build.build_flags: missing {sorted(REQUIRED_FLAGS - flags)}")

    safety = _obj(candidate.get("safety"), SAFETY_KEYS, "$.sealed_candidate.safety", errors)
    _bool(safety.get("observe_only"), True, "$.sealed_candidate.safety.observe_only", errors)
    if safety.get("active_controls") != []:
        errors.append("$.sealed_candidate.safety.active_controls: must be []")
    for field in ("lsass_protection", "process_control", "file_control", "self_protection", "scan_port", "agent_auto_load"):
        _bool(safety.get(field), False, f"$.sealed_candidate.safety.{field}", errors)
    _bool(safety.get("orchestrator_only_load"), True, "$.sealed_candidate.safety.orchestrator_only_load", errors)

    signing = _obj(candidate.get("signing"), SIGNING_KEYS, "$.sealed_candidate.signing", errors)
    if signing.get("state") != "verified":
        errors.append("$.sealed_candidate.signing.state: must be verified")
    _bool(signing.get("driver_signed"), True, "$.sealed_candidate.signing.driver_signed", errors)
    _bool(signing.get("inf_cat_verified"), True, "$.sealed_candidate.signing.inf_cat_verified", errors)
    _digest(signing.get("signer_identity_digest"), "$.sealed_candidate.signing.signer_identity_digest", errors)
    _digest(signing.get("verification_receipt_digest"), "$.sealed_candidate.signing.verification_receipt_digest", errors)

    lab = _obj(candidate.get("lab"), LAB_KEYS, "$.sealed_candidate.lab", errors)
    if lab.get("provider") != "proxmox":
        errors.append("$.sealed_candidate.lab.provider: must be proxmox")
    for field in ("vm_id", "snapshot_id", "network_id"):
        _token(lab.get(field), f"$.sealed_candidate.lab.{field}", errors)
    for field in ("disposable", "qga_ready", "isolated_network"):
        _bool(lab.get(field), True, f"$.sealed_candidate.lab.{field}", errors)
    _digest(lab.get("recovery_receipt_digest"), "$.sealed_candidate.lab.recovery_receipt_digest", errors)

    guest = _obj(candidate.get("guest"), GUEST_KEYS, "$.sealed_candidate.guest", errors)
    for field in ("windows_build", "kernel_build"):
        _token(guest.get(field), f"$.sealed_candidate.guest.{field}", errors)
    for field in ("secure_boot", "vbs", "hvci", "wdac"):
        if not isinstance(guest.get(field), bool):
            errors.append(f"$.sealed_candidate.guest.{field}: explicit boolean is required")
    _bool(guest.get("testsigning"), False, "$.sealed_candidate.guest.testsigning", errors)

    lease = _obj(candidate.get("lease"), LEASE_KEYS, "$.sealed_candidate.lease", errors)
    for field in ("owner", "target"):
        _token(lease.get(field), f"$.sealed_candidate.lease.{field}", errors)
    if lease.get("target") != lab.get("vm_id"):
        errors.append("$.sealed_candidate.lease.target: must equal lab.vm_id")
    if lease.get("surface") != "anti_cheat_windows_driver_live_lab":
        errors.append("$.sealed_candidate.lease.surface: unexpected lab surface")
    previous_fence = lease.get("previous_fencing_token")
    current_fence = lease.get("fencing_token")
    _positive_int(previous_fence, 1, "$.sealed_candidate.lease.previous_fencing_token", errors)
    _positive_int(current_fence, 2, "$.sealed_candidate.lease.fencing_token", errors)
    if (
        isinstance(previous_fence, int) and not isinstance(previous_fence, bool)
        and isinstance(current_fence, int) and not isinstance(current_fence, bool)
        and current_fence <= previous_fence
    ):
        errors.append("$.sealed_candidate.lease.fencing_token: must increase monotonically")
    if lease.get("source_sha") != source_sha:
        errors.append("$.sealed_candidate.lease.source_sha: must bind candidate source_sha")
    if lease.get("artifact_digest") != artifacts.get("driver"):
        errors.append("$.sealed_candidate.lease.artifact_digest: must bind driver digest")
    heartbeat = _parse_utc(lease.get("heartbeat_at"), "$.sealed_candidate.lease.heartbeat_at", errors)
    validated = _parse_utc(lease.get("validated_at"), "$.sealed_candidate.lease.validated_at", errors)
    expiry = _parse_utc(lease.get("expires_at"), "$.sealed_candidate.lease.expires_at", errors)
    if heartbeat and validated and validated < heartbeat:
        errors.append("$.sealed_candidate.lease.validated_at: must be at or after heartbeat_at")
    if validated and expiry and validated >= expiry:
        errors.append("$.sealed_candidate.lease.expires_at: lease must be live at validated_at")
    now = datetime.now(timezone.utc)
    if validated and abs(now - validated) > timedelta(minutes=5):
        errors.append("$.sealed_candidate.lease.validated_at: must be current within five minutes")
    if expiry and expiry <= now:
        errors.append("$.sealed_candidate.lease.expires_at: lease is expired at validation time")

    ab = _obj(candidate.get("ab_design"), AB_KEYS, "$.sealed_candidate.ab_design", errors)
    for field in ("same_build", "same_policy", "same_seed", "restore_before_each_arm"):
        _bool(ab.get(field), True, f"$.sealed_candidate.ab_design.{field}", errors)
    for field in ("experiment_id", "pair_group_id", "build_id", "policy_id", "seed_id"):
        _token(ab.get(field), f"$.sealed_candidate.ab_design.{field}", errors)
    _digest(ab.get("workload_digest"), "$.sealed_candidate.ab_design.workload_digest", errors)
    arms: list[dict[str, Any]] = []
    for arm_name in ("baseline", "privileged"):
        arm = _obj(ab.get(arm_name), ARM_KEYS, f"$.sealed_candidate.ab_design.{arm_name}", errors)
        arms.append(arm)
        for field in ARM_KEYS:
            _token(arm.get(field), f"$.sealed_candidate.ab_design.{arm_name}.{field}", errors)
    if len(arms) == 2:
        for field in ("arm_id", "session_id"):
            if arms[0].get(field) == arms[1].get(field):
                errors.append(f"$.sealed_candidate.ab_design: {field} values must be distinct")
        for arm_name, arm in zip(("baseline", "privileged"), arms):
            if arm.get("pair_id") != ab.get("pair_group_id"):
                errors.append(
                    f"$.sealed_candidate.ab_design.{arm_name}.pair_id: must bind pair_group_id"
                )
    if ab.get("ordering") != ["AB", "BA"]:
        errors.append("$.sealed_candidate.ab_design.ordering: must be ['AB', 'BA']")
    _token_list(ab.get("clean_families"), "$.sealed_candidate.ab_design.clean_families", errors, exact_count=6)
    _token_list(ab.get("positive_families"), "$.sealed_candidate.ab_design.positive_families", errors, exact_count=6)
    if ab.get("paired_attempts_per_family") != 5:
        errors.append("$.sealed_candidate.ab_design.paired_attempts_per_family: must be exactly 5")

    performance = _obj(candidate.get("performance"), PERFORMANCE_KEYS, "$.sealed_candidate.performance", errors)
    if performance.get("measurement_source") != "external_harness":
        errors.append("$.sealed_candidate.performance.measurement_source: must be external_harness")
    _bool(performance.get("legacy_stub"), False, "$.sealed_candidate.performance.legacy_stub", errors)
    if performance.get("pairs_per_scene") != 5:
        errors.append("$.sealed_candidate.performance.pairs_per_scene: must be exactly 5")
    duration, frames = performance.get("duration_minutes"), performance.get("frames_per_scene")
    duration_valid = (
        isinstance(duration, (int, float)) and not isinstance(duration, bool)
        and math.isfinite(duration) and duration >= 0
    )
    frames_valid = isinstance(frames, int) and not isinstance(frames, bool) and frames >= 0
    if not duration_valid:
        errors.append("$.sealed_candidate.performance.duration_minutes: finite non-negative number is required")
    if not frames_valid:
        errors.append("$.sealed_candidate.performance.frames_per_scene: non-negative integer is required")
    duration_ok = duration_valid and duration >= 10
    frames_ok = frames_valid and frames >= 3000
    if not (duration_ok or frames_ok):
        errors.append("$.sealed_candidate.performance: requires >=10 minutes or >=3000 frames per scene")
    _positive_int(performance.get("cold_starts"), 20, "$.sealed_candidate.performance.cold_starts", errors)
    _token_list(performance.get("scenes"), "$.sealed_candidate.performance.scenes", errors)

    crash = _obj(candidate.get("crash_monitoring"), CRASH_KEYS, "$.sealed_candidate.crash_monitoring", errors)
    _bool(crash.get("external_heartbeat"), True, "$.sealed_candidate.crash_monitoring.external_heartbeat", errors)
    _bool(crash.get("bsod_detection"), True, "$.sealed_candidate.crash_monitoring.bsod_detection", errors)
    _digest(crash.get("heartbeat_receipt_digest"), "$.sealed_candidate.crash_monitoring.heartbeat_receipt_digest", errors)

    rollback = _obj(candidate.get("rollback"), ROLLBACK_KEYS, "$.sealed_candidate.rollback", errors)
    steps = set(_token_list(rollback.get("steps"), "$.sealed_candidate.rollback.steps", errors))
    if not REQUIRED_ROLLBACK_STEPS.issubset(steps):
        errors.append(f"$.sealed_candidate.rollback.steps: missing {sorted(REQUIRED_ROLLBACK_STEPS - steps)}")
    if rollback.get("cycles_required") != 3 or rollback.get("cycles_completed") != 3:
        errors.append("$.sealed_candidate.rollback: exactly 3/3 completed cycles are required")
    _digest(rollback.get("receipt_digest"), "$.sealed_candidate.rollback.receipt_digest", errors)


def validate_document(data: Any) -> tuple[list[str], dict[str, Any]]:
    errors = _scan(data)
    if not isinstance(data, dict):
        errors.append("$: object is required")
        return errors, _report(errors, "contract_rejected", [])
    packet = _obj(data, TOP_KEYS, "$", errors)
    if packet.get("schema_version") != "tamandua.anti_cheat_windows_live_lab_preflight/v1":
        errors.append("$.schema_version: unsupported or missing")
    state = packet.get("packet_state")
    if state not in {"preregistered_hold", "sealed_candidate"}:
        errors.append("$.packet_state: must be preregistered_hold or sealed_candidate")
    _bool(packet.get("execution_requested"), False, "$.execution_requested", errors)
    if packet.get("evidence_class") != "preregistration_only":
        errors.append("$.evidence_class: must be preregistration_only")
    claims = _obj(packet.get("claims"), CLAIM_KEYS, "$.claims", errors)
    for field in CLAIM_KEYS:
        _bool(claims.get(field), False, f"$.claims.{field}", errors)
    blockers = _current_driver(packet.get("current_driver"), state, errors)
    if state == "preregistered_hold":
        if packet.get("sealed_candidate") is not None:
            errors.append("$.sealed_candidate: must be null for preregistered_hold")
        decision = "HOLD"
    elif state == "sealed_candidate":
        _validate_candidate(packet.get("sealed_candidate"), errors)
        blockers = blockers + ["operator_authorization_required"]
        decision = "operator_authorization_required"
    else:
        decision = "contract_rejected"
    if errors:
        decision = "contract_rejected"
    return errors, _report(errors, decision, blockers)


def _report(errors: list[str], decision: str, blockers: list[str]) -> dict[str, Any]:
    return {
        "gate": "anti_cheat_windows_live_lab_preflight",
        "contract_valid": not errors,
        "decision": decision,
        "blockers": blockers,
        "execution_authorized": False,
        "operator_authorization_required": decision == "operator_authorization_required",
        "errors": errors,
        "claim_boundary": (
            "Read-only preregistration structure only; no command, driver, VM, effectiveness, "
            "FPR, execution, release, or production claim is authorized."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        data = load_json(args.fixture)
        errors, report = validate_document(data)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        errors = [f"{args.fixture}: {exc}"]
        report = _report(errors, "contract_rejected", [])
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
