from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "anti_cheat_privileged_canary_gate.py"
FIXTURE = ROOT / "tools" / "detection_validation" / "fixtures" / "anti_cheat_privileged_canary_valid.json"
SPEC = importlib.util.spec_from_file_location("anti_cheat_privileged_canary_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def valid_packet() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def platform(packet: dict, name: str) -> dict:
    return next(item for item in packet["platforms"] if item["platform"] == name)


def messages(packet: dict) -> str:
    errors, _ = GATE.validate_document(packet)
    return "\n".join(errors)


def test_valid_synthetic_cross_platform_packet_passes_and_stays_honest() -> None:
    errors, report = GATE.validate_document(valid_packet())

    assert errors == []
    assert report["passed"] is True
    assert report["verdict"] == "contract_valid"
    assert report["platforms"]["windows"]["capability_state"] == "degraded"
    assert report["platforms"]["windows"]["privileged_evidence_state"] == "synthetic"
    assert report["platforms"]["linux"]["capability_state"] == "unsupported"
    assert report["platforms"]["macos"]["capability_state"] == "unsupported"
    assert all(
        item["server_authoritative_corroboration"] == "not_executed"
        for item in report["platforms"].values()
    )
    assert report["evidence_class"] == "synthetic_contract_only"
    assert "not efficacy" in report["claim_boundary"]
    assert "external anti-cheat claim" in report["claim_boundary"]


def test_cli_emits_json_report_and_exit_codes(tmp_path: Path) -> None:
    passed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(FIXTURE)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert passed.returncode == 0, passed.stdout + passed.stderr
    assert json.loads(passed.stdout)["passed"] is True

    invalid_path = tmp_path / "anti_cheat_privileged_canary_invalid.json"
    invalid = valid_packet()
    invalid["mode"] = "enforce"
    invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(invalid_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    report = json.loads(failed.stdout)
    assert failed.returncode == 1
    assert report["passed"] is False
    assert report["verdict"] == "contract_rejected"
    assert report["errors"]


@pytest.mark.parametrize(
    ("os_name", "false_backend"),
    [
        ("windows", "driverkit"),
        ("linux", "linux_kernel_module"),
        ("macos", "kext"),
    ],
)
def test_rejects_false_privileged_backend_equivalence(os_name: str, false_backend: str) -> None:
    packet = valid_packet()
    platform(packet, os_name)["privileged"]["backend"] = false_backend

    result = messages(packet)

    assert f"{os_name} requires exactly" in result


@pytest.mark.parametrize("value", ["enforce", "kick", "ban", " ban ", "permanent_ban", "kill_session"])
def test_rejects_enforcement_and_durable_sanction_values(value: str) -> None:
    packet = valid_packet()
    packet["proposed_action"] = value

    assert "enforcement or durable sanction" in messages(packet)


@pytest.mark.parametrize(
    "field",
    ["source_sha", "artifact_digest", "build_id", "session_id", "protected_target_id"],
)
def test_rejects_missing_source_artifact_build_and_session_identity(field: str) -> None:
    packet = valid_packet()
    del packet["identity"][field]

    assert f"$.identity.{field}" in messages(packet)


def test_rejects_silent_capability_and_missing_reasons_or_limitations() -> None:
    packet = valid_packet()
    windows = platform(packet, "windows")
    del windows["capability_state"]
    windows["reasons"] = []
    del windows["limitations"]

    result = messages(packet)

    assert "capability_state" in result
    assert ".reasons" in result
    assert ".limitations" in result


def test_rejects_missing_clean_controls_rollback_uninstall_and_performance() -> None:
    packet = valid_packet()
    privileged = platform(packet, "windows")["privileged"]
    for key in ("clean_controls", "rollback", "uninstall", "performance"):
        del privileged[key]

    result = messages(packet)

    assert "clean_controls: object is required" in result
    assert "rollback: object is required" in result
    assert "uninstall: object is required" in result
    assert "performance: object is required" in result


def test_synthetic_performance_is_explicitly_estimated_but_metrics_remain_required() -> None:
    packet = valid_packet()
    performance = platform(packet, "windows")["privileged"]["performance"]
    performance["state"] = "measured"

    assert "evidence_state=synthetic requires state=synthetic_estimate" in messages(packet)

    packet = valid_packet()
    performance = platform(packet, "windows")["privileged"]["performance"]
    del performance["metrics"]["frame_time_p95_delta_ms"]

    assert "frame_time_p95_delta_ms: finite non-negative number is required" in messages(packet)


def test_rejects_non_independent_privileged_source() -> None:
    packet = valid_packet()
    windows = platform(packet, "windows")
    windows["privileged"]["independent_of_baseline"] = False
    windows["privileged"]["synthetic_identity"]["source_id"] = windows["baseline"]["synthetic_identity"]["source_id"]

    result = messages(packet)

    assert "independent_of_baseline: must be true" in result
    assert "privileged source_id must differ" in result


def test_rejects_supported_platform_without_live_proof() -> None:
    packet = valid_packet()
    platform(packet, "windows")["capability_state"] = "supported"

    assert "v1 allows only degraded or unsupported" in messages(packet)


def test_rejects_missing_or_inferred_server_authoritative_corroboration() -> None:
    packet = valid_packet()
    del platform(packet, "windows")["server_authoritative_corroboration"]

    assert "server_authoritative_corroboration: object is required" in messages(packet)


def test_rejects_invalid_incremental_detector_family_math() -> None:
    packet = valid_packet()
    metric = platform(packet, "windows")["privileged"]["detector_metrics"][0]
    metric["incremental_detected"] = 4

    assert "must equal privileged_detected - baseline_detected" in messages(packet)


@pytest.mark.parametrize("unknown_key", ["keystrokes", "memory_dump", "password", "home_address"])
def test_rejects_unknown_or_sensitive_fields_by_closed_allowlist(unknown_key: str) -> None:
    packet = valid_packet()
    platform(packet, "windows")["privileged"][unknown_key] = "redacted-is-still-not-allowed"

    assert "unknown fields" in messages(packet)


def test_requires_exactly_all_three_platforms() -> None:
    packet = valid_packet()
    packet["platforms"] = [item for item in packet["platforms"] if item["platform"] != "macos"]

    assert "missing required platforms ['macos']" in messages(packet)


def test_fixture_is_sanitized_observe_shadow_metadata_only() -> None:
    packet = valid_packet()
    serialized = json.dumps(packet).lower()

    assert packet["mode"] == "observe_shadow"
    assert packet["decision"] == "observe"
    assert packet["durable_sanctions_allowed"] is False
    assert packet["privacy_mode"] == "metadata_only"
    assert not any(f'"{key}"' in serialized for key in {"password", "home_address", "raw_payload", "keystrokes"})
    assert {item["platform"] for item in packet["platforms"]} == {"windows", "linux", "macos"}


def test_v1_rejects_supported_live_even_when_controls_fail() -> None:
    packet = valid_packet()
    windows = platform(packet, "windows")
    windows["capability_state"] = "supported"
    windows["privileged"]["evidence_state"] = "live"
    windows["privileged"]["clean_controls"] = {"state": "failed", "count": 2}

    result = messages(packet)

    assert "v1 allows only degraded or unsupported" in result
    assert "v1 rejects live" in result
    assert "not_executed evidence requires state=not_executed and count=0" in result


def test_v1_rejects_trust_me_server_corroboration_and_receipt() -> None:
    packet = valid_packet()
    corroboration = platform(packet, "windows")["server_authoritative_corroboration"]
    corroboration["state"] = "executed"
    corroboration["receipt"] = "trust-me"

    result = messages(packet)

    assert "unknown fields ['receipt']" in result
    assert "v1 requires not_executed" in result


def test_synthetic_detector_family_requires_positive_attempts() -> None:
    packet = valid_packet()
    platform(packet, "windows")["privileged"]["detector_metrics"][0].update(
        attempts=0, baseline_detected=0, privileged_detected=0, incremental_detected=0
    )

    assert "synthetic metric requires attempts > 0" in messages(packet)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_rejects_non_finite_performance_numbers(value: float) -> None:
    packet = valid_packet()
    metrics = platform(packet, "windows")["privileged"]["performance"]["metrics"]
    metrics["cpu_median_percent"] = value

    result = messages(packet)

    assert "NaN and Infinity are forbidden" in result
    assert "finite non-negative number is required" in result


def test_in_memory_validator_rejects_depth_1200_without_recursion_error() -> None:
    packet = valid_packet()
    nested: dict = {}
    packet["unexpected"] = nested
    for _ in range(1200):
        child: dict = {}
        nested["next"] = child
        nested = child

    result = messages(packet)

    assert "nesting exceeds maximum depth" in result
    assert "unknown fields ['unexpected']" in result


def test_in_memory_validator_rejects_cycle_without_hanging() -> None:
    packet = valid_packet()
    packet["unexpected"] = packet

    result = messages(packet)

    assert "cyclic or reused container" in result
    assert "unknown fields ['unexpected']" in result


def test_rejects_evidence_class_contradiction() -> None:
    packet = valid_packet()
    packet["evidence_class"] = "live_protected_session"
    windows = platform(packet, "windows")
    windows["privileged"]["evidence_state"] = "live"

    result = messages(packet)

    assert "v1 is strictly synthetic_observe_shadow" in result
    assert "v1 rejects live" in result


@pytest.mark.parametrize("field", ["rollback", "uninstall"])
def test_unsupported_lane_rejects_claimed_available_lifecycle_controls(field: str) -> None:
    packet = valid_packet()
    control = platform(packet, "linux")["privileged"][field]
    control.update(available=True, procedure_id="trust-me-procedure")

    assert "unsupported lane requires available=false" in messages(packet)


def test_each_arm_requires_reproducible_synthetic_identity() -> None:
    packet = valid_packet()
    windows = platform(packet, "windows")
    del windows["baseline"]["synthetic_identity"]["preregistration_id"]
    windows["privileged"]["synthetic_identity"]["artifact_digest"] = windows["baseline"]["synthetic_identity"]["artifact_digest"]

    result = messages(packet)

    assert "preregistration_id: strict opaque identifier is required" in result
    assert "privileged artifact_digest must differ" in result


def test_cli_rejects_oversized_fixture_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "anti_cheat_privileged_canary_oversized.json"
    path.write_text(" " * (GATE.MAX_FILE_BYTES + 1), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 1
    assert "exceeds maximum size" in json.loads(completed.stdout)["errors"][0]


def test_cli_rejects_duplicate_json_key_instead_of_last_key_wins(tmp_path: Path) -> None:
    path = tmp_path / "anti_cheat_privileged_canary_duplicate_mode.json"
    text = FIXTURE.read_text(encoding="utf-8").replace(
        '  "mode": "observe_shadow",',
        '  "mode": "enforce",\n  "mode": "observe_shadow",',
        1,
    )
    path.write_text(text, encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 1
    assert "duplicate JSON key 'mode'" in json.loads(completed.stdout)["errors"][0]


def test_rejects_divergent_ab_preregistration_identity() -> None:
    packet = valid_packet()
    identity = platform(packet, "windows")["privileged"]["synthetic_identity"]
    identity["preregistration_id"] = "different-preregistration-v1"

    assert "baseline and privileged preregistration_id must match" in messages(packet)


@pytest.mark.parametrize("pii_kind", ["email", "uri", "control"])
def test_rejects_pii_or_free_form_content_in_allowlisted_strings(pii_kind: str) -> None:
    packet = valid_packet()
    windows = platform(packet, "windows")
    if pii_kind == "email":
        windows["baseline"]["synthetic_identity"]["source_id"] = "player@example.com"
        expected = "email-like data is forbidden"
    elif pii_kind == "uri":
        windows["limitations"] = ["https://example.invalid/player/123"]
        expected = "URI-like data is forbidden"
    else:
        windows["server_authoritative_corroboration"]["reason"] = "bad\nvalue"
        expected = "control characters are forbidden"

    result = messages(packet)

    assert expected in result
    assert "safe token" in result or "safe-token" in result or "opaque identifier" in result
