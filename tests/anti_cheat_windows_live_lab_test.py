from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "anti_cheat_windows_live_lab_preflight.py"
FIXTURE = ROOT / "tools" / "detection_validation" / "fixtures" / "anti_cheat_windows_live_lab_preregistered_hold.json"
SPEC = importlib.util.spec_from_file_location("anti_cheat_windows_live_lab_preflight", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def packet() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def errors(value: object) -> str:
    found, _ = GATE.validate_document(value)
    return "\n".join(found)


def sha(character: str) -> str:
    return "sha256:" + character * 64


def sealed_packet() -> dict:
    value = packet()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    timestamp = lambda moment: moment.isoformat().replace("+00:00", "Z")
    value["packet_state"] = "sealed_candidate"
    value["current_driver"].update({
        "status": "neutralized_or_absent",
        "neutralization_receipt_digest": sha("0"),
        "observe_only": False,
        "active_controls": [],
        "process_control": False,
        "file_control": False,
        "lsass_protection": False,
        "self_protection": False,
        "agent_auto_load": False,
        "scan_port": False,
        "digest_evidence_state": "not_applicable_removed",
        "local_digests": {},
    })
    value["sealed_candidate"] = {
        "source": {
            "source_sha": "0123456789abcdef0123456789abcdef01234567",
            "clean_worktree_receipt": {"state": "verified", "receipt_digest": sha("9")},
        },
        "artifacts": {
            "driver": sha("a"), "inf": sha("b"), "cat": sha("c"), "agent": sha("d"),
            "game": sha("e"), "harness": sha("f"), "policy": sha("1"), "scripts": sha("2"),
        },
        "build": {
            "toolchain_id": "wdk-10.0.26100.0",
            "toolchain_digest": sha("3"),
            "build_flags": ["observe_only", "no_active_controls", "orchestrator_only_load"],
        },
        "safety": {
            "observe_only": True, "active_controls": [], "lsass_protection": False,
            "process_control": False, "file_control": False, "self_protection": False,
            "scan_port": False, "agent_auto_load": False, "orchestrator_only_load": True,
        },
        "signing": {
            "state": "verified", "driver_signed": True, "inf_cat_verified": True,
            "signer_identity_digest": sha("4"), "verification_receipt_digest": sha("5"),
        },
        "lab": {
            "provider": "proxmox", "vm_id": "vm-9133", "disposable": True,
            "snapshot_id": "snap-clean-133", "recovery_receipt_digest": sha("6"),
            "qga_ready": True, "isolated_network": True, "network_id": "isolated-133",
        },
        "guest": {
            "windows_build": "windows-11-24h2", "kernel_build": "26100.4652",
            "secure_boot": True, "testsigning": False, "vbs": True, "hvci": True, "wdac": True,
        },
        "lease": {
            "owner": "operator-133", "target": "vm-9133", "surface": "anti_cheat_windows_driver_live_lab",
            "source_sha": "0123456789abcdef0123456789abcdef01234567",
            "artifact_digest": sha("a"), "heartbeat_at": timestamp(now - timedelta(minutes=1)),
            "validated_at": timestamp(now), "expires_at": timestamp(now + timedelta(minutes=30)),
            "previous_fencing_token": 1, "fencing_token": 2,
        },
        "ab_design": {
            "same_build": True, "same_policy": True, "same_seed": True,
            "restore_before_each_arm": True,
            "experiment_id": "experiment-133", "pair_group_id": "pair-133",
            "build_id": "build-133", "policy_id": "policy-133", "seed_id": "seed-133",
            "workload_digest": sha("b"),
            "baseline": {"arm_id": "arm-a", "session_id": "session-baseline-133", "pair_id": "pair-133"},
            "privileged": {"arm_id": "arm-b", "session_id": "session-privileged-133", "pair_id": "pair-133"},
            "ordering": ["AB", "BA"],
            "clean_families": ["game_start", "game_idle", "match_join", "match_play", "match_exit", "game_stop"],
            "positive_families": ["handle_access", "image_tamper", "memory_write", "thread_inject", "debug_attach", "driver_abuse"],
            "paired_attempts_per_family": 5,
        },
        "performance": {
            "measurement_source": "external_harness", "legacy_stub": False,
            "pairs_per_scene": 5, "duration_minutes": 10, "frames_per_scene": 3000,
            "cold_starts": 20, "scenes": ["menu", "match", "stress"],
        },
        "crash_monitoring": {
            "external_heartbeat": True, "bsod_detection": True,
            "heartbeat_receipt_digest": sha("7"),
        },
        "rollback": {
            "steps": ["disable", "unload", "uninstall", "reboot", "snapshot_restore"],
            "cycles_required": 3, "cycles_completed": 3, "receipt_digest": sha("8"),
        },
    }
    value["sealed_candidate"]["artifacts"]["manifest_digest"] = GATE.artifact_manifest_digest(
        value["sealed_candidate"]["artifacts"]
    )
    return value


def test_current_fixture_is_contract_valid_hold_with_derived_blockers() -> None:
    found, report = GATE.validate_document(packet())

    assert found == []
    assert report["contract_valid"] is True
    assert report["decision"] == "HOLD"
    assert report["execution_authorized"] is False
    assert report["operator_authorization_required"] is False
    assert set(report["blockers"]) >= {
        "current_driver_not_observe_only", "active_controls_enabled", "process_control_enabled",
        "file_control_enabled", "lsass_protection_enabled", "self_protection_enabled",
        "agent_auto_load_enabled", "scan_port_enabled", "current_driver_digest_receipts_missing",
    }
    assert packet()["current_driver"]["local_digests"] == {}


def test_hold_rejects_receipt_shaped_placeholder_digests() -> None:
    value = packet()
    value["current_driver"]["local_digests"]["driver"] = sha("1")

    assert "must be empty until digest receipts are collected" in errors(value)


def test_current_driver_blockers_are_derived_from_observed_fields() -> None:
    value = packet()
    value["current_driver"]["observe_only"] = True
    value["current_driver"]["process_control"] = False
    found, report = GATE.validate_document(value)

    assert found
    assert "current_driver_not_observe_only" not in report["blockers"]
    assert "process_control_enabled" not in report["blockers"]
    assert "file_control_enabled" in report["blockers"]


def test_cli_emits_json_and_zero_for_contract_valid_hold() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(FIXTURE)], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    report = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert report["decision"] == "HOLD"
    assert report["execution_authorized"] is False


def test_structurally_sealed_candidate_still_requires_operator_and_never_authorizes() -> None:
    found, report = GATE.validate_document(sealed_packet())

    assert found == []
    assert report["decision"] == "operator_authorization_required"
    assert report["operator_authorization_required"] is True
    assert report["execution_authorized"] is False
    assert report["blockers"] == ["operator_authorization_required"]


def test_sealed_candidate_requires_current_driver_neutralization_receipt() -> None:
    value = sealed_packet()
    current = value["current_driver"]
    current.update(status="ineligible_active", process_control=True)
    current["active_controls"] = ["process_control"]
    current["neutralization_receipt_digest"] = None

    result = errors(value)

    assert "requires neutralized_or_absent" in result
    assert "must be [] after neutralization" in result
    assert "process_control: must be false" in result
    assert "neutralization_receipt_digest: sha256" in result


@pytest.mark.parametrize("requested", [True, "true", 1])
def test_execution_requested_can_never_be_true(requested: object) -> None:
    value = packet()
    value["execution_requested"] = requested
    assert "$.execution_requested: must be false" in errors(value)


def test_rejects_duplicate_keys_and_cli_returns_one(tmp_path: Path) -> None:
    path = tmp_path / "anti_cheat_windows_live_lab_duplicate.json"
    text = FIXTURE.read_text(encoding="utf-8").replace(
        '  "execution_requested": false,',
        '  "execution_requested": true,\n  "execution_requested": false,', 1,
    )
    path.write_text(text, encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(path)], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert "duplicate JSON key 'execution_requested'" in json.loads(completed.stdout)["errors"][0]


@pytest.mark.parametrize("field", ["driver", "inf", "cat", "agent", "game", "harness", "policy", "scripts"])
def test_sealed_candidate_requires_every_artifact_digest(field: str) -> None:
    value = sealed_packet()
    value["sealed_candidate"]["artifacts"][field] = "local-file-exists"
    assert f"artifacts.{field}: sha256" in errors(value)


def test_rejects_short_source_sha_and_dirty_worktree_receipt() -> None:
    value = sealed_packet()
    value["sealed_candidate"]["source"]["source_sha"] = "0123456"
    value["sealed_candidate"]["source"]["clean_worktree_receipt"]["state"] = "self_declared"
    result = errors(value)
    assert "exact 40-char lowercase SHA" in result
    assert "must be verified" in result


def test_rejects_unsafe_candidate_controls_and_load_path() -> None:
    value = sealed_packet()
    safety = value["sealed_candidate"]["safety"]
    safety.update(observe_only=False, active_controls=["process_control"], process_control=True, agent_auto_load=True, orchestrator_only_load=False)
    result = errors(value)
    assert "safety.observe_only: must be true" in result
    assert "active_controls: must be []" in result
    assert "process_control: must be false" in result
    assert "agent_auto_load: must be false" in result
    assert "orchestrator_only_load: must be true" in result


def test_rejects_missing_signing_and_disposable_lab_receipts() -> None:
    value = sealed_packet()
    value["sealed_candidate"]["signing"]["driver_signed"] = False
    value["sealed_candidate"]["lab"].update(disposable=False, qga_ready=False, isolated_network=False)
    result = errors(value)
    assert "driver_signed: must be true" in result
    assert "disposable: must be true" in result
    assert "qga_ready: must be true" in result
    assert "isolated_network: must be true" in result


def test_rejects_guest_testsigning_and_missing_explicit_posture() -> None:
    value = sealed_packet()
    guest = value["sealed_candidate"]["guest"]
    guest["testsigning"] = True
    del guest["hvci"]
    result = errors(value)
    assert "testsigning: must be false" in result
    assert "hvci: explicit boolean is required" in result


def test_rejects_lease_binding_expiry_and_missing_fence() -> None:
    value = sealed_packet()
    lease = value["sealed_candidate"]["lease"]
    lease.update(source_sha="f" * 40, artifact_digest=sha("f"), expires_at=lease["validated_at"], fencing_token=0)
    result = errors(value)
    assert "must bind candidate source_sha" in result
    assert "must bind driver digest" in result
    assert "lease must be live at validated_at" in result
    assert "fencing_token: integer >= 2" in result


def test_rejects_wrong_lease_target_surface_and_stale_validation() -> None:
    value = sealed_packet()
    lease = value["sealed_candidate"]["lease"]
    lease.update(
        target="vm-other",
        surface="other-surface",
        heartbeat_at="2026-07-17T12:10:00Z",
        validated_at="2026-07-17T12:05:00Z",
    )

    result = errors(value)

    assert "target: must equal lab.vm_id" in result
    assert "surface: unexpected lab surface" in result
    assert "validated_at: must be at or after heartbeat_at" in result


def test_invalid_calendar_timestamp_is_structured_error() -> None:
    value = sealed_packet()
    value["sealed_candidate"]["lease"]["validated_at"] = "2026-13-17T12:05:00Z"

    assert "valid UTC calendar timestamp" in errors(value)


def test_rejects_expired_lease_and_nonmonotonic_fence() -> None:
    value = sealed_packet()
    lease = value["sealed_candidate"]["lease"]
    lease.update(
        heartbeat_at="2020-01-01T00:00:00Z",
        validated_at="2020-01-01T00:01:00Z",
        expires_at="2020-01-01T00:02:00Z",
        previous_fencing_token=9,
        fencing_token=9,
    )

    result = errors(value)

    assert "validated_at: must be current within five minutes" in result
    assert "lease is expired at validation time" in result
    assert "must increase monotonically" in result


def test_rejects_unpaired_ab_design_and_insufficient_families() -> None:
    value = sealed_packet()
    ab = value["sealed_candidate"]["ab_design"]
    ab.update(same_seed=False, restore_before_each_arm=False, ordering=["AB"], paired_attempts_per_family=4)
    ab["privileged"] = dict(ab["baseline"])
    ab["privileged"]["pair_id"] = "unrelated-pair"
    ab["clean_families"] = ab["clean_families"][:5]
    result = errors(value)
    assert "same_seed: must be true" in result
    assert "restore_before_each_arm: must be true" in result
    assert "session_id values must be distinct" in result
    assert "arm_id values must be distinct" in result
    assert "must bind pair_group_id" in result
    assert "must be ['AB', 'BA']" in result
    assert "exactly 6 values" in result
    assert "paired_attempts_per_family: must be exactly 5" in result


def test_rejects_legacy_or_insufficient_performance_plan() -> None:
    value = sealed_packet()
    performance = value["sealed_candidate"]["performance"]
    performance.update(measurement_source="legacy_stub", legacy_stub=True, pairs_per_scene=4, duration_minutes=9, frames_per_scene=2999, cold_starts=19)
    result = errors(value)
    assert "must be external_harness" in result
    assert "legacy_stub: must be false" in result
    assert "pairs_per_scene: must be exactly 5" in result
    assert ">=10 minutes or >=3000 frames" in result
    assert "cold_starts: integer >= 20" in result


@pytest.mark.parametrize(
    ("field", "bad_value", "message"),
    [
        ("duration_minutes", -100, "finite non-negative number"),
        ("frames_per_scene", -1, "non-negative integer"),
    ],
)
def test_rejects_negative_performance_fields_even_when_other_threshold_passes(
    field: str, bad_value: int, message: str
) -> None:
    value = sealed_packet()
    value["sealed_candidate"]["performance"][field] = bad_value

    assert message in errors(value)


def test_artifact_roles_are_distinct_and_manifest_bound() -> None:
    value = sealed_packet()
    artifacts = value["sealed_candidate"]["artifacts"]
    artifacts["inf"] = artifacts["driver"]

    result = errors(value)

    assert "each artifact role must have a distinct digest" in result
    assert "manifest_digest: must bind the canonical role map" in result


def test_ab_arms_must_share_registered_pair_identity() -> None:
    value = sealed_packet()
    value["sealed_candidate"]["ab_design"]["privileged"]["pair_id"] = "other-pair"

    assert "privileged.pair_id: must bind pair_group_id" in errors(value)


def test_rejects_missing_crash_and_rollback_proof() -> None:
    value = sealed_packet()
    value["sealed_candidate"]["crash_monitoring"].update(external_heartbeat=False, bsod_detection=False)
    rollback = value["sealed_candidate"]["rollback"]
    rollback["steps"].remove("reboot")
    rollback["cycles_completed"] = 2
    result = errors(value)
    assert "external_heartbeat: must be true" in result
    assert "bsod_detection: must be true" in result
    assert "missing ['reboot']" in result
    assert "3/3 completed cycles" in result


@pytest.mark.parametrize("value", ["ban", " kill_session ", "enforce"])
def test_rejects_enforcement_and_sanction_values(value: str) -> None:
    document = packet()
    document["claims"]["unknown_action"] = value
    result = errors(document)
    assert "enforcement or sanction value" in result
    assert "unknown fields" in result


def test_rejects_raw_secret_pii_unknown_and_mutable_latest() -> None:
    value = sealed_packet()
    value["sealed_candidate"]["lease"]["password"] = "secret"
    value["sealed_candidate"]["lease"]["owner"] = "person@example.com"
    value["sealed_candidate"]["build"]["toolchain_id"] = "wdk:latest"
    result = errors(value)
    assert "sensitive/raw field is forbidden" in result
    assert "PII/URI-like string is forbidden" in result
    assert "mutable/latest reference is forbidden" in result
    assert "unknown fields" in result


def test_rejects_claims_of_effectiveness_or_fpr() -> None:
    value = packet()
    value["claims"]["effectiveness"] = True
    value["claims"]["fpr"] = True
    result = errors(value)
    assert "claims.effectiveness: must be false" in result
    assert "claims.fpr: must be false" in result


@pytest.mark.parametrize("number", [float("nan"), float("inf")])
def test_rejects_nonfinite_values(number: float) -> None:
    value = sealed_packet()
    value["sealed_candidate"]["performance"]["duration_minutes"] = number
    assert "NaN and Infinity are forbidden" in errors(value)


def test_rejects_deep_and_cyclic_in_memory_structures_without_recursion() -> None:
    value = packet()
    nested: dict = {}
    value["unknown"] = nested
    for _ in range(1200):
        child: dict = {}
        nested["next"] = child
        nested = child
    assert "nesting exceeds" in errors(value)

    value = packet()
    value["unknown"] = value
    assert "cyclic or reused container" in errors(value)


def test_cli_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "anti_cheat_windows_live_lab_oversized.json"
    path.write_text(" " * (GATE.MAX_BYTES + 1), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(path)], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert "file exceeds" in json.loads(completed.stdout)["errors"][0]
