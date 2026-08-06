from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/runtime_rx_page_content_live_probe_v1.py"
FIXTURE = ROOT / "tools/detection_validation/fixtures/runtime_rx_page_content_live_probe_v1.json"
SCHEMA = ROOT / "schemas/runtime_rx_page_content_live_probe_v1.schema.json"

SPEC = importlib.util.spec_from_file_location("runtime_rx_page_content_live_probe_v1", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def scenario(payload: dict, scenario_id: str) -> dict:
    return next(item for item in payload["scenarios"] if item["id"] == scenario_id)["receipt"]


def gate_errors(tmp_path: Path, payload: dict, require_executed: bool = False) -> list[str]:
    path = tmp_path / "receipt-fixture.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    errors, _summary = GATE.validate_fixture(path, SCHEMA, require_executed)
    return errors


def executed_receipt() -> dict:
    receipt = copy.deepcopy(scenario(load_fixture(), "owned-release-clean"))
    receipt["execute"] = True
    receipt["run_id"] = "20260717T120000Z-runtime-rx-live-a1b2c3d4e5f6"
    receipt["executed_at_utc"] = "2026-07-17T12:00:00Z"
    receipt["receipt_provenance"] = "live_probe_runner"
    provenance = receipt["provenance"]
    digest = lambda label: hashlib.sha256(label.encode()).hexdigest()
    provenance.update({
        "source_sha": digest("live-source")[:40],
        "scoped_dirty": True,
        "scoped_dirty_diff_sha256": digest("live-dirty-diff"),
        "cargo_lock_sha256": digest("live-cargo-lock"),
        "rustc_version": "rustc 1.88.0 (6b00bc388 2025-06-23)",
        "cargo_version": "cargo 1.88.0 (873a06493 2025-05-10)",
        "artifact_sha256": digest("live-artifact"),
        "config_sha256": digest("live-config"),
    })
    receipt["custody"]["artifact_sha256_before"] = provenance["artifact_sha256"]
    receipt["custody"]["artifact_sha256_after"] = provenance["artifact_sha256"]
    receipt["custody"]["config_sha256_before"] = provenance["config_sha256"]
    receipt["custody"]["config_sha256_after"] = provenance["config_sha256"]
    return receipt


def test_schema_fixture_and_cli_pass_only_as_unexecuted_synthetic_model() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout) == {
        "evidence_class": "synthetic_smoke",
        "execute": False,
        "execution_scope": "local_synthetic",
        "external_claim_allowed": False,
        "fpr_claim_allowed": False,
        "modeled_receipt_schema": "tamandua.runtime_integrity_live_probe_receipt/v1",
        "performance_claim_allowed": False,
        "scenario_count": 3,
        "vendor_parity_claimed": False,
    }
    payload = load_fixture()
    assert payload["execute"] is False
    assert all(item["receipt"]["execute"] is False for item in payload["scenarios"])
    assert "No probe" in payload["claim_boundary"]


def test_require_executed_rejects_every_synthetic_modeled_receipt() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--require-executed"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert "requires an explicit --receipt direct lane" in completed.stdout
    assert "Traceback" not in completed.stdout + completed.stderr


def test_direct_executed_receipt_lane_accepts_only_execute_true(tmp_path: Path) -> None:
    receipt = executed_receipt()
    path = tmp_path / "executed-receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--receipt", str(path)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary == {
        "evidence_class": "local_live_collector_smoke",
        "execute": True,
        "execution_scope": "wsl2_network_isolated",
        "external_claim_allowed": False,
        "fpr_claim_allowed": False,
        "performance_claim_allowed": False,
        "receipt_schema": "tamandua.runtime_integrity_live_probe_receipt/v1",
        "vendor_parity_claimed": False,
    }

    receipt["execute"] = False
    path.write_text(json.dumps(receipt), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--receipt", str(path)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert "an executed receipt is required" in completed.stdout


def test_synthetic_fixture_receipts_can_never_be_promoted(tmp_path: Path) -> None:
    payload = load_fixture()
    scenario(payload, "owned-release-clean")["execute"] = True
    assert any("synthetic fixture receipts must remain false" in error for error in gate_errors(tmp_path, payload))


@pytest.mark.parametrize(
    ("location", "field", "value", "needle"),
    [
        (None, "run_id", "synthetic-owned-release-clean", "synthetic or placeholder run IDs"),
        (None, "executed_at_utc", "2000-01-01T00:00:02Z", "synthetic or sentinel timestamps"),
        (None, "receipt_provenance", "synthetic_fixture", "live_probe_runner provenance"),
        ("provenance", "rustc_version", "rustc 1.88.0 (synthetic)", "synthetic build provenance"),
        ("provenance", "artifact_sha256", "4" * 64, "placeholder or sentinel hash"),
    ],
)
def test_direct_lane_rejects_synthetic_or_placeholder_provenance(
    tmp_path: Path, location: str | None, field: str, value: str, needle: str
) -> None:
    receipt = executed_receipt()
    target = receipt if location is None else receipt[location]
    target[field] = value
    if field == "artifact_sha256":
        receipt["custody"]["artifact_sha256_before"] = value
        receipt["custody"]["artifact_sha256_after"] = value
    path = tmp_path / "direct.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--receipt", str(path), "--require-executed"],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert needle in completed.stdout


@pytest.mark.parametrize(("dirty", "diff_sha"), [(False, "8" * 64), (True, GATE.EMPTY_SHA256)])
def test_direct_cli_rejects_dirty_diff_contradictions(
    tmp_path: Path, dirty: bool, diff_sha: str
) -> None:
    receipt = executed_receipt()
    receipt["provenance"]["scoped_dirty"] = dirty
    receipt["provenance"]["scoped_dirty_diff_sha256"] = diff_sha
    path = tmp_path / "direct-diff.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--receipt", str(path), "--require-executed"],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert "scoped_dirty must be true iff" in completed.stdout


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-99-99T99:99:99Z",
        "2026-02-31T12:00:00Z",
        "2025-02-29T12:00:00Z",
        "2026-07-17T24:00:00Z",
        "2026-07-17T12:00:00+00:00",
        "2026-07-17t12:00:00z",
    ],
)
def test_direct_cli_rejects_invalid_or_noncanonical_utc_calendar(
    tmp_path: Path, timestamp: str
) -> None:
    receipt = executed_receipt()
    receipt["executed_at_utc"] = timestamp
    path = tmp_path / "direct-timestamp.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--receipt", str(path), "--require-executed"],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert "executed_at_utc" in completed.stdout


@pytest.mark.parametrize(
    "timestamp",
    ["2024-02-29T23:59:59Z", "2024-02-29T23:59:59.123456Z"],
)
def test_leap_day_and_fractional_utc_timestamp_are_accepted(timestamp: str) -> None:
    receipt = executed_receipt()
    receipt["executed_at_utc"] = timestamp
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(receipt))
    assert GATE.utc_timestamp_error(timestamp) is None


def test_disabled_degraded_clean_benign_matrix_is_exact() -> None:
    payload = load_fixture()
    expected = [
        ("disabled-control", "disabled_control", "disabled", 1),
        ("baseline-degraded-control", "baseline_degraded_control", "degraded", 1),
        ("owned-release-clean", "owned_release_clean", "clean", 3),
    ]
    observed = []
    for item in payload["scenarios"]:
        receipt = item["receipt"]
        output = receipt["probe_output"]
        observed.append((item["id"], receipt["scenario"], output["final_summary"]["page_content"]["status"], output["ticks_executed"]))
        assert receipt["benign_matrix"]["compromise_observed"] is False
        assert receipt["benign_matrix"]["drift_observed"] is False
        assert output["finding_kinds"] == []
    assert observed == expected


@pytest.mark.parametrize(
    ("location", "field", "value", "needle"),
    [
        ("provenance", "source_sha", "a" * 41, "does not match"),
        ("provenance", "cargo_lock_sha256", "A" * 64, "does not match"),
        ("provenance", "build_command", "cargo build --release", "was expected"),
        ("provenance", "artifact_size_bytes", 0, "less than the minimum"),
        ("protection", "artifact_owner_uid", 1000, "0 was expected"),
        ("protection", "config_mode", "0644", "'0600' was expected"),
        ("isolation", "network_namespace_isolated", False, "True was expected"),
        ("isolation", "strace_network_syscalls", 1, "0 was expected"),
        ("isolation", "strace_filesystem_mutation_syscalls", 1, "0 was expected"),
        ("cleanup", "temporary_artifacts_remaining", 1, "0 was expected"),
        ("measurements", "max_rss_kib", 262145, "greater than the maximum"),
        ("measurements", "max_rss_source", "proc_status", "'usr_bin_time_v' was expected"),
    ],
)
def test_provenance_protection_isolation_rss_and_cleanup_fail_closed(
    tmp_path: Path, location: str, field: str, value, needle: str
) -> None:
    payload = load_fixture()
    scenario(payload, "owned-release-clean")[location][field] = value
    joined = "\n".join(gate_errors(tmp_path, payload))
    assert needle in joined


def test_sha_before_after_and_scoped_dirty_bindings_are_exact(tmp_path: Path) -> None:
    payload = load_fixture()
    receipt = scenario(payload, "owned-release-clean")
    receipt["custody"]["artifact_sha256_after"] = "8" * 64
    assert any("artifact SHA must remain equal" in error for error in gate_errors(tmp_path, payload))

    payload = load_fixture()
    receipt = scenario(payload, "owned-release-clean")
    receipt["custody"]["config_sha256_before"] = "8" * 64
    assert any("config SHA must remain equal" in error for error in gate_errors(tmp_path, payload))

    payload = load_fixture()
    receipt = scenario(payload, "owned-release-clean")
    receipt["provenance"]["scoped_dirty"] = False
    assert any("scoped_dirty must be true iff" in error for error in gate_errors(tmp_path, payload))

    payload = load_fixture()
    receipt = scenario(payload, "owned-release-clean")
    receipt["provenance"]["scoped_dirty_diff_sha256"] = GATE.EMPTY_SHA256
    assert any("scoped_dirty must be true iff" in error for error in gate_errors(tmp_path, payload))


@pytest.mark.parametrize("timing", ["config_load_elapsed_us", "collector_init_elapsed_us", "probe_wall_elapsed_us"])
def test_phase_timings_are_exactly_bound_to_probe_output(tmp_path: Path, timing: str) -> None:
    payload = load_fixture()
    scenario(payload, "owned-release-clean")["measurements"][timing] += 1
    assert any(f"external and probe {timing} must match exactly" in error for error in gate_errors(tmp_path, payload))


def test_wall_time_covers_phases_and_bootstrap_cap(tmp_path: Path) -> None:
    payload = load_fixture()
    receipt = scenario(payload, "owned-release-clean")
    receipt["measurements"]["probe_wall_elapsed_us"] = 1000
    receipt["probe_output"]["probe_wall_elapsed_us"] = 1000
    assert any("wall time must cover" in error for error in gate_errors(tmp_path, payload))

    payload = load_fixture()
    receipt = scenario(payload, "owned-release-clean")
    receipt["measurements"]["collector_init_elapsed_us"] = 100001
    receipt["probe_output"]["collector_init_elapsed_us"] = 100001
    assert any("greater than the maximum" in error for error in gate_errors(tmp_path, payload))


def test_tick_summary_progress_final_and_aggregate_bindings_fail_closed(tmp_path: Path) -> None:
    mutations = []
    payload = load_fixture()
    scenario(payload, "owned-release-clean")["probe_output"]["ticks_executed"] = 2
    mutations.append((payload, "ticks_executed must equal"))

    payload = load_fixture()
    output = scenario(payload, "owned-release-clean")["probe_output"]
    output["final_summary"] = copy.deepcopy(output["summaries"][0])
    mutations.append((payload, "final_summary must exactly equal"))

    payload = load_fixture()
    output = scenario(payload, "owned-release-clean")["probe_output"]
    output["state"] = "degraded"
    mutations.append((payload, "aggregate state and page_content"))

    payload = load_fixture()
    output = scenario(payload, "owned-release-clean")["probe_output"]
    output["limitations"] = ["rx_page_content_disabled"]
    mutations.append((payload, "aggregate limitations must be"))

    payload = load_fixture()
    output = scenario(payload, "owned-release-clean")["probe_output"]
    output["summaries"][1]["page_content"]["sweep_pages_compared"] = 15
    mutations.append((payload, "committed sweep progress is not monotonic and exact"))

    payload = load_fixture()
    output = scenario(payload, "owned-release-clean")["probe_output"]
    output["summaries"][1]["page_content"]["eligible_pages"] = 18
    mutations.append((payload, "eligible and relocation-exclusion totals must remain stable"))

    for mutated, needle in mutations:
        assert needle in "\n".join(gate_errors(tmp_path, mutated))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("elapsed_us_this_tick", 10001),
        ("memory_bytes_read_this_tick", 69632),
        ("pages_compared_this_tick", 9),
    ],
)
def test_every_tick_is_bounded_by_10ms_64kib_and_eight_pages(
    tmp_path: Path, field: str, value: int
) -> None:
    payload = load_fixture()
    output = scenario(payload, "owned-release-clean")["probe_output"]
    output["summaries"][0]["page_content"][field] = value
    errors = gate_errors(tmp_path, payload)
    assert errors
    assert "maximum" in "\n".join(errors) or "every accepted tick" in "\n".join(errors)


def test_summary_count_is_capped_at_1024(tmp_path: Path) -> None:
    payload = load_fixture()
    output = scenario(payload, "owned-release-clean")["probe_output"]
    output["summaries"] = [copy.deepcopy(output["summaries"][0]) for _ in range(1025)]
    output["ticks_executed"] = 1024
    errors = gate_errors(tmp_path, payload)
    assert any("is too long" in error for error in errors)


def test_raw_v3_status_cause_and_finding_mutations_fail_closed(tmp_path: Path) -> None:
    payload = load_fixture()
    summary = scenario(payload, "owned-release-clean")["probe_output"]["summaries"][0]
    summary["limitations"] = ["rx_page_content_disabled"]
    assert any("raw v3" in error or "normal status" in error for error in gate_errors(tmp_path, payload))

    payload = load_fixture()
    output = scenario(payload, "owned-release-clean")["probe_output"]
    output["finding_kinds"] = ["file_backed_executable_page_drift"]
    output["summaries"][0]["finding_kinds"] = ["file_backed_executable_page_drift"]
    assert any("benign matrix must not contain runtime findings" in error for error in gate_errors(tmp_path, payload))


@pytest.mark.parametrize("field", GATE.PRIVACY_MUTATION_FIELDS)
def test_forbidden_privacy_fields_are_rejected(tmp_path: Path, field: str) -> None:
    payload = load_fixture()
    scenario(payload, "owned-release-clean")[field] = "forbidden"
    assert any(f".{field}: forbidden privacy field" in error for error in gate_errors(tmp_path, payload))


@pytest.mark.parametrize("leak", ["/tmp/agent", "pid=4242", "inode:123", "0x7fffdeadbeef"])
def test_raw_path_pid_inode_and_address_strings_are_rejected(tmp_path: Path, leak: str) -> None:
    payload = load_fixture()
    scenario(payload, "owned-release-clean")["provenance"]["rustc_version"] = f"rustc 1.88.0 ({leak})"
    assert any("forbidden raw path, PID, inode, or address" in error for error in gate_errors(tmp_path, payload))


@pytest.mark.parametrize("claim", ["external_claim_allowed", "fpr_claim_allowed", "performance_claim_allowed", "vendor_parity_claimed"])
def test_claim_escalation_is_rejected(tmp_path: Path, claim: str) -> None:
    payload = load_fixture()
    payload[claim] = True
    assert f"fixture: {claim} must remain exact" in gate_errors(tmp_path, payload)


@pytest.mark.parametrize("field", GATE.SHARED_PROVENANCE_FIELDS)
def test_matrix_binds_every_source_build_and_artifact_field(tmp_path: Path, field: str) -> None:
    payload = load_fixture()
    degraded = scenario(payload, "baseline-degraded-control")
    original = degraded["provenance"][field]
    if isinstance(original, bool):
        degraded["provenance"][field] = not original
    elif isinstance(original, int):
        degraded["provenance"][field] = original + 1
    else:
        degraded["provenance"][field] = "9" * len(original)
    assert any("one source/build/artifact identity" in error for error in gate_errors(tmp_path, payload))


def test_matrix_requires_three_distinct_configs(tmp_path: Path) -> None:
    payload = load_fixture()

    degraded = scenario(payload, "baseline-degraded-control")
    disabled = scenario(payload, "disabled-control")
    degraded["provenance"]["config_sha256"] = disabled["provenance"]["config_sha256"]
    degraded["custody"]["config_sha256_before"] = disabled["provenance"]["config_sha256"]
    degraded["custody"]["config_sha256_after"] = disabled["provenance"]["config_sha256"]
    assert any("three distinct configs" in error for error in gate_errors(tmp_path, payload))


def test_malformed_fixture_cli_is_bounded_without_traceback(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"scenarios": [', encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(malformed)], cwd=ROOT,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    diagnostic = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert "Traceback" not in diagnostic
    assert len(diagnostic) <= 320
