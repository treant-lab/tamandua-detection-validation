from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/runtime_rx_page_content_preview_v2.py"
FIXTURE = ROOT / "tools/detection_validation/fixtures/runtime_rx_page_content_preview_v2.json"
SCHEMA = ROOT / "schemas/runtime_rx_page_content_preview_v2.schema.json"
V1_SCRIPT = ROOT / "tools/detection_validation/scripts/runtime_rx_page_content_preview_v1.py"

SPEC = importlib.util.spec_from_file_location("runtime_rx_page_content_preview_v2", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def scenario(payload: dict, scenario_id: str) -> dict:
    return next(item for item in payload["scenarios"] if item["id"] == scenario_id)


def gate_errors(tmp_path: Path, payload: dict) -> list[str]:
    path = tmp_path / "runtime-rx-page-content-preview-v2.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    errors, _summary = GATE.validate_gate(path, SCHEMA)
    return errors


def test_schema_fixture_cli_and_frozen_v1_gate_pass() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout) == {
        "covered_statuses": ["clean", "degraded", "disabled", "mismatch", "partial", "unsupported"],
        "evidence_class": "synthetic_smoke",
        "execution_scope": "local_synthetic",
        "external_claim_allowed": False,
        "fpr_claim_allowed": False,
        "frozen_v1_hash_count": 4,
        "performance_claim_allowed": False,
        "privacy_mutation_count": 12,
        "runtime_schema": "tamandua.runtime_integrity/v3",
        "scenario_count": 16,
        "server_projection_schema": "tamandua.runtime_integrity_preview/v2",
        "vendor_parity_claimed": False,
    }
    v1 = subprocess.run(
        [sys.executable, str(V1_SCRIPT)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert v1.returncode == 0, v1.stdout + v1.stderr


def test_identity_claim_boundary_default_off_and_projection_are_exact() -> None:
    payload = load_fixture()
    assert payload["runtime_schema"] == "tamandua.runtime_integrity/v3"
    assert payload["server_projection_schema"] == "tamandua.runtime_integrity_preview/v2"
    assert "does not execute or prove" in payload["claim_boundary"]
    for claim in (
        "external_claim_allowed", "fpr_claim_allowed", "performance_claim_allowed",
        "vendor_parity_claimed",
    ):
        assert payload[claim] is False
    for item in payload["scenarios"]:
        page = item["evidence"]["page_content"]
        assert item["evidence"]["schema"] == GATE.RUNTIME_SCHEMA
        assert page["capability_id"] == GATE.CAPABILITY_ID
        assert page["maturity"] == "preview"
        assert page["mode"] == "observe_only"
    disabled = scenario(payload, "default-off-disabled")["evidence"]["page_content"]
    assert disabled["enabled"] is False
    assert disabled["status"] == "disabled"


def test_lifecycle_freezes_17_4964_8192_and_8193_fail_closed() -> None:
    payload = load_fixture()
    expected = {
        "eligible-17-first-tick": (17, 8, 8, False),
        "eligible-17-rollover-pending": (17, 8, 16, False),
        "eligible-17-full-clean": (17, 1, 17, True),
        "release-4964-partial": (4964, 8, 2480, False),
        "release-4964-full-clean": (4964, 4, 4964, True),
        "capacity-8192-partial": (8192, 8, 8184, False),
        "capacity-8192-full-clean": (8192, 8, 8192, True),
    }
    for scenario_id, values in expected.items():
        page = scenario(payload, scenario_id)["evidence"]["page_content"]
        assert (
            page["eligible_pages"], page["pages_compared_this_tick"],
            page["sweep_pages_compared"], page["full_sweep_completed"],
        ) == values
    overflow = scenario(payload, "capacity-8193-degraded")["evidence"]
    assert overflow["page_content"]["eligible_pages"] == 0
    assert overflow["page_content"]["sweep_pages_compared"] == 0
    assert "rx_page_content_coverage_limit_exceeded" in overflow["limitations"]


@pytest.mark.parametrize(
    ("scenario_id", "field", "value", "needle"),
    [
        ("eligible-17-first-tick", "pages_compared_this_tick", 9, "greater than the maximum of 8"),
        ("capacity-8192-full-clean", "eligible_pages", 8193, "greater than the maximum of 8192"),
        ("eligible-17-full-clean", "full_sweep_completed", False, "full_sweep_completed must exactly reflect"),
        ("eligible-17-first-tick", "sweep_pages_compared", 18, "sweep_pages_compared must be <= eligible_pages"),
        ("eligible-17-first-tick", "memory_bytes_read_this_tick", 32768, "normal status memory bytes must equal"),
        ("eligible-17-first-tick", "elapsed_us_this_tick", 10001, "budget_state must exactly reflect"),
        ("capacity-8193-degraded", "eligible_pages", 1, "capacity overflow must fail closed"),
        ("bootstrap-budget-degraded", "sweep_pages_compared", 1, "bootstrap timeout is not a tick"),
    ],
)
def test_count_progress_capacity_and_budget_mutations_fail_closed(
    tmp_path: Path, scenario_id: str, field: str, value, needle: str
) -> None:
    payload = load_fixture()
    scenario(payload, scenario_id)["evidence"]["page_content"][field] = value
    errors = gate_errors(tmp_path, payload)
    assert errors
    assert needle in "\n".join(errors)


def test_real_double_read_accounting_and_degraded_partial_first_read() -> None:
    payload = load_fixture()
    partial = scenario(payload, "eligible-17-first-tick")["evidence"]["page_content"]
    assert partial["pages_compared_this_tick"] == 8
    assert partial["memory_bytes_read_this_tick"] == 8 * 2 * 4096
    first_only = scenario(payload, "partial-first-read-degraded")["evidence"]["page_content"]
    assert first_only["pages_compared_this_tick"] == 0
    assert first_only["memory_bytes_read_this_tick"] == 4096
    assert first_only["sweep_pages_compared"] == 8


def test_unstable_pages_are_exclusive_degraded_identity_race(tmp_path: Path) -> None:
    payload = load_fixture()
    unstable = scenario(payload, "unstable-double-read-degraded")["evidence"]
    assert unstable["limitations"] == ["rx_page_content_identity_race"]
    assert unstable["page_content"]["unstable_pages_this_tick"] == 1
    assert unstable["page_content"]["status"] == "degraded"

    payload = load_fixture()
    evidence = scenario(payload, "eligible-17-first-tick")["evidence"]
    evidence["page_content"]["unstable_pages_this_tick"] = 1
    errors = gate_errors(tmp_path, payload)
    assert any("unstable pages require degraded status with exact identity-race cause" in error for error in errors)

    payload = load_fixture()
    evidence = scenario(payload, "unstable-double-read-degraded")["evidence"]
    evidence["limitations"] = ["rx_page_content_memory_read_unavailable"]
    errors = gate_errors(tmp_path, payload)
    assert any("unstable pages require degraded status with exact identity-race cause" in error for error in errors)


def test_full_progress_is_independent_of_tick_status(tmp_path: Path) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "full-progress-tick-budget-degraded")["evidence"]
    page = evidence["page_content"]
    assert page["status"] == "degraded"
    assert page["sweep_pages_compared"] == page["eligible_pages"] == 17
    assert page["full_sweep_completed"] is True

    page["full_sweep_completed"] = False
    errors = gate_errors(tmp_path, payload)
    assert any("full_sweep_completed must exactly reflect committed sweep completion" in error for error in errors)


def test_mismatch_finding_and_full_sweep_relations_fail_closed(tmp_path: Path) -> None:
    payload = load_fixture()
    scenario(payload, "release-4964-mismatch")["evidence"]["findings"] = []
    errors = gate_errors(tmp_path, payload)
    assert any("mismatch requires the exact page drift finding" in error for error in errors)

    payload = load_fixture()
    evidence = scenario(payload, "release-4964-full-clean")["evidence"]
    evidence["findings"] = [{"kind": GATE.DRIFT_KIND, "evidence": GATE.DRIFT_EVIDENCE}]
    errors = gate_errors(tmp_path, payload)
    assert any("only mismatch may contain page drift" in error for error in errors)


def test_tick_and_bootstrap_budget_causes_are_not_interchangeable(tmp_path: Path) -> None:
    payload = load_fixture()
    tick = scenario(payload, "tick-budget-degraded")["evidence"]
    tick["limitations"] = [
        item for item in tick["limitations"] if item != "rx_page_content_budget_exceeded"
    ]
    errors = gate_errors(tmp_path, payload)
    assert any("tick budget limitation must be present iff" in error for error in errors)

    payload = load_fixture()
    bootstrap = scenario(payload, "bootstrap-budget-degraded")["evidence"]
    bootstrap["limitations"] = [
        "point-in-time userspace observation of the current process only",
        "rx_page_content_budget_exceeded",
    ]
    bootstrap["page_content"]["elapsed_us_this_tick"] = 10001
    bootstrap["page_content"]["budget_state"] = "exceeded"
    errors = gate_errors(tmp_path, payload)
    assert any("causal limitations do not match frozen scenario" in error for error in errors)


@pytest.mark.parametrize("field", GATE.PRIVACY_MUTATION_FIELDS)
def test_every_declared_privacy_field_is_rejected(tmp_path: Path, field: str) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "release-4964-full-clean")["evidence"]
    evidence["page_content"][field] = "forbidden"
    errors = gate_errors(tmp_path, payload)
    assert any(f".{field}: forbidden privacy field" in error for error in errors)


@pytest.mark.parametrize(
    "leak",
    [
        "module /tmp/tamandua-agent",
        "mapping at 0x7fffdeadbeef",
        "digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ],
)
def test_finding_text_cannot_leak_path_address_or_hash(tmp_path: Path, leak: str) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "release-4964-full-clean")["evidence"]
    evidence["findings"] = [{"kind": "debugger_or_tracer_attached", "evidence": leak}]
    errors = gate_errors(tmp_path, payload)
    assert any("forbidden path, address, or hash-like value" in error for error in errors)


@pytest.mark.parametrize(
    "claim",
    ["external_claim_allowed", "fpr_claim_allowed", "performance_claim_allowed", "vendor_parity_claimed"],
)
def test_claim_escalation_is_rejected(tmp_path: Path, claim: str) -> None:
    payload = load_fixture()
    payload[claim] = True
    assert f"fixture: {claim} must remain false" in gate_errors(tmp_path, payload)


@pytest.mark.parametrize("mutation", ["swap", "rename", "extra", "duplicate", "counter-drift"])
def test_scenario_order_identity_and_lifecycle_map_are_frozen(tmp_path: Path, mutation: str) -> None:
    payload = load_fixture()
    if mutation == "swap":
        payload["scenarios"][0], payload["scenarios"][1] = payload["scenarios"][1], payload["scenarios"][0]
    elif mutation == "rename":
        payload["scenarios"][0]["id"] = "renamed-disabled"
    elif mutation == "extra":
        extra = copy.deepcopy(payload["scenarios"][-1])
        extra["id"] = "unexpected-extra"
        payload["scenarios"].append(extra)
    elif mutation == "duplicate":
        payload["scenarios"].append(copy.deepcopy(payload["scenarios"][0]))
    else:
        scenario(payload, "eligible-17-rollover-pending")["evidence"]["page_content"]["sweep_pages_compared"] = 15
    joined = "\n".join(gate_errors(tmp_path, payload))
    if mutation == "counter-drift":
        assert "lifecycle counters do not match frozen scenario" in joined
    else:
        assert "scenario ids and order must exactly match" in joined


def test_unknown_namespaced_limitation_and_projection_identity_drift_are_rejected(tmp_path: Path) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "release-4964-full-clean")["evidence"]
    evidence["limitations"].append("rx_page_content_typo")
    evidence["limitations"].sort()
    assert any(
        "must contain only closed categorical IDs" in error
        for error in gate_errors(tmp_path, payload)
    )

    payload = load_fixture()
    payload["server_projection_schema"] = "tamandua.runtime_integrity_preview/v1"
    assert "fixture: server_projection_schema must remain exact" in gate_errors(tmp_path, payload)


@pytest.mark.parametrize(
    "adversarial",
    [
        "/tmp/tamandua-agent",
        "pid-1234",
        "windows_debugger_api_unavailable",
        "relative/path",
        "point-in-time userspace observation of the current process only",
        "rx_page_content_typo",
    ],
)
def test_limitations_are_closed_categorical_ids_only(
    tmp_path: Path, adversarial: str
) -> None:
    payload = load_fixture()
    scenario(payload, "release-4964-full-clean")["evidence"]["limitations"] = [adversarial]
    errors = gate_errors(tmp_path, payload)
    assert errors
    assert any(
        "is not one of" in error
        or "must contain only closed categorical IDs" in error
        or "exclusive causal limitations" in error
        for error in errors
    )


def test_elf_unsupported_is_reserved_exclusively_for_unsupported(tmp_path: Path) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "capacity-8193-degraded")["evidence"]
    evidence["limitations"] = ["rx_page_content_elf_unsupported"]
    errors = gate_errors(tmp_path, payload)
    assert any("degraded requires exactly one non-ELF categorical cause" in error for error in errors)


def test_finding_types_fail_closed_without_gate_exception(tmp_path: Path) -> None:
    payload = load_fixture()
    scenario(payload, "release-4964-full-clean")["evidence"]["findings"] = [7, "debugger"]
    errors = gate_errors(tmp_path, payload)
    assert errors
    assert sum("must be an exact finding object" in error for error in errors) == 2


def test_cli_diagnostic_is_bounded_and_has_no_traceback(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"scenarios": [', encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(malformed)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    diagnostic = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert "Traceback" not in diagnostic
    assert len(diagnostic) <= 320

    noisy = load_fixture()
    noisy["scenarios"] = [
        {"id": f"invalid-{index}", "evidence": {"findings": [index]}}
        for index in range(100)
    ]
    noisy_path = tmp_path / "noisy.json"
    noisy_path.write_text(json.dumps(noisy), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(noisy_path)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    diagnostic = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert "Traceback" not in diagnostic
    assert len(diagnostic) <= 8192
    assert "additional validation errors omitted" in diagnostic


def test_v1_frozen_hashes_are_pinned_and_gate_detects_expected_hash_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = {
        "runtime_rx_page_content_preview_v1.schema.json": "9d78bc43855cf7c853a45dfdaab396e7aef508377f5b18ba2886cbf9f234dc88",
        "runtime_rx_page_content_preview_v1.json": "d49b1eac951f71e9d183e25d3b0cb7795992794d5d8f3a87964f1286b0195cb7",
        "runtime_rx_page_content_preview_v1.py": "464f9f5c73f7b848b5f5d21235fffb28b77e891aab04a1e579e83d48bcf6d0bb",
        "test_runtime_rx_page_content_preview_v1.py": "ed0ecb9cbe18282b468bdc2136930348a7040ef4e00c70b087be6bac0b6e52b0",
    }
    assert {path.name: digest for path, digest in GATE.FROZEN_V1_HASHES.items()} == expected
    for path, digest in GATE.FROZEN_V1_HASHES.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest

    path = next(iter(GATE.FROZEN_V1_HASHES))
    monkeypatch.setattr(GATE, "FROZEN_V1_HASHES", {path: "0" * 64})
    errors = gate_errors(tmp_path, load_fixture())
    assert any("frozen-v1: hash drift" in error for error in errors)


def test_closed_page_shape_rejects_legacy_v1_counter_names(tmp_path: Path) -> None:
    payload = load_fixture()
    page = scenario(payload, "eligible-17-first-tick")["evidence"]["page_content"]
    page["compared_pages"] = page["pages_compared_this_tick"]
    page["bytes_read"] = page["memory_bytes_read_this_tick"]
    errors = gate_errors(tmp_path, payload)
    assert any("Additional properties are not allowed" in error for error in errors)
