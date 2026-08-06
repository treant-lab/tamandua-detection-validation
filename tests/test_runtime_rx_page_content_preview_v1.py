from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    ROOT
    / "tools"
    / "detection_validation"
    / "scripts"
    / "runtime_rx_page_content_preview_v1.py"
)
FIXTURE = (
    ROOT
    / "tools"
    / "detection_validation"
    / "fixtures"
    / "runtime_rx_page_content_preview_v1.json"
)
SCHEMA = ROOT / "schemas" / "runtime_rx_page_content_preview_v1.schema.json"

SPEC = importlib.util.spec_from_file_location("runtime_rx_page_content_preview_v1", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def write_fixture(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "runtime-rx-page-content-preview.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def scenario(payload: dict, scenario_id: str) -> dict:
    return next(item for item in payload["scenarios"] if item["id"] == scenario_id)


def gate_errors(tmp_path: Path, payload: dict) -> list[str]:
    errors, _summary = GATE.validate_gate(write_fixture(tmp_path, payload), SCHEMA)
    return errors


def test_schema_fixture_and_cli_pass_as_synthetic_smoke() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(FIXTURE), "--schema", str(SCHEMA)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary == {
        "covered_statuses": [
            "clean",
            "degraded",
            "disabled",
            "mismatch",
            "partial",
            "unsupported",
        ],
        "evidence_class": "synthetic_smoke",
        "execution_scope": "local_synthetic",
        "external_claim_allowed": False,
        "fpr_claim_allowed": False,
        "performance_claim_allowed": False,
        "privacy_mutation_count": 12,
        "scenario_count": 10,
        "vendor_parity_claimed": False,
    }


def test_fixture_freezes_default_off_preview_observe_only_and_local_baseline_authority() -> None:
    payload = load_fixture()
    assert payload["external_claim_allowed"] is False
    assert payload["fpr_claim_allowed"] is False
    assert payload["performance_claim_allowed"] is False
    assert payload["vendor_parity_claimed"] is False
    assert "local root-protected config plus startup-held fd" in payload["claim_boundary"]
    assert "did not execute or prove either protection or startup-FD behavior" in payload["claim_boundary"]
    for item in payload["scenarios"]:
        page = item["evidence"]["page_content"]
        assert page["capability_id"] == GATE.CAPABILITY_ID
        assert page["maturity"] == "preview"
        assert page["mode"] == "observe_only"
        assert page["baseline_source"] != "signed_config_sha256_startup_fd"
    disabled = scenario(payload, "default-off-disabled")["evidence"]["page_content"]
    assert disabled["enabled"] is False
    assert disabled["status"] == "disabled"


@pytest.mark.parametrize(
    ("scenario_id", "mutate", "needle"),
    [
        (
            "full-sweep-clean",
            lambda evidence: evidence["page_content"].update(full_sweep_completed=False),
            "is not valid under any of the given schemas",
        ),
        (
            "controlled-page-mismatch",
            lambda evidence: evidence.update(findings=[]),
            "does not contain items matching",
        ),
        (
            "bounded-round-robin-partial",
            lambda evidence: evidence["page_content"].update(full_sweep_completed=True),
            "is not valid under any of the given schemas",
        ),
        (
            "backing-deleted-degraded",
            lambda evidence: evidence.update(
                limitations=[
                    item
                    for item in evidence["limitations"]
                    if item != "rx_page_content_backing_deleted"
                ]
            ),
            "does not contain items matching",
        ),
        (
            "elf-unsupported",
            lambda evidence: evidence["page_content"].update(eligible_pages=1),
            "is not valid under any of the given schemas",
        ),
        (
            "bounded-round-robin-partial",
            lambda evidence: evidence["page_content"].update(unstable_pages=17),
            "unstable_pages",
        ),
        (
            "bounded-round-robin-partial",
            lambda evidence: evidence["page_content"].update(compared_pages=17),
            "greater than the maximum of 16",
        ),
        (
            "full-sweep-clean",
            lambda evidence: evidence["page_content"].update(bytes_read=65537),
            "greater than the maximum of 65536",
        ),
        (
            "full-sweep-clean",
            lambda evidence: evidence["page_content"].update(elapsed_us=10001),
            "is not valid under any of the given schemas",
        ),
        (
            "budget-exceeded-degraded",
            lambda evidence: evidence.update(
                limitations=[
                    item
                    for item in evidence["limitations"]
                    if item != "rx_page_content_budget_exceeded"
                ]
            ),
            "does not contain items matching",
        ),
    ],
)
def test_status_count_and_budget_invariants_fail_closed(
    tmp_path: Path, scenario_id: str, mutate, needle: str
) -> None:
    payload = load_fixture()
    evidence = scenario(payload, scenario_id)["evidence"]
    mutate(evidence)
    errors = gate_errors(tmp_path, payload)
    assert errors
    assert needle in "\n".join(errors)


@pytest.mark.parametrize("field", GATE.PRIVACY_MUTATION_FIELDS)
def test_every_declared_privacy_field_mutation_is_rejected(tmp_path: Path, field: str) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "full-sweep-clean")["evidence"]
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
def test_legacy_finding_text_cannot_leak_path_address_or_hash(
    tmp_path: Path, leak: str
) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "full-sweep-clean")["evidence"]
    evidence["findings"] = [
        {"kind": "debugger_or_tracer_attached", "evidence": leak}
    ]
    errors = gate_errors(tmp_path, payload)
    assert any("forbidden path, address, or hash-like value" in error for error in errors)


def test_clean_page_status_can_coexist_with_bounded_legacy_finding() -> None:
    payload = load_fixture()
    evidence = scenario(payload, "full-sweep-clean")["evidence"]
    evidence["findings"] = [
        {
            "kind": "debugger_or_tracer_attached",
            "evidence": "current process reported a debugger or tracer attached",
        }
    ]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(evidence)
    assert GATE.semantic_errors(evidence, "evidence") == []


@pytest.mark.parametrize(
    ("kind", "literal"),
    list(GATE.LEGACY_FINDING_EVIDENCE.items()),
)
def test_each_legacy_finding_kind_accepts_only_its_generic_literal(
    kind: str, literal: str
) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "full-sweep-clean")["evidence"]
    evidence["findings"] = [{"kind": kind, "evidence": literal}]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(evidence)
    evidence["findings"][0]["evidence"] = "current process reported arbitrary detail"
    assert list(Draft202012Validator(schema).iter_errors(evidence))
    assert any(
        "legacy evidence literal is invalid" in error
        for error in GATE.semantic_errors(evidence, "evidence")
    )


@pytest.mark.parametrize("mutation", ["swap", "rename", "extra", "duplicate", "evidence_swap"])
def test_scenario_ids_order_and_id_to_semantics_map_are_frozen(
    tmp_path: Path, mutation: str
) -> None:
    payload = load_fixture()
    if mutation == "swap":
        payload["scenarios"][0], payload["scenarios"][1] = (
            payload["scenarios"][1],
            payload["scenarios"][0],
        )
    elif mutation == "rename":
        payload["scenarios"][0]["id"] = "renamed-disabled"
    elif mutation == "extra":
        extra = copy.deepcopy(payload["scenarios"][-1])
        extra["id"] = "unexpected-extra"
        payload["scenarios"].append(extra)
    elif mutation == "duplicate":
        payload["scenarios"].append(copy.deepcopy(payload["scenarios"][0]))
    else:
        deleted = scenario(payload, "backing-deleted-degraded")
        replaced = scenario(payload, "backing-replaced-degraded")
        deleted["evidence"], replaced["evidence"] = (
            replaced["evidence"],
            deleted["evidence"],
        )
    errors = gate_errors(tmp_path, payload)
    assert errors
    joined = "\n".join(errors)
    if mutation == "evidence_swap":
        assert "causal limitations do not match frozen scenario" in joined
    else:
        assert "scenario ids and order must exactly match" in joined


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fixture_id", "renamed-fixture"),
        ("fixture_id", "x" * 65),
        ("fixture_id", 7),
        ("description", "renamed description"),
        ("description", "x" * 161),
        ("description", 7),
    ],
)
def test_fixture_identity_and_description_are_exact_typed_and_bounded(
    tmp_path: Path, field: str, value
) -> None:
    payload = load_fixture()
    payload[field] = value
    errors = gate_errors(tmp_path, payload)
    assert errors
    assert any(field in error for error in errors)


def test_exact_page_byte_and_budget_equivalences_are_enforced(tmp_path: Path) -> None:
    payload = load_fixture()
    page = scenario(payload, "bounded-round-robin-partial")["evidence"]["page_content"]
    page["bytes_read"] -= 1
    errors = gate_errors(tmp_path, payload)
    assert any("bytes_read must equal compared_pages * 4096" in error for error in errors)

    payload = load_fixture()
    page = scenario(payload, "bounded-round-robin-partial")["evidence"]["page_content"]
    page["compared_pages"] = 0
    page["bytes_read"] = 0
    errors = gate_errors(tmp_path, payload)
    assert any("partial requires compared_pages >= 1" in error for error in errors)

    payload = load_fixture()
    page = scenario(payload, "budget-exceeded-degraded")["evidence"]["page_content"]
    page["elapsed_us"] = 10000
    errors = gate_errors(tmp_path, payload)
    assert any("budget_state must exactly reflect" in error for error in errors)

    payload = load_fixture()
    evidence = scenario(payload, "full-sweep-clean")["evidence"]
    evidence["limitations"].append("rx_page_content_budget_exceeded")
    evidence["limitations"].sort()
    errors = gate_errors(tmp_path, payload)
    assert any("budget limitation must be present iff" in error for error in errors)


def test_duplicate_drift_finding_is_rejected(tmp_path: Path) -> None:
    payload = load_fixture()
    evidence = scenario(payload, "controlled-page-mismatch")["evidence"]
    evidence["findings"].append(copy.deepcopy(evidence["findings"][0]))
    errors = gate_errors(tmp_path, payload)
    assert errors
    assert "non-unique elements" in "\n".join(errors)


@pytest.mark.parametrize(
    "claim",
    [
        "external_claim_allowed",
        "fpr_claim_allowed",
        "performance_claim_allowed",
        "vendor_parity_claimed",
    ],
)
def test_claim_escalation_is_rejected(tmp_path: Path, claim: str) -> None:
    payload = load_fixture()
    payload[claim] = True
    errors = gate_errors(tmp_path, payload)
    assert f"fixture: {claim} must remain false" in errors


def test_limitations_must_be_sorted_unique_and_known_when_namespaced(
    tmp_path: Path,
) -> None:
    payload = load_fixture()
    limitations = scenario(payload, "full-sweep-clean")["evidence"]["limitations"]
    limitations.reverse()
    errors = gate_errors(tmp_path, payload)
    assert any("must be lexically sorted" in error for error in errors)

    payload = load_fixture()
    limitations = scenario(payload, "full-sweep-clean")["evidence"]["limitations"]
    limitations.append(limitations[-1])
    errors = gate_errors(tmp_path, payload)
    assert any("must not contain duplicates" in error for error in errors)

    payload = load_fixture()
    limitations = scenario(payload, "full-sweep-clean")["evidence"]["limitations"]
    limitations.append("rx_page_content_typo")
    limitations.sort()
    errors = gate_errors(tmp_path, payload)
    assert any("unknown page-content IDs" in error for error in errors)


def test_signed_or_package_baseline_authority_substitution_is_rejected(
    tmp_path: Path,
) -> None:
    payload = load_fixture()
    page = scenario(payload, "full-sweep-clean")["evidence"]["page_content"]
    page["baseline_source"] = "signed_config_sha256_startup_fd"
    errors = gate_errors(tmp_path, payload)
    assert errors
    assert "is not one of" in "\n".join(errors)


def test_missing_required_scenario_and_privacy_plan_drift_are_rejected(
    tmp_path: Path,
) -> None:
    payload = load_fixture()
    payload["scenarios"] = [
        item for item in payload["scenarios"] if item["id"] != "controlled-page-mismatch"
    ]
    errors = gate_errors(tmp_path, payload)
    assert any("ids and order must exactly match" in error for error in errors)

    payload = load_fixture()
    payload["privacy_mutation_fields"].remove("inode")
    errors = gate_errors(tmp_path, payload)
    assert "fixture: privacy mutation field plan must remain exact" in errors
