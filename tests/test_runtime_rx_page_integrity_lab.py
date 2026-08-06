from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "runtime_rx_page_integrity_lab.py"
FIXTURE = ROOT / "tools" / "detection_validation" / "fixtures" / "runtime_rx_page_integrity_lab_v1.json"
SPEC = importlib.util.spec_from_file_location("runtime_rx_page_integrity_lab", SCRIPT)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


def fixture_document():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def case(report, scenario):
    return next(item for item in report["cases"] if item["scenario"] == scenario)


def test_fixture_reports_only_bounded_synthetic_lab_evidence():
    report = LAB.validate_fixture(fixture_document())

    assert report["status"] == "pass"
    assert report["evidence_class"] == "synthetic_lab"
    assert report["external_claim_allowed"] is False
    assert report["production_ready"] is False
    assert report["vendor_parity"] is False
    assert report["cost_budget"]["fixture_pages"] == 2
    assert report["cost_budget"]["fixture_bytes"] == 64


def test_rx_restored_unmasked_drift_is_a_finding():
    result = case(LAB.validate_fixture(fixture_document()), "rx_restored_malicious_drift")

    assert result["state"] == "supported"
    assert result["outcome"] == "finding"
    assert result["drift_offsets"] == [10]
    assert result["baseline_sha256"] != result["current_sha256"]


def test_benign_relocation_is_masked_without_hiding_other_drift():
    document = fixture_document()
    report = LAB.validate_fixture(document)
    result = case(report, "benign_relocation")
    assert result["outcome"] == "clean"
    assert result["masked_byte_count"] == 1

    benign = next(item for item in document["cases"] if item["scenario"] == "benign_relocation")
    current = bytearray.fromhex(benign["current_hex"])
    current[11] = 0xFE
    benign["current_hex"] = current.hex()
    with pytest.raises(LAB.ContractError, match="exactly match changed bytes"):
        LAB.validate_fixture(document)

    document = fixture_document()
    benign = next(item for item in document["cases"] if item["scenario"] == "benign_relocation")
    benign["relocation_allowlist"].append({"offset": 12, "length": 1, "reason": "relocation"})
    with pytest.raises(LAB.ContractError, match="exactly match changed bytes"):
        LAB.validate_fixture(document)


@pytest.mark.parametrize(
    ("scenario", "state", "limitation"),
    [
        ("jit_no_stable_baseline", "unsupported", "jit_region_has_no_stable_baseline"),
        ("execute_only_unreadable", "degraded", "executable_page_unreadable"),
    ],
)
def test_unavailable_pages_never_collapse_to_clean(scenario, state, limitation):
    result = case(LAB.validate_fixture(fixture_document()), scenario)

    assert result["state"] == state
    assert result["outcome"] == state
    assert result["limitations"] == [limitation]


@pytest.mark.parametrize("claim", ["production_ready", "vendor_parity"])
def test_claim_elevation_is_rejected(claim):
    document = fixture_document()
    document["claims"][claim] = True

    with pytest.raises(LAB.ContractError, match="claims cannot be elevated"):
        LAB.validate_fixture(document)


def test_unknown_fields_and_overbroad_relocation_masks_are_rejected():
    document = fixture_document()
    document["unexpected"] = "claim-shaped-drift"
    with pytest.raises(LAB.ContractError, match="exactly"):
        LAB.validate_fixture(document)

    document = fixture_document()
    benign = next(item for item in document["cases"] if item["scenario"] == "benign_relocation")
    benign["relocation_allowlist"] = [{"offset": 0, "length": 9, "reason": "relocation"}]
    with pytest.raises(LAB.ContractError, match="exceed 25%"):
        LAB.validate_fixture(document)

    document = fixture_document()
    document["external_claim_allowed"] = True
    with pytest.raises(LAB.ContractError, match="external_claim_allowed"):
        LAB.validate_fixture(document)

    document = fixture_document()
    malicious = next(
        item for item in document["cases"] if item["scenario"] == "rx_restored_malicious_drift"
    )
    malicious["state"] = "unsupported"
    malicious["baseline_hex"] = None
    malicious["current_hex"] = None
    malicious["limitations"] = ["claim_downgrade_attempt"]
    malicious["expected"] = {"outcome": "unsupported", "drift_offsets": []}
    with pytest.raises(LAB.ContractError, match="state does not match"):
        LAB.validate_fixture(document)


def test_case_ids_cannot_be_relabelled_to_hide_malicious_drift():
    document = fixture_document()
    malicious = next(item for item in document["cases"] if item["id"] == "rx-restored-malicious-drift")
    benign = next(item for item in document["cases"] if item["id"] == "benign-relocation-masked")
    malicious["scenario"], benign["scenario"] = benign["scenario"], malicious["scenario"]

    with pytest.raises(LAB.ContractError, match="canonical scenario"):
        LAB.validate_fixture(document)


def test_cost_metrics_cannot_be_underreported():
    document = fixture_document()
    document["cost_budget"]["fixture_bytes"] = 1

    with pytest.raises(LAB.ContractError, match="cost metrics"):
        LAB.validate_fixture(document)

    document = fixture_document()
    document["cost_budget"]["max_pages"] = 5
    document["cost_budget"]["max_bytes"] = 160
    with pytest.raises(LAB.ContractError, match="bounded lab matrix"):
        LAB.validate_fixture(document)


def test_cli_validates_the_frozen_fixture_and_preserves_claim_boundaries():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(FIXTURE)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "pass"
    assert report["external_claim_allowed"] is False
    assert report["production_ready"] is False
    assert report["vendor_parity"] is False
