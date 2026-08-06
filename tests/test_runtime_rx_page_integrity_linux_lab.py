from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    ROOT
    / "tools"
    / "detection_validation"
    / "scripts"
    / "runtime_rx_page_integrity_linux_lab.py"
)
SPEC = importlib.util.spec_from_file_location("runtime_rx_page_integrity_linux_lab", SCRIPT)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


def raw_supported(scenario="clean_no_relocation", drift=False):
    baseline = bytes(range(32))
    current = bytearray(baseline)
    offsets = []
    if drift:
        current[LAB.DRIFT_OFFSET % len(current)] ^= 0xFF
        offsets = [LAB.DRIFT_OFFSET % len(current)]
    return {
        "schema": "tamandua.runtime-rx-page-integrity-linux-raw/v1",
        "scenario": scenario,
        "state": "supported",
        "page_size_bytes": 32,
        "initial_protection": "rw",
        "final_protection": "rx",
        "baseline_hex": baseline.hex(),
        "current_hex": current.hex(),
        "drift_offsets": offsets,
        "limitations": [],
        "observed_permissions": "r-xp",
        "mapped_pages": 1,
        "compared_bytes": 32,
        "comparison_duration_ns": 10,
        "cleanup": "unmapped",
    }


def test_raw_clean_case_is_projected_without_page_bytes():
    projected = LAB.validate_raw_case(raw_supported(), "clean_no_relocation", 32)
    assert projected["outcome"] == "clean"
    assert "baseline_hex" not in projected
    assert "current_hex" not in projected
    assert projected["baseline_sha256"] == projected["current_sha256"]


def test_raw_malformed_and_writable_executable_cases_are_rejected():
    malformed = raw_supported()
    malformed["extra"] = True
    with pytest.raises(LAB.LabError, match="exactly"):
        LAB.validate_raw_case(malformed, "clean_no_relocation", 32)

    writable_executable = raw_supported()
    writable_executable["final_protection"] = "rwx"
    writable_executable["observed_permissions"] = "rwxp"
    with pytest.raises(LAB.LabError, match=r"finish RX|W\^X"):
        LAB.validate_raw_case(writable_executable, "clean_no_relocation", 32)


def valid_report():
    cases = [
        {
            "scenario": scenario,
            "state": "supported" if index < 2 else ("unsupported" if index == 2 else "degraded"),
            "outcome": "clean" if index == 0 else ("finding" if index == 1 else ("unsupported" if index == 2 else "degraded")),
            "page_size_bytes": 4096,
            "initial_protection": "rw",
            "final_protection": "rx" if index < 3 else "x",
            "observed_permissions": "r-xp" if index < 3 else "--xp",
            "baseline_sha256": "a" * 64 if index < 2 else None,
            "current_sha256": ("a" * 64 if index == 0 else "b" * 64) if index < 2 else None,
            "drift_offsets": [LAB.DRIFT_OFFSET] if index == 1 else [],
            "limitations": [] if index < 2 else (["jit_region_has_no_stable_baseline"] if index == 2 else ["execute_only_policy_refused_dereference"]),
            "compared_bytes": 4096 if index < 2 else 0,
            "comparison_duration_ns": 10 if index < 2 else None,
            "cleanup": "unmapped",
        }
        for index, scenario in enumerate(LAB.SCENARIOS)
    ]
    return {
        "schema": "tamandua.runtime-rx-page-integrity-linux-lab/v1",
        "evidence_class": "local_wsl_lab",
        "external_claim_allowed": False,
        "production_ready": False,
        "vendor_parity": False,
        "provenance": {
            "source_sha256": "c" * 64,
            "binary_sha256": "d" * 64,
            "kernel": "Linux test",
            "architecture": "x86_64",
            "rustc_version": "rustc 1.88.0",
            "page_size_bytes": 4096,
        },
        "safety": {
            "self_owned_anonymous_mapping_only": True,
            "writable_executable_used": False,
            "mapped_bytes_executed": False,
            "ptrace_used": False,
            "raw_page_bytes_retained": False,
        },
        "cost": {
            "mapped_pages": 4,
            "compared_pages": 2,
            "compared_bytes": 8192,
            "max_mapped_pages": 4,
            "max_compared_bytes": 8192,
            "max_comparison_duration_ns": LAB.MAX_COMPARISON_DURATION_NS,
        },
        "cases": cases,
        "cleanup_confirmed": True,
        "repeatability": {"runs": 2, "normalized_equal": True},
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("external_claim_allowed", True),
        ("production_ready", True),
        ("vendor_parity", True),
        ("evidence_class", "production"),
    ],
)
def test_claim_elevation_is_rejected(field, value):
    report = valid_report()
    report[field] = value
    with pytest.raises(LAB.LabError, match="claim boundary"):
        LAB.validate_report(report)


def test_cleanup_and_safety_tampering_are_rejected():
    report = valid_report()
    report["cleanup_confirmed"] = False
    with pytest.raises(LAB.LabError, match="cleanup"):
        LAB.validate_report(report)

    report = valid_report()
    report["safety"]["writable_executable_used"] = True
    with pytest.raises(LAB.LabError, match="safety"):
        LAB.validate_report(report)


def test_report_semantics_hashes_and_cost_tampering_are_rejected():
    report = valid_report()
    report["cases"][0]["scenario"] = "rx_restored_drift"
    with pytest.raises(LAB.LabError, match="semantics"):
        LAB.validate_report(report)

    report = valid_report()
    report["cases"][0]["baseline_sha256"] = "not-a-digest"
    with pytest.raises(LAB.LabError, match="evidence"):
        LAB.validate_report(report)

    report = valid_report()
    report["cost"]["max_comparison_duration_ns"] += 1
    with pytest.raises(LAB.LabError, match="comparison budget"):
        LAB.validate_report(report)

    report = valid_report()
    report["cases"][3]["current_sha256"] = "e" * 64
    with pytest.raises(LAB.LabError, match="claims comparison"):
        LAB.validate_report(report)


def test_temporary_namespace_rejects_paths_with_extra_components():
    assert LAB._safe_temp_path("/tmp/tamandua-rx-lab.Abc123") == (
        "/tmp/tamandua-rx-lab.Abc123"
    )
    with pytest.raises(LAB.LabError, match="escaped"):
        LAB._safe_temp_path("/tmp/tamandua-rx-lab.Abc123/child")


def test_raw_page_fields_cannot_survive_projection():
    report = valid_report()
    report["cases"][0]["baseline_hex"] = "00"
    with pytest.raises(LAB.LabError, match="exactly|raw page bytes"):
        LAB.validate_report(report)


def test_normalization_ignores_only_timing():
    first = valid_report()
    second = copy.deepcopy(first)
    second["cases"][0]["comparison_duration_ns"] = 99
    assert LAB.normalized_report(first) == LAB.normalized_report(second)
    second["cases"][0]["current_sha256"] = "e" * 64
    assert LAB.normalized_report(first) != LAB.normalized_report(second)


def test_wsl_integration_runs_only_after_explicit_capability_passes():
    capability = LAB.preflight()
    if capability.get("capable") is not True:
        pytest.skip(f"explicit WSL lab capability unavailable: {capability.get('reasons')}")

    report = LAB.run_lab(repeat=2)
    assert report["evidence_class"] == "local_wsl_lab"
    assert report["external_claim_allowed"] is False
    assert report["production_ready"] is False
    assert report["vendor_parity"] is False
    assert report["repeatability"] == {"runs": 2, "normalized_equal": True}
    assert [item["outcome"] for item in report["cases"]] == [
        "clean",
        "finding",
        "unsupported",
        "degraded",
    ]
    assert all("baseline_hex" not in item and "current_hex" not in item for item in report["cases"])
