from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    ROOT
    / "tools"
    / "detection_validation"
    / "scripts"
    / "runtime_rx_filebacked_elf_linux_lab.py"
)
SPEC = importlib.util.spec_from_file_location(
    "runtime_rx_filebacked_elf_linux_lab", SCRIPT
)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


def raw_supported(scenario="clean_file_backed_rx", drift=False):
    baseline = bytes(index % 251 for index in range(4096))
    current = bytearray(baseline)
    offsets = []
    outcome = "clean"
    if drift:
        current[LAB.load_contract()["drift_offset"]] ^= 0xFF
        offsets = [LAB.load_contract()["drift_offset"]]
        outcome = "finding"
    return {
        "schema": "tamandua.runtime-rx-filebacked-elf-linux-raw/v1",
        "scenario": scenario,
        "state": "supported",
        "outcome": outcome,
        "backing_state": "original",
        "page_size_bytes": 4096,
        "initial_protection": "rx",
        "final_protection": "rx",
        "observed_permissions": "r-xp",
        "mapping_file_offset": 4096,
        "probe_file_offset": 8192,
        "load_bias": 0x555550000000,
        "mapping_inode": 42,
        "backing_inode": 42,
        "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
        "current_sha256": hashlib.sha256(current).hexdigest(),
        "drift_offsets": offsets,
        "limitations": [],
        "compared_bytes": 4096,
        "comparison_pipeline_duration_ns": 100,
        "writable_executable_used": False,
        "mapped_bytes_executed": False,
        "absolute_paths_emitted": False,
        "cleanup": "process_exit_discards_private_mapping",
    }


def expected(scenario):
    return next(
        item for item in LAB.load_contract()["cases"] if item["scenario"] == scenario
    )


def raw_unavailable(scenario):
    wanted = expected(scenario)
    raw = raw_supported()
    raw.update(
        {
            "scenario": scenario,
            "state": wanted["state"],
            "outcome": wanted["outcome"],
            "backing_state": wanted["backing_state"],
            "final_protection": "x" if scenario == "execute_only_file_backed" else "rx",
            "observed_permissions": (
                "--xp" if scenario == "execute_only_file_backed" else "r-xp"
            ),
            "mapping_inode": 0 if scenario == "anonymous_jit_no_baseline" else 42,
            "backing_inode": (
                None
                if scenario in {"deleted_backing", "anonymous_jit_no_baseline"}
                else 84
                if scenario == "replaced_backing"
                else 42
            ),
            "baseline_sha256": None,
            "current_sha256": None,
            "drift_offsets": [],
            "limitations": wanted["limitations"],
            "compared_bytes": 0,
            "comparison_pipeline_duration_ns": None,
            "cleanup": wanted["cleanup"],
        }
    )
    return raw


def test_contract_freezes_claims_matrix_and_cost():
    contract = LAB.load_contract()

    assert contract["external_claim_allowed"] is False
    assert contract["production_ready"] is False
    assert contract["vendor_parity"] is False
    assert contract["relocation_policy"] == "reject_probe_overlap"
    assert [item["scenario"] for item in contract["cases"]] == list(LAB.SCENARIOS)
    assert contract["cost_budget"] == {
        "max_cases": 6,
        "max_compared_pages": 2,
        "max_compared_bytes": 8192,
        "max_case_duration_ms": 1000,
        "max_comparison_pipeline_duration_ns": 100000000,
    }


def test_supported_raw_projection_redacts_page_address_and_inode_material():
    projected = LAB.validate_raw_case(
        raw_supported(), expected("clean_file_backed_rx"), 4096, 137
    )

    assert projected["outcome"] == "clean"
    assert projected["baseline_sha256"] == projected["current_sha256"]
    assert projected["load_bias"] == "verified_redacted"
    assert projected["mapping_identity"] == "verified_redacted"
    assert "baseline_hex" not in projected
    assert "current_hex" not in projected
    assert "inode" not in " ".join(projected)


def test_controlled_rw_to_rx_drift_is_exact_and_never_wx():
    raw = raw_supported("file_backed_rw_to_rx_drift", drift=True)
    projected = LAB.validate_raw_case(
        raw, expected("file_backed_rw_to_rx_drift"), 4096, 137
    )

    assert projected["outcome"] == "finding"
    assert projected["drift_offsets"] == [137]
    assert projected["baseline_sha256"] != projected["current_sha256"]

    raw["writable_executable_used"] = True
    with pytest.raises(LAB.LabError, match="safety"):
        LAB.validate_raw_case(raw, expected("file_backed_rw_to_rx_drift"), 4096, 137)


def test_drift_outside_fixed_offset_and_writable_executable_permissions_fail():
    raw = raw_supported("file_backed_rw_to_rx_drift", drift=True)
    raw["drift_offsets"].append(138)
    with pytest.raises(LAB.LabError, match="fixed scenario"):
        LAB.validate_raw_case(raw, expected("file_backed_rw_to_rx_drift"), 4096, 137)

    raw = raw_supported()
    raw["observed_permissions"] = "rwxp"
    with pytest.raises(LAB.LabError, match=r"W\^X"):
        LAB.validate_raw_case(raw, expected("clean_file_backed_rx"), 4096, 137)


def test_contract_rejects_claim_elevation_and_case_relabel(monkeypatch, tmp_path):
    contract = LAB.load_contract()
    contract["vendor_parity"] = True
    altered = tmp_path / "contract.json"
    altered.write_text(__import__("json").dumps(contract), encoding="utf-8")
    monkeypatch.setattr(LAB, "CONTRACT", altered)
    with pytest.raises(LAB.LabError, match="claim boundary"):
        LAB.load_contract()

    contract["vendor_parity"] = False
    contract["cases"][0]["scenario"] = "file_backed_rw_to_rx_drift"
    altered.write_text(__import__("json").dumps(contract), encoding="utf-8")
    with pytest.raises(LAB.LabError, match="changed semantics"):
        LAB.load_contract()


def test_raw_scenario_and_cleanup_semantics_are_pinned():
    raw = raw_supported()
    raw["scenario"] = "file_backed_rw_to_rx_drift"
    with pytest.raises(LAB.LabError, match="changed scenario"):
        LAB.validate_raw_case(raw, expected("clean_file_backed_rx"), 4096, 137)

    raw = raw_supported()
    raw["cleanup"] = "claimed_without_cleanup"
    with pytest.raises(LAB.LabError, match="cleanup semantics"):
        LAB.validate_raw_case(raw, expected("clean_file_backed_rx"), 4096, 137)


@pytest.mark.parametrize(
    ("scenario", "field", "value", "message"),
    [
        ("deleted_backing", "final_protection", "banana", "final protection"),
        ("deleted_backing", "backing_inode", 42, "backing identity"),
        ("replaced_backing", "backing_inode", None, "backing identity"),
        ("replaced_backing", "backing_inode", 42, "not changed"),
        ("anonymous_jit_no_baseline", "mapping_inode", 1, "mapping identity"),
        ("anonymous_jit_no_baseline", "backing_inode", 42, "backing identity"),
        ("execute_only_file_backed", "final_protection", "rx", "final protection"),
        ("execute_only_file_backed", "backing_inode", 84, "backing identity"),
        ("execute_only_file_backed", "backing_inode", True, "malformed"),
    ],
)
def test_unavailable_protection_and_inode_semantics_fail_closed(
    scenario, field, value, message
):
    raw = raw_unavailable(scenario)
    raw[field] = value
    with pytest.raises(LAB.LabError, match=message):
        LAB.validate_raw_case(raw, expected(scenario), 4096, 137)


def test_supported_bool_inodes_are_not_integers():
    raw = raw_supported()
    raw["backing_inode"] = True
    with pytest.raises(LAB.LabError, match="backing_inode is malformed"):
        LAB.validate_raw_case(raw, expected("clean_file_backed_rx"), 4096, 137)

    raw = raw_supported()
    raw["mapping_inode"] = True
    with pytest.raises(LAB.LabError, match="mapping_inode is malformed"):
        LAB.validate_raw_case(raw, expected("clean_file_backed_rx"), 4096, 137)


def test_elf_class_machine_and_relocation_widths_fail_closed():
    LAB._validate_pinned_elf_identity("ELF64", "Advanced Micro Devices X86-64")
    with pytest.raises(LAB.LabError, match="pinned"):
        LAB._validate_pinned_elf_identity("ELF32", "Advanced Micro Devices X86-64")
    with pytest.raises(LAB.LabError, match="pinned"):
        LAB._validate_pinned_elf_identity("ELF64", "AArch64")

    intervals = LAB._relocation_intervals(
        "0000000000001000  0000000000000000 R_X86_64_RELATIVE  0"
    )
    assert intervals == [(0x1000, 0x1008, "R_X86_64_RELATIVE")]
    assert LAB._probe_relocation_overlaps(intervals, 0x1004, 4096) == intervals
    crossing = [(0x0FFC, 0x1004, "R_X86_64_RELATIVE")]
    assert LAB._probe_relocation_overlaps(crossing, 0x1000, 4096) == crossing
    assert LAB._probe_relocation_overlaps(intervals, 0x1008, 4096) == []
    with pytest.raises(LAB.LabError, match="unsupported"):
        LAB._relocation_intervals(
            "0000000000001000  0000000000000000 R_X86_64_UNKNOWN  0"
        )
    with pytest.raises(LAB.LabError, match="packed"):
        LAB._relocation_intervals("Android packed relocation section")


def test_case_binary_hash_mismatch_fails_closed():
    digest = "a" * 64
    LAB._require_hash_match(digest, digest, "case binary")
    with pytest.raises(LAB.LabError, match="master provenance"):
        LAB._require_hash_match("b" * 64, digest, "case binary")
    with pytest.raises(LAB.LabError, match="master provenance"):
        LAB._require_hash_match("not-a-digest", digest, "case binary")


def test_temporary_namespace_is_strict():
    assert LAB._safe_temp_path("/tmp/tamandua-rx-elf-lab.Abc123") == (
        "/tmp/tamandua-rx-elf-lab.Abc123"
    )
    with pytest.raises(LAB.LabError, match="escaped"):
        LAB._safe_temp_path("/tmp/tamandua-rx-elf-lab.Abc123/child")


def test_normalization_ignores_only_measurement_duration():
    first = {
        "repeatability": {"runs": 2, "normalized_equal": True},
        "cases": [{"comparison_pipeline_duration_ns": 10, "outcome": "clean"}],
    }
    second = copy.deepcopy(first)
    second["cases"][0]["comparison_pipeline_duration_ns"] = 999
    assert LAB.normalized_report(first) == LAB.normalized_report(second)
    second["cases"][0]["outcome"] = "finding"
    assert LAB.normalized_report(first) != LAB.normalized_report(second)


def test_wsl_integration_runs_only_after_explicit_capability_passes():
    capability = LAB.preflight()
    if capability.get("capable") is not True:
        pytest.skip(
            f"explicit WSL lab capability unavailable: {capability.get('reasons')}"
        )

    report = LAB.run_lab(repeat=2)
    assert report["evidence_class"] == "local_wsl_filebacked_elf_lab"
    assert report["external_claim_allowed"] is False
    assert report["production_ready"] is False
    assert report["vendor_parity"] is False
    assert report["provenance"]["probe_relocation_count"] == 0
    assert report["repeatability"] == {"runs": 2, "normalized_equal": True}
    assert [item["outcome"] for item in report["cases"]] == [
        "clean",
        "finding",
        "degraded",
        "degraded",
        "unsupported",
        "degraded",
    ]
    assert all("baseline_hex" not in item for item in report["cases"])
    assert all("current_hex" not in item for item in report["cases"])
    assert report["cleanup_confirmed"] is True
