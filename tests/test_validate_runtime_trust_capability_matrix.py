from __future__ import annotations

import copy
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "validate_runtime_trust_capability_matrix.py"
SPEC = importlib.util.spec_from_file_location("validate_runtime_trust_capability_matrix", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def matrix() -> dict:
    return MODULE.load_json(MODULE.MATRIX_PATH)


def android_entry() -> dict:
    return next(e for e in matrix()["entries"] if e["profile"] == "mobile_app_guard" and e["platform"] == "android")


def test_strict_matrix_is_complete_but_not_supported() -> None:
    report = MODULE.validate(strict=True)
    assert report["ok"] is True
    assert report["entries"] == 11
    assert report["external_claim_allowed"] is False


def test_missing_required_signals_are_derived_not_trusted() -> None:
    entry = android_entry()
    result = MODULE.derive_signal_completeness(entry, ["debugger_detected"])
    assert result["signal_completeness"] == "missing_required"
    assert result["missing_signal_ids"] == ["app_integrity_violation", "frida_detected", "root_detected"]


def test_complete_requires_all_pinned_bundle_signals() -> None:
    entry = android_entry()
    result = MODULE.derive_signal_completeness(entry, list(reversed(entry["required_signal_ids"])))
    assert result == {"signal_completeness": "complete", "missing_signal_ids": []}


def test_unsupported_profile_derives_unknown_without_bundle() -> None:
    entry = next(e for e in matrix()["entries"] if e["profile"] == "anti_cheat" and e["platform"] == "windows")
    assert MODULE.derive_signal_completeness(entry, ["debugger_detected"]) == {
        "signal_completeness": "unknown", "missing_signal_ids": []
    }


def test_duplicate_or_missing_profile_platform_pair_is_rejected() -> None:
    value = matrix()
    value["entries"].append(copy.deepcopy(value["entries"][0]))
    errors = MODULE.semantic_errors(value)
    assert "profile/platform pairs must be unique" in errors


def test_bundle_digest_drift_is_rejected() -> None:
    value = matrix()
    entry = value["entries"][0]
    entry["required_signal_ids"].append("new_unpinned_signal")
    assert any("contract digest mismatch" in error for error in MODULE.semantic_errors(value))


def test_unsupported_entry_cannot_assert_bundle_or_required_signals() -> None:
    value = matrix()
    entry = next(e for e in value["entries"] if e["profile"] == "anti_cheat")
    entry["required_signal_ids"] = ["debugger_detected"]
    entry["detector_bundle"] = {
        "bundle_id": "tamandua.invalid",
        "bundle_version": "1",
        "contract_digest": "0" * 64,
        "binding_status": "contract_only"
    }
    errors = MODULE.semantic_errors(value)
    assert any("cannot assert required signals" in error for error in errors)
    assert any("cannot assert detector bundle" in error for error in errors)


def test_desktop_cannot_be_promoted_with_mobile_source() -> None:
    value = matrix()
    entry = next(e for e in value["entries"] if e["profile"] == "desktop_app_guard" and e["platform"] == "windows")
    entry.update({
        "state": "degraded",
        "evidence_status": "source_validated",
        "required_signal_ids": ["debugger_detected"],
        "source_paths": ["sdk/mobile/rust-core/src/lib.rs"],
        "detector_bundle": {
            "bundle_id": "tamandua.invalid.desktop",
            "bundle_version": "1",
            "contract_digest": "0" * 64,
            "binding_status": "contract_only"
        }
    })
    entry["detector_bundle"]["contract_digest"] = MODULE.bundle_contract_digest(entry)
    errors = MODULE.semantic_errors(value)
    assert any("category invariant mismatch" in error for error in errors)
    assert any("violates category source family" in error for error in errors)


def test_anti_cheat_cannot_be_promoted_in_source_review_v1() -> None:
    value = matrix()
    entry = next(e for e in value["entries"] if e["profile"] == "anti_cheat" and e["platform"] == "windows")
    entry["state"] = "degraded"
    entry["evidence_status"] = "source_validated"
    assert any("category invariant mismatch" in error for error in MODULE.semantic_errors(value))


def test_target_scope_is_pinned_to_profile() -> None:
    value = matrix()
    value["entries"][0]["target_scope"] = "web_session"
    assert any("category invariant mismatch" in error for error in MODULE.semantic_errors(value))


def test_category_boundary_limitation_cannot_be_removed() -> None:
    value = matrix()
    entry = next(e for e in value["entries"] if e["profile"] == "web_guard")
    entry["limitations"] = ["generic_limitation"]
    errors = MODULE.semantic_errors(value)
    assert any("missing required category boundaries" in error for error in errors)


def test_source_path_must_be_normalized_tracked_and_category_scoped() -> None:
    value = matrix()
    value["entries"][0]["source_paths"] = ["../tamandua/AGENTS.md"]
    errors = MODULE.semantic_errors(value)
    assert any("normalized repo-relative POSIX" in error for error in errors)


def test_mobile_entry_requires_platform_specific_and_shared_sources() -> None:
    value = matrix()
    entry = next(e for e in value["entries"] if e["profile"] == "mobile_app_guard" and e["platform"] == "ios")
    entry["source_paths"] = ["sdk/mobile/rust-core/src/lib.rs"]
    entry["detector_bundle"]["contract_digest"] = MODULE.bundle_contract_digest(entry)
    errors = MODULE.semantic_errors(value)
    assert any("missing required source prefix group" in error for error in errors)


def test_ios_source_review_does_not_claim_unbound_physical_evidence() -> None:
    value = matrix()
    entry = next(e for e in value["entries"] if e["profile"] == "mobile_app_guard" and e["platform"] == "ios")
    assert entry["evidence_status"] == "source_validated"
    assert "immutable_physical_evidence_receipt_not_bound" in entry["limitations"]
