#!/usr/bin/env python3
"""Validate the bounded synthetic RX-page integrity lab contract."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FIXTURE = (
    ROOT
    / "tools"
    / "detection_validation"
    / "fixtures"
    / "runtime_rx_page_integrity_lab_v1.json"
)

TOP_LEVEL_KEYS = {
    "schema",
    "evidence_class",
    "external_claim_allowed",
    "claims",
    "page_size_bytes",
    "cost_budget",
    "cases",
}
CLAIM_KEYS = {"lab", "synthetic", "production_ready", "vendor_parity"}
COST_KEYS = {"metric", "max_pages", "max_bytes", "fixture_pages", "fixture_bytes"}
CASE_KEYS = {
    "id",
    "scenario",
    "description",
    "state",
    "baseline_hex",
    "current_hex",
    "relocation_allowlist",
    "limitations",
    "expected",
}
ALLOWLIST_KEYS = {"offset", "length", "reason"}
EXPECTED_KEYS = {"outcome", "drift_offsets"}
REQUIRED_CASE_STATES = {
    "rx_restored_malicious_drift": "supported",
    "benign_relocation": "supported",
    "jit_no_stable_baseline": "unsupported",
    "execute_only_unreadable": "degraded",
}
CANONICAL_CASE_SCENARIOS = {
    "rx-restored-malicious-drift": "rx_restored_malicious_drift",
    "benign-relocation-masked": "benign_relocation",
    "jit-no-stable-baseline": "jit_no_stable_baseline",
    "execute-only-unreadable": "execute_only_unreadable",
}


class ContractError(ValueError):
    """Raised when a lab fixture violates the strict contract."""


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError(f"{label} must contain exactly {sorted(expected)}")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractError(f"{label} must be a positive integer")
    return value


def _page_bytes(value: Any, page_size: int, label: str) -> bytes:
    if not isinstance(value, str) or value.lower() != value or len(value) != page_size * 2:
        raise ContractError(f"{label} must be canonical lowercase hex for one page")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ContractError(f"{label} is not valid hex") from error
    if len(decoded) != page_size:
        raise ContractError(f"{label} must decode to exactly {page_size} bytes")
    return decoded


def _validate_allowlist(value: Any, page_size: int, case_id: str) -> set[int]:
    if not isinstance(value, list):
        raise ContractError(f"{case_id}.relocation_allowlist must be a list")
    masked: set[int] = set()
    for index, entry in enumerate(value):
        entry = _exact_keys(entry, ALLOWLIST_KEYS, f"{case_id}.relocation_allowlist[{index}]")
        offset = entry["offset"]
        length = entry["length"]
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ContractError(f"{case_id} relocation offset must be a non-negative integer")
        _positive_int(length, f"{case_id} relocation length")
        if entry["reason"] != "relocation" or offset + length > page_size:
            raise ContractError(f"{case_id} has an invalid relocation allowance")
        region = set(range(offset, offset + length))
        if masked & region:
            raise ContractError(f"{case_id} relocation allowances must not overlap")
        masked |= region
    if len(masked) > page_size // 4:
        raise ContractError(f"{case_id} relocation allowances exceed 25% of the page")
    return masked


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_supported_case(case: dict[str, Any], page_size: int) -> dict[str, Any]:
    case_id = case["id"]
    baseline = _page_bytes(case["baseline_hex"], page_size, f"{case_id}.baseline_hex")
    current = _page_bytes(case["current_hex"], page_size, f"{case_id}.current_hex")
    masked = _validate_allowlist(case["relocation_allowlist"], page_size, case_id)
    if case["limitations"] != []:
        raise ContractError(f"{case_id} supported case must not declare limitations")
    raw_drift_offsets = [
        offset
        for offset, (before, after) in enumerate(zip(baseline, current, strict=True))
        if before != after
    ]
    raw_drift = set(raw_drift_offsets)
    if case["scenario"] == "rx_restored_malicious_drift":
        if masked or not raw_drift:
            raise ContractError(f"{case_id} malicious drift must be non-empty and unmasked")
    elif not masked or raw_drift != masked:
        raise ContractError(f"{case_id} relocation mask must exactly match changed bytes")
    drift_offsets = [offset for offset in raw_drift_offsets if offset not in masked]
    outcome = "finding" if drift_offsets else "clean"
    expected = _exact_keys(case["expected"], EXPECTED_KEYS, f"{case_id}.expected")
    if expected != {"outcome": outcome, "drift_offsets": drift_offsets}:
        raise ContractError(f"{case_id} expected result does not match computed page drift")
    return {
        "id": case_id,
        "scenario": case["scenario"],
        "state": "supported",
        "outcome": outcome,
        "drift_offsets": drift_offsets,
        "baseline_sha256": _hash(baseline),
        "current_sha256": _hash(current),
        "masked_byte_count": len(masked),
    }


def _validate_unavailable_case(case: dict[str, Any], page_size: int) -> dict[str, Any]:
    case_id = case["id"]
    if case["baseline_hex"] is not None or case["current_hex"] is not None:
        raise ContractError(f"{case_id} unavailable case must not contain page bytes")
    if case["relocation_allowlist"] != []:
        raise ContractError(f"{case_id} unavailable case must not contain relocation allowances")
    if not isinstance(case["limitations"], list) or not case["limitations"]:
        raise ContractError(f"{case_id} unavailable case requires explicit limitations")
    if any(not isinstance(item, str) or not item for item in case["limitations"]):
        raise ContractError(f"{case_id} limitations must be non-empty strings")
    expected = _exact_keys(case["expected"], EXPECTED_KEYS, f"{case_id}.expected")
    wanted = {"outcome": case["state"], "drift_offsets": []}
    if expected != wanted:
        raise ContractError(f"{case_id} must preserve its explicit unavailable state")
    return {
        "id": case_id,
        "scenario": case["scenario"],
        "state": case["state"],
        "outcome": case["state"],
        "drift_offsets": [],
        "limitations": case["limitations"],
    }


def validate_fixture(document: Any) -> dict[str, Any]:
    document = _exact_keys(document, TOP_LEVEL_KEYS, "fixture")
    if document["schema"] != "tamandua.runtime-rx-page-integrity-lab/v1":
        raise ContractError("fixture schema is unsupported")
    if document["evidence_class"] != "synthetic_lab":
        raise ContractError("evidence_class must remain synthetic_lab")
    if document["external_claim_allowed"] is not False:
        raise ContractError("external_claim_allowed must remain false")
    claims = _exact_keys(document["claims"], CLAIM_KEYS, "claims")
    required_claims = {
        "lab": True,
        "synthetic": True,
        "production_ready": False,
        "vendor_parity": False,
    }
    if claims != required_claims:
        raise ContractError("lab claims cannot be elevated or relabeled")

    page_size = _positive_int(document["page_size_bytes"], "page_size_bytes")
    if page_size > 4096:
        raise ContractError("synthetic page_size_bytes exceeds the lab bound")
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(REQUIRED_CASE_STATES):
        raise ContractError("fixture must contain exactly four bounded cases")

    results = []
    scenarios = set()
    ids = set()
    supported_pages = 0
    for index, raw_case in enumerate(cases):
        case = _exact_keys(raw_case, CASE_KEYS, f"cases[{index}]")
        if not isinstance(case["id"], str) or not case["id"] or case["id"] in ids:
            raise ContractError("case ids must be unique non-empty strings")
        canonical_scenario = CANONICAL_CASE_SCENARIOS.get(case["id"])
        if canonical_scenario is None or case["scenario"] != canonical_scenario:
            raise ContractError(f"{case['id']} does not match its canonical scenario")
        if (
            not isinstance(case["description"], str)
            or not case["description"]
            or case["description"] != case["description"].strip()
        ):
            raise ContractError(f"{case['id']} requires a description")
        if not isinstance(case["scenario"], str) or case["scenario"] not in REQUIRED_CASE_STATES:
            raise ContractError(f"{case['id']} has an unsupported scenario")
        if case["state"] != REQUIRED_CASE_STATES[case["scenario"]]:
            raise ContractError(f"{case['id']} state does not match its required scenario")
        ids.add(case["id"])
        scenarios.add(case["scenario"])
        if case["state"] == "supported":
            results.append(_validate_supported_case(case, page_size))
            supported_pages += 1
        elif case["state"] in {"degraded", "unsupported"}:
            results.append(_validate_unavailable_case(case, page_size))
        else:
            raise ContractError(f"{case['id']} has an invalid state")
    if scenarios != set(REQUIRED_CASE_STATES):
        raise ContractError("fixture scenarios do not match the required lab matrix")

    cost = _exact_keys(document["cost_budget"], COST_KEYS, "cost_budget")
    if cost["metric"] != "page_bytes_compared_per_scan":
        raise ContractError("cost_budget.metric is unsupported")
    max_pages = _positive_int(cost["max_pages"], "cost_budget.max_pages")
    max_bytes = _positive_int(cost["max_bytes"], "cost_budget.max_bytes")
    if max_pages > len(cases) or max_bytes > max_pages * page_size:
        raise ContractError("cost budget exceeds the bounded lab matrix")
    fixture_pages = supported_pages
    fixture_bytes = fixture_pages * page_size
    if cost["fixture_pages"] != fixture_pages or cost["fixture_bytes"] != fixture_bytes:
        raise ContractError("fixture cost metrics do not match the supported cases")
    if fixture_pages > max_pages or fixture_bytes > max_bytes:
        raise ContractError("fixture exceeds its declared cost budget")

    return {
        "schema": document["schema"],
        "evidence_class": "synthetic_lab",
        "external_claim_allowed": False,
        "status": "pass",
        "production_ready": False,
        "vendor_parity": False,
        "cost_budget": cost,
        "cases": results,
    }


def load_and_validate(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"unable to load fixture: {error}") from error
    return validate_fixture(document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()
    try:
        report = load_and_validate(args.fixture)
    except ContractError as error:
        print(json.dumps({"status": "fail", "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
