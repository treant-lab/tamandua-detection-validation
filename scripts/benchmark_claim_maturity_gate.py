#!/usr/bin/env python3
"""Validate honest FP/FN, mobile shielding, endpoint parity, and vendor matrix gates."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, is_standalone
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    is_standalone = lambda: False

DEFAULT_FIXTURE = (
    ROOT / "fixtures" / "benchmark_claim_maturity_matrix_v1.json"
    if is_standalone()
    else ROOT / "tools" / "detection_validation" / "fixtures" / "benchmark_claim_maturity_matrix_v1.json"
)

API_VERSION = "tamandua.io/benchmark-claim-maturity-matrix/v1"
REQUIRED_STATUS_LABELS = {"local", "synthetic", "live missing"}
REQUIRED_EVIDENCE_TYPES = {"smoke_local", "synthetic_parity", "governed_holdout", "production_telemetry"}
EVIDENCE_TYPE_ORDER = {
    "smoke_local": 0,
    "synthetic_parity": 1,
    "governed_holdout": 2,
    "production_telemetry": 3,
}
REQUIRED_GATES = {
    "goodware_fp",
    "malware_fn",
    "mobile_shielding_synthetic_vs_physical",
    "endpoint_parity",
}
REQUIRED_PROMOTION_TARGETS = {
    "goodware_fp": "production_false_positive_rate",
    "malware_fn": "governed_malware_false_negative_rate",
    "mobile_shielding_synthetic_vs_physical": "physical_mobile_shielding",
    "endpoint_parity": "cross_platform_endpoint_parity",
}
MINIMUM_LIVE_TIERS = {
    "goodware_fp": "production_telemetry",
    "malware_fn": "governed_holdout",
    "mobile_shielding_synthetic_vs_physical": "physical_device_lab",
    "endpoint_parity": "selected_live_smoke",
}
CURRENT_GATE_EVIDENCE_TYPES = {
    "goodware_fp": "smoke_local",
    "malware_fn": "smoke_local",
    "mobile_shielding_synthetic_vs_physical": "synthetic_parity",
    "endpoint_parity": "smoke_local",
}
MINIMUM_GATE_EVIDENCE_TYPES = {
    "goodware_fp": "production_telemetry",
    "malware_fn": "governed_holdout",
    "mobile_shielding_synthetic_vs_physical": "governed_holdout",
    "endpoint_parity": "governed_holdout",
}
REQUIRED_VENDORS = {"Elastic", "Wazuh", "Appdome", "Verimatrix", "Guardcore"}
MOBILE_RELEASE_REQUIREMENTS = {
    "live_signed_app_guard_ingestion",
    "live_duplicate_signed_request_rejection",
    "physical_device_collection_packet",
    "ios_native_build_evidence",
    "ios_xcframework_binding_evidence",
    "governed_physical_attack_lab_evidence",
}
RATE_TOLERANCE = 1e-12
SCORE_ORIENTATIONS = {"as_is", "inverted", "inverted_selected"}
MARKDOWN_HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
MARKDOWN_ANCHOR_STRIP_PATTERN = re.compile(r"[^a-z0-9 _-]")
MARKDOWN_ANCHOR_SPACE_PATTERN = re.compile(r"\s+")


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def non_negative_integer(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def unit_interval_number(value: Any) -> float | None:
    numeric = number(value)
    if numeric is None or numeric < 0.0 or numeric > 1.0:
        return None
    return numeric


def string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) and item for item in value):
        return None
    return value


def evidence_type_rank(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    return EVIDENCE_TYPE_ORDER.get(value)


def evidence_is_mature(current: Any, minimum: Any) -> bool:
    current_rank = evidence_type_rank(current)
    minimum_rank = evidence_type_rank(minimum)
    return current_rank is not None and minimum_rank is not None and current_rank >= minimum_rank


def validate_missing_artifact_coverage(
    path: Path,
    field: str,
    required_artifacts: list[str] | None,
    satisfied_artifacts: list[str] | None,
    missing_evidence: list[str] | None,
) -> list[str]:
    if required_artifacts is None or satisfied_artifacts is None or missing_evidence is None:
        return []

    errors: list[str] = []
    duplicate_required = sorted({item for item in required_artifacts if required_artifacts.count(item) > 1})
    duplicate_satisfied = sorted({item for item in satisfied_artifacts if satisfied_artifacts.count(item) > 1})
    duplicate_missing = sorted({item for item in missing_evidence if missing_evidence.count(item) > 1})
    if duplicate_required:
        errors.append(f"{path}: {field}.required artifacts must not contain duplicates {duplicate_required}")
    if duplicate_satisfied:
        errors.append(f"{path}: {field}.satisfied artifacts must not contain duplicates {duplicate_satisfied}")
    if duplicate_missing:
        errors.append(f"{path}: {field}.missing_evidence must not contain duplicates {duplicate_missing}")

    required = set(required_artifacts)
    satisfied = set(satisfied_artifacts)
    missing = set(missing_evidence)
    unexpected_satisfied = sorted(satisfied - required)
    unexpected_missing = sorted(missing - required)
    overlap = sorted(satisfied & missing)
    expected_missing = required - satisfied
    missing_required = sorted(expected_missing - missing)
    if unexpected_satisfied:
        errors.append(f"{path}: {field}.satisfied artifacts are not required {unexpected_satisfied}")
    if unexpected_missing:
        errors.append(f"{path}: {field}.missing_evidence contains non-required artifacts {unexpected_missing}")
    if overlap:
        errors.append(f"{path}: {field}.artifacts cannot be both satisfied and missing {overlap}")
    if missing_required:
        errors.append(f"{path}: {field}.missing_evidence must include unsatisfied required artifacts {missing_required}")
    return errors


def validate_source_artifacts(path: Path, gate_id: str, value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return [f"{path}: gate {gate_id} source_artifacts must be non-empty"]

    errors: list[str] = []
    root = ROOT.resolve()
    standalone_prefix = Path("tools/detection_validation").parts
    for index, reference in enumerate(value):
        field = f"{path}: gate {gate_id} source_artifacts[{index}]"
        if not isinstance(reference, str) or not reference:
            errors.append(f"{field} must be a non-empty string")
            continue

        # A fragment identifies a section inside the artifact. It is not part
        # of the filesystem path, but an explicitly present '#' must have a
        # non-empty anchor so malformed references cannot pass accidentally.
        artifact_text, separator, anchor = reference.partition("#")
        if not artifact_text:
            errors.append(f"{field} must contain a repository-relative path before #anchor")
            continue
        if separator and not anchor:
            errors.append(f"{field} must contain a non-empty #anchor")
            continue

        artifact_path = Path(artifact_text)
        if artifact_path.is_absolute():
            errors.append(f"{field} must be repository-relative")
            continue

        candidates = [root / artifact_path]
        if is_standalone() and artifact_path.parts[:2] == standalone_prefix:
            candidates.append(root.joinpath(*artifact_path.parts[2:]))
        resolved_candidates = [candidate.resolve() for candidate in candidates]
        existing_candidates = [
            candidate for candidate in resolved_candidates if candidate.is_relative_to(root) and candidate.is_file()
        ]
        if not existing_candidates:
            errors.append(f"{field} does not reference an existing repository file: {artifact_text}")
            continue
        if anchor and existing_candidates[0].suffix.lower() in {".md", ".markdown"}:
            errors.extend(validate_markdown_anchor(field, existing_candidates[0], anchor))
    return errors


def markdown_heading_anchor(heading_text: str) -> str:
    text = heading_text.strip().lower()
    text = MARKDOWN_ANCHOR_STRIP_PATTERN.sub("", text)
    text = MARKDOWN_ANCHOR_SPACE_PATTERN.sub("-", text)
    return text.strip("-")


def markdown_anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = MARKDOWN_HEADING_PATTERN.match(line)
        if not match:
            continue
        anchor = markdown_heading_anchor(match.group(2))
        if not anchor:
            continue
        seen_count = seen.get(anchor, 0)
        seen[anchor] = seen_count + 1
        anchors.add(anchor if seen_count == 0 else f"{anchor}-{seen_count}")
    return anchors


def validate_markdown_anchor(field: str, path: Path, anchor: str) -> list[str]:
    if anchor in markdown_anchors(path):
        return []
    return [f"{field} does not reference an existing markdown heading anchor: #{anchor}"]


def validate_matrix(path: Path) -> tuple[list[str], dict[str, Any]]:
    data = load_json(path)
    errors: list[str] = []

    if data.get("api_version") != API_VERSION:
        errors.append(f"{path}: api_version must be {API_VERSION}")
    if data.get("kind") != "BenchmarkClaimMaturityMatrix":
        errors.append(f"{path}: kind must be BenchmarkClaimMaturityMatrix")
    if not isinstance(data.get("claim_boundary"), str) or "does not authorize vendor parity" not in data["claim_boundary"]:
        errors.append(f"{path}: claim_boundary must block vendor parity claims")

    labels = set(data.get("status_labels", []))
    if labels != REQUIRED_STATUS_LABELS:
        errors.append(f"{path}: status_labels must be {sorted(REQUIRED_STATUS_LABELS)}")
    evidence_types = set(data.get("evidence_types", []))
    if evidence_types != REQUIRED_EVIDENCE_TYPES:
        errors.append(f"{path}: evidence_types must be {sorted(REQUIRED_EVIDENCE_TYPES)}")

    gates = data.get("gates")
    if not isinstance(gates, list):
        return errors + [f"{path}: gates must be a list"], {}
    gate_ids = [gate.get("id") for gate in gates if isinstance(gate, dict)]
    duplicate_gate_ids = sorted({gate_id for gate_id in gate_ids if gate_ids.count(gate_id) > 1})
    if duplicate_gate_ids:
        errors.append(f"{path}: duplicate gate ids {duplicate_gate_ids}")
    by_id = {gate.get("id"): gate for gate in gates if isinstance(gate, dict)}
    missing_gates = sorted(REQUIRED_GATES - set(by_id))
    if missing_gates:
        errors.append(f"{path}: missing required gates {missing_gates}")

    for gate_id in sorted(REQUIRED_GATES & set(by_id)):
        gate = by_id[gate_id]
        errors.extend(validate_common_gate(path, gate_id, gate))

    if "goodware_fp" in by_id:
        errors.extend(validate_goodware_fp(path, by_id["goodware_fp"]))
    if "malware_fn" in by_id:
        errors.extend(validate_malware_fn(path, by_id["malware_fn"]))
    if "mobile_shielding_synthetic_vs_physical" in by_id:
        errors.extend(validate_mobile_gate(path, by_id["mobile_shielding_synthetic_vs_physical"]))
    if "endpoint_parity" in by_id:
        errors.extend(validate_endpoint_parity(path, by_id["endpoint_parity"]))

    competitor_matrix = data.get("competitor_matrix")
    if not isinstance(competitor_matrix, list):
        errors.append(f"{path}: competitor_matrix must be a list")
        competitor_matrix = []
    vendors = [row.get("vendor") for row in competitor_matrix if isinstance(row, dict)]
    duplicate_vendors = sorted({vendor for vendor in vendors if vendors.count(vendor) > 1})
    if duplicate_vendors:
        errors.append(f"{path}: duplicate competitor vendors {duplicate_vendors}")
    vendor_rows = {row.get("vendor"): row for row in competitor_matrix if isinstance(row, dict)}
    missing_vendors = sorted(REQUIRED_VENDORS - set(vendor_rows))
    if missing_vendors:
        errors.append(f"{path}: competitor_matrix missing vendors {missing_vendors}")
    for vendor in sorted(REQUIRED_VENDORS & set(vendor_rows)):
        row = vendor_rows[vendor]
        if row.get("external_claim_allowed") is not False:
            errors.append(f"{path}: competitor_matrix.{vendor}.external_claim_allowed must be false")
        if row.get("tamandua_status") not in REQUIRED_STATUS_LABELS:
            errors.append(f"{path}: competitor_matrix.{vendor}.tamandua_status must be one of {sorted(REQUIRED_STATUS_LABELS)}")
        if row.get("evidence_type") not in REQUIRED_EVIDENCE_TYPES:
            errors.append(f"{path}: competitor_matrix.{vendor}.evidence_type must be one of {sorted(REQUIRED_EVIDENCE_TYPES)}")
        live_parity = row.get("live_parity_evidence")
        if not isinstance(live_parity, dict):
            errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence must be an object")
        else:
            errors.extend(validate_competitor_evidence(path, vendor, row, live_parity))
            if live_parity.get("live_proof_required") is not True:
                errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.live_proof_required must be true")
            for field in ["required_artifacts", "satisfied_artifacts"]:
                value = live_parity.get(field)
                if not isinstance(value, list):
                    errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.{field} must be a list")
                elif field == "required_artifacts" and not value:
                    errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.required_artifacts must be non-empty")
                elif not all(isinstance(item, str) and item for item in value):
                    errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.{field} must contain strings")
            if not isinstance(live_parity.get("blocked_claim"), str) or len(live_parity["blocked_claim"]) < 40:
                errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.blocked_claim must explain the blocked parity claim")
        boundary = str(row.get("claim_boundary") or "").lower()
        if "parity" not in boundary and "replacement" not in boundary and "shielding" not in boundary:
            errors.append(f"{path}: competitor_matrix.{vendor}.claim_boundary must state the non-parity/non-replacement boundary")

    summary = {
        "fixture": str(path),
        "status_labels": sorted(labels),
        "gates": {
            gate_id: {
                "status": by_id[gate_id].get("status"),
                "evidence_tier": by_id[gate_id].get("evidence_tier"),
                "evidence_type": by_id[gate_id].get("evidence_type"),
                "external_claim_allowed": by_id[gate_id].get("external_claim_allowed"),
            }
            for gate_id in sorted(REQUIRED_GATES & set(by_id))
        },
        "vendors": {
            vendor: vendor_rows[vendor].get("tamandua_status")
            for vendor in sorted(REQUIRED_VENDORS & set(vendor_rows))
        },
        "claim_boundary": data.get("claim_boundary"),
    }
    return errors, summary


def validate_common_gate(path: Path, gate_id: str, gate: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if gate.get("status") not in REQUIRED_STATUS_LABELS:
        errors.append(f"{path}: gate {gate_id} status must be one of {sorted(REQUIRED_STATUS_LABELS)}")
    if gate.get("external_claim_allowed") is not False:
        errors.append(f"{path}: gate {gate_id} external_claim_allowed must be false")
    if gate.get("evidence_type") != CURRENT_GATE_EVIDENCE_TYPES[gate_id]:
        errors.append(f"{path}: gate {gate_id} evidence_type must be {CURRENT_GATE_EVIDENCE_TYPES[gate_id]}")
    errors.extend(validate_source_artifacts(path, gate_id, gate.get("source_artifacts")))
    if not isinstance(gate.get("required_for_stronger_claim"), list):
        errors.append(f"{path}: gate {gate_id} required_for_stronger_claim must be a list")
    if not isinstance(gate.get("metrics"), dict):
        errors.append(f"{path}: gate {gate_id} metrics must be an object")
    errors.extend(validate_promotion_evidence(path, gate_id, gate))
    return errors


def validate_promotion_evidence(path: Path, gate_id: str, gate: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    promotion = gate.get("promotion_evidence")
    if not isinstance(promotion, dict):
        return [f"{path}: gate {gate_id} promotion_evidence must be an object"]
    if promotion.get("claim_target") != REQUIRED_PROMOTION_TARGETS[gate_id]:
        errors.append(
            f"{path}: gate {gate_id} promotion_evidence.claim_target must be {REQUIRED_PROMOTION_TARGETS[gate_id]}"
        )
    if promotion.get("current_evidence_class") != gate.get("evidence_tier"):
        errors.append(f"{path}: gate {gate_id} promotion_evidence.current_evidence_class must match evidence_tier")
    if promotion.get("current_evidence_type") != gate.get("evidence_type"):
        errors.append(f"{path}: gate {gate_id} promotion_evidence.current_evidence_type must match evidence_type")
    if promotion.get("live_proof_required") is not True:
        errors.append(f"{path}: gate {gate_id} promotion_evidence.live_proof_required must be true")
    if promotion.get("minimum_required_tier") != MINIMUM_LIVE_TIERS[gate_id]:
        errors.append(
            f"{path}: gate {gate_id} promotion_evidence.minimum_required_tier must be {MINIMUM_LIVE_TIERS[gate_id]}"
        )
    minimum_required_evidence_type = promotion.get("minimum_required_evidence_type")
    if minimum_required_evidence_type != MINIMUM_GATE_EVIDENCE_TYPES[gate_id]:
        errors.append(
            f"{path}: gate {gate_id} promotion_evidence.minimum_required_evidence_type "
            f"must be {MINIMUM_GATE_EVIDENCE_TYPES[gate_id]}"
        )
    required_artifacts = promotion.get("required_live_artifacts")
    valid_required_artifacts = None
    if not isinstance(required_artifacts, list) or not required_artifacts:
        errors.append(f"{path}: gate {gate_id} promotion_evidence.required_live_artifacts must be non-empty")
    elif not all(isinstance(item, str) and item for item in required_artifacts):
        errors.append(f"{path}: gate {gate_id} promotion_evidence.required_live_artifacts must contain strings")
    else:
        valid_required_artifacts = required_artifacts
    satisfied_artifacts = promotion.get("satisfied_live_artifacts")
    valid_satisfied_artifacts = None
    if not isinstance(satisfied_artifacts, list):
        errors.append(f"{path}: gate {gate_id} promotion_evidence.satisfied_live_artifacts must be a list")
    elif not all(isinstance(item, str) and item for item in satisfied_artifacts):
        errors.append(f"{path}: gate {gate_id} promotion_evidence.satisfied_live_artifacts must contain strings")
    else:
        valid_satisfied_artifacts = satisfied_artifacts
    blocked_reason = promotion.get("promotion_blocked_reason")
    if not isinstance(blocked_reason, str) or len(blocked_reason) < 40:
        errors.append(f"{path}: gate {gate_id} promotion_evidence.promotion_blocked_reason must explain the live-proof gap")
    missing_evidence = string_list(promotion.get("missing_evidence"))
    if missing_evidence is None:
        errors.append(f"{path}: gate {gate_id} promotion_evidence.missing_evidence must be a list of strings")
    next_evidence_step = promotion.get("next_evidence_step")
    if not isinstance(next_evidence_step, str) or len(next_evidence_step) < 20:
        errors.append(f"{path}: gate {gate_id} promotion_evidence.next_evidence_step must describe the next evidence step")
    mature = evidence_is_mature(promotion.get("current_evidence_type"), minimum_required_evidence_type)
    if gate.get("external_claim_allowed") is True and not mature:
        errors.append(f"{path}: gate {gate_id} strong claim requires {minimum_required_evidence_type} evidence")
    if not mature and not missing_evidence:
        errors.append(f"{path}: gate {gate_id} promotion_evidence.missing_evidence must be non-empty while immature")
    errors.extend(
        validate_missing_artifact_coverage(
            path,
            f"gate {gate_id} promotion_evidence",
            valid_required_artifacts,
            valid_satisfied_artifacts,
            missing_evidence,
        )
    )
    return errors


def validate_competitor_evidence(
    path: Path, vendor: str, row: dict[str, Any], live_parity: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    current_type = live_parity.get("current_evidence_type")
    minimum_type = live_parity.get("minimum_required_evidence_type")
    if current_type != row.get("evidence_type"):
        errors.append(
            f"{path}: competitor_matrix.{vendor}.live_parity_evidence.current_evidence_type must match evidence_type"
        )
    if minimum_type not in REQUIRED_EVIDENCE_TYPES:
        errors.append(
            f"{path}: competitor_matrix.{vendor}.live_parity_evidence.minimum_required_evidence_type "
            f"must be one of {sorted(REQUIRED_EVIDENCE_TYPES)}"
        )
    missing_evidence = string_list(live_parity.get("missing_evidence"))
    if missing_evidence is None:
        errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.missing_evidence must be a list of strings")
    required_artifacts = string_list(live_parity.get("required_artifacts"))
    satisfied_artifacts = string_list(live_parity.get("satisfied_artifacts"))
    next_evidence_step = live_parity.get("next_evidence_step")
    if not isinstance(next_evidence_step, str) or len(next_evidence_step) < 20:
        errors.append(
            f"{path}: competitor_matrix.{vendor}.live_parity_evidence.next_evidence_step must describe the next evidence step"
        )
    mature = evidence_is_mature(current_type, minimum_type)
    if row.get("external_claim_allowed") is True and not mature:
        errors.append(f"{path}: competitor_matrix.{vendor} strong claim requires {minimum_type} evidence")
    if not mature and not missing_evidence:
        errors.append(
            f"{path}: competitor_matrix.{vendor}.live_parity_evidence.missing_evidence must be non-empty while immature"
        )
    errors.extend(
        validate_missing_artifact_coverage(
            path,
            f"competitor_matrix.{vendor}.live_parity_evidence",
            required_artifacts,
            satisfied_artifacts,
            missing_evidence,
        )
    )
    return errors


def validate_goodware_fp(path: Path, gate: dict[str, Any]) -> list[str]:
    metrics = gate.get("metrics", {})
    errors: list[str] = []
    if gate.get("status") != "local" or gate.get("evidence_tier") != "bootstrap_local":
        errors.append(f"{path}: goodware_fp must remain local bootstrap evidence")
    samples = non_negative_integer(metrics.get("goodware_samples"))
    min_samples = non_negative_integer(metrics.get("minimum_goodware_samples"))
    false_positives = non_negative_integer(metrics.get("false_positives"))
    max_fp = non_negative_integer(metrics.get("maximum_false_positives"))
    fpr = unit_interval_number(metrics.get("fpr"))
    threshold = unit_interval_number(metrics.get("threshold"))
    if samples is None:
        errors.append(f"{path}: goodware_fp goodware_samples must be a non-negative integer")
    if min_samples is None:
        errors.append(f"{path}: goodware_fp minimum_goodware_samples must be a non-negative integer")
    if samples is not None and min_samples is not None and samples < min_samples:
        errors.append(f"{path}: goodware_fp samples must meet minimum_goodware_samples")
    if false_positives is None:
        errors.append(f"{path}: goodware_fp false_positives must be a non-negative integer")
    if max_fp is None:
        errors.append(f"{path}: goodware_fp maximum_false_positives must be a non-negative integer")
    if false_positives is not None and max_fp is not None and false_positives > max_fp:
        errors.append(f"{path}: goodware_fp false_positives exceed maximum_false_positives")
    if false_positives is not None and samples is not None and false_positives > samples:
        errors.append(f"{path}: goodware_fp false_positives cannot exceed goodware_samples")
    if fpr is None:
        errors.append(f"{path}: goodware_fp fpr must be a number between 0 and 1")
    if samples and false_positives is not None and fpr is not None:
        expected_fpr = false_positives / samples
        if abs(fpr - expected_fpr) > RATE_TOLERANCE:
            errors.append(f"{path}: goodware_fp fpr must equal false_positives / goodware_samples")
    if metrics.get("fpr") != 0.0:
        errors.append(f"{path}: goodware_fp fpr must be 0.0 for the recorded bootstrap slice")
    if threshold is None:
        errors.append(f"{path}: goodware_fp threshold must be a number between 0 and 1")
    if metrics.get("score_orientation") not in SCORE_ORIENTATIONS:
        errors.append(f"{path}: goodware_fp score_orientation must be one of {sorted(SCORE_ORIENTATIONS)}")
    return errors


def validate_malware_fn(path: Path, gate: dict[str, Any]) -> list[str]:
    metrics = gate.get("metrics", {})
    errors: list[str] = []
    if gate.get("status") != "local" or gate.get("evidence_tier") != "bootstrap_local":
        errors.append(f"{path}: malware_fn must remain local bootstrap evidence")
    samples = non_negative_integer(metrics.get("malware_samples"))
    min_samples = non_negative_integer(metrics.get("minimum_malware_samples"))
    false_negatives = non_negative_integer(metrics.get("false_negatives"))
    max_fn = non_negative_integer(metrics.get("maximum_false_negatives"))
    fnr = unit_interval_number(metrics.get("fnr"))
    threshold = unit_interval_number(metrics.get("threshold"))
    if samples is None:
        errors.append(f"{path}: malware_fn malware_samples must be a non-negative integer")
    if min_samples is None:
        errors.append(f"{path}: malware_fn minimum_malware_samples must be a non-negative integer")
    if samples is not None and min_samples is not None and samples < min_samples:
        errors.append(f"{path}: malware_fn samples must meet minimum_malware_samples")
    if false_negatives is None:
        errors.append(f"{path}: malware_fn false_negatives must be a non-negative integer")
    if max_fn is None:
        errors.append(f"{path}: malware_fn maximum_false_negatives must be a non-negative integer")
    if false_negatives is not None and max_fn is not None and false_negatives > max_fn:
        errors.append(f"{path}: malware_fn false_negatives exceed maximum_false_negatives")
    if false_negatives is not None and samples is not None and false_negatives > samples:
        errors.append(f"{path}: malware_fn false_negatives cannot exceed malware_samples")
    if fnr is None:
        errors.append(f"{path}: malware_fn fnr must be a number between 0 and 1")
    if samples and false_negatives is not None and fnr is not None:
        expected_fnr = false_negatives / samples
        if abs(fnr - expected_fnr) > RATE_TOLERANCE:
            errors.append(f"{path}: malware_fn fnr must equal false_negatives / malware_samples")
    if metrics.get("fnr") != 0.0:
        errors.append(f"{path}: malware_fn fnr must be 0.0 for the recorded bootstrap slice")
    if threshold is None:
        errors.append(f"{path}: malware_fn threshold must be a number between 0 and 1")
    if metrics.get("score_orientation") not in SCORE_ORIENTATIONS:
        errors.append(f"{path}: malware_fn score_orientation must be one of {sorted(SCORE_ORIENTATIONS)}")
    return errors


def validate_mobile_gate(path: Path, gate: dict[str, Any]) -> list[str]:
    metrics = gate.get("metrics", {})
    required = set(gate.get("required_for_stronger_claim", []))
    promotion = gate.get("promotion_evidence", {})
    errors: list[str] = []
    if gate.get("status") != "synthetic" or gate.get("evidence_tier") != "synthetic_replay_contract":
        errors.append(f"{path}: mobile_shielding gate must remain synthetic replay only")
    if not MOBILE_RELEASE_REQUIREMENTS.issubset(required):
        errors.append(f"{path}: mobile_shielding gate missing release evidence {sorted(MOBILE_RELEASE_REQUIREMENTS - required)}")
    synthetic_count = non_negative_integer(metrics.get("synthetic_fixture_count"))
    goodware_count = non_negative_integer(metrics.get("goodware_false_positive_fixtures"))
    if synthetic_count is None:
        errors.append(f"{path}: mobile_shielding synthetic_fixture_count must be a non-negative integer")
    elif synthetic_count < 10:
        errors.append(f"{path}: mobile_shielding synthetic_fixture_count must be >= 10")
    if goodware_count is None:
        errors.append(f"{path}: mobile_shielding goodware_false_positive_fixtures must be a non-negative integer")
    elif goodware_count < 2:
        errors.append(f"{path}: mobile_shielding goodware_false_positive_fixtures must be >= 2")
    if synthetic_count is not None and goodware_count is not None and goodware_count > synthetic_count:
        errors.append(
            f"{path}: mobile_shielding goodware_false_positive_fixtures cannot exceed synthetic_fixture_count"
        )
    if metrics.get("shielding_claim_allowed") is not False:
        errors.append(f"{path}: mobile_shielding shielding_claim_allowed must be false")
    if metrics.get("physical_device_smoke_collected") is not False:
        errors.append(f"{path}: mobile_shielding physical_device_smoke_collected must be false in this matrix")
    if metrics.get("governed_physical_attack_lab_collected") is not False:
        errors.append(f"{path}: mobile_shielding governed_physical_attack_lab_collected must be false")
    if isinstance(promotion, dict) and promotion.get("satisfied_live_artifacts"):
        errors.append(
            f"{path}: mobile_shielding promotion_evidence.satisfied_live_artifacts must remain empty "
            "until physical device and governed attack-lab evidence are attached"
        )
    return errors


def validate_endpoint_parity(path: Path, gate: dict[str, Any]) -> list[str]:
    metrics = gate.get("metrics", {})
    errors: list[str] = []
    if gate.get("status") != "live missing":
        errors.append(f"{path}: endpoint_parity status must be live missing")
    if metrics.get("parity_claim_allowed") is not False:
        errors.append(f"{path}: endpoint_parity parity_claim_allowed must be false")
    required_blockers = [
        "windows_identity_blocked",
        "linux_kernel_sensor_live_missing",
        "macos_fresh_live_missing",
        "mobile_runtime_protection_live_missing",
    ]
    for blocker in required_blockers:
        if metrics.get(blocker) is not True:
            errors.append(f"{path}: endpoint_parity metrics.{blocker} must be true")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()

    errors, summary = validate_matrix(args.fixture)
    if errors:
        for error in errors:
            print(error)
        return 1

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
