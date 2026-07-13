#!/usr/bin/env python3
"""Validate the governed goodware/malware FP/FN corpus claim gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, is_standalone
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    is_standalone = lambda: False

DEFAULT_FIXTURE = (
    ROOT / "fixtures" / "governed_fp_fn_corpus_gate_v1.json"
    if is_standalone()
    else ROOT / "tools" / "detection_validation" / "fixtures" / "governed_fp_fn_corpus_gate_v1.json"
)

API_VERSION = "tamandua.io/governed-fp-fn-corpus-gate/v1"
REQUIRED_BLOCKED_CLAIMS = {
    "production false-positive rate",
    "production malware false-negative rate",
    "malware detection quality",
    "vendor parity",
    "live protection efficacy",
}
REQUIRED_PROMOTION_ARTIFACTS = {
    "governed_goodware_manifest_with_hashes_license_and_lineage",
    "governed_malware_holdout_manifest_with_source_lineage_and_label_review",
    "deduplicated_sample_count_report",
    "locked_threshold_and_score_orientation_record",
    "computed_fpr_fnr_confidence_interval_report",
    "end_to_end_agent_server_alert_feed_proof",
    "retained_critical_scenario_replay_report",
    "reviewed_fpr_fnr_summary_with_blocked_external_claim_status",
}
REQUIRED_CRITICAL_FAMILIES = {
    "ntdll_lsass_or_cross_process_memory",
    "etw_or_amsi_tamper",
    "critical_attack_counterpart_retention",
}
PUBLIC_METRIC_NAMES = {"fpr", "fnr"}
PROMOTABLE_EVIDENCE_CLASSES = {"governed_holdout", "production_telemetry"}


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


def string_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str) and item}


def validate_gate(path: Path) -> tuple[list[str], dict[str, Any]]:
    data = load_json(path)
    errors: list[str] = []

    if data.get("api_version") != API_VERSION:
        errors.append(f"{path}: api_version must be {API_VERSION}")
    if data.get("kind") != "GovernedFpFnCorpusGate":
        errors.append(f"{path}: kind must be GovernedFpFnCorpusGate")
    if data.get("external_claim_allowed") is not False:
        errors.append(f"{path}: external_claim_allowed must be false")

    boundary = str(data.get("claim_boundary") or "").lower()
    if "does not authorize external claims" not in boundary:
        errors.append(f"{path}: claim_boundary must explicitly block external claims")
    if "governed holdout" not in boundary and "production telemetry" not in boundary:
        errors.append(f"{path}: claim_boundary must require governed or production evidence")

    evidence_class = data.get("evidence_class")
    gate_status = data.get("gate_status")
    if evidence_class in {"bootstrap_local", "governed_plan"} and gate_status != "hold":
        errors.append(f"{path}: non-governed evidence_class must keep gate_status hold")
    if gate_status == "governed_pass":
        errors.append(f"{path}: governed_pass is not accepted without a live/governed evidence verifier")

    errors.extend(validate_lineage(path, data.get("corpus_lineage")))
    errors.extend(validate_label_review(path, data.get("label_review")))
    errors.extend(validate_sample_accounting(path, data.get("sample_accounting")))
    errors.extend(validate_dedupe(path, data.get("dedupe"), data.get("sample_accounting")))
    errors.extend(validate_thresholds(path, data.get("thresholds")))
    errors.extend(validate_outcomes(path, data.get("outcomes"), data.get("sample_accounting")))
    errors.extend(validate_confidence_intervals(path, data.get("confidence_intervals")))
    errors.extend(validate_retained_critical(path, data.get("retained_critical_scenarios")))
    errors.extend(validate_promotion(path, data.get("claim_promotion_requirements"), data))

    source_artifacts = data.get("source_artifacts")
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append(f"{path}: source_artifacts must be a non-empty list")
    elif not all(isinstance(item, str) and item for item in source_artifacts):
        errors.append(f"{path}: source_artifacts must contain strings")

    sample_accounting = data.get("sample_accounting") if isinstance(data.get("sample_accounting"), dict) else {}
    outcomes = data.get("outcomes") if isinstance(data.get("outcomes"), dict) else {}
    summary = {
        "fixture": str(path),
        "gate_status": gate_status,
        "evidence_class": evidence_class,
        "external_claim_allowed": data.get("external_claim_allowed"),
        "goodware_samples": sample_accounting.get("goodware_samples"),
        "malware_samples": sample_accounting.get("malware_samples"),
        "promotion_minimum_goodware_samples": sample_accounting.get("promotion_minimum_goodware_samples"),
        "promotion_minimum_malware_samples": sample_accounting.get("promotion_minimum_malware_samples"),
        "fpr": outcomes.get("fpr"),
        "fnr": outcomes.get("fnr"),
        "blocked_claims": sorted(string_set(data.get("claim_promotion_requirements", {}).get("blocked_claims"))),
    }
    return errors, summary


def validate_lineage(path: Path, lineage: Any) -> list[str]:
    if not isinstance(lineage, dict):
        return [f"{path}: corpus_lineage must be an object"]
    errors: list[str] = []
    for label in ("goodware", "malware"):
        entry = lineage.get(label)
        if not isinstance(entry, dict):
            errors.append(f"{path}: corpus_lineage.{label} must be an object")
            continue
        if entry.get("label_review_required") is not True:
            errors.append(f"{path}: corpus_lineage.{label}.label_review_required must be true")
        if entry.get("source_class") != "local_bootstrap" or entry.get("lineage_status") != "bootstrap_local":
            errors.append(f"{path}: corpus_lineage.{label} must remain bootstrap_local until governed evidence exists")
        manifests = entry.get("manifest_refs")
        if not isinstance(manifests, list) or not manifests:
            errors.append(f"{path}: corpus_lineage.{label}.manifest_refs must be non-empty")
        for field in ("dataset_id", "provenance_status", "license_status", "collection_method", "hash_manifest_ref"):
            if not isinstance(entry.get(field), str) or not entry[field]:
                errors.append(f"{path}: corpus_lineage.{label}.{field} must be present")
        if entry.get("provenance_status") != "local_bootstrap_not_governed":
            errors.append(f"{path}: corpus_lineage.{label}.provenance_status must remain local_bootstrap_not_governed")
        if entry.get("license_status") not in {"local_internal_only", "governed_redistribution_review_pending"}:
            errors.append(f"{path}: corpus_lineage.{label}.license_status must block public claims")
        prohibited = string_set(entry.get("prohibited_actions"))
        required = {"no_dataset_download_performed", "no_public_claim_from_bootstrap_slice"}
        label_requirement = f"no_unreviewed_{label}_labels"
        if not (required | {label_requirement}).issubset(prohibited):
            missing = sorted((required | {label_requirement}) - prohibited)
            errors.append(f"{path}: corpus_lineage.{label}.prohibited_actions missing {missing}")
    return errors


def validate_label_review(path: Path, review: Any) -> list[str]:
    if not isinstance(review, dict):
        return [f"{path}: label_review must be an object"]
    errors: list[str] = []
    for label in ("goodware", "malware"):
        entry = review.get(label)
        if not isinstance(entry, dict):
            errors.append(f"{path}: label_review.{label} must be an object")
            continue
        if entry.get("status") != "pending_governed_review":
            errors.append(f"{path}: label_review.{label}.status must be pending_governed_review")
        if entry.get("review_required_for_public_metrics") is not True:
            errors.append(f"{path}: label_review.{label}.review_required_for_public_metrics must be true")
        if entry.get("review_complete") is not False:
            errors.append(f"{path}: label_review.{label}.review_complete must be false until governed review is attached")
        if not isinstance(entry.get("review_artifact_ref"), str) or not entry["review_artifact_ref"]:
            errors.append(f"{path}: label_review.{label}.review_artifact_ref must be present")
    return errors


def validate_sample_accounting(path: Path, samples: Any) -> list[str]:
    if not isinstance(samples, dict):
        return [f"{path}: sample_accounting must be an object"]
    errors: list[str] = []
    for label in ("goodware", "malware"):
        actual = non_negative_integer(samples.get(f"{label}_samples"))
        minimum = non_negative_integer(samples.get(f"minimum_{label}_samples"))
        if actual is None:
            errors.append(f"{path}: sample_accounting.{label}_samples must be a non-negative integer")
        if minimum is None:
            errors.append(f"{path}: sample_accounting.minimum_{label}_samples must be a non-negative integer")
        if actual is not None and minimum is not None and actual < minimum:
            errors.append(f"{path}: sample_accounting.{label}_samples must meet minimum_{label}_samples")
        promotion_minimum = non_negative_integer(samples.get(f"promotion_minimum_{label}_samples"))
        if promotion_minimum is None or promotion_minimum < 1000:
            errors.append(
                f"{path}: sample_accounting.promotion_minimum_{label}_samples must be a non-negative integer at least 1000"
            )
    if samples.get("dedupe_key") != "sha256":
        errors.append(f"{path}: sample_accounting.dedupe_key must be sha256")
    if not isinstance(samples.get("sample_count_source"), str) or not samples["sample_count_source"]:
        errors.append(f"{path}: sample_accounting.sample_count_source must be present")
    return errors


def validate_dedupe(path: Path, dedupe: Any, samples: Any) -> list[str]:
    if not isinstance(dedupe, dict):
        return [f"{path}: dedupe must be an object"]
    sample_data = samples if isinstance(samples, dict) else {}
    errors: list[str] = []
    if dedupe.get("key") != "sha256":
        errors.append(f"{path}: dedupe.key must be sha256")
    if dedupe.get("status") != "local_bootstrap_deduped_not_governed":
        errors.append(f"{path}: dedupe.status must be local_bootstrap_deduped_not_governed")
    if dedupe.get("required_for_public_metrics") is not True:
        errors.append(f"{path}: dedupe.required_for_public_metrics must be true")
    duplicate_count = number(dedupe.get("duplicate_count"))
    if duplicate_count is None or duplicate_count != 0:
        errors.append(f"{path}: dedupe.duplicate_count must be 0 for the current fixture")
    unique_goodware = number(dedupe.get("unique_goodware_samples"))
    unique_malware = number(dedupe.get("unique_malware_samples"))
    if unique_goodware != number(sample_data.get("goodware_samples")):
        errors.append(f"{path}: dedupe.unique_goodware_samples must match sample_accounting.goodware_samples")
    if unique_malware != number(sample_data.get("malware_samples")):
        errors.append(f"{path}: dedupe.unique_malware_samples must match sample_accounting.malware_samples")
    if not isinstance(dedupe.get("dedupe_report_ref"), str) or not dedupe["dedupe_report_ref"]:
        errors.append(f"{path}: dedupe.dedupe_report_ref must be present")
    return errors


def validate_thresholds(path: Path, thresholds: Any) -> list[str]:
    if not isinstance(thresholds, dict):
        return [f"{path}: thresholds must be an object"]
    errors: list[str] = []
    if number(thresholds.get("score_threshold")) is None:
        errors.append(f"{path}: thresholds.score_threshold must be numeric")
    if thresholds.get("score_orientation") != "inverted_selected":
        errors.append(f"{path}: thresholds.score_orientation must preserve the calibrated inverted_selected orientation")
    if thresholds.get("threshold_locked") is not True:
        errors.append(f"{path}: thresholds.threshold_locked must be true")
    if thresholds.get("threshold_change_requires_new_gate") is not True:
        errors.append(f"{path}: thresholds.threshold_change_requires_new_gate must be true")
    if not isinstance(thresholds.get("threshold_source"), str) or not thresholds["threshold_source"]:
        errors.append(f"{path}: thresholds.threshold_source must be present")
    if not isinstance(thresholds.get("threshold_record_id"), str) or not thresholds["threshold_record_id"]:
        errors.append(f"{path}: thresholds.threshold_record_id must be present")
    digest_material = thresholds.get("threshold_record_digest_material")
    record_hash = thresholds.get("threshold_record_sha256")
    if not isinstance(digest_material, str) or not digest_material:
        errors.append(f"{path}: thresholds.threshold_record_digest_material must be present")
    if not isinstance(record_hash, str) or len(record_hash) != 64 or any(ch not in "0123456789abcdef" for ch in record_hash):
        errors.append(f"{path}: thresholds.threshold_record_sha256 must be a lowercase sha256")
    elif isinstance(digest_material, str) and hashlib.sha256(digest_material.encode()).hexdigest() != record_hash:
        errors.append(f"{path}: thresholds.threshold_record_sha256 must match threshold_record_digest_material")
    if thresholds.get("mutation_policy") != "immutable_requires_new_gate_artifact":
        errors.append(f"{path}: thresholds.mutation_policy must be immutable_requires_new_gate_artifact")
    return errors


def validate_outcomes(path: Path, outcomes: Any, samples: Any) -> list[str]:
    if not isinstance(outcomes, dict):
        return [f"{path}: outcomes must be an object"]
    sample_data = samples if isinstance(samples, dict) else {}
    errors: list[str] = []
    fp = number(outcomes.get("false_positives"))
    fn = number(outcomes.get("false_negatives"))
    max_fp = number(outcomes.get("maximum_false_positives"))
    max_fn = number(outcomes.get("maximum_false_negatives"))
    fpr = number(outcomes.get("fpr"))
    fnr = number(outcomes.get("fnr"))
    max_fpr = number(outcomes.get("maximum_fpr"))
    max_fnr = number(outcomes.get("maximum_fnr"))
    goodware_samples = number(sample_data.get("goodware_samples"))
    malware_samples = number(sample_data.get("malware_samples"))

    if fp is None or max_fp is None or fp > max_fp:
        errors.append(f"{path}: outcomes.false_positives exceed maximum_false_positives")
    if fn is None or max_fn is None or fn > max_fn:
        errors.append(f"{path}: outcomes.false_negatives exceed maximum_false_negatives")
    if fpr is None or max_fpr is None or fpr > max_fpr:
        errors.append(f"{path}: outcomes.fpr exceeds maximum_fpr")
    if fnr is None or max_fnr is None or fnr > max_fnr:
        errors.append(f"{path}: outcomes.fnr exceeds maximum_fnr")
    if fp is not None and goodware_samples:
        expected_fpr = fp / goodware_samples
        if fpr is None or abs(fpr - expected_fpr) > 0.000001:
            errors.append(f"{path}: outcomes.fpr must equal false_positives / goodware_samples")
    if fn is not None and malware_samples:
        expected_fnr = fn / malware_samples
        if fnr is None or abs(fnr - expected_fnr) > 0.000001:
            errors.append(f"{path}: outcomes.fnr must equal false_negatives / malware_samples")
    if not isinstance(outcomes.get("outcome_source"), str) or not outcomes["outcome_source"]:
        errors.append(f"{path}: outcomes.outcome_source must be present")
    return errors


def validate_confidence_intervals(path: Path, intervals: Any) -> list[str]:
    if not isinstance(intervals, dict):
        return [f"{path}: confidence_intervals must be an object"]
    errors: list[str] = []
    for metric in PUBLIC_METRIC_NAMES:
        entry = intervals.get(metric)
        if not isinstance(entry, dict):
            errors.append(f"{path}: confidence_intervals.{metric} must be an object")
            continue
        if entry.get("status") != "not_computed_bootstrap_public_claim_blocked":
            errors.append(f"{path}: confidence_intervals.{metric}.status must block public claims until computed")
        if entry.get("required_for_public_claim") is not True:
            errors.append(f"{path}: confidence_intervals.{metric}.required_for_public_claim must be true")
        if entry.get("lower") is not None or entry.get("upper") is not None:
            errors.append(f"{path}: confidence_intervals.{metric} bounds must remain null until governed computation")
        if not isinstance(entry.get("method_placeholder"), str) or not entry["method_placeholder"]:
            errors.append(f"{path}: confidence_intervals.{metric}.method_placeholder must be present")
    return errors


def validate_retained_critical(path: Path, retained: Any) -> list[str]:
    if not isinstance(retained, dict):
        return [f"{path}: retained_critical_scenarios must be an object"]
    errors: list[str] = []
    count = number(retained.get("scenario_count"))
    minimum_count = number(retained.get("minimum_scenario_count"))
    rate = number(retained.get("retention_rate"))
    minimum_rate = number(retained.get("minimum_retention_rate"))
    if count is None or minimum_count is None or count < minimum_count:
        errors.append(f"{path}: retained_critical_scenarios.scenario_count must meet minimum_scenario_count")
    if rate is None or minimum_rate is None or rate < minimum_rate:
        errors.append(f"{path}: retained_critical_scenarios.retention_rate must meet minimum_retention_rate")
    if not isinstance(retained.get("scenario_sources"), list) or not retained["scenario_sources"]:
        errors.append(f"{path}: retained_critical_scenarios.scenario_sources must be non-empty")
    missing_families = sorted(REQUIRED_CRITICAL_FAMILIES - string_set(retained.get("required_scenario_families")))
    if missing_families:
        errors.append(f"{path}: retained_critical_scenarios.required_scenario_families missing {missing_families}")
    return errors


def validate_promotion(path: Path, promotion: Any, data: dict[str, Any]) -> list[str]:
    if not isinstance(promotion, dict):
        return [f"{path}: claim_promotion_requirements must be an object"]
    errors: list[str] = []
    if promotion.get("minimum_required_evidence_class") != "governed_holdout":
        errors.append(f"{path}: claim_promotion_requirements.minimum_required_evidence_class must be governed_holdout")
    if promotion.get("live_or_governed_evidence_required") is not True:
        errors.append(f"{path}: claim_promotion_requirements.live_or_governed_evidence_required must be true")
    if set(promotion.get("public_metric_names") or []) != PUBLIC_METRIC_NAMES:
        errors.append(f"{path}: claim_promotion_requirements.public_metric_names must be ['fnr', 'fpr']")
    if set(promotion.get("public_fpr_fnr_requires_evidence_class") or []) != PROMOTABLE_EVIDENCE_CLASSES:
        errors.append(
            f"{path}: claim_promotion_requirements.public_fpr_fnr_requires_evidence_class must require governed_holdout and production_telemetry"
        )
    for field in (
        "public_metric_claims_blocked_without_minimum_sample_size",
        "public_metric_claims_blocked_without_reviewed_labels",
        "public_metric_claims_blocked_without_dedupe",
        "public_metric_claims_blocked_without_confidence_intervals",
        "public_metric_claims_blocked_without_dataset_provenance",
        "public_metric_claims_blocked_without_threshold_immutability",
    ):
        if promotion.get(field) is not True:
            errors.append(f"{path}: claim_promotion_requirements.{field} must be true")
    missing_artifacts = sorted(REQUIRED_PROMOTION_ARTIFACTS - string_set(promotion.get("required_artifacts")))
    if missing_artifacts:
        errors.append(f"{path}: claim_promotion_requirements.required_artifacts missing {missing_artifacts}")
    missing_claims = sorted(REQUIRED_BLOCKED_CLAIMS - string_set(promotion.get("blocked_claims")))
    if missing_claims:
        errors.append(f"{path}: claim_promotion_requirements.blocked_claims missing {missing_claims}")
    satisfied = string_set(promotion.get("satisfied_artifacts"))
    forbidden_satisfied = REQUIRED_PROMOTION_ARTIFACTS & satisfied
    if forbidden_satisfied:
        errors.append(
            f"{path}: claim_promotion_requirements.satisfied_artifacts must not satisfy governed promotion artifacts without live verification {sorted(forbidden_satisfied)}"
        )
    if data.get("external_claim_allowed") is not False and data.get("evidence_class") not in PROMOTABLE_EVIDENCE_CLASSES:
        errors.append(f"{path}: public FPR/FNR claims require governed_holdout or production_telemetry evidence")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()

    errors, summary = validate_gate(args.fixture)
    if errors:
        for error in errors:
            print(error)
        return 1

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
