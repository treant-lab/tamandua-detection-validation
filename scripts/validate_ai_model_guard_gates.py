#!/usr/bin/env python3
"""Validate AI Model Guard benchmark coverage and claim gates.

This gate is offline-only. It reads the current scorecard, validation JSON, and
coverage-plan markdown, then emits an honest status without downloading models
or executing scanner/runtime code.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, is_standalone
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    is_standalone = lambda: False

REPO_ROOT = ROOT.parent.parent if is_standalone() else ROOT
DEFAULT_SCORECARD = REPO_ROOT / "docs" / "benchmarks" / "AI_MODEL_SCANNER_SCORECARD.md"
DEFAULT_COVERAGE_PLAN = REPO_ROOT / "docs" / "ai-security" / "AI_MODEL_GUARD_BENCHMARK_MATRIX.md"
DEFAULT_VALIDATION_DIR = REPO_ROOT / "docs" / "benchmarks"
DEFAULT_VALIDATION_GLOB = "AI_MODEL_SCANNER_VALIDATION_*.json"
API_VERSION = "tamandua.io/ai-model-guard-gate-report/v1"
KIND = "AiModelGuardGateReport"
VALIDATION_NAME_PATTERN = re.compile(r"^AI_MODEL_SCANNER_VALIDATION_(?P<stamp>\d{8}T\d{6}Z)\.json$")
EVIDENCE_CLASSES = {
    "smoke",
    "synthetic_parity",
    "bootstrap_calibration",
    "governed_holdout",
    "production_telemetry",
}
SMOKE_CLAIM = "small-corpus smoke/regression only"
KNOWN_SIGNATURE_PATTERNS = {
    "format_confusion": re.compile(r"format confusion|disguised", re.I),
    "unsafe_deserialization": re.compile(r"(code execution|os\.system|pickle)", re.I),
    "template_code_execution": re.compile(r"(cve-2024-34359|jinja)", re.I),
    "external_reference": re.compile(r"external data|external ref|path traversal", re.I),
    "parser_dos": re.compile(r"dos|compression|truncated|bomb", re.I),
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def parse_scorecard_source(scorecard: Path) -> Path | None:
    text = scorecard.read_text(encoding="utf-8")
    match = re.search(r"Source artifact:\s*`([^`]+)`", text)
    if not match:
        return None
    return (REPO_ROOT / match.group(1)).resolve()


def validation_sort_key(path: Path) -> tuple[str, str]:
    match = VALIDATION_NAME_PATTERN.match(path.name)
    stamp = match.group("stamp") if match else ""
    return stamp, path.name


def latest_validation_json(directory: Path = DEFAULT_VALIDATION_DIR) -> Path:
    candidates = sorted(directory.glob(DEFAULT_VALIDATION_GLOB), key=validation_sort_key, reverse=True)
    if not candidates:
        raise FileNotFoundError(f"{repo_rel(directory)}: no {DEFAULT_VALIDATION_GLOB} files found")
    return candidates[0].resolve()


def parse_int_cell(value: str) -> int:
    match = re.search(r"\d+", value)
    if not match:
        raise ValueError(f"cannot parse integer target from {value!r}")
    return int(match.group(0))


def parse_coverage_plan(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for required in [
        "## Evidence Classes",
        "## Corpus Matrix",
        "## Gates",
        "## Threshold Policy",
        "## Promotion Rules",
    ]:
        if required not in text:
            errors.append(f"{repo_rel(path)}: missing required coverage-plan section {required!r}")

    formats: dict[str, dict[str, int]] = {}
    in_matrix = False
    for line in text.splitlines():
        if line.startswith("## Corpus Matrix"):
            in_matrix = True
            continue
        if in_matrix and line.startswith("## "):
            break
        if not in_matrix or not line.startswith("|") or "---" in line:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[0].lower() == "format":
            continue
        fmt = cells[0].replace("`", "")
        if fmt.startswith("TensorFlow"):
            fmt = "savedmodel"
        else:
            fmt = fmt.split(",")[0].strip().lower()
        try:
            benign_target = parse_int_cell(cells[1])
            synthetic_target = parse_int_cell(cells[2])
            real_defanged_target = parse_int_cell(cells[3])
        except ValueError as exc:
            errors.append(f"{repo_rel(path)}: {exc}")
            continue
        formats[fmt] = {
            "benign_target": benign_target,
            "synthetic_adversarial_target": synthetic_target,
            "real_defanged_target": real_defanged_target,
            "adversarial_target": synthetic_target + real_defanged_target,
        }
    if not formats:
        errors.append(f"{repo_rel(path)}: coverage-plan corpus matrix must include format targets")

    evidence_text = ""
    evidence_match = re.search(r"## Evidence Classes\n(?P<body>.*?)(?:\n## |\Z)", text, re.S)
    if evidence_match:
        evidence_text = evidence_match.group("body")
    evidence_classes = set(re.findall(r"\|\s*`([^`]+)`\s*\|", evidence_text))
    missing_evidence = {
        "synthetic_smoke",
        "hf_hot_benign",
        "framework_benign",
        "adversarial_synthetic",
        "adversarial_real_defanged",
        "holdout",
    } - evidence_classes
    if missing_evidence:
        errors.append(f"{repo_rel(path)}: missing evidence-class rows {sorted(missing_evidence)}")

    return {
        "path": repo_rel(path),
        "formats": formats,
        "errors": errors,
        "documented_evidence_classes": sorted(evidence_classes),
    }


def scanner_flagged(scanner_result: Any) -> bool:
    return isinstance(scanner_result, dict) and scanner_result.get("flagged") is True


def sample_flagged(sample: dict[str, Any]) -> bool:
    scanners = sample.get("scanners")
    if not isinstance(scanners, dict):
        return False
    return any(scanner_flagged(result) for result in scanners.values())


def count_outcomes(
    samples: list[dict[str, Any]], scanner_outcomes_available: bool = True
) -> dict[str, int | float | None]:
    malicious = [sample for sample in samples if sample.get("type") == "malicious"]
    clean = [sample for sample in samples if sample.get("type") == "clean"]
    if not scanner_outcomes_available:
        return {
            "tp": None,
            "tn": None,
            "fp": None,
            "fn": None,
            "malicious_total": len(malicious),
            "benign_total": len(clean),
            "fpr": None,
            "fnr": None,
        }
    tp = sum(1 for sample in malicious if sample_flagged(sample))
    fn = len(malicious) - tp
    fp = sum(1 for sample in clean if sample_flagged(sample))
    tn = len(clean) - fp
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "malicious_total": len(malicious),
        "benign_total": len(clean),
        "fpr": fp / len(clean) if clean else None,
        "fnr": fn / len(malicious) if malicious else None,
    }


def normalize_manifest_sample(sample: dict[str, Any]) -> dict[str, Any]:
    label = sample.get("label")
    sample_type = "clean" if label == "benign" else "malicious" if label == "adversarial" else None
    return {
        "name": sample.get("sample_id"),
        "type": sample_type,
        "format": sample.get("format"),
        "attack_family": sample.get("attack_family"),
        "sha256": sample.get("sha256"),
        "path": sample.get("path"),
        "scanners": sample.get("scanners"),
    }


def load_validation_samples(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    results = load_json(path)
    samples = results.get("samples")
    if not isinstance(samples, list) or not all(isinstance(sample, dict) for sample in samples):
        raise ValueError(f"{repo_rel(path)}: samples must be a list of objects")
    return results, samples, "validation_json"


def load_manifest_samples(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    manifest = load_json(path)
    samples = manifest.get("samples")
    if not isinstance(samples, list) or not all(isinstance(sample, dict) for sample in samples):
        raise ValueError(f"{repo_rel(path)}: samples must be a list of objects")

    errors: list[str] = []
    normalized: list[dict[str, Any]] = []
    required_fields = {"sample_id", "format", "label", "attack_family", "sha256", "path"}
    seen: set[str] = set()
    for index, sample in enumerate(samples):
        missing = sorted(field for field in required_fields if field not in sample)
        if missing:
            errors.append(f"{repo_rel(path)}.samples[{index}]: missing required fields {missing}")
            continue
        sample_id = sample.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            errors.append(f"{repo_rel(path)}.samples[{index}].sample_id: must be a non-empty string")
        elif sample_id in seen:
            errors.append(f"{repo_rel(path)}.samples[{index}].sample_id: duplicate sample_id {sample_id!r}")
        else:
            seen.add(sample_id)
        if sample.get("label") not in {"benign", "adversarial"}:
            errors.append(f"{repo_rel(path)}.samples[{index}].label: must be benign or adversarial")
        if not isinstance(sample.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", str(sample.get("sha256"))):
            errors.append(f"{repo_rel(path)}.samples[{index}].sha256: must be lowercase SHA-256 hex")
        if not isinstance(sample.get("path"), str) or not sample.get("path"):
            errors.append(f"{repo_rel(path)}.samples[{index}].path: must be a non-empty string")
        normalized.append(normalize_manifest_sample(sample))

    if errors:
        raise ValueError("\n".join(errors))
    return manifest, normalized, "manifest"


def classify_evidence(samples: list[dict[str, Any]], results: dict[str, Any]) -> str:
    classes = {sample.get("evidence_class") for sample in samples if isinstance(sample.get("evidence_class"), str)}
    splits = {sample.get("split") for sample in samples if isinstance(sample.get("split"), str)}
    has_hashes = bool(samples) and all(isinstance(sample.get("sha256"), str) for sample in samples)
    if classes == {"production_telemetry"}:
        return "production_telemetry"
    if "holdout" in splits and has_hashes:
        return "governed_holdout"
    if "calibration" in splits or isinstance(results.get("thresholds"), dict):
        return "bootstrap_calibration"
    if classes and classes <= {"synthetic_smoke", "adversarial_synthetic", "framework_benign"}:
        return "synthetic_parity"
    return "smoke"


def known_signature_misses(samples: list[dict[str, Any]], scanner_outcomes_available: bool = True) -> list[dict[str, str]]:
    if not scanner_outcomes_available:
        return []
    misses: list[dict[str, str]] = []
    for sample in samples:
        if sample.get("type") != "malicious":
            continue
        attack_text = f"{sample.get('attack', '')} {sample.get('attack_family', '')} {sample.get('name', '')}"
        family = None
        for candidate, pattern in KNOWN_SIGNATURE_PATTERNS.items():
            if pattern.search(attack_text):
                family = candidate
                break
        if family and not sample_flagged(sample):
            misses.append(
                {
                    "sample_id": str(sample.get("name") or "<unnamed>"),
                    "attack_family": family,
                    "reason": "known signature sample was not flagged by any scanner",
                }
            )
    return misses


def coverage_accounting(
    samples: list[dict[str, Any]], plan: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for sample in samples:
        fmt = str(sample.get("format") or "unknown").lower()
        label = "benign" if sample.get("type") == "clean" else "adversarial"
        counts[fmt][label] += 1

    by_format: dict[str, Any] = {}
    blockers: list[dict[str, Any]] = []
    for fmt, targets in sorted(plan.get("formats", {}).items()):
        current = counts.get(fmt, Counter())
        benign = int(current.get("benign", 0))
        adversarial = int(current.get("adversarial", 0))
        benign_gap = max(0, int(targets["benign_target"]) - benign)
        adversarial_gap = max(0, int(targets["adversarial_target"]) - adversarial)
        by_format[fmt] = {
            "benign": benign,
            "adversarial": adversarial,
            "benign_target": targets["benign_target"],
            "adversarial_target": targets["adversarial_target"],
            "benign_gap": benign_gap,
            "adversarial_gap": adversarial_gap,
            "fpr_claim_allowed": benign >= 30,
            "fnr_claim_allowed": adversarial >= 20,
        }
        if benign_gap:
            blockers.append({"format": fmt, "gate": "benign_coverage", "missing_samples": benign_gap})
        if adversarial_gap:
            blockers.append({"format": fmt, "gate": "adversarial_coverage", "missing_samples": adversarial_gap})
    return by_format, blockers


def validate_scorecard(scorecard: Path, results_path: Path | None, results: dict[str, Any]) -> list[str]:
    text = scorecard.read_text(encoding="utf-8")
    errors: list[str] = []
    required_phrases = [
        "small-corpus",
        "smoke/regression",
        "not production-ready",
    ]
    lower_text = text.lower()
    for phrase in required_phrases:
        if phrase not in lower_text:
            errors.append(f"{repo_rel(scorecard)}: scorecard must preserve {phrase!r} claim boundary")

    if results_path is not None:
        expected_source = repo_rel(results_path)
        if expected_source not in text:
            errors.append(f"{repo_rel(scorecard)}: scorecard must reference source artifact {expected_source}")

    corpus = results.get("corpus")
    if isinstance(corpus, dict):
        malicious = corpus.get("malicious_count")
        clean = corpus.get("clean_count")
        if f"`{malicious}` malicious" not in text and f"{malicious} malicious" not in text:
            errors.append(f"{repo_rel(scorecard)}: scorecard must mention {malicious} malicious samples")
        if f"`{clean}` clean" not in text and f"{clean} clean" not in text:
            errors.append(f"{repo_rel(scorecard)}: scorecard must mention {clean} clean samples")
    return errors


def build_report(
    scorecard: Path,
    coverage_plan: Path,
    results_path: Path,
    *,
    source_kind: str = "validation_json",
    require_scorecard_source_ref: bool = True,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    try:
        if source_kind == "manifest":
            results, samples, loaded_source_kind = load_manifest_samples(results_path)
        else:
            results, samples, loaded_source_kind = load_validation_samples(results_path)
    except ValueError as exc:
        return str(exc).splitlines(), {}

    plan = parse_coverage_plan(coverage_plan)
    errors.extend(plan["errors"])
    scorecard_source = results_path if loaded_source_kind != "manifest" and require_scorecard_source_ref else None
    errors.extend(validate_scorecard(scorecard, scorecard_source, results))

    corpus = results.get("corpus") if isinstance(results.get("corpus"), dict) else {}
    declared_malicious = corpus.get("malicious_count")
    declared_clean = corpus.get("clean_count")
    observed_malicious = sum(1 for sample in samples if sample.get("type") == "malicious")
    observed_clean = sum(1 for sample in samples if sample.get("type") == "clean")
    if loaded_source_kind == "manifest":
        declared_malicious = observed_malicious
        declared_clean = observed_clean
    if declared_malicious != observed_malicious:
        errors.append(f"{repo_rel(results_path)}: corpus.malicious_count must equal observed malicious samples")
    if declared_clean != observed_clean:
        errors.append(f"{repo_rel(results_path)}: corpus.clean_count must equal observed clean samples")

    evidence_class = classify_evidence(samples, results)
    if evidence_class not in EVIDENCE_CLASSES:
        errors.append(f"{repo_rel(results_path)}: invalid evidence class {evidence_class}")
    scanner_outcomes_available = loaded_source_kind == "validation_json"
    outcomes = count_outcomes(samples, scanner_outcomes_available)
    known_misses = known_signature_misses(samples, scanner_outcomes_available)
    by_format, coverage_blockers = coverage_accounting(samples, plan)

    blocker_reasons = []
    if loaded_source_kind == "manifest" and not scanner_outcomes_available:
        blocker_reasons.append("manifest_only_without_scanner_outcomes")
    if evidence_class != "governed_holdout" and evidence_class != "production_telemetry":
        blocker_reasons.append("evidence_class_below_governed_holdout")
    if outcomes["benign_total"] < 300:
        blocker_reasons.append("overall_benign_sample_count_below_300")
    if outcomes["malicious_total"] < 150:
        blocker_reasons.append("overall_adversarial_sample_count_below_150")
    if outcomes["fnr"] is not None and outcomes["fnr"] > 0.05:
        blocker_reasons.append("overall_fnr_above_5_percent")
    if known_misses:
        blocker_reasons.append("known_signature_fn")
    if coverage_blockers:
        blocker_reasons.append("coverage_plan_minimums_not_met")

    gate_status = "production_claim_ready" if not blocker_reasons else "blocked_for_production_claim"
    report = {
        "api_version": API_VERSION,
        "kind": KIND,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gate_status": gate_status,
        "external_claim_allowed": gate_status == "production_claim_ready",
        "local_gate_runnable": True,
        "claim_boundary": SMOKE_CLAIM if gate_status != "production_claim_ready" else "governed holdout metrics claimable",
        "evidence": {
            "class": evidence_class,
            "class_reason": evidence_reason(evidence_class),
            "source_artifacts": [repo_rel(scorecard), repo_rel(coverage_plan), repo_rel(results_path)],
            "source_kind": loaded_source_kind,
        },
        "sample_accounting": {
            "declared_malicious": declared_malicious,
            "declared_benign": declared_clean,
            "observed_malicious": observed_malicious,
            "observed_benign": observed_clean,
            "total_samples": len(samples),
        },
        "outcomes": outcomes,
        "coverage_plan": {
            "path": plan["path"],
            "formats": by_format,
            "coverage_blockers": coverage_blockers,
            "documented_evidence_classes": plan["documented_evidence_classes"],
        },
        "known_signature_gate": {
            "require_zero_known_signature_fn": True,
            "misses": known_misses,
            "passed": not known_misses,
        },
        "promotion_blockers": sorted(set(blocker_reasons)),
        "claimable_status": (
            "current artifacts support smoke/regression tracking only"
            if gate_status != "production_claim_ready"
            else "current artifacts meet configured production-claim gates"
        ),
    }
    return errors, report


def evidence_reason(evidence_class: str) -> str:
    return {
        "smoke": "current validation JSON lacks frozen hashes, governed splits, and holdout lineage",
        "synthetic_parity": "samples are synthetic fixtures without governed holdout lineage",
        "bootstrap_calibration": "calibration or threshold evidence is present but not governed holdout",
        "governed_holdout": "samples include holdout split and hashes",
        "production_telemetry": "samples are classified as production telemetry",
    }[evidence_class]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scorecard", type=Path, default=DEFAULT_SCORECARD)
    parser.add_argument("--coverage-plan", type=Path, default=DEFAULT_COVERAGE_PLAN)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--validation-json", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--fail-on-blocked",
        action="store_true",
        help="Return non-zero when the gate is honest but blocked for production claims.",
    )
    args = parser.parse_args()

    scorecard = args.scorecard.resolve()
    coverage_plan = args.coverage_plan.resolve()
    provided_inputs = [value is not None for value in (args.results, args.validation_json, args.manifest)]
    if sum(provided_inputs) > 1:
        print("provide only one of --results, --validation-json, or --manifest")
        return 1
    source_kind = "manifest" if args.manifest else "validation_json"
    require_scorecard_source_ref = False
    if args.manifest:
        results = args.manifest.resolve()
    elif args.validation_json:
        results = args.validation_json.resolve()
    elif args.results:
        results = args.results.resolve()
        require_scorecard_source_ref = True
    else:
        try:
            results = latest_validation_json()
        except FileNotFoundError:
            results = parse_scorecard_source(scorecard)
    if results is None:
        print(f"{repo_rel(scorecard)}: unable to find Source artifact in scorecard")
        return 1

    errors, report = build_report(
        scorecard,
        coverage_plan,
        results,
        source_kind=source_kind,
        require_scorecard_source_ref=require_scorecard_source_ref,
    )
    if errors:
        for error in errors:
            print(error)
        return 1

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if args.fail_on_blocked and report["gate_status"] != "production_claim_ready":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
