#!/usr/bin/env python3
"""Validate model package scanner smoke outcomes and claim gates.

This gate is offline-only. It reads model package scanner outcomes for a
minimum package corpus and emits TP/TN/FP/FN, fixture coverage, reproducible
commands, and conservative claim status. It does not execute package code,
download models, or inspect runtime artifacts.
"""

from __future__ import annotations

import argparse
import json
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
API_VERSION = "tamandua.io/model-package-scanner-gate/v1"
KIND = "ModelPackageScannerGateReport"
DEFAULT_INPUT = REPO_ROOT / "docs" / "benchmarks" / "model_package_scanner_smoke.example.json"
DEFAULT_SCHEMA = REPO_ROOT / "schemas" / "model_package_scanner_gate_v1.schema.json"
EVIDENCE_CLASSES = {
    "smoke",
    "synthetic_parity",
    "bootstrap_calibration",
    "governed_holdout",
    "production_telemetry",
}
PRODUCTION_READY_CLASSES = {"governed_holdout", "production_telemetry"}
REQUIRED_FIXTURE_CLASSES = {
    "benign_package",
    "reverse_shell",
    "persistence",
    "remote_code",
    "sidecar_injection",
}
MALICIOUS_LABELS = {"malicious", "malware", "adversarial", "positive"}
BENIGN_LABELS = {"benign", "goodware", "clean", "negative"}
POSITIVE_VERDICTS = {"malicious", "suspicious", "blocked", "block", "positive"}
NEGATIVE_VERDICTS = {"benign", "clean", "allowed", "allow", "negative"}


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{repo_rel(path)}: top-level JSON must be an object")
    return payload


def normalize_label(value: Any, sample_id: str) -> str:
    label = str(value or "").strip().lower()
    if label in MALICIOUS_LABELS:
        return "malicious"
    if label in BENIGN_LABELS:
        return "benign"
    raise ValueError(f"{sample_id}: label must be malicious/benign compatible, got {value!r}")


def normalize_verdict(value: Any, sample_id: str) -> str:
    verdict = str(value or "").strip().lower()
    if verdict in POSITIVE_VERDICTS:
        return "malicious"
    if verdict in NEGATIVE_VERDICTS:
        return "benign"
    raise ValueError(f"{sample_id}: verdict must be malicious/suspicious/benign compatible")


def normalize_evidence(raw: Any, sample_id: str) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{sample_id}: evidence must be a list when present")
    evidence: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"{sample_id}.evidence[{index}]: must be an object")
        evidence_class = str(item.get("class") or "").strip()
        if not evidence_class:
            raise ValueError(f"{sample_id}.evidence[{index}].class: required")
        evidence.append(
            {
                "class": evidence_class,
                "file": item.get("file"),
                "indicator": item.get("indicator"),
                "reason": item.get("reason"),
            }
        )
    return evidence


def normalize_samples(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_samples = payload.get("samples")
    if not isinstance(raw_samples, list) or not raw_samples:
        raise ValueError("samples must be a non-empty list")

    samples: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_samples):
        if not isinstance(raw, dict):
            raise ValueError(f"samples[{index}]: must be an object")
        sample_id = str(raw.get("sample_id") or raw.get("id") or raw.get("name") or "").strip()
        if not sample_id:
            raise ValueError(f"samples[{index}]: sample_id is required")
        if sample_id in seen_ids:
            raise ValueError(f"{sample_id}: duplicate sample_id")
        seen_ids.add(sample_id)
        fixture_class = str(raw.get("fixture_class") or "").strip().lower()
        if not fixture_class:
            raise ValueError(f"{sample_id}: fixture_class is required")
        label = normalize_label(raw.get("label") or raw.get("type"), sample_id)
        verdict = normalize_verdict(raw.get("verdict") or raw.get("scanner_verdict"), sample_id)
        samples.append(
            {
                "sample_id": sample_id,
                "fixture_class": fixture_class,
                "label": label,
                "verdict": verdict,
                "format": raw.get("format"),
                "package_kind": raw.get("package_kind"),
                "path": raw.get("path"),
                "evidence": normalize_evidence(raw.get("evidence"), sample_id),
            }
        )
    return samples


def empty_counts() -> dict[str, int]:
    return {"tp": 0, "tn": 0, "fp": 0, "fn": 0}


def add_outcome(counts: dict[str, int], label: str, verdict: str) -> str:
    if label == "malicious" and verdict == "malicious":
        counts["tp"] += 1
        return "tp"
    if label == "malicious":
        counts["fn"] += 1
        return "fn"
    if verdict == "malicious":
        counts["fp"] += 1
        return "fp"
    counts["tn"] += 1
    return "tn"


def finalize_counts(counts: dict[str, int]) -> dict[str, Any]:
    malicious_total = counts["tp"] + counts["fn"]
    benign_total = counts["tn"] + counts["fp"]
    return {
        **counts,
        "malicious_total": malicious_total,
        "benign_total": benign_total,
        "fpr": counts["fp"] / benign_total if benign_total else None,
        "fnr": counts["fn"] / malicious_total if malicious_total else None,
    }


def evidence_reason(evidence_class: str) -> str:
    return {
        "smoke": "minimum local package fixtures only; useful for regression, not production claims",
        "synthetic_parity": "synthetic package fixtures can test parity but lack governed holdout lineage",
        "bootstrap_calibration": "calibration evidence can guide thresholds but is not a governed holdout",
        "governed_holdout": "governed holdout evidence can support bounded claims when sample gates pass",
        "production_telemetry": "production telemetry can support operational claims when lineage and gates pass",
    }[evidence_class]


def default_commands(input_path: Path, output_path: Path | None) -> list[str]:
    command = (
        "python tools/detection_validation/scripts/validate_model_package_scanner_gate.py "
        f"--input {repo_rel(input_path)}"
    )
    if output_path is not None:
        command += f" --output {repo_rel(output_path)}"
    return [
        command,
        "python -m pytest tools/detection_validation/tests/test_validate_model_package_scanner_gate.py -q -o addopts=",
        "python -m json.tool docs/benchmarks/model_package_scanner_smoke.example.json > NUL",
        "python -m json.tool schemas/model_package_scanner_gate_v1.schema.json > NUL",
    ]


def build_report(input_path: Path, output_path: Path | None = None) -> dict[str, Any]:
    payload = load_json(input_path)
    evidence_class = str(payload.get("evidence_class") or "smoke").strip().lower()
    if evidence_class not in EVIDENCE_CLASSES:
        raise ValueError(f"{repo_rel(input_path)}: evidence_class must be one of {sorted(EVIDENCE_CLASSES)}")
    samples = normalize_samples(payload)

    counts = empty_counts()
    fixture_counts: Counter[str] = Counter()
    format_counts: dict[str, Counter[str]] = defaultdict(Counter)
    rows: list[dict[str, Any]] = []
    for sample in samples:
        outcome = add_outcome(counts, sample["label"], sample["verdict"])
        fixture_counts[sample["fixture_class"]] += 1
        fmt = str(sample.get("format") or "unknown").lower()
        format_counts[fmt][sample["label"]] += 1
        rows.append(
            {
                "sample_id": sample["sample_id"],
                "fixture_class": sample["fixture_class"],
                "label": sample["label"],
                "verdict": sample["verdict"],
                "outcome": outcome,
                "evidence_classes": sorted({item["class"] for item in sample["evidence"]}),
            }
        )

    missing_fixtures = sorted(REQUIRED_FIXTURE_CLASSES - set(fixture_counts))
    outcomes = finalize_counts(counts)
    blockers: list[str] = []
    if evidence_class not in PRODUCTION_READY_CLASSES:
        blockers.append("evidence_class_below_governed_holdout")
    if missing_fixtures:
        blockers.append("required_fixture_classes_missing")
    if outcomes["benign_total"] < 300:
        blockers.append("overall_benign_sample_count_below_300")
    if outcomes["malicious_total"] < 150:
        blockers.append("overall_malicious_sample_count_below_150")
    if outcomes["fpr"] is not None and outcomes["fpr"] > 0.02:
        blockers.append("overall_fpr_above_2_percent")
    if outcomes["fnr"] is not None and outcomes["fnr"] > 0.05:
        blockers.append("overall_fnr_above_5_percent")

    gate_status = "production_claim_ready" if not blockers else "blocked_for_production_claim"
    return {
        "api_version": API_VERSION,
        "kind": KIND,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gate_status": gate_status,
        "external_claim_allowed": gate_status == "production_claim_ready",
        "local_gate_runnable": True,
        "claim_boundary": (
            "model package scanner smoke/regression only"
            if gate_status != "production_claim_ready"
            else "governed model package scanner metrics claimable"
        ),
        "evidence": {
            "class": evidence_class,
            "class_reason": evidence_reason(evidence_class),
            "source_artifacts": [repo_rel(input_path)],
            "input_kind": "offline_model_package_scanner_results",
        },
        "scanner": {
            "name": payload.get("scanner") or "model_package_scanner",
            "mode": payload.get("mode") or "offline_static_package_scan",
            "enforcement": payload.get("enforcement") or "decision_only",
        },
        "sample_accounting": {
            "total_samples": len(samples),
            "malicious": outcomes["malicious_total"],
            "benign": outcomes["benign_total"],
            "formats": {
                key: {"malicious": int(value["malicious"]), "benign": int(value["benign"])}
                for key, value in sorted(format_counts.items())
            },
        },
        "fixture_coverage": {
            "required": sorted(REQUIRED_FIXTURE_CLASSES),
            "present": sorted(fixture_counts),
            "missing": missing_fixtures,
            "counts": dict(sorted(fixture_counts.items())),
        },
        "outcomes": outcomes,
        "sample_outcomes": rows,
        "reproducibility": {
            "commands": payload.get("reproducibility_commands") or default_commands(input_path, output_path),
            "schema": repo_rel(DEFAULT_SCHEMA),
        },
        "promotion_blockers": sorted(set(blockers)),
        "claimable_status": (
            "current artifacts support model package scanner smoke/regression tracking only"
            if gate_status != "production_claim_ready"
            else "current artifacts meet configured model package scanner gates"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--fail-on-blocked",
        action="store_true",
        help="Return non-zero when the gate is valid but blocked for production claims.",
    )
    args = parser.parse_args()

    try:
        report = build_report(args.input.resolve(), args.output.resolve() if args.output else None)
    except ValueError as exc:
        print(str(exc))
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
