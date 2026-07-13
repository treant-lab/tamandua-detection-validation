#!/usr/bin/env python3
"""Guard defensive driver/kernel containment roadmap claims.

This validator is intentionally document-level. It does not inspect endpoints,
load drivers, or exercise kernel controls. Its job is to keep roadmap language
bounded until runtime, lab, rollback, and platform evidence exist.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]


DEFAULT_ROADMAP = ROOT / "docs" / "planejamento" / "DRIVER_KERNEL_CONTAINMENT_ROADMAP.md"

REQUIRED_SECTIONS = [
    "## Product Boundary",
    "## Defensive Model",
    "## Windows Roadmap",
    "## Linux Roadmap",
    "## macOS Roadmap",
    "## Cross-Platform Capability Matrix",
    "## Tamandua Work Packages",
    "## Validation Gates",
]

REQUIRED_BOUNDARY_PHRASES = [
    "not production validated",
    "defensive research only",
    "must not claim reliable safe unloading",
    "It is not kernel malware removal",
    "not a product claim",
    "rebuild",
]

FORBIDDEN_OVERCLAIMS = [
    "provides guaranteed kernel malware removal",
    "offers guaranteed kernel malware removal",
    "guarantees rootkit removal",
    "production-ready kernel malware removal",
    "production validated kernel malware removal",
    "safely unloads malicious drivers",
    "bypass-resistant kernel detection",
]

REQUIRED_WORK_PACKAGES = ["Phase A", "Phase B", "Phase C", "Phase D"]

MOBILE_SHIELDING_CLAIMS = [
    "sdk shielding efficacy",
    "mobile shielding efficacy",
    "prevents frida",
    "blocks frida",
    "prevents magisk",
    "blocks magisk",
    "prevents zygisk",
    "blocks zygisk",
    "tamper-proof mobile",
]

KERNEL_SHIELDING_CLAIMS = [
    "kernel shielding efficacy",
    "driver shielding efficacy",
    "reliable kernel containment",
    "bypass-resistant kernel containment",
    "rootkit shielding",
]

REQUIRED_MOBILE_STRONG_CLAIM_EVIDENCE_CLASSES = [
    "live_signed_ingestion",
    "live_anti_replay_duplicate_rejection",
    "ios_native_build",
    "ios_xcframework",
    "physical_attack_lab",
]

ADEQUATE_KERNEL_SHIELDING_EVIDENCE_CLASSES = [
    "kernel_lab_runtime_evidence",
    "driver_rollback_evidence",
    "platform_runtime_evidence",
    "governed_holdout",
    "production_telemetry",
]


def validate_text(text: str, source: Path) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    lower = text.lower()

    missing_sections = [section for section in REQUIRED_SECTIONS if section not in text]
    if missing_sections:
        errors.append(f"{source}: missing required sections {missing_sections}")

    missing_phrases = [phrase for phrase in REQUIRED_BOUNDARY_PHRASES if phrase.lower() not in lower]
    if missing_phrases:
        errors.append(f"{source}: missing boundary phrases {missing_phrases}")

    present_overclaims = [phrase for phrase in FORBIDDEN_OVERCLAIMS if phrase.lower() in lower]
    if present_overclaims:
        errors.append(f"{source}: forbidden overclaims present {present_overclaims}")

    missing_packages = [phase for phase in REQUIRED_WORK_PACKAGES if phase not in text]
    if missing_packages:
        errors.append(f"{source}: missing work-package phases {missing_packages}")

    mobile_claims = [phrase for phrase in MOBILE_SHIELDING_CLAIMS if phrase in lower]
    missing_mobile_evidence = [
        term for term in REQUIRED_MOBILE_STRONG_CLAIM_EVIDENCE_CLASSES if term not in lower
    ]
    if mobile_claims and missing_mobile_evidence:
        errors.append(
            f"{source}: mobile shielding claims {mobile_claims} require evidence class "
            f"{REQUIRED_MOBILE_STRONG_CLAIM_EVIDENCE_CLASSES}; missing {missing_mobile_evidence}"
        )

    kernel_claims = [phrase for phrase in KERNEL_SHIELDING_CLAIMS if phrase in lower]
    if kernel_claims and not any(term in lower for term in ADEQUATE_KERNEL_SHIELDING_EVIDENCE_CLASSES):
        errors.append(
            f"{source}: kernel shielding claims {kernel_claims} require evidence class "
            f"{ADEQUATE_KERNEL_SHIELDING_EVIDENCE_CLASSES}"
        )

    summary = {
        "roadmap": str(source),
        "required_sections": len(REQUIRED_SECTIONS),
        "boundary_phrases": len(REQUIRED_BOUNDARY_PHRASES),
        "forbidden_overclaims_absent": not present_overclaims,
        "work_package_phases": len(REQUIRED_WORK_PACKAGES) - len(missing_packages),
        "evidence_class": "roadmap_claim_boundary",
        "strong_claims_checked": {
            "mobile_shielding": len(mobile_claims),
            "kernel_shielding": len(kernel_claims),
        },
        "required_mobile_strong_claim_evidence_classes": REQUIRED_MOBILE_STRONG_CLAIM_EVIDENCE_CLASSES,
    }
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roadmap", type=Path, default=DEFAULT_ROADMAP)
    args = parser.parse_args()

    text = args.roadmap.read_text(encoding="utf-8")
    errors, summary = validate_text(text, args.roadmap)
    if errors:
        for error in errors:
            print(error)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
