#!/usr/bin/env python3
"""Guard public ML wording against production overclaims."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


DEFAULT_PUBLIC_FILES = [
    ROOT / "README.md",
    ROOT / "docs/KNOWN_PRODUCTION_GAPS.md",
    ROOT / "docs/hackathon/KNOWN_GAPS.md",
    ROOT / "docs/hackathon/README_HACKATHON.md",
    ROOT / "docs/hackathon/SUBMISSION_BRIEF.md",
    ROOT / "docs/benchmarks/ML_TRAINING_PIPELINE_ROADMAP.md",
    ROOT / "website/src/content/docs/detection/index.md",
    ROOT / "website/src/content/docs/detection/ml-detection.md",
    ROOT / "website/src/content/docs/getting-started/index.md",
    ROOT / "website/src/content/docs/getting-started/architecture.md",
    ROOT / "website/src/content/docs/getting-started/system-requirements.md",
    ROOT / "website/src/content/docs/roadmap/known-production-gaps.md",
    ROOT / "website/src/content/docs/troubleshooting/faq.md",
    ROOT / "website/src/components/FeatureGrid.astro",
    ROOT / "website/src/pages/features.astro",
]


BANNED_PHRASES = {
    "ml-powered": "Use ML-assisted/scoring wording until ML-1..ML-6 production benchmarks exist.",
    "machine learning-powered malware detection": "Use ML-assisted scoring wording.",
    "zero-shot malware scoring": "Keep zero-shot as a research target unless governed benchmarks prove it.",
    "zero-shot malware detection": "Keep zero-shot as a research target unless governed benchmarks prove it.",
    "detects unknown malware families": "This is a production-quality claim without current ML-1 evidence.",
    "model implemented": "State validation-ready/smoke-scale unless production training and benchmarks exist.",
}


BOUNDARY_TERMS = (
    "ML-1..ML-6",
    "validation-ready",
    "not production-trained",
    "not_production_ready",
    "production validation pending",
    "production model benchmarks remain gated",
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    phrase: str
    reason: str
    text: str


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def find_overclaims(paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            lower = line.lower()
            for phrase, reason in BANNED_PHRASES.items():
                if phrase in lower:
                    findings.append(
                        Finding(
                            path=path,
                            line=line_no,
                            phrase=phrase,
                            reason=reason,
                            text=line.strip(),
                        )
                    )
    return findings


def find_missing_boundaries(paths: list[Path]) -> list[Path]:
    missing: list[Path] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if "Malware-SMELL" not in text and "ML " not in text:
            continue
        if not any(term in text for term in BOUNDARY_TERMS):
            missing.append(path)
    return missing


def validate_public_claims(paths: list[Path]) -> None:
    missing_files = [path for path in paths if not path.exists()]
    if missing_files:
        names = ", ".join(_relative(path) for path in missing_files)
        raise SystemExit(f"missing public claim files: {names}")

    findings = find_overclaims(paths)
    missing_boundaries = find_missing_boundaries(paths)
    if not findings and not missing_boundaries:
        return

    lines: list[str] = []
    if findings:
        lines.append("public ML overclaims found:")
        for finding in findings:
            lines.append(
                f"- {_relative(finding.path)}:{finding.line}: "
                f"{finding.phrase!r}: {finding.reason} :: {finding.text}"
            )
    if missing_boundaries:
        lines.append("public ML files missing validation boundary wording:")
        for path in missing_boundaries:
            lines.append(f"- {_relative(path)}")
    raise SystemExit("\n".join(lines))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path",
        action="append",
        type=Path,
        help="Public file to scan. Defaults to the canonical public ML claim surfaces.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    paths = [path if path.is_absolute() else ROOT / path for path in args.path] if args.path else DEFAULT_PUBLIC_FILES
    validate_public_claims(paths)
    print(f"validated public ML claim boundaries: {len(paths)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
