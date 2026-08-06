#!/usr/bin/env python3
"""Validate the model-agnostic detector observation/consensus contract.

This is a contract smoke validator. Passing it does not establish detector
accuracy, false-positive rate, false-negative rate, or production readiness.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
from typing import Any

import jsonschema


SCRIPT_DIR = Path(__file__).resolve().parent
STANDALONE_ROOT = SCRIPT_DIR.parent
if (STANDALONE_ROOT / "schemas").exists() and (STANDALONE_ROOT / "fixtures").exists():
    ROOT = STANDALONE_ROOT
    FIXTURES_DIR = ROOT / "fixtures"
else:
    ROOT = Path(os.environ.get("TAMANDUA_ROOT", SCRIPT_DIR.parents[2]))
    FIXTURES_DIR = ROOT / "tools" / "detection_validation" / "fixtures"
SCHEMA_PATH = ROOT / "schemas" / "detector_observation_consensus_v1.schema.json"
DEFAULT_FIXTURE = FIXTURES_DIR / "detector_observation_consensus_contract_smoke_valid_v1.json"
MAX_MESSAGE_BYTES = 1024 * 1024


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def load_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError(f"{path}: message exceeds 1 MiB")
    payload = json.loads(raw, parse_constant=_reject_non_finite)
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return payload


def build_validator() -> jsonschema.Draft202012Validator:
    schema = load_json(SCHEMA_PATH)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def semantic_errors(payload: dict[str, Any]) -> list[str]:
    observations = payload.get("observations")
    consensus = payload.get("consensus")
    if not isinstance(observations, list) or not isinstance(consensus, dict):
        return []

    detector_ids = [
        observation.get("detector_id")
        for observation in observations
        if isinstance(observation, dict) and isinstance(observation.get("detector_id"), str)
    ]
    errors: list[str] = []

    def check_finite(value: Any, path: str = "<root>") -> None:
        if isinstance(value, float) and not math.isfinite(value):
            errors.append(f"{path}: number must be finite")
        elif isinstance(value, dict):
            for key, child in value.items():
                check_finite(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                check_finite(child, f"{path}.{index}")

    check_finite(payload)

    duplicates = sorted(
        detector_id for detector_id in set(detector_ids) if detector_ids.count(detector_id) > 1
    )
    if duplicates:
        errors.append(f"detector_id values must be unique: {', '.join(duplicates)}")

    members = consensus.get("member_detector_ids")
    if isinstance(members, list):
        unknown = sorted(member for member in members if member not in set(detector_ids))
        if unknown:
            errors.append(
                "consensus references unknown detector_id values: " + ", ".join(unknown)
            )

    return errors


def validation_errors(payload: dict[str, Any]) -> list[str]:
    validator = build_validator()
    schema_errors = [
        f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in sorted(
            validator.iter_errors(payload),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
    ]
    return schema_errors + semantic_errors(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[DEFAULT_FIXTURE])
    args = parser.parse_args()

    failed = False
    for path in args.paths:
        try:
            payload = load_json(path)
            errors = validation_errors(payload)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors = [str(exc)]

        if errors:
            failed = True
            print(f"INVALID {path}")
            for error in errors:
                print(f"- {error}")
        else:
            context = payload.get("validation_context", {})
            evidence_class = context.get("evidence_class", "contract_unknown")
            claim_scope = context.get("claim_scope", "claim_unknown")
            print(
                f"VALID {path} ({evidence_class}; {claim_scope}; "
                "no FP/FN or efficacy claim)"
            )

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
