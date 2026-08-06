#!/usr/bin/env python3
"""Validate bounded local-model-service protocol messages.

This validates protocol shape and synthetic parity only. It makes no detector
efficacy, false-positive, false-negative, or production-readiness claim.
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
else:
    ROOT = Path(os.environ.get("TAMANDUA_ROOT", SCRIPT_DIR.parents[2]))
SCHEMA_PATH = ROOT / "schemas" / "local_model_service_contract_v1.schema.json"
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
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _finite_errors(value: Any, path: str = "<root>") -> list[str]:
    if isinstance(value, float) and not math.isfinite(value):
        return [f"{path}: number must be finite"]
    if isinstance(value, dict):
        return [
            error
            for key, child in value.items()
            for error in _finite_errors(child, f"{path}.{key}")
        ]
    if isinstance(value, list):
        return [
            error
            for index, child in enumerate(value)
            for error in _finite_errors(child, f"{path}.{index}")
        ]
    return []


def semantic_errors(payload: dict[str, Any]) -> list[str]:
    errors = _finite_errors(payload)
    result = payload.get("result")
    if not isinstance(result, dict):
        return errors

    envelope_contract = payload.get("model_contract_id")
    result_contract = result.get("model_contract_id")
    if result_contract is not None and result_contract != envelope_contract:
        errors.append("result.model_contract_id must match envelope model_contract_id")

    votes = result.get("ensemble_votes", [])
    if isinstance(votes, list):
        detector_ids = [
            vote.get("detector_id")
            for vote in votes
            if isinstance(vote, dict) and isinstance(vote.get("detector_id"), str)
        ]
        duplicates = sorted(
            detector_id
            for detector_id in set(detector_ids)
            if detector_ids.count(detector_id) > 1
        )
        if duplicates:
            errors.append("ensemble detector_id values must be unique: " + ", ".join(duplicates))

    if result.get("safe") is True and result.get("threats"):
        errors.append("safe result cannot contain detected threats")
    return errors


def validation_errors(payload: dict[str, Any]) -> list[str]:
    schema_errors = [
        f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in sorted(
            build_validator().iter_errors(payload),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
    ]
    return schema_errors + semantic_errors(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    failed = False
    for path in args.paths:
        try:
            errors = validation_errors(load_json(path))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors = [str(exc)]
        if errors:
            failed = True
            print(f"INVALID {path}")
            for error in errors:
                print(f"- {error}")
        else:
            print(f"VALID {path} (synthetic parity; no efficacy claim)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
