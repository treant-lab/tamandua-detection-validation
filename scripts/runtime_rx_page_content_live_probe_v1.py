#!/usr/bin/env python3
"""Validate closed isolated live-probe receipts and their synthetic contract fixture."""

from __future__ import annotations

import argparse
from datetime import datetime
import importlib.util
import json
import math
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCHEMA = ROOT / "schemas/runtime_rx_page_content_live_probe_v1.schema.json"
DEFAULT_FIXTURE = ROOT / "tools/detection_validation/fixtures/runtime_rx_page_content_live_probe_v1.json"
PREVIEW_SCHEMA = ROOT / "schemas/runtime_rx_page_content_preview_v2.schema.json"
PREVIEW_SCRIPT = ROOT / "tools/detection_validation/scripts/runtime_rx_page_content_preview_v2.py"

SPEC = importlib.util.spec_from_file_location("runtime_rx_page_content_preview_v2", PREVIEW_SCRIPT)
assert SPEC and SPEC.loader
PREVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREVIEW)

API_VERSION = "tamandua.io/runtime-rx-page-content-live-probe-contract/v1"
FIXTURE_ID = "runtime-rx-page-content-live-probe-v1"
DESCRIPTION = "Synthetic contract model for isolated disabled, degraded, and clean runtime page-content live-probe receipts."
CLAIM_BOUNDARY = "Synthetic receipt-shape validation only. No probe, WSL2 namespace, strace, protected file, RSS measurement, live collector, benign workload, or cleanup was executed or observed."
PRIVACY_MUTATION_FIELDS = ["path", "pid", "inode", "device", "address", "raw_trace", "raw_config", "raw_bytes", "page_hash", "drift_offsets"]
SCENARIOS = (
    ("disabled-control", "disabled_control", "disabled"),
    ("baseline-degraded-control", "baseline_degraded_control", "degraded"),
    ("owned-release-clean", "owned_release_clean", "clean"),
)
FINDING_EVIDENCE = {
    "writable_executable_mapping": "current process exposed a writable executable mapping",
    "debugger_or_tracer_attached": "current process reported a debugger or tracer attached",
    "instrumentation_library_loaded": "current process loaded a known instrumentation library marker",
    "file_backed_executable_page_drift": PREVIEW.DRIFT_EVIDENCE,
}
HASH_64 = re.compile(r"^[0-9a-f]{64}$")
LEAK = re.compile(r"(?:0x[0-9a-fA-F]{6,}|\bpid\s*[=:]\s*\d+|\binode\s*[=:]\s*\d+|(?:^|[\s(])/(?:[^\s)]+))", re.I)
UTC_TIMESTAMP = re.compile(
    r"^(?P<calendar>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?P<fraction>\.[0-9]{1,6})?Z$"
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHARED_PROVENANCE_FIELDS = (
    "source_sha", "scoped_dirty", "scoped_dirty_diff_sha256", "cargo_lock_sha256",
    "rustc_version", "cargo_version", "build_command", "build_command_sha256",
    "artifact_sha256", "artifact_size_bytes", "artifact_arch", "artifact_profile",
)


def _walk(value: Any, field: str):
    if isinstance(value, dict):
        for key, child in value.items():
            location = f"{field}.{key}"
            yield key, child, location
            yield from _walk(child, location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{field}[{index}]")


def privacy_errors(receipt: dict[str, Any], field: str) -> list[str]:
    errors: list[str] = []
    forbidden = set(PRIVACY_MUTATION_FIELDS)
    for key, value, location in _walk(receipt, field):
        if key in forbidden:
            errors.append(f"{location}: forbidden privacy field")
        if isinstance(value, str) and key != "build_command" and not HASH_64.fullmatch(value) and LEAK.search(value):
            errors.append(f"{location}: forbidden raw path, PID, inode, or address")
    return errors


def _finding_objects(kinds: list[str]) -> list[dict[str, str]]:
    return [{"kind": kind, "evidence": FINDING_EVIDENCE[kind]} for kind in kinds if kind in FINDING_EVIDENCE]


def _raw_evidence(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "tamandua.runtime_integrity/v3",
        "provenance": "platform_collector",
        "platform": "linux",
        "state": summary["state"],
        "findings": _finding_objects(summary["finding_kinds"]),
        "limitations": summary["limitations"],
        "page_content": summary["page_content"],
    }


def _first_seen_union(summaries: list[dict[str, Any]], key: str) -> list[str]:
    result: list[str] = []
    for summary in summaries:
        for item in summary[key]:
            if item not in result:
                result.append(item)
    return result


def utc_timestamp_error(value: Any) -> str | None:
    if not isinstance(value, str):
        return "must be a string"
    match = UTC_TIMESTAMP.fullmatch(value)
    if match is None:
        return "must be exact uppercase UTC YYYY-MM-DDTHH:MM:SS[.fraction]Z without an offset"
    try:
        parsed = datetime.strptime(match.group("calendar"), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return "must contain a real Gregorian calendar date and bounded time"
    roundtrip = parsed.strftime("%Y-%m-%dT%H:%M:%S") + (match.group("fraction") or "") + "Z"
    if roundtrip != value:
        return "must survive exact UTC calendar parse and round-trip"
    return None


def receipt_semantic_errors(receipt: dict[str, Any], field: str, require_executed: bool) -> list[str]:
    errors: list[str] = []
    if require_executed and receipt.get("execute") is not True:
        errors.append(f"{field}.execute: an executed receipt is required")
    provenance = receipt["provenance"]
    custody = receipt["custody"]
    measurements = receipt["measurements"]
    output = receipt["probe_output"]
    summaries = output["summaries"]
    timestamp_error = utc_timestamp_error(receipt.get("executed_at_utc"))
    if timestamp_error:
        errors.append(f"{field}.executed_at_utc: {timestamp_error}")

    if not (
        provenance["artifact_sha256"]
        == custody["artifact_sha256_before"]
        == custody["artifact_sha256_after"]
    ):
        errors.append(f"{field}: artifact SHA must remain equal before and after the probe")
    if not (
        provenance["config_sha256"]
        == custody["config_sha256_before"]
        == custody["config_sha256_after"]
    ):
        errors.append(f"{field}: config SHA must remain equal before and after the probe")
    dirty_diff = provenance["scoped_dirty_diff_sha256"]
    if provenance["scoped_dirty"] is not (dirty_diff != EMPTY_SHA256):
        errors.append(f"{field}: scoped_dirty must be true iff the diff SHA is not the canonical empty SHA")

    if require_executed:
        if receipt.get("receipt_provenance") != "live_probe_runner":
            errors.append(f"{field}.receipt_provenance: executed receipts require live_probe_runner provenance")
        run_id = str(receipt.get("run_id", ""))
        executed_at = str(receipt.get("executed_at_utc", ""))
        if "synthetic" in run_id.lower() or run_id in {"placeholder", "test", "example"}:
            errors.append(f"{field}.run_id: synthetic or placeholder run IDs are forbidden")
        if executed_at.startswith(("1970-01-01T", "2000-01-01T")) or "synthetic" in executed_at.lower():
            errors.append(f"{field}.executed_at_utc: synthetic or sentinel timestamps are forbidden")
        for key in ("rustc_version", "cargo_version", "build_command"):
            if "synthetic" in str(provenance[key]).lower():
                errors.append(f"{field}.provenance.{key}: synthetic build provenance is forbidden")
        for key in (
            "source_sha", "scoped_dirty_diff_sha256", "cargo_lock_sha256",
            "build_command_sha256", "artifact_sha256", "config_sha256",
        ):
            value = str(provenance[key])
            if value == EMPTY_SHA256 or len(set(value)) <= 1:
                errors.append(f"{field}.provenance.{key}: placeholder or sentinel hash is forbidden")

    for timing in ("config_load_elapsed_us", "collector_init_elapsed_us", "probe_wall_elapsed_us"):
        if measurements[timing] != output[timing]:
            errors.append(f"{field}: external and probe {timing} must match exactly")
    if measurements["probe_wall_elapsed_us"] < (
        measurements["config_load_elapsed_us"] + measurements["collector_init_elapsed_us"]
    ):
        errors.append(f"{field}: probe wall time must cover config load plus collector init")

    if output["ticks_executed"] != len(summaries):
        errors.append(f"{field}: ticks_executed must equal the bounded summary count")
    if not summaries or output["final_summary"] != summaries[-1]:
        errors.append(f"{field}: final_summary must exactly equal the last tick summary")
    final = output["final_summary"]
    if output["state"] != final["state"] or output["page_content"] != final["page_content"]:
        errors.append(f"{field}: aggregate state and page_content must equal the final summary")
    if output["finding_kinds"] != _first_seen_union(summaries, "finding_kinds"):
        errors.append(f"{field}: aggregate finding kinds must be the first-seen tick union")
    if output["limitations"] != _first_seen_union(summaries, "limitations"):
        errors.append(f"{field}: aggregate limitations must be the first-seen tick union")
    if len(json.dumps(output, separators=(",", ":")).encode("utf-8")) >= 2 * 1024 * 1024:
        errors.append(f"{field}: sanitized probe output must remain below 2 MiB")

    preview_schema = json.loads(PREVIEW_SCHEMA.read_text(encoding="utf-8"))
    preview_validator = Draft202012Validator(preview_schema)
    previous_progress: int | None = None
    eligible: int | None = None
    excluded: int | None = None
    for index, summary in enumerate(summaries):
        tick_field = f"{field}.probe_output.summaries[{index}]"
        evidence = _raw_evidence(summary)
        for error in preview_validator.iter_errors(evidence):
            errors.append(f"{tick_field}: raw v3 schema rejected {error.message}")
        try:
            errors.extend(PREVIEW.semantic_errors(evidence, tick_field))
        except (KeyError, TypeError, AttributeError) as error:
            errors.append(f"{tick_field}: malformed raw v3 summary ({type(error).__name__})")
            continue
        page = summary["page_content"]
        if page["elapsed_us_this_tick"] > 10000 or page["memory_bytes_read_this_tick"] > 65536:
            errors.append(f"{tick_field}: every accepted tick must stay within 10 ms and 64 KiB")
        if eligible is None:
            eligible = page["eligible_pages"]
            excluded = page["excluded_relocation_pages"]
        elif page["eligible_pages"] != eligible or page["excluded_relocation_pages"] != excluded:
            errors.append(f"{tick_field}: eligible and relocation-exclusion totals must remain stable")
        progress = page["sweep_pages_compared"]
        if previous_progress is None:
            if progress not in {0, page["pages_compared_this_tick"]}:
                errors.append(f"{tick_field}: first tick progress must be zero or its committed page count")
        elif progress < previous_progress or (
            progress > previous_progress and progress - previous_progress != page["pages_compared_this_tick"]
        ):
            errors.append(f"{tick_field}: committed sweep progress is not monotonic and exact")
        previous_progress = progress
        if page["full_sweep_completed"] and index != len(summaries) - 1:
            errors.append(f"{tick_field}: probe must stop at the first completed sweep")

    scenario = receipt["scenario"]
    expected = {
        "disabled_control": ("disabled", "disabled_control"),
        "baseline_degraded_control": ("degraded", "wrong_baseline_control"),
        "owned_release_clean": ("clean", "owned_release_unchanged"),
    }[scenario]
    status = final["page_content"]["status"]
    if status != expected[0] or receipt["benign_matrix"]["expected_status"] != expected[0]:
        errors.append(f"{field}: scenario and final status do not match the benign matrix")
    if receipt["benign_matrix"]["input_class"] != expected[1]:
        errors.append(f"{field}: scenario and benign input class do not match")
    if any(summary["finding_kinds"] for summary in summaries):
        errors.append(f"{field}: the benign matrix must not contain runtime findings")
    if scenario == "disabled_control" and not (
        len(summaries) == 1 and final["limitations"] == ["rx_page_content_disabled"]
    ):
        errors.append(f"{field}: disabled control must terminate in one disabled tick")
    if scenario == "baseline_degraded_control" and not (
        len(summaries) == 1
        and final["limitations"] == ["rx_page_content_baseline_mismatch"]
        and final["page_content"]["eligible_pages"] == 0
    ):
        errors.append(f"{field}: degraded control must be the terminal wrong-baseline case")
    if scenario == "owned_release_clean":
        page = final["page_content"]
        expected_ticks = math.ceil(page["eligible_pages"] / 8)
        if not (
            page["status"] == "clean"
            and page["full_sweep_completed"] is True
            and page["sweep_pages_compared"] == page["eligible_pages"]
            and len(summaries) == expected_ticks
            and output["ticks_executed"] == expected_ticks
        ):
            errors.append(f"{field}: clean receipt must cover exactly one bounded full sweep")

    errors.extend(privacy_errors(receipt, field))
    return errors


def hashlib_empty_sha256() -> str:
    return EMPTY_SHA256


def validate_fixture(fixture_path: Path, schema_path: Path, require_executed: bool = False) -> tuple[list[str], dict[str, Any]]:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors: list[str] = []
    required = {
        "api_version", "fixture_id", "description", "evidence_class", "execution_scope",
        "execute", "external_claim_allowed", "fpr_claim_allowed", "performance_claim_allowed",
        "vendor_parity_claimed", "claim_boundary", "privacy_mutation_fields", "scenarios",
    }
    if not isinstance(fixture, dict) or set(fixture) != required:
        return ["fixture: top-level fields must be exact"], {}
    exact = {
        "api_version": API_VERSION, "fixture_id": FIXTURE_ID, "description": DESCRIPTION,
        "evidence_class": "synthetic_smoke", "execution_scope": "local_synthetic",
        "execute": False, "external_claim_allowed": False, "fpr_claim_allowed": False,
        "performance_claim_allowed": False, "vendor_parity_claimed": False,
        "claim_boundary": CLAIM_BOUNDARY, "privacy_mutation_fields": PRIVACY_MUTATION_FIELDS,
    }
    for key, value in exact.items():
        if fixture.get(key) != value:
            errors.append(f"fixture: {key} must remain exact")
    if require_executed:
        errors.append("fixture: synthetic fixtures cannot satisfy --require-executed; provide an explicit --receipt")
    scenarios = fixture.get("scenarios")
    if not isinstance(scenarios, list):
        return errors + ["fixture: scenarios must be an array"], {}
    identities: list[tuple[str, str, str]] = []
    for index, modeled in enumerate(scenarios):
        field = f"scenarios[{index}]"
        if not isinstance(modeled, dict) or set(modeled) != {"id", "receipt"}:
            errors.append(f"{field}: fields must be exactly id,receipt")
            continue
        receipt = modeled["receipt"]
        for error in sorted(validator.iter_errors(receipt), key=lambda item: list(item.path)):
            location = ".".join(str(part) for part in error.path)
            errors.append(f"{field}.receipt.{location}: {error.message}")
        if isinstance(receipt, dict):
            try:
                if receipt.get("execute") is not False:
                    errors.append(f"{field}.receipt.execute: synthetic fixture receipts must remain false")
                if receipt.get("receipt_provenance") != "synthetic_fixture":
                    errors.append(f"{field}.receipt.receipt_provenance: synthetic fixture provenance must remain exact")
                errors.extend(receipt_semantic_errors(receipt, f"{field}.receipt", False))
                identities.append((modeled["id"], receipt["scenario"], receipt["probe_output"]["final_summary"]["page_content"]["status"]))
            except (KeyError, TypeError, AttributeError) as error:
                errors.append(f"{field}.receipt: malformed receipt ({type(error).__name__})")
    if identities != list(SCENARIOS):
        errors.append("fixture: scenario order, identity, and final semantics must remain exact")
    if scenarios:
        bound_builds = {
            tuple(item["receipt"]["provenance"][key] for key in SHARED_PROVENANCE_FIELDS)
            for item in scenarios if isinstance(item, dict) and isinstance(item.get("receipt"), dict)
        }
        configs = {item["receipt"]["provenance"]["config_sha256"] for item in scenarios if isinstance(item, dict) and isinstance(item.get("receipt"), dict)}
        if len(bound_builds) != 1 or len(configs) != 3:
            errors.append("fixture: benign matrix must bind one source/build/artifact identity and three distinct configs")
    summary = {
        "evidence_class": "synthetic_smoke", "execution_scope": "local_synthetic",
        "execute": False, "external_claim_allowed": False, "fpr_claim_allowed": False,
        "performance_claim_allowed": False, "vendor_parity_claimed": False,
        "scenario_count": len(scenarios), "modeled_receipt_schema": "tamandua.runtime_integrity_live_probe_receipt/v1",
    }
    return errors, summary


def validate_receipt_file(receipt_path: Path, schema_path: Path) -> tuple[list[str], dict[str, Any]]:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = []
    for error in sorted(validator.iter_errors(receipt), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path)
        errors.append(f"receipt.{location}: {error.message}")
    if isinstance(receipt, dict):
        try:
            errors.extend(receipt_semantic_errors(receipt, "receipt", True))
        except (KeyError, TypeError, AttributeError) as error:
            errors.append(f"receipt: malformed receipt ({type(error).__name__})")
    else:
        errors.append("receipt: top level must be an object")
    summary = {
        "evidence_class": "local_live_collector_smoke",
        "execution_scope": "wsl2_network_isolated",
        "execute": True,
        "external_claim_allowed": False,
        "fpr_claim_allowed": False,
        "performance_claim_allowed": False,
        "vendor_parity_claimed": False,
        "receipt_schema": "tamandua.runtime_integrity_live_probe_receipt/v1",
    }
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--fixture", type=Path)
    source.add_argument("--receipt", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--require-executed", action="store_true")
    args = parser.parse_args()
    try:
        if args.require_executed and args.receipt is None:
            print("fixture: --require-executed requires an explicit --receipt direct lane")
            return 1
        if args.receipt is not None:
            errors, summary = validate_receipt_file(args.receipt, args.schema)
        else:
            errors, summary = validate_fixture(
                args.fixture or DEFAULT_FIXTURE, args.schema, args.require_executed
            )
    except Exception as error:
        print(f"validation failed ({type(error).__name__}): {' '.join(str(error).splitlines())[:240]}")
        return 1
    if errors:
        bounded = [" ".join(error.splitlines())[:240] for error in errors[:32]]
        if len(errors) > len(bounded):
            bounded.append(f"... {len(errors) - len(bounded)} additional validation errors omitted")
        print("\n".join(bounded))
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
