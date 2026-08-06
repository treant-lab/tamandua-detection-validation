#!/usr/bin/env python3
"""Validate the closed synthetic Loop68 RX page-content Preview v2 contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FIXTURE = ROOT / "tools/detection_validation/fixtures/runtime_rx_page_content_preview_v2.json"
DEFAULT_SCHEMA = ROOT / "schemas/runtime_rx_page_content_preview_v2.schema.json"
FROZEN_V1_HASHES = {
    ROOT / "schemas/runtime_rx_page_content_preview_v1.schema.json": "9d78bc43855cf7c853a45dfdaab396e7aef508377f5b18ba2886cbf9f234dc88",
    ROOT / "tools/detection_validation/fixtures/runtime_rx_page_content_preview_v1.json": "d49b1eac951f71e9d183e25d3b0cb7795992794d5d8f3a87964f1286b0195cb7",
    ROOT / "tools/detection_validation/scripts/runtime_rx_page_content_preview_v1.py": "464f9f5c73f7b848b5f5d21235fffb28b77e891aab04a1e579e83d48bcf6d0bb",
    ROOT / "tools/detection_validation/tests/test_runtime_rx_page_content_preview_v1.py": "ed0ecb9cbe18282b468bdc2136930348a7040ef4e00c70b087be6bac0b6e52b0",
}

API_VERSION = "tamandua.io/runtime-rx-page-content-preview-contract/v2"
FIXTURE_ID = "runtime-rx-page-content-preview-v2"
DESCRIPTION = (
    "Deterministic synthetic model separating bounded per-tick reads from committed "
    "full-sweep progress for the default-off Linux Preview."
)
EVIDENCE_CLASS = "synthetic_smoke"
EXECUTION_SCOPE = "local_synthetic"
RUNTIME_SCHEMA = "tamandua.runtime_integrity/v3"
SERVER_PROJECTION_SCHEMA = "tamandua.runtime_integrity_preview/v2"
CAPABILITY_ID = "linux_self_file_backed_elf_rx_page_content_preview_v2"
DRIFT_KIND = "file_backed_executable_page_drift"
DRIFT_EVIDENCE = (
    "file-backed executable page content differed from the protected startup baseline"
)
CLAIM_BOUNDARY = (
    "Synthetic local contract smoke only. It does not execute or prove the protected "
    "config, startup-held fd, bootstrap deadline, live memory reads, benign FPR, fleet "
    "performance, production readiness, or vendor parity."
)
PRIVACY_MUTATION_FIELDS = [
    "path", "pid", "virtual_address", "va", "rva", "offset", "dev", "inode",
    "build_id", "raw_bytes", "page_hash", "drift_offsets",
]
LEGACY_FINDING_EVIDENCE = {
    "writable_executable_mapping": "current process exposed a writable executable mapping",
    "debugger_or_tracer_attached": "current process reported a debugger or tracer attached",
    "instrumentation_library_loaded": "current process loaded a known instrumentation library marker",
}
PAGE_LIMITATION_IDS = {
    "rx_page_content_anonymous_jit_out_of_scope",
    "rx_page_content_backing_deleted",
    "rx_page_content_backing_replaced",
    "rx_page_content_baseline_mismatch",
    "rx_page_content_baseline_unavailable",
    "rx_page_content_bootstrap_budget_exceeded",
    "rx_page_content_budget_exceeded",
    "rx_page_content_coverage_limit_exceeded",
    "rx_page_content_disabled",
    "rx_page_content_elf_unsupported",
    "rx_page_content_execute_only",
    "rx_page_content_identity_race",
    "rx_page_content_memory_read_unavailable",
    "rx_page_content_no_eligible_pages",
    "rx_page_content_relocation_unsupported",
}
DEGRADED_CAUSES = PAGE_LIMITATION_IDS - {
    "rx_page_content_anonymous_jit_out_of_scope",
    "rx_page_content_disabled",
}
SCENARIO_IDS = (
    "default-off-disabled",
    "eligible-17-first-tick",
    "eligible-17-rollover-pending",
    "eligible-17-full-clean",
    "release-4964-partial",
    "release-4964-mismatch",
    "release-4964-full-clean",
    "capacity-8192-partial",
    "capacity-8192-full-clean",
    "capacity-8193-degraded",
    "bootstrap-budget-degraded",
    "partial-first-read-degraded",
    "tick-budget-degraded",
    "full-progress-tick-budget-degraded",
    "unstable-double-read-degraded",
    "elf-unsupported",
)
SCENARIO_EXPECTATIONS = {
    "default-off-disabled": ("disabled", 0, 0, 0, 0, False, "rx_page_content_disabled"),
    "eligible-17-first-tick": ("partial", 17, 8, 8, 65536, False, None),
    "eligible-17-rollover-pending": ("partial", 17, 8, 16, 65536, False, None),
    "eligible-17-full-clean": ("clean", 17, 1, 17, 8192, True, None),
    "release-4964-partial": ("partial", 4964, 8, 2480, 65536, False, None),
    "release-4964-mismatch": ("mismatch", 4964, 8, 2488, 65536, False, None),
    "release-4964-full-clean": ("clean", 4964, 4, 4964, 32768, True, None),
    "capacity-8192-partial": ("partial", 8192, 8, 8184, 65536, False, None),
    "capacity-8192-full-clean": ("clean", 8192, 8, 8192, 65536, True, None),
    "capacity-8193-degraded": ("degraded", 0, 0, 0, 0, False, "rx_page_content_coverage_limit_exceeded"),
    "bootstrap-budget-degraded": ("degraded", 0, 0, 0, 0, False, "rx_page_content_bootstrap_budget_exceeded"),
    "partial-first-read-degraded": ("degraded", 17, 0, 8, 4096, False, "rx_page_content_memory_read_unavailable"),
    "tick-budget-degraded": ("degraded", 17, 8, 16, 65536, False, "rx_page_content_budget_exceeded"),
    "full-progress-tick-budget-degraded": ("degraded", 17, 1, 17, 8192, True, "rx_page_content_budget_exceeded"),
    "unstable-double-read-degraded": ("degraded", 17, 1, 8, 8192, False, "rx_page_content_identity_race"),
    "elf-unsupported": ("unsupported", 0, 0, 0, 0, False, "rx_page_content_elf_unsupported"),
}
SCENARIO_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ADDRESS_OR_HASH = re.compile(r"(?:0x[0-9a-fA-F]{6,}|\b[0-9a-fA-F]{64}\b|(?:^|\s)/(?:[^\s]+))")


def _walk(value: Any, field: str):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child, f"{field}.{key}"
            yield from _walk(child, f"{field}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{field}[{index}]")


def privacy_errors(evidence: dict[str, Any], field: str) -> list[str]:
    errors: list[str] = []
    forbidden = set(PRIVACY_MUTATION_FIELDS)
    for key, value, location in _walk(evidence, field):
        if key in forbidden:
            errors.append(f"{location}: forbidden privacy field")
        if isinstance(value, str) and ADDRESS_OR_HASH.search(value):
            errors.append(f"{location}: forbidden path, address, or hash-like value")
    return errors


def semantic_errors(evidence: dict[str, Any], field: str) -> list[str]:
    errors: list[str] = []
    required = {"schema", "provenance", "platform", "state", "findings", "limitations", "page_content"}
    if not isinstance(evidence, dict) or set(evidence) != required:
        return [f"{field}: evidence fields must be exact"]
    page = evidence["page_content"]
    limitations = evidence["limitations"]
    findings = evidence["findings"]
    if not isinstance(page, dict):
        return [f"{field}.page_content must be an object"]
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        return [f"{field}.limitations must be a closed categorical string array"]
    if not isinstance(findings, list):
        return [f"{field}.findings must be an array"]
    if limitations != sorted(limitations):
        errors.append(f"{field}.limitations must be lexically sorted")
    if len(limitations) != len(set(limitations)):
        errors.append(f"{field}.limitations must not contain duplicates")
    page_ids = set(limitations)
    unknown = page_ids - PAGE_LIMITATION_IDS
    if unknown:
        errors.append(f"{field}.limitations must contain only closed categorical IDs; unknown={sorted(unknown)}")
    if len(page_ids) != 1:
        errors.append(f"{field}.limitations must contain exactly one exclusive categorical cause")

    valid_findings: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or set(finding) != {"kind", "evidence"}:
            errors.append(f"{field}.findings[{index}] must be an exact finding object")
            continue
        if not isinstance(finding["kind"], str) or not isinstance(finding["evidence"], str):
            errors.append(f"{field}.findings[{index}] kind and evidence must be strings")
            continue
        valid_findings.append(finding)
    drift = [item for item in valid_findings if item["kind"] == DRIFT_KIND]
    if len(drift) > 1:
        errors.append(f"{field}.findings must contain at most one drift finding")
    if drift and drift[0].get("evidence") != DRIFT_EVIDENCE:
        errors.append(f"{field}.findings page drift evidence literal is invalid")
    for finding in valid_findings:
        kind = finding.get("kind")
        if kind in LEGACY_FINDING_EVIDENCE and finding.get("evidence") != LEGACY_FINDING_EVIDENCE[kind]:
            errors.append(f"{field}.findings legacy evidence literal is invalid for {kind}")

    required_page = {
        "capability_id", "maturity", "mode", "enabled", "status", "baseline_source",
        "eligible_pages", "pages_compared_this_tick", "sweep_pages_compared",
        "excluded_relocation_pages", "unstable_pages_this_tick",
        "memory_bytes_read_this_tick", "elapsed_us_this_tick", "budget_limit_us",
        "full_sweep_completed", "budget_state",
    }
    if set(page) != required_page:
        errors.append(f"{field}.page_content fields must be exact")
        errors.extend(privacy_errors(evidence, field))
        return errors
    numeric_fields = (
        "eligible_pages", "pages_compared_this_tick", "sweep_pages_compared",
        "excluded_relocation_pages", "unstable_pages_this_tick",
        "memory_bytes_read_this_tick", "elapsed_us_this_tick", "budget_limit_us",
    )
    if any(not isinstance(page[name], int) or isinstance(page[name], bool) for name in numeric_fields):
        errors.append(f"{field}.page_content counters must be integers")
        errors.extend(privacy_errors(evidence, field))
        return errors
    status = page["status"]
    eligible = page["eligible_pages"]
    per_tick = page["pages_compared_this_tick"]
    sweep = page["sweep_pages_compared"]
    unstable = page["unstable_pages_this_tick"]
    memory_bytes = page["memory_bytes_read_this_tick"]
    elapsed = page["elapsed_us_this_tick"]
    full = page["full_sweep_completed"]
    budget_exceeded = page["budget_state"] == "exceeded"

    if sweep > eligible:
        errors.append(f"{field}: sweep_pages_compared must be <= eligible_pages")
    if unstable > per_tick:
        errors.append(f"{field}: unstable_pages_this_tick must be <= pages_compared_this_tick")
    if status in {"partial", "clean", "mismatch"} and memory_bytes != per_tick * 8192:
        errors.append(f"{field}: normal status memory bytes must equal pages_compared_this_tick * 8192")
    if status == "degraded" and memory_bytes not in {per_tick * 8192, per_tick * 8192 + 4096}:
        errors.append(f"{field}: degraded memory bytes must reflect complete double reads plus at most one first read")
    expected_full = eligible > 0 and sweep == eligible
    if full != expected_full:
        errors.append(f"{field}: full_sweep_completed must exactly reflect committed sweep completion")
    if status == "partial" and not (0 < per_tick <= 8 and 0 < sweep < eligible):
        errors.append(f"{field}: partial requires bounded tick work and incomplete committed sweep")
    if status == "clean" and (not full or unstable != 0 or drift):
        errors.append(f"{field}: clean requires a stable complete sweep without drift")
    if status == "mismatch" and len(drift) != 1:
        errors.append(f"{field}: mismatch requires the exact page drift finding")
    if status != "mismatch" and drift:
        errors.append(f"{field}: only mismatch may contain page drift")
    if unstable > 0 and not (
        status == "degraded" and page_ids == {"rx_page_content_identity_race"}
    ):
        errors.append(f"{field}: unstable pages require degraded status with exact identity-race cause")
    if unstable == 0 and page_ids == {"rx_page_content_identity_race"}:
        errors.append(f"{field}: identity-race scenario must report unstable_pages_this_tick")

    has_tick_budget = "rx_page_content_budget_exceeded" in page_ids
    if budget_exceeded != (elapsed > page["budget_limit_us"]):
        errors.append(f"{field}: budget_state must exactly reflect elapsed_us_this_tick")
    if has_tick_budget != budget_exceeded:
        errors.append(f"{field}: tick budget limitation must be present iff tick budget is exceeded")
    if budget_exceeded and status != "degraded":
        errors.append(f"{field}: exceeded tick budget requires degraded status")

    if status == "disabled":
        if evidence["state"] != "supported" or page_ids != {"rx_page_content_disabled"}:
            errors.append(f"{field}: disabled must be supported and carry only its categorical cause")
    elif status in {"partial", "clean", "mismatch"}:
        if evidence["state"] != "supported" or page_ids != {"rx_page_content_anonymous_jit_out_of_scope"}:
            errors.append(f"{field}: normal status must carry only the anonymous-JIT scope limitation")
    elif status == "degraded":
        if (
            evidence["state"] != "degraded"
            or len(page_ids) != 1
            or not page_ids.issubset(DEGRADED_CAUSES - {"rx_page_content_elf_unsupported"})
        ):
            errors.append(f"{field}: degraded requires exactly one non-ELF categorical cause")
    elif status == "unsupported":
        if evidence["state"] != "degraded" or page_ids != {"rx_page_content_elf_unsupported"}:
            errors.append(f"{field}: unsupported is reserved for the exact ELF/platform cause")

    if "rx_page_content_coverage_limit_exceeded" in page_ids and not (
        status == "degraded" and eligible == 0 and sweep == 0 and page["baseline_source"] == "none"
    ):
        errors.append(f"{field}: capacity overflow must fail closed without truncated coverage")
    if "rx_page_content_bootstrap_budget_exceeded" in page_ids and not (
        status == "degraded" and eligible == 0 and sweep == 0 and elapsed == 0
    ):
        errors.append(f"{field}: bootstrap timeout is not a tick and must expose no partial plan")

    errors.extend(privacy_errors(evidence, field))
    return errors


def scenario_contract_errors(scenario_id: str, evidence: dict[str, Any], field: str) -> list[str]:
    expected = SCENARIO_EXPECTATIONS.get(scenario_id)
    if expected is None:
        return [f"{field}: unknown frozen scenario"]
    page = evidence["page_content"]
    actual = (
        page["status"], page["eligible_pages"], page["pages_compared_this_tick"],
        page["sweep_pages_compared"], page["memory_bytes_read_this_tick"],
        page["full_sweep_completed"],
    )
    errors: list[str] = []
    if actual != expected[:6]:
        errors.append(f"{field}: lifecycle counters do not match frozen scenario")
    cause = expected[6]
    expected_causes = {cause} if cause is not None else {"rx_page_content_anonymous_jit_out_of_scope"}
    if set(evidence["limitations"]) != expected_causes:
        errors.append(f"{field}: exclusive causal limitations do not match frozen scenario")
    return errors


def validate_gate(fixture_path: Path, schema_path: Path) -> tuple[list[str], dict[str, Any]]:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors: list[str] = []
    for frozen_path, expected_hash in FROZEN_V1_HASHES.items():
        try:
            actual_hash = hashlib.sha256(frozen_path.read_bytes()).hexdigest()
        except OSError as error:
            errors.append(f"frozen-v1: cannot read {frozen_path.relative_to(ROOT)}: {error}")
            continue
        if actual_hash != expected_hash:
            errors.append(
                f"frozen-v1: hash drift for {frozen_path.relative_to(ROOT)}; "
                f"expected={expected_hash} actual={actual_hash}"
            )
    required_outer = {
        "api_version", "fixture_id", "description", "evidence_class", "execution_scope",
        "external_claim_allowed", "fpr_claim_allowed", "performance_claim_allowed",
        "vendor_parity_claimed", "claim_boundary", "runtime_schema",
        "server_projection_schema", "privacy_mutation_fields", "scenarios",
    }
    if set(fixture) != required_outer:
        errors.append("fixture: top-level fields must be exact")
    exact = {
        "api_version": API_VERSION, "fixture_id": FIXTURE_ID, "description": DESCRIPTION,
        "evidence_class": EVIDENCE_CLASS, "execution_scope": EXECUTION_SCOPE,
        "claim_boundary": CLAIM_BOUNDARY, "runtime_schema": RUNTIME_SCHEMA,
        "server_projection_schema": SERVER_PROJECTION_SCHEMA,
        "privacy_mutation_fields": PRIVACY_MUTATION_FIELDS,
    }
    for key, value in exact.items():
        if fixture.get(key) != value:
            errors.append(f"fixture: {key} must remain exact")
    for claim in ("external_claim_allowed", "fpr_claim_allowed", "performance_claim_allowed", "vendor_parity_claimed"):
        if fixture.get(claim) is not False:
            errors.append(f"fixture: {claim} must remain false")
    if SERVER_PROJECTION_SCHEMA not in schema.get("$comment", ""):
        errors.append("schema: server projection identity must be documented")

    scenarios = fixture.get("scenarios")
    if not isinstance(scenarios, list):
        return errors + ["fixture: scenarios must be an array"], {}
    seen: list[str] = []
    statuses: set[str] = set()
    for index, scenario in enumerate(scenarios):
        field = f"scenarios[{index}]"
        if not isinstance(scenario, dict) or set(scenario) != {"id", "evidence"}:
            errors.append(f"{field}: fields must be exactly id,evidence")
            continue
        scenario_id = scenario["id"]
        if not isinstance(scenario_id, str) or len(scenario_id) > 64 or not SCENARIO_ID_PATTERN.fullmatch(scenario_id):
            errors.append(f"{field}.id must be a bounded canonical id")
            continue
        seen.append(scenario_id)
        evidence = scenario["evidence"]
        for item in sorted(validator.iter_errors(evidence), key=lambda error: list(error.path)):
            location = ".".join(str(part) for part in item.path)
            errors.append(f"{field}.evidence.{location}: {item.message}")
        if isinstance(evidence, dict) and isinstance(evidence.get("page_content"), dict):
            statuses.add(str(evidence["page_content"].get("status")))
            try:
                errors.extend(semantic_errors(evidence, f"{field}.evidence"))
                errors.extend(scenario_contract_errors(scenario_id, evidence, f"{field}.evidence"))
            except (KeyError, TypeError):
                pass
    if seen != list(SCENARIO_IDS):
        errors.append("fixture: scenario ids and order must exactly match the frozen contract")
    if len(seen) != len(set(seen)):
        errors.append("fixture: duplicate scenario ids")
    required_statuses = {"disabled", "partial", "clean", "mismatch", "degraded", "unsupported"}
    if not required_statuses.issubset(statuses):
        errors.append(f"fixture: missing statuses {sorted(required_statuses - statuses)}")

    summary = {
        "covered_statuses": sorted(statuses),
        "evidence_class": EVIDENCE_CLASS,
        "execution_scope": EXECUTION_SCOPE,
        "external_claim_allowed": False,
        "fpr_claim_allowed": False,
        "frozen_v1_hash_count": len(FROZEN_V1_HASHES),
        "performance_claim_allowed": False,
        "privacy_mutation_count": len(PRIVACY_MUTATION_FIELDS),
        "runtime_schema": RUNTIME_SCHEMA,
        "scenario_count": len(scenarios),
        "server_projection_schema": SERVER_PROJECTION_SCHEMA,
        "vendor_parity_claimed": False,
    }
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    args = parser.parse_args()
    try:
        errors, summary = validate_gate(args.fixture, args.schema)
    except Exception as error:  # CLI boundary: invalid diagnostics never emit a traceback.
        message = " ".join(str(error).splitlines())[:240]
        print(f"validation failed ({type(error).__name__}): {message}")
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
