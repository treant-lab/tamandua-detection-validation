#!/usr/bin/env python3
"""Gate the synthetic Linux RX page-content Preview contract.

This validates schemas and deterministic synthetic scenarios only. It does not
inspect a live process or support efficacy, FPR, performance, production, or
vendor-parity claims.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FIXTURE = (
    ROOT
    / "tools"
    / "detection_validation"
    / "fixtures"
    / "runtime_rx_page_content_preview_v1.json"
)
DEFAULT_SCHEMA = ROOT / "schemas" / "runtime_rx_page_content_preview_v1.schema.json"

API_VERSION = "tamandua.io/runtime-rx-page-content-preview-contract/v1"
FIXTURE_ID = "runtime-rx-page-content-preview-v1"
DESCRIPTION = (
    "Deterministic synthetic smoke model for the default-off Linux self-image RX "
    "page-content Preview contract."
)
EVIDENCE_CLASS = "synthetic_smoke"
EXECUTION_SCOPE = "local_synthetic"
CAPABILITY_ID = "linux_self_file_backed_elf_rx_page_content_preview_v1"
DRIFT_KIND = "file_backed_executable_page_drift"
DRIFT_EVIDENCE = (
    "file-backed executable page content differed from the protected startup baseline"
)
LEGACY_FINDING_EVIDENCE = {
    "writable_executable_mapping": (
        "current process exposed a writable executable mapping"
    ),
    "debugger_or_tracer_attached": (
        "current process reported a debugger or tracer attached"
    ),
    "instrumentation_library_loaded": (
        "current process loaded a known instrumentation library marker"
    ),
}
CLAIM_BOUNDARY = (
    "Synthetic local contract smoke model only. The modeled baseline expects a local "
    "root-protected config plus startup-held fd; this fixture did not execute or prove "
    "either protection or startup-FD behavior. It does not prove live-host detection, "
    "benign FPR, fleet performance, production readiness, or parity with any vendor."
)
PAGE_LIMITATION_IDS = {
    "rx_page_content_disabled",
    "rx_page_content_baseline_unavailable",
    "rx_page_content_baseline_mismatch",
    "rx_page_content_backing_deleted",
    "rx_page_content_backing_replaced",
    "rx_page_content_identity_race",
    "rx_page_content_execute_only",
    "rx_page_content_elf_unsupported",
    "rx_page_content_relocation_unsupported",
    "rx_page_content_budget_exceeded",
    "rx_page_content_no_eligible_pages",
    "rx_page_content_memory_read_unavailable",
    "rx_page_content_anonymous_jit_out_of_scope",
}
DEGRADED_CAUSE_IDS = PAGE_LIMITATION_IDS - {
    "rx_page_content_disabled",
    "rx_page_content_anonymous_jit_out_of_scope",
}
PRIVACY_MUTATION_FIELDS = [
    "path",
    "pid",
    "virtual_address",
    "va",
    "rva",
    "offset",
    "dev",
    "inode",
    "build_id",
    "raw_bytes",
    "page_hash",
    "drift_offsets",
]
FORBIDDEN_KEYS = set(PRIVACY_MUTATION_FIELDS) | {
    "address",
    "device",
    "build-id",
    "hash",
    "hashes",
    "page_hashes",
    "sha256",
}
PATH_PATTERN = re.compile(r"(?:[A-Za-z]:[\\/]|(?:^|\s)/(?:[^\s/]+/)*[^\s/]+|\\\\[^\s]+)")
ADDRESS_PATTERN = re.compile(r"\b0x[0-9a-fA-F]+\b")
HASH_PATTERN = re.compile(r"\b[0-9a-fA-F]{32,}\b")
SCENARIO_IDS = (
    "default-off-disabled",
    "bounded-round-robin-partial",
    "full-sweep-clean",
    "controlled-page-mismatch",
    "backing-deleted-degraded",
    "backing-replaced-degraded",
    "execute-only-degraded",
    "relocation-unsupported-degraded",
    "budget-exceeded-degraded",
    "elf-unsupported",
)
SCENARIO_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _page(
    *,
    enabled: bool,
    status: str,
    baseline_source: str,
    eligible_pages: int,
    compared_pages: int,
    excluded_relocation_pages: int,
    unstable_pages: int,
    elapsed_us: int,
    full_sweep_completed: bool,
    budget_state: str,
) -> dict[str, Any]:
    return {
        "capability_id": CAPABILITY_ID,
        "maturity": "preview",
        "mode": "observe_only",
        "enabled": enabled,
        "status": status,
        "baseline_source": baseline_source,
        "eligible_pages": eligible_pages,
        "compared_pages": compared_pages,
        "excluded_relocation_pages": excluded_relocation_pages,
        "unstable_pages": unstable_pages,
        "bytes_read": compared_pages * 4096,
        "elapsed_us": elapsed_us,
        "budget_limit_us": 10000,
        "full_sweep_completed": full_sweep_completed,
        "budget_state": budget_state,
    }


SCENARIO_CONTRACT = {
    "default-off-disabled": {
        "state": "supported",
        "findings": [],
        "page_ids": ["rx_page_content_disabled"],
        "page_content": _page(
            enabled=False,
            status="disabled",
            baseline_source="none",
            eligible_pages=0,
            compared_pages=0,
            excluded_relocation_pages=0,
            unstable_pages=0,
            elapsed_us=0,
            full_sweep_completed=False,
            budget_state="within_budget",
        ),
    },
    "bounded-round-robin-partial": {
        "state": "supported",
        "findings": [],
        "page_ids": ["rx_page_content_anonymous_jit_out_of_scope"],
        "page_content": _page(
            enabled=True,
            status="partial",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=32,
            compared_pages=16,
            excluded_relocation_pages=3,
            unstable_pages=1,
            elapsed_us=8500,
            full_sweep_completed=False,
            budget_state="within_budget",
        ),
    },
    "full-sweep-clean": {
        "state": "supported",
        "findings": [],
        "page_ids": ["rx_page_content_anonymous_jit_out_of_scope"],
        "page_content": _page(
            enabled=True,
            status="clean",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=4,
            compared_pages=4,
            excluded_relocation_pages=2,
            unstable_pages=0,
            elapsed_us=4200,
            full_sweep_completed=True,
            budget_state="within_budget",
        ),
    },
    "controlled-page-mismatch": {
        "state": "supported",
        "findings": [{"kind": DRIFT_KIND, "evidence": DRIFT_EVIDENCE}],
        "page_ids": ["rx_page_content_anonymous_jit_out_of_scope"],
        "page_content": _page(
            enabled=True,
            status="mismatch",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=4,
            compared_pages=2,
            excluded_relocation_pages=2,
            unstable_pages=0,
            elapsed_us=2800,
            full_sweep_completed=False,
            budget_state="within_budget",
        ),
    },
    "backing-deleted-degraded": {
        "state": "degraded",
        "findings": [],
        "page_ids": [
            "rx_page_content_anonymous_jit_out_of_scope",
            "rx_page_content_backing_deleted",
        ],
        "page_content": _page(
            enabled=True,
            status="degraded",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=0,
            compared_pages=0,
            excluded_relocation_pages=0,
            unstable_pages=0,
            elapsed_us=900,
            full_sweep_completed=False,
            budget_state="within_budget",
        ),
    },
    "backing-replaced-degraded": {
        "state": "degraded",
        "findings": [],
        "page_ids": [
            "rx_page_content_anonymous_jit_out_of_scope",
            "rx_page_content_backing_replaced",
        ],
        "page_content": _page(
            enabled=True,
            status="degraded",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=0,
            compared_pages=0,
            excluded_relocation_pages=0,
            unstable_pages=0,
            elapsed_us=950,
            full_sweep_completed=False,
            budget_state="within_budget",
        ),
    },
    "execute-only-degraded": {
        "state": "degraded",
        "findings": [],
        "page_ids": [
            "rx_page_content_anonymous_jit_out_of_scope",
            "rx_page_content_execute_only",
        ],
        "page_content": _page(
            enabled=True,
            status="degraded",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=1,
            compared_pages=0,
            excluded_relocation_pages=0,
            unstable_pages=0,
            elapsed_us=1100,
            full_sweep_completed=False,
            budget_state="within_budget",
        ),
    },
    "relocation-unsupported-degraded": {
        "state": "degraded",
        "findings": [],
        "page_ids": [
            "rx_page_content_anonymous_jit_out_of_scope",
            "rx_page_content_relocation_unsupported",
        ],
        "page_content": _page(
            enabled=True,
            status="degraded",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=0,
            compared_pages=0,
            excluded_relocation_pages=0,
            unstable_pages=0,
            elapsed_us=1300,
            full_sweep_completed=False,
            budget_state="within_budget",
        ),
    },
    "budget-exceeded-degraded": {
        "state": "degraded",
        "findings": [],
        "page_ids": [
            "rx_page_content_anonymous_jit_out_of_scope",
            "rx_page_content_budget_exceeded",
        ],
        "page_content": _page(
            enabled=True,
            status="degraded",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=32,
            compared_pages=16,
            excluded_relocation_pages=2,
            unstable_pages=0,
            elapsed_us=12000,
            full_sweep_completed=False,
            budget_state="exceeded",
        ),
    },
    "elf-unsupported": {
        "state": "degraded",
        "findings": [],
        "page_ids": [
            "rx_page_content_anonymous_jit_out_of_scope",
            "rx_page_content_elf_unsupported",
        ],
        "page_content": _page(
            enabled=True,
            status="unsupported",
            baseline_source="protected_config_sha256_startup_fd",
            eligible_pages=0,
            compared_pages=0,
            excluded_relocation_pages=0,
            unstable_pages=0,
            elapsed_us=500,
            full_sweep_completed=False,
            budget_state="within_budget",
        ),
    },
}


def load_object(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return value


def privacy_errors(value: Any, field: str = "evidence") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in {item.replace("-", "_") for item in FORBIDDEN_KEYS}:
                errors.append(f"{field}.{key}: forbidden privacy field")
            errors.extend(privacy_errors(child, f"{field}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(privacy_errors(child, f"{field}[{index}]"))
    elif isinstance(value, str) and (
        PATH_PATTERN.search(value) or ADDRESS_PATTERN.search(value) or HASH_PATTERN.search(value)
    ):
        errors.append(f"{field}: forbidden path, address, or hash-like value")
    return errors


def semantic_errors(evidence: dict[str, Any], field: str) -> list[str]:
    errors: list[str] = []
    page = evidence["page_content"]
    limitations = evidence["limitations"]
    if limitations != sorted(limitations):
        errors.append(f"{field}.limitations must be lexically sorted")
    if len(limitations) != len(set(limitations)):
        errors.append(f"{field}.limitations must not contain duplicates")
    unknown_page_ids = {
        item
        for item in limitations
        if item.startswith("rx_page_content_") and item not in PAGE_LIMITATION_IDS
    }
    if unknown_page_ids:
        errors.append(f"{field}.limitations contains unknown page-content IDs {sorted(unknown_page_ids)}")
    page_ids = set(limitations) & PAGE_LIMITATION_IDS

    findings = evidence["findings"]
    for finding in findings:
        kind = finding.get("kind")
        if kind in LEGACY_FINDING_EVIDENCE and finding.get("evidence") != LEGACY_FINDING_EVIDENCE[kind]:
            errors.append(f"{field}.findings legacy evidence literal is invalid for {kind}")
    drift = [finding for finding in findings if finding.get("kind") == DRIFT_KIND]
    if len(drift) > 1:
        errors.append(f"{field}.findings must contain at most one page drift finding")
    if drift and drift[0].get("evidence") != DRIFT_EVIDENCE:
        errors.append(f"{field}.findings page drift evidence literal is invalid")

    status = page["status"]
    if status == "mismatch":
        if len(drift) != 1:
            errors.append(f"{field}: mismatch requires the exact page drift finding")
    elif drift:
        errors.append(f"{field}: only mismatch may contain the page drift finding")

    if page["unstable_pages"] > page["compared_pages"]:
        errors.append(f"{field}: unstable_pages must be <= compared_pages")
    if page["compared_pages"] > page["eligible_pages"]:
        errors.append(f"{field}: compared_pages must be <= eligible_pages")
    if page["bytes_read"] != page["compared_pages"] * 4096:
        errors.append(f"{field}: bytes_read must equal compared_pages * 4096")
    if page["full_sweep_completed"] and page["compared_pages"] != page["eligible_pages"]:
        errors.append(f"{field}: full sweep requires compared_pages == eligible_pages")
    if status == "partial" and page["compared_pages"] >= page["eligible_pages"]:
        errors.append(f"{field}: partial requires incomplete eligible-page coverage")
    if status == "partial" and page["compared_pages"] < 1:
        errors.append(f"{field}: partial requires compared_pages >= 1")

    if status == "disabled" and "rx_page_content_disabled" not in page_ids:
        errors.append(f"{field}: disabled requires rx_page_content_disabled")
    if status in {"clean", "partial", "mismatch"} and (
        page_ids - {"rx_page_content_anonymous_jit_out_of_scope"}
    ):
        errors.append(f"{field}: {status} contains a contradictory page limitation")
    if status == "degraded":
        if evidence["state"] != "degraded":
            errors.append(f"{field}: degraded page status requires degraded collector state")
        if not (page_ids & DEGRADED_CAUSE_IDS):
            errors.append(f"{field}: degraded requires a concrete page-content limitation")
    if status == "unsupported":
        if evidence["state"] != "degraded":
            errors.append(f"{field}: unsupported page status requires degraded collector state")
        if "rx_page_content_elf_unsupported" not in page_ids:
            errors.append(f"{field}: unsupported requires rx_page_content_elf_unsupported")

    time_exceeded = page["elapsed_us"] > page["budget_limit_us"]
    budget_exceeded = page["budget_state"] == "exceeded"
    has_budget_limitation = "rx_page_content_budget_exceeded" in page_ids
    if budget_exceeded != time_exceeded:
        errors.append(f"{field}: budget_state must exactly reflect elapsed_us > budget_limit_us")
    if has_budget_limitation != budget_exceeded:
        errors.append(f"{field}: budget limitation must be present iff budget_state is exceeded")
    if budget_exceeded and status != "degraded":
        errors.append(f"{field}: exceeded budget must have degraded status")

    errors.extend(privacy_errors(evidence, field))
    return errors


def scenario_contract_errors(
    scenario_id: str, evidence: dict[str, Any], field: str
) -> list[str]:
    expected = SCENARIO_CONTRACT.get(scenario_id)
    if expected is None:
        return [f"{field}: scenario id is not part of the frozen contract"]
    errors: list[str] = []
    if evidence.get("state") != expected["state"]:
        errors.append(f"{field}: state does not match frozen scenario {scenario_id}")
    if evidence.get("findings") != expected["findings"]:
        errors.append(f"{field}: findings do not match frozen scenario {scenario_id}")
    limitations = evidence.get("limitations", [])
    actual_page_ids = sorted(set(limitations) & PAGE_LIMITATION_IDS)
    if actual_page_ids != expected["page_ids"]:
        errors.append(f"{field}: causal limitations do not match frozen scenario {scenario_id}")
    if evidence.get("page_content") != expected["page_content"]:
        errors.append(f"{field}: page_content does not match frozen scenario {scenario_id}")
    return errors


def validate_gate(
    fixture_path: Path, schema_path: Path = DEFAULT_SCHEMA
) -> tuple[list[str], dict[str, Any]]:
    fixture = load_object(fixture_path)
    schema = load_object(schema_path)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors: list[str] = []

    required_outer = {
        "api_version",
        "fixture_id",
        "description",
        "evidence_class",
        "execution_scope",
        "external_claim_allowed",
        "fpr_claim_allowed",
        "performance_claim_allowed",
        "vendor_parity_claimed",
        "claim_boundary",
        "runtime_schema",
        "privacy_mutation_fields",
        "scenarios",
    }
    if set(fixture) != required_outer:
        errors.append("fixture: top-level fields must be exact")
    if fixture.get("api_version") != API_VERSION:
        errors.append(f"fixture: api_version must be {API_VERSION}")
    fixture_id = fixture.get("fixture_id")
    if (
        not isinstance(fixture_id, str)
        or len(fixture_id) > 64
        or SCENARIO_ID_PATTERN.fullmatch(fixture_id) is None
        or fixture_id != FIXTURE_ID
    ):
        errors.append(f"fixture: fixture_id must be exact literal {FIXTURE_ID!r}")
    description = fixture.get("description")
    if (
        not isinstance(description, str)
        or not (1 <= len(description) <= 160)
        or description != DESCRIPTION
    ):
        errors.append("fixture: description must be the exact bounded synthetic-model literal")
    if fixture.get("evidence_class") != EVIDENCE_CLASS:
        errors.append(f"fixture: evidence_class must be {EVIDENCE_CLASS}")
    if fixture.get("execution_scope") != EXECUTION_SCOPE:
        errors.append(f"fixture: execution_scope must be {EXECUTION_SCOPE}")
    for claim in (
        "external_claim_allowed",
        "fpr_claim_allowed",
        "performance_claim_allowed",
        "vendor_parity_claimed",
    ):
        if fixture.get(claim) is not False:
            errors.append(f"fixture: {claim} must remain false")
    if fixture.get("runtime_schema") != "tamandua.runtime_integrity/v2":
        errors.append("fixture: runtime_schema must remain tamandua.runtime_integrity/v2")
    if fixture.get("privacy_mutation_fields") != PRIVACY_MUTATION_FIELDS:
        errors.append("fixture: privacy mutation field plan must remain exact")
    if fixture.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("fixture: claim_boundary must remain the exact synthetic-model boundary")

    scenarios = fixture.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        return errors + ["fixture: scenarios must be a non-empty array"], {}
    seen_ids: list[str] = []
    statuses: set[str] = set()
    for index, scenario in enumerate(scenarios):
        field = f"scenarios[{index}]"
        if not isinstance(scenario, dict) or set(scenario) != {"id", "evidence"}:
            errors.append(f"{field}: fields must be exactly id,evidence")
            continue
        scenario_id = scenario.get("id")
        if (
            not isinstance(scenario_id, str)
            or len(scenario_id) > 64
            or SCENARIO_ID_PATTERN.fullmatch(scenario_id) is None
        ):
            errors.append(f"{field}.id must match the bounded canonical id pattern")
        else:
            seen_ids.append(scenario_id)
        evidence = scenario.get("evidence")
        if not isinstance(evidence, dict):
            errors.append(f"{field}.evidence must be an object")
            continue
        for validation_error in sorted(validator.iter_errors(evidence), key=lambda item: list(item.path)):
            location = ".".join(str(item) for item in validation_error.path)
            errors.append(f"{field}.evidence.{location}: {validation_error.message}")
        if "page_content" in evidence and isinstance(evidence["page_content"], dict):
            statuses.add(str(evidence["page_content"].get("status")))
        try:
            errors.extend(semantic_errors(evidence, f"{field}.evidence"))
            if isinstance(scenario_id, str):
                errors.extend(
                    scenario_contract_errors(
                        scenario_id, evidence, f"{field}.evidence"
                    )
                )
        except (KeyError, TypeError):
            pass

    duplicate_ids = sorted({item for item in seen_ids if seen_ids.count(item) > 1})
    if duplicate_ids:
        errors.append(f"fixture: duplicate scenario ids {duplicate_ids}")
    if seen_ids != list(SCENARIO_IDS):
        errors.append("fixture: scenario ids and order must exactly match the frozen contract")
    required_statuses = {"disabled", "partial", "clean", "mismatch", "degraded", "unsupported"}
    if not required_statuses.issubset(statuses):
        errors.append(f"fixture: missing statuses {sorted(required_statuses - statuses)}")

    summary = {
        "evidence_class": EVIDENCE_CLASS,
        "execution_scope": EXECUTION_SCOPE,
        "external_claim_allowed": False,
        "fpr_claim_allowed": False,
        "performance_claim_allowed": False,
        "vendor_parity_claimed": False,
        "scenario_count": len(scenarios),
        "covered_statuses": sorted(statuses),
        "privacy_mutation_count": len(PRIVACY_MUTATION_FIELDS),
    }
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    args = parser.parse_args()
    try:
        errors, summary = validate_gate(args.fixture, args.schema)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error)
        return 1
    if errors:
        for error in errors:
            print(error)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
