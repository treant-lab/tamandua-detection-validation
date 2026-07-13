#!/usr/bin/env python3
"""Static Plugins/BOF readiness boundary probe.

This probe validates that the repository keeps plugins, BOF loading, and
dynamic modules separated from runtime-ready claims. It only reads source and
documentation files. It never builds the agent, loads WASM, executes BOF/native
code, changes policy, or enables dormant runtime features.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def resolve_repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "apps").exists() and (parent / "tools" / "detection_validation").exists():
            return parent
    return current.parents[1]


try:
    from root_resolver import ROOT, RUNS_DIR
except ImportError:
    ROOT = resolve_repo_root()
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"


PROFILE_ID = "plugins-bof-static-readiness-probe"
PROFILE_NAME = "Plugins/BOF Static Readiness Probe"

CHECKS: list[dict[str, Any]] = [
    {
        "id": "server-catalog-marks-plugin-bof-dormant",
        "name": "Server collector catalog exposes plugin/BOF/dynamic module work as dormant, not enabled collectors",
        "file": "apps/tamandua_server/lib/tamandua_server/agents/collector_catalog.ex",
        "required": [
            '@lab_design_dormant_collectors',
            'id: "plugin_runtime"',
            'id: "bof_loader"',
            'id: "dynamic_collector"',
            'policy_enabled: false',
            'maturity: "design_dormant"',
            'maturity: "lab"',
        ],
        "forbidden": [
            '"plugin_runtime" => true',
            '"bof_loader" => true',
            '"dynamic_collector" => true',
        ],
    },
    {
        "id": "server-catalog-preserves-capability-blockers",
        "name": "Server catalog lists required blockers before dynamic module enablement",
        "file": "apps/tamandua_server/lib/tamandua_server/agents/collector_catalog.ex",
        "required": [
            'id: "plugin_manifest_contract"',
            'id: "sandbox_enforcement"',
            'id: "runtime_telemetry_contract"',
            'id: "policy_rollout_gate"',
            'status: "missing"',
        ],
        "forbidden": [],
    },
    {
        "id": "server-tests-deny-dormant-policy-enablement",
        "name": "Server tests assert dormant plugin/BOF/dynamic collectors are not valid production collectors",
        "file": "apps/tamandua_server/test/tamandua_server/agents/collector_catalog_test.exs",
        "required": [
            "catalogues plugin and BOF work as lab or design dormant without policy enablement",
            'refute CollectorCatalog.valid_collector?("plugin-runtime")',
            'refute CollectorCatalog.valid_collector?("bof_loader")',
            'refute CollectorCatalog.valid_collector?("dynamic_collector")',
            "plugin_manifest_contract",
            "sandbox_enforcement",
            "runtime_telemetry_contract",
            "policy_rollout_gate",
        ],
        "forbidden": [],
    },
    {
        "id": "agent-cargo-keeps-wasm-plugin-feature-disabled",
        "name": "Agent Cargo feature keeps WASM plugins disabled by default and not wired to Wasmtime deps",
        "file": "apps/tamandua_agent/Cargo.toml",
        "required": [
            "# WASM Plugin System",
            'wasmtime = { version = "20.0", optional = true }',
            '# plugins = ["dep:wasmtime", "dep:wasmtime-wasi", "dep:wasi-common", "dep:cap-std"]',
            "plugins = []",
            "temporarily disabled",
        ],
        "forbidden": [
            'default = ["compression", "plugins"]',
            'default = ["plugins"',
        ],
    },
    {
        "id": "agent-wasm-runtime-is-feature-gated",
        "name": "Agent WASM runtime source remains feature-gated and documents non-production host API gaps",
        "file": "apps/tamandua_agent/src/plugins/runtime.rs",
        "required": [
            '#![cfg(feature = "plugins")]',
            "STUB",
            "DESIGN-DORMANT",
            "not yet shipped",
            "Do not treat returns as authoritative",
        ],
        "forbidden": [],
    },
    {
        "id": "agent-plugin-sandbox-is-source-only",
        "name": "Agent plugin sandbox source defines intended resource and access limits without release enablement",
        "file": "apps/tamandua_agent/src/plugins/sandbox.rs",
        "required": [
            "memory_limit_bytes",
            "cpu_time_limit_us",
            "filesystem_access",
            "network_access",
            "enable_wasi",
            "enable_networking",
        ],
        "forbidden": [],
    },
    {
        "id": "agent-bof-detector-is-detection-not-loader",
        "name": "Agent BOF surface is detection/telemetry oriented, not a BOF execution loader",
        "file": "apps/tamandua_agent/src/collectors/bof_collector.rs",
        "required": [
            "BOF Collector",
            "monitors memory",
            "COFF Header Detection",
            "Beacon API Pattern Detection",
            "API Hashing Detection",
            "Create a telemetry event from BOF detection",
        ],
        "forbidden": [
            "execute_bof",
            "load_bof",
            "run_bof",
        ],
    },
    {
        "id": "operations-doc-states-claim-boundary",
        "name": "Operations doc separates design-dormant, lab, and runtime-ready boundaries",
        "file": "docs/operations/plugins-bof-dynamic-modules-readiness.md",
        "required": [
            "Design-Dormant",
            "Runtime-Ready",
            "Must stay disabled",
            "No runtime execution is enabled by this document",
            "Release blockers",
        ],
        "forbidden": [],
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            ).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--short"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def read_text(relative: str) -> tuple[bool, str]:
    path = ROOT / relative
    if not path.exists():
        return False, ""
    return True, path.read_text(encoding="utf-8", errors="replace")


def check_item(item: dict[str, Any]) -> dict[str, Any]:
    exists, text = read_text(item["file"])
    lowered = text.lower()
    missing_terms = [term for term in item.get("required", []) if term.lower() not in lowered]
    forbidden_hits = [term for term in item.get("forbidden", []) if term.lower() in lowered]
    missing_files = [] if exists else [item["file"]]
    passed = exists and not missing_terms and not forbidden_hits

    return {
        "id": item["id"],
        "name": item["name"],
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else "plugins_bof_static_boundary",
        "validation_category": "plugins_bof_static_readiness",
        "execution_class": "static_source_probe",
        "claim_level": "design_dormant_or_lab_boundary",
        "evidence": {
            "checked_paths": [item["file"]],
            "missing_files": missing_files,
            "missing_terms": missing_terms,
            "forbidden_hits": forbidden_hits,
        },
        "missing_expected_fields": missing_files + missing_terms + forbidden_hits,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
    }


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = [test for test in tests if test["status"] != "covered"]
    return {
        "tests": len(tests),
        "covered": covered,
        "missed": missed,
        "partial": 0,
        "planned": 0,
        "execution_failed": 0,
        "executor_counts": {PROFILE_ID: len(tests)},
        "execution_class_counts": {"static_source_probe": len(tests)},
        "claim_level_counts": {"design_dormant_or_lab_boundary": len(tests)},
        "gap_category_counts": {"plugins_bof_static_boundary": missed} if missed else {},
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    passed = summary["missed"] == 0
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "maturity_score": 68 if passed else int(50 * covered_rate),
        "maturity_band": "plugins-bof-design-dormant-boundary-covered" if passed else "plugins-bof-boundary-gaps",
        "recommended_claim": (
            "Plugins/BOF/dynamic modules have a repo-side dormant/lab boundary; runtime execution is not production-ready"
            if passed
            else "Plugins/BOF/dynamic module boundaries have gaps; do not claim runtime readiness"
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "blocking_gaps": [] if passed else sorted(summary["gap_category_counts"].keys()),
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- Scope: static source/docs boundary for Plugins, BOF detection/loading, and dynamic modules.",
        "- Runtime effect: none; no WASM module, BOF/native code, agent policy, or collector runtime is executed or enabled.",
        "",
        "| Check | Status | Missing | Forbidden hits |",
        "| --- | --- | --- | --- |",
    ]
    for test in report["tests"]:
        evidence = test["evidence"]
        missing = evidence["missing_files"] + evidence["missing_terms"]
        forbidden = evidence["forbidden_hits"]
        lines.append(
            f"| `{test['id']}` | `{test['status']}` | `{'; '.join(missing) if missing else '-'}` | `{'; '.join(forbidden) if forbidden else '-'}` |"
        )
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = [check_item(item) for item in CHECKS]
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "plugins-bof-dynamic-modules",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "cross-platform",
            "quality_bar": {
                "purpose": "plugins_bof_static_readiness",
                "requires_runtime_execution": False,
                "requires_live_agent": False,
                "requires_wasm_execution": False,
                "requires_bof_execution": False,
            },
        },
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["plugins_bof_static_boundary_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "fail_on_missed": True,
                "fail_on_forbidden_runtime_claims": True,
                "require_runtime_execution": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Validates only that repo-side documentation, catalog entries, tests, and feature gates keep Plugins/BOF/dynamic "
            "modules in design-dormant or lab status. It does not prove signed plugin packaging, ABI compatibility, "
            "Wasmtime isolation, BOF prevention/removal, live agent telemetry, policy rollout, RBAC/audit paths, "
            "kill switch behavior, or production runtime safety."
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{run_id}.json"
    md_path = args.output_dir / f"{run_id}.md"
    write_json(json_path, report)
    write_markdown(md_path, report)
    print(f"json={json_path} markdown={md_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
