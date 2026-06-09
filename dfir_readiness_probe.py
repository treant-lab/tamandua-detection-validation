#!/usr/bin/env python3
"""Non-destructive Roadmap T DFIR readiness probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "dfir-hunting-readiness-static-probe"
PROFILE_NAME = "DFIR Hunting Readiness Static/API Probe"

SOURCE_CHECKS: list[dict[str, Any]] = [
    {
        "id": "dfir-api-routes-present",
        "name": "DFIR API routes expose collection and investigation surfaces",
        "category": "dfir-api",
        "file": "apps/tamandua_server/lib/tamandua_server_web/router.ex",
        "required": [
            "resources(\"/forensics\", ForensicsController",
            "get(\"/forensics/:id/download\", ForensicsController, :download)",
            "post(\"/forensics/:id/analyze\", ForensicsController, :analyze)",
            "resources(\"/forensics/investigations\", ForensicsInvestigationController",
            "post(\"/forensics/investigations/:id/collect\", ForensicsInvestigationController, :collect)",
            "post(\"/forensics/investigations/:id/report\", ForensicsInvestigationController, :report)",
            "post(\"/live-response/:agent_id/collect\", LiveResponseController, :collect_artifacts)",
        ],
    },
    {
        "id": "dfir-context-modules-present",
        "name": "Server has DFIR context, artifact, collector, engine, analyzer, and timeline modules",
        "category": "dfir-backend",
        "files": [
            "apps/tamandua_server/lib/tamandua_server/forensics.ex",
            "apps/tamandua_server/lib/tamandua_server/forensics/artifact.ex",
            "apps/tamandua_server/lib/tamandua_server/forensics/collector.ex",
            "apps/tamandua_server/lib/tamandua_server/forensics/engine.ex",
            "apps/tamandua_server/lib/tamandua_server/forensics/artifact_analyzer.ex",
            "apps/tamandua_server/lib/tamandua_server/forensics/timeline.ex",
        ],
    },
    {
        "id": "dfir-db-schema-present",
        "name": "Forensic artifact persistence migration exists",
        "category": "dfir-persistence",
        "file": "apps/tamandua_server/priv/repo/migrations/20260220700002_create_forensic_artifacts.exs",
        "required": ["create table(:forensic_artifacts", "add :sha256", "add :metadata", "timestamps("],
    },
    {
        "id": "dfir-agent-forensics-module-present",
        "name": "Agent has endpoint-side forensics response module",
        "category": "dfir-agent",
        "file": "apps/tamandua_agent/src/response/forensics.rs",
        "required": ["forensic"],
    },
    {
        "id": "dfir-analyst-ui-route-present",
        "name": "Authenticated UI has forensics pages for analyst review",
        "category": "analyst-ux",
        "file": "apps/tamandua_server/lib/tamandua_server_web/router.ex",
        "required": [
            "get(\"/forensics\", InertiaController, :forensics)",
            "get(\"/forensics/:collection_id\", InertiaController, :forensics_detail)",
        ],
    },
]

MANIFEST_FILES = [
    "tools/detection_validation/profiles/dfir_hunting_artifact_collection_dry_run.json",
    "tools/detection_validation/fixtures/roadmap_k_n_s_t_contracts_v1.json",
    "docs/benchmarks/NEXT_VALIDATION_WORK_QUEUE.md",
]

REMOTE_DENY_PATHS = [
    "/api/v1/forensics",
    "/api/v1/forensics/investigations/stats",
    "/api/v1/live-response/example-agent-id/processes",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--short"]).splitlines()
    return {"commit": commit, "commit_short": commit[:8] if commit else "", "dirty": bool(status), "status_short": status}


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8", errors="replace")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def make_result(test_id: str, name: str, passed: bool, category: str, evidence: dict[str, Any], missing: list[str] | None = None) -> dict[str, Any]:
    status = "covered" if passed else "missed"
    return {
        "id": test_id,
        "name": name,
        "status": status,
        "gap_category": "none" if passed else category,
        "execution_class": "static_code_probe",
        "claim_level": "dfir_readiness",
        "executor_used": "dfir_readiness_probe",
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": category,
        "coverage": {
            "telemetry": "not_expected",
            "fields": "ok" if passed else "missing",
            "detection": "not_expected",
            "alert": "not_expected",
            "correlation": "not_expected",
            "driver_raw": "not_expected",
            "timeline": "not_expected",
            "values": "ok" if passed else "missing",
        },
        "evidence": evidence,
        "missing_expected_fields": missing or [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [],
    }


def source_check_result(check: dict[str, Any]) -> dict[str, Any]:
    if check.get("files"):
        missing = [path for path in check["files"] if not (ROOT / path).exists()]
        return make_result(check["id"], check["name"], not missing, check["category"], {"files": check["files"]}, missing)
    source = read(check["file"])
    missing = [needle for needle in check.get("required", []) if needle not in source]
    return make_result(check["id"], check["name"], not missing, check["category"], {"file": check["file"], "required_patterns": check.get("required", [])}, missing)


def manifest_result() -> dict[str, Any]:
    entries = []
    missing = []
    for relative in MANIFEST_FILES:
        path = ROOT / relative
        if not path.exists():
            missing.append(relative)
            continue
        entries.append({"path": relative, "sha256": sha256_file(path), "bytes": path.stat().st_size})
    manifest = {
        "manifest_version": 1,
        "created_at": utc_now(),
        "redaction_policy": "repo_contract_files_only_no_endpoint_artifacts",
        "chain_of_custody": "local_probe_generated",
        "entries": entries,
    }
    return make_result(
        "dfir-local-triage-manifest-hashes",
        "Local DFIR contract package manifest has SHA-256 hashes and redaction policy",
        not missing and len(entries) >= 3,
        "evidence-integrity",
        manifest,
        missing,
    )


def request_without_auth(server: str, path: str, timeout: float) -> dict[str, Any]:
    url = server.rstrip("/") + path
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(256).decode("utf-8", errors="replace")
            return {"url": url, "status_code": response.status, "body_preview": body}
    except urllib.error.HTTPError as exc:
        body = exc.read(256).decode("utf-8", errors="replace")
        return {"url": url, "status_code": exc.code, "body_preview": body}
    except Exception as exc:
        return {"url": url, "status_code": None, "error": repr(exc), "body_preview": ""}


def remote_deny_result(path: str, response: dict[str, Any]) -> dict[str, Any]:
    code = response.get("status_code")
    return make_result(
        "dfir-unauth-deny-" + path.strip("/").replace("/", "-"),
        f"Unauthenticated DFIR route denied: {path}",
        code in (401, 403),
        "auth",
        response,
        [] if code in (401, 403) else [f"expected_401_or_403_got_{code}"],
    )


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = []
    gap_counts: dict[str, int] = {}
    for test in tests:
        if test["status"] == "covered":
            continue
        gaps.append({
            "test_id": test["id"],
            "status": test["status"],
            "gap_category": test["gap_category"],
            "validation_category": test.get("validation_category"),
            "missing_expected_fields": test.get("missing_expected_fields", []),
            "missing_expected_telemetry": [],
            "missing_expected_detections": [],
            "missing_expected_alerts": [],
            "missing_expected_correlations": [],
            "missing_expected_driver_raw_event_types": [],
            "execution_class": test.get("execution_class"),
            "fallback_used": False,
            "tactics": [],
            "techniques": [],
        })
        gap_counts[test["gap_category"]] = gap_counts.get(test["gap_category"], 0) + 1
    return {
        "tests": len(tests),
        "covered": covered,
        "partial": 0,
        "missed": missed,
        "planned": 0,
        "execution_failed": 0,
        "unknown_source_events": 0,
        "unexpected_high_or_critical_events": 0,
        "unexpected_high_or_critical_alerts": 0,
        "missing_expected_fields": missed,
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"dfir_readiness_probe": len(tests)},
        "execution_class_counts": {"static_code_probe": len(tests)},
        "claim_level_counts": {"dfir_readiness": len(tests)},
        "category_coverage": {},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": gap_counts,
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 72 if passed else int(45 * covered_rate),
        "maturity_band": "dfir-readiness-validation" if passed else "dfir-readiness-gaps",
        "recommended_claim": "DFIR API/catalog/manifest readiness is validated; no endpoint collection or triage export claim" if passed else "DFIR readiness probe has gaps; do not claim DFIR readiness",
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if passed else covered_rate,
        "context_quality": 1.0 if passed else covered_rate,
        "analytic_quality": 1.0 if passed else covered_rate,
        "noise_quality": 1.0,
        "driver_quality": 1.0,
        "upstream_rate": 0.0,
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
        "- Scope: DFIR API/catalog/manifest readiness only; no endpoint artifact collection.",
        "",
        "| Test | Status | Category |",
        "|------|--------|----------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['validation_category']}` |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="https://tamandua.treantlab.org")
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = [source_check_result(check) for check in SOURCE_CHECKS]
    tests.append(manifest_result())
    tests.extend(remote_deny_result(path, request_without_auth(args.server, path, args.timeout)) for path in REMOTE_DENY_PATHS)
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "dfir-hunting",
        "server": args.server,
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "dfir_hunting_readiness_static_api_probe",
                "requires_persisted_events": False,
                "requires_driver_health": False,
                "max_unknown_source_events": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
            },
        },
        "selected_tests": [test["id"] for test in tests],
        "tests": tests,
        "summary": summary,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["dfir_readiness_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "dfir-hunting",
                "fail_on_missed": True,
                "fail_on_partial": False,
                "max_unknown_source": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
                "require_upstream": False,
            },
        },
        "scorecard": scorecard(summary),
        "claim_boundary": "Validates DFIR API/catalog/manifest readiness only. It does not collect endpoint artifacts or prove analyst triage export.",
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "dfir-hunting",
        "summary": summary,
        "quality_gate": report["quality_gate"],
        "scorecard": report["scorecard"],
        "tests": tests,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"{run_id}.json"
    comparison_path = args.output_dir / f"{run_id}.comparison.json"
    md_path = args.output_dir / f"{run_id}.md"
    write_json(json_path, report)
    write_json(comparison_path, comparison)
    write_markdown(md_path, report)
    print(f"json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
