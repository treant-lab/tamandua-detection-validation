#!/usr/bin/env python3
"""Local DFIR collection evidence fixture for Roadmap T.

This deterministic fixture validates the evidence semantics expected from a
DFIR hunt/collection package without touching endpoints, the server, or live
alerts. It is a regression contract for collection quality, export integrity,
analyst review, and chain-of-custody semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "dfir-collection-fixture-probe"
PROFILE_NAME = "DFIR Collection Fixture Probe"


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


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def test_result(
    test_id: str,
    name: str,
    passed: bool,
    evidence: dict[str, Any],
    missing: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if passed else "missed",
        "gap_category": None if passed else "dfir-fixture",
        "validation_category": "dfir_collection",
        "execution_class": "local_fixture_probe",
        "fallback_used": False,
        "claim_level": "dfir_collection_fixture_contract",
        "tactics": [],
        "techniques": [],
        "evidence": evidence,
        "missing_expected_fields": missing or [],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def fixture() -> dict[str, Any]:
    artifacts = [
        {"type": "process_tree", "path": "collections/hunt-001/process_tree.json", "bytes": 3200, "redacted": False},
        {"type": "autoruns", "path": "collections/hunt-001/autoruns.json", "bytes": 5400, "redacted": False},
        {"type": "services", "path": "collections/hunt-001/services.json", "bytes": 4300, "redacted": False},
        {"type": "scheduled_tasks", "path": "collections/hunt-001/tasks.json", "bytes": 3800, "redacted": False},
        {"type": "registry_persistence", "path": "collections/hunt-001/registry_persistence.json", "bytes": 2600, "redacted": False},
        {"type": "recent_files", "path": "collections/hunt-001/recent_files.json", "bytes": 1900, "redacted": True},
        {"type": "browser_artifacts", "path": "collections/hunt-001/browser_artifacts.json", "bytes": 2100, "redacted": True},
        {"type": "event_logs", "path": "collections/hunt-001/event_logs.evtx.manifest.json", "bytes": 4100, "redacted": False},
        {"type": "powershell_history", "path": "collections/hunt-001/powershell_history.txt.manifest.json", "bytes": 900, "redacted": True},
        {"type": "network_connections", "path": "collections/hunt-001/network_connections.json", "bytes": 1700, "redacted": False},
        {"type": "selected_file", "path": "collections/hunt-001/files/suspicious.lnk.metadata.json", "bytes": 1200, "redacted": False},
    ]
    for artifact in artifacts:
        artifact["sha256"] = sha256_json({"type": artifact["type"], "path": artifact["path"], "bytes": artifact["bytes"]})

    collection = {
        "hunt_id": "hunt-fixture-001",
        "tenant_id": "tenant-alpha",
        "agent_id": "agent-fixture-win-1",
        "hostname": "WIN-FIXTURE",
        "platform": "windows",
        "status": "completed",
        "started_at": "2026-06-02T08:00:00Z",
        "finished_at": "2026-06-02T08:02:20Z",
        "duration_ms": 140000,
        "bytes_collected": sum(item["bytes"] for item in artifacts),
        "errors": [],
        "artifacts": artifacts,
    }
    manifest = {
        "package_id": "dfir-pkg-fixture-001",
        "hunt_id": collection["hunt_id"],
        "agent_id": collection["agent_id"],
        "created_at": utc_now(),
        "format": "tamandua-dfir-package-v1",
        "artifact_count": len(artifacts),
        "artifact_hashes": {item["path"]: item["sha256"] for item in artifacts},
        "package_sha256": sha256_json(artifacts),
        "redaction_policy": {
            "mode": "metadata-first",
            "redacted_artifact_types": sorted(item["type"] for item in artifacts if item["redacted"]),
            "raw_secret_patterns_allowed": False,
        },
    }
    review = {
        "review_id": "review-fixture-001",
        "hunt_id": collection["hunt_id"],
        "analyst": "analyst-fixture",
        "status": "review_ready",
        "search_indexed_fields": ["type", "path", "sha256", "agent_id", "hostname", "collected_at"],
        "linked_alert_ids": ["alert-fixture-001"],
        "notes": "fixture package ready for analyst triage",
    }
    custody = {
        "hunt_id": collection["hunt_id"],
        "events": [
            {"action": "collection_requested", "actor": "analyst-fixture", "at": "2026-06-02T08:00:00Z"},
            {"action": "collection_completed", "actor": "agent-fixture-win-1", "at": "2026-06-02T08:02:20Z"},
            {"action": "package_exported", "actor": "server-fixture", "at": "2026-06-02T08:02:30Z"},
            {"action": "analyst_review_linked", "actor": "analyst-fixture", "at": "2026-06-02T08:03:00Z"},
        ],
        "append_only": True,
    }
    raw_payload = json.dumps({"manifest": manifest, "review": review, "custody": custody}, sort_keys=True)
    return {"collection": collection, "manifest": manifest, "review": review, "custody": custody, "raw_payload": raw_payload}


def collect_tests() -> list[dict[str, Any]]:
    data = fixture()
    collection = data["collection"]
    manifest = data["manifest"]
    review = data["review"]
    custody = data["custody"]

    required_types = {
        "process_tree",
        "autoruns",
        "services",
        "scheduled_tasks",
        "registry_persistence",
        "recent_files",
        "browser_artifacts",
        "event_logs",
        "powershell_history",
        "network_connections",
        "selected_file",
    }
    present_types = {item["type"] for item in collection["artifacts"]}
    missing_types = sorted(required_types - present_types)
    catalog_ok = collection["status"] == "completed" and not collection["errors"] and not missing_types

    status_ok = (
        collection["duration_ms"] > 0
        and collection["bytes_collected"] == sum(item["bytes"] for item in collection["artifacts"])
        and all(item.get("sha256") for item in collection["artifacts"])
    )

    manifest_ok = (
        manifest["artifact_count"] == len(collection["artifacts"])
        and len(manifest["artifact_hashes"]) == len(collection["artifacts"])
        and bool(manifest["package_sha256"])
        and manifest["format"] == "tamandua-dfir-package-v1"
    )

    redaction_ok = (
        manifest["redaction_policy"]["mode"] == "metadata-first"
        and manifest["redaction_policy"]["raw_secret_patterns_allowed"] is False
        and {"browser_artifacts", "powershell_history", "recent_files"}.issubset(
            set(manifest["redaction_policy"]["redacted_artifact_types"])
        )
        and "password=" not in data["raw_payload"].lower()
        and "secret=" not in data["raw_payload"].lower()
    )

    review_ok = (
        review["hunt_id"] == collection["hunt_id"]
        and review["status"] == "review_ready"
        and {"type", "path", "sha256", "agent_id", "hostname"}.issubset(set(review["search_indexed_fields"]))
        and bool(review["linked_alert_ids"])
    )

    custody_ok = (
        custody["hunt_id"] == collection["hunt_id"]
        and custody["append_only"] is True
        and [event["action"] for event in custody["events"]]
        == ["collection_requested", "collection_completed", "package_exported", "analyst_review_linked"]
    )

    return [
        test_result(
            "dfir-artifact-catalog-fixture",
            "DFIR fixture includes the first Windows artifact catalog without collection errors",
            catalog_ok,
            {"required_types": sorted(required_types), "present_types": sorted(present_types), "missing_types": missing_types},
            missing_types,
        ),
        test_result(
            "dfir-collection-status-fixture",
            "DFIR fixture records per-agent status, duration, bytes, errors, and artifact hashes",
            status_ok,
            {"collection": collection},
        ),
        test_result(
            "dfir-export-manifest-fixture",
            "DFIR fixture exports a package manifest with per-artifact hashes and package hash",
            manifest_ok,
            {"manifest": manifest},
        ),
        test_result(
            "dfir-redaction-policy-fixture",
            "DFIR fixture enforces metadata-first redaction for sensitive artifact families",
            redaction_ok,
            {"redaction_policy": manifest["redaction_policy"]},
        ),
        test_result(
            "dfir-analyst-review-fixture",
            "DFIR fixture links hunt output to searchable analyst review and alert context",
            review_ok,
            {"review": review},
        ),
        test_result(
            "dfir-chain-of-custody-fixture",
            "DFIR fixture records ordered append-only chain-of-custody actions",
            custody_ok,
            {"custody": custody},
        ),
    ]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gaps = [test for test in tests if test["status"] != "covered"]
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
        "missing_expected_fields": sum(len(test["missing_expected_fields"]) for test in tests),
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"dfir_collection_fixture_probe": len(tests)},
        "execution_class_counts": {"local_fixture_probe": len(tests)},
        "claim_level_counts": {"dfir_collection_fixture_contract": len(tests)},
        "category_coverage": {"dfir_collection": {"covered": covered, "missed": missed}},
        "roadmap_coverage": {"T": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"dfir-fixture": missed} if missed else {},
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    passed = summary["missed"] == 0
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    return {
        "maturity_score": 82 if passed else int(50 * covered_rate),
        "maturity_band": "dfir-fixture-contract-ready" if passed else "dfir-fixture-gaps",
        "recommended_claim": (
            "DFIR collection fixture is green for artifact catalog, export manifest, redaction, analyst review, and custody"
            if passed
            else "DFIR collection fixture gaps remain"
        ),
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
        "- Scope: local deterministic DFIR collection fixture contract only.",
        "- Runtime effect: none; no endpoint, server, DB, live hunt, or alert mutation.",
        "",
        "| Test | Status |",
        "|------|--------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` |")
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = collect_tests()
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "dfir-hunting",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "windows",
            "quality_bar": {
                "purpose": "dfir_collection_fixture",
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
            "failures": [] if passed else ["dfir_collection_fixture_gaps"],
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
        "claim_boundary": (
            "Local DFIR collection fixture only. It proves expected package semantics for catalog, "
            "collection status, manifest hashes, redaction, analyst review, and chain-of-custody. "
            "It does not prove live endpoint artifact collection, live export, real analyst search, "
            "or Velociraptor-class coverage."
        ),
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
