#!/usr/bin/env python3
"""Non-destructive Roadmap K platform capability probe.

This probe promotes Roadmap K beyond report-only contracts by validating
source-level readiness for FIM, inventory, compliance, and SIEM/export, plus
basic unauthenticated deny checks against deployed API routes. It does not
claim live endpoint FIM baselines, vulnerability freshness, compliance posture,
or SIEM delivery acknowledgement.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import urllib.error
import urllib.request
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
PROFILE_ID = "platform-capabilities-static-api-probe"
PROFILE_NAME = "Platform Capabilities Static/API Probe"


SOURCE_CHECKS: list[dict[str, Any]] = [
    {
        "id": "platform-fim-agent-collector-contract",
        "name": "Agent FIM collector exposes baseline, hash, permission, owner, and compliance fields",
        "capability": "fim",
        "category": "collector",
        "file": "apps/tamandua_agent/src/collectors/fim.rs",
        "required": [
            "pub struct FileIntegrityEvent",
            "pub previous_hash: Vec<u8>",
            "pub current_hash: Vec<u8>",
            "pub previous_permissions: String",
            "pub current_permissions: String",
            "pub compliance_impact: Vec<ComplianceFramework>",
            "pub modifier_pid: Option<u32>",
            "pub modifier_process: Option<String>",
            "pub struct FileBaseline",
        ],
    },
    {
        "id": "platform-fim-server-persistence-contract",
        "name": "Server FIM persistence stores baselines, history, changes, whitelist, and review state",
        "capability": "fim",
        "category": "persistence",
        "file": "apps/tamandua_server/priv/repo/migrations/20260226012000_create_fim_tables.exs",
        "required": [
            "create table(:fim_baselines",
            "create table(:fim_baseline_history",
            "create table(:fim_changes",
            "create table(:fim_whitelist_rules",
            "add :previous_hash",
            "add :current_hash",
            "add :compliance_impact",
            "add :modifier_process",
            "add :reviewed",
            "add :remediated",
        ],
    },
    {
        "id": "platform-fim-backend-manager-contract",
        "name": "FIM backend can store baselines, record changes, whitelist, and report stats",
        "capability": "fim",
        "category": "backend",
        "file": "apps/tamandua_server/lib/tamandua_server/fim/baseline_manager.ex",
        "required": [
            "def store_baseline(agent_id, path, baseline_data)",
            "def record_change(agent_id, change_data)",
            "def get_recent_changes(agent_id, opts \\\\ [])",
            "def generate_compliance_report(agent_id, framework)",
            "def add_whitelist_rule(agent_id, rule_data)",
            "def get_stats(agent_id)",
        ],
    },
    {
        "id": "platform-fim-ui-route-contract",
        "name": "Operational UI exposes FIM view",
        "capability": "fim",
        "category": "analyst-ux",
        "file": "apps/tamandua_server/lib/tamandua_server_web/router.ex",
        "required": ["live(\"/fim\", FimLive, :index)"],
    },
    {
        "id": "platform-inventory-asset-schema-contract",
        "name": "Inventory asset schema carries host, hardware, software, network, risk, and vulnerability data",
        "capability": "inventory",
        "category": "normalization",
        "file": "apps/tamandua_server/lib/tamandua_server/inventory/asset_manager.ex",
        "required": [
            "field :agent_id, :binary_id",
            "field :hostname, :string",
            "field :os_build, :string",
            "field :ip_addresses, {:array, :string}",
            "field :cpu_model, :string",
            "field :installed_software, {:array, :map}",
            "field :running_services, {:array, :map}",
            "field :open_ports, {:array, :map}",
            "field :vulnerabilities, {:array, :map}",
            "field :critical_vuln_count, :integer",
        ],
    },
    {
        "id": "platform-inventory-agent-software-collector",
        "name": "Agent has software inventory collector for endpoint package/application metadata",
        "capability": "inventory",
        "category": "collector",
        "file": "apps/tamandua_agent/src/collectors/software_inventory.rs",
        "required": ["software", "inventory"],
    },
    {
        "id": "platform-compliance-framework-pack-contract",
        "name": "Compliance framework pack exists for common audit frameworks",
        "capability": "compliance",
        "category": "content",
        "files": [
            "apps/tamandua_server/priv/compliance_frameworks/cis_benchmarks.yml",
            "apps/tamandua_server/priv/compliance_frameworks/soc2.yml",
            "apps/tamandua_server/priv/compliance_frameworks/iso_27001.yml",
            "apps/tamandua_server/priv/compliance_frameworks/nist_csf.yml",
        ],
    },
    {
        "id": "platform-compliance-evidence-contract",
        "name": "Compliance evidence collector hashes evidence and supports export",
        "capability": "compliance",
        "category": "evidence",
        "file": "apps/tamandua_server/lib/tamandua_server/compliance/evidence_collector.ex",
        "required": [
            "defmodule Evidence do",
            ":framework",
            ":control_id",
            ":evidence_type",
            ":hash",
            "def collect_framework_evidence(framework_id, options \\\\ %{})",
            "def export_evidence(framework_id, period_start, period_end, format \\\\ :json)",
            "hash: hash_evidence(data)",
        ],
    },
    {
        "id": "platform-compliance-api-route-contract",
        "name": "Compliance API exposes overview, framework, controls, assessment, and evidence routes",
        "capability": "compliance",
        "category": "api",
        "file": "apps/tamandua_server/lib/tamandua_server_web/router.ex",
        "required": [
            "get(\"/compliance/overview\", ComplianceController, :overview)",
            "get(\"/compliance/frameworks\", ComplianceController, :list_frameworks)",
            "get(\"/compliance/frameworks/:framework/controls\", ComplianceController, :list_controls)",
            "post(\"/compliance/controls/:control_id/assess\", ComplianceController, :assess_control)",
            "post(\"/compliance/controls/:control_id/evidence\", ComplianceController, :collect_evidence)",
        ],
    },
    {
        "id": "platform-siem-router-contract",
        "name": "SIEM router supports immediate/batch dispatch, enabled connectors, and stats",
        "capability": "siem_export",
        "category": "integration",
        "file": "apps/tamandua_server/lib/tamandua_server/integrations/siem_router.ex",
        "required": [
            "def route_alert(alert, opts \\\\ [])",
            "def route_batch(alerts, opts \\\\ []) when is_list(alerts)",
            "def queue_for_batch(alert)",
            "def get_enabled_siem_integrations",
            "def get_stats do",
            "splunk: SplunkHEC",
            "sentinel: SentinelConnector",
        ],
    },
    {
        "id": "platform-siem-api-route-contract",
        "name": "Integration API exposes SIEM test, forward, and stats routes",
        "capability": "siem_export",
        "category": "api",
        "file": "apps/tamandua_server/lib/tamandua_server_web/router.ex",
        "required": [
            "post(\"/integrations/siem/test\", IntegrationsController, :test_siem_connection)",
            "post(\"/integrations/siem/forward\", IntegrationsController, :forward_to_siem)",
            "get(\"/integrations/siem/stats\", IntegrationsController, :siem_stats)",
            "post(\"/logs/ingest/cef\", LogIngestionController, :ingest_cef)",
            "post(\"/logs/ingest/syslog\", LogIngestionController, :ingest_syslog)",
        ],
    },
    {
        "id": "platform-siem-forwarder-contract",
        "name": "Audit forwarders provide SIEM/syslog delivery surfaces",
        "capability": "siem_export",
        "category": "integration",
        "files": [
            "apps/tamandua_server/lib/tamandua_server/audit/forwarders/siem_forwarder.ex",
            "apps/tamandua_server/lib/tamandua_server/audit/forwarders/syslog_forwarder.ex",
            "apps/tamandua_agent/src/transport/siem.rs",
        ],
    },
]


REMOTE_DENY_PATHS = [
    "/api/v1/compliance/overview",
    "/api/v1/compliance/frameworks",
    "/api/v1/integrations",
    "/api/v1/integrations/siem/stats",
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
    return {"commit": commit, "commit_short": commit[:8] if commit else "", "dirty": bool(status), "status_short": status}


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8", errors="replace")


def make_result(
    test_id: str,
    name: str,
    passed: bool,
    capability: str,
    category: str,
    evidence: dict[str, Any],
    missing: list[str] | None = None,
    executor: str = "platform_capabilities_probe",
) -> dict[str, Any]:
    status = "covered" if passed else "missed"
    return {
        "id": test_id,
        "name": name,
        "status": status,
        "gap_category": "none" if passed else category,
        "execution_class": "static_api_probe" if executor == "platform_capabilities_probe" else "remote_api_probe",
        "claim_level": "platform_capability_readiness",
        "executor_used": executor,
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": category,
        "capability": capability,
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


def source_result(check: dict[str, Any]) -> dict[str, Any]:
    if check.get("files"):
        missing = [path for path in check["files"] if not (ROOT / path).exists()]
        return make_result(
            check["id"],
            check["name"],
            not missing,
            check["capability"],
            check["category"],
            {"files": check["files"]},
            missing,
        )

    source = read(check["file"])
    missing = [needle for needle in check.get("required", []) if needle not in source]
    return make_result(
        check["id"],
        check["name"],
        not missing,
        check["capability"],
        check["category"],
        {"file": check["file"], "required_patterns": check.get("required", [])},
        missing,
    )


def request_without_auth(server: str, path: str, timeout: float) -> dict[str, Any]:
    url = server.rstrip("/") + path
    request = urllib.request.Request(url, method="GET")
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=timeout) as response:
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
        "platform-unauth-deny-" + path.strip("/").replace("/", "-"),
        f"Unauthenticated platform route denied: {path}",
        code in (401, 403),
        "control_plane_api",
        "auth",
        response,
        [] if code in (401, 403) else [f"expected_401_or_403_got_{code}"],
        executor="remote_api_deny",
    )


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gap_counts: dict[str, int] = {}
    capability_coverage: dict[str, dict[str, int]] = {}
    gaps = []
    for test in tests:
        capability = test.get("capability", "unknown")
        capability_coverage.setdefault(capability, {"covered": 0, "missed": 0})
        capability_coverage[capability]["covered" if test["status"] == "covered" else "missed"] += 1
        if test["status"] == "covered":
            continue
        gap = {
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
        }
        gaps.append(gap)
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
        "executor_counts": {"platform_capabilities_probe": len(tests)},
        "execution_class_counts": {"static_api_probe": len(tests)},
        "claim_level_counts": {"platform_capability_readiness": len(tests)},
        "category_coverage": capability_coverage,
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
        "maturity_score": 76 if passed else int(50 * covered_rate),
        "maturity_band": "platform-capability-readiness" if passed else "platform-capability-gaps",
        "recommended_claim": (
            "Platform capability source/API readiness is validated for FIM, inventory, compliance, and SIEM; "
            "no live endpoint baseline or external SIEM delivery claim"
            if passed
            else "Platform capability probe has gaps; keep Roadmap K report-only"
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
        "- Scope: source/API readiness only; no live endpoint FIM baseline, compliance posture, or SIEM delivery claim.",
        "",
        "| Test | Status | Capability | Category |",
        "|------|--------|------------|----------|",
    ]
    for test in report["tests"]:
        lines.append(
            f"| `{test['id']}` | `{test['status']}` | `{test.get('capability', '')}` | `{test['validation_category']}` |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="https://tamandua.treantlab.org")
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = [source_result(check) for check in SOURCE_CHECKS]
    tests.extend(remote_deny_result(path, request_without_auth(args.server, path, args.timeout)) for path in REMOTE_DENY_PATHS)
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "platform-capability",
        "server": args.server,
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "platform_capabilities_static_api_probe",
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
            "failures": [] if passed else ["platform_capability_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "platform-capability",
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
            "Validates platform capability source/API readiness only. It does not prove live FIM baselines, "
            "inventory freshness, compliance control posture, or acknowledged SIEM delivery."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "platform-capability",
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
