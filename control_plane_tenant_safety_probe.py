#!/usr/bin/env python3
"""Non-destructive Roadmap N control-plane safety probe.

This probe is intentionally narrower than a full multi-tenant integration test:
it validates static tenant/RBAC/audit guardrails in the server source and
performs unauthenticated deny checks against a deployed server. It should not be
used to claim complete tenant isolation until paired with real two-tenant API
fixtures.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "control-plane-tenant-safety-static-probe"
PROFILE_NAME = "Control Plane Tenant Safety Static/API Probe"


STATIC_CHECKS: list[dict[str, Any]] = [
    {
        "id": "tenant-scope-helper-enforced",
        "name": "TenantScope rejects nil tenant and provides scoped reads",
        "category": "tenant-isolation",
        "file": "apps/tamandua_server/lib/tamandua_server/tenant_scope.ex",
        "required": [
            "def scope_to_tenant(query, org_id) when not is_nil(org_id)",
            "organization_id cannot be nil when scoping query",
            "def get_scoped(schema, org_id, id)",
            "def belongs_to_tenant?(schema, org_id, id)",
        ],
    },
    {
        "id": "agents-context-tenant-scoped",
        "name": "Agent context exposes tenant-scoped list/show/create helpers",
        "category": "tenant-isolation",
        "file": "apps/tamandua_server/lib/tamandua_server/agents.ex",
        "required": [
            "def list_agents_for_org(organization_id",
            "TenantScope.scope_to_tenant(organization_id)",
            "def get_agent_for_org(organization_id, agent_id)",
            "def create_agent_for_org(organization_id, attrs)",
            "def count_online_for_org(organization_id)",
        ],
    },
    {
        "id": "alerts-context-tenant-scoped",
        "name": "Alert context and bulk operations accept organization scope",
        "category": "tenant-isolation",
        "file": "apps/tamandua_server/lib/tamandua_server/alerts.ex",
        "required": [
            "def list_alerts_for_org(organization_id",
            "def get_alert_for_org(organization_id, alert_id)",
            "def get_alert_with_evidence_for_org(organization_id, id)",
            "organization_id = Keyword.get(opts, :organization_id)",
            "|> TenantScope.scope_to_tenant(organization_id)",
        ],
    },
    {
        "id": "api-auth-requires-user-context",
        "name": "API pipeline requires bearer/session auth and assigns tenant context",
        "category": "auth",
        "file": "apps/tamandua_server/lib/tamandua_server_web/plugs/api_auth.ex",
        "required": [
            "unauthorized(conn, \"Missing authorization header or session\")",
            "TamanduaServer.CLIAuth.verify_token(token)",
            "assign(:current_user, user)",
            "assign(:current_organization_id, Map.get(user, :organization_id))",
        ],
    },
    {
        "id": "api-pipeline-requires-tenant-context",
        "name": "Authenticated API pipeline adds tenant context checks",
        "category": "tenant-isolation",
        "file": "apps/tamandua_server/lib/tamandua_server_web/router.ex",
        "required": [
            "plug(TamanduaServerWeb.Plugs.APIAuth)",
            "plug(TamanduaServerWeb.Plugs.SetOrganizationContext)",
            "plug(TamanduaServerWeb.Plugs.RequireTenantContext",
            "plug(TamanduaServerWeb.Plugs.TenantSuspension",
        ],
    },
    {
        "id": "rbac-controller-cross-user-denies",
        "name": "RBAC controller rejects cross-organization user operations",
        "category": "rbac",
        "file": "apps/tamandua_server/lib/tamandua_server_web/controllers/api/v1/rbac_controller.ex",
        "required": [
            "org_id = conn.assigns[:current_user].organization_id",
            "user.organization_id == org_id",
            "user.organization_id != org_id",
            "RBACAuditLog.log_role_assigned",
            "RBACAuditLog.list_for_user(org_id, user_id",
        ],
    },
    {
        "id": "api-key-lifecycle-scoped",
        "name": "API keys are org-scoped, hashed, expirable, and permission-gated",
        "category": "token-scope",
        "file": "apps/tamandua_server/lib/tamandua_server/accounts/api_key.ex",
        "required": [
            "belongs_to :organization, Organization",
            "key_hash",
            "Bcrypt.hash_pwd_salt(raw_key)",
            "def valid?(%__MODULE__{is_active: false}), do: false",
            "def has_permission?(%__MODULE__{scope: \"read_only\"}, permission)",
        ],
    },
    {
        "id": "rbac-audit-append-only-schema",
        "name": "RBAC audit log has tenant scope and append-only timestamps",
        "category": "audit",
        "file": "apps/tamandua_server/lib/tamandua_server/accounts/rbac_audit_log.ex",
        "required": [
            "schema \"rbac_audit_log\"",
            "belongs_to :organization, Organization",
            "timestamps(type: :utc_datetime_usec, updated_at: false)",
            "defp create_entry(attrs)",
            "where: al.organization_id == ^org_id",
        ],
        "forbidden": [
            "def update_",
            "def delete_",
            "Repo.update",
            "Repo.delete",
        ],
    },
    {
        "id": "response-controller-audits-actions",
        "name": "Response actions resolve org context and write audit entries",
        "category": "response",
        "file": "apps/tamandua_server/lib/tamandua_server_web/controllers/api/v1/response_controller.ex",
        "required": [
            "current_organization_id(conn)",
            "AuditLog.log_response_action",
            "organization_id: current_organization_id(conn)",
            "defp current_organization_id(conn)",
        ],
    },
]


DEFAULT_REMOTE_DENY_PATHS = [
    "/api/v1/agents",
    "/api/v1/agents/data-sources/health",
    "/api/v1/alerts",
    "/api/v1/alerts/summary",
    "/api/v1/events",
    "/api/v1/response/metrics",
    "/api/v1/response-audit",
    "/api/v1/rbac/roles",
    "/api/v1/rbac/audit-log",
    "/api/v1/api-keys",
    "/api/v1/tenants",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


def read_text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8", errors="replace")


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            completed = subprocess.run(
                args,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return completed.stdout.strip()
        except OSError:
            return ""

    status = run(["git", "status", "--short"]).splitlines()
    commit = run(["git", "rev-parse", "HEAD"])
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def static_result(check: dict[str, Any]) -> dict[str, Any]:
    source = read_text(check["file"])
    missing = [needle for needle in check.get("required", []) if needle not in source]
    forbidden_hits = [needle for needle in check.get("forbidden", []) if needle in source]
    status = "covered" if not missing and not forbidden_hits else "missed"
    gap_category = "none" if status == "covered" else check["category"]
    return {
        "id": check["id"],
        "name": check["name"],
        "status": status,
        "gap_category": gap_category,
        "execution_class": "static_code_probe",
        "claim_level": "control_plane_static",
        "executor_used": "source_scan",
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": check["category"],
        "coverage": {
            "telemetry": "not_expected",
            "fields": "ok" if status == "covered" else "missing",
            "detection": "not_expected",
            "alert": "not_expected",
            "correlation": "not_expected",
            "driver_raw": "not_expected",
            "timeline": "not_expected",
            "values": "ok" if status == "covered" else "missing",
        },
        "evidence": {
            "file": check["file"],
            "required_patterns": check.get("required", []),
            "forbidden_patterns": check.get("forbidden", []),
            "missing_patterns": missing,
            "forbidden_hits": forbidden_hits,
        },
        "missing_expected_fields": missing + [f"forbidden:{hit}" for hit in forbidden_hits],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [],
    }


def request_without_auth(server: str, path: str, timeout: float) -> dict[str, Any]:
    url = server.rstrip("/") + path
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(512).decode("utf-8", errors="replace")
            return {"url": url, "status_code": response.status, "body_preview": body}
    except urllib.error.HTTPError as exc:
        body = exc.read(512).decode("utf-8", errors="replace")
        return {"url": url, "status_code": exc.code, "body_preview": body}
    except Exception as exc:  # network is evidence, but should not mask static checks
        return {"url": url, "status_code": None, "error": repr(exc), "body_preview": ""}


def remote_deny_result(path: str, response: dict[str, Any]) -> dict[str, Any]:
    code = response.get("status_code")
    status = "covered" if code in (401, 403) else "missed"
    gap_category = "none" if status == "covered" else "auth"
    return {
        "id": "unauth-deny-" + path.strip("/").replace("/", "-"),
        "name": f"Unauthenticated request denied: {path}",
        "status": status,
        "gap_category": gap_category,
        "execution_class": "remote_api_probe",
        "claim_level": "control_plane_api_deny",
        "executor_used": "https_get_without_auth",
        "fallback_used": False,
        "upstream_backed": False,
        "validation_category": "auth",
        "coverage": {
            "telemetry": "not_expected",
            "fields": "ok" if status == "covered" else "missing",
            "detection": "not_expected",
            "alert": "not_expected",
            "correlation": "not_expected",
            "driver_raw": "not_expected",
            "timeline": "not_expected",
            "values": "ok" if status == "covered" else "missing",
        },
        "evidence": response,
        "missing_expected_fields": [] if status == "covered" else [f"expected_401_or_403_got_{code}"],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "observed_telemetry_alternative": [],
        "expected_telemetry_any": [],
    }


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = sum(1 for test in tests if test["status"] != "covered")
    gaps: list[dict[str, Any]] = []
    gap_counts: dict[str, int] = {}
    category_coverage: dict[str, int] = {}

    for test in tests:
        category = str(test.get("validation_category") or "control-plane")
        if test["status"] == "covered":
            category_coverage[category] = category_coverage.get(category, 0) + 1
        if test["status"] != "covered":
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
        "executor_counts": {
            "source_scan": sum(1 for test in tests if test["executor_used"] == "source_scan"),
            "https_get_without_auth": sum(1 for test in tests if test["executor_used"] == "https_get_without_auth"),
        },
        "execution_class_counts": {
            "static_code_probe": sum(1 for test in tests if test["execution_class"] == "static_code_probe"),
            "remote_api_probe": sum(1 for test in tests if test["execution_class"] == "remote_api_probe"),
        },
        "claim_level_counts": {
            "control_plane_static": sum(1 for test in tests if test["claim_level"] == "control_plane_static"),
            "control_plane_api_deny": sum(1 for test in tests if test["claim_level"] == "control_plane_api_deny"),
        },
        "category_coverage": category_coverage,
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": gap_counts,
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    total = summary["tests"] or 1
    covered_rate = summary["covered"] / total
    gate_clean = summary["missed"] == 0
    return {
        "maturity_score": 82 if gate_clean else int(50 * covered_rate),
        "maturity_band": "control-plane-static-api-validation" if gate_clean else "control-plane-gaps",
        "recommended_claim": (
            "Control-plane source and unauthenticated API deny guardrails are validated; "
            "two-tenant runtime isolation still requires executed API fixtures"
        )
        if gate_clean
        else "Control-plane safety probe found gaps; do not make tenant-safety claims",
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if gate_clean else covered_rate,
        "context_quality": 1.0 if gate_clean else covered_rate,
        "analytic_quality": 1.0 if gate_clean else covered_rate,
        "noise_quality": 1.0,
        "driver_quality": 1.0,
        "upstream_rate": 0.0,
        "blocking_gaps": []
        if gate_clean
        else sorted(summary["gap_category_counts"].keys()),
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    summ = report["summary"]
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Server: `{report['server']}`",
        f"- Gate: `{'pass' if report['quality_gate']['passed'] else 'fail'}`",
        f"- Covered: `{summ['covered']}/{summ['tests']}`",
        f"- Scope: static server guardrails plus unauthenticated deny probes; not full two-tenant runtime proof.",
        "",
        "## Results",
        "",
        "| Test | Status | Category | Evidence |",
        "|------|--------|----------|----------|",
    ]
    for test in report["tests"]:
        evidence = test.get("evidence", {})
        evidence_ref = evidence.get("file") or evidence.get("url") or "-"
        lines.append(
            f"| `{test['id']}` | `{test['status']}` | `{test.get('validation_category')}` | `{evidence_ref}` |"
        )
    if summ["actionable_gaps"]:
        lines += ["", "## Gaps", ""]
        for gap in summ["actionable_gaps"]:
            lines.append(
                f"- `{gap['test_id']}`: `{gap['gap_category']}` missing `{gap['missing_expected_fields']}`"
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="https://tamandua.treantlab.org")
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    started_at = utc_now()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"

    static_tests = [static_result(check) for check in STATIC_CHECKS]
    remote_tests = [
        remote_deny_result(path, request_without_auth(args.server, path, args.timeout))
        for path in DEFAULT_REMOTE_DENY_PATHS
    ]
    tests = static_tests + remote_tests
    summ = build_summary(tests)
    passed = summ["missed"] == 0
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "control-plane-safety",
        "server": args.server,
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "control-plane",
            "quality_bar": {
                "purpose": "tenant_safety_static_api_probe",
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
        "summary": summ,
        "quality_gate": {
            "passed": passed,
            "failures": [] if passed else ["control_plane_safety_gaps"],
            "actionable_gaps": summ["actionable_gaps"],
            "gap_category_counts": summ["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "control-plane-safety",
                "fail_on_missed": True,
                "fail_on_partial": False,
                "max_unknown_source": 0,
                "max_unexpected_high_critical": 0,
                "max_driver_channel_drops": 0,
                "max_driver_kernel_drops": 0,
                "require_upstream": False,
            },
        },
        "scorecard": scorecard(summ),
        "claim_boundary": (
            "Validates source-level control-plane guardrails and unauthenticated deny behavior only. "
            "It does not prove full cross-tenant runtime isolation with separate tenant fixtures."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "control-plane-safety",
        "summary": summ,
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
    write_markdown(report, md_path)
    print(f"json={json_path} markdown={md_path} comparison_json={comparison_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
