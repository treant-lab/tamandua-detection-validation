#!/usr/bin/env python3
"""Local two-tenant control-plane fixture probe for Roadmap N.

This is a deterministic fixture test, not a production database integration
test. It exercises tenant isolation, token scope, revocation, role denial,
append-only audit semantics, and destructive-response approval requirements in
memory so the expected enterprise safety rules are executable and regression
gated before live two-tenant API fixtures are available.
"""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
PROFILE_ID = "control-plane-two-tenant-fixture-probe"
PROFILE_NAME = "Control Plane Two-Tenant Fixture Probe"


@dataclass(frozen=True)
class User:
    id: str
    tenant_id: str
    role: str


@dataclass(frozen=True)
class Token:
    id: str
    tenant_id: str
    scopes: tuple[str, ...]
    active: bool = True


@dataclass(frozen=True)
class Agent:
    id: str
    tenant_id: str
    hostname: str


@dataclass(frozen=True)
class Alert:
    id: str
    tenant_id: str
    agent_id: str


TENANT_A = "tenant-alpha"
TENANT_B = "tenant-bravo"

USERS = {
    "a-admin": User("a-admin", TENANT_A, "admin"),
    "a-analyst": User("a-analyst", TENANT_A, "analyst"),
    "a-viewer": User("a-viewer", TENANT_A, "viewer"),
    "b-admin": User("b-admin", TENANT_B, "admin"),
}

TOKENS = {
    "a-read": Token("a-read", TENANT_A, ("alerts:read", "agents:read")),
    "a-response": Token("a-response", TENANT_A, ("alerts:read", "response:execute")),
    "a-revoked": Token("a-revoked", TENANT_A, ("alerts:read",), active=False),
    "b-read": Token("b-read", TENANT_B, ("alerts:read", "agents:read")),
}

AGENTS = {
    "agent-a": Agent("agent-a", TENANT_A, "alpha-win"),
    "agent-b": Agent("agent-b", TENANT_B, "bravo-linux"),
}

ALERTS = {
    "alert-a": Alert("alert-a", TENANT_A, "agent-a"),
    "alert-b": Alert("alert-b", TENANT_B, "agent-b"),
}

ROLE_PERMISSIONS = {
    "admin": {"alerts:read", "agents:read", "policy:write", "response:execute", "audit:read"},
    "analyst": {"alerts:read", "agents:read", "response:request", "audit:read"},
    "viewer": {"alerts:read", "agents:read"},
}


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


def can_read_alert(user: User, token: Token, alert: Alert) -> tuple[bool, str]:
    if not token.active:
        return False, "token_revoked"
    if user.tenant_id != token.tenant_id:
        return False, "token_tenant_mismatch"
    if alert.tenant_id != user.tenant_id:
        return False, "cross_tenant_alert_denied"
    if "alerts:read" not in token.scopes:
        return False, "token_scope_missing"
    if "alerts:read" not in ROLE_PERMISSIONS[user.role]:
        return False, "role_scope_missing"
    return True, "allowed"


def can_read_agent(user: User, token: Token, agent: Agent) -> tuple[bool, str]:
    if not token.active:
        return False, "token_revoked"
    if user.tenant_id != token.tenant_id:
        return False, "token_tenant_mismatch"
    if agent.tenant_id != user.tenant_id:
        return False, "cross_tenant_agent_denied"
    if "agents:read" not in token.scopes:
        return False, "token_scope_missing"
    if "agents:read" not in ROLE_PERMISSIONS[user.role]:
        return False, "role_scope_missing"
    return True, "allowed"


def can_execute_response(user: User, token: Token, alert: Alert, approval: dict[str, Any] | None) -> tuple[bool, str]:
    if not token.active:
        return False, "token_revoked"
    if user.tenant_id != token.tenant_id or alert.tenant_id != user.tenant_id:
        return False, "tenant_mismatch"
    if "response:execute" not in token.scopes:
        return False, "token_scope_missing"
    if "response:execute" not in ROLE_PERMISSIONS[user.role]:
        return False, "role_scope_missing"
    if not approval or approval.get("tenant_id") != user.tenant_id or approval.get("approved_by_role") != "admin":
        return False, "approval_required"
    return True, "allowed"


def append_audit(log: tuple[dict[str, Any], ...], entry: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    required = {"tenant_id", "actor_id", "action", "target_id", "decision", "reason", "created_at"}
    missing = required - set(entry)
    if missing:
        raise ValueError(f"audit entry missing {sorted(missing)}")
    return log + (copy.deepcopy(entry),)


def test_case(test_id: str, name: str, observed: bool, expected: bool, evidence: dict[str, Any]) -> dict[str, Any]:
    covered = observed == expected
    return {
        "id": test_id,
        "name": name,
        "status": "covered" if covered else "missed",
        "gap_category": None if covered else "tenant-safety-fixture",
        "validation_category": "control_plane_two_tenant_fixture",
        "execution_class": "local_fixture_probe",
        "fallback_used": False,
        "claim_level": "two_tenant_fixture_contract",
        "tactics": [],
        "techniques": [],
        "evidence": {"observed": observed, "expected": expected, **evidence},
        "missing_expected_fields": [] if covered else [f"expected_{expected}_got_{observed}"],
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []

    allowed, reason = can_read_alert(USERS["a-analyst"], TOKENS["a-read"], ALERTS["alert-a"])
    tests.append(test_case("tenant-same-org-alert-read-allowed", "Same-tenant alert read is allowed", allowed, True, {"reason": reason}))

    allowed, reason = can_read_alert(USERS["a-analyst"], TOKENS["a-read"], ALERTS["alert-b"])
    tests.append(test_case("tenant-cross-org-alert-read-denied", "Cross-tenant alert read is denied", allowed, False, {"reason": reason}))

    allowed, reason = can_read_agent(USERS["a-analyst"], TOKENS["a-read"], AGENTS["agent-b"])
    tests.append(test_case("tenant-cross-org-agent-read-denied", "Cross-tenant agent read is denied", allowed, False, {"reason": reason}))

    allowed, reason = can_read_alert(USERS["a-analyst"], TOKENS["a-revoked"], ALERTS["alert-a"])
    tests.append(test_case("token-revoked-denied", "Revoked token is denied", allowed, False, {"reason": reason}))

    allowed, reason = can_execute_response(USERS["a-viewer"], TOKENS["a-response"], ALERTS["alert-a"], None)
    tests.append(test_case("role-denies-response-execute", "Viewer role cannot execute response even with token scope", allowed, False, {"reason": reason}))

    allowed, reason = can_execute_response(USERS["a-admin"], TOKENS["a-response"], ALERTS["alert-a"], None)
    tests.append(test_case("destructive-response-requires-approval", "Destructive response requires explicit approval", allowed, False, {"reason": reason}))

    approval = {"tenant_id": TENANT_A, "approved_by_role": "admin", "approved_by": "a-admin"}
    allowed, reason = can_execute_response(USERS["a-admin"], TOKENS["a-response"], ALERTS["alert-a"], approval)
    tests.append(test_case("destructive-response-approved-allowed", "Admin response with tenant-matched approval is allowed", allowed, True, {"reason": reason}))

    log: tuple[dict[str, Any], ...] = ()
    log = append_audit(
        log,
        {
            "tenant_id": TENANT_A,
            "actor_id": "a-admin",
            "action": "response.execute",
            "target_id": "alert-a",
            "decision": "allowed",
            "reason": "approval_present",
            "created_at": utc_now(),
        },
    )
    original = copy.deepcopy(log[0])
    log = append_audit(
        log,
        {
            "tenant_id": TENANT_A,
            "actor_id": "a-viewer",
            "action": "response.execute",
            "target_id": "alert-a",
            "decision": "denied",
            "reason": "role_scope_missing",
            "created_at": utc_now(),
        },
    )
    append_only = len(log) == 2 and log[0] == original and all("created_at" in item for item in log)
    tests.append(test_case("audit-log-append-only-fixture", "Audit log append-only semantics preserve prior entries", append_only, True, {"audit_entries": len(log)}))

    return tests


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
        "missing_expected_fields": missed,
        "missing_expected_telemetry": 0,
        "missing_expected_driver_raw_events": 0,
        "investigable_alert_gaps": 0,
        "excluded_benchmark_setup_alerts": 0,
        "upstream_backed_tests": 0,
        "deterministic_command_tests": 0,
        "fallback_command_tests": 0,
        "executor_counts": {"control_plane_two_tenant_fixture_probe": len(tests)},
        "execution_class_counts": {"local_fixture_probe": len(tests)},
        "claim_level_counts": {"two_tenant_fixture_contract": len(tests)},
        "category_coverage": {"control_plane_two_tenant_fixture": {"covered": covered, "missed": missed}},
        "roadmap_coverage": {"N": {"covered": covered, "missed": missed}},
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": {"tenant-safety-fixture": missed} if missed else {},
        "actionable_gaps": gaps,
    }


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 80 if passed else int(50 * covered_rate),
        "maturity_band": "two-tenant-fixture-contract-ready" if passed else "two-tenant-fixture-gaps",
        "recommended_claim": (
            "Two-tenant tenant/RBAC/token/audit/approval fixture contracts are green; live API fixtures still pending"
            if passed
            else "Two-tenant fixture contract gaps remain"
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
        "- Scope: local deterministic two-tenant fixture contract only.",
        "- Runtime effect: none; no server, DB, tenant, token, response, or audit row mutation.",
        "",
        "| Test | Status | Reason |",
        "|------|--------|--------|",
    ]
    for test in report["tests"]:
        lines.append(f"| `{test['id']}` | `{test['status']}` | `{test['evidence'].get('reason', '-')}` |")
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
        "benchmark_lane": "control-plane-safety",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "control-plane",
            "quality_bar": {
                "purpose": "two_tenant_fixture_contract",
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
            "failures": [] if passed else ["two_tenant_fixture_contract_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
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
        "scorecard": scorecard(summary),
        "claim_boundary": (
            "Local two-tenant fixture contract only. It proves expected tenant/RBAC/token/audit/approval "
            "semantics are executable as a regression gate, but it does not prove runtime database isolation, "
            "authenticated API denial across real tenants, immutable persisted audit rows, or MFA approval enforcement."
        ),
    }
    comparison = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "execute": True,
        "benchmark_lane": "control-plane-safety",
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
