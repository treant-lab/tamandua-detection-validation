#!/usr/bin/env python3
"""Static contract probe for robust agent enrollment and identity.

This probe validates repo-side source and documentation contracts for agent
identity, installation-token/CSR enrollment, token rotation readiness, machine
ID handling, certificate expiry/revocation hints, and Linux/Windows/mobile
platform gaps. It does not enroll an agent, issue credentials, mutate database
state, rotate certificates, or call a live control plane.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"


PROFILE_ID = "agent-enrollment-identity-contract-probe"
PROFILE_NAME = "Agent Enrollment Identity Contract Probe"


CHECKS: list[dict[str, Any]] = [
    {
        "id": "enrollment-token-model-contract",
        "name": "Installation tokens are hashed, scoped, expirable, revocable, and usage limited",
        "category": "installation_token",
        "claim_level": "source_contract_readiness",
        "files": ["apps/tamandua_server/lib/tamandua_server/enrollment.ex"],
        "required_any_file": [
            "schema \"installation_tokens\"",
            "token_hash",
            "token_digest",
            "expires_at",
            "max_uses",
            "use_count",
            "revoked",
            "organization_id",
            "Argon2.hash_pwd_salt",
            "Argon2.verify_pass",
            "lock: \"FOR UPDATE\"",
            "Installation token is not bound to an organization",
        ],
    },
    {
        "id": "csr-private-key-stays-on-agent-contract",
        "name": "CSR enrollment signs an agent-owned key and returns certificate material without server-side private key custody",
        "category": "csr_enrollment",
        "claim_level": "source_contract_readiness",
        "files": ["apps/tamandua_server/lib/tamandua_server/enrollment.ex"],
        "required_any_file": [
            "Enroll an agent using CSR-based flow",
            "private key never leaves agent",
            "validate_csr_format",
            "openssl([\"req\", \"-in\", temp_path, \"-verify\", \"-noout\"])",
            "CertificateAuthority.sign_csr",
            "validity_days: 90",
            "ca_bundle",
            "renew_certificate_with_csr",
            "agent_id_mismatch",
        ],
    },
    {
        "id": "agent-token-rotation-revocation-contract",
        "name": "Agent JWT lifecycle has generation tracking, refresh windows, revocation cache, and audit hints",
        "category": "token_rotation",
        "claim_level": "source_contract_readiness",
        "files": ["apps/tamandua_server/lib/tamandua_server/agents/token_manager.ex"],
        "required_any_file": [
            "current_token_generation",
            "token_rotation_enabled",
            "token_ttl_hours",
            "token_refresh_window_percent",
            "revoke_previous_generations",
            ":agent_token_revocations",
            "check_revocation_cache",
            "revocation_reason",
            "refresh_grace_seconds",
            "maybe_warn_refresh_count_anomaly",
            "Audit.log_event",
        ],
    },
    {
        "id": "agent-machine-id-storage-contract",
        "name": "Agents persist machine_id and support org-scoped lookup without global uniqueness",
        "category": "machine_id",
        "claim_level": "source_contract_readiness",
        "files": [
            "apps/tamandua_server/lib/tamandua_server/agents/agent.ex",
            "apps/tamandua_server/lib/tamandua_server/agents.ex",
            "apps/tamandua_server/priv/repo/migrations/20260518000100_drop_residual_agent_machine_id_unique_idx.exs",
        ],
        "required_any_file": [
            "field :machine_id, :binary",
            "{:machine_id, org_id, machine_id}",
            "agents_org_machine_id_index",
            "DROP INDEX IF EXISTS agents_machine_id_unique_idx",
        ],
    },
    {
        "id": "agent-machine-id-preservation-gap-contract",
        "name": "Docs call out that nil/changed machine_id must not silently replace a registered identity during re-enrollment",
        "category": "machine_id_preservation",
        "claim_level": "documented_gap",
        "files": [
            "docs/architecture/agent-enrollment-identity-contract.md",
            "docs/operations/agent-enrollment-robust-contract.md",
        ],
        "required_any_file": [
            "machine_id preservation invariant",
            "must not overwrite a non-null machine_id with nil",
            "quarantine duplicate host",
            "same organization",
        ],
    },
    {
        "id": "mtls-agent-identity-certificate-contract",
        "name": "Agent socket verifies client certificate identity, validity, chain, and revocation hints",
        "category": "mtls_identity",
        "claim_level": "source_contract_readiness",
        "files": ["apps/tamandua_server/lib/tamandua_server_web/channels/agent_socket.ex"],
        "required_any_file": [
            "mTLS certificate validation",
            "Agent ID verification against certificate CN",
            "verify_client_certificate",
            "verify_certificate_time",
            "certificate_expired",
            "certificate_not_yet_valid",
            "invalid_certificate_chain",
            "certificate_revoked",
            "certificate_fingerprint",
            "certificate_valid_until",
        ],
    },
    {
        "id": "certificate-inventory-revocation-expiry-contract",
        "name": "Certificate inventory exposes revocation, expiry, and expiring-soon operational hints",
        "category": "certificate_lifecycle",
        "claim_level": "source_contract_readiness",
        "files": [
            "apps/tamandua_server/lib/tamandua_server/agents/certificates.ex",
            "apps/tamandua_server/lib/tamandua_server/agents/revoked_certificate.ex",
            "apps/tamandua_server/priv/repo/migrations/20260220000023_create_revoked_certificates.exs",
            "apps/tamandua_server/priv/repo/migrations/20260220000032_add_certificate_fingerprint_to_agents.exs",
        ],
        "required_any_file": [
            "Revoked certificates are checked during connection authentication",
            "find_expiring_certificates",
            "expiring_soon",
            "revoke_certificate",
            "is_revoked?",
            "unique_index(:revoked_certificates, [:fingerprint])",
            "certificate_fingerprint",
            "certificate_valid_until",
        ],
    },
    {
        "id": "windows-enrollment-installer-contract",
        "name": "Windows installer path carries enrollment URL, token, host metadata, and certificate paths",
        "category": "windows",
        "claim_level": "source_contract_readiness",
        "files": ["apps/tamandua_agent/installer/windows/write-config.ps1"],
        "required_any_file": [
            "EnrollmentToken",
            "EnrollmentUrl",
            "hostname",
            "os_type",
            "agent_version",
            "api/v1/enrollment/exchange",
            "client_certificate",
            "ca_certificate",
            "Restrictive permissions set on certificates directory",
        ],
    },
    {
        "id": "windows-machine-id-gap-contract",
        "name": "Windows machine_id preservation gap is explicit before installer production claims",
        "category": "windows_machine_id",
        "claim_level": "documented_gap",
        "files": [
            "docs/architecture/agent-enrollment-identity-contract.md",
            "docs/operations/agent-enrollment-robust-contract.md",
        ],
        "required_any_file": [
            "Windows gap",
            "stable machine_id",
            "repair install preserves machine_id",
            "token cleanup",
        ],
    },
    {
        "id": "mobile-enrollment-mirror-contract",
        "name": "Mobile endpoint enrollment mirrors stable install identity into Agents while remaining scoped as mobile posture",
        "category": "mobile",
        "claim_level": "source_contract_readiness",
        "files": [
            "apps/tamandua_server/lib/tamandua_server/mobile/mobile.ex",
            "apps/tamandua_server/priv/repo/migrations/20260702000100_sync_mobile_devices_to_agents.exs",
            "docs/architecture/agent-enrollment-identity-contract.md",
        ],
        "required_any_file": [
            "machine_id: device.device_id",
            "upsert_mobile_agent",
            "sync_mobile_device_agent",
            "Endpoint tab",
            "not a persistent phone-wide endpoint sensor",
        ],
    },
    {
        "id": "linux-enrollment-gap-contract",
        "name": "Linux enrollment gaps are explicit and testable before production claims",
        "category": "linux",
        "claim_level": "documented_gap",
        "files": [
            "docs/architecture/agent-enrollment-identity-contract.md",
            "docs/operations/agent-enrollment-robust-contract.md",
        ],
        "required_any_file": [
            "Linux gap",
            "systemd",
            "/etc/machine-id",
            "credential file permissions",
            "certificate renewal smoke",
        ],
    },
    {
        "id": "operational-runbook-contract",
        "name": "Runbook defines probe usage, incident hints, blockers, and rollout evidence requirements",
        "category": "operations",
        "claim_level": "operator_contract",
        "files": ["docs/operations/agent-enrollment-robust-contract.md"],
        "required_any_file": [
            "agent_enrollment_identity_contract_probe.py",
            "installation token",
            "CSR",
            "rotation readiness",
            "machine_id preservation invariant",
            "certificate expiry",
            "revocation",
            "Production claim boundary",
        ],
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


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def check_item(item: dict[str, Any]) -> dict[str, Any]:
    checked_paths: list[str] = []
    missing_files: list[str] = []
    combined = ""

    for relative in item["files"]:
        path = ROOT / relative
        checked_paths.append(relative)
        if not path.exists():
            missing_files.append(relative)
            continue
        combined += "\n" + read_text(path)

    missing_terms = [
        term for term in item.get("required_any_file", []) if term.lower() not in combined.lower()
    ]
    covered = not missing_files and not missing_terms

    return {
        "id": item["id"],
        "name": item["name"],
        "status": "covered" if covered else "missed",
        "gap_category": "none" if covered else item["category"],
        "validation_category": item["category"],
        "execution_class": "static_source_doc_probe",
        "claim_level": item["claim_level"],
        "fallback_used": False,
        "upstream_backed": False,
        "evidence": {
            "checked_paths": checked_paths,
            "missing_files": missing_files,
            "missing_terms": missing_terms,
            "runtime_effect": "none",
        },
        "missing_expected_fields": missing_files + missing_terms,
        "missing_expected_telemetry": [],
        "missing_expected_detections": [],
        "missing_expected_alerts": [],
        "missing_expected_correlations": [],
        "missing_expected_driver_raw_event_types": [],
        "tactics": [],
        "techniques": [],
    }


def collect_tests() -> list[dict[str, Any]]:
    return [check_item(item) for item in CHECKS]


def build_summary(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for test in tests if test["status"] == "covered")
    missed = len(tests) - covered
    gap_counts: dict[str, int] = {}
    category_coverage: dict[str, dict[str, int]] = {}
    actionable_gaps: list[dict[str, Any]] = []

    for test in tests:
        category = test["validation_category"]
        category_coverage.setdefault(category, {"covered": 0, "missed": 0})
        category_coverage[category]["covered" if test["status"] == "covered" else "missed"] += 1
        if test["status"] != "covered":
            gap_counts[category] = gap_counts.get(category, 0) + 1
            actionable_gaps.append(
                {
                    "test_id": test["id"],
                    "status": test["status"],
                    "gap_category": category,
                    "missing_expected_fields": test["missing_expected_fields"],
                    "execution_class": test["execution_class"],
                    "fallback_used": False,
                    "tactics": [],
                    "techniques": [],
                }
            )

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
        "executor_counts": {PROFILE_ID: len(tests)},
        "execution_class_counts": {"static_source_doc_probe": len(tests)},
        "claim_level_counts": claim_level_counts(tests),
        "category_coverage": category_coverage,
        "tactic_coverage": {},
        "technique_coverage": {},
        "evidence_source_coverage": {},
        "gap_category_counts": gap_counts,
        "actionable_gaps": actionable_gaps,
    }


def claim_level_counts(tests: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for test in tests:
        level = test["claim_level"]
        counts[level] = counts.get(level, 0) + 1
    return counts


def scorecard(summary: dict[str, Any]) -> dict[str, Any]:
    covered_rate = summary["covered"] / max(summary["tests"], 1)
    passed = summary["missed"] == 0
    return {
        "maturity_score": 74 if passed else int(55 * covered_rate),
        "maturity_band": (
            "agent-enrollment-source-contract-ready"
            if passed
            else "agent-enrollment-contract-gaps"
        ),
        "recommended_claim": (
            "Agent enrollment identity source/docs contract is present. This is not live production enrollment proof."
            if passed
            else "Agent enrollment identity contract gaps exist; keep enrollment robustness as not production validated."
        ),
        "external_claim_allowed": False,
        "covered_rate": covered_rate,
        "telemetry_rate": 1.0,
        "field_quality": 1.0 if passed else covered_rate,
        "context_quality": 1.0 if passed else covered_rate,
        "analytic_quality": 1.0,
        "noise_quality": 1.0,
        "driver_quality": 1.0,
        "upstream_rate": 0.0,
        "blocking_gaps": sorted(summary["gap_category_counts"].keys()),
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
        "- Scope: static source/docs contract only.",
        "- Runtime effect: none; no enrollment, credential issuance, database mutation, certificate rotation, or control-plane call.",
        "",
        "| Test | Category | Claim Level | Status | Missing |",
        "|------|----------|-------------|--------|---------|",
    ]
    for test in report["tests"]:
        missing = test["evidence"]["missing_files"] + test["evidence"]["missing_terms"]
        lines.append(
            f"| `{test['id']}` | `{test['validation_category']}` | `{test['claim_level']}` | `{test['status']}` | `{'; '.join(missing) if missing else '-'}` |"
        )
    lines.extend(["", "## Claim Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_report() -> dict[str, Any]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    tests = collect_tests()
    summary = build_summary(tests)
    passed = summary["missed"] == 0
    return {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "execute": True,
        "benchmark_lane": "agent-enrollment-identity",
        "git": git_snapshot(),
        "profile_id": PROFILE_ID,
        "profile": {
            "profile_id": PROFILE_ID,
            "name": PROFILE_NAME,
            "platform": "multi",
            "quality_bar": {
                "purpose": "agent_enrollment_identity_contract_probe",
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
            "failures": [] if passed else ["agent_enrollment_identity_contract_gaps"],
            "actionable_gaps": summary["actionable_gaps"],
            "gap_category_counts": summary["gap_category_counts"],
            "thresholds": {
                "benchmark_lane": "agent-enrollment-identity",
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
            "Validates static source and documentation contracts for robust agent enrollment only. "
            "It does not prove a live Linux, Windows, or mobile enrollment; does not prove mTLS handshake success; "
            "does not prove certificate renewal under outage; does not prove token compromise response; "
            "and does not allow production readiness claims without live lab evidence."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=RUNS_DIR)
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Print the report JSON to stdout without writing run artifacts.",
    )
    args = parser.parse_args()

    report = build_report()
    if args.no_write:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        json_path = args.output_dir / f"{report['run_id']}.json"
        comparison_path = args.output_dir / f"{report['run_id']}.comparison.json"
        md_path = args.output_dir / f"{report['run_id']}.md"
        write_json(json_path, report)
        write_json(
            comparison_path,
            {
                "schema_version": 1,
                "profile_id": PROFILE_ID,
                "execute": True,
                "benchmark_lane": "agent-enrollment-identity",
                "summary": report["summary"],
                "quality_gate": report["quality_gate"],
                "scorecard": report["scorecard"],
                "tests": report["tests"],
            },
        )
        write_markdown(md_path, report)
        print(f"json={json_path} markdown={md_path} comparison_json={comparison_path}")

    return 0 if report["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
