#!/usr/bin/env python3
"""Source audit for mobile recovery and signed-posture cutover ordering.

This is intentionally narrower than the PostgreSQL concurrency test. It checks
that recovery issuance and signed-posture request issuance share the canonical
installation advisory lock and that signed-posture issuance delegates to the
recovery-domain barrier after taking that lock. The barrier must expire stale
leases inside the caller transaction and keep any live pending recovery
fail-closed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
IDENTITY = ROOT / "apps" / "tamandua_server" / "lib" / "tamandua_server" / "mobile" / "mobile_device_identity.ex"
CANDIDATE_LOCK = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "lib"
    / "tamandua_server"
    / "mobile"
    / "mobile_device_identity_candidate_lock.ex"
)
RECOVERY = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "lib"
    / "tamandua_server"
    / "mobile"
    / "mobile_device_identity_recovery.ex"
)
INGESTION = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "lib"
    / "tamandua_server"
    / "mobile"
    / "mobile_signed_posture_ingestion.ex"
)
CUTOVER_TEST = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "test"
    / "tamandua_server"
    / "mobile"
    / "mobile_recovery_signed_posture_cutover_test.exs"
)
EXPIRY_TEST = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "test"
    / "tamandua_server"
    / "mobile"
    / "mobile_recovery_expiry_barrier_test.exs"
)
RECOVERY_MIGRATION = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "priv"
    / "repo"
    / "migrations"
    / "20260715220000_create_mobile_device_identity_recovery.exs"
)
CANDIDATE_CONTRACT_TEST = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "test"
    / "tamandua_server_web"
    / "controllers"
    / "api"
    / "v1"
    / "mobile_device_identity_recovery_candidate_contract_test.exs"
)
CANDIDATE_BIND_TEST = (
    ROOT
    / "apps"
    / "tamandua_server"
    / "test"
    / "tamandua_server"
    / "mobile"
    / "mobile_recovery_candidate_bind_serialization_test.exs"
)

LOCK_DOMAIN = "tamandua.mobile.installation-lock/v1"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def extract_function(source: str, name: str, private: bool = False) -> str:
    keyword = "defp" if private else "def"
    match = re.search(
        rf"^\s*{keyword}\s+{re.escape(name)}\b.*?(?=^\s*(?:def|defp)\s|\Z)",
        source,
        re.M | re.S,
    )
    return match.group(0) if match else ""


def marker_order(source: str, markers: list[str]) -> bool:
    cursor = -1
    for marker in markers:
        next_index = source.find(marker, cursor + 1)
        if next_index < 0:
            return False
        cursor = next_index
    return True


def evaluate(
    identity_path: Path = IDENTITY,
    candidate_lock_path: Path = CANDIDATE_LOCK,
    recovery_path: Path = RECOVERY,
    ingestion_path: Path = INGESTION,
    cutover_test_path: Path = CUTOVER_TEST,
    expiry_test_path: Path = EXPIRY_TEST,
    recovery_migration_path: Path = RECOVERY_MIGRATION,
    candidate_contract_test_path: Path = CANDIDATE_CONTRACT_TEST,
    candidate_bind_test_path: Path = CANDIDATE_BIND_TEST,
) -> dict[str, object]:
    identity = read(identity_path)
    candidate_lock = read(candidate_lock_path)
    recovery = read(recovery_path)
    ingestion = read(ingestion_path)
    cutover_test = read(cutover_test_path)
    expiry_test = read(expiry_test_path)
    recovery_migration = read(recovery_migration_path)
    candidate_contract_test = read(candidate_contract_test_path)
    candidate_bind_test = read(candidate_bind_test_path)

    identity_bind = extract_function(identity, "verify_and_bind_transaction", private=True)
    recovery_issue = extract_function(recovery, "issue")
    posture_issue = extract_function(ingestion, "issue")
    posture_request_status = extract_function(ingestion, "request_status")
    posture_verify_transaction = extract_function(ingestion, "verify_transaction", private=True)
    posture_upsert_projection = extract_function(ingestion, "upsert_projection", private=True)
    pending_recovery = extract_function(ingestion, "ensure_no_pending_recovery", private=True)
    recovery_barrier = extract_function(recovery, "enforce_signed_posture_barrier")
    expire_stale_pending = extract_function(recovery, "expire_stale_pending", private=True)

    checks = {
        "identity_uses_canonical_lock_domain": LOCK_DOMAIN in identity,
        "recovery_uses_canonical_lock_domain": LOCK_DOMAIN in recovery,
        "ingestion_uses_canonical_lock_domain": LOCK_DOMAIN in ingestion,
        "candidate_lock_is_tenant_scoped_and_ordered": all(
            marker in candidate_lock
            for marker in [
                "defmodule TamanduaServer.Mobile.MobileDeviceIdentityCandidateLock",
                '@lock_domain "tamandua.mobile.device-key-lock/v1"',
                '@key_id_format ~r/^tmdk_v1_[A-Za-z0-9_-]{43}$/',
                "@lock_domain <> <<0>> <> organization_id <> <<0>> <> candidate_id",
                "Repo.query!(\"SELECT pg_advisory_xact_lock($1, $2)\", [first, second])",
                "candidate_ids |> Enum.uniq() |> Enum.sort()",
                "candidate_ids != []",
            ]
        ),
        "identity_bind_locks_candidate_before_reservation_and_bind": marker_order(
            identity_bind,
            [
                "verify_p256_signature(public_key_spki, payload, signature)",
                "lock_installations(challenge.organization_id, [challenge.installation_id])",
                "MobileDeviceIdentityCandidateLock.lock_keys(challenge.organization_id, device_key_id)",
                "ensure_candidate_not_reserved_elsewhere(",
                "bind_for_purpose(",
            ],
        ),
        "recovery_issue_locks_before_binding_checks": marker_order(
            recovery_issue,
            [
                "lock_installation(organization_id, installation_id)",
                "MobileDeviceIdentityCandidateLock.lock_keys(",
                "ensure_no_live_pending_recovery(organization_id, installation_id, now)",
                "ensure_key_binding(organization_id, installation_id, old_device_key_id)",
                "ensure_candidate_binding(",
                "Repo.insert()",
            ],
        ),
        "posture_issue_locks_before_recovery_check": marker_order(
            posture_issue,
            [
                "lock_installation(organization_id, installation_id)",
                "active_key(organization_id, installation_id, true)",
                "ensure_no_pending_recovery(organization_id, installation_id, now)",
            ],
        ),
        "posture_verify_locks_before_recovery_check": marker_order(
            posture_verify_transaction,
            [
                "lock_installation(organization_id, request.installation_id)",
                "active_key(organization_id, request.installation_id, true)",
                "snapshot_matches(request, key)",
                "ensure_no_pending_recovery(organization_id, request.installation_id, now)",
            ],
        ),
        "posture_status_reflects_recovery_barrier": marker_order(
            posture_request_status,
            [
                'lock: "FOR UPDATE"',
                "pending_and_fresh(request, now)",
                "lock_installation(organization_id, request.installation_id)",
                "ensure_no_pending_recovery(organization_id, request.installation_id, now)",
                'state: "blocked", reason: "identity_recovery_in_progress"',
            ],
        ),
        "posture_projection_upsert_is_monotonic": all(
            marker in posture_upsert_projection
            for marker in [
                "from(p in MobileSignedPostureProjection",
                'fragment("EXCLUDED.verified_at")',
                "where: p.verified_at <=",
                "conflict_target: [:organization_id, :installation_id]",
                "returning: true",
            ]
        )
        and "{:replace," not in posture_upsert_projection,
        "ingestion_delegates_to_recovery_barrier": all(
            marker in pending_recovery
            for marker in [
                "MobileDeviceIdentityRecovery.enforce_signed_posture_barrier",
                "organization_id",
                "installation_id",
                "now",
            ]
        ),
        "recovery_barrier_locks_pending_intents": marker_order(
            recovery_barrier,
            [
                'intent.state == "pending"',
                'lock("FOR UPDATE")',
                "Repo.all()",
                "expire_stale_pending(intents, now)",
                "{:error, :identity_recovery_in_progress}",
            ],
        ),
        "recovery_barrier_expires_stale_inside_transaction": all(
            marker in expire_stale_pending
            for marker in [
                "DateTime.compare(now, intent.expires_at) in [:eq, :gt]",
                'changeset(%{state: "expired", expired_at: now, last_checked_at: now})',
                "Repo.update()",
                "{:cont, {:ok, live_pending?}}",
                "{:cont, {:ok, true}}",
            ]
        ),
        "recovery_issue_has_pending_uniqueness_backstop": all(
            marker in recovery
            for marker in [
                "defp ensure_no_live_pending_recovery(organization_id, installation_id, now)",
                "enforce_signed_posture_barrier(organization_id, installation_id, now)",
                "mobile_recovery_one_pending_installation_index",
                "mobile_recovery_one_pending_candidate_index",
            ]
        ),
        "recovery_migration_has_partial_pending_unique_index": all(
            marker in recovery_migration
            for marker in [
                "unique_index(",
                ":mobile_recovery_one_pending_installation_index",
                'where: "state = \'pending\'"',
                "[:organization_id, :installation_id]",
            ]
        ),
        "recovery_migration_reserves_pending_candidate_cross_installation": all(
            marker in recovery_migration
            for marker in [
                "unique_index(",
                ":mobile_recovery_one_pending_candidate_index",
                "[:organization_id, :candidate_device_key_id]",
                'where: "state = \'pending\'"',
            ]
        ),
        "recovery_rejects_nil_candidate_contract": all(
            marker in recovery
            for marker in [
                "defp normalize_candidate(nil), do: {:error, :candidate_key_required}",
                'defp normalize_candidate(""), do: {:error, :candidate_key_required}',
                'add_error(changeset, :candidate_device_key_id, "is required for identity recovery")',
            ]
        )
        and "candidate_device_key_id IS NULL OR" not in recovery_migration
        and "defp ensure_candidate_binding(_organization_id, _installation_id, _old_key_id, nil)" not in recovery,
        "recovery_candidate_http_contract_test_exists": all(
            marker in candidate_contract_test
            for marker in [
                "missing, null, and empty candidates share one generic 422 contract",
                "whitespace-only candidate preserves the generic 400 request contract",
                'Map.put(base, "candidate_device_key_id", nil)',
                'Map.put(base, "candidate_device_key_id", "")',
                '"candidate_device_key_id" => "   "',
                'assert response == %{"error" => %{"code" => "recovery_intent_invalid"}}',
                'assert response == %{"error" => %{"code" => "recovery_request_invalid"}}',
                'assert get_resp_header(conn, "cache-control") == ["no-store"]',
                "Repo.aggregate(MobileDeviceIdentityRecovery, :count) == 0",
                'refute inspect(response) =~ "candidate_device_key_id"',
                'refute inspect(response) =~ "binding"',
                'refute inspect(response) =~ "reservation"',
                'refute inspect(response) =~ "recovery_token"',
            ]
        ),
        "postgres_cutover_test_exists": all(
            marker in cutover_test
            for marker in [
                "recovery issue waits for the canonical installation transaction lock",
                "committed recovery cutover makes signed posture issuance fail closed",
                "Sandbox.unboxed_run",
                "pg_advisory_xact_lock",
            ]
        ),
        "postgres_expiry_barrier_test_exists": all(
            marker in expiry_test
            for marker in [
                "persists expiry at the exact server-time boundary before allowing posture",
                "rolls stale expiry back when the enclosing posture decision fails",
                "rolls an expired lease back when later posture work fails",
                "blocks before expiry and rejects a missing server time",
                "Repo.rollback(:posture_failed)",
                "pg_advisory_xact_lock",
            ]
        ),
        "postgres_candidate_bind_serialization_test_exists": all(
            marker in candidate_bind_test
            for marker in [
                "candidate locks deduplicate and sort keys before acquiring PostgreSQL locks",
                "the same candidate remains independently lockable in another tenant",
                "identity validates proof before installation and candidate locks, then binds",
                "recovery locks installation then candidate before barriers and insertion",
                "MobileDeviceIdentityCandidateLock.lock_keys",
                "Sandbox.unboxed_run",
            ]
        ),
    }

    reasons = [name for name, ok in checks.items() if not ok]

    return {
        "schema_version": 1,
        "evidence_class": "source_audit",
        "external_claim_allowed": False,
        "ok": not reasons,
        "sources": {
            "identity": str(identity_path),
            "candidate_lock": str(candidate_lock_path),
            "recovery": str(recovery_path),
            "ingestion": str(ingestion_path),
            "cutover_test": str(cutover_test_path),
            "expiry_test": str(expiry_test_path),
            "recovery_migration": str(recovery_migration_path),
            "candidate_contract_test": str(candidate_contract_test_path),
            "candidate_bind_test": str(candidate_bind_test_path),
        },
        "checks": checks,
        "reasons": reasons,
        "claim_boundary": (
            "Source audit only. PostgreSQL advisory-lock concurrency, migration, "
            "and ExUnit execution remain required before promotion."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", type=Path, default=IDENTITY)
    parser.add_argument("--candidate-lock", type=Path, default=CANDIDATE_LOCK)
    parser.add_argument("--recovery", type=Path, default=RECOVERY)
    parser.add_argument("--ingestion", type=Path, default=INGESTION)
    parser.add_argument("--cutover-test", type=Path, default=CUTOVER_TEST)
    parser.add_argument("--expiry-test", type=Path, default=EXPIRY_TEST)
    parser.add_argument("--recovery-migration", type=Path, default=RECOVERY_MIGRATION)
    parser.add_argument("--candidate-contract-test", type=Path, default=CANDIDATE_CONTRACT_TEST)
    parser.add_argument("--candidate-bind-test", type=Path, default=CANDIDATE_BIND_TEST)
    args = parser.parse_args(argv)

    result = evaluate(
        args.identity,
        args.candidate_lock,
        args.recovery,
        args.ingestion,
        args.cutover_test,
        args.expiry_test,
        args.recovery_migration,
        args.candidate_contract_test,
        args.candidate_bind_test,
    )
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
