from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "mobile_recovery_signed_posture_cutover_audit.py"
)
SPEC = importlib.util.spec_from_file_location("mobile_recovery_signed_posture_cutover_audit", SCRIPT)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def write_sources(
    tmp_path: Path,
    *,
    candidate_lock: bool = True,
    identity_candidate_order: bool = True,
    recovery_candidate_lock: bool = True,
    candidate_bind_test: bool = True,
    posture_issue_recovery_check: bool = True,
    posture_status_recovery_check: bool = True,
    monotonic_projection: bool = True,
    expiry_barrier: bool = True,
    pending_backstop: bool = True,
    candidate_reservation: bool = True,
    reject_nil_candidate: bool = True,
    candidate_http_contract: bool = True,
) -> dict[str, Path]:
    identity = tmp_path / "mobile_device_identity.ex"
    candidate_lock_path = tmp_path / "mobile_device_identity_candidate_lock.ex"
    recovery = tmp_path / "mobile_device_identity_recovery.ex"
    ingestion = tmp_path / "mobile_signed_posture_ingestion.ex"
    cutover = tmp_path / "mobile_recovery_signed_posture_cutover_test.exs"
    expiry = tmp_path / "mobile_recovery_expiry_barrier_test.exs"
    migration = tmp_path / "20260715220000_create_mobile_device_identity_recovery.exs"
    candidate_test = tmp_path / "mobile_device_identity_recovery_candidate_contract_test.exs"
    candidate_bind = tmp_path / "mobile_recovery_candidate_bind_serialization_test.exs"

    identity_bind_body = '''
defp verify_and_bind_transaction(organization_id, proof, now) do
  verify_p256_signature(public_key_spki, payload, signature)
  lock_installations(challenge.organization_id, [challenge.installation_id])
'''
    if identity_candidate_order:
        identity_bind_body += '''
  MobileDeviceIdentityCandidateLock.lock_keys(challenge.organization_id, device_key_id)
  ensure_candidate_not_reserved_elsewhere(
    challenge.organization_id,
    challenge.installation_id,
    device_key_id,
    now
  )
'''
    else:
        identity_bind_body += '''
  ensure_candidate_not_reserved_elsewhere(
    challenge.organization_id,
    challenge.installation_id,
    device_key_id,
    now
  )
  MobileDeviceIdentityCandidateLock.lock_keys(challenge.organization_id, device_key_id)
'''
    identity_bind_body += '''
  bind_for_purpose(challenge, proof, public_key_spki, device_key_id, payload, now)
end
'''
    identity.write_text(
        '@installation_lock_domain "tamandua.mobile.installation-lock/v1"\n'
        + identity_bind_body,
        encoding="utf-8",
    )

    if candidate_lock:
        candidate_lock_path.write_text(
            '''
defmodule TamanduaServer.Mobile.MobileDeviceIdentityCandidateLock do
  @lock_domain "tamandua.mobile.device-key-lock/v1"
  @key_id_format ~r/^tmdk_v1_[A-Za-z0-9_-]{43}$/

  def lock_keys(organization_id, candidate_ids) do
    candidate_ids != []
    @lock_domain <> <<0>> <> organization_id <> <<0>> <> candidate_id
    Repo.query!("SELECT pg_advisory_xact_lock($1, $2)", [first, second])
    candidate_ids |> Enum.uniq() |> Enum.sort()
  end
end
''',
            encoding="utf-8",
        )
    else:
        candidate_lock_path.write_text(
            '''
defmodule TamanduaServer.Mobile.MobileDeviceIdentityCandidateLock do
  @lock_domain "tamandua.mobile.device-key-lock/v1"
  def lock_keys(_organization_id, candidate_ids), do: candidate_ids
end
''',
            encoding="utf-8",
        )

    recovery_body = '''
@installation_lock_domain "tamandua.mobile.installation-lock/v1"
def issue(organization_id, installation_id) do
  lock_installation(organization_id, installation_id)
'''
    if recovery_candidate_lock:
        recovery_body += '''
  MobileDeviceIdentityCandidateLock.lock_keys(
    organization_id,
    candidate_device_key_id
  )
'''
    recovery_body += '''
  ensure_no_live_pending_recovery(organization_id, installation_id, now)
  ensure_key_binding(organization_id, installation_id, old_device_key_id)
  ensure_candidate_binding(organization_id, installation_id, old_device_key_id, candidate)
  Repo.insert()
end

def enforce_signed_posture_barrier(organization_id, installation_id, now) do
  intent.state == "pending"
  lock("FOR UPDATE")
  Repo.all()
  expire_stale_pending(intents, now)
  {:error, :identity_recovery_in_progress}
end
'''
    if expiry_barrier:
        recovery_body += '''

defp expire_stale_pending(intents, now) do
  DateTime.compare(now, intent.expires_at) in [:eq, :gt]
  changeset(%{state: "expired", expired_at: now, last_checked_at: now})
  Repo.update()
  {:cont, {:ok, live_pending?}}
  {:cont, {:ok, true}}
end
'''
    if pending_backstop:
        recovery_body += '''

def changeset(intent, attrs) do
  unique_constraint([:organization_id, :installation_id],
    name: :mobile_recovery_one_pending_installation_index
  )
  unique_constraint([:organization_id, :candidate_device_key_id],
    name: :mobile_recovery_one_pending_candidate_index
  )
end

defp ensure_no_live_pending_recovery(organization_id, installation_id, now) do
  enforce_signed_posture_barrier(organization_id, installation_id, now)
end
'''
    if reject_nil_candidate:
        recovery_body += '''

defp normalize_candidate(nil), do: {:error, :candidate_key_required}
defp normalize_candidate(""), do: {:error, :candidate_key_required}
defp validate_purpose_contract(changeset) do
  add_error(changeset, :candidate_device_key_id, "is required for identity recovery")
end
'''
    else:
        recovery_body += '''

defp normalize_candidate(nil), do: {:ok, nil}
defp ensure_candidate_binding(_organization_id, _installation_id, _old_key_id, nil), do: :ok
'''
    recovery.write_text(recovery_body, encoding="utf-8")

    issue_body = [
        '@installation_lock_domain "tamandua.mobile.installation-lock/v1"',
        "def issue(organization_id, installation_id) do",
        "  lock_installation(organization_id, installation_id)",
        "  active_key(organization_id, installation_id, true)",
    ]
    if posture_issue_recovery_check:
        issue_body.append("  ensure_no_pending_recovery(organization_id, installation_id, now)")
    issue_body.append("end")

    ingestion.write_text(
        "\n".join(issue_body)
        + '''

def request_status(organization_id, request_id) do
  lock: "FOR UPDATE"
  pending_and_fresh(request, now)
'''
        + (
            '''
  lock_installation(organization_id, request.installation_id)
  ensure_no_pending_recovery(organization_id, request.installation_id, now)
  state: "blocked", reason: "identity_recovery_in_progress"
'''
            if posture_status_recovery_check
            else ""
        )
        + '''
end

defp upsert_projection(request, key, receipt, envelope, posture, observed_at, now) do
'''
        + (
            '''
  from(p in MobileSignedPostureProjection,
    where: p.verified_at <= fragment("EXCLUDED.verified_at")
  )
  conflict_target: [:organization_id, :installation_id]
  returning: true
'''
            if monotonic_projection
            else '''
  {:replace, [:receipt_id, :verified_at]}
  conflict_target: [:organization_id, :installation_id]
  returning: true
'''
        )
        + '''
end

defp verify_transaction(organization_id, request) do
  lock_installation(organization_id, request.installation_id)
  active_key(organization_id, request.installation_id, true)
  snapshot_matches(request, key)
  ensure_no_pending_recovery(organization_id, request.installation_id, now)
end

defp ensure_no_pending_recovery(organization_id, installation_id, now) do
  MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
    organization_id,
    installation_id,
    now
  )
end
''',
        encoding="utf-8",
    )

    cutover.write_text(
        '''
test "recovery issue waits for the canonical installation transaction lock" do
  Sandbox.unboxed_run(Repo, fn -> Repo.query!("pg_advisory_xact_lock") end)
end

test "committed recovery cutover makes signed posture issuance fail closed" do
end
''',
        encoding="utf-8",
    )

    expiry.write_text(
        '''
test "persists expiry at the exact server-time boundary before allowing posture" do
  Repo.query!("pg_advisory_xact_lock")
end

test "rolls stale expiry back when the enclosing posture decision fails" do
end

test "rolls an expired lease back when later posture work fails" do
  Repo.rollback(:posture_failed)
end

test "blocks before expiry and rejects a missing server time" do
end
''',
        encoding="utf-8",
    )

    migration_body = '''
constraint(:mobile_device_identity_recovery_intents, :recovery_intent_distinct_keys,
  check: "candidate_device_key_id <> old_device_key_id"
)

create(
  unique_index(
    :mobile_device_identity_recovery_intents,
    [:organization_id, :installation_id],
    name: :mobile_recovery_one_pending_installation_index,
    where: "state = 'pending'"
  )
)
'''
    if not reject_nil_candidate:
        migration_body = migration_body.replace(
            'check: "candidate_device_key_id <> old_device_key_id"',
            'check: "candidate_device_key_id IS NULL OR candidate_device_key_id <> old_device_key_id"',
        )
    if candidate_reservation:
        migration_body += '''

create(
  unique_index(
    :mobile_device_identity_recovery_intents,
    [:organization_id, :candidate_device_key_id],
    name: :mobile_recovery_one_pending_candidate_index,
    where: "state = 'pending'"
  )
)
'''
    migration.write_text(migration_body, encoding="utf-8")

    candidate_body = ""
    if candidate_http_contract:
        candidate_body = '''
test "missing, null, and empty candidates share one generic 422 contract" do
  Map.put(base, "candidate_device_key_id", nil)
  Map.put(base, "candidate_device_key_id", "")
  assert response == %{"error" => %{"code" => "recovery_intent_invalid"}}
  assert get_resp_header(conn, "cache-control") == ["no-store"]
  assert Repo.aggregate(MobileDeviceIdentityRecovery, :count) == 0
  refute inspect(response) =~ "candidate_device_key_id"
  refute inspect(response) =~ "binding"
  refute inspect(response) =~ "reservation"
  refute inspect(response) =~ "recovery_token"
end

test "whitespace-only candidate preserves the generic 400 request contract" do
  "candidate_device_key_id" => "   "
  assert response == %{"error" => %{"code" => "recovery_request_invalid"}}
  assert get_resp_header(conn, "cache-control") == ["no-store"]
  assert Repo.aggregate(MobileDeviceIdentityRecovery, :count) == 0
  refute inspect(response) =~ "candidate_device_key_id"
  refute inspect(response) =~ "binding"
  refute inspect(response) =~ "reservation"
  refute inspect(response) =~ "recovery_token"
end
'''
    candidate_test.write_text(candidate_body, encoding="utf-8")

    candidate_bind_body = ""
    if candidate_bind_test:
        candidate_bind_body = '''
test "candidate locks deduplicate and sort keys before acquiring PostgreSQL locks" do
  Sandbox.unboxed_run(Repo, fn -> MobileDeviceIdentityCandidateLock.lock_keys(org, keys) end)
end

test "the same candidate remains independently lockable in another tenant" do
  Sandbox.unboxed_run(Repo, fn -> MobileDeviceIdentityCandidateLock.lock_keys(org, key) end)
end

test "identity validates proof before installation and candidate locks, then binds" do
  MobileDeviceIdentityCandidateLock.lock_keys(org, key)
end

test "recovery locks installation then candidate before barriers and insertion" do
  MobileDeviceIdentityCandidateLock.lock_keys(org, key)
end
'''
    candidate_bind.write_text(candidate_bind_body, encoding="utf-8")

    return {
        "identity": identity,
        "candidate_lock": candidate_lock_path,
        "recovery": recovery,
        "ingestion": ingestion,
        "cutover": cutover,
        "expiry": expiry,
        "migration": migration,
        "candidate_test": candidate_test,
        "candidate_bind": candidate_bind,
    }


def evaluate(paths: dict[str, Path]) -> dict[str, object]:
    return audit.evaluate(
        paths["identity"],
        paths["candidate_lock"],
        paths["recovery"],
        paths["ingestion"],
        paths["cutover"],
        paths["expiry"],
        paths["migration"],
        paths["candidate_test"],
        paths["candidate_bind"],
    )


def test_valid_sources_pass_source_audit(tmp_path: Path):
    result = evaluate(write_sources(tmp_path))

    assert result["ok"] is True
    assert result["reasons"] == []


def test_candidate_lock_must_be_tenant_scoped_and_ordered(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, candidate_lock=False))

    assert result["ok"] is False
    assert "candidate_lock_is_tenant_scoped_and_ordered" in result["reasons"]


def test_identity_bind_must_lock_candidate_before_reservation_and_bind(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, identity_candidate_order=False))

    assert result["ok"] is False
    assert "identity_bind_locks_candidate_before_reservation_and_bind" in result["reasons"]


def test_recovery_issue_must_lock_candidate_before_barriers(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, recovery_candidate_lock=False))

    assert result["ok"] is False
    assert "recovery_issue_locks_before_binding_checks" in result["reasons"]


def test_posture_issue_requires_recovery_gate_after_installation_lock(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, posture_issue_recovery_check=False))

    assert result["ok"] is False
    assert "posture_issue_locks_before_recovery_check" in result["reasons"]


def test_posture_status_reflects_recovery_barrier(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, posture_status_recovery_check=False))

    assert result["ok"] is False
    assert "posture_status_reflects_recovery_barrier" in result["reasons"]


def test_posture_projection_upsert_must_be_monotonic(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, monotonic_projection=False))

    assert result["ok"] is False
    assert "posture_projection_upsert_is_monotonic" in result["reasons"]


def test_recovery_barrier_requires_transactional_expiry(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, expiry_barrier=False))

    assert result["ok"] is False
    assert "recovery_barrier_expires_stale_inside_transaction" in result["reasons"]


def test_recovery_issue_requires_pending_uniqueness_backstop(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, pending_backstop=False))

    assert result["ok"] is False
    assert "recovery_issue_has_pending_uniqueness_backstop" in result["reasons"]


def test_recovery_migration_reserves_pending_candidate_cross_installation(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, candidate_reservation=False))

    assert result["ok"] is False
    assert "recovery_migration_reserves_pending_candidate_cross_installation" in result["reasons"]


def test_recovery_rejects_nil_candidate_contract(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, reject_nil_candidate=False))

    assert result["ok"] is False
    assert "recovery_rejects_nil_candidate_contract" in result["reasons"]


def test_recovery_candidate_http_contract_test_is_required(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, candidate_http_contract=False))

    assert result["ok"] is False
    assert "recovery_candidate_http_contract_test_exists" in result["reasons"]


def test_candidate_bind_postgres_test_is_required(tmp_path: Path):
    result = evaluate(write_sources(tmp_path, candidate_bind_test=False))

    assert result["ok"] is False
    assert "postgres_candidate_bind_serialization_test_exists" in result["reasons"]
