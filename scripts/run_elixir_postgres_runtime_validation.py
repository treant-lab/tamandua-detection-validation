#!/usr/bin/env python3
"""Fail-closed, provenance-bound local Elixir/PostgreSQL runtime smoke harness."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[3]
HARNESS = Path(__file__).resolve()
LOADED_HARNESS_SHA256 = hashlib.sha256(HARNESS.read_bytes()).hexdigest()
SERVER = ROOT / "apps" / "tamandua_server"
PROFILE_ID = "elixir-postgres-runtime-validation"
EXECUTION_CONTRACT_VERSION = 2
PASSWORD_ENV = "TAMANDUA_ELIXIR_RUNTIME_DB_PASSWORD"
DEFAULT_TESTS = (
    "test/tamandua_server/mobile/mobile_mutation_authorization_test.exs",
    "test/tamandua_server/mobile/mobile_mutation_authorization_rls_test.exs",
    "test/tamandua_server_web/controllers/api/v1/mobile_device_mutation_authorization_controller_test.exs",
)
OPTIONAL_RUNTIME_TEST = "test/tamandua_server/mobile/mobile_mutation_authorization_runtime_pg_test.exs"
INPUTS = ("mix.exs", "mix.lock", "config", "lib", "priv", "test")
AUTHORITY_BOOTSTRAP = ROOT / "tools" / "authority_bootstrap" / "authority_bootstrap.sql"
STAGED_AUTHORITY_BOOTSTRAP = "authority_bootstrap.sql"
CLAIM_BOUNDARY = (
    "Local dirty-worktree Elixir/PostgreSQL runtime smoke for the exact recorded source inputs and "
    "container identities only. It is not production, release, deployment, governed holdout, vendor "
    "parity, complete server validation, or external-claim evidence."
)
FULL_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
MAX_OWNED_READINESS_SECONDS = 180
MAX_PSQL_STDIN_BYTES = 64 * 1024
MAX_PSQL_OUTPUT_BYTES = 64 * 1024
MAX_RUNNER_OUTPUT_BYTES = 64 * 1024
BOOTSTRAP_MIGRATION_CUTOFF = "20260716007000"
MIGRATIONS_BEGIN = "TAMANDUA_MIGRATIONS_BEGIN"
MIGRATIONS_END = "TAMANDUA_MIGRATIONS_END"
OWNED_RUNTIME_TESTS = (
    "test/tamandua_server/authorization/access_policy_global_rls_runtime_pg_test.exs",
    "test/tamandua_server/authorization/rbac_fresh_permission_test.exs",
    "test/tamandua_server_web/controllers/api/v1/mobile_device_identity_recovery_controller_test.exs",
)
DEGRADED_ROLE_SQL = b"""CREATE ROLE tamandua_authority_login LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE tamandua_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE tamandua_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
"""
MIGRATION_AUDIT_SQL = b"SELECT version::text FROM public.schema_migrations ORDER BY version;\n"
ROLE_AUDIT_SQL = b"""SELECT roles.rolname || '|' || roles.rolcanlogin::text || '|' || roles.rolinherit::text || '|' || roles.rolsuper::text || '|' || roles.rolcreatedb::text || '|' || roles.rolcreaterole::text || '|' || roles.rolreplication::text || '|' || roles.rolbypassrls::text || '|' || roles.rolconnlimit || '|' || (roles.rolvaliduntil IS NULL)::text || '|' || (roles.rolconfig IS NULL)::text || '|' || (auth.rolpassword IS NULL)::text || '|' || COALESCE((
  SELECT pg_catalog.string_agg(granted.rolname || ':' || membership.admin_option::text || ':' || membership.inherit_option::text || ':' || membership.set_option::text, ',' ORDER BY granted.rolname)
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
  WHERE membership.member = roles.oid
), '-') || '|' || COALESCE((
  SELECT pg_catalog.string_agg(member_role.rolname || ':' || membership.admin_option::text || ':' || membership.inherit_option::text || ':' || membership.set_option::text, ',' ORDER BY member_role.rolname)
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
  WHERE membership.roleid = roles.oid
), '-')
FROM pg_catalog.pg_roles AS roles
JOIN pg_catalog.pg_authid AS auth ON auth.oid = roles.oid
WHERE roles.rolname IN ('tamandua_authority_login', 'tamandua_authority_retention_executor', 'tamandua_authority_retention_owner', 'tamandua_migrator', 'tamandua_runtime')
ORDER BY roles.rolname;
"""
EXPECTED_DEGRADED_ROLE_ROWS = (
    "tamandua_authority_login|true|false|false|false|false|false|false|-1|true|true|true|tamandua_authority_retention_executor:false:false:true|-",
    "tamandua_authority_retention_executor|false|false|false|false|false|false|false|-1|true|true|true|-|tamandua_authority_login:false:false:true",
    "tamandua_authority_retention_owner|false|false|false|false|false|false|false|-1|true|true|true|-|-",
    "tamandua_migrator|true|false|false|false|false|false|false|-1|true|true|true|-|-",
    "tamandua_runtime|true|false|false|false|false|false|false|-1|true|true|true|-|-",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_source_digest(
    server: Path = SERVER, authority_bootstrap: Path = AUTHORITY_BOOTSTRAP
) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    paths: list[Path] = []
    for item in INPUTS:
        candidate = server / item
        if candidate.is_symlink():
            raise RuntimeError(f"source_symlink_forbidden:{item}")
        if candidate.is_file():
            paths.append(candidate)
        elif candidate.is_dir():
            for path in candidate.rglob("*"):
                relative = path.relative_to(server).as_posix()
                if path.is_symlink():
                    raise RuntimeError(f"source_symlink_forbidden:{relative}")
                if path.is_file():
                    paths.append(path)
                elif not path.is_dir():
                    raise RuntimeError(f"source_non_regular_forbidden:{relative}")
        else:
            raise RuntimeError(f"source_input_missing:{item}")
    sources = [(path.relative_to(server).as_posix(), path) for path in paths]
    if authority_bootstrap.is_symlink():
        raise RuntimeError("authority_bootstrap_symlink_forbidden")
    if not authority_bootstrap.is_file():
        raise RuntimeError("authority_bootstrap_missing")
    sources.append((STAGED_AUTHORITY_BOOTSTRAP, authority_bootstrap))
    for relative_name, path in sorted(sources):
        relative = relative_name.encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        count += 1
    return digest.hexdigest(), count


def stage_source(server: Path = SERVER) -> tuple[tempfile.TemporaryDirectory[str], Path, str, int]:
    # Reject links and special files before a copying API can follow them into
    # the staged runner context. The staged/live digest check below still
    # closes ordinary source drift after this static boundary validation.
    canonical_source_digest(server, AUTHORITY_BOOTSTRAP)
    temporary = tempfile.TemporaryDirectory(prefix="tamandua-elixir-runtime-")
    staged = Path(temporary.name) / "source"
    staged.mkdir()
    for item in INPUTS:
        source = server / item
        target = staged / item
        if source.is_dir():
            shutil.copytree(source, target)
        elif source.is_file():
            shutil.copy2(source, target)
        else:
            temporary.cleanup()
            raise RuntimeError(f"source_input_missing:{item}")
    shutil.copy2(AUTHORITY_BOOTSTRAP, staged / STAGED_AUTHORITY_BOOTSTRAP)
    digest, count = canonical_source_digest(staged, staged / STAGED_AUTHORITY_BOOTSTRAP)
    return temporary, staged, digest, count


def safe_text(value: str, secret: str | None) -> str:
    return value.replace(secret, "[REDACTED]") if secret else value


class Commands:
    def __init__(self, secret: str | None = None) -> None:
        self.secret = secret

    def run(self, args: list[str], *, timeout: int = 60, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
            completed = subprocess.CompletedProcess(args, 124, stdout, f"{stderr}\ncommand_timeout".lstrip())
        completed.stdout = safe_text(completed.stdout, self.secret)
        completed.stderr = safe_text(completed.stderr, self.secret)
        return completed

    def run_stdin(
        self, args: list[str], payload: bytes, *, timeout: int = 60
    ) -> subprocess.CompletedProcess[str]:
        validate_bounded_utf8(payload, "psql_stdin", MAX_PSQL_STDIN_BYTES)
        try:
            completed = subprocess.run(
                args, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            validate_bounded_utf8(stdout, "psql_stdout", MAX_PSQL_OUTPUT_BYTES)
            validate_bounded_utf8(stderr, "psql_stderr", MAX_PSQL_OUTPUT_BYTES)
            return subprocess.CompletedProcess(
                args, 124, stdout.decode("utf-8"), stderr.decode("utf-8")
            )
        validate_bounded_utf8(completed.stdout, "psql_stdout", MAX_PSQL_OUTPUT_BYTES)
        validate_bounded_utf8(completed.stderr, "psql_stderr", MAX_PSQL_OUTPUT_BYTES)
        return subprocess.CompletedProcess(
            args, completed.returncode, completed.stdout.decode("utf-8"), completed.stderr.decode("utf-8")
        )


def validate_bounded_utf8(payload: bytes, field: str, maximum: int) -> None:
    if not isinstance(payload, bytes):
        raise ValueError(f"{field}_must_be_bytes")
    if len(payload) > maximum:
        raise ValueError(f"{field}_too_large")
    if b"\x00" in payload:
        raise ValueError(f"{field}_contains_nul")
    try:
        decoded = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"{field}_not_utf8") from error
    if decoded.encode("utf-8") != payload:
        raise ValueError(f"{field}_not_byte_stable")


def validate_bounded_text(value: str, field: str, maximum: int) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field}_must_be_text")
    if "\x00" in value:
        raise ValueError(f"{field}_contains_nul")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field}_not_utf8") from error
    if len(encoded) > maximum:
        raise ValueError(f"{field}_too_large")


def inspect(commands: Commands, kind: str, name: str) -> dict[str, Any]:
    result = commands.run(["docker", kind, "inspect", name])
    if result.returncode != 0:
        raise RuntimeError(f"{kind}_inspect_failed:{safe_text(result.stderr.strip(), commands.secret)}")
    payload = json.loads(result.stdout)
    if not isinstance(payload, list) or len(payload) != 1:
        raise RuntimeError(f"{kind}_inspect_invalid")
    return payload[0]


def inspect_container_optional(commands: Commands, reference: str) -> dict[str, Any] | None:
    result = commands.run(["docker", "container", "inspect", reference])
    if result.returncode == 0:
        payload = json.loads(result.stdout)
        if not isinstance(payload, list) or len(payload) != 1:
            raise RuntimeError("container_inspect_invalid")
        return payload[0]
    filter_value = f"id={reference}" if len(reference) == 64 else f"name={reference}"
    absence = commands.run([
        "docker", "container", "ls", "--all", "--no-trunc", "--filter", filter_value,
        "--format", "{{.ID}}",
    ])
    if absence.returncode == 0 and not absence.stdout.strip():
        return None
    raise RuntimeError(f"container_inspect_unknown:{safe_text(result.stderr.strip(), commands.secret)}")


def inspect_network_optional(commands: Commands, reference: str) -> dict[str, Any] | None:
    result = commands.run(["docker", "network", "inspect", reference])
    if result.returncode == 0:
        payload = json.loads(result.stdout)
        if not isinstance(payload, list) or len(payload) != 1:
            raise RuntimeError("network_inspect_invalid")
        return payload[0]
    filter_value = f"id={reference}" if re.fullmatch(r"[a-f0-9]{64}", reference) else f"name=^{reference}$"
    absence = commands.run([
        "docker", "network", "ls", "--no-trunc", "--filter", filter_value,
        "--format", "{{.ID}}",
    ])
    if absence.returncode == 0 and not absence.stdout.strip():
        return None
    raise RuntimeError(f"network_inspect_unknown:{safe_text(result.stderr.strip(), commands.secret)}")


def network_names(container: dict[str, Any]) -> list[str]:
    networks = container.get("NetworkSettings", {}).get("Networks", {})
    return sorted(networks) if isinstance(networks, dict) else []


def normalized_health(container: dict[str, Any]) -> str:
    health = container.get("State", {}).get("Health", {}).get("Status")
    return str(health or "missing").lower()


def network_endpoint(container: dict[str, Any], network: str) -> str:
    networks = container.get("NetworkSettings", {}).get("Networks", {})
    attachment = networks.get(network) if isinstance(networks, dict) else None
    endpoint = attachment.get("IPAddress") if isinstance(attachment, dict) else None
    try:
        parsed = ipaddress.ip_address(str(endpoint or ""))
    except ValueError as error:
        raise RuntimeError("database_network_endpoint_invalid") from error
    if parsed.version != 4 or parsed.is_unspecified:
        raise RuntimeError("database_network_endpoint_invalid")
    return str(parsed)


def readonly_bind_mount(source: Path, destination: str = "/source") -> str:
    rendered = str(source.resolve())
    if not source.is_absolute() or not destination.startswith("/"):
        raise RuntimeError("bind_mount_path_not_absolute")
    if any(character in rendered or character in destination for character in (",", "\n", "\r", "\x00")):
        raise RuntimeError("bind_mount_path_not_serializable")
    return f"type=bind,src={rendered},dst={destination},readonly"


def selected_tests(server: Path, explicit: Iterable[str]) -> list[str]:
    tests = list(explicit) or list(DEFAULT_TESTS)
    if not explicit and (server / OPTIONAL_RUNTIME_TEST).is_file():
        tests.append(OPTIONAL_RUNTIME_TEST)
    normalized: list[str] = []
    for test in tests:
        candidate = Path(test).as_posix().lstrip("/")
        if not candidate.startswith("test/") or ".." in Path(candidate).parts or not candidate.endswith("_test.exs"):
            raise ValueError(f"invalid_test_path:{test}")
        if not (server / candidate).is_file():
            raise ValueError(f"missing_test_path:{candidate}")
        normalized.append(candidate)
    if len(normalized) != len(set(normalized)):
        raise ValueError("duplicate_test_path")
    return normalized


def base_receipt(args: argparse.Namespace, source_digest: str, file_count: int, tests: list[str]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "execution_contract_version": EXECUTION_CONTRACT_VERSION,
        "profile_id": PROFILE_ID,
        "generated_at": now(),
        "mode": "execute" if args.execute else "inspect",
        "status": "blocked",
        "source": {"sha256": source_digest, "file_count": file_count, "dirty_worktree": True,
                   "staged_sha256": None, "staged_file_count": None,
                   "harness_sha256": LOADED_HARNESS_SHA256},
        "database": {"mode": "owned" if args.owned_database else "shared",
                     "container_name": args.db_container, "expected_container_id": args.expected_db_container_id,
                     "image": args.db_image, "expected_image_id": args.expected_db_image_id,
                     "network": args.network, "readiness_timeout_seconds": args.readiness_timeout},
        "runner": {"image": args.runner_image, "expected_image_id": args.expected_runner_image_id},
        "tests": tests,
        "checks": {},
        "cleanup": {"runner_absent": None, "pre_bootstrap_runner_absent": None,
                    "post_bootstrap_runner_absent": None, "test_database_absent": None,
                    "database_container_absent": None, "network_absent": None,
                    "zero_residue": False, "verified": False},
        "claims": {"local_dirty_worktree_runtime_smoke": False, "product_ready": False,
                   "production_validated": False, "external_claim_allowed": False, "vendor_parity": False},
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": [],
    }


def pin_and_check(receipt: dict[str, Any], args: argparse.Namespace, commands: Commands) -> bool:
    if args.owned_database:
        raise RuntimeError("owned_database_requires_owned_preflight")
    db = inspect(commands, "container", args.db_container)
    runner = inspect(commands, "image", args.runner_image)
    observed = {
        "db_container_id": db.get("Id"), "db_image_id": db.get("Image"),
        "runner_image_id": runner.get("Id"), "db_health": normalized_health(db),
        "db_networks": network_names(db), "db_network_endpoint": None,
    }
    if args.network in observed["db_networks"]:
        observed["db_network_endpoint"] = network_endpoint(db, args.network)
    receipt["observed"] = observed
    checks = receipt["checks"]
    checks["network_exact"] = observed["db_networks"] == [args.network]
    checks["database_healthy"] = observed["db_health"] == "healthy"
    checks["database_endpoint_pinned"] = bool(observed["db_network_endpoint"])
    full_container_id = bool(args.expected_db_container_id) and len(args.expected_db_container_id) == 64 and all(
        character in "0123456789abcdef" for character in args.expected_db_container_id
    )
    checks["database_container_id_pinned"] = full_container_id and observed["db_container_id"] == args.expected_db_container_id
    full_db_image_id = bool(args.expected_db_image_id) and len(args.expected_db_image_id) == 71 and args.expected_db_image_id.startswith("sha256:") and all(
        character in "0123456789abcdef" for character in args.expected_db_image_id[7:]
    )
    full_runner_image_id = bool(args.expected_runner_image_id) and len(args.expected_runner_image_id) == 71 and args.expected_runner_image_id.startswith("sha256:") and all(
        character in "0123456789abcdef" for character in args.expected_runner_image_id[7:]
    )
    checks["database_image_id_pinned"] = full_db_image_id and observed["db_image_id"] == args.expected_db_image_id
    checks["runner_image_id_pinned"] = full_runner_image_id and observed["runner_image_id"] == args.expected_runner_image_id
    if not all(checks.values()):
        receipt["limitations"].append("container_preflight_failed_or_expected_full_ids_not_supplied")
        return False
    return True


def owned_pin_and_check(receipt: dict[str, Any], args: argparse.Namespace, commands: Commands) -> bool:
    db = inspect(commands, "image", args.db_image)
    runner = inspect(commands, "image", args.runner_image)
    receipt["observed"] = {
        "db_container_id": None, "db_image_id": db.get("Id"),
        "runner_image_id": runner.get("Id"), "db_health": "not_created",
        "db_networks": [], "db_network_endpoint": None,
    }
    receipt["checks"].update({
        "database_image_id_pinned": db.get("Id") == args.db_image == args.expected_db_image_id,
        "runner_image_id_pinned": runner.get("Id") == args.runner_image == args.expected_runner_image_id,
    })
    if not all(receipt["checks"].values()):
        receipt["limitations"].append("owned_image_ids_must_be_full_pinned_and_match_inspection")
        return False
    return True


def runner_script(tests: list[str], *, owned_database: bool = False) -> str:
    if owned_database:
        raise ValueError("owned_database_requires_two_phase_runner")
    quoted_tests = " ".join(shlex.quote(test) for test in tests)
    cleanup = "mix ecto.drop --quiet >/dev/null 2>&1 || true"
    migration_setup = "mix ecto.migrate --quiet"
    return f"""set -eu
rm -rf /work/app
test -f mix.exs
test -d deps
cp -a . /work/app
for item in mix.exs mix.lock config lib priv test; do rm -rf \"/work/app/$item\"; cp -a \"/source/$item\" \"/work/app/$item\"; done
cd /work/app
export MIX_ENV=test TEST_DB_PASS=\"$TAMANDUA_ELIXIR_RUNTIME_DB_PASSWORD\" PGPASSWORD=\"$TAMANDUA_ELIXIR_RUNTIME_DB_PASSWORD\"
cleanup() {{ {cleanup}; }}
trap cleanup EXIT INT TERM
mix ecto.create --quiet
psql -h \"$TEST_DB_HOST\" -U \"$TEST_DB_USER\" -d postgres -v ON_ERROR_STOP=1 -c "COMMENT ON DATABASE \"$TEST_DB_NAME\" IS 'tamandua-runtime-validation:$TAMANDUA_RUNTIME_INVOCATION_ID'" >/dev/null
{migration_setup}
printf '%s\n' '{MIGRATIONS_BEGIN}'
psql -h "$TEST_DB_HOST" -U "$TEST_DB_USER" -At -d "$TEST_DB_NAME" -c 'SELECT version::text FROM public.schema_migrations ORDER BY version'
printf '%s\n' '{MIGRATIONS_END}'
mix test {quoted_tests}
"""


def owned_runner_script(tests: list[str], phase: str) -> str:
    if tuple(tests) != OWNED_RUNTIME_TESTS:
        raise ValueError("owned_runtime_tests_must_match_exact_gate")
    setup = """set -eu
rm -rf /work/app
test -f mix.exs
test -d deps
cp -a . /work/app
for item in mix.exs mix.lock config lib priv test; do rm -rf \"/work/app/$item\"; cp -a \"/source/$item\" \"/work/app/$item\"; done
cd /work/app
export MIX_ENV=test TAMANDUA_ALLOW_DEGRADED_CREDENTIALS=true
"""
    if phase == "pre_bootstrap":
        return setup + f"mix ecto.migrate --quiet --to {BOOTSTRAP_MIGRATION_CUTOFF}\n"
    if phase == "post_bootstrap":
        quoted_tests = " ".join(shlex.quote(test) for test in tests)
        return setup + (
            "export TAMANDUA_ACCESS_POLICY_GLOBAL_RLS_RUNTIME_PG_TESTS=true\n"
            "mix ecto.migrate --quiet\n"
            f"mix test {quoted_tests}\n"
        )
    raise ValueError("owned_runner_phase_invalid")


def parse_execution_audit(stdout: str, expected_tests: list[str]) -> dict[str, Any]:
    if stdout.count(MIGRATIONS_BEGIN) != 1 or stdout.count(MIGRATIONS_END) != 1:
        raise RuntimeError("migration_audit_markers_invalid")
    body = stdout.split(MIGRATIONS_BEGIN, 1)[1].split(MIGRATIONS_END, 1)[0]
    versions = [line.strip() for line in body.splitlines() if line.strip()]
    if not versions or any(not re.fullmatch(r"[0-9]+", version) for version in versions):
        raise RuntimeError("migration_audit_invalid")
    if versions != sorted(set(versions), key=int):
        raise RuntimeError("migration_audit_not_strictly_ordered")
    summaries = re.findall(r"(?m)^\s*(\d+) tests?,\s*(\d+) failures?(.*)$", stdout)
    if len(summaries) != 1:
        raise RuntimeError("exunit_summary_invalid")
    total, failures, suffix = summaries[0]
    excluded = re.search(r"(\d+) excluded", suffix)
    skipped = re.search(r"(\d+) skipped", suffix)
    encoded = "\n".join(versions).encode("ascii")
    return {
        "migration_count": len(versions),
        "migration_max": versions[-1],
        "migration_digest_sha256": hashlib.sha256(encoded).hexdigest(),
        "test_files_requested": len(expected_tests),
        "test_command_count": 1,
        "test_retry_count": 0,
        "tests_total": int(total),
        "failures": int(failures),
        "excluded": int(excluded.group(1)) if excluded else 0,
        "skipped": int(skipped.group(1)) if skipped else 0,
    }


def parse_migration_rows(stdout: str) -> dict[str, Any]:
    versions = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not versions or any(not re.fullmatch(r"[0-9]+", version) for version in versions):
        raise RuntimeError("migration_audit_invalid")
    if versions != sorted(set(versions), key=int):
        raise RuntimeError("migration_audit_not_strictly_ordered")
    encoded = "\n".join(versions).encode("ascii")
    return {
        "migration_count": len(versions),
        "migration_max": versions[-1],
        "migration_digest_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def parse_test_audit(stdout: str, expected_tests: list[str]) -> dict[str, Any]:
    summaries = re.findall(r"(?m)^\s*(\d+) tests?,\s*(\d+) failures?(.*)$", stdout)
    if len(summaries) != 1:
        raise RuntimeError("exunit_summary_invalid")
    total, failures, suffix = summaries[0]
    excluded = re.search(r"(\d+) excluded", suffix)
    skipped = re.search(r"(\d+) skipped", suffix)
    return {
        "test_files_requested": len(expected_tests), "test_command_count": 1,
        "test_retry_count": 0, "tests_total": int(total), "failures": int(failures),
        "excluded": int(excluded.group(1)) if excluded else 0,
        "skipped": int(skipped.group(1)) if skipped else 0,
    }


def migration_inventory(staged: Path) -> dict[str, Any]:
    versions = []
    for path in (staged / "priv" / "repo" / "migrations").glob("*.exs"):
        match = re.fullmatch(r"([0-9]+)_.+\.exs", path.name)
        if not match:
            continue
        versions.append(match.group(1))
    versions.sort(key=int)
    if not versions or len(versions) != len(set(versions)):
        raise RuntimeError("migration_source_inventory_invalid")
    encoded = "\n".join(versions).encode("ascii")
    return {"migration_count": len(versions), "migration_max": versions[-1],
            "migration_digest_sha256": hashlib.sha256(encoded).hexdigest()}


def validate_bootstrap_cutoff(staged: Path) -> None:
    candidates = list(
        (staged / "priv" / "repo" / "migrations").glob(f"{BOOTSTRAP_MIGRATION_CUTOFF}_*.exs")
    )
    if len(candidates) != 1 or not candidates[0].is_file():
        raise RuntimeError("bootstrap_migration_cutoff_source_invalid")


def source_pair_matches(
    staged: Path, expected_digest: str, expected_count: int, expected_harness_sha256: str
) -> bool:
    live_digest, live_count = canonical_source_digest()
    staged_digest, staged_count = canonical_source_digest(
        staged, staged / STAGED_AUTHORITY_BOOTSTRAP
    )
    return bool(
        live_digest == staged_digest == expected_digest
        and live_count == staged_count == expected_count
        and sha256_file(HARNESS) == expected_harness_sha256
    )


def psql_stdin(
    commands: Commands, database_id: str, database: str, payload: bytes,
    *, variables: tuple[str, ...] = (), category: str
) -> str:
    validate_bounded_utf8(payload, "psql_stdin", MAX_PSQL_STDIN_BYTES)
    command = [
        "docker", "exec", "-i", database_id, "psql", "-X", "--no-psqlrc", "-qAt",
        "--no-password", "-v", "ON_ERROR_STOP=1", "-U", "tamandua",
    ]
    for variable in variables:
        command.extend(["-v", variable])
    command.extend(["-d", database])
    result = commands.run_stdin(command, payload, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"{category}_failed")
    return result.stdout


def owned_database_matches(
    commands: Commands, database_id: str, database_name: str, network_name: str,
    invocation_id: str, expected_image_id: str
) -> bool:
    try:
        by_id = inspect_container_optional(commands, database_id)
        by_name = inspect_container_optional(commands, database_name)
    except (RuntimeError, ValueError, json.JSONDecodeError):
        return False
    if not by_id or not by_name or by_id.get("Id") != database_id or by_name.get("Id") != database_id:
        return False
    labels = by_id.get("Config", {}).get("Labels", {})
    return bool(
        by_id.get("Id") == database_id and by_name.get("Id") == database_id
        and by_id.get("Image") == expected_image_id
        and labels.get("tamandua.runtime-validation.invocation") == invocation_id
        and network_names(by_id) == [network_name]
        and not by_id.get("HostConfig", {}).get("PortBindings")
        and by_id.get("State", {}).get("Running") is True
    )


def database_marker(commands: Commands, db_container_id: str, user: str, database: str) -> tuple[bool, str | None]:
    query = (
        "SELECT 'present:' || COALESCE(shobj_description(oid,'pg_database'),'') FROM pg_database "
        f"WHERE datname='{database}'"
    )
    result = commands.run(["docker", "exec", db_container_id, "psql", "-U", user, "-d", "postgres", "-tAc", query])
    if result.returncode != 0:
        raise RuntimeError("database_presence_unknown")
    output = result.stdout.strip()
    if not output:
        return False, None
    if not output.startswith("present:"):
        raise RuntimeError("database_marker_invalid")
    return True, output.removeprefix("present:") or None


def verify_database_absent(commands: Commands, db_container_id: str, user: str, database: str) -> bool:
    query = f"SELECT 1 FROM pg_database WHERE datname='{database}'"
    result = commands.run(["docker", "exec", db_container_id, "psql", "-U", user, "-d", "postgres", "-tAc", query])
    if result.returncode != 0:
        raise RuntimeError("database_absence_unknown")
    return result.stdout.strip() == ""


def cleanup(commands: Commands, args: argparse.Namespace, runner_name: str, runner_id: str | None, database: str,
            invocation_id: str, database_owned: bool) -> dict[str, bool]:
    runner_absent = False
    if runner_id:
        current = inspect_container_optional(commands, runner_id)
        labels = (current or {}).get("Config", {}).get("Labels", {})
        if current is not None and labels.get("tamandua.runtime-validation.invocation") != invocation_id:
            raise RuntimeError("runner_ownership_mismatch")
        if current is not None:
            removed = commands.run(["docker", "rm", "-f", runner_id], timeout=30)
            if removed.returncode != 0:
                raise RuntimeError("runner_cleanup_failed")
        runner_absent = inspect_container_optional(commands, runner_id) is None
    else:
        runner_absent = inspect_container_optional(commands, runner_name) is None
    if database_owned:
        exists, marker = database_marker(commands, args.expected_db_container_id, args.db_user, database)
        if exists and marker != f"tamandua-runtime-validation:{invocation_id}":
            raise RuntimeError("database_ownership_mismatch")
        if exists:
            dropped = commands.run(["docker", "exec", args.expected_db_container_id, "dropdb", "-U", args.db_user,
                                    "--force", database], timeout=30)
            if dropped.returncode != 0:
                raise RuntimeError("database_cleanup_failed")
    database_absent = verify_database_absent(
        commands, args.expected_db_container_id, args.db_user, database
    )
    verified = runner_absent and database_absent
    return {"runner_absent": runner_absent, "test_database_absent": database_absent,
            "database_container_absent": None, "network_absent": None,
            "zero_residue": verified, "verified": verified}


def execute(receipt: dict[str, Any], args: argparse.Namespace, commands: Commands, source_digest: str) -> bool:
    suffix = secrets.token_hex(16)
    runner_name = f"tamandua-elixir-runtime-{suffix}"
    database = f"tamandua_loop84_{suffix}"
    invocation_id = suffix
    receipt["execution"] = {"invocation_id": invocation_id, "runner_name": runner_name,
                            "runner_container_id": None, "database_endpoint": None,
                            "test_database": database, "exit_code": None}
    env = os.environ.copy()
    env[PASSWORD_ENV] = commands.secret or ""
    temporary: tempfile.TemporaryDirectory[str] | None = None
    runner_id: str | None = None
    database_owned = False
    passed = False
    try:
        db_before = inspect_container_optional(commands, args.expected_db_container_id)
        if not db_before or db_before.get("Id") != args.expected_db_container_id:
            raise RuntimeError("database_container_disappeared_before_execution")
        db_endpoint = network_endpoint(db_before, args.network)
        if db_endpoint != receipt.get("observed", {}).get("db_network_endpoint"):
            raise RuntimeError("database_endpoint_changed_before_execution")
        receipt["execution"]["database_endpoint"] = db_endpoint
        if inspect_container_optional(commands, runner_name) is not None:
            raise RuntimeError("runner_name_preexisting")
        if not verify_database_absent(commands, args.expected_db_container_id, args.db_user, database):
            raise RuntimeError("test_database_preexisting")
        receipt["checks"]["generated_resources_absent_preflight"] = True
        temporary, staged, staged_digest, staged_count = stage_source()
        receipt["source"].update(staged_sha256=staged_digest, staged_file_count=staged_count)
        source_after_stage, source_count_after_stage = canonical_source_digest()
        receipt["checks"]["staged_source_matches_recorded"] = (
            staged_digest == source_digest and staged_count == receipt["source"]["file_count"]
            and source_after_stage == source_digest and source_count_after_stage == receipt["source"]["file_count"]
        )
        if not receipt["checks"]["staged_source_matches_recorded"]:
            raise RuntimeError("staged_source_digest_mismatch")
        command = [
            "docker", "run", "--name", runner_name, "--network", args.network,
            "--label", f"tamandua.runtime-validation.invocation={invocation_id}",
            "--mount", readonly_bind_mount(staged),
            "--tmpfs", "/work:rw,exec,nosuid,size=2g", "--env", PASSWORD_ENV,
            "--env", f"TAMANDUA_RUNTIME_INVOCATION_ID={invocation_id}",
            "--env", f"TEST_DB_HOST={db_endpoint}", "--env", f"TEST_DB_USER={args.db_user}",
            "--env", f"TEST_DB_NAME={database}", "--entrypoint", "sh", args.expected_runner_image_id,
            "-c", runner_script(receipt["tests"]),
        ]
        result = commands.run(command, timeout=args.timeout, env=env)
        receipt["execution"].update(exit_code=result.returncode, stdout=result.stdout[-8000:], stderr=result.stderr[-8000:])
        created = inspect_container_optional(commands, runner_name)
        if created is None:
            raise RuntimeError("finished_runner_missing")
        labels = created.get("Config", {}).get("Labels", {})
        if labels.get("tamandua.runtime-validation.invocation") != invocation_id:
            raise RuntimeError("runner_ownership_mismatch")
        runner_id = created.get("Id")
        if (not isinstance(runner_id, str) or len(runner_id) != 64
                or any(character not in "0123456789abcdef" for character in runner_id)):
            raise RuntimeError("runner_container_id_invalid")
        runner_state = created.get("State", {})
        receipt["checks"]["finished_runner_verified"] = bool(
            runner_state.get("Status") == "exited" and runner_state.get("Running") is False
            and runner_state.get("ExitCode") == result.returncode
        )
        if not receipt["checks"]["finished_runner_verified"]:
            raise RuntimeError("finished_runner_state_invalid")
        receipt["execution"]["runner_container_id"] = runner_id
        exists, marker = database_marker(commands, args.expected_db_container_id, args.db_user, database)
        database_owned = exists and marker == f"tamandua-runtime-validation:{invocation_id}"
        if result.returncode == 0:
            receipt["audit"] = parse_execution_audit(result.stdout, receipt["tests"])
        passed = bool(result.returncode == 0 and receipt.get("audit", {}).get("failures") == 0)
    finally:
        try:
            receipt["cleanup"] = cleanup(
                commands, args, runner_name, runner_id, database, invocation_id, database_owned
            )
        finally:
            if temporary is not None:
                temporary.cleanup()
    db_after = inspect_container_optional(commands, args.expected_db_container_id)
    db_name_after = inspect_container_optional(commands, args.db_container)
    receipt["checks"]["database_identity_stable"] = bool(
        db_after and db_name_after and db_after.get("Id") == args.expected_db_container_id
        and db_name_after.get("Id") == args.expected_db_container_id
        and db_after.get("Image") == args.expected_db_image_id
        and network_names(db_after) == [args.network] and normalized_health(db_after) == "healthy"
        and network_endpoint(db_after, args.network) == receipt["execution"]["database_endpoint"]
    )
    receipt["checks"]["cleanup_verified"] = receipt["cleanup"]["verified"]
    return (passed and receipt["checks"].get("staged_source_matches_recorded", False)
            and receipt["checks"]["database_identity_stable"] and receipt["checks"]["cleanup_verified"])


def owned_cleanup(
    commands: Commands, invocation_id: str,
    runners: tuple[tuple[str, str | None, str], ...], database_name: str,
    network_name: str, database_id: str | None, network_id: str | None,
) -> dict[str, Any]:
    outcomes: dict[str, bool | None] = {
        "pre_bootstrap_runner_absent": None, "post_bootstrap_runner_absent": None,
        "database_container_absent": None, "network_absent": None,
    }

    def remove_container(name: str, resource_id: str | None) -> bool:
        try:
            by_name = inspect_container_optional(commands, name)
            if by_name is not None:
                labels = by_name.get("Config", {}).get("Labels", {})
                if labels.get("tamandua.runtime-validation.invocation") != invocation_id:
                    return False
                observed_id = by_name.get("Id")
                if resource_id is not None and observed_id != resource_id:
                    return False
                resource_id = observed_id
            if resource_id is None:
                return True
            if not re.fullmatch(r"[a-f0-9]{64}", str(resource_id)):
                return False
            current = inspect_container_optional(commands, resource_id)
            labels = (current or {}).get("Config", {}).get("Labels", {})
            if current is not None and labels.get("tamandua.runtime-validation.invocation") != invocation_id:
                return False
            if current is not None and commands.run(["docker", "rm", "-f", resource_id], timeout=30).returncode != 0:
                return False
            return (inspect_container_optional(commands, resource_id) is None
                    and inspect_container_optional(commands, name) is None)
        except (RuntimeError, ValueError, json.JSONDecodeError):
            return False

    for name, resource_id, outcome in runners:
        outcomes[outcome] = remove_container(name, resource_id)
    outcomes["database_container_absent"] = remove_container(database_name, database_id)

    try:
        by_name = inspect_network_optional(commands, network_name)
        if by_name is not None:
            labels = by_name.get("Labels", {})
            if labels.get("tamandua.runtime-validation.invocation") != invocation_id:
                outcomes["network_absent"] = False
            elif network_id is not None and by_name.get("Id") != network_id:
                outcomes["network_absent"] = False
            else:
                network_id = by_name.get("Id")
        if outcomes["network_absent"] is None:
            if network_id is None:
                outcomes["network_absent"] = True
            elif not re.fullmatch(r"[a-f0-9]{64}", str(network_id)):
                outcomes["network_absent"] = False
            else:
                current = inspect_network_optional(commands, network_id)
                labels = (current or {}).get("Labels", {})
                if current is not None and labels.get("tamandua.runtime-validation.invocation") != invocation_id:
                    outcomes["network_absent"] = False
                elif current is not None and commands.run(["docker", "network", "rm", network_id], timeout=30).returncode != 0:
                    outcomes["network_absent"] = False
                else:
                    outcomes["network_absent"] = (
                        inspect_network_optional(commands, network_id) is None
                        and inspect_network_optional(commands, network_name) is None
                    )
    except (RuntimeError, ValueError, json.JSONDecodeError):
        outcomes["network_absent"] = False

    outcomes["runner_absent"] = bool(
        outcomes["pre_bootstrap_runner_absent"] is True
        and outcomes["post_bootstrap_runner_absent"] is True
    )
    outcomes["test_database_absent"] = outcomes["database_container_absent"]
    zero_residue = all(value is True for value in outcomes.values())
    return {**outcomes, "zero_residue": zero_residue, "verified": zero_residue}


def run_owned_phase(
    commands: Commands, args: argparse.Namespace, staged: Path, network_id: str,
    invocation_id: str, test_database: str, phase: str, runner_name: str,
) -> tuple[subprocess.CompletedProcess[str], str]:
    label = f"tamandua.runtime-validation.invocation={invocation_id}"
    result = commands.run([
        "docker", "run", "--name", runner_name, "--network", network_id, "--label", label,
        "--mount", readonly_bind_mount(staged), "--tmpfs", "/work:rw,exec,nosuid,size=2g",
        "--env", "TAMANDUA_ALLOW_DEGRADED_CREDENTIALS=true",
        "--env", "TEST_DB_HOST=db", "--env", "TEST_DB_USER=tamandua",
        "--env", f"TEST_DB_NAME={test_database}", "--entrypoint", "sh", args.runner_image,
        "-c", owned_runner_script(list(OWNED_RUNTIME_TESTS), phase),
    ], timeout=args.timeout)
    validate_bounded_text(result.stdout, f"{phase}_stdout", MAX_RUNNER_OUTPUT_BYTES)
    validate_bounded_text(result.stderr, f"{phase}_stderr", MAX_RUNNER_OUTPUT_BYTES)
    finished = inspect_container_optional(commands, runner_name)
    if finished is None:
        raise RuntimeError(f"{phase}_runner_missing")
    runner_id = finished.get("Id")
    labels = finished.get("Config", {}).get("Labels", {})
    state = finished.get("State", {})
    if (not isinstance(runner_id, str) or not re.fullmatch(r"[a-f0-9]{64}", runner_id)
            or finished.get("Image") != args.runner_image
            or labels.get("tamandua.runtime-validation.invocation") != invocation_id):
        raise RuntimeError(f"{phase}_runner_ownership_mismatch")
    if (state.get("Status") != "exited" or state.get("Running") is not False
            or state.get("ExitCode") != result.returncode):
        raise RuntimeError(f"{phase}_runner_state_invalid")
    return result, runner_id


def owned_execute(receipt: dict[str, Any], args: argparse.Namespace, commands: Commands,
                  source_digest: str) -> bool:
    suffix = secrets.token_hex(16)
    invocation_id = suffix
    network_name = f"tamandua-pg-runtime-net-{suffix}"
    database_name = f"tamandua-pg-runtime-db-{suffix}"
    pre_runner_name = f"tamandua-elixir-runtime-pre-{suffix}"
    post_runner_name = f"tamandua-elixir-runtime-post-{suffix}"
    test_database = f"tamandua_loop105_{suffix}"
    receipt["execution"] = {
        "invocation_id": invocation_id, "runner_name": post_runner_name,
        "runner_container_id": None, "database_endpoint": None,
        "test_database": test_database, "exit_code": None,
        "database_container_id": None, "network_id": None,
        "phase_order": [],
        "runners": {
            "pre_bootstrap": {"name": pre_runner_name, "container_id": None, "exit_code": None, "verified": False},
            "post_bootstrap": {"name": post_runner_name, "container_id": None, "exit_code": None, "verified": False},
        },
        "stdin": {
            "limit_bytes": MAX_PSQL_STDIN_BYTES,
            "degraded_roles_sha256": hashlib.sha256(DEGRADED_ROLE_SQL).hexdigest(),
            "degraded_roles_bytes": len(DEGRADED_ROLE_SQL),
            "authority_bootstrap_sha256": None, "authority_bootstrap_bytes": None,
        },
        "role_audit": "not_run",
    }
    temporary: tempfile.TemporaryDirectory[str] | None = None
    pre_runner_id: str | None = None
    post_runner_id: str | None = None
    database_id: str | None = None
    network_id: str | None = None
    passed = False
    try:
        db_image = inspect(commands, "image", args.db_image)
        runner_image = inspect(commands, "image", args.runner_image)
        receipt["checks"].update({
            "database_image_id_pinned": db_image.get("Id") == args.db_image == args.expected_db_image_id,
            "runner_image_id_pinned": runner_image.get("Id") == args.runner_image == args.expected_runner_image_id,
        })
        if not all(receipt["checks"].values()):
            raise RuntimeError("owned_image_identity_mismatch")
        if (inspect_network_optional(commands, network_name) is not None
                or inspect_container_optional(commands, database_name) is not None
                or inspect_container_optional(commands, pre_runner_name) is not None
                or inspect_container_optional(commands, post_runner_name) is not None):
            raise RuntimeError("owned_resource_name_preexisting")
        receipt["checks"]["generated_resources_absent_preflight"] = True
        temporary, staged, staged_digest, staged_count = stage_source()
        expected_migrations = migration_inventory(staged)
        validate_bootstrap_cutoff(staged)
        receipt["source"].update(staged_sha256=staged_digest, staged_file_count=staged_count)
        source_after, count_after = canonical_source_digest()
        receipt["checks"]["staged_source_matches_recorded"] = bool(
            staged_digest == source_digest == source_after
            and staged_count == count_after == receipt["source"]["file_count"]
            and sha256_file(HARNESS) == receipt["source"]["harness_sha256"]
        )
        if not receipt["checks"]["staged_source_matches_recorded"]:
            raise RuntimeError("staged_source_digest_mismatch")
        authority_bytes = (staged / STAGED_AUTHORITY_BOOTSTRAP).read_bytes()
        validate_bounded_utf8(authority_bytes, "authority_bootstrap", MAX_PSQL_STDIN_BYTES)
        authority_sha256 = hashlib.sha256(authority_bytes).hexdigest()
        if authority_sha256 != hashlib.sha256(AUTHORITY_BOOTSTRAP.read_bytes()).hexdigest():
            raise RuntimeError("authority_bootstrap_hash_drift")
        receipt["execution"]["stdin"].update({
            "authority_bootstrap_sha256": authority_sha256,
            "authority_bootstrap_bytes": len(authority_bytes),
        })
        label = f"tamandua.runtime-validation.invocation={invocation_id}"
        created_network = commands.run([
            "docker", "network", "create", "--internal", "--label", label, network_name,
        ], timeout=30)
        if created_network.returncode != 0:
            raise RuntimeError("owned_network_create_failed")
        created_network_id = created_network.stdout.strip()
        if not re.fullmatch(r"[a-f0-9]{64}", created_network_id):
            raise RuntimeError("owned_network_id_invalid")
        network_id = created_network_id
        network = inspect_network_optional(commands, network_id)
        network_labels = (network or {}).get("Labels", {})
        if ((network or {}).get("Internal") is not True or (network or {}).get("Name") != network_name
                or network_labels.get("tamandua.runtime-validation.invocation") != invocation_id):
            raise RuntimeError("owned_network_not_internal")
        receipt["execution"]["network_id"] = network_id
        readiness_deadline = time.monotonic() + args.readiness_timeout
        created_db = commands.run([
            "docker", "run", "--detach", "--name", database_name, "--network", network_id,
            "--network-alias", "db", "--label", label,
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=2g",
            "--env", "POSTGRES_USER=tamandua", "--env", "POSTGRES_DB=postgres",
            "--env", "POSTGRES_HOST_AUTH_METHOD=trust", args.db_image,
        ], timeout=30)
        if created_db.returncode != 0:
            raise RuntimeError("owned_database_create_failed")
        created_database_id = created_db.stdout.strip()
        if not re.fullmatch(r"[a-f0-9]{64}", created_database_id):
            raise RuntimeError("owned_database_id_invalid")
        database_id = created_database_id
        database = inspect_container_optional(commands, database_id)
        labels = (database or {}).get("Config", {}).get("Labels", {})
        port_bindings = (database or {}).get("HostConfig", {}).get("PortBindings")
        if (database or {}).get("Image") != args.db_image or labels.get(
                "tamandua.runtime-validation.invocation") != invocation_id or port_bindings:
            raise RuntimeError("owned_database_contract_invalid")
        version = commands.run(["docker", "exec", database_id, "postgres", "--version"], timeout=10)
        psql_version = commands.run(["docker", "exec", database_id, "psql", "--version"], timeout=10)
        if (version.returncode != 0 or not version.stdout.startswith("postgres (PostgreSQL) 16.")
                or psql_version.returncode != 0 or not psql_version.stdout.startswith("psql (PostgreSQL) 16.")):
            raise RuntimeError("owned_database_not_postgresql_16")
        receipt["execution"]["database_container_id"] = database_id
        receipt["checks"].update({"network_exact": network_names(database or {}) == [network_name],
                                  "database_container_id_pinned": True,
                                  "database_endpoint_pinned": True})
        attempts = 0
        while True:
            attempts += 1
            remaining = readiness_deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("owned_database_readiness_timeout")
            ready = commands.run([
                "docker", "exec", database_id, "pg_isready", "-U", "tamandua", "-d", "postgres",
            ], timeout=max(0.1, min(10.0, remaining)))
            if ready.returncode == 0:
                break
            if time.monotonic() >= readiness_deadline:
                raise RuntimeError("owned_database_readiness_timeout")
            time.sleep(min(1.0, max(0.0, readiness_deadline - time.monotonic())))
        receipt["checks"]["database_healthy"] = True
        receipt["execution"]["database_endpoint"] = "db"
        receipt["execution"]["readiness_attempts"] = attempts
        receipt["observed"].update({
            "db_container_id": database_id, "db_health": "ready",
            "db_networks": [network_name], "db_network_endpoint": None,
            "postgres_version": version.stdout.strip(), "psql_version": psql_version.stdout.strip(),
        })
        create_database = commands.run([
            "docker", "exec", database_id, "createdb", "--no-password", "-U", "tamandua",
            "-O", "tamandua", test_database,
        ], timeout=30)
        if create_database.returncode != 0:
            raise RuntimeError("owned_test_database_create_failed")
        receipt["execution"]["phase_order"].append("database_created")
        if not owned_database_matches(commands, database_id, database_name, network_name,
                                      invocation_id, args.db_image):
            raise RuntimeError("database_identity_drift_before_pre_bootstrap")

        pre_result, pre_runner_id = run_owned_phase(
            commands, args, staged, network_id, invocation_id, test_database,
            "pre_bootstrap", pre_runner_name,
        )
        receipt["execution"]["runners"]["pre_bootstrap"].update(
            container_id=pre_runner_id, exit_code=pre_result.returncode, verified=True
        )
        if pre_result.returncode != 0:
            raise RuntimeError("pre_bootstrap_runner_failed")
        receipt["execution"]["phase_order"].append("pre_bootstrap_migrated")
        receipt["checks"]["pre_bootstrap_source_stable"] = source_pair_matches(
            staged, source_digest, receipt["source"]["file_count"],
            receipt["source"]["harness_sha256"],
        )
        if not receipt["checks"]["pre_bootstrap_source_stable"]:
            raise RuntimeError("source_drift_after_pre_bootstrap")

        psql_stdin(commands, database_id, "postgres", DEGRADED_ROLE_SQL, category="degraded_roles")
        receipt["execution"]["phase_order"].append("degraded_roles_created")
        psql_stdin(
            commands, database_id, test_database, authority_bytes,
            variables=("authority_login=tamandua_authority_login", "runtime_login=tamandua_runtime",
                       "migrator_login=tamandua_migrator"), category="authority_bootstrap",
        )
        receipt["execution"]["phase_order"].append("authority_bootstrapped")
        receipt["checks"]["bootstrap_source_stable"] = source_pair_matches(
            staged, source_digest, receipt["source"]["file_count"],
            receipt["source"]["harness_sha256"],
        )
        if not receipt["checks"]["bootstrap_source_stable"]:
            raise RuntimeError("source_drift_after_bootstrap")
        if not owned_database_matches(commands, database_id, database_name, network_name,
                                      invocation_id, args.db_image):
            raise RuntimeError("database_identity_drift_before_post_bootstrap")

        post_result, post_runner_id = run_owned_phase(
            commands, args, staged, network_id, invocation_id, test_database,
            "post_bootstrap", post_runner_name,
        )
        receipt["execution"]["runners"]["post_bootstrap"].update(
            container_id=post_runner_id, exit_code=post_result.returncode, verified=True
        )
        receipt["execution"].update(runner_container_id=post_runner_id, exit_code=post_result.returncode)
        receipt["checks"]["finished_runner_verified"] = True
        if post_result.returncode != 0:
            raise RuntimeError("post_bootstrap_runner_failed")
        receipt["execution"]["phase_order"].append("post_bootstrap_tests_completed")

        migration_stdout = psql_stdin(
            commands, database_id, test_database, MIGRATION_AUDIT_SQL, category="migration_audit"
        )
        migration_audit = parse_migration_rows(migration_stdout)
        role_stdout = psql_stdin(
            commands, database_id, "postgres", ROLE_AUDIT_SQL, category="role_audit"
        )
        role_rows = tuple(line.strip() for line in role_stdout.splitlines() if line.strip())
        if role_rows != EXPECTED_DEGRADED_ROLE_ROWS:
            raise RuntimeError("degraded_role_attributes_invalid")
        receipt["execution"]["role_audit"] = "closed_degraded"
        receipt["execution"]["phase_order"].extend(["migrations_audited", "roles_audited"])
        audit = {**migration_audit, **parse_test_audit(post_result.stdout, receipt["tests"])}
        receipt["audit"] = audit
        receipt["checks"]["post_bootstrap_source_stable"] = source_pair_matches(
            staged, source_digest, receipt["source"]["file_count"],
            receipt["source"]["harness_sha256"],
        )
        receipt["checks"]["staged_source_matches_recorded"] = bool(
            receipt["checks"]["staged_source_matches_recorded"]
            and receipt["checks"]["pre_bootstrap_source_stable"]
            and receipt["checks"]["bootstrap_source_stable"]
            and receipt["checks"]["post_bootstrap_source_stable"]
        )
        receipt["checks"]["migration_inventory_matches"] = all(
            audit[key] == value for key, value in expected_migrations.items()
        )
        receipt["checks"]["database_identity_stable"] = owned_database_matches(
            commands, database_id, database_name, network_name, invocation_id, args.db_image
        )
        passed = bool(post_result.returncode == 0 and audit["failures"] == 0
                      and audit["excluded"] == 0 and audit["skipped"] == 0
                      and receipt["checks"]["migration_inventory_matches"]
                      and receipt["checks"]["staged_source_matches_recorded"]
                      and receipt["checks"]["database_identity_stable"])
    finally:
        try:
            receipt["cleanup"] = owned_cleanup(
                commands, invocation_id,
                ((pre_runner_name, pre_runner_id, "pre_bootstrap_runner_absent"),
                 (post_runner_name, post_runner_id, "post_bootstrap_runner_absent")),
                database_name, network_name, database_id, network_id,
            )
        finally:
            if temporary is not None:
                temporary.cleanup()
    receipt["checks"].setdefault("database_identity_stable", False)
    receipt["checks"]["cleanup_verified"] = receipt["cleanup"]["verified"]
    return passed and receipt["checks"]["cleanup_verified"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-container")
    parser.add_argument("--network")
    parser.add_argument("--owned-database", action="store_true")
    parser.add_argument("--db-image")
    parser.add_argument("--runner-image", required=True)
    parser.add_argument("--expected-db-container-id")
    parser.add_argument("--expected-db-image-id")
    parser.add_argument("--expected-runner-image-id")
    parser.add_argument("--db-user", default="tamandua")
    parser.add_argument("--test", action="append", default=[])
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--readiness-timeout", type=int, default=MAX_OWNED_READINESS_SECONDS)
    parser.add_argument("--output", type=Path)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.timeout < 1:
        raise ValueError("timeout_must_be_positive")
    if not 1 <= args.readiness_timeout <= MAX_OWNED_READINESS_SECONDS:
        raise ValueError("readiness_timeout_out_of_range")
    if args.owned_database:
        if args.db_container or args.network:
            raise ValueError("owned_database_rejects_shared_resource_arguments")
        if args.db_user != "tamandua":
            raise ValueError("owned_database_user_is_fixed")
        if not args.test:
            raise ValueError("owned_database_requires_explicit_tests")
        if tuple(args.test) != OWNED_RUNTIME_TESTS:
            raise ValueError("owned_database_requires_exact_runtime_tests")
        for field in ("db_image", "runner_image", "expected_db_image_id", "expected_runner_image_id"):
            if not FULL_IMAGE_ID.fullmatch(str(getattr(args, field) or "")):
                raise ValueError(f"owned_database_requires_full_{field}")
        if args.db_image != args.expected_db_image_id or args.runner_image != args.expected_runner_image_id:
            raise ValueError("owned_database_image_identity_arguments_must_match")
        if args.expected_db_container_id:
            raise ValueError("owned_database_rejects_external_container_id")
    elif not args.db_container or not args.network:
        raise ValueError("shared_database_requires_container_and_network")


def run(args: argparse.Namespace, commands: Commands | None = None) -> tuple[int, dict[str, Any]]:
    validate_args(args)
    secret = os.environ.get(PASSWORD_ENV) if args.execute and not args.owned_database else None
    commands = commands or Commands(secret)
    digest, count = canonical_source_digest()
    tests = selected_tests(SERVER, args.test)
    receipt = base_receipt(args, digest, count, tests)
    try:
        ready = (owned_pin_and_check(receipt, args, commands) if args.owned_database
                 else pin_and_check(receipt, args, commands))
        if not ready:
            receipt["status"] = "blocked_preflight"
            return 2, receipt
        if not args.execute:
            receipt["status"] = "ready_inspect_only"
            receipt["limitations"].append("execution_not_requested")
            return 0, receipt
        if not args.owned_database and not secret:
            receipt["status"] = "blocked_missing_password_env"
            receipt["limitations"].append(f"operator_must_supply_{PASSWORD_ENV}")
            return 2, receipt
        passed = (owned_execute(receipt, args, commands, digest) if args.owned_database
                  else execute(receipt, args, commands, digest))
        receipt["status"] = "pass" if passed else "fail"
        receipt["claims"]["local_dirty_worktree_runtime_smoke"] = passed
        return (0 if passed else 1), receipt
    except (RuntimeError, ValueError, json.JSONDecodeError) as error:
        receipt["status"] = "blocked_error"
        receipt["limitations"].append(safe_text(str(error), secret))
        return 2, receipt


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code, receipt = run(args)
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
