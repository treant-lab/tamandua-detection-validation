#!/usr/bin/env python3
"""Read-only preflight for an isolated Tamandua mobile-identity server run.

The validator never invokes Mix, dependency hydration, containers, PostgreSQL,
or any command from the emitted plan. It inspects only the server-local lock and
hydrated cache paths supplied by the caller.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable


EVIDENCE_CLASS = "local_preflight"
EXPECTED_OTP_MAJOR = 26
EXPECTED_ELIXIR = (1, 15)
DEFAULT_REQUIRED_DEPS = ("h2", "quic", "otel_http")
LOCK_MARKER = ".mix_lock_sha256"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEPENDENCY_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
LOCK_DEP_RE = re.compile(r'^  "([^"]+)"\s*:', re.MULTILINE)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path: Path) -> str:
    """Hash file names and content hashes without following symlinks."""

    digest = hashlib.sha256()
    for entry in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = entry.relative_to(path).as_posix()
        if entry.is_symlink():
            digest.update(b"symlink\0")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(entry.readlink()).encode("utf-8"))
        elif entry.is_file():
            digest.update(b"file\0")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(sha256_file(entry).encode("ascii"))
            digest.update(b"\0")
    return digest.hexdigest()


def parse_version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    match = re.search(r"\d+(?:\.\d+)*", value)
    if not match:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


def canonical_run_id(value: str | None) -> str:
    candidate = value or uuid.uuid4().hex[:12]
    normalized = re.sub(r"[^a-zA-Z0-9_]", "_", candidate).strip("_").lower()
    if not normalized:
        raise ValueError("run_id must contain at least one alphanumeric character")
    return normalized[:48]


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "deps_manifest_invalid"
    if not isinstance(value, dict):
        return None, "deps_manifest_invalid"
    return value, None


def marker_status(root: Path, lock_hash: str, prefix: str, reasons: set[str]) -> None:
    marker = root / LOCK_MARKER
    if not marker.is_file():
        reasons.add(f"{prefix}_lock_marker_missing")
        return
    if marker.is_symlink():
        reasons.add(f"{prefix}_lock_marker_symlink_forbidden")
        return
    try:
        marker_hash = marker.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError):
        reasons.add(f"{prefix}_lock_marker_unreadable")
        return
    if marker_hash != lock_hash:
        reasons.add(f"{prefix}_stale_for_mix_lock")


def tree_has_symlink(path: Path) -> bool:
    return path.is_symlink() or any(entry.is_symlink() for entry in path.rglob("*"))


def hydrated_dependency_complete(path: Path) -> bool:
    if not path.is_dir() or tree_has_symlink(path):
        return False
    if (path / "mix.exs").is_file() or (path / "rebar.config").is_file():
        return True
    source = path / "src"
    return source.is_dir() and any(entry.is_file() for entry in source.rglob("*"))


def compiled_dependency_complete(build_path: Path, dependency: str) -> bool:
    dependency_path = build_path / "test" / "lib" / dependency
    return (
        dependency_path.is_dir()
        and not tree_has_symlink(dependency_path)
        and (dependency_path / "ebin" / f"{dependency}.app").is_file()
    )


def dependency_attestation(
    manifest_path: Path | None,
    lock_hash: str,
    required_deps: Iterable[str],
    deps_path: Path,
    reasons: set[str],
) -> dict[str, Any]:
    if manifest_path is None:
        return {"provided": False, "verified": False, "path": None}
    if not manifest_path.is_file():
        reasons.add("deps_manifest_missing")
        return {"provided": True, "verified": False, "path": str(manifest_path)}
    if manifest_path.is_symlink():
        reasons.add("deps_manifest_symlink_forbidden")
        return {"provided": True, "verified": False, "path": str(manifest_path)}

    manifest, error = load_json(manifest_path)
    if error or manifest is None:
        reasons.add(error or "deps_manifest_invalid")
        return {"provided": True, "verified": False, "path": str(manifest_path)}

    if deps_path.is_symlink():
        reasons.add("deps_manifest_source_symlink_forbidden")
        return {"provided": True, "verified": False, "path": str(manifest_path)}

    verified = True
    if manifest.get("schema_version") != 1:
        reasons.add("deps_manifest_schema_invalid")
        verified = False
    if str(manifest.get("mix_lock_sha256", "")).lower() != lock_hash:
        reasons.add("deps_manifest_lock_hash_mismatch")
        verified = False

    entries = manifest.get("dependencies")
    if not isinstance(entries, dict):
        reasons.add("deps_manifest_dependencies_invalid")
        entries = {}
        verified = False

    for dependency in required_deps:
        entry = entries.get(dependency)
        if not isinstance(entry, dict):
            reasons.add(f"deps_manifest_entry_missing:{dependency}")
            verified = False
            continue
        expected_relative = f"deps/{dependency}"
        if entry.get("path") != expected_relative:
            reasons.add(f"deps_manifest_path_invalid:{dependency}")
            verified = False
        expected_hash = str(entry.get("sha256", "")).lower()
        if not SHA256_RE.fullmatch(expected_hash):
            reasons.add(f"deps_manifest_sha_invalid:{dependency}")
            verified = False
            continue
        hydrated_path = deps_path / dependency
        if not hydrated_path.is_dir() or sha256_tree(hydrated_path) != expected_hash:
            reasons.add(f"deps_manifest_sha_mismatch:{dependency}")
            verified = False

    return {"provided": True, "verified": verified, "path": str(manifest_path)}


def isolated_plan(repo_root: Path, server_root: Path, run_id: str) -> dict[str, Any]:
    run_root = repo_root / ".tmp" / "mobile_identity_server_runner" / run_id
    pg_port = "${TAMANDUA_PG_PORT}"
    http_port = "${TAMANDUA_HTTP_PORT}"
    database = f"tamandua_mobile_identity_{run_id}"
    env = {
        "MIX_ENV": "test",
        "MIX_BUILD_PATH": str(run_root / "_build"),
        "MIX_DEPS_PATH": str(run_root / "deps"),
        "MIX_HOME": str(run_root / "mix_home"),
        "HEX_HOME": str(run_root / "hex_home"),
        "PGDATA": str(run_root / "pgdata"),
        "PGHOST": "127.0.0.1",
        "PGPORT": pg_port,
        "PORT": http_port,
        "DATABASE_URL": f"ecto://postgres:${{TAMANDUA_PG_PASSWORD}}@127.0.0.1:{pg_port}/{database}",
    }
    return {
        "run_id": run_id,
        "working_directory": str(server_root),
        "run_root": str(run_root),
        "database": database,
        "dynamic_port_placeholders": {
            "postgres": pg_port,
            "http": http_port,
        },
        "environment": env,
        "hydration": {
            "source_deps": str(server_root / "deps"),
            "target_deps": str(run_root / "deps"),
            "require_sha_attestation_before_materialization": True,
        },
        "commands": [
            {"program": "initdb", "args": ["-D", env["PGDATA"]]},
            {
                "program": "pg_ctl",
                "args": [
                    "-D",
                    env["PGDATA"],
                    "-o",
                    f"-h 127.0.0.1 -p {pg_port}",
                    "start",
                ],
            },
            {
                "program": "createdb",
                "args": ["-h", "127.0.0.1", "-p", pg_port, database],
            },
            {"program": "mix", "args": ["compile", "--warnings-as-errors"]},
            {"program": "mix", "args": ["ecto.migrate"]},
            {
                "program": "mix",
                "args": [
                    "test",
                    "test/tamandua_server/mobile/mobile_device_identity_recovery_test.exs",
                    (
                        "test/tamandua_server_web/controllers/api/v1/"
                        "mobile_device_identity_recovery_controller_test.exs"
                    ),
                ],
            },
            {"program": "pg_ctl", "args": ["-D", env["PGDATA"], "stop"]},
        ],
        "command_encoding": "argv_no_shell",
        "prohibited_execution_by_preflight": ["dependency hydration", "containers", "mix", "postgres"],
    }


def evaluate(
    repo_root: Path,
    *,
    server_root: Path | None = None,
    required_deps: Iterable[str] = DEFAULT_REQUIRED_DEPS,
    otp_version: str | None,
    elixir_version: str | None,
    expected_lock_sha256: str | None = None,
    deps_manifest: Path | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    canonical_server_root = (repo_root / "apps" / "tamandua_server").resolve()
    requested_server_root = server_root.resolve() if server_root else canonical_server_root
    reasons: set[str] = set()
    if requested_server_root != canonical_server_root:
        reasons.add("server_root_not_canonical")
    server_root = canonical_server_root
    configured_candidates = tuple(dict.fromkeys((*DEFAULT_REQUIRED_DEPS, *required_deps)))
    configured_required = tuple(
        dependency for dependency in configured_candidates if DEPENDENCY_NAME_RE.fullmatch(dependency)
    )
    invalid_dependencies = tuple(
        dependency for dependency in configured_candidates if not DEPENDENCY_NAME_RE.fullmatch(dependency)
    )
    for dependency in invalid_dependencies:
        fingerprint = hashlib.sha256(dependency.encode("utf-8")).hexdigest()[:12]
        reasons.add(f"invalid_dependency_name:{fingerprint}")
    lock_path = server_root / "mix.lock"
    lock_hash: str | None = None
    lock_dependencies: set[str] = set()
    lock_dependency_order: tuple[str, ...] = ()

    if not lock_path.is_file():
        reasons.add("server_mix_lock_missing")
    elif lock_path.is_symlink():
        reasons.add("server_mix_lock_symlink_forbidden")
    else:
        lock_hash = sha256_file(lock_path)
        try:
            parsed_dependencies = LOCK_DEP_RE.findall(lock_path.read_text(encoding="utf-8"))
            lock_dependency_order = tuple(
                dict.fromkeys(
                    dependency
                    for dependency in parsed_dependencies
                    if DEPENDENCY_NAME_RE.fullmatch(dependency)
                )
            )
            for dependency in parsed_dependencies:
                if not DEPENDENCY_NAME_RE.fullmatch(dependency):
                    fingerprint = hashlib.sha256(dependency.encode("utf-8")).hexdigest()[:12]
                    reasons.add(f"invalid_locked_dependency_name:{fingerprint}")
            lock_dependencies = set(lock_dependency_order)
        except (OSError, UnicodeError):
            reasons.add("server_mix_lock_unreadable")
        if expected_lock_sha256:
            expected = expected_lock_sha256.strip().lower()
            if not SHA256_RE.fullmatch(expected) or expected != lock_hash:
                reasons.add("server_mix_lock_hash_mismatch")

    for dependency in configured_required:
        if dependency not in lock_dependencies:
            reasons.add(f"required_dependency_not_locked:{dependency}")

    hydrated_required = tuple(dict.fromkeys((*configured_required, *lock_dependency_order)))

    otp = parse_version(otp_version)
    elixir = parse_version(elixir_version)
    if otp is None:
        reasons.add("otp_version_missing")
    elif otp[0] != EXPECTED_OTP_MAJOR:
        reasons.add("otp_version_mismatch")
    if elixir is None:
        reasons.add("elixir_version_missing")
    elif len(elixir) < 2 or elixir[:2] != EXPECTED_ELIXIR:
        reasons.add("elixir_version_mismatch")

    deps_path = server_root / "deps"
    build_path = server_root / "_build"
    deps_usable = deps_path.is_dir() and not deps_path.is_symlink()
    build_usable = build_path.is_dir() and not build_path.is_symlink()
    if not deps_path.is_dir():
        reasons.add("deps_path_missing")
    elif deps_path.is_symlink():
        reasons.add("deps_path_symlink_forbidden")
    if not build_path.is_dir():
        reasons.add("build_path_missing")
    elif build_path.is_symlink():
        reasons.add("build_path_symlink_forbidden")

    if lock_hash:
        if deps_usable:
            marker_status(deps_path, lock_hash, "deps", reasons)
        if build_usable:
            marker_status(build_path, lock_hash, "build", reasons)

    for dependency in hydrated_required:
        hydrated_dependency = deps_path / dependency
        if not deps_usable or not hydrated_dependency.is_dir():
            reasons.add(f"hydrated_dependency_missing:{dependency}")
        elif not hydrated_dependency_complete(hydrated_dependency):
            reasons.add(f"hydrated_dependency_partial:{dependency}")

    for dependency in configured_required:
        compiled_dependency = build_path / "test" / "lib" / dependency
        if not build_usable or not compiled_dependency.is_dir():
            reasons.add(f"compiled_dependency_missing:{dependency}")
        elif not compiled_dependency_complete(build_path, dependency):
            reasons.add(f"compiled_dependency_partial:{dependency}")

    attestation = dependency_attestation(
        deps_manifest.resolve() if deps_manifest else None,
        lock_hash or "",
        hydrated_required,
        deps_path,
        reasons,
    )
    normalized_run_id = canonical_run_id(run_id)
    return {
        "schema_version": 1,
        "evidence_class": EVIDENCE_CLASS,
        "external_claim_allowed": False,
        "ready": not reasons,
        "reasons": sorted(reasons),
        "target": {
            "server_root": str(server_root),
            "requested_server_root": str(requested_server_root),
            "mix_lock_path": str(lock_path),
            "mix_lock_sha256": lock_hash,
            "root_lock_fallback_allowed": False,
        },
        "toolchain": {
            "expected": {"otp_major": EXPECTED_OTP_MAJOR, "elixir_major_minor": "1.15"},
            "declared": {"otp": otp_version, "elixir": elixir_version},
            "version_source": "caller_declared_not_executed",
        },
        "dependencies": {
            "required": list(hydrated_required),
            "compiled_required": list(configured_required),
            "invalid_configured_dependency_count": len(invalid_dependencies),
            "locked_count": len(lock_dependencies),
            "deps_path": str(deps_path),
            "build_path": str(build_path),
            "attestation": attestation,
        },
        "execution_plan": isolated_plan(repo_root, server_root, normalized_run_id),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    default_repo = Path(__file__).resolve().parents[3]
    parser.add_argument("--repo-root", type=Path, default=default_repo)
    parser.add_argument("--server-root", type=Path)
    parser.add_argument("--required-dep", action="append", dest="required_deps")
    parser.add_argument("--otp-version", required=True)
    parser.add_argument("--elixir-version", required=True)
    parser.add_argument("--expected-lock-sha256")
    parser.add_argument("--deps-manifest", type=Path)
    parser.add_argument("--run-id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = evaluate(
        args.repo_root,
        server_root=args.server_root,
        required_deps=args.required_deps or DEFAULT_REQUIRED_DEPS,
        otp_version=args.otp_version,
        elixir_version=args.elixir_version,
        expected_lock_sha256=args.expected_lock_sha256,
        deps_manifest=args.deps_manifest,
        run_id=args.run_id,
    )
    json.dump(result, sys.stdout, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
