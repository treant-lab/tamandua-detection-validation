from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "mobile_identity_server_runner_preflight.py"
)
SPEC = importlib.util.spec_from_file_location("mobile_identity_server_runner_preflight", SCRIPT)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


LOCK_TEXT = """%{
  "h2": {:hex, :h2, "0.6.1", "hash", [:rebar3], [], "hexpm", "outer"},
  "otel_http": {:hex, :otel_http, "0.2.0", "hash", [:rebar3], [], "hexpm", "outer"},
  "quic": {:hex, :quic, "1.4.5", "hash", [:rebar3], [], "hexpm", "outer"}
}
"""


def lock_hash(server: Path) -> str:
    return hashlib.sha256((server / "mix.lock").read_bytes()).hexdigest()


def fixture_repo(tmp_path: Path, *, build: bool = True, deps: bool = True) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    server = repo / "apps" / "tamandua_server"
    server.mkdir(parents=True)
    (server / "mix.lock").write_text(LOCK_TEXT, encoding="utf-8")
    current_hash = lock_hash(server)
    if deps:
        deps_root = server / "deps"
        deps_root.mkdir()
        (deps_root / preflight.LOCK_MARKER).write_text(current_hash, encoding="ascii")
        for name in preflight.DEFAULT_REQUIRED_DEPS:
            dependency = deps_root / name
            dependency.mkdir()
            (dependency / "mix.exs").write_text(f"# {name}\n", encoding="utf-8")
    if build:
        build_root = server / "_build"
        build_root.mkdir()
        (build_root / preflight.LOCK_MARKER).write_text(current_hash, encoding="ascii")
        for name in preflight.DEFAULT_REQUIRED_DEPS:
            compiled = build_root / "test" / "lib" / name
            (compiled / "ebin").mkdir(parents=True)
            (compiled / "ebin" / f"{name}.app").write_text("compiled\n", encoding="utf-8")
    return repo, server


def evaluate(repo: Path, **overrides):
    values = {
        "otp_version": "26.2.5",
        "elixir_version": "Elixir 1.15.8",
        "run_id": "pytest-run-01",
    }
    values.update(overrides)
    return preflight.evaluate(repo, **values)


def test_ready_fixture_emits_local_non_claim_plan(tmp_path: Path):
    repo, server = fixture_repo(tmp_path)
    result = evaluate(repo, expected_lock_sha256=lock_hash(server))

    assert result["ready"] is True
    assert result["reasons"] == []
    assert result["evidence_class"] == "local_preflight"
    assert result["external_claim_allowed"] is False
    assert result["target"]["mix_lock_path"] == str(server / "mix.lock")
    assert result["target"]["root_lock_fallback_allowed"] is False
    plan = result["execution_plan"]
    assert plan["dynamic_port_placeholders"] == {
        "postgres": "${TAMANDUA_PG_PORT}",
        "http": "${TAMANDUA_HTTP_PORT}",
    }
    assert "pytest_run_01" in plan["run_root"]
    assert plan["environment"]["PGHOST"] == "127.0.0.1"
    assert plan["database"] == "tamandua_mobile_identity_pytest_run_01"
    assert plan["command_encoding"] == "argv_no_shell"
    assert all(set(command) == {"program", "args"} for command in plan["commands"])
    commands = json.dumps(plan["commands"]).lower()
    assert "deps.get" not in commands
    assert "docker" not in commands


def test_missing_server_lock_never_falls_back_to_root_lock(tmp_path: Path):
    repo = tmp_path / "repo"
    server = repo / "apps" / "tamandua_server"
    server.mkdir(parents=True)
    (repo / "mix.lock").write_text(LOCK_TEXT, encoding="utf-8")

    result = evaluate(repo, server_root=repo)

    assert result["ready"] is False
    assert "server_mix_lock_missing" in result["reasons"]
    assert "server_root_not_canonical" in result["reasons"]
    assert result["target"]["mix_lock_sha256"] is None
    assert result["target"]["mix_lock_path"] == str(server / "mix.lock")


def test_missing_build_and_partial_dependency_restore_are_blocking(tmp_path: Path):
    repo, server = fixture_repo(tmp_path, build=False)
    (server / "deps" / "quic").rename(server / "deps" / "quic.partial")

    result = evaluate(repo)

    assert result["ready"] is False
    assert "build_path_missing" in result["reasons"]
    assert "hydrated_dependency_missing:quic" in result["reasons"]
    assert "compiled_dependency_missing:h2" in result["reasons"]


def test_stale_build_and_deps_markers_are_detected(tmp_path: Path):
    repo, server = fixture_repo(tmp_path)
    stale_hash = "0" * 64
    (server / "_build" / preflight.LOCK_MARKER).write_text(stale_hash, encoding="ascii")
    (server / "deps" / preflight.LOCK_MARKER).write_text(stale_hash, encoding="ascii")

    result = evaluate(repo)

    assert result["ready"] is False
    assert "build_stale_for_mix_lock" in result["reasons"]
    assert "deps_stale_for_mix_lock" in result["reasons"]


def test_wrong_expected_lock_hash_and_toolchain_are_blocking(tmp_path: Path):
    repo, _server = fixture_repo(tmp_path)

    result = evaluate(
        repo,
        expected_lock_sha256="f" * 64,
        otp_version="OTP 27.0",
        elixir_version="Elixir 1.16.0",
    )

    assert result["ready"] is False
    assert "server_mix_lock_hash_mismatch" in result["reasons"]
    assert "otp_version_mismatch" in result["reasons"]
    assert "elixir_version_mismatch" in result["reasons"]


def test_optional_sha_manifest_attests_every_required_dependency(tmp_path: Path):
    repo, server = fixture_repo(tmp_path)
    manifest_path = tmp_path / "hydrated-deps.json"
    dependencies = {
        name: {
            "path": f"deps/{name}",
            "sha256": preflight.sha256_tree(server / "deps" / name),
        }
        for name in preflight.DEFAULT_REQUIRED_DEPS
    }
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mix_lock_sha256": lock_hash(server),
                "dependencies": dependencies,
            }
        ),
        encoding="utf-8",
    )

    ready = evaluate(repo, deps_manifest=manifest_path)
    assert ready["ready"] is True
    assert ready["dependencies"]["attestation"]["verified"] is True

    dependencies["otel_http"]["sha256"] = "0" * 64
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mix_lock_sha256": "f" * 64,
                "dependencies": dependencies,
            }
        ),
        encoding="utf-8",
    )
    blocked = evaluate(repo, deps_manifest=manifest_path)
    assert blocked["ready"] is False
    assert "deps_manifest_lock_hash_mismatch" in blocked["reasons"]
    assert "deps_manifest_sha_mismatch:otel_http" in blocked["reasons"]


def test_locked_dependency_missing_and_partial_build_are_reported(tmp_path: Path):
    repo, server = fixture_repo(tmp_path)
    (server / "mix.lock").write_text(LOCK_TEXT.replace('  "h2":', '  "not_h2":'), encoding="utf-8")
    new_hash = lock_hash(server)
    (server / "deps" / preflight.LOCK_MARKER).write_text(new_hash, encoding="ascii")
    (server / "_build" / preflight.LOCK_MARKER).write_text(new_hash, encoding="ascii")
    compiled_quic = server / "_build" / "test" / "lib" / "quic"
    (compiled_quic / "ebin" / "quic.app").unlink()
    (compiled_quic / "ebin").rmdir()
    compiled_quic.rmdir()

    result = evaluate(repo)

    assert result["ready"] is False
    assert "required_dependency_not_locked:h2" in result["reasons"]
    assert "compiled_dependency_missing:quic" in result["reasons"]


def test_configured_dependencies_are_additive_and_empty_restore_is_partial(tmp_path: Path):
    repo, server = fixture_repo(tmp_path)
    (server / "deps" / "extra_dep").mkdir()
    (server / "_build" / "test" / "lib" / "extra_dep").mkdir(parents=True)

    invalid_dependency = "../../escape"
    result = evaluate(repo, required_deps=("extra_dep", invalid_dependency))

    assert result["dependencies"]["required"] == ["h2", "quic", "otel_http", "extra_dep"]
    assert result["dependencies"]["compiled_required"] == [
        "h2",
        "quic",
        "otel_http",
        "extra_dep",
    ]
    invalid_fingerprint = hashlib.sha256(invalid_dependency.encode("utf-8")).hexdigest()[:12]
    assert f"invalid_dependency_name:{invalid_fingerprint}" in result["reasons"]
    assert result["dependencies"]["invalid_configured_dependency_count"] == 1
    assert "required_dependency_not_locked:extra_dep" in result["reasons"]
    assert "hydrated_dependency_partial:extra_dep" in result["reasons"]
    assert "compiled_dependency_partial:extra_dep" in result["reasons"]
