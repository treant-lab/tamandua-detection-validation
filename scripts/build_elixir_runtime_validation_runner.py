#!/usr/bin/env python3
"""Build a provenance-bound Elixir-only validation runner.

Inspect mode is deliberately offline and does not contact Docker. Execute mode is
reserved for the single governed build attempt described by the Loop116 handoff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "apps" / "tamandua_server"
DOCKERFILE = SERVER / "Dockerfile.elixir-runtime-validation-runner"
HELPER = Path(__file__).resolve()
SCHEMA = ROOT / "schemas" / "elixir_runtime_validation_runner_receipt_v1.schema.json"
PROFILE = "elixir-only-current-lock-v1"
PLATFORM = "linux/amd64"
ELIXIR_VERSION = "1.18.4"
ERLANG_VERSION = "28.5.0.2"
OTP_RELEASE = "28"
HEX_VERSION = "2.5.1"
REBAR_VERSION = "3.26.0"
TOOLCHAIN_PROFILE = "f314-hydrator-b825-final-v1"
FULL_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
INVOCATION = re.compile(r"^[a-z0-9][a-z0-9_.-]{7,63}$")
REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9._/-]{1,126}$")
VERSION = re.compile(r"^[0-9][0-9A-Za-z.+_-]{0,31}$")
HYDRATOR_IMAGE_ID = "sha256:f31484716c92e442efbe163ff5df3456ac6dd3e0c96a2c3d1cc4fd295661e5a0"
FINAL_BASE_IMAGE_ID = "sha256:b825e4efea9c3296ffec1e065b5f56eb385654dec0c81ba70d72a481b81e4de9"
LOCAL_ALIAS_REPOSITORY = "tamandua/elixir-runtime-validation-base"
LABEL_PREFIX = "io.tamandua.validation."
MAX_BUILD_BYTES = 65536
MAX_DIAGNOSTIC_LINES = 16
DEPS_GET_FAILED_MARKER = "TAMANDUA_HYDRATOR_DEPS_GET_FAILED_V1"
DEPS_GET_OK_MARKER = "TAMANDUA_HYDRATOR_DEPS_GET_OK_V1"
LOCK_CHANGED_MARKER = "TAMANDUA_HYDRATOR_LOCK_CHANGED_V1"
HYDRATOR_RUN_PREFIX = re.compile(
    r"^#([1-9][0-9]{0,5}) \[hydrator [1-9][0-9]{0,3}/[1-9][0-9]{0,3}\] "
    r"RUN --network=default\b",
)
HYDRATOR_RUN = re.compile(
    r"^#([1-9][0-9]{0,5}) \[hydrator [1-9][0-9]{0,3}/[1-9][0-9]{0,3}\] "
    r"RUN --network=default set -eu;[ \t]+"
    r"lock_before=\"\$\(sha256sum mix\.lock \| cut -d' ' -f1\)\";[ \t]+"
    r"if ! mix deps\.get --only test --check-locked; then[ \t]+"
    r"printf '%s\\n' '" + re.escape(DEPS_GET_FAILED_MARKER) + r"' >&2;[ \t]+"
    r"exit 41;[ \t]+fi;[ \t]+"
    r"printf '%s\\n' '" + re.escape(DEPS_GET_OK_MARKER) + r"';[ \t]+"
    r"if test \"\$\(sha256sum mix\.lock \| cut -d' ' -f1\)\" != \"\$\{lock_before\}\"; then[ \t]+"
    r"printf '%s\\n' '" + re.escape(LOCK_CHANGED_MARKER) + r"' >&2;[ \t]+"
    r"exit 42;[ \t]+fi$",
)
CLAIM_BOUNDARY = (
    "Local artifact-build contract for the current dependency inputs, dirty-worktree status, toolchain and full "
    "image ID only. It is not byte reproducibility, runtime/RLS execution, Inbox authorization, release, "
    "deployment, production, product readiness, vendor parity or external-claim evidence."
)
FALSE_CLAIMS = {
    "artifact_verified": False,
    "byte_reproducible": False,
    "runtime_validation_executed": False,
    "rls_validated": False,
    "inbox_unlocked": False,
    "product_ready": False,
    "production_validated": False,
    "external_claim_allowed": False,
    "vendor_parity": False,
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def exception_marker(error: Exception) -> str:
    if isinstance(error, OSError):
        return "oserror"
    message = str(error)
    return message if re.fullmatch(r"[a-z0-9_:.-]{1,160}", message) else type(error).__name__.lower()


def _git(*args: str, root: Path = ROOT) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("git_state_unavailable") from error
    if result.returncode != 0:
        raise RuntimeError("git_state_unavailable")
    return result.stdout


def git_state(root: Path = ROOT) -> dict[str, Any]:
    head = _git("rev-parse", "HEAD", root=root).decode("ascii").strip()
    status_bytes = _git("status", "--porcelain=v1", "-z", "--untracked-files=all", root=root)
    if not re.fullmatch(r"[a-f0-9]{40}", head):
        raise RuntimeError("git_head_invalid")
    return {"head": head, "dirty": bool(status_bytes), "status_sha256": sha256_bytes(status_bytes)}


def canonical_tree(path: Path) -> tuple[str, int, list[str]]:
    if not path.is_dir() or path.is_symlink():
        raise RuntimeError(f"unsafe_tree:{path.name}")
    digest = hashlib.sha256()
    manifest: list[str] = []
    count = 0
    for candidate in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = candidate.relative_to(path).as_posix()
        mode = candidate.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode) or candidate.is_symlink():
            raise RuntimeError(f"special_or_symlink_input_forbidden:{relative}")
        if any(character in relative for character in ("\n", "\r", "\\")):
            raise RuntimeError("manifest_path_unsafe")
        payload = candidate.read_bytes()
        relative_bytes = relative.encode("utf-8")
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        manifest.append(f"{sha256_bytes(payload)}  {relative}")
        count += 1
    if not count:
        raise RuntimeError("empty_config_tree")
    return digest.hexdigest(), count, manifest


def input_provenance() -> dict[str, Any]:
    paths = {
        "mix_exs_sha256": SERVER / "mix.exs",
        "mix_lock_sha256": SERVER / "mix.lock",
        "dockerfile_sha256": DOCKERFILE,
        "helper_sha256": HELPER,
        "schema_sha256": SCHEMA,
    }
    for path in paths.values():
        if not path.is_file() or path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise RuntimeError(f"unsafe_or_missing_input:{path.name}")
    dependency_contract = (SERVER / "mix.exs").read_text(encoding="utf-8") + "\n" + (
        SERVER / "mix.lock"
    ).read_text(encoding="utf-8")
    if re.search(r"\b(?:git|github|path)\s*:", dependency_contract) or re.search(
        r"\{:(?:git|path)\b", dependency_contract
    ):
        raise RuntimeError("non_hex_dependency_source_forbidden")
    config_sha, config_count, manifest = canonical_tree(SERVER / "config")
    values: dict[str, Any] = {name: sha256_file(path) for name, path in paths.items()}
    values.update({"config_sha256": config_sha, "config_file_count": config_count})
    bundle = hashlib.sha256()
    for name in sorted(key for key in values if key != "config_file_count"):
        bundle.update(name.encode("ascii") + b"\0" + str(values[name]).encode("ascii") + b"\n")
    values["bundle_sha256"] = bundle.hexdigest()
    values["config_manifest"] = manifest
    return values


def stage_context(provenance: dict[str, Any], source: dict[str, Any]) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    temporary = tempfile.TemporaryDirectory(prefix="tamandua-elixir-runner-")
    context = Path(temporary.name) / "context"
    context.mkdir()
    try:
        shutil.copy2(DOCKERFILE, context / DOCKERFILE.name)
        shutil.copy2(SERVER / "mix.exs", context / "mix.exs")
        shutil.copy2(SERVER / "mix.lock", context / "mix.lock")
        # Keep links visible so the staged verifier rejects them instead of following them.
        shutil.copytree(SERVER / "config", context / "config", symlinks=True)
        (context / ".tamandua-config-files.sha256").write_text(
            "\n".join(provenance["config_manifest"]) + "\n", encoding="utf-8", newline="\n"
        )
        public_provenance = {key: value for key, value in provenance.items() if key != "config_manifest"}
        public_provenance["source"] = source
        (context / ".tamandua-input-provenance.json").write_text(
            json.dumps(public_provenance, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8", newline="\n",
        )
    except Exception:
        temporary.cleanup()
        raise
    return temporary, context


def staged_context_matches(context: Path, provenance: dict[str, Any], source: dict[str, Any]) -> bool:
    allowed = {
        DOCKERFILE.name, "mix.exs", "mix.lock", "config",
        ".tamandua-config-files.sha256", ".tamandua-input-provenance.json",
    }
    if {entry.name for entry in context.iterdir()} != allowed:
        return False
    for name in (DOCKERFILE.name, "mix.exs", "mix.lock", ".tamandua-config-files.sha256",
                 ".tamandua-input-provenance.json"):
        candidate = context / name
        if not candidate.is_file() or candidate.is_symlink() or not stat.S_ISREG(candidate.lstat().st_mode):
            return False
    config_sha, config_count, manifest = canonical_tree(context / "config")
    expected_public = {key: value for key, value in provenance.items() if key != "config_manifest"}
    expected_public["source"] = source
    try:
        observed_public = json.loads((context / ".tamandua-input-provenance.json").read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    return bool(
        sha256_file(context / DOCKERFILE.name) == provenance["dockerfile_sha256"]
        and sha256_file(context / "mix.exs") == provenance["mix_exs_sha256"]
        and sha256_file(context / "mix.lock") == provenance["mix_lock_sha256"]
        and config_sha == provenance["config_sha256"]
        and config_count == provenance["config_file_count"]
        and (context / ".tamandua-config-files.sha256").read_text(encoding="utf-8")
            == "\n".join(manifest) + "\n"
        and observed_public == expected_public
    )


class Commands:
    def run(self, command: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
            return subprocess.CompletedProcess(command, 124, stdout, stderr)
        except OSError:
            return subprocess.CompletedProcess(command, 125, "", "adapter_error")

    def run_build(self, command: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["DOCKER_BUILDKIT"] = "1"
        try:
            return subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False, timeout=timeout, env=environment,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            return subprocess.CompletedProcess(command, 124, stdout, None)
        except OSError:
            return subprocess.CompletedProcess(command, 125, "adapter_error\n", None)


def inspect_image(commands: Commands, reference: str) -> dict[str, Any] | None:
    result = commands.run(["docker", "image", "inspect", reference], timeout=60)
    if result.returncode != 0:
        error = (result.stderr or "").strip().lower()
        canonical_missing = {
            "not found",
            f"error response from daemon: no such image: {reference}".lower(),
            f"error: no such object: {reference}".lower(),
        }
        if error in canonical_missing:
            return None
        raise RuntimeError("docker_inspect_failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("docker_inspect_invalid_json") from error
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise RuntimeError("docker_inspect_invalid_shape")
    return payload[0]


def rootfs_layers(image: dict[str, Any]) -> list[str]:
    layers = image.get("RootFS", {}).get("Layers")
    if not isinstance(layers, list) or not layers or any(not FULL_IMAGE_ID.fullmatch(item) for item in layers):
        raise RuntimeError("image_rootfs_invalid")
    return layers


def rootfs_digest(image: dict[str, Any]) -> str:
    return sha256_bytes(("\n".join(rootfs_layers(image)) + "\n").encode("ascii"))


def expected_labels(args: argparse.Namespace, provenance: dict[str, Any], source: dict[str, Any],
                    hydrator_rootfs: str, final_rootfs: str) -> dict[str, str]:
    return {
        "org.opencontainers.image.revision": source["head"],
        LABEL_PREFIX + "profile": PROFILE,
        LABEL_PREFIX + "invocation": args.invocation_id,
        LABEL_PREFIX + "source.status.sha256": source["status_sha256"],
        LABEL_PREFIX + "input.mix-exs.sha256": provenance["mix_exs_sha256"],
        LABEL_PREFIX + "input.mix-lock.sha256": provenance["mix_lock_sha256"],
        LABEL_PREFIX + "input.config.sha256": provenance["config_sha256"],
        LABEL_PREFIX + "input.dockerfile.sha256": provenance["dockerfile_sha256"],
        LABEL_PREFIX + "input.helper.sha256": provenance["helper_sha256"],
        LABEL_PREFIX + "input.schema.sha256": provenance["schema_sha256"],
        LABEL_PREFIX + "input.bundle.sha256": provenance["bundle_sha256"],
        LABEL_PREFIX + "hydrator.id": args.hydrator_image,
        LABEL_PREFIX + "hydrator.rootfs.sha256": hydrator_rootfs,
        LABEL_PREFIX + "final-base.id": args.final_base_image,
        LABEL_PREFIX + "final-base.rootfs.sha256": final_rootfs,
        LABEL_PREFIX + "toolchain.profile": TOOLCHAIN_PROFILE,
        LABEL_PREFIX + "tool.elixir": ELIXIR_VERSION,
        LABEL_PREFIX + "tool.erlang": ERLANG_VERSION,
        LABEL_PREFIX + "tool.otp": OTP_RELEASE,
        LABEL_PREFIX + "tool.hex": HEX_VERSION,
        LABEL_PREFIX + "tool.rebar": args.rebar_version,
    }


def base_aliases(args: argparse.Namespace, source: dict[str, Any]) -> dict[str, str]:
    suffix = f"{source['head'][:12]}-{args.invocation_id}"
    return {
        "hydrator": f"{LOCAL_ALIAS_REPOSITORY}:hydrator-{suffix}",
        "final_base": f"{LOCAL_ALIAS_REPOSITORY}:final-{suffix}",
    }


def build_args(args: argparse.Namespace, context: Path, tag: str, iidfile: Path,
               provenance: dict[str, Any], source: dict[str, Any], hydrator_rootfs: str,
               final_rootfs: str, aliases: dict[str, str]) -> list[str]:
    arguments = {
        "HYDRATOR_LOCAL_ALIAS": aliases["hydrator"],
        "FINAL_BASE_LOCAL_ALIAS": aliases["final_base"],
        "SOURCE_SHA": source["head"],
        "SOURCE_STATUS_SHA256": source["status_sha256"],
        "MIX_EXS_SHA256": provenance["mix_exs_sha256"],
        "MIX_LOCK_SHA256": provenance["mix_lock_sha256"],
        "CONFIG_SHA256": provenance["config_sha256"],
        "DOCKERFILE_SHA256": provenance["dockerfile_sha256"],
        "HELPER_SHA256": provenance["helper_sha256"],
        "SCHEMA_SHA256": provenance["schema_sha256"],
        "HYDRATOR_IMAGE_ID": args.hydrator_image,
        "HYDRATOR_ROOTFS_SHA256": hydrator_rootfs,
        "FINAL_BASE_IMAGE_ID": args.final_base_image,
        "FINAL_BASE_ROOTFS_SHA256": final_rootfs,
        "ELIXIR_VERSION": ELIXIR_VERSION,
        "ERLANG_VERSION": ERLANG_VERSION,
        "OTP_RELEASE": OTP_RELEASE,
        "HEX_VERSION": HEX_VERSION,
        "REBAR_VERSION": args.rebar_version,
        "TOOLCHAIN_PROFILE": TOOLCHAIN_PROFILE,
        "INPUT_BUNDLE_SHA256": provenance["bundle_sha256"],
        "INVOCATION_ID": args.invocation_id,
    }
    command = [
        "docker", "build", "--platform", PLATFORM, "--pull=false", "--progress=plain",
        "--file", str(context / DOCKERFILE.name), "--tag", tag, "--iidfile", str(iidfile),
    ]
    for name, value in arguments.items():
        command.extend(["--build-arg", f"{name}={value}"])
    command.append(str(context))
    return command


def diagnostic(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    def stream_bytes(value: str | bytes | None) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode("utf-8", errors="replace")
        return b""

    adapter_error = bool(
        result.returncode == 125
        and result.stdout in ("adapter_error\n", b"adapter_error\n")
        and result.stderr is None
    )
    combined = stream_bytes(result.stdout) + b"\n" + stream_bytes(result.stderr)
    retained = combined[-MAX_BUILD_BYTES:]
    lines: list[str] = []
    step = re.compile(r"^#([0-9]{1,6})\s+\[(?:[A-Za-z0-9_.-]+\s+)?([0-9]{1,4})/([0-9]{1,4})\]\s+([A-Z]+)\b")
    error = re.compile(r"^#([0-9]{1,6})\s+ERROR\b")
    warning = re.compile(r"^#[0-9]{1,6}\s+WARN:\s+([A-Za-z][A-Za-z0-9_-]{0,63}):")
    marker = re.compile(
        r"^#([1-9][0-9]{0,5}) (?:0|[1-9][0-9]*)(?:\.[0-9]+)? ("
        + "|".join(re.escape(value) for value in (
            DEPS_GET_FAILED_MARKER, DEPS_GET_OK_MARKER, LOCK_CHANGED_MARKER,
        ))
        + r")$"
    )
    hydrator_exit = re.compile(
        r'^#([1-9][0-9]{0,5}) ERROR: process ".+" '
        r"did not complete successfully: exit code: (41|42)$",
    )
    decoded = retained.decode("utf-8", errors="replace")
    base_resolution = bool(
        "docker.io/library/sha256" in decoded.lower()
        or ("load metadata for" in decoded.lower() and "pull access denied" in decoded.lower())
    )
    observed_markers: list[tuple[int, str]] = []
    observed_hydrator_exits: list[tuple[int, int]] = []
    observed_hydrator_run_prefixes: list[int] = []
    observed_hydrator_runs: list[int] = []
    observed_hydrator_events: list[tuple[int, int, str]] = []
    for line_index, raw in enumerate(decoded.splitlines()):
        if match := step.match(raw):
            lines.append(f"step:{match.group(1)}:{match.group(2)}/{match.group(3)}:{match.group(4)}")
        elif match := error.match(raw):
            lines.append(f"step:{match.group(1)}:error")
        elif match := warning.match(raw):
            lines.append(f"warning:{match.group(1)}")
        elif "failed to solve" in raw.lower():
            lines.append("buildkit_failed")
        observed = marker.fullmatch(raw)
        if observed:
            observed_markers.append((int(observed.group(1)), observed.group(2)))
            observed_hydrator_events.append((line_index, int(observed.group(1)), observed.group(2)))
        if observed_prefix := HYDRATOR_RUN_PREFIX.match(raw):
            observed_hydrator_run_prefixes.append(int(observed_prefix.group(1)))
        if observed_run := HYDRATOR_RUN.fullmatch(raw):
            observed_hydrator_runs.append(int(observed_run.group(1)))
            observed_hydrator_events.append((line_index, int(observed_run.group(1)), "RUN"))
        if terminal := hydrator_exit.fullmatch(raw):
            observed_hydrator_exits.append((int(terminal.group(1)), int(terminal.group(2))))
            observed_hydrator_events.append((
                line_index, int(terminal.group(1)), f"terminal:{terminal.group(2)}",
            ))
    if base_resolution:
        lines.append("base_reference_resolution")
    if result.returncode == 124:
        lines.append("timeout")
        kind = "timeout"
    elif adapter_error:
        lines.append("adapter_error")
        kind = "adapter"
    else:
        lines.append(f"process_exit:{max(0, min(255, result.returncode))}")
        kind = "buildkit" if any(line == "buildkit_failed" for line in lines) else "process_exit"
    if (
        result.returncode in (1, 41)
        and len(observed_hydrator_run_prefixes) == 1
        and len(observed_hydrator_runs) == 1
        and len(observed_markers) == 1
        and len(observed_hydrator_exits) == 1
        and observed_markers[0][1] == DEPS_GET_FAILED_MARKER
        and observed_hydrator_runs[0] == observed_markers[0][0]
        and observed_hydrator_exits[0] == (observed_markers[0][0], 41)
        and [event for _, _, event in observed_hydrator_events] == [
            "RUN", DEPS_GET_FAILED_MARKER, "terminal:41",
        ]
        and len({step_id for _, step_id, _ in observed_hydrator_events}) == 1
    ):
        category = "dependency_fetch_failed"
        lines.append(category)
    elif (
        result.returncode in (1, 42)
        and len(observed_hydrator_run_prefixes) == 1
        and len(observed_hydrator_runs) == 1
        and len(observed_markers) == 2
        and len(observed_hydrator_exits) == 1
        and [value for _, value in observed_markers] == [DEPS_GET_OK_MARKER, LOCK_CHANGED_MARKER]
        and observed_hydrator_runs[0] == observed_markers[0][0]
        and observed_markers[0][0] == observed_markers[1][0]
        and observed_hydrator_exits[0] == (observed_markers[0][0], 42)
        and [event for _, _, event in observed_hydrator_events] == [
            "RUN", DEPS_GET_OK_MARKER, LOCK_CHANGED_MARKER, "terminal:42",
        ]
        and len({step_id for _, step_id, _ in observed_hydrator_events}) == 1
    ):
        category = "dependency_lock_guard_failed"
        lines.extend(("dependency_fetch_succeeded", category))
    elif base_resolution:
        category = "base_reference_resolution"
    else:
        category = "other"
    canonical = list(dict.fromkeys(lines))[-MAX_DIAGNOSTIC_LINES:] or ["unknown_failure"]
    encoded = ("\n".join(canonical) + "\n").encode("ascii")
    return {
        "kind": kind, "exit_code": max(0, min(255, result.returncode)), "canonical_tail": canonical,
        "category": category,
        "canonical_tail_sha256": sha256_bytes(encoded), "observed_bytes": len(combined),
        "discarded_bytes": max(0, len(combined) - len(retained)),
    }


def checks() -> dict[str, bool]:
    return {key: False for key in (
        "inputs_staged", "inputs_unchanged", "dependency_sources_hex_only", "bases_verified",
        "base_rootfs_lineage", "aliases_absent", "aliases_created", "alias_ids_stable",
        "tag_absent", "build_succeeded", "iid_verified", "labels_verified",
        "final_base_lineage", "hydrator_layers_excluded", "tag_removed",
        "aliases_removed", "base_images_preserved",
        "network_none_postverify", "read_only_postverify", "lock_unchanged", "deps_check",
        "psql_absent", "nif_closure",
    )}


def cleanup_state() -> dict[str, Any]:
    resource = {"attempted": False, "outcome": "not_needed", "observed_id": None}
    return {
        "required": False, "complete": True, "tag": dict(resource), "image": dict(resource),
        "hydrator_alias": dict(resource), "final_base_alias": dict(resource), "residuals": [],
    }


def receipt(args: argparse.Namespace, provenance: dict[str, Any], source: dict[str, Any], tag: str,
            aliases: dict[str, str]) -> dict[str, Any]:
    public_inputs = {key: value for key, value in provenance.items() if key != "config_manifest"}
    return {
        "schema_version": 1, "profile": PROFILE, "status": "blocked", "generated_at": now(),
        "mode": "execute" if args.execute else "inspect", "invocation_id": args.invocation_id,
        "tag": tag, "source": source, "inputs": public_inputs,
        "aliases": {
            name: {"reference": aliases[name], "expected_id": expected_id, "observed_id": None,
                   "created": False, "stable": False}
            for name, expected_id in (("hydrator", args.hydrator_image), ("final_base", args.final_base_image))
        },
        "images": {
            "hydrator": {"expected_id": args.hydrator_image, "observed_id": None, "rootfs_sha256": None,
                         "os": None, "architecture": None, "verified": False, "preexisting_references": []},
            "final_base": {"expected_id": args.final_base_image, "observed_id": None, "rootfs_sha256": None,
                            "os": None, "architecture": None, "verified": False, "preexisting_references": []},
        },
        "artifact": {"full_id": None, "rootfs_sha256": None, "labels_verified": False,
                     "final_base_lineage_verified": False, "postverify_output_sha256": None},
        "checks": checks(), "cleanup": cleanup_state(), "diagnostic": None,
        "limitations": ["artifact_not_built" if not args.execute else "artifact_not_yet_verified"],
        "claims": dict(FALSE_CLAIMS), "claim_boundary": CLAIM_BOUNDARY,
    }


def validate_args(args: argparse.Namespace) -> None:
    if args.hydrator_image != HYDRATOR_IMAGE_ID:
        raise ValueError("hydrator_image_must_match_rejected_f314_candidate_full_id")
    if args.final_base_image != FINAL_BASE_IMAGE_ID:
        raise ValueError("final_base_image_must_match_clean_b825_base_full_id")
    if args.hydrator_image == args.final_base_image:
        raise ValueError("hydrator_and_final_base_must_be_distinct")
    if not VERSION.fullmatch(args.rebar_version) or args.rebar_version != REBAR_VERSION:
        raise ValueError("rebar_version_invalid")
    if not INVOCATION.fullmatch(args.invocation_id) or args.invocation_id == "latest":
        raise ValueError("invocation_id_invalid")
    if not REPOSITORY.fullmatch(args.repository) or args.repository.endswith("/latest"):
        raise ValueError("repository_invalid")
    if not 30 <= args.postverify_timeout <= 900:
        raise ValueError("postverify_timeout_out_of_range")


def validate_receipt(payload: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    if "aliases" in payload and "images" in payload:
        references = []
        for name in ("hydrator", "final_base"):
            alias = payload["aliases"][name]
            base = payload["images"][name]
            if alias["expected_id"] != base["expected_id"]:
                raise ValueError("receipt_alias_expected_id_mismatch")
            if alias["stable"] and alias["observed_id"] != alias["expected_id"]:
                raise ValueError("receipt_stable_alias_identity_mismatch")
            references.append(alias["reference"])
        if len(set(references)) != 2:
            raise ValueError("receipt_alias_reference_collision")


def _labels(image: dict[str, Any] | None) -> dict[str, str]:
    labels = (image or {}).get("Config", {}).get("Labels")
    return labels if isinstance(labels, dict) else {}


def _remove(commands: Commands, reference: str) -> bool:
    return commands.run(["docker", "image", "rm", reference], timeout=60).returncode == 0


def cleanup_owned(commands: Commands, result: dict[str, Any], tag: str, image_id: str | None,
                  preexisting: set[str]) -> None:
    state = result["cleanup"]
    state.update({"required": True, "complete": False})
    tagged = inspect_image(commands, tag)
    tag_id = (tagged or {}).get("Id")
    state["tag"].update({"attempted": True, "observed_id": tag_id if FULL_IMAGE_ID.fullmatch(str(tag_id)) else None})
    candidate = image_id if FULL_IMAGE_ID.fullmatch(str(image_id)) else tag_id
    image = inspect_image(commands, candidate) if FULL_IMAGE_ID.fullmatch(str(candidate)) else None
    iid_owned = bool(FULL_IMAGE_ID.fullmatch(str(image_id)) and image_id == candidate)
    tag_owned = bool(tag_id == candidate and FULL_IMAGE_ID.fullmatch(str(candidate)))
    # Cleanup ownership comes from the unique preflight-absent tag or the fresh iidfile plus
    # pre-build inventory. Labels are an artifact acceptance gate, not a reason to leak a
    # newly created, provenance-invalid image.
    owned_image = bool(image and candidate not in preexisting and (iid_owned or tag_owned))
    owned_tag = bool(tagged and tag_id == candidate and tag_owned)
    if tagged is None:
        state["tag"]["outcome"] = "absent"
    elif not owned_tag:
        state["tag"]["outcome"] = "skipped_unowned"
    else:
        _remove(commands, tag)
        state["tag"]["outcome"] = (
            "removed" if inspect_image(commands, tag) is None else "unknown"
        )
    state["image"].update({"attempted": True, "observed_id": candidate if FULL_IMAGE_ID.fullmatch(str(candidate)) else None})
    if not FULL_IMAGE_ID.fullmatch(str(candidate)):
        state["image"]["outcome"] = "unknown"
    elif candidate in preexisting:
        state["image"]["outcome"] = "skipped_preexisting"
    elif not owned_image:
        state["image"]["outcome"] = "skipped_unowned"
    else:
        current = inspect_image(commands, candidate)
        foreign_tags = [item for item in ((current or {}).get("RepoTags") or []) if item != tag]
        if foreign_tags:
            state["image"]["outcome"] = "skipped_unowned"
        else:
            _remove(commands, candidate)
            state["image"]["outcome"] = (
                "removed" if inspect_image(commands, candidate) is None else "unknown"
            )
    state["residuals"] = [tag] if inspect_image(commands, tag) is not None else []
    if (FULL_IMAGE_ID.fullmatch(str(candidate)) and candidate not in preexisting
            and inspect_image(commands, str(candidate)) is not None):
        state["residuals"].append(str(candidate))
    state["complete"] = not state["residuals"]


def aliases_stable(commands: Commands, aliases: dict[str, str], expected_ids: dict[str, str],
                   result: dict[str, Any] | None = None) -> bool:
    stable = True
    for name, alias in aliases.items():
        observed = inspect_image(commands, alias)
        underlying = inspect_image(commands, expected_ids[name])
        observed_id = (observed or {}).get("Id")
        current = bool(
            observed_id == expected_ids[name]
            and underlying and underlying.get("Id") == expected_ids[name]
        )
        if result is not None:
            result["aliases"][name].update({
                "observed_id": observed_id if FULL_IMAGE_ID.fullmatch(str(observed_id)) else None,
                "stable": current,
            })
        stable = stable and current
    if result is not None:
        result["checks"]["alias_ids_stable"] = stable
    return stable


def create_base_aliases(commands: Commands, result: dict[str, Any], aliases: dict[str, str],
                        expected_ids: dict[str, str], created: set[str]) -> None:
    if any(inspect_image(commands, alias) is not None for alias in aliases.values()):
        raise RuntimeError("local_base_alias_preexisting")
    result["checks"]["aliases_absent"] = True
    for name in ("hydrator", "final_base"):
        alias = aliases[name]
        # Preflight proved this unique alias absent. Track every attempted mutation so
        # cleanup can recover from an adapter failure after Docker changed local state.
        # Cleanup still removes it only when a fresh inspect binds it to the exact ID.
        created.add(name)
        tagged = commands.run(["docker", "image", "tag", expected_ids[name], alias], timeout=60)
        observed = inspect_image(commands, alias)
        observed_id = (observed or {}).get("Id")
        # Docker may complete the tag mutation even when its adapter reports failure.
        # Record ownership only when the postcondition binds the alias to our exact ID.
        if observed_id == expected_ids[name]:
            result["aliases"][name].update({
                "observed_id": observed_id, "created": True, "stable": True,
            })
        if tagged.returncode != 0:
            raise RuntimeError(f"{name}_alias_creation_failed")
        if observed_id != expected_ids[name]:
            raise RuntimeError(f"{name}_alias_identity_mismatch")
    result["checks"].update({"aliases_created": True, "alias_ids_stable": True})


def cleanup_base_aliases(commands: Commands, result: dict[str, Any], aliases: dict[str, str],
                         expected_ids: dict[str, str], created: set[str]) -> bool:
    all_removed = True
    bases_preserved = True
    residuals = result["cleanup"]["residuals"]
    for name in ("hydrator", "final_base"):
        state = result["cleanup"][f"{name}_alias"]
        alias = aliases[name]
        if name not in created:
            state["outcome"] = "not_needed"
        else:
            state["attempted"] = True
            try:
                observed = inspect_image(commands, alias)
                observed_id = (observed or {}).get("Id")
                state["observed_id"] = observed_id if FULL_IMAGE_ID.fullmatch(str(observed_id)) else None
                if observed is None:
                    state["outcome"] = "absent"
                elif observed_id != expected_ids[name]:
                    state["outcome"] = "skipped_unowned"
                    residuals.append(alias)
                    all_removed = False
                else:
                    _remove(commands, alias)
                    remaining = inspect_image(commands, alias)
                    remaining_id = (remaining or {}).get("Id")
                    if remaining is None:
                        state["outcome"] = "removed"
                    elif remaining_id != expected_ids[name]:
                        state["outcome"] = "skipped_unowned"
                        residuals.append(alias)
                        all_removed = False
                    else:
                        state["outcome"] = "unknown"
                        residuals.append(alias)
                        all_removed = False
            except Exception:
                state["outcome"] = "unknown"
                residuals.append(alias)
                all_removed = False
        try:
            underlying = inspect_image(commands, expected_ids[name])
            original_references = set(result["images"][name].get("preexisting_references") or [])
            current_references = set([*((underlying or {}).get("RepoTags") or []),
                                      *((underlying or {}).get("RepoDigests") or [])])
            if original_references and (not underlying or underlying.get("Id") != expected_ids[name]
                    or not original_references.issubset(current_references)):
                residuals.append(f"missing_preexisting_base:{name}")
                bases_preserved = False
            elif not original_references:
                bases_preserved = False
        except Exception:
            residuals.append(f"base_preservation_unknown:{name}")
            bases_preserved = False
    result["cleanup"]["residuals"] = list(dict.fromkeys(residuals))
    result["checks"].update({"aliases_removed": all_removed, "base_images_preserved": bases_preserved})
    result["cleanup"]["complete"] = not result["cleanup"]["residuals"]
    return all_removed and bases_preserved


def postverify_command() -> str:
    return r"""set -eu
test ! -e lib; test ! -e priv; test ! -e test
! command -v psql >/dev/null 2>&1
test -z "$(find / -xdev -type f -name psql -print -quit)"
lock_before="$(sha256sum mix.lock | cut -d' ' -f1)"
(cd config && sha256sum -c /opt/tamandua/provenance/config-files.sha256 >/dev/null)
mix deps.loadpaths --no-compile
test "$(sha256sum mix.lock | cut -d' ' -f1)" = "$lock_before"
find deps _build/test -type f -exec sha256sum '{}' + | LC_ALL=C sort | cmp -s - /opt/tamandua/provenance/hydrated-files.sha256
nif_count="$(find _build/test -type f \( -name '*.so' -o -name '*.nif' \) -exec printf x ';' | wc -c)"
test "$nif_count" -gt 0
find _build/test -type f \( -name '*.so' -o -name '*.nif' \) -exec sh -c 'for nif do ldd "$nif" || exit 1; done' sh '{}' + > /tmp/nif-ldd.txt
test -s /tmp/nif-ldd.txt
! grep -F 'not found' /tmp/nif-ldd.txt
elixir --version
mix --version
"${MIX_REBAR3}" version
sha256sum mix.exs mix.lock /opt/tamandua/provenance/hydrated-files.sha256
printf '%s\n' TAMANDUA_ELIXIR_RUNNER_POSTVERIFY_V1
"""


def execute(args: argparse.Namespace, commands: Commands | None = None) -> tuple[dict[str, Any], int]:
    validate_args(args)
    provenance = input_provenance()
    source = git_state()
    if source["head"] != args.source_sha:
        raise ValueError("source_sha_does_not_match_head")
    tag = f"{args.repository}:{source['head'][:12]}-{args.invocation_id}"
    aliases = base_aliases(args, source)
    result = receipt(args, provenance, source, tag, aliases)
    if not args.execute:
        validate_receipt(result)
        return result, 2
    commands = commands or Commands()
    temporary: tempfile.TemporaryDirectory[str] | None = None
    iid: str | None = None
    expected: dict[str, str] = {}
    preexisting: set[str] = set()
    expected_ids = {"hydrator": args.hydrator_image, "final_base": args.final_base_image}
    created_aliases: set[str] = set()
    built = False
    try:
        hydrator = inspect_image(commands, args.hydrator_image)
        final_base = inspect_image(commands, args.final_base_image)
        for name, image, expected_id in (
            ("hydrator", hydrator, args.hydrator_image), ("final_base", final_base, args.final_base_image)
        ):
            if not image or image.get("Id") != expected_id or image.get("Os") != "linux" or image.get("Architecture") != "amd64":
                raise RuntimeError(f"{name}_identity_mismatch")
            digest = rootfs_digest(image)
            references = list(dict.fromkeys([*((image.get("RepoTags") or [])), *((image.get("RepoDigests") or []))]))
            if not references:
                raise RuntimeError(f"{name}_requires_preexisting_reference_for_safe_alias_cleanup")
            result["images"][name].update({"observed_id": image["Id"], "rootfs_sha256": digest,
                                           "os": "linux", "architecture": "amd64", "verified": True,
                                           "preexisting_references": references})
        hydrator_layers = rootfs_layers(hydrator)
        final_layers = rootfs_layers(final_base)
        base_lineage_ok = (
            len(hydrator_layers) > len(final_layers)
            and hydrator_layers[:len(final_layers)] == final_layers
        )
        result["checks"].update({"bases_verified": True, "base_rootfs_lineage": base_lineage_ok})
        if not base_lineage_ok:
            raise RuntimeError("base_rootfs_lineage_mismatch")
        hydrator_rootfs = result["images"]["hydrator"]["rootfs_sha256"]
        final_rootfs = result["images"]["final_base"]["rootfs_sha256"]
        expected = expected_labels(args, provenance, source, hydrator_rootfs, final_rootfs)
        inventory = commands.run(["docker", "image", "ls", "--no-trunc", "--quiet"], timeout=60)
        if inventory.returncode != 0:
            raise RuntimeError("image_inventory_unavailable")
        preexisting = {line.strip() for line in inventory.stdout.splitlines() if FULL_IMAGE_ID.fullmatch(line.strip())}
        if args.hydrator_image not in preexisting or args.final_base_image not in preexisting:
            raise RuntimeError("base_images_missing_from_prebuild_inventory")
        create_base_aliases(commands, result, aliases, expected_ids, created_aliases)
        if inspect_image(commands, tag) is not None:
            raise RuntimeError("unique_tag_preexisting")
        result["checks"]["tag_absent"] = True
        temporary, context = stage_context(provenance, source)
        staged = input_provenance()
        if (any(staged[key] != provenance[key] for key in provenance if key != "config_manifest")
                or not staged_context_matches(context, provenance, source)):
            raise RuntimeError("inputs_changed_before_build")
        result["checks"].update({
            "inputs_staged": True, "inputs_unchanged": True, "dependency_sources_hex_only": True,
        })
        if not aliases_stable(commands, aliases, expected_ids, result):
            raise RuntimeError("local_base_alias_drift_before_build")
        iidfile = Path(temporary.name) / "artifact.iid"
        built = True  # a failed BuildKit process can still leave an owned tag or iid behind
        build = commands.run_build(build_args(
            args, context, tag, iidfile, provenance, source, hydrator_rootfs, final_rootfs, aliases
        ))
        if not aliases_stable(commands, aliases, expected_ids, result):
            raise RuntimeError("local_base_alias_drift_after_build")
        observed_iid = iidfile.read_text(encoding="ascii").strip() if iidfile.is_file() else None
        if FULL_IMAGE_ID.fullmatch(str(observed_iid)):
            iid = observed_iid
        if build.returncode != 0:
            result["diagnostic"] = diagnostic(build)
            result["limitations"] = ["docker_build_failed"]
            raise RuntimeError("docker_build_failed")
        result["checks"]["build_succeeded"] = True
        if not FULL_IMAGE_ID.fullmatch(str(iid)) or iid in preexisting:
            raise RuntimeError("iid_invalid_or_preexisting")
        result["checks"]["iid_verified"] = True
        artifact = inspect_image(commands, iid)
        tagged = inspect_image(commands, tag)
        if not artifact or not tagged or tagged.get("Id") != iid:
            raise RuntimeError("artifact_or_tag_identity_mismatch")
        labels_ok = all(_labels(artifact).get(key) == value for key, value in expected.items())
        artifact_layers = rootfs_layers(artifact)
        lineage_ok = artifact_layers[:len(final_layers)] == final_layers and len(artifact_layers) > len(final_layers)
        hydrator_only_layers = set(hydrator_layers[len(final_layers):])
        hydrator_layers_excluded = not hydrator_only_layers.intersection(artifact_layers)
        result["artifact"].update({
            "full_id": iid, "rootfs_sha256": rootfs_digest(artifact), "labels_verified": labels_ok,
            "final_base_lineage_verified": lineage_ok,
        })
        result["checks"].update({
            "labels_verified": labels_ok, "final_base_lineage": lineage_ok,
            "hydrator_layers_excluded": hydrator_layers_excluded,
        })
        if not labels_ok or not lineage_ok or not hydrator_layers_excluded:
            raise RuntimeError("artifact_provenance_mismatch")
        if not aliases_stable(commands, aliases, expected_ids, result):
            raise RuntimeError("local_base_alias_drift_before_postverify")
        verify = commands.run([
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--entrypoint", "sh", iid,
            "-c", postverify_command(),
        ], timeout=args.postverify_timeout)
        marker_ok = verify.stdout.count("TAMANDUA_ELIXIR_RUNNER_POSTVERIFY_V1") == 1
        if verify.returncode != 0 or not marker_ok:
            raise RuntimeError("offline_read_only_postverify_failed")
        if not aliases_stable(commands, aliases, expected_ids, result):
            raise RuntimeError("local_base_alias_drift_after_postverify")
        result["artifact"]["postverify_output_sha256"] = sha256_bytes(verify.stdout.encode("utf-8"))
        result["checks"].update({
            "network_none_postverify": True, "read_only_postverify": True, "lock_unchanged": True,
            "deps_check": True, "psql_absent": True, "nif_closure": True,
        })
        _remove(commands, tag)
        if inspect_image(commands, tag) is not None:
            raise RuntimeError("owned_tag_removal_failed")
        retained = inspect_image(commands, iid)
        if not retained or retained.get("Id") != iid:
            raise RuntimeError("full_id_not_retained")
        result["checks"]["tag_removed"] = True
        result["cleanup"].update({"required": False, "complete": True, "residuals": []})
        result["cleanup"]["tag"].update({"attempted": True, "outcome": "removed", "observed_id": iid})
        result["cleanup"]["image"].update({"attempted": False, "outcome": "retained_full_id", "observed_id": iid})
        result["cleanup"]["required"] = True
        if not cleanup_base_aliases(commands, result, aliases, expected_ids, created_aliases):
            raise RuntimeError("local_base_alias_cleanup_incomplete")
        if input_provenance()["bundle_sha256"] != provenance["bundle_sha256"] or git_state() != source:
            raise RuntimeError("inputs_changed_during_build")
        result.update({"status": "pass", "limitations": [
            "public_dependency_egress_is_lock_bounded_not_domain_acl_bounded", "byte_reproducibility_not_proven"
        ]})
        result["claims"]["artifact_verified"] = True
        validate_receipt(result)
        return result, 0
    except Exception as error:
        result["status"] = "blocked"
        result["claims"] = dict(FALSE_CLAIMS)
        marker = exception_marker(error)
        result["limitations"] = list(dict.fromkeys([*result.get("limitations", []), marker]))
        if built or iid:
            try:
                cleanup_owned(commands, result, tag, iid, preexisting)
            except Exception as cleanup_error:
                result["cleanup"]["residuals"].append(
                    f"artifact_cleanup_error:{type(cleanup_error).__name__}"
                )
                result["cleanup"]["complete"] = False
        result["cleanup"]["required"] = bool(created_aliases or result["cleanup"]["required"])
        cleanup_base_aliases(commands, result, aliases, expected_ids, created_aliases)
        validate_receipt(result)
        return result, 2
    finally:
        if temporary is not None:
            temporary.cleanup()


def blocked_error(error: Exception) -> dict[str, Any]:
    marker = exception_marker(error)
    return {
        "schema_version": 1, "profile": PROFILE, "status": "blocked", "generated_at": now(),
        "error": marker, "claims": dict(FALSE_CLAIMS), "claim_boundary": CLAIM_BOUNDARY,
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--hydrator-image", required=True)
    value.add_argument("--final-base-image", required=True)
    value.add_argument("--source-sha", required=True)
    value.add_argument("--rebar-version", required=True)
    value.add_argument("--repository", default="tamandua/elixir-runtime-validation-runner")
    value.add_argument("--invocation-id", default=f"local-{uuid.uuid4().hex[:12]}")
    value.add_argument("--postverify-timeout", type=int, default=300)
    value.add_argument("--execute", action="store_true")
    value.add_argument("--output", type=Path)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        payload, code = execute(args)
    except Exception as error:
        payload, code = blocked_error(error), 2
    validate_receipt(payload)
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(serialized)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
