#!/usr/bin/env python3
"""Build and verify a local-only provenance-bound runtime validation runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "apps" / "tamandua_server"
DOCKERFILE = SERVER / "Dockerfile.runtime-validation-runner"
RECEIPT_SCHEMA = ROOT / "schemas" / "elixir_postgres_runtime_runner_receipt_v1.schema.json"
SCHEMA_VERSION = 1
DIAGNOSTIC_CONTRACT_VERSION = 2
PROFILE_ID = "elixir-postgres-runtime-runner-build"
FULL_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
FULL_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
BASE_REPOSITORY = "hexpm/elixir"
BASE_TAG = "1.18.4-erlang-27.3.4-alpine-3.21.3"
BASE_INDEX_REFERENCE = re.compile(rf"^{re.escape(BASE_REPOSITORY)}:{re.escape(BASE_TAG)}@sha256:[a-f0-9]{{64}}$")
BASE_PLATFORM_REFERENCE = re.compile(rf"^{re.escape(BASE_REPOSITORY)}@sha256:[a-f0-9]{{64}}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
VERSION = re.compile(r"^[0-9][0-9A-Za-z.+:~_-]*$")
INVOCATION = re.compile(r"^[a-z0-9][a-z0-9_.-]{7,63}$")
LABEL_PREFIX = "io.tamandua.validation."
PLATFORM = "linux/amd64"
OS = "linux"
ARCHITECTURE = "amd64"
ELIXIR_VERSION = "1.18.4"
ERLANG_VERSION = "27.3.4"
OTP_RELEASE = "27"
ALPINE_VERSION = "3.21.3"
HEX_VERSION = "2.2.1"
APK_REPOSITORY_BRANCH = "v3.21"
APK_MAIN_REPOSITORY = "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"
APK_COMMUNITY_REPOSITORY = "https://dl-cdn.alpinelinux.org/alpine/v3.21/community"
POSTGRESQL_CLIENT_PACKAGE = "postgresql16-client"
POSTGRESQL_CLIENT_PACKAGE_VERSION = "16.14-r0"
PSQL_VERSION = "16.14"
ALPINE_TOOLCHAIN_PACKAGES = "build-base git python3 pkgconf openssl-dev libxml2-dev"
CLAIM_BOUNDARY = (
    "Local immutable validation-runner artifact evidence for the exact recorded inputs and image ID only. "
    "It is not byte-reproducibility, server runtime, PostgreSQL/RLS execution, release, deployment, "
    "production, vendor parity, product readiness, or external-claim evidence."
)
BUILD_STREAM_TAIL_BYTES = 65536
BUILD_DIAGNOSTIC_MAX_LINES = 12
BUILD_DIAGNOSTIC_MAX_WARNINGS = 8
BUILD_WARNING_CODES = frozenset({
    "ConsistentInstructionCasing", "CopyIgnoredFile", "DuplicateStageName", "ExposeProtoCasing",
    "FromAsCasing", "FromPlatformFlagConstDisallowed", "InvalidDefaultArgInFrom",
    "InvalidDefinitionDescription", "JSONArgsRecommended", "LegacyKeyValueFormat",
    "MaintainerDeprecated", "MultipleInstructionsDisallowed", "NoEmptyContinuation",
    "RedundantTargetPlatform", "ReservedStageName", "SecretsUsedInArgOrEnv", "StageNameCasing",
    "UndefinedArgInFrom", "UndefinedVar", "WorkdirRelativePath",
})
BUILD_STEP = re.compile(
    r"^#(?P<id>[0-9]{1,6})\s+\[(?:(?P<stage>[A-Za-z0-9_.-]{1,32})\s+)?"
    r"(?P<index>[0-9]{1,4})/(?P<total>[0-9]{1,4})\]\s+"
    r"(?P<instruction>ARG|CMD|COPY|ENTRYPOINT|ENV|FROM|LABEL|RUN|USER|WORKDIR)\b"
)
BUILD_ERROR_STEP = re.compile(r"^#(?P<id>[0-9]{1,6})\s+ERROR\b")
BUILD_WARNING = re.compile(r"^#[0-9]{1,6}\s+WARN:\s+(?P<code>[A-Za-z][A-Za-z0-9_-]{0,63}):")
BUILD_EXIT_CODE = re.compile(r"\bexit code:?\s*(?P<code>[0-9]{1,3})\b", re.IGNORECASE)
ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
RUNNER_FAILURE_CHECKPOINTS = ("repositories", "apk_install", "psql_version", "closure_digest")
RUNNER_FAILURE_MARKER = re.compile(
    r"^#(?P<id>[0-9]{1,6})\s+[0-9]+(?:\.[0-9]+)?s?\s+"
    r"TAMANDUA_RUNNER_FAILURE_V1:(?P<checkpoint>repositories|apk_install|psql_version|closure_digest)$"
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_source_sha(root: Path = ROOT) -> str:
    try:
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("current_source_sha_unavailable") from error
    value = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[a-f0-9]{40}", value):
        raise RuntimeError("current_source_sha_unavailable")
    return value


def canonical_tree_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    candidates = sorted(path.rglob("*"))
    for candidate in candidates:
        if candidate.is_symlink():
            raise RuntimeError(f"symlink_input_forbidden:{candidate.relative_to(path).as_posix()}")
    files = [candidate for candidate in candidates if candidate.is_file()]
    if not files:
        raise RuntimeError(f"empty_input_tree:{path.name}")
    for candidate in files:
        if candidate.is_symlink():
            raise RuntimeError(f"symlink_input_forbidden:{candidate.relative_to(path).as_posix()}")
        relative = candidate.relative_to(path).as_posix().encode("utf-8")
        payload = candidate.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest(), len(files)


def input_provenance(server: Path = SERVER, dockerfile: Path = DOCKERFILE) -> dict[str, Any]:
    mix_exs = server / "mix.exs"
    mix_lock = server / "mix.lock"
    config = server / "config"
    for path in (dockerfile, mix_exs, mix_lock):
        if not path.is_file():
            raise RuntimeError(f"input_missing:{path.name}")
        if path.is_symlink():
            raise RuntimeError(f"symlink_input_forbidden:{path.name}")
    if not config.is_dir():
        raise RuntimeError("input_missing:config")
    config_digest, config_count = canonical_tree_digest(config)
    entries = {
        "dockerfile_sha256": sha256_file(dockerfile),
        "mix_exs_sha256": sha256_file(mix_exs),
        "mix_lock_sha256": sha256_file(mix_lock),
        "config_sha256": config_digest,
    }
    bundle = hashlib.sha256()
    for name, value in sorted(entries.items()):
        bundle.update(name.encode("ascii") + b"\0" + value.encode("ascii") + b"\n")
    return {**entries, "input_bundle_sha256": bundle.hexdigest(), "config_file_count": config_count}


def stage_context(server: Path = SERVER, dockerfile: Path = DOCKERFILE) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    temporary = tempfile.TemporaryDirectory(prefix="tamandua-runtime-runner-")
    context = Path(temporary.name) / "context"
    context.mkdir()
    shutil.copy2(dockerfile, context / dockerfile.name)
    shutil.copy2(server / "mix.exs", context / "mix.exs")
    shutil.copy2(server / "mix.lock", context / "mix.lock")
    shutil.copytree(server / "config", context / "config")
    manifest = []
    for candidate in sorted(path for path in (server / "config").rglob("*") if path.is_file()):
        relative = candidate.relative_to(server / "config").as_posix()
        if "\n" in relative or "\r" in relative or relative.startswith("\\"):
            temporary.cleanup()
            raise RuntimeError("config_path_not_manifest_safe")
        manifest.append(f"{sha256_file(candidate)}  {relative}")
    (context / ".tamandua-config-files.sha256").write_text("\n".join(manifest) + "\n", encoding="utf-8", newline="\n")
    return temporary, context


class Commands:
    def run(self, args: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  check=False, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
            return subprocess.CompletedProcess(args, 124, stdout, f"{stderr}\ncommand_timeout".lstrip())

    def run_build(self, args: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
        states = {
            "stdout": {"tail": bytearray(), "observed_bytes": 0},
            "stderr": {"tail": bytearray(), "observed_bytes": 0},
        }
        try:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as error:
            marker = f"adapter_error:{type(error).__name__}"
            result = subprocess.CompletedProcess(args, 127, "", marker)
            result.stdout_observed_bytes = 0
            result.stderr_observed_bytes = len(marker.encode("ascii"))
            result.stdout_truncated = False
            result.stderr_truncated = False
            result.timed_out = False
            return result

        def drain(name: str) -> None:
            pipe = process.stdout if name == "stdout" else process.stderr
            assert pipe is not None
            state = states[name]
            while True:
                chunk = pipe.read(8192)
                if not chunk:
                    break
                state["observed_bytes"] += len(chunk)
                state["tail"].extend(chunk)
                overflow = len(state["tail"]) - BUILD_STREAM_TAIL_BYTES
                if overflow > 0:
                    del state["tail"][:overflow]

        readers = [threading.Thread(target=drain, args=(name,), daemon=True) for name in ("stdout", "stderr")]
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            returncode = process.wait()
        for reader in readers:
            reader.join()
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()

        result = subprocess.CompletedProcess(
            args,
            124 if timed_out else returncode,
            bytes(states["stdout"]["tail"]).decode("utf-8", errors="replace"),
            bytes(states["stderr"]["tail"]).decode("utf-8", errors="replace"),
        )
        for name in ("stdout", "stderr"):
            observed = states[name]["observed_bytes"]
            setattr(result, f"{name}_observed_bytes", observed)
            setattr(result, f"{name}_truncated", observed > BUILD_STREAM_TAIL_BYTES)
        result.timed_out = timed_out
        return result


def build_failure_diagnostic(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    stdout = result.stdout or ""
    stderr = result.stderr or ""

    def sanitize_lines(value: str) -> list[str]:
        sanitized = []
        for raw_line in value.splitlines():
            without_ansi = ANSI_ESCAPE.sub("", raw_line)
            sanitized.append("".join(
                character if 32 <= ord(character) <= 126 else " " for character in without_ansi
            ).strip())
        return sanitized

    stdout_lines = sanitize_lines(stdout)
    stderr_lines = sanitize_lines(stderr)
    lines = stdout_lines + stderr_lines

    # The Dockerfile writes this closed marker to stderr. Restricting parsing to
    # that stream prevents unrelated stdout from being paired with a BuildKit
    # error after the two bounded stream tails are joined for diagnostics.
    structured_markers: list[tuple[int, re.Match[str]]] = []
    numbered_errors: list[tuple[int, int]] = []
    for index, line in enumerate(stderr_lines):
        marker = RUNNER_FAILURE_MARKER.fullmatch(line)
        if marker:
            structured_markers.append((index, marker))
        error = BUILD_ERROR_STEP.match(line)
        if error:
            numbered_errors.append((index, int(error.group("id"))))

    terminal_markers: list[tuple[int, str]] = []
    valid_marker_lines: set[int] = set()
    if len(structured_markers) == 1 and numbered_errors:
        index, marker = structured_markers[0]
        following = index + 1
        while following < len(stderr_lines) and not stderr_lines[following]:
            following += 1
        final_error_index, final_error_id = numbered_errors[-1]
        marker_id = int(marker.group("id"))
        if following == final_error_index and marker_id == final_error_id:
            terminal_markers.append((marker_id, marker.group("checkpoint")))
            valid_marker_lines.add(len(stdout_lines) + index)

    failure_checkpoint = terminal_markers[0][1] if len(terminal_markers) == 1 else "unknown"

    canonical: list[str] = []
    warnings: list[str] = []
    step: dict[str, Any] | None = None
    steps_by_id: dict[int, dict[str, Any]] = {}
    error_step_id: int | None = None
    observed_exit_code: int | None = None
    final_error_exit_code: int | None = None
    recognized_lines = 0
    total_lines = 0

    for line_index, line in enumerate(lines):
        total_lines += 1
        if line_index in valid_marker_lines:
            recognized_lines += 1
            continue
        match = BUILD_STEP.match(line)
        if match:
            recognized_lines += 1
            step = {
                "buildkit_id": int(match.group("id")),
                "index": int(match.group("index")),
                "total": int(match.group("total")),
                # Stage names are Dockerfile-controlled free text and may
                # accidentally contain credentials or customer identifiers.
                # Preserve only whether BuildKit reported a named stage.
                "stage": "named" if match.group("stage") else None,
                "instruction": match.group("instruction"),
            }
            steps_by_id[step["buildkit_id"]] = step
            canonical.append(
                f"step:{step['buildkit_id']}:{step['index']}/{step['total']}:{step['instruction']}"
            )
            continue
        match = BUILD_WARNING.match(line)
        if match:
            recognized_lines += 1
            observed_code = match.group("code")
            code = observed_code if observed_code in BUILD_WARNING_CODES else "Other"
            if code not in warnings and len(warnings) < BUILD_DIAGNOSTIC_MAX_WARNINGS:
                warnings.append(code)
            canonical.append(f"warning:{code}")
            continue
        line_recognized = False
        match = BUILD_ERROR_STEP.match(line)
        if match:
            line_recognized = True
            error_step_id = int(match.group("id"))
            error_exit = BUILD_EXIT_CODE.search(line)
            final_error_exit_code = int(error_exit.group("code")) if error_exit else None
            canonical.append(f"step:{error_step_id}:error")
        match = BUILD_EXIT_CODE.search(line)
        if match:
            line_recognized = True
            observed_exit_code = int(match.group("code"))
        if line.lower().startswith("failed to solve:"):
            line_recognized = True
            canonical.append("buildkit_failed_to_solve")
        if line.startswith("adapter_error:"):
            line_recognized = True
            canonical.append(line if re.fullmatch(r"adapter_error:[A-Za-z][A-Za-z0-9_]{0,63}", line) else "adapter_error:unknown")
        if line_recognized:
            recognized_lines += 1

    # Bind the reported process exit to the final numbered BuildKit ERROR when
    # it carries one. Later untrusted output may contain exit-like prose and
    # must not overwrite the terminal error's code or add conflicting events.
    exit_code = final_error_exit_code if final_error_exit_code is not None else observed_exit_code
    if exit_code is not None:
        canonical.append(f"process_exit:{exit_code}")

    if getattr(result, "timed_out", False) or result.returncode == 124:
        failure_kind = "timeout"
        canonical.append("timeout")
    elif any(item.startswith("adapter_error:") for item in canonical):
        failure_kind = "adapter_error"
    elif exit_code is not None:
        failure_kind = "process_exit"
    elif error_step_id is not None or "buildkit_failed_to_solve" in canonical:
        failure_kind = "buildkit_error"
    else:
        failure_kind = "unknown"
        canonical.append("unknown_failure")

    if error_step_id is not None and error_step_id in steps_by_id:
        step = steps_by_id[error_step_id]

    canonical.append(f"checkpoint:{failure_checkpoint}")
    canonical = canonical[-BUILD_DIAGNOSTIC_MAX_LINES:]
    canonical_payload = ("\n".join(canonical) + "\n").encode("ascii")

    def stream_metadata(name: str, value: str) -> dict[str, Any]:
        retained = len(value.encode("utf-8", errors="replace"))
        observed = int(getattr(result, f"{name}_observed_bytes", retained))
        return {
            "observed_bytes": observed,
            "retained_bytes": min(retained, BUILD_STREAM_TAIL_BYTES),
            "truncated": bool(getattr(result, f"{name}_truncated", observed > BUILD_STREAM_TAIL_BYTES)),
        }

    return {
        "failure_kind": failure_kind,
        "failure_checkpoint": failure_checkpoint,
        "command_exit_code": result.returncode if 0 <= result.returncode <= 255 else 255,
        "process_exit_code": exit_code,
        "error_step_id": error_step_id,
        "step": step,
        "warnings": warnings,
        "canonical_tail": canonical,
        "canonical_tail_sha256": hashlib.sha256(canonical_payload).hexdigest(),
        "observed_line_count": total_lines,
        "discarded_line_count": total_lines - recognized_lines,
        "stdout": stream_metadata("stdout", stdout),
        "stderr": stream_metadata("stderr", stderr),
    }


def inspect_image(commands: Commands, reference: str) -> dict[str, Any]:
    result = commands.run(["docker", "image", "inspect", reference])
    if result.returncode != 0:
        raise RuntimeError("image_inspect_failed")
    payload = json.loads(result.stdout)
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise RuntimeError("image_inspect_invalid")
    return payload[0]


def image_reference_absent(commands: Commands, reference: str) -> bool:
    inspected = commands.run(["docker", "image", "inspect", reference])
    if inspected.returncode == 0:
        return False
    listed = commands.run([
        "docker", "image", "ls", "--no-trunc", "--filter", f"reference={reference}",
        "--format", "{{.Repository}}:{{.Tag}}",
    ])
    if listed.returncode != 0:
        raise RuntimeError("unique_tag_absence_unknown")
    return not listed.stdout.strip()


def image_ids(commands: Commands) -> set[str]:
    result = commands.run(["docker", "image", "ls", "--no-trunc", "--quiet"], timeout=60)
    if result.returncode != 0:
        raise RuntimeError("image_inventory_failed")
    values = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    if any(not FULL_IMAGE_ID.fullmatch(value) for value in values):
        raise RuntimeError("image_inventory_invalid")
    return values


def reference_digest(reference: str) -> str:
    digest = reference.rsplit("@", 1)[-1]
    if not FULL_DIGEST.fullmatch(digest):
        raise ValueError("reference_digest_invalid")
    return digest


def platform_matches(image: dict[str, Any]) -> bool:
    return image.get("Os") == OS and image.get("Architecture") == ARCHITECTURE


def validate_receipt(payload: dict[str, Any]) -> None:
    schema = json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    if "error" in payload:
        return
    base = payload["base"]
    if base["index_digest"] != reference_digest(base["index_reference"]):
        raise ValueError("receipt_base_index_digest_mismatch")
    if base["platform_manifest_digest"] != reference_digest(base["platform_reference"]):
        raise ValueError("receipt_base_platform_manifest_digest_mismatch")
    if base["index_digest"] == base["platform_manifest_digest"]:
        raise ValueError("receipt_base_index_manifest_identity_collision")
    if base["verified"] and base["observed_config_id"] != base["expected_config_id"]:
        raise ValueError("receipt_base_config_identity_mismatch")


def cleanup_state() -> dict[str, Any]:
    resource = {"attempted": False, "outcome": "not_needed", "observed_image_id": None, "error": None}
    return {
        "required": False,
        "attempted": False,
        "complete": True,
        "tag": dict(resource),
        "image": dict(resource),
        "residuals": [],
    }


def _inspect_for_cleanup(commands: Commands, reference: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        result = commands.run(["docker", "image", "inspect", reference], timeout=60)
    except Exception as error:  # cleanup must keep progressing after an adapter failure
        return None, f"inspect_exception:{type(error).__name__}"
    if result.returncode != 0:
        stderr = (result.stderr or "").lower()
        if any(marker in stderr for marker in ("no such image", "no such object", "not found")):
            return None, None
        return None, f"inspect_exit_{result.returncode}"
    try:
        payload = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return None, "inspect_invalid_json"
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        return None, "inspect_invalid_shape"
    return payload[0], None


def _remove_for_cleanup(commands: Commands, reference: str) -> tuple[int | None, str | None]:
    try:
        removed = commands.run(["docker", "image", "rm", reference], timeout=60)
    except Exception as error:  # the other resource cleanup must still be attempted
        return None, f"remove_exception:{type(error).__name__}"
    return removed.returncode, None


def _image_labels(image: dict[str, Any] | None) -> dict[str, str]:
    config = image.get("Config") if isinstance(image, dict) else None
    labels = config.get("Labels") if isinstance(config, dict) else None
    return labels if isinstance(labels, dict) else {}


def cleanup_failed_build(
    commands: Commands,
    result: dict[str, Any],
    tag: str,
    expected: dict[str, str],
    preexisting_ids: set[str],
    iid_candidate: str | None,
) -> None:
    cleanup = result["cleanup"]
    cleanup.update({"required": True, "attempted": True, "complete": False})

    tag_state = cleanup["tag"]
    tag_state["attempted"] = True
    tagged, tag_error = _inspect_for_cleanup(commands, tag)
    tag_id = tagged.get("Id") if tagged else None
    if isinstance(tag_id, str) and FULL_IMAGE_ID.fullmatch(tag_id):
        tag_state["observed_image_id"] = tag_id
    candidate = iid_candidate if isinstance(iid_candidate, str) and FULL_IMAGE_ID.fullmatch(iid_candidate) else tag_id

    candidate_image, candidate_error = (None, None)
    identity_proven = False
    if isinstance(candidate, str) and FULL_IMAGE_ID.fullmatch(candidate):
        candidate_image, candidate_error = _inspect_for_cleanup(commands, candidate)
        labels = _image_labels(candidate_image)
        identity_proven = (
            isinstance(labels, dict)
            and all(labels.get(key) == value for key, value in expected.items())
        )

    if tag_error:
        tag_state.update({"outcome": "unknown", "error": tag_error})
    elif tagged is None:
        tag_state["outcome"] = "absent"
    elif candidate in preexisting_ids:
        tag_state["outcome"] = "skipped_preexisting"
    elif not identity_proven or tag_id != candidate:
        tag_state["outcome"] = "skipped_divergent"
    else:
        remove_code, remove_error = _remove_for_cleanup(commands, tag)
        remaining, remaining_error = _inspect_for_cleanup(commands, tag)
        if remove_code == 0 and remaining is None and remaining_error is None:
            tag_state["outcome"] = "removed"
        else:
            tag_state.update({
                "outcome": "failed",
                "error": remove_error or remaining_error or f"remove_exit_{remove_code}",
            })

    image_state = cleanup["image"]
    image_state["attempted"] = True
    if isinstance(candidate, str) and FULL_IMAGE_ID.fullmatch(candidate):
        image_state["observed_image_id"] = candidate
    if not isinstance(candidate, str) or not FULL_IMAGE_ID.fullmatch(candidate):
        image_state["outcome"] = "unknown"
        image_state["error"] = "built_image_identity_unavailable"
    elif candidate in preexisting_ids:
        image_state["outcome"] = "skipped_preexisting"
    elif candidate_error:
        image_state.update({"outcome": "unknown", "error": candidate_error})
    elif candidate_image is None:
        image_state["outcome"] = "absent"
    elif not identity_proven:
        image_state["outcome"] = "skipped_divergent"
    else:
        current, current_error = _inspect_for_cleanup(commands, candidate)
        current_labels = _image_labels(current)
        repo_tags = (current or {}).get("RepoTags") or []
        current_proven = (
            isinstance(current_labels, dict)
            and all(current_labels.get(key) == value for key, value in expected.items())
        )
        foreign_tags = [value for value in repo_tags if value != tag]
        if current_error:
            image_state.update({"outcome": "unknown", "error": current_error})
        elif current is None:
            image_state["outcome"] = "absent"
        elif not current_proven or foreign_tags:
            image_state["outcome"] = "skipped_divergent"
        else:
            remove_code, remove_error = _remove_for_cleanup(commands, candidate)
            remaining, remaining_error = _inspect_for_cleanup(commands, candidate)
            if remove_code == 0 and remaining is None and remaining_error is None:
                image_state["outcome"] = "removed"
            else:
                image_state.update({
                    "outcome": "failed",
                    "error": remove_error or remaining_error or f"remove_exit_{remove_code}",
                })

    # Reconcile both resources after the independent attempts. Removing the
    # exact image can also remove its last tag, so residuals must describe the
    # final state rather than an earlier failed command.
    final_tag, final_tag_error = _inspect_for_cleanup(commands, tag)
    if (final_tag is None and final_tag_error is None
            and tag_state["outcome"] not in {"removed", "absent"}):
        tag_state.update({"outcome": "absent", "error": None})
    final_image = None
    final_image_error = None
    if isinstance(candidate, str) and FULL_IMAGE_ID.fullmatch(candidate):
        final_image, final_image_error = _inspect_for_cleanup(commands, candidate)
        if (final_image is None and final_image_error is None
                and image_state["outcome"] not in {"removed", "absent"}):
            image_state.update({"outcome": "absent", "error": None})

    cleanup["residuals"] = [
        name for name, state in (("tag", tag_state), ("image", image_state))
        if state["outcome"] not in {"removed", "absent"}
    ]
    cleanup["complete"] = not cleanup["residuals"]


def validate_args(args: argparse.Namespace) -> None:
    if not BASE_INDEX_REFERENCE.fullmatch(args.base_image):
        raise ValueError("base_image_must_be_exact_hexpm_alpine_index_digest")
    if not BASE_PLATFORM_REFERENCE.fullmatch(args.base_platform_image):
        raise ValueError("base_platform_image_must_be_exact_amd64_manifest_digest")
    if reference_digest(args.base_image) == reference_digest(args.base_platform_image):
        raise ValueError("base_index_and_manifest_digests_must_be_distinct")
    if not FULL_IMAGE_ID.fullmatch(args.expected_base_image_id):
        raise ValueError("expected_base_config_id_must_be_full")
    if not re.fullmatch(r"[a-f0-9]{40}", args.source_sha):
        raise ValueError("source_sha_must_be_full_git_sha")
    for name in ("elixir_version", "erlang_version", "otp_release", "alpine_version", "hex_version",
                 "postgresql_client_package_version", "psql_version"):
        if not VERSION.fullmatch(getattr(args, name)):
            raise ValueError(f"invalid_version:{name}")
    if not SHA256.fullmatch(args.expected_package_manifest_sha256):
        raise ValueError("expected_package_manifest_sha256_must_be_full")
    exact = {
        "elixir_version": ELIXIR_VERSION, "erlang_version": ERLANG_VERSION,
        "otp_release": OTP_RELEASE, "alpine_version": ALPINE_VERSION, "hex_version": HEX_VERSION,
        "apk_repository_branch": APK_REPOSITORY_BRANCH,
        "postgresql_client_package": POSTGRESQL_CLIENT_PACKAGE,
        "postgresql_client_package_version": POSTGRESQL_CLIENT_PACKAGE_VERSION,
        "psql_version": PSQL_VERSION, "alpine_toolchain_packages": ALPINE_TOOLCHAIN_PACKAGES,
        "platform": PLATFORM,
    }
    for name, expected in exact.items():
        if getattr(args, name) != expected:
            raise ValueError(f"unexpected_alpine_chain_value:{name}")
    if not INVOCATION.fullmatch(args.invocation_id) or args.invocation_id == "latest":
        raise ValueError("invocation_id_invalid")
    if args.repository.endswith(":latest") or "@" in args.repository or not re.fullmatch(r"[a-z0-9][a-z0-9./_-]{2,127}", args.repository):
        raise ValueError("repository_invalid")


def expected_labels(args: argparse.Namespace, provenance: dict[str, Any]) -> dict[str, str]:
    return {
        "org.opencontainers.image.revision": args.source_sha,
        f"{LABEL_PREFIX}claim-scope": "local-only",
        f"{LABEL_PREFIX}product-ready": "false",
        f"{LABEL_PREFIX}production-validated": "false",
        f"{LABEL_PREFIX}external-claim-allowed": "false",
        f"{LABEL_PREFIX}vendor-parity": "false",
        f"{LABEL_PREFIX}platform": PLATFORM,
        f"{LABEL_PREFIX}base.index-reference": args.base_image,
        f"{LABEL_PREFIX}base.index-digest": reference_digest(args.base_image),
        f"{LABEL_PREFIX}base.manifest-reference": args.base_platform_image,
        f"{LABEL_PREFIX}base.manifest-digest": reference_digest(args.base_platform_image),
        f"{LABEL_PREFIX}base.config-id": args.expected_base_image_id,
        f"{LABEL_PREFIX}source.sha": args.source_sha,
        f"{LABEL_PREFIX}input.dockerfile.sha256": provenance["dockerfile_sha256"],
        f"{LABEL_PREFIX}input.mix-exs.sha256": provenance["mix_exs_sha256"],
        f"{LABEL_PREFIX}input.mix-lock.sha256": provenance["mix_lock_sha256"],
        f"{LABEL_PREFIX}input.config.sha256": provenance["config_sha256"],
        f"{LABEL_PREFIX}input.bundle.sha256": provenance["input_bundle_sha256"],
        f"{LABEL_PREFIX}invocation.id": args.invocation_id,
        f"{LABEL_PREFIX}tool.elixir": args.elixir_version,
        f"{LABEL_PREFIX}tool.erlang": args.erlang_version,
        f"{LABEL_PREFIX}tool.otp": args.otp_release,
        f"{LABEL_PREFIX}os.alpine": args.alpine_version,
        f"{LABEL_PREFIX}tool.hex": args.hex_version,
        f"{LABEL_PREFIX}tool.psql": args.psql_version,
        f"{LABEL_PREFIX}package.manager": "apk",
        f"{LABEL_PREFIX}package.repository-branch": args.apk_repository_branch,
        f"{LABEL_PREFIX}package.repository-main": APK_MAIN_REPOSITORY,
        f"{LABEL_PREFIX}package.repository-community": APK_COMMUNITY_REPOSITORY,
        f"{LABEL_PREFIX}package.postgresql-client": f"{args.postgresql_client_package}={args.postgresql_client_package_version}",
        f"{LABEL_PREFIX}package.toolchain": args.alpine_toolchain_packages,
        f"{LABEL_PREFIX}package.manifest.sha256": args.expected_package_manifest_sha256,
    }


def build_args(
    args: argparse.Namespace, context: Path, provenance: dict[str, Any], tag: str, iidfile: Path
) -> list[str]:
    values = {
        "BASE_PLATFORM_IMAGE": args.base_platform_image,
        "BASE_INDEX_IMAGE": args.base_image,
        "BASE_INDEX_DIGEST": reference_digest(args.base_image),
        "BASE_PLATFORM_MANIFEST_DIGEST": reference_digest(args.base_platform_image),
        "EXPECTED_BASE_CONFIG_ID": args.expected_base_image_id,
        "EXPECTED_ELIXIR_VERSION": args.elixir_version,
        "EXPECTED_ERLANG_VERSION": args.erlang_version,
        "EXPECTED_OTP_RELEASE": args.otp_release,
        "EXPECTED_ALPINE_VERSION": args.alpine_version,
        "HEX_VERSION": args.hex_version,
        "APK_REPOSITORY_BRANCH": args.apk_repository_branch,
        "POSTGRESQL_CLIENT_PACKAGE": args.postgresql_client_package,
        "POSTGRESQL_CLIENT_PACKAGE_VERSION": args.postgresql_client_package_version,
        "EXPECTED_PSQL_VERSION": args.psql_version,
        "ALPINE_TOOLCHAIN_PACKAGES": args.alpine_toolchain_packages,
        "EXPECTED_PACKAGE_MANIFEST_SHA256": args.expected_package_manifest_sha256,
        "SOURCE_SHA": args.source_sha,
        "DOCKERFILE_SHA256": provenance["dockerfile_sha256"],
        "MIX_EXS_SHA256": provenance["mix_exs_sha256"],
        "MIX_LOCK_SHA256": provenance["mix_lock_sha256"],
        "CONFIG_SHA256": provenance["config_sha256"],
        "INPUT_BUNDLE_SHA256": provenance["input_bundle_sha256"],
        "INVOCATION_ID": args.invocation_id,
    }
    command = [
        "docker", "build", "--platform", PLATFORM, "--pull=false", "--progress=plain",
        "--file", str(context / DOCKERFILE.name),
        "--iidfile", str(iidfile), "--tag", tag,
    ]
    for name, value in values.items():
        command.extend(["--build-arg", f"{name}={value}"])
    command.append(str(context))
    return command


def verify_command(image_id: str, args: argparse.Namespace) -> list[str]:
    script = (
        "set -eu; "
        "test \"$(elixir --version | sed -n 's/^Elixir \\([0-9][^ ]*\\).*/\\1/p')\" = \"$EXPECTED_ELIXIR\"; "
        "test \"$(erl -noshell -eval 'io:format(\\\"~s\\\", [erlang:system_info(otp_release)]), halt().' 2>/dev/null)\" = \"$EXPECTED_OTP\"; "
        "test \"$(cat /usr/local/lib/erlang/releases/$EXPECTED_OTP/OTP_VERSION)\" = \"$EXPECTED_ERLANG\"; "
        "test \"$(cat /etc/alpine-release)\" = \"$EXPECTED_ALPINE\"; "
        "test \"$(apk --print-arch)\" = x86_64; "
        "test \"$(grep -Ev '^[[:space:]]*($|#)' /etc/apk/repositories | wc -l | tr -d '[:space:]')\" = 2; "
        f"grep -Fqx '{APK_MAIN_REPOSITORY}' /etc/apk/repositories; "
        f"grep -Fqx '{APK_COMMUNITY_REPOSITORY}' /etc/apk/repositories; "
        "test \"$(psql --version | sed 's/^psql (PostgreSQL) //')\" = \"$EXPECTED_PSQL\"; "
        "mix hex.info | grep -F \"Hex: $EXPECTED_HEX\"; "
        "test \"$(sha256sum /opt/tamandua/provenance/apk-manifest.txt | cut -d' ' -f1)\" = \"$EXPECTED_MANIFEST\"; "
        "test \"$(apk info -v | LC_ALL=C sort | sha256sum | cut -d' ' -f1)\" = \"$EXPECTED_MANIFEST\"; "
        "MIX_ENV=test mix deps.check"
    )
    return [
        "docker", "run", "--platform", PLATFORM, "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--env", f"EXPECTED_ELIXIR={args.elixir_version}",
        "--env", f"EXPECTED_ERLANG={args.erlang_version}",
        "--env", f"EXPECTED_OTP={args.otp_release}",
        "--env", f"EXPECTED_ALPINE={args.alpine_version}",
        "--env", f"EXPECTED_HEX={args.hex_version}",
        "--env", f"EXPECTED_PSQL={args.psql_version}",
        "--env", f"EXPECTED_MANIFEST={args.expected_package_manifest_sha256}",
        "--entrypoint", "/bin/sh", image_id, "-c", script,
    ]


def receipt(args: argparse.Namespace, provenance: dict[str, Any], tag: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_contract_version": DIAGNOSTIC_CONTRACT_VERSION,
        "profile_id": PROFILE_ID,
        "generated_at": now(),
        "mode": "execute" if args.execute else "inspect",
        "status": "blocked",
        "invocation_id": args.invocation_id,
        "tag": tag,
        "source_sha": args.source_sha,
        "inputs": provenance,
        "base": {"index_reference": args.base_image, "index_digest": reference_digest(args.base_image),
                 "platform_reference": args.base_platform_image,
                 "platform_manifest_digest": reference_digest(args.base_platform_image),
                 "expected_config_id": args.expected_base_image_id, "observed_config_id": None,
                 "expected_os": OS, "expected_architecture": ARCHITECTURE,
                 "index_observed_os": None, "index_observed_architecture": None,
                 "platform_observed_os": None, "platform_observed_architecture": None,
                 "verified": False},
        "tools": {"elixir": args.elixir_version, "erlang": args.erlang_version,
                  "otp": args.otp_release, "alpine": args.alpine_version, "hex": args.hex_version,
                  "package_manager": "apk", "apk_repository_branch": args.apk_repository_branch,
                  "apk_repositories": [APK_MAIN_REPOSITORY, APK_COMMUNITY_REPOSITORY],
                  "postgresql_client_package": args.postgresql_client_package,
                  "postgresql_client_package_version": args.postgresql_client_package_version,
                  "alpine_toolchain_packages": args.alpine_toolchain_packages.split(),
                  "psql": args.psql_version, "package_manifest_sha256": args.expected_package_manifest_sha256},
        "image": {"full_id": None, "observed_os": None, "observed_architecture": None,
                  "labels_verified": False, "post_build_verified": False},
        "build_failure_diagnostic": None,
        "cleanup": cleanup_state(),
        "checks": {"inputs_staged": False, "inputs_unchanged": False, "lock_unchanged": False,
                   "base_id_verified": False, "base_platform_verified": False,
                   "tag_absent_before_build": False,
                   "build_succeeded": False, "iidfile_verified": False,
                   "full_image_id_inspected": False, "final_platform_verified": False,
                   "tag_resolved_to_full_id": False,
                   "labels_verified": False, "network_none_verification": False,
                   "read_only_verification": False, "deps_check": False, "versions_verified": False,
                   "no_post_build_hydration": False},
        "claims": {"build_verified": False, "runtime_validation_executed": False,
                   "runtime_validated": False, "byte_reproducible": False, "product_ready": False,
                   "production_validated": False, "external_claim_allowed": False, "vendor_parity": False},
        "limitations": ["alpine_repository_indexes_not_snapshotted", "alpine_mirror_retention_unproven",
                        "musl_nif_runtime_compatibility_unproven", "rebar_version_not_pinned",
                        "byte_reproducibility_not_claimed",
                        "runtime_validation_not_executed"],
        "claim_boundary": CLAIM_BOUNDARY,
    }


def execute(args: argparse.Namespace, commands: Commands | None = None) -> tuple[dict[str, Any], int]:
    commands = commands or Commands()
    validate_args(args)
    if args.source_sha != current_source_sha():
        raise ValueError("source_sha_does_not_match_current_head")
    before = input_provenance()
    tag = f"{args.repository}:{args.source_sha[:12]}-{args.invocation_id}"
    result = receipt(args, before, tag)
    if not args.execute:
        result["limitations"].append("build_not_authorized_or_requested")
        validate_receipt(result)
        return result, 2

    base_index = inspect_image(commands, args.base_image)
    base_platform = inspect_image(commands, args.base_platform_image)
    observed_base = base_platform.get("Id")
    result["base"]["observed_config_id"] = observed_base
    result["base"].update({
        "index_observed_os": base_index.get("Os"),
        "index_observed_architecture": base_index.get("Architecture"),
        "platform_observed_os": base_platform.get("Os"),
        "platform_observed_architecture": base_platform.get("Architecture"),
    })
    result["checks"]["base_platform_verified"] = platform_matches(base_index) and platform_matches(base_platform)
    result["checks"]["base_id_verified"] = (
        base_index.get("Id") == args.expected_base_image_id
        and observed_base == args.expected_base_image_id
    )
    result["base"]["verified"] = result["checks"]["base_id_verified"] and result["checks"]["base_platform_verified"]
    if not result["checks"]["base_platform_verified"]:
        result["limitations"].append("base_platform_mismatch")
        validate_receipt(result)
        return result, 2
    if not result["checks"]["base_id_verified"]:
        result["limitations"].append("base_config_id_mismatch")
        validate_receipt(result)
        return result, 2
    result["checks"]["tag_absent_before_build"] = image_reference_absent(commands, tag)
    if not result["checks"]["tag_absent_before_build"]:
        result["limitations"].append("unique_invocation_tag_already_exists")
        validate_receipt(result)
        return result, 2

    preexisting_ids = image_ids(commands)
    expected = expected_labels(args, before)
    build_succeeded = False
    iid_candidate: str | None = None

    def blocked(reason: str) -> tuple[dict[str, Any], int]:
        if reason not in result["limitations"]:
            result["limitations"].append(reason)
        result["status"] = "blocked"
        result["claims"]["build_verified"] = False
        if build_succeeded:
            cleanup_failed_build(commands, result, tag, expected, preexisting_ids, iid_candidate)
        validate_receipt(result)
        return result, 2

    temporary, context = stage_context()
    try:
        staged = input_provenance(context, context / DOCKERFILE.name)
        result["checks"]["inputs_staged"] = staged == before
        if not result["checks"]["inputs_staged"]:
            return blocked("staged_input_digest_mismatch")
        iidfile = context.parent / "built-image.id"
        build = commands.run_build(build_args(args, context, before, tag, iidfile))
        result["checks"]["build_succeeded"] = build.returncode == 0
        if build.returncode != 0:
            result["build_failure_diagnostic"] = build_failure_diagnostic(build)
            return blocked("docker_build_failed")
        build_succeeded = True
        try:
            image_id = iidfile.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            image_id = ""
        iid_candidate = image_id
        result["checks"]["iidfile_verified"] = bool(FULL_IMAGE_ID.fullmatch(image_id))
        if not result["checks"]["iidfile_verified"]:
            return blocked("build_iidfile_invalid")
        try:
            image = inspect_image(commands, image_id)
        except (RuntimeError, json.JSONDecodeError):
            return blocked("built_image_inspect_failed")
        result["image"]["full_id"] = image_id
        result["image"]["observed_os"] = image.get("Os")
        result["image"]["observed_architecture"] = image.get("Architecture")
        result["checks"]["full_image_id_inspected"] = bool(isinstance(image_id, str) and FULL_IMAGE_ID.fullmatch(image_id))
        if not result["checks"]["full_image_id_inspected"]:
            return blocked("final_image_id_not_full")
        result["checks"]["final_platform_verified"] = platform_matches(image)
        if not result["checks"]["final_platform_verified"]:
            return blocked("final_image_platform_mismatch")
        try:
            tagged = inspect_image(commands, tag)
        except (RuntimeError, json.JSONDecodeError):
            return blocked("build_tag_inspect_failed")
        result["checks"]["tag_resolved_to_full_id"] = tagged.get("Id") == image_id
        if not result["checks"]["tag_resolved_to_full_id"]:
            return blocked("build_tag_identity_mismatch")
        config = image.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        labels = labels if isinstance(labels, dict) else {}
        result["checks"]["labels_verified"] = all(labels.get(key) == value for key, value in expected.items())
        result["image"]["labels_verified"] = result["checks"]["labels_verified"]
        if not result["checks"]["labels_verified"]:
            return blocked("provenance_labels_mismatch")
        verification = verify_command(image_id, args)
        try:
            post = commands.run(verification)
        except Exception:
            return blocked("offline_read_only_post_build_verification_error")
        ok = post.returncode == 0
        result["checks"].update({"network_none_verification": ok, "read_only_verification": ok,
                                 "deps_check": ok, "versions_verified": ok, "no_post_build_hydration": ok})
        result["image"]["post_build_verified"] = ok
        try:
            after = input_provenance()
        except (OSError, RuntimeError):
            return blocked("source_input_recheck_failed")
        result["checks"]["inputs_unchanged"] = after == before
        result["checks"]["lock_unchanged"] = after["mix_lock_sha256"] == before["mix_lock_sha256"]
        if not ok:
            return blocked("offline_read_only_post_build_verification_failed")
        if not result["checks"]["inputs_unchanged"]:
            return blocked("source_input_drift_during_build")
        result["status"] = "pass"
        result["claims"]["build_verified"] = True
        result["limitations"] = [item for item in result["limitations"] if item != "runtime_validation_not_executed"]
        result["limitations"].append("runner_built_and_verified_but_runtime_validation_not_executed")
        try:
            validate_receipt(result)
        except Exception:
            return blocked("receipt_schema_validation_failed")
        return result, 0
    finally:
        temporary.cleanup()


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--base-image", required=True)
    value.add_argument("--base-platform-image", required=True)
    value.add_argument("--expected-base-image-id", required=True)
    value.add_argument("--source-sha", required=True)
    value.add_argument("--elixir-version", required=True)
    value.add_argument("--erlang-version", required=True)
    value.add_argument("--otp-release", required=True)
    value.add_argument("--alpine-version", required=True)
    value.add_argument("--hex-version", required=True)
    value.add_argument("--apk-repository-branch", required=True)
    value.add_argument("--postgresql-client-package", required=True)
    value.add_argument("--postgresql-client-package-version", required=True)
    value.add_argument("--psql-version", required=True)
    value.add_argument("--alpine-toolchain-packages", required=True)
    value.add_argument("--platform", required=True)
    value.add_argument("--expected-package-manifest-sha256", required=True)
    value.add_argument("--repository", default="tamandua/runtime-validation-runner")
    value.add_argument("--invocation-id", default=f"local-{uuid.uuid4().hex[:12]}")
    value.add_argument("--execute", action="store_true")
    value.add_argument("--output", type=Path)
    return value


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result, code = execute(args)
    except (ValueError, RuntimeError, json.JSONDecodeError) as error:
        result = {"schema_version": SCHEMA_VERSION, "profile_id": PROFILE_ID, "generated_at": now(),
                  "status": "blocked", "error": str(error),
                  "claims": {"build_verified": False, "runtime_validation_executed": False,
                             "runtime_validated": False, "byte_reproducible": False,
                             "product_ready": False, "production_validated": False,
                             "external_claim_allowed": False, "vendor_parity": False},
                  "claim_boundary": CLAIM_BOUNDARY}
        code = 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
