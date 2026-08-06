#!/usr/bin/env python3
"""Generate or validate an offline, privacy-safe iOS APNs categorical receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "schemas/ios_native_apns_categorical_receipt_v1.schema.json"
GOVERNED_RUNS_DIR = ROOT / "docs/benchmarks/runs"
OBSERVATION_KEYS = {"outcome", "permission", "token_type", "token_present", "token_length_bucket"}
CLAIMS = {key: False for key in (
    "token_valid", "apns_delivery", "expo_token", "backend_registration", "token_rotation",
    "cold_start_routing", "production_apns", "distribution", "release_ready", "external_claim_allowed"
)}
FORBIDDEN_CATEGORY_TERMS = {"id", "identifier", "token", "hash", "sha", "path", "account", "device"}


class ContractError(ValueError):
    pass


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ContractError("symlink_component_rejected")


def safe_output(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise ContractError("absolute_non_traversing_output_required")
    resolved = path.resolve(strict=False)
    if resolved == Path("/tmp") or Path("/tmp") in resolved.parents or resolved == Path("/private/tmp") or Path("/private/tmp") in resolved.parents:
        raise ContractError("temporary_output_rejected")
    reject_symlink_components(path)
    if not path.parent.is_dir() or path.parent.resolve() != GOVERNED_RUNS_DIR.resolve():
        raise ContractError("output_parent_missing")
    if not re.fullmatch(r"ios-native-apns-categorical-[0-9]{8}T[0-9]{6}Z\.json", path.name):
        raise ContractError("output_filename_rejected")
    return path


def clean_source_sha(root: Path = ROOT) -> str:
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, text=True, capture_output=True, check=True)
    if status.stdout:
        raise ContractError("dirty_source_rejected")
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip().lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise ContractError("source_sha_invalid")
    return sha


def read_regular_file(path: Path, category: str, max_bytes: int, require_executable: bool = False) -> bytes:
    reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ContractError(category) from None
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1
                or metadata.st_size > max_bytes
                or (require_executable and metadata.st_mode & 0o111 == 0)):
            raise ContractError(category)
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes - total + 1))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > max_bytes:
                raise ContractError(category)
            chunks.append(chunk)
    finally:
        os.close(descriptor)


def read_observation(path: Path) -> dict:
    value = json.loads(read_regular_file(path, "observation_file_rejected", 16 * 1024).decode("utf-8"))
    if not isinstance(value, dict) or set(value) != OBSERVATION_KEYS:
        raise ContractError("observation_fields_rejected")
    return value


def digest_file(path: Path) -> str:
    payload = read_regular_file(
        path, "app_executable_rejected", 512 * 1024 * 1024,
        require_executable=True,
    )
    macho_magics = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
    if payload[:4] not in macho_magics:
        raise ContractError("app_executable_rejected")
    return hashlib.sha256(payload).hexdigest()


def validate_receipt(value: dict) -> None:
    jsonschema.validate(value, schema(), format_checker=jsonschema.FormatChecker())
    for category in (value["device"]["model_category"], value["device"]["os_build_category"]):
        if FORBIDDEN_CATEGORY_TERMS.intersection(category.split("_")):
            raise ContractError("privacy_unsafe_category_rejected")
    obs = value["observation"]
    present = obs["token_present"]
    coherent = {
        "token_present": present and obs["permission"] == "granted" and obs["token_type"] == "ios" and obs["token_length_bucket"] != "none",
        "token_absent": not present and obs["permission"] == "granted" and obs["token_type"] == "unknown" and obs["token_length_bucket"] == "none",
        "permission_not_granted": not present and obs["permission"] in ("denied", "undetermined") and obs["token_type"] == "unknown" and obs["token_length_bucket"] == "none",
        "error": not present and obs["permission"] in ("granted", "unknown") and obs["token_type"] == "unknown" and obs["token_length_bucket"] == "none",
    }[obs["outcome"]]
    if not coherent:
        raise ContractError("observation_categories_incoherent")
    unsigned = dict(value)
    claimed = unsigned.pop("manifest_sha256")
    actual = hashlib.sha256(canonical(unsigned)).hexdigest()
    if claimed != actual:
        raise ContractError("manifest_digest_mismatch")


def generate(args: argparse.Namespace) -> dict:
    output = safe_output(Path(args.output))
    observation = read_observation(Path(args.observation))
    value = {
        "schema_version": "tamandua.ios_native_apns_categorical_receipt/v1",
        "run_id": str(uuid.uuid4()),
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source": {"clean": True, "sha": clean_source_sha()},
        "app": {"executable_sha256": digest_file(Path(args.app_executable)), "configuration": "Debug", "signing_identity_class": "apple_development", "apns_environment": "development"},
        "device": {"physical": True, "model_category": args.model_category, "os_build_category": args.os_build_category},
        "diagnostic": {"flag": "EXPO_PUBLIC_TAMANDUA_IOS_NATIVE_APNS_DIAGNOSTIC=1"},
        "observation": observation,
        "receipt_signature_present": False,
        "claims": dict(CLAIMS),
    }
    value["manifest_sha256"] = hashlib.sha256(canonical(value)).hexdigest()
    validate_receipt(value)
    directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        try:
            payload = canonical(value)
            written = 0
            while written < len(payload):
                count = os.write(fd, payload[written:])
                if count <= 0:
                    raise OSError("receipt_write_failed")
                written += count
            os.fsync(fd)
        except Exception:
            os.unlink(output.name, dir_fd=directory_fd)
            raise
        finally:
            os.close(fd)
        try:
            os.fsync(directory_fd)
        except Exception as publish_error:
            cleanup_error = None
            try:
                os.unlink(output.name, dir_fd=directory_fd)
            except Exception as error:
                cleanup_error = error
            try:
                os.fsync(directory_fd)
            except Exception:
                pass
            if cleanup_error is not None:
                raise ContractError("receipt_cleanup_failed") from None
            raise publish_error
    finally:
        os.close(directory_fd)
    return value


def validate_file(path: Path) -> dict:
    value = json.loads(read_regular_file(path, "receipt_file_rejected", 64 * 1024).decode("utf-8"))
    validate_receipt(value)
    return value


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--observation", required=True); g.add_argument("--app-executable", required=True)
    g.add_argument("--model-category", required=True); g.add_argument("--os-build-category", required=True); g.add_argument("--output", required=True)
    v = sub.add_parser("validate"); v.add_argument("receipt")
    return p


def main() -> int:
    try:
        args = parser().parse_args()
        value = generate(args) if args.command == "generate" else validate_file(Path(args.receipt))
        print(json.dumps({"status": "valid", "run_id": value["run_id"], "manifest_sha256": value["manifest_sha256"]}, sort_keys=True))
        return 0
    except (ContractError, UnicodeDecodeError, json.JSONDecodeError, jsonschema.ValidationError, OSError, subprocess.SubprocessError):
        print("invalid: contract_rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
