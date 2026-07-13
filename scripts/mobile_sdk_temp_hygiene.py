#!/usr/bin/env python3
"""Block commit-time temp/evidence/log hygiene regressions.

This guard is intentionally path/content based. It does not delete files and it
does not inspect SDK, mobile app, server, or frontend source behavior.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


try:
    from root_resolver import ROOT
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]


TEMP_DIR_NAMES = {"tmp", "temp", ".tmp", ".temp", ".tmp-mobile-sdk-evidence"}
PUBLIC_ENV_TEMPLATE_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.test.example",
}
SENSITIVE_LOG_NAME_TERMS = {
    "auth",
    "cookie",
    "credential",
    "credentials",
    "env",
    "key",
    "private",
    "secret",
    "session",
    "token",
}
SENSITIVE_CONTENT_MARKERS = {
    "authorization:",
    "bearer ",
    "client_secret",
    "cookie:",
    "password=",
    "private key",
    "refresh_token",
    "secret=",
    "session_token",
    "token=",
}
MAX_CONTENT_SCAN_BYTES = 1_000_000
LEGACY_TRACKED_ALLOWED_PATHS = {
    "apps/tamandua_server/.env.example.notifications",
    "deploy/docker/.env.secrets.example",
}


@dataclass(frozen=True)
class Finding:
    path: Path
    reason: str


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _normalize(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def staged_paths() -> list[Path]:
    completed = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.decode("utf-8", errors="replace"))
    names = [name for name in completed.stdout.decode("utf-8", errors="surrogateescape").split("\0") if name]
    return [ROOT / name for name in names]


def tracked_paths() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.decode("utf-8", errors="replace"))
    names = [name for name in completed.stdout.decode("utf-8", errors="surrogateescape").split("\0") if name]
    return [ROOT / name for name in names]


def _has_temp_sdk_mobile_part(path: Path) -> bool:
    sdk_mobile = ROOT / "sdk" / "mobile"
    if not _is_under(path, sdk_mobile):
        return False
    parts = [part.lower() for part in path.parts]
    for part in parts:
        if part in TEMP_DIR_NAMES:
            return True
        if part.startswith(".tmp-") or part.startswith("tmp-") or part.startswith("temp-"):
            return True
        if part.endswith("-tmp") or part.endswith("-temp"):
            return True
    return False


def _is_evidence_tmp(path: Path) -> bool:
    lower_name = path.name.lower()
    lower_path = str(path).replace("\\", "/").lower()
    return lower_name.endswith(".tmp") and ("evidence" in lower_name or "/evidence" in lower_path)


def _is_sensitive_log_path(path: Path) -> bool:
    if path.suffix.lower() != ".log":
        return False
    lower_name = path.name.lower()
    return any(term in lower_name for term in SENSITIVE_LOG_NAME_TERMS)


def _is_env_backup_path(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name in PUBLIC_ENV_TEMPLATE_NAMES:
        return False
    return lower_name == ".env" or lower_name.startswith(".env.") or lower_name.startswith(".env-")


def _is_root_server_frontend_tmp(path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return False
    return len(relative.parts) == 1 and relative.name.lower().startswith(".tmp-server-frontend")


def _is_legacy_tracked_exception(path: Path) -> bool:
    relative = _relative(path).replace("\\", "/")
    return relative in LEGACY_TRACKED_ALLOWED_PATHS or (
        "/" not in relative and Path(relative).name.lower().startswith(".tmp-server-frontend")
    )


def _has_sensitive_log_content(path: Path) -> bool:
    if path.suffix.lower() != ".log" or not path.exists() or not path.is_file():
        return False
    try:
        if path.stat().st_size > MAX_CONTENT_SCAN_BYTES:
            return False
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False
    return any(marker in text for marker in SENSITIVE_CONTENT_MARKERS)


def find_hygiene_findings(paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for raw_path in paths:
        path = _normalize(raw_path)
        if _has_temp_sdk_mobile_part(path):
            findings.append(Finding(path, "SDK/mobile temporary directory path must not be committed"))
        if _is_evidence_tmp(path):
            findings.append(Finding(path, "evidence .tmp artifact must not be committed"))
        if _is_sensitive_log_path(path):
            findings.append(Finding(path, "sensitive log filename must not be committed"))
        elif _has_sensitive_log_content(path):
            findings.append(Finding(path, "log content appears to include sensitive values"))
        if _is_env_backup_path(path):
            findings.append(Finding(path, "environment/secret backup file must not be committed"))
        if _is_root_server_frontend_tmp(path):
            findings.append(Finding(path, "root server frontend temporary audit artifact must not be committed"))
    return findings


def validate_paths(paths: list[Path], *, allow_legacy_tracked: bool = False) -> None:
    findings = find_hygiene_findings(paths)
    if allow_legacy_tracked:
        findings = [finding for finding in findings if not _is_legacy_tracked_exception(finding.path)]
    if not findings:
        return
    lines = ["temp/evidence/log hygiene findings:"]
    for finding in findings:
        lines.append(f"- {_relative(finding.path)}: {finding.reason}")
    raise SystemExit("\n".join(lines))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", action="append", type=Path, help="Path to check. Repeatable.")
    parser.add_argument("--staged", action="store_true", help="Check staged files from git diff --cached.")
    parser.add_argument("--tracked", action="store_true", help="Check tracked files from git ls-files.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    paths = [path if path.is_absolute() else ROOT / path for path in args.path or []]
    if args.staged:
        paths.extend(staged_paths())
    if args.tracked:
        paths.extend(tracked_paths())
    if not paths:
        paths = staged_paths()
    validate_paths(paths, allow_legacy_tracked=bool(args.tracked and not args.path and not args.staged))
    print(f"validated temp/evidence/log hygiene: {len(paths)} paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
