#!/usr/bin/env python3
"""Readiness probe for Elixir runtime tests that require a Mix runner.

This probe is intentionally static. It does not install Elixir, run Mix, start
Phoenix, touch the database, or execute the Elixir test suite. Its purpose is
to emit the exact test files that must be run on an Elixir-capable runner for
the current dirty server worktree.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"


PROFILE_ID = "elixir-runtime-test-readiness-probe"
PROFILE_NAME = "Elixir Runtime Test Readiness Probe"

MANDATORY_TESTS = [
    "apps/tamandua_server/test/tamandua_server/agents/command_delivery_test.exs",
    "apps/tamandua_server/test/tamandua_server/agents/geofencing_test.exs",
    "apps/tamandua_server/test/tamandua_server_web/controllers/api/v1/mobile_controller_app_guard_test.exs",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_repo_path(path: str) -> str:
    return path.replace("\\", "/").strip()


def run_git_status(repo_root: Path) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "status", "--short", "--", "apps/tamandua_server/test"],
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return []
    if completed.returncode != 0:
        return []
    return [line for line in completed.stdout.splitlines() if line.strip()]


def touched_elixir_tests(status_lines: list[str]) -> list[str]:
    tests: set[str] = set()
    for line in status_lines:
        if len(line) < 4:
            continue
        path = normalize_repo_path(line[3:])
        if " -> " in path:
            path = normalize_repo_path(path.split(" -> ", 1)[1])
        if path.startswith("apps/tamandua_server/test/") and path.endswith("_test.exs"):
            tests.add(path)
    return sorted(tests)


def required_tests(status_lines: list[str] | None = None) -> list[str]:
    discovered = touched_elixir_tests(status_lines if status_lines is not None else run_git_status(ROOT))
    return sorted(set(MANDATORY_TESTS).union(discovered))


def tool_readiness() -> dict[str, dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {}
    for name in ["mix", "elixir"]:
        path = shutil.which(name)
        tools[name] = {"available": bool(path), "path": path}
    return tools


def test_entries(repo_root: Path, tests: list[str]) -> list[dict[str, Any]]:
    entries = []
    for test in tests:
        exists = (repo_root / test).exists()
        entries.append(
            {
                "path": test,
                "exists": exists,
                "runner_command": f"mix test {test.removeprefix('apps/tamandua_server/')}",
                "absolute_runner_command": f"cd apps/tamandua_server && mix test {test.removeprefix('apps/tamandua_server/')}",
            }
        )
    return entries


def git_snapshot(repo_root: Path) -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args,
                cwd=repo_root,
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
        "status_count": len(status),
    }


def build_report(repo_root: Path = ROOT, status_lines: list[str] | None = None) -> dict[str, Any]:
    status_lines = run_git_status(repo_root) if status_lines is None else status_lines
    tests = required_tests(status_lines)
    tools = tool_readiness()
    entries = test_entries(repo_root, tests)
    missing = [entry["path"] for entry in entries if not entry["exists"]]
    unavailable = [name for name, info in tools.items() if not info["available"]]

    if missing:
        status = "blocked_missing_test_files"
    elif unavailable:
        status = "blocked_with_runner_required"
    else:
        status = "ready_to_run_on_local_runner"

    commands = [entry["absolute_runner_command"] for entry in entries]
    return {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "profile_name": PROFILE_NAME,
        "generated_at": utc_now(),
        "status": status,
        "git": git_snapshot(repo_root),
        "tools": tools,
        "mandatory_tests": MANDATORY_TESTS,
        "touched_tests_from_status": touched_elixir_tests(status_lines),
        "required_tests": entries,
        "missing_test_files": missing,
        "runner_required": bool(unavailable),
        "unavailable_tools": unavailable,
        "runner_workdir": "apps/tamandua_server",
        "runner_commands": commands,
        "claim_boundary": (
            "Static readiness only. This report identifies Elixir tests that must run on a Mix/Elixir runner; "
            "it does not compile Elixir code, validate migrations, start services, or prove runtime behavior."
        ),
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        f"# {PROFILE_NAME}",
        "",
        f"- Status: `{report['status']}`",
        f"- Mix available: `{report['tools']['mix']['available']}`",
        f"- Elixir available: `{report['tools']['elixir']['available']}`",
        f"- Runner workdir: `{report['runner_workdir']}`",
        "",
        "## Required Tests",
        "",
        "| Test | Exists | Runner command |",
        "| --- | --- | --- |",
    ]
    for entry in report["required_tests"]:
        lines.append(f"| `{entry['path']}` | `{entry['exists']}` | `{entry['absolute_runner_command']}` |")
    lines.extend(["", "## Boundary", "", report["claim_boundary"]])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_outputs(output_dir: Path, report: dict[str, Any]) -> tuple[Path, Path]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{PROFILE_ID}"
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    return json_path, md_path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=None, help="Write JSON/Markdown report to this directory.")
    parser.add_argument("--no-write", action="store_true", help="Only print the summary; do not write report files.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    report = build_report(ROOT)
    print(f"{PROFILE_ID}={report['status']}")
    print(f"required_tests={len(report['required_tests'])}")
    for entry in report["required_tests"]:
        print(f"- {entry['path']}")
    if report["unavailable_tools"]:
        print(f"runner_required=missing {','.join(report['unavailable_tools'])}")
    if report["missing_test_files"]:
        print(f"missing_test_files={','.join(report['missing_test_files'])}")
    if not args.no_write:
        json_path, md_path = write_outputs(args.output_dir or RUNS_DIR, report)
        print(f"json={json_path}")
        print(f"markdown={md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
