#!/usr/bin/env python3
"""
Atomic Upstream Harness - Run Atomic Red Team tests via tamandua-ctl.

This harness uses tamandua-ctl's live-response feature to execute Atomic tests
on remote agents and verify detection coverage.

PREREQUISITES:
  1. tamandua-ctl binary built:
     cd apps/tamandua_ctl && cargo build --release

  2. Backend token configured (one of):
     - Set TAMANDUA_TOKEN environment variable
     - Run: tamandua-ctl remote login

  3. Invoke-AtomicTest installed on target VM:
     PowerShell: IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

USAGE:
  # Dry-run (default) - shows what would execute
  python run_atomic_upstream_harness.py --agent-id <agent-uuid>

  # Execute tests
  python run_atomic_upstream_harness.py --agent-id <agent-uuid> --execute

  # With explicit token
  python run_atomic_upstream_harness.py --agent-id <agent-uuid> --token <token> --execute

PROFILES:
  - windows_atomic_upstream_smoke (default): 8 safe discovery/execution tests
  - windows_atomic_core_coverage: Extended test coverage
  - windows_atomic_detection_smoke: Detection-focused tests
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    from root_resolver import ROOT, is_standalone, get_component_path
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    is_standalone = lambda: False
    get_component_path = lambda p: ROOT / p

if is_standalone():
    CTL_PATH = Path(os.environ.get("TAMANDUA_CTL_PATH", "tamandua-ctl.exe"))
    PROFILE_DIR = Path(__file__).parent / "profiles"
    VALIDATION_SCRIPT = Path(__file__).parent / "tamandua_detection_validation.py"
else:
    CTL_PATH = get_component_path("apps/tamandua_ctl") / "target" / "release" / "tamandua-ctl.exe"
    PROFILE_DIR = ROOT / "tools" / "detection_validation" / "profiles"
    VALIDATION_SCRIPT = ROOT / "tools" / "detection_validation" / "tamandua_detection_validation.py"

DEFAULT_PROFILE = "windows_atomic_upstream_smoke"
DEFAULT_SERVER = "https://tamandua.treantlab.org"


def check_prerequisites() -> list[str]:
    """Check all prerequisites and return list of issues."""
    issues = []

    # Check tamandua-ctl binary
    if not CTL_PATH.exists():
        issues.append(f"tamandua-ctl not found at {CTL_PATH}")
        issues.append("  Run: cd apps/tamandua_ctl && cargo build --release")

    # Check validation script
    if not VALIDATION_SCRIPT.exists():
        issues.append(f"Validation script not found at {VALIDATION_SCRIPT}")

    # Check profile directory
    if not PROFILE_DIR.exists():
        issues.append(f"Profile directory not found at {PROFILE_DIR}")

    return issues


def get_available_profiles() -> list[str]:
    """List available atomic profiles."""
    profiles = []
    if PROFILE_DIR.exists():
        for p in PROFILE_DIR.glob("windows_atomic*.json"):
            profiles.append(p.stem)
    return sorted(profiles)


def check_agent_id(agent_id: str | None, server: str, token: str | None) -> dict:
    """Check if agent ID is valid and online."""
    if not agent_id:
        return {"ok": False, "error": "No agent ID provided"}

    if not CTL_PATH.exists():
        return {"ok": False, "error": "tamandua-ctl not found"}

    cmd = [str(CTL_PATH), "--json", "remote", "agents", "list"]
    if server:
        cmd.extend(["--server", server])
    if token:
        cmd.extend(["--token", token])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            env={**os.environ, "NO_PROXY": "*", "no_proxy": "*"}
        )
        if result.returncode != 0:
            return {"ok": False, "error": result.stderr or "Failed to list agents"}

        data = json.loads(result.stdout)
        agents = data if isinstance(data, list) else data.get("agents", [])

        for agent in agents:
            if agent.get("agent_id") == agent_id or agent.get("id") == agent_id:
                return {
                    "ok": True,
                    "agent": agent,
                    "status": agent.get("status", "unknown"),
                    "hostname": agent.get("hostname", "unknown"),
                }

        return {"ok": False, "error": f"Agent {agent_id} not found in {len(agents)} agents"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Timeout connecting to server"}
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"Invalid JSON response: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def run_validation(args: argparse.Namespace) -> int:
    """Run the detection validation with specified profile."""
    profile_path = PROFILE_DIR / f"{args.profile}.json"
    if not profile_path.exists():
        print(f"ERROR: Profile not found: {profile_path}", file=sys.stderr)
        return 1

    cmd = [
        sys.executable, str(VALIDATION_SCRIPT),
        "--profile", str(profile_path),
        "--execution-transport", "tamandua-ctl",
        "--agent-id", args.agent_id,
        "--tamandua-ctl-path", str(CTL_PATH),
    ]

    if args.server:
        cmd.extend(["--tamandua-ctl-server", args.server])
    if args.token:
        cmd.extend(["--tamandua-ctl-token", args.token])
    if args.execute:
        cmd.append("--execute")
    if args.require_upstream:
        cmd.append("--require-upstream")
    if args.output_dir:
        cmd.extend(["--output-dir", args.output_dir])
    # Note: validation script doesn't support -v flag, use env var for trace
    if args.verbose:
        os.environ["TAMANDUA_VALIDATION_TRACE"] = "1"

    print(f"\n{'='*60}")
    print("RUNNING ATOMIC UPSTREAM HARNESS")
    print(f"{'='*60}")
    print(f"Profile: {args.profile}")
    print(f"Agent:   {args.agent_id}")
    print(f"Mode:    {'EXECUTE' if args.execute else 'DRY-RUN'}")
    print(f"{'='*60}\n")

    if not args.execute:
        print("DRY-RUN MODE: Use --execute to run actual tests\n")

    env = {**os.environ, "NO_PROXY": "*", "no_proxy": "*"}
    if args.token:
        env["TAMANDUA_TOKEN"] = args.token

    result = subprocess.run(cmd, env=env)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Atomic Red Team tests via tamandua-ctl live-response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--agent-id", "-a",
        default=os.getenv("TAMANDUA_TARGET_AGENT_ID"),
        help="Target agent UUID (env: TAMANDUA_TARGET_AGENT_ID)",
    )
    parser.add_argument(
        "--profile", "-p",
        default=DEFAULT_PROFILE,
        help=f"Test profile name (default: {DEFAULT_PROFILE})",
    )
    parser.add_argument(
        "--server", "-s",
        default=os.getenv("TAMANDUA_CTL_SERVER") or os.getenv("TAMANDUA_SERVER") or DEFAULT_SERVER,
        help=f"Tamandua server URL (default: {DEFAULT_SERVER})",
    )
    parser.add_argument(
        "--token", "-t",
        default=os.getenv("TAMANDUA_CTL_TOKEN") or os.getenv("TAMANDUA_TOKEN"),
        help="Operator token (env: TAMANDUA_TOKEN)",
    )
    parser.add_argument(
        "--execute", "-x",
        action="store_true",
        help="Actually execute tests (default: dry-run)",
    )
    parser.add_argument(
        "--require-upstream",
        action="store_true",
        help="Fail if tests fall back to deterministic commands",
    )
    parser.add_argument(
        "--output-dir", "-o",
        help="Output directory for results",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only check prerequisites, don't run tests",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available profiles",
    )

    args = parser.parse_args()

    # List profiles
    if args.list_profiles:
        print("Available atomic profiles:")
        for profile in get_available_profiles():
            marker = " (default)" if profile == DEFAULT_PROFILE else ""
            print(f"  - {profile}{marker}")
        return 0

    # Check prerequisites
    issues = check_prerequisites()
    if issues:
        print("PREREQUISITE ISSUES:", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        if args.check_only:
            return 1

    # Check agent ID requirement
    if not args.agent_id:
        print("\nERROR: --agent-id is required", file=sys.stderr)
        print("\nKnown agents from recent sessions:", file=sys.stderr)
        print("  WIN-TEMPLATE: cb145360-8ba8-475a-bfd6-2bc16d5281d7", file=sys.stderr)
        return 1

    # Check agent connectivity
    if args.token or args.check_only:
        print("\nChecking agent connectivity...")
        check = check_agent_id(args.agent_id, args.server, args.token)
        if check.get("ok"):
            print(f"  Agent: {check.get('hostname', 'unknown')}")
            print(f"  Status: {check.get('status', 'unknown')}")
        else:
            print(f"  Warning: {check.get('error', 'Unknown error')}")
            if args.check_only:
                return 1

    if args.check_only:
        print("\nPrerequisites OK!")
        return 0

    # Run validation
    return run_validation(args)


if __name__ == "__main__":
    sys.exit(main())
