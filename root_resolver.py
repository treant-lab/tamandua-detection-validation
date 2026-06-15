#!/usr/bin/env python3
"""
Root resolver for detection_validation scripts.

Handles both monorepo and standalone mirror operation:
- Monorepo: tools/detection_validation/ is 2 levels deep → ROOT = parents[2]
- Standalone: scripts are at repo root → ROOT = script dir or cwd

Usage:
    from root_resolver import ROOT, RUNS_DIR, DOCS_DIR, get_component_path

    # ROOT is the monorepo or deployment root
    # RUNS_DIR is docs/benchmarks/runs (relative to ROOT)
    # get_component_path("apps/tamandua_server") returns the server path
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["ROOT", "RUNS_DIR", "DOCS_DIR", "GENERATED_DIR", "get_component_path", "is_standalone"]

# Marker files that indicate monorepo root
MONOREPO_MARKERS = {"Makefile", "ROADMAP.md", "apps", "libs", "tools"}

# Marker files that indicate standalone detection-validation root
STANDALONE_MARKERS = {"profiles", "fixtures", "run_atomic_upstream_harness.py", "tamandua_detection_validation.py"}


def _find_root() -> tuple[Path, bool]:
    """Find root directory and determine if standalone.

    Returns:
        (root_path, is_standalone_mode)
    """
    # 1. Environment variable override (explicit deployment root)
    env_root = os.environ.get("TAMANDUA_ROOT")
    if env_root:
        return Path(env_root).resolve(), False

    # 2. Try to detect based on script location
    script_dir = Path(__file__).resolve().parent

    # Check if we're in monorepo (parents[2] has monorepo markers)
    try:
        monorepo_root = script_dir.parents[1]  # tools/detection_validation → tools → monorepo
        if all((monorepo_root / m).exists() for m in ["Makefile", "apps"]):
            return monorepo_root, False
    except IndexError:
        pass

    # Check if we're standalone (script_dir has standalone markers)
    if all((script_dir / m).exists() for m in ["profiles", "fixtures"]):
        return script_dir, True

    # 3. Fallback to environment variable for external deployments
    env_root = os.environ.get("TAMANDUA_DEPLOYMENT_ROOT")
    if env_root:
        return Path(env_root).resolve(), True

    # 4. Final fallback: assume monorepo layout from script location
    return script_dir.parents[1], False


ROOT, _IS_STANDALONE = _find_root()

# Standard directories
if _IS_STANDALONE:
    # Standalone: runs/ is local, no docs/benchmarks hierarchy
    RUNS_DIR = ROOT / "runs"
    DOCS_DIR = ROOT / "docs"
    GENERATED_DIR = ROOT / "generated"
else:
    # Monorepo: standard paths
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    DOCS_DIR = ROOT / "docs" / "benchmarks"
    GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"


def is_standalone() -> bool:
    """Check if running in standalone mode."""
    return _IS_STANDALONE


def get_component_path(component: str) -> Path:
    """Get path to a component, handling monorepo vs standalone.

    Args:
        component: Component path like "apps/tamandua_server" or "libs/tamandua-core"

    Returns:
        Resolved path to the component.

    Raises:
        FileNotFoundError: If component not found and not in deployment mode.
    """
    if _IS_STANDALONE:
        # In standalone mode, components are external
        # Check TAMANDUA_DEPLOYMENT_ROOT or environment for component paths
        env_key = f"TAMANDUA_{component.split('/')[-1].upper().replace('-', '_')}_PATH"
        env_path = os.environ.get(env_key)
        if env_path:
            return Path(env_path).resolve()

        # Try relative to deployment root
        deploy_root = os.environ.get("TAMANDUA_DEPLOYMENT_ROOT")
        if deploy_root:
            candidate = Path(deploy_root) / component
            if candidate.exists():
                return candidate.resolve()

        # Standalone probes may not need component paths (API-only checks)
        # Return a placeholder that will fail gracefully
        return ROOT / component

    # Monorepo: direct path
    return ROOT / component


# Ensure directories exist for writes
def ensure_runs_dir() -> Path:
    """Ensure RUNS_DIR exists and return it."""
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    return RUNS_DIR


def ensure_generated_dir() -> Path:
    """Ensure GENERATED_DIR exists and return it."""
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    return GENERATED_DIR
