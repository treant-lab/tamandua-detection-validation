from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "plugins_bof_static_readiness_probe.py"


def load_probe():
    sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("plugins_bof_static_readiness_probe", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_static_probe_contract_passes_current_boundary():
    probe = load_probe()
    tests = [probe.check_item(item) for item in probe.CHECKS]
    summary = probe.build_summary(tests)

    assert summary["missed"] == 0
    assert summary["covered"] == len(probe.CHECKS)
    assert probe.scorecard(summary)["external_claim_allowed"] is False


def test_probe_never_requires_runtime_execution():
    probe = load_probe()

    assert "runtime execution is not production-ready" in probe.scorecard(
        {"covered": 1, "tests": 1, "missed": 0}
    )["recommended_claim"]
