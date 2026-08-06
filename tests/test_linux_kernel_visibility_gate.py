from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from linux_kernel_visibility_gate import classify


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "detection_validation" / "scripts" / "linux_kernel_visibility_gate.py"


def aggressive_config() -> dict:
    return {
        "feature_flags": {"ebpf": True, "auditd": True},
        "collectors": {
            "ebpf_enabled": True,
            "auditd_enabled": True,
        },
    }


def active_snapshot() -> dict:
    return {
        "kernel": {"release": "5.15.0-106-generic"},
        "btf": {"available": True},
        "capabilities": {
            "is_root": False,
            "cap_bpf": True,
            "cap_perfmon": True,
        },
        "auditd": {"active": True},
    }


def test_classifies_active_when_kernel_btf_caps_flags_and_auditd_are_ready() -> None:
    result = classify(active_snapshot(), aggressive_config())

    assert result["verdict"] == "active"
    assert result["missing_required"] == []
    assert result["missing_optional"] == []


def test_classifies_degraded_when_auditd_is_missing_but_ebpf_is_ready() -> None:
    snapshot = active_snapshot()
    snapshot["auditd"] = {"active": False}

    result = classify(snapshot, aggressive_config())

    assert result["verdict"] == "degraded"
    assert result["missing_required"] == []
    assert "auditd_available" in result["missing_optional"]


def test_classifies_degraded_when_kernel_btf_and_intent_exist_without_required_privilege() -> None:
    snapshot = active_snapshot()
    snapshot["capabilities"] = {"is_root": False, "cap_bpf": True, "cap_perfmon": False}

    result = classify(snapshot, aggressive_config())

    assert result["verdict"] == "degraded"
    assert result["missing_required"] == ["cap_bpf_and_cap_perfmon_or_root"]


def test_classifies_unavailable_for_old_kernel_even_when_config_is_enabled() -> None:
    snapshot = active_snapshot()
    snapshot["kernel"] = {"release": "5.4.0"}

    result = classify(snapshot, aggressive_config())

    assert result["verdict"] == "unavailable"
    assert "kernel_minimum_5_8" in result["missing_required"]


def test_cli_reads_snapshot_and_returns_zero_only_for_active(tmp_path: Path) -> None:
    snapshot_path = tmp_path / "snapshot.json"
    config_path = tmp_path / "config.json"
    snapshot_path.write_text(json.dumps(active_snapshot()), encoding="utf-8")
    config_path.write_text(json.dumps(aggressive_config()), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--snapshot", str(snapshot_path), "--config", str(config_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    output = json.loads(completed.stdout)
    assert output["verdict"] == "active"
