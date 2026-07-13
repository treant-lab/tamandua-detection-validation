from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "elixir_runtime_test_readiness_probe.py"


def load_probe():
    sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("elixir_runtime_test_readiness_probe", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_required_tests_include_mandatory_and_touched_status_tests():
    probe = load_probe()
    status_lines = [
        " M apps/tamandua_server/test/tamandua_server/agents/command_delivery_test.exs",
        " M apps/tamandua_server/test/tamandua_server/sensors/new_runtime_test.exs",
        " M apps/tamandua_server/lib/tamandua_server/agents/worker.ex",
    ]

    tests = probe.required_tests(status_lines)

    assert "apps/tamandua_server/test/tamandua_server/agents/command_delivery_test.exs" in tests
    assert "apps/tamandua_server/test/tamandua_server/agents/geofencing_test.exs" in tests
    assert (
        "apps/tamandua_server/test/tamandua_server_web/controllers/api/v1/mobile_controller_app_guard_test.exs"
        in tests
    )
    assert "apps/tamandua_server/test/tamandua_server/sensors/new_runtime_test.exs" in tests


def test_report_blocks_with_runner_required_when_mix_or_elixir_is_missing(tmp_path, monkeypatch):
    probe = load_probe()
    for test in probe.MANDATORY_TESTS:
        path = tmp_path / test
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("defmodule RuntimeReadinessTest do\nend\n", encoding="utf-8")

    monkeypatch.setattr(probe, "tool_readiness", lambda: {"mix": {"available": False, "path": None}, "elixir": {"available": False, "path": None}})
    monkeypatch.setattr(probe, "git_snapshot", lambda repo_root: {"dirty": True, "status_count": 3})

    report = probe.build_report(tmp_path, [])

    assert report["status"] == "blocked_with_runner_required"
    assert report["runner_required"] is True
    assert report["unavailable_tools"] == ["mix", "elixir"]
    assert report["missing_test_files"] == []


def test_report_blocks_missing_files_before_runner_availability(tmp_path, monkeypatch):
    probe = load_probe()
    monkeypatch.setattr(probe, "tool_readiness", lambda: {"mix": {"available": True, "path": "mix"}, "elixir": {"available": True, "path": "elixir"}})
    monkeypatch.setattr(probe, "git_snapshot", lambda repo_root: {"dirty": True, "status_count": 1})

    report = probe.build_report(tmp_path, [])

    assert report["status"] == "blocked_missing_test_files"
    assert sorted(report["missing_test_files"]) == sorted(probe.MANDATORY_TESTS)


def test_rename_status_uses_destination_path():
    probe = load_probe()

    tests = probe.touched_elixir_tests(
        [
            "R  apps/tamandua_server/test/old_test.exs -> apps/tamandua_server/test/new_test.exs",
        ]
    )

    assert tests == ["apps/tamandua_server/test/new_test.exs"]
