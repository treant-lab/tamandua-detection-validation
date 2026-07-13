from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "server_release_build_readonly_probe.py"


def load_probe():
    sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("server_release_build_readonly_probe", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def base_report() -> dict:
    return {
        "active_build_processes": [],
        "candidate_images": {
            "product-lab-test": {
                "id": {"returncode": 1, "stdout": "", "stderr": "No such image"},
                "created": {"returncode": 1, "stdout": "", "stderr": "No such image"},
            }
        },
        "live_container": {
            "image": {"stdout": "docker_server:latest"},
            "state": {"stdout": "running"},
            "oom_killed": {"stdout": "false"},
        },
        "docker_ps": {"stdout": "tamandua-server-light mix phx.server"},
        "recent_kill_evidence": {
            "docker_journal_matches": [],
            "kernel_journal_matches": [],
            "docker_event_matches": [],
        },
        "health": {"ok": True},
        "listeners": [{"open": True}, {"open": True}],
    }


def test_summary_recommends_clean_runner_after_dead_137_build():
    probe = load_probe()
    report = base_report()
    report["recent_kill_evidence"]["docker_event_matches"] = [
        "docker build product-lab-test exited with code 137 during mix deps.compile"
    ]

    summary = probe.summarize(report)

    assert summary["candidate_release_image_missing"] is True
    assert summary["active_build_detected"] is False
    assert summary["release_build_dead_by_137"] is True
    assert summary["classifications"]["candidate_present"]["status"] == "blocked"
    assert summary["classifications"]["candidate_present"]["present"] is False
    assert summary["classifications"]["active_build"]["status"] == "ok"
    assert summary["classifications"]["active_build"]["present"] is False
    assert summary["classifications"]["source_runtime_healthy"]["status"] == "degraded"
    assert summary["classifications"]["source_runtime_healthy"]["present"] is True
    assert summary["classifications"]["release_build_dead_by_137_or_sigkill"]["status"] == "blocked"
    assert summary["classifications"]["release_build_dead_by_137_or_sigkill"]["present"] is True
    assert summary["clean_runner_recommended"] is True
    assert summary["retry_local_recommended"] is False
    assert "release_build_dead_by_137_or_sigkill" in summary["blockers"]
    assert summary["next_action"] == "move_build_to_clean_runner_or_more_memory_before_retrying_local_host"


def test_summary_distinguishes_active_build_from_dead_137():
    probe = load_probe()
    report = base_report()
    report["active_build_processes"] = ["123 docker build docker_server:product-lab-test"]

    summary = probe.summarize(report)

    assert summary["active_build_detected"] is True
    assert summary["release_build_dead_by_137"] is False
    assert summary["classifications"]["active_build"]["status"] == "blocked"
    assert summary["classifications"]["active_build"]["present"] is True
    assert summary["classifications"]["release_build_dead_by_137_or_sigkill"]["status"] == "ok"
    assert summary["classifications"]["release_build_dead_by_137_or_sigkill"]["present"] is False
    assert summary["clean_runner_recommended"] is False
    assert summary["retry_local_recommended"] is False
    assert summary["next_action"] == "build_active_wait_or_monitor_do_not_retry_or_retag_concurrently"


def test_summary_distinguishes_missing_image_with_healthy_source_runtime():
    probe = load_probe()
    summary = probe.summarize(base_report())

    assert summary["candidate_release_image_missing"] is True
    assert summary["live_container_source_runtime"] is True
    assert summary["live_container_source_runtime_healthy"] is True
    assert summary["live_health_ok"] is True
    assert summary["listeners_ok"] is True
    assert summary["classifications"]["candidate_present"]["status"] == "blocked"
    assert summary["classifications"]["source_runtime_healthy"]["status"] == "degraded"
    assert summary["classifications"]["source_runtime_healthy"]["present"] is True
    assert summary["clean_runner_recommended"] is True
    assert summary["next_action"] == "no_candidate_but_source_runtime_healthy_start_release_build_on_clean_runner"


def test_summary_classifies_present_candidate_before_retry_guidance():
    probe = load_probe()
    report = base_report()
    report["candidate_images"]["product-lab-test"]["id"]["returncode"] = 0
    report["candidate_images"]["product-lab-test"]["id"]["stdout"] = "sha256:test"

    summary = probe.summarize(report)

    assert summary["candidate_release_images_ready"] == ["product-lab-test"]
    assert summary["classifications"]["candidate_present"]["status"] == "ok"
    assert summary["classifications"]["candidate_present"]["present"] is True
    assert summary["next_action"] == "candidate_image_present_run_release_image_probe_or_smoke_before_any_promotion"


def test_default_output_dir_uses_untracked_tmp_path():
    probe = load_probe()

    args = probe.build_parser().parse_args([])

    assert args.output_dir == probe.DEFAULT_OUTPUT_DIR
    assert "docs" not in args.output_dir.parts
    assert "benchmarks" not in args.output_dir.parts
    assert "runs" not in args.output_dir.parts
