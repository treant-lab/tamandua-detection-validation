import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "platform_visibility_gate.py"


def run_gate(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT.parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_platform_visibility_gate_runs_all_default_gates() -> None:
    completed = run_gate()

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["kind"] == "PlatformVisibilityGate"
    assert summary["status"] == "pass"
    assert summary["checked_platforms"] == ["linux", "windows", "macos", "mobile"]
    assert summary["failed_platforms"] == []
    assert {result["platform"] for result in summary["results"]} == {
        "linux",
        "windows",
        "macos",
        "mobile",
    }
    assert summary["endpoint_health_evidence"]["status"] == "not_provided"
    assert summary["endpoint_health_evidence"]["evidence_class"] == "none"


def test_platform_visibility_gate_can_run_single_platform() -> None:
    completed = run_gate("--platform", "mobile")

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["status"] == "pass"
    assert summary["checked_platforms"] == ["mobile"]
    assert summary["results"][0]["kind"] == "MobileNetworkVisibilityReadinessGate"


def test_platform_visibility_gate_surfaces_linux_degraded_snapshot(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot.json"
    config = tmp_path / "config.json"
    snapshot.write_text(
        json.dumps(
            {
                "kernel": {"release": "6.8.0"},
                "btf": {"available": True},
                "capabilities": {"is_root": False},
                "auditd": {"active": True},
            }
        ),
        encoding="utf-8",
    )
    config.write_text(
        json.dumps(
            {
                "feature_flags": {"ebpf": True, "auditd": True},
                "collectors": {"ebpf_enabled": True, "auditd_enabled": True},
            }
        ),
        encoding="utf-8",
    )

    completed = run_gate(
        "--platform",
        "linux",
        "--linux-snapshot",
        str(snapshot),
        "--linux-config",
        str(config),
    )

    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    assert summary["status"] == "fail"
    assert summary["failed_platforms"] == ["linux"]
    assert summary["results"][0]["status"] == "degraded"


def test_platform_visibility_gate_accepts_live_endpoint_health_bundle() -> None:
    fixture = ROOT / "fixtures" / "platform_endpoint_health_live_bundle_v1.json"

    completed = run_gate("--endpoint-health-bundle", str(fixture))

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    endpoint_health = summary["endpoint_health_evidence"]
    assert summary["status"] == "pass"
    assert endpoint_health["status"] == "pass"
    assert endpoint_health["evidence_class"] == "live_endpoint_health"
    assert endpoint_health["checked_endpoints"] == 2
    assert endpoint_health["failed_endpoints"] == []


def test_platform_visibility_gate_builds_bundle_from_endpoint_health_export() -> None:
    fixture = ROOT / "fixtures" / "platform_endpoint_health_api_export_v1.json"

    completed = run_gate("--endpoint-health-export", str(fixture))

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    endpoint_health = summary["endpoint_health_evidence"]
    assert summary["status"] == "pass"
    assert endpoint_health["status"] == "pass"
    assert endpoint_health["source_export"] == str(fixture)
    assert endpoint_health["evidence_class"] == "live_endpoint_health"
    assert endpoint_health["generated_bundle"]["source_export_shape"] == "data_sources_health_export"
    assert endpoint_health["checked_endpoints"] == 2


def test_platform_visibility_gate_rejects_synthetic_readiness_as_live_endpoint_health(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "synthetic-health.json"
    bundle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "bundle_id": "synthetic-readiness-is-not-live",
                "evidence_class": "synthetic_parity",
                "claim_boundary": "Synthetic readiness fixture only.",
                "endpoints": [
                    {
                        "endpoint_id": "fixture-only",
                        "platform": "linux",
                        "collected_at": "2026-07-15T00:00:00Z",
                        "source": "agent_cli_health",
                        "health": {
                            "agent_running": True,
                            "telemetry_recent": True,
                            "clock_synchronized": True,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    completed = run_gate("--endpoint-health-bundle", str(bundle))

    assert completed.returncode == 1
    summary = json.loads(completed.stdout)
    endpoint_health = summary["endpoint_health_evidence"]
    assert summary["status"] == "fail"
    assert endpoint_health["status"] == "fail"
    assert endpoint_health["evidence_class"] == "synthetic_parity"
    assert "synthetic readiness evidence cannot satisfy live endpoint health" in endpoint_health["errors"]
