import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "platform_endpoint_health_bundle_probe.py"
FIXTURE = ROOT / "fixtures" / "platform_endpoint_health_api_export_v1.json"


def run_probe(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT.parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_probe_builds_live_endpoint_health_bundle_from_data_sources_export(tmp_path: Path) -> None:
    output = tmp_path / "bundle.json"

    completed = run_probe(str(FIXTURE), "--output", str(output), "--bundle-id", "test-live-bundle")

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    bundle = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "pass"
    assert bundle["bundle_id"] == "test-live-bundle"
    assert bundle["evidence_class"] == "live_endpoint_health"
    assert bundle["source_export_shape"] == "data_sources_health_export"
    assert [endpoint["endpoint_id"] for endpoint in bundle["endpoints"]] == [
        "lab-linux-endpoint-001",
        "lab-windows-endpoint-001",
    ]
    assert all(endpoint["health"]["agent_running"] is True for endpoint in bundle["endpoints"])
    assert all(endpoint["health"]["telemetry_recent"] is True for endpoint in bundle["endpoints"])
    assert all(endpoint["health"]["clock_synchronized"] is True for endpoint in bundle["endpoints"])


def test_probe_builds_live_endpoint_health_bundle_from_agent_detail_export(tmp_path: Path) -> None:
    export = tmp_path / "agent-detail.json"
    export.write_text(
        json.dumps(
            {
                "data": {
                    "id": "macos-lab-001",
                    "hostname": "macos-lab-001",
                    "os_type": "macos",
                    "status": "online",
                    "last_seen": "2026-07-15T00:00:00Z",
                    "health_status": {
                        "status": "healthy",
                        "metrics": {"clockSynchronized": True},
                    },
                    "dataSourceHealth": {
                        "sources": [
                            {
                                "source": "process",
                                "status": "healthy",
                                "count": 3,
                                "last_seen": "2026-07-15T00:00:00Z",
                            }
                        ]
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    completed = run_probe(str(export), "--bundle-id", "agent-detail-live-bundle")

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    bundle = report["bundle"]
    assert report["status"] == "pass"
    assert bundle["source_export_shape"] == "agent_detail_export"
    assert bundle["endpoints"][0]["endpoint_id"] == "macos-lab-001"
    assert bundle["endpoints"][0]["platform"] == "macos"
    assert bundle["endpoints"][0]["health"] == {
        "agent_running": True,
        "telemetry_recent": True,
        "clock_synchronized": True,
    }


def test_probe_rejects_readiness_or_synthetic_export(tmp_path: Path) -> None:
    export = tmp_path / "synthetic-export.json"
    export.write_text(
        json.dumps(
            {
                "evidence_class": "readiness_fixture",
                "data": [
                    {
                        "agentId": "fixture-only",
                        "osType": "linux",
                        "heartbeatState": "online",
                        "lastTelemetryAt": "2026-07-15T00:00:00Z",
                        "healthStatus": {
                            "status": "healthy",
                            "metrics": {"clock_synchronized": True},
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    completed = run_probe(str(export))

    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report["status"] == "fail"
    assert "input evidence_class='readiness_fixture' is not live endpoint health" in report["errors"]
