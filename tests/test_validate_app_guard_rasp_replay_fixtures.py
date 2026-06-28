import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_replay_fixtures.py"
FIXTURE = ROOT / "fixtures" / "app_guard_rasp_replay_v1.json"
BROWSER_FIXTURE = ROOT / "fixtures" / "browser_guard_rasp_replay_v1.json"


def test_app_guard_rasp_replay_fixture_validates():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture-dir", str(FIXTURE.parent)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "validated" in completed.stdout


def test_default_replay_fixture_dir_validates_from_repo_root():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "validated" in completed.stdout


def test_app_guard_rasp_replay_fixture_preserves_privacy_and_projection_contracts():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert data["schema"] == "tamandua.detection_validation.app_guard_rasp_replay/v1"
    assert "live backend ingestion" in data["claim_boundary"]
    assert "physical-device collection" in data["claim_boundary"]

    fixtures = {item["id"]: item for item in data["fixtures"]}
    network = fixtures["rasp-network-exfiltration-step-up"]
    tamper = fixtures["rasp-browser-tamper-observe"]

    assert network["input"]["evidence"]["privacy_mode"] == "metadata_only"
    assert network["input"]["evidence"]["network"]["host_hash"].startswith("sha256:")
    assert network["expected"]["alert"]["recommended_action"] == "step_up_auth"
    assert network["expected"]["server"]["must_not_500"] is True

    assert tamper["input"]["evidence"]["tamper"]["content_sampled"] is False
    assert tamper["expected"]["alert"]["recommended_action"] is None
    assert tamper["expected"]["timeline"]["must_preserve_active_signals"] is True


def test_browser_guard_rasp_replay_fixture_covers_direct_reuse_taxonomy():
    data = json.loads(BROWSER_FIXTURE.read_text(encoding="utf-8"))
    assert data["schema"] == "tamandua.detection_validation.app_guard_rasp_replay/v1"
    assert "browser-extension packaging" in data["claim_boundary"]
    assert "native Android/iOS collector behavior" in data["claim_boundary"]

    fixtures = {item["id"]: item for item in data["fixtures"]}
    assert set(fixtures) == {
        "browser-guard-anti-debug-warn",
        "browser-guard-anti-tamper-block",
        "browser-guard-integrity-drift-observe",
        "browser-guard-service-worker-persistence-step-up",
        "browser-guard-suspicious-network-step-up",
        "browser-guard-behavior-anomaly-kill-session",
    }

    event_types = {item["input"]["event_type"] for item in fixtures.values()}
    assert event_types == {
        "debugger_detected",
        "browser_tamper_detected",
        "integrity_snapshot_changed",
        "network_exfiltration_suspected",
        "behavior_anomaly_detected",
    }

    actions = {item["expected"]["alert"]["recommended_action"] for item in fixtures.values()}
    assert actions == {None, "block_mobile_workflow", "step_up_auth", "kill_session"}

    for item in fixtures.values():
        evidence = item["input"]["evidence"]
        assert evidence["collector"] == "protected-webview"
        assert evidence["privacy_mode"] == "metadata_only"
        assert "page_content" not in evidence
        assert "dom_snapshot" not in evidence
        assert "request_body" not in evidence
        if "network" in evidence:
            assert evidence["network"]["host_hash"].startswith("sha256:")
        if "tamper" in evidence:
            assert evidence["tamper"]["content_sampled"] is False
