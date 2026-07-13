import argparse
import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools" / "detection_validation" / "scripts" / "proxmox_virtualization_host_readiness_probe.py"
PROFILE_PATH = REPO_ROOT / "tools" / "detection_validation" / "profiles" / "proxmox_virtualization_host_readiness_probe.json"

SPEC = importlib.util.spec_from_file_location("proxmox_virtualization_host_readiness_probe", MODULE_PATH)
proxmox_host_readiness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = proxmox_host_readiness
SPEC.loader.exec_module(proxmox_host_readiness)


def test_proxmox_host_readiness_reports_missing_password_without_network(monkeypatch):
    monkeypatch.setattr(proxmox_host_readiness, "git_snapshot", lambda: {"dirty": False, "status_short": []})
    args = argparse.Namespace(
        proxmox_host="192.0.2.10",
        proxmox_user="root@pam",
        proxmox_password=None,
        http_timeout_seconds=1,
    )

    report = proxmox_host_readiness.build_report(args)

    assert report["profile_id"] == "proxmox-virtualization-host-readiness-probe"
    assert report["collector"] == "proxmox"
    assert report["capability"] == "virtualization_host"
    assert report["event_type"] == "virtualization_host_inventory"
    assert report["quality_gate"]["passed"] is False
    assert report["tests"][0]["id"] == "proxmox-api-authenticated"
    assert report["tests"][0]["collector"] == "proxmox"
    assert report["tests"][0]["capability"] == "virtualization_host"
    assert report["tests"][0]["event_type"] == "virtualization_host_inventory"
    assert report["tests"][0]["expected_telemetry_any"] == ["virtualization_host_inventory"]
    assert report["tests"][0]["evidence"]["error"] == "missing_proxmox_password"
    assert report["virtualization_host_inventory"]["resource_summary"]["resource_count"] == 0
    assert "not production validated" in report["virtualization_host_inventory"]["claim_boundary"]


def test_proxmox_host_readiness_profile_points_at_script():
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))

    assert profile["profile_id"] == "proxmox-virtualization-host-readiness-probe"
    assert profile["platform"] == "proxmox"
    assert profile["collector"] == "proxmox"
    assert profile["capability"] == "virtualization_host"
    assert profile["event_type"] == "virtualization_host_inventory"
    assert profile["execution"]["type"] == "local_probe"
    assert profile["execution"]["command"] == (
        "python tools\\detection_validation\\scripts\\proxmox_virtualization_host_readiness_probe.py"
    )
    assert "not production validated" in profile["claim_boundary"]
    assert {telemetry for test in profile["tests"] for telemetry in test["expected_telemetry"]} == {
        "virtualization_host_inventory"
    }
    assert {test["id"] for test in profile["tests"]} == {
        "proxmox-api-authenticated",
        "proxmox-cluster-resources-readable",
        "proxmox-node-inventory-readable",
        "proxmox-node-status-readable",
        "proxmox-guest-inventory-readable",
        "proxmox-storage-inventory-readable",
    }
