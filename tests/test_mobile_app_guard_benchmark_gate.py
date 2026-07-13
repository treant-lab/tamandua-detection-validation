from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "mobile_app_guard_benchmark_gate.py"
FIXTURE = ROOT / "fixtures" / "mobile_app_guard_aggressive_replay_v1.json"


def run_gate_subprocess(fixture: Path) -> subprocess.CompletedProcess[str]:
    """True subprocess smoke: covers the real CLI entrypoint (argv, exit code)."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(fixture)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_gate(fixture: Path) -> subprocess.CompletedProcess[str]:
    """In-process invocation: same exit-code/stdout contract, no process spawn."""
    return run_cli_in_process(SCRIPT, ["--fixture", str(fixture)])


def test_mobile_app_guard_aggressive_fixture_passes_gate() -> None:
    completed = run_gate_subprocess(FIXTURE)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["fixtures"] == 11
    assert summary["goodware_false_positive_fixtures"] == 2
    assert summary["negative_goodware_controls"] == 2
    assert summary["scenario_coverage_fields"] == [
        "appdome_gap",
        "control_type",
        "coverage_tags",
        "evidence_bucket",
        "expected_decision",
        "platform",
        "verimatrix_gap",
    ]
    assert summary["evidence_class"] == "synthetic_replay_contract"
    assert summary["evidence_buckets"] == {
        "implemented_contract": 6,
        "physical_device_lab_required": 5,
        "physical_device_smoke": 0,
        "roadmap_device_evidence_required": 5,
    }
    assert summary["required_coverage_tags"] == [
        "accessibility",
        "fraud",
        "goodware_negative",
        "malware",
        "mitm",
        "overlay",
        "tamper",
    ]
    assert set(summary["coverage_tags"]) == set(summary["required_coverage_tags"])
    assert len(summary["claim_separation"]["implemented_contract"]) == 6
    assert len(summary["claim_separation"]["physical_device_lab_required"]) == 5
    assert summary["claim_separation"]["goodware_negative_controls"] == [
        "mobile-goodware-managed-device-allow",
        "mobile-goodware-browser-normal-allow",
    ]
    assert "physical_device_smoke" in summary["evidence_boundary_notes"]
    assert summary["evidence_boundary"]["fixture_evidence_class"] == "synthetic_replay_contract"
    assert summary["evidence_boundary"]["local_fixture_claimable"] is True
    assert summary["evidence_boundary"]["live_signed_ingestion_claimable"] is False
    assert summary["evidence_boundary"]["live_anti_replay_claimable"] is False


def test_mobile_app_guard_gate_rejects_missing_live_evidence_requirements(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    boundary = data["benchmark_gate"]["evidence_boundary"]
    boundary["release_claim_requires"] = [
        item for item in boundary["release_claim_requires"] if not item.startswith("live_")
    ]
    fixture = tmp_path / "missing-live-evidence.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    assert "missing live evidence requirements" in completed.stdout
    assert "live_signed_app_guard_ingestion" in completed.stdout
    assert "live_duplicate_signed_request_rejection" in completed.stdout


def test_mobile_app_guard_gate_rejects_missing_control_requirements(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    del data["benchmark_gate"]["control_requirements"]
    fixture = tmp_path / "missing-control-requirements.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    assert "benchmark_gate.control_requirements is required" in completed.stdout


def test_mobile_app_guard_gate_rejects_missing_scenario_coverage(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    del data["fixtures"][0]["scenario_coverage"]["appdome_gap"]
    fixture = tmp_path / "missing-scenario-coverage.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    assert "scenario_coverage missing required fields" in completed.stdout
    assert "appdome_gap" in completed.stdout


def test_mobile_app_guard_gate_rejects_missing_required_coverage_tag(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for item in data["fixtures"]:
        item["scenario_coverage"]["coverage_tags"] = [
            tag for tag in item["scenario_coverage"]["coverage_tags"] if tag != "mitm"
        ]
    fixture = tmp_path / "missing-coverage-tag.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    assert "missing required coverage tags" in completed.stdout
    assert "mitm" in completed.stdout


def test_mobile_app_guard_gate_rejects_goodware_blocking_control(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    goodware = next(item for item in data["fixtures"] if item["benchmark_category"] == "goodware_false_positive")
    goodware["scenario_coverage"]["control_type"] = "positive_replay"
    fixture = tmp_path / "blocking-goodware-control.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    assert "goodware FP fixture must be a negative_goodware_control" in completed.stdout


def test_mobile_app_guard_gate_rejects_missing_ios_evidence_requirements(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    boundary = data["benchmark_gate"]["evidence_boundary"]
    boundary["release_claim_requires"] = [
        item for item in boundary["release_claim_requires"] if not item.startswith("ios_")
    ]
    fixture = tmp_path / "missing-ios-evidence.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    assert "missing ios evidence requirements" in completed.stdout
    assert "ios_native_build_evidence" in completed.stdout
    assert "ios_xcframework_binding_evidence" in completed.stdout


def test_mobile_app_guard_gate_rejects_missing_lab_evidence_requirements(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    boundary = data["benchmark_gate"]["evidence_boundary"]
    boundary["release_claim_requires"].remove("governed_physical_attack_lab_evidence")
    fixture = tmp_path / "missing-lab-evidence.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    assert "missing lab evidence requirements" in completed.stdout
    assert "governed_physical_attack_lab_evidence" in completed.stdout


def test_mobile_app_guard_gate_rejects_missing_non_claim_boundary(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    boundary = data["benchmark_gate"]["evidence_boundary"]
    boundary["non_claims"].remove("iOS native build")
    fixture = tmp_path / "missing-non-claim.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    assert "non_claims must include" in completed.stdout
    assert "iOS native build" in completed.stdout


def test_mobile_app_guard_aggressive_fixture_covers_required_categories() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    required = set(data["benchmark_gate"]["required_categories"])
    categories = {item["benchmark_category"] for item in data["fixtures"]}

    assert categories == required
    assert required == {
        "magisk_zygisk",
        "frida_attach_spawn",
        "debugger",
        "hook_framework",
        "webview_browser_tamper",
        "apk_repack_integrity",
        "cert_pinning_bypass",
        "doh_exfiltration",
        "spyware_like_behavior",
        "goodware_false_positive",
    }


def test_mobile_app_guard_aggressive_fixture_uses_honest_claim_labels() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    boundary = data["claim_boundary"]

    assert "Synthetic offline replay contract only" in boundary
    assert "do not prove live backend ingestion" in boundary
    assert "physical-device collection" in boundary
    assert "SDK shielding efficacy" in boundary
    assert "production malware accuracy" in boundary

    statuses = {item["claim_status"] for item in data["fixtures"]}
    assert statuses == {"implemented_contract", "roadmap_device_evidence_required"}

    boundary = data["benchmark_gate"]["evidence_boundary"]
    assert boundary["fixture_evidence_class"] == "synthetic_replay_contract"
    assert boundary["release_claim_requires"] == [
        "live_signed_app_guard_ingestion",
        "live_duplicate_signed_request_rejection",
        "physical_device_collection_packet",
        "ios_native_build_evidence",
        "ios_xcframework_binding_evidence",
        "governed_physical_attack_lab_evidence",
    ]
    assert data["benchmark_gate"]["control_requirements"] == {
        "goodware_category": "goodware_false_positive",
        "minimum_negative_controls": 2,
        "negative_control_type": "negative_goodware_control",
        "allowed_negative_decisions": ["allow"],
        "privacy_boundary": "metadata_only",
    }
    assert data["benchmark_gate"]["required_coverage_tags"] == [
        "accessibility",
        "fraud",
        "goodware_negative",
        "malware",
        "mitm",
        "overlay",
        "tamper",
    ]
    assert set(boundary["non_claims"]) == {
        "live backend ingestion",
        "live anti-replay",
        "physical-device collection",
        "iOS native build",
        "iOS XCFramework",
        "physical attack-lab protection evidence",
        "production malware accuracy",
    }

    roadmap_categories = {
        item["benchmark_category"]
        for item in data["fixtures"]
        if item["claim_status"] == "roadmap_device_evidence_required"
    }
    assert roadmap_categories == {
        "magisk_zygisk",
        "frida_attach_spawn",
        "hook_framework",
        "apk_repack_integrity",
        "cert_pinning_bypass",
    }


def test_mobile_app_guard_aggressive_fixture_keeps_goodware_non_blocking() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    goodware = [item for item in data["fixtures"] if item["benchmark_category"] == "goodware_false_positive"]

    assert len(goodware) == 2
    for item in goodware:
        assert item["scenario_coverage"]["control_type"] == "negative_goodware_control"
        assert item["scenario_coverage"]["expected_decision"] == "allow"
        assert item["scenario_coverage"]["evidence_bucket"] == "implemented_contract"
        assert "goodware_negative" in item["scenario_coverage"]["coverage_tags"]
        assert item["input"]["severity"] == "info"
        assert item["input"]["risk"]["decision"] == "allow"
        assert item["expected"]["alert"]["recommended_action"] is None


def test_mobile_app_guard_aggressive_fixture_is_metadata_only() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    forbidden = {
        "raw_body",
        "raw_payload",
        "page_content",
        "dom_snapshot",
        "request_body",
        "response_body",
        "raw_pointer_data",
        "raw_key_data",
    }

    for item in data["fixtures"]:
        evidence = item["input"]["evidence"]
        scenario_coverage = item["scenario_coverage"]
        assert evidence["privacy_mode"] == "metadata_only"
        assert forbidden.isdisjoint(evidence)
        assert scenario_coverage["evidence_bucket"] in {
            "implemented_contract",
            "physical_device_lab_required",
        }
        assert scenario_coverage["coverage_tags"]
        if "network" in evidence:
            assert evidence["network"]["host_hash"].startswith("sha256:")
        if "tamper" in evidence:
            assert evidence["tamper"]["content_sampled"] is False
