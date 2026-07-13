from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "sdk" / "mobile" / "scripts" / "physical_attack_lab_evidence.py"
FIXTURE = ROOT / "sdk" / "mobile" / "examples" / "physical-attack-lab-evidence.sanitized.json"


def _gate_argv(path: Path | None) -> list[str]:
    argv = ["--strict"]
    if path is None:
        argv.append("--example-sanitized-fixture")
    else:
        argv.extend(["--evidence", str(path)])
    return argv


def run_gate_subprocess(path: Path | None = None) -> subprocess.CompletedProcess[str]:
    """True subprocess smoke: covers the real CLI entrypoint (argv, exit code)."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *_gate_argv(path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_gate(path: Path | None = None) -> subprocess.CompletedProcess[str]:
    """In-process invocation: same exit-code/stdout contract, no process spawn."""
    return run_cli_in_process(SCRIPT, _gate_argv(path))


def test_sanitized_physical_attack_lab_fixture_passes_strict_gate() -> None:
    completed = run_gate_subprocess()

    assert completed.returncode == 0, completed.stdout + completed.stderr
    status = json.loads(completed.stdout)
    assert status["physical_attack_lab_evidence_ok"] is True
    assert status["evidence_class"] == "sanitized_validator_fixture"
    assert status["release_evidence"] is False
    assert status["event_ids"] == [
        "evt-physical-root-001",
        "evt-physical-frida-001",
        "evt-physical-overlay-fraud-001",
        "evt-physical-accessibility-001",
        "evt-physical-mitm-pinning-001",
        "evt-physical-app-tamper-001",
        "evt-physical-malware-behavior-001",
        "evt-goodware-managed-001",
        "evt-goodware-accessibility-001",
    ]
    assert status["server_request_ids"] == [
        "req-physical-root-001",
        "req-physical-frida-001",
        "req-physical-overlay-fraud-001",
        "req-physical-accessibility-001",
        "req-physical-mitm-pinning-001",
        "req-physical-app-tamper-001",
        "req-physical-malware-behavior-001",
        "req-goodware-managed-001",
        "req-goodware-accessibility-001",
    ]
    assert status["failure_reasons"] == []
    assert status["rollback"]["performed"] is True
    assert status["rollback"]["verification"]["verified"] is True
    assert status["privacy_boundary"]["metadata_only"] is True
    assert status["privacy_boundary"]["contains_pii"] is False
    assert "adb_logcat_raw" in status["privacy_boundary"]["excluded_raw_fields"]
    assert status["operator_attestation"]["attested"] is True
    assert status["controls"]["positive"] == [
        "physical-root-zygisk-block",
        "physical-frida-session-kill",
        "physical-overlay-fraud-step-up",
        "physical-accessibility-abuse-kill-session",
        "physical-mitm-pinning-step-up",
        "physical-app-tamper-repack-block",
        "physical-malware-behavior-kill-session",
    ]
    assert status["controls"]["negative"] == [
        "physical-goodware-managed-allow",
        "physical-goodware-accessibility-allow",
    ]
    assert status["reproducible_lab_command"]["executes_attacks"] is False
    assert {item["claim_status"] for item in status["scenarios"]} == {
        "attack_positive",
        "goodware_negative",
    }
    assert all(item["observed_at"].startswith("2026-07-07T12:") for item in status["scenarios"])
    assert status["competitive_coverage_tags"] == [
        "accessibility",
        "fraud",
        "goodware_negative",
        "malware",
        "mitm",
        "overlay",
        "tamper",
    ]
    assert status["missing_competitive_coverage_tags"] == []
    assert status["evidence_bucket_ids"]["implemented_contract"] == [
        "physical-goodware-managed-allow",
        "physical-goodware-accessibility-allow",
    ]
    assert status["evidence_bucket_ids"]["physical_device_lab_required"] == [
        "physical-root-zygisk-block",
        "physical-frida-session-kill",
        "physical-overlay-fraud-step-up",
        "physical-accessibility-abuse-kill-session",
        "physical-mitm-pinning-step-up",
        "physical-app-tamper-repack-block",
        "physical-malware-behavior-kill-session",
    ]


def test_physical_attack_lab_gate_requires_goodware_negative(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["scenarios"] = [item for item in data["scenarios"] if item["claim_status"] != "goodware_negative"]
    fixture = tmp_path / "missing-goodware-negative.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert "scenarios must include at least one goodware_negative case" in status["validation_errors"]


def test_physical_attack_lab_gate_rejects_failed_scenario_marked_ok(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["scenarios"][0]["result"] = "fail"
    data["failure_reasons"] = [
        {
            "section": "scenarios[0]",
            "reason": "sanitized failure reason for validator coverage",
        }
    ]
    fixture = tmp_path / "failed-scenario-marked-ok.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert "all scenarios must pass when ok is true" in status["validation_errors"]


def test_physical_attack_lab_gate_requires_per_scenario_timestamps(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    del data["scenarios"][0]["observed_at"]
    fixture = tmp_path / "missing-scenario-timestamp.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert "scenarios[0].observed_at must be an ISO-8601 timestamp" in status["validation_errors"]


def test_physical_attack_lab_gate_requires_operator_attestation(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["operator_attestation"]["attested"] = False
    fixture = tmp_path / "missing-operator-attestation.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert "operator_attestation.attested must be true" in status["validation_errors"]


def test_physical_attack_lab_gate_requires_rollback_verification(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["rollback"]["verification"]["verified"] = False
    fixture = tmp_path / "missing-rollback-verification.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert "rollback.verification.verified must be true" in status["validation_errors"]


def test_physical_attack_lab_gate_requires_excluded_raw_fields(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["privacy_boundary"]["excluded_raw_fields"].remove("frida_script")
    fixture = tmp_path / "missing-excluded-raw-field.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert any(
        error.startswith("privacy_boundary.excluded_raw_fields must include")
        for error in status["validation_errors"]
    )


def test_physical_attack_lab_gate_requires_reproducible_non_attack_command(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["reproducible_lab_command"]["executes_attacks"] = True
    fixture = tmp_path / "attack-command.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert "reproducible_lab_command.executes_attacks must be false" in status["validation_errors"]


def test_physical_attack_lab_gate_requires_competitive_coverage_tags(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for item in data["scenarios"]:
        item["scenario_coverage"]["coverage_tags"] = [
            tag for tag in item["scenario_coverage"]["coverage_tags"] if tag != "overlay"
        ]
    fixture = tmp_path / "missing-competitive-coverage.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert "scenario coverage missing required competitive tags ['overlay']" in status["validation_errors"]


def test_physical_attack_lab_gate_requires_attack_bucket_separation(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["scenarios"][0]["scenario_coverage"]["evidence_bucket"] = "implemented_contract"
    fixture = tmp_path / "wrong-attack-bucket.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    completed = run_gate(fixture)

    assert completed.returncode == 1
    status = json.loads(completed.stdout)
    assert (
        "scenarios[0].scenario_coverage.evidence_bucket must be physical_device_lab_required for attack_positive"
        in status["validation_errors"]
    )
