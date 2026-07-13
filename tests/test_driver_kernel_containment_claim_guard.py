from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from inprocess_gate_cli import run_cli_in_process


ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools" / "detection_validation"
SCRIPT = TOOLS / "scripts" / "driver_kernel_containment_claim_guard.py"
ROADMAP = ROOT / "docs" / "planejamento" / "DRIVER_KERNEL_CONTAINMENT_ROADMAP.md"


def run_guard(roadmap: Path):
    """In-process invocation: same exit-code/stdout contract, no process spawn."""
    return run_cli_in_process(SCRIPT, ["--roadmap", str(roadmap)])


def test_driver_kernel_containment_roadmap_passes_claim_guard() -> None:
    # Kept as a true subprocess smoke test: covers the real CLI entrypoint.
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--roadmap", str(ROADMAP)],
        cwd=TOOLS,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["evidence_class"] == "roadmap_claim_boundary"
    assert summary["forbidden_overclaims_absent"] is True
    assert summary["work_package_phases"] == 4


def test_driver_kernel_containment_guard_rejects_overclaim(tmp_path: Path) -> None:
    roadmap = tmp_path / "driver.md"
    roadmap.write_text(
        "\n".join(
            [
                "# Driver and Kernel Containment Roadmap",
                "Status: defensive research only, not production validated.",
                "## Product Boundary",
                "must not claim reliable safe unloading. It is not kernel malware removal. not a product claim. rebuild.",
                "## Defensive Model",
                "## Windows Roadmap",
                "## Linux Roadmap",
                "## macOS Roadmap",
                "## Cross-Platform Capability Matrix",
                "## Tamandua Work Packages",
                "Phase A Phase B Phase C Phase D",
                "## Validation Gates",
                "This offers guaranteed kernel malware removal.",
            ]
        ),
        encoding="utf-8",
    )

    completed = run_guard(roadmap)

    assert completed.returncode == 1
    assert "forbidden overclaims" in completed.stdout


def test_driver_kernel_containment_guard_rejects_mobile_shielding_without_evidence_class(tmp_path: Path) -> None:
    roadmap = tmp_path / "mobile.md"
    roadmap.write_text(
        "\n".join(
            [
                "# Mobile Shielding Claim",
                "Status: defensive research only, not production validated.",
                "## Product Boundary",
                "must not claim reliable safe unloading. It is not kernel malware removal. not a product claim. rebuild.",
                "## Defensive Model",
                "## Windows Roadmap",
                "## Linux Roadmap",
                "## macOS Roadmap",
                "## Cross-Platform Capability Matrix",
                "## Tamandua Work Packages",
                "Phase A Phase B Phase C Phase D",
                "## Validation Gates",
                "Tamandua proves SDK shielding efficacy for hostile mobile runtimes.",
            ]
        ),
        encoding="utf-8",
    )

    completed = run_guard(roadmap)

    assert completed.returncode == 1
    assert "mobile shielding claims" in completed.stdout
    assert "live_signed_ingestion" in completed.stdout
    assert "ios_xcframework" in completed.stdout
    assert "physical_attack_lab" in completed.stdout


def test_driver_kernel_containment_guard_rejects_mobile_shielding_with_partial_evidence_class(tmp_path: Path) -> None:
    roadmap = tmp_path / "mobile.md"
    roadmap.write_text(
        "\n".join(
            [
                "# Mobile Shielding Claim",
                "Status: defensive research only, not production validated.",
                "## Product Boundary",
                "must not claim reliable safe unloading. It is not kernel malware removal. not a product claim. rebuild.",
                "## Defensive Model",
                "## Windows Roadmap",
                "## Linux Roadmap",
                "## macOS Roadmap",
                "## Cross-Platform Capability Matrix",
                "## Tamandua Work Packages",
                "Phase A Phase B Phase C Phase D",
                "## Validation Gates",
                "Tamandua proves SDK shielding efficacy for hostile mobile runtimes.",
                "Evidence class: live_signed_ingestion.",
            ]
        ),
        encoding="utf-8",
    )

    completed = run_guard(roadmap)

    assert completed.returncode == 1
    assert "live_anti_replay_duplicate_rejection" in completed.stdout
    assert "ios_native_build" in completed.stdout


def test_driver_kernel_containment_guard_accepts_mobile_shielding_with_full_release_evidence_classes(tmp_path: Path) -> None:
    roadmap = tmp_path / "mobile.md"
    roadmap.write_text(
        "\n".join(
            [
                "# Mobile Shielding Claim",
                "Status: defensive research only, not production validated.",
                "## Product Boundary",
                "must not claim reliable safe unloading. It is not kernel malware removal. not a product claim. rebuild.",
                "## Defensive Model",
                "## Windows Roadmap",
                "## Linux Roadmap",
                "## macOS Roadmap",
                "## Cross-Platform Capability Matrix",
                "## Tamandua Work Packages",
                "Phase A Phase B Phase C Phase D",
                "## Validation Gates",
                "Tamandua proves SDK shielding efficacy for hostile mobile runtimes.",
                "Evidence classes: live_signed_ingestion, live_anti_replay_duplicate_rejection, ios_native_build, ios_xcframework, physical_attack_lab.",
            ]
        ),
        encoding="utf-8",
    )

    completed = run_guard(roadmap)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["strong_claims_checked"]["mobile_shielding"] == 1
    assert summary["required_mobile_strong_claim_evidence_classes"] == [
        "live_signed_ingestion",
        "live_anti_replay_duplicate_rejection",
        "ios_native_build",
        "ios_xcframework",
        "physical_attack_lab",
    ]
