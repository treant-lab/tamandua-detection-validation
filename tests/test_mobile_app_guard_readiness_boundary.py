from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "sdk" / "mobile" / "scripts" / "app_guard_product_readiness_check.py"


def load_readiness_module():
    sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("app_guard_product_readiness_check", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ok_report(**overrides):
    report = {
        "ok": True,
        "signed": True,
        "signed_request": True,
        "signature_algorithm": "HMAC-SHA256",
        "request_seen": True,
    }
    report.update(overrides)
    return report


def test_local_hmac_rehearsal_is_not_live_release_evidence() -> None:
    readiness = load_readiness_module()

    signing = readiness.classify_signing(
        signed_envelope=ok_report(),
        local_signed=ok_report(),
        local_ingestion=ok_report(),
        live_ingestion={},
        signature_vectors={"ok": True},
    )

    assert signing["local_signed_rehearsal_ok"] is True
    assert signing["local_ingestion_hmac_ok"] is True
    assert signing["signature_vectors_ok"] is True
    assert signing["live_signed_ingestion_ok"] is False
    assert signing["live_anti_replay_ok"] is False
    assert signing["evidence_classes"]["local_ingestion_hmac"] == "local_rehearsal"
    assert signing["evidence_classes"]["live_signed_ingestion"] == "missing"
    assert signing["evidence_classes"]["live_anti_replay"] == "missing"


def test_live_signed_ingestion_requires_live_anti_replay_for_release_boundary() -> None:
    readiness = load_readiness_module()

    live_without_replay = ok_report(
        ingestion_ok=True,
        anti_replay={"checked": True, "ok": False, "method": "duplicate_signed_request", "http_status": 201},
    )
    signing = readiness.classify_signing(
        signed_envelope=ok_report(),
        local_signed=ok_report(),
        local_ingestion=ok_report(),
        live_ingestion=live_without_replay,
        signature_vectors={"ok": True},
    )

    assert signing["live_signed_ingestion_ok"] is True
    assert signing["live_anti_replay_ok"] is False
    assert signing["evidence_classes"]["live_signed_ingestion"] == "live_signed_ingestion"
    assert signing["evidence_classes"]["live_anti_replay"] == "missing"

    live_with_replay = ok_report(
        ingestion_ok=True,
        anti_replay={"checked": True, "ok": True, "method": "duplicate_signed_request", "http_status": 409},
    )
    signing = readiness.classify_signing(
        signed_envelope=ok_report(),
        local_signed=ok_report(),
        local_ingestion=ok_report(),
        live_ingestion=live_with_replay,
        signature_vectors={"ok": True},
    )

    assert signing["live_signed_ingestion_ok"] is True
    assert signing["live_anti_replay_ok"] is True
    assert signing["evidence_classes"]["live_anti_replay"] == "live_anti_replay_duplicate_rejection"


def test_readiness_report_blocks_strong_claims_without_live_ios_and_lab_evidence(tmp_path: Path) -> None:
    readiness = load_readiness_module()

    report = readiness.build_report(tmp_path, run_local=False)

    assert report["release_ready"] is False
    assert report["evidence_boundary"]["strong_claims_allowed"] is False
    # df12c5991 strengthened the release evidence boundary with
    # android_attack_lab_setup and clean_goodware_negative_controls.
    assert report["evidence_boundary"]["release_claim_requires"] == [
        "live_signed_ingestion",
        "live_anti_replay_duplicate_rejection",
        "ios_native_build",
        "ios_xcframework",
        "android_attack_lab_setup",
        "physical_attack_lab",
        "clean_goodware_negative_controls",
        "release_protection_packet",
        "mirror_publication",
    ]
    assert "live backend ingestion" in report["evidence_boundary"]["non_claims_when_release_ready_false"]
    assert "iOS native build" in report["evidence_boundary"]["non_claims_when_release_ready_false"]
    assert "physical attack-lab runtime protection evidence" in report["evidence_boundary"]["non_claims_when_release_ready_false"]
