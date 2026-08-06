from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from tools.detection_validation.scripts.local_model_sidecar_readiness_gate import build_report


ROOT = Path(__file__).parents[3]
PACKAGE = ROOT / "apps" / "tamandua_agent" / "installer" / "model-sidecar"
SCHEMA = ROOT / "schemas" / "local_model_sidecar_readiness_gate_v1.schema.json"
ARTIFACT_SHA = "a" * 64


def _model_bytes() -> bytes:
    return b"""tree
version=v4
num_class=1
num_tree_per_iteration=1
max_feature_idx=255
objective=binary sigmoid:1
tree_sizes=123
Tree=0
num_leaves=2
num_cat=0
split_feature=3
split_gain=0.5
threshold=0.1
decision_type=2
left_child=-1
right_child=-2
leaf_value=-0.25 0.75
leaf_weight=1 1
leaf_count=1 1
internal_value=0
internal_weight=2
internal_count=2
shrinkage=1
end of trees
"""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    repo = tmp_path / "repo"
    package = repo / "apps" / "tamandua_agent" / "installer" / "model-sidecar"
    package.parent.mkdir(parents=True)
    shutil.copytree(PACKAGE, package)
    schema_target = repo / "schemas"
    schema_target.mkdir(parents=True)
    for name in (
        "external_model_promotion_gate_v1.schema.json",
        "hist256_candidate_freeze_v1.schema.json",
        "hist256_holdout_evaluation_v1.schema.json",
        "hist256_feature_contract_v1.schema.json",
    ):
        shutil.copy2(ROOT / "schemas" / name, schema_target / name)

    artifact = repo / "artifacts" / "hist256.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(_model_bytes())
    artifact_sha = _sha(artifact)
    contract = repo / "contracts" / "hist256.json"
    contract.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "schemas" / "examples" / "hist256_feature_contract_v1.json", contract)
    contract_payload = json.loads(contract.read_text())

    freeze = repo / "evidence" / "freeze.json"
    freeze.parent.mkdir(parents=True)
    freeze_payload = {
        "api_version": "tamandua.io/hist256-candidate-freeze/v1",
        "kind": "Hist256CandidateFreezeManifest",
        "status": "frozen_for_governed_holdout",
        "frozen_at": "2026-07-15T12:00:00Z",
        "model_id": "tamandua/hist256-test-v1",
        "artifact": {"format": "lightgbm-text-v4", "sha256": artifact_sha, "size_bytes": artifact.stat().st_size},
        "feature_contract": {"id": "tamandua.byte-histogram-256.v1", "sha256": contract_payload["contract_sha256"], "feature_count": 256},
        "decision": {"threshold": 0.75, "calibration_id": "governed-holdout-test-v1", "score_orientation": "higher_is_more_malicious", "initial_lane": "endpoint_shadow", "may_enforce": False},
        "lineage": {"training_sha256": "1" * 64, "calibration_sha256": "2" * 64, "calibration_evidence_sha256": "3" * 64, "forbidden_consumed_datasets": ["EMBER2018-test", "EMBER2024-test", "EMBER2024-challenge"]},
        "holdout_not_opened_attestation": True,
        "claim_boundary": "Synthetic schema-valid readiness fixture; no efficacy or deployment claim.",
    }
    freeze_payload["freeze_payload_sha256"] = hashlib.sha256((json.dumps(freeze_payload, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
    freeze.write_text(json.dumps(freeze_payload), encoding="utf-8")

    holdout = repo / "evidence" / "holdout.json"
    holdout.write_text(json.dumps({
        "api_version": "tamandua.io/hist256-holdout-evaluation/v1",
        "kind": "Hist256GovernedHoldoutEvaluation",
        "evidence_class": "governed_holdout",
        "status": "evaluation_complete_not_promotion_eligible",
        "generated_at": "2026-07-15T13:00:00Z",
        "model_id": "tamandua/hist256-test-v1",
        "freeze_manifest_sha256": _sha(freeze),
        "artifact_sha256": artifact_sha,
        "feature_contract_id": "tamandua.byte-histogram-256.v1",
        "threshold": 0.75,
        "calibration_id": "governed-holdout-test-v1",
        "holdout_lineage_sha256": "4" * 64,
        "consumed_membership_manifest_sha256": ["5" * 64],
        "metrics": {"sample_count": 110000, "goodware_count": 100000, "malware_count": 10000, "confusion": {"tp": 9900, "tn": 99900, "fp": 100, "fn": 100}, "fpr": 0.001, "fnr": 0.01, "latency_ms": {"mean": 1.0, "p95": 2.0, "max": 3.0}, "minimum_goodware_gate": 100000, "minimum_malware_gate": 10000, "sample_gate_met": True},
        "reproducibility_commands": ["synthetic-test-only"],
        "may_promote": False,
        "may_enforce": False,
        "claim_boundary": "Synthetic schema-valid readiness fixture only; no efficacy or deployment claim."
    }), encoding="utf-8")
    registry = repo / "apps" / "tamandua_ml" / "src" / "local_model_service" / "providers.json"
    registry.parent.mkdir(parents=True)
    registry_payload = {
        "schema_version": "tamandua.local_model_providers.v1",
        "policy": {
            "enabled_default": False,
            "remote_bind_allowed": False,
            "remote_download_allowed": False,
            "enforcement_allowed": False,
        },
        "providers": [{
            "provider_id": "governed-lightgbm",
            "model_contract_id": "tamandua.governed-lightgbm.v1",
            "implementation": "lightgbm_local",
            "enabled": False,
            "evidence_class": "governed_holdout",
            "decision_mode": "decision_only",
            "max_file_bytes": 50_000_000,
            "artifact_path": str(artifact.resolve()),
            "artifact_sha256": artifact_sha,
            "artifact_size_bytes": artifact.stat().st_size,
            "artifact_format": "lightgbm-text-v4",
            "feature_contract_id": "tamandua.byte-histogram-256.v1",
            "feature_dimension": 256,
            "threshold": 0.75,
            "calibration_id": "governed-holdout-test-v1",
            "score_orientation": "higher_is_more_malicious",
        }],
    }
    registry.write_text(json.dumps(registry_payload), encoding="utf-8")

    source_manifest = json.loads((PACKAGE / "package-readiness-manifest.json").read_text())
    # Pin the exact bytes copied into the temporary package. Git's checkout EOL
    # policy may materialize platform scripts differently on Windows.
    for entry in source_manifest["files"]:
        entry["sha256"] = _sha(repo / entry["path"])
    source_manifest["provider_registry"]["sha256"] = _sha(registry)
    source_manifest["candidate_bundle"] = {
        "artifact": {"path": "artifacts/hist256.txt", "sha256": artifact_sha},
        "feature_contract": {"path": "contracts/hist256.json", "sha256": _sha(contract)},
        "freeze_manifest": {"path": "evidence/freeze.json", "sha256": _sha(freeze)},
        "holdout_evidence": {"path": "evidence/holdout.json", "sha256": _sha(holdout)},
    }
    manifest = package / "package-readiness-manifest.json"
    manifest.write_text(json.dumps(source_manifest), encoding="utf-8")

    promotion = repo / "promotion.json"
    promotion.write_text(json.dumps({
        "api_version": "tamandua.io/external-model-promotion-gate/v1",
        "kind": "ExternalModelPromotionGateReport",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "mode": "offline_static_no_execution",
        "target": "endpoint_shadow",
        "decision": "eligible_for_manual_review",
        "may_execute_model": False,
        "may_publish_claim": False,
        "candidate": {
            "model_id": "governed-test-model",
            "status": "intake_approved",
            "artifact_format": "lightgbm-text-v4",
            "artifact_sha256": artifact_sha,
            "source_uri": "https://example.invalid/model",
            "source_revision": "1" * 40,
            "license_name": "test-only",
            "license_usage": "benchmark_only",
        },
        "benchmark_evidence": {
            "class": "governed_holdout",
            "path": "evidence/holdout.json",
            "artifact_sha256": artifact_sha,
        },
        "static_scans": [
            {"engine": "lightgbm_guard", "status": "clean", "findings": []},
            {"engine": "model_package_guard", "status": "clean", "findings": []},
        ],
        "promotion_blockers": [],
        "claim_boundary": "Static synthetic test input only; this does not authorize inference, deployment, or malware efficacy claims.",
    }), encoding="utf-8")
    manifest_payload = json.loads(manifest.read_text())
    manifest_payload["promotion_report"] = {
        "path": "promotion.json",
        "sha256": _sha(promotion),
    }
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
    return repo, manifest, registry, promotion


def test_gate_accepts_pinned_default_off_package_without_execution(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    report = build_report(repo, manifest, registry, promotion)
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(report)
    assert report["decision"] == "eligible_for_manual_review"
    assert report["promotion_blockers"] == []
    assert report["may_start_service"] is False
    assert report["may_execute_model"] is False
    assert report["may_publish_efficacy_claim"] is False
    assert report["evidence"] == {"class": "synthetic_parity", "scope": "package_readiness_smoke"}


def test_gate_blocks_tampered_package_hash(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    target = repo / "apps" / "tamandua_agent" / "installer" / "model-sidecar" / "linux" / "local-model-sidecar.env.example"
    target.write_text(target.read_text() + "# drift\n")
    report = build_report(repo, manifest, registry, promotion)
    assert report["decision"] == "blocked"
    assert "package_hash_validation_failed" in report["promotion_blockers"]


def test_gate_blocks_enabled_provider_even_with_eligible_report(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    payload = json.loads(registry.read_text())
    payload["providers"][0]["enabled"] = True
    registry.write_text(json.dumps(payload), encoding="utf-8")
    manifest_payload = json.loads(manifest.read_text())
    manifest_payload["provider_registry"]["sha256"] = _sha(registry)
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
    report = build_report(repo, manifest, registry, promotion)
    assert "provider_registry_invalid_or_unpinned" in report["promotion_blockers"]


def test_gate_blocks_promotion_candidate_hash_mismatch(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    payload = json.loads(promotion.read_text())
    payload["candidate"]["artifact_sha256"] = "b" * 64
    promotion.write_text(json.dumps(payload), encoding="utf-8")
    report = build_report(repo, manifest, registry, promotion)
    assert "promotion_report_not_eligible_or_provider_mismatch" in report["promotion_blockers"]


def test_gate_blocks_replaced_promotion_report_even_when_content_claims_eligible(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    payload = json.loads(promotion.read_text())
    payload["claim_boundary"] = "attacker-added field"
    promotion.write_text(json.dumps(payload), encoding="utf-8")
    report = build_report(repo, manifest, registry, promotion)
    assert "promotion_report_not_eligible_or_provider_mismatch" in report["promotion_blockers"]


def test_gate_blocks_threat_static_scan_even_if_report_decision_is_eligible(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    payload = json.loads(promotion.read_text())
    payload["static_scans"][0]["status"] = "threat"
    promotion.write_text(json.dumps(payload), encoding="utf-8")
    manifest_payload = json.loads(manifest.read_text())
    manifest_payload["promotion_report"]["sha256"] = _sha(promotion)
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
    report = build_report(repo, manifest, registry, promotion)
    assert "promotion_report_not_eligible_or_provider_mismatch" in report["promotion_blockers"]


def test_gate_blocks_non_endpoint_shadow_target(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    payload = json.loads(promotion.read_text())
    payload["target"] = "server_shadow"
    promotion.write_text(json.dumps(payload), encoding="utf-8")
    manifest_payload = json.loads(manifest.read_text())
    manifest_payload["promotion_report"]["sha256"] = _sha(promotion)
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
    report = build_report(repo, manifest, registry, promotion)
    assert report["decision"] == "blocked"
    assert "promotion_report_not_eligible_or_provider_mismatch" in report["promotion_blockers"]


def test_gate_blocks_holdout_below_sample_gate(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    manifest_payload = json.loads(manifest.read_text())
    holdout = repo / manifest_payload["candidate_bundle"]["holdout_evidence"]["path"]
    payload = json.loads(holdout.read_text())
    payload["evidence_class"] = "governed_holdout_below_sample_gate"
    payload["metrics"]["sample_gate_met"] = False
    holdout.write_text(json.dumps(payload), encoding="utf-8")
    manifest_payload["candidate_bundle"]["holdout_evidence"]["sha256"] = _sha(holdout)
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
    report = build_report(repo, manifest, registry, promotion)
    assert report["decision"] == "blocked"
    assert "hist256_cross_contract_mismatch" in report["promotion_blockers"]


def test_gate_blocks_threshold_drift_after_freeze(tmp_path: Path) -> None:
    repo, manifest, registry, promotion = _inputs(tmp_path)
    manifest_payload = json.loads(manifest.read_text())
    holdout = repo / manifest_payload["candidate_bundle"]["holdout_evidence"]["path"]
    payload = json.loads(holdout.read_text())
    payload["threshold"] = 0.76
    holdout.write_text(json.dumps(payload), encoding="utf-8")
    manifest_payload["candidate_bundle"]["holdout_evidence"]["sha256"] = _sha(holdout)
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
    report = build_report(repo, manifest, registry, promotion)
    assert report["decision"] == "blocked"
    assert "hist256_cross_contract_mismatch" in report["promotion_blockers"]


def test_checked_in_package_is_honestly_blocked_without_promoted_provider(tmp_path: Path) -> None:
    promotion = tmp_path / "promotion.json"
    promotion.write_text(json.dumps({
        "api_version": "tamandua.io/external-model-promotion-gate/v1",
        "mode": "offline_static_no_execution",
        "decision": "blocked",
        "may_execute_model": False,
        "may_publish_claim": False,
        "candidate": {"artifact_sha256": None},
        "promotion_blockers": ["no_governed_model_selected"],
    }), encoding="utf-8")
    report = build_report(
        ROOT,
        PACKAGE / "package-readiness-manifest.json",
        ROOT / "apps" / "tamandua_ml" / "src" / "local_model_service" / "providers.json",
        promotion,
    )
    assert report["decision"] == "blocked"
    assert "promotion_report_not_eligible_or_provider_mismatch" in report["promotion_blockers"]
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(report)
