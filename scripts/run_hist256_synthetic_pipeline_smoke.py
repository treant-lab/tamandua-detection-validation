#!/usr/bin/env python3
"""Run an offline synthetic hist256 pipeline smoke without product claims."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import shutil
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

import numpy as np


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(value)
    return value


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha_file(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _fake_lightgbm():
    class Dataset:
        def __init__(self, data, label, free_raw_data, params=None):
            if not isinstance(data, np.memmap) or not isinstance(label, np.memmap) or free_raw_data is not False:
                raise AssertionError("scalable trainer did not preserve memmap inputs")
            if not isinstance(params, dict):
                raise AssertionError("scalable trainer did not pass governed training params")
            self.data = data

        def construct(self):
            return self

    class Model:
        def predict(self, data):
            return np.where(data[:, ord("m")] > 0, 0.9, 0.1)

        def save_model(self, path):
            Path(path).write_bytes(b"""tree
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
threshold=0.25
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
""")

    return types.SimpleNamespace(Dataset=Dataset, train=lambda params, dataset, num_boost_round: Model())


def _lineage(root: Path, split: str, rows: list[tuple[str, bytes, str]], converter) -> Path:
    sample_root = root / f"{split}-samples"; sample_root.mkdir()
    samples = []
    for name, raw, label in rows:
        (sample_root / name).write_bytes(raw)
        samples.append({
            "sha256": _sha_bytes(raw), "label": label, "split": split, "relative_path": name,
            "size_bytes": len(raw), "source_id": "synthetic-pipeline-smoke", "version_id": f"v-{name}",
            "source_object_key": f"incoming/{name}" if label == "malware" else None,
            "content_identity": "sha256" if label == "goodware" else None,
            "curation_manifest_sha256": "a" * 64, "promotion_manifest_sha256": "b" * 64,
            "license_status": "approved_for_ml_training" if label == "goodware" else "restricted-malware-research",
            "license_review_id": "synthetic-only" if label == "goodware" else None,
            "provenance_uri": "case://synthetic-license" if label == "goodware" else None,
            "usage_status": "approved_for_internal_ml_training" if label == "malware" else None,
            "dataset_use_review_id": "malware-training-fixture" if label == "malware" else None,
            "dataset_use_provenance_uri": "case://malware-training-fixture" if label == "malware" else None,
            "dataset_use_attestation_sha256": "e" * 64 if label == "malware" else None,
            "dataset_use_receipt_sha256": "f" * 64 if label == "malware" else None,
            "dataset_use_membership_sha256": "9" * 64 if label == "malware" else None,
        })
    manifest = {
        "split": split, "feature_contract_id": "tamandua.byte-histogram-256.v1",
        "feature_contract_sha256": converter.FEATURE_CONTRACT_SHA256,
        "extractor_implementation_sha256": converter.EXTRACTOR_IMPLEMENTATION_SHA256,
        "downstream_bytes_sha256_revalidation": {"required": True, "algorithm": "sha256", "stage": "before_feature_extraction"},
        "eligibility": {"status": "eligible", "holdout_excluded": True,
            "lineage_audit_sha256": ("c" if split == "train" else "e") * 64,
            "consumed_dataset_overlap_count": 0,
            "consumed_membership_indexes": {name: "d" * 64 for name in converter.REQUIRED_CONSUMED_DATASETS}},
        "samples": samples,
    }
    lineage = root / f"{split}-lineage.json"; lineage.write_bytes(_canonical(manifest))
    return converter.convert_lineage_to_hist256_bundle(
        lineage_path=lineage, sample_root=sample_root, split=split, output_dir=root / f"{split}-bundle")


def run_smoke(repo_root: Path) -> dict:
    repo_root = repo_root.resolve()
    app = repo_root / "apps" / "tamandua_ml"
    for entry in (app, app / "scripts"):
        if str(entry) not in sys.path:
            sys.path.insert(0, str(entry))
    from src.ai_security.lightgbm_guard import LightGBMGuard, LightGBMGuardPolicy
    import src.hist256_matrix_converter as converter

    trainer = _module("hist256_smoke_trainer", app / "scripts" / "train_hist256_matrix_candidate.py")
    governance = _module("hist256_smoke_governance", app / "scripts" / "hist256_governed_pipeline.py")
    readiness = _module("hist256_smoke_readiness", repo_root / "tools" / "detection_validation" / "scripts" / "local_model_sidecar_readiness_gate.py")
    actual_version = importlib.metadata.version("lightgbm")
    scratch_parent = repo_root / ".tmp"; scratch_parent.mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="hist256-synthetic-smoke-", dir=scratch_parent))
    try:
        train_bundle = _lineage(scratch, "train", [("g.bin", b"good", "goodware"), ("m.bin", b"malware", "malware")], converter)
        calibration_bundle = _lineage(scratch, "calibration", [("g.bin", b"good-2", "goodware"), ("m.bin", b"malware-2", "malware")], converter)
        candidate = scratch / "candidate"
        with patch.object(trainer, "MIN_TRAIN_ROWS", 2), patch.object(trainer, "MIN_CALIBRATION_GOODWARE", 1), \
             patch.object(trainer, "MIN_CALIBRATION_MALWARE", 1), patch.object(trainer.importlib.metadata, "version", return_value="4.5.0"), \
             patch.dict(sys.modules, {"lightgbm": _fake_lightgbm()}):
            calibration = trainer.train_scalable_candidate(
                train_bundle_path=train_bundle, calibration_bundle_path=calibration_bundle,
                config_path=app / "config" / "hist256_training_config.v1.json",
                calibration_id="synthetic-pipeline-smoke-only", output_dir=candidate)
        artifact = candidate / "candidate.lightgbm.txt"
        guard = LightGBMGuard(LightGBMGuardPolicy(expected_feature_dim=256, allowed_versions=("v4",))).scan_file(artifact)
        if not guard.clean:
            raise RuntimeError(f"synthetic artifact failed Guard: {guard.findings}")
        freeze = governance.build_freeze_manifest(
            model_id="tamandua/hist256-synthetic-pipeline-smoke", artifact_path=artifact,
            feature_contract_path=repo_root / "schemas" / "examples" / "hist256_feature_contract_v1.json",
            calibration_evidence_path=candidate / "calibration.json",
            threshold=calibration["selected_threshold"], calibration_id=calibration["calibration_id"],
            training_lineage_sha256=calibration["training_lineage_sha256"],
            calibration_lineage_sha256=calibration["calibration_lineage_sha256"],
            frozen_at="2026-07-15T00:00:00Z")
        freeze_path = scratch / "freeze.json"; freeze_path.write_bytes(governance.canonical_bytes(freeze))
        freeze_sha = _sha_file(freeze_path)
        holdout_rows = [(b"holdout-good", "goodware", 0.1), (b"holdout-malware", "malware", 0.9)]
        holdout_manifest = {"dataset_id": "synthetic-independent-holdout-smoke", "split": "holdout",
                            "samples": [{"sha256": _sha_bytes(raw), "label": label} for raw, label, _ in holdout_rows]}
        holdout_path = scratch / "holdout-lineage.json"; holdout_path.write_bytes(_canonical(holdout_manifest))
        holdout_sha = _sha_file(holdout_path)
        predictions = [{"sample_sha256": _sha_bytes(raw), "label": label,
            "predicted_label": "malware" if score >= calibration["selected_threshold"] else "goodware",
            "score": score, "latency_ms": 0.1, "model_id": freeze["model_id"],
            "artifact_sha256": freeze["artifact"]["sha256"], "feature_contract_id": "tamandua.byte-histogram-256.v1",
            "calibration_id": calibration["calibration_id"], "threshold": calibration["selected_threshold"],
            "holdout_lineage_sha256": holdout_sha, "split": "holdout"} for raw, label, score in holdout_rows]
        consumed = []
        for index, dataset_id in enumerate(("EMBER2018-test", "EMBER2024-test", "EMBER2024-challenge"), 1):
            path = scratch / f"consumed-{index}.json"
            path.write_bytes(_canonical({"dataset_id": dataset_id, "samples": [{"sha256": _sha_bytes(f"consumed-{index}".encode()), "label": "malware"}]}))
            consumed.append(path)
        holdout = governance.evaluate_holdout(freeze, predictions, freeze_manifest_sha256=freeze_sha,
            holdout_lineage_path=holdout_path, consumed_membership_paths=consumed,
            reproducibility_commands=["python tools/detection_validation/scripts/run_hist256_synthetic_pipeline_smoke.py --repo-root . --output <report.json>"])
        holdout_path_out = scratch / "holdout-evidence.json"; holdout_path_out.write_bytes(governance.canonical_bytes(holdout))
        promotion = repo_root / "docs" / "benchmarks" / "templates" / "hist256_promotion_report.blocked.json"
        registry = app / "src" / "local_model_service" / "providers.json"
        base_manifest = json.loads((repo_root / "apps" / "tamandua_agent" / "installer" / "model-sidecar" / "package-readiness-manifest.json").read_text())
        def pin(path: Path): return {"path": path.relative_to(repo_root).as_posix(), "sha256": _sha_file(path)}
        base_manifest["provider_registry"] = pin(registry); base_manifest["promotion_report"] = pin(promotion)
        base_manifest["candidate_bundle"] = {"artifact": pin(artifact),
            "feature_contract": pin(repo_root / "schemas" / "examples" / "hist256_feature_contract_v1.json"),
            "freeze_manifest": pin(freeze_path), "holdout_evidence": pin(holdout_path_out)}
        readiness_manifest = scratch / "readiness-manifest.json"; readiness_manifest.write_bytes(_canonical(base_manifest))
        readiness_report = readiness.build_report(repo_root, readiness_manifest, registry, promotion)
        if readiness_report["decision"] != "blocked" or readiness_report["may_execute_model"] is not False:
            raise RuntimeError("readiness smoke did not remain blocked/default-off")
        return {
            "api_version": "tamandua.io/hist256-synthetic-pipeline-smoke/v1",
            "kind": "Hist256SyntheticPipelineSmoke",
            "evidence_class": "synthetic_pipeline_smoke",
            "status": "completed_blocked_as_required",
            "real_runtime": {"lightgbm_version": actual_version,
                "governed_trainer_status": "blocked_runtime_version_mismatch" if actual_version != "4.5.0" else "available_not_used_by_synthetic_branch",
                "required_version": "4.5.0"},
            "stages": {"bytes_to_lineage": "synthetic_pass", "matrix_converter": "synthetic_pass",
                "scalable_trainer": "fake_contract_pass_minima_overridden_in_harness_only",
                "lightgbm_guard": guard.status, "freeze": "synthetic_pass",
                "holdout": holdout["evidence_class"], "holdout_sample_gate_met": holdout["metrics"]["sample_gate_met"],
                "readiness": readiness_report["decision"]},
            "pins": {"artifact_sha256": freeze["artifact"]["sha256"], "freeze_manifest_sha256": freeze_sha,
                "holdout_evidence_sha256": _sha_file(holdout_path_out), "feature_contract_sha256": freeze["feature_contract"]["sha256"]},
            "readiness_blockers": readiness_report["promotion_blockers"],
            "commands": ["python tools/detection_validation/scripts/run_hist256_synthetic_pipeline_smoke.py --repo-root . --output <report.json>",
                "# Re-run in an isolated environment with lightgbm==4.5.0 for a real governed trainer smoke; no package download is performed by this command."],
            "may_promote": False, "may_enforce": False, "may_publish_efficacy_claim": False,
            "claim_boundary": "Synthetic pipeline wiring smoke only. The trainer branch uses a fake LightGBM contract and undersized fixtures; installed LightGBM is version-incompatible. This does not establish efficacy, governed holdout quality, promotion, deployment, or enforcement readiness."
        }
    finally:
        shutil.rmtree(scratch)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run_smoke(args.repo_root)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
