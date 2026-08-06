from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(ROOT / "apps" / "tamandua_ml" / "tests"))

from validate_ml_contracts import ContractError, validate_dataset_manifest  # noqa: E402
from apps.tamandua_ml.tests.maki_signed_receipt_test_support import signed_receipt_bundle  # noqa: E402


def smoke_manifest() -> dict:
    return json.loads((ROOT / "docs/apps/tamandua_ml/examples/ml_dataset_manifest_smoke_v1.json").read_text())


def production_manifest() -> dict:
    payload = smoke_manifest()
    payload["metadata"]["dataset_id"] = "ml-prod-candidate-v1"
    payload["metadata"]["purpose"] = "training"
    payload["metadata"]["claim_boundary"] = "Production candidate training manifest only; raw samples remain external to Git."
    payload["storage"]["raw_sample_storage"] = "external://tamandua-lab/ml-prod-candidate-v1"
    payload["sources"] = [
        {
            "source_id": "malwarebazaar_prod",
            "source_type": "malwarebazaar",
            "role": "malware",
            "acquired_at": "2026-06-04T00:00:00Z",
        },
        {
            "source_id": "goodware_system_prod",
            "source_type": "goodware_system",
            "role": "goodware",
            "acquired_at": "2026-06-04T00:00:00Z",
        },
    ]
    samples = []
    for split, suffix in [("train", "1"), ("validation", "2"), ("test", "3")]:
        samples.append(
            {
                "sample_id": f"malware-{split}",
                "sha256": f"{suffix}" * 64,
                "sha1": None,
                "md5": None,
                "label": "malware",
                "label_source": "malwarebazaar",
                "source_id": "malwarebazaar_prod",
                "split": split,
                "storage_ref": f"external://tamandua-lab/ml-prod-candidate-v1/malware-{split}",
            }
        )
        samples.append(
            {
                "sample_id": f"goodware-{split}",
                "sha256": chr(ord("a") + int(suffix)) * 64,
                "sha1": None,
                "md5": None,
                "label": "goodware",
                "label_source": "signed_goodware",
                "source_id": "goodware_system_prod",
                "split": split,
                "storage_ref": f"external://tamandua-lab/ml-prod-candidate-v1/goodware-{split}",
            }
        )
    payload["samples"] = samples
    payload["splits"] = {
        "strategy": "stratified_family",
        "seed": 1337,
        "ratios": {"train": 0.7, "validation": 0.15, "test": 0.15, "holdout": 0.0},
    }
    return payload


def test_validate_dataset_manifest_accepts_smoke_fixture() -> None:
    validate_dataset_manifest(smoke_manifest(), Path("memory://dataset.json"))


def test_validate_dataset_manifest_accepts_production_training_manifest() -> None:
    validate_dataset_manifest(production_manifest(), Path("memory://dataset.json"))


def test_validate_dataset_manifest_rejects_duplicate_sha256() -> None:
    payload = smoke_manifest()
    payload["samples"][1]["sha256"] = payload["samples"][0]["sha256"]

    try:
        validate_dataset_manifest(payload, Path("memory://dataset.json"))
    except ContractError as exc:
        assert "duplicate sample hash" in str(exc)
    else:
        raise AssertionError("expected duplicate sample sha256 to fail")


def test_validate_dataset_manifest_rejects_production_synthetic_storage() -> None:
    payload = production_manifest()
    payload["storage"]["raw_sample_storage"] = "synthetic://tamandua/ml-prod-candidate-v1"

    try:
        validate_dataset_manifest(payload, Path("memory://dataset.json"))
    except ContractError as exc:
        assert "must not use synthetic storage" in str(exc)
    else:
        raise AssertionError("expected production synthetic storage to fail")


def test_validate_dataset_manifest_rejects_production_local_storage_path() -> None:
    payload = production_manifest()
    payload["storage"]["raw_sample_storage"] = "D:\\tamandua_ml_lab_data\\production"

    try:
        validate_dataset_manifest(payload, Path("memory://dataset.json"))
    except ContractError as exc:
        assert "must use external storage URI" in str(exc)
    else:
        raise AssertionError("expected production local storage path to fail")


def test_validate_dataset_manifest_rejects_production_local_sample_storage_ref() -> None:
    payload = production_manifest()
    payload["samples"][0]["storage_ref"] = "D:\\tamandua_ml_lab_data\\production\\sample.bin"

    try:
        validate_dataset_manifest(payload, Path("memory://dataset.json"))
    except ContractError as exc:
        assert "must use external storage refs" in str(exc)
    else:
        raise AssertionError("expected production local sample storage ref to fail")


def test_validate_dataset_manifest_rejects_production_synthetic_source() -> None:
    payload = production_manifest()
    payload["sources"][0]["source_type"] = "synthetic"

    try:
        validate_dataset_manifest(payload, Path("memory://dataset.json"))
    except ContractError as exc:
        assert "must not use synthetic sources" in str(exc)
    else:
        raise AssertionError("expected production synthetic source to fail")


def test_validate_dataset_manifest_rejects_production_smoke_split() -> None:
    payload = production_manifest()
    payload["samples"][0]["split"] = "smoke"

    try:
        validate_dataset_manifest(payload, Path("memory://dataset.json"))
    except ContractError as exc:
        assert "must not use smoke/parity splits" in str(exc)
    else:
        raise AssertionError("expected production smoke split to fail")


def test_validate_dataset_manifest_rejects_training_manifest_without_all_core_splits() -> None:
    payload = production_manifest()
    payload["samples"] = [sample for sample in payload["samples"] if sample["split"] != "validation"]

    try:
        validate_dataset_manifest(payload, Path("memory://dataset.json"))
    except ContractError as exc:
        assert "must include train, validation, and test splits" in str(exc)
    else:
        raise AssertionError("expected missing training split to fail")


def test_validate_dataset_manifest_accepts_governed_v2_and_recounts(tmp_path: Path, monkeypatch) -> None:
    script = ROOT / "apps/tamandua_ml/scripts/build_governed_dataset_manifest.py"
    spec = importlib.util.spec_from_file_location("governed_manifest_builder_for_contract_test", script)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)

    def receipt(index: int, label: str, tier: str, split: str, observed_at: str) -> dict:
        sha256 = f"{index:064x}"
        return {
            "sha256": sha256, "sample_class": label, "size_bytes": 4096,
            "source_id": "contract-test", "source_evidence_sha256": "d" * 64,
            "leakage_group_id": f"group-{index}", "observed_at": observed_at, "split": split,
            "promotion_manifest_sha256": "e" * 64, "curation_manifest_sha256": "f" * 64,
            "bucket": "corpus", "version_id": f"v-{index}",
        }

    specs = [
        receipt(1, "goodware", "accepted", "train", "2026-07-14T00:00:00Z"),
        receipt(2, "goodware", "accepted", "validation", "2026-07-15T00:00:00Z"),
        receipt(3, "malware", "accepted", "train", "2026-07-14T00:00:00Z"),
        receipt(4, "malware", "accepted", "validation", "2026-07-15T00:00:00Z"),
        receipt(5, "goodware", "holdout", "holdout", "2026-08-15T00:00:00Z"),
        receipt(6, "malware", "holdout", "holdout", "2026-08-15T00:00:00Z"),
    ]
    bundle = signed_receipt_bundle(module.receipt_verifier, monkeypatch, tmp_path, specs)
    payload = module.build_snapshot(bundle.receipts, **bundle.builder_kwargs(), minimum_accepted_per_class=2, minimum_holdout_per_class=1)
    assert payload["ready_for_training"] is False
    assert payload["counts"]["holdout"] == {"goodware": 0, "malware": 0}
    validate_dataset_manifest(payload, Path("memory://governed-v2.json"))
    manifest_path = tmp_path / "governed-v2.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    command = [sys.executable, str(ROOT / "tools/detection_validation/validate_ml_contracts.py"), "--dataset-manifest", str(manifest_path)]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr

    invalid = copy.deepcopy(payload)
    invalid["policy"].pop("holdout_temporal_rule")
    manifest_path.write_text(json.dumps(invalid), encoding="utf-8")
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "holdout_temporal_rule" in result.stderr

    bad_rejections = copy.deepcopy(payload)
    bad_rejections["rejections"] = [{"reasons": ["duplicate_sha256_receipt"]}]
    try:
        validate_dataset_manifest(bad_rejections, Path("memory://governed-v2.json"))
    except ContractError as exc:
        assert "rejected_receipts" in str(exc)
    else:
        raise AssertionError("expected rejection count drift to fail")

    temporal_leak = copy.deepcopy(payload)
    next(sample for sample in temporal_leak["samples"] if sample["label"] == "malware" and sample["split"] == "validation")["observed_at"] = "2026-07-13T00:00:00Z"
    temporal_leak["dataset_snapshot_sha256"] = hashlib.sha256((json.dumps(temporal_leak["samples"], sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()).hexdigest()
    try:
        validate_dataset_manifest(temporal_leak, Path("memory://governed-v2.json"))
    except ContractError as exc:
        assert "train/validation temporal leakage" in str(exc)
    else:
        raise AssertionError("expected accepted/holdout temporal leakage to fail")

    below_target = copy.deepcopy(payload)
    below_target["policy"]["accepted_target_per_class"] = 3
    try:
        validate_dataset_manifest(below_target, Path("memory://governed-v2.json"))
    except ContractError as exc:
        assert "accepted_goodware_below_target" in str(exc)
    else:
        raise AssertionError("expected missing below-target blocker to fail")

    below_target["blockers"] = sorted(set(payload["blockers"] + ["accepted_goodware_below_target", "accepted_malware_below_target"]))
    below_target["ready_for_training"] = False
    validate_dataset_manifest(below_target, Path("memory://governed-v2-blocked.json"))

    payload["counts"]["accepted"]["malware"] += 1
    try:
        validate_dataset_manifest(payload, Path("memory://governed-v2.json"))
    except ContractError as exc:
        assert "recount mismatch" in str(exc)
    else:
        raise AssertionError("expected governed v2 count drift to fail")
