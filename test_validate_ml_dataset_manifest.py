from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import ContractError, validate_dataset_manifest  # noqa: E402


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
