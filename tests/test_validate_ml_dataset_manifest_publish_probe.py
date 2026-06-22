from __future__ import annotations

import copy
import json
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

from validate_ml_contracts import (  # noqa: E402
    DATASET_MANIFEST_PUBLISH_PROBE_SCHEMA,
    ContractError,
    validate_contract,
    validate_dataset_manifest_publish_probe,
)


def valid_publish_probe() -> dict:
    return {
        "api_version": "tamandua.io/ml-dataset-manifest-publish-probe/v1",
        "kind": "MLDatasetManifestPublishProbe",
        "metadata": {
            "report_id": "test_publish_probe",
            "generated_at": "2026-06-04T20:29:15Z",
            "created_by": "tamandua-ml-dataset-manifest-publish-probe",
            "claim_boundary": "Synthetic manifest publication proof only. Does not download malware, collect goodware, publish the canonical production candidate manifest, train models, run inference, or contact live services.",
        },
        "source_status_summary": {
            "source_manifest_outside_repo": True,
            "output_is_not_canonical_manifest": True,
            "raw_samples_not_in_git": True,
            "malware_and_goodware_present": True,
            "train_validation_test_splits_present": True,
            "manifest_contract_validated": True,
            "dataset_id": "ml-publish-probe-v1",
            "sample_count": 4,
            "label_count": 2,
            "split_count": 3,
            "check_count": 6,
            "passed_checks": 6,
            "failed_checks": 0,
            "passed": True,
        },
        "configuration": {
            "source_manifest": "D:/ml-data/publish_probe/production/manifest.json",
            "output_manifest": "docs/benchmarks/runs/20260604T-ml-dataset-manifest-publish-probe-output.json",
            "canonical_manifest_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
            "dataset_id": "ml-publish-probe-v1",
        },
        "passed": True,
        "checks": [
            {"name": "source_manifest_outside_repo", "passed": True, "detail": "D:/ml-data/publish_probe/production/manifest.json"},
            {"name": "output_is_not_canonical_manifest", "passed": True, "detail": "docs/benchmarks/runs/20260604T-ml-dataset-manifest-publish-probe-output.json"},
            {"name": "raw_samples_not_in_git", "passed": True, "detail": "False"},
            {"name": "malware_and_goodware_present", "passed": True, "detail": "goodware,malware"},
            {"name": "train_validation_test_splits_present", "passed": True, "detail": "test,train,validation"},
            {"name": "manifest_contract_validated", "passed": True, "detail": "validate_dataset_manifest passed"},
        ],
        "sample_count": 4,
    }


def test_validate_dataset_manifest_publish_probe_accepts_valid_contract() -> None:
    validate_dataset_manifest_publish_probe(valid_publish_probe(), Path("memory://ml-dataset-manifest-publish-probe.json"))


def test_validate_dataset_manifest_publish_probe_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-dataset-manifest-publish-probe.json"
    report_path.write_text(json.dumps(valid_publish_probe()), encoding="utf-8")

    mode = validate_contract(report_path, DATASET_MANIFEST_PUBLISH_PROBE_SCHEMA, validate_dataset_manifest_publish_probe)

    assert mode == "jsonschema+built-in"


def test_validate_dataset_manifest_publish_probe_rejects_canonical_output() -> None:
    payload = copy.deepcopy(valid_publish_probe())
    canonical = payload["configuration"]["canonical_manifest_ref"]
    payload["configuration"]["output_manifest"] = canonical

    try:
        validate_dataset_manifest_publish_probe(payload, Path("memory://ml-dataset-manifest-publish-probe.json"))
    except ContractError as exc:
        assert "output_manifest" in str(exc)
    else:
        raise AssertionError("expected canonical output to fail")


def test_validate_dataset_manifest_publish_probe_rejects_wrong_dataset_id() -> None:
    payload = copy.deepcopy(valid_publish_probe())
    payload["configuration"]["dataset_id"] = "ml-prod-candidate-v1"

    try:
        validate_dataset_manifest_publish_probe(payload, Path("memory://ml-dataset-manifest-publish-probe.json"))
    except ContractError as exc:
        assert "dataset_id" in str(exc)
    else:
        raise AssertionError("expected wrong dataset_id to fail")


def test_validate_dataset_manifest_publish_probe_rejects_missing_manifest_validation_detail() -> None:
    payload = copy.deepcopy(valid_publish_probe())
    check = next(check for check in payload["checks"] if check["name"] == "manifest_contract_validated")
    check["detail"] = "skipped"

    try:
        validate_dataset_manifest_publish_probe(payload, Path("memory://ml-dataset-manifest-publish-probe.json"))
    except ContractError as exc:
        assert "manifest_contract_validated" in str(exc)
    else:
        raise AssertionError("expected missing manifest validation detail to fail")


def test_validate_dataset_manifest_publish_probe_rejects_source_summary_drift() -> None:
    payload = copy.deepcopy(valid_publish_probe())
    payload["source_status_summary"]["sample_count"] = 3

    try:
        validate_dataset_manifest_publish_probe(payload, Path("memory://ml-dataset-manifest-publish-probe.json"))
    except ContractError as exc:
        assert "source_status_summary.sample_count" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")
