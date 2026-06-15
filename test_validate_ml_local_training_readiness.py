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

from validate_ml_contracts import (  # noqa: E402
    ContractError,
    ML_LOCAL_TRAINING_READINESS_SCHEMA,
    validate_contract,
    validate_ml_local_training_readiness,
)


CHECK_NAMES = [
    "dockerfile_exists",
    "compose_exists",
    "gitattributes_exists",
    "gitignore_exists",
    "verifier_exists",
    "model_lifecycle_exists",
    "adr_local_first_accepted",
    "ci_workflow_exists",
    "dockerfile_cuda_pytorch_onnx_uv",
    "dockerfile_non_root_trainer",
    "compose_trainer_network_disabled",
    "compose_gpu_passthrough_declared",
    "compose_dataset_read_only",
    "compose_source_read_only",
    "gitattributes_lfs_patterns_present",
    "gitignore_artifact_binaries_ignored",
    "git_index_artifact_binaries_untracked",
    "verifier_checks_gpu_docker_lfs",
    "model_lifecycle_documents_training_and_lfs",
    "model_lifecycle_references_wave1_dataset_manifest",
    "ci_workflow_builds_training_dockerfile",
    "ci_workflow_does_not_train",
    "no_execution_claim_boundary_documented",
]


def valid_readiness() -> dict:
    checks = [{"name": name, "passed": True, "detail": name} for name in CHECK_NAMES]
    next(item for item in checks if item["name"] == "gitattributes_lfs_patterns_present")["missing_lfs"] = []
    next(item for item in checks if item["name"] == "gitignore_artifact_binaries_ignored")[
        "missing_artifact_ignores"
    ] = []
    next(item for item in checks if item["name"] == "git_index_artifact_binaries_untracked")[
        "tracked_artifact_binaries"
    ] = []
    next(item for item in checks if item["name"] == "git_index_artifact_binaries_untracked")[
        "git_index_available"
    ] = True
    next(item for item in checks if item["name"] == "git_index_artifact_binaries_untracked")[
        "git_index_error"
    ] = ""
    return {
        "api_version": "tamandua.io/ml-local-training-readiness/v1",
        "kind": "MLLocalTrainingReadiness",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-05T15:00:00Z",
            "created_by": "tamandua-ml-local-training-readiness",
            "claim_boundary": "No-execution ML local training readiness only. It reads local Docker, Git LFS, lifecycle, and verifier files, and does not build Docker images, run containers, run the host verifier, train models, export ONNX, run inference, benchmarks, or live services.",
        },
        "configuration": {
            "dockerfile": "docker/training-lab/Dockerfile",
            "compose": "docker/training-lab/docker-compose.yml",
            "gitattributes": ".gitattributes",
            "gitignore": ".gitignore",
            "verifier": "scripts/local-training/verify_environment.py",
            "model_lifecycle": "docs/MODEL_LIFECYCLE.md",
            "adr": "docs/architecture/adr/ADR-0001-local-first-ml-development.md",
            "ci_workflow": ".github/workflows/ml-training-lab-smoke.yml",
            "required_lfs_patterns": ["*.onnx", "*.pt", "*.safetensors", "*.pkl", "*.gguf", "*.tflite", "*.mlmodel"],
            "required_artifact_ignore_patterns": [
                "docs/benchmarks/runs/*-artifacts/*.pt",
                "docs/benchmarks/runs/*-artifacts/*.pth",
                "docs/benchmarks/runs/*-artifacts/*.pkl",
                "docs/benchmarks/runs/*-artifacts/*.npz",
                "docs/benchmarks/runs/*-artifacts/*.onnx",
            ],
        },
        "source_status_summary": {
            **{name: True for name in CHECK_NAMES},
            "check_count": len(CHECK_NAMES),
            "passed_checks": len(CHECK_NAMES),
            "failed_checks": 0,
            "passed": True,
        },
        "passed": True,
        "checks": checks,
    }


def test_validate_ml_local_training_readiness_accepts_valid_contract() -> None:
    validate_ml_local_training_readiness(valid_readiness(), Path("memory://ml-local-training-readiness.json"))


def test_validate_ml_local_training_readiness_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-local-training-readiness.json"
    report_path.write_text(json.dumps(valid_readiness()), encoding="utf-8")

    mode = validate_contract(report_path, ML_LOCAL_TRAINING_READINESS_SCHEMA, validate_ml_local_training_readiness)

    assert mode == "jsonschema+built-in"


def test_validate_ml_local_training_readiness_rejects_passed_mismatch() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["checks"][0]["passed"] = False

    try:
        validate_ml_local_training_readiness(payload, Path("memory://ml-local-training-readiness.json"))
    except ContractError as exc:
        assert ".passed" in str(exc)
    else:
        raise AssertionError("expected passed mismatch to fail")


def test_validate_ml_local_training_readiness_rejects_wrong_compose_path() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["configuration"]["compose"] = "docker-compose.yml"

    try:
        validate_ml_local_training_readiness(payload, Path("memory://ml-local-training-readiness.json"))
    except ContractError as exc:
        assert "compose" in str(exc)
    else:
        raise AssertionError("expected wrong compose path to fail")


def test_validate_ml_local_training_readiness_rejects_lfs_missing_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    check = next(item for item in payload["checks"] if item["name"] == "gitattributes_lfs_patterns_present")
    check["missing_lfs"] = ["*.pt"]

    try:
        validate_ml_local_training_readiness(payload, Path("memory://ml-local-training-readiness.json"))
    except ContractError as exc:
        assert "missing_lfs" in str(exc)
    else:
        raise AssertionError("expected missing LFS evidence to fail")


def test_validate_ml_local_training_readiness_rejects_artifact_ignore_missing_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    check = next(item for item in payload["checks"] if item["name"] == "gitignore_artifact_binaries_ignored")
    check["missing_artifact_ignores"] = ["docs/benchmarks/runs/*-artifacts/*.pt"]

    try:
        validate_ml_local_training_readiness(payload, Path("memory://ml-local-training-readiness.json"))
    except ContractError as exc:
        assert "missing_artifact_ignores" in str(exc)
    else:
        raise AssertionError("expected missing artifact ignore evidence to fail")


def test_validate_ml_local_training_readiness_rejects_tracked_artifacts_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    check = next(item for item in payload["checks"] if item["name"] == "git_index_artifact_binaries_untracked")
    check["tracked_artifact_binaries"] = ["docs/benchmarks/runs/smoke-artifacts/malware_smell.onnx"]

    try:
        validate_ml_local_training_readiness(payload, Path("memory://ml-local-training-readiness.json"))
    except ContractError as exc:
        assert "tracked_artifact_binaries" in str(exc)
    else:
        raise AssertionError("expected tracked artifact evidence to fail")


def test_validate_ml_local_training_readiness_rejects_unavailable_git_index_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    check = next(item for item in payload["checks"] if item["name"] == "git_index_artifact_binaries_untracked")
    check["git_index_available"] = False
    check["git_index_error"] = "git unavailable"

    try:
        validate_ml_local_training_readiness(payload, Path("memory://ml-local-training-readiness.json"))
    except ContractError as exc:
        assert "git_index_available" in str(exc)
    else:
        raise AssertionError("expected unavailable git index evidence to fail")


def test_validate_ml_local_training_readiness_rejects_training_ci_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    check = next(item for item in payload["checks"] if item["name"] == "ci_workflow_does_not_train")
    check["passed"] = False

    try:
        validate_ml_local_training_readiness(payload, Path("memory://ml-local-training-readiness.json"))
    except ContractError as exc:
        assert ".passed" in str(exc)
    else:
        raise AssertionError("expected training CI evidence to fail")
