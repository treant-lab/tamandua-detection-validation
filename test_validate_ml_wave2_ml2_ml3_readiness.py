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
    WAVE2_ML2_ML3_READINESS_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave2_ml2_ml3_readiness,
)
from test_validate_ml_wave2_ml1_readiness import GOAL_SNAPSHOT  # noqa: E402


def valid_wave2_ml2_ml3_readiness() -> dict:
    return {
        "api_version": "tamandua.io/ml-wave2-ml2-ml3-readiness-probe/v1",
        "kind": "MLWave2ML2ML3ReadinessProbe",
        "metadata": {
            "report_id": "test_wave2_ml2_ml3_readiness",
            "generated_at": "2026-06-04T22:30:00Z",
            "created_by": "tamandua-ml-wave2-ml2-ml3-readiness-probe",
            "claim_boundary": "No-execution ML-2/ML-3 readiness probe only. Does not run ONNX parity, build fixtures, run cargo, train models, run inference, or contact live services.",
        },
        "configuration": {
            "status_ref": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
            "wave2_ml1_readiness_ref": "docs/benchmarks/runs/20260604T-ml-wave2-ml1-readiness-probe.json",
            "ml1_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
            "model_contract": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
            "onnx_model": "docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.onnx",
            "onnx_metadata": "docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json",
            "launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml2_ml3_parity_launcher.ps1",
            "data_root": "D:/tamandua_ml_lab_data",
        },
        "source": {
            "execution_status": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
            "execution_status_validation": "jsonschema+built-in",
            "wave2_ml1_readiness": "docs/benchmarks/runs/20260604T-ml-wave2-ml1-readiness-probe.json",
            "wave2_ml1_readiness_validation": "jsonschema+built-in",
            "ml1_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
            "ml1_report_validation": "missing",
            "model_contract": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
            "ml1_model_contract_validation": "missing",
            "onnx_model": "docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.onnx",
            "onnx_metadata": "docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json",
            "source_status_summary": {
                **GOAL_SNAPSHOT,
                "wave2_ml1_ready_for_candidate": False,
                "wave2_ml1_lab_guard_proof_mismatch_count": 0,
                "wave2_ml1_ml_lab_standby_guards_unset": True,
                "ml1_benchmark_report_present": False,
                "ml1_model_contract_present": False,
                "ml1_model_contract_valid": False,
                "ml1_model_contract_artifact_sha256": "",
                "ml1_model_contract_artifact_size_bytes": 0,
                "ml1_model_contract_artifact_sha256_matches_onnx": False,
                "ml1_model_contract_artifact_size_matches_onnx": False,
                "ml1_model_contract_metadata_sha256": "",
                "ml1_model_contract_metadata_size_bytes": 0,
                "ml1_model_contract_metadata_sha256_matches_sidecar": False,
                "ml1_model_contract_metadata_size_matches_sidecar": False,
                "candidate_onnx_model_present": False,
                "candidate_onnx_model_nonempty": False,
                "candidate_onnx_model_size_bytes": 0,
                "candidate_onnx_model_sha256": "",
                "candidate_onnx_model_canonical_path": True,
                "candidate_onnx_metadata_present": True,
                "candidate_onnx_metadata_sha256": "1" * 64,
                "candidate_onnx_metadata_contract_ref": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
                "candidate_onnx_metadata_model_contract_type": "malware_smell_onnx",
                "candidate_onnx_metadata_io_names_valid": True,
                "candidate_onnx_metadata_preprocessing_valid": True,
                "rustc_version": "rustc 1.88.0 (fixture)",
                "rustc_minimum_version": "1.88.0",
                "rustc_present_for_agent_onnx_parity": True,
                "rustc_meets_minimum_for_agent_onnx_parity": True,
                "ort_dylib_path": "D:/tamandua_ml_lab/tools/onnxruntime.dll",
                "ort_dylib_version": "1.23.2",
                "ort_dylib_minimum_version": "1.23.0",
                "ort_dylib_path_configured_for_agent_onnx_parity": True,
                "ort_dylib_path_exists_for_agent_onnx_parity": True,
                "ort_dylib_path_is_dll_for_agent_onnx_parity": True,
                "ort_dylib_meets_minimum_for_agent_onnx_parity": True,
                "ml2_ml3_launcher_exists": True,
                "data_root_outside_repo": True,
                "required_input_count": 5,
                "required_inputs_present": 5,
                "blocker_count": 4,
                "blockers": [
                    "wave2_ml1_readiness_blocked",
                    "missing_ml1_benchmark_report",
                    "missing_candidate_onnx_model",
                    "missing_ml1_model_contract",
                ],
            },
        },
        "ready_for_ml2_ml3_parity": False,
        "blockers": [
            "wave2_ml1_readiness_blocked",
            "missing_ml1_benchmark_report",
            "missing_candidate_onnx_model",
            "missing_ml1_model_contract",
        ],
        "checks": [
            {"name": "execution_status_valid", "passed": True, "detail": "status"},
            {"name": "wave2_ml1_readiness_valid", "passed": True, "detail": "ml1 readiness"},
            {"name": "wave2_ml1_ready_for_candidate", "passed": False, "detail": "ml1 readiness blockers"},
            {"name": "wave2_ml1_lab_guard_proof_clean", "passed": True, "detail": "mismatch_count=0"},
            {"name": "wave2_ml1_ml_lab_standby_guards_unset", "passed": True, "detail": "guards_unset=True"},
            {"name": "ml1_benchmark_report_present", "passed": False, "detail": "ml1"},
            {"name": "ml1_report_lane_is_ml1", "passed": False, "detail": "ml1"},
            {"name": "ml1_report_dataset_candidate", "passed": False, "detail": "ml1"},
            {"name": "ml1_report_quality_gate_passed", "passed": False, "detail": "ml1"},
            {"name": "ml1_report_has_malware_goodware_samples", "passed": False, "detail": "ml1"},
            {"name": "candidate_onnx_model_present", "passed": False, "detail": "onnx"},
            {"name": "candidate_onnx_model_nonempty", "passed": False, "detail": "onnx"},
            {"name": "candidate_onnx_model_canonical_path", "passed": True, "detail": "onnx"},
            {"name": "candidate_onnx_model_sha256_recorded", "passed": False, "detail": "missing"},
            {"name": "ml1_model_contract_present", "passed": False, "detail": "contract"},
            {"name": "ml1_model_contract_valid", "passed": False, "detail": "missing"},
            {"name": "ml1_model_contract_artifact_sha256_matches_onnx", "passed": False, "detail": "missing"},
            {"name": "ml1_model_contract_artifact_size_matches_onnx", "passed": False, "detail": "missing"},
            {"name": "ml1_model_contract_metadata_sha256_matches_sidecar", "passed": False, "detail": "missing"},
            {"name": "ml1_model_contract_metadata_size_matches_sidecar", "passed": False, "detail": "missing"},
            {"name": "candidate_onnx_metadata_present", "passed": True, "detail": "metadata"},
            {
                "name": "candidate_onnx_metadata_contract_ref_candidate",
                "passed": True,
                "detail": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
            },
            {"name": "candidate_onnx_metadata_contract_type_valid", "passed": True, "detail": "malware_smell_onnx"},
            {"name": "candidate_onnx_metadata_io_names_valid", "passed": True, "detail": "input->output"},
            {"name": "candidate_onnx_metadata_preprocessing_valid", "passed": True, "detail": "image_size=64"},
            {"name": "rustc_present_for_agent_onnx_parity", "passed": True, "detail": "rustc 1.88.0 (fixture)"},
            {"name": "rustc_meets_minimum_for_agent_onnx_parity", "passed": True, "detail": "required>=1.88.0; observed=rustc 1.88.0 (fixture)"},
            {"name": "ort_dylib_path_configured_for_agent_onnx_parity", "passed": True, "detail": "D:/tamandua_ml_lab/tools/onnxruntime.dll"},
            {"name": "ort_dylib_path_exists_for_agent_onnx_parity", "passed": True, "detail": "D:/tamandua_ml_lab/tools/onnxruntime.dll"},
            {"name": "ort_dylib_path_is_dll_for_agent_onnx_parity", "passed": True, "detail": "D:/tamandua_ml_lab/tools/onnxruntime.dll"},
            {"name": "ort_dylib_meets_minimum_for_agent_onnx_parity", "passed": True, "detail": "required>=1.23.0; observed=1.23.2"},
            {"name": "ml2_ml3_launcher_exists", "passed": True, "detail": "launcher"},
            {"name": "data_root_outside_repo", "passed": True, "detail": "data-root"},
            {"name": "required_input_exists:apps/tamandua_ml/scripts/onnx_parity.py", "passed": True, "detail": "script"},
            {
                "name": "required_input_exists:apps/tamandua_ml/scripts/build_agent_parity_fixture.py",
                "passed": True,
                "detail": "script",
            },
            {
                "name": "required_input_exists:apps/tamandua_ml/scripts/ml3_agent_parity_report.py",
                "passed": True,
                "detail": "script",
            },
            {
                "name": "required_input_exists:apps/tamandua_agent/tests/ml_agent_parity_fixture_contract.rs",
                "passed": True,
                "detail": "test",
            },
            {
                "name": "required_input_exists:apps/tamandua_agent/src/bin/ml_agent_onnx_parity.rs",
                "passed": True,
                "detail": "bin",
            },
        ],
        "operator_sequence": [
            {
                "step": 1,
                "mode": "validation_only",
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml2_ml3_parity_launcher.ps1'",
                "claim_boundary": "Validates ML-2/ML-3 prerequisites and prints parity commands without running them.",
            },
            {
                "step": 2,
                "mode": "execute",
                "guard_set_command": "$env:TAMANDUA_ALLOW_ML_PARITY = '1'",
                "required_env": {
                    "TAMANDUA_ML_DATA_ROOT": "D:/tamandua_ml_lab_data",
                    "TAMANDUA_ALLOW_ML_PARITY": "1",
                    "ORT_DYLIB_PATH": "D:/tamandua_ml_lab/tools/onnxruntime.dll",
                },
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml2_ml3_parity_launcher.ps1' -Execute",
                "guard_cleanup_command": "Remove-Item Env:TAMANDUA_ALLOW_ML_PARITY -ErrorAction SilentlyContinue",
                "claim_boundary": "Runs ML-2 ONNX parity plus ML-3 fixture contract/Rust agent parity commands.",
            },
        ],
    }


def sync_source(payload: dict) -> None:
    source_summary = payload["source"]["source_status_summary"]
    check_by_name = {check["name"]: check for check in payload["checks"]}
    for field, check_name in {
        "wave2_ml1_ready_for_candidate": "wave2_ml1_ready_for_candidate",
        "wave2_ml1_ml_lab_standby_guards_unset": "wave2_ml1_ml_lab_standby_guards_unset",
        "ml1_benchmark_report_present": "ml1_benchmark_report_present",
        "ml1_model_contract_present": "ml1_model_contract_present",
        "ml1_model_contract_valid": "ml1_model_contract_valid",
        "ml1_model_contract_artifact_sha256_matches_onnx": "ml1_model_contract_artifact_sha256_matches_onnx",
        "ml1_model_contract_artifact_size_matches_onnx": "ml1_model_contract_artifact_size_matches_onnx",
        "ml1_model_contract_metadata_sha256_matches_sidecar": "ml1_model_contract_metadata_sha256_matches_sidecar",
        "ml1_model_contract_metadata_size_matches_sidecar": "ml1_model_contract_metadata_size_matches_sidecar",
        "candidate_onnx_model_present": "candidate_onnx_model_present",
        "candidate_onnx_model_nonempty": "candidate_onnx_model_nonempty",
        "candidate_onnx_model_canonical_path": "candidate_onnx_model_canonical_path",
        "candidate_onnx_metadata_present": "candidate_onnx_metadata_present",
        "candidate_onnx_metadata_io_names_valid": "candidate_onnx_metadata_io_names_valid",
        "candidate_onnx_metadata_preprocessing_valid": "candidate_onnx_metadata_preprocessing_valid",
        "rustc_present_for_agent_onnx_parity": "rustc_present_for_agent_onnx_parity",
        "rustc_meets_minimum_for_agent_onnx_parity": "rustc_meets_minimum_for_agent_onnx_parity",
        "ort_dylib_path_configured_for_agent_onnx_parity": "ort_dylib_path_configured_for_agent_onnx_parity",
        "ort_dylib_path_exists_for_agent_onnx_parity": "ort_dylib_path_exists_for_agent_onnx_parity",
        "ort_dylib_path_is_dll_for_agent_onnx_parity": "ort_dylib_path_is_dll_for_agent_onnx_parity",
        "ort_dylib_meets_minimum_for_agent_onnx_parity": "ort_dylib_meets_minimum_for_agent_onnx_parity",
        "ml2_ml3_launcher_exists": "ml2_ml3_launcher_exists",
        "data_root_outside_repo": "data_root_outside_repo",
    }.items():
        source_summary[field] = check_by_name[check_name]["passed"]
    source_summary["wave2_ml1_lab_guard_proof_mismatch_count"] = 0 if check_by_name["wave2_ml1_lab_guard_proof_clean"]["passed"] else 1
    if check_by_name["candidate_onnx_model_present"]["passed"] is True:
        source_summary["candidate_onnx_model_size_bytes"] = 4 if check_by_name["candidate_onnx_model_nonempty"]["passed"] is True else 0
        source_summary["candidate_onnx_model_sha256"] = (
            "0" * 64 if check_by_name["candidate_onnx_model_sha256_recorded"]["passed"] is True else ""
        )
    else:
        source_summary["candidate_onnx_model_size_bytes"] = 0
        source_summary["candidate_onnx_model_sha256"] = ""
    if check_by_name["ml1_model_contract_present"]["passed"] is True:
        source_summary["ml1_model_contract_artifact_sha256"] = (
            source_summary["candidate_onnx_model_sha256"]
            if check_by_name["ml1_model_contract_artifact_sha256_matches_onnx"]["passed"] is True
            else "1" * 64
        )
        source_summary["ml1_model_contract_artifact_size_bytes"] = (
            source_summary["candidate_onnx_model_size_bytes"]
            if check_by_name["ml1_model_contract_artifact_size_matches_onnx"]["passed"] is True
            else 1
        )
        source_summary["ml1_model_contract_metadata_sha256"] = (
            source_summary["candidate_onnx_metadata_sha256"]
            if check_by_name["ml1_model_contract_metadata_sha256_matches_sidecar"]["passed"] is True
            else "2" * 64
        )
        source_summary["ml1_model_contract_metadata_size_bytes"] = (
            128 if check_by_name["ml1_model_contract_metadata_size_matches_sidecar"]["passed"] is True else 1
        )
    else:
        source_summary["ml1_model_contract_artifact_sha256"] = ""
        source_summary["ml1_model_contract_artifact_size_bytes"] = 0
        source_summary["ml1_model_contract_metadata_sha256"] = ""
        source_summary["ml1_model_contract_metadata_size_bytes"] = 0
    if check_by_name["candidate_onnx_metadata_present"]["passed"] is True:
        source_summary["candidate_onnx_metadata_sha256"] = "1" * 64
        source_summary["candidate_onnx_metadata_contract_ref"] = (
            "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json"
            if check_by_name["candidate_onnx_metadata_contract_ref_candidate"]["passed"] is True
            else "docs/apps/tamandua_ml/examples/ml_model_contract_malware_smell_onnx_v1.json"
        )
        source_summary["candidate_onnx_metadata_model_contract_type"] = (
            "malware_smell_onnx" if check_by_name["candidate_onnx_metadata_contract_type_valid"]["passed"] is True else "unexpected"
        )
    else:
        source_summary["candidate_onnx_metadata_sha256"] = ""
        source_summary["candidate_onnx_metadata_contract_ref"] = ""
        source_summary["candidate_onnx_metadata_model_contract_type"] = ""
    input_checks = [name for name in check_by_name if name.startswith("required_input_exists:")]
    source_summary["required_input_count"] = len(input_checks)
    source_summary["required_inputs_present"] = sum(1 for name in input_checks if check_by_name[name]["passed"] is True)
    source_summary["blockers"] = list(payload["blockers"])
    source_summary["blocker_count"] = len(payload["blockers"])


def test_validate_wave2_ml2_ml3_readiness_accepts_blocked_contract() -> None:
    validate_wave2_ml2_ml3_readiness(valid_wave2_ml2_ml3_readiness(), Path("memory://ml-wave2-ml2-ml3-readiness.json"))


def test_validate_wave2_ml2_ml3_readiness_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-wave2-ml2-ml3-readiness.json"
    report_path.write_text(json.dumps(valid_wave2_ml2_ml3_readiness()), encoding="utf-8")

    mode = validate_contract(report_path, WAVE2_ML2_ML3_READINESS_SCHEMA, validate_wave2_ml2_ml3_readiness)

    assert mode == "jsonschema+built-in"


def test_validate_wave2_ml2_ml3_readiness_rejects_ready_without_onnx() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["ready_for_ml2_ml3_parity"] = True
    payload["blockers"] = []
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "failed checks" in str(exc)
    else:
        raise AssertionError("expected ready without candidate artifacts to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_ready_with_failed_required_input() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["ready_for_ml2_ml3_parity"] = True
    payload["blockers"] = []
    for check in payload["checks"]:
        check["passed"] = True
    failed_input = next(check for check in payload["checks"] if check["name"] == "required_input_exists:apps/tamandua_ml/scripts/onnx_parity.py")
    failed_input["passed"] = False
    payload["source"]["ml1_report_validation"] = "jsonschema+built-in"
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "failed checks" in str(exc)
    else:
        raise AssertionError("expected ready parity report with failed required input to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_onnx_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_ml1_benchmark_report"]
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "candidate ONNX model blocker" in str(exc)
    else:
        raise AssertionError("expected missing ONNX blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_empty_onnx_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_ml1_benchmark_report", "missing_candidate_onnx_model"]
    for check in payload["checks"]:
        if check["name"] == "candidate_onnx_model_present":
            check["passed"] = True
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "empty candidate ONNX model blocker" in str(exc)
    else:
        raise AssertionError("expected missing empty ONNX blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_noncanonical_onnx_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_ml1_benchmark_report"]
    for check in payload["checks"]:
        if check["name"] in {
            "candidate_onnx_model_present",
            "candidate_onnx_model_nonempty",
            "candidate_onnx_model_sha256_recorded",
        }:
            check["passed"] = True
        if check["name"] == "candidate_onnx_model_canonical_path":
            check["passed"] = False
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "canonical candidate ONNX model blocker" in str(exc)
    else:
        raise AssertionError("expected missing noncanonical ONNX blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_model_contract_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_ml1_benchmark_report", "missing_candidate_onnx_model"]
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "missing ML-1 model contract blocker" in str(exc)
    else:
        raise AssertionError("expected missing model contract blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_model_contract_hash_mismatch() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_ml1_benchmark_report", "ml1_model_contract_onnx_size_mismatch"]
    for check in payload["checks"]:
        if check["name"] in {
            "candidate_onnx_model_present",
            "candidate_onnx_model_nonempty",
            "candidate_onnx_model_sha256_recorded",
            "ml1_model_contract_present",
            "ml1_model_contract_valid",
            "ml1_model_contract_artifact_size_matches_onnx",
        }:
            check["passed"] = True
        if check["name"] == "ml1_model_contract_artifact_sha256_matches_onnx":
            check["passed"] = False
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "must match candidate ONNX SHA-256" in str(exc)
    else:
        raise AssertionError("expected model contract SHA mismatch to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_model_contract_metadata_hash_mismatch() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = [
        "wave2_ml1_readiness_blocked",
        "missing_ml1_benchmark_report",
        "ml1_model_contract_onnx_metadata_size_mismatch",
    ]
    for check in payload["checks"]:
        if check["name"] in {
            "candidate_onnx_model_present",
            "candidate_onnx_model_nonempty",
            "candidate_onnx_model_sha256_recorded",
            "ml1_model_contract_present",
            "ml1_model_contract_valid",
            "ml1_model_contract_artifact_sha256_matches_onnx",
            "ml1_model_contract_artifact_size_matches_onnx",
            "ml1_model_contract_metadata_size_matches_sidecar",
        }:
            check["passed"] = True
        if check["name"] == "ml1_model_contract_metadata_sha256_matches_sidecar":
            check["passed"] = False
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "must match candidate ONNX metadata SHA-256" in str(exc)
    else:
        raise AssertionError("expected model contract metadata SHA mismatch to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_invalid_ml1_report_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_candidate_onnx_model"]
    for check in payload["checks"]:
        if check["name"] in {"ml1_benchmark_report_present", "ml1_report_lane_is_ml1"}:
            check["passed"] = True
    payload["source"]["ml1_report_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "invalid candidate ML-1 report blocker" in str(exc)
    else:
        raise AssertionError("expected missing invalid ML-1 report blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_ml1_readiness_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = ["missing_ml1_benchmark_report", "missing_candidate_onnx_model"]
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "blocked ML-1 readiness blocker" in str(exc)
    else:
        raise AssertionError("expected missing ML-1 readiness blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_ml1_lab_guard_proof_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    for check in payload["checks"]:
        if check["name"] == "wave2_ml1_lab_guard_proof_clean":
            check["passed"] = False
            break
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "lab guard proof blocker" in str(exc)
    else:
        raise AssertionError("expected missing ML-1 lab guard proof blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_ml1_lab_guard_unset_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    for check in payload["checks"]:
        if check["name"] == "wave2_ml1_ml_lab_standby_guards_unset":
            check["passed"] = False
            break
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "lab execution guard blocker" in str(exc)
    else:
        raise AssertionError("expected missing ML-1 lab guard unset blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_parity_guard() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["operator_sequence"][1]["required_env"]["TAMANDUA_ALLOW_ML_PARITY"] = "0"

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "ML parity guard" in str(exc)
    else:
        raise AssertionError("expected missing parity guard to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_parity_guard_set_command() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["operator_sequence"][1]["guard_set_command"] = "$env:TAMANDUA_ALLOW_ML_PARITY='1'"

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "guard_set_command" in str(exc)
    else:
        raise AssertionError("expected missing parity guard set command to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_parity_guard_cleanup_command() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["operator_sequence"][1]["guard_cleanup_command"] = "Remove-Item Env:TAMANDUA_ALLOW_ML_TRAINING"

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "guard_cleanup_command" in str(exc)
    else:
        raise AssertionError("expected missing parity guard cleanup command to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_inline_parity_guard_assignment() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["operator_sequence"][1]["command"] = (
        "$env:TAMANDUA_ALLOW_ML_PARITY = '1'; "
        "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml2_ml3_parity_launcher.ps1' -Execute"
    )

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "inline parity guard assignment" in str(exc)
    else:
        raise AssertionError("expected inline parity guard assignment to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_ort_dylib_required_env() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    del payload["operator_sequence"][1]["required_env"]["ORT_DYLIB_PATH"]

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "ONNX Runtime dylib path" in str(exc)
    else:
        raise AssertionError("expected missing ONNX Runtime dylib env to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_missing_ort_minimum_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    for check in payload["checks"]:
        if check["name"] == "ort_dylib_meets_minimum_for_agent_onnx_parity":
            check["passed"] = False
            break
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "ONNX Runtime minimum-version blocker" in str(exc)
    else:
        raise AssertionError("expected missing ONNX Runtime minimum-version blocker to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_not_ready_when_all_checks_pass() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["blockers"] = ["stale_blocker"]
    for check in payload["checks"]:
        check["passed"] = True
    payload["source"]["ml1_report_validation"] = "jsonschema+built-in"
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "cannot be false when all checks pass" in str(exc)
    else:
        raise AssertionError("expected stale parity readiness report to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_source_status_summary_drift() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["source"]["source_status_summary"]["candidate_onnx_model_present"] = True

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "source_status_summary" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_wave2_ml2_ml3_readiness_rejects_source_validation_mode_drift() -> None:
    payload = copy.deepcopy(valid_wave2_ml2_ml3_readiness())
    payload["source"]["execution_status_validation"] = "failed"

    try:
        validate_wave2_ml2_ml3_readiness(payload, Path("memory://ml-wave2-ml2-ml3-readiness.json"))
    except ContractError as exc:
        assert "execution_status_validation" in str(exc)
    else:
        raise AssertionError("expected source validation drift to fail")
