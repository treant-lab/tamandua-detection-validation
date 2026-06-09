from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import (  # noqa: E402
    WAVE2_ML4_READINESS_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave2_ml4_readiness,
)
from test_validate_ml_wave2_ml1_readiness import GOAL_SNAPSHOT  # noqa: E402


def valid_wave2_ml4_readiness() -> dict:
    return {
        "api_version": "tamandua.io/ml-wave2-ml4-readiness-probe/v1",
        "kind": "MLWave2ML4ReadinessProbe",
        "metadata": {
            "report_id": "test_wave2_ml4_readiness",
            "generated_at": "2026-06-04T22:45:00Z",
            "created_by": "tamandua-ml-wave2-ml4-readiness-probe",
            "claim_boundary": "No-execution ML-4 readiness probe only. Does not contact the FastAPI service, run benchmark requests, train models, run inference, or publish manifests.",
        },
        "configuration": {
            "status_ref": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
            "wave2_ml1_readiness_ref": "docs/benchmarks/runs/20260604T-ml-wave2-ml1-readiness-probe.json",
            "ml1_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
            "model_contract": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
            "model_card": "docs/benchmarks/runs/ml-prod-candidate-v1-model-card.md",
            "launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml4_service_launcher.ps1",
            "base_url": "http://127.0.0.1:8000",
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
            "model_card": "docs/benchmarks/runs/ml-prod-candidate-v1-model-card.md",
            "source_status_summary": {
                **GOAL_SNAPSHOT,
                "wave2_ml1_ready_for_candidate": False,
                "wave2_ml1_lab_guard_proof_mismatch_count": 0,
                "wave2_ml1_ml_lab_standby_guards_unset": True,
                "ml1_benchmark_report_present": False,
                "ml1_model_contract_present": False,
                "ml1_model_contract_valid": False,
                "ml1_model_card_present": False,
                "ml1_model_card_nonempty": False,
                "ml1_model_card_references_contract": False,
                "api_key_present": False,
                "base_url": "http://127.0.0.1:8000",
                "base_url_valid_http": True,
                "base_url_no_credentials": True,
                "base_url_origin_only": True,
                "base_url_not_placeholder": True,
                "benchmark_endpoint_count": 4,
                "benchmark_endpoints": ["GET /health", "GET /ready", "POST /predict", "POST /predict/batch"],
                "ml4_launcher_exists": True,
                "required_input_count": 1,
                "required_inputs_present": 1,
                "blocker_count": 5,
                "blockers": [
                    "wave2_ml1_readiness_blocked",
                    "missing_ml1_benchmark_report",
                    "missing_ml1_model_contract",
                    "missing_ml1_model_card",
                    "missing_env:TAMANDUA_ML_API_KEY",
                ],
            },
        },
        "ready_for_ml4_service_benchmark": False,
        "blockers": [
            "wave2_ml1_readiness_blocked",
            "missing_ml1_benchmark_report",
            "missing_ml1_model_contract",
            "missing_ml1_model_card",
            "missing_env:TAMANDUA_ML_API_KEY",
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
            {"name": "ml1_model_contract_present", "passed": False, "detail": "contract"},
            {"name": "ml1_model_contract_valid", "passed": False, "detail": "missing"},
            {"name": "ml1_model_card_present", "passed": False, "detail": "card"},
            {"name": "ml1_model_card_nonempty", "passed": False, "detail": "card"},
            {"name": "ml1_model_card_references_contract", "passed": False, "detail": "contract"},
            {"name": "api_key_present", "passed": False, "detail": "missing_or_placeholder"},
            {"name": "base_url_valid_http", "passed": True, "detail": "http://127.0.0.1:8000"},
            {"name": "base_url_no_credentials", "passed": True, "detail": "http://127.0.0.1:8000"},
            {"name": "base_url_origin_only", "passed": True, "detail": "http://127.0.0.1:8000"},
            {"name": "base_url_not_placeholder", "passed": True, "detail": "http://127.0.0.1:8000"},
            {"name": "ml4_launcher_exists", "passed": True, "detail": "launcher"},
            {"name": "required_input_exists:apps/tamandua_ml/scripts/ml4_api_benchmark.py", "passed": True, "detail": "script"},
        ],
        "operator_sequence": [
            {
                "step": 1,
                "mode": "validation_only",
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml4_service_launcher.ps1'",
                "claim_boundary": "Validates ML-4 prerequisites and prints service benchmark command without contacting the service.",
            },
            {
                "step": 2,
                "mode": "execute",
                "guard_set_command": "$env:TAMANDUA_ALLOW_ML_SERVICE_BENCH = '1'",
                "required_env": {
                    "TAMANDUA_ML_API_KEY": "<ml-service-api-key>",
                    "TAMANDUA_ALLOW_ML_SERVICE_BENCH": "1",
                },
                "optional_env": {"TAMANDUA_ML_BASE_URL": "http://127.0.0.1:8000"},
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml4_service_launcher.ps1' -Execute",
                "guard_cleanup_command": "Remove-Item Env:TAMANDUA_ALLOW_ML_SERVICE_BENCH -ErrorAction SilentlyContinue",
                "claim_boundary": "Runs live FastAPI ML service benchmark against the candidate model service.",
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
        "ml1_model_card_present": "ml1_model_card_present",
        "ml1_model_card_nonempty": "ml1_model_card_nonempty",
        "ml1_model_card_references_contract": "ml1_model_card_references_contract",
        "api_key_present": "api_key_present",
        "base_url_valid_http": "base_url_valid_http",
        "base_url_no_credentials": "base_url_no_credentials",
        "base_url_origin_only": "base_url_origin_only",
        "base_url_not_placeholder": "base_url_not_placeholder",
        "ml4_launcher_exists": "ml4_launcher_exists",
    }.items():
        source_summary[field] = check_by_name[check_name]["passed"]
    source_summary["wave2_ml1_lab_guard_proof_mismatch_count"] = 0 if check_by_name["wave2_ml1_lab_guard_proof_clean"]["passed"] else 1
    source_summary["base_url"] = payload["configuration"]["base_url"]
    source_summary["benchmark_endpoint_count"] = len(source_summary["benchmark_endpoints"])
    input_checks = [name for name in check_by_name if name.startswith("required_input_exists:")]
    source_summary["required_input_count"] = len(input_checks)
    source_summary["required_inputs_present"] = sum(1 for name in input_checks if check_by_name[name]["passed"] is True)
    source_summary["blockers"] = list(payload["blockers"])
    source_summary["blocker_count"] = len(payload["blockers"])


def test_validate_wave2_ml4_readiness_accepts_blocked_contract() -> None:
    validate_wave2_ml4_readiness(valid_wave2_ml4_readiness(), Path("memory://ml-wave2-ml4-readiness.json"))


def test_validate_wave2_ml4_readiness_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-wave2-ml4-readiness.json"
    report_path.write_text(json.dumps(valid_wave2_ml4_readiness()), encoding="utf-8")

    mode = validate_contract(report_path, WAVE2_ML4_READINESS_SCHEMA, validate_wave2_ml4_readiness)

    assert mode == "jsonschema+built-in"


def test_validate_wave2_ml4_readiness_rejects_ready_without_api_key() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["ready_for_ml4_service_benchmark"] = True
    payload["blockers"] = []
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "failed checks" in str(exc)
    else:
        raise AssertionError("expected ready without API key to fail")


def test_validate_wave2_ml4_readiness_rejects_ready_with_failed_required_input() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["ready_for_ml4_service_benchmark"] = True
    payload["blockers"] = []
    for check in payload["checks"]:
        check["passed"] = True
    failed_input = next(check for check in payload["checks"] if check["name"] == "required_input_exists:apps/tamandua_ml/scripts/ml4_api_benchmark.py")
    failed_input["passed"] = False
    payload["source"]["ml1_report_validation"] = "jsonschema+built-in"
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "failed checks" in str(exc)
    else:
        raise AssertionError("expected ready ML-4 report with failed required input to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_api_key_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_ml1_benchmark_report", "missing_ml1_model_contract", "missing_ml1_model_card"]
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "API key blocker" in str(exc)
    else:
        raise AssertionError("expected missing API key blocker to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_base_url_credentials_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["configuration"]["base_url"] = "http://user:pass@127.0.0.1:8000"
    payload["operator_sequence"][1]["optional_env"]["TAMANDUA_ML_BASE_URL"] = "http://user:pass@127.0.0.1:8000"
    payload["blockers"] = [
        "wave2_ml1_readiness_blocked",
        "missing_ml1_benchmark_report",
        "missing_ml1_model_contract",
        "missing_ml1_model_card",
        "missing_env:TAMANDUA_ML_API_KEY",
    ]
    for check in payload["checks"]:
        if check["name"] == "base_url_no_credentials":
            check["passed"] = False
            check["detail"] = "http://user:pass@127.0.0.1:8000"
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "base URL credentials blocker" in str(exc)
    else:
        raise AssertionError("expected missing base URL credentials blocker to fail")


def test_validate_wave2_ml4_readiness_rejects_optional_base_url_drift() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["operator_sequence"][1]["optional_env"]["TAMANDUA_ML_BASE_URL"] = "http://127.0.0.1:9000"

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "TAMANDUA_ML_BASE_URL" in str(exc)
    else:
        raise AssertionError("expected optional base URL drift to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_invalid_ml1_report_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_ml1_model_contract", "missing_ml1_model_card", "missing_env:TAMANDUA_ML_API_KEY"]
    for check in payload["checks"]:
        if check["name"] in {"ml1_benchmark_report_present", "ml1_report_lane_is_ml1"}:
            check["passed"] = True
    payload["source"]["ml1_report_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "invalid candidate ML-1 report blocker" in str(exc)
    else:
        raise AssertionError("expected missing invalid ML-1 report blocker to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_ml1_readiness_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["blockers"] = ["missing_ml1_benchmark_report", "missing_ml1_model_contract", "missing_ml1_model_card", "missing_env:TAMANDUA_ML_API_KEY"]
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "blocked ML-1 readiness blocker" in str(exc)
    else:
        raise AssertionError("expected missing ML-1 readiness blocker to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_ml1_lab_guard_proof_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    for check in payload["checks"]:
        if check["name"] == "wave2_ml1_lab_guard_proof_clean":
            check["passed"] = False
            break
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "lab guard proof blocker" in str(exc)
    else:
        raise AssertionError("expected missing ML-1 lab guard proof blocker to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_ml1_lab_guard_unset_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    for check in payload["checks"]:
        if check["name"] == "wave2_ml1_ml_lab_standby_guards_unset":
            check["passed"] = False
            break
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "lab execution guard blocker" in str(exc)
    else:
        raise AssertionError("expected missing ML-1 lab guard unset blocker to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_model_contract_blocker() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["blockers"] = ["wave2_ml1_readiness_blocked", "missing_ml1_benchmark_report", "missing_ml1_model_card", "missing_env:TAMANDUA_ML_API_KEY"]
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "missing ML-1 model contract blocker" in str(exc)
    else:
        raise AssertionError("expected missing model contract blocker to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_service_guard() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["operator_sequence"][1]["required_env"]["TAMANDUA_ALLOW_ML_SERVICE_BENCH"] = "0"

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "ML service benchmark guard" in str(exc)
    else:
        raise AssertionError("expected missing service guard to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_service_guard_set_command() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["operator_sequence"][1]["guard_set_command"] = "$env:TAMANDUA_ALLOW_ML_SERVICE_BENCH='1'"

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "guard_set_command" in str(exc)
    else:
        raise AssertionError("expected missing service guard set command to fail")


def test_validate_wave2_ml4_readiness_rejects_missing_service_guard_cleanup_command() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["operator_sequence"][1]["guard_cleanup_command"] = "Remove-Item Env:TAMANDUA_ALLOW_ML_PARITY"

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "guard_cleanup_command" in str(exc)
    else:
        raise AssertionError("expected missing service guard cleanup command to fail")


def test_validate_wave2_ml4_readiness_rejects_inline_service_guard_assignment() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["operator_sequence"][1]["command"] = (
        "$env:TAMANDUA_ALLOW_ML_SERVICE_BENCH = '1'; "
        "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_2_ml4_service_launcher.ps1' -Execute"
    )

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "inline service benchmark guard assignment" in str(exc)
    else:
        raise AssertionError("expected inline service guard assignment to fail")


def test_validate_wave2_ml4_readiness_rejects_not_ready_when_all_checks_pass() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["blockers"] = ["stale_blocker"]
    for check in payload["checks"]:
        check["passed"] = True
    payload["source"]["ml1_report_validation"] = "jsonschema+built-in"
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "cannot be false when all checks pass" in str(exc)
    else:
        raise AssertionError("expected stale ML-4 readiness report to fail")


def test_validate_wave2_ml4_readiness_rejects_source_status_summary_drift() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["source"]["source_status_summary"]["api_key_present"] = True

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "source_status_summary" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_wave2_ml4_readiness_rejects_source_validation_mode_drift() -> None:
    payload = copy.deepcopy(valid_wave2_ml4_readiness())
    payload["source"]["execution_status_validation"] = "failed"

    try:
        validate_wave2_ml4_readiness(payload, Path("memory://ml-wave2-ml4-readiness.json"))
    except ContractError as exc:
        assert "execution_status_validation" in str(exc)
    else:
        raise AssertionError("expected source validation drift to fail")
