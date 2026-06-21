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
    WAVE3_ML5_READINESS_SCHEMA,
    ContractError,
    validate_contract,
    validate_wave3_ml5_readiness,
)
from test_validate_ml_wave2_ml1_readiness import GOAL_SNAPSHOT  # noqa: E402


def upstream_goal_snapshot() -> dict:
    upstream = RUNS_DIR / "20260604T-ml-wave2-ml2-ml3-readiness-probe.json"
    if not upstream.exists():
        return copy.deepcopy(GOAL_SNAPSHOT)
    payload = json.loads(upstream.read_text(encoding="utf-8"))
    source = payload.get("source", {}) if isinstance(payload.get("source"), dict) else {}
    summary = source.get("source_status_summary", {}) if isinstance(source.get("source_status_summary"), dict) else {}
    snapshot = copy.deepcopy(GOAL_SNAPSHOT)
    for key in snapshot:
        if key in summary:
            snapshot[key] = summary[key]
    return snapshot


def valid_wave3_ml5_readiness() -> dict:
    return {
        "api_version": "tamandua.io/ml-wave3-ml5-readiness-probe/v1",
        "kind": "MLWave3ML5ReadinessProbe",
        "metadata": {
            "report_id": "test_wave3_ml5_readiness",
            "generated_at": "2026-06-04T23:00:00Z",
            "created_by": "tamandua-ml-wave3-ml5-readiness-probe",
            "claim_boundary": "No-execution ML-5 readiness probe only. Does not build fixtures, run replay benchmarks, train models, run inference, or contact live services.",
        },
        "configuration": {
            "status_ref": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
            "wave2_ml2_ml3_readiness_ref": "docs/benchmarks/runs/20260604T-ml-wave2-ml2-ml3-readiness-probe.json",
            "wave2_ml4_readiness_ref": "docs/benchmarks/runs/20260604T-ml-wave2-ml4-readiness-probe.json",
            "ml1_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
            "model_contract": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
            "model_card": "docs/benchmarks/runs/ml-prod-candidate-v1-model-card.md",
            "ml3_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml3-agent-parity.json",
            "ml3_agent_side_evidence": "docs/benchmarks/runs/20260620T-ml3-agent-parity-with-win-template.json",
            "ml4_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml4-api.json",
            "replay_outcomes": "docs/benchmarks/runs/ml-prod-candidate-v1-ml5-replay-outcomes.json",
            "launcher": "docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_3_ml5_pipeline_launcher.ps1",
        },
        "source": {
            "execution_status": "docs/benchmarks/runs/20260604T-ml-execution-status.json",
            "execution_status_validation": "jsonschema+built-in",
            "wave2_ml2_ml3_readiness": "docs/benchmarks/runs/20260604T-ml-wave2-ml2-ml3-readiness-probe.json",
            "wave2_ml2_ml3_readiness_validation": "jsonschema+built-in",
            "wave2_ml4_readiness": "docs/benchmarks/runs/20260604T-ml-wave2-ml4-readiness-probe.json",
            "wave2_ml4_readiness_validation": "jsonschema+built-in",
            "ml1_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
            "ml1_report_validation": "missing",
            "ml1_model_contract": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
            "ml1_model_contract_validation": "missing",
            "ml1_model_card": "docs/benchmarks/runs/ml-prod-candidate-v1-model-card.md",
            "ml3_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml3-agent-parity.json",
            "ml3_report_validation": "missing",
            "ml3_agent_side_evidence": "docs/benchmarks/runs/20260620T-ml3-agent-parity-with-win-template.json",
            "ml3_agent_side_evidence_validation": "missing",
            "ml4_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml4-api.json",
            "ml4_report_validation": "missing",
            "replay_outcomes": "docs/benchmarks/runs/ml-prod-candidate-v1-ml5-replay-outcomes.json",
            "source_status_summary": {
                **upstream_goal_snapshot(),
                "wave2_ml2_ml3_ready_for_parity": False,
                "wave2_ml2_ml3_lab_guard_proof_mismatch_count": 0,
                "wave2_ml2_ml3_ml_lab_standby_guards_unset": True,
                "wave2_ml4_ready_for_service_benchmark": False,
                "wave2_ml4_lab_guard_proof_mismatch_count": 0,
                "wave2_ml4_ml_lab_standby_guards_unset": True,
                "ml1_benchmark_report_present": False,
                "ml1_model_contract_present": False,
                "ml1_model_contract_valid": False,
                "ml1_model_contract_quality_gate_status": "",
                "ml1_model_contract_quality_gate_passed": False,
                "ml1_model_card_present": False,
                "ml1_model_card_nonempty": False,
                "ml1_model_card_references_contract": False,
                "ml1_model_card_readiness": "",
                "ml1_model_card_readiness_production_candidate": False,
                "ml3_agent_parity_report_present": False,
                "ml3_agent_side_evidence_present": False,
                "ml3_agent_side_evidence_valid": False,
                "ml3_agent_side_evidence_quality_gate_passed": False,
                "ml3_agent_side_evidence_sample_count": 0,
                "ml3_agent_side_evidence_win_template_attached": False,
                "ml4_service_report_present": False,
                "ml5_replay_outcomes_present": False,
                "ml5_replay_outcome_sample_count": 0,
                "ml5_replay_outcomes_have_malicious": False,
                "ml5_replay_outcomes_have_benign": False,
                "ml5_replay_outcomes_no_raw_samples": False,
                "ml5_replay_outcomes_have_pipeline_verdicts": False,
                "ml5_launcher_exists": True,
                "required_input_count": 3,
                "required_inputs_present": 3,
                "blocker_count": 8,
                "blockers": [
                    "wave2_ml2_ml3_readiness_blocked",
                    "wave2_ml4_readiness_blocked",
                    "missing_ml1_benchmark_report",
                    "missing_ml1_model_contract",
                    "missing_ml1_model_card",
                    "missing_ml3_agent_parity_report",
                    "missing_ml4_service_report",
                    "missing_ml5_replay_outcomes",
                ],
            },
        },
        "ready_for_ml5_pipeline_replay": False,
        "blockers": [
            "wave2_ml2_ml3_readiness_blocked",
            "wave2_ml4_readiness_blocked",
            "missing_ml1_benchmark_report",
            "missing_ml1_model_contract",
            "missing_ml1_model_card",
            "missing_ml3_agent_parity_report",
            "missing_ml4_service_report",
            "missing_ml5_replay_outcomes",
        ],
        "checks": [
            {"name": "execution_status_valid", "passed": True, "detail": "status"},
            {"name": "wave2_ml2_ml3_readiness_valid", "passed": True, "detail": "parity readiness"},
            {"name": "wave2_ml4_readiness_valid", "passed": True, "detail": "service readiness"},
            {"name": "wave2_ml2_ml3_ready_for_parity", "passed": False, "detail": "parity blockers"},
            {"name": "wave2_ml2_ml3_lab_guard_proof_clean", "passed": True, "detail": "mismatch_count=0"},
            {"name": "wave2_ml2_ml3_ml_lab_standby_guards_unset", "passed": True, "detail": "guards_unset=True"},
            {"name": "wave2_ml4_ready_for_service_benchmark", "passed": False, "detail": "service blockers"},
            {"name": "wave2_ml4_lab_guard_proof_clean", "passed": True, "detail": "mismatch_count=0"},
            {"name": "wave2_ml4_ml_lab_standby_guards_unset", "passed": True, "detail": "guards_unset=True"},
            {"name": "ml1_benchmark_report_present", "passed": False, "detail": "ml1"},
            {"name": "ml1_benchmark_report_candidate_passed", "passed": False, "detail": "ml1"},
            {"name": "ml1_benchmark_report_candidate_passed_sample_coverage", "passed": False, "detail": "ml1"},
            {"name": "ml1_benchmark_report_candidate_passed_candidate_dataset", "passed": False, "detail": "ml1"},
            {"name": "ml1_model_contract_present", "passed": False, "detail": "contract"},
            {"name": "ml1_model_contract_valid", "passed": False, "detail": "contract"},
            {"name": "ml1_model_contract_quality_gate_passed", "passed": False, "detail": "contract"},
            {"name": "ml1_model_card_present", "passed": False, "detail": "card"},
            {"name": "ml1_model_card_nonempty", "passed": False, "detail": "card"},
            {"name": "ml1_model_card_references_contract", "passed": False, "detail": "card"},
            {"name": "ml1_model_card_readiness_production_candidate", "passed": False, "detail": "card"},
            {"name": "ml3_agent_parity_report_present", "passed": False, "detail": "ml3"},
            {"name": "ml3_agent_parity_report_passed", "passed": False, "detail": "ml3"},
            {"name": "ml3_agent_parity_report_passed_sample_coverage", "passed": False, "detail": "ml3"},
            {"name": "ml3_agent_side_evidence_present", "passed": False, "detail": "ml3 agent-side"},
            {"name": "ml3_agent_side_evidence_valid", "passed": False, "detail": "ml3 agent-side"},
            {"name": "ml3_agent_side_evidence_quality_gate_passed", "passed": False, "detail": "ml3 agent-side"},
            {"name": "ml3_agent_side_evidence_win_template_attached", "passed": False, "detail": "ml3 agent-side"},
            {"name": "ml4_service_report_present", "passed": False, "detail": "ml4"},
            {"name": "ml4_service_report_passed", "passed": False, "detail": "ml4"},
            {"name": "ml4_service_report_passed_sample_coverage", "passed": False, "detail": "ml4"},
            {"name": "ml5_replay_outcomes_present", "passed": False, "detail": "outcomes"},
            {"name": "ml5_replay_outcomes_nonempty", "passed": False, "detail": "outcomes"},
            {"name": "ml5_replay_outcomes_have_malicious", "passed": False, "detail": "outcomes"},
            {"name": "ml5_replay_outcomes_have_benign", "passed": False, "detail": "outcomes"},
            {"name": "ml5_replay_outcomes_no_raw_samples", "passed": False, "detail": "outcomes"},
            {"name": "ml5_replay_outcomes_have_pipeline_verdicts", "passed": False, "detail": "outcomes"},
            {"name": "ml5_launcher_exists", "passed": True, "detail": "launcher"},
            {"name": "required_input_exists:apps/tamandua_ml/scripts/build_ml5_pipeline_fixture.py", "passed": True, "detail": "builder"},
            {"name": "required_input_exists:apps/tamandua_ml/scripts/ml5_pipeline_benchmark.py", "passed": True, "detail": "bench"},
            {"name": "required_input_exists:schemas/ml5_pipeline_fixture_v1.schema.json", "passed": True, "detail": "schema"},
        ],
        "operator_sequence": [
            {
                "step": 1,
                "mode": "validation_only",
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_3_ml5_pipeline_launcher.ps1'",
                "claim_boundary": "Validates ML-5 prerequisites and prints fixture/replay commands without running them.",
            },
            {
                "step": 2,
                "mode": "execute",
                "guard_set_command": "$env:TAMANDUA_ALLOW_ML_PIPELINE_REPLAY = '1'",
                "required_env": {"TAMANDUA_ALLOW_ML_PIPELINE_REPLAY": "1"},
                "command": "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_3_ml5_pipeline_launcher.ps1' -Execute",
                "guard_cleanup_command": "Remove-Item Env:TAMANDUA_ALLOW_ML_PIPELINE_REPLAY -ErrorAction SilentlyContinue",
                "claim_boundary": "Builds ML-5 replay fixture, validates it, and runs the controlled pipeline replay benchmark.",
            },
        ],
    }


def sync_source(payload: dict) -> None:
    source_summary = payload["source"]["source_status_summary"]
    check_by_name = {check["name"]: check for check in payload["checks"]}
    for field, check_name in {
        "wave2_ml2_ml3_ready_for_parity": "wave2_ml2_ml3_ready_for_parity",
        "wave2_ml2_ml3_ml_lab_standby_guards_unset": "wave2_ml2_ml3_ml_lab_standby_guards_unset",
        "wave2_ml4_ready_for_service_benchmark": "wave2_ml4_ready_for_service_benchmark",
        "wave2_ml4_ml_lab_standby_guards_unset": "wave2_ml4_ml_lab_standby_guards_unset",
        "ml1_benchmark_report_present": "ml1_benchmark_report_present",
        "ml1_model_contract_present": "ml1_model_contract_present",
        "ml1_model_contract_valid": "ml1_model_contract_valid",
        "ml1_model_contract_quality_gate_passed": "ml1_model_contract_quality_gate_passed",
        "ml1_model_card_present": "ml1_model_card_present",
        "ml1_model_card_nonempty": "ml1_model_card_nonempty",
        "ml1_model_card_references_contract": "ml1_model_card_references_contract",
        "ml1_model_card_readiness_production_candidate": "ml1_model_card_readiness_production_candidate",
        "ml3_agent_parity_report_present": "ml3_agent_parity_report_present",
        "ml3_agent_side_evidence_present": "ml3_agent_side_evidence_present",
        "ml3_agent_side_evidence_valid": "ml3_agent_side_evidence_valid",
        "ml3_agent_side_evidence_quality_gate_passed": "ml3_agent_side_evidence_quality_gate_passed",
        "ml3_agent_side_evidence_win_template_attached": "ml3_agent_side_evidence_win_template_attached",
        "ml4_service_report_present": "ml4_service_report_present",
        "ml5_replay_outcomes_present": "ml5_replay_outcomes_present",
        "ml5_replay_outcomes_have_malicious": "ml5_replay_outcomes_have_malicious",
        "ml5_replay_outcomes_have_benign": "ml5_replay_outcomes_have_benign",
        "ml5_replay_outcomes_no_raw_samples": "ml5_replay_outcomes_no_raw_samples",
        "ml5_replay_outcomes_have_pipeline_verdicts": "ml5_replay_outcomes_have_pipeline_verdicts",
        "ml5_launcher_exists": "ml5_launcher_exists",
    }.items():
        source_summary[field] = check_by_name[check_name]["passed"]
    source_summary["wave2_ml2_ml3_lab_guard_proof_mismatch_count"] = (
        0 if check_by_name["wave2_ml2_ml3_lab_guard_proof_clean"]["passed"] else 1
    )
    source_summary["wave2_ml4_lab_guard_proof_mismatch_count"] = (
        0 if check_by_name["wave2_ml4_lab_guard_proof_clean"]["passed"] else 1
    )
    source_summary["ml5_replay_outcome_sample_count"] = 2 if check_by_name["ml5_replay_outcomes_nonempty"]["passed"] else 0
    source_summary["ml3_agent_side_evidence_sample_count"] = (
        6 if check_by_name["ml3_agent_side_evidence_quality_gate_passed"]["passed"] else 0
    )
    input_checks = [name for name in check_by_name if name.startswith("required_input_exists:")]
    source_summary["required_input_count"] = len(input_checks)
    source_summary["required_inputs_present"] = sum(1 for name in input_checks if check_by_name[name]["passed"] is True)
    source_summary["blockers"] = list(payload["blockers"])
    source_summary["blocker_count"] = len(payload["blockers"])


def test_validate_wave3_ml5_readiness_accepts_blocked_contract() -> None:
    validate_wave3_ml5_readiness(valid_wave3_ml5_readiness(), Path("memory://ml-wave3-ml5-readiness.json"))


def test_validate_wave3_ml5_readiness_accepts_ml2_ml3_packet_readiness() -> None:
    payload = valid_wave3_ml5_readiness()
    readiness = "docs/benchmarks/runs/20260620T2105Z-ml-wave2-ml2-ml3-readiness-ml1-packets.json"
    payload["configuration"]["wave2_ml2_ml3_readiness_ref"] = readiness
    payload["source"]["wave2_ml2_ml3_readiness"] = readiness

    validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))


def test_validate_wave3_ml5_readiness_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-wave3-ml5-readiness.json"
    report_path.write_text(json.dumps(valid_wave3_ml5_readiness()), encoding="utf-8")

    mode = validate_contract(report_path, WAVE3_ML5_READINESS_SCHEMA, validate_wave3_ml5_readiness)

    assert mode == "jsonschema+built-in"


def test_validate_wave3_ml5_readiness_rejects_ready_with_missing_dependencies() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["ready_for_ml5_pipeline_replay"] = True
    payload["blockers"] = []
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "cannot be ready" in str(exc)
    else:
        raise AssertionError("expected ready with missing dependencies to fail")


def test_validate_wave3_ml5_readiness_rejects_ready_with_failed_required_input() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["ready_for_ml5_pipeline_replay"] = True
    payload["blockers"] = []
    for check in payload["checks"]:
        check["passed"] = True
    failed_input = next(check for check in payload["checks"] if check["name"] == "required_input_exists:apps/tamandua_ml/scripts/build_ml5_pipeline_fixture.py")
    failed_input["passed"] = False
    payload["source"]["ml1_report_validation"] = "jsonschema+built-in"
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    payload["source"]["ml3_report_validation"] = "jsonschema+built-in"
    payload["source"]["ml3_agent_side_evidence_validation"] = "jsonschema+built-in"
    payload["source"]["ml4_report_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "failed checks" in str(exc)
    else:
        raise AssertionError("expected ready ML-5 report with failed required input to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_replay_blocker() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["blockers"] = [
        "wave2_ml2_ml3_readiness_blocked",
        "wave2_ml4_readiness_blocked",
        "missing_ml1_benchmark_report",
        "missing_ml1_model_contract",
        "missing_ml1_model_card",
        "missing_ml3_agent_parity_report",
        "missing_ml4_service_report",
    ]
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "missing_ml5_replay_outcomes" in str(exc)
    else:
        raise AssertionError("expected missing replay outcomes blocker to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_empty_replay_outcomes_blocker() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["blockers"] = [
        "wave2_ml2_ml3_readiness_blocked",
        "wave2_ml4_readiness_blocked",
        "missing_ml1_benchmark_report",
        "missing_ml1_model_contract",
        "missing_ml1_model_card",
        "missing_ml3_agent_parity_report",
        "missing_ml4_service_report",
    ]
    next(check for check in payload["checks"] if check["name"] == "ml5_replay_outcomes_present")["passed"] = True
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "ml5_replay_outcomes_empty" in str(exc)
    else:
        raise AssertionError("expected missing empty replay outcomes blocker to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_weak_ml1_blocker() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["blockers"] = [
        "wave2_ml2_ml3_readiness_blocked",
        "wave2_ml4_readiness_blocked",
        "missing_ml1_model_contract",
        "missing_ml1_model_card",
        "missing_ml3_agent_parity_report",
        "missing_ml4_service_report",
        "missing_ml5_replay_outcomes",
    ]
    next(check for check in payload["checks"] if check["name"] == "ml1_benchmark_report_present")["passed"] = True
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "ml1_benchmark_report_quality_gate_not_pass" in str(exc)
    else:
        raise AssertionError("expected missing weak ML-1 blocker to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_contract_quality_gate_blocker() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["blockers"] = [
        "wave2_ml2_ml3_readiness_blocked",
        "wave2_ml4_readiness_blocked",
        "missing_ml1_benchmark_report",
        "missing_ml1_model_card",
        "missing_ml3_agent_parity_report",
        "missing_ml4_service_report",
        "missing_ml5_replay_outcomes",
    ]
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    for check in payload["checks"]:
        if check["name"] in {"ml1_model_contract_present", "ml1_model_contract_valid"}:
            check["passed"] = True
        if check["name"] == "ml1_model_contract_quality_gate_passed":
            check["passed"] = False
            check["detail"] = "fail"
    payload["source"]["source_status_summary"]["ml1_model_contract_quality_gate_status"] = "fail"
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "ml1_model_contract_quality_gate_not_pass" in str(exc)
    else:
        raise AssertionError("expected missing contract quality gate blocker to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_model_card_readiness_blocker() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["blockers"] = [
        "wave2_ml2_ml3_readiness_blocked",
        "wave2_ml4_readiness_blocked",
        "missing_ml1_benchmark_report",
        "missing_ml1_model_contract",
        "missing_ml3_agent_parity_report",
        "missing_ml4_service_report",
        "missing_ml5_replay_outcomes",
    ]
    for check in payload["checks"]:
        if check["name"] in {"ml1_model_card_present", "ml1_model_card_nonempty", "ml1_model_card_references_contract"}:
            check["passed"] = True
        if check["name"] == "ml1_model_card_readiness_production_candidate":
            check["passed"] = False
            check["detail"] = "not_production_ready"
    payload["source"]["source_status_summary"]["ml1_model_card_readiness"] = "not_production_ready"
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "ml1_model_card_not_production_candidate" in str(exc)
    else:
        raise AssertionError("expected missing model card readiness blocker to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_upstream_readiness_blocker() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["blockers"] = [
        "wave2_ml4_readiness_blocked",
        "missing_ml1_benchmark_report",
        "missing_ml1_model_contract",
        "missing_ml1_model_card",
        "missing_ml3_agent_parity_report",
        "missing_ml4_service_report",
        "missing_ml5_replay_outcomes",
    ]
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "wave2_ml2_ml3_readiness_blocked" in str(exc)
    else:
        raise AssertionError("expected missing upstream readiness blocker to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_guard_proof_mismatch_blocker() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    next(check for check in payload["checks"] if check["name"] == "wave2_ml2_ml3_lab_guard_proof_clean")["passed"] = False
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "wave2_ml2_ml3_lab_guard_proof_mismatch" in str(exc)
    else:
        raise AssertionError("expected missing Wave 2 parity guard proof blocker to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_lab_guards_set_blocker() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    next(check for check in payload["checks"] if check["name"] == "wave2_ml4_ml_lab_standby_guards_unset")["passed"] = False
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "wave2_ml4_lab_execution_guards_set" in str(exc)
    else:
        raise AssertionError("expected missing Wave 2 service guard-set blocker to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_replay_guard() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["operator_sequence"][1]["required_env"]["TAMANDUA_ALLOW_ML_PIPELINE_REPLAY"] = "0"

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "ML pipeline replay guard" in str(exc)
    else:
        raise AssertionError("expected missing replay guard to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_replay_guard_set_command() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["operator_sequence"][1]["guard_set_command"] = "$env:TAMANDUA_ALLOW_ML_PIPELINE_REPLAY='1'"

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "guard_set_command" in str(exc)
    else:
        raise AssertionError("expected missing replay guard set command to fail")


def test_validate_wave3_ml5_readiness_rejects_missing_replay_guard_cleanup_command() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["operator_sequence"][1]["guard_cleanup_command"] = "Remove-Item Env:TAMANDUA_ALLOW_ML_SERVICE_BENCH"

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "guard_cleanup_command" in str(exc)
    else:
        raise AssertionError("expected missing replay guard cleanup command to fail")


def test_validate_wave3_ml5_readiness_rejects_inline_replay_guard_assignment() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["operator_sequence"][1]["command"] = (
        "$env:TAMANDUA_ALLOW_ML_PIPELINE_REPLAY = '1'; "
        "& 'docs/benchmarks/runs/20260604T-ml-execution-plan.handoff/wave_3_ml5_pipeline_launcher.ps1' -Execute"
    )

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "inline pipeline replay guard assignment" in str(exc)
    else:
        raise AssertionError("expected inline replay guard assignment to fail")


def test_validate_wave3_ml5_readiness_rejects_not_ready_when_all_checks_pass() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["blockers"] = ["stale_blocker"]
    for check in payload["checks"]:
        check["passed"] = True
    payload["source"]["ml1_report_validation"] = "jsonschema+built-in"
    payload["source"]["ml1_model_contract_validation"] = "jsonschema+built-in"
    payload["source"]["ml3_report_validation"] = "jsonschema+built-in"
    payload["source"]["ml3_agent_side_evidence_validation"] = "jsonschema+built-in"
    payload["source"]["ml4_report_validation"] = "jsonschema+built-in"
    sync_source(payload)

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "cannot be false when all checks pass" in str(exc)
    else:
        raise AssertionError("expected stale ML-5 readiness report to fail")


def test_validate_wave3_ml5_readiness_rejects_source_status_summary_drift() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["source"]["source_status_summary"]["ml5_replay_outcomes_present"] = True

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "source_status_summary" in str(exc)
    else:
        raise AssertionError("expected source summary drift to fail")


def test_validate_wave3_ml5_readiness_rejects_source_validation_mode_drift() -> None:
    payload = copy.deepcopy(valid_wave3_ml5_readiness())
    payload["source"]["execution_status_validation"] = "failed"

    try:
        validate_wave3_ml5_readiness(payload, Path("memory://ml-wave3-ml5-readiness.json"))
    except ContractError as exc:
        assert "execution_status_validation" in str(exc)
    else:
        raise AssertionError("expected source validation drift to fail")
