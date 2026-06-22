from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


VALIDATION_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(VALIDATION_ROOT))

from validate_ml_contracts import (  # noqa: E402
    ML3_AGENT_PRODUCTION_GAP_AUDIT_SCHEMA,
    ContractError,
    file_sha256,
    validate_contract,
    validate_ml3_agent_production_gap_audit,
)


SMOKE_REPORT = Path("docs/benchmarks/runs/20260621T-ml3-agent-onnx-parity-smoke-with-win-template-rerun.json")


def valid_audit() -> dict:
    return {
        "api_version": "tamandua.io/ml3-agent-production-gap-audit/v1",
        "kind": "ML3AgentProductionGapAudit",
        "metadata": {
            "report_id": "unit",
            "created_at": "2026-06-21T00:00:00+00:00",
            "created_by": "tamandua-ml3-agent-production-gap-audit",
        },
        "claim_boundary": (
            "No-execution ML-3 production gap audit. It records existing smoke parity and missing "
            "production-candidate artifacts; it does not run inference, contact WIN-TEMPLATE, train, "
            "publish ML artifacts, or unblock ML-5."
        ),
        "summary": {
            "status": "blocked",
            "smoke_agent_onnx_parity_available": True,
            "win_template_context_available": True,
            "canonical_ml3_agent_parity_ready": False,
            "unblocks_ml5_platform_replay": False,
            "blocker_count": 4,
            "next_required_guard": "TAMANDUA_ALLOW_ML_PARITY",
        },
        "source": {
            "smoke_report": SMOKE_REPORT.as_posix(),
            "smoke_report_sha256": file_sha256(SMOKE_REPORT),
            "canonical_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml3-agent-parity.json",
            "model_contract": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
            "onnx_metadata": "docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json",
        },
        "quality_gate": {
            "status": "pass",
            "checks": [
                {
                    "name": "smoke_agent_onnx_parity_present",
                    "status": "pass",
                    "details": "{\"model_version\": \"ml-smoke-fixture-v1\", \"smoke_quality_gate\": \"pass\"}",
                },
                {
                    "name": "win_template_false_positive_context_attached",
                    "status": "pass",
                    "details": "{\"artifact_names\": [\"win_template_ml_probe\"]}",
                },
                {
                    "name": "smoke_report_does_not_unblock_production",
                    "status": "pass",
                    "details": (
                        "Smoke parity does not satisfy the canonical ml-prod-candidate-v1 ML-3 gate "
                        "or prove malware detection."
                    ),
                },
                {
                    "name": "canonical_ml3_agent_parity_report_missing",
                    "status": "pass",
                    "details": "docs/benchmarks/runs/ml-prod-candidate-v1-ml3-agent-parity.json",
                },
                {
                    "name": "candidate_model_contract_missing",
                    "status": "pass",
                    "details": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
                },
                {
                    "name": "candidate_onnx_metadata_missing",
                    "status": "pass",
                    "details": "docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json",
                },
            ],
        },
        "blockers": [
            "missing_canonical_ml3_agent_parity_report",
            "missing_candidate_model_contract",
            "missing_candidate_onnx_metadata",
            "upstream_ml1_candidate_not_available",
        ],
        "next_actions": [
            {
                "id": "ml3-prod-001",
                "description": "Wait for ML-1 production candidate artifacts and model contract.",
                "required_artifacts": [
                    "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
                    "docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.json",
                ],
            },
            {
                "id": "ml3-prod-002",
                "description": "Run Wave 2 ML-2/ML-3 parity in the isolated lab after upstream artifacts exist.",
                "command": ".\\docs\\benchmarks\\runs\\20260604T-ml-execution-plan.handoff\\wave_2_ml2_ml3_parity_launcher.ps1 -Execute",
                "guard": "TAMANDUA_ALLOW_ML_PARITY",
            },
            {
                "id": "ml3-prod-003",
                "description": "Produce canonical ml-prod-candidate-v1 ML-3 report without treating smoke parity as production evidence.",
                "required_artifacts": ["docs/benchmarks/runs/ml-prod-candidate-v1-ml3-agent-parity.json"],
            },
        ],
    }


def test_validate_ml3_agent_production_gap_audit_accepts_contract(tmp_path: Path) -> None:
    report = tmp_path / "ml3-agent-production-gap-audit.json"
    report.write_text(json.dumps(valid_audit()), encoding="utf-8")

    mode = validate_contract(report, ML3_AGENT_PRODUCTION_GAP_AUDIT_SCHEMA, validate_ml3_agent_production_gap_audit)

    assert mode in {"jsonschema+built-in", "built-in"}


def test_validate_ml3_agent_production_gap_audit_rejects_unblock_claim() -> None:
    payload = valid_audit()
    payload["summary"]["unblocks_ml5_platform_replay"] = True

    with pytest.raises(ContractError, match="unblocks_ml5_platform_replay"):
        validate_ml3_agent_production_gap_audit(payload, Path("memory://ml3-agent-production-gap-audit.json"))


def test_validate_ml3_agent_production_gap_audit_rejects_missing_blocker() -> None:
    payload = valid_audit()
    payload["blockers"] = payload["blockers"][:-1]

    with pytest.raises(ContractError, match="blockers"):
        validate_ml3_agent_production_gap_audit(payload, Path("memory://ml3-agent-production-gap-audit.json"))


def test_validate_ml3_agent_production_gap_audit_rejects_boundary_drift() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["quality_gate"]["checks"][2]["details"] = "Smoke parity passed."

    with pytest.raises(ContractError, match="production boundary"):
        validate_ml3_agent_production_gap_audit(payload, Path("memory://ml3-agent-production-gap-audit.json"))
