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
    ML_PLATFORM_READINESS_AUDIT_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_platform_readiness_audit,
)


def artifact_ref(path: str, *, exists: bool) -> dict:
    return {
        "path": path,
        "exists": exists,
        "usable": exists,
        "status": "usable" if exists else "missing",
    }


def add_goal_snapshot(payload: dict) -> None:
    requirements = payload["completion_requirements"]
    goal_requirements = [
        requirement
        for requirement in requirements
        if requirement["requirement_id"] != "public_claim_evidence_boundary"
    ]
    missing_requirements = [requirement for requirement in goal_requirements if requirement["status"] != "proven"]
    evidence_refs = [evidence for requirement in requirements for evidence in requirement["evidence_refs"]]
    by_status: dict[str, int] = {}
    for evidence in evidence_refs:
        by_status[evidence["status"]] = by_status.get(evidence["status"], 0) + 1
    next_requirement = missing_requirements[0] if missing_requirements else None
    next_payload = {
        "id": next_requirement["requirement_id"] if next_requirement else "none",
        "phase": "01-wave1-manifest-publication" if next_requirement else "complete",
        "phase_state": "ready_validation_only" if next_requirement else "complete",
        "execute_guard_env": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION" if next_requirement else "none",
        "pending_targets": [],
        "required_evidence": [evidence["path"] for evidence in next_requirement["evidence_refs"]] if next_requirement else [],
        "missing_or_unusable_evidence": [
            evidence["path"]
            for evidence in next_requirement["evidence_refs"]
            if not evidence["exists"] or not evidence["usable"]
        ] if next_requirement else [],
    }
    payload["completion_summary"].update(
        {
            "goal_complete": not missing_requirements,
            "completion_state": "complete" if not missing_requirements else "partial_evidence",
            "goal_missing_requirements": len(missing_requirements),
            "goal_required_evidence_total": len(evidence_refs),
            "goal_present_required_evidence": sum(1 for evidence in evidence_refs if evidence["exists"]),
            "goal_usable_required_evidence": sum(1 for evidence in evidence_refs if evidence["usable"]),
            "goal_missing_required_evidence": sum(1 for evidence in evidence_refs if not evidence["exists"]),
            "goal_unusable_present_required_evidence": sum(
                1 for evidence in evidence_refs if evidence["exists"] and not evidence["usable"]
            ),
            "next_unproven_requirement_id": next_payload["id"],
            "next_unproven_requirement_phase": next_payload["phase"],
            "next_unproven_execute_guard_env": next_payload["execute_guard_env"],
            "missing_requirement_ids": [requirement["requirement_id"] for requirement in missing_requirements],
            "evidence_status_summary": {
                "total_required_evidence": len(evidence_refs),
                "present_required_evidence": sum(1 for evidence in evidence_refs if evidence["exists"]),
                "usable_required_evidence": sum(1 for evidence in evidence_refs if evidence["usable"]),
                "missing_required_evidence": sum(1 for evidence in evidence_refs if not evidence["exists"]),
                "unusable_present_required_evidence": sum(
                    1 for evidence in evidence_refs if evidence["exists"] and not evidence["usable"]
                ),
                "by_status": by_status,
            },
            "next_unproven_requirement": next_payload,
        }
    )


def add_next_unblock_actions(payload: dict) -> None:
    phase = {
        "wave1_governed_acquisition": "01-wave1-manifest-publication",
        "wave1_sanitized_manifest": "01-wave1-manifest-publication",
        "ml1_model_quality": "02-ml1-candidate-quality",
        "ml1_model_contract_and_card": "02-ml1-candidate-quality",
        "ml2_pytorch_onnx_parity": "03-onnx-agent-parity",
        "ml3_agent_onnx_parity": "03-onnx-agent-parity",
        "ml4_service_benchmark": "04-service-benchmark",
        "ml5_tamandua_replay": "05-platform-replay",
        "ml6_cross_time_holdout": "06-cross-time-holdout",
    }
    guard = {
        "wave1_governed_acquisition": "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        "wave1_sanitized_manifest": "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
        "ml1_model_quality": "TAMANDUA_ALLOW_ML_TRAINING",
        "ml1_model_contract_and_card": "TAMANDUA_ALLOW_ML_TRAINING",
        "ml2_pytorch_onnx_parity": "TAMANDUA_ALLOW_ML_PARITY",
        "ml3_agent_onnx_parity": "TAMANDUA_ALLOW_ML_PARITY",
        "ml4_service_benchmark": "TAMANDUA_ALLOW_ML_SERVICE_BENCH",
        "ml5_tamandua_replay": "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY",
        "ml6_cross_time_holdout": "TAMANDUA_ALLOW_ML_HOLDOUT",
    }
    action = {
        "wave1_governed_acquisition": (
            "Run the guarded Wave 1 acquisition packet in the isolated lab, then publish the validated "
            "acquisition transcript and receipt."
        ),
        "wave1_sanitized_manifest": (
            "Publish the sanitized production candidate dataset manifest and Wave 1 acceptance checklist after "
            "the governed acquisition receipt is usable."
        ),
        "ml1_model_quality": (
            "Train/evaluate the ML-1 candidate against the production candidate dataset and publish a passing "
            "standalone benchmark report."
        ),
        "ml1_model_contract_and_card": "Generate the candidate model contract and model card from passing ML-1 evidence.",
        "ml2_pytorch_onnx_parity": "Export the candidate ONNX model and publish PyTorch versus ONNX parity evidence.",
        "ml3_agent_onnx_parity": "Run the Rust agent ONNX parity benchmark with the exported candidate model.",
        "ml4_service_benchmark": "Run the live FastAPI ML service benchmark with the production candidate model contract.",
        "ml5_tamandua_replay": "Run the full Tamandua replay benchmark with ML-1, ML-3, and ML-4 evidence linked.",
        "ml6_cross_time_holdout": "Run the cross-time holdout benchmark against the governed holdout window.",
    }
    payload["next_unblock_actions"] = []
    for requirement in payload["completion_requirements"]:
        requirement_id = requirement["requirement_id"]
        if requirement_id == "public_claim_evidence_boundary" or requirement["status"] == "proven":
            continue
        payload["next_unblock_actions"].append(
            {
                "order": len(payload["next_unblock_actions"]) + 1,
                "requirement_id": requirement_id,
                "lane": requirement["lane"],
                "phase": phase[requirement_id],
                "execute_guard_env": guard[requirement_id],
                "status": requirement["status"],
                "action": action[requirement_id],
                "evidence_refs": [evidence["path"] for evidence in requirement["evidence_refs"]],
                "blockers": list(requirement["blockers"]),
            }
        )


def valid_audit() -> dict:
    lane_states = []
    source_refs = {
        "wave1_go_no_go": "docs/benchmarks/runs/20260604T-ml-wave1-go-no-go.json",
        "wave2_ml1_readiness": "docs/benchmarks/runs/20260604T-ml-wave2-ml1-readiness-probe.json",
        "wave2_ml2_ml3_readiness": "docs/benchmarks/runs/20260604T-ml-wave2-ml2-ml3-readiness-probe.json",
        "wave2_ml4_readiness": "docs/benchmarks/runs/20260604T-ml-wave2-ml4-readiness-probe.json",
        "wave3_ml5_readiness": "docs/benchmarks/runs/20260604T-ml-wave3-ml5-readiness-probe.json",
        "wave3_ml6_readiness": "docs/benchmarks/runs/20260604T-ml-wave3-ml6-readiness-probe.json",
    }
    for name, ready_field, source_key in [
        ("guarded_real_acquisition", "go_for_guarded_real_acquisition", "wave1_go_no_go"),
        ("ml1_candidate", "ready_for_ml1_candidate", "wave2_ml1_readiness"),
        ("ml2_ml3_parity", "ready_for_ml2_ml3_parity", "wave2_ml2_ml3_readiness"),
        ("ml4_service_benchmark", "ready_for_ml4_service_benchmark", "wave2_ml4_readiness"),
        ("ml5_pipeline_replay", "ready_for_ml5_pipeline_replay", "wave3_ml5_readiness"),
        ("ml6_cross_time_holdout", "ready_for_ml6_holdout", "wave3_ml6_readiness"),
    ]:
        lane_states.append(
            {
                "lane": "Wave 1" if name == "guarded_real_acquisition" else "Wave 2",
                "name": name,
                "evidence_ref": source_refs[source_key],
                "valid": True,
                "ready": False,
                "ready_field": ready_field,
                "detail": "valid",
                "blockers": ["missing_dependency"],
            }
        )
    lane_states[-2]["lane"] = "Wave 3"
    lane_states[-1]["lane"] = "Wave 3"
    artifact_names = {
        "wave1_acquisition_transcript": "docs/benchmarks/runs/20260604T-ml-wave1-real-acquisition-transcript.json",
        "wave1_acquisition_receipt": "docs/benchmarks/runs/20260604T-ml-wave1-acquisition-receipt.json",
        "wave1_manifest_publish_receipt": "docs/benchmarks/runs/20260604T-ml-wave1-manifest-publish-receipt.json",
        "wave1_acceptance_checklist": "docs/benchmarks/runs/20260604T-ml-wave1-acceptance-checklist.json",
        "dataset_manifest": "docs/benchmarks/runs/ml-prod-candidate-v1-dataset-manifest.json",
        "ml1_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml1.json",
        "model_contract": "docs/benchmarks/runs/ml-prod-candidate-v1-model-contract.json",
        "model_card": "docs/benchmarks/runs/ml-prod-candidate-v1-model-card.md",
        "onnx_model": "docs/benchmarks/runs/ml-prod-candidate-v1-artifacts/malware_smell.onnx",
        "ml2_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml2-parity.json",
        "ml3_agent_parity_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml3-agent-parity.json",
        "ml4_service_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml4-api.json",
        "ml5_pipeline_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml5-pipeline.json",
        "ml6_holdout_report": "docs/benchmarks/runs/ml-prod-candidate-v1-ml6-holdout.json",
    }
    completion_requirements = [
        (
            "wave1_governed_acquisition",
            "Wave 1",
            "Governed acquisition evidence complete",
            [artifact_names["wave1_acquisition_transcript"], artifact_names["wave1_acquisition_receipt"]],
        ),
        (
            "wave1_sanitized_manifest",
            "Wave 1",
            "Sanitized manifest evidence complete",
            [
                artifact_names["wave1_manifest_publish_receipt"],
                artifact_names["wave1_acceptance_checklist"],
                artifact_names["dataset_manifest"],
            ],
        ),
        ("ml1_model_quality", "ML-1", "ML-1 benchmark evidence complete", [artifact_names["ml1_report"]]),
        (
            "ml1_model_contract_and_card",
            "ML-1",
            "ML-1 model contract and model card evidence complete",
            [artifact_names["model_contract"], artifact_names["model_card"]],
        ),
        (
            "ml2_pytorch_onnx_parity",
            "ML-2",
            "ML-2 PyTorch ONNX parity evidence complete",
            [artifact_names["onnx_model"], artifact_names["ml2_report"]],
        ),
        (
            "ml3_agent_onnx_parity",
            "ML-3",
            "ML-3 agent ONNX parity evidence complete",
            [artifact_names["onnx_model"], artifact_names["ml3_agent_parity_report"]],
        ),
        ("ml4_service_benchmark", "ML-4", "ML-4 service benchmark evidence complete", [artifact_names["ml4_service_report"]]),
        ("ml5_tamandua_replay", "ML-5", "ML-5 Tamandua replay evidence complete", [artifact_names["ml5_pipeline_report"]]),
        ("ml6_cross_time_holdout", "ML-6", "ML-6 cross-time holdout evidence complete", [artifact_names["ml6_holdout_report"]]),
        (
            "public_claim_evidence_boundary",
            "ML-0",
            "Public claim boundary guard evidence complete",
            ["tools/detection_validation/scripts/ml_public_claims_guard.py"],
        ),
    ]
    completion_items = [
        {
            "requirement_id": requirement_id,
            "lane": lane,
            "title": title,
            "status": "missing" if requirement_id != "public_claim_evidence_boundary" else "proven",
            "evidence_refs": [
                artifact_ref(evidence_path, exists=requirement_id == "public_claim_evidence_boundary")
                for evidence_path in evidence_paths
            ],
            "blockers": []
            if requirement_id == "public_claim_evidence_boundary"
            else [f"missing_evidence:{evidence_paths[0]}"],
        }
        for requirement_id, lane, title, evidence_paths in completion_requirements
    ]
    payload = {
        "api_version": "tamandua.io/ml-platform-readiness-audit/v1",
        "kind": "MLPlatformReadinessAudit",
        "metadata": {
            "report_id": "test_platform_readiness",
            "generated_at": "2026-06-04T23:30:00Z",
            "created_by": "tamandua-ml-platform-readiness-audit",
            "claim_boundary": "No-execution ML platform readiness audit only. Does not acquire samples, train models, export ONNX, run inference, build fixtures, run benchmarks, or contact live services.",
        },
        "source": {"readiness_inputs": source_refs},
        "production_candidate_ready": False,
        "blockers": [
            "ml1_candidate_not_ready",
            "missing_artifact:wave1_acquisition_transcript",
            "missing_artifact:wave1_acquisition_receipt",
            "missing_artifact:wave1_manifest_publish_receipt",
            "missing_artifact:wave1_acceptance_checklist",
            "missing_artifact:dataset_manifest",
            "missing_artifact:ml1_report",
            "missing_artifact:model_contract",
            "missing_artifact:model_card",
            "missing_artifact:onnx_model",
            "missing_artifact:ml2_report",
            "missing_artifact:ml3_agent_parity_report",
            "missing_artifact:ml4_service_report",
            "missing_artifact:ml5_pipeline_report",
            "missing_artifact:ml6_holdout_report",
        ],
        "lane_states": lane_states,
        "required_artifacts": {name: artifact_ref(artifact_path, exists=False) for name, artifact_path in artifact_names.items()},
        "completion_summary": {
            "total_requirements": 10,
            "proven": 1,
            "incomplete": 0,
            "missing": 9,
            "goal_ready": False,
        },
        "completion_requirements": completion_items,
        "next_operator_action": "Continue the guarded ML execution queue in dependency order.",
    }
    add_goal_snapshot(payload)
    add_next_unblock_actions(payload)
    return payload


def test_validate_ml_platform_readiness_audit_accepts_blocked_contract() -> None:
    validate_ml_platform_readiness_audit(valid_audit(), Path("memory://ml-platform-readiness-audit.json"))


def test_validate_ml_platform_readiness_audit_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-platform-readiness-audit.json"
    report_path.write_text(json.dumps(valid_audit()), encoding="utf-8")

    mode = validate_contract(report_path, ML_PLATFORM_READINESS_AUDIT_SCHEMA, validate_ml_platform_readiness_audit)

    assert mode == "jsonschema+built-in"


def test_validate_ml_platform_readiness_audit_accepts_packet_readiness_refs() -> None:
    payload = valid_audit()
    packet_refs = {
        "wave2_ml1_readiness": "docs/benchmarks/runs/20260620T2055Z-ml-wave2-ml1-readiness-master-packets.json",
        "wave2_ml2_ml3_readiness": "docs/benchmarks/runs/20260620T2105Z-ml-wave2-ml2-ml3-readiness-ml1-packets.json",
        "wave3_ml5_readiness": "docs/benchmarks/runs/20260620T2125Z-ml-wave3-ml5-readiness-ml2-ml3-packets.json",
        "wave3_ml6_readiness": "docs/benchmarks/runs/20260620T2135Z-ml-wave3-ml6-readiness-ml5-packets.json",
    }
    payload["source"]["readiness_inputs"].update(packet_refs)
    for lane in payload["lane_states"]:
        source_key = {
            "ml1_candidate": "wave2_ml1_readiness",
            "ml2_ml3_parity": "wave2_ml2_ml3_readiness",
            "ml5_pipeline_replay": "wave3_ml5_readiness",
            "ml6_cross_time_holdout": "wave3_ml6_readiness",
        }.get(lane["name"])
        if source_key:
            lane["evidence_ref"] = packet_refs[source_key]

    validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))


def test_validate_ml_platform_readiness_audit_rejects_ready_with_missing_artifacts() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["production_candidate_ready"] = True
    payload["blockers"] = []

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "cannot be ready" in str(exc)
    else:
        raise AssertionError("expected ready audit with missing artifacts to fail")


def test_validate_ml_platform_readiness_audit_rejects_missing_required_lane() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["lane_states"] = payload["lane_states"][:-1]

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "missing required lanes" in str(exc)
    else:
        raise AssertionError("expected missing lane to fail")


def test_validate_ml_platform_readiness_audit_rejects_duplicate_lane() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["lane_states"][1]["name"] = "guarded_real_acquisition"

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "duplicate lane" in str(exc)
    else:
        raise AssertionError("expected duplicate lane to fail")


def test_validate_ml_platform_readiness_audit_rejects_wrong_ready_field() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["lane_states"][1]["ready_field"] = "go_for_guarded_real_acquisition"

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "ready_field" in str(exc)
    else:
        raise AssertionError("expected wrong ready field to fail")


def test_validate_ml_platform_readiness_audit_rejects_lane_source_mismatch() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["lane_states"][1]["evidence_ref"] = "docs/benchmarks/runs/20260604T-ml-wave2-ml4-readiness-probe.json"

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "source.readiness_inputs.wave2_ml1_readiness" in str(exc)
    else:
        raise AssertionError("expected lane evidence/source mismatch to fail")


def test_validate_ml_platform_readiness_audit_rejects_blocked_lane_without_blockers() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["lane_states"][1]["blockers"] = []

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "must explain blockers" in str(exc)
    else:
        raise AssertionError("expected blocked lane without blockers to fail")


def test_validate_ml_platform_readiness_audit_rejects_ready_lane_with_blockers() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["lane_states"][1]["ready"] = True
    payload["lane_states"][1]["blockers"] = ["stale_blocker"]

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "ready lane must not contain blockers" in str(exc)
    else:
        raise AssertionError("expected ready lane with blockers to fail")


def test_validate_ml_platform_readiness_audit_rejects_declared_existing_artifact_without_file() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["required_artifacts"]["dataset_manifest"] = {
        "path": "docs/benchmarks/runs/does-not-exist-dataset-manifest.json",
        "exists": True,
        "usable": True,
        "status": "missing",
    }

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "usable artifact must report usable" in str(exc)
    else:
        raise AssertionError("expected inconsistent declared artifact to fail")


def test_validate_ml_platform_readiness_audit_rejects_unusable_artifact_without_blocker(tmp_path: Path) -> None:
    artifact_path = tmp_path / "ml-prod-candidate-v1-dataset-manifest.json"
    artifact_path.write_text("{}", encoding="utf-8")
    payload = copy.deepcopy(valid_audit())
    payload["required_artifacts"]["dataset_manifest"] = {
        "path": str(artifact_path),
        "exists": True,
        "usable": False,
        "status": "invalid_content",
    }
    payload["blockers"] = [
        blocker
        for blocker in payload["blockers"]
        if blocker not in {"missing_artifact:dataset_manifest", "unusable_artifact:dataset_manifest:invalid_content"}
    ]

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "unusable_artifact:dataset_manifest:invalid_content" in str(exc)
    else:
        raise AssertionError("expected unusable artifact without blocker to fail")


def test_validate_ml_platform_readiness_audit_rejects_noncanonical_onnx_path() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["required_artifacts"]["onnx_model"]["path"] = "docs/benchmarks/runs/ml-prod-candidate-v1.onnx"

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "onnx_model" in str(exc)
    else:
        raise AssertionError("expected noncanonical ONNX path to fail")


def test_validate_ml_platform_readiness_audit_rejects_missing_completion_requirement() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["completion_requirements"] = payload["completion_requirements"][:-1]
    payload["completion_summary"]["total_requirements"] = len(payload["completion_requirements"])

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "missing required ids" in str(exc)
    else:
        raise AssertionError("expected missing completion requirement to fail")


def test_validate_ml_platform_readiness_audit_rejects_declared_existing_unusable_evidence_without_file() -> None:
    payload = copy.deepcopy(valid_audit())
    requirement = payload["completion_requirements"][-1]
    requirement["status"] = "incomplete"
    requirement["evidence_refs"] = [
        {
            "path": "docs/benchmarks/runs/does-not-exist-public-claim-guard.py",
            "exists": False,
            "usable": True,
            "status": "usable",
        }
    ]
    requirement["blockers"] = ["missing_evidence:docs/benchmarks/runs/does-not-exist-public-claim-guard.py"]
    payload["completion_summary"]["proven"] = 0
    payload["completion_summary"]["missing"] = 10

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "missing evidence must report missing" in str(exc)
    else:
        raise AssertionError("expected inconsistent evidence state to fail")


def test_validate_ml_platform_readiness_audit_rejects_completion_summary_drift() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["completion_summary"]["missing"] = 0

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "completion_summary.missing" in str(exc)
    else:
        raise AssertionError("expected completion summary drift to fail")


def test_validate_ml_platform_readiness_audit_rejects_next_unblock_action_drift() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["next_unblock_actions"] = []

    try:
        validate_ml_platform_readiness_audit(payload, Path("memory://ml-platform-readiness-audit.json"))
    except ContractError as exc:
        assert "next_unblock_actions" in str(exc)
    else:
        raise AssertionError("expected next unblock action drift to fail")
