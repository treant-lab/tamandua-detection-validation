from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from validate_ml_contracts import (  # noqa: E402
    ML_MIRROR_PUBLICATION_AUDIT_SCHEMA,
    ContractError,
    validate_contract,
    validate_ml_mirror_publication_audit,
)


def valid_audit() -> dict:
    return {
        "api_version": "tamandua.io/ml-mirror-publication-audit/v1",
        "kind": "MLMirrorPublicationAudit",
        "metadata": {
            "report_id": "test_mirror_publication_audit",
            "generated_at": "2026-06-19T00:00:00Z",
            "created_by": "tamandua-ml-mirror-publication-audit",
            "claim_boundary": (
                "No-push mirror publication audit only. Does not sync, commit, push, tag, "
                "publish releases, run acquisition, train models, or run benchmarks."
            ),
        },
        "source": {
            "manifest": "D:\\treant\\tamandua\\tools\\mirror_deploy\\mirror_manifest.json",
            "staging_root": "D:\\treant\\mirrors-staging",
            "component_count": 2,
        },
        "components": [
            {
                "name": "tamandua-agent",
                "wave": 1,
                "hold": False,
                "hold_reason": "",
                "staging_path": "D:\\treant\\mirrors-staging\\tamandua-agent",
                "staging_exists": True,
                "git_repo": True,
                "tracked_files": 494,
                "local_head": "a235e3c",
                "remote": {"state": "has_content", "head": "a235e3c7", "detail": "origin_has_content"},
                "dirty_count": 0,
                "dirty_top_levels": [],
                "build_deferred": False,
                "build_note": "",
                "artifact_policy": {},
                "initial_publication_decision": {},
                "experimental_release_gate": {},
                "publication_blockers": [],
                "clearance_criteria": [],
                "push_ready": True,
                "publication_decision": "ready_to_push",
            },
            {
                "name": "tamandua-ml",
                "wave": 5,
                "hold": True,
                "hold_reason": "Experimental release gate",
                "staging_path": "D:\\treant\\mirrors-staging\\tamandua-ml",
                "staging_exists": True,
                "git_repo": True,
                "tracked_files": 570,
                "local_head": "7765d60",
                "remote": {"state": "empty", "head": "", "detail": "origin_empty"},
                "dirty_count": 26,
                "dirty_top_levels": [".github", "README.md", "docs", "pyproject.toml", "scripts", "src"],
                "build_deferred": True,
                "build_note": "Experimental",
                "artifact_policy": {
                    "status": "resolved",
                    "source_mirror_policy": "metadata_and_code_only",
                    "release_artifact_policy": "release artifacts require benchmark gates",
                },
                "initial_publication_decision": {},
                "experimental_release_gate": {},
                "publication_blockers": [
                    "manifest_hold_active",
                    "ml_experimental_release_gate_active",
                    "ml_remote_empty_initial_publish_requires_explicit_release_decision",
                    "ml_staging_dirty",
                    "ml_standalone_validation_deferred",
                    "staging_dirty",
                ],
                "clearance_criteria": [
                    {
                        "id": "ml_manifest_hold_removed",
                        "passed": False,
                        "evidence": "Experimental release gate",
                    },
                    {
                        "id": "ml_staging_clean",
                        "passed": False,
                        "evidence": ".github,README.md,docs,pyproject.toml,scripts,src",
                    },
                ],
                "push_ready": False,
                "publication_decision": "hold_do_not_push",
            },
        ],
        "summary": {
            "component_count": 2,
            "push_ready_count": 1,
            "push_ready_components": ["tamandua-agent"],
            "held_components": ["tamandua-ml"],
            "dirty_components": ["tamandua-ml"],
            "remote_empty_components": ["tamandua-ml"],
            "tamandua_ml_present": True,
            "tamandua_ml_hold": True,
            "tamandua_ml_dirty_count": 26,
            "tamandua_ml_remote_state": "empty",
            "tamandua_ml_publication_ready": False,
            "tamandua_ml_publication_decision": "hold_do_not_push",
            "tamandua_ml_publication_blockers": [
                "manifest_hold_active",
                "ml_experimental_release_gate_active",
                "ml_remote_empty_initial_publish_requires_explicit_release_decision",
                "ml_staging_dirty",
                "ml_standalone_validation_deferred",
                "staging_dirty",
            ],
            "tamandua_ml_clearance_criteria": [
                {
                    "id": "ml_manifest_hold_removed",
                    "passed": False,
                    "evidence": "Experimental release gate",
                },
                {
                    "id": "ml_staging_clean",
                    "passed": False,
                    "evidence": ".github,README.md,docs,pyproject.toml,scripts,src",
                },
            ],
            "recommended_next_action": "keep_tamandua_ml_mirror_on_hold_until_experimental_release_gate_clears",
        },
    }


def write_json(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "mirror-audit.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_validate_mirror_publication_audit_accepts_contract(tmp_path: Path) -> None:
    mode = validate_contract(
        write_json(tmp_path, valid_audit()),
        ML_MIRROR_PUBLICATION_AUDIT_SCHEMA,
        validate_ml_mirror_publication_audit,
    )

    assert mode in {"jsonschema+built-in", "built-in"}


def test_validate_mirror_publication_audit_rejects_publish_ready_hold(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_audit())
    payload["components"][1]["push_ready"] = True

    with pytest.raises(ContractError, match="push_ready"):
        validate_ml_mirror_publication_audit(payload, Path("memory://mirror-audit.json"))


def test_validate_mirror_publication_audit_rejects_summary_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_audit())
    payload["summary"]["tamandua_ml_publication_decision"] = "ready_to_push"

    with pytest.raises(ContractError, match="tamandua_ml_publication_decision"):
        validate_ml_mirror_publication_audit(payload, Path("memory://mirror-audit.json"))


def test_validate_mirror_publication_audit_rejects_boundary_drift(tmp_path: Path) -> None:
    payload = copy.deepcopy(valid_audit())
    payload["metadata"]["claim_boundary"] = "Push mirror now."

    with pytest.raises(ContractError, match="claim_boundary"):
        validate_ml_mirror_publication_audit(payload, Path("memory://mirror-audit.json"))
