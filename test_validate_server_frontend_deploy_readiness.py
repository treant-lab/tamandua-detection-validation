from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from validate_ml_contracts import (  # noqa: E402
    SERVER_FRONTEND_DEPLOY_READINESS_SCHEMA,
    ContractError,
    validate_contract,
    validate_server_frontend_deploy_readiness,
)


def valid_readiness() -> dict:
    return {
        "api_version": "tamandua.io/server-frontend-deploy-readiness/v1",
        "kind": "ServerFrontendDeployReadiness",
        "metadata": {
            "report_id": "test_server_frontend_deploy_readiness",
            "generated_at": "2026-06-21T00:00:00Z",
            "created_by": "server-frontend-deploy-readiness",
            "claim_boundary": (
                "No-deploy readiness audit only. It inspects local assets, required tools, env presence, "
                "and the publication audit; it does not copy assets, restart containers, change portproxy, "
                "or contact SSH/SCP endpoints."
            ),
        },
        "source": {
            "endpoint": "http://192.168.12.146:4000",
            "local_manifest": "D:\\treant\\tamandua\\apps\\tamandua_server\\priv\\static\\assets\\manifest.json",
            "deploy_script": "D:\\treant\\tamandua\\deploy\\scripts\\proxmox\\deploy-tamandua-front-assets-light.ps1",
            "publication_audit": "docs/benchmarks/runs/20260621T-server-frontend-publication-audit-after-dns-storyline.json",
        },
        "summary": {
            "ready_for_front_assets_publish": False,
            "publish_command": ".\\deploy\\scripts\\proxmox\\deploy-tamandua-front-assets-light.ps1 -NoBuild",
            "required_secret_env": "TAMANDUA_LAB_VM_PASSWORD",
            "required_secret_present": False,
            "local_main": "js/main-DBzupRKj.js",
            "local_css": "css/main-BvND_Izm.css",
            "publication_state": "published_bundle_differs_from_local_build",
            "published_matches_local_build": False,
            "blockers": ["lab_password_present"],
        },
        "checks": [
            {"name": "deploy_script_present", "passed": True, "detail": "deploy script"},
            {"name": "local_manifest_present", "passed": True, "detail": "manifest"},
            {"name": "local_assets_present", "passed": True, "detail": "assets"},
            {"name": "pscp_present", "passed": True, "detail": "pscp"},
            {"name": "plink_present", "passed": True, "detail": "plink"},
            {"name": "tar_present", "passed": True, "detail": "tar"},
            {"name": "lab_password_present", "passed": False, "detail": "TAMANDUA_LAB_VM_PASSWORD"},
            {"name": "publication_audit_present", "passed": True, "detail": "audit"},
        ],
    }


def test_validate_server_frontend_deploy_readiness_accepts_contract(tmp_path: Path) -> None:
    report = tmp_path / "server-frontend-deploy-readiness.json"
    report.write_text(json.dumps(valid_readiness()), encoding="utf-8")

    mode = validate_contract(report, SERVER_FRONTEND_DEPLOY_READINESS_SCHEMA, validate_server_frontend_deploy_readiness)

    assert mode in {"jsonschema+built-in", "built-in"}


def test_validate_server_frontend_deploy_readiness_rejects_secret_without_blocker() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["summary"]["blockers"] = []
    payload["summary"]["ready_for_front_assets_publish"] = True

    with pytest.raises(ContractError, match="lab password"):
        validate_server_frontend_deploy_readiness(payload, Path("memory://server-frontend-deploy-readiness.json"))


def test_validate_server_frontend_deploy_readiness_rejects_ready_with_blockers() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["summary"]["ready_for_front_assets_publish"] = True

    with pytest.raises(ContractError, match="ready_for_front_assets_publish"):
        validate_server_frontend_deploy_readiness(payload, Path("memory://server-frontend-deploy-readiness.json"))


def test_validate_server_frontend_deploy_readiness_rejects_deploy_boundary_drift() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["metadata"]["claim_boundary"] = "Deploy front assets now."

    with pytest.raises(ContractError, match="claim_boundary"):
        validate_server_frontend_deploy_readiness(payload, Path("memory://server-frontend-deploy-readiness.json"))
