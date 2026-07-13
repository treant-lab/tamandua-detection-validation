from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


VALIDATION_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(VALIDATION_ROOT))
sys.path.insert(0, str(ROOT))

from validate_ml_contracts import (  # noqa: E402
    SERVER_FRONTEND_DEPLOY_READINESS_SCHEMA,
    ContractError,
    validate_contract,
    validate_server_frontend_deploy_readiness,
)
from tools.mirror_deploy import server_frontend_deploy_readiness  # noqa: E402


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


def test_server_frontend_deploy_readiness_cli_writes_temp_outputs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = tmp_path / "apps" / "tamandua_server" / "priv" / "static" / "assets" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"src/main.tsx": {"file": "js/main-test.js", "css": ["css/main-test.css"]}}),
        encoding="utf-8",
    )
    (manifest.parent / "js").mkdir()
    (manifest.parent / "css").mkdir()
    (manifest.parent / "js" / "main-test.js").write_text("", encoding="utf-8")
    (manifest.parent / "css" / "main-test.css").write_text("", encoding="utf-8")
    deploy_script = tmp_path / "deploy" / "scripts" / "proxmox" / "deploy-tamandua-front-assets-light.ps1"
    deploy_script.parent.mkdir(parents=True)
    deploy_script.write_text("# no deploy in test\n", encoding="utf-8")
    publication_audit = tmp_path / "20260621T-server-frontend-publication-audit-temp.json"
    publication_audit.write_text(
        json.dumps({"summary": {"same_bundle": False, "publication_state": "published_bundle_differs_from_local_build"}}),
        encoding="utf-8",
    )
    output = tmp_path / "tmp" / "server_frontend_deploy_readiness.json"
    markdown_output = tmp_path / "tmp" / "nested" / "server_frontend_deploy_readiness.md"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "server_frontend_deploy_readiness.py",
            "--endpoint",
            "http://127.0.0.1:4000",
            "--local-manifest",
            str(manifest),
            "--deploy-script",
            str(deploy_script),
            "--publication-audit",
            str(publication_audit),
            "--output",
            str(output),
            "--markdown-output",
            str(markdown_output),
            "--report-id",
            "test_server_frontend_deploy_readiness_temp",
        ],
    )

    assert server_frontend_deploy_readiness.main() == 0
    assert output.exists()
    assert markdown_output.exists()
    assert server_frontend_deploy_readiness.DEFAULT_OUTPUT.parent.name == ".tmp"
    assert server_frontend_deploy_readiness.DEFAULT_MARKDOWN.parent.name == ".tmp"
    validate_server_frontend_deploy_readiness(
        json.loads(output.read_text(encoding="utf-8")),
        Path("memory://server-frontend-deploy-readiness.json"),
    )


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
