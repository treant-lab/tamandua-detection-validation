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
    SERVER_FRONTEND_PUBLICATION_AUDIT_SCHEMA,
    ContractError,
    validate_contract,
    validate_server_frontend_publication_audit,
)
from tools.mirror_deploy import server_frontend_publication_audit  # noqa: E402


def valid_audit() -> dict:
    return {
        "api_version": "tamandua.io/server-frontend-publication-audit/v1",
        "kind": "ServerFrontendPublicationAudit",
        "metadata": {
            "report_id": "test_server_frontend_publication_audit",
            "generated_at": "2026-06-19T00:00:00Z",
            "created_by": "server-frontend-publication-audit",
            "claim_boundary": (
                "No-deploy audit only. Reads the local Vite manifest and endpoint health/manifest; "
                "does not start services, copy assets, change portproxy, or publish releases."
            ),
        },
        "source": {
            "endpoint": "http://192.168.12.146:4000",
            "endpoint_host": "192.168.12.146",
            "endpoint_ipv4": ["192.168.12.146"],
            "local_hostname": "DESKTOP-CQKJ5Q9",
            "local_ipv4_observed": ["127.0.0.1", "192.168.12.103"],
            "local_manifest": "D:\\treant\\tamandua\\apps\\tamandua_server\\priv\\static\\assets\\manifest.json",
        },
        "summary": {
            "health_body": '{"status":"alive"}',
            "health_error": "",
            "health_status": 200,
            "local_css": "css/main-Cu8IIs9x.css",
            "local_main": "js/main-CnMn_IjM.js",
            "manifest_error": "",
            "manifest_status": 200,
            "publication_state": "published_bundle_differs_from_local_build",
            "remote_css": "css/main-Cu8IIs9x.css",
            "remote_main": "js/main-BHDSocFt.js",
            "remote_manifest_available": True,
            "same_bundle": False,
        },
    }


def write_json(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "server-frontend-publication-audit.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_validate_server_frontend_publication_audit_accepts_contract(tmp_path: Path) -> None:
    mode = validate_contract(
        write_json(tmp_path, valid_audit()),
        SERVER_FRONTEND_PUBLICATION_AUDIT_SCHEMA,
        validate_server_frontend_publication_audit,
    )

    assert mode in {"jsonschema+built-in", "built-in"}


def test_server_frontend_publication_audit_cli_writes_temp_outputs_without_real_endpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = tmp_path / "apps" / "tamandua_server" / "priv" / "static" / "assets" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"src/main.tsx": {"file": "js/main-local.js", "css": ["css/main-local.css"]}}),
        encoding="utf-8",
    )
    output = tmp_path / "tmp" / "server_frontend_publication_audit.json"
    markdown_output = tmp_path / "tmp" / "nested" / "server_frontend_publication_audit.md"

    def fake_fetch_text(url: str, timeout: float) -> tuple[int | None, str, str]:
        if url.endswith("/health/live"):
            return 200, '{"status":"alive"}', ""
        if url.endswith("/assets/manifest.json"):
            return (
                200,
                json.dumps({"src/main.tsx": {"file": "js/main-remote.js", "css": ["css/main-local.css"]}}),
                "",
            )
        return None, "", "unexpected URL"

    monkeypatch.setattr(server_frontend_publication_audit, "fetch_text", fake_fetch_text)
    monkeypatch.setattr(server_frontend_publication_audit, "host_ips", lambda hostname: ["127.0.0.1"])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "server_frontend_publication_audit.py",
            "--endpoint",
            "http://127.0.0.1:4000",
            "--local-manifest",
            str(manifest),
            "--output",
            str(output),
            "--markdown-output",
            str(markdown_output),
            "--report-id",
            "test_server_frontend_publication_audit_temp",
        ],
    )

    assert server_frontend_publication_audit.main() == 0
    assert output.exists()
    assert markdown_output.exists()
    assert server_frontend_publication_audit.DEFAULT_OUTPUT.parent.name == ".tmp"
    assert server_frontend_publication_audit.DEFAULT_MARKDOWN.parent.name == ".tmp"
    validate_server_frontend_publication_audit(
        json.loads(output.read_text(encoding="utf-8")),
        Path("memory://server-frontend-publication-audit.json"),
    )


def test_validate_server_frontend_publication_audit_rejects_same_bundle_drift() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["summary"]["same_bundle"] = True

    with pytest.raises(ContractError, match="same_bundle"):
        validate_server_frontend_publication_audit(payload, Path("memory://server-frontend-publication-audit.json"))


def test_validate_server_frontend_publication_audit_rejects_state_drift() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["summary"]["publication_state"] = "published_matches_local_build"

    with pytest.raises(ContractError, match="publication_state"):
        validate_server_frontend_publication_audit(payload, Path("memory://server-frontend-publication-audit.json"))


def test_validate_server_frontend_publication_audit_rejects_deploy_boundary_drift() -> None:
    payload = copy.deepcopy(valid_audit())
    payload["metadata"]["claim_boundary"] = "Deploy the frontend now."

    with pytest.raises(ContractError, match="claim_boundary"):
        validate_server_frontend_publication_audit(payload, Path("memory://server-frontend-publication-audit.json"))
