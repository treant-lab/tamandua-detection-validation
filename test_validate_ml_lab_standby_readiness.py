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
    ML_LAB_STANDBY_READINESS_SCHEMA,
    validate_contract,
    validate_ml_lab_standby_readiness,
)


def valid_readiness() -> dict:
    checks = [
        {"name": "module_dir_exists", "passed": True, "detail": "infra/azure/ml-lab"},
        {"name": "required_terraform_files_present", "passed": True, "detail": "missing=[]", "missing_files": []},
        {"name": "readme_exists", "passed": True, "detail": "infra/azure/ml-lab/README.md"},
        {"name": "readme_declares_dormant_standby", "passed": True, "detail": "infra/azure/ml-lab/README.md"},
        {"name": "readme_references_adr_and_roadmap", "passed": True, "detail": "infra/azure/ml-lab/README.md"},
        {"name": "adr_local_first_accepted", "passed": True, "detail": "docs/architecture/adr/ADR-0001-local-first-ml-development.md"},
        {"name": "roadmap_local_first_section_present", "passed": True, "detail": "ROADMAP.md"},
        {"name": "terraform_state_absent", "passed": True, "detail": "state_paths=[]", "state_paths": []},
        {
            "name": "active_vm_definitions_absent",
            "passed": True,
            "detail": "active_paths=[]; vm_markers=[]",
            "active_paths": [],
            "vm_resource_markers": [],
        },
        {"name": "storage_public_network_disabled", "passed": True, "detail": "storage.tf public_network_access_enabled=false"},
        {"name": "key_vault_default_deny", "passed": True, "detail": "storage.tf Key Vault network ACL deny + RBAC"},
        {"name": "compute_nsg_denies_inbound_internet", "passed": True, "detail": "network.tf DenyAllInboundInternet"},
        {"name": "raw_malware_guard_documented", "passed": True, "detail": "README and ADR reference real acquisition guard"},
        {"name": "no_execution_claim_boundary_documented", "passed": True, "detail": "README warns module must not be applied while standby"},
        {
            "name": "ml_execution_guards_unset",
            "passed": True,
            "detail": "enabled_guards=[]",
            "expected_unset_guards": [
                "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
                "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
                "TAMANDUA_ALLOW_ML_TRAINING",
                "TAMANDUA_ALLOW_ML_PARITY",
                "TAMANDUA_ALLOW_ML_SERVICE_BENCH",
                "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY",
                "TAMANDUA_ALLOW_ML_HOLDOUT",
                "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            ],
            "enabled_guards": [],
        },
    ]
    return {
        "api_version": "tamandua.io/ml-lab-standby-readiness/v1",
        "kind": "MLLabStandbyReadiness",
        "metadata": {
            "report_id": "test",
            "generated_at": "2026-06-05T15:00:00Z",
            "created_by": "tamandua-ml-lab-standby-readiness",
            "claim_boundary": "No-execution ML lab standby readiness only. It reads local Terraform and docs, and does not run terraform init, plan, apply, contact Azure, acquire samples, train models, run inference, benchmarks, or live services.",
        },
        "configuration": {
            "module_dir": "infra/azure/ml-lab",
            "readme": "infra/azure/ml-lab/README.md",
            "adr": "docs/architecture/adr/ADR-0001-local-first-ml-development.md",
            "roadmap": "ROADMAP.md",
            "required_tf_files": ["versions.tf", "variables.tf", "main.tf", "network.tf", "storage.tf", "bastion.tf"],
            "forbidden_active_paths": ["vm_acquisition.tf", "vm_training.tf", "outputs.tf", "cloud-init"],
            "forbidden_state_patterns": ["*.tfstate", "*.tfstate.backup", ".terraform", ".terraform.lock.hcl"],
            "required_unset_guard_env": [
                "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
                "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
                "TAMANDUA_ALLOW_ML_TRAINING",
                "TAMANDUA_ALLOW_ML_PARITY",
                "TAMANDUA_ALLOW_ML_SERVICE_BENCH",
                "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY",
                "TAMANDUA_ALLOW_ML_HOLDOUT",
                "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
            ],
        },
        "source_status_summary": {
            "module_dir_exists": True,
            "required_terraform_files_present": True,
            "readme_exists": True,
            "readme_declares_dormant_standby": True,
            "readme_references_adr_and_roadmap": True,
            "adr_local_first_accepted": True,
            "roadmap_local_first_section_present": True,
            "terraform_state_absent": True,
            "active_vm_definitions_absent": True,
            "storage_public_network_disabled": True,
            "key_vault_default_deny": True,
            "compute_nsg_denies_inbound_internet": True,
            "raw_malware_guard_documented": True,
            "no_execution_claim_boundary_documented": True,
            "ml_execution_guards_unset": True,
            "check_count": 15,
            "passed_checks": 15,
            "failed_checks": 0,
            "passed": True,
        },
        "passed": True,
        "checks": checks,
    }


def test_validate_ml_lab_standby_readiness_accepts_valid_contract() -> None:
    validate_ml_lab_standby_readiness(valid_readiness(), Path("memory://ml-lab-standby-readiness.json"))


def test_validate_ml_lab_standby_readiness_accepts_jsonschema_path(tmp_path: Path) -> None:
    report_path = tmp_path / "ml-lab-standby-readiness.json"
    report_path.write_text(json.dumps(valid_readiness()), encoding="utf-8")

    mode = validate_contract(report_path, ML_LAB_STANDBY_READINESS_SCHEMA, validate_ml_lab_standby_readiness)

    assert mode == "jsonschema+built-in"


def test_validate_ml_lab_standby_readiness_rejects_passed_mismatch() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["checks"][0]["passed"] = False

    try:
        validate_ml_lab_standby_readiness(payload, Path("memory://ml-lab-standby-readiness.json"))
    except ContractError as exc:
        assert ".passed" in str(exc)
    else:
        raise AssertionError("expected passed mismatch to fail")


def test_validate_ml_lab_standby_readiness_rejects_active_vm_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    check = next(item for item in payload["checks"] if item["name"] == "active_vm_definitions_absent")
    check["active_paths"] = ["infra/azure/ml-lab/vm_acquisition.tf"]

    try:
        validate_ml_lab_standby_readiness(payload, Path("memory://ml-lab-standby-readiness.json"))
    except ContractError as exc:
        assert "active_vm_definitions_absent" in str(exc)
    else:
        raise AssertionError("expected active VM evidence to fail")


def test_validate_ml_lab_standby_readiness_rejects_wrong_module_path() -> None:
    payload = copy.deepcopy(valid_readiness())
    payload["configuration"]["module_dir"] = "infra/azure/prod"

    try:
        validate_ml_lab_standby_readiness(payload, Path("memory://ml-lab-standby-readiness.json"))
    except ContractError as exc:
        assert "module_dir" in str(exc)
    else:
        raise AssertionError("expected wrong module path to fail")


def test_validate_ml_lab_standby_readiness_rejects_enabled_ml_guard_for_green_report() -> None:
    payload = copy.deepcopy(valid_readiness())
    check = next(item for item in payload["checks"] if item["name"] == "ml_execution_guards_unset")
    check["enabled_guards"] = ["TAMANDUA_ALLOW_ML_TRAINING"]

    try:
        validate_ml_lab_standby_readiness(payload, Path("memory://ml-lab-standby-readiness.json"))
    except ContractError as exc:
        assert "ml_execution_guards_unset" in str(exc)
    else:
        raise AssertionError("expected enabled guard evidence to fail")
