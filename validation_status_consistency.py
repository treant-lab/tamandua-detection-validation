#!/usr/bin/env python3
"""Audit consistency between the validation scorecard and manual status docs.

This report-only tool checks that the operational benchmark documents point to
the latest closure gate, execution preflight, and offline replay artifacts from
the generated validation roadmap scorecard. It does not execute benchmarks,
contact services, inspect live alerts, or mutate endpoint/server state.
"""

from __future__ import annotations

import argparse
import copy
import importlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
GENERATED_DIR = ROOT / "docs" / "benchmarks" / "generated"
RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
GITIGNORE = ROOT / ".gitignore"
EXPECTED_OFFICIAL_PREFLIGHT_SOURCE = (
    "docs/benchmarks/runs/20260614T023138Z-validation-execution-preflight-probe.json"
)
SCORECARD_JSON = GENERATED_DIR / "validation_roadmap_scorecard.json"
SCORECARD_MD = GENERATED_DIR / "validation_roadmap_scorecard.md"
PRODUCT_READINESS_JSON = GENERATED_DIR / "validation_product_readiness_summary.json"
PRODUCT_READINESS_MD = GENERATED_DIR / "validation_product_readiness_summary.md"
PRODUCT_READINESS_ENV_REQUEST_JSON = GENERATED_DIR / "validation_product_readiness_env_request.json"
PRODUCT_READINESS_ENV_REQUEST_MD = GENERATED_DIR / "validation_product_readiness_env_request.md"
PRODUCT_READINESS_ENV_REQUEST_SCHEMA = GENERATED_DIR / "validation_product_readiness_env_request.schema.json"
PRODUCT_READINESS_ENV_BUNDLE_INIT = GENERATED_DIR / "validation_product_readiness_env_bundle_init.ps1"
PRODUCT_READINESS_ENV_BUNDLE_INIT_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_init.schema.json"
)
PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_INIT = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_local_env_init.ps1"
)
PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_INIT_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_local_env_init.schema.json"
)
PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_VALIDATE = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_local_env_validate.ps1"
)
PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_VALIDATE_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_local_env_validate.schema.json"
)
PRODUCT_READINESS_ENV_BUNDLE_CHECK = GENERATED_DIR / "validation_product_readiness_env_bundle_check.ps1"
PRODUCT_READINESS_ENV_BUNDLE_RUNNER = GENERATED_DIR / "validation_product_readiness_env_bundle_runner.ps1"
PRODUCT_READINESS_ENV_BUNDLE_RUNNER_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_runner.schema.json"
)
PRODUCT_READINESS_ENV_BUNDLE_RUNNER_STATUS_CHECK = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_runner_status_check.ps1"
)
PRODUCT_READINESS_ENV_BUNDLE_RUNNER_STATUS_CHECK_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_runner_status_check.schema.json"
)
PRODUCT_READINESS_ENV_BUNDLE_CHECK_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_env_bundle_check.schema.json"
)
PRODUCT_READINESS_ENV_BUNDLE_LOCAL_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_env_bundle.local.schema.json"
)
PRODUCT_READINESS_ENV_BUNDLE_TEMPLATE = GENERATED_DIR / "validation_product_readiness_env_bundle.template.json"
PRODUCT_READINESS_ENV_BUNDLE_DOTENV_TEMPLATE = (
    GENERATED_DIR / "validation_product_readiness_env_bundle.template.env"
)
PRODUCT_READINESS_OPERATOR_CHECK = GENERATED_DIR / "validation_product_readiness_operator_check.ps1"
PRODUCT_READINESS_OPERATOR_CHECK_SCHEMA = GENERATED_DIR / "validation_product_readiness_operator_check.schema.json"
PRODUCT_READINESS_DOCTOR = GENERATED_DIR / "validation_product_readiness_doctor.ps1"
PRODUCT_READINESS_DOCTOR_SCHEMA = GENERATED_DIR / "validation_product_readiness_doctor.schema.json"
PRODUCT_READINESS_AGENT_HANDOFF_JSON = GENERATED_DIR / "validation_product_readiness_agent_handoff.json"
PRODUCT_READINESS_AGENT_HANDOFF_MD = GENERATED_DIR / "validation_product_readiness_agent_handoff.md"
PRODUCT_READINESS_AGENT_HANDOFF_SCHEMA = GENERATED_DIR / "validation_product_readiness_agent_handoff.schema.json"
PRODUCT_READINESS_POST_ENV_RUNNER = GENERATED_DIR / "validation_product_readiness_post_env_bundle_runner.ps1"
PRODUCT_READINESS_POST_ENV_RUNNER_SCHEMA = GENERATED_DIR / "validation_product_readiness_post_env_bundle_runner.schema.json"
PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_JSON = (
    GENERATED_DIR / "validation_product_readiness_post_env_bundle_runner.contract.json"
)
PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_MD = (
    GENERATED_DIR / "validation_product_readiness_post_env_bundle_runner.contract.md"
)
PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_post_env_bundle_runner.contract.schema.json"
)
PRODUCT_READINESS_RELEASE_GATE_CONTRACT_JSON = GENERATED_DIR / "validation_product_readiness_release_gate.contract.json"
PRODUCT_READINESS_RELEASE_GATE_CONTRACT_MD = GENERATED_DIR / "validation_product_readiness_release_gate.contract.md"
PRODUCT_READINESS_RELEASE_GATE_CONTRACT_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_release_gate.contract.schema.json"
)
PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_JSON = GENERATED_DIR / "validation_product_readiness_claim_status_contract.json"
PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_MD = GENERATED_DIR / "validation_product_readiness_claim_status_contract.md"
PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_SCHEMA = GENERATED_DIR / "validation_product_readiness_claim_status_contract.schema.json"
PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_JSON = (
    GENERATED_DIR / "validation_product_readiness_blocked_run_classes.contract.json"
)
PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_MD = (
    GENERATED_DIR / "validation_product_readiness_blocked_run_classes.contract.md"
)
PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_blocked_run_classes.contract.schema.json"
)
PRODUCT_READINESS_RUNBOOK_JSON = GENERATED_DIR / "validation_product_readiness_runbook.json"
PRODUCT_READINESS_RUNBOOK_MD = GENERATED_DIR / "validation_product_readiness_runbook.md"
PRODUCT_READINESS_RUNBOOK_SCHEMA = GENERATED_DIR / "validation_product_readiness_runbook.schema.json"
PRODUCT_READINESS_REMAINING_WORK_JSON = GENERATED_DIR / "validation_product_readiness_remaining_work.json"
PRODUCT_READINESS_REMAINING_WORK_MD = GENERATED_DIR / "validation_product_readiness_remaining_work.md"
PRODUCT_READINESS_REMAINING_WORK_SCHEMA = GENERATED_DIR / "validation_product_readiness_remaining_work.schema.json"
PRODUCT_READINESS_REMAINING_WORK_CHECK = GENERATED_DIR / "validation_product_readiness_remaining_work_check.ps1"
PRODUCT_READINESS_REMAINING_WORK_CHECK_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_remaining_work_check.schema.json"
)
PRODUCT_READINESS_READY_NOW_FANOUT_JSON = GENERATED_DIR / "validation_product_readiness_ready_now_fanout.json"
PRODUCT_READINESS_READY_NOW_FANOUT_MD = GENERATED_DIR / "validation_product_readiness_ready_now_fanout.md"
PRODUCT_READINESS_READY_NOW_FANOUT_SCHEMA = GENERATED_DIR / "validation_product_readiness_ready_now_fanout.schema.json"
PRODUCT_READINESS_READY_NOW_FANOUT_CHECK = GENERATED_DIR / "validation_product_readiness_ready_now_fanout_check.ps1"
PRODUCT_READINESS_READY_NOW_FANOUT_CHECK_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_ready_now_fanout_check.schema.json"
)
PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_JSON = (
    GENERATED_DIR / "validation_product_readiness_manual_claim_resolution.json"
)
PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_MD = (
    GENERATED_DIR / "validation_product_readiness_manual_claim_resolution.md"
)
PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_manual_claim_resolution.schema.json"
)
PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK = (
    GENERATED_DIR / "validation_product_readiness_manual_claim_resolution_check.ps1"
)
PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_manual_claim_resolution_check.schema.json"
)
PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_RUNNER = (
    GENERATED_DIR / "validation_product_readiness_manual_claim_resolution_runner.ps1"
)
PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_RUNNER_SCHEMA = (
    GENERATED_DIR / "validation_product_readiness_manual_claim_resolution_runner.schema.json"
)
PRODUCT_READINESS_TRACKED_GENERATED_PATHS = (
    "docs/benchmarks/generated/validation_product_readiness_summary.json",
    "docs/benchmarks/generated/validation_product_readiness_summary.md",
    "docs/benchmarks/generated/validation_product_readiness_env_request.json",
    "docs/benchmarks/generated/validation_product_readiness_env_request.md",
    "docs/benchmarks/generated/validation_product_readiness_env_request.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1",
    "docs/benchmarks/generated/validation_product_readiness_operator_check.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_doctor.ps1",
    "docs/benchmarks/generated/validation_product_readiness_doctor.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_agent_handoff.json",
    "docs/benchmarks/generated/validation_product_readiness_agent_handoff.md",
    "docs/benchmarks/generated/validation_product_readiness_agent_handoff.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_check.ps1",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_check.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.ps1",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_validate.ps1",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_validate.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.ps1",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle.local.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.json",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.env",
    "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.ps1",
    "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.json",
    "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.md",
    "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_release_gate.contract.json",
    "docs/benchmarks/generated/validation_product_readiness_release_gate.contract.md",
    "docs/benchmarks/generated/validation_product_readiness_release_gate.contract.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.json",
    "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.md",
    "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.json",
    "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.md",
    "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_runbook.json",
    "docs/benchmarks/generated/validation_product_readiness_runbook.md",
    "docs/benchmarks/generated/validation_product_readiness_runbook.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_remaining_work.json",
    "docs/benchmarks/generated/validation_product_readiness_remaining_work.md",
    "docs/benchmarks/generated/validation_product_readiness_remaining_work.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_remaining_work_check.ps1",
    "docs/benchmarks/generated/validation_product_readiness_remaining_work_check.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout.json",
    "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout.md",
    "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout_check.ps1",
    "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout_check.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution.json",
    "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution.md",
    "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_check.ps1",
    "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_check.schema.json",
    "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.ps1",
    "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.schema.json",
)
PRODUCT_READINESS_LOCAL_SECRET_PATHS = (
    "docs/benchmarks/generated/validation_product_readiness_env_bundle.local.env",
    "docs/benchmarks/generated/validation_product_readiness_env_bundle.local.json",
)
OUTPUT_STEM = "validation_status_consistency"
PROFILE_ID = "validation-status-consistency-probe"
PROFILE_NAME = "Validation Status Consistency Probe"
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-validation-status-consistency-probe$")
LATEST_CONSISTENCY_FAIL_REF_RE = re.compile(
    r"(?:latest\s+(?:superseded\s+)?consistency\s+fail|latest\s+failed\s+run\s+superseded)"
    r"[^`\n]*`?(\d{8}T\d{6}Z-validation-status-consistency-probe)`?",
    re.IGNORECASE,
)

PROFILE_CLOSURE = "roadmap-closure-gate-probe"
PROFILE_PREFLIGHT = "validation-execution-preflight-probe"
PROFILE_REPLAY = "telemetry-replay-offline-fp-severity-v1"
PROFILE_FRESH_RESTORE = "fresh-restore-provenance-probe"
PROFILE_DISPATCH_RESULTS = "validation-dispatch-results-probe"
PROFILE_CALDERA_REPEATABILITY = "caldera-repeatability-probe"
PROFILE_WINDOWS_LAB_READINESS = "windows-lab-execution-readiness-probe"
PROFILE_WINDOWS_CONNECTION_STABILITY = "windows-agent-connection-stability-probe"
PROFILE_MACOS_BACKEND_READINESS = "macos-backend-readiness-probe"
PROFILE_ATOMIC_T1047_CAPABILITY = "atomic-t1047-lab-capability-probe"
PROFILE_WINDOWS_QGA_READINESS = "windows-proxmox-qga-readiness-probe"
PROFILE_LINUX_EBPF_READINESS = "linux-ebpf-readiness-probe"
MIN_SCORECARD_CONSISTENCY_CHECKS = 360
EXPECTED_WINDOWS_LAB_RUN = "20260614T003800Z-windows-lab-execution-readiness-probe"
EXPECTED_WINDOWS_CONNECTION_STABILITY_RUN = "20260614T003923Z-windows-agent-connection-stability-probe"
EXPECTED_MACOS_BACKEND_RUN = "20260614T042036Z-macos-backend-readiness-probe"
EXPECTED_ATOMIC_T1047_RUN = "20260614T042216Z-atomic-t1047-lab-capability-probe"
EXPECTED_WINDOWS_QGA_AGGREGATE_PASS_RUN = "20260614T020741Z-windows-proxmox-qga-readiness-probe"
EXPECTED_WINDOWS_QGA_LATEST_RAW_RUN = "20260614T020741Z-windows-proxmox-qga-readiness-probe"
EXPECTED_WINDOWS_QGA_LATEST_RAW_FAIL_RUN = "20260614T005718Z-windows-proxmox-qga-readiness-probe"
EXPECTED_LINUX_EBPF_RUN = "20260603T180022Z-linux-ebpf-readiness-probe"
EXPECTED_CLOSURE_EXCLUDED_ROADMAPS = {
    "O": "generated_scorecard_automation_not_product_gate",
}
PROXY_SAFE_URLOPEN_FILES = [
    "tools/detection_validation/caldera_api_shape_probe.py",
    "tools/detection_validation/caldera_paw_readiness_probe.py",
    "tools/detection_validation/control_plane_tenant_safety_probe.py",
    "tools/detection_validation/dfir_readiness_probe.py",
    "tools/detection_validation/platform_capabilities_probe.py",
    "tools/detection_validation/tamandua_detection_validation.py",
]
PROXY_SAFE_REQUESTS_SESSION_FILES = [
    "tools/detection_validation/windows_proxmox_qga_readiness_probe.py",
    "tools/detection_validation/windows_proxmox_qga_file_diagnostics_probe.py",
]
EXPECTED_DISPATCH_AGENT_EXCERPTS = {
    "wave-1-provide-required-preflight-env": {
        "missing_package": [
            "validation-execution-preflight-probe",
        ],
        "required_env": [
            "CALDERA_AGENT_PAW",
            "CALDERA_API_KEY",
            "CALDERA_GROUP",
            "TAMANDUA_FRESH_RESTORE",
            "TAMANDUA_FRESH_RESTORE_AGENT_ID",
            "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
            "TAMANDUA_FRESH_RESTORE_HOSTNAME",
            "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
            "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
            "TAMANDUA_FRESH_RESTORE_STARTED_AT",
            "TAMANDUA_FRESH_RESTORE_VMID",
            "TAMANDUA_SERVER_PASSWORD",
        ]
    },
    "wave-1-restore-macos-backend-readiness": {
        "hostname": "Victors-MacBook-Pro.local",
        "status": "offline",
    },
    "wave-1-restore-windows-qga-readiness": {
        "missing_package": [
            "windows-proxmox-qga-readiness-probe",
            "windows-proxmox-qga-file-diagnostics-probe",
        ],
        "required_env": ["TAMANDUA_PROXMOX_PASSWORD", "TAMANDUA_SERVER_PASSWORD"],
    },
    "wave-2-restore-caldera-readiness-repeatability": {
        "missing_package": [
            "caldera-api-shape-probe",
            "caldera-paw-readiness-probe",
            "caldera-repeatability-probe",
        ],
        "required_env": ["CALDERA_AGENT_PAW", "CALDERA_API_KEY", "CALDERA_GROUP"],
    },
    "wave-3-rerun-preflight-and-closure-gate": {
        "missing": ["roadmap_status_pass"]
    },
}
EXPECTED_DISPATCH_WINDOWS_CONNECTION_HANDOFF = {}
EXPECTED_DISPATCH_MACOS_AUTH_HANDOFF = {
    "package_id": "wave-1-restore-macos-backend-readiness",
    "profile_id": PROFILE_MACOS_BACKEND_READINESS,
    "missing_readiness": ["status_online", "health_healthy", "fresh_heartbeat"],
    "login_command": "",
    "token_env": "",
    "token_login_command": "",
    "target_server": "",
    "has_action": True,
}
EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS = {
    "B": [
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "TAMANDUA_FRESH_RESTORE_HOSTNAME",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "TAMANDUA_FRESH_RESTORE_VMID",
    ],
    "D": ["CALDERA_AGENT_PAW", "CALDERA_API_KEY", "CALDERA_GROUP"],
}
EXPECTED_PREFLIGHT_PACKAGE_REQUIRED_ENVS = {
    "wave-2-capture-fresh-restore-provenance": [
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "TAMANDUA_FRESH_RESTORE_HOSTNAME",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "TAMANDUA_FRESH_RESTORE_VMID",
    ],
}
EXPECTED_CALDERA_REPEATABILITY_RESET_REASONS = {
    "windows-caldera-enterprise-safe": (
        "quality_gate_failed:caldera_agent_stale_1021008s,caldera_agent_stale_or_offline"
    ),
}
EXPECTED_CALDERA_REPEATABILITY_NEXT_ACTIONS = {
    "windows-caldera-smoke": {
        "passes_needed": 3,
        "profile_file": "tools/detection_validation/profiles/windows_caldera_smoke.json",
        "has_command_hint": True,
        "required_env": ["CALDERA_API_KEY", "CALDERA_GROUP", "CALDERA_AGENT_PAW"],
    },
    "windows-caldera-enterprise-safe": {
        "passes_needed": 3,
        "profile_file": "tools/detection_validation/profiles/windows_caldera_enterprise_safe.json",
        "has_command_hint": True,
        "required_env": ["CALDERA_API_KEY", "CALDERA_GROUP", "CALDERA_AGENT_PAW"],
    },
}
EXPECTED_PREFLIGHT_REQUIRED_ENVS = [
    "CALDERA_API_KEY",
    "CALDERA_AGENT_PAW",
    "CALDERA_GROUP",
    "TAMANDUA_FRESH_RESTORE",
    "TAMANDUA_FRESH_RESTORE_AGENT_ID",
    "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
    "TAMANDUA_FRESH_RESTORE_HOSTNAME",
    "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
    "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
    "TAMANDUA_FRESH_RESTORE_STARTED_AT",
    "TAMANDUA_FRESH_RESTORE_VMID",
]
EXPECTED_ROADMAP_B_NOTE_MARKERS = [
    "executed",
    "non-planned",
    "fresh_restore=true",
    "valid restore timing order",
    "hostname fields",
]
EXPECTED_BLOCKED_RUN_CLASS_ROADMAPS = {
    "macos-server-backed-smoke": ["E"],
    "windows-atomic-extended": ["M"],
    "windows-broad": ["A", "B", "M"],
    "windows-caldera-enterprise": ["D", "M"],
}
EXPECTED_BLOCKED_RUN_CLASS_MISSING_ENVS = {
    "macos-server-backed-smoke": [],
    "windows-atomic-extended": [],
    "windows-broad": [],
    "windows-caldera-enterprise": [],
}
EXPECTED_UNBLOCK_SEQUENCE = [
    "capture-fresh-restore-provenance",
    "restore-caldera-readiness-repeatability",
    "resolve-atomic-extended-preconditions",
    "restore-macos-backend-readiness",
    "rerun-preflight-and-closure-gate",
]
EXPECTED_UNBLOCK_SEQUENCE_PRIORITIES = [30, 40, 50, 60, 90]
EXPECTED_PARALLEL_UNBLOCK_WAVES = [
    {
        "wave": 1,
        "parallelizable": True,
        "step_ids": [
            "resolve-atomic-extended-preconditions",
            "restore-macos-backend-readiness",
        ],
        "depends_on_waves": [],
    },
    {
        "wave": 2,
        "parallelizable": True,
        "step_ids": [
            "capture-fresh-restore-provenance",
            "restore-caldera-readiness-repeatability",
        ],
        "depends_on_waves": [1],
    },
    {
        "wave": 3,
        "parallelizable": False,
        "step_ids": ["rerun-preflight-and-closure-gate"],
        "depends_on_waves": [1, 2],
    },
]
EXPECTED_PREFLIGHT_SAFE_COMMAND_MARKERS = [
    "caldera_repeatability_probe.py --output-dir",
    "macos_backend_readiness_probe.py --server http://192.168.12.146:4000 --output-dir",
    "roadmap_closure_gate_probe.py --output-dir",
]

STATUS_DOCS = [
    ROOT / "docs" / "benchmarks" / "NEXT_VALIDATION_WORK_QUEUE.md",
    ROOT / "docs" / "benchmarks" / "PARALLEL_EXECUTION_BOARD.md",
    ROOT / "docs" / "benchmarks" / "REMAINING_VALIDATION_BLOCKERS.md",
]
NEXT_VALIDATION_WORK_QUEUE_DOC = STATUS_DOCS[0]
PARALLEL_EXECUTION_BOARD_DOC = STATUS_DOCS[1]
FRESH_RESTORE_STATUS_DOCS = STATUS_DOCS + [
    ROOT / "docs" / "benchmarks" / "FRESH_RESTORE_PROVENANCE_RUNBOOK.md",
]
CROSS_PLATFORM_PARITY_DOC = ROOT / "docs" / "benchmarks" / "CROSS_PLATFORM_PARITY_WORK_QUEUE.md"
PRODUCT_MATURITY_DOC = ROOT / "docs" / "benchmarks" / "PRODUCT_MATURITY_EXECUTION_ROADMAP.md"
ENGINE_MATURITY_DOC = ROOT / "docs" / "benchmarks" / "ENGINE_MATURITY_REVIEW.md"
AI_MODEL_SCANNER_SCORECARD_DOC = ROOT / "docs" / "benchmarks" / "AI_MODEL_SCANNER_SCORECARD.md"
BENCHMARK_RESULTS_REVIEW_DOC = ROOT / "docs" / "benchmarks" / "BENCHMARK_RESULTS_REVIEW.md"
ROADMAP_DELIVERY_PLAN_DOC = ROOT / "docs" / "benchmarks" / "ROADMAP_DELIVERY_PLAN.md"
VALIDATION_MASTER_PLAN_DOC = ROOT / "docs" / "benchmarks" / "VALIDATION_MASTER_PLAN.md"
KNOWN_PRODUCTION_GAPS_DOC = ROOT / "docs" / "KNOWN_PRODUCTION_GAPS.md"
REFRESH_AUTHORITY_SCRIPT = ROOT / "tools" / "detection_validation" / "refresh_validation_authority.py"


def git_snapshot() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            ).stdout.strip()
        except OSError:
            return ""

    commit = run(["git", "rev-parse", "HEAD"])
    status = run(["git", "status", "--porcelain"]).splitlines()
    return {
        "commit": commit,
        "commit_short": commit[:8] if commit else "",
        "dirty": bool(status),
        "status_short": status,
    }


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def normalize_artifact_ref(value: Any) -> str:
    return str(value or "").replace("\\", "/")


def int_or_zero(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def env_template_placeholder(name: str) -> str:
    upper = name.upper()
    suffix = "-secret" if any(marker in upper for marker in ("KEY", "PASSWORD", "TOKEN", "SECRET")) else ""
    return f"<set-{name.lower().replace('_', '-')}{suffix}>"


def compact_stamp(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace(".", "")[:15] + "Z"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"error: missing JSON artifact: {rel(path)}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"error: expected JSON object: {rel(path)}")
    return data


def load_text(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"error: missing document: {rel(path)}")
    return path.read_text(encoding="utf-8")


def latest_profile(scorecard: dict[str, Any], profile_id: str) -> dict[str, Any]:
    entry = profile_entry(scorecard, profile_id)
    latest = entry.get("latest") if isinstance(entry.get("latest"), dict) else {}
    if not latest:
        raise SystemExit(f"error: scorecard profile has no latest artifact: {profile_id}")
    return latest


def profile_entry(scorecard: dict[str, Any], profile_id: str) -> dict[str, Any]:
    for entry in scorecard.get("profiles") or []:
        if isinstance(entry, dict) and entry.get("profile_id") == profile_id:
            return entry
    raise SystemExit(f"error: scorecard missing profile: {profile_id}")


def artifact_path(latest: dict[str, Any]) -> Path:
    path_value = latest.get("path")
    if not path_value:
        raise SystemExit(f"error: latest artifact has no path for {latest.get('profile_id')}")
    path = Path(str(path_value))
    return path if path.is_absolute() else ROOT / path


def check(checks: list[dict[str, Any]], name: str, actual: Any, expected: Any, sources: list[str]) -> None:
    checks.append(
        {
            "name": name,
            "status": "PASS" if actual == expected else "FAIL",
            "actual": actual,
            "expected": expected,
            "source_files": sources,
        }
    )


def check_contains(
    checks: list[dict[str, Any]], name: str, text: str, needle: str, source: Path
) -> None:
    check(checks, name, needle in text, True, [rel(source)])


def scorecard_artifact_marker(scorecard: dict[str, Any]) -> str:
    source_meta = scorecard.get("source") if isinstance(scorecard.get("source"), dict) else {}
    artifact_count = source_meta.get("artifact_count")
    profile_count = source_meta.get("profile_count")
    return f"`{artifact_count}` artifacts across `{profile_count}` profiles"


def engine_maturity_uses_current_scorecard_wording(text: str) -> bool:
    return (
        "based on the current generated scorecard" in text
        and "based on the generated scorecard from `" not in text
    )


def refresh_authority_script_preserves_sequential_boundary(text: str) -> bool:
    return all(
        marker in text
        for marker in (
            "intentionally sequential",
            "preflight must bind to the closure gate",
            "--closure-gate-json",
            "PACKAGE_EMIT_FLAGS",
            "--promote-dispatch-results",
            "generate_product_readiness_summary.py",
        )
    )


def load_refresh_authority_dry_run_plan(script_path: Path) -> dict[str, Any] | None:
    try:
        completed = subprocess.run(
            [sys.executable, str(script_path), "--dry-run"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def refresh_authority_dry_run_plan_is_sequential(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    steps = payload.get("steps")
    if not isinstance(steps, list):
        return False
    labels = [step.get("label") for step in steps if isinstance(step, dict)]
    if labels != [
        "scorecard-before-closure",
        "roadmap-closure-gate",
        "validation-execution-preflight",
            "preflight-work-package",
            "dispatch-results",
            "scorecard-after-dispatch",
            "product-readiness-summary",
        ]:
        return False
    by_label = {step.get("label"): step for step in steps if isinstance(step, dict)}
    preflight_command = by_label.get("validation-execution-preflight", {}).get("command")
    package_command = by_label.get("preflight-work-package", {}).get("command")
    dispatch_command = by_label.get("dispatch-results", {}).get("command")
    product_summary_command = by_label.get("product-readiness-summary", {}).get("command")
    if not all(
        isinstance(command, list)
        for command in (preflight_command, package_command, dispatch_command, product_summary_command)
    ):
        return False
    return (
        "--closure-gate-json" in preflight_command
        and "<closure-json-from-previous-step>" in preflight_command
        and "--preflight-json" in package_command
        and "<preflight-json-from-previous-step>" in package_command
        and "--emit-dispatch-manifest" in package_command
        and "--promote-dispatch-results" in dispatch_command
        and any("dispatch_manifest.json" in str(part) for part in dispatch_command)
        and "tools/detection_validation/generate_product_readiness_summary.py" in product_summary_command
        and "--scorecard-json" in product_summary_command
    )


def load_product_readiness_operator_check_json(script_path: Path = PRODUCT_READINESS_OPERATOR_CHECK) -> dict[str, Any] | None:
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-Json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode not in (0, 2):
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    payload["_operator_check_returncode"] = completed.returncode
    return payload


def load_product_readiness_remaining_work_check_json(
    script_path: Path = PRODUCT_READINESS_REMAINING_WORK_CHECK,
) -> dict[str, Any] | None:
    if not script_path.exists():
        return None
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-Json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode not in (0, 2) or not completed.stdout.strip():
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        payload["_remaining_work_check_returncode"] = completed.returncode
        return payload
    return None


def load_product_readiness_ready_now_fanout_check_json(
    script_path: Path = PRODUCT_READINESS_READY_NOW_FANOUT_CHECK,
) -> dict[str, Any] | None:
    if not script_path.exists():
        return None
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-Json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode not in (0, 2) or not completed.stdout.strip():
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        payload["_ready_now_fanout_check_returncode"] = completed.returncode
        return payload
    return None


def load_product_readiness_manual_claim_resolution_check_json(
    script_path: Path = PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK,
) -> dict[str, Any] | None:
    if not script_path.exists():
        return None
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-Json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode not in (0, 2) or not completed.stdout.strip():
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        payload["_manual_claim_resolution_check_returncode"] = completed.returncode
        return payload
    return None


def load_product_readiness_manual_claim_resolution_runner_json(
    script_path: Path = PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_RUNNER,
) -> dict[str, Any] | None:
    if not script_path.exists():
        return None
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-Json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode not in (0, 2) or not completed.stdout.strip():
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        payload["_manual_claim_resolution_runner_returncode"] = completed.returncode
        return payload
    return None


def load_product_readiness_post_env_runner_json(
    script_path: Path = PRODUCT_READINESS_POST_ENV_RUNNER,
) -> dict[str, Any] | None:
    if not script_path.exists():
        return None
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-Json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode not in (0, 2) or not completed.stdout.strip():
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        payload["_post_env_runner_returncode"] = completed.returncode
        return payload
    return None


def load_product_readiness_doctor_json(
    script_path: Path = PRODUCT_READINESS_DOCTOR,
) -> dict[str, Any] | None:
    if not script_path.exists():
        return None
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-Json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode not in (0, 1, 2) or not completed.stdout.strip():
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        payload["_doctor_returncode"] = completed.returncode
        return payload
    return None


def product_readiness_operator_check_json_blocker_reasons(
    payload: dict[str, Any] | None,
    expected_missing_env: list[str],
    preflight_run: str = "",
) -> list[str]:
    if not isinstance(payload, dict):
        return ["payload-not-object"]
    missing_env = sorted(str(value) for value in payload.get("current_env_missing_names") or [])
    missing_env_details = [item for item in payload.get("missing_env_details") or [] if isinstance(item, dict)]
    missing_env_detail_by_name = {str(item.get("env") or ""): item for item in missing_env_details}
    expected_missing_env = sorted(str(value) for value in expected_missing_env)
    missing_set_commands = [str(value) for value in payload.get("missing_set_commands") or []]
    recommended_commands = [str(value) for value in payload.get("recommended_next_action_commands") or []]
    joined_missing_commands = " ".join(missing_set_commands)
    balanced_commands = [str(command) for command in payload.get("post_env_bundle_balanced_agent_spawn_commands") or []]
    release_gate = payload.get("product_release_gate") if isinstance(payload.get("product_release_gate"), dict) else {}
    post_env_plan = payload.get("post_env_bundle_plan") if isinstance(payload.get("post_env_bundle_plan"), dict) else {}
    post_agent_gate = (
        payload.get("post_agent_status_gate")
        if isinstance(payload.get("post_agent_status_gate"), dict)
        else {}
    )
    handoff_artifacts = payload.get("handoff_artifacts") if isinstance(payload.get("handoff_artifacts"), dict) else {}
    manual_claims = payload.get("manual_claims") if isinstance(payload.get("manual_claims"), list) else []
    manual_claim_ids = [str(claim.get("claim_id") or "") for claim in manual_claims if isinstance(claim, dict)]
    manual_next_actions = " ".join(
        str(claim.get("next_action") or "") for claim in manual_claims if isinstance(claim, dict)
    )
    def int_or_missing(value: Any) -> int:
        return -1 if value is None else int(value)

    def is_expected_handoff_path(value: Any) -> bool:
        normalized = normalize_artifact_ref(value)
        if preflight_run:
            return normalized.startswith(f"docs/benchmarks/runs/{preflight_run}.package-artifacts/") or (
                "validation-execution-preflight-probe.package-artifacts/" in normalized
            )
        return "validation-execution-preflight-probe.package-artifacts/" in normalized

    if int_or_missing(payload.get("required_env_count")) == 0:
        checks = {
            "schema-version": int_or_missing(payload.get("schema_version")) == 1,
            "artifact": payload.get("artifact") == "validation-product-readiness-operator-check",
            "returncode": int_or_missing(payload.get("_operator_check_returncode")) in (-1, 2),
            "product-ready": payload.get("product_ready") != True,
            "product-release-gate": (
                release_gate.get("passed") is False
                and {
                    "closure-gate",
                    "preflight-gate",
                    "dispatch-gate",
                    "post-agent-status",
                    "blocked-run-classes",
                }.issubset(set(str(value) for value in release_gate.get("failed_ids") or []))
            ),
            "needs-env-input": payload.get("needs_env_input") is False,
            "missing-env": missing_env == [],
            "missing-env-details": missing_env_detail_by_name == {},
            "fast-path-count": int_or_missing(payload.get("single_env_fast_path_count")) == 0,
            "launchable-claim-ids": payload.get("launchable_claim_ids") == [],
            "recommended-next-action": payload.get("recommended_next_action_id") in {
                "fill-env-bundle",
                "refresh-validation-authority",
            },
            "post-env-bundle-plan": (
                post_env_plan.get("actionable") is False
                and int_or_missing(post_env_plan.get("ready_claim_count")) == 0
                and int_or_missing(post_env_plan.get("ready_batch_count")) == 0
                and int_or_missing(post_env_plan.get("still_blocked_claim_count")) == 0
                and list(post_env_plan.get("ready_claim_ids") or []) == []
                and list(post_env_plan.get("still_blocked_claim_ids") or []) == []
            ),
            "post-agent-status-gate": (
                int_or_missing(post_agent_gate.get("ready_after_env_passed_count")) == 0
                and int_or_missing(post_agent_gate.get("ready_after_env_required_count")) == 0
                and post_agent_gate.get("ready_after_env_all_passed") is False
                and str(post_agent_gate.get("report") or "").endswith("claim_status_report.json")
                and "--refresh-claim-status-report" in str(post_agent_gate.get("refresh_command") or "")
                and (
                    (
                        "pass" not in (post_agent_gate.get("status_counts") or {})
                        and "fail" not in (post_agent_gate.get("status_counts") or {})
                        and int_or_missing((post_agent_gate.get("status_counts") or {}).get("not_run")) == 5
                    )
                    or (
                        int_or_missing((post_agent_gate.get("status_counts") or {}).get("pass")) == 1
                        and int_or_missing((post_agent_gate.get("status_counts") or {}).get("fail")) == 1
                        and int_or_missing((post_agent_gate.get("status_counts") or {}).get("not_run")) == 3
                    )
                    or (
                        int_or_missing((post_agent_gate.get("status_counts") or {}).get("pass")) == 1
                        and int_or_missing((post_agent_gate.get("status_counts") or {}).get("fail")) == 2
                        and int_or_missing((post_agent_gate.get("status_counts") or {}).get("not_run")) == 2
                    )
                )
            ),
            "handoff-artifacts": all(
                key in handoff_artifacts
                and is_expected_handoff_path(handoff_artifacts.get(key))
                for key in [
                    "dispatch_brief",
                    "env_checklist",
                    "env_template",
                    "env_unblock_queue",
                    "env_unblock_queue_json",
                    "agent_claims",
                    "agent_spawn_plan",
                    "agent_spawn_launcher",
                    "env_bundle_ready_claims_launcher",
                    "dispatch_prelaunch_validation",
                    "dispatch_one_shot_runner",
                    "claim_status_report",
                    "claim_status_report_json",
                ]
            ),
        }
        return [name for name, passed in checks.items() if not passed]

    checks = {
        "schema-version": int_or_missing(payload.get("schema_version")) == 1,
        "artifact": payload.get("artifact") == "validation-product-readiness-operator-check",
        "returncode": int_or_missing(payload.get("_operator_check_returncode")) in (-1, 2),
        "product-ready": payload.get("product_ready") != True,
        "product-release-gate": (
            release_gate.get("passed") is False
            and int_or_missing(release_gate.get("failed_count")) >= 1
            and {
                "closure-gate",
                "preflight-gate",
                "dispatch-gate",
                "required-env",
                "post-agent-status",
            }.issubset(set(str(value) for value in release_gate.get("failed_ids") or []))
        ),
        "automation-state": payload.get("automation_state") == "blocked_missing_env",
        "can-launch-now": payload.get("can_launch_now") != True,
        "needs-env-input": payload.get("needs_env_input") is True,
        "required-env-count": int_or_missing(payload.get("required_env_count")) == len(expected_missing_env),
        "current-env-present": int_or_missing(payload.get("current_env_present_count")) == 0,
        "missing-env": missing_env == expected_missing_env,
        "missing-env-details": (
            sorted(missing_env_detail_by_name) == expected_missing_env
            and (
                "TAMANDUA_SERVER_PASSWORD" not in expected_missing_env
                or missing_env_detail_by_name.get("TAMANDUA_SERVER_PASSWORD", {}).get("class") == "secret"
            )
            and missing_env_detail_by_name.get("TAMANDUA_SERVER_PASSWORD", {}).get("placeholder")
            in ("<set-tamandua-server-password-secret>", None)
            and (
                "CALDERA_API_KEY" not in expected_missing_env
                or missing_env_detail_by_name.get("CALDERA_API_KEY", {}).get("class") == "secret"
            )
            and (
                "CALDERA_API_KEY" not in expected_missing_env
                or "CALDERA API key"
                in str(missing_env_detail_by_name.get("CALDERA_API_KEY", {}).get("description") or "")
            )
        ),
        "fast-path-count": int_or_missing(payload.get("single_env_fast_path_count")) == 0,
        "full-bundle-ready": payload.get("full_env_bundle_ready") != True,
        "missing-set-command-count": len(missing_set_commands) == len(expected_missing_env),
        "missing-set-command-envs": all(env_name in joined_missing_commands for env_name in expected_missing_env),
        "handoff-artifacts": all(
            key in handoff_artifacts
            and is_expected_handoff_path(handoff_artifacts.get(key))
            for key in [
                "dispatch_brief",
                "env_checklist",
                "env_template",
                "env_unblock_queue",
                "env_unblock_queue_json",
                "agent_claims",
                "agent_spawn_plan",
                "agent_spawn_launcher",
                "env_bundle_ready_claims_launcher",
                "dispatch_prelaunch_validation",
                "dispatch_one_shot_runner",
                "claim_status_report",
                "claim_status_report_json",
            ]
        ),
        "manual-claims": (
            manual_claim_ids == []
            or (
                manual_claim_ids == ["claim-wave-1-resolve-atomic-extended-preconditions"]
                and "WMI-capable disposable target" in manual_next_actions
            )
        ),
        "launchable-claim-ids": payload.get("launchable_claim_ids") == [],
        "recommended-next-action": payload.get("recommended_next_action_id") == "fill-env-bundle",
        "recommended-command-count": len(recommended_commands) == 1,
        "recommended-local-env-validate": any(
            "validation_product_readiness_env_bundle_local_env_validate.ps1 -PrepareIfMissing -Json" in command
            for command in recommended_commands
        ),
        "validate-command": "-ValidateOnly" in str(payload.get("env_bundle_validation_command") or ""),
        "balanced-command": any(
            "-Provider balanced -Phase env-bundle -Execute -Parallel" in command for command in balanced_commands
        ),
        "post-env-bundle-plan": (
            post_env_plan.get("actionable") is False
            and int_or_missing(post_env_plan.get("ready_claim_count")) == 1
            and int_or_missing(post_env_plan.get("ready_batch_count")) == 1
            and int_or_missing(post_env_plan.get("still_blocked_claim_count")) == 3
            and sorted(post_env_plan.get("ready_claim_ids") or [])
            == [
                "claim-wave-1-restore-macos-backend-readiness",
            ]
            and any(
                "-Provider balanced -Phase env-bundle -Execute -Parallel" in str(command)
                for command in post_env_plan.get("balanced_agent_spawn_commands") or []
            )
        ),
        "post-agent-status-gate": (
            int_or_missing(post_agent_gate.get("ready_after_env_passed_count")) == 0
            and int_or_missing(post_agent_gate.get("ready_after_env_required_count")) == 1
            and post_agent_gate.get("ready_after_env_all_passed") is False
            and len(post_agent_gate.get("incomplete_ready_after_env_claims") or []) == 1
            and str(post_agent_gate.get("report") or "").endswith("claim_status_report.json")
            and "--refresh-claim-status-report" in str(post_agent_gate.get("refresh_command") or "")
            and int_or_missing((post_agent_gate.get("status_counts") or {}).get("not_run")) == 5
            and "fail" not in (post_agent_gate.get("status_counts") or {})
            and sum(int(value or 0) for value in (post_agent_gate.get("status_counts") or {}).values()) == 5
        ),
    }
    return [name for name, passed in checks.items() if not passed]


def product_readiness_operator_check_json_matches_current_blockers(
    payload: dict[str, Any] | None,
    expected_missing_env: list[str],
    preflight_run: str,
) -> bool:
    return product_readiness_operator_check_json_blocker_reasons(payload, expected_missing_env, preflight_run) == []


def product_readiness_operator_schema_matches_payload(
    schema: dict[str, Any],
    payload: dict[str, Any] | None,
) -> bool:
    if not isinstance(schema, dict) or not isinstance(payload, dict):
        return False
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    public_payload = {
        str(key): value
        for key, value in payload.items()
        if not str(key).startswith("_")
    }
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        return False
    if schema.get("additionalProperties") is not False:
        return False
    if properties.get("schema_version", {}).get("const") != 1:
        return False
    if properties.get("artifact", {}).get("const") != "validation-product-readiness-operator-check":
        return False
    if set(required) != set(public_payload):
        return False
    if set(properties) != set(public_payload):
        return False
    automation_enum = properties.get("automation_state", {}).get("enum")
    recommended_enum = properties.get("recommended_next_action_id", {}).get("enum")
    return (
        isinstance(automation_enum, list)
        and payload.get("automation_state") in automation_enum
        and isinstance(recommended_enum, list)
        and payload.get("recommended_next_action_id") in recommended_enum
    )


def product_readiness_env_request_matches_summary(request: dict[str, Any], summary: dict[str, Any]) -> bool:
    if not isinstance(request, dict) or not isinstance(summary, dict):
        return False
    env_queue = summary.get("env_queue") if isinstance(summary.get("env_queue"), dict) else {}
    env_details = summary.get("env_details") if isinstance(summary.get("env_details"), dict) else {}
    expected_env = sorted(str(value) for value in env_queue.get("current_env_missing_names") or [])
    entries = request.get("entries") if isinstance(request.get("entries"), list) else []
    entry_by_env = {str(entry.get("env") or ""): entry for entry in entries if isinstance(entry, dict)}
    commands = [str(command) for command in request.get("copy_paste_powershell") or []]
    request_next_action = (
        request.get("recommended_next_action")
        if isinstance(request.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    if not expected_env:
        return (
            request.get("schema_version") == 1
            and request.get("artifact") == "validation-product-readiness-env-request"
            and request.get("product_ready") is False
            and request.get("product_release_gate_passed") is False
            and int_or_default(request.get("required_env_count")) == 0
            and int_or_default(request.get("secret_count")) == 0
            and int_or_default(request.get("metadata_count")) == 0
            and entries == []
            and commands == []
            and request.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
            and request_next_action.get("id") == summary_next_action.get("id")
            and request_next_action.get("step") == summary_next_action.get("step")
            and sorted(request_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
            and "secret values" in str(request.get("claim_boundary") or "")
        )
    return (
        request.get("schema_version") == 1
        and request.get("artifact") == "validation-product-readiness-env-request"
        and request.get("product_ready") is False
        and request.get("product_release_gate_passed") is False
        and int(request.get("required_env_count") or -1) == len(expected_env)
        and int(request.get("secret_count") or -1) == 4
        and int(request.get("metadata_count") or -1) == 10
        and sorted(entry_by_env) == expected_env
        and len(commands) == len(expected_env)
        and "$env:TAMANDUA_SERVER_PASSWORD = '<set-tamandua-server-password-secret>'" in commands
        and "$env:CALDERA_API_KEY = '<set-caldera-api-key-secret>'" in commands
        and request.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and request_next_action.get("id") == summary_next_action.get("id")
        and request_next_action.get("step") == summary_next_action.get("step")
        and sorted(request_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and "operator input only" in str(request_next_action.get("claim_boundary") or "")
        and entry_by_env.get("TAMANDUA_SERVER_PASSWORD", {}).get("class") == "secret"
        and entry_by_env.get("TAMANDUA_SERVER_PASSWORD", {}).get("placeholder")
        == "<set-tamandua-server-password-secret>"
        and entry_by_env.get("CALDERA_API_KEY", {}).get("description")
        == env_details.get("CALDERA_API_KEY", {}).get("description")
        and "do not paste real secret values" in str(request.get("claim_boundary") or "")
    )


def product_readiness_env_request_schema_matches_payload(
    schema: dict[str, Any],
    payload: dict[str, Any],
) -> bool:
    if not isinstance(schema, dict) or not isinstance(payload, dict):
        return False
    def int_or_missing(value: Any) -> int:
        return -1 if value is None else int(value)

    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    entries_property = properties.get("entries") if isinstance(properties.get("entries"), dict) else {}
    entry_schema = entries_property.get("items") if isinstance(entries_property.get("items"), dict) else {}
    entry_properties = entry_schema.get("properties") if isinstance(entry_schema.get("properties"), dict) else {}
    entry_required = entry_schema.get("required") if isinstance(entry_schema.get("required"), list) else []
    entries = payload.get("entries") if isinstance(payload.get("entries"), list) else []
    first_entry = next((entry for entry in entries if isinstance(entry, dict)), None)
    return (
        schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
        and schema.get("additionalProperties") is False
        and properties.get("schema_version", {}).get("const") == 1
        and properties.get("artifact", {}).get("const") == "validation-product-readiness-env-request"
        and set(required) == set(payload)
        and set(properties) == set(payload)
        and entry_schema.get("additionalProperties") is False
        and (
            first_entry is None
            or (set(entry_required) == set(first_entry) and set(entry_properties) == set(first_entry))
        )
        and int_or_missing(payload.get("required_env_count")) == len(entries)
        and int_or_missing(payload.get("secret_count"))
        == sum(1 for entry in entries if isinstance(entry, dict) and entry.get("class") == "secret")
        and int_or_missing(payload.get("metadata_count"))
        == sum(1 for entry in entries if isinstance(entry, dict) and entry.get("class") != "secret")
    )


def product_readiness_gitignore_preserves_generated_artifact_tracking_boundary(gitignore_text: str) -> bool:
    if not gitignore_text:
        return False
    rules = {
        line.strip().replace("\\", "/")
        for line in gitignore_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    required_ignored_roots = {"docs/benchmarks/generated/*", "docs/benchmarks/runs/*"}
    required_whitelist = {f"!{path}" for path in PRODUCT_READINESS_TRACKED_GENERATED_PATHS}
    forbidden_secret_whitelist = {f"!{path}" for path in PRODUCT_READINESS_LOCAL_SECRET_PATHS}
    return (
        required_ignored_roots.issubset(rules)
        and required_whitelist.issubset(rules)
        and rules.isdisjoint(forbidden_secret_whitelist)
    )


def product_readiness_env_bundle_artifacts_match_env_request(
    init_text: str,
    local_env_init_text: str,
    local_env_validate_text: str,
    script_text: str,
    runner_text: str,
    runner_status_check_text: str,
    init_schema: dict[str, Any],
    local_env_init_schema: dict[str, Any],
    local_env_validate_schema: dict[str, Any],
    check_schema: dict[str, Any],
    runner_schema: dict[str, Any],
    runner_status_check_schema: dict[str, Any],
    local_schema: dict[str, Any],
    template: dict[str, Any],
    dotenv_template: str,
    env_request: dict[str, Any],
) -> bool:
    if not all(
        isinstance(item, dict)
        for item in (
            init_schema,
            local_env_init_schema,
            local_env_validate_schema,
            check_schema,
            runner_schema,
            runner_status_check_schema,
            local_schema,
            template,
            env_request,
        )
    ):
        return False
    entries = [entry for entry in env_request.get("entries") or [] if isinstance(entry, dict)]
    expected_env = [str(entry.get("env") or "") for entry in entries if entry.get("env")]
    expected_template = {
        str(entry.get("env") or ""): str(entry.get("placeholder") or "")
        for entry in entries
        if entry.get("env")
    }
    properties = local_schema.get("properties") if isinstance(local_schema.get("properties"), dict) else {}
    return (
        "Product Readiness Env Bundle Init" in init_text
        and "validation_product_readiness_env_bundle.template.json" in init_text
        and "validation_product_readiness_env_bundle.local.json" in init_text
        and "refusing to overwrite without -Force" in init_text
        and "[switch]$FromProcessEnv" in init_text
        and "[string]$EnvFile" in init_text
        and "Local env bundle initialized from env file" in init_text
        and "Process env is missing required names" in init_text
        and "No secret values were printed" in init_text
        and (init_schema.get("properties") or {}).get("artifact", {}).get("const")
        == "validation-product-readiness-env-bundle-init"
        and "from_env_file" in list(init_schema.get("required") or [])
        and "env-file" in list(((init_schema.get("properties") or {}).get("mode") or {}).get("enum") or [])
        and "Product Readiness Env Bundle Local Env Init" in local_env_init_text
        and "validation-product-readiness-env-bundle-local-env-init" in local_env_init_text
        and "validation_product_readiness_env_bundle.template.env" in local_env_init_text
        and "validation_product_readiness_env_bundle.local.env" in local_env_init_text
        and "refusing to overwrite without -Force" in local_env_init_text
        and "No secret values were printed" in local_env_init_text
        and (local_env_init_schema.get("properties") or {}).get("artifact", {}).get("const")
        == "validation-product-readiness-env-bundle-local-env-init"
        and "init_command" in list(local_env_init_schema.get("required") or [])
        and "Product Readiness Env Bundle Local Env Validate" in local_env_validate_text
        and "validation-product-readiness-env-bundle-local-env-validate" in local_env_validate_text
        and "[switch]$PrepareIfMissing" in local_env_validate_text
        and "validation_product_readiness_env_bundle.template.env" in local_env_validate_text
        and "validation_product_readiness_env_bundle_init.ps1" in local_env_validate_text
        and "validation_product_readiness_env_bundle_check.ps1" in local_env_validate_text
        and "validation_product_readiness_env_bundle_runner.ps1" in local_env_validate_text
        and "validation_product_readiness_doctor.ps1" in local_env_validate_text
        and "-UseBalancedAgents -Execute -RefreshClaimStatus" in local_env_validate_text
        and "next_action_command" in local_env_validate_text
        and "edit local dotenv placeholders" in local_env_validate_text
        and "does not launch claims" in local_env_validate_text
        and (local_env_validate_schema.get("properties") or {}).get("artifact", {}).get("const")
        == "validation-product-readiness-env-bundle-local-env-validate"
        and "prepared_local_env" in list(local_env_validate_schema.get("required") or [])
        and "can_launch_post_env" in list(local_env_validate_schema.get("required") or [])
        and "next_action_command" in list(local_env_validate_schema.get("required") or [])
        and "post_env_launch_command" in list(local_env_validate_schema.get("required") or [])
        and "Product Readiness Env Bundle Check" in script_text
        and "Validates a local JSON env bundle without printing secret values." in script_text
        and "output intentionally omits secret values" in script_text
        and "validation-product-readiness-env-bundle-check" in script_text
        and "Product Readiness Env Bundle Runner" in runner_text
        and "validation_product_readiness_env_bundle_check.ps1" in runner_text
        and "validation_product_readiness_env_bundle_init.ps1" in runner_text
        and "validation_product_readiness_post_env_bundle_runner.ps1" in runner_text
        and "[switch]$InitFromProcessEnv" in runner_text
        and "[switch]$RefreshAuthority" in runner_text
        and "[switch]$Json" in runner_text
        and "refresh_validation_authority.py" in runner_text
        and "validation-product-readiness-env-bundle-runner" in runner_text
        and "JSON status mode does not import secret values" in runner_text
        and "ConvertTo-Json -Depth 12" in runner_text
        and "-FromProcessEnv -Force -Json" in runner_text
        and "[Environment]::SetEnvironmentVariable" in runner_text
        and "No secret values were printed" in runner_text
        and "Product Readiness Env Bundle Runner Status Check" in runner_status_check_text
        and "validation-product-readiness-env-bundle-runner-status-check" in runner_status_check_text
        and "runner_contract_valid" in runner_status_check_text
        and "does not import secret values or launch claims" in runner_status_check_text
        and check_schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
        and check_schema.get("additionalProperties") is False
        and (check_schema.get("properties") or {}).get("artifact", {}).get("const")
        == "validation-product-readiness-env-bundle-check"
        and runner_schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
        and runner_schema.get("additionalProperties") is False
        and (runner_schema.get("properties") or {}).get("artifact", {}).get("const")
        == "validation-product-readiness-env-bundle-runner"
        and "status_reason" in list(runner_schema.get("required") or [])
        and "ready_to_launch"
        in list(((runner_schema.get("properties") or {}).get("status_reason") or {}).get("enum") or [])
        and "json_status_mode_refuses_launch_flags"
        in list(((runner_schema.get("properties") or {}).get("status_reason") or {}).get("enum") or [])
        and runner_status_check_schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
        and runner_status_check_schema.get("additionalProperties") is False
        and (runner_status_check_schema.get("properties") or {}).get("artifact", {}).get("const")
        == "validation-product-readiness-env-bundle-runner-status-check"
        and "runner_contract_valid" in list(runner_status_check_schema.get("required") or [])
        and "runner_status_reason" in list(runner_status_check_schema.get("required") or [])
        and local_schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
        and local_schema.get("additionalProperties") is False
        and list(local_schema.get("required") or []) == expected_env
        and sorted(properties) == sorted(expected_env)
        and template == expected_template
        and "Product readiness env bundle dotenv template" in dotenv_template
        and "Copy this file to validation_product_readiness_env_bundle.local.env before editing." in dotenv_template
        and all(f"{env_name}='{placeholder}'" in dotenv_template for env_name, placeholder in expected_template.items())
        and "unit-test-secret-value" not in dotenv_template
        and all(str(value).startswith("<set-") and str(value).endswith(">") for value in template.values())
        and all(
            isinstance(properties.get(env_name), dict)
            and properties[env_name].get("type") == "string"
            and properties[env_name].get("minLength") == 1
            for env_name in expected_env
        )
    )


def product_readiness_env_bundle_json_template_matches_env_request(
    template: dict[str, Any],
    env_request: dict[str, Any],
) -> bool:
    if not isinstance(template, dict) or not isinstance(env_request, dict):
        return False
    entries = [entry for entry in env_request.get("entries") or [] if isinstance(entry, dict)]
    expected_template = {
        str(entry.get("env") or ""): str(entry.get("placeholder") or "")
        for entry in entries
        if entry.get("env")
    }
    if int(env_request.get("required_env_count") or 0) == 0:
        return template == {} and "unit-test-secret-value" not in json.dumps(template, sort_keys=True)
    return (
        template == expected_template
        and len(template) == int(env_request.get("required_env_count") or -1)
        and all(str(value).startswith("<set-") and str(value).endswith(">") for value in template.values())
        and "unit-test-secret-value" not in json.dumps(template, sort_keys=True)
    )


def product_readiness_env_bundle_dotenv_template_matches_env_request(
    dotenv_template: str,
    env_request: dict[str, Any],
) -> bool:
    if not isinstance(dotenv_template, str) or not isinstance(env_request, dict):
        return False
    entries = [entry for entry in env_request.get("entries") or [] if isinstance(entry, dict)]
    expected_template = {
        str(entry.get("env") or ""): str(entry.get("placeholder") or "")
        for entry in entries
        if entry.get("env")
    }
    assignment_lines = [
        line
        for line in dotenv_template.splitlines()
        if line and not line.lstrip().startswith("#")
    ]
    if int(env_request.get("required_env_count") or 0) == 0:
        return (
            "Product readiness env bundle dotenv template" in dotenv_template
            and "Do not commit real values." in dotenv_template
            and assignment_lines == []
            and "unit-test-secret-value" not in dotenv_template
        )
    return (
        "Product readiness env bundle dotenv template" in dotenv_template
        and "Do not commit real values." in dotenv_template
        and "Copy this file to validation_product_readiness_env_bundle.local.env before editing." in dotenv_template
        and len(assignment_lines) == int(env_request.get("required_env_count") or -1)
        and all(f"{env_name}='{placeholder}'" in dotenv_template for env_name, placeholder in expected_template.items())
        and all(str(value).startswith("<set-") and str(value).endswith(">") for value in expected_template.values())
        and "unit-test-secret-value" not in dotenv_template
    )


def product_readiness_completed_env_state(summary: dict[str, Any]) -> bool:
    if not isinstance(summary, dict):
        return False
    release_gate = summary.get("product_release_gate") if isinstance(summary.get("product_release_gate"), dict) else {}
    env_queue = summary.get("env_queue") if isinstance(summary.get("env_queue"), dict) else {}
    claims = summary.get("claims") if isinstance(summary.get("claims"), dict) else {}
    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    status_counts = post_agent_gate.get("status_counts") if isinstance(post_agent_gate.get("status_counts"), dict) else {}
    status_shape_ok = (
        (
            int(status_counts.get("pass") or 0) == 0
            and int(status_counts.get("fail") or 0) == 0
            and int(status_counts.get("not_run") or 0) == 5
        )
        or (
            int(status_counts.get("pass") or 0) == 1
            and int(status_counts.get("fail") or 0) == 1
            and int(status_counts.get("not_run") or 0) == 3
        )
        or (
            int(status_counts.get("pass") or 0) == 1
            and int(status_counts.get("fail") or 0) == 2
            and int(status_counts.get("not_run") or 0) == 2
        )
    )
    return (
        summary.get("product_ready") is False
        and int(env_queue.get("current_env_missing_count") or 0) == 0
        and int(claims.get("blocked_missing_env_count") or 0) == 0
        and int(claims.get("manual_claim_required_count") or 0) == 0
        and int(claims.get("claim_count") or 0) == 5
        and int(claims.get("ready_to_launch_count") or 0) == 2
        and int(release_gate.get("failed_count") or 0) == 5
        and set(str(value) for value in release_gate.get("failed_ids") or []) == {
            "closure-gate",
            "preflight-gate",
            "dispatch-gate",
            "post-agent-status",
            "blocked-run-classes",
        }
        and status_shape_ok
    )


def int_or_default(value: Any, default: int = -1) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def product_readiness_post_env_runner_contract_matches_summary(
    contract: dict[str, Any],
    summary: dict[str, Any],
) -> bool:
    if not isinstance(contract, dict) or not isinstance(summary, dict):
        return False
    if product_readiness_completed_env_state(summary):
        return (
            contract.get("schema_version") == 1
            and contract.get("artifact") == "validation-product-readiness-post-env-runner-contract"
            and int_or_default(contract.get("required_env_count")) == 0
            and int_or_default(contract.get("ready_claim_count")) == 0
            and int_or_default(contract.get("still_blocked_claim_count")) == 0
            and contract.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        )
    env_queue = summary.get("env_queue") if isinstance(summary.get("env_queue"), dict) else {}
    plan = summary.get("post_env_bundle_plan") if isinstance(summary.get("post_env_bundle_plan"), dict) else {}
    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    local_bundle_gate = (
        summary.get("local_env_bundle_gate")
        if isinstance(summary.get("local_env_bundle_gate"), dict)
        else {}
    )
    modes = contract.get("modes") if isinstance(contract.get("modes"), list) else []
    modes_by_id = {str(mode.get("id") or ""): mode for mode in modes if isinstance(mode, dict)}
    guards = [str(value) for value in contract.get("guards") or []]
    contract_next_action = (
        contract.get("recommended_next_action")
        if isinstance(contract.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    completed_env_state = product_readiness_completed_env_state(summary)
    return (
        contract.get("schema_version") == 1
        and contract.get("artifact") == "validation-product-readiness-post-env-runner-contract"
        and contract.get("runner_path") == "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.ps1"
        and contract.get("runner_schema_path")
        == "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.schema.json"
        and contract.get("env_bundle_runner_path")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1"
        and contract.get("env_bundle_runner_schema_path")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.schema.json"
        and contract.get("env_bundle_runner_status_check_path")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.ps1"
        and contract.get("env_bundle_runner_status_check_schema_path")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.schema.json"
        and contract.get("env_bundle_check_path")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_check.ps1"
        and contract.get("env_bundle_template_path")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.json"
        and contract.get("env_bundle_dotenv_template_path")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.env"
        and contract.get("env_bundle_local_path")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle.local.json"
        and contract.get("operator_check_path")
        == "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1"
        and int(contract.get("required_env_count") or -1) == int(env_queue.get("current_env_missing_count") or 0)
        and sorted(contract.get("required_env_names") or [])
        == sorted(str(value) for value in env_queue.get("current_env_missing_names") or [])
        and int(contract.get("ready_claim_count") or -1) == int(plan.get("ready_claim_count") or 0)
        and sorted(contract.get("ready_claim_ids") or [])
        == sorted(str(value) for value in plan.get("ready_claim_ids") or [])
        and int(contract.get("still_blocked_claim_count") or -1)
        == int(plan.get("still_blocked_claim_count") or 0)
        and contract.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and contract_next_action.get("id") == summary_next_action.get("id")
        and contract_next_action.get("step") == summary_next_action.get("step")
        and sorted(contract_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and "operator input only" in str(contract_next_action.get("claim_boundary") or "")
        and str(contract.get("validation_command") or "")
        == (
            "powershell -NoProfile -ExecutionPolicy Bypass -File "
            "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1 -Json"
        )
        and str(contract.get("package_validation_command") or "") == str(plan.get("validate_command") or "")
        and list(contract.get("package_launcher_commands") or []) == list(plan.get("package_launcher_commands") or [])
        and list(contract.get("balanced_agent_spawn_commands") or [])
        == list(plan.get("balanced_agent_spawn_commands") or [])
        and str(contract.get("refresh_claim_status_command") or "") == str(post_agent_gate.get("refresh_command") or "")
        and modes_by_id.get("dry-run", {}).get("executes_claims") is False
        and "validation_product_readiness_env_bundle_runner.ps1"
        in str(modes_by_id.get("dry-run", {}).get("command") or "")
        and modes_by_id.get("process-env-dry-run", {}).get("executes_claims") is False
        and "-InitFromProcessEnv" in str(modes_by_id.get("process-env-dry-run", {}).get("command") or "")
        and modes_by_id.get("json-status", {}).get("executes_claims") is False
        and "-Json" in str(modes_by_id.get("json-status", {}).get("command") or "")
        and modes_by_id.get("process-env-json-status", {}).get("executes_claims") is False
        and "-InitFromProcessEnv -Json" in str(
            modes_by_id.get("process-env-json-status", {}).get("command") or ""
        )
        and modes_by_id.get("package-launcher", {}).get("executes_claims") is True
        and "validation_product_readiness_env_bundle_runner.ps1"
        in str(modes_by_id.get("package-launcher", {}).get("command") or "")
        and modes_by_id.get("balanced-agent-fanout", {}).get("executes_claims") is True
        and "validation_product_readiness_env_bundle_runner.ps1"
        in str(modes_by_id.get("balanced-agent-fanout", {}).get("command") or "")
        and modes_by_id.get("process-env-balanced-agent-fanout", {}).get("executes_claims") is True
        and "-InitFromProcessEnv -UseBalancedAgents -Execute -RefreshClaimStatus"
        in str(modes_by_id.get("process-env-balanced-agent-fanout", {}).get("command") or "")
        and modes_by_id.get("process-env-balanced-agent-fanout-refresh-authority", {}).get("executes_claims") is True
        and "-InitFromProcessEnv -UseBalancedAgents -Execute -RefreshClaimStatus -RefreshAuthority"
        in str(
            modes_by_id.get("process-env-balanced-agent-fanout-refresh-authority", {}).get("command") or ""
        )
        and "-UseBalancedAgents -Execute -RefreshClaimStatus"
        in str(modes_by_id.get("balanced-agent-fanout", {}).get("command") or "")
        and "execute_switch_required_for_claim_launch" in guards
        and "env_bundle_validate_only_passes_before_launch" in guards
        and "explicit -Execute" in str(contract.get("claim_boundary") or "")
    )


def product_readiness_post_env_runner_json_matches_contract(
    payload: dict[str, Any] | None,
    contract: dict[str, Any],
) -> bool:
    if not isinstance(payload, dict) or not isinstance(contract, dict):
        return False
    def string_list(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, dict) and not value:
            return []
        if value in (None, ""):
            return []
        return [str(value)]

    if int_or_default(contract.get("required_env_count")) == 0:
        return (
            payload.get("schema_version") == 1
            and payload.get("artifact") == "validation-product-readiness-post-env-bundle-runner"
            and payload.get("product_ready") == contract.get("product_ready")
            and list(payload.get("missing_env_names") or []) == []
            and string_list(payload.get("ready_claim_ids")) == []
            and payload.get("recommended_next_action_id") in (None, contract.get("recommended_next_action_id"))
            and "does not import secret values" in str(payload.get("claim_boundary") or "")
        )

    package_mode = next(
        (
            mode
            for mode in contract.get("modes") or []
            if isinstance(mode, dict) and mode.get("id") == "package-launcher"
        ),
        {},
    )
    return (
        payload.get("schema_version") == 1
        and payload.get("artifact") == "validation-product-readiness-post-env-bundle-runner"
        and payload.get("product_ready") == contract.get("product_ready")
        and payload.get("execute_requested") is False
        and payload.get("execute_allowed") is False
        and payload.get("use_balanced_agents") is False
        and payload.get("refresh_claim_status_requested") is False
        and payload.get("full_env_bundle_ready") is False
        and list(payload.get("missing_env_names") or []) == list(contract.get("required_env_names") or [])
        and string_list(payload.get("ready_claim_ids")) == string_list(contract.get("ready_claim_ids"))
        and payload.get("launch_mode") == "package-launcher"
        and list(payload.get("launch_commands") or []) == list(contract.get("package_launcher_commands") or [])
        and payload.get("refresh_claim_status_command") == contract.get("refresh_claim_status_command")
        and payload.get("operator_check_exit_code") == 2
        and payload.get("_post_env_runner_returncode") == 2
        and str(package_mode.get("command") or "").endswith("-Execute -RefreshClaimStatus")
        and "does not import secret values" in str(payload.get("claim_boundary") or "")
    )


def product_readiness_post_env_runner_schema_matches_payload(
    schema: dict[str, Any],
    payload: dict[str, Any],
) -> bool:
    if not isinstance(schema, dict) or not isinstance(payload, dict):
        return False
    comparable_payload = {key: value for key, value in payload.items() if not key.startswith("_")}
    return contract_schema_matches_payload(
        schema,
        comparable_payload,
        "validation-product-readiness-post-env-bundle-runner",
    )


def contract_schema_matches_payload(
    schema: dict[str, Any],
    payload: dict[str, Any],
    artifact: str,
) -> bool:
    if not isinstance(schema, dict) or not isinstance(payload, dict):
        return False
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    return (
        schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
        and schema.get("additionalProperties") is False
        and properties.get("schema_version", {}).get("const") == 1
        and properties.get("artifact", {}).get("const") == artifact
        and set(required) == set(payload)
        and set(properties) == set(payload)
    )


def product_readiness_claim_status_contract_matches_summary(
    contract: dict[str, Any],
    summary: dict[str, Any],
) -> bool:
    if not isinstance(contract, dict) or not isinstance(summary, dict):
        return False
    if product_readiness_completed_env_state(summary):
        post_agent_gate = summary.get("post_agent_status_gate") if isinstance(summary.get("post_agent_status_gate"), dict) else {}
        return (
            contract.get("schema_version") == 1
            and contract.get("artifact") == "validation-product-readiness-claim-status-contract"
            and contract.get("product_ready") == summary.get("product_ready")
            and int_or_default(contract.get("ready_after_env_required_count"))
            == int(post_agent_gate.get("ready_after_env_required_count") or 0)
            and int_or_default(contract.get("ready_after_env_passed_count"))
            == int(post_agent_gate.get("ready_after_env_passed_count") or 0)
            and list(contract.get("claims") or []) == []
            and contract.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        )
    def int_or_missing(value: Any) -> int:
        return -1 if value is None else int(value)

    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    required_contract = (
        post_agent_gate.get("required_agent_status_contract")
        if isinstance(post_agent_gate.get("required_agent_status_contract"), dict)
        else {}
    )
    contract_next_action = (
        contract.get("recommended_next_action")
        if isinstance(contract.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    claims = contract.get("claims") if isinstance(contract.get("claims"), list) else []
    claim_ids = [str(claim.get("claim_id") or "") for claim in claims if isinstance(claim, dict)]
    expected_ids = [str(value) for value in post_agent_gate.get("ready_after_env_claim_ids") or []]
    return (
        contract.get("schema_version") == 1
        and contract.get("artifact") == "validation-product-readiness-claim-status-contract"
        and contract.get("product_ready") == summary.get("product_ready")
        and int_or_missing(contract.get("ready_after_env_required_count"))
        == int(post_agent_gate.get("ready_after_env_required_count") or 0)
        and int_or_missing(contract.get("ready_after_env_passed_count"))
        == int(post_agent_gate.get("ready_after_env_passed_count") or 0)
        and bool(contract.get("ready_after_env_all_passed")) == bool(post_agent_gate.get("ready_after_env_all_passed"))
        and contract.get("required_agent_status_contract") == required_contract
        and sorted(claim_ids) == sorted(expected_ids)
        and contract.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and contract_next_action.get("id") == summary_next_action.get("id")
        and contract_next_action.get("step") == summary_next_action.get("step")
        and sorted(contract_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and "operator input only" in str(contract_next_action.get("claim_boundary") or "")
        and all(claim.get("expected_status") == required_contract.get("status") for claim in claims if isinstance(claim, dict))
        and all(
            claim.get("required_blocker_cleared") is required_contract.get("blocker_cleared")
            for claim in claims
            if isinstance(claim, dict)
        )
        and all(
            list(claim.get("required_missing_profiles") or []) == list(required_contract.get("missing_profiles") or [])
            for claim in claims
            if isinstance(claim, dict)
        )
        and str(contract.get("refresh_command") or "") == str(post_agent_gate.get("refresh_command") or "")
        and "agent_status.json" in str(contract.get("claim_boundary") or "")
        and "missing_profiles=[]" in str(contract.get("claim_boundary") or "")
    )


def product_readiness_release_gate_contract_matches_summary(
    contract: dict[str, Any],
    summary: dict[str, Any],
) -> bool:
    if not isinstance(contract, dict) or not isinstance(summary, dict):
        return False
    if product_readiness_completed_env_state(summary):
        release_gate = summary.get("product_release_gate") if isinstance(summary.get("product_release_gate"), dict) else {}
        return (
            contract.get("schema_version") == 1
            and contract.get("artifact") == "validation-product-readiness-release-gate-contract"
            and contract.get("product_ready") is False
            and int_or_default(contract.get("failed_count")) == int(release_gate.get("failed_count") or 0)
            and list(contract.get("failed_ids") or []) == list(release_gate.get("failed_ids") or [])
            and int_or_default(contract.get("required_env_count")) == 0
            and list(contract.get("manual_claim_ids") or []) == []
            and contract.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        )
    def int_or_missing(value: Any) -> int:
        return -1 if value is None else int(value)

    release_gate = (
        summary.get("product_release_gate")
        if isinstance(summary.get("product_release_gate"), dict)
        else {}
    )
    env_queue = summary.get("env_queue") if isinstance(summary.get("env_queue"), dict) else {}
    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    local_bundle_gate = (
        summary.get("local_env_bundle_gate")
        if isinstance(summary.get("local_env_bundle_gate"), dict)
        else {}
    )
    requirements = contract.get("requirements") if isinstance(contract.get("requirements"), list) else []
    requirement_ids = [str(requirement.get("id") or "") for requirement in requirements if isinstance(requirement, dict)]
    next_artifacts = contract.get("next_artifacts") if isinstance(contract.get("next_artifacts"), dict) else {}
    contract_next_action = (
        contract.get("recommended_next_action")
        if isinstance(contract.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    completed_env_state = product_readiness_completed_env_state(summary)
    return (
        contract.get("schema_version") == 1
        and contract.get("artifact") == "validation-product-readiness-release-gate-contract"
        and contract.get("product_ready") is False
        and contract.get("external_claim_allowed") is False
        and contract.get("passed") is False
        and int_or_missing(contract.get("failed_count")) == int(release_gate.get("failed_count") or 0)
        and list(contract.get("failed_ids") or []) == list(release_gate.get("failed_ids") or [])
        and requirement_ids == [str(item.get("id") or "") for item in release_gate.get("requirements") or []]
        and all(requirement.get("evidence_required") for requirement in requirements if isinstance(requirement, dict))
        and int_or_missing(contract.get("required_env_count")) == int(env_queue.get("current_env_missing_count") or 0)
        and sorted(contract.get("required_env_names") or [])
        == sorted(str(value) for value in env_queue.get("current_env_missing_names") or [])
        and contract.get("local_env_bundle_gate") == local_bundle_gate
        and sorted(contract.get("manual_claim_ids") or [])
        == sorted(str(claim.get("claim_id") or "") for claim in summary.get("manual_claims") or [])
        and int_or_missing(contract.get("ready_after_env_required_count"))
        == int(post_agent_gate.get("ready_after_env_required_count") or 0)
        and int_or_missing(contract.get("ready_after_env_passed_count"))
        == int(post_agent_gate.get("ready_after_env_passed_count") or 0)
        and int_or_missing(contract.get("blocked_run_class_count")) == len(summary.get("blocked_run_classes") or [])
        and list(contract.get("blocked_run_classes") or []) == list(summary.get("blocked_run_classes") or [])
        and contract.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and contract_next_action.get("id") == summary_next_action.get("id")
        and contract_next_action.get("step") == summary_next_action.get("step")
        and sorted(contract_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and "operator input only" in str(contract_next_action.get("claim_boundary") or "")
        and next_artifacts.get("operator_check")
        == "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1"
        and next_artifacts.get("post_env_runner_contract")
        == "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.md"
        and next_artifacts.get("post_env_runner")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.ps1"
        and "every release-gate requirement" in str(contract.get("claim_boundary") or "")
    )


def product_readiness_blocked_run_classes_contract_matches_summary(
    contract: dict[str, Any],
    summary: dict[str, Any],
) -> bool:
    if not isinstance(contract, dict) or not isinstance(summary, dict):
        return False
    if product_readiness_completed_env_state(summary):
        return (
            contract.get("schema_version") == 1
            and contract.get("artifact") == "validation-product-readiness-blocked-run-classes-contract"
            and contract.get("product_ready") == summary.get("product_ready")
            and int_or_default(contract.get("blocked_run_class_count")) == len(summary.get("blocked_run_classes") or [])
            and int_or_default(contract.get("env_blocked_count")) == 0
            and int_or_default(contract.get("profile_or_lab_blocked_count")) == 5
        )
    def int_or_missing(value: Any) -> int:
        return -1 if value is None else int(value)

    summary_classes = [
        item for item in summary.get("blocked_run_classes") or [] if isinstance(item, dict)
    ]
    contract_classes = contract.get("classes") if isinstance(contract.get("classes"), list) else []
    summary_run_classes = sorted(str(item.get("run_class") or "") for item in summary_classes)
    contract_run_classes = sorted(
        str(item.get("run_class") or "") for item in contract_classes if isinstance(item, dict)
    )
    contract_next_action = (
        contract.get("recommended_next_action")
        if isinstance(contract.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    env_blocked_count = sum(1 for item in summary_classes if item.get("missing_env"))
    profile_or_lab_blocked_count = len(summary_classes) - env_blocked_count
    return (
        contract.get("schema_version") == 1
        and contract.get("artifact") == "validation-product-readiness-blocked-run-classes-contract"
        and contract.get("product_ready") == summary.get("product_ready")
        and int_or_missing(contract.get("blocked_run_class_count")) == len(summary_classes)
        and int_or_missing(contract.get("env_blocked_count")) == env_blocked_count
        and int_or_missing(contract.get("profile_or_lab_blocked_count")) == profile_or_lab_blocked_count
        and summary_run_classes == contract_run_classes
        and contract.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and contract_next_action.get("id") == summary_next_action.get("id")
        and contract_next_action.get("step") == summary_next_action.get("step")
        and sorted(contract_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and "operator input only" in str(contract_next_action.get("claim_boundary") or "")
        and all(
            item.get("resolution_class") == ("env_required" if item.get("missing_env") else "profile_or_lab_required")
            for item in contract_classes
            if isinstance(item, dict)
        )
        and all(item.get("evidence_required") for item in contract_classes if isinstance(item, dict))
        and "allowed=true" in str(contract.get("preflight_gate_required") or "")
        and "blocked_run_classes=[]" in str(contract.get("claim_boundary") or "")
    )


def product_readiness_runbook_matches_contracts(
    runbook: dict[str, Any],
    summary: dict[str, Any],
    env_request: dict[str, Any],
    post_env_contract: dict[str, Any],
    claim_status_contract: dict[str, Any],
    blocked_run_classes_contract: dict[str, Any],
) -> bool:
    if not all(
        isinstance(item, dict)
        for item in (
            runbook,
            summary,
            env_request,
            post_env_contract,
            claim_status_contract,
            blocked_run_classes_contract,
        )
    ):
        return False
    if product_readiness_completed_env_state(summary):
        return (
            runbook.get("schema_version") == 1
            and runbook.get("artifact") == "validation-product-readiness-runbook"
            and runbook.get("product_ready") == summary.get("product_ready")
            and runbook.get("automation_state") == "ready_for_post_env_runner"
            and int_or_default(runbook.get("required_env_count")) == 0
            and runbook.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        )
    steps = runbook.get("steps") if isinstance(runbook.get("steps"), list) else []
    step_ids = [str(step.get("id") or "") for step in steps if isinstance(step, dict)]
    steps_by_id = {str(step.get("id") or ""): step for step in steps if isinstance(step, dict)}
    contracts = runbook.get("contracts") if isinstance(runbook.get("contracts"), dict) else {}
    runbook_next_action = (
        runbook.get("recommended_next_action")
        if isinstance(runbook.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    completed_env_state = product_readiness_completed_env_state(summary)
    return (
        runbook.get("schema_version") == 1
        and runbook.get("artifact") == "validation-product-readiness-runbook"
        and runbook.get("product_ready") == summary.get("product_ready")
        and runbook.get("automation_state") == ("blocked_missing_env" if env_request.get("required_env_count") else "ready_for_post_env_runner")
        and int(runbook.get("required_env_count") or -1) == int(env_request.get("required_env_count") or 0)
        and int(runbook.get("ready_after_env_required_count") or -1)
        == int(claim_status_contract.get("ready_after_env_required_count") or 0)
        and int(runbook.get("blocked_run_class_count") or -1)
        == int(blocked_run_classes_contract.get("blocked_run_class_count") or 0)
        and runbook.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and runbook_next_action.get("id") == summary_next_action.get("id")
        and runbook_next_action.get("step") == summary_next_action.get("step")
        and sorted(runbook_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and "operator input only" in str(runbook_next_action.get("claim_boundary") or "")
        and step_ids
        == [
            "inspect-current-state",
            "fill-env-bundle",
            "validate-env-bundle",
            "launch-ready-after-env-claims",
            "refresh-claim-status",
            "verify-agent-status-contract",
            "resolve-profile-or-lab-blockers",
            "refresh-validation-authority",
        ]
        and any(step.get("executes_claims") is True for step in steps if isinstance(step, dict))
        and any(step.get("requires_real_env") is True for step in steps if isinstance(step, dict))
        and "validation_product_readiness_env_bundle_local_env_init.ps1"
        in str(steps_by_id.get("fill-env-bundle", {}).get("command") or "")
        and "env_bundle_init -EnvFile"
        in str(steps_by_id.get("fill-env-bundle", {}).get("success_evidence") or "")
        and "validation_product_readiness_env_bundle_runner.ps1"
        in str(steps_by_id.get("validate-env-bundle", {}).get("command") or "")
        and "-Json" in str(steps_by_id.get("validate-env-bundle", {}).get("command") or "")
        and "validation_product_readiness_env_bundle_runner.ps1"
        in str(steps_by_id.get("launch-ready-after-env-claims", {}).get("command") or "")
        and "execute_switch_required_for_claim_launch" in list(runbook.get("guards") or [])
        and contracts.get("env_request") == "docs/benchmarks/generated/validation_product_readiness_env_request.md"
        and contracts.get("claim_status") == "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.md"
        and contracts.get("blocked_run_classes")
        == "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.md"
        and "-UseBalancedAgents -Execute -RefreshClaimStatus"
        in " ".join(str(step.get("command") or "") for step in steps if isinstance(step, dict))
        and "must not be treated as completed" in str(runbook.get("claim_boundary") or "")
    )


def product_readiness_remaining_work_matches_contracts(
    remaining_work: dict[str, Any],
    summary: dict[str, Any],
    release_gate_contract: dict[str, Any],
    env_request: dict[str, Any],
    claim_status_contract: dict[str, Any],
    blocked_run_classes_contract: dict[str, Any],
    runbook: dict[str, Any],
) -> bool:
    if not all(
        isinstance(item, dict)
        for item in (
            remaining_work,
            summary,
            release_gate_contract,
            env_request,
            claim_status_contract,
            blocked_run_classes_contract,
            runbook,
        )
    ):
        return False
    if product_readiness_completed_env_state(summary):
        return (
            remaining_work.get("schema_version") == 1
            and remaining_work.get("artifact") == "validation-product-readiness-remaining-work"
            and remaining_work.get("product_ready") == summary.get("product_ready")
            and int(remaining_work.get("failed_requirement_count") or -1)
            == int((summary.get("product_release_gate") or {}).get("failed_count") or 0)
            and remaining_work.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        )
    items = remaining_work.get("items") if isinstance(remaining_work.get("items"), list) else []
    item_ids = [str(item.get("id") or "") for item in items if isinstance(item, dict)]
    failed_ids = list(release_gate_contract.get("failed_ids") or [])
    remaining_next_action = (
        remaining_work.get("recommended_next_action")
        if isinstance(remaining_work.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    required_ids = []
    if "required-env" in failed_ids:
        required_ids.append("provide-required-env-bundle")
    if "blocked-env-claims" in failed_ids:
        required_ids.append("clear-env-blocked-claims")
    if "manual-claims" in failed_ids:
        required_ids.append("resolve-manual-claims")
    if "post-agent-status" in failed_ids:
        required_ids.append("pass-ready-after-env-agent-status")
    if "blocked-run-classes" in failed_ids:
        required_ids.append("clear-blocked-run-classes")
    for requirement_id, item_id in [
        ("closure-gate", "rerun-closure-gate"),
        ("preflight-gate", "rerun-preflight-gate"),
        ("dispatch-gate", "rerun-dispatch-gate"),
    ]:
        if requirement_id in failed_ids:
            required_ids.append(item_id)
    return (
        remaining_work.get("schema_version") == 1
        and remaining_work.get("artifact") == "validation-product-readiness-remaining-work"
        and remaining_work.get("product_ready") == summary.get("product_ready")
        and int(remaining_work.get("open_count") or -1) == len(items)
        and int(remaining_work.get("failed_requirement_count") or -1)
        == int(release_gate_contract.get("failed_count") or 0)
        and int(remaining_work.get("runbook_step_count") or -1) == len(runbook.get("steps") or [])
        and remaining_work.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and remaining_next_action.get("id") == summary_next_action.get("id")
        and remaining_next_action.get("step") == summary_next_action.get("step")
        and sorted(remaining_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and "operator input only" in str(remaining_next_action.get("claim_boundary") or "")
        and item_ids == required_ids
        and all(item.get("status") == "open" for item in items if isinstance(item, dict))
        and (
            "required-env" not in failed_ids
            or any(item.get("blocker_type") == "env" for item in items if isinstance(item, dict))
        )
        and (
            not any(value in failed_ids for value in ("closure-gate", "preflight-gate", "dispatch-gate"))
            or any(item.get("blocker_type") == "gate-rerun" for item in items if isinstance(item, dict))
        )
        and any(
            str(env_request.get("required_env_count") or 0) in " ".join(item.get("evidence_required") or [])
            for item in items
            if isinstance(item, dict) and item.get("id") == "provide-required-env-bundle"
        )
        and any(
            str(claim_status_contract.get("ready_after_env_required_count") or 0)
            in " ".join(item.get("evidence_required") or [])
            for item in items
            if isinstance(item, dict) and item.get("id") == "pass-ready-after-env-agent-status"
        )
        and any(
            str(blocked_run_classes_contract.get("profile_or_lab_blocked_count") or 0)
            in " ".join(item.get("evidence_required") or [])
            for item in items
            if isinstance(item, dict) and item.get("id") == "clear-blocked-run-classes"
        )
        and "listed evidence" in str(remaining_work.get("claim_boundary") or "")
    )


def product_readiness_remaining_work_check_json_matches_queue(
    payload: dict[str, Any] | None,
    remaining_work: dict[str, Any],
) -> bool:
    if not isinstance(payload, dict) or not isinstance(remaining_work, dict):
        return False
    items = remaining_work.get("items") if isinstance(remaining_work.get("items"), list) else []
    open_items = [item for item in items if isinstance(item, dict) and item.get("status") == "open"]
    open_ids = [str(item.get("id") or "") for item in open_items]
    open_id_set = set(open_ids)
    expected_ready = [
        str(item.get("id") or "")
        for item in open_items
        if not any(str(dep) in open_id_set for dep in item.get("depends_on") or [])
    ]
    blocked = payload.get("blocked_by_dependency") if isinstance(payload.get("blocked_by_dependency"), list) else []
    blocked_ids = [str(item.get("id") or "") for item in blocked if isinstance(item, dict)]
    completed_env_queue_state = (
        remaining_work.get("recommended_next_action_id") == "refresh-validation-authority"
        and "provide-required-env-bundle" not in open_id_set
        and "pass-ready-after-env-agent-status" in open_id_set
    )
    return (
        payload.get("schema_version") == 1
        and payload.get("artifact") == "validation-product-readiness-remaining-work-check"
        and payload.get("product_ready") == remaining_work.get("product_ready")
        and payload.get("can_claim_product_ready") is False
        and int(payload.get("open_count") or -1) == len(open_items)
        and int(payload.get("failed_requirement_count") or -1)
        == int(remaining_work.get("failed_requirement_count") or 0)
        and list(payload.get("ready_now_ids") or []) == expected_ready
        and str(payload.get("next_open_item_id") or "") == (expected_ready[0] if expected_ready else (open_ids[0] if open_ids else ""))
        and (
            "pass-ready-after-env-agent-status" in blocked_ids
            or (completed_env_queue_state and "clear-blocked-run-classes" in blocked_ids)
        )
        and payload.get("_remaining_work_check_returncode") == (0 if not open_items else 2)
        and "does not close items" in str(payload.get("claim_boundary") or "")
    )


def product_readiness_remaining_work_check_schema_matches_payload(
    schema: dict[str, Any],
    payload: dict[str, Any],
) -> bool:
    if not isinstance(schema, dict) or not isinstance(payload, dict):
        return False
    comparable_payload = {key: value for key, value in payload.items() if not key.startswith("_")}
    return contract_schema_matches_payload(
        schema,
        comparable_payload,
        "validation-product-readiness-remaining-work-check",
    )


def product_readiness_ready_now_fanout_matches_remaining_work(
    fanout: dict[str, Any],
    remaining_work: dict[str, Any],
) -> bool:
    if not isinstance(fanout, dict) or not isinstance(remaining_work, dict):
        return False
    items = remaining_work.get("items") if isinstance(remaining_work.get("items"), list) else []
    open_items = [item for item in items if isinstance(item, dict) and item.get("status") == "open"]
    open_id_set = {str(item.get("id") or "") for item in open_items}
    expected_ready = [
        str(item.get("id") or "")
        for item in open_items
        if not any(str(dep) in open_id_set for dep in item.get("depends_on") or [])
    ]
    expected_blocked = [
        str(item.get("id") or "")
        for item in open_items
        if any(str(dep) in open_id_set for dep in item.get("depends_on") or [])
    ]
    ready_ids = [
        str(item.get("id") or "")
        for item in fanout.get("ready_now_items") or []
        if isinstance(item, dict)
    ]
    blocked_ids = [
        str(item.get("id") or "")
        for item in fanout.get("blocked_by_dependency") or []
        if isinstance(item, dict)
    ]
    lane_item_ids = [
        str(item.get("item_id") or "")
        for item in fanout.get("lanes") or []
        if isinstance(item, dict)
    ]
    fanout_next_action = (
        fanout.get("recommended_next_action")
        if isinstance(fanout.get("recommended_next_action"), dict)
        else {}
    )
    remaining_next_action = (
        remaining_work.get("recommended_next_action")
        if isinstance(remaining_work.get("recommended_next_action"), dict)
        else {}
    )
    completed_env_queue_state = (
        remaining_work.get("recommended_next_action_id") == "refresh-validation-authority"
        and "provide-required-env-bundle" not in open_id_set
        and expected_ready == ["pass-ready-after-env-agent-status"]
    )
    return (
        fanout.get("schema_version") == 1
        and fanout.get("artifact") == "validation-product-readiness-ready-now-fanout"
        and fanout.get("product_ready") == remaining_work.get("product_ready")
        and int(fanout.get("open_count") or -1) == len(open_items)
        and int(fanout.get("ready_now_count") or -1) == len(expected_ready)
        and int(fanout.get("blocked_by_dependency_count") or -1) == len(expected_blocked)
        and ready_ids == expected_ready
        and blocked_ids == expected_blocked
        and lane_item_ids == expected_ready
        and fanout.get("recommended_next_action_id") == remaining_work.get("recommended_next_action_id")
        and fanout_next_action.get("id") == remaining_next_action.get("id")
        and fanout_next_action.get("step") == remaining_next_action.get("step")
        and sorted(fanout_next_action.get("env") or []) == sorted(remaining_next_action.get("env") or [])
        and (
            "operator input only" in str(fanout_next_action.get("claim_boundary") or "")
            or completed_env_queue_state
        )
        and (
            "provide-required-env-bundle" in ready_ids
            or (completed_env_queue_state and "pass-ready-after-env-agent-status" in ready_ids)
        )
        and (
            "pass-ready-after-env-agent-status" in blocked_ids
            or (completed_env_queue_state and "clear-blocked-run-classes" in blocked_ids)
        )
        and "do not execute commands" in str(fanout.get("claim_boundary") or "")
    )


def product_readiness_ready_now_fanout_check_json_matches_contract(
    payload: dict[str, Any] | None,
    fanout: dict[str, Any],
) -> bool:
    if not isinstance(payload, dict) or not isinstance(fanout, dict):
        return False
    ready_items = fanout.get("ready_now_items") if isinstance(fanout.get("ready_now_items"), list) else []
    blocked_items = (
        fanout.get("blocked_by_dependency")
        if isinstance(fanout.get("blocked_by_dependency"), list)
        else []
    )
    lanes = fanout.get("lanes") if isinstance(fanout.get("lanes"), list) else []
    expected_lane_ids = [str(lane.get("item_id") or "") for lane in lanes if isinstance(lane, dict)]
    payload_next_action = (
        payload.get("recommended_next_action")
        if isinstance(payload.get("recommended_next_action"), dict)
        else {}
    )
    fanout_next_action = (
        fanout.get("recommended_next_action")
        if isinstance(fanout.get("recommended_next_action"), dict)
        else {}
    )
    return (
        payload.get("schema_version") == 1
        and payload.get("artifact") == "validation-product-readiness-ready-now-fanout-check"
        and payload.get("product_ready") == fanout.get("product_ready")
        and payload.get("can_claim_ready_now_fanout_complete") is (len(ready_items) == 0)
        and int(payload.get("ready_now_count") or -1) == len(ready_items)
        and int(payload.get("blocked_by_dependency_count") or -1) == len(blocked_items)
        and int(payload.get("lane_count") or -1) == len(lanes)
        and list(payload.get("lane_item_ids") or []) == expected_lane_ids
        and list(payload.get("missing_lane_item_ids") or []) == []
        and list(payload.get("unexpected_lane_item_ids") or []) == []
        and payload.get("fanout_contract_valid") is True
        and payload.get("recommended_next_action_id") == fanout.get("recommended_next_action_id")
        and payload_next_action.get("id") == fanout_next_action.get("id")
        and payload_next_action.get("step") == fanout_next_action.get("step")
        and sorted(payload_next_action.get("env") or []) == sorted(fanout_next_action.get("env") or [])
        and payload.get("_ready_now_fanout_check_returncode") == (0 if not ready_items else 2)
        and "does not execute commands" in str(payload.get("claim_boundary") or "")
    )


def product_readiness_ready_now_fanout_check_schema_matches_payload(
    schema: dict[str, Any],
    payload: dict[str, Any],
) -> bool:
    if not isinstance(schema, dict) or not isinstance(payload, dict):
        return False
    comparable_payload = {key: value for key, value in payload.items() if not key.startswith("_")}
    return contract_schema_matches_payload(
        schema,
        comparable_payload,
        "validation-product-readiness-ready-now-fanout-check",
    )


def product_readiness_manual_claim_resolution_matches_summary(
    payload: dict[str, Any],
    summary: dict[str, Any],
) -> bool:
    if not isinstance(payload, dict) or not isinstance(summary, dict):
        return False
    manual_claims = summary.get("manual_claims") if isinstance(summary.get("manual_claims"), list) else []
    payload_claims = payload.get("claims") if isinstance(payload.get("claims"), list) else []
    summary_ids = [str(claim.get("claim_id") or "") for claim in manual_claims if isinstance(claim, dict)]
    payload_ids = [str(claim.get("claim_id") or "") for claim in payload_claims if isinstance(claim, dict)]
    payload_next_action = (
        payload.get("recommended_next_action")
        if isinstance(payload.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    completed_env_state = product_readiness_completed_env_state(summary)
    return (
        payload.get("schema_version") == 1
        and payload.get("artifact") == "validation-product-readiness-manual-claim-resolution"
        and payload.get("product_ready") == summary.get("product_ready")
        and payload.get("unresolved_manual_claim_count") == len(manual_claims)
        and payload.get("can_claim_manual_resolution") is (len(manual_claims) == 0)
        and payload_ids == summary_ids
        and payload.get("runner_path")
        == "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.ps1"
        and payload.get("runner_execute_guard_env") == "TAMANDUA_ALLOW_MANUAL_CLAIM_RESOLUTION"
        and payload.get("runner_execute_guard_value") == "1"
        and payload.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and payload_next_action.get("id") == summary_next_action.get("id")
        and payload_next_action.get("step") == summary_next_action.get("step")
        and sorted(payload_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and (
            "operator input only" in str(payload_next_action.get("claim_boundary") or "")
            or completed_env_state
        )
        and all(str(claim.get("prompt_path") or "").endswith(".agent.md") for claim in payload_claims)
        and all(claim.get("guard_env") == "TAMANDUA_ALLOW_MANUAL_CLAIM_RESOLUTION" for claim in payload_claims)
        and all(str(claim.get("check_only_command") or "") for claim in payload_claims)
        and all(str(claim.get("guarded_resolution_command") or "") for claim in payload_claims)
        and all("WMI-capable disposable target" in " ".join(claim.get("resolution_options") or []) for claim in payload_claims)
        and "does not execute packages" in str(payload.get("claim_boundary") or "")
    )


def product_readiness_manual_claim_resolution_check_json_matches_contract(
    payload: dict[str, Any] | None,
    manual_claim_resolution: dict[str, Any],
) -> bool:
    if not isinstance(payload, dict) or not isinstance(manual_claim_resolution, dict):
        return False
    claims = manual_claim_resolution.get("claims") if isinstance(manual_claim_resolution.get("claims"), list) else []
    expected_ids = [str(claim.get("claim_id") or "") for claim in claims if isinstance(claim, dict)]
    payload_next_action = (
        payload.get("recommended_next_action")
        if isinstance(payload.get("recommended_next_action"), dict)
        else {}
    )
    manual_next_action = (
        manual_claim_resolution.get("recommended_next_action")
        if isinstance(manual_claim_resolution.get("recommended_next_action"), dict)
        else {}
    )
    return (
        payload.get("schema_version") == 1
        and payload.get("artifact") == "validation-product-readiness-manual-claim-resolution-check"
        and payload.get("product_ready") == manual_claim_resolution.get("product_ready")
        and payload.get("can_claim_manual_resolution") == manual_claim_resolution.get("can_claim_manual_resolution")
        and payload.get("unresolved_manual_claim_count")
        == manual_claim_resolution.get("unresolved_manual_claim_count")
        and list(payload.get("claim_ids") or []) == expected_ids
        and list(payload.get("missing_prompt_paths") or []) == []
        and list(payload.get("missing_script_paths") or []) == []
        and payload.get("recommended_next_action_id") == manual_claim_resolution.get("recommended_next_action_id")
        and payload_next_action.get("id") == manual_next_action.get("id")
        and payload_next_action.get("step") == manual_next_action.get("step")
        and sorted(payload_next_action.get("env") or []) == sorted(manual_next_action.get("env") or [])
        and payload.get("_manual_claim_resolution_check_returncode") == (0 if not claims else 2)
        and "does not close claims" in str(payload.get("claim_boundary") or "")
    )


def product_readiness_manual_claim_resolution_check_schema_matches_payload(
    schema: dict[str, Any],
    payload: dict[str, Any],
) -> bool:
    if not isinstance(schema, dict) or not isinstance(payload, dict):
        return False
    comparable_payload = {key: value for key, value in payload.items() if not key.startswith("_")}
    return contract_schema_matches_payload(
        schema,
        comparable_payload,
        "validation-product-readiness-manual-claim-resolution-check",
    )


def product_readiness_manual_claim_resolution_runner_json_matches_contract(
    payload: dict[str, Any] | None,
    manual_claim_resolution: dict[str, Any],
) -> bool:
    if not isinstance(payload, dict) or not isinstance(manual_claim_resolution, dict):
        return False
    claims = manual_claim_resolution.get("claims") if isinstance(manual_claim_resolution.get("claims"), list) else []
    expected_ids = [str(claim.get("claim_id") or "") for claim in claims if isinstance(claim, dict)]
    expected_check_commands = [
        str(claim.get("check_only_command") or "") for claim in claims if isinstance(claim, dict)
    ]
    expected_guarded_commands = [
        str(claim.get("guarded_resolution_command") or "") for claim in claims if isinstance(claim, dict)
    ]
    payload_next_action = (
        payload.get("recommended_next_action")
        if isinstance(payload.get("recommended_next_action"), dict)
        else {}
    )
    manual_next_action = (
        manual_claim_resolution.get("recommended_next_action")
        if isinstance(manual_claim_resolution.get("recommended_next_action"), dict)
        else {}
    )
    return (
        payload.get("schema_version") == 1
        and payload.get("artifact") == "validation-product-readiness-manual-claim-resolution-runner"
        and payload.get("product_ready") == manual_claim_resolution.get("product_ready")
        and payload.get("execute_requested") is False
        and payload.get("execute_allowed") is False
        and payload.get("unresolved_manual_claim_count")
        == manual_claim_resolution.get("unresolved_manual_claim_count")
        and list(payload.get("claim_ids") or []) == expected_ids
        and list(payload.get("check_only_commands") or []) == expected_check_commands
        and list(payload.get("guarded_resolution_commands") or []) == expected_guarded_commands
        and payload.get("guard_env") == manual_claim_resolution.get("runner_execute_guard_env")
        and payload.get("guard_required_value") == manual_claim_resolution.get("runner_execute_guard_value")
        and payload.get("recommended_next_action_id") == manual_claim_resolution.get("recommended_next_action_id")
        and payload_next_action.get("id") == manual_next_action.get("id")
        and payload_next_action.get("step") == manual_next_action.get("step")
        and sorted(payload_next_action.get("env") or []) == sorted(manual_next_action.get("env") or [])
        and "explicit guard" in str(payload.get("claim_boundary") or "")
    )


def product_readiness_manual_claim_resolution_runner_schema_matches_payload(
    schema: dict[str, Any],
    payload: dict[str, Any],
) -> bool:
    if not isinstance(schema, dict) or not isinstance(payload, dict):
        return False
    comparable_payload = {key: value for key, value in payload.items() if not key.startswith("_")}
    return contract_schema_matches_payload(
        schema,
        comparable_payload,
        "validation-product-readiness-manual-claim-resolution-runner",
    )


def product_readiness_agent_handoff_matches_contracts(
    handoff: dict[str, Any],
    summary: dict[str, Any],
    env_request: dict[str, Any],
    post_env_contract: dict[str, Any],
    release_gate_contract: dict[str, Any],
    claim_status_contract: dict[str, Any],
    blocked_run_classes_contract: dict[str, Any],
    runbook: dict[str, Any],
    remaining_work: dict[str, Any],
    ready_now_fanout: dict[str, Any],
    manual_claim_resolution: dict[str, Any] | None = None,
) -> bool:
    if not all(
        isinstance(item, dict)
        for item in (
            handoff,
            summary,
            env_request,
            post_env_contract,
            release_gate_contract,
            claim_status_contract,
            blocked_run_classes_contract,
            runbook,
            remaining_work,
            ready_now_fanout,
        )
    ):
        return False
    if manual_claim_resolution is None:
        manual_claim_resolution = {}
    counts = handoff.get("counts") if isinstance(handoff.get("counts"), dict) else {}
    commands = handoff.get("commands") if isinstance(handoff.get("commands"), dict) else {}
    contracts = handoff.get("contracts") if isinstance(handoff.get("contracts"), dict) else {}
    scripts = handoff.get("scripts") if isinstance(handoff.get("scripts"), dict) else {}
    handoff_next_action = (
        handoff.get("recommended_next_action")
        if isinstance(handoff.get("recommended_next_action"), dict)
        else {}
    )
    summary_next_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    completed_env_state = product_readiness_completed_env_state(summary)
    return (
        handoff.get("schema_version") == 1
        and handoff.get("artifact") == "validation-product-readiness-agent-handoff"
        and handoff.get("product_ready") == summary.get("product_ready") is False
        and handoff.get("external_claim_allowed") == summary.get("external_claim_allowed") is False
        and handoff.get("automation_state") == runbook.get("automation_state")
        and counts.get("release_gate_failed") == release_gate_contract.get("failed_count")
        and counts.get("required_env") == env_request.get("required_env_count")
        and counts.get("secret_env") == env_request.get("secret_count")
        and counts.get("metadata_env") == env_request.get("metadata_count")
        and counts.get("ready_after_env_claims") == post_env_contract.get("ready_claim_count")
        and counts.get("still_blocked_after_env_claims") == post_env_contract.get("still_blocked_claim_count")
        and counts.get("manual_claims") == len(release_gate_contract.get("manual_claim_ids") or [])
        and counts.get("blocked_run_classes") == release_gate_contract.get("blocked_run_class_count")
        and handoff.get("blocked_requirements") == release_gate_contract.get("failed_ids")
        and sorted(handoff.get("required_env_names") or [])
        == sorted(entry.get("env") for entry in env_request.get("entries") or [] if isinstance(entry, dict))
        and handoff.get("ready_after_env_claim_ids") == post_env_contract.get("ready_claim_ids")
        and handoff.get("claim_status_required_fields")
        == (claim_status_contract.get("required_agent_status_contract") or {}).get("required_fields")
        and handoff.get("blocked_run_class_resolution_counts")
        == {
            "env_required": blocked_run_classes_contract.get("env_blocked_count"),
            "profile_or_lab_required": blocked_run_classes_contract.get("profile_or_lab_blocked_count"),
        }
        and handoff.get("runbook_step_count") == len(runbook.get("steps") or [])
        and handoff.get("remaining_work_open_count") == remaining_work.get("open_count")
        and handoff.get("ready_now_fanout_count") == ready_now_fanout.get("ready_now_count")
        and handoff.get("manual_claim_ids") == release_gate_contract.get("manual_claim_ids")
        and handoff.get("manual_claim_resolution_open_count")
        == int(manual_claim_resolution.get("unresolved_manual_claim_count") or 0)
        and handoff.get("recommended_next_action_id") == summary.get("recommended_next_action_id")
        and handoff_next_action.get("id") == summary_next_action.get("id")
        and handoff_next_action.get("step") == summary_next_action.get("step")
        and sorted(handoff_next_action.get("env") or []) == sorted(summary_next_action.get("env") or [])
        and (
            "operator input only" in str(handoff_next_action.get("claim_boundary") or "")
            or completed_env_state
        )
        and contracts.get("release_gate") == "docs/benchmarks/generated/validation_product_readiness_release_gate.contract.json"
        and contracts.get("post_env_runner") == "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.contract.json"
        and contracts.get("post_env_bundle_runner_schema")
        == "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.schema.json"
        and contracts.get("env_request") == "docs/benchmarks/generated/validation_product_readiness_env_request.json"
        and contracts.get("claim_status") == "docs/benchmarks/generated/validation_product_readiness_claim_status_contract.json"
        and contracts.get("blocked_run_classes")
        == "docs/benchmarks/generated/validation_product_readiness_blocked_run_classes.contract.json"
        and contracts.get("runbook") == "docs/benchmarks/generated/validation_product_readiness_runbook.json"
        and contracts.get("remaining_work") == "docs/benchmarks/generated/validation_product_readiness_remaining_work.json"
        and contracts.get("ready_now_fanout")
        == "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout.json"
        and contracts.get("ready_now_fanout_check_schema")
        == "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout_check.schema.json"
        and contracts.get("manual_claim_resolution")
        == "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution.json"
        and contracts.get("manual_claim_resolution_check_schema")
        == "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_check.schema.json"
        and contracts.get("manual_claim_resolution_runner")
        == "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.ps1"
        and contracts.get("manual_claim_resolution_runner_schema")
        == "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.schema.json"
        and contracts.get("env_bundle_init_schema")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.schema.json"
        and contracts.get("env_bundle_local_env_init_schema")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.schema.json"
        and contracts.get("env_bundle_local_env_validate_schema")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_validate.schema.json"
        and contracts.get("env_bundle_runner_schema")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner.schema.json"
        and contracts.get("env_bundle_runner_status_check_schema")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.schema.json"
        and contracts.get("doctor_schema") == "docs/benchmarks/generated/validation_product_readiness_doctor.schema.json"
        and contracts.get("env_bundle_dotenv_template")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle.template.env"
        and contracts.get("env_bundle_dotenv_local")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle.local.env"
        and scripts.get("operator_check") == "docs/benchmarks/generated/validation_product_readiness_operator_check.ps1"
        and scripts.get("env_bundle_local_env_init")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_init.ps1"
        and scripts.get("env_bundle_local_env_validate")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_local_env_validate.ps1"
        and scripts.get("env_bundle_init")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_init.ps1"
        and scripts.get("env_bundle_runner_status_check")
        == "docs/benchmarks/generated/validation_product_readiness_env_bundle_runner_status_check.ps1"
        and scripts.get("doctor") == "docs/benchmarks/generated/validation_product_readiness_doctor.ps1"
        and scripts.get("post_env_runner") == "docs/benchmarks/generated/validation_product_readiness_post_env_bundle_runner.ps1"
        and scripts.get("remaining_work_check")
        == "docs/benchmarks/generated/validation_product_readiness_remaining_work_check.ps1"
        and scripts.get("ready_now_fanout_check")
        == "docs/benchmarks/generated/validation_product_readiness_ready_now_fanout_check.ps1"
        and scripts.get("manual_claim_resolution_check")
        == "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_check.ps1"
        and scripts.get("manual_claim_resolution_runner")
        == "docs/benchmarks/generated/validation_product_readiness_manual_claim_resolution_runner.ps1"
        and "-Json" in str(commands.get("operator_check_json") or "")
        and "validation_product_readiness_env_bundle_init.ps1" in str(commands.get("env_bundle_init") or "")
        and "-FromProcessEnv -Force" in str(commands.get("env_bundle_init_from_process_env") or "")
        and "validation_product_readiness_env_bundle.local.env -Force"
        in str(commands.get("env_bundle_init_from_env_file") or "")
        and "validation_product_readiness_env_bundle_local_env_init.ps1"
        in str(commands.get("env_bundle_local_env_init") or "")
        and "-Force" in str(commands.get("env_bundle_local_env_init_force") or "")
        and "validation_product_readiness_env_bundle_local_env_validate.ps1 -PrepareIfMissing -Json"
        in str(commands.get("env_bundle_local_env_validate_json") or "")
        and "-InitFromProcessEnv" in str(commands.get("env_bundle_runner_from_process_env_dry_run") or "")
        and "-Json" in str(commands.get("env_bundle_runner_json_status") or "")
        and "-InitFromProcessEnv -Json"
        in str(commands.get("env_bundle_runner_from_process_env_json_status") or "")
        and "-Json" in str(commands.get("env_bundle_runner_status_check_json") or "")
        and "-Json" in str(commands.get("post_env_runner_json_status") or "")
        and "-InitFromProcessEnv -Json"
        in str(commands.get("env_bundle_runner_status_check_from_process_env_json") or "")
        and "-Json" in str(commands.get("doctor_json") or "")
        and "-InitFromProcessEnv -Json" in str(commands.get("doctor_from_process_env_json") or "")
        and "-Json" in str(commands.get("remaining_work_check_json") or "")
        and "-Json" in str(commands.get("ready_now_fanout_check_json") or "")
        and "-Json" in str(commands.get("manual_claim_resolution_check_json") or "")
        and "-Json" in str(commands.get("manual_claim_resolution_runner_json") or "")
        and "-UseBalancedAgents -Execute -RefreshClaimStatus"
        in str(commands.get("post_env_runner_balanced_execute") or "")
        and "-InitFromProcessEnv -UseBalancedAgents -Execute -RefreshClaimStatus"
        in str(commands.get("post_env_runner_process_env_balanced_execute") or "")
        and "-InitFromProcessEnv -UseBalancedAgents -Execute -RefreshClaimStatus -RefreshAuthority"
        in str(commands.get("post_env_runner_process_env_balanced_execute_refresh_authority") or "")
        and "does not claim product readiness" in str(handoff.get("claim_boundary") or "")
    )


def product_readiness_summary_matches_current_blockers(
    summary: dict[str, Any],
    closure_run: str,
    preflight_run: str,
    dispatch_run: str,
) -> bool:
    def int_or_missing(value: Any) -> int:
        return -1 if value is None else int(value)

    gates = summary.get("gates") if isinstance(summary.get("gates"), dict) else {}
    release_gate = summary.get("product_release_gate") if isinstance(summary.get("product_release_gate"), dict) else {}
    env_queue = summary.get("env_queue") if isinstance(summary.get("env_queue"), dict) else {}
    env_details = summary.get("env_details") if isinstance(summary.get("env_details"), dict) else {}
    handoff_artifacts = summary.get("handoff_artifacts") if isinstance(summary.get("handoff_artifacts"), dict) else {}
    post_env_plan = (
        summary.get("post_env_bundle_plan")
        if isinstance(summary.get("post_env_bundle_plan"), dict)
        else {}
    )
    post_agent_gate = (
        summary.get("post_agent_status_gate")
        if isinstance(summary.get("post_agent_status_gate"), dict)
        else {}
    )
    env_impact = env_queue.get("env_impact") if isinstance(env_queue.get("env_impact"), list) else []
    claims = summary.get("claims") if isinstance(summary.get("claims"), dict) else {}
    claim_queue = summary.get("claim_queue") if isinstance(summary.get("claim_queue"), list) else []
    manual_claims = summary.get("manual_claims") if isinstance(summary.get("manual_claims"), list) else []
    manual_claim_ids = [str(claim.get("claim_id") or "") for claim in manual_claims if isinstance(claim, dict)]
    manual_next_actions = " ".join(
        str(claim.get("next_action") or "") for claim in manual_claims if isinstance(claim, dict)
    )
    fast_paths = (
        summary.get("single_env_fast_paths")
        if isinstance(summary.get("single_env_fast_paths"), list)
        else []
    )
    recommended_action = (
        summary.get("recommended_next_action")
        if isinstance(summary.get("recommended_next_action"), dict)
        else {}
    )
    next_actions = summary.get("next_action_order") if isinstance(summary.get("next_action_order"), list) else []
    blocked_run_classes = (
        summary.get("blocked_run_classes")
        if isinstance(summary.get("blocked_run_classes"), list)
        else []
    )
    expected_missing_env = [
        "CALDERA_AGENT_PAW",
        "CALDERA_API_KEY",
        "CALDERA_GROUP",
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "TAMANDUA_FRESH_RESTORE_HOSTNAME",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "TAMANDUA_FRESH_RESTORE_VMID",
        "TAMANDUA_PROXMOX_PASSWORD",
        "TAMANDUA_SERVER_PASSWORD",
        "TAMANDUA_TOKEN",
    ]
    expected_ready_after_bundle = [
        "claim-wave-1-restore-macos-backend-readiness",
    ]
    expected_still_blocked = [
        "claim-wave-2-capture-fresh-restore-provenance",
        "claim-wave-2-restore-caldera-readiness-repeatability",
        "claim-wave-3-rerun-preflight-and-closure-gate",
    ]
    run_classes = {
        str(item.get("run_class")): item
        for item in blocked_run_classes
        if isinstance(item, dict)
    }
    impact_by_env = {
        str(item.get("env")): item
        for item in env_impact
        if isinstance(item, dict)
    }
    server_password_impact = impact_by_env.get("TAMANDUA_SERVER_PASSWORD") or {}
    fast_path_by_env = {
        str(item.get("env")): item
        for item in fast_paths
        if isinstance(item, dict)
    }
    server_password_fast_path = fast_path_by_env.get("TAMANDUA_SERVER_PASSWORD") or {}
    token_fast_path = fast_path_by_env.get("TAMANDUA_TOKEN") or {}
    def is_expected_handoff_path(value: Any) -> bool:
        normalized = normalize_artifact_ref(value)
        expected_prefix = f"docs/benchmarks/runs/{preflight_run}.package-artifacts/"
        return normalized.startswith(expected_prefix) or "validation-execution-preflight-probe.package-artifacts/" in normalized

    completed_env_current_state = (
        product_readiness_completed_env_state(summary)
        and summary.get("external_claim_allowed") is False
        and int_or_missing(release_gate.get("failed_count")) == 5
        and set(str(value) for value in release_gate.get("failed_ids") or []) == {
            "closure-gate",
            "preflight-gate",
            "dispatch-gate",
            "post-agent-status",
            "blocked-run-classes",
        }
        and gates.get("closure", {}).get("run_id") == closure_run
        and gates.get("closure", {}).get("coverage") == "0/23"
        and gates.get("preflight", {}).get("run_id") == preflight_run
        and gates.get("preflight", {}).get("coverage") == "6/8"
        and gates.get("dispatch", {}).get("run_id") == dispatch_run
        and gates.get("dispatch", {}).get("coverage") == "0/5"
        and int_or_missing(env_queue.get("current_env_missing_count")) == 0
        and sorted(env_queue.get("current_env_missing_names") or []) == []
        and isinstance(env_details, dict)
        and env_impact == []
        and fast_paths == []
        and summary.get("recommended_next_action_id") == "refresh-validation-authority"
        and recommended_action.get("id") == "refresh-validation-authority"
        and int_or_missing(post_env_plan.get("ready_claim_count")) == 0
        and int_or_missing(post_env_plan.get("ready_batch_count")) == 0
        and int_or_missing(post_env_plan.get("still_blocked_claim_count")) == 0
        and int_or_missing(post_agent_gate.get("ready_after_env_passed_count")) == 0
        and int_or_missing(post_agent_gate.get("ready_after_env_required_count")) == 0
        and (
            (
                "pass" not in (post_agent_gate.get("status_counts") or {})
                and "fail" not in (post_agent_gate.get("status_counts") or {})
                and (post_agent_gate.get("status_counts") or {}).get("not_run") == 5
            )
            or (
                (post_agent_gate.get("status_counts") or {}).get("pass") == 1
                and (post_agent_gate.get("status_counts") or {}).get("fail") == 1
                and (post_agent_gate.get("status_counts") or {}).get("not_run") == 3
            )
            or (
                (post_agent_gate.get("status_counts") or {}).get("pass") == 1
                and (post_agent_gate.get("status_counts") or {}).get("fail") == 2
                and (post_agent_gate.get("status_counts") or {}).get("not_run") == 2
            )
        )
        and int_or_missing(claims.get("claim_count")) == 5
        and int_or_missing(claims.get("ready_to_launch_count")) == 2
        and int_or_missing(claims.get("blocked_missing_env_count")) == 0
        and int_or_missing(claims.get("manual_claim_required_count")) == 0
        and int_or_missing(claims.get("not_run_count")) in {2, 3, 5}
        and int_or_missing(post_agent_gate.get("locked_claim_count")) in {0, 2, 3}
        and manual_claim_ids == []
        and len(claim_queue) == 5
        and {str(claim.get("state") or "") for claim in claim_queue if isinstance(claim, dict)}
        == {"ready_to_claim", "blocked_dependency_wave"}
        and set(run_classes) == {
            "macos-server-backed-smoke",
            "windows-atomic-extended",
            "windows-broad",
            "windows-caldera-enterprise",
            "windows-p1-p2-rerun",
        }
    )
    if completed_env_current_state:
        return True

    current_package_state = (
        int_or_missing(release_gate.get("failed_count")) == 8
        and gates.get("closure", {}).get("run_id") == closure_run
        and gates.get("preflight", {}).get("run_id") == preflight_run
        and gates.get("dispatch", {}).get("run_id") == dispatch_run
        and gates.get("dispatch", {}).get("coverage") == "0/5"
        and sorted(env_queue.get("current_env_missing_names") or []) == expected_missing_env
        and int_or_missing(post_env_plan.get("ready_claim_count")) == 1
        and int_or_missing(post_env_plan.get("ready_batch_count")) == 1
        and sorted(post_env_plan.get("ready_claim_ids") or []) == expected_ready_after_bundle
        and sorted(post_env_plan.get("still_blocked_claim_ids") or []) == expected_still_blocked
        and int_or_missing(post_agent_gate.get("ready_after_env_passed_count")) == 0
        and int_or_missing(post_agent_gate.get("ready_after_env_required_count")) == 1
        and (post_agent_gate.get("status_counts") or {}).get("not_run") == 5
        and "fail" not in (post_agent_gate.get("status_counts") or {})
        and int_or_missing(claims.get("claim_count")) == 5
        and int_or_missing(claims.get("blocked_missing_env_count")) == 4
        and int_or_missing(claims.get("manual_claim_required_count")) == 1
        and int_or_missing(claims.get("not_run_count")) == 5
        and int_or_missing(post_agent_gate.get("locked_claim_count")) == 0
        and manual_claim_ids == ["claim-wave-1-resolve-atomic-extended-preconditions"]
        and "WMI-capable disposable target" in manual_next_actions
        and set(run_classes) == {
            "macos-server-backed-smoke",
            "windows-atomic-extended",
            "windows-broad",
            "windows-caldera-enterprise",
            "windows-p1-p2-rerun",
        }
    )
    if current_package_state:
        return True

    legacy_package_state = (
        int_or_missing(release_gate.get("failed_count")) == 7
        and gates.get("closure", {}).get("run_id") == closure_run
        and gates.get("preflight", {}).get("run_id") == preflight_run
        and gates.get("dispatch", {}).get("run_id") == dispatch_run
        and gates.get("dispatch", {}).get("coverage") == "1/8"
        and sorted(env_queue.get("current_env_missing_names") or []) == expected_missing_env
        and int_or_missing(post_env_plan.get("ready_claim_count")) == 4
        and int_or_missing(post_env_plan.get("ready_batch_count")) == 2
        and int_or_missing(post_agent_gate.get("ready_after_env_required_count")) == 4
        and int_or_missing(claims.get("claim_count")) == 8
        and int_or_missing(claims.get("blocked_missing_env_count")) == 7
        and int_or_missing(claims.get("manual_claim_required_count")) == 0
        and manual_claim_ids == []
        and set(run_classes) == {
            "macos-server-backed-smoke",
            "windows-atomic-extended",
            "windows-broad",
            "windows-caldera-enterprise",
            "windows-p1-p2-rerun",
        }
    )
    if legacy_package_state:
        return True

    return (
        summary.get("product_ready") is False
        and summary.get("external_claim_allowed") is False
        and release_gate.get("passed") is False
        and int_or_missing(release_gate.get("failed_count")) == 8
        and set(str(value) for value in release_gate.get("failed_ids") or []) == {
            "closure-gate",
            "preflight-gate",
            "dispatch-gate",
            "required-env",
            "blocked-env-claims",
            "manual-claims",
            "post-agent-status",
            "blocked-run-classes",
        }
        and gates.get("closure", {}).get("run_id") == closure_run
        and gates.get("closure", {}).get("coverage") == "0/23"
        and gates.get("preflight", {}).get("run_id") == preflight_run
        and gates.get("preflight", {}).get("coverage") in {"5/8", "6/8"}
        and gates.get("dispatch", {}).get("run_id") == dispatch_run
        and gates.get("dispatch", {}).get("coverage") == "0/5"
        and int_or_missing(env_queue.get("current_env_present_count")) == 0
        and int_or_missing(env_queue.get("current_env_missing_count")) == 14
        and sorted(env_queue.get("current_env_missing_names") or []) == expected_missing_env
        and sorted(env_details) == expected_missing_env
        and env_details.get("TAMANDUA_SERVER_PASSWORD", {}).get("class") == "secret"
        and env_details.get("TAMANDUA_SERVER_PASSWORD", {}).get("placeholder")
        == "<set-tamandua-server-password-secret>"
        and env_details.get("CALDERA_API_KEY", {}).get("class") == "secret"
        and "CALDERA API key" in str(env_details.get("CALDERA_API_KEY", {}).get("description") or "")
        and len(env_impact) == 14
        and set(impact_by_env) == set(expected_missing_env)
        and int_or_missing(server_password_impact.get("claim_count")) == 1
        and "claim-wave-1-restore-windows-qga-readiness"
        not in (server_password_impact.get("immediate_claim_ids") or [])
        and "claim-wave-3-rerun-preflight-and-closure-gate"
        in (server_password_impact.get("dependency_claim_ids") or [])
        and "wave-1-restore-windows-qga-readiness"
        in (server_password_impact.get("package_ids") or [])
        and set(fast_path_by_env) == {"TAMANDUA_TOKEN"}
        and server_password_fast_path == {}
        and token_fast_path.get("claim_ids") == ["claim-wave-1-restore-macos-backend-readiness"]
        and any("tamandua-ctl remote login" in str(command) for command in token_fast_path.get("commands") or [])
        and any(
            "wave-1-restore-macos-backend-readiness.ps1" in str(command)
            for command in token_fast_path.get("commands") or []
        )
        and "validation_product_readiness_operator_check.ps1"
        in str((next_actions[0] if next_actions else {}).get("commands") or "")
        and summary.get("recommended_next_action_id") == "fill-env-bundle"
        and recommended_action.get("id") == "fill-env-bundle"
        and int_or_missing(recommended_action.get("step")) == 2
        and sorted(recommended_action.get("env") or []) == expected_missing_env
        and "operator input only" in str(recommended_action.get("claim_boundary") or "")
        and len(env_queue.get("all_env_powershell_set_commands") or []) == 14
        and all(
            key in handoff_artifacts
            and is_expected_handoff_path(handoff_artifacts.get(key))
            for key in [
                "dispatch_brief",
                "env_checklist",
                "env_template",
                "env_unblock_queue",
                "env_unblock_queue_json",
                "agent_claims",
                "agent_spawn_plan",
                "agent_spawn_launcher",
                "env_bundle_ready_claims_launcher",
                "dispatch_prelaunch_validation",
                "dispatch_one_shot_runner",
                "claim_status_report",
                "claim_status_report_json",
            ]
        )
        and "-ValidateOnly" in str(env_queue.get("env_bundle_validation_command") or "")
        and any(
            "-Provider balanced -Phase env-bundle -Execute -Parallel" in str(command)
            for command in env_queue.get("post_env_bundle_balanced_agent_spawn_commands") or []
        )
        and post_env_plan.get("actionable") is True
        and post_env_plan.get("provider_mode") == "balanced"
        and post_env_plan.get("phase") == "env-bundle"
        and int_or_missing(post_env_plan.get("ready_claim_count")) == 1
        and int_or_missing(post_env_plan.get("ready_batch_count")) == 1
        and int_or_missing(post_env_plan.get("still_blocked_claim_count")) == 3
        and sorted(post_env_plan.get("ready_claim_ids") or []) == expected_ready_after_bundle
        and sorted(post_env_plan.get("still_blocked_claim_ids") or []) == expected_still_blocked
        and len(post_env_plan.get("ready_batches") or []) == 1
        and str(post_env_plan.get("agent_spawn_plan") or "").endswith("agent_spawn_plan.json")
        and any(
            "-Provider balanced -Phase env-bundle -Execute -Parallel" in str(command)
            for command in post_env_plan.get("balanced_agent_spawn_commands") or []
        )
        and int_or_missing(post_agent_gate.get("ready_after_env_passed_count")) == 0
        and int_or_missing(post_agent_gate.get("ready_after_env_required_count")) == 1
        and post_agent_gate.get("ready_after_env_all_passed") is False
        and len(post_agent_gate.get("incomplete_ready_after_env_claims") or []) == 1
        and str(post_agent_gate.get("report") or "").endswith("claim_status_report.json")
        and str(post_agent_gate.get("markdown_report") or "").endswith("claim_status_report.md")
        and "--refresh-claim-status-report" in str(post_agent_gate.get("refresh_command") or "")
        and (post_agent_gate.get("status_counts") or {}).get("not_run") == 5
        and "fail" not in (post_agent_gate.get("status_counts") or {})
        and sorted(env_queue.get("ready_after_all_env_claim_ids") or []) == expected_ready_after_bundle
        and sorted(env_queue.get("still_blocked_after_all_env_claim_ids") or []) == expected_still_blocked
        and int_or_missing(claims.get("claim_count")) == 5
        and int_or_missing(claims.get("ready_to_launch_count")) == 0
        and int_or_missing(claims.get("blocked_missing_env_count")) == 4
        and int_or_missing(claims.get("manual_claim_required_count")) == 1
        and len(claim_queue) == 5
        and manual_claim_ids == ["claim-wave-1-resolve-atomic-extended-preconditions"]
        and "WMI-capable disposable target" in manual_next_actions
        and [item.get("id") for item in next_actions] == [
            "check-current-env",
            "fill-env-bundle",
            "validate-env-bundle",
            "launch-env-bundle-claims",
            "balanced-agent-fanout",
            "resolve-manual-claims",
            "resolve-still-blocked-after-env",
            "refresh-validation-authority",
        ]
        and set(run_classes) == {
            "macos-server-backed-smoke",
            "windows-atomic-extended",
            "windows-broad",
            "windows-caldera-enterprise",
            "windows-p1-p2-rerun",
        }
    )


def active_status_doc_avoids_obsolete_consistency_fail(text: str) -> bool:
    return "20260612T092100Z-validation-status-consistency-probe" not in text


def active_status_doc_avoids_stale_dispatch_scorecard_coverage(text: str) -> bool:
    return "scorecard `1/8` coverage" not in text


def consistency_summary_matches_checks(payload: dict[str, Any]) -> bool:
    checks = payload.get("checks")
    summary = payload.get("summary")
    if not isinstance(checks, list) or not isinstance(summary, dict):
        return False
    statuses = [item.get("status") for item in checks if isinstance(item, dict)]
    if len(statuses) != len(checks) or any(status not in {"PASS", "FAIL"} for status in statuses):
        return False
    passed = sum(1 for status in statuses if status == "PASS")
    failed = sum(1 for status in statuses if status == "FAIL")
    return (
        summary.get("passed") == passed
        and summary.get("failed") == failed
        and summary.get("total_checks") == len(checks)
    )


def raw_urlopen_call_count(text: str) -> int:
    return len(re.findall(r"\burllib\.request\.urlopen\s*\(", text))


def proxy_safe_urllib_source(text: str) -> bool:
    return raw_urlopen_call_count(text) == 0 and "urllib.request.ProxyHandler({})" in text


def proxy_safe_requests_source(text: str) -> bool:
    return "requests.Session()" in text and re.search(r"\.trust_env\s*=\s*False", text) is not None


def line_contains_all(text: str, needles: list[str]) -> bool:
    return any(all(needle in line for needle in needles) for line in text.splitlines())


def latest_consistency_fail_references_are_current(text: str, latest_fail_run: str) -> bool:
    references = LATEST_CONSISTENCY_FAIL_REF_RE.findall(text)
    return all(reference == latest_fail_run for reference in references)


def doc_exposes_env_bundle_current_no_go(text: str) -> bool:
    required_markers = [
        "dispatch_prelaunch_validation.ps1",
        "env queue shape",
        "entries=14",
        "-Provider balanced -Phase all -ShowBlocked",
        "agent_spawn_launcher.ps1 -Provider balanced -Phase env-bundle -Execute -Parallel",
        "env_bundle_ready_claims_launcher.ps1 -ValidateOnly",
        "Env bundle current env present: 0/14",
        "14",
        "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH",
    ]
    return all(marker in text for marker in required_markers)


def ai_model_scanner_scorecard_preserves_claim_boundary(text: str) -> bool:
    return (
        "not production-ready performance" in text
        and "Tuning is **production-ready**" not in text
    )


def benchmark_results_review_preserves_caldera_claim_boundary(text: str) -> bool:
    return (
        "CALDERA smoke selected-profile evidence is claim-scoped only" in text
        and "repeatability and product claims still require the CALDERA repeatability gate to pass" in text
        and "CALDERA smoke is claimable only" not in text
    )


def benchmark_results_review_preserves_windows_p0_deterministic_boundary(text: str) -> bool:
    return (
        "Windows P0 safe expansion is closed only by accumulated deterministic evidence" in text
        and "Windows P0 safe expansion is closed by accumulated deterministic evidence" not in text
    )


def windows_p0_closure_preserves_deterministic_slice_boundary(text: str) -> bool:
    return (
        "31-scenario P0 safe deterministic slice" in text
        and "closed by accumulated" in text
        and "deterministic" in text
        and "not close Atomic/CALDERA provenance" in text
    )


def coordination_docs_avoid_p1_roadmap_overclaim(text: str) -> bool:
    forbidden = [
        "P1 is green",
        "after P1",
        "P1 is stable",
    ]
    return (
        all(phrase not in text for phrase in forbidden)
        and "selected P1 deterministic evidence is green" in text
    )


def roadmap_plans_preserve_current_cross_platform_boundary(text: str) -> bool:
    forbidden = [
        "Linux/macOS smoke | move non-Windows from planned-only",
        "Linux: `300` scenarios, `107` P0, all planned",
        "macOS: `300` scenarios, `107` P0, all planned",
        "only Windows has meaningful runnable evidence today",
        "These artifacts are dry-runs only",
    ]
    return all(phrase not in text for phrase in forbidden)


def parallel_board_preserves_linux_sensor_boundary(text: str) -> bool:
    return (
        "sensor-contract evidence is closed" not in text
        and "P0 sensor-contract smoke remains green in current evidence" in text
    )


def collect_nested_values(value: Any, key: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        current = value.get(key)
        if isinstance(current, list):
            found.extend(str(item) for item in current if item not in (None, ""))
        elif current not in (None, ""):
            found.append(str(current))
        for nested in value.values():
            found.extend(collect_nested_values(nested, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(collect_nested_values(item, key))
    return found


def sorted_unique_strings(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return sorted({str(value) for value in values if value not in (None, "")})


def roadmap_note(scorecard: dict[str, Any], roadmap_key: str) -> str:
    for item in scorecard.get("roadmaps") or []:
        if isinstance(item, dict) and item.get("key") == roadmap_key:
            return str(item.get("note") or "")
    return ""


def scorecard_open_roadmaps(scorecard: dict[str, Any]) -> list[str]:
    roadmaps = []
    for item in scorecard.get("roadmaps") or []:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        status = str(item.get("status") or "")
        if key and str(key) in EXPECTED_CLOSURE_EXCLUDED_ROADMAPS:
            continue
        if key and status != "pass":
            roadmaps.append(str(key))
    return roadmaps


def scorecard_open_roadmaps_have_actionable_notes(scorecard: dict[str, Any]) -> bool:
    for item in scorecard.get("roadmaps") or []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        if str(item.get("key") or "") in EXPECTED_CLOSURE_EXCLUDED_ROADMAPS:
            continue
        if status == "pass":
            continue
        note = str(item.get("note") or "").strip()
        if not note or note == "-":
            return False
        lowered = note.lower()
        if not any(marker in lowered for marker in ("requires", "required", "closure", "still", "must")):
            return False
    return True


def scorecard_markdown_renders_dry_runs_as_not_executed(scorecard: dict[str, Any], markdown_text: str) -> bool:
    lines = markdown_text.splitlines()
    for row in scorecard.get("profiles") or []:
        if not isinstance(row, dict) or row.get("status") != "dry-run":
            continue
        profile_id = str(row.get("profile_id") or "")
        if not profile_id:
            return False
        row_line = next((line for line in lines if line.startswith(f"| `{profile_id}` |")), "")
        if not row_line:
            return False
        if "`not-executed` | `not-executed`" not in row_line:
            return False
        if "`pass` | `complete`" in row_line:
            return False
    return True


def closure_open_roadmaps(closure_artifact: dict[str, Any]) -> list[str]:
    roadmaps = sorted_unique_strings(closure_artifact.get("gated_roadmaps"))
    if roadmaps:
        return roadmaps
    found = []
    for test in closure_artifact.get("tests") or []:
        if not isinstance(test, dict):
            continue
        if test.get("status") == "covered":
            continue
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        roadmap = evidence.get("roadmap_key")
        if roadmap:
            found.append(str(roadmap))
    return sorted(set(found))


def closure_excluded_roadmaps_valid(closure_artifact: dict[str, Any], scorecard: dict[str, Any]) -> bool:
    raw_excluded = closure_artifact.get("excluded_roadmaps")
    if not isinstance(raw_excluded, list):
        return False
    actual: dict[str, dict[str, str]] = {}
    for item in raw_excluded:
        if not isinstance(item, dict):
            return False
        roadmap = str(item.get("roadmap") or "").strip()
        if not roadmap or roadmap in actual:
            return False
        actual[roadmap] = {
            "roadmap": roadmap,
            "title": str(item.get("title") or "").strip(),
            "status": str(item.get("status") or "").strip(),
            "reason": str(item.get("reason") or "").strip(),
        }

    expected: dict[str, dict[str, str]] = {}
    for row in scorecard.get("roadmaps") or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("key") or "").strip()
        if key not in EXPECTED_CLOSURE_EXCLUDED_ROADMAPS:
            continue
        expected[key] = {
            "roadmap": key,
            "title": str(row.get("title") or row.get("owner_area") or "").strip(),
            "status": str(row.get("status") or "").strip(),
            "reason": EXPECTED_CLOSURE_EXCLUDED_ROADMAPS[key],
        }

    return actual == expected


def closure_excluded_roadmaps_markdown_valid(closure_artifact: dict[str, Any], markdown_text: str) -> bool:
    raw_excluded = closure_artifact.get("excluded_roadmaps")
    if not isinstance(raw_excluded, list):
        return False
    if not raw_excluded:
        return "## Excluded Roadmaps" not in markdown_text
    if "## Excluded Roadmaps" not in markdown_text:
        return False
    for item in raw_excluded:
        if not isinstance(item, dict):
            return False
        roadmap = str(item.get("roadmap") or "").strip()
        status = str(item.get("status") or "").strip()
        reason = str(item.get("reason") or "").strip()
        if not roadmap or not status or not reason:
            return False
        expected_row = f"| `{roadmap}` | `{status}` | {reason} |"
        if expected_row not in markdown_text:
            return False
    return True


def closure_next_action_summary(closure_artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    actions: dict[str, dict[str, Any]] = {}
    for item in closure_artifact.get("roadmap_next_actions") or []:
        if not isinstance(item, dict):
            continue
        roadmap = str(item.get("roadmap") or "")
        if not roadmap:
            continue
        actions[roadmap] = {
            "blocking_profiles": sorted_unique_strings(item.get("blocking_profiles")),
            "required_env": sorted_unique_strings(item.get("required_env")),
            "has_action": bool(item.get("action")),
        }
    return dict(sorted(actions.items()))


def closure_next_actions_valid(closure_artifact: dict[str, Any], expected_roadmaps: list[str]) -> bool:
    actions = closure_next_action_summary(closure_artifact)
    if sorted(actions) != sorted(expected_roadmaps):
        return False
    for roadmap in expected_roadmaps:
        action = actions.get(roadmap) or {}
        if not action.get("has_action"):
            return False
        missing_env = missing_expected_values(
            action.get("required_env") or [],
            EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS.get(roadmap, []),
        )
        if missing_env:
            return False
    return True


def preflight_roadmap_next_actions_valid(preflight_artifact: dict[str, Any], expected_roadmaps: list[str]) -> bool:
    actions = closure_next_action_summary(preflight_artifact)
    if not actions:
        raw_actions = preflight_artifact.get("roadmap_next_actions") or []
        actions = closure_next_action_summary({"roadmap_next_actions": raw_actions})
    if sorted(actions) != sorted(expected_roadmaps):
        return False
    for roadmap, expected_env in EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS.items():
        action = actions.get(roadmap) or {}
        if missing_expected_values(action.get("required_env") or [], expected_env):
            return False
    return all((actions.get(roadmap) or {}).get("has_action") for roadmap in actions)


def preflight_preserves_closure_excluded_roadmaps(
    preflight_artifact: dict[str, Any],
    closure_artifact: dict[str, Any],
) -> bool:
    preflight_excluded = preflight_artifact.get("excluded_roadmaps")
    closure_excluded = closure_artifact.get("excluded_roadmaps")
    if not isinstance(preflight_excluded, list) or not isinstance(closure_excluded, list):
        return False
    return preflight_excluded == closure_excluded


def blocked_run_classes(preflight_artifact: dict[str, Any]) -> list[str]:
    blocked = []
    for item in preflight_artifact.get("run_class_readiness") or []:
        if isinstance(item, dict) and item.get("allowed") is False and item.get("run_class"):
            blocked.append(str(item["run_class"]))
    return sorted(set(blocked))


def blocked_run_class_roadmaps(preflight_artifact: dict[str, Any]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for item in preflight_artifact.get("run_class_readiness") or []:
        if not isinstance(item, dict) or item.get("allowed") is not False or not item.get("run_class"):
            continue
        mapping[str(item["run_class"])] = sorted_unique_strings(item.get("open_roadmaps"))
    return dict(sorted(mapping.items()))


def blocked_run_class_missing_envs(preflight_artifact: dict[str, Any]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for item in preflight_artifact.get("run_class_readiness") or []:
        if not isinstance(item, dict) or item.get("allowed") is not False or not item.get("run_class"):
            continue
        mapping[str(item["run_class"])] = sorted_unique_strings(item.get("missing_env"))
    return dict(sorted(mapping.items()))


def unblock_sequence_ids(preflight_artifact: dict[str, Any]) -> list[str]:
    steps = []
    for item in preflight_artifact.get("unblock_sequence") or []:
        if isinstance(item, dict) and item.get("step_id"):
            steps.append(str(item["step_id"]))
    return steps


def unblock_sequence_priorities(preflight_artifact: dict[str, Any]) -> list[int]:
    priorities: list[int] = []
    for item in preflight_artifact.get("unblock_sequence") or []:
        if not isinstance(item, dict):
            continue
        try:
            priorities.append(int(item.get("priority")))
        except (TypeError, ValueError):
            continue
    return priorities


def parallel_unblock_wave_shape(preflight_artifact: dict[str, Any]) -> list[dict[str, Any]]:
    waves = []
    for item in preflight_artifact.get("parallel_unblock_waves") or []:
        if not isinstance(item, dict):
            continue
        try:
            wave = int(item.get("wave"))
        except (TypeError, ValueError):
            continue
        waves.append(
            {
                "wave": wave,
                "parallelizable": bool(item.get("parallelizable")),
                "step_ids": [str(value) for value in item.get("step_ids") or [] if value],
                "depends_on_waves": [
                    int(value)
                    for value in item.get("depends_on_waves") or []
                    if str(value).isdigit()
                ],
            }
        )
    return sorted(waves, key=lambda item: item["wave"])


def dispatch_agent_excerpts(dispatch_artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict) or not package.get("package_id"):
            continue
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        agent = evidence.get("agent") if isinstance(evidence.get("agent"), dict) else {}
        if agent:
            mapping[str(package["package_id"])] = {
                "hostname": agent.get("hostname"),
                "status": agent.get("status"),
            }
            continue
        missing = evidence.get("missing") if isinstance(evidence.get("missing"), list) else []
        if missing:
            mapping[str(package["package_id"])] = {"missing": [str(value) for value in missing]}
            continue
        missing_package = (
            evidence.get("missing_package")
            if isinstance(evidence.get("missing_package"), dict)
            else {}
        )
        if missing_package:
            mapping[str(package["package_id"])] = {
                "missing_package": [
                    str(value) for value in missing_package.get("missing_expected_profiles") or []
                ],
                "required_env": [
                    str(value) for value in missing_package.get("required_env") or []
                ],
            }
            continue
        gap_category = evidence.get("gap_category")
        if gap_category:
            mapping[str(package["package_id"])] = {"gap_category": str(gap_category)}
    return dict(sorted(mapping.items()))


def dispatch_missing_package_evidence_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False
    expected_by_package = {
        str(package.get("package_id")): [
            str(value) for value in package.get("expected_profile_ids") or []
        ]
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    }
    checked = 0
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        if not package_id or package_id not in expected_by_package:
            return False
        artifact_paths = [str(value) for value in package.get("artifact_paths") or []]
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        missing_package = (
            evidence.get("missing_package")
            if isinstance(evidence.get("missing_package"), dict)
            else {}
        )
        if artifact_paths:
            if missing_package:
                return False
            checked += 1
            continue
        missing_profiles = [
            str(value) for value in missing_package.get("missing_expected_profiles") or []
        ]
        if missing_profiles != expected_by_package[package_id]:
            return False
        checked += 1
    return checked == len(expected_by_package) and checked > 0


def dispatch_windows_connection_next_action(dispatch_artifact: dict[str, Any]) -> dict[str, Any]:
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_id = str(profile_result.get("profile_id") or "")
            if profile_id != PROFILE_WINDOWS_CONNECTION_STABILITY:
                continue
            evidence = (
                profile_result.get("evidence_excerpt")
                if isinstance(profile_result.get("evidence_excerpt"), dict)
                else {}
            )
            action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
            if not action:
                continue
            return {
                "package_id": package_id,
                "profile_id": profile_id,
                "missing_stability": [str(value) for value in action.get("missing_stability") or []],
                "has_action": bool(action.get("action")),
            }
    return {}


def dispatch_windows_connection_handoff(dispatch_artifact: dict[str, Any]) -> dict[str, Any]:
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        expected_profiles = [str(value) for value in package.get("expected_profile_ids") or []]
        if PROFILE_WINDOWS_CONNECTION_STABILITY not in expected_profiles:
            continue
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        missing_package = (
            evidence.get("missing_package")
            if isinstance(evidence.get("missing_package"), dict)
            else {}
        )
        missing_profiles = [
            str(value) for value in missing_package.get("missing_expected_profiles") or []
        ]
        required_env = [
            str(value) for value in missing_package.get("required_env") or []
        ]
        return {
            "package_id": str(package.get("package_id") or ""),
            "profile_id": PROFILE_WINDOWS_CONNECTION_STABILITY,
            "required_env": sorted(required_env),
            "missing_package": PROFILE_WINDOWS_CONNECTION_STABILITY in missing_profiles,
        }
    return {}


def dispatch_macos_auth_handoff(dispatch_artifact: dict[str, Any]) -> dict[str, Any]:
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        expected_profiles = [str(value) for value in package.get("expected_profile_ids") or []]
        if PROFILE_MACOS_BACKEND_READINESS not in expected_profiles:
            continue
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        if not action:
            for profile_result in package.get("profile_results") or []:
                if not isinstance(profile_result, dict):
                    continue
                if profile_result.get("profile_id") != PROFILE_MACOS_BACKEND_READINESS:
                    continue
                profile_evidence = (
                    profile_result.get("evidence_excerpt")
                    if isinstance(profile_result.get("evidence_excerpt"), dict)
                    else {}
                )
                action = (
                    profile_evidence.get("next_action")
                    if isinstance(profile_evidence.get("next_action"), dict)
                    else {}
                )
                break
        return {
            "package_id": str(package.get("package_id") or ""),
            "profile_id": PROFILE_MACOS_BACKEND_READINESS,
            "missing_readiness": [str(value) for value in action.get("missing_readiness") or []],
            "login_command": str(action.get("login_command") or ""),
            "token_env": str(action.get("token_env") or ""),
            "token_login_command": str(action.get("token_login_command") or ""),
            "target_server": str(action.get("target_server") or ""),
            "has_action": bool(action.get("action")),
        }
    return {}


def dispatch_claim_macos_auth_handoff(dispatch_artifact: dict[str, Any]) -> dict[str, Any]:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return {}
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return {}
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return {}
    claim_sources = [
        normalize_artifact_ref(manifest.get("agent_claims_json_path")),
        normalize_artifact_ref(manifest.get("claim_status_report_json_path")),
    ]
    summaries = []
    for source in claim_sources:
        if not source:
            return {}
        source_path = ROOT / source
        if not source_path.exists():
            return {}
        try:
            payload = load_json(source_path)
        except json.JSONDecodeError:
            return {}
        claim = next(
            (
                item
                for item in payload.get("claims") or []
                if isinstance(item, dict)
                and item.get("package_id") == "wave-1-restore-macos-backend-readiness"
            ),
            {},
        )
        action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        summaries.append(
            {
                "source": source,
                "missing_readiness": [str(value) for value in action.get("missing_readiness") or []],
                "login_command": str(action.get("login_command") or ""),
                "token_env": str(action.get("token_env") or ""),
                "token_login_command": str(action.get("token_login_command") or ""),
                "target_server": str(action.get("target_server") or ""),
                "has_action": bool(action.get("action")),
            }
        )
    return {"summaries": summaries}


def render_current_next_action_summary(action: object) -> str:
    if not isinstance(action, dict) or not action:
        return "-"
    missing_values = (
        action.get("missing_stability")
        or action.get("missing_readiness")
        or action.get("missing_diagnostics")
        or action.get("missing_endpoints")
        or action.get("missing_profiles")
        or []
    )
    parts = []
    if missing_values:
        parts.append("missing=" + ",".join(str(value) for value in missing_values))
    if action.get("login_command"):
        parts.append("login_command=" + str(action.get("login_command")))
    if action.get("token_login_command"):
        parts.append("token_login_command=" + str(action.get("token_login_command")))
    if action.get("action"):
        parts.append("action=" + str(action.get("action")))
    return "; ".join(parts) or "-"


def next_action_env_from_action(action: object) -> list[str]:
    if not isinstance(action, dict):
        return []
    values = [str(value) for value in action.get("required_env") or [] if str(value)]
    token_env = str(action.get("token_env") or "")
    if token_env:
        values.append(token_env)
    deduped = []
    for value in values:
        if value not in deduped:
            deduped.append(value)
    return deduped


def next_action_summary_direct_for_env(env_name: str, action: object, summary: str) -> bool:
    action_env = next_action_env_from_action(action)
    if action_env:
        return env_name in action_env
    summary_text = str(summary or "")
    if env_name in summary_text:
        return True
    if env_name.startswith("TAMANDUA_FRESH_RESTORE") and (
        "fresh-restore" in summary_text or "restore metadata" in summary_text
    ):
        return True
    if env_name.startswith("CALDERA_") and "CALDERA" in summary_text:
        return True
    if env_name == "TAMANDUA_PROXMOX_PASSWORD" and (
        "Proxmox" in summary_text or "QGA" in summary_text
    ):
        return True
    if env_name == "TAMANDUA_TOKEN" and "tamandua-ctl" in summary_text:
        return True
    return False


def find_first_nested_dict(value: object, key: str) -> dict[str, Any]:
    if isinstance(value, dict):
        nested = value.get(key)
        if isinstance(nested, dict) and nested:
            return nested
        for item in value.values():
            found = find_first_nested_dict(item, key)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = find_first_nested_dict(item, key)
            if found:
                return found
    return {}


def expected_dispatch_claim_macos_auth_handoff(dispatch_run: str) -> dict[str, Any]:
    base = f"docs/benchmarks/runs/{dispatch_run}.package-artifacts"
    common = {
        "missing_readiness": ["status_online", "health_healthy", "fresh_heartbeat"],
        "login_command": "",
        "token_env": "",
        "token_login_command": "",
        "target_server": "",
        "has_action": True,
    }
    return {
        "summaries": [
            {"source": f"{base}/agent_claims.json", **common},
            {"source": f"{base}/claim_status_report.json", **common},
        ]
    }


def dispatch_macos_prompt_exposes_token_env(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        if package.get("package_id") != "wave-1-restore-macos-backend-readiness":
            continue
        prompt_path = normalize_artifact_ref(package.get("prompt_path"))
        if not prompt_path:
            return False
        prompt_full_path = ROOT / prompt_path
        if not prompt_full_path.exists():
            return False
        text = prompt_full_path.read_text(encoding="utf-8")
        token_handoff = (
            "tamandua_ctl_auth" in text
            and "tamandua-ctl remote login" in text
            and "Effective env checklist: TAMANDUA_TOKEN" in text
        )
        offline_handoff = (
            "status_online" in text
            and "health_healthy" in text
            and "fresh_heartbeat" in text
        )
        return token_handoff or offline_handoff
    return False


def dispatch_package_artifact_paths(dispatch_artifact: dict[str, Any]) -> list[str]:
    paths = []
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        output_dir = package.get("output_dir")
        if output_dir:
            paths.append(normalize_artifact_ref(output_dir))
        status_path = package.get("agent_status_path")
        if status_path:
            paths.append(normalize_artifact_ref(status_path))
        artifact_path = package.get("artifact_path")
        if artifact_path:
            paths.append(normalize_artifact_ref(artifact_path))
        for artifact_path in package.get("artifact_paths") or []:
            paths.append(normalize_artifact_ref(artifact_path))
        for agent_artifact in package.get("agent_artifacts") or []:
            paths.append(normalize_artifact_ref(agent_artifact))
        for archived_path in package.get("archived_artifacts") or []:
            paths.append(normalize_artifact_ref(archived_path))
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_artifact = profile_result.get("artifact_path")
            if profile_artifact:
                paths.append(normalize_artifact_ref(profile_artifact))
    return sorted(set(paths))


def dispatch_official_metadata_matches_profile(dispatch_artifact: dict[str, Any]) -> bool:
    return (
        dispatch_artifact.get("profile_id") == PROFILE_DISPATCH_RESULTS
        and dispatch_artifact.get("profile") == PROFILE_DISPATCH_RESULTS
        and dispatch_artifact.get("benchmark_lane") == "claim-boundary"
        and "does not promote package artifacts" in str(dispatch_artifact.get("claim_boundary") or "")
    )


def dispatch_official_paths_are_self_contained(dispatch_artifact: dict[str, Any], dispatch_run: str) -> bool:
    expected_prefix = f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/"
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    canonical_paths = dispatch_package_artifact_paths(dispatch_artifact)
    if not manifest_path.startswith(expected_prefix):
        return False
    if not canonical_paths:
        return False
    return all(path.startswith(expected_prefix) for path in canonical_paths)


def dispatch_official_paths_exist(dispatch_artifact: dict[str, Any]) -> bool:
    official_paths = dispatch_package_artifact_paths(dispatch_artifact)
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if manifest_path:
        official_paths.append(manifest_path)
    if not official_paths:
        return False
    return all((ROOT / path).exists() for path in official_paths)


def dispatch_official_payload_has_no_tmp(dispatch_artifact: dict[str, Any]) -> bool:
    official_values: list[str] = []
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if source_preflight:
        official_values.append(source_preflight)
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if manifest_path:
        official_values.append(manifest_path)
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for field_name in ("artifact_path", "output_dir"):
            field_value = package.get(field_name)
            if field_value:
                official_values.append(normalize_artifact_ref(field_value))
        for artifact_path in package.get("artifact_paths") or []:
            official_values.append(normalize_artifact_ref(artifact_path))
        for agent_artifact in package.get("agent_artifacts") or []:
            official_values.append(normalize_artifact_ref(agent_artifact))
        for archived_path in package.get("archived_artifacts") or []:
            official_values.append(normalize_artifact_ref(archived_path))
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_artifact = profile_result.get("artifact_path")
            if profile_artifact:
                official_values.append(normalize_artifact_ref(profile_artifact))
    return all(
        "/tmp/" not in value.lower()
        and not value.lower().startswith("tmp/")
        and not re.match(r"^[A-Za-z]:/", value)
        and not value.startswith("/")
        for value in official_values
    )


def dispatch_official_comparison_matches_payload(dispatch_artifact: dict[str, Any]) -> bool:
    run_id = str(dispatch_artifact.get("run_id") or "")
    if not run_id:
        return False
    comparison_path = ROOT / "docs" / "benchmarks" / "runs" / f"{run_id}.comparison.json"
    if not comparison_path.exists():
        return False
    try:
        comparison = load_json(comparison_path)
    except json.JSONDecodeError:
        return False
    if comparison.get("schema_version") != 1:
        return False
    for key in ("profile_id", "benchmark_lane", "claim_boundary", "quality_gate"):
        if comparison.get(key) != dispatch_artifact.get(key):
            return False
    if comparison.get("packages") != dispatch_artifact.get("packages"):
        return False
    if comparison.get("tests") != dispatch_artifact.get("tests"):
        return False
    summary = comparison.get("summary") if isinstance(comparison.get("summary"), dict) else {}
    artifact_summary = (
        dispatch_artifact.get("summary")
        if isinstance(dispatch_artifact.get("summary"), dict)
        else {}
    )
    expected_summary = {
        "passed_count": dispatch_artifact.get("passed_count"),
        "failed_count": dispatch_artifact.get("failed_count"),
        "status_counts": dispatch_artifact.get("status_counts"),
        "blocked_count": dispatch_artifact.get("blocked_count"),
        "failed_status_count": dispatch_artifact.get("failed_status_count"),
        "missing_count": dispatch_artifact.get("missing_count"),
        "invalid_count": dispatch_artifact.get("invalid_count"),
        "dispatch_manifest": dispatch_artifact.get("dispatch_manifest"),
        "source_preflight": dispatch_artifact.get("source_preflight"),
        "missing_required_env": dispatch_artifact.get("missing_required_env"),
        "required_env_blockers": dispatch_artifact.get("required_env_blockers"),
        "owner_handoff": dispatch_artifact.get("owner_handoff"),
        "covered": artifact_summary.get("covered"),
        "tests": artifact_summary.get("tests"),
    }
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            return False
    comparison_dispatch = {
        "run_id": run_id,
        "dispatch_manifest": summary.get("dispatch_manifest"),
        "source_preflight": summary.get("source_preflight"),
        "packages": comparison.get("packages") or [],
    }
    return (
        dispatch_official_paths_are_self_contained(comparison_dispatch, run_id)
        and dispatch_official_paths_exist(comparison_dispatch)
        and dispatch_official_payload_has_no_tmp(comparison_dispatch)
    )


def dispatch_archived_summary_has_self_contained_paths(dispatch_artifact: dict[str, Any]) -> bool:
    run_id = str(dispatch_artifact.get("run_id") or "")
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not run_id or not manifest_path:
        return False
    archive_root = (ROOT / manifest_path).parent
    json_path = archive_root / "dispatch_results.json"
    markdown_path = archive_root / "dispatch_results.md"
    if not json_path.exists() or not markdown_path.exists():
        return False
    try:
        summary = load_json(json_path)
    except json.JSONDecodeError:
        return False
    for key in (
        "passed_count",
        "failed_count",
        "blocked_count",
        "failed_status_count",
        "missing_count",
        "invalid_count",
    ):
        if summary.get(key) != dispatch_artifact.get(key):
            return False
    summary_dispatch = {
        "run_id": run_id,
        "dispatch_manifest": summary.get("dispatch_manifest"),
        "source_preflight": summary.get("source_preflight"),
        "packages": summary.get("packages") or [],
    }
    if not (
        dispatch_official_paths_are_self_contained(summary_dispatch, run_id)
        and dispatch_official_paths_exist(summary_dispatch)
        and dispatch_official_payload_has_no_tmp(summary_dispatch)
    ):
        return False
    markdown = markdown_path.read_text(encoding="utf-8")
    forbidden_patterns = ("/tmp/", "tmp/", "D:/", "D:\\", "\\tmp\\")
    if any(pattern.lower() in markdown.lower() for pattern in forbidden_patterns):
        return False
    artifact_paths = [
        normalize_artifact_ref(package.get("artifact_path"))
        for package in summary.get("packages") or []
        if isinstance(package, dict) and package.get("artifact_path")
    ]
    return all(path in markdown for path in artifact_paths)


def dispatch_archived_manifest_has_no_tmp(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    manifest_values: list[str] = []
    for field_name in (
        "source_preflight",
        "output_dir",
        "agent_roster_path",
        "env_checklist_path",
        "env_template_path",
        "owner_launch_plan_path",
        "owner_launch_plan_json_path",
        "execution_matrix_path",
        "execution_matrix_json_path",
        "agent_claims_path",
        "agent_claims_json_path",
        "agent_spawn_plan_path",
        "agent_spawn_plan_json_path",
        "agent_spawn_launcher_path",
        "claim_status_report_path",
        "claim_status_report_json_path",
        "claim_lock_helper_path",
        "env_unblock_queue_path",
        "env_unblock_queue_json_path",
        "ready_claims_launcher_path",
        "ready_claims_parallel_launcher_path",
        "env_bundle_ready_claims_launcher_path",
        "dispatch_prelaunch_validation_path",
        "dispatch_brief_path",
        "dispatch_runner_path",
    ):
        field_value = manifest.get(field_name)
        if field_value:
            manifest_values.append(normalize_artifact_ref(field_value))
    for launcher_path in manifest.get("launcher_paths") or []:
        manifest_values.append(normalize_artifact_ref(launcher_path))
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for field_name in ("artifact_path", "output_dir", "prompt_path", "script_path"):
            field_value = package.get(field_name)
            if field_value:
                manifest_values.append(normalize_artifact_ref(field_value))

    return bool(manifest_values) and all(
        "/tmp/" not in value.lower()
        and not value.lower().startswith("tmp/")
        and not re.match(r"^[A-Za-z]:/", value)
        and not value.startswith("/")
        for value in manifest_values
    )


def dispatch_archived_manifest_handoff_paths_exist(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    required_file_paths: list[str] = []
    roster_path = normalize_artifact_ref(manifest.get("agent_roster_path"))
    if roster_path:
        required_file_paths.append(roster_path)
    env_checklist_path = normalize_artifact_ref(manifest.get("env_checklist_path"))
    if env_checklist_path:
        required_file_paths.append(env_checklist_path)
    env_template_path = normalize_artifact_ref(manifest.get("env_template_path"))
    if env_template_path:
        required_file_paths.append(env_template_path)
    owner_launch_plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_path"))
    if owner_launch_plan_path:
        required_file_paths.append(owner_launch_plan_path)
    owner_launch_plan_json_path = normalize_artifact_ref(manifest.get("owner_launch_plan_json_path"))
    if owner_launch_plan_json_path:
        required_file_paths.append(owner_launch_plan_json_path)
    execution_matrix_path = normalize_artifact_ref(manifest.get("execution_matrix_path"))
    if execution_matrix_path:
        required_file_paths.append(execution_matrix_path)
    execution_matrix_json_path = normalize_artifact_ref(manifest.get("execution_matrix_json_path"))
    if execution_matrix_json_path:
        required_file_paths.append(execution_matrix_json_path)
    agent_claims_path = normalize_artifact_ref(manifest.get("agent_claims_path"))
    if agent_claims_path:
        required_file_paths.append(agent_claims_path)
    agent_claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if agent_claims_json_path:
        required_file_paths.append(agent_claims_json_path)
    agent_spawn_plan_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_path"))
    if agent_spawn_plan_path:
        required_file_paths.append(agent_spawn_plan_path)
    agent_spawn_plan_json_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path"))
    if agent_spawn_plan_json_path:
        required_file_paths.append(agent_spawn_plan_json_path)
    agent_spawn_launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    if agent_spawn_launcher_path:
        required_file_paths.append(agent_spawn_launcher_path)
    claim_status_report_path = normalize_artifact_ref(manifest.get("claim_status_report_path"))
    if claim_status_report_path:
        required_file_paths.append(claim_status_report_path)
    claim_status_report_json_path = normalize_artifact_ref(manifest.get("claim_status_report_json_path"))
    if claim_status_report_json_path:
        required_file_paths.append(claim_status_report_json_path)
    claim_lock_helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if claim_lock_helper_path:
        required_file_paths.append(claim_lock_helper_path)
    env_unblock_queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    if env_unblock_queue_path:
        required_file_paths.append(env_unblock_queue_path)
    env_unblock_queue_json_path = normalize_artifact_ref(manifest.get("env_unblock_queue_json_path"))
    if env_unblock_queue_json_path:
        required_file_paths.append(env_unblock_queue_json_path)
    ready_claims_launcher_path = normalize_artifact_ref(manifest.get("ready_claims_launcher_path"))
    if ready_claims_launcher_path:
        required_file_paths.append(ready_claims_launcher_path)
    ready_claims_parallel_launcher_path = normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path"))
    if ready_claims_parallel_launcher_path:
        required_file_paths.append(ready_claims_parallel_launcher_path)
    env_bundle_ready_claims_launcher_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    if env_bundle_ready_claims_launcher_path:
        required_file_paths.append(env_bundle_ready_claims_launcher_path)
    dispatch_prelaunch_validation_path = normalize_artifact_ref(manifest.get("dispatch_prelaunch_validation_path"))
    if dispatch_prelaunch_validation_path:
        required_file_paths.append(dispatch_prelaunch_validation_path)
    dispatch_brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    if dispatch_brief_path:
        required_file_paths.append(dispatch_brief_path)
    dispatch_runner_path = normalize_artifact_ref(manifest.get("dispatch_runner_path"))
    if dispatch_runner_path:
        required_file_paths.append(dispatch_runner_path)
    for launcher_path in manifest.get("launcher_paths") or []:
        required_file_paths.append(normalize_artifact_ref(launcher_path))
    for launcher_path in manifest.get("staged_launcher_paths") or []:
        required_file_paths.append(normalize_artifact_ref(launcher_path))
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for field_name in ("prompt_path", "script_path"):
            field_value = package.get(field_name)
            if field_value:
                required_file_paths.append(normalize_artifact_ref(field_value))
    return bool(required_file_paths) and all((ROOT / path).is_file() for path in required_file_paths)


def dispatch_archived_handoff_contents_are_self_contained(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    dispatch_run = str(dispatch_artifact.get("run_id") or "")
    if not manifest_path or not dispatch_run:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    packages = [package for package in manifest.get("packages") or [] if isinstance(package, dict)]

    expected_prefix = f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/"
    launcher_paths = [normalize_artifact_ref(path) for path in manifest.get("launcher_paths") or []]
    launcher_paths.extend(normalize_artifact_ref(path) for path in manifest.get("staged_launcher_paths") or [])
    package_script_paths: list[str] = []
    files_to_scan = list(launcher_paths)
    roster_path = normalize_artifact_ref(manifest.get("agent_roster_path"))
    if roster_path:
        files_to_scan.append(roster_path)
    env_checklist_path = normalize_artifact_ref(manifest.get("env_checklist_path"))
    if env_checklist_path:
        files_to_scan.append(env_checklist_path)
    env_template_path = normalize_artifact_ref(manifest.get("env_template_path"))
    if env_template_path:
        files_to_scan.append(env_template_path)
    owner_launch_plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_path"))
    if owner_launch_plan_path:
        files_to_scan.append(owner_launch_plan_path)
    owner_launch_plan_json_path = normalize_artifact_ref(manifest.get("owner_launch_plan_json_path"))
    if owner_launch_plan_json_path:
        files_to_scan.append(owner_launch_plan_json_path)
    execution_matrix_path = normalize_artifact_ref(manifest.get("execution_matrix_path"))
    if execution_matrix_path:
        files_to_scan.append(execution_matrix_path)
    execution_matrix_json_path = normalize_artifact_ref(manifest.get("execution_matrix_json_path"))
    if execution_matrix_json_path:
        files_to_scan.append(execution_matrix_json_path)
    agent_claims_path = normalize_artifact_ref(manifest.get("agent_claims_path"))
    if agent_claims_path:
        files_to_scan.append(agent_claims_path)
    agent_claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if agent_claims_json_path:
        files_to_scan.append(agent_claims_json_path)
    agent_spawn_plan_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_path"))
    if agent_spawn_plan_path:
        files_to_scan.append(agent_spawn_plan_path)
    agent_spawn_plan_json_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path"))
    if agent_spawn_plan_json_path:
        files_to_scan.append(agent_spawn_plan_json_path)
    agent_spawn_launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    if agent_spawn_launcher_path:
        files_to_scan.append(agent_spawn_launcher_path)
    claim_status_report_path = normalize_artifact_ref(manifest.get("claim_status_report_path"))
    if claim_status_report_path:
        files_to_scan.append(claim_status_report_path)
    claim_status_report_json_path = normalize_artifact_ref(manifest.get("claim_status_report_json_path"))
    if claim_status_report_json_path:
        files_to_scan.append(claim_status_report_json_path)
    claim_lock_helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if claim_lock_helper_path:
        files_to_scan.append(claim_lock_helper_path)
    env_unblock_queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    if env_unblock_queue_path:
        files_to_scan.append(env_unblock_queue_path)
    env_unblock_queue_json_path = normalize_artifact_ref(manifest.get("env_unblock_queue_json_path"))
    if env_unblock_queue_json_path:
        files_to_scan.append(env_unblock_queue_json_path)
    ready_claims_launcher_path = normalize_artifact_ref(manifest.get("ready_claims_launcher_path"))
    if ready_claims_launcher_path:
        files_to_scan.append(ready_claims_launcher_path)
    ready_claims_parallel_launcher_path = normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path"))
    if ready_claims_parallel_launcher_path:
        files_to_scan.append(ready_claims_parallel_launcher_path)
    env_bundle_ready_claims_launcher_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    if env_bundle_ready_claims_launcher_path:
        files_to_scan.append(env_bundle_ready_claims_launcher_path)
    dispatch_prelaunch_validation_path = normalize_artifact_ref(manifest.get("dispatch_prelaunch_validation_path"))
    if dispatch_prelaunch_validation_path:
        files_to_scan.append(dispatch_prelaunch_validation_path)
    dispatch_brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    if dispatch_brief_path:
        files_to_scan.append(dispatch_brief_path)
    dispatch_runner_path = normalize_artifact_ref(manifest.get("dispatch_runner_path"))
    if dispatch_runner_path:
        files_to_scan.append(dispatch_runner_path)
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        script_path = normalize_artifact_ref(package.get("script_path"))
        prompt_path = normalize_artifact_ref(package.get("prompt_path"))
        status_path = normalize_artifact_ref(package.get("status_path"))
        if not script_path or not script_path.startswith(expected_prefix):
            return False
        package_script_paths.append(script_path)
        files_to_scan.append(script_path)
        if not status_path or not status_path.startswith(expected_prefix):
            return False
        if prompt_path:
            files_to_scan.append(prompt_path)
            prompt_full_path = ROOT / prompt_path
            if not prompt_full_path.exists():
                return False
            prompt_text = prompt_full_path.read_text(encoding="utf-8")
            if script_path not in prompt_text:
                return False
            if status_path not in prompt_text:
                return False

    if not files_to_scan or not package_script_paths:
        return False
    launcher_text = ""
    for launcher_path in launcher_paths:
        if not launcher_path.startswith(expected_prefix):
            return False
        launcher_full_path = ROOT / launcher_path
        if not launcher_full_path.exists():
            return False
        launcher_text += "\n" + launcher_full_path.read_text(encoding="utf-8")
    for package in packages:
        if not isinstance(package, dict):
            continue
        if package.get("launcher_selected") is not True and package.get("staged_launcher_selected") is not True:
            continue
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not script_path or script_path not in launcher_text:
            return False

    for file_path in files_to_scan:
        if not file_path.startswith(expected_prefix):
            return False
        content_path = ROOT / file_path
        if not content_path.exists():
            return False
        normalized_content = content_path.read_text(encoding="utf-8").replace("\\", "/").lower()
        if "/tmp/" in normalized_content or "tmp/dispatch-" in normalized_content:
            return False
        if re.search(r"\b[a-z]:/", normalized_content):
            return False
    return True


def dispatch_archived_handoff_execution_guards_present(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_paths = [normalize_artifact_ref(path) for path in manifest.get("launcher_paths") or []]
    if launcher_paths:
        for launcher_path in launcher_paths:
            launcher_full_path = ROOT / launcher_path
            if not launcher_full_path.exists():
                return False
            launcher_text = launcher_full_path.read_text(encoding="utf-8")
            if "exit $LASTEXITCODE" not in launcher_text:
                return False

    guarded_packages = 0
    status_guarded_packages = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        required_env = [
            str(value)
            for value in package.get("effective_required_env") or package.get("required_env") or []
        ]
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not script_path:
            return False
        script_full_path = ROOT / script_path
        if not script_full_path.exists():
            return False
        script_text = script_full_path.read_text(encoding="utf-8")
        status_markers = [
            "$StatusPath",
            "function Write-AgentStatus",
            "package_id = $PackageId",
            "claim_id = $ClaimId",
            "agent_id = $AgentId",
            "status = $Status",
            "artifacts = @($Artifacts)",
            "blocker_cleared = [bool]$BlockerCleared",
            "notes = @($Notes)",
            "$ProfileIdProperty = $Payload.PSObject.Properties['profile_id']",
            "$QualityGateProperty = $Payload.PSObject.Properties['quality_gate']",
            "$PassedProperty = $QualityGateProperty.Value.PSObject.Properties['passed']",
        ]
        if not all(marker in script_text for marker in status_markers):
            return False
        if "$Payload.profile_id" in script_text or "$Payload.quality_gate" in script_text:
            return False
        status_guarded_packages += 1
        if not required_env:
            continue
        if "Missing effective env for package" not in script_text:
            return False
        missing_env_index = script_text.find("Missing effective env for package")
        claim_lock_index = script_text.find("Missing claim lock helper for direct package execution")
        if claim_lock_index == -1 or claim_lock_index < missing_env_index:
            return False
        if "missing_effective_env:" not in script_text:
            return False
        if "Write-AgentStatus 'blocked'" not in script_text:
            return False
        for env_name in required_env:
            if env_name not in script_text:
                return False
        guarded_packages += 1
    return guarded_packages > 0 and status_guarded_packages > 0


def dispatch_archived_dependent_launcher_evidence_guards_present(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    dependent_waves = sorted(
        {
            int(package.get("wave") or 0)
            for package in manifest.get("packages") or []
            if isinstance(package, dict)
            and package.get("parallelizable_in_wave")
            and package.get("depends_on_waves")
            and package.get("launcher_selected") is True
        }
    )
    if not dependent_waves:
        return True

    launcher_text_by_wave: dict[int, str] = {}
    for launcher_path in [*(manifest.get("launcher_paths") or []), *(manifest.get("staged_launcher_paths") or [])]:
        launcher_ref = normalize_artifact_ref(launcher_path)
        launcher_full_path = ROOT / launcher_ref
        if not launcher_ref or not launcher_full_path.exists():
            return False
        launcher_text = launcher_full_path.read_text(encoding="utf-8")
        match = re.search(r"(?m)^# Wave: (\d+)\s*$", launcher_text)
        if match:
            launcher_text_by_wave[int(match.group(1))] = launcher_text

    required_markers = [
        "TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH",
        "dispatch_manifest.json",
        "Dependent wave evidence missing",
        "missing_json_output",
        "expected_profile_ids",
        "quality_gate_not_passed",
        "staged_launcher_selected",
        "missing_dependency_packages",
        "Split-Path -Parent $LauncherDir",
        "AgentId may only contain letters",
    ]
    for wave in dependent_waves:
        launcher_text = launcher_text_by_wave.get(wave)
        if not launcher_text:
            return False
        if not all(marker in launcher_text for marker in required_markers):
            return False
    return True


def dispatch_archived_one_shot_runner_guard_present(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    runner_path = normalize_artifact_ref(manifest.get("dispatch_runner_path"))
    if not runner_path:
        return False
    runner_full_path = ROOT / runner_path
    if not runner_full_path.exists():
        return False
    runner_text = runner_full_path.read_text(encoding="utf-8")
    required_markers = [
        "TAMANDUA_ALLOW_ONE_SHOT_DISPATCH",
        "TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH",
        "TAMANDUA_DISPATCH_AGENT_ID",
        "AgentId may only contain letters",
        "ClaimLockHelperPath",
        "Missing claim lock helper",
        "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
        "$env:TAMANDUA_AGENT_ID = $script:DispatchAgentId",
        "-File $script:ClaimLockHelperPath -ClaimId $ClaimId -AgentId $script:DispatchAgentId",
        "claim lock exit",
        "DispatchFailures",
        "FailedWaves",
        "Write-DispatchBlockedPackageStatus",
        "Write-DispatchBlockedWaveStatuses",
        "claim_id = 'claim-' + [string]$Package.package_id",
        "agent_id = $script:DispatchAgentId",
        "status = 'blocked'",
        "exit_code = 2",
        "missing_profiles = $ExpectedProfiles",
        "Test-DispatchWaveDependencies",
        "skipped because dependency wave failed",
        "skipped because dependency evidence missing",
        "Invoke-DispatchCommand",
        "Dispatch one-shot completed with failures",
        "--summarize-dispatch",
        "--promote-dispatch-results",
        "generate_validation_scorecard.py",
        "validation_status_consistency.py",
    ]
    if not all(marker in runner_text for marker in required_markers):
        return False
    if "--refresh-scorecard" in runner_text:
        return False
    staged_paths = [normalize_artifact_ref(path) for path in manifest.get("staged_launcher_paths") or []]
    if staged_paths and not any(path in runner_text for path in staged_paths):
        return False
    staged_required_markers = [
        "StageFailures",
        "Failed package jobs across staged wave",
        "stage ",
    ]
    for staged_path in staged_paths:
        staged_full_path = ROOT / staged_path
        if not staged_path or not staged_full_path.exists():
            return False
        staged_text = staged_full_path.read_text(encoding="utf-8")
        if not all(marker in staged_text for marker in staged_required_markers):
            return False
    return True


def dispatch_archived_env_checklist_includes_operator_input_details(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    checklist_path = normalize_artifact_ref(manifest.get("env_checklist_path"))
    if not checklist_path:
        return False
    checklist_full_path = ROOT / checklist_path
    if not checklist_full_path.exists():
        return False
    checklist_text = checklist_full_path.read_text(encoding="utf-8")
    if "| Flag | Description |" not in checklist_text:
        return False

    rows: dict[tuple[str, str], dict[str, str]] = {}
    for line in checklist_text.splitlines():
        if not line.startswith("|") or "`" not in line:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 9:
            continue
        package_id = cells[1].strip("`")
        env_name = cells[2].strip("`")
        rows[(package_id, env_name)] = {
            "flag": cells[6].strip("`"),
            "description": cells[7].strip(),
        }

    checked = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        env_details = package.get("env_details") if isinstance(package.get("env_details"), dict) else {}
        for item in package.get("operator_inputs") or []:
            if not isinstance(item, dict) or not item.get("env"):
                continue
            env_name = str(item.get("env"))
            row = rows.get((package_id, env_name))
            if not row:
                return False
            expected_flag = str(item.get("flag") or "-")
            expected_description = str(item.get("description") or "-")
            if row["flag"] != expected_flag:
                return False
            if row["description"] != expected_description:
                return False
            manifest_detail = env_details.get(env_name)
            if not isinstance(manifest_detail, dict):
                return False
            if str(manifest_detail.get("name") or "") != str(item.get("name") or ""):
                return False
            if str(manifest_detail.get("flag") or "") != str(item.get("flag") or ""):
                return False
            if str(manifest_detail.get("description") or "") != str(item.get("description") or ""):
                return False
            checked += 1
    return checked > 0


def dispatch_archived_env_template_is_redacted_and_complete(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    template_path = normalize_artifact_ref(manifest.get("env_template_path"))
    if not template_path:
        return False
    template_full_path = ROOT / template_path
    if not template_full_path.exists():
        return False
    template_text = template_full_path.read_text(encoding="utf-8")
    if "# Validation env handoff template" not in template_text:
        return False
    if "placeholder values only" not in template_text:
        return False
    if "<set-" not in template_text:
        return False

    expected_env: set[str] = set()
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for env_name in package.get("effective_required_env") or []:
            if isinstance(env_name, str) and env_name.strip():
                expected_env.add(env_name)
    if not expected_env:
        return False

    for env_name in expected_env:
        marker = f"$env:{env_name} = '<set-{env_name.lower().replace('_', '-')}"
        if marker not in template_text:
            return False
    assignment_values = re.findall(r"(?m)^\$env:[A-Z0-9_]+\s*=\s*'([^']*)'", template_text)
    return bool(assignment_values) and all(value.startswith("<set-") and value.endswith(">") for value in assignment_values)


def dispatch_archived_owner_launch_plan_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_path"))
    if not plan_path:
        return False
    plan_full_path = ROOT / plan_path
    if not plan_full_path.exists():
        return False
    plan_text = plan_full_path.read_text(encoding="utf-8")
    if "# Validation Owner Launch Plan" not in plan_text:
        return False
    if "| Wave | Stage | Package | Launch mode | Depends | Missing env | Command | Prompt |" not in plan_text:
        return False
    if manifest.get("env_checklist_path") and normalize_artifact_ref(manifest.get("env_checklist_path")) not in plan_text:
        return False
    if manifest.get("env_template_path") and normalize_artifact_ref(manifest.get("env_template_path")) not in plan_text:
        return False
    if dispatch_archived_owner_launch_plan_json_matches_manifest(dispatch_artifact):
        return True

    checked = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        owner = str(package.get("recommended_owner_role") or "unassigned")
        script_path = normalize_artifact_ref(package.get("script_path"))
        prompt_path = normalize_artifact_ref(package.get("prompt_path"))
        if not package_id or not owner or not script_path:
            return False
        if f"## Owner: {owner}" not in plan_text:
            return False
        if f"`{package_id}`" not in plan_text:
            return False
        if f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_path}'" not in plan_text:
            return False
        if prompt_path and prompt_path not in plan_text:
            return False
        for env_name in package.get("effective_required_env") or []:
            if isinstance(env_name, str) and env_name.strip() and env_name not in plan_text:
                return False
        checked += 1
    return checked > 0


def dispatch_archived_owner_launch_plan_json_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_json_path"))
    if not plan_path:
        return False
    plan_full_path = ROOT / plan_path
    if not plan_full_path.exists():
        return False
    try:
        plan = load_json(plan_full_path)
    except json.JSONDecodeError:
        return False
    if plan.get("schema_version") != 1 or plan.get("artifact") != "validation-owner-launch-plan":
        return False
    packages = [package for package in manifest.get("packages") or [] if isinstance(package, dict)]
    owners = [owner for owner in plan.get("owners") or [] if isinstance(owner, dict)]
    if plan.get("package_count") != len(packages):
        return False
    if plan.get("owner_count") != len(owners):
        return False
    if manifest.get("env_checklist_path") and normalize_artifact_ref(manifest.get("env_checklist_path")) != normalize_artifact_ref(plan.get("env_checklist_path")):
        return False
    if manifest.get("env_template_path") and normalize_artifact_ref(manifest.get("env_template_path")) != normalize_artifact_ref(plan.get("env_template_path")):
        return False

    plan_packages: dict[str, dict[str, Any]] = {}
    launchable_package_count = 0
    blocked_package_count = 0
    for owner in owners:
        owner_name = str(owner.get("owner") or "")
        owner_packages = [package for package in owner.get("packages") or [] if isinstance(package, dict)]
        if owner.get("package_count") != len(owner_packages):
            return False
        owner_launchable_count = sum(1 for package in owner_packages if package.get("ready_to_launch") is True)
        if owner.get("launchable_package_count") != owner_launchable_count:
            return False
        if owner.get("blocked_package_count") != len(owner_packages) - owner_launchable_count:
            return False
        launchable_package_count += owner_launchable_count
        blocked_package_count += len(owner_packages) - owner_launchable_count
        for package in owner_packages:
            package_id = str(package.get("package_id") or "")
            if not package_id or package_id in plan_packages:
                return False
            if owner_name != str(package.get("owner") or owner_name):
                package["owner"] = owner_name
            plan_packages[package_id] = package

    if set(plan_packages) != {str(package.get("package_id") or "") for package in packages}:
        return False
    dispatch_packages_by_id = {
        str(package.get("package_id") or ""): package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict)
    }
    for manifest_package in packages:
        package_id = str(manifest_package.get("package_id") or "")
        plan_package = plan_packages.get(package_id)
        if not plan_package:
            return False
        script_path = normalize_artifact_ref(manifest_package.get("script_path"))
        prompt_path = normalize_artifact_ref(manifest_package.get("prompt_path"))
        status_path = normalize_artifact_ref(manifest_package.get("status_path"))
        if normalize_artifact_ref(plan_package.get("script_path")) != script_path:
            return False
        if prompt_path and normalize_artifact_ref(plan_package.get("prompt_path")) != prompt_path:
            return False
        if status_path and normalize_artifact_ref(plan_package.get("status_path")) != status_path:
            return False
        status_full_path = ROOT / status_path if status_path else None
        if status_full_path and status_full_path.exists():
            try:
                status_payload = load_json(status_full_path)
            except json.JSONDecodeError:
                return False
            dispatch_package = dispatch_packages_by_id.get(package_id) or {}
            stale_handoff_before_pass = (
                dispatch_package.get("status") == "pass"
                and str(plan_package.get("current_status") or "") == "not_run"
                and plan_package.get("current_exit_code") is None
                and plan_package.get("current_blocker_cleared") is None
                and [str(value) for value in plan_package.get("current_notes") or []] == []
                and [str(value) for value in plan_package.get("current_missing_profiles") or []] == []
                and [normalize_artifact_ref(value) for value in plan_package.get("current_artifacts") or []] == []
            )
            if stale_handoff_before_pass:
                pass
            elif str(plan_package.get("current_status") or "") != str(status_payload.get("status") or ""):
                return False
            elif plan_package.get("current_exit_code") != status_payload.get("exit_code"):
                return False
            elif [str(value) for value in plan_package.get("current_notes") or []] != [
                str(value) for value in status_payload.get("notes") or []
            ]:
                return False
            elif [str(value) for value in plan_package.get("current_missing_profiles") or []] != [
                str(value) for value in status_payload.get("missing_profiles") or []
            ]:
                return False
            elif plan_package.get("current_blocker_cleared") != status_payload.get("blocker_cleared"):
                return False
            else:
                expected_artifacts = [normalize_artifact_ref(value) for value in status_payload.get("artifacts") or []]
                if [normalize_artifact_ref(value) for value in plan_package.get("current_artifacts") or []] != expected_artifacts:
                    return False
        else:
            if str(plan_package.get("current_status") or "") != "not_run":
                return False
            if plan_package.get("current_artifacts") not in (None, []):
                return False
        current_next_action = plan_package.get("current_next_action") if isinstance(plan_package.get("current_next_action"), dict) else {}
        current_next_action_env = [str(value) for value in current_next_action.get("required_env") or [] if str(value)]
        token_env = str(current_next_action.get("token_env") or "")
        if token_env and token_env not in current_next_action_env:
            current_next_action_env.append(token_env)
        expected_next_action_env = []
        for value in [str(value) for value in manifest_package.get("next_action_required_env") or []] + current_next_action_env:
            if value and value not in expected_next_action_env:
                expected_next_action_env.append(value)
        manifest_effective_env = [str(value) for value in manifest_package.get("effective_required_env") or []]
        manifest_required_env = [str(value) for value in manifest_package.get("required_env") or []]
        expected_effective_env = []
        for value in (manifest_effective_env or manifest_required_env) + expected_next_action_env:
            if value and value not in expected_effective_env:
                expected_effective_env.append(value)
        if "current_next_action_required_env" in plan_package and [
            str(value) for value in plan_package.get("current_next_action_required_env") or []
        ] != current_next_action_env:
            return False
        if "next_action_required_env" in plan_package and [
            str(value) for value in plan_package.get("next_action_required_env") or []
        ] != expected_next_action_env:
            return False
        if "effective_required_env" in plan_package and [
            str(value) for value in plan_package.get("effective_required_env") or []
        ] != expected_effective_env:
            return False
        if str(plan_package.get("command") or "") != f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_path}'":
            return False
        if not set(str(value) for value in plan_package.get("missing_effective_env") or []).issubset(
            set(expected_effective_env)
        ):
            return False
        if [int(value) for value in plan_package.get("depends_on_waves") or []] != [
            int(value) for value in manifest_package.get("depends_on_waves") or []
        ]:
            return False
        expected_reasons = []
        if plan_package.get("missing_effective_env"):
            expected_reasons.append("missing_effective_env")
        if manifest_package.get("depends_on_waves"):
            expected_reasons.append("depends_on_prior_waves")
        if manifest_package.get("launcher_selected") is False and not str(
            manifest_package.get("manual_reason") or ""
        ).startswith("blocked:"):
            expected_reasons.append("manual_launch_required")
        if [str(value) for value in plan_package.get("blocked_reasons") or []] != expected_reasons:
            return False
        if bool(plan_package.get("ready_to_launch")) != (not expected_reasons):
            return False
    if plan.get("launchable_package_count") != launchable_package_count:
        return False
    if plan.get("blocked_package_count") != blocked_package_count:
        return False
    return True


def dispatch_archived_execution_matrix_matches_owner_plan(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    matrix_path = normalize_artifact_ref(manifest.get("execution_matrix_path"))
    matrix_json_path = normalize_artifact_ref(manifest.get("execution_matrix_json_path"))
    if not matrix_path and not matrix_json_path:
        return True
    if not matrix_path or not matrix_json_path:
        return False
    matrix_full_path = ROOT / matrix_path
    matrix_json_full_path = ROOT / matrix_json_path
    if not matrix_full_path.exists() or not matrix_json_full_path.exists():
        return False
    matrix_text = matrix_full_path.read_text(encoding="utf-8")
    if "# Validation Execution Matrix" not in matrix_text:
        return False
    if "| Wave | Stage | Owner | Package | Current | Ready | Blockers | Missing env | Artifacts | Next action | Command |" not in matrix_text:
        return False

    plan_path = normalize_artifact_ref(manifest.get("owner_launch_plan_json_path"))
    if not plan_path:
        return False
    try:
        plan = load_json(ROOT / plan_path)
        matrix = load_json(matrix_json_full_path)
    except json.JSONDecodeError:
        return False
    if matrix.get("schema_version") != 1 or matrix.get("artifact") != "validation-execution-matrix":
        return False
    rows = [row for row in matrix.get("rows") or [] if isinstance(row, dict)]
    plan_rows = []
    for owner in plan.get("owners") or []:
        if not isinstance(owner, dict):
            continue
        owner_name = str(owner.get("owner") or "unassigned")
        for package in owner.get("packages") or []:
            if not isinstance(package, dict):
                continue
            plan_rows.append(
                {
                    "package_id": str(package.get("package_id") or ""),
                    "owner": owner_name,
                    "wave": int(package.get("wave") or 0),
                    "stage": package.get("stage"),
                    "current_status": str(package.get("current_status") or "not_run"),
                    "current_exit_code": package.get("current_exit_code"),
                    "ready_to_launch": bool(package.get("ready_to_launch")),
                    "blocked_reasons": [str(value) for value in package.get("blocked_reasons") or []],
                    "missing_effective_env": [str(value) for value in package.get("missing_effective_env") or []],
                    "depends_on_waves": [int(value) for value in package.get("depends_on_waves") or []],
                    "resource_tags": [str(value) for value in package.get("resource_tags") or []],
                    "launcher_selected": package.get("launcher_selected"),
                    "manual_reason": package.get("manual_reason"),
                    "current_artifacts": [str(value) for value in package.get("current_artifacts") or []],
                    "current_next_action": package.get("current_next_action") if isinstance(package.get("current_next_action"), dict) else {},
                    "command": str(package.get("command") or ""),
                    "script_path": str(package.get("script_path") or ""),
                    "prompt_path": package.get("prompt_path"),
                    "status_path": str(package.get("status_path") or ""),
                }
            )
    plan_rows.sort(
        key=lambda item: (
            int(item.get("wave") or 0),
            int(item.get("stage") or 999),
            str(item.get("owner") or ""),
            str(item.get("package_id") or ""),
        )
    )
    if rows != plan_rows:
        return False
    if matrix.get("package_count") != len(plan_rows):
        return False
    if matrix.get("ready_to_launch_count") != sum(1 for row in plan_rows if row.get("ready_to_launch") is True):
        return False
    if matrix.get("blocked_count") != sum(1 for row in plan_rows if row.get("ready_to_launch") is not True):
        return False
    for row in plan_rows:
        package_id = str(row.get("package_id") or "")
        if f"`{package_id}`" not in matrix_text:
            return False
        command = str(row.get("command") or "")
        if command and command not in matrix_text:
            return False
    return True


def dispatch_archived_agent_claims_match_execution_matrix(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    claims_path = normalize_artifact_ref(manifest.get("agent_claims_path"))
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_path and not claims_json_path:
        return True
    if not claims_path or not claims_json_path:
        return False
    claims_full_path = ROOT / claims_path
    claims_json_full_path = ROOT / claims_json_path
    if not claims_full_path.exists() or not claims_json_full_path.exists():
        return False
    claims_text = claims_full_path.read_text(encoding="utf-8")
    if "# Validation Agent Claims" not in claims_text:
        return False
    if "| Claim | Wave | Stage | Owner | Package | State | Current | Blockers | Missing env | Next action | Command |" not in claims_text:
        return False

    matrix_json_path = normalize_artifact_ref(manifest.get("execution_matrix_json_path"))
    if not matrix_json_path:
        return False
    try:
        matrix = load_json(ROOT / matrix_json_path)
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    if claims_payload.get("schema_version") != 1 or claims_payload.get("artifact") != "validation-agent-claims":
        return False
    expected_claims = []
    for row in matrix.get("rows") or []:
        if not isinstance(row, dict):
            continue
        package_id = str(row.get("package_id") or "")
        blocked_reasons = [str(value) for value in row.get("blocked_reasons") or []]
        blocked_reason_set = set(blocked_reasons)
        current_status = str(row.get("current_status") or "")
        if row.get("ready_to_launch") is True:
            claim_state = "ready_to_claim"
        elif "missing_effective_env" in blocked_reason_set:
            claim_state = "blocked_missing_env"
        elif "depends_on_prior_waves" in blocked_reason_set:
            claim_state = "blocked_dependency_wave"
        elif "manual_launch_required" in blocked_reason_set:
            claim_state = "manual_claim_required"
        elif current_status in {"pass", "fail", "blocked"}:
            claim_state = f"has_current_{current_status}_evidence"
        else:
            claim_state = "not_ready"
        expected_claims.append(
            {
                "claim_id": f"claim-{package_id}",
                "package_id": package_id,
                "owner": str(row.get("owner") or "unassigned"),
                "wave": int(row.get("wave") or 0),
                "stage": row.get("stage"),
                "claim_state": claim_state,
                "ready_to_launch": bool(row.get("ready_to_launch")),
                "current_status": str(row.get("current_status") or "not_run"),
                "blocked_reasons": blocked_reasons,
                "missing_effective_env": [str(value) for value in row.get("missing_effective_env") or []],
                "depends_on_waves": [int(value) for value in row.get("depends_on_waves") or []],
                "resource_tags": [str(value) for value in row.get("resource_tags") or []],
                "current_artifacts": [str(value) for value in row.get("current_artifacts") or []],
                "current_next_action": row.get("current_next_action") if isinstance(row.get("current_next_action"), dict) else {},
                "command": str(row.get("command") or ""),
                "script_path": str(row.get("script_path") or ""),
                "prompt_path": row.get("prompt_path"),
                "status_path": str(row.get("status_path") or ""),
                "claim_output": {
                    "status_file": "agent_status.json",
                    "allowed_status": ["pass", "fail", "blocked"],
                    "must_update_current_status": True,
                },
            }
        )
    expected_claims.sort(key=lambda item: (int(item.get("wave") or 0), int(item.get("stage") or 999), str(item.get("claim_id") or "")))
    actual_claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    if actual_claims != expected_claims:
        return False
    if claims_payload.get("claim_count") != len(expected_claims):
        return False
    if claims_payload.get("ready_to_claim_count") != sum(1 for claim in expected_claims if claim.get("claim_state") == "ready_to_claim"):
        return False
    if claims_payload.get("blocked_claim_count") != sum(1 for claim in expected_claims if str(claim.get("claim_state") or "").startswith("blocked_")):
        return False
    if claims_payload.get("manual_claim_count") != sum(1 for claim in expected_claims if claim.get("claim_state") == "manual_claim_required"):
        return False
    for claim in expected_claims:
        claim_id = str(claim.get("claim_id") or "")
        if f"`{claim_id}`" not in claims_text:
            return False
        command = str(claim.get("command") or "")
        if command and command not in claims_text:
            return False
    return True


def dispatch_archived_agent_spawn_plan_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    plan_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_path"))
    plan_json_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path"))
    if not plan_path and not plan_json_path:
        return True
    if not plan_path or not plan_json_path:
        return False
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    claim_lock_helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if not claims_json_path or not claim_lock_helper_path:
        return False
    plan_full_path = ROOT / plan_path
    plan_json_full_path = ROOT / plan_json_path
    claims_json_full_path = ROOT / claims_json_path
    if not plan_full_path.exists() or not plan_json_full_path.exists() or not claims_json_full_path.exists():
        return False
    plan_text = plan_full_path.read_text(encoding="utf-8")
    if "# Validation Agent Spawn Plan" not in plan_text:
        return False
    try:
        plan = load_json(plan_json_full_path)
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    if plan.get("schema_version") != 1 or plan.get("artifact") != "validation-agent-spawn-plan":
        return False
    claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    ready_claims = [claim for claim in claims if claim.get("claim_state") == "ready_to_claim"]
    blocked_or_manual_claims = [claim for claim in claims if claim.get("claim_state") != "ready_to_claim"]
    env_bundle_ready_claims = [
        claim
        for claim in claims
        if [str(value) for value in claim.get("missing_effective_env") or []]
        and {str(value) for value in claim.get("blocked_reasons") or []} <= {"missing_effective_env"}
    ]
    env_bundle_still_blocked_claims = [
        claim
        for claim in claims
        if [str(value) for value in claim.get("missing_effective_env") or []]
        and {str(value) for value in claim.get("blocked_reasons") or []} > {"missing_effective_env"}
    ]
    spawn_claims = [
        claim
        for batch in plan.get("batches") or []
        if isinstance(batch, dict)
        for claim in batch.get("claims") or []
        if isinstance(claim, dict)
    ]
    env_bundle_spawn_claims = [
        claim
        for batch in plan.get("env_bundle_ready_batches") or []
        if isinstance(batch, dict)
        for claim in batch.get("claims") or []
        if isinstance(claim, dict)
    ]
    if plan.get("ready_claim_count") != len(ready_claims):
        return False
    current_env_multi_agent_actionable = len(ready_claims) >= 2
    if plan.get("current_env_multi_agent_actionable") is not current_env_multi_agent_actionable:
        return False
    if (
        f"- Current-env multi-agent actionable: `{str(current_env_multi_agent_actionable).lower()}`"
        not in plan_text
    ):
        return False
    if (
        ready_claims
        and "| Claim | Owner | Package | Resources | Next action | Prompt | Codex template | Claude template | Lock command | Run command | Status |"
        not in plan_text
    ):
        return False
    if plan.get("blocked_or_manual_claim_count") != len(blocked_or_manual_claims):
        return False
    if plan.get("env_bundle_ready_claim_count") != len(env_bundle_ready_claims):
        return False
    post_env_bundle_multi_agent_actionable = len(env_bundle_ready_claims) >= 2
    if plan.get("post_env_bundle_multi_agent_actionable") is not post_env_bundle_multi_agent_actionable:
        return False
    if (
        f"- Post-env-bundle multi-agent actionable: `{str(post_env_bundle_multi_agent_actionable).lower()}`"
        not in plan_text
    ):
        return False
    if plan.get("env_bundle_ready_batch_count") != len(plan.get("env_bundle_ready_batches") or []):
        return False
    if plan.get("env_bundle_still_blocked_claim_count") != len(env_bundle_still_blocked_claims):
        return False
    if len(env_bundle_spawn_claims) != len(env_bundle_ready_claims):
        return False
    if env_bundle_ready_claims and "## Ready After Env Bundle" not in plan_text:
        return False
    if env_bundle_ready_claims and "### Copy/Paste Env-Bundle Spawn Prompts" not in plan_text:
        return False
    if env_bundle_still_blocked_claims and "## Still Blocked After Env Bundle" not in plan_text:
        return False
    if len(spawn_claims) != len(ready_claims):
        return False
    if plan.get("ready_batch_count") != len(plan.get("batches") or []):
        return False
    if len(ready_claims) < 2 and plan.get("not_multi_agent_actionable_reason") != "fewer than two ready claims":
        return False
    if len(ready_claims) >= 2 and plan.get("not_multi_agent_actionable_reason"):
        return False
    if (
        len(env_bundle_ready_claims) < 2
        and plan.get("post_env_bundle_not_multi_agent_actionable_reason")
        != "fewer than two env-bundle ready claims"
    ):
        return False
    if len(env_bundle_ready_claims) >= 2 and plan.get("post_env_bundle_not_multi_agent_actionable_reason"):
        return False
    if normalize_artifact_ref(plan.get("claim_lock_helper_path")) != claim_lock_helper_path:
        return False
    if "--refresh-claim-status-report" not in str(plan.get("refresh_command") or ""):
        return False
    ready_by_id = {str(claim.get("claim_id") or ""): claim for claim in ready_claims}
    seen_ready_ids = set()
    for spawn_claim in spawn_claims:
        claim_id = str(spawn_claim.get("claim_id") or "")
        source_claim = ready_by_id.get(claim_id)
        if not source_claim:
            return False
        seen_ready_ids.add(claim_id)
        for field in ("package_id", "owner", "prompt_path", "script_path", "status_path"):
            if normalize_artifact_ref(spawn_claim.get(field)) != normalize_artifact_ref(source_claim.get(field)):
                return False
        if [str(value) for value in spawn_claim.get("resource_tags") or []] != [
            str(value) for value in source_claim.get("resource_tags") or []
        ]:
            return False
        if spawn_claim.get("current_next_action") != (
            source_claim.get("current_next_action") if isinstance(source_claim.get("current_next_action"), dict) else {}
        ):
            return False
        action_summary = render_current_next_action_summary(spawn_claim.get("current_next_action"))
        if action_summary != "-" and action_summary not in plan_text:
            return False
        if claim_id not in str(spawn_claim.get("lock_command") or ""):
            return False
        if claim_lock_helper_path not in str(spawn_claim.get("lock_command") or ""):
            return False
        if str(source_claim.get("command") or "") != str(spawn_claim.get("run_command") or ""):
            return False
        if spawn_claim.get("cwd") != ".":
            return False
        if spawn_claim.get("claim_id_env") != f"TAMANDUA_AGENT_CLAIM_ID={claim_id}":
            return False
        if spawn_claim.get("agent_id_env") != "TAMANDUA_AGENT_ID=<agent-id>":
            return False
        templates = spawn_claim.get("agent_spawn_command_templates") or {}
        for provider in ("codex", "claude"):
            template = str(templates.get(provider) or "")
            if provider not in template or claim_id not in template:
                return False
            if str(spawn_claim.get("prompt_path") or "") not in template:
                return False
            if claim_lock_helper_path not in template or "-ClaimId" not in template or "-AgentId" not in template:
                return False
            if "exit $LASTEXITCODE" not in template:
                return False
        prompt_text = str(spawn_claim.get("prompt_text") or "")
        copy_paste_prompt = str(spawn_claim.get("copy_paste_prompt") or "")
        if not prompt_text.strip() or not copy_paste_prompt.strip():
            return False
        for required_text in [
            claim_id,
            str(spawn_claim.get("package_id") or ""),
            str(spawn_claim.get("prompt_path") or ""),
            f"Working directory: {spawn_claim.get('cwd')}",
            str(spawn_claim.get("claim_id_env") or ""),
            str(spawn_claim.get("agent_id_env") or ""),
            str(spawn_claim.get("lock_command") or ""),
            str(spawn_claim.get("run_command") or ""),
            str(templates.get("codex") or ""),
            str(templates.get("claude") or ""),
            prompt_text,
        ]:
            if required_text and required_text not in copy_paste_prompt:
                return False
        if "### Copy/Paste Spawn Prompts" not in plan_text:
            return False
        if copy_paste_prompt not in plan_text:
            return False
        if f"`{claim_id}`" not in plan_text:
            return False
    if seen_ready_ids != set(ready_by_id):
        return False
    env_ready_by_id = {str(claim.get("claim_id") or ""): claim for claim in env_bundle_ready_claims}
    seen_env_ready_ids = set()
    for spawn_claim in env_bundle_spawn_claims:
        claim_id = str(spawn_claim.get("claim_id") or "")
        source_claim = env_ready_by_id.get(claim_id)
        if not source_claim:
            return False
        seen_env_ready_ids.add(claim_id)
        for field in ("package_id", "owner", "prompt_path", "script_path", "status_path"):
            if normalize_artifact_ref(spawn_claim.get(field)) != normalize_artifact_ref(source_claim.get(field)):
                return False
        if [str(value) for value in spawn_claim.get("resource_tags") or []] != [
            str(value) for value in source_claim.get("resource_tags") or []
        ]:
            return False
        if spawn_claim.get("current_next_action") != (
            source_claim.get("current_next_action") if isinstance(source_claim.get("current_next_action"), dict) else {}
        ):
            return False
        action_summary = render_current_next_action_summary(spawn_claim.get("current_next_action"))
        if action_summary != "-" and action_summary not in plan_text:
            return False
        if claim_id not in str(spawn_claim.get("lock_command") or ""):
            return False
        if claim_lock_helper_path not in str(spawn_claim.get("lock_command") or ""):
            return False
        if str(source_claim.get("command") or "") != str(spawn_claim.get("run_command") or ""):
            return False
        if spawn_claim.get("cwd") != ".":
            return False
        if spawn_claim.get("claim_id_env") != f"TAMANDUA_AGENT_CLAIM_ID={claim_id}":
            return False
        if spawn_claim.get("agent_id_env") != "TAMANDUA_AGENT_ID=<agent-id>":
            return False
        templates = spawn_claim.get("agent_spawn_command_templates") or {}
        for provider in ("codex", "claude"):
            template = str(templates.get(provider) or "")
            if provider not in template or claim_id not in template:
                return False
            if str(spawn_claim.get("prompt_path") or "") not in template:
                return False
            if claim_lock_helper_path not in template or "-ClaimId" not in template or "-AgentId" not in template:
                return False
            if "exit $LASTEXITCODE" not in template:
                return False
        prompt_text = str(spawn_claim.get("prompt_text") or "")
        copy_paste_prompt = str(spawn_claim.get("copy_paste_prompt") or "")
        if not prompt_text.strip() or not copy_paste_prompt.strip() or copy_paste_prompt not in plan_text:
            return False
        for required_text in [
            claim_id,
            str(spawn_claim.get("package_id") or ""),
            str(spawn_claim.get("prompt_path") or ""),
            f"Working directory: {spawn_claim.get('cwd')}",
            str(spawn_claim.get("claim_id_env") or ""),
            str(spawn_claim.get("agent_id_env") or ""),
            str(spawn_claim.get("lock_command") or ""),
            str(spawn_claim.get("run_command") or ""),
            str(templates.get("codex") or ""),
            str(templates.get("claude") or ""),
            prompt_text,
        ]:
            if required_text and required_text not in copy_paste_prompt:
                return False
    if seen_env_ready_ids != set(env_ready_by_id):
        return False
    env_still_ids = {str(claim.get("claim_id") or "") for claim in env_bundle_still_blocked_claims}
    plan_env_still_ids = {
        str(claim.get("claim_id") or "")
        for claim in plan.get("env_bundle_still_blocked_claims") or []
        if isinstance(claim, dict)
    }
    if plan_env_still_ids != env_still_ids:
        return False
    for source_claim in env_bundle_still_blocked_claims:
        claim_id = str(source_claim.get("claim_id") or "")
        plan_claim = next(
            (
                claim
                for claim in plan.get("env_bundle_still_blocked_claims") or []
                if isinstance(claim, dict) and str(claim.get("claim_id") or "") == claim_id
            ),
            {},
        )
        if plan_claim.get("current_next_action") != (
            source_claim.get("current_next_action") if isinstance(source_claim.get("current_next_action"), dict) else {}
        ):
            return False
    blocked_ids = {str(claim.get("claim_id") or "") for claim in blocked_or_manual_claims}
    plan_blocked_ids = {
        str(claim.get("claim_id") or "")
        for claim in plan.get("blocked_or_manual_claims") or []
        if isinstance(claim, dict)
    }
    if plan_blocked_ids != blocked_ids:
        return False
    for source_claim in blocked_or_manual_claims:
        claim_id = str(source_claim.get("claim_id") or "")
        plan_claim = next(
            (
                claim
                for claim in plan.get("blocked_or_manual_claims") or []
                if isinstance(claim, dict) and str(claim.get("claim_id") or "") == claim_id
            ),
            {},
        )
        if plan_claim.get("current_next_action") != (
            source_claim.get("current_next_action") if isinstance(source_claim.get("current_next_action"), dict) else {}
        ):
            return False
    return True


def dispatch_archived_agent_spawn_launcher_matches_spawn_plan(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    plan_json_path = normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path"))
    if not launcher_path and not plan_json_path:
        return True
    if not launcher_path or not plan_json_path:
        return False
    launcher_full_path = ROOT / launcher_path
    plan_json_full_path = ROOT / plan_json_path
    if not launcher_full_path.exists() or not plan_json_full_path.exists():
        return False
    launcher_text = launcher_full_path.read_text(encoding="utf-8")
    try:
        plan = load_json(plan_json_full_path)
    except json.JSONDecodeError:
        return False
    execute_policy = plan.get("execute_policy") or {}
    if execute_policy.get("one_provider_per_claim") is not True:
        return False
    if execute_policy.get("override_switch") != "-AllowDuplicateProviderPerClaim":
        return False
    if execute_policy.get("override_env") != "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM":
        return False
    if execute_policy.get("parallel_switch") != "-Parallel":
        return False
    for required_text in [
        "# Validation Agent Spawn Launcher",
        "[ValidateSet('codex','claude','all','balanced')]",
        "$BalancedProviderIndex = 0",
        "$Provider -eq 'balanced'",
        "$BalancedProvider = if (($script:BalancedProviderIndex % 2) -eq 0) { 'codex' } else { 'claude' }",
        "[ValidateSet('ready','env-bundle','all')]",
        "[switch]$ShowBlocked",
        "[switch]$AllowDuplicateProviderPerClaim",
        "[switch]$Parallel",
        "Group-Object claim_id",
        "Refusing to execute multiple providers for the same claim",
        "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM",
        "Refusing duplicate provider execution without TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1",
        "[duplicate-provider-override]",
        "Start-Job -Name ($Row.provider + '-' + $Row.claim_id)",
        "Remove-Job -Job $Job -Force",
        "Agent spawn parallel execution failed",
        "AgentId may only contain letters",
        "$SawResult = $false",
        "produced no result",
        "Agent spawn sequential execution failed",
        "Show-BlockedClaims",
        "Show-EnvBundleReadiness",
        "Get-EnvBundleRequiredEnv",
        "Assert-EnvBundleReadyForExecution",
        "[env-bundle-readiness] present=",
        "env_unblock_queue.json",
        "Env unblock queue contains an entry without env.",
        "Env unblock queue contains duplicate env entries:",
        "Env unblock queue missing ready_after_all_env_claim_ids.",
        "Env unblock queue ready_after_all_env_claim_ids mismatch:",
        "Env unblock queue missing still_blocked_after_all_env_claim_ids.",
        "Env unblock queue still_blocked_after_all_env_claim_ids mismatch:",
        "Env unblock queue missing required_env_names.",
        "Env unblock queue missing all_env_powershell_set_commands.",
        "Env unblock queue env set commands mismatch:",
        "$Plan.blocked_or_manual_claims",
        "Format-NextAction",
        "next_action=",
        "[blocked][",
        "TAMANDUA_SPAWN_AGENT_ID",
        "TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH",
        "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH",
        "Refusing to execute env-bundle spawn commands without TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH=1",
        "Refusing env-bundle spawn while env values are missing",
        "Refusing env-bundle spawn while placeholder env values remain",
        "Dry run only",
        "Invoke-Expression $Row.command",
        "if ($Phase -in @('ready','all')) { Add-SpawnRows @($Plan.batches) 'ready' }",
        "if ($Phase -in @('env-bundle','all')) { Add-SpawnRows @($Plan.env_bundle_ready_batches) 'env-bundle' }",
        plan_json_path,
    ]:
        if required_text not in launcher_text:
            return False
    for batch_key, phase_name in (("batches", "ready"), ("env_bundle_ready_batches", "env-bundle")):
        for batch in plan.get(batch_key) or []:
            if not isinstance(batch, dict):
                continue
            for claim in batch.get("claims") or []:
                if not isinstance(claim, dict):
                    continue
                claim_id = str(claim.get("claim_id") or "")
                if not claim_id:
                    return False
                templates = claim.get("agent_spawn_command_templates") or {}
                for provider in ("codex", "claude"):
                    template = str(templates.get(provider) or "")
                    if not template or provider not in template or claim_id not in template:
                        return False
                if phase_name not in launcher_text:
                    return False
    return True


def dispatch_archived_claim_status_report_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    report_path = normalize_artifact_ref(manifest.get("claim_status_report_path"))
    report_json_path = normalize_artifact_ref(manifest.get("claim_status_report_json_path"))
    if not report_path and not report_json_path:
        return True
    if not report_path or not report_json_path:
        return False
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    report_full_path = ROOT / report_path
    report_json_full_path = ROOT / report_json_path
    claims_json_full_path = ROOT / claims_json_path
    if not report_full_path.exists() or not report_json_full_path.exists() or not claims_json_full_path.exists():
        return False
    report_text = report_full_path.read_text(encoding="utf-8")
    if "# Validation Claim Status Report" not in report_text:
        return False
    if "| Claim | Wave | Stage | Owner | Package | State | Agent status | Agent claim | Agent id | Lock | Lock agent | Locked at | Exit | Missing env | Missing profiles | Artifacts | Next action | Command |" not in report_text:
        return False
    try:
        claims_payload = load_json(claims_json_full_path)
        report = load_json(report_json_full_path)
    except json.JSONDecodeError:
        return False
    if report.get("schema_version") != 1 or report.get("artifact") != "validation-claim-status-report":
        return False
    claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    report_claims = [claim for claim in report.get("claims") or [] if isinstance(claim, dict)]
    if report.get("claim_count") != len(claims):
        return False
    if report.get("ready_to_claim_count") != sum(1 for claim in claims if claim.get("claim_state") == "ready_to_claim"):
        return False
    if report.get("blocked_claim_count") != sum(1 for claim in claims if str(claim.get("claim_state") or "").startswith("blocked_")):
        return False
    if report.get("manual_claim_count") != sum(1 for claim in claims if claim.get("claim_state") == "manual_claim_required"):
        return False
    if report.get("locked_claim_count") != sum(
        1 for claim in report_claims if claim.get("lock_state") == "locked"
    ):
        return False
    if report.get("invalid_lock_count") != sum(
        1 for claim in report_claims if claim.get("lock_state") == "invalid"
    ):
        return False
    for required_text in [
        f"- Claims: `{report.get('claim_count')}`",
        f"- Ready to claim: `{report.get('ready_to_claim_count')}`",
        f"- Blocked: `{report.get('blocked_claim_count')}`",
        f"- Manual: `{report.get('manual_claim_count')}`",
        f"- Locked claims: `{report.get('locked_claim_count')}`",
        f"- Invalid locks: `{report.get('invalid_lock_count')}`",
        "- Status counts:",
    ]:
        if required_text not in report_text:
            return False
    claim_by_id = {str(claim.get("claim_id") or ""): claim for claim in claims}
    report_by_id = {str(claim.get("claim_id") or ""): claim for claim in report_claims}
    if set(claim_by_id) != set(report_by_id):
        return False
    status_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for claim_id, claim in claim_by_id.items():
        report_claim = report_by_id[claim_id]
        for field in [
            "package_id",
            "owner",
            "wave",
            "stage",
            "claim_state",
            "ready_to_launch",
            "script_path",
            "prompt_path",
            "status_path",
            "command",
            "current_next_action",
        ]:
            if report_claim.get(field) != claim.get(field):
                return False
        if [str(value) for value in report_claim.get("missing_effective_env") or []] != [
            str(value) for value in claim.get("missing_effective_env") or []
        ]:
            return False
        if [str(value) for value in report_claim.get("blocked_reasons") or []] != [
            str(value) for value in claim.get("blocked_reasons") or []
        ]:
            return False
        if [str(value) for value in report_claim.get("resource_tags") or []] != [
            str(value) for value in claim.get("resource_tags") or []
        ]:
            return False
        lock_state = str(report_claim.get("lock_state") or "")
        if lock_state not in {"unlocked", "locked", "invalid"}:
            return False
        lock_path = normalize_artifact_ref(report_claim.get("lock_path"))
        expected_lock_suffix = f"claim_locks/{claim_id}.claim-lock.json"
        if not lock_path or not lock_path.replace("\\", "/").endswith(expected_lock_suffix):
            return False
        if lock_state == "locked" and (
            not str(report_claim.get("lock_agent_id") or "") or not str(report_claim.get("locked_at") or "")
        ):
            return False
        if lock_state == "unlocked" and (
            str(report_claim.get("lock_agent_id") or "") or str(report_claim.get("locked_at") or "")
        ):
            return False
        current_status = str(claim.get("current_status") or "not_run")
        if str(report_claim.get("agent_status") or "") not in {current_status, "pass", "fail", "blocked", "invalid"}:
            return False
        status_path = normalize_artifact_ref(claim.get("status_path"))
        if status_path:
            status_full_path = ROOT / status_path
            if not status_full_path.exists():
                expected_agent_claim_id = ""
                expected_agent_id = ""
            else:
                try:
                    status_payload = load_json(status_full_path)
                except json.JSONDecodeError:
                    expected_agent_claim_id = ""
                    expected_agent_id = ""
                else:
                    expected_agent_claim_id = str(status_payload.get("claim_id") or f"claim-{claim.get('package_id') or ''}")
                    expected_agent_id = str(status_payload.get("agent_id") or "unknown-agent")
            if str(report_claim.get("agent_claim_id") or "") != expected_agent_claim_id:
                return False
            if str(report_claim.get("agent_id") or "") != expected_agent_id:
                return False
        elif str(report_claim.get("agent_claim_id") or "") or str(report_claim.get("agent_id") or ""):
            return False
        status = str(report_claim.get("agent_status") or "unknown")
        state = str(report_claim.get("claim_state") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        state_counts[state] = state_counts.get(state, 0) + 1
        if f"`{claim_id}`" not in report_text:
            return False
        agent_claim_id = str(report_claim.get("agent_claim_id") or "")
        if agent_claim_id and f"`{agent_claim_id}`" not in report_text:
            return False
        agent_id = str(report_claim.get("agent_id") or "")
        if agent_id and agent_id not in report_text:
            return False
    if report.get("status_counts") != dict(sorted(status_counts.items())):
        return False
    if report.get("claim_state_counts") != dict(sorted(state_counts.items())):
        return False
    return True


def dispatch_archived_claim_lock_helper_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if not helper_path:
        return True
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    helper_full_path = ROOT / helper_path
    claims_json_full_path = ROOT / claims_json_path
    if not helper_full_path.exists() or not claims_json_full_path.exists():
        return False
    helper_text = helper_full_path.read_text(encoding="utf-8")
    for required_text in [
        "# Validation Claim Lock Helper",
        "CreateNew",
        "claim_locks",
        "Unknown validation claim",
        "Claim already locked",
        "ConvertTo-Json",
        "[switch]$List",
        "[string]$ResetClaimId",
        "[switch]$ResetAll",
        "Refusing to reset claim lock without -Force",
        "Refusing to reset all claim locks without -Force",
        "AgentId may only contain letters",
    ]:
        if required_text not in helper_text:
            return False
    try:
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    known_claims_match = re.search(r"(?s)\$KnownClaims\s*=\s*@\((.*?)\)", helper_text)
    if not known_claims_match:
        return False
    known_claims = sorted(re.findall(r"'([^']+)'", known_claims_match.group(1)))
    claim_ids = sorted(
        str(claim.get("claim_id") or "")
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and str(claim.get("claim_id") or "")
    )
    if known_claims != claim_ids:
        return False
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        claim_id = str(claim.get("claim_id") or "")
        if claim_id and claim_id not in helper_text:
            return False
    return True


def dispatch_archived_env_unblock_queue_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    queue_json_path = normalize_artifact_ref(manifest.get("env_unblock_queue_json_path"))
    if not queue_path and not queue_json_path:
        return True
    if not queue_path or not queue_json_path:
        return False
    queue_full_path = ROOT / queue_path
    queue_json_full_path = ROOT / queue_json_path
    if not queue_full_path.exists() or not queue_json_full_path.exists():
        return False
    queue_text = queue_full_path.read_text(encoding="utf-8")
    if "# Validation Env Unblock Queue" not in queue_text:
        return False
    if "| Env | Owners | Claims | Single-env ready | Single-env still blocked | Immediate | Dependency | Manual | Set command | Claim IDs |" not in queue_text:
        return False

    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    try:
        claims_payload = load_json(ROOT / claims_json_path)
        queue = load_json(queue_json_full_path)
    except json.JSONDecodeError:
        return False
    if queue.get("schema_version") != 1 or queue.get("artifact") != "validation-env-unblock-queue":
        return False
    if (
        int_or_default(queue.get("env_count")) == 0
        and list(queue.get("entries") or []) == []
        and isinstance(queue.get("next_action_entries"), list)
        and int_or_default(queue.get("current_env_missing_count")) == 0
    ):
        return True
    env_entries: dict[str, dict[str, Any]] = {}
    next_action_env_entries: dict[str, dict[str, Any]] = {}
    claims = [claim for claim in claims_payload.get("claims") or [] if isinstance(claim, dict)]
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        next_action_env = [str(value) for value in next_action.get("required_env") or [] if str(value)]
        token_env = str(next_action.get("token_env") or "")
        if token_env:
            next_action_env.append(token_env)
        seen_next_action_env = set()
        for env_name in next_action_env:
            if env_name in seen_next_action_env:
                continue
            seen_next_action_env.add(env_name)
            entry = next_action_env_entries.setdefault(
                env_name,
                {
                    "env": env_name,
                    "owners": set(),
                    "claim_ids": [],
                    "package_ids": [],
                    "waves": set(),
                    "token_login_commands": set(),
                    "actions": [],
                },
            )
            entry["owners"].add(str(claim.get("owner") or "unassigned"))
            entry["claim_ids"].append(str(claim.get("claim_id") or ""))
            entry["package_ids"].append(str(claim.get("package_id") or ""))
            entry["waves"].add(int(claim.get("wave") or 0))
            if next_action.get("token_login_command"):
                entry["token_login_commands"].add(str(next_action.get("token_login_command")))
            if next_action.get("action"):
                entry["actions"].append(str(next_action.get("action")))
        for env_name in [str(value) for value in claim.get("missing_effective_env") or []]:
            entry = env_entries.setdefault(
                env_name,
                {
                    "env": env_name,
                    "owners": set(),
                    "claim_ids": [],
                    "package_ids": [],
                    "waves": set(),
                    "immediate_claim_ids": [],
                    "dependency_claim_ids": [],
                    "manual_claim_ids": [],
                    "next_action_summaries": [],
                    "direct_next_action_summaries": [],
                    "indirect_next_action_summaries": [],
                },
            )
            entry["owners"].add(str(claim.get("owner") or "unassigned"))
            claim_id = str(claim.get("claim_id") or "")
            entry["claim_ids"].append(claim_id)
            entry["package_ids"].append(str(claim.get("package_id") or ""))
            entry["waves"].add(int(claim.get("wave") or 0))
            next_action_summary = render_current_next_action_summary(claim.get("current_next_action"))
            if claim_id and next_action_summary != "-":
                summary = f"{claim_id}: {next_action_summary}"
                entry["next_action_summaries"].append(summary)
                current_next_action = claim.get("current_next_action")
                if next_action_summary_direct_for_env(
                    env_name,
                    current_next_action,
                    next_action_summary,
                ):
                    entry["direct_next_action_summaries"].append(summary)
                else:
                    entry["indirect_next_action_summaries"].append(summary)
            blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
            if "depends_on_prior_waves" in blocked_reasons:
                entry["dependency_claim_ids"].append(claim_id)
            elif "manual_launch_required" in blocked_reasons:
                entry["manual_claim_ids"].append(claim_id)
            else:
                entry["immediate_claim_ids"].append(claim_id)
    expected_entries = []
    for entry in env_entries.values():
        claim_ids = sorted(set(value for value in entry["claim_ids"] if value))
        immediate_claim_ids = sorted(set(value for value in entry["immediate_claim_ids"] if value))
        dependency_claim_ids = sorted(set(value for value in entry["dependency_claim_ids"] if value))
        manual_claim_ids = sorted(set(value for value in entry["manual_claim_ids"] if value))
        env_name = str(entry["env"])
        single_env_ready_claim_ids = []
        single_env_still_blocked_claim_ids = []
        remaining_env_after_setting: dict[str, list[str]] = {}
        for claim in claims:
            claim_id = str(claim.get("claim_id") or "")
            missing_env = [str(value) for value in claim.get("missing_effective_env") or []]
            if env_name not in missing_env:
                continue
            remaining_env = sorted(value for value in missing_env if value != env_name)
            remaining_env_after_setting[claim_id] = remaining_env
            blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
            if not remaining_env and blocked_reasons <= {"missing_effective_env"}:
                single_env_ready_claim_ids.append(claim_id)
            else:
                single_env_still_blocked_claim_ids.append(claim_id)
        expected_entries.append(
            {
                "env": env_name,
                "owners": sorted(entry["owners"]),
                "claim_ids": claim_ids,
                "package_ids": sorted(set(value for value in entry["package_ids"] if value)),
                "waves": sorted(entry["waves"]),
                "claim_count": len(claim_ids),
                "immediate_claim_count": len(immediate_claim_ids),
                "dependency_claim_count": len(dependency_claim_ids),
                "manual_claim_count": len(manual_claim_ids),
                "immediate_claim_ids": immediate_claim_ids,
                "dependency_claim_ids": dependency_claim_ids,
                "manual_claim_ids": manual_claim_ids,
                "single_env_ready_claim_ids": sorted(single_env_ready_claim_ids),
                "single_env_still_blocked_claim_ids": sorted(single_env_still_blocked_claim_ids),
                "remaining_env_after_setting": remaining_env_after_setting,
                "next_action_summaries": sorted(set(value for value in entry["next_action_summaries"] if value)),
                "direct_next_action_summaries": sorted(
                    set(value for value in entry["direct_next_action_summaries"] if value)
                ),
                "indirect_next_action_summaries": sorted(
                    set(value for value in entry["indirect_next_action_summaries"] if value)
                ),
            }
        )
    expected_entries.sort(
        key=lambda item: (
            -int(item.get("immediate_claim_count") or 0),
            -int(item.get("claim_count") or 0),
            str(item.get("env") or ""),
        )
    )
    expected_next_action_entries = []
    for entry in next_action_env_entries.values():
        claim_ids = sorted(set(value for value in entry["claim_ids"] if value))
        env_name = str(entry["env"])
        expected_next_action_entries.append(
            {
                "env": env_name,
                "owners": sorted(entry["owners"]),
                "claim_ids": claim_ids,
                "package_ids": sorted(set(value for value in entry["package_ids"] if value)),
                "waves": sorted(entry["waves"]),
                "claim_count": len(claim_ids),
                "token_login_commands": sorted(entry["token_login_commands"]),
                "actions": sorted(set(value for value in entry["actions"] if value)),
            }
        )
    existing_next_action_env = {str(entry.get("env") or "") for entry in expected_next_action_entries}
    for entry in expected_entries:
        env_name = str(entry.get("env") or "")
        if not env_name or env_name in existing_next_action_env:
            continue
        direct_next_action_summaries = [
            str(value) for value in entry.get("direct_next_action_summaries") or [] if value
        ]
        if not direct_next_action_summaries:
            continue
        expected_next_action_entries.append(
            {
                "env": env_name,
                "owners": [str(value) for value in entry.get("owners") or []],
                "claim_ids": [str(value) for value in entry.get("claim_ids") or []],
                "package_ids": [str(value) for value in entry.get("package_ids") or []],
                "waves": [int(value) for value in entry.get("waves") or []],
                "claim_count": int(entry.get("claim_count") or 0),
                "token_login_commands": [],
                "actions": direct_next_action_summaries,
            }
        )
        existing_next_action_env.add(env_name)
    expected_next_action_entries.sort(
        key=lambda item: (
            -int(item.get("claim_count") or 0),
            str(item.get("env") or ""),
        )
    )
    queue_entries = [entry for entry in queue.get("entries") or [] if isinstance(entry, dict)]
    comparable_queue_entries = [
        {
            key: value
            for key, value in entry.items()
            if key not in ("placeholder", "powershell_set_command", "copy_paste_unblock_prompt")
        }
        for entry in queue_entries
    ]
    if comparable_queue_entries != expected_entries:
        return False
    queue_next_action_entries = [
        entry for entry in queue.get("next_action_entries") or [] if isinstance(entry, dict)
    ]
    comparable_queue_next_action_entries = [
        {
            key: value
            for key, value in entry.items()
            if key not in ("placeholder", "powershell_set_command")
        }
        for entry in queue_next_action_entries
    ]
    if comparable_queue_next_action_entries != expected_next_action_entries:
        return False
    if queue.get("env_count") != len(expected_entries):
        return False
    if queue.get("next_action_env_count") != len(expected_next_action_entries):
        return False
    if queue.get("blocked_claim_count") != int(claims_payload.get("blocked_claim_count") or 0):
        return False
    all_env_names = {str(entry.get("env") or "") for entry in expected_entries}
    if queue.get("required_env_names") != sorted(all_env_names):
        return False
    expected_ready_after_all = []
    expected_still_blocked_after_all = []
    for claim in claims:
        claim_id = str(claim.get("claim_id") or "")
        missing_env = {str(value) for value in claim.get("missing_effective_env") or []}
        if not missing_env:
            continue
        remaining_env = missing_env - all_env_names
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
        if not remaining_env and blocked_reasons <= {"missing_effective_env"}:
            expected_ready_after_all.append(claim_id)
        else:
            expected_still_blocked_after_all.append(claim_id)
    expected_all_env_commands = [
        f"$env:{entry.get('env')} = '{env_template_placeholder(str(entry.get('env') or ''))}'"
        for entry in expected_entries
    ]
    expected_next_action_env_commands = [
        f"$env:{entry.get('env')} = '{env_template_placeholder(str(entry.get('env') or ''))}'"
        for entry in expected_next_action_entries
    ]
    if queue.get("all_env_powershell_set_commands") != expected_all_env_commands:
        return False
    if queue.get("next_action_env_powershell_set_commands") != expected_next_action_env_commands:
        return False
    current_present_names = sorted(str(value) for value in queue.get("current_env_present_names") or [])
    current_missing_names = sorted(str(value) for value in queue.get("current_env_missing_names") or [])
    current_placeholder_names = sorted(str(value) for value in queue.get("current_env_placeholder_names") or [])
    if (
        set(current_present_names) & set(current_missing_names)
        or set(current_present_names) & set(current_placeholder_names)
        or set(current_missing_names) & set(current_placeholder_names)
    ):
        return False
    if sorted(set(current_present_names) | set(current_missing_names) | set(current_placeholder_names)) != sorted(all_env_names):
        return False
    if queue.get("current_env_present_count") != len(current_present_names):
        return False
    if queue.get("current_env_missing_count") != len(current_missing_names):
        return False
    if queue.get("current_env_placeholder_count") != len(current_placeholder_names):
        return False
    expected_ready_with_current = []
    expected_still_blocked_with_current = []
    current_unready_set = set(current_missing_names) | set(current_placeholder_names)
    for claim in claims:
        claim_id = str(claim.get("claim_id") or "")
        missing_env = {str(value) for value in claim.get("missing_effective_env") or []}
        if not missing_env:
            continue
        remaining_current_env = missing_env & current_unready_set
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or []}
        if not remaining_current_env and blocked_reasons <= {"missing_effective_env"}:
            expected_ready_with_current.append(claim_id)
        else:
            expected_still_blocked_with_current.append(claim_id)
    if queue.get("ready_with_current_env_claim_ids") != sorted(expected_ready_with_current):
        return False
    if queue.get("still_blocked_with_current_env_claim_ids") != sorted(expected_still_blocked_with_current):
        return False
    if f"- Current env present: `{len(current_present_names)}`" not in queue_text:
        return False
    if f"- Current env missing: `{len(current_missing_names)}`" not in queue_text:
        return False
    if f"- Current env placeholders: `{len(current_placeholder_names)}`" not in queue_text:
        return False
    ready_with_current_text = ", ".join(sorted(expected_ready_with_current)) or "-"
    still_blocked_with_current_text = ", ".join(sorted(expected_still_blocked_with_current)) or "-"
    if f"- Claims ready with current env: `{ready_with_current_text}`" not in queue_text:
        return False
    if f"- Claims still blocked with current env: `{still_blocked_with_current_text}`" not in queue_text:
        return False
    env_bundle_launcher_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    agent_spawn_launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    expected_post_env_bundle_launcher_commands = []
    expected_post_env_bundle_balanced_agent_spawn_commands = []
    expected_env_bundle_validation_command = ""
    if expected_ready_after_all:
        if not env_bundle_launcher_path or not agent_spawn_launcher_path:
            return False
        expected_env_bundle_validation_command = (
            f"powershell -NoProfile -ExecutionPolicy Bypass -File '{env_bundle_launcher_path}' -ValidateOnly"
        )
        expected_post_env_bundle_launcher_commands = [
            "$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
            f"powershell -NoProfile -ExecutionPolicy Bypass -File '{env_bundle_launcher_path}'",
        ]
        expected_post_env_bundle_balanced_agent_spawn_commands = [
            "$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'",
            "$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
            (
                f"powershell -NoProfile -ExecutionPolicy Bypass -File '{agent_spawn_launcher_path}' "
                "-Provider balanced -Phase env-bundle -Execute -Parallel"
            ),
        ]
    if queue.get("env_bundle_validation_command") != expected_env_bundle_validation_command:
        return False
    if queue.get("post_env_bundle_launcher_commands") != expected_post_env_bundle_launcher_commands:
        return False
    if queue.get("post_env_bundle_balanced_agent_spawn_commands") != expected_post_env_bundle_balanced_agent_spawn_commands:
        return False
    if queue.get("ready_after_all_env_claim_ids") != sorted(expected_ready_after_all):
        return False
    if queue.get("still_blocked_after_all_env_claim_ids") != sorted(expected_still_blocked_after_all):
        return False
    if "## Copy/Paste Complete Env Bundle" not in queue_text:
        return False
    for command in expected_all_env_commands:
        if command not in queue_text:
            return False
    for entry in expected_entries:
        next_action_summaries = [str(value) for value in entry.get("next_action_summaries") or [] if str(value)]
        if not next_action_summaries:
            continue
        direct_next_action_summaries = [
            str(value) for value in entry.get("direct_next_action_summaries") or [] if str(value)
        ]
        indirect_next_action_summaries = [
            str(value) for value in entry.get("indirect_next_action_summaries") or [] if str(value)
        ]
        expected_direct_next_action_line = (
            "Direct claim next actions: " + (" | ".join(direct_next_action_summaries) or "-")
        )
        if expected_direct_next_action_line not in queue_text:
            return False
        expected_indirect_next_action_line = (
            "Other affected claim next actions: " + (" | ".join(indirect_next_action_summaries) or "-")
        )
        if expected_indirect_next_action_line not in queue_text:
            return False
        expected_next_action_line = "Affected claim next actions: " + " | ".join(next_action_summaries)
        if expected_next_action_line not in queue_text:
            return False
    if expected_next_action_env_commands:
        if "## Copy/Paste Next-Action Env Commands" not in queue_text:
            return False
        if "## Next-Action Env Follow-Ups" not in queue_text:
            return False
        for command in expected_next_action_env_commands:
            if command not in queue_text:
                return False
        for entry in expected_next_action_entries:
            env_name = str(entry.get("env") or "")
            if f"`{env_name}`" not in queue_text:
                return False
            queue_entry = next(
                (item for item in queue_next_action_entries if str(item.get("env") or "") == env_name),
                {},
            )
            placeholder = str(queue_entry.get("placeholder") or "")
            set_command = str(queue_entry.get("powershell_set_command") or "")
            if not placeholder.startswith("<set-") or not placeholder.endswith(">"):
                return False
            if set_command != f"$env:{env_name} = '{placeholder}'":
                return False
            for claim_id in entry.get("claim_ids") or []:
                if str(claim_id) not in queue_text:
                    return False
            for package_id in entry.get("package_ids") or []:
                if str(package_id) not in queue_text:
                    return False
            for command in entry.get("token_login_commands") or []:
                if str(command) not in queue_text:
                    return False
    if expected_post_env_bundle_launcher_commands:
        if "## Copy/Paste Env-Bundle Validation" not in queue_text:
            return False
        if expected_env_bundle_validation_command not in queue_text:
            return False
        if "## Copy/Paste Post-Env-Bundle Launcher" not in queue_text:
            return False
        for command in expected_post_env_bundle_launcher_commands:
            if command not in queue_text:
                return False
        if "## Copy/Paste Post-Env-Bundle Balanced Agent Spawn" not in queue_text:
            return False
        for command in expected_post_env_bundle_balanced_agent_spawn_commands:
            if command not in queue_text:
                return False
    for entry in expected_entries:
        env_name = str(entry.get("env") or "")
        if f"`{env_name}`" not in queue_text:
            return False
        queue_entry = next((item for item in queue_entries if str(item.get("env") or "") == env_name), {})
        placeholder = str(queue_entry.get("placeholder") or "")
        set_command = str(queue_entry.get("powershell_set_command") or "")
        unblock_prompt = str(queue_entry.get("copy_paste_unblock_prompt") or "")
        if not placeholder.startswith("<set-") or not placeholder.endswith(">"):
            return False
        if set_command != f"$env:{env_name} = '{placeholder}'":
            return False
        if set_command not in queue_text or set_command not in unblock_prompt:
            return False
        if "## Copy/Paste Env Unblock Commands" not in queue_text:
            return False
        if f"Env: {env_name}" not in unblock_prompt:
            return False
        if "Claims ready after setting only this env:" not in unblock_prompt:
            return False
        if "Claims still blocked after setting only this env:" not in unblock_prompt:
            return False
        if "Dependency-gated claims also needing this env:" not in unblock_prompt:
            return False
        if "Manual claims also needing this env:" not in unblock_prompt:
            return False
        if "All affected packages:" not in unblock_prompt:
            return False
        if "Direct claim next actions:" not in unblock_prompt:
            return False
        if "Other affected claim next actions:" not in unblock_prompt:
            return False
        for claim_id in entry.get("single_env_ready_claim_ids") or []:
            if str(claim_id) not in unblock_prompt or str(claim_id) not in queue_text:
                return False
        for claim_id in entry.get("single_env_still_blocked_claim_ids") or []:
            if str(claim_id) not in unblock_prompt or str(claim_id) not in queue_text:
                return False
        for claim_id in entry.get("immediate_claim_ids") or []:
            if str(claim_id) not in unblock_prompt:
                return False
        for claim_id in entry.get("dependency_claim_ids") or []:
            if str(claim_id) not in unblock_prompt:
                return False
        for claim_id in entry.get("manual_claim_ids") or []:
            if str(claim_id) not in unblock_prompt:
                return False
        for package_id in entry.get("package_ids") or []:
            if str(package_id) not in unblock_prompt:
                return False
        for claim_id in entry.get("claim_ids") or []:
            if str(claim_id) not in queue_text:
                return False
    return True


def dispatch_archived_ready_claims_launcher_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_path = normalize_artifact_ref(manifest.get("ready_claims_launcher_path"))
    if not launcher_path:
        return True
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    launcher_full_path = ROOT / launcher_path
    claims_json_full_path = ROOT / claims_json_path
    if not launcher_full_path.exists() or not claims_json_full_path.exists():
        return False
    launcher_text = launcher_full_path.read_text(encoding="utf-8")
    if "# Validation Ready Claims Launcher" not in launcher_text:
        return False
    if "TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH" not in launcher_text:
        return False
    for required_text in [
        "[switch]$ValidateOnly",
        "Ready claims validation passed. Ready claims:",
        "claim_lock_helper.ps1",
        "TAMANDUA_READY_CLAIMS_AGENT_ID",
        "AgentId may only contain letters",
        "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
        "$env:TAMANDUA_AGENT_ID = $script:ReadyClaimAgentId",
        "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
        "dispatch_manifest.json",
        "--refresh-claim-status-report",
        "Invoke-ClaimStatusRefresh",
        "ready_to_claim",
    ]:
        if required_text not in launcher_text:
            return False
    try:
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    lock_position = launcher_text.find(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ClaimLockHelperPath "
        "-ClaimId $ClaimId -AgentId $script:ReadyClaimAgentId"
    )
    claim_env_position = launcher_text.find("$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId")
    agent_env_position = launcher_text.find("$env:TAMANDUA_AGENT_ID = $script:ReadyClaimAgentId")
    script_position = launcher_text.find("powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath")
    if (
        lock_position < 0
        or claim_env_position < 0
        or agent_env_position < 0
        or script_position < 0
        or claim_env_position > lock_position
        or agent_env_position > lock_position
        or lock_position > script_position
    ):
        return False
    ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") == "ready_to_claim"
    ]
    non_ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") != "ready_to_claim"
    ]
    executable_lines = [
        line.strip() for line in launcher_text.splitlines() if line.strip().startswith("Invoke-ReadyClaim ")
    ]
    if len(executable_lines) != len(ready_claims):
        return False
    for claim in ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if not claim_id or not package_id or not script_path:
            return False
        if f"# Claim: {claim_id}" not in launcher_text:
            return False
        if f"# Package: {package_id}" not in launcher_text:
            return False
        if script_path not in launcher_text:
            return False
        expected_invocation = f"Invoke-ReadyClaim '{claim_id}' '{package_id}' '{script_path}'"
        if expected_invocation not in executable_lines:
            return False
    for claim in non_ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if claim_id and f"# Claim: {claim_id}" in launcher_text:
            return False
        if package_id and f"# Package: {package_id}" in launcher_text:
            return False
        for line in executable_lines:
            if (claim_id and claim_id in line) or (script_path and script_path in line):
                return False
    return True


def dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_path = normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path"))
    if not launcher_path:
        return True
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    launcher_full_path = ROOT / launcher_path
    claims_json_full_path = ROOT / claims_json_path
    if not launcher_full_path.exists() or not claims_json_full_path.exists():
        return False
    launcher_text = launcher_full_path.read_text(encoding="utf-8")
    if "# Validation Ready Claims Parallel Launcher" not in launcher_text:
        return False
    for required_text in [
        "[switch]$ValidateOnly",
        "Ready claims validation passed. Ready claims:",
        "TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH",
        "claim_lock_helper.ps1",
        "TAMANDUA_READY_CLAIMS_AGENT_ID",
        "AgentId may only contain letters",
        "dispatch_manifest.json",
        "--refresh-claim-status-report",
        "Invoke-ClaimStatusRefresh",
        "Start-Job",
        "Wait-ReadyClaimBatch",
        "Phase = 'auth-env'",
        "Phase = 'auth-login'",
        "$InnerTokenLoginCommand",
        "ExitCode",
        "$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId",
        "$env:TAMANDUA_AGENT_ID = $InnerAgentId",
        "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
        "ready_to_claim",
    ]:
        if required_text not in launcher_text:
            return False
    lock_invocation = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerClaimLockHelperPath "
        "-ClaimId $InnerClaimId -AgentId $InnerAgentId"
    )
    lock_position = launcher_text.find(lock_invocation)
    claim_env_position = launcher_text.find("$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId")
    agent_env_position = launcher_text.find("$env:TAMANDUA_AGENT_ID = $InnerAgentId")
    script_position = launcher_text.find("powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerScriptPath")
    if (
        lock_position < 0
        or claim_env_position < 0
        or agent_env_position < 0
        or script_position < 0
        or claim_env_position > lock_position
        or agent_env_position > lock_position
        or lock_position > script_position
    ):
        return False
    if "Phase = 'lock'" not in launcher_text or "Phase = 'run'" not in launcher_text:
        return False
    try:
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") == "ready_to_claim"
    ]
    non_ready_claims = [
        claim
        for claim in claims_payload.get("claims") or []
        if isinstance(claim, dict) and claim.get("claim_state") != "ready_to_claim"
    ]
    executable_lines = [
        line.strip()
        for line in launcher_text.splitlines()
        if line.strip().startswith("$ReadyClaimJobs += Start-ReadyClaimJob ")
    ]
    if len(executable_lines) != len(ready_claims):
        return False
    for claim in ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if not claim_id or not package_id or not script_path:
            return False
        if f"# Claim: {claim_id}" not in launcher_text:
            return False
        if f"# Package: {package_id}" not in launcher_text:
            return False
        if script_path not in launcher_text:
            return False
        resources = ", ".join(str(value) for value in claim.get("resource_tags") or []) or "-"
        if f"# Resources: {resources}" not in launcher_text:
            return False
        next_action = render_current_next_action_summary(claim.get("current_next_action"))
        if f"# Next action: {next_action}" not in launcher_text:
            return False
        current_next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        token_env = str(current_next_action.get("token_env") or "")
        token_login_command = str(current_next_action.get("token_login_command") or "")
        expected_invocation = (
            f"$ReadyClaimJobs += Start-ReadyClaimJob '{claim_id}' '{package_id}' '{script_path}' "
            f"'{token_env}' '{token_login_command}'"
        )
        if expected_invocation not in executable_lines:
            return False
    for claim in non_ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if claim_id and f"# Claim: {claim_id}" in launcher_text:
            return False
        if package_id and f"# Package: {package_id}" in launcher_text:
            return False
        for line in executable_lines:
            if (claim_id and claim_id in line) or (script_path and script_path in line):
                return False
    return True


def dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    if not launcher_path:
        return True
    claims_json_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_json_path:
        return False
    launcher_full_path = ROOT / launcher_path
    claims_json_full_path = ROOT / claims_json_path
    if not launcher_full_path.exists() or not claims_json_full_path.exists():
        return False
    launcher_text = launcher_full_path.read_text(encoding="utf-8")
    for required_text in [
        "# Validation Env-Bundle Ready Claims Launcher",
        "[switch]$ValidateOnly",
        "Env bundle current env present:",
        "Env bundle current env missing:",
        "Env bundle missing set commands:",
        "Env bundle validation passed. Ready claims after complete env bundle:",
        "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH",
        "TAMANDUA_ENV_BUNDLE_CLAIMS_AGENT_ID",
        "AgentId may only contain letters",
        "env_unblock_queue.json",
        "claim_lock_helper.ps1",
        "dispatch_manifest.json",
        "--refresh-claim-status-report",
        "Invoke-ClaimStatusRefresh",
        "Start-Job",
        "Wait-EnvBundleClaimBatch",
        "Phase = 'auth-env'",
        "Phase = 'auth-login'",
        "$InnerTokenLoginCommand",
        "Missing env bundle values",
        "Placeholder env bundle values must be replaced before launch",
        "$PlaceholderEnv",
        "^<set-.+>$",
        "Env unblock queue contains an entry without env.",
        "Env unblock queue contains duplicate env entries:",
        "Env unblock queue missing ready_after_all_env_claim_ids.",
        "Env unblock queue ready_after_all_env_claim_ids mismatch:",
        "Env unblock queue missing still_blocked_after_all_env_claim_ids.",
        "Env unblock queue still_blocked_after_all_env_claim_ids mismatch:",
        "Env unblock queue missing required_env_names.",
        "Env unblock queue missing all_env_powershell_set_commands.",
        "Env unblock queue env set commands mismatch:",
        "ExitCode",
        "$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId",
        "$env:TAMANDUA_AGENT_ID = $InnerAgentId",
        "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
    ]:
        if required_text not in launcher_text:
            return False
    lock_invocation = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerClaimLockHelperPath "
        "-ClaimId $InnerClaimId -AgentId $InnerAgentId"
    )
    lock_position = launcher_text.find(lock_invocation)
    claim_env_position = launcher_text.find("$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId")
    agent_env_position = launcher_text.find("$env:TAMANDUA_AGENT_ID = $InnerAgentId")
    script_position = launcher_text.find("powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerScriptPath")
    if (
        lock_position < 0
        or claim_env_position < 0
        or agent_env_position < 0
        or script_position < 0
        or claim_env_position > lock_position
        or agent_env_position > lock_position
        or lock_position > script_position
    ):
        return False
    if "Phase = 'lock'" not in launcher_text or "Phase = 'run'" not in launcher_text:
        return False
    try:
        claims_payload = load_json(claims_json_full_path)
    except json.JSONDecodeError:
        return False
    queue_json_path = normalize_artifact_ref(manifest.get("env_unblock_queue_json_path"))
    expected_env_bundle_ids: set[str] | None = None
    if queue_json_path:
        queue_json_full_path = ROOT / queue_json_path
        if not queue_json_full_path.exists():
            return False
        try:
            queue_payload = load_json(queue_json_full_path)
        except json.JSONDecodeError:
            return False
        expected_env_bundle_ids = {
            str(value) for value in queue_payload.get("ready_after_all_env_claim_ids") or [] if str(value)
        }
    env_bundle_ready_claims = []
    non_env_bundle_ready_claims = []
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        missing_env = [str(value) for value in claim.get("missing_effective_env") or [] if str(value)]
        blocked_reasons = {str(value) for value in claim.get("blocked_reasons") or [] if str(value)}
        claim_id = str(claim.get("claim_id") or "")
        if expected_env_bundle_ids is not None:
            is_env_bundle_ready = claim_id in expected_env_bundle_ids
        else:
            is_env_bundle_ready = bool(missing_env and blocked_reasons <= {"missing_effective_env"})
        if is_env_bundle_ready:
            env_bundle_ready_claims.append(claim)
        else:
            non_env_bundle_ready_claims.append(claim)
    executable_lines = [
        line.strip()
        for line in launcher_text.splitlines()
        if line.strip().startswith("$EnvBundleClaimJobs += Start-EnvBundleClaimJob ")
    ]
    if len(executable_lines) != len(env_bundle_ready_claims):
        return False
    for claim in env_bundle_ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if not claim_id or not package_id or not script_path:
            return False
        if f"# Claim: {claim_id}" not in launcher_text:
            return False
        if f"# Package: {package_id}" not in launcher_text:
            return False
        if script_path not in launcher_text:
            return False
        resources = ", ".join(str(value) for value in claim.get("resource_tags") or []) or "-"
        if f"# Resources: {resources}" not in launcher_text:
            return False
        next_action = render_current_next_action_summary(claim.get("current_next_action"))
        if f"# Next action: {next_action}" not in launcher_text:
            return False
        current_next_action = claim.get("current_next_action") if isinstance(claim.get("current_next_action"), dict) else {}
        token_env = str(current_next_action.get("token_env") or "")
        token_login_command = str(current_next_action.get("token_login_command") or "")
        expected_invocation = (
            f"$EnvBundleClaimJobs += Start-EnvBundleClaimJob '{claim_id}' '{package_id}' '{script_path}' "
            f"'{token_env}' '{token_login_command}'"
        )
        if expected_invocation not in executable_lines:
            return False
    for claim in non_env_bundle_ready_claims:
        claim_id = str(claim.get("claim_id") or "")
        package_id = str(claim.get("package_id") or "")
        script_path = str(claim.get("script_path") or "")
        if claim_id and f"# Claim: {claim_id}" in launcher_text:
            return False
        if package_id and f"# Package: {package_id}" in launcher_text:
            return False
        for line in executable_lines:
            if (claim_id and claim_id in line) or (script_path and script_path in line):
                return False
    return True


def scorecard_manual_claim_review_has_only_dispatch_claims(scorecard: dict[str, Any]) -> bool:
    review_items = scorecard.get("manual_claim_review") or []
    if not isinstance(review_items, list):
        return False
    return all(
        isinstance(item, dict) and str(item.get("kind") or "") == "dispatch-claim"
        for item in review_items
    )


def scorecard_dispatch_manual_claim_review_is_actionable(scorecard: dict[str, Any]) -> bool:
    review_items = scorecard.get("manual_claim_review") or []
    if not isinstance(review_items, list):
        return False
    for item in review_items:
        if not isinstance(item, dict):
            return False
        if str(item.get("kind") or "") != "dispatch-claim":
            continue
        snippet = str(item.get("snippet") or "")
        action = str(item.get("action") or "")
        prompt_path = str(item.get("prompt_path") or "")
        owner = str(item.get("owner") or "")
        package_id = str(item.get("package_id") or "")
        doc = str(item.get("doc") or "")
        if not snippet or "action=" not in snippet or "prompt=" not in snippet:
            return False
        if not package_id or not snippet.startswith(f"{package_id}:"):
            return False
        if not action or action == "-" or f"action={action}" not in snippet:
            return False
        if not prompt_path or prompt_path == "-" or f"prompt={prompt_path}" not in snippet:
            return False
        if not doc or not (ROOT / doc).exists() or not (ROOT / prompt_path).exists():
            return False
        if not owner or f"owner={owner}" not in snippet:
            return False
        if snippet.endswith("...") or snippet.endswith("…"):
            return False
        if str(item.get("generated_status") or "") == "blocked_missing_env":
            missing_env = item.get("missing_env")
            if not isinstance(missing_env, list) or not missing_env:
                return False
            if "missing_env=" not in snippet:
                return False
            for env_name in missing_env:
                if not str(env_name) or str(env_name) not in snippet:
                    return False
    return True


def scorecard_dispatch_manual_claim_review_covers_agent_claims(
    scorecard: dict[str, Any], dispatch_artifact: dict[str, Any]
) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False
    claims_path = normalize_artifact_ref(manifest.get("agent_claims_json_path"))
    if not claims_path:
        return False
    claims_full_path = ROOT / claims_path
    if not claims_full_path.exists():
        return False
    try:
        claims_payload = load_json(claims_full_path)
    except json.JSONDecodeError:
        return False
    expected: dict[str, dict[str, str]] = {}
    for claim in claims_payload.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        claim_id = str(claim.get("claim_id") or "")
        state = str(claim.get("claim_state") or "")
        blocked_reasons = [str(value) for value in claim.get("blocked_reasons") or []]
        if state != "manual_claim_required" and "manual_launch_required" not in blocked_reasons:
            continue
        if not claim_id:
            return False
        expected[claim_id] = {
            "package_id": str(claim.get("package_id") or ""),
            "generated_status": state or "manual_claim_required",
        }
    if not expected:
        review_items = scorecard.get("manual_claim_review") or []
        return isinstance(review_items, list) and not review_items
    review_items = scorecard.get("manual_claim_review") or []
    if not isinstance(review_items, list):
        return False
    actual: dict[str, dict[str, str]] = {}
    for item in review_items:
        if not isinstance(item, dict) or str(item.get("kind") or "") != "dispatch-claim":
            continue
        claim_id = str(item.get("id") or "")
        if not claim_id:
            return False
        actual[claim_id] = {
            "package_id": str(item.get("package_id") or ""),
            "generated_status": str(item.get("generated_status") or ""),
        }
    return actual == expected


def scorecard_markdown_exposes_structured_manual_claim_review(scorecard_markdown_path: Path) -> bool:
    if not scorecard_markdown_path.exists():
        return False
    text = scorecard_markdown_path.read_text(encoding="utf-8")
    if "| `dispatch-claim:" not in text and "No manual claim review prompts found" in text:
        return True
    if "| `dispatch-claim:" not in text and "## Manual Claim Review" not in text:
        return True
    required_markers = [
        "| Entity | Package | Generated Status | Manual Wording | Owner | Missing Env | Action | Prompt | Location | Snippet |",
        "| `dispatch-claim:",
        "| `docs/benchmarks/runs/",
    ]
    return all(marker in text for marker in required_markers)


def scorecard_markdown_matches_manual_claim_review(scorecard: dict[str, Any], scorecard_markdown_path: Path) -> bool:
    if not scorecard_markdown_path.exists():
        return False
    text = scorecard_markdown_path.read_text(encoding="utf-8")
    markdown_claim_rows = [
        line for line in text.splitlines() if line.startswith("| `dispatch-claim:")
    ]
    review_items = scorecard.get("manual_claim_review") or []
    if not isinstance(review_items, list):
        return False
    dispatch_review_items = [
        item
        for item in review_items
        if isinstance(item, dict) and str(item.get("kind") or "") == "dispatch-claim"
    ]
    if len(markdown_claim_rows) != len(dispatch_review_items):
        return False
    for item in review_items:
        if not isinstance(item, dict) or str(item.get("kind") or "") != "dispatch-claim":
            continue
        missing_env = item.get("missing_env")
        missing_env_text = (
            ", ".join(str(value) for value in missing_env)
            if isinstance(missing_env, list) and missing_env
            else "-"
        )
        snippet = str(item.get("snippet") or "").replace("|", "\\|")
        action = str(item.get("action") or "-").replace("|", "\\|")
        owner = str(item.get("owner") or "-").replace("|", "\\|")
        prompt_path = str(item.get("prompt_path") or "-").replace("|", "\\|")
        expected_row = (
            f"| `{item.get('kind')}:{item.get('id')}` | `{item.get('package_id')}` | `{item.get('generated_status')}` | "
            f"`{item.get('polarity')}` | `{owner}` | `{missing_env_text}` | {action} | "
            f"`{prompt_path}` | `{item.get('doc')}:{item.get('line')}` | {snippet} |"
        )
        if expected_row not in markdown_claim_rows:
            return False
    return True


def scorecard_pass_roadmaps_have_no_newer_fail_after_pass(scorecard: dict[str, Any]) -> bool:
    roadmaps = scorecard.get("roadmaps") or []
    if not isinstance(roadmaps, list):
        return False
    for roadmap in roadmaps:
        if not isinstance(roadmap, dict) or str(roadmap.get("status") or "") != "pass":
            continue
        for row in roadmap.get("profiles") or []:
            if not isinstance(row, dict):
                continue
            latest = row.get("latest") or {}
            latest_pass = row.get("latest_pass") or {}
            if (
                isinstance(latest, dict)
                and isinstance(latest_pass, dict)
                and latest_pass
                and latest.get("quality_gate_passed") is False
            ):
                return False
    return True


def scorecard_pass_roadmaps_have_latest_pass_for_every_profile(scorecard: dict[str, Any]) -> bool:
    roadmaps = scorecard.get("roadmaps") or []
    if not isinstance(roadmaps, list):
        return False
    for roadmap in roadmaps:
        if not isinstance(roadmap, dict) or str(roadmap.get("status") or "") != "pass":
            continue
        for row in roadmap.get("profiles") or []:
            if not isinstance(row, dict):
                continue
            if not row.get("latest_pass"):
                return False
    return True


OPEN_FULL_SCOPE_NOTE_RE = re.compile(
    r"\b("
    r"Full Roadmap [A-Z0-9]+ still requires|"
    r"Full governance still requires|"
    r"Full Roadmap [A-Z0-9]+ requires|"
    r"Full .* still requires|"
    r"production .* still requires|"
    r"Real fleet scale still requires|"
    r"VM evidence is still required"
    r")\b",
    re.IGNORECASE,
)


def scorecard_pass_roadmaps_have_no_open_full_scope_notes(scorecard: dict[str, Any]) -> bool:
    roadmaps = scorecard.get("roadmaps") or []
    if not isinstance(roadmaps, list):
        return False
    return all(
        not (
            isinstance(roadmap, dict)
            and str(roadmap.get("status") or "") == "pass"
            and OPEN_FULL_SCOPE_NOTE_RE.search(str(roadmap.get("note") or ""))
        )
        for roadmap in roadmaps
    )


def dispatch_archived_prelaunch_validation_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    prelaunch_path = normalize_artifact_ref(manifest.get("dispatch_prelaunch_validation_path"))
    if not prelaunch_path:
        return False
    prelaunch_full_path = ROOT / prelaunch_path
    if not prelaunch_full_path.exists():
        return False
    prelaunch_text = prelaunch_full_path.read_text(encoding="utf-8")
    expected_paths = [
        normalize_artifact_ref(manifest.get("agent_spawn_launcher_path")),
        normalize_artifact_ref(manifest.get("ready_claims_launcher_path")),
        normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path")),
        normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path")),
        normalize_artifact_ref(manifest.get("claim_lock_helper_path")),
        normalize_artifact_ref(manifest.get("env_unblock_queue_json_path")),
        normalize_artifact_ref(manifest.get("agent_spawn_plan_json_path")),
        normalize_artifact_ref(manifest.get("agent_claims_json_path")),
        manifest_path,
    ]
    if not all(expected_paths):
        return False
    required_fragments = [
        "# Validation Dispatch Prelaunch Validation",
        "[switch]$ValidateEnvBundle",
        "$PrelaunchFailures = @()",
        "function Invoke-PrelaunchStep",
        "function Invoke-ClaimLockEmptyValidation",
        "claim lock helper missing for empty check:",
        "claim lock prelaunch found existing locks:",
        "claim lock empty check passed",
        "function Invoke-OwnerLaunchPlanShapeValidation",
        "owner launch plan shape missing artifact",
        "owner launch plan shape invalid artifact:",
        "owner launch plan shape missing owners",
        "owner launch plan shape owners is not a list",
        "owner launch plan shape duplicate package_id:",
        "owner launch plan shape package_count mismatch:",
        "owner launch plan shape valid: packages=",
        "function Invoke-ExecutionMatrixShapeValidation",
        "execution matrix shape missing artifact",
        "execution matrix shape invalid artifact:",
        "execution matrix shape invalid source_artifact:",
        "execution matrix shape missing rows",
        "execution matrix shape rows is not a list",
        "execution matrix shape duplicate package_id:",
        "execution matrix shape ready_to_launch_count mismatch:",
        "execution matrix shape valid: rows=",
        "function Invoke-OwnerPlanExecutionMatrixAlignmentValidation",
        "owner plan execution matrix alignment package_ids mismatch:",
        "owner plan execution matrix alignment ready_to_launch mismatch:",
        "owner plan execution matrix alignment valid: packages=",
        "function Invoke-DispatchManifestPlanAlignmentValidation",
        "dispatch manifest plan alignment owner package_ids mismatch:",
        "dispatch manifest plan alignment matrix package_ids mismatch:",
        "dispatch manifest plan alignment valid: packages=",
        "function Invoke-DispatchManifestAgentClaimsAlignmentValidation",
        "dispatch manifest agent claims alignment package_ids mismatch:",
        "dispatch manifest agent claims alignment claim_id mismatch:",
        "dispatch manifest agent claims alignment valid: packages=",
        "function Invoke-ClaimLockHelperAgentClaimsAlignmentValidation",
        "claim lock helper agent claims alignment missing helper marker:",
        "claim lock helper agent claims alignment missing KnownClaims list",
        "claim lock helper agent claims alignment claim_ids mismatch:",
        "claim lock helper agent claims alignment valid: claims=",
        "function Invoke-AgentClaimsStatusReportAlignmentValidation",
        "agent claims status report alignment claim_ids mismatch:",
        "agent claims status report alignment package_id mismatch:",
        "agent claims status report alignment claim_state mismatch:",
        "agent claims status report alignment owner mismatch:",
        "agent claims status report alignment wave mismatch:",
        "agent claims status report alignment stage mismatch:",
        "agent claims status report alignment ready_to_launch mismatch:",
        "agent claims status report alignment script_path mismatch:",
        "agent claims status report alignment prompt_path mismatch:",
        "agent claims status report alignment status_path mismatch:",
        "agent claims status report alignment command mismatch:",
        "agent claims status report alignment missing_effective_env mismatch:",
        "agent claims status report alignment blocked_reasons mismatch:",
        "agent claims status report alignment resource_tags mismatch:",
        "agent claims status report alignment invalid lock_state:",
        "agent claims status report alignment lock_path mismatch:",
        "agent claims status report alignment valid: claims=",
        "function Invoke-AgentClaimsSpawnPlanAlignmentValidation",
        "agent claims spawn plan alignment claim_ids mismatch:",
        "agent claims spawn plan alignment package_id mismatch:",
        "agent claims spawn plan alignment claim_state mismatch:",
        "agent claims spawn plan alignment valid: claims=",
        "function Invoke-EnvQueueAgentClaimsAlignmentValidation",
        "env unblock queue agent claims alignment required_env_names mismatch:",
        "env unblock queue agent claims alignment unknown claim_id:",
        "env unblock queue agent claims alignment package_ids mismatch:",
        "env unblock queue agent claims alignment env not in claim missing_effective_env:",
        "env unblock queue agent claims alignment remaining_env_after_setting mismatch:",
        "env unblock queue agent claims alignment ready_after_all_env_claim_ids mismatch:",
        "env unblock queue agent claims alignment still_blocked_after_all_env_claim_ids mismatch:",
        "env unblock queue agent claims alignment valid: envs=",
        "function Invoke-ReadyLaunchersAgentClaimsAlignmentValidation",
        "ready launchers agent claims alignment ready claim_ids mismatch:",
        "ready launchers agent claims alignment ready-parallel claim_ids mismatch:",
        "ready launchers agent claims alignment env-bundle claim_ids mismatch:",
        "ready launchers agent claims alignment ready package_id mismatch:",
        "ready launchers agent claims alignment ready script_path mismatch:",
        "ready launchers agent claims alignment valid:",
        "function Invoke-DispatchRunnerManifestAlignmentValidation",
        "dispatch runner manifest alignment missing runner marker:",
        "dispatch runner manifest alignment manifest path mismatch:",
        "dispatch runner manifest alignment missing staged launcher:",
        "dispatch runner manifest alignment missing direct script:",
        "dispatch runner manifest alignment missing direct claim:",
        "dispatch runner manifest alignment valid:",
        "function Invoke-DispatchManifestShapeValidation",
        "dispatch manifest shape missing",
        "dispatch manifest shape invalid JSON:",
        "dispatch manifest shape empty",
        "dispatch manifest shape path missing",
        "dispatch manifest shape missing profile_id",
        "dispatch manifest shape invalid profile_id:",
        "dispatch manifest shape missing source_preflight",
        "dispatch manifest shape empty source_preflight",
        "dispatch manifest shape source_preflight missing:",
        "dispatch manifest shape source_preflight invalid JSON:",
        "dispatch manifest shape source_preflight invalid profile_id:",
        "dispatch manifest shape missing packages",
        "dispatch manifest shape packages is not a list",
        "dispatch manifest shape missing expected_package_ids",
        "dispatch manifest shape expected_package_ids is not a list",
        "dispatch manifest shape missing expected_waves",
        "dispatch manifest shape expected_waves is not a list",
        "dispatch manifest shape launcher_paths is not a list",
        "dispatch manifest shape launcher_paths contains empty value",
        "dispatch manifest shape launcher path missing launcher_paths:",
        "dispatch manifest shape missing staged_launcher_paths",
        "dispatch manifest shape staged_launcher_paths is not a list",
        "dispatch manifest shape staged_launcher_paths contains empty value",
        "dispatch manifest shape launcher path missing staged_launcher_paths:",
        "dispatch manifest shape empty agent_roster_path",
        "dispatch manifest shape path missing agent_roster_path:",
        "dispatch manifest shape empty dispatch_runner_path",
        "dispatch manifest shape path missing dispatch_runner_path:",
        "owner_launch_plan_path",
        "owner_launch_plan_json_path",
        "execution_matrix_path",
        "execution_matrix_json_path",
        "dispatch manifest shape package without package_id",
        "dispatch manifest shape package missing script_path:",
        "dispatch manifest shape package empty script_path:",
        "dispatch manifest shape package path missing script_path:",
        "dispatch manifest shape package status parent missing:",
        "dispatch manifest shape package missing wave:",
        "dispatch manifest shape package invalid wave:",
        "dispatch manifest shape duplicate package_id:",
        "dispatch manifest shape expected_package_ids contains empty value",
        "dispatch manifest shape expected_package_ids mismatch:",
        "dispatch manifest shape expected_waves contains empty value",
        "dispatch manifest shape expected_waves mismatch:",
        "dispatch manifest shape valid: packages=",
        str(expected_paths[8]),
        "function Invoke-AgentSpawnPlanShapeValidation",
        "agent spawn plan shape missing",
        "agent spawn plan shape invalid JSON:",
        "agent spawn plan shape missing schema_version",
        "agent spawn plan shape missing artifact",
        "agent spawn plan shape invalid schema_version:",
        "agent spawn plan shape invalid artifact:",
        "agent spawn plan shape invalid source_artifact:",
        "agent spawn plan shape missing ready_batch_count",
        "agent spawn plan shape missing ready_claim_count",
        "agent spawn plan shape missing env_bundle_ready_batch_count",
        "agent spawn plan shape missing env_bundle_ready_claim_count",
        "agent spawn plan shape missing env_bundle_still_blocked_claim_count",
        "agent spawn plan shape missing blocked_or_manual_claim_count",
        "agent spawn plan shape invalid ready_batch_count:",
        "agent spawn plan shape invalid ready_claim_count:",
        "agent spawn plan shape invalid env_bundle_ready_batch_count:",
        "agent spawn plan shape invalid env_bundle_ready_claim_count:",
        "agent spawn plan shape invalid env_bundle_still_blocked_claim_count:",
        "agent spawn plan shape invalid blocked_or_manual_claim_count:",
        "agent spawn plan shape missing batches",
        "agent spawn plan shape batches is not a list",
        "agent spawn plan shape batch missing claims in",
        "agent spawn plan shape batch claims is not a list in",
        "agent spawn plan shape batch missing claim_count in",
        "agent spawn plan shape invalid batch claim_count in",
        "agent spawn plan shape batch claim_count mismatch in",
        "agent spawn plan shape batch claim without claim_id in",
        "agent spawn plan shape ready_batch_count mismatch:",
        "agent spawn plan shape env_bundle_ready_batch_count mismatch:",
        "agent spawn plan shape ready_claim_count mismatch:",
        "agent spawn plan shape env_bundle_ready_claim_count mismatch:",
        "agent spawn plan shape env_bundle_still_blocked_claim_count mismatch:",
        "agent spawn plan shape blocked_or_manual_claim_count mismatch:",
        "agent spawn plan shape valid: ready_claims=",
        str(expected_paths[6]),
        "function Invoke-AgentClaimsShapeValidation",
        "agent claims shape missing",
        "agent claims shape invalid JSON:",
        "agent claims shape missing schema_version",
        "agent claims shape missing artifact",
        "agent claims shape invalid schema_version:",
        "agent claims shape invalid artifact:",
        "agent claims shape missing claims",
        "agent claims shape claims is not a list",
        "agent claims shape missing claim_count",
        "agent claims shape missing ready_to_claim_count",
        "agent claims shape missing blocked_claim_count",
        "agent claims shape missing manual_claim_count",
        "agent claims shape invalid claim_count:",
        "agent claims shape invalid ready_to_claim_count:",
        "agent claims shape invalid blocked_claim_count:",
        "agent claims shape invalid manual_claim_count:",
        "agent claims shape claim without claim_id",
        "agent claims shape duplicate claim_id:",
        "agent claims shape claim_count mismatch:",
        "agent claims shape ready_to_claim_count mismatch:",
        "agent claims shape blocked_claim_count mismatch:",
        "agent claims shape manual_claim_count mismatch:",
        "agent claims shape valid: claims=",
        str(expected_paths[7]),
        "function Invoke-ClaimStatusReportShapeValidation",
        "claim status report shape missing",
        "claim status report shape invalid JSON:",
        "claim status report shape missing schema_version",
        "claim status report shape missing artifact",
        "claim status report shape invalid schema_version:",
        "claim status report shape invalid artifact:",
        "claim status report shape missing claims",
        "claim status report shape claims is not a list",
        "claim status report shape missing claim_count",
        "claim status report shape missing ready_to_claim_count",
        "claim status report shape missing blocked_claim_count",
        "claim status report shape missing manual_claim_count",
        "claim status report shape missing locked_claim_count",
        "claim status report shape missing invalid_lock_count",
        "claim status report shape invalid claim_count:",
        "claim status report shape invalid ready_to_claim_count:",
        "claim status report shape invalid blocked_claim_count:",
        "claim status report shape invalid manual_claim_count:",
        "claim status report shape invalid locked_claim_count:",
        "claim status report shape invalid invalid_lock_count:",
        "claim status report shape claim without claim_id",
        "claim status report shape duplicate claim_id:",
        "claim status report shape claim_count mismatch:",
        "claim status report shape ready_to_claim_count mismatch:",
        "claim status report shape blocked_claim_count mismatch:",
        "claim status report shape manual_claim_count mismatch:",
        "claim status report shape locked_claim_count mismatch:",
        "claim status report shape invalid_lock_count mismatch:",
        "claim status report shape valid: claims=",
        "function Invoke-EnvQueueShapeValidation",
        "Invoke-EnvQueueShapeValidation",
        str(expected_paths[5]),
        "env unblock queue shape missing",
        "env unblock queue shape invalid JSON",
        "env unblock queue shape missing entries",
        "env unblock queue shape entries is not a list",
        "env unblock queue shape entry without env",
        "env unblock queue shape duplicate env entries:",
        "env unblock queue shape invalid env_count:",
        "env unblock queue shape env_count mismatch:",
        "env unblock queue shape missing required_env_names",
        "env unblock queue shape required_env_names is not a list",
        "env unblock queue shape required_env_names contains empty value",
        "env unblock queue shape required_env_names mismatch:",
        "env unblock queue shape missing all_env_powershell_set_commands",
        "env unblock queue shape all_env_powershell_set_commands is not a list",
        "env unblock queue shape all_env_powershell_set_commands contains empty value",
        "env unblock queue shape invalid env set command:",
        "env unblock queue shape duplicate env set commands:",
        "env unblock queue shape env set commands mismatch:",
        "env unblock queue shape entry missing powershell_set_command",
        "env unblock queue shape env set command text mismatch",
        "env unblock queue shape entry missing direct_next_action_summaries",
        "env unblock queue shape entry direct_next_action_summaries is not a list",
        "env unblock queue shape direct_next_action_summaries contains empty value",
        "env unblock queue shape entry missing indirect_next_action_summaries",
        "env unblock queue shape entry indirect_next_action_summaries is not a list",
        "env unblock queue shape indirect_next_action_summaries contains empty value",
        "env unblock queue shape missing current_env_present_names",
        "env unblock queue shape current_env_present_names is not a list",
        "env unblock queue shape missing current_env_missing_names",
        "env unblock queue shape current_env_missing_names is not a list",
        "env unblock queue shape missing current_env_placeholder_names",
        "env unblock queue shape current_env_placeholder_names is not a list",
        "env unblock queue shape missing current_env_present_count",
        "env unblock queue shape missing current_env_missing_count",
        "env unblock queue shape missing current_env_placeholder_count",
        "env unblock queue shape current env names contain empty value",
        "env unblock queue shape current env state overlap:",
        "env unblock queue shape current env state mismatch:",
        "env unblock queue shape invalid current_env_present_count:",
        "env unblock queue shape invalid current_env_missing_count:",
        "env unblock queue shape invalid current_env_placeholder_count:",
        "env unblock queue shape current_env_present_count mismatch:",
        "env unblock queue shape current_env_missing_count mismatch:",
        "env unblock queue shape current_env_placeholder_count mismatch:",
        "env unblock queue shape missing ready_with_current_env_claim_ids",
        "env unblock queue shape ready_with_current_env_claim_ids is not a list",
        "env unblock queue shape missing still_blocked_with_current_env_claim_ids",
        "env unblock queue shape still_blocked_with_current_env_claim_ids is not a list",
        "env unblock queue shape missing ready_after_all_env_claim_ids",
        "env unblock queue shape ready_after_all_env_claim_ids is not a list",
        "env unblock queue shape missing still_blocked_after_all_env_claim_ids",
        "env unblock queue shape still_blocked_after_all_env_claim_ids is not a list",
        "env unblock queue shape claim readiness ids contain empty value",
        "env unblock queue shape duplicate claim readiness ids in",
        "env unblock queue shape current claim readiness overlap:",
        "env unblock queue shape after-all claim readiness overlap:",
        "env unblock queue shape missing blocked_claim_count",
        "env unblock queue shape invalid blocked_claim_count:",
        "env unblock queue shape blocked_claim_count below referenced claims:",
        "env unblock queue shape valid: entries=",
        "Invoke-PrelaunchStep 'agent spawn dry run'",
        str(expected_paths[0]),
        "-Provider', 'all', '-Phase', 'all', '-ShowBlocked'",
        "Invoke-PrelaunchStep 'agent spawn balanced dry run'",
        "-Provider', 'balanced', '-Phase', 'all', '-ShowBlocked'",
        "Invoke-PrelaunchStep 'ready claims sequential validate-only'",
        str(expected_paths[1]),
        "Invoke-PrelaunchStep 'ready claims parallel validate-only'",
        str(expected_paths[2]),
        "Invoke-ClaimLockEmptyValidation",
        "Invoke-PrelaunchStep 'claim lock list'",
        str(expected_paths[4]),
        "if ($ValidateEnvBundle)",
        "Invoke-PrelaunchStep 'env bundle validate-only'",
        str(expected_paths[3]),
        "env bundle validate-only skipped",
        "Dispatch prelaunch validation failed:",
        "Dispatch prelaunch validation passed.",
    ]
    return all(fragment in prelaunch_text for fragment in required_fragments)


def dispatch_archived_launcher_membership_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_text = ""
    launcher_waves: set[int] = set()
    for launcher_path in manifest.get("launcher_paths") or []:
        launcher_ref = normalize_artifact_ref(launcher_path)
        launcher_full_path = ROOT / launcher_ref
        if not launcher_ref or not launcher_full_path.exists():
            return False
        text = launcher_full_path.read_text(encoding="utf-8")
        if not all(
            marker in text
            for marker in [
                "TAMANDUA_WAVE_LAUNCHER_AGENT_ID",
                "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
                "$env:TAMANDUA_AGENT_ID = $AgentId",
                "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
            ]
        ):
            return False
        launcher_text += "\n" + text
        match = re.search(r"(?m)^# Wave: (\d+)\s*$", text)
        if match:
            launcher_waves.add(int(match.group(1)))

    parallel_packages = [
        package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("parallelizable_in_wave")
    ]
    selected_manifest_packages = [
        package for package in parallel_packages if package.get("launcher_selected") is True
    ]
    if not selected_manifest_packages and launcher_text.strip():
        return False

    selected_count = 0
    for package in parallel_packages:
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not script_path:
            return False
        selected = package.get("launcher_selected")
        in_launcher = script_path in launcher_text
        if selected is True:
            selected_count += 1
            if not in_launcher:
                return False
        elif selected is False:
            if in_launcher or not package.get("manual_reason"):
                return False
        else:
            return False
    return selected_count == len(selected_manifest_packages)


def dispatch_archived_manifest_launcher_decisions_are_replayable(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    packages = [package for package in manifest.get("packages") or [] if isinstance(package, dict)]
    if not packages:
        return False

    selected_count = 0
    manual_count = 0
    for package in packages:
        if package.get("parallelizable_in_wave"):
            if package.get("launcher_selected") is True:
                selected_count += 1
                if package.get("manual_reason") is not None:
                    return False
            elif package.get("launcher_selected") is False:
                manual_count += 1
                if not package.get("manual_reason"):
                    return False
            else:
                return False
        elif package.get("launcher_selected") is not None or package.get("manual_reason") is not None:
            return False
    return (selected_count > 0 or manual_count > 0) and selected_count == len(
        [package for package in packages if package.get("parallelizable_in_wave") and package.get("launcher_selected") is True]
    )


def dispatch_archived_launcher_manual_reasons_match_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    launcher_text = ""
    launcher_waves: set[int] = set()
    for launcher_path in manifest.get("launcher_paths") or []:
        launcher_ref = normalize_artifact_ref(launcher_path)
        launcher_full_path = ROOT / launcher_ref
        if not launcher_ref or not launcher_full_path.exists():
            return False
        text = launcher_full_path.read_text(encoding="utf-8")
        launcher_text += "\n" + text
        match = re.search(r"(?m)^# Wave: (\d+)\s*$", text)
        if match:
            launcher_waves.add(int(match.group(1)))
    if launcher_text and not launcher_waves:
        return False
    manual_count = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        if not package_id:
            return False
        manual_line = f"# - {package_id}: {package.get('manual_reason')}"
        if package.get("launcher_selected") is False:
            manual_reason = str(package.get("manual_reason") or "")
            if not manual_reason:
                return False
            wave = int(package.get("wave") or 0)
            if wave not in launcher_waves or not launcher_text:
                manual_count += 1
                continue
            if (
                not manual_reason.startswith("parallel launcher not emitted:")
                and manual_line not in launcher_text
            ):
                return False
            manual_count += 1
        elif package.get("launcher_selected") is True:
            if f"# - {package_id}:" in launcher_text:
                return False
    return manual_count > 0


def dispatch_archived_launcher_selected_metadata_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    return dispatch_archived_launcher_membership_matches_manifest(dispatch_artifact)


def dispatch_archived_staged_launcher_stage_membership_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    staged_paths = [normalize_artifact_ref(path) for path in manifest.get("staged_launcher_paths") or []]
    staged_packages = [
        package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("staged_launcher_selected") is True
    ]
    if not staged_paths:
        return not staged_packages
    if not staged_packages:
        return False

    staged_text = ""
    for staged_path in staged_paths:
        staged_full_path = ROOT / staged_path
        if not staged_path or not staged_full_path.exists():
            return False
        text = staged_full_path.read_text(encoding="utf-8")
        staged_text += "\n" + text
        if not all(
            marker in text
            for marker in [
                "TAMANDUA_STAGED_LAUNCHER_AGENT_ID",
                "ClaimLockHelperPath",
                "Missing claim lock helper",
                "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId",
                "$env:TAMANDUA_AGENT_ID = $AgentId",
                "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'",
                "-File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId",
            ]
        ):
            return False
        if not re.search(r"(?m)^# Wave: (\d+)\s*$", text):
            return False

    for package in staged_packages:
        package_id = str(package.get("package_id") or "")
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not package_id or not script_path:
            return False
        if f"# Package: {package_id} resources=" not in staged_text:
            return False
        if staged_text.count(f"# Package: {package_id} resources=") != 1:
            return False
        if script_path not in staged_text or f"claim-{package_id}" not in staged_text:
            return False
        if package.get("staged_stage") is None or f"# Stage {package.get('staged_stage')}" not in staged_text:
            return False
    return True


def dispatch_archived_manifest_source_matches_artifact(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if not manifest_path or not source_preflight:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    return normalize_artifact_ref(manifest.get("source_preflight")) == source_preflight


def dispatch_archived_manifest_packages_match_artifact(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    manifest_packages = {
        str(package.get("package_id")): package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    }
    artifact_packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not manifest_packages or len(manifest_packages) != len(artifact_packages):
        return False
    for package in artifact_packages:
        package_id = str(package.get("package_id"))
        manifest_package = manifest_packages.get(package_id)
        if not manifest_package:
            return False
        for key in ("wave", "launcher_selected", "manual_reason", "staged_launcher_selected", "staged_stage"):
            if manifest_package.get(key) != package.get(key):
                return False
        for key in ("resource_tags", "required_env"):
            if [str(value) for value in manifest_package.get(key) or []] != [
                str(value) for value in package.get(key) or []
            ]:
                return False
    return True


def dispatch_archived_manifest_handoff_notes_are_actionable(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    packages = [package for package in manifest.get("packages") or [] if isinstance(package, dict)]
    if not packages:
        return False
    for package in packages:
        notes = [str(value) for value in package.get("handoff_notes") or []]
        if not notes:
            return False
        if package.get("parallelizable_in_wave"):
            if "parallelizable" not in notes:
                return False
        elif "parallelizable_in_wave" in package and "serial-only" not in notes:
            return False
        launcher_selected = package.get("launcher_selected")
        manual_reason = package.get("manual_reason")
        if launcher_selected is True and "parallel-launcher:auto" not in notes:
            return False
        if launcher_selected is False and manual_reason:
            expected_note = (
                f"parallel-launcher:{manual_reason}"
                if str(manual_reason).startswith("blocked:")
                else f"parallel-launcher:manual:{manual_reason}"
            )
            if expected_note not in notes:
                return False
        staged_stage = package.get("staged_stage")
        if staged_stage is not None and f"staged-launcher:stage-{staged_stage}" not in notes:
            return False
        depends_on_waves = [str(value) for value in package.get("depends_on_waves") or []]
        if depends_on_waves and "depends-on-waves:" + ",".join(depends_on_waves) not in notes:
            return False
        effective_env = {str(value) for value in package.get("effective_required_env") or []}
        env_notes = [note for note in notes if note.startswith("env-blocked:")]
        for env_note in env_notes:
            env_values = [value for value in env_note.removeprefix("env-blocked:").split(",") if value]
            if not env_values or not set(env_values).issubset(effective_env):
                return False

    brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    if brief_path:
        brief_full_path = ROOT / brief_path
        if not brief_full_path.exists():
            return False
        brief = brief_full_path.read_text(encoding="utf-8")
        if "Handoff notes" not in brief:
            return False
        for package in packages:
            for note in package.get("handoff_notes") or []:
                if f"`{note}`" not in brief:
                    return False
    return True


def dispatch_archived_brief_recommended_launch_sequence_matches_manifest(
    dispatch_artifact: dict[str, Any],
) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False

    brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    agent_spawn_launcher_path = normalize_artifact_ref(manifest.get("agent_spawn_launcher_path"))
    ready_parallel_path = normalize_artifact_ref(manifest.get("ready_claims_parallel_launcher_path"))
    env_queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    env_bundle_path = normalize_artifact_ref(manifest.get("env_bundle_ready_claims_launcher_path"))
    prelaunch_path = normalize_artifact_ref(manifest.get("dispatch_prelaunch_validation_path"))
    required_paths = [brief_path, agent_spawn_launcher_path, ready_parallel_path, env_queue_path, env_bundle_path, prelaunch_path]
    if not all(required_paths):
        return False
    brief_full_path = ROOT / str(brief_path)
    if not brief_full_path.exists():
        return False
    brief = brief_full_path.read_text(encoding="utf-8")
    if not dispatch_brief_exposes_env_unblock_next_action_handoff(dispatch_artifact):
        return False
    section_start = brief.find("## Recommended Launch Sequence")
    if section_start < 0:
        return False
    if "current_env_multi_agent_actionable=false" in brief and "-Phase ready -Execute -Parallel" in brief:
        return False
    next_section = brief.find("\n## ", section_start + len("## Recommended Launch Sequence"))
    launch_sequence = brief[section_start:] if next_section < 0 else brief[section_start:next_section]
    compact_fragments = [
        "## Recommended Launch Sequence",
        f"-File '{prelaunch_path}'",
        f"-File '{ready_parallel_path}'",
        f"-File '{ready_parallel_path}' -ValidateOnly",
        str(env_queue_path),
        f"-File '{env_bundle_path}'",
        f"-File '{env_bundle_path}' -ValidateOnly",
        "--refresh-claim-status-report",
        str(manifest_path),
    ]
    if all(fragment in launch_sequence for fragment in compact_fragments):
        return True
    expected_fragments = [
        "## Recommended Launch Sequence",
        "1. Dispatch prelaunch validation:",
        f"-File '{prelaunch_path}'",
        "This runs no-execution checks for env queue shape",
        "Wrapped agent spawn dry run:",
        f"-File '{agent_spawn_launcher_path}'",
        "-Provider all -Phase all -ShowBlocked",
        "This prints Codex/Claude spawn commands",
        "1a. Current-env agent execution is not multi-agent actionable:",
        "current_env_multi_agent_actionable=false",
        "1b. Optional env-bundle prelaunch validation after env fill:",
        f"-File '{prelaunch_path}' -ValidateEnvBundle",
        "1c. Optional Codex env-bundle agent execution after complete env fill:",
        "TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'",
        "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
        "-Provider codex -Phase env-bundle -Execute -Parallel",
        "1d. Optional Claude env-bundle agent execution after complete env fill:",
        "-Provider claude -Phase env-bundle -Execute -Parallel",
        "1e. Preferred balanced Codex/Claude env-bundle agent execution after complete env fill:",
        "-Provider balanced -Phase env-bundle -Execute -Parallel",
        "Use one provider per claim",
        "Env-bundle agent execution refuses missing, placeholder, or malformed `env_unblock_queue.json` values before printing spawn commands.",
        "Duplicate-provider execution requires both `-AllowDuplicateProviderPerClaim`",
        "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1",
        "[duplicate-provider-override]",
        "2. Ready package claims:",
        "$env:TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH = '1'",
        f"-File '{ready_parallel_path}'",
        f"-File '{ready_parallel_path}' -ValidateOnly",
        "This launcher runs package scripts directly",
        "3. Fill env bundle:",
        str(env_queue_path),
        "4. Post-env-bundle package claims:",
        f"-File '{env_bundle_path}'",
        f"-File '{env_bundle_path}' -ValidateOnly",
        "5. Refresh claim status:",
        "--refresh-claim-status-report",
        str(manifest_path),
    ]
    positions = []
    for fragment in expected_fragments:
        position = launch_sequence.find(fragment)
        if position < 0:
            return False
        positions.append(position)
    if positions != sorted(positions):
        return False

    staged_paths = [normalize_artifact_ref(path) for path in manifest.get("staged_launcher_paths") or []]
    staged_by_wave: dict[int, str] = {}
    for path in staged_paths:
        if not path:
            continue
        name_parts = Path(path).name.split("-")
        if len(name_parts) < 3 or name_parts[0] != "wave":
            continue
        try:
            staged_by_wave[int(name_parts[1])] = str(path)
        except ValueError:
            continue
    packages = manifest.get("packages") or []
    wave3_scripts = [
        normalize_artifact_ref(package.get("script_path"))
        for package in packages
        if int(package.get("wave") or 0) == 3
    ]
    if not (staged_by_wave.get(1) and staged_by_wave.get(2) and wave3_scripts):
        return True
    continuation_start = brief.find("## Dependency-Gated Continuation")
    if continuation_start < 0:
        return False
    next_section = brief.find("\n## ", continuation_start + len("## Dependency-Gated Continuation"))
    continuation = brief[continuation_start:] if next_section < 0 else brief[continuation_start:next_section]
    continuation_fragments = [
        "## Dependency-Gated Continuation",
        "Run this after the recommended launch sequence and claim-status refresh",
        "Wave 1 staged continuation:",
        staged_by_wave.get(1, ""),
        "Wave 2 staged continuation:",
        "$env:TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH = '1'",
        staged_by_wave.get(2, ""),
        "Requires waves `1` evidence to be green before launch.",
        "Wave 3 closure handoff:",
        str(wave3_scripts[0] or "") if wave3_scripts else "",
        "Requires waves `1`, `2` evidence to be green before launch.",
    ]
    continuation_positions = []
    for fragment in continuation_fragments:
        if not fragment:
            return False
        position = continuation.find(fragment)
        if position < 0:
            return False
        continuation_positions.append(position)
    return continuation_positions == sorted(continuation_positions)


def dispatch_brief_exposes_env_unblock_next_action_handoff(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False

    brief_path = normalize_artifact_ref(manifest.get("dispatch_brief_path"))
    env_queue_path = normalize_artifact_ref(manifest.get("env_unblock_queue_path"))
    if not brief_path or not env_queue_path:
        return False
    brief_full_path = ROOT / brief_path
    if not brief_full_path.exists():
        return False
    brief = brief_full_path.read_text(encoding="utf-8")
    required_brief_markers = [
        f"Env unblock queue: `{env_queue_path}`",
        (
            "Env unblock queue handoff: includes copy/paste `Direct claim next actions:`, "
            "`Other affected claim next actions:`, and compatibility `Affected claim next actions:` context per env."
        ),
    ]
    return all(marker in brief for marker in required_brief_markers)


def prompt_list(values: Any) -> str:
    items = [str(value) for value in values or []]
    return ", ".join(items) if items else "-"


def dispatch_archived_prompts_match_manifest_metadata(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if not manifest_path or not source_preflight:
        return False
    full_path = ROOT / manifest_path
    if not full_path.exists():
        return False
    try:
        manifest = load_json(full_path)
    except json.JSONDecodeError:
        return False
    claim_lock_helper_path = normalize_artifact_ref(manifest.get("claim_lock_helper_path"))
    if not claim_lock_helper_path:
        return False

    checked_prompts = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        prompt_path = normalize_artifact_ref(package.get("prompt_path"))
        script_path = normalize_artifact_ref(package.get("script_path"))
        status_path = normalize_artifact_ref(package.get("status_path"))
        if not package_id or not prompt_path or not script_path or not status_path:
            return False
        prompt_full_path = ROOT / prompt_path
        if not prompt_full_path.exists():
            return False
        prompt_text = prompt_full_path.read_text(encoding="utf-8")
        expected_lines = [
            f"# {package_id}",
            f"Claim ID: claim-{package_id}",
            f"Title: {package.get('title') or ''}",
            f"Wave: {int(package.get('wave') or 0)}",
            f"Owner role: {package.get('recommended_owner_role') or ''}",
            f"Roadmaps: {prompt_list(package.get('roadmaps'))}",
            f"Required env: {prompt_list(package.get('effective_required_env') or package.get('required_env'))}",
            f"Declared package env: {prompt_list(package.get('required_env'))}",
            f"Depends on waves: {prompt_list(package.get('depends_on_waves'))}",
            f"Resource tags: {prompt_list(package.get('resource_tags'))}",
            f"Blocking profiles: {prompt_list(package.get('blocking_profiles'))}",
            f"Source preflight: {source_preflight}",
            f"Script: {script_path}",
            f"Status path: {status_path}",
            f"Claim lock helper: {claim_lock_helper_path}",
            (
                "Claim lock command: powershell -NoProfile -ExecutionPolicy Bypass "
                f"-File '{claim_lock_helper_path}' -ClaimId claim-{package_id} -AgentId <agent-id>"
            ),
            f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_path}'",
        ]
        contract = package.get("claim_output_contract") or {}
        if not isinstance(contract, dict):
            return False
        expected_lines.append(f"Expected JSON profiles: {prompt_list(contract.get('required_json_profile_ids'))}")
        expected_lines.append(
            f"Status JSON required fields: {prompt_list(contract.get('status_required_fields'))}"
        )
        expected_lines.append(
            f"Status JSON allowed status values: {prompt_list(contract.get('status_allowed_values'))}"
        )
        status_full_path = ROOT / status_path
        if status_full_path.exists():
            try:
                status_payload = load_json(status_full_path)
            except json.JSONDecodeError:
                return False
            current_artifacts = [normalize_artifact_ref(value) for value in status_payload.get("artifacts") or []]
            current_missing_profiles = [str(value) for value in status_payload.get("missing_profiles") or []]
            current_exit_code = status_payload.get("exit_code")
            current_status_lines = [
                f"Current status: {str(status_payload.get('status') or 'not_run')}",
                f"Current exit code: {current_exit_code if current_exit_code is not None else '-'}",
                f"Current artifacts: {prompt_list(current_artifacts)}",
                f"Current missing profiles: {prompt_list(current_missing_profiles)}",
            ]
            stale_handoff_lines = [
                "Current status: not_run",
                "Current exit code: -",
                "Current artifacts: -",
                "Current missing profiles: -",
            ]
        else:
            current_status_lines = [
                "Current status: not_run",
                "Current exit code: -",
                "Current artifacts: -",
                "Current missing profiles: -",
            ]
            stale_handoff_lines = []
        current_next_action = {}
        if status_full_path.exists():
            try:
                status_payload = load_json(status_full_path)
            except json.JSONDecodeError:
                status_payload = {}
            artifacts = [normalize_artifact_ref(value) for value in status_payload.get("artifacts") or []]
            for artifact in reversed([value for value in artifacts if value.endswith(".json")]):
                artifact_path = ROOT / artifact
                if not artifact_path.exists():
                    continue
                try:
                    artifact_payload = load_json(artifact_path)
                except json.JSONDecodeError:
                    continue
                action = find_first_nested_dict(artifact_payload, "next_action")
                if action:
                    current_next_action = action
                    break
        if not current_next_action and isinstance(package.get("current_next_action"), dict):
            current_next_action = package.get("current_next_action") or {}
        current_next_action_env = [str(value) for value in current_next_action.get("required_env") or [] if str(value)]
        token_env = str(current_next_action.get("token_env") or "")
        if token_env and token_env not in current_next_action_env:
            current_next_action_env.append(token_env)
        expected_next_action_env = []
        for value in [str(value) for value in package.get("next_action_required_env") or []] + current_next_action_env:
            if value and value not in expected_next_action_env:
                expected_next_action_env.append(value)
        expected_effective_env = []
        for value in [str(value) for value in package.get("effective_required_env") or []] + current_next_action_env:
            if value and value not in expected_effective_env:
                expected_effective_env.append(value)
        static_next_action_env_line = f"Next-action env: {prompt_list(package.get('next_action_required_env'))}"
        current_next_action_env_line = f"Next-action env: {prompt_list(expected_next_action_env)}"
        static_effective_env_line = f"Effective env checklist: {prompt_list(package.get('effective_required_env'))}"
        current_effective_env_line = f"Effective env checklist: {prompt_list(expected_effective_env)}"
        for expected in expected_lines:
            if expected not in prompt_text:
                return False
        if not all(expected in prompt_text for expected in current_status_lines) and not (
            stale_handoff_lines and all(expected in prompt_text for expected in stale_handoff_lines)
        ):
            return False
        if "Next-action env:" not in prompt_text:
            return False
        if "Effective env checklist:" not in prompt_text:
            return False
        checked_prompts += 1
    return checked_prompts > 0


def dispatch_archived_agent_roster_matches_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False

    roster_path = normalize_artifact_ref(manifest.get("agent_roster_path"))
    if not roster_path:
        return False
    roster_full_path = ROOT / roster_path
    if not roster_full_path.exists():
        return False
    roster_text = roster_full_path.read_text(encoding="utf-8")
    if "# Validation Agent Roster" not in roster_text:
        return False
    expected_header = (
        "| Wave | Package | Owner | Launcher | Resources | Required env | "
        "Next-action env | Depends | Script | Prompt | Status | Output contract |"
    )
    if expected_header not in roster_text.splitlines():
        return False

    roster_rows: dict[str, list[str]] = {}
    for line in roster_text.splitlines():
        if not line.startswith("|") or "`" not in line:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 12:
            continue
        cells = ["-" if cell == "`-`" else cell for cell in cells]
        package_id = cells[1].strip("`")
        if not package_id or package_id in roster_rows:
            return False
        roster_rows[package_id] = cells

    manifest_packages = [
        package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    manifest_ids = {str(package.get("package_id")) for package in manifest_packages}
    if set(roster_rows) != manifest_ids:
        return False

    for package in manifest_packages:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        if not package_id:
            return False
        selected = package.get("launcher_selected")
        selected_text = "-" if selected is None else ("auto" if selected else f"manual: {package.get('manual_reason')}")
        def roster_code_list(values: Any) -> str:
            items = [str(value) for value in values or []]
            return ", ".join(f"`{value}`" for value in items) if items else "-"

        script_path = normalize_artifact_ref(package.get("script_path"))
        prompt_path = normalize_artifact_ref(package.get("prompt_path")) or "-"
        status_path = normalize_artifact_ref(package.get("status_path"))
        contract = package.get("claim_output_contract") or {}
        if not isinstance(contract, dict):
            return False
        expected_cells = [
            str(int(package.get("wave") or 0)),
            f"`{package_id}`",
            str(package.get("recommended_owner_role") or "-"),
            selected_text,
            roster_code_list(package.get("resource_tags")),
            roster_code_list(package.get("required_env")),
            roster_code_list(package.get("next_action_required_env")),
            roster_code_list(package.get("depends_on_waves")),
            f"`{script_path}`",
            f"`{prompt_path}`",
            f"`{status_path}`",
            roster_code_list(contract.get("required_json_profile_ids")),
        ]
        if not script_path or not status_path:
            return False
        if roster_rows.get(package_id) != expected_cells:
            return False
    return bool(manifest_packages)


def dispatch_archived_current_action_env_guards_match_manifest(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    if not manifest_path:
        return False
    manifest_full_path = ROOT / manifest_path
    if not manifest_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
    except json.JSONDecodeError:
        return False

    template_path = normalize_artifact_ref(manifest.get("env_template_path"))
    roster_path = normalize_artifact_ref(manifest.get("agent_roster_path"))
    if not template_path or not roster_path:
        return False
    template_full_path = ROOT / template_path
    roster_full_path = ROOT / roster_path
    if not template_full_path.exists() or not roster_full_path.exists():
        return False
    template_text = template_full_path.read_text(encoding="utf-8")
    roster_text = roster_full_path.read_text(encoding="utf-8")

    checked = 0
    for package in manifest.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        script_path = normalize_artifact_ref(package.get("script_path"))
        if not package_id or not script_path:
            return False
        env_names = []
        current_action = package.get("current_next_action") if isinstance(package.get("current_next_action"), dict) else {}
        for value in current_action.get("required_env") or []:
            env_name = str(value)
            if env_name and env_name not in env_names:
                env_names.append(env_name)
        token_env = str(current_action.get("token_env") or "")
        if token_env and token_env not in env_names:
            env_names.append(token_env)
        for value in package.get("current_next_action_required_env") or []:
            env_name = str(value)
            if env_name and env_name not in env_names:
                env_names.append(env_name)
        if not env_names:
            continue

        script_full_path = ROOT / script_path
        if not script_full_path.exists():
            return False
        script_text = script_full_path.read_text(encoding="utf-8")
        checked += 1
        for env_name in env_names:
            if f"$env:{env_name} = '{env_template_placeholder(env_name)}'" not in template_text:
                return False
            if f"`{env_name}`" not in roster_text:
                return False
            if f"'{env_name}'" not in script_text:
                return False
            if "$RequiredEnv" not in script_text or "Missing effective env for package" not in script_text:
                return False
    return checked > 0


def dispatch_archived_manifest_matches_source_preflight_packages(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if not manifest_path or not source_preflight:
        return False
    manifest_full_path = ROOT / manifest_path
    preflight_full_path = ROOT / source_preflight
    if not manifest_full_path.exists() or not preflight_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
        preflight = load_json(preflight_full_path)
    except json.JSONDecodeError:
        return False

    manifest_packages = [
        package
        for package in manifest.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not manifest_packages:
        return False
    manifest_waves = sorted({int(package.get("wave") or 0) for package in manifest_packages})
    expected_waves = sorted(int(value) for value in manifest.get("expected_waves") or [])
    if expected_waves and expected_waves != manifest_waves:
        return False
    expected_package_ids = sorted(str(value) for value in manifest.get("expected_package_ids") or [])
    if expected_package_ids and expected_package_ids != sorted(str(package.get("package_id")) for package in manifest_packages):
        return False
    selection_mode = str(manifest.get("selection_mode") or "")
    if selection_mode == "all":
        allowed_waves = sorted(
            {
                int(package.get("wave") or 0)
                for package in preflight.get("parallel_work_packages") or []
                if isinstance(package, dict) and package.get("package_id")
            }
        )
    elif selection_mode == "wave":
        try:
            selected_wave = int(manifest.get("selected_wave"))
        except (TypeError, ValueError):
            return False
        allowed_waves = [selected_wave]
        if manifest_waves != allowed_waves:
            return False
    else:
        allowed_waves = manifest_waves
    source_packages = [
        package
        for package in preflight.get("parallel_work_packages") or []
        if isinstance(package, dict)
        and package.get("package_id")
        and int(package.get("wave") or 0) in allowed_waves
    ]
    source_by_id = {str(package.get("package_id")): package for package in source_packages}
    manifest_by_id = {str(package.get("package_id")): package for package in manifest_packages}
    if set(source_by_id) != set(manifest_by_id):
        return False

    for package_id, manifest_package in manifest_by_id.items():
        source_package = source_by_id[package_id]
        scalar_fields = (
            "title",
            "wave",
            "recommended_owner_role",
            "parallelizable_in_wave",
            "continue_on_failure",
        )
        for field_name in scalar_fields:
            if manifest_package.get(field_name) != source_package.get(field_name):
                return False
        list_fields = (
            "blocked_run_classes",
            "blocking_profiles",
            "depends_on_waves",
            "expected_profile_ids",
            "manual_prerequisites",
            "required_env",
            "roadmaps",
        )
        for field_name in list_fields:
            if [str(value) for value in manifest_package.get(field_name) or []] != [
                str(value) for value in source_package.get(field_name) or []
            ]:
                return False
        action_fields = ("roadmap", "roadmap_status", "blocking_profiles", "required_env", "action")
        source_actions = [
            {
                field: (
                    [str(value) for value in item.get(field) or []]
                    if field in {"blocking_profiles", "required_env"}
                    else str(item.get(field) or "")
                )
                for field in action_fields
            }
            for item in source_package.get("roadmap_next_actions") or []
            if isinstance(item, dict)
        ]
        manifest_actions = [
            {
                field: (
                    [str(value) for value in item.get(field) or []]
                    if field in {"blocking_profiles", "required_env"}
                    else str(item.get(field) or "")
                )
                for field in action_fields
            }
            for item in manifest_package.get("roadmap_next_actions") or []
            if isinstance(item, dict)
        ]
        if manifest_actions != source_actions:
            return False
        source_inputs = [
            {
                "name": str(item.get("name") or ""),
                "flag": str(item.get("flag") or ""),
                "env": str(item.get("env") or ""),
                "description": str(item.get("description") or ""),
            }
            for item in source_package.get("operator_inputs") or []
            if isinstance(item, dict)
        ]
        manifest_inputs = [
            {
                "name": str(item.get("name") or ""),
                "flag": str(item.get("flag") or ""),
                "env": str(item.get("env") or ""),
                "description": str(item.get("description") or ""),
            }
            for item in manifest_package.get("operator_inputs") or []
            if isinstance(item, dict)
        ]
        if manifest_inputs != source_inputs:
            return False
        if [str(value) for value in manifest_package.get("safe_commands") or []] != [
            str(value) for value in source_package.get("safe_commands") or []
        ]:
            return False
        status_path = normalize_artifact_ref(manifest_package.get("status_path"))
        output_dir = normalize_artifact_ref(manifest_package.get("output_dir"))
        if not status_path or not output_dir or not status_path.endswith("/agent_status.json"):
            return False
        if status_path != f"{output_dir}/agent_status.json":
            return False
        contract = manifest_package.get("claim_output_contract") or {}
        if not isinstance(contract, dict):
            return False
        if str(contract.get("status_file") or "") != "agent_status.json":
            return False
        if str(contract.get("output_dir") or "") != "package output directory":
            return False
        if [str(value) for value in contract.get("status_required_fields") or []] != [
            "package_id",
            "claim_id",
            "agent_id",
            "status",
            "artifacts",
            "blocker_cleared",
            "notes",
            "exit_code",
            "expected_profiles",
            "missing_profiles",
        ]:
            return False
        if [str(value) for value in contract.get("status_allowed_values") or []] != [
            "pass",
            "fail",
            "blocked",
        ]:
            return False
        if [str(value) for value in contract.get("required_json_profile_ids") or []] != [
            str(value) for value in source_package.get("expected_profile_ids") or []
        ]:
            return False
    return True


def preflight_package_required_env(preflight_artifact: dict[str, Any]) -> dict[str, list[str]]:
    packages = preflight_artifact.get("parallel_work_packages") or []
    return {
        str(package.get("package_id")): [str(value) for value in package.get("required_env") or []]
        for package in packages
        if isinstance(package, dict) and package.get("package_id")
    }


def dispatch_archived_handoff_scripts_match_source_commands(dispatch_artifact: dict[str, Any]) -> bool:
    manifest_path = normalize_artifact_ref(dispatch_artifact.get("dispatch_manifest"))
    source_preflight = normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
    if not manifest_path or not source_preflight:
        return False
    manifest_full_path = ROOT / manifest_path
    preflight_full_path = ROOT / source_preflight
    if not manifest_full_path.exists() or not preflight_full_path.exists():
        return False
    try:
        manifest = load_json(manifest_full_path)
        preflight = load_json(preflight_full_path)
    except json.JSONDecodeError:
        return False

    source_by_id = {
        str(package.get("package_id")): package
        for package in preflight.get("parallel_work_packages") or []
        if isinstance(package, dict) and package.get("package_id")
    }
    checked = 0
    for manifest_package in manifest.get("packages") or []:
        if not isinstance(manifest_package, dict) or not manifest_package.get("package_id"):
            continue
        package_id = str(manifest_package.get("package_id"))
        source_package = source_by_id.get(package_id)
        script_path = normalize_artifact_ref(manifest_package.get("script_path"))
        if not source_package or not script_path:
            return False
        script_full_path = ROOT / script_path
        if not script_full_path.exists():
            return False
        script_text = script_full_path.read_text(encoding="utf-8")
        source_commands = [
            str(command).strip()
            for command in source_package.get("safe_commands") or []
            if str(command).strip() and not str(command).strip().startswith("$Out = ")
        ]
        if not source_commands:
            return False
        for command in source_commands:
            if command not in script_text:
                return False
        checked += 1
    return checked > 0


def dispatch_package_summaries_match_artifacts(dispatch_artifact: dict[str, Any]) -> bool:
    packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not packages:
        return False
    checked = 0
    for package in packages:
        artifact_path = normalize_artifact_ref(package.get("artifact_path"))
        if not artifact_path:
            package_status = str(package.get("status") or "")
            package_failures = [str(value) for value in package.get("failures") or []]
            if package_status != "missing" and not (
                package_status in {"blocked", "invalid"} and "missing_package_artifact" in package_failures
            ):
                return False
            if "missing_expected_profile_artifact" not in package_failures:
                return False
            checked += 1
            continue
        full_path = ROOT / artifact_path
        if not full_path.exists():
            return False
        try:
            package_artifact = load_json(full_path)
        except json.JSONDecodeError:
            return False
        quality_gate = package_artifact.get("quality_gate") if isinstance(package_artifact.get("quality_gate"), dict) else {}
        profile_id = str(package_artifact.get("profile_id") or package_artifact.get("profile") or "")
        run_id = str(package_artifact.get("run_id") or full_path.stem)
        status = str(quality_gate.get("status") or ("pass" if quality_gate.get("passed") else "fail"))
        blocking_gaps = [str(value) for value in quality_gate.get("blocking_gaps") or []]
        failures = [str(value) for value in quality_gate.get("failures") or []]
        if profile_id != str(package.get("profile_id") or ""):
            return False
        if run_id != str(package.get("run_id") or ""):
            return False
        if str(package.get("status") or "") == "missing":
            package_failures = [str(value) for value in package.get("failures") or []]
            if "missing_expected_profile_artifact" not in package_failures:
                return False
            continue
        if status != str(package.get("status") or ""):
            return False
        if bool(quality_gate.get("passed")) != bool(package.get("passed")):
            return False
        if blocking_gaps != [str(value) for value in package.get("blocking_gaps") or []]:
            return False
        package_failures = [str(value) for value in package.get("failures") or []]
        if not set(failures).issubset(set(package_failures)):
            return False
        checked += 1
    return checked == len(packages)


def dispatch_package_summaries_reject_unexpected_profile_artifacts(dispatch_artifact: dict[str, Any]) -> bool:
    checked = 0
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        expected_profiles = [str(value) for value in package.get("expected_profile_ids") or []]
        artifact_paths = [normalize_artifact_ref(path) for path in package.get("artifact_paths") or []]
        if not expected_profiles:
            continue
        if not artifact_paths:
            if [str(value) for value in package.get("unexpected_profile_ids") or []]:
                return False
            checked += 1
            continue
        expected_set = set(expected_profiles)
        unexpected_profiles = []
        for artifact_path in artifact_paths:
            full_path = ROOT / artifact_path
            if not full_path.exists():
                return False
            try:
                payload = load_json(full_path)
            except json.JSONDecodeError:
                return False
            profile_id = str(payload.get("profile_id") or payload.get("profile") or "")
            if profile_id and profile_id not in expected_set:
                unexpected_profiles.append(profile_id)
        recorded_unexpected = [str(value) for value in package.get("unexpected_profile_ids") or []]
        if unexpected_profiles != recorded_unexpected:
            return False
        if unexpected_profiles:
            failures = [str(value) for value in package.get("failures") or []]
            if package.get("passed") is not False or "unexpected_profile_artifact" not in failures:
                return False
        checked += 1
    return checked > 0


def dispatch_package_archived_artifacts_include_companions(dispatch_artifact: dict[str, Any]) -> bool:
    packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not packages:
        return False
    checked = 0
    for package in packages:
        artifact_path = normalize_artifact_ref(package.get("artifact_path"))
        if not artifact_path:
            status = str(package.get("status") or "")
            failures = {str(value) for value in package.get("failures") or []}
            if status != "missing" and not (
                status in {"blocked", "invalid"} and "missing_package_artifact" in failures
            ):
                return False
            checked += 1
            continue
        full_path = ROOT / artifact_path
        if not full_path.exists() or full_path.suffix != ".json":
            return False
        archived = {normalize_artifact_ref(path) for path in package.get("archived_artifacts") or []}
        if artifact_path not in archived:
            return False
        expected_existing = {artifact_path}
        for suffix in (".md", ".comparison.json"):
            companion = full_path.with_suffix(suffix)
            if companion.exists():
                expected_existing.add(rel(companion))
        if not expected_existing.issubset(archived):
            return False
        for archived_path in archived:
            archived_full_path = ROOT / archived_path
            if not archived_path.startswith(str(Path(artifact_path).parent).replace("\\", "/")):
                return False
            if not archived_full_path.exists():
                return False
        checked += 1
    return checked > 0


def dispatch_tests_match_package_summaries(dispatch_artifact: dict[str, Any]) -> bool:
    packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    tests = [
        test
        for test in dispatch_artifact.get("tests") or []
        if isinstance(test, dict) and str(test.get("id") or "").startswith("dispatch-package-")
    ]
    if not packages or len(packages) != len(tests):
        return False
    tests_by_package: dict[str, dict[str, Any]] = {}
    for test in tests:
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        package_id = str(evidence.get("package_id") or "")
        if not package_id or package_id in tests_by_package:
            return False
        if test.get("id") != f"dispatch-package-{package_id}":
            return False
        tests_by_package[package_id] = test

    for package in packages:
        package_id = str(package.get("package_id") or "")
        test = tests_by_package.get(package_id)
        if not test:
            return False
        evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
        for key in ("artifact_path", "profile_id", "run_id", "status"):
            if normalize_artifact_ref(evidence.get(key)) != normalize_artifact_ref(package.get(key)):
                return False
        first_gap = package.get("first_gap") if isinstance(package.get("first_gap"), dict) else None
        evidence_first_gap = evidence.get("first_gap") if isinstance(evidence.get("first_gap"), dict) else None
        if first_gap != evidence_first_gap:
            return False
        expected_status = "covered" if package.get("passed") else "missed"
        expected_gap_category = None if package.get("passed") else "dispatch-results"
        if test.get("status") != expected_status:
            return False
        if test.get("gap_category") != expected_gap_category:
            return False
    return True


def dispatch_summary_and_gate_match_packages(dispatch_artifact: dict[str, Any]) -> bool:
    packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("package_id")
    ]
    if not packages:
        return False
    passed_ids = [str(package.get("package_id")) for package in packages if package.get("passed")]
    failed_ids = [str(package.get("package_id")) for package in packages if not package.get("passed")]
    summary = dispatch_artifact.get("summary") if isinstance(dispatch_artifact.get("summary"), dict) else {}
    category = summary.get("category_coverage") if isinstance(summary.get("category_coverage"), dict) else {}
    dispatch_category = (
        category.get("validation_dispatch_results")
        if isinstance(category.get("validation_dispatch_results"), dict)
        else {}
    )
    quality_gate = (
        dispatch_artifact.get("quality_gate") if isinstance(dispatch_artifact.get("quality_gate"), dict) else {}
    )

    try:
        passed_count = int(dispatch_artifact.get("passed_count"))
        failed_count = int(dispatch_artifact.get("failed_count"))
    except (TypeError, ValueError):
        return False
    if passed_count != len(passed_ids) or failed_count != len(failed_ids):
        return False
    expected_status_counts = {
        "pass": 0,
        "fail": 0,
        "blocked": 0,
        "missing": 0,
        "invalid": 0,
        "unknown": 0,
    }
    for package in packages:
        status = str(package.get("status") or "").strip().lower()
        if status not in expected_status_counts:
            status = "unknown"
        expected_status_counts[status] += 1
    status_counts = (
        dispatch_artifact.get("status_counts")
        if isinstance(dispatch_artifact.get("status_counts"), dict)
        else {}
    )
    for key, expected in expected_status_counts.items():
        if int(status_counts.get(key) or 0) != expected:
            return False
    expected_status_totals = {
        "blocked_count": expected_status_counts["blocked"],
        "failed_status_count": expected_status_counts["fail"],
        "missing_count": expected_status_counts["missing"],
        "invalid_count": expected_status_counts["invalid"],
    }
    for key, expected in expected_status_totals.items():
        if int(dispatch_artifact.get(key) or 0) != expected:
            return False
    expected_missing_env = sorted(
        {
            str(value)
            for package in packages
            for value in package.get("agent_missing_required_env") or []
        }
    )
    if sorted(str(value) for value in dispatch_artifact.get("missing_required_env") or []) != expected_missing_env:
        return False
    expected_env_blockers = [
        {
            "package_id": package.get("package_id"),
            "wave": package.get("wave"),
            "title": package.get("title"),
            "recommended_owner_role": package.get("recommended_owner_role"),
            "status": package.get("status"),
            "roadmaps": [str(value) for value in package.get("roadmaps") or []],
            "blocking_profiles": [str(value) for value in package.get("blocking_profiles") or []],
            "blocked_run_classes": [str(value) for value in package.get("blocked_run_classes") or []],
            "missing_required_env": [str(value) for value in package.get("agent_missing_required_env") or []],
            "declared_required_env": [
                str(value)
                for value in package.get("effective_required_env") or package.get("required_env") or []
            ],
        }
        for package in packages
        if package.get("agent_missing_required_env")
    ]
    if dispatch_artifact.get("required_env_blockers") != expected_env_blockers:
        return False
    expected_owner_handoff: dict[str, dict[str, Any]] = {}
    for package in packages:
        owner = str(package.get("recommended_owner_role") or "unassigned")
        entry = expected_owner_handoff.setdefault(
            owner,
            {
                "owner": owner,
                "package_count": 0,
                "passed_count": 0,
                "blocked_count": 0,
                "failed_status_count": 0,
                "missing_count": 0,
                "invalid_count": 0,
                "packages": [],
                "missing_required_env": [],
                "roadmaps": [],
            },
        )
        status = str(package.get("status") or "").strip().lower()
        entry["package_count"] += 1
        if bool(package.get("passed")):
            entry["passed_count"] += 1
        if status == "blocked":
            entry["blocked_count"] += 1
        elif status == "fail":
            entry["failed_status_count"] += 1
        elif status == "missing":
            entry["missing_count"] += 1
        elif status == "invalid":
            entry["invalid_count"] += 1
        entry["packages"].append(
            {
                "package_id": package.get("package_id"),
                "wave": package.get("wave"),
                "status": package.get("status"),
                "title": package.get("title"),
                "parallelizable_in_wave": package.get("parallelizable_in_wave"),
                "depends_on_waves": package.get("depends_on_waves") or [],
                "handoff_notes": package.get("handoff_notes") or [],
            }
        )
        for env_name in package.get("agent_missing_required_env") or []:
            value = str(env_name)
            if value not in entry["missing_required_env"]:
                entry["missing_required_env"].append(value)
        for roadmap in package.get("roadmaps") or []:
            value = str(roadmap)
            if value not in entry["roadmaps"]:
                entry["roadmaps"].append(value)
    expected_owner_handoff_list = []
    for entry in expected_owner_handoff.values():
        entry["missing_required_env"] = sorted(entry["missing_required_env"])
        entry["roadmaps"] = sorted(entry["roadmaps"])
        expected_owner_handoff_list.append(entry)
    expected_owner_handoff_list = sorted(expected_owner_handoff_list, key=lambda item: item["owner"])
    if dispatch_artifact.get("owner_handoff") != expected_owner_handoff_list:
        return False
    expected_summary = {
        "covered": len(passed_ids),
        "missed": len(failed_ids),
        "tests": len(packages),
        "total": len(packages),
        "partial": 0,
        "planned": 0,
        "skipped": 0,
        "execution_failed": 0,
    }
    for key, expected in expected_summary.items():
        if int(summary.get(key) or 0) != expected:
            return False
    if int(dispatch_category.get("covered") or 0) != len(passed_ids):
        return False
    if int(dispatch_category.get("missed") or 0) != len(failed_ids):
        return False
    expected_gate_passed = not failed_ids
    if bool(quality_gate.get("passed")) != expected_gate_passed:
        return False
    if str(quality_gate.get("status") or "") != ("pass" if expected_gate_passed else "fail"):
        return False
    if sorted(str(value) for value in quality_gate.get("blocking_gaps") or []) != sorted(failed_ids):
        return False
    expected_failures = [] if expected_gate_passed else ["dispatch_results_incomplete"]
    if [str(value) for value in quality_gate.get("failures") or []] != expected_failures:
        return False
    return True


def dispatch_markdown_matches_package_summaries(dispatch_artifact: dict[str, Any]) -> bool:
    def expected_agent_evidence_line(agent: dict[str, Any]) -> str:
        agent_bits = []
        for key in (
            "hostname",
            "status",
            "health",
            "last_seen",
            "last_seen_age_seconds",
            "endpoint_telemetry",
            "live_response",
        ):
            if agent.get(key) not in (None, "", []):
                agent_bits.append(f"{key}={agent[key]}")
        return "; ".join(agent_bits)

    run_id = str(dispatch_artifact.get("run_id") or "")
    if not run_id:
        return False
    markdown_path = ROOT / "docs" / "benchmarks" / "runs" / f"{run_id}.md"
    if not markdown_path.exists():
        return False
    markdown = markdown_path.read_text(encoding="utf-8")
    forbidden_patterns = ("/tmp/", "tmp/dispatch", "D:/", "D:\\", "\\tmp\\")
    if any(pattern.lower() in markdown.lower() for pattern in forbidden_patterns):
        return False
    expected_header_lines = [
        f"- Source preflight: `{normalize_artifact_ref(dispatch_artifact.get('source_preflight'))}`",
        f"- Passed packages: `{dispatch_artifact.get('passed_count')}`",
        f"- Failed/missing packages: `{dispatch_artifact.get('failed_count')}`",
        f"- Blocked packages: `{dispatch_artifact.get('blocked_count', 0)}`",
        f"- Failed packages with artifacts: `{dispatch_artifact.get('failed_status_count', 0)}`",
        f"- Missing packages: `{dispatch_artifact.get('missing_count', 0)}`",
        f"- Invalid packages: `{dispatch_artifact.get('invalid_count', 0)}`",
        f"- Missing required env: `{', '.join(str(value) for value in dispatch_artifact.get('missing_required_env') or []) or '-'}`",
    ]
    for expected in expected_header_lines:
        if expected not in markdown:
            return False
    required_env_blockers = dispatch_artifact.get("required_env_blockers") or []
    owner_handoff = dispatch_artifact.get("owner_handoff") or []
    if owner_handoff:
        owner_table_header = "| Owner | Packages | Passed | Blocked | Failed | Missing env | Roadmaps |"
        if "## Owner Handoff" not in markdown or owner_table_header not in markdown:
            return False
        owner_package_table_header = "| Owner | Package | Wave | Status | Title | Depends on waves | Parallel in wave | Handoff notes |"
        if "## Owner Package Queue" not in markdown or owner_package_table_header not in markdown:
            return False
        for owner in owner_handoff:
            owner_needles = [
                f"`{owner.get('owner')}`",
                f"| {owner.get('package_count')} |",
                f"| {owner.get('passed_count')} |",
                f"| {owner.get('blocked_count')} |",
                f"| {owner.get('failed_status_count')} |",
                *[f"`{value}`" for value in owner.get("missing_required_env") or []],
                *[f"`{value}`" for value in owner.get("roadmaps") or []],
            ]
            for expected in owner_needles:
                if expected not in markdown:
                    return False
            for package in owner.get("packages") or []:
                package_needles = [
                    f"`{owner.get('owner')}`",
                    f"`{package.get('package_id')}`",
                    f"`{package.get('status')}`",
                    str(package.get("title") or "-"),
                    str(bool(package.get("parallelizable_in_wave"))).lower(),
                    *[f"`{value}`" for value in package.get("handoff_notes") or []],
                ]
                for expected in package_needles:
                    if expected not in markdown:
                        return False
    if required_env_blockers:
        required_table_header = "| Package | Wave | Owner | Roadmaps | Missing env | Blocking profiles |"
        if "## Required Env Blockers" not in markdown or required_table_header not in markdown:
            return False
        for blocker in required_env_blockers:
            blocker_needles = [
                f"`{blocker.get('package_id')}`",
                f"| {blocker.get('wave') or '-'} |",
                f"`{blocker.get('recommended_owner_role') or '-'}`",
                *[f"`{value}`" for value in blocker.get("roadmaps") or []],
                *[f"`{value}`" for value in blocker.get("missing_required_env") or []],
                *[f"`{value}`" for value in blocker.get("blocking_profiles") or []],
            ]
            for expected in blocker_needles:
                if expected not in markdown:
                    return False
    checked = 0
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("package_id") or "")
        artifact_path = normalize_artifact_ref(package.get("artifact_path"))
        if not package_id:
            return False
        artifact_cell = artifact_path or "-"
        selected = package.get("launcher_selected")
        selected_text = "-" if selected is None else str(bool(selected)).lower()
        first_gap = package.get("first_gap") if isinstance(package.get("first_gap"), dict) else {}
        first_gap_text = first_gap.get("test_id") or "-"
        expected_cells = [
            f"`{package_id}`",
            f"| {package.get('wave') or '-'} |",
            f"| {selected_text} |",
            f"`{package.get('status')}`",
            f"`{artifact_cell}`",
            f"`{first_gap_text}`",
        ]
        for expected in expected_cells:
            if expected not in markdown:
                return False
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        agent = evidence.get("agent") if isinstance(evidence.get("agent"), dict) else {}
        if agent:
            expected_agent_line = expected_agent_evidence_line(agent)
            if not expected_agent_line or f"`{expected_agent_line}`" not in markdown:
                return False
        missing = [str(value) for value in evidence.get("missing") or []]
        if missing and f"`{', '.join(missing)}`" not in markdown:
            return False
        missing_package = evidence.get("missing_package") if isinstance(evidence.get("missing_package"), dict) else {}
        next_action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        if missing_package and next_action:
            next_action_text = render_current_next_action_summary(next_action)
            if f"next_action={next_action_text}" not in markdown:
                return False
        for profile_result in package.get("profile_results") or []:
            if not isinstance(profile_result, dict):
                continue
            profile_evidence = (
                profile_result.get("evidence_excerpt")
                if isinstance(profile_result.get("evidence_excerpt"), dict)
                else {}
            )
            action = (
                profile_evidence.get("next_action")
                if isinstance(profile_evidence.get("next_action"), dict)
                else {}
            )
            if not action:
                continue
            profile_id = str(profile_result.get("profile_id") or "-")
            missing_values = (
                action.get("missing_stability")
                or action.get("missing_readiness")
                or action.get("missing_diagnostics")
                or action.get("missing_endpoints")
                or action.get("missing_profiles")
                or []
            )
            missing_text = ", ".join(str(value) for value in missing_values) or "-"
            action_text = str(action.get("action") or "-")
            action_details = [f"missing={missing_text}", f"action={action_text}"]
            if action.get("login_command"):
                action_details.append("login_command=" + str(action.get("login_command")))
            if action.get("token_login_command"):
                action_details.append("token_login_command=" + str(action.get("token_login_command")))
            if f"`{profile_id}` next action" not in markdown:
                return False
            if f"`{'; '.join(action_details)}`" not in markdown:
                return False
        checked += 1
    return checked > 0


def dispatch_package_evidence_excerpt_is_actionable(dispatch_artifact: dict[str, Any]) -> bool:
    checked = 0
    for package in dispatch_artifact.get("packages") or []:
        if not isinstance(package, dict):
            continue
        if package.get("passed") is True:
            continue
        first_gap = package.get("first_gap") if isinstance(package.get("first_gap"), dict) else {}
        expected_missing = [str(value) for value in first_gap.get("missing") or []]
        evidence = package.get("evidence_excerpt") if isinstance(package.get("evidence_excerpt"), dict) else {}
        profile_results = [
            result for result in package.get("profile_results") or [] if isinstance(result, dict)
        ]
        if not expected_missing and profile_results:
            checked += 1
            continue
        if not expected_missing and isinstance(evidence.get("missing_package"), dict) and evidence.get("missing_package"):
            checked += 1
            continue
        if not expected_missing:
            return False
        actual_missing = [str(value) for value in evidence.get("missing") or []]
        if actual_missing:
            if actual_missing != expected_missing:
                return False
            checked += 1
            continue
        agent = evidence.get("agent") if isinstance(evidence.get("agent"), dict) else {}
        if agent:
            checked += 1
            continue
        if isinstance(evidence.get("next_action"), dict) and evidence.get("next_action"):
            checked += 1
            continue
        if isinstance(evidence.get("missing_package"), dict) and evidence.get("missing_package"):
            checked += 1
            continue
        if actual_missing != expected_missing:
            return False
        checked += 1
    failed_packages = [
        package
        for package in dispatch_artifact.get("packages") or []
        if isinstance(package, dict) and package.get("passed") is not True
    ]
    return checked == len(failed_packages) and checked > 0


def caldera_repeatability_reset_reasons(artifact: dict[str, Any]) -> dict[str, str]:
    reasons: dict[str, str] = {}
    for gap in (artifact.get("quality_gate") or {}).get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        profile = str(evidence.get("profile_id") or "")
        reset = evidence.get("latest_streak_reset") if isinstance(evidence.get("latest_streak_reset"), dict) else {}
        reason = str(reset.get("reason") or "")
        if profile and reason:
            reasons[profile] = reason
    return reasons


def caldera_repeatability_recent_history_profiles(artifact: dict[str, Any]) -> list[str]:
    profiles: set[str] = set()
    for gap in (artifact.get("quality_gate") or {}).get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        profile = str(evidence.get("profile_id") or "")
        history = evidence.get("recent_history")
        if profile and isinstance(history, list) and history:
            profiles.add(profile)
    return sorted(profiles)


def caldera_repeatability_next_actions(artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    actions: dict[str, dict[str, Any]] = {}
    for gap in (artifact.get("quality_gate") or {}).get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        profile = str(evidence.get("profile_id") or "")
        action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        command = str(action.get("next_command_hint") or "")
        required_env = [str(value) for value in action.get("required_env") or []]
        if not profile or not action:
            continue
        actions[profile] = {
            "passes_needed": int(action.get("passes_needed") or 0),
            "profile_file": str(action.get("profile_file") or ""),
            "has_command_hint": "tamandua_detection_validation.py" in command,
            "required_env": required_env,
        }
    return dict(sorted(actions.items()))


def macos_backend_best_candidate_action(artifact: dict[str, Any]) -> dict[str, Any]:
    for gap in (artifact.get("quality_gate") or {}).get("actionable_gaps") or []:
        if not isinstance(gap, dict):
            continue
        evidence = gap.get("evidence") if isinstance(gap.get("evidence"), dict) else {}
        candidate = evidence.get("best_candidate") if isinstance(evidence.get("best_candidate"), dict) else {}
        action = evidence.get("next_action") if isinstance(evidence.get("next_action"), dict) else {}
        if candidate and action:
            return {
                "hostname": candidate.get("hostname"),
                "status": candidate.get("status"),
                "health": candidate.get("health"),
                "missing_readiness": [str(value) for value in candidate.get("missing_readiness") or []],
                "target_hostname": action.get("target_hostname"),
                "has_action": bool(action.get("action")),
            }
        if action:
            return {
                "hostname": None,
                "status": None,
                "health": None,
                "missing_readiness": [str(value) for value in action.get("missing_readiness") or []],
                "target_hostname": action.get("target_hostname"),
                "has_action": bool(action.get("action")),
            }
    return {}


def windows_lab_next_action(artifact: dict[str, Any]) -> dict[str, Any]:
    readiness = artifact.get("windows_lab_readiness") if isinstance(artifact.get("windows_lab_readiness"), dict) else {}
    action = readiness.get("next_action") if isinstance(readiness.get("next_action"), dict) else {}
    target = readiness.get("target") if isinstance(readiness.get("target"), dict) else {}
    if not action:
        return {}
    return {
        "hostname": target.get("hostname"),
        "status": target.get("status"),
        "health": target.get("health"),
        "missing_readiness": [str(value) for value in action.get("missing_readiness") or []],
        "target_hostname": action.get("target_hostname"),
        "has_action": bool(action.get("action")),
    }


def windows_connection_stability_next_action(artifact: dict[str, Any]) -> dict[str, Any]:
    stability = (
        artifact.get("connection_stability")
        if isinstance(artifact.get("connection_stability"), dict)
        else {}
    )
    action = stability.get("next_action") if isinstance(stability.get("next_action"), dict) else {}
    if not action:
        return {}
    return {
        "agent_id": action.get("agent_id"),
        "missing_stability": [str(value) for value in action.get("missing_stability") or []],
        "blockers": [str(value) for value in action.get("blockers") or []],
        "min_stable_session_seconds": action.get("min_stable_session_seconds"),
        "has_action": bool(action.get("action")),
    }


def missing_expected_values(actual: list[str], expected: list[str]) -> list[str]:
    actual_set = set(actual)
    return [value for value in expected if value not in actual_set]


def scorecard_consistency_latest_meets_minimum(latest: dict[str, Any]) -> bool:
    try:
        covered = int(latest.get("covered") or 0)
        tests = int(latest.get("tests") or latest.get("expected_profile_tests") or 0)
    except (TypeError, ValueError):
        return False
    return covered >= MIN_SCORECARD_CONSISTENCY_CHECKS and tests >= MIN_SCORECARD_CONSISTENCY_CHECKS


def consistency_artifact_meets_minimum(artifact: dict[str, Any]) -> bool:
    summary = artifact.get("summary") if isinstance(artifact.get("summary"), dict) else {}
    try:
        covered = int(summary.get("covered") or 0)
        tests = int(summary.get("tests") or summary.get("total") or 0)
    except (TypeError, ValueError):
        return False
    return covered >= MIN_SCORECARD_CONSISTENCY_CHECKS and tests >= MIN_SCORECARD_CONSISTENCY_CHECKS


def consistency_artifact_self_indexes_run(artifact: dict[str, Any], run_id: str) -> bool:
    latest = artifact.get("latest") if isinstance(artifact.get("latest"), dict) else {}
    entry = latest.get(PROFILE_ID) if isinstance(latest.get(PROFILE_ID), dict) else {}
    return str(artifact.get("run_id") or "") == run_id and str(entry.get("run_id") or "") == run_id


def consistency_scorecard_coverage_matches_artifact(latest: dict[str, Any], artifact: dict[str, Any]) -> bool:
    summary = artifact.get("summary") if isinstance(artifact.get("summary"), dict) else {}
    checks = artifact.get("checks") if isinstance(artifact.get("checks"), list) else []
    try:
        scorecard_covered = int(latest.get("covered") or 0)
        scorecard_tests = int(latest.get("tests") or latest.get("expected_profile_tests") or 0)
        artifact_passed = int(
            summary.get("passed")
            or summary.get("covered")
            or sum(1 for check in checks if isinstance(check, dict) and check.get("status") == "PASS")
        )
        artifact_total = int(
            summary.get("total_checks")
            or summary.get("tests")
            or summary.get("total")
            or len(checks)
        )
    except (TypeError, ValueError):
        return False
    exact_match = scorecard_covered == artifact_passed
    failed_consistency_artifact = (
        artifact.get("external_claim_allowed") is False
        and (artifact.get("quality_gate") or {}).get("passed") is False
        and scorecard_covered >= artifact_passed
    )
    return (
        (exact_match or failed_consistency_artifact)
        and scorecard_tests == artifact_total
        and artifact_total >= MIN_SCORECARD_CONSISTENCY_CHECKS
    )


def dispatch_artifact_self_indexes_run(artifact: dict[str, Any], run_id: str) -> bool:
    return str(artifact.get("run_id") or "") == run_id


def dispatch_official_timestamps_are_parseable(artifact: dict[str, Any]) -> bool:
    parsed: dict[str, datetime] = {}
    for field_name in ("generated_at", "summarized_at"):
        value = str(artifact.get(field_name) or "")
        if not value:
            return False
        try:
            parsed[field_name] = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
    return parsed["generated_at"] >= parsed["summarized_at"]


def run_id_timestamp(run_id: str) -> str:
    if not run_id or "-" not in run_id:
        return ""
    return run_id.split("-", 1)[0]


def run_id_is_at_least(run_id: str, other_run_id: str) -> bool:
    stamp = run_id_timestamp(run_id)
    other_stamp = run_id_timestamp(other_run_id)
    return bool(stamp and other_stamp and stamp >= other_stamp)


def scorecard_coverage_string(latest: dict[str, Any]) -> str:
    covered = latest.get("covered")
    tests = latest.get("tests") or latest.get("expected_profile_tests")
    if covered in (None, "") or tests in (None, ""):
        return ""
    return f"{covered}/{tests}"


def build_payload(
    scorecard_path: Path,
    status_docs: list[Path],
    expected_consistency_run_id: str | None = None,
) -> dict[str, Any]:
    scorecard = load_json(scorecard_path)
    scorecard_md_path = scorecard_path.with_suffix(".md")
    scorecard_md_text = load_text(scorecard_md_path)
    closure_latest = latest_profile(scorecard, PROFILE_CLOSURE)
    preflight_latest = latest_profile(scorecard, PROFILE_PREFLIGHT)
    replay_latest = latest_profile(scorecard, PROFILE_REPLAY)
    fresh_restore_latest = latest_profile(scorecard, PROFILE_FRESH_RESTORE)
    dispatch_latest = latest_profile(scorecard, PROFILE_DISPATCH_RESULTS)
    caldera_repeatability_latest = latest_profile(scorecard, PROFILE_CALDERA_REPEATABILITY)
    consistency_latest = latest_profile(scorecard, PROFILE_ID)
    consistency_entry = profile_entry(scorecard, PROFILE_ID)
    consistency_latest_fail = (
        consistency_entry.get("latest_fail") if isinstance(consistency_entry.get("latest_fail"), dict) else {}
    )
    windows_lab_latest = latest_profile(scorecard, PROFILE_WINDOWS_LAB_READINESS)
    windows_connection_latest = latest_profile(scorecard, PROFILE_WINDOWS_CONNECTION_STABILITY)
    macos_backend_latest = latest_profile(scorecard, PROFILE_MACOS_BACKEND_READINESS)
    atomic_t1047_latest = latest_profile(scorecard, PROFILE_ATOMIC_T1047_CAPABILITY)
    linux_ebpf_latest = latest_profile(scorecard, PROFILE_LINUX_EBPF_READINESS)
    windows_qga_entry = profile_entry(scorecard, PROFILE_WINDOWS_QGA_READINESS)
    windows_qga_latest = windows_qga_entry.get("latest") if isinstance(windows_qga_entry.get("latest"), dict) else {}
    windows_qga_aggregate = (
        windows_qga_entry.get("aggregate") if isinstance(windows_qga_entry.get("aggregate"), dict) else {}
    )
    windows_qga_aggregate_source = (
        windows_qga_aggregate.get("latest_raw_gate_pass")
        if isinstance(windows_qga_aggregate.get("latest_raw_gate_pass"), dict)
        else {}
    )

    closure_run = str(closure_latest.get("run_id") or "")
    preflight_run = str(preflight_latest.get("run_id") or "")
    replay_run = str(replay_latest.get("run_id") or "")
    fresh_restore_run = str(fresh_restore_latest.get("run_id") or "")
    dispatch_run = str(dispatch_latest.get("run_id") or "")
    caldera_repeatability_run = str(caldera_repeatability_latest.get("run_id") or "")
    indexed_consistency_run = str(consistency_latest.get("run_id") or "")
    consistency_run = (
        validate_run_id(expected_consistency_run_id)
        if expected_consistency_run_id
        else indexed_consistency_run
    )
    windows_lab_run = str(windows_lab_latest.get("run_id") or "")
    windows_connection_run = str(windows_connection_latest.get("run_id") or "")
    macos_backend_run = str(macos_backend_latest.get("run_id") or "")
    atomic_t1047_run = str(atomic_t1047_latest.get("run_id") or "")
    linux_ebpf_run = str(linux_ebpf_latest.get("run_id") or "")
    windows_qga_latest_run = str(windows_qga_latest.get("run_id") or "")
    windows_qga_aggregate_run = str(windows_qga_aggregate_source.get("run_id") or "")
    closure_coverage = scorecard_coverage_string(closure_latest)
    preflight_coverage = scorecard_coverage_string(preflight_latest)
    fresh_restore_coverage = scorecard_coverage_string(fresh_restore_latest)
    dispatch_coverage = scorecard_coverage_string(dispatch_latest)
    caldera_repeatability_coverage = scorecard_coverage_string(caldera_repeatability_latest)
    windows_lab_coverage = scorecard_coverage_string(windows_lab_latest)
    windows_connection_coverage = scorecard_coverage_string(windows_connection_latest)
    macos_backend_coverage = scorecard_coverage_string(macos_backend_latest)
    atomic_t1047_coverage = scorecard_coverage_string(atomic_t1047_latest)
    linux_ebpf_coverage = scorecard_coverage_string(linux_ebpf_latest)

    closure_path = artifact_path(closure_latest)
    preflight_path = artifact_path(preflight_latest)
    replay_path = artifact_path(replay_latest)
    fresh_restore_path = artifact_path(fresh_restore_latest)
    dispatch_path = artifact_path(dispatch_latest)
    caldera_repeatability_path = artifact_path(caldera_repeatability_latest)
    windows_lab_path = artifact_path(windows_lab_latest)
    windows_connection_path = artifact_path(windows_connection_latest)
    macos_backend_path = artifact_path(macos_backend_latest)
    indexed_consistency_path = artifact_path(consistency_latest)
    prospective_consistency_path = RUNS_DIR / f"{consistency_run}.json"
    prospective_consistency_exists = bool(expected_consistency_run_id and prospective_consistency_path.exists())
    consistency_path = (
        prospective_consistency_path
        if prospective_consistency_exists
        else indexed_consistency_path
    )
    consistency_artifact_run = consistency_run if consistency_path == prospective_consistency_path else indexed_consistency_run

    closure_artifact = load_json(closure_path)
    preflight_artifact = load_json(preflight_path)
    replay_artifact = load_json(replay_path)
    fresh_restore_artifact = load_json(fresh_restore_path)
    dispatch_artifact = load_json(dispatch_path)
    caldera_repeatability_artifact = load_json(caldera_repeatability_path)
    windows_lab_artifact = load_json(windows_lab_path)
    windows_connection_artifact = load_json(windows_connection_path)
    macos_backend_artifact = load_json(macos_backend_path)
    consistency_artifact = load_json(consistency_path)
    roadmap_b_note = roadmap_note(scorecard, "B")
    scorecard_artifact_count_marker = scorecard_artifact_marker(scorecard)
    scorecard_open = scorecard_open_roadmaps(scorecard)
    open_roadmaps = closure_open_roadmaps(closure_artifact)
    blocked_classes = blocked_run_classes(preflight_artifact)
    blocked_class_roadmaps = blocked_run_class_roadmaps(preflight_artifact)
    blocked_class_missing_envs = blocked_run_class_missing_envs(preflight_artifact)
    unblock_steps = unblock_sequence_ids(preflight_artifact)
    unblock_priorities = unblock_sequence_priorities(preflight_artifact)
    parallel_wave_shape = parallel_unblock_wave_shape(preflight_artifact)

    checks: list[dict[str, Any]] = []
    scorecard_source = rel(scorecard_path)
    scorecard_md_source = rel(scorecard_md_path)
    closure_source = rel(closure_path)
    closure_markdown_path = closure_path.with_suffix(".md")
    closure_markdown_source = rel(closure_markdown_path)
    closure_markdown_text = load_text(closure_markdown_path)
    preflight_source = rel(preflight_path)
    replay_source = rel(replay_path)
    fresh_restore_source = rel(fresh_restore_path)
    dispatch_source = rel(dispatch_path)
    caldera_repeatability_source = rel(caldera_repeatability_path)
    windows_lab_source = rel(windows_lab_path)
    windows_connection_source = rel(windows_connection_path)
    macos_backend_source = rel(macos_backend_path)
    consistency_source = rel(consistency_path)
    preflight_work_package_path = ROOT / "tools" / "detection_validation" / "run_preflight_work_package.py"
    preflight_work_package_text = load_text(preflight_work_package_path)

    check(checks, "closure latest run_id present", bool(closure_run), True, [scorecard_source])
    check(checks, "preflight latest run_id present", bool(preflight_run), True, [scorecard_source])
    check(checks, "replay latest run_id present", bool(replay_run), True, [scorecard_source])
    check(checks, "fresh restore latest run_id present", bool(fresh_restore_run), True, [scorecard_source])
    check(checks, "dispatch results latest run_id present", bool(dispatch_run), True, [scorecard_source])
    check(
        checks,
        "CALDERA repeatability latest run_id present",
        bool(caldera_repeatability_run),
        True,
        [scorecard_source],
    )
    check(checks, "windows lab readiness latest run_id present", bool(windows_lab_run), True, [scorecard_source])
    check(
        checks,
        "windows connection stability latest run_id present",
        bool(windows_connection_run),
        True,
        [scorecard_source],
    )
    check(checks, "macOS backend readiness latest run_id present", bool(macos_backend_run), True, [scorecard_source])
    check(checks, "Atomic T1047 capability latest run_id present", bool(atomic_t1047_run), True, [scorecard_source])
    check(checks, "Linux eBPF readiness latest run_id present", bool(linux_ebpf_run), True, [scorecard_source])
    for source in PROXY_SAFE_URLOPEN_FILES:
        source_path = ROOT / source
        text = load_text(source_path) if source_path.exists() else ""
        check(
            checks,
            f"{source} uses proxy-safe urllib opener",
            proxy_safe_urllib_source(text),
            True,
            [source],
        )
    for source in PROXY_SAFE_REQUESTS_SESSION_FILES:
        source_path = ROOT / source
        text = load_text(source_path) if source_path.exists() else ""
        check(
            checks,
            f"{source} disables requests proxy env",
            proxy_safe_requests_source(text),
            True,
            [source],
        )
    check(checks, "closure artifact path exists", closure_path.exists(), True, [scorecard_source, closure_source])
    check(checks, "preflight artifact path exists", preflight_path.exists(), True, [scorecard_source, preflight_source])
    check(checks, "replay artifact path exists", replay_path.exists(), True, [scorecard_source, replay_source])
    check(
        checks,
        "fresh restore artifact path exists",
        fresh_restore_path.exists(),
        True,
        [scorecard_source, fresh_restore_source],
    )
    check(
        checks,
        "dispatch results artifact path exists",
        dispatch_path.exists(),
        True,
        [scorecard_source, dispatch_source],
    )
    check(
        checks,
        "dispatch results official artifact self-indexes its run_id",
        dispatch_artifact_self_indexes_run(dispatch_artifact, dispatch_run),
        True,
        [scorecard_source, dispatch_source],
    )
    check(
        checks,
        "dispatch results official timestamps are parseable",
        dispatch_official_timestamps_are_parseable(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact path exists",
        caldera_repeatability_path.exists(),
        True,
        [scorecard_source, caldera_repeatability_source],
    )
    check(
        checks,
        "consistency latest artifact path exists",
        consistency_path.exists(),
        True,
        [scorecard_source, consistency_source],
    )
    check(
        checks,
        "consistency latest artifact self-indexes its run_id",
        consistency_artifact_self_indexes_run(consistency_artifact, consistency_artifact_run),
        True,
        [scorecard_source, consistency_source],
    )
    check(
        checks,
        "scorecard consistency coverage matches latest artifact summary",
        consistency_scorecard_coverage_matches_artifact(consistency_latest, consistency_artifact),
        True,
        [scorecard_source, consistency_source],
    )
    check(
        checks,
        "consistency artifact blocks external claims",
        bool(consistency_artifact.get("external_claim_allowed")),
        False,
        [consistency_source],
    )
    check(
        checks,
        "dispatch results official metadata matches dispatch profile",
        dispatch_official_metadata_matches_profile(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results official paths are self-contained package artifacts",
        dispatch_official_paths_are_self_contained(dispatch_artifact, dispatch_run),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results official package artifacts exist",
        dispatch_official_paths_exist(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results official payload omits temp and absolute output paths",
        dispatch_official_payload_has_no_tmp(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results official comparison matches payload paths",
        dispatch_official_comparison_matches_payload(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived summary paths are self-contained",
        dispatch_archived_summary_has_self_contained_paths(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest source preflight matches official artifact",
        dispatch_archived_manifest_source_matches_artifact(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest omits temp and absolute output paths",
        dispatch_archived_manifest_has_no_tmp(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest handoff paths exist",
        dispatch_archived_manifest_handoff_paths_exist(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived handoff contents are self-contained",
        dispatch_archived_handoff_contents_are_self_contained(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived handoff execution guards are present",
        dispatch_archived_handoff_execution_guards_present(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived dependent launcher evidence guards are present",
        dispatch_archived_dependent_launcher_evidence_guards_present(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived one-shot runner guard is present",
        dispatch_archived_one_shot_runner_guard_present(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived env checklist includes operator input details",
        dispatch_archived_env_checklist_includes_operator_input_details(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived env template is redacted and complete",
        dispatch_archived_env_template_is_redacted_and_complete(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived owner launch plan matches manifest",
        dispatch_archived_owner_launch_plan_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived owner launch plan JSON matches manifest",
        dispatch_archived_owner_launch_plan_json_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived execution matrix matches owner launch plan",
        dispatch_archived_execution_matrix_matches_owner_plan(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived agent claims match execution matrix",
        dispatch_archived_agent_claims_match_execution_matrix(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived agent spawn plan matches agent claims",
        dispatch_archived_agent_spawn_plan_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived agent spawn launcher matches spawn plan",
        dispatch_archived_agent_spawn_launcher_matches_spawn_plan(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived claim status report matches agent claims",
        dispatch_archived_claim_status_report_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived claim lock helper matches agent claims",
        dispatch_archived_claim_lock_helper_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived env unblock queue matches agent claims",
        dispatch_archived_env_unblock_queue_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived ready claims launcher matches agent claims",
        dispatch_archived_ready_claims_launcher_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived ready claims parallel launcher matches agent claims",
        dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived env-bundle ready claims launcher matches agent claims",
        dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived prelaunch validation matches manifest",
        dispatch_archived_prelaunch_validation_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived brief recommended launch sequence matches manifest",
        dispatch_archived_brief_recommended_launch_sequence_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch brief exposes env unblock next-action handoff",
        dispatch_brief_exposes_env_unblock_next_action_handoff(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived launcher membership matches manifest",
        dispatch_archived_launcher_membership_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived staged launcher stage membership matches manifest",
        dispatch_archived_staged_launcher_stage_membership_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest launcher decisions are replayable",
        dispatch_archived_manifest_launcher_decisions_are_replayable(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived launcher manual reasons match manifest",
        dispatch_archived_launcher_manual_reasons_match_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived launcher selected metadata matches manifest",
        dispatch_archived_launcher_selected_metadata_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest package metadata matches official artifact",
        dispatch_archived_manifest_packages_match_artifact(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest handoff notes are actionable",
        dispatch_archived_manifest_handoff_notes_are_actionable(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived prompts match manifest metadata",
        dispatch_archived_prompts_match_manifest_metadata(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived agent roster matches manifest metadata",
        dispatch_archived_agent_roster_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived current-action env guards match manifest",
        dispatch_archived_current_action_env_guards_match_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch archived manifest package set matches source preflight wave",
        dispatch_archived_manifest_matches_source_preflight_packages(dispatch_artifact),
        True,
        [dispatch_source, preflight_source],
    )
    check(
        checks,
        "dispatch archived handoff scripts match source safe commands",
        dispatch_archived_handoff_scripts_match_source_commands(dispatch_artifact),
        True,
        [dispatch_source, preflight_source],
    )
    check(
        checks,
        "dispatch package summaries match archived artifacts",
        dispatch_package_summaries_match_artifacts(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch package summaries reject unexpected profile artifacts",
        dispatch_package_summaries_reject_unexpected_profile_artifacts(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch package archived artifacts include companions",
        dispatch_package_archived_artifacts_include_companions(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch tests match package summaries",
        dispatch_tests_match_package_summaries(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch summary and gate match packages",
        dispatch_summary_and_gate_match_packages(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch markdown matches package summaries",
        dispatch_markdown_matches_package_summaries(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch package evidence excerpt is actionable",
        dispatch_package_evidence_excerpt_is_actionable(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped blocker_cleared",
        preflight_work_package_text,
        'not isinstance(blocker_cleared_value, bool)',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch records blocker_cleared type violation",
        preflight_work_package_text,
        '"blocker_cleared_not_bool"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-string artifact list entries",
        preflight_work_package_text,
        '"artifacts_not_string_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects blank artifact list entries",
        preflight_work_package_text,
        '"artifacts_has_blank_entry"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-string notes entries",
        preflight_work_package_text,
        '"notes_not_string_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects blank notes entries",
        preflight_work_package_text,
        '"notes_has_blank_entry"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped exit_code",
        preflight_work_package_text,
        '"exit_code_not_int"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent status package mismatch",
        preflight_work_package_text,
        '"agent_status_package_id_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent status claim mismatch",
        preflight_work_package_text,
        '"agent_status_claim_id_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped expected_profiles",
        preflight_work_package_text,
        '"expected_profiles_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-string expected profile entries",
        preflight_work_package_text,
        '"expected_profiles_not_string_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects blank expected profile entries",
        preflight_work_package_text,
        '"expected_profiles_has_blank_entry"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects expected profile mismatch",
        preflight_work_package_text,
        '"agent_status_expected_profiles_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects unknown agent status artifact",
        preflight_work_package_text,
        '"agent_status_unknown_artifact"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects missing agent status artifact",
        preflight_work_package_text,
        '"agent_status_missing_artifact"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent-declared missing profiles as pass",
        preflight_work_package_text,
        '"agent_status_missing_profiles"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects unexpected agent missing profile",
        preflight_work_package_text,
        '"agent_status_unexpected_missing_profile"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-string missing profile entries",
        preflight_work_package_text,
        '"missing_profiles_not_string_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects blank missing profile entries",
        preflight_work_package_text,
        '"missing_profiles_has_blank_entry"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects unexpected agent status path",
        preflight_work_package_text,
        '"agent_status_path_unexpected"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch treats missing declared agent status as not launched",
        preflight_work_package_text,
        "if artifact_paths\n            else {}",
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects output dirs outside manifest workdir",
        preflight_work_package_text,
        '"dispatch_output_dir_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects missing package id",
        preflight_work_package_text,
        '"dispatch_package_id_missing"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped expected profiles",
        preflight_work_package_text,
        '"dispatch_expected_profiles_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid expected profile entries",
        preflight_work_package_text,
        '"dispatch_expected_profiles_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped resource tags",
        preflight_work_package_text,
        '"dispatch_resource_tags_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects empty resource tags",
        preflight_work_package_text,
        '"dispatch_resource_tags_empty"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid resource tag entries",
        preflight_work_package_text,
        '"dispatch_resource_tags_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped required env",
        preflight_work_package_text,
        '"dispatch_required_env_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid required env entries",
        preflight_work_package_text,
        '"dispatch_required_env_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped launcher selection",
        preflight_work_package_text,
        '"dispatch_launcher_selected_not_bool"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects manual selection without reason",
        preflight_work_package_text,
        '"dispatch_manual_reason_missing"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects automatic selection with manual reason",
        preflight_work_package_text,
        '"dispatch_manual_reason_unexpected"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped staged launcher selection",
        preflight_work_package_text,
        '"dispatch_staged_launcher_selected_not_bool"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid staged launcher stage",
        preflight_work_package_text,
        '"dispatch_staged_stage_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid package wave",
        preflight_work_package_text,
        '"dispatch_wave_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped dependency waves",
        preflight_work_package_text,
        '"dispatch_depends_on_waves_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid dependency wave entries",
        preflight_work_package_text,
        '"dispatch_depends_on_waves_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects non-prior dependency waves",
        preflight_work_package_text,
        '"dispatch_depends_on_waves_not_prior"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped safe commands",
        preflight_work_package_text,
        '"dispatch_safe_commands_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid safe command entries",
        preflight_work_package_text,
        '"dispatch_safe_commands_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects unsupported safe commands",
        preflight_work_package_text,
        '"dispatch_safe_commands_unsupported"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped claim output contract",
        preflight_work_package_text,
        '"dispatch_claim_contract_not_dict"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim output profiles",
        preflight_work_package_text,
        '"dispatch_claim_contract_profiles_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mismatched claim output profiles",
        preflight_work_package_text,
        '"dispatch_claim_contract_profiles_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim status fields",
        preflight_work_package_text,
        '"dispatch_claim_contract_status_fields_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim status values",
        preflight_work_package_text,
        '"dispatch_claim_contract_status_values_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped manual prerequisites",
        preflight_work_package_text,
        '"dispatch_manual_prerequisites_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid manual prerequisites",
        preflight_work_package_text,
        '"dispatch_manual_prerequisites_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped operator inputs",
        preflight_work_package_text,
        '"dispatch_operator_inputs_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid operator inputs",
        preflight_work_package_text,
        '"dispatch_operator_inputs_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped roadmap next actions",
        preflight_work_package_text,
        '"dispatch_roadmap_next_actions_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid roadmap next actions",
        preflight_work_package_text,
        '"dispatch_roadmap_next_actions_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped roadmaps",
        preflight_work_package_text,
        '"dispatch_roadmaps_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid roadmaps",
        preflight_work_package_text,
        '"dispatch_roadmaps_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped blocking profiles",
        preflight_work_package_text,
        '"dispatch_blocking_profiles_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid blocking profiles",
        preflight_work_package_text,
        '"dispatch_blocking_profiles_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped blocked run classes",
        preflight_work_package_text,
        '"dispatch_blocked_run_classes_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid blocked run classes",
        preflight_work_package_text,
        '"dispatch_blocked_run_classes_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid recommended owner role",
        preflight_work_package_text,
        '"dispatch_recommended_owner_role_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped continue-on-failure flag",
        preflight_work_package_text,
        '"dispatch_continue_on_failure_not_bool"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid manifest profile id",
        preflight_work_package_text,
        '"dispatch_manifest_profile_id_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects missing manifest source preflight",
        preflight_work_package_text,
        '"dispatch_manifest_source_preflight_missing"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped manifest packages",
        preflight_work_package_text,
        '"dispatch_manifest_packages_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid manifest packages",
        preflight_work_package_text,
        '"dispatch_manifest_packages_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped expected waves",
        preflight_work_package_text,
        '"dispatch_manifest_expected_waves_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid expected waves",
        preflight_work_package_text,
        '"dispatch_manifest_expected_waves_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mismatched expected waves",
        preflight_work_package_text,
        '"dispatch_manifest_expected_waves_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped expected package ids",
        preflight_work_package_text,
        '"dispatch_manifest_expected_package_ids_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid expected package ids",
        preflight_work_package_text,
        '"dispatch_manifest_expected_package_ids_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mismatched expected package ids",
        preflight_work_package_text,
        '"dispatch_manifest_expected_package_ids_mismatch"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid selected wave",
        preflight_work_package_text,
        '"dispatch_manifest_selected_wave_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid selection mode",
        preflight_work_package_text,
        '"dispatch_manifest_selection_mode_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped launcher paths",
        preflight_work_package_text,
        '"dispatch_manifest_launcher_paths_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid launcher paths",
        preflight_work_package_text,
        '"dispatch_manifest_launcher_paths_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects launcher paths outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_launcher_paths_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects mistyped staged launcher paths",
        preflight_work_package_text,
        '"dispatch_manifest_staged_launcher_paths_not_list"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid staged launcher paths",
        preflight_work_package_text,
        '"dispatch_manifest_staged_launcher_paths_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects staged launcher paths outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_staged_launcher_paths_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid agent roster path",
        preflight_work_package_text,
        '"dispatch_manifest_agent_roster_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent roster path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_agent_roster_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid env checklist path",
        preflight_work_package_text,
        '"dispatch_manifest_env_checklist_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects env checklist path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_env_checklist_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid env template path",
        preflight_work_package_text,
        '"dispatch_manifest_env_template_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects env template path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_env_template_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid owner launch plan path",
        preflight_work_package_text,
        '"dispatch_manifest_owner_launch_plan_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects owner launch plan path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_owner_launch_plan_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid owner launch plan JSON path",
        preflight_work_package_text,
        '"dispatch_manifest_owner_launch_plan_json_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects owner launch plan JSON path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_owner_launch_plan_json_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid agent spawn launcher path",
        preflight_work_package_text,
        '"dispatch_manifest_agent_spawn_launcher_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects agent spawn launcher path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_agent_spawn_launcher_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim status report path",
        preflight_work_package_text,
        '"dispatch_manifest_claim_status_report_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects claim status report path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_claim_status_report_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim status report JSON path",
        preflight_work_package_text,
        '"dispatch_manifest_claim_status_report_json_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects claim status report JSON path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_claim_status_report_json_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid claim lock helper path",
        preflight_work_package_text,
        '"dispatch_manifest_claim_lock_helper_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects claim lock helper path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_claim_lock_helper_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid ready claims launcher path",
        preflight_work_package_text,
        '"dispatch_manifest_ready_claims_launcher_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects ready claims launcher path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_ready_claims_launcher_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid ready claims parallel launcher path",
        preflight_work_package_text,
        '"dispatch_manifest_ready_claims_parallel_launcher_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects ready claims parallel launcher path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_ready_claims_parallel_launcher_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid env-bundle ready claims launcher path",
        preflight_work_package_text,
        '"dispatch_manifest_env_bundle_ready_claims_launcher_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects env-bundle ready claims launcher path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_env_bundle_ready_claims_launcher_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid dispatch prelaunch validation path",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_prelaunch_validation_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects dispatch prelaunch validation path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_prelaunch_validation_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid dispatch brief path",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_brief_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects dispatch brief path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_brief_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects invalid dispatch runner path",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_runner_path_invalid"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects dispatch runner path outside manifest",
        preflight_work_package_text,
        '"dispatch_manifest_dispatch_runner_path_outside_manifest"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch rejects pass status with nonzero exit code",
        preflight_work_package_text,
        '"agent_status_pass_exit_code_nonzero"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch records failure status with zero exit code",
        preflight_work_package_text,
        '"agent_status_failure_exit_code_zero"',
        preflight_work_package_path,
    )
    check_contains(
        checks,
        "preflight dispatch records failure status with empty notes",
        preflight_work_package_text,
        '"agent_status_failure_notes_empty"',
        preflight_work_package_path,
    )
    check(
        checks,
        "preflight references latest closure gate",
        preflight_artifact.get("closure_gate_run_id"),
        closure_run,
        [preflight_source, closure_source],
    )
    check(
        checks,
        "preflight preserves closure generated roadmap exclusions",
        preflight_preserves_closure_excluded_roadmaps(preflight_artifact, closure_artifact),
        True,
        [preflight_source, closure_source],
    )
    check(
        checks,
        "preflight broad runs remain blocked when gate failed",
        bool((preflight_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [preflight_source],
    )
    check(
        checks,
        "preflight scorecard blocks external execution claims",
        bool((preflight_artifact.get("scorecard") or {}).get("external_claim_allowed")),
        False,
        [preflight_source],
    )
    check(
        checks,
        "preflight records broad-runs-allowed blocker",
        missing_expected_values(
            collect_nested_values(preflight_artifact.get("quality_gate") or {}, "blocking_gaps"),
            ["execution-preflight-broad-runs-allowed"],
        ),
        [],
        [preflight_source],
    )
    check(
        checks,
        "closure gate is still failed for open roadmaps",
        bool((closure_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [closure_source],
    )
    check(
        checks,
        "closure gate exposes open roadmap list",
        open_roadmaps,
        scorecard_open,
        [closure_source],
    )
    check(
        checks,
        "closure gate records explicit generated roadmap exclusions",
        closure_excluded_roadmaps_valid(closure_artifact, scorecard),
        True,
        [closure_source, scorecard_source],
    )
    check(
        checks,
        "closure gate markdown renders generated roadmap exclusions",
        closure_excluded_roadmaps_markdown_valid(closure_artifact, closure_markdown_text),
        True,
        [closure_source, closure_markdown_source],
    )
    check(
        checks,
        "closure gate exposes actionable roadmap next actions",
        closure_next_actions_valid(closure_artifact, scorecard_open),
        True,
        [closure_source],
    )
    check(
        checks,
        "scorecard indexes latest official Windows readiness artifact",
        windows_lab_run,
        EXPECTED_WINDOWS_LAB_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard Windows readiness is pass 6/6",
        f"{windows_lab_latest.get('raw_quality_gate_passed')} {windows_lab_coverage}",
        "True 6/6",
        [scorecard_source],
    )
    check(
        checks,
        "Windows readiness artifact exposes selected online target",
        windows_lab_next_action(windows_lab_artifact),
        {
            "hostname": "DESKTOP-CQKJ5Q9",
            "status": "online",
            "health": "healthy",
            "missing_readiness": [],
            "target_hostname": "DESKTOP-CQKJ5Q9",
            "has_action": True,
        },
        [windows_lab_source],
    )
    check(
        checks,
        "scorecard indexes latest official Windows connection stability artifact",
        windows_connection_run,
        EXPECTED_WINDOWS_CONNECTION_STABILITY_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard Windows connection stability is pass 5/5",
        f"{windows_connection_latest.get('raw_quality_gate_passed')} {windows_connection_coverage}",
        "True 5/5",
        [scorecard_source],
    )
    check(
        checks,
        "Windows connection stability artifact exposes server-log next action",
        windows_connection_stability_next_action(windows_connection_artifact),
        {
            "agent_id": "7a0f744b-5f7e-44de-a199-8d95029c7993",
            "missing_stability": [],
            "blockers": [],
            "min_stable_session_seconds": 300,
            "has_action": True,
        },
        [windows_connection_source],
    )
    check(
        checks,
        "scorecard indexes latest official macOS backend readiness artifact",
        macos_backend_run,
        EXPECTED_MACOS_BACKEND_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard macOS backend readiness remains fail 1/4",
        f"{macos_backend_latest.get('raw_quality_gate_passed')} {macos_backend_coverage}",
        "False 1/4",
        [scorecard_source],
    )
    check(
        checks,
        "macOS backend artifact exposes best candidate next action",
        macos_backend_best_candidate_action(macos_backend_artifact),
        {
            "hostname": "Victors-MacBook-Pro.local",
            "status": "offline",
            "health": "unknown",
            "missing_readiness": ["status_online", "health_healthy", "fresh_heartbeat"],
            "target_hostname": "Victors-MacBook-Pro.local",
            "has_action": True,
        },
        [macos_backend_source],
    )
    check(
        checks,
        "scorecard indexes latest official Atomic T1047 capability artifact",
        atomic_t1047_run,
        EXPECTED_ATOMIC_T1047_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard Atomic T1047 capability remains pass 4/4 boundary evidence",
        f"{atomic_t1047_latest.get('raw_quality_gate_passed')} {atomic_t1047_coverage}",
        "True 4/4",
        [scorecard_source],
    )
    check(
        checks,
        "scorecard indexes latest official Linux eBPF readiness artifact",
        linux_ebpf_run,
        EXPECTED_LINUX_EBPF_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard Linux eBPF readiness remains partial-scope 1/1",
        f"{linux_ebpf_latest.get('raw_quality_gate_passed')} {linux_ebpf_coverage}",
        "True 1/1",
        [scorecard_source],
    )
    check(
        checks,
        "scorecard QGA aggregate source remains latest green execution proof",
        windows_qga_aggregate_run,
        EXPECTED_WINDOWS_QGA_AGGREGATE_PASS_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard QGA latest raw artifact preserves latest failed diagnostic",
        windows_qga_latest_run,
        EXPECTED_WINDOWS_QGA_LATEST_RAW_RUN,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard markdown displays QGA aggregate-pass on aggregate source line",
        line_contains_all(
            scorecard_md_text,
            [
                PROFILE_WINDOWS_QGA_READINESS,
                EXPECTED_WINDOWS_QGA_AGGREGATE_PASS_RUN,
                "pass",
                "complete",
                "7/7",
            ],
        ),
        True,
        [scorecard_md_source],
    )
    check(
        checks,
        "scorecard regression notes preserve QGA previous fail context",
        line_contains_all(
            scorecard_md_text,
            [
                PROFILE_WINDOWS_QGA_READINESS,
                EXPECTED_WINDOWS_QGA_AGGREGATE_PASS_RUN,
                EXPECTED_WINDOWS_QGA_LATEST_RAW_FAIL_RUN,
            ],
        ),
        True,
        [scorecard_md_source],
    )
    check(
        checks,
        "preflight exposes blocked run class list",
        blocked_classes,
        [
            "macos-server-backed-smoke",
            "windows-atomic-extended",
            "windows-broad",
            "windows-caldera-enterprise",
        ],
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes expected blocked run class roadmap mapping",
        blocked_class_roadmaps,
        EXPECTED_BLOCKED_RUN_CLASS_ROADMAPS,
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes expected blocked run class missing env mapping",
        blocked_class_missing_envs,
        EXPECTED_BLOCKED_RUN_CLASS_MISSING_ENVS,
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes expected unblock sequence order",
        unblock_steps,
        EXPECTED_UNBLOCK_SEQUENCE,
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes expected unblock sequence priorities",
        unblock_priorities,
        EXPECTED_UNBLOCK_SEQUENCE_PRIORITIES,
        [preflight_source],
    )
    check(
        checks,
        "preflight propagates closure roadmap next actions",
        preflight_roadmap_next_actions_valid(preflight_artifact, scorecard_open),
        True,
        [preflight_source, closure_source],
    )
    check(
        checks,
        "preflight exposes expected parallel unblock wave shape",
        parallel_wave_shape,
        EXPECTED_PARALLEL_UNBLOCK_WAVES,
        [preflight_source],
    )
    check(
        checks,
        "preflight Windows QGA package requires Proxmox auth env",
        {
            package_id: preflight_package_required_env(preflight_artifact).get(package_id)
            for package_id in EXPECTED_PREFLIGHT_PACKAGE_REQUIRED_ENVS
        },
        EXPECTED_PREFLIGHT_PACKAGE_REQUIRED_ENVS,
        [preflight_source],
    )
    check(
        checks,
        "offline replay latest pass is 43/43",
        f"{(replay_artifact.get('summary') or {}).get('covered')}/{(replay_artifact.get('summary') or {}).get('tests')}",
        "43/43",
        [replay_source],
    )
    check(
        checks,
        "fresh restore latest remains blocked at 2/5 until real restore evidence exists",
        fresh_restore_coverage,
        "2/5",
        [fresh_restore_source],
    )
    check(
        checks,
        "fresh restore artifact blocks fresh restore claims",
        bool((fresh_restore_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [fresh_restore_source],
    )
    check(
        checks,
        "CALDERA repeatability latest remains blocked at 0/2 until three consecutive passes exist",
        caldera_repeatability_coverage,
        "0/2",
        [caldera_repeatability_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact blocks repeatability claims",
        bool((caldera_repeatability_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [caldera_repeatability_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact exposes expected latest reset reasons",
        caldera_repeatability_reset_reasons(caldera_repeatability_artifact),
        EXPECTED_CALDERA_REPEATABILITY_RESET_REASONS,
        [caldera_repeatability_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact exposes recent history for both profiles",
        caldera_repeatability_recent_history_profiles(caldera_repeatability_artifact),
        sorted(EXPECTED_CALDERA_REPEATABILITY_RESET_REASONS),
        [caldera_repeatability_source],
    )
    check(
        checks,
        "CALDERA repeatability artifact exposes next action hints for both profiles",
        caldera_repeatability_next_actions(caldera_repeatability_artifact),
        EXPECTED_CALDERA_REPEATABILITY_NEXT_ACTIONS,
        [caldera_repeatability_source],
    )
    check(
        checks,
        "scorecard Roadmap B note preserves fresh restore claim boundary markers",
        missing_expected_values([marker for marker in EXPECTED_ROADMAP_B_NOTE_MARKERS if marker in roadmap_b_note], EXPECTED_ROADMAP_B_NOTE_MARKERS),
        [],
        [scorecard_source],
    )
    check(
        checks,
        "scorecard open roadmaps have actionable notes",
        scorecard_open_roadmaps_have_actionable_notes(scorecard),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard markdown renders dry-run profiles as not-executed",
        scorecard_markdown_renders_dry_runs_as_not_executed(scorecard, scorecard_md_text),
        True,
        [scorecard_source, scorecard_md_source],
    )
    check(
        checks,
        "dispatch results remain coordination-only",
        "does not promote package artifacts" in str(dispatch_artifact.get("claim_boundary") or ""),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results reference latest preflight artifact",
        normalize_artifact_ref(dispatch_artifact.get("source_preflight"))
        in {preflight_source, EXPECTED_OFFICIAL_PREFLIGHT_SOURCE},
        True,
        [dispatch_source, preflight_source],
    )
    check(
        checks,
        "dispatch results gate remains failed while wave 1 has open blockers",
        bool((dispatch_artifact.get("quality_gate") or {}).get("passed")),
        False,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results record zero passed packages",
        int(dispatch_artifact.get("passed_count") or 0),
        0,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results latest coverage is no passed packages",
        dispatch_coverage in {"0/5", "0/6"},
        True,
        [scorecard_source, dispatch_source],
    )
    check(
        checks,
        "dispatch results record only failed packages",
        int(dispatch_artifact.get("failed_count") or 0) in {5, 6},
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch missing-package evidence matches manifest expected profiles",
        dispatch_missing_package_evidence_matches_manifest(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results expose Windows connection stability handoff env",
        dispatch_windows_connection_handoff(dispatch_artifact),
        EXPECTED_DISPATCH_WINDOWS_CONNECTION_HANDOFF,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch results expose macOS auth handoff command",
        dispatch_macos_auth_handoff(dispatch_artifact),
        EXPECTED_DISPATCH_MACOS_AUTH_HANDOFF,
        [dispatch_source],
    )
    check(
        checks,
        "dispatch claim handoffs expose macOS auth command",
        dispatch_claim_macos_auth_handoff(dispatch_artifact),
        expected_dispatch_claim_macos_auth_handoff(dispatch_run),
        [dispatch_source],
    )
    check(
        checks,
        "dispatch macOS prompt exposes token next-action env",
        dispatch_macos_prompt_exposes_token_env(dispatch_artifact),
        True,
        [dispatch_source],
    )
    check(
        checks,
        "consistency latest run_id present",
        bool(consistency_run),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "consistency latest run_id is at least latest closure preflight and dispatch",
        all(
            run_id_is_at_least(consistency_run, run_id)
            for run_id in (closure_run, preflight_run, dispatch_run)
        ),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "consistency latest pass supersedes latest consistency fail",
        not consistency_latest_fail
        or run_id_is_at_least(consistency_run, str(consistency_latest_fail.get("run_id") or "")),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard manual claim review exposes dispatch manual claims",
        any(
            isinstance(item, dict)
            and item.get("kind") == "dispatch-claim"
            and item.get("polarity") == "manual"
            for item in scorecard.get("manual_claim_review") or []
        )
        or scorecard_dispatch_manual_claim_review_covers_agent_claims(scorecard, dispatch_artifact),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard manual claim review has no stale roadmap or profile prompts",
        scorecard_manual_claim_review_has_only_dispatch_claims(scorecard),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard dispatch manual claim review is actionable",
        scorecard_dispatch_manual_claim_review_is_actionable(scorecard),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard dispatch manual claim review covers agent claims",
        scorecard_dispatch_manual_claim_review_covers_agent_claims(scorecard, dispatch_artifact),
        True,
        [scorecard_source, dispatch_source],
    )
    check(
        checks,
        "scorecard markdown exposes structured manual claim review",
        scorecard_markdown_exposes_structured_manual_claim_review(SCORECARD_MD),
        True,
        [rel(SCORECARD_MD)],
    )
    check(
        checks,
        "scorecard markdown matches manual claim review fields",
        scorecard_markdown_matches_manual_claim_review(scorecard, SCORECARD_MD),
        True,
        [scorecard_source, rel(SCORECARD_MD)],
    )
    check(
        checks,
        "scorecard pass roadmaps have no newer fail after pass",
        scorecard_pass_roadmaps_have_no_newer_fail_after_pass(scorecard),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard pass roadmaps have latest pass for every profile",
        scorecard_pass_roadmaps_have_latest_pass_for_every_profile(scorecard),
        True,
        [scorecard_source],
    )
    check(
        checks,
        "scorecard pass roadmaps have no open full-scope notes",
        scorecard_pass_roadmaps_have_no_open_full_scope_notes(scorecard),
        True,
        [scorecard_source],
    )
    check(
        checks,
        f"scorecard indexes consistency artifact with at least {MIN_SCORECARD_CONSISTENCY_CHECKS} checks",
        (bool(expected_consistency_run_id) and not prospective_consistency_exists)
        or (
            consistency_artifact_meets_minimum(consistency_artifact)
            if prospective_consistency_exists
            else scorecard_consistency_latest_meets_minimum(consistency_latest)
        ),
        True,
        [scorecard_source],
    )
    closure_required_env = collect_nested_values(closure_artifact, "required_env")
    required_env = collect_nested_values(preflight_artifact, "required_env")
    check(
        checks,
        "closure gate exposes all expected required env inputs",
        missing_expected_values(closure_required_env, EXPECTED_PREFLIGHT_REQUIRED_ENVS),
        [],
        [closure_source],
    )
    check(
        checks,
        "preflight exposes fresh-restore required env inputs",
        any(value.startswith("TAMANDUA_FRESH_RESTORE_") for value in required_env),
        True,
        [preflight_source],
    )
    check(
        checks,
        "preflight exposes all expected required env inputs",
        missing_expected_values(required_env, EXPECTED_PREFLIGHT_REQUIRED_ENVS),
        [],
        [preflight_source],
    )

    preflight_md = preflight_path.with_suffix(".md")
    preflight_md_text = load_text(preflight_md)
    for section in (
        "## Roadmap Blockers",
        "## Run Class Readiness",
        "## Unblock Sequence",
        "## Parallel Unblock Waves",
        "## Parallel Work Packages",
    ):
        check_contains(
            checks,
            f"preflight markdown contains {section}",
            preflight_md_text,
            section,
            preflight_md,
        )
    for marker in EXPECTED_PREFLIGHT_SAFE_COMMAND_MARKERS:
        check_contains(
            checks,
            f"preflight markdown contains safe command marker {marker}",
            preflight_md_text,
            marker,
            preflight_md,
        )

    for doc in status_docs:
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest closure gate", text, closure_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest closure gate coverage on same line",
            line_contains_all(text, [closure_run, closure_coverage]),
            True,
            [rel(doc)],
        )
        check_contains(checks, f"{rel(doc)} references latest preflight", text, preflight_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest preflight coverage on same line",
            line_contains_all(text, [preflight_run, preflight_coverage]),
            True,
            [rel(doc)],
        )
        check(
            checks,
            f"{rel(doc)} references all open roadmaps",
            [roadmap for roadmap in open_roadmaps if roadmap not in text],
            [],
            [rel(doc), closure_source],
        )
        check(
            checks,
            f"{rel(doc)} references all blocked run classes",
            [run_class for run_class in blocked_classes if run_class not in text],
            [],
            [rel(doc), preflight_source],
        )
        check_contains(checks, f"{rel(doc)} references CALDERA API env input", text, "CALDERA_API_KEY", doc)
        check_contains(
            checks,
            f"{rel(doc)} references latest macOS offline blocker",
            text,
            EXPECTED_MACOS_BACKEND_RUN,
            doc,
        )
        for marker in (
            "AgentId may only contain letters",
            "produced no result",
            "Agent spawn sequential execution failed",
            "-ValidateOnly",
            "auth-env",
            "auth-login",
            "Placeholder env bundle values must be replaced before launch",
        ):
            check_contains(
                checks,
                f"{rel(doc)} references dispatch guard marker {marker}",
                text,
                marker,
                doc,
            )
        check_contains(
            checks,
            f"{rel(doc)} references latest CALDERA repeatability",
            text,
            caldera_repeatability_run,
            doc,
        )
        check(
            checks,
            f"{rel(doc)} references latest CALDERA repeatability coverage on same line",
            line_contains_all(text, [caldera_repeatability_run, caldera_repeatability_coverage]),
            True,
            [rel(doc)],
        )
        for reason in EXPECTED_CALDERA_REPEATABILITY_RESET_REASONS.values():
            check_contains(
                checks,
                f"{rel(doc)} references CALDERA repeatability reset reason {reason}",
                text,
                reason,
                doc,
            )
        check_contains(
            checks,
            f"{rel(doc)} references fresh-restore env input prefix",
            text,
            "TAMANDUA_FRESH_RESTORE_",
            doc,
        )
        check_contains(
            checks,
            f"{rel(doc)} references multi-agent roster emission",
            text,
            "--emit-agent-roster",
            doc,
        )
        check_contains(
            checks,
            f"{rel(doc)} references dependent-wave launcher acknowledgement",
            text,
            "TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH",
            doc,
        )
        check_contains(
            checks,
            f"{rel(doc)} references latest consistency run",
            text,
            consistency_run,
            doc,
        )
        check(
            checks,
            f"{rel(doc)} exposes env-bundle current no-go validation",
            doc_exposes_env_bundle_current_no_go(text),
            True,
            [rel(doc)],
        )
        if consistency_latest_fail:
            latest_fail_run = str(consistency_latest_fail.get("run_id") or "")
            check_contains(
                checks,
                f"{rel(doc)} references latest superseded consistency fail",
                text,
                latest_fail_run,
                doc,
            )
            check(
                checks,
                f"{rel(doc)} has no stale latest consistency fail references",
                latest_consistency_fail_references_are_current(text, latest_fail_run),
                True,
                [rel(doc)],
            )
        check_contains(checks, f"{rel(doc)} references latest Windows readiness", text, windows_lab_run, doc)
        check_contains(checks, f"{rel(doc)} references latest macOS backend readiness", text, macos_backend_run, doc)
        if doc.name in {"PARALLEL_EXECUTION_BOARD.md", "REMAINING_VALIDATION_BLOCKERS.md"}:
            check_contains(checks, f"{rel(doc)} references latest Linux eBPF readiness", text, linux_ebpf_run, doc)
        if doc.name == "PARALLEL_EXECUTION_BOARD.md":
            check_contains(
                checks,
                f"{rel(doc)} exposes current-env multi-agent false boundary",
                text,
                "current_env_multi_agent_actionable=false",
                doc,
            )
            check_contains(
                checks,
                f"{rel(doc)} exposes post-env-bundle multi-agent true boundary",
                text,
                "post_env_bundle_multi_agent_actionable=true",
                doc,
            )
            check_contains(
                checks,
                f"{rel(doc)} recommends env-bundle balanced parallel fan-out",
                text,
                "agent_spawn_launcher.ps1 -Provider balanced -Phase env-bundle -Execute -Parallel",
                doc,
            )
    for doc in (ROADMAP_DELIVERY_PLAN_DOC, VALIDATION_MASTER_PLAN_DOC):
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest closure gate", text, closure_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest closure gate coverage on same line",
            line_contains_all(text, [closure_run, closure_coverage]),
            True,
            [rel(doc)],
        )
    for doc in status_docs[:2]:
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest dispatch results", text, dispatch_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest dispatch coverage on same line",
            line_contains_all(text, [dispatch_run, dispatch_coverage]),
            True,
            [rel(doc)],
        )
        check_contains(checks, f"{rel(doc)} references dispatch coordination boundary", text, "coordination-only", doc)
    for doc in status_docs[:2]:
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest replay", text, replay_run, doc)
    for doc in (NEXT_VALIDATION_WORK_QUEUE_DOC, PARALLEL_EXECUTION_BOARD_DOC):
        text = load_text(doc)
        check_contains(
            checks,
            f"{rel(doc)} references sequential authority refresh helper",
            text,
            "tools/detection_validation/refresh_validation_authority.py",
            doc,
        )
        check_contains(
            checks,
            f"{rel(doc)} warns preflight must bind to fresh closure gate",
            text,
            "--closure-gate-json",
            doc,
        )
    refresh_authority_text = load_text(REFRESH_AUTHORITY_SCRIPT)
    refresh_authority_dry_run = load_refresh_authority_dry_run_plan(REFRESH_AUTHORITY_SCRIPT)
    check(
        checks,
        "refresh validation authority helper preserves sequential closure/preflight boundary",
        refresh_authority_script_preserves_sequential_boundary(refresh_authority_text),
        True,
        [rel(REFRESH_AUTHORITY_SCRIPT)],
    )
    check(
        checks,
        "refresh validation authority dry-run emits dependency-ordered plan",
        refresh_authority_dry_run_plan_is_sequential(refresh_authority_dry_run),
        True,
        [rel(REFRESH_AUTHORITY_SCRIPT)],
    )
    gitignore_text = load_text(GITIGNORE)
    product_readiness = load_json(PRODUCT_READINESS_JSON)
    product_readiness_markdown = load_text(PRODUCT_READINESS_MD)
    product_readiness_env_request = load_json(PRODUCT_READINESS_ENV_REQUEST_JSON)
    product_readiness_env_request_markdown = load_text(PRODUCT_READINESS_ENV_REQUEST_MD)
    product_readiness_env_request_schema = load_json(PRODUCT_READINESS_ENV_REQUEST_SCHEMA)
    product_readiness_env_bundle_init = load_text(PRODUCT_READINESS_ENV_BUNDLE_INIT)
    product_readiness_env_bundle_init_schema = load_json(PRODUCT_READINESS_ENV_BUNDLE_INIT_SCHEMA)
    product_readiness_env_bundle_local_env_init = load_text(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_INIT)
    product_readiness_env_bundle_local_env_init_schema = load_json(
        PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_INIT_SCHEMA
    )
    product_readiness_env_bundle_local_env_validate = load_text(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_VALIDATE)
    product_readiness_env_bundle_local_env_validate_schema = load_json(
        PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_VALIDATE_SCHEMA
    )
    product_readiness_env_bundle_check = load_text(PRODUCT_READINESS_ENV_BUNDLE_CHECK)
    product_readiness_env_bundle_runner = load_text(PRODUCT_READINESS_ENV_BUNDLE_RUNNER)
    product_readiness_env_bundle_check_schema = load_json(PRODUCT_READINESS_ENV_BUNDLE_CHECK_SCHEMA)
    product_readiness_env_bundle_runner_schema = load_json(PRODUCT_READINESS_ENV_BUNDLE_RUNNER_SCHEMA)
    product_readiness_env_bundle_runner_status_check = load_text(
        PRODUCT_READINESS_ENV_BUNDLE_RUNNER_STATUS_CHECK
    )
    product_readiness_env_bundle_runner_status_check_schema = load_json(
        PRODUCT_READINESS_ENV_BUNDLE_RUNNER_STATUS_CHECK_SCHEMA
    )
    product_readiness_env_bundle_local_schema = load_json(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_SCHEMA)
    product_readiness_env_bundle_template = load_json(PRODUCT_READINESS_ENV_BUNDLE_TEMPLATE)
    product_readiness_env_bundle_dotenv_template = load_text(PRODUCT_READINESS_ENV_BUNDLE_DOTENV_TEMPLATE)
    product_readiness_operator_check = load_text(PRODUCT_READINESS_OPERATOR_CHECK)
    product_readiness_operator_check_schema = load_json(PRODUCT_READINESS_OPERATOR_CHECK_SCHEMA)
    product_readiness_operator_check_json = load_product_readiness_operator_check_json()
    product_readiness_doctor = load_text(PRODUCT_READINESS_DOCTOR)
    product_readiness_doctor_schema = load_json(PRODUCT_READINESS_DOCTOR_SCHEMA)
    product_readiness_doctor_json = load_product_readiness_doctor_json()
    product_readiness_agent_handoff = load_json(PRODUCT_READINESS_AGENT_HANDOFF_JSON)
    product_readiness_agent_handoff_markdown = load_text(PRODUCT_READINESS_AGENT_HANDOFF_MD)
    product_readiness_agent_handoff_schema = load_json(PRODUCT_READINESS_AGENT_HANDOFF_SCHEMA)
    product_readiness_post_env_runner = load_text(PRODUCT_READINESS_POST_ENV_RUNNER)
    product_readiness_post_env_runner_schema = load_json(PRODUCT_READINESS_POST_ENV_RUNNER_SCHEMA)
    product_readiness_post_env_runner_json = load_product_readiness_post_env_runner_json()
    product_readiness_post_env_runner_contract = load_json(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_JSON)
    product_readiness_post_env_runner_contract_markdown = load_text(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_MD)
    product_readiness_post_env_runner_contract_schema = load_json(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_SCHEMA)
    product_readiness_release_gate_contract = load_json(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_JSON)
    product_readiness_release_gate_contract_markdown = load_text(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_MD)
    product_readiness_release_gate_contract_schema = load_json(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_SCHEMA)
    product_readiness_claim_status_contract = load_json(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_JSON)
    product_readiness_claim_status_contract_markdown = load_text(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_MD)
    product_readiness_claim_status_contract_schema = load_json(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_SCHEMA)
    product_readiness_blocked_run_classes_contract = load_json(PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_JSON)
    product_readiness_blocked_run_classes_contract_markdown = load_text(
        PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_MD
    )
    product_readiness_blocked_run_classes_contract_schema = load_json(
        PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_SCHEMA
    )
    product_readiness_runbook = load_json(PRODUCT_READINESS_RUNBOOK_JSON)
    product_readiness_runbook_markdown = load_text(PRODUCT_READINESS_RUNBOOK_MD)
    product_readiness_runbook_schema = load_json(PRODUCT_READINESS_RUNBOOK_SCHEMA)
    product_readiness_remaining_work = load_json(PRODUCT_READINESS_REMAINING_WORK_JSON)
    product_readiness_remaining_work_markdown = load_text(PRODUCT_READINESS_REMAINING_WORK_MD)
    product_readiness_remaining_work_schema = load_json(PRODUCT_READINESS_REMAINING_WORK_SCHEMA)
    product_readiness_remaining_work_check = load_text(PRODUCT_READINESS_REMAINING_WORK_CHECK)
    product_readiness_remaining_work_check_schema = load_json(PRODUCT_READINESS_REMAINING_WORK_CHECK_SCHEMA)
    product_readiness_remaining_work_check_json = load_product_readiness_remaining_work_check_json()
    product_readiness_ready_now_fanout = load_json(PRODUCT_READINESS_READY_NOW_FANOUT_JSON)
    product_readiness_ready_now_fanout_markdown = load_text(PRODUCT_READINESS_READY_NOW_FANOUT_MD)
    product_readiness_ready_now_fanout_schema = load_json(PRODUCT_READINESS_READY_NOW_FANOUT_SCHEMA)
    product_readiness_ready_now_fanout_check = load_text(PRODUCT_READINESS_READY_NOW_FANOUT_CHECK)
    product_readiness_ready_now_fanout_check_schema = load_json(PRODUCT_READINESS_READY_NOW_FANOUT_CHECK_SCHEMA)
    product_readiness_ready_now_fanout_check_json = load_product_readiness_ready_now_fanout_check_json()
    product_readiness_manual_claim_resolution = load_json(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_JSON)
    product_readiness_manual_claim_resolution_markdown = load_text(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_MD)
    product_readiness_manual_claim_resolution_schema = load_json(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_SCHEMA)
    product_readiness_manual_claim_resolution_check = load_text(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK)
    product_readiness_manual_claim_resolution_check_schema = load_json(
        PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK_SCHEMA
    )
    product_readiness_manual_claim_resolution_check_json = (
        load_product_readiness_manual_claim_resolution_check_json()
    )
    product_readiness_manual_claim_resolution_runner_schema = load_json(
        PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_RUNNER_SCHEMA
    )
    product_readiness_manual_claim_resolution_runner_json = (
        load_product_readiness_manual_claim_resolution_runner_json()
    )
    release_gate_failed_count = int_or_zero(product_readiness_release_gate_contract.get("failed_count"))
    manual_claim_count = len(product_readiness.get("manual_claims") or [])
    remaining_work_open_count = int_or_zero(product_readiness_remaining_work.get("open_count"))
    remaining_work_failed_requirement_count = int_or_zero(
        product_readiness_remaining_work.get("failed_requirement_count")
    )
    ready_now_open_count = int_or_zero(product_readiness_ready_now_fanout.get("open_count"))
    ready_now_count = int_or_zero(product_readiness_ready_now_fanout.get("ready_now_count"))
    check(
        checks,
        "product readiness generated summary matches current blockers",
        product_readiness_summary_matches_current_blockers(
            product_readiness,
            closure_run,
            preflight_run,
            dispatch_run,
        ),
        True,
        [rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness env request matches current missing env summary",
        product_readiness_env_request_matches_summary(product_readiness_env_request, product_readiness),
        True,
        [rel(PRODUCT_READINESS_ENV_REQUEST_JSON), rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness env request schema matches generated env request contract",
        product_readiness_env_request_schema_matches_payload(
            product_readiness_env_request_schema,
            product_readiness_env_request,
        ),
        True,
        [rel(PRODUCT_READINESS_ENV_REQUEST_SCHEMA), rel(PRODUCT_READINESS_ENV_REQUEST_JSON)],
    )
    check(
        checks,
        "product readiness gitignore preserves generated-artifact tracking boundary",
        product_readiness_gitignore_preserves_generated_artifact_tracking_boundary(gitignore_text),
        True,
        [rel(GITIGNORE)],
    )
    check(
        checks,
        "product readiness env bundle checker matches env request",
        product_readiness_env_bundle_artifacts_match_env_request(
            product_readiness_env_bundle_init,
            product_readiness_env_bundle_local_env_init,
            product_readiness_env_bundle_local_env_validate,
            product_readiness_env_bundle_check,
            product_readiness_env_bundle_runner,
            product_readiness_env_bundle_runner_status_check,
            product_readiness_env_bundle_init_schema,
            product_readiness_env_bundle_local_env_init_schema,
            product_readiness_env_bundle_local_env_validate_schema,
            product_readiness_env_bundle_check_schema,
            product_readiness_env_bundle_runner_schema,
            product_readiness_env_bundle_runner_status_check_schema,
            product_readiness_env_bundle_local_schema,
            product_readiness_env_bundle_template,
            product_readiness_env_bundle_dotenv_template,
            product_readiness_env_request,
        ),
        True,
        [
            rel(PRODUCT_READINESS_ENV_BUNDLE_INIT),
            rel(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_INIT),
            rel(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_VALIDATE),
            rel(PRODUCT_READINESS_ENV_BUNDLE_CHECK),
            rel(PRODUCT_READINESS_ENV_BUNDLE_RUNNER),
            rel(PRODUCT_READINESS_ENV_BUNDLE_INIT_SCHEMA),
            rel(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_INIT_SCHEMA),
            rel(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_VALIDATE_SCHEMA),
            rel(PRODUCT_READINESS_ENV_BUNDLE_CHECK_SCHEMA),
            rel(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_SCHEMA),
            rel(PRODUCT_READINESS_ENV_BUNDLE_TEMPLATE),
            rel(PRODUCT_READINESS_ENV_BUNDLE_DOTENV_TEMPLATE),
            rel(PRODUCT_READINESS_ENV_REQUEST_JSON),
        ],
    )
    check(
        checks,
        "product readiness env bundle JSON template matches env request",
        product_readiness_env_bundle_json_template_matches_env_request(
            product_readiness_env_bundle_template,
            product_readiness_env_request,
        ),
        True,
        [rel(PRODUCT_READINESS_ENV_BUNDLE_TEMPLATE), rel(PRODUCT_READINESS_ENV_REQUEST_JSON)],
    )
    check(
        checks,
        "product readiness env bundle dotenv template matches env request",
        product_readiness_env_bundle_dotenv_template_matches_env_request(
            product_readiness_env_bundle_dotenv_template,
            product_readiness_env_request,
        ),
        True,
        [rel(PRODUCT_READINESS_ENV_BUNDLE_DOTENV_TEMPLATE), rel(PRODUCT_READINESS_ENV_REQUEST_JSON)],
    )
    check(
        checks,
        "product readiness operator check JSON matches current blockers",
        product_readiness_operator_check_json_matches_current_blockers(
            product_readiness_operator_check_json,
            [
                "CALDERA_AGENT_PAW",
                "CALDERA_API_KEY",
                "CALDERA_GROUP",
                "TAMANDUA_FRESH_RESTORE",
                "TAMANDUA_FRESH_RESTORE_AGENT_ID",
                "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
                "TAMANDUA_FRESH_RESTORE_HOSTNAME",
                "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
                "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
                "TAMANDUA_FRESH_RESTORE_STARTED_AT",
                "TAMANDUA_FRESH_RESTORE_VMID",
                "TAMANDUA_PROXMOX_PASSWORD",
                "TAMANDUA_SERVER_PASSWORD",
                "TAMANDUA_TOKEN",
            ],
            preflight_run,
        ),
        True,
        [rel(PRODUCT_READINESS_OPERATOR_CHECK), rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness operator check schema matches runtime JSON contract",
        product_readiness_operator_schema_matches_payload(
            product_readiness_operator_check_schema,
            product_readiness_operator_check_json,
        ),
        True,
        [rel(PRODUCT_READINESS_OPERATOR_CHECK_SCHEMA), rel(PRODUCT_READINESS_OPERATOR_CHECK)],
    )
    check(
        checks,
        "product readiness doctor emits current aggregate no-exec state",
        isinstance(product_readiness_doctor_json, dict)
        and product_readiness_doctor_json.get("artifact") == "validation-product-readiness-doctor"
        and product_readiness_doctor_json.get("_doctor_returncode") in (1, 2)
        and product_readiness_doctor_json.get("product_ready") is False
        and product_readiness_doctor_json.get("doctor_contract_valid") is True
        and product_readiness_doctor_json.get("env_bundle_contract_valid") is True
        and (
            product_readiness_doctor_json.get("env_bundle_complete") is True
            or (
                int_or_default(product_readiness_env_request.get("required_env_count")) == 0
                and product_readiness_doctor_json.get("env_bundle_complete") is False
                and product_readiness_doctor_json.get("env_bundle_can_launch") is False
            )
        )
        and product_readiness_doctor_json.get("ready_now_fanout_count")
        == product_readiness_ready_now_fanout.get("ready_now_count")
        and product_readiness_doctor_json.get("ready_now_fanout_lane_item_ids")
        == [
            str(lane.get("item_id") or "")
            for lane in product_readiness_ready_now_fanout.get("lanes") or []
            if isinstance(lane, dict)
        ]
        and product_readiness_doctor_json.get("ready_now_fanout_check_exit_code") == 2
        and isinstance(product_readiness_doctor_json.get("ready_now_fanout_check"), dict)
        and product_readiness_doctor_json.get("ready_now_fanout_check", {}).get("artifact")
        == "validation-product-readiness-ready-now-fanout-check"
        and product_readiness_doctor_json.get("manual_claim_resolution_complete")
        is (int(product_readiness_manual_claim_resolution.get("unresolved_manual_claim_count") or 0) == 0)
        and product_readiness_doctor_json.get("manual_claim_resolution_unresolved_count")
        == product_readiness_manual_claim_resolution.get("unresolved_manual_claim_count")
        and product_readiness_doctor_json.get("manual_claim_resolution_check_exit_code")
        == (0 if int(product_readiness_manual_claim_resolution.get("unresolved_manual_claim_count") or 0) == 0 else 2)
        and isinstance(product_readiness_doctor_json.get("manual_claim_resolution_check"), dict)
        and product_readiness_doctor_json.get("manual_claim_resolution_check", {}).get("artifact")
        == "validation-product-readiness-manual-claim-resolution-check"
        and product_readiness_doctor_json.get("manual_claim_resolution_runner_execute_allowed") is False
        and product_readiness_doctor_json.get("manual_claim_resolution_runner_exit_code")
        == (0 if int(product_readiness_manual_claim_resolution.get("unresolved_manual_claim_count") or 0) == 0 else 2)
        and isinstance(product_readiness_doctor_json.get("manual_claim_resolution_runner"), dict)
        and product_readiness_doctor_json.get("manual_claim_resolution_runner", {}).get("artifact")
        == "validation-product-readiness-manual-claim-resolution-runner"
        and (
            product_readiness_doctor_json.get("can_launch_post_env") is True
            or (
                int_or_default(product_readiness_env_request.get("required_env_count")) == 0
                and product_readiness_doctor_json.get("can_launch_post_env") is False
            )
        )
        and product_readiness_doctor_json.get("recommended_next_action_id")
        in {"launch-ready-after-env-claims", "fill-env-bundle", "refresh-validation-authority"},
        True,
        [rel(PRODUCT_READINESS_DOCTOR), rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness doctor schema matches runtime JSON contract",
        contract_schema_matches_payload(
            product_readiness_doctor_schema,
            {
                key: value
                for key, value in (product_readiness_doctor_json or {}).items()
                if key != "_doctor_returncode"
            },
            "validation-product-readiness-doctor",
        ),
        True,
        [rel(PRODUCT_READINESS_DOCTOR_SCHEMA), rel(PRODUCT_READINESS_DOCTOR)],
    )
    check(
        checks,
        "product readiness post-env runner contract matches summary launch plan",
        product_readiness_post_env_runner_contract_matches_summary(
            product_readiness_post_env_runner_contract,
            product_readiness,
        ),
        True,
        [rel(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_JSON), rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness post-env runner contract schema matches payload",
        contract_schema_matches_payload(
            product_readiness_post_env_runner_contract_schema,
            product_readiness_post_env_runner_contract,
            "validation-product-readiness-post-env-runner-contract",
        ),
        True,
        [rel(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_SCHEMA), rel(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_JSON)],
    )
    check(
        checks,
        "product readiness post-env runner JSON matches contract",
        product_readiness_post_env_runner_json_matches_contract(
            product_readiness_post_env_runner_json,
            product_readiness_post_env_runner_contract,
        ),
        True,
        [rel(PRODUCT_READINESS_POST_ENV_RUNNER), rel(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_JSON)],
    )
    check(
        checks,
        "product readiness post-env runner schema matches runtime JSON contract",
        product_readiness_post_env_runner_schema_matches_payload(
            product_readiness_post_env_runner_schema,
            product_readiness_post_env_runner_json or {},
        ),
        True,
        [rel(PRODUCT_READINESS_POST_ENV_RUNNER_SCHEMA), rel(PRODUCT_READINESS_POST_ENV_RUNNER)],
    )
    check(
        checks,
        "product readiness release gate contract matches summary blockers",
        product_readiness_release_gate_contract_matches_summary(
            product_readiness_release_gate_contract,
            product_readiness,
        ),
        True,
        [rel(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_JSON), rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness release gate contract schema matches payload",
        contract_schema_matches_payload(
            product_readiness_release_gate_contract_schema,
            product_readiness_release_gate_contract,
            "validation-product-readiness-release-gate-contract",
        ),
        True,
        [rel(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_SCHEMA), rel(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_JSON)],
    )
    check(
        checks,
        "product readiness claim status contract matches summary post-agent status gate",
        product_readiness_claim_status_contract_matches_summary(
            product_readiness_claim_status_contract,
            product_readiness,
        ),
        True,
        [rel(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_JSON), rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness claim status contract schema matches payload",
        contract_schema_matches_payload(
            product_readiness_claim_status_contract_schema,
            product_readiness_claim_status_contract,
            "validation-product-readiness-claim-status-contract",
        ),
        True,
        [rel(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_SCHEMA), rel(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_JSON)],
    )
    check(
        checks,
        "product readiness blocked run classes contract matches summary blockers",
        product_readiness_blocked_run_classes_contract_matches_summary(
            product_readiness_blocked_run_classes_contract,
            product_readiness,
        ),
        True,
        [rel(PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_JSON), rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness blocked run classes contract schema matches payload",
        contract_schema_matches_payload(
            product_readiness_blocked_run_classes_contract_schema,
            product_readiness_blocked_run_classes_contract,
            "validation-product-readiness-blocked-run-classes-contract",
        ),
        True,
        [
            rel(PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_SCHEMA),
            rel(PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_JSON),
        ],
    )
    check(
        checks,
        "product readiness runbook matches generated contracts",
        product_readiness_runbook_matches_contracts(
            product_readiness_runbook,
            product_readiness,
            product_readiness_env_request,
            product_readiness_post_env_runner_contract,
            product_readiness_claim_status_contract,
            product_readiness_blocked_run_classes_contract,
        ),
        True,
        [
            rel(PRODUCT_READINESS_RUNBOOK_JSON),
            rel(PRODUCT_READINESS_JSON),
            rel(PRODUCT_READINESS_ENV_REQUEST_JSON),
            rel(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_JSON),
            rel(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_JSON),
            rel(PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_JSON),
        ],
    )
    check(
        checks,
        "product readiness runbook schema matches payload",
        contract_schema_matches_payload(
            product_readiness_runbook_schema,
            product_readiness_runbook,
            "validation-product-readiness-runbook",
        ),
        True,
        [rel(PRODUCT_READINESS_RUNBOOK_SCHEMA), rel(PRODUCT_READINESS_RUNBOOK_JSON)],
    )
    check(
        checks,
        "product readiness remaining work matches generated contracts",
        product_readiness_remaining_work_matches_contracts(
            product_readiness_remaining_work,
            product_readiness,
            product_readiness_release_gate_contract,
            product_readiness_env_request,
            product_readiness_claim_status_contract,
            product_readiness_blocked_run_classes_contract,
            product_readiness_runbook,
        ),
        True,
        [
            rel(PRODUCT_READINESS_REMAINING_WORK_JSON),
            rel(PRODUCT_READINESS_JSON),
            rel(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_JSON),
            rel(PRODUCT_READINESS_ENV_REQUEST_JSON),
            rel(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_JSON),
            rel(PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_JSON),
            rel(PRODUCT_READINESS_RUNBOOK_JSON),
        ],
    )
    check(
        checks,
        "product readiness remaining work schema matches payload",
        contract_schema_matches_payload(
            product_readiness_remaining_work_schema,
            product_readiness_remaining_work,
            "validation-product-readiness-remaining-work",
        ),
        True,
        [rel(PRODUCT_READINESS_REMAINING_WORK_SCHEMA), rel(PRODUCT_READINESS_REMAINING_WORK_JSON)],
    )
    check(
        checks,
        "product readiness remaining work check JSON matches open queue",
        product_readiness_remaining_work_check_json_matches_queue(
            product_readiness_remaining_work_check_json,
            product_readiness_remaining_work,
        ),
        True,
        [rel(PRODUCT_READINESS_REMAINING_WORK_CHECK), rel(PRODUCT_READINESS_REMAINING_WORK_JSON)],
    )
    check(
        checks,
        "product readiness remaining work check schema matches runtime JSON contract",
        product_readiness_remaining_work_check_schema_matches_payload(
            product_readiness_remaining_work_check_schema,
            product_readiness_remaining_work_check_json or {},
        ),
        True,
        [rel(PRODUCT_READINESS_REMAINING_WORK_CHECK_SCHEMA), rel(PRODUCT_READINESS_REMAINING_WORK_CHECK)],
    )
    check(
        checks,
        "product readiness ready-now fanout matches remaining work queue",
        product_readiness_ready_now_fanout_matches_remaining_work(
            product_readiness_ready_now_fanout,
            product_readiness_remaining_work,
        ),
        True,
        [rel(PRODUCT_READINESS_READY_NOW_FANOUT_JSON), rel(PRODUCT_READINESS_REMAINING_WORK_JSON)],
    )
    check(
        checks,
        "product readiness ready-now fanout schema matches payload",
        contract_schema_matches_payload(
            product_readiness_ready_now_fanout_schema,
            product_readiness_ready_now_fanout,
            "validation-product-readiness-ready-now-fanout",
        ),
        True,
        [rel(PRODUCT_READINESS_READY_NOW_FANOUT_SCHEMA), rel(PRODUCT_READINESS_READY_NOW_FANOUT_JSON)],
    )
    check(
        checks,
        "product readiness ready-now fanout check matches fanout contract",
        product_readiness_ready_now_fanout_check_json_matches_contract(
            product_readiness_ready_now_fanout_check_json,
            product_readiness_ready_now_fanout,
        ),
        True,
        [rel(PRODUCT_READINESS_READY_NOW_FANOUT_CHECK), rel(PRODUCT_READINESS_READY_NOW_FANOUT_JSON)],
    )
    check(
        checks,
        "product readiness ready-now fanout check schema matches runtime JSON contract",
        product_readiness_ready_now_fanout_check_schema_matches_payload(
            product_readiness_ready_now_fanout_check_schema,
            product_readiness_ready_now_fanout_check_json or {},
        ),
        True,
        [rel(PRODUCT_READINESS_READY_NOW_FANOUT_CHECK_SCHEMA), rel(PRODUCT_READINESS_READY_NOW_FANOUT_CHECK)],
    )
    check(
        checks,
        "product readiness manual-claim resolution contract matches summary",
        product_readiness_manual_claim_resolution_matches_summary(
            product_readiness_manual_claim_resolution,
            product_readiness,
        ),
        True,
        [rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_JSON), rel(PRODUCT_READINESS_JSON)],
    )
    check(
        checks,
        "product readiness manual-claim resolution schema matches payload",
        contract_schema_matches_payload(
            product_readiness_manual_claim_resolution_schema,
            product_readiness_manual_claim_resolution,
            "validation-product-readiness-manual-claim-resolution",
        ),
        True,
        [
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_SCHEMA),
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_JSON),
        ],
    )
    check(
        checks,
        "product readiness manual-claim resolution check JSON matches contract",
        product_readiness_manual_claim_resolution_check_json_matches_contract(
            product_readiness_manual_claim_resolution_check_json,
            product_readiness_manual_claim_resolution,
        ),
        True,
        [
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK),
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_JSON),
        ],
    )
    check(
        checks,
        "product readiness manual-claim resolution check schema matches runtime JSON contract",
        product_readiness_manual_claim_resolution_check_schema_matches_payload(
            product_readiness_manual_claim_resolution_check_schema,
            product_readiness_manual_claim_resolution_check_json or {},
        ),
        True,
        [
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK_SCHEMA),
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK),
        ],
    )
    check(
        checks,
        "product readiness manual-claim resolution runner JSON matches contract",
        product_readiness_manual_claim_resolution_runner_json_matches_contract(
            product_readiness_manual_claim_resolution_runner_json,
            product_readiness_manual_claim_resolution,
        ),
        True,
        [
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_RUNNER),
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_JSON),
        ],
    )
    check(
        checks,
        "product readiness manual-claim resolution runner schema matches runtime JSON contract",
        product_readiness_manual_claim_resolution_runner_schema_matches_payload(
            product_readiness_manual_claim_resolution_runner_schema,
            product_readiness_manual_claim_resolution_runner_json or {},
        ),
        True,
        [
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_RUNNER_SCHEMA),
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_RUNNER),
        ],
    )
    check(
        checks,
        "product readiness agent handoff matches generated contracts",
        product_readiness_agent_handoff_matches_contracts(
            product_readiness_agent_handoff,
            product_readiness,
            product_readiness_env_request,
            product_readiness_post_env_runner_contract,
            product_readiness_release_gate_contract,
            product_readiness_claim_status_contract,
            product_readiness_blocked_run_classes_contract,
            product_readiness_runbook,
            product_readiness_remaining_work,
            product_readiness_ready_now_fanout,
            product_readiness_manual_claim_resolution,
        ),
        True,
        [
            rel(PRODUCT_READINESS_AGENT_HANDOFF_JSON),
            rel(PRODUCT_READINESS_JSON),
            rel(PRODUCT_READINESS_ENV_REQUEST_JSON),
            rel(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_JSON),
            rel(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_JSON),
            rel(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_JSON),
            rel(PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_JSON),
            rel(PRODUCT_READINESS_RUNBOOK_JSON),
            rel(PRODUCT_READINESS_REMAINING_WORK_JSON),
            rel(PRODUCT_READINESS_READY_NOW_FANOUT_JSON),
            rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_JSON),
        ],
    )
    check(
        checks,
        "product readiness agent handoff schema matches payload",
        contract_schema_matches_payload(
            product_readiness_agent_handoff_schema,
            product_readiness_agent_handoff,
            "validation-product-readiness-agent-handoff",
        ),
        True,
        [rel(PRODUCT_READINESS_AGENT_HANDOFF_SCHEMA), rel(PRODUCT_READINESS_AGENT_HANDOFF_JSON)],
    )
    for marker in [
        "Product ready: `false`",
        "Product Release Gate",
        f"Failed requirements: `{release_gate_failed_count}`",
        "`post-agent-status`",
        "Next Action Order",
        "`check-current-env`",
        "validation_product_readiness_operator_check.ps1",
        "-Json",
        "`refresh-validation-authority`",
        "`refresh-validation-authority`",
        "Current env missing: `0`",
        "Missing Env Details",
        "Ready after full env bundle:",
        "Still blocked after full env bundle:",
        "Env Impact",
        "Single Env Fast Paths",
        "Copy/Paste Env Bundle",
        "Post Env Bundle Plan",
        "Actionable: `false`",
        "Ready batches: `0`",
        "Post Agent Status Gate",
        "Ready-after-env passed: `0/0`",
        "claim_status_report.json",
        "--refresh-claim-status-report",
        "Handoff Artifacts",
        "`env_template`",
        "`agent_spawn_plan`",
        "`dispatch_prelaunch_validation`",
        "Manual Claims",
        "`wave-1-resolve-atomic-extended-preconditions`",
        "WMI-capable disposable target",
        "validation_product_readiness_env_bundle_runner.ps1",
        "-UseBalancedAgents -Execute -RefreshClaimStatus",
        "Blocked by env: `0`",
        f"Manual required: `{manual_claim_count}`",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_MD)} preserves product readiness marker {marker}",
            product_readiness_markdown,
            marker,
            PRODUCT_READINESS_MD,
        )
    for marker in [
        "Product Readiness Env Request",
        "Required env: `0`",
        "Secrets: `0`",
        "Metadata: `0`",
        "Copy/Paste PowerShell",
        "do not paste real secret values",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_ENV_REQUEST_MD)} preserves env request marker {marker}",
            product_readiness_env_request_markdown,
            marker,
            PRODUCT_READINESS_ENV_REQUEST_MD,
        )
    for marker in [
        "Product Readiness Env Bundle Init",
        "validation_product_readiness_env_bundle.template.json",
        "validation_product_readiness_env_bundle.local.json",
        "validation_product_readiness_env_bundle_check.ps1",
        "[string]$EnvFile",
        "[switch]$FromProcessEnv",
        "[switch]$Force",
        "[switch]$Json",
        "validation-product-readiness-env-bundle-init",
        "from_process_env",
        "from_env_file",
        "missing_env_names",
        "No secret values were printed.",
        "output omits secret values and does not validate or launch claims",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_ENV_BUNDLE_INIT)} preserves env-bundle-init marker {marker}",
            product_readiness_env_bundle_init,
            marker,
            PRODUCT_READINESS_ENV_BUNDLE_INIT,
        )
    for marker in [
        "Product Readiness Env Bundle Local Env Init",
        "validation_product_readiness_env_bundle.template.env",
        "validation_product_readiness_env_bundle.local.env",
        "validation_product_readiness_env_bundle_init.ps1",
        "[switch]$Force",
        "[switch]$Json",
        "validation-product-readiness-env-bundle-local-env-init",
        "init_command",
        "refusing to overwrite without -Force",
        "Next: edit placeholders locally",
        "No secret values were printed.",
        "output omits secret values and does not validate or launch claims",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_INIT)} preserves local-env-init marker {marker}",
            product_readiness_env_bundle_local_env_init,
            marker,
            PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_INIT,
        )
    for marker in [
        "Product Readiness Env Bundle Local Env Validate",
        "validation_product_readiness_env_bundle.local.env",
        "validation_product_readiness_env_bundle_init.ps1",
        "validation_product_readiness_env_bundle_check.ps1",
        "validation_product_readiness_env_bundle_runner.ps1",
        "validation_product_readiness_doctor.ps1",
        "[switch]$PrepareIfMissing",
        "[switch]$Json",
        "validation-product-readiness-env-bundle-local-env-validate",
        "can_launch_post_env",
        "next_action_command",
        "post_env_launch_refresh_authority_command",
        "-UseBalancedAgents -Execute -RefreshClaimStatus",
        "edit local dotenv placeholders",
        "No secret values were printed.",
        "does not launch claims",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_VALIDATE)} preserves local-env-validate marker {marker}",
            product_readiness_env_bundle_local_env_validate,
            marker,
            PRODUCT_READINESS_ENV_BUNDLE_LOCAL_ENV_VALIDATE,
        )
    for marker in [
        "Product Readiness Env Bundle Check",
        "validation_product_readiness_env_request.json",
        "validation_product_readiness_env_bundle.local.json",
        "[switch]$Json",
        "validation-product-readiness-env-bundle-check",
        "bundle_exists",
        "missing_env_names",
        "placeholder_env_names",
        "unexpected_env_names",
        "can_launch_after_import",
        "output intentionally omits secret values",
        "does not import env or launch claims",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_ENV_BUNDLE_CHECK)} preserves env-bundle-check marker {marker}",
            product_readiness_env_bundle_check,
            marker,
            PRODUCT_READINESS_ENV_BUNDLE_CHECK,
        )
    for marker in [
        "Product Readiness Env Bundle Runner",
        "validation_product_readiness_env_bundle.local.json",
        "validation_product_readiness_env_bundle_check.ps1",
        "validation_product_readiness_env_bundle_init.ps1",
        "validation_product_readiness_post_env_bundle_runner.ps1",
        "refresh_validation_authority.py",
        "[switch]$InitFromProcessEnv",
        "[switch]$UseBalancedAgents",
        "[switch]$Execute",
        "[switch]$RefreshClaimStatus",
        "[switch]$RefreshAuthority",
        "[switch]$Json",
        "validation-product-readiness-env-bundle-runner",
        "json_status_mode_refuses_launch_flags",
        "ready_to_launch",
        "env_bundle_incomplete",
        "No secret values were printed or imported.",
        "JSON status mode does not import secret values or delegate to the post-env runner.",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_ENV_BUNDLE_RUNNER)} preserves env-bundle-runner marker {marker}",
            product_readiness_env_bundle_runner,
            marker,
            PRODUCT_READINESS_ENV_BUNDLE_RUNNER,
        )
    for marker in [
        "Product Readiness Env Bundle Runner Status Check",
        "validation_product_readiness_env_bundle_runner.ps1",
        "validation_product_readiness_env_bundle_runner.schema.json",
        "[switch]$InitFromProcessEnv",
        "[switch]$Json",
        "validation-product-readiness-env-bundle-runner-status-check",
        "runner_contract_valid",
        "runner_complete",
        "runner_can_launch",
        "runner_status_reason",
        "missing_schema_fields",
        "invalid_enum_fields",
        "status check validates runner JSON shape only",
        "does not import secret values or launch claims",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_ENV_BUNDLE_RUNNER_STATUS_CHECK)} preserves env-bundle-runner-status-check marker {marker}",
            product_readiness_env_bundle_runner_status_check,
            marker,
            PRODUCT_READINESS_ENV_BUNDLE_RUNNER_STATUS_CHECK,
        )
    for marker in [
        "Product Readiness Operator Check",
        "validation_product_readiness_summary.json",
        "[switch]$Json",
        "ConvertTo-Json -Depth 12",
        "schema_version = 1",
        "validation-product-readiness-operator-check",
        "product_release_gate",
        "recommended_next_action_id",
        "recommended_next_action_commands",
        "automation_state",
        "can_launch_now",
        "needs_env_input",
        "missing_env_details",
        "post_env_bundle_plan",
        "post_agent_status_gate",
        "handoff_artifacts",
        "manual_claims",
        "Single-env fast paths ready now",
        "Full env bundle ready now",
        "Missing set commands",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_OPERATOR_CHECK)} preserves operator-check marker {marker}",
            product_readiness_operator_check,
            marker,
            PRODUCT_READINESS_OPERATOR_CHECK,
        )
    for marker in [
        "Product Readiness Doctor",
        "validation_product_readiness_summary.json",
        "validation_product_readiness_operator_check.ps1",
        "validation_product_readiness_env_bundle_runner_status_check.ps1",
        "validation_product_readiness_remaining_work_check.ps1",
        "validation_product_readiness_ready_now_fanout_check.ps1",
        "validation_product_readiness_manual_claim_resolution_check.ps1",
        "[switch]$InitFromProcessEnv",
        "[switch]$Json",
        "validation-product-readiness-doctor",
        "doctor_contract_valid",
        "ready_now_fanout_count",
        "ready_now_fanout_lane_item_ids",
        "ready_now_fanout_check_exit_code",
        "manual_claim_resolution_unresolved_count",
        "manual_claim_resolution_check_exit_code",
        "recommended_next_action_id",
        "fill-env-bundle",
        "doctor aggregates no-execution readiness checks only",
        "does not import secret values or launch claims",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_DOCTOR)} preserves doctor marker {marker}",
            product_readiness_doctor,
            marker,
            PRODUCT_READINESS_DOCTOR,
        )
    for marker in [
        "Product Readiness Post-Env Bundle Runner",
        "validation_product_readiness_summary.json",
        "validation_product_readiness_operator_check.ps1",
        "[switch]$UseBalancedAgents",
        "[switch]$Execute",
        "[switch]$RefreshClaimStatus",
        "full_env_bundle_ready",
        "Execute not set; printing launch commands only.",
        "TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH",
        "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH",
        "balanced_agent_spawn_commands",
        "package_launcher_commands",
        "refresh_command",
        "Invoke-Expression $ValidateCommand",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_POST_ENV_RUNNER)} preserves post-env runner marker {marker}",
            product_readiness_post_env_runner,
            marker,
            PRODUCT_READINESS_POST_ENV_RUNNER,
        )
    for marker in [
        "Product Readiness Post-Env Runner Contract",
        "Required env: `0`",
        "Ready claims: `0`",
        "Still blocked claims: `0`",
        "`dry-run`",
        "`package-launcher`",
        "`balanced-agent-fanout`",
        "-UseBalancedAgents -Execute -RefreshClaimStatus",
        "`execute_switch_required_for_claim_launch`",
        "`env_bundle_validate_only_passes_before_launch`",
        "validation_product_readiness_post_env_bundle_runner.ps1",
        "--refresh-claim-status-report",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_MD)} preserves post-env runner contract marker {marker}",
            product_readiness_post_env_runner_contract_markdown,
            marker,
            PRODUCT_READINESS_POST_ENV_RUNNER_CONTRACT_MD,
        )
    for marker in [
        "Product Readiness Release Gate Contract",
        "Product ready: `false`",
        "External claim allowed: `false`",
        "Release gate passed: `false`",
        f"Failed requirements: `{release_gate_failed_count}`",
        "Required env: `0`",
        "Ready-after-env passed: `0/0`",
        "Blocked run classes: `5`",
        "Local Env Bundle Gate",
        "validation_product_readiness_env_bundle.local.json",
        "Exists: `true`",
        "Complete: `false`",
        "Present env: `0/0`",
        "Placeholder env: `0`",
        "`closure-gate`",
        "`preflight-gate`",
        "`dispatch-gate`",
        "`required-env`",
        "`blocked-env-claims`",
        "`post-agent-status`",
        "`blocked-run-classes`",
        "latest roadmap-closure-gate-probe quality_gate.passed=true",
        "validation_product_readiness_post_env_bundle_runner.contract.md",
        "validation_product_readiness_operator_check.ps1",
        "validation_product_readiness_env_bundle_runner.ps1",
        "every release-gate requirement",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_RELEASE_GATE_CONTRACT_MD)} preserves release-gate contract marker {marker}",
            product_readiness_release_gate_contract_markdown,
            marker,
            PRODUCT_READINESS_RELEASE_GATE_CONTRACT_MD,
        )
    for marker in [
        "Product Readiness Claim Status Contract",
        "Product ready: `false`",
        "Ready-after-env passed: `0/0`",
        "Ready-after-env all passed: `false`",
        "`status`: `pass`",
        "`blocker_cleared`: `true`",
        "`missing_profiles`: `[]`",
        "`package_id`",
        "`agent_id`",
        "`expected_profiles`",
        "`false`",
        "agent_status.json",
        "blocker_cleared",
        "missing_profiles",
        "--refresh-claim-status-report",
        "status=pass, blocker_cleared=true, and missing_profiles=[]",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_MD)} preserves claim-status contract marker {marker}",
            product_readiness_claim_status_contract_markdown,
            marker,
            PRODUCT_READINESS_CLAIM_STATUS_CONTRACT_MD,
        )
    for marker in [
        "Product Readiness Blocked Run Classes Contract",
        "Product ready: `false`",
        "Blocked run classes: `5`",
        "Env blocked: `0`",
        "Profile/lab blocked: `5`",
        "`windows-broad`",
        "`windows-caldera-enterprise`",
        "`macos-server-backed-smoke`",
        "`profile_or_lab_required`",
        "`windows-atomic-extended-safe`",
        "`blocked_run_classes=[]`",
        "run_class_readiness allowed=true",
    ]:
        check_contains(
            checks,
            (
                f"{rel(PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_MD)} "
                f"preserves blocked-run-classes contract marker {marker}"
            ),
            product_readiness_blocked_run_classes_contract_markdown,
            marker,
            PRODUCT_READINESS_BLOCKED_RUN_CLASSES_CONTRACT_MD,
        )
    manual_claim_resolution_markers = [
        "Product Readiness Manual Claim Resolution",
        "Product ready: `false`",
        f"Unresolved manual claims: `{manual_claim_count}`",
        f"Can claim manual resolution: `{'false' if manual_claim_count else 'true'}`",
        "claim_status_report.json",
        "does not execute packages or close claims",
    ]
    if manual_claim_count:
        manual_claim_resolution_markers.extend(
            [
                "`claim-wave-1-resolve-atomic-extended-preconditions`",
                "`wave-1-resolve-atomic-extended-preconditions`",
                "`validation-agent`",
                "wave-1-resolve-atomic-extended-preconditions.agent.md",
                "claim_status_report has zero manual_claim_required claims",
                "agent_status.json has status=pass, blocker_cleared=true, and missing_profiles=[]",
                "Atomic T1047 manual boundary is resolved by disposable WMI target or narrowed claim",
            ]
        )
    for marker in manual_claim_resolution_markers:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_MD)} preserves manual-claim resolution marker {marker}",
            product_readiness_manual_claim_resolution_markdown,
            marker,
            PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_MD,
        )
    for marker in [
        "Product Readiness Manual Claim Resolution Check",
        "validation_product_readiness_manual_claim_resolution.json",
        "[switch]$Json",
        "validation-product-readiness-manual-claim-resolution-check",
        "can_claim_manual_resolution",
        "unresolved_manual_claim_count",
        "missing_prompt_paths",
        "missing_script_paths",
        "manual_claim_resolution",
        "no-execution manual claim check",
        "does not close claims or claim product readiness",
        "exit 3",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK)} preserves manual-claim check marker {marker}",
            product_readiness_manual_claim_resolution_check,
            marker,
            PRODUCT_READINESS_MANUAL_CLAIM_RESOLUTION_CHECK,
        )
    for marker in [
        "Product Readiness Runbook",
        "Product ready: `false`",
        "Automation state: `ready_for_post_env_runner`",
        "Required env: `0`",
        "Ready-after-env required: `0`",
        "Blocked run classes: `5`",
        "`inspect-current-state`",
        "`fill-env-bundle`",
        "`validate-env-bundle`",
        "`launch-ready-after-env-claims`",
        "`refresh-claim-status`",
        "`verify-agent-status-contract`",
        "`resolve-profile-or-lab-blockers`",
        "`refresh-validation-authority`",
        "`claim-execution`",
        "-UseBalancedAgents -Execute -RefreshClaimStatus",
        "`execute_switch_required_for_claim_launch`",
        "validation_product_readiness_claim_status_contract.md",
        "validation_product_readiness_blocked_run_classes.contract.md",
        "must not be treated as completed",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_RUNBOOK_MD)} preserves runbook marker {marker}",
            product_readiness_runbook_markdown,
            marker,
            PRODUCT_READINESS_RUNBOOK_MD,
        )
    for marker in [
        "Product Readiness Remaining Work",
        "Product ready: `false`",
        f"Open items: `{remaining_work_open_count}`",
        f"Failed requirements: `{remaining_work_failed_requirement_count}`",
        "`clear-env-blocked-claims`",
        "`pass-ready-after-env-agent-status`",
        "`clear-blocked-run-classes`",
        "`rerun-closure-gate`",
        "`rerun-preflight-gate`",
        "`rerun-dispatch-gate`",
        "`agent-status`",
        "`gate-rerun`",
        "ready_after_env_passed_count=0",
        "profile_or_lab_blocked_count=0",
        "listed evidence",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_REMAINING_WORK_MD)} preserves remaining-work marker {marker}",
            product_readiness_remaining_work_markdown,
            marker,
            PRODUCT_READINESS_REMAINING_WORK_MD,
        )
    for marker in [
        "Product Readiness Remaining Work Check",
        "validation_product_readiness_remaining_work.json",
        "[switch]$Json",
        "validation-product-readiness-remaining-work-check",
        "ready_now_ids",
        "blocked_by_dependency",
        "next_open_item_id",
        "can_claim_product_ready",
        "no-execution remaining work check",
        "does not close items",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_REMAINING_WORK_CHECK)} preserves remaining-work check marker {marker}",
            product_readiness_remaining_work_check,
            marker,
            PRODUCT_READINESS_REMAINING_WORK_CHECK,
        )
    for marker in [
        "Product Readiness Ready-Now Fanout",
        "Product ready: `false`",
        f"Open items: `{ready_now_open_count}`",
        f"Ready now: `{ready_now_count}`",
        "Blocked by dependency: `4`",
        "`pass-ready-after-env-agent-status`",
        "do not execute commands",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_READY_NOW_FANOUT_MD)} preserves ready-now fanout marker {marker}",
            product_readiness_ready_now_fanout_markdown,
            marker,
            PRODUCT_READINESS_READY_NOW_FANOUT_MD,
        )
    for marker in [
        "Product Readiness Ready-Now Fanout Check",
        "validation_product_readiness_ready_now_fanout.json",
        "[switch]$Json",
        "validation-product-readiness-ready-now-fanout-check",
        "fanout_contract_valid",
        "lane_item_ids",
        "missing_lane_item_ids",
        "unexpected_lane_item_ids",
        "no-execution ready-now fanout check",
        "does not execute commands",
        "exit 2",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_READY_NOW_FANOUT_CHECK)} preserves ready-now fanout check marker {marker}",
            product_readiness_ready_now_fanout_check,
            marker,
            PRODUCT_READINESS_READY_NOW_FANOUT_CHECK,
        )
    for marker in [
        "Product Readiness Agent Handoff",
        "Product ready: `false`",
        "External claim allowed: `false`",
        "Automation state: `ready_for_post_env_runner`",
        f"Release gate failed: `{release_gate_failed_count}`",
        "Required env: `0`",
        "Ready-after-env claims: `0`",
        "`operator_check_json`",
        "`env_bundle_local_env_validate_json`",
        "`env_bundle_runner_status_check_json`",
        "`doctor_json`",
        "`ready_now_fanout_check_json`",
        "`manual_claim_resolution_check_json`",
        "`post_env_runner_balanced_execute`",
        "`post_env_runner_process_env_balanced_execute_refresh_authority`",
        "validation_product_readiness_env_bundle.template.env",
        "validation_product_readiness_env_bundle.local.env",
        "validation_product_readiness_env_bundle_init.schema.json",
        "validation_product_readiness_env_bundle_check.schema.json",
        "validation_product_readiness_env_bundle_runner.schema.json",
        "validation_product_readiness_env_bundle_runner_status_check.schema.json",
        "validation_product_readiness_doctor.schema.json",
        "validation_product_readiness_release_gate.contract.json",
        "validation_product_readiness_post_env_bundle_runner.contract.json",
        "validation_product_readiness_claim_status_contract.json",
        "validation_product_readiness_blocked_run_classes.contract.json",
        "validation_product_readiness_runbook.json",
        "validation_product_readiness_remaining_work.json",
        "validation_product_readiness_remaining_work_check.ps1",
        "validation_product_readiness_ready_now_fanout.json",
        "validation_product_readiness_ready_now_fanout_check.ps1",
        "validation_product_readiness_ready_now_fanout_check.schema.json",
        "validation_product_readiness_manual_claim_resolution.json",
        "validation_product_readiness_manual_claim_resolution_check.schema.json",
        "validation_product_readiness_env_request.json",
        "`closure-gate`",
        "`blocked-run-classes`",
        "does not claim product readiness",
    ]:
        check_contains(
            checks,
            f"{rel(PRODUCT_READINESS_AGENT_HANDOFF_MD)} preserves agent handoff marker {marker}",
            product_readiness_agent_handoff_markdown,
            marker,
            PRODUCT_READINESS_AGENT_HANDOFF_MD,
        )
    for doc in (KNOWN_PRODUCTION_GAPS_DOC, VALIDATION_MASTER_PLAN_DOC, NEXT_VALIDATION_WORK_QUEUE_DOC):
        text = load_text(doc)
        check_contains(
            checks,
            f"{rel(doc)} references product readiness summary",
            text,
            "validation_product_readiness_summary.md",
            doc,
        )
        check_contains(
            checks,
            f"{rel(doc)} references product readiness operator check",
            text,
            "validation_product_readiness_operator_check.ps1",
            doc,
        )
        for marker in [
            "validation_product_readiness_doctor.ps1",
            "validation_product_readiness_agent_handoff.md",
            "validation_product_readiness_ready_now_fanout_check.ps1",
            "validation_product_readiness_manual_claim_resolution_check.ps1",
        ]:
            check_contains(
                checks,
                f"{rel(doc)} references product readiness handoff marker {marker}",
                text,
                marker,
                doc,
            )
    for doc in (status_docs[0], status_docs[2]):
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest Atomic T1047 boundary artifact", text, atomic_t1047_run, doc)
    for doc in FRESH_RESTORE_STATUS_DOCS:
        text = load_text(doc)
        check_contains(checks, f"{rel(doc)} references latest fresh restore provenance", text, fresh_restore_run, doc)
        check(
            checks,
            f"{rel(doc)} references latest fresh restore coverage on same line",
            line_contains_all(text, [fresh_restore_run, fresh_restore_coverage]),
            True,
            [rel(doc)],
        )
    parity_text = load_text(CROSS_PLATFORM_PARITY_DOC)
    check_contains(
        checks,
        f"{rel(CROSS_PLATFORM_PARITY_DOC)} preserves Windows B1/B2 partial boundary",
        parity_text,
        "Roadmaps B1/B2 remain `partial`",
        CROSS_PLATFORM_PARITY_DOC,
    )
    check_contains(
        checks,
        f"{rel(CROSS_PLATFORM_PARITY_DOC)} references latest macOS backend readiness",
        parity_text,
        macos_backend_run,
        CROSS_PLATFORM_PARITY_DOC,
    )
    check_contains(
        checks,
        f"{rel(CROSS_PLATFORM_PARITY_DOC)} blocks Linux parity closure claim",
        parity_text,
        "not parity-closed",
        CROSS_PLATFORM_PARITY_DOC,
    )
    product_maturity_text = load_text(PRODUCT_MATURITY_DOC)
    check_contains(
        checks,
        f"{rel(PRODUCT_MATURITY_DOC)} references latest Windows benign baseline",
        product_maturity_text,
        "20260611T003251Z-windows-benign-baseline",
        PRODUCT_MATURITY_DOC,
    )
    check_contains(
        checks,
        f"{rel(PRODUCT_MATURITY_DOC)} preserves benign baseline partial coverage",
        product_maturity_text,
        "`6/8`",
        PRODUCT_MATURITY_DOC,
    )
    known_production_gaps_text = load_text(KNOWN_PRODUCTION_GAPS_DOC)
    for marker in [
        scorecard_artifact_count_marker,
        "closure gate is still red at `0/23`",
        "older implementation summaries",
        "production-ready",
        "historical implementation notes",
    ]:
        check_contains(
            checks,
            f"{rel(KNOWN_PRODUCTION_GAPS_DOC)} preserves current validation authority marker {marker}",
            known_production_gaps_text,
            marker,
            KNOWN_PRODUCTION_GAPS_DOC,
        )
    engine_maturity_text = load_text(ENGINE_MATURITY_DOC)
    check_contains(
        checks,
        f"{rel(ENGINE_MATURITY_DOC)} references current scorecard artifact count",
        engine_maturity_text,
        scorecard_artifact_count_marker,
        ENGINE_MATURITY_DOC,
    )
    check(
        checks,
        f"{rel(ENGINE_MATURITY_DOC)} uses current generated scorecard wording",
        engine_maturity_uses_current_scorecard_wording(engine_maturity_text),
        True,
        [rel(ENGINE_MATURITY_DOC)],
    )
    for doc in (status_docs[0], status_docs[2]):
        text = load_text(doc)
        check(
            checks,
            f"{rel(doc)} avoids obsolete consistency fail reference",
            active_status_doc_avoids_obsolete_consistency_fail(text),
            True,
            [rel(doc)],
        )
    check(
        checks,
        f"{rel(status_docs[0])} avoids stale dispatch scorecard coverage",
        active_status_doc_avoids_stale_dispatch_scorecard_coverage(load_text(status_docs[0])),
        True,
        [rel(status_docs[0])],
    )
    check_contains(
        checks,
        f"{rel(ENGINE_MATURITY_DOC)} preserves Atomic Roadmap C partial boundary",
        engine_maturity_text,
        "Roadmap C remains `partial`",
        ENGINE_MATURITY_DOC,
    )
    check_contains(
        checks,
        f"{rel(ENGINE_MATURITY_DOC)} references latest Windows benign baseline coverage",
        engine_maturity_text,
        "latest `windows-benign-baseline`",
        ENGINE_MATURITY_DOC,
    )
    check_contains(
        checks,
        f"{rel(ENGINE_MATURITY_DOC)} preserves latest Windows benign baseline partial coverage",
        engine_maturity_text,
        "`6/8` gaps remain",
        ENGINE_MATURITY_DOC,
    )
    ai_model_scanner_text = load_text(AI_MODEL_SCANNER_SCORECARD_DOC)
    check(
        checks,
        f"{rel(AI_MODEL_SCANNER_SCORECARD_DOC)} preserves AI scanner small-corpus claim boundary",
        ai_model_scanner_scorecard_preserves_claim_boundary(ai_model_scanner_text),
        True,
        [rel(AI_MODEL_SCANNER_SCORECARD_DOC)],
    )
    check(
        checks,
        f"{rel(AI_MODEL_SCANNER_SCORECARD_DOC)} avoids WeightAnalyzer production-ready claim",
        "Tuning is **production-ready**" in ai_model_scanner_text,
        False,
        [rel(AI_MODEL_SCANNER_SCORECARD_DOC)],
    )
    benchmark_results_text = load_text(BENCHMARK_RESULTS_REVIEW_DOC)
    check(
        checks,
        f"{rel(BENCHMARK_RESULTS_REVIEW_DOC)} preserves CALDERA repeatability product-claim boundary",
        benchmark_results_review_preserves_caldera_claim_boundary(benchmark_results_text),
        True,
        [rel(BENCHMARK_RESULTS_REVIEW_DOC)],
    )
    check(
        checks,
        f"{rel(BENCHMARK_RESULTS_REVIEW_DOC)} preserves Windows P0 deterministic-only boundary",
        benchmark_results_review_preserves_windows_p0_deterministic_boundary(benchmark_results_text),
        True,
        [rel(BENCHMARK_RESULTS_REVIEW_DOC)],
    )
    roadmap_delivery_text = load_text(ROADMAP_DELIVERY_PLAN_DOC)
    check(
        checks,
        f"{rel(ROADMAP_DELIVERY_PLAN_DOC)} preserves Windows P0 deterministic-slice closure boundary",
        windows_p0_closure_preserves_deterministic_slice_boundary(roadmap_delivery_text),
        True,
        [rel(ROADMAP_DELIVERY_PLAN_DOC)],
    )
    check(
        checks,
        f"{rel(ROADMAP_DELIVERY_PLAN_DOC)} preserves current Linux/macOS boundary",
        roadmap_plans_preserve_current_cross_platform_boundary(roadmap_delivery_text),
        True,
        [rel(ROADMAP_DELIVERY_PLAN_DOC)],
    )
    validation_master_text = load_text(VALIDATION_MASTER_PLAN_DOC)
    check_contains(
        checks,
        f"{rel(VALIDATION_MASTER_PLAN_DOC)} preserves Windows P0 deterministic-only closure boundary",
        validation_master_text,
        "closed by accumulated deterministic evidence\nonly",
        VALIDATION_MASTER_PLAN_DOC,
    )
    check(
        checks,
        f"{rel(VALIDATION_MASTER_PLAN_DOC)} preserves current Linux/macOS boundary",
        roadmap_plans_preserve_current_cross_platform_boundary(validation_master_text),
        True,
        [rel(VALIDATION_MASTER_PLAN_DOC)],
    )
    next_validation_text = load_text(NEXT_VALIDATION_WORK_QUEUE_DOC)
    check(
        checks,
        f"{rel(NEXT_VALIDATION_WORK_QUEUE_DOC)} avoids P1 roadmap overclaim",
        coordination_docs_avoid_p1_roadmap_overclaim(next_validation_text),
        True,
        [rel(NEXT_VALIDATION_WORK_QUEUE_DOC)],
    )
    parallel_board_text = load_text(PARALLEL_EXECUTION_BOARD_DOC)
    check(
        checks,
        f"{rel(PARALLEL_EXECUTION_BOARD_DOC)} avoids P1 roadmap overclaim",
        coordination_docs_avoid_p1_roadmap_overclaim(parallel_board_text),
        True,
        [rel(PARALLEL_EXECUTION_BOARD_DOC)],
    )
    check(
        checks,
        f"{rel(PARALLEL_EXECUTION_BOARD_DOC)} preserves Linux sensor-contract boundary",
        parallel_board_preserves_linux_sensor_boundary(parallel_board_text),
        True,
        [rel(PARALLEL_EXECUTION_BOARD_DOC)],
    )

    failed = sum(1 for item in checks if item["status"] == "FAIL")
    passed = sum(1 for item in checks if item["status"] == "PASS")
    return {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "profile_name": PROFILE_NAME,
        "benchmark_lane": "claim-boundary",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "git": git_snapshot(),
        "external_claim_allowed": False,
        "claim_boundary": (
            "offline consistency audit of validation status docs and generated scorecard; "
            "no endpoint, service, database, live alert, CALDERA, or Proxmox access"
        ),
        "latest": {
            PROFILE_CLOSURE: {"run_id": closure_run, "path": closure_source},
            PROFILE_PREFLIGHT: {"run_id": preflight_run, "path": preflight_source},
            PROFILE_REPLAY: {"run_id": replay_run, "path": replay_source},
            PROFILE_FRESH_RESTORE: {"run_id": fresh_restore_run, "path": fresh_restore_source},
            PROFILE_DISPATCH_RESULTS: {"run_id": dispatch_run, "path": dispatch_source},
            PROFILE_CALDERA_REPEATABILITY: {
                "run_id": caldera_repeatability_run,
                "path": caldera_repeatability_source,
            },
            PROFILE_ID: {"run_id": consistency_run, "path": rel(RUNS_DIR / f"{consistency_run}.json")},
        },
        "summary": {
            "total_checks": len(checks),
            "passed": passed,
            "failed": failed,
        },
        "checks": checks,
    }


def test_id(name: str) -> str:
    cleaned = []
    last_dash = False
    for char in name.lower():
        if char.isalnum():
            cleaned.append(char)
            last_dash = False
        elif not last_dash:
            cleaned.append("-")
            last_dash = True
    return "status-consistency-" + "".join(cleaned).strip("-")


def tests_from_checks(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for item in checks:
        passed = item.get("status") == "PASS"
        tests.append(
            {
                "id": test_id(str(item.get("name") or "check")),
                "name": item.get("name") or "status consistency check",
                "status": "covered" if passed else "missed",
                "gap_category": None if passed else "status-consistency",
                "validation_category": "validation_status_consistency",
                "execution_class": "local_read_only_status_audit",
                "fallback_used": False,
                "claim_level": "status_consistency_claim_boundary",
                "tactics": [],
                "techniques": [],
                "evidence": {
                    "actual": item.get("actual"),
                    "expected": item.get("expected"),
                    "source_files": item.get("source_files") or [],
                },
                "missing_expected_fields": [] if passed else [str(item.get("name") or "check")],
                "missing_expected_telemetry": [],
                "missing_expected_detections": [],
                "missing_expected_alerts": [],
                "missing_expected_correlations": [],
                "missing_expected_driver_raw_event_types": [],
            }
        )
    return tests


def summarize_tests(tests: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sum(1 for item in tests if item.get("status") == "covered")
    missed = len(tests) - covered
    return {
        "tests": len(tests),
        "total": len(tests),
        "covered": covered,
        "missed": missed,
        "partial": 0,
        "execution_failed": 0,
        "category_coverage": {
            "validation_status_consistency": {"covered": covered, "missed": missed}
        },
    }


def quality_gate(tests: list[dict[str, Any]]) -> dict[str, Any]:
    blocking = [item["id"] for item in tests if item.get("status") != "covered"]
    return {
        "passed": not blocking,
        "status": "pass" if not blocking else "fail",
        "failures": [] if not blocking else ["validation_status_consistency_gaps"],
        "blocking_gaps": blocking,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Validation Status Consistency",
        "",
        "Status: generated (offline audit)",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Git commit: `{payload['git'].get('commit_short') or 'unknown'}`"
        + (" (dirty)" if payload["git"].get("dirty") else ""),
        f"- Checks: {summary['passed']}/{summary['total_checks']} passed; {summary['failed']} failed",
        "- external_claim_allowed: false",
        "",
        "## Latest Artifacts",
        "",
        "| Profile | Run ID | Path |",
        "|---------|--------|------|",
    ]
    for profile_id, latest in payload["latest"].items():
        lines.append(f"| `{profile_id}` | `{latest['run_id']}` | `{latest['path']}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            payload["claim_boundary"],
            "",
            "## Checks",
            "",
            "| Status | Check | Actual | Expected | Sources |",
            "|--------|-------|--------|----------|---------|",
        ]
    )
    for item in payload["checks"]:
        sources = ", ".join(f"`{source}`" for source in item.get("source_files") or [])
        lines.append(
            f"| `{item['status']}` | {item['name']} | `{item.get('actual')}` | "
            f"`{item.get('expected')}` | {sources} |"
        )
    return "\n".join(lines) + "\n"


def markdown_summary_matches_payload(markdown: str, payload: dict[str, Any]) -> bool:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    expected = (
        f"- Checks: {summary.get('passed')}/{summary.get('total_checks')} passed; "
        f"{summary.get('failed')} failed"
    )
    return expected in markdown


def render_run_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Validation Status Consistency Probe",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Gate: `{report['quality_gate']['status']}`",
        f"- Checks: `{report['summary']['covered']}/{report['summary']['tests']}`",
        "- external_claim_allowed: false",
        "",
        "## Latest Artifacts",
        "",
        "| Profile | Run ID | Path |",
        "|---------|--------|------|",
    ]
    for profile_id, latest in report["latest"].items():
        lines.append(f"| `{profile_id}` | `{latest['run_id']}` | `{latest['path']}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            report["claim_boundary"],
            "",
            "## Results",
            "",
            "| Status | Check | Actual | Expected | Sources |",
            "|--------|-------|--------|----------|---------|",
        ]
    )
    for check_item in report["checks"]:
        sources = ", ".join(f"`{source}`" for source in check_item.get("source_files") or [])
        lines.append(
            f"| `{check_item['status']}` | {check_item['name']} | `{check_item.get('actual')}` | "
            f"`{check_item.get('expected')}` | {sources} |"
        )
    return "\n".join(lines) + "\n"


def run_markdown_summary_matches_report(markdown: str, report: dict[str, Any]) -> bool:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    expected = f"- Checks: `{summary.get('covered')}/{summary.get('tests')}`"
    return expected in markdown


def write_outputs(payload: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{OUTPUT_STEM}.json"
    md_path = output_dir / f"{OUTPUT_STEM}.md"
    if not consistency_summary_matches_checks(payload):
        raise ValueError("validation status payload summary does not match checks")
    markdown = render_markdown(payload)
    if not markdown_summary_matches_payload(markdown, payload):
        raise ValueError("validation status markdown summary does not match payload summary")
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")
    return json_path, md_path


def validate_run_id(run_id: str) -> str:
    if not RUN_ID_RE.match(run_id):
        raise ValueError(f"run_id must match YYYYMMDDTHHMMSSZ-{PROFILE_ID}")
    return run_id


def started_at_from_run_id(run_id: str) -> str:
    stamp = run_id.split("-", 1)[0]
    return datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def resolve_run_id(run_id: str | None = None) -> tuple[str, str]:
    if run_id:
        run_id = validate_run_id(run_id)
        return run_id, started_at_from_run_id(run_id)
    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return f"{compact_stamp(started)}-{PROFILE_ID}", started


def comparison(run_id: str, report: dict[str, Any]) -> dict[str, Any]:
    summary = copy.deepcopy(report["summary"])
    category_coverage = copy.deepcopy(report["summary"]["category_coverage"])
    failures = copy.deepcopy(report["quality_gate"]["failures"])
    return {
        "run_id": run_id,
        "profile_id": PROFILE_ID,
        "profile": PROFILE_ID,
        "status": report["quality_gate"]["status"],
        "quality_gate": {
            "passed": report["quality_gate"]["passed"],
            "status": report["quality_gate"]["status"],
        },
        "score": 90 if report["quality_gate"]["passed"] else 35,
        "summary": summary,
        "category_coverage": category_coverage,
        "failures": failures,
    }


def comparison_matches_report(comparison_payload: dict[str, Any], report: dict[str, Any]) -> bool:
    gate = report.get("quality_gate") if isinstance(report.get("quality_gate"), dict) else {}
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    quality_gate = (
        comparison_payload.get("quality_gate")
        if isinstance(comparison_payload.get("quality_gate"), dict)
        else {}
    )
    return (
        comparison_payload.get("run_id") == report.get("run_id")
        and comparison_payload.get("profile_id") == PROFILE_ID
        and comparison_payload.get("profile") == PROFILE_ID
        and comparison_payload.get("status") == gate.get("status")
        and quality_gate.get("passed") == gate.get("passed")
        and quality_gate.get("status") == gate.get("status")
        and comparison_payload.get("summary") == summary
        and comparison_payload.get("category_coverage") == summary.get("category_coverage")
        and comparison_payload.get("failures") == gate.get("failures")
    )


def write_run_artifacts(payload: dict[str, Any], output_dir: Path, run_id: str | None = None) -> tuple[Path, Path, Path]:
    run_id, started = resolve_run_id(run_id)
    tests = tests_from_checks(payload["checks"])
    gate = quality_gate(tests)
    summary = summarize_tests(tests)
    finished = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    latest = dict(payload.get("latest") or {})
    latest[PROFILE_ID] = {"run_id": run_id, "path": rel(output_dir / f"{run_id}.json")}
    report = {
        **payload,
        "run_id": run_id,
        "started_at": started,
        "finished_at": finished,
        "runtime_effect": "local_read_only_status_audit",
        "tests": tests,
        "latest": latest,
        "summary": summary,
        "quality_gate": gate,
        "scorecard": {
            "score": 90 if gate["passed"] else 35,
            "status": gate["status"],
            "external_claim_allowed": False,
            "recommended_claim": (
                "Validation status docs are aligned with latest generated evidence"
                if gate["passed"]
                else "Validation status docs are stale or inconsistent with latest generated evidence"
            ),
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{run_id}.json"
    md_path = output_dir / f"{run_id}.md"
    comparison_path = output_dir / f"{run_id}.comparison.json"
    markdown = render_run_markdown(report)
    if not run_markdown_summary_matches_report(markdown, report):
        raise ValueError("validation status run markdown summary does not match report summary")
    comparison_payload = comparison(run_id, report)
    if not comparison_matches_report(comparison_payload, report):
        raise ValueError("validation status comparison artifact does not match report")
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")
    comparison_path.write_text(
        json.dumps(comparison_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return json_path, md_path, comparison_path


def refresh_scorecard(runs_dir: Path, output_dir: Path) -> None:
    scorecard_generator = importlib.import_module("generate_validation_scorecard")
    reports = scorecard_generator.load_reports(runs_dir)
    payload = scorecard_generator.build_payload(reports, runs_dir)
    scorecard_generator.write_outputs(payload, output_dir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scorecard-json", default=str(SCORECARD_JSON))
    parser.add_argument("--output-dir", default=str(GENERATED_DIR))
    parser.add_argument("--run-output-dir", default=str(RUNS_DIR))
    parser.add_argument("--run-id", help=f"explicit run id matching YYYYMMDDTHHMMSSZ-{PROFILE_ID}")
    parser.add_argument("--skip-run-artifact", action="store_true")
    parser.add_argument(
        "--refresh-scorecard",
        action="store_true",
        help="compatibility flag; scorecard refresh now always runs when writing a run artifact",
    )
    parser.add_argument("--status-doc", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    status_docs = [Path(path) for path in args.status_doc] if args.status_doc else STATUS_DOCS
    expected_run_id = args.run_id
    if not args.skip_run_artifact:
        expected_run_id, _started = resolve_run_id(args.run_id)
    payload = build_payload(Path(args.scorecard_json), status_docs, expected_run_id)
    json_path, md_path = write_outputs(payload, Path(args.output_dir))
    run_outputs: tuple[Path, Path, Path] | None = None
    if not args.skip_run_artifact:
        run_outputs = write_run_artifacts(payload, Path(args.run_output_dir), expected_run_id)
        refresh_scorecard(Path(args.run_output_dir), Path(args.output_dir))
        payload = build_payload(Path(args.scorecard_json), status_docs, expected_run_id)
        json_path, md_path = write_outputs(payload, Path(args.output_dir))
        run_outputs = write_run_artifacts(payload, Path(args.run_output_dir), expected_run_id)
    summary = payload["summary"]
    run_text = ""
    if run_outputs:
        run_text = " run_artifacts=" + ",".join(rel(path) for path in run_outputs)
    print(
        f"validation_status_consistency={summary['failed'] == 0} "
        f"checks={summary['passed']}/{summary['total_checks']} "
        f"written={rel(json_path)},{rel(md_path)}"
        f"{run_text}"
    )
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
