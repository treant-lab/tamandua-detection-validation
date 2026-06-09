import importlib.util
import json
import os
import subprocess
import sys
from argparse import Namespace
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("tamandua_detection_validation.py")
if str(MODULE_PATH.parent) not in sys.path:
    sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("tamandua_detection_validation", MODULE_PATH)
validation = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = validation
SPEC.loader.exec_module(validation)

ROADMAP_MODULE_PATH = Path(__file__).with_name("generate_windows_roadmap_300.py")
ROADMAP_SPEC = importlib.util.spec_from_file_location("generate_windows_roadmap_300", ROADMAP_MODULE_PATH)
roadmap = importlib.util.module_from_spec(ROADMAP_SPEC)
assert ROADMAP_SPEC.loader is not None
sys.modules[ROADMAP_SPEC.name] = roadmap
ROADMAP_SPEC.loader.exec_module(roadmap)

ROADMAP_BATCH_MODULE_PATH = Path(__file__).with_name("generate_roadmap_batch_profiles.py")
ROADMAP_BATCH_SPEC = importlib.util.spec_from_file_location(
    "generate_roadmap_batch_profiles",
    ROADMAP_BATCH_MODULE_PATH,
)
roadmap_batch = importlib.util.module_from_spec(ROADMAP_BATCH_SPEC)
assert ROADMAP_BATCH_SPEC.loader is not None
sys.modules[ROADMAP_BATCH_SPEC.name] = roadmap_batch
ROADMAP_BATCH_SPEC.loader.exec_module(roadmap_batch)

SCORECARD_MODULE_PATH = Path(__file__).with_name("generate_validation_scorecard.py")
SCORECARD_SPEC = importlib.util.spec_from_file_location("generate_validation_scorecard", SCORECARD_MODULE_PATH)
scorecard = importlib.util.module_from_spec(SCORECARD_SPEC)
assert SCORECARD_SPEC.loader is not None
sys.modules[SCORECARD_SPEC.name] = scorecard
SCORECARD_SPEC.loader.exec_module(scorecard)

CLOSURE_GATE_MODULE_PATH = Path(__file__).with_name("roadmap_closure_gate_probe.py")
CLOSURE_GATE_SPEC = importlib.util.spec_from_file_location("roadmap_closure_gate_probe", CLOSURE_GATE_MODULE_PATH)
closure_gate = importlib.util.module_from_spec(CLOSURE_GATE_SPEC)
assert CLOSURE_GATE_SPEC.loader is not None
sys.modules[CLOSURE_GATE_SPEC.name] = closure_gate
CLOSURE_GATE_SPEC.loader.exec_module(closure_gate)

CONSISTENCY_MODULE_PATH = Path(__file__).with_name("validation_status_consistency.py")
CONSISTENCY_SPEC = importlib.util.spec_from_file_location("validation_status_consistency", CONSISTENCY_MODULE_PATH)
consistency = importlib.util.module_from_spec(CONSISTENCY_SPEC)
assert CONSISTENCY_SPEC.loader is not None
sys.modules[CONSISTENCY_SPEC.name] = consistency
CONSISTENCY_SPEC.loader.exec_module(consistency)

PREFLIGHT_MODULE_PATH = Path(__file__).with_name("validation_execution_preflight_probe.py")
PREFLIGHT_SPEC = importlib.util.spec_from_file_location("validation_execution_preflight_probe", PREFLIGHT_MODULE_PATH)
preflight = importlib.util.module_from_spec(PREFLIGHT_SPEC)
assert PREFLIGHT_SPEC.loader is not None
sys.modules[PREFLIGHT_SPEC.name] = preflight
PREFLIGHT_SPEC.loader.exec_module(preflight)

PREFLIGHT_WORK_PACKAGE_MODULE_PATH = Path(__file__).with_name("run_preflight_work_package.py")
PREFLIGHT_WORK_PACKAGE_SPEC = importlib.util.spec_from_file_location(
    "run_preflight_work_package",
    PREFLIGHT_WORK_PACKAGE_MODULE_PATH,
)
preflight_work_package = importlib.util.module_from_spec(PREFLIGHT_WORK_PACKAGE_SPEC)
assert PREFLIGHT_WORK_PACKAGE_SPEC.loader is not None
sys.modules[PREFLIGHT_WORK_PACKAGE_SPEC.name] = preflight_work_package
PREFLIGHT_WORK_PACKAGE_SPEC.loader.exec_module(preflight_work_package)

FRESH_RESTORE_MODULE_PATH = Path(__file__).with_name("fresh_restore_provenance_probe.py")
FRESH_RESTORE_SPEC = importlib.util.spec_from_file_location(
    "fresh_restore_provenance_probe",
    FRESH_RESTORE_MODULE_PATH,
)
fresh_restore = importlib.util.module_from_spec(FRESH_RESTORE_SPEC)
assert FRESH_RESTORE_SPEC.loader is not None
sys.modules[FRESH_RESTORE_SPEC.name] = fresh_restore
FRESH_RESTORE_SPEC.loader.exec_module(fresh_restore)

CALDERA_PAW_MODULE_PATH = Path(__file__).with_name("caldera_paw_readiness_probe.py")
CALDERA_PAW_SPEC = importlib.util.spec_from_file_location(
    "caldera_paw_readiness_probe",
    CALDERA_PAW_MODULE_PATH,
)
caldera_paw = importlib.util.module_from_spec(CALDERA_PAW_SPEC)
assert CALDERA_PAW_SPEC.loader is not None
sys.modules[CALDERA_PAW_SPEC.name] = caldera_paw
CALDERA_PAW_SPEC.loader.exec_module(caldera_paw)

CALDERA_API_MODULE_PATH = Path(__file__).with_name("caldera_api_shape_probe.py")
CALDERA_API_SPEC = importlib.util.spec_from_file_location(
    "caldera_api_shape_probe",
    CALDERA_API_MODULE_PATH,
)
caldera_api = importlib.util.module_from_spec(CALDERA_API_SPEC)
assert CALDERA_API_SPEC.loader is not None
sys.modules[CALDERA_API_SPEC.name] = caldera_api
CALDERA_API_SPEC.loader.exec_module(caldera_api)

CALDERA_REPEATABILITY_MODULE_PATH = Path(__file__).with_name("caldera_repeatability_probe.py")
CALDERA_REPEATABILITY_SPEC = importlib.util.spec_from_file_location(
    "caldera_repeatability_probe",
    CALDERA_REPEATABILITY_MODULE_PATH,
)
caldera_repeatability = importlib.util.module_from_spec(CALDERA_REPEATABILITY_SPEC)
assert CALDERA_REPEATABILITY_SPEC.loader is not None
sys.modules[CALDERA_REPEATABILITY_SPEC.name] = caldera_repeatability
CALDERA_REPEATABILITY_SPEC.loader.exec_module(caldera_repeatability)

MACOS_BACKEND_MODULE_PATH = Path(__file__).with_name("macos_backend_readiness_probe.py")
MACOS_BACKEND_SPEC = importlib.util.spec_from_file_location(
    "macos_backend_readiness_probe",
    MACOS_BACKEND_MODULE_PATH,
)
macos_backend = importlib.util.module_from_spec(MACOS_BACKEND_SPEC)
assert MACOS_BACKEND_SPEC.loader is not None
sys.modules[MACOS_BACKEND_SPEC.name] = macos_backend
MACOS_BACKEND_SPEC.loader.exec_module(macos_backend)

ATOMIC_T1047_MODULE_PATH = Path(__file__).with_name("atomic_t1047_lab_capability_probe.py")
ATOMIC_T1047_SPEC = importlib.util.spec_from_file_location(
    "atomic_t1047_lab_capability_probe",
    ATOMIC_T1047_MODULE_PATH,
)
atomic_t1047 = importlib.util.module_from_spec(ATOMIC_T1047_SPEC)
assert ATOMIC_T1047_SPEC.loader is not None
sys.modules[ATOMIC_T1047_SPEC.name] = atomic_t1047
ATOMIC_T1047_SPEC.loader.exec_module(atomic_t1047)

WINDOWS_QGA_READINESS_MODULE_PATH = Path(__file__).with_name("windows_proxmox_qga_readiness_probe.py")
WINDOWS_QGA_READINESS_SPEC = importlib.util.spec_from_file_location(
    "windows_proxmox_qga_readiness_probe",
    WINDOWS_QGA_READINESS_MODULE_PATH,
)
windows_qga_readiness = importlib.util.module_from_spec(WINDOWS_QGA_READINESS_SPEC)
assert WINDOWS_QGA_READINESS_SPEC.loader is not None
sys.modules[WINDOWS_QGA_READINESS_SPEC.name] = windows_qga_readiness
WINDOWS_QGA_READINESS_SPEC.loader.exec_module(windows_qga_readiness)

WINDOWS_QGA_FILE_DIAGNOSTICS_MODULE_PATH = Path(__file__).with_name(
    "windows_proxmox_qga_file_diagnostics_probe.py"
)
WINDOWS_QGA_FILE_DIAGNOSTICS_SPEC = importlib.util.spec_from_file_location(
    "windows_proxmox_qga_file_diagnostics_probe",
    WINDOWS_QGA_FILE_DIAGNOSTICS_MODULE_PATH,
)
windows_qga_file_diagnostics = importlib.util.module_from_spec(WINDOWS_QGA_FILE_DIAGNOSTICS_SPEC)
assert WINDOWS_QGA_FILE_DIAGNOSTICS_SPEC.loader is not None
sys.modules[WINDOWS_QGA_FILE_DIAGNOSTICS_SPEC.name] = windows_qga_file_diagnostics
WINDOWS_QGA_FILE_DIAGNOSTICS_SPEC.loader.exec_module(windows_qga_file_diagnostics)

WINDOWS_LAB_READINESS_MODULE_PATH = Path(__file__).with_name("windows_lab_execution_readiness_probe.py")
WINDOWS_LAB_READINESS_SPEC = importlib.util.spec_from_file_location(
    "windows_lab_execution_readiness_probe",
    WINDOWS_LAB_READINESS_MODULE_PATH,
)
windows_lab_readiness = importlib.util.module_from_spec(WINDOWS_LAB_READINESS_SPEC)
assert WINDOWS_LAB_READINESS_SPEC.loader is not None
sys.modules[WINDOWS_LAB_READINESS_SPEC.name] = windows_lab_readiness
WINDOWS_LAB_READINESS_SPEC.loader.exec_module(windows_lab_readiness)

WINDOWS_CONNECTION_STABILITY_MODULE_PATH = Path(__file__).with_name(
    "windows_agent_connection_stability_probe.py"
)
WINDOWS_CONNECTION_STABILITY_SPEC = importlib.util.spec_from_file_location(
    "windows_agent_connection_stability_probe",
    WINDOWS_CONNECTION_STABILITY_MODULE_PATH,
)
windows_connection_stability = importlib.util.module_from_spec(WINDOWS_CONNECTION_STABILITY_SPEC)
assert WINDOWS_CONNECTION_STABILITY_SPEC.loader is not None
sys.modules[WINDOWS_CONNECTION_STABILITY_SPEC.name] = windows_connection_stability
WINDOWS_CONNECTION_STABILITY_SPEC.loader.exec_module(windows_connection_stability)


def test_repeatability_roadmap_requires_all_profiles_pass():
    rows = [
        {"status": "pass", "consecutive_latest_passes": 3},
        {"status": "fail", "consecutive_latest_passes": 0},
    ]

    assert scorecard.roadmap_status(rows, required_passes=3) == "needs-repeatability"


def test_repeatability_roadmap_passes_after_all_profiles_pass_and_repeatability_met():
    rows = [
        {"status": "pass", "consecutive_latest_passes": 3},
        {"status": "pass", "consecutive_latest_passes": 1},
    ]

    assert scorecard.roadmap_status(rows, required_passes=3) == "pass"


def test_scorecard_roadmap_b_note_requires_true_fresh_restore_and_timing_order():
    roadmap_b = next(item for item in scorecard.ROADMAPS if item.key == "B")

    assert "fresh_restore=true" in roadmap_b.note
    assert "valid restore timing order" in roadmap_b.note
    assert "hostname" in roadmap_b.note


def test_scorecard_profile_evidence_uses_aggregate_pass_source_run_id():
    payload = {
        "generated_at": "2026-06-03T00:00:00Z",
        "source": {"artifact_count": 2, "profile_count": 1},
        "roadmaps": [],
        "profiles": [
            {
                "profile_id": "windows-proxmox-qga-readiness-probe",
                "status": "partial",
                "latest": {
                    "run_id": "20260603T134808Z-windows-proxmox-qga-readiness-probe",
                    "raw_quality_gate_passed": False,
                    "quality_gate_failures": ["windows_proxmox_qga_readiness_missing"],
                    "complete_profile_scope": True,
                    "covered": 0,
                    "tests": 1,
                },
                "latest_pass": {
                    "run_id": "20260603T131556Z-windows-proxmox-qga-readiness-probe",
                    "raw_quality_gate_passed": True,
                    "maturity_score": 100,
                    "covered": 7,
                    "tests": 7,
                    "partial": 0,
                    "missed": 0,
                    "execution_failed": 0,
                },
                "latest_fail": {
                    "run_id": "20260603T134808Z-windows-proxmox-qga-readiness-probe",
                },
                "aggregate": {
                    "complete": True,
                    "covered": 7,
                    "expected": 7,
                    "latest_raw_gate_pass": {
                        "run_id": "20260603T131556Z-windows-proxmox-qga-readiness-probe",
                        "raw_quality_gate_passed": True,
                        "maturity_score": 100,
                        "covered": 7,
                        "tests": 7,
                        "partial": 0,
                        "missed": 0,
                        "execution_failed": 0,
                    },
                    "partial_contributor_count": 0,
                },
                "diagnostic_failing_artifacts": 0,
            }
        ],
        "contradictions": [],
        "manual_claim_review": [],
    }

    markdown = scorecard.render_markdown(payload)

    assert (
        "| `windows-proxmox-qga-readiness-probe` | "
        "`20260603T131556Z-windows-proxmox-qga-readiness-probe` | "
        "`aggregate-pass` |"
    ) in markdown
    assert "`20260603T134808Z-windows-proxmox-qga-readiness-probe` | `0` | -" in markdown


def test_scorecard_status_consistency_profile_does_not_aggregate_historical_checks():
    latest_report = {
        "_run_id": "20260603T172105Z-validation-status-consistency-probe",
        "_timestamp": "2026-06-03T17:21:05Z",
        "profile_id": "validation-status-consistency-probe",
        "quality_gate": {"passed": True},
        "summary": {"tests": 1, "covered": 1},
        "tests": [{"id": "status-consistency-new-minimum", "status": "covered"}],
    }
    old_report = {
        "_run_id": "20260603T171727Z-validation-status-consistency-probe",
        "_timestamp": "2026-06-03T17:17:27Z",
        "profile_id": "validation-status-consistency-probe",
        "quality_gate": {"passed": True},
        "summary": {"tests": 1, "covered": 1},
        "tests": [{"id": "status-consistency-old-minimum", "status": "covered"}],
    }

    row = scorecard.profile_status(
        "validation-status-consistency-probe",
        {"validation-status-consistency-probe": latest_report},
        {"validation-status-consistency-probe": [latest_report, old_report]},
        {},
        {},
        {"validation-status-consistency-probe": [latest_report, old_report]},
    )

    assert row["aggregate"]["covered"] == 1
    assert row["aggregate"]["covered_test_ids"] == ["status-consistency-new-minimum"]


def test_scorecard_manual_claim_review_includes_dispatch_manual_claims(tmp_path):
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / "20260604T130502Z-validation-dispatch-results-probe.package-artifacts"
    archive_root.mkdir(parents=True)
    claims_path = archive_root / "agent_claims.json"
    manifest_path = archive_root / "dispatch_manifest.json"
    claims_path.write_text(
        json.dumps(
            {
                "claims": [
                    {
                        "claim_id": "claim-wave-1-qga",
                        "package_id": "wave-1-qga",
                        "owner": "operator-or-secret-holder",
                        "claim_state": "blocked_missing_env",
                        "blocked_reasons": ["missing_effective_env", "manual_launch_required"],
                        "missing_effective_env": ["TAMANDUA_PROXMOX_PASSWORD"],
                        "prompt_path": "docs/benchmarks/runs/dispatch/handoffs/wave-1-qga.agent.md",
                    },
                    {
                        "claim_id": "claim-wave-1-ready",
                        "package_id": "wave-1-ready",
                        "owner": "validation-agent",
                        "claim_state": "ready_to_claim",
                        "blocked_reasons": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps(
            {
                "agent_claims_json_path": "docs/benchmarks/runs/20260604T130502Z-validation-dispatch-results-probe.package-artifacts/agent_claims.json",
                "packages": [
                    {
                        "package_id": "wave-1-qga",
                        "manual_reason": "resource overlap: windows-lab",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    latest = {
        "validation-dispatch-results-probe": {
            "dispatch_manifest": "docs/benchmarks/runs/20260604T130502Z-validation-dispatch-results-probe.package-artifacts/dispatch_manifest.json"
        }
    }
    old_root = scorecard.ROOT
    scorecard.ROOT = tmp_path
    try:
        review = scorecard.dispatch_manual_claim_review(latest)
    finally:
        scorecard.ROOT = old_root

    assert len(review) == 1
    assert review[0]["kind"] == "dispatch-claim"
    assert review[0]["id"] == "claim-wave-1-qga"
    assert review[0]["polarity"] == "manual"
    assert "resource overlap: windows-lab" in review[0]["snippet"]
    assert "TAMANDUA_PROXMOX_PASSWORD" in review[0]["snippet"]


def test_closure_gate_collects_nested_required_input_envs():
    artifact = {
        "tests": [
            {
                "evidence": {
                    "required_inputs": {
                        "snapshot_id": {"env": "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"},
                        "notes": {"env": None},
                    }
                }
            }
        ]
    }

    summary = closure_gate.artifact_gap_summary(artifact)

    assert summary["required_env"] == ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"]


def test_closure_gate_flattens_nested_required_env_lists():
    artifact = {
        "quality_gate": {
            "actionable_gaps": [
                {
                    "evidence": {
                        "next_action": {
                            "required_env": [
                                "CALDERA_API_KEY",
                                "CALDERA_GROUP",
                                "CALDERA_AGENT_PAW",
                            ]
                        }
                    }
                }
            ]
        }
    }

    summary = closure_gate.artifact_gap_summary(artifact)

    assert summary["required_env"] == [
        "CALDERA_AGENT_PAW",
        "CALDERA_API_KEY",
        "CALDERA_GROUP",
    ]


def test_closure_gate_roadmap_test_result_includes_next_action():
    roadmap_item = {
        "key": "D",
        "title": "CALDERA Repeatability Gate",
        "status": "needs-repeatability",
        "profiles": [
            {
                "profile_id": "caldera-api-shape-probe",
                "status": "fail",
                "latest": {
                    "run_id": "20260604T000000Z-caldera-api-shape-probe",
                    "blocking_gaps": ["caldera_api_shape_gaps"],
                },
            }
        ],
    }

    result = closure_gate.test_result("D", "CALDERA Repeatability Gate", roadmap_item)
    action = result["evidence"]["next_action"]

    assert result["status"] == "missed"
    assert action["roadmap"] == "D"
    assert action["blocking_profiles"] == ["caldera-api-shape-probe"]
    assert "CALDERA_API_KEY" in action["action"]


def test_closure_gate_roadmap_e_prioritizes_macos_auth():
    action = closure_gate.roadmap_action_text(
        "E",
        [{"profile_id": "macos-backend-readiness-probe", "missing_values": ["tamandua_ctl_auth"]}],
        [],
    )

    assert "Refresh tamandua-ctl authentication" in action
    assert "reconnect or re-enroll" in action


def test_closure_gate_markdown_renders_next_actions(tmp_path):
    report = {
        "run_id": "20260604T000000Z-roadmap-closure-gate-probe",
        "quality_gate": {"status": "fail"},
        "scorecard_generated_at": "2026-06-04T00:00:00Z",
        "gated_roadmaps": ["D"],
        "roadmap_next_actions": [
            {
                "roadmap": "D",
                "blocking_profiles": ["caldera-api-shape-probe"],
                "required_env": ["CALDERA_API_KEY"],
                "action": "Provide CALDERA_API_KEY, then rerun.",
            }
        ],
        "tests": [
            {
                "evidence": {
                    "roadmap_key": "D",
                    "roadmap_status": "needs-repeatability",
                    "blocking_profiles": [
                        {
                            "profile_id": "caldera-api-shape-probe",
                            "status": "fail",
                            "required_env": ["CALDERA_API_KEY"],
                        }
                    ],
                }
            }
        ],
    }
    path = tmp_path / "closure.md"

    closure_gate.write_markdown(path, report)
    markdown = path.read_text(encoding="utf-8")

    assert "## Next Actions" in markdown
    assert "caldera-api-shape-probe" in markdown
    assert "CALDERA_API_KEY" in markdown
    assert "Provide CALDERA_API_KEY" in markdown


def test_fresh_restore_required_inputs_include_boolean_env():
    assert fresh_restore.RESTORE_FIELD_INPUTS["fresh_restore"]["env"] == "TAMANDUA_FRESH_RESTORE"


def test_fresh_restore_artifact_timestamp_prefers_report_times(tmp_path):
    path = tmp_path / "20260603T100000Z-windows-roadmap-300-batch-01.json"
    report = {
        "run_id": "20260603T090000Z-windows-roadmap-300-batch-01",
        "started_at": "2026-06-03T11:00:00Z",
    }

    assert fresh_restore.artifact_timestamp(report, path) == "2026-06-03T11:00:00Z"


def test_fresh_restore_execution_status_rejects_planned_or_dry_run_artifacts():
    planned = {"execute": False, "mode": "planned", "summary": {"planned": 1, "tests": 1}}
    executed = {"mode": "execute", "summary": {"planned": 0, "tests": 6}}

    planned_status = fresh_restore.execution_status(planned)
    executed_status = fresh_restore.execution_status(executed)

    assert not planned_status["executed"]
    assert "execute=false" in planned_status["reasons"]
    assert "mode=planned" in planned_status["reasons"]
    assert "planned>0" in planned_status["reasons"]
    assert executed_status["executed"]


def write_fresh_restore_batch_artifacts(
    runs_dir: Path,
    *,
    provenance_overrides: dict[str, dict[str, object]] | None = None,
) -> None:
    provenance_overrides = provenance_overrides or {}
    base_provenance = {
        "fresh_restore": True,
        "restore_started_at": "2026-06-03T09:50:00Z",
        "restore_finished_at": "2026-06-03T09:59:00Z",
        "snapshot_name": "pre-roadmap-b",
        "snapshot_id": "snapshot-1",
        "vmid": 1521,
        "agent_id_after_restore": "agent-1",
        "hostname_after_restore": "WIN-TEMPLATE",
    }
    runs_dir.mkdir(parents=True, exist_ok=True)
    for index, profile_id in enumerate(fresh_restore.WINDOWS_300_BATCHES, start=1):
        provenance = dict(base_provenance)
        provenance.update(provenance_overrides.get(profile_id) or {})
        report = {
            "run_id": f"20260603T10{index:02d}00Z-{profile_id}",
            "profile_id": profile_id,
            "mode": "execute",
            "execute": True,
            "started_at": f"2026-06-03T10{index:02d}:00Z",
            "finished_at": f"2026-06-03T10{index:02d}:30Z",
            "summary": {"planned": 0, "tests": 50},
            "fresh_restore_provenance": provenance,
        }
        path = runs_dir / f"20260603T10{index:02d}00Z-{profile_id}.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def test_fresh_restore_build_tests_accepts_six_batches_with_one_restore_window(tmp_path, monkeypatch):
    runs_dir = tmp_path / "docs" / "benchmarks" / "runs"
    write_fresh_restore_batch_artifacts(runs_dir)
    monkeypatch.setattr(fresh_restore, "ROOT", tmp_path)
    monkeypatch.setattr(fresh_restore, "RUNS_DIR", runs_dir)

    tests = fresh_restore.build_tests()

    assert [test["status"] for test in tests] == ["covered"] * 5
    single_window = next(test for test in tests if test["id"] == "fresh-restore-single-provenance-window")
    assert single_window["evidence"]["unique_restore_windows"] == 1


def test_fresh_restore_build_tests_rejects_inconsistent_restore_window(tmp_path, monkeypatch):
    runs_dir = tmp_path / "docs" / "benchmarks" / "runs"
    write_fresh_restore_batch_artifacts(
        runs_dir,
        provenance_overrides={"windows-roadmap-300-batch-06": {"snapshot_id": "snapshot-2"}},
    )
    monkeypatch.setattr(fresh_restore, "ROOT", tmp_path)
    monkeypatch.setattr(fresh_restore, "RUNS_DIR", runs_dir)

    tests = fresh_restore.build_tests()
    single_window = next(test for test in tests if test["id"] == "fresh-restore-single-provenance-window")

    assert single_window["status"] == "missed"
    assert single_window["evidence"]["unique_restore_windows"] == 2
    assert single_window["missing_expected_fields"] == ["no single complete restore window"]


def test_fresh_restore_next_action_for_missing_batches(tmp_path, monkeypatch):
    runs_dir = tmp_path / "docs" / "benchmarks" / "runs"
    monkeypatch.setattr(fresh_restore, "ROOT", tmp_path)
    monkeypatch.setattr(fresh_restore, "RUNS_DIR", runs_dir)

    tests = fresh_restore.build_tests()
    action = fresh_restore.next_action_hint(tests, False)

    assert action["missing_profiles"] == fresh_restore.WINDOWS_300_BATCHES
    assert action["non_executed_profiles"] == fresh_restore.WINDOWS_300_BATCHES
    assert action["missing_metadata_profiles"] == fresh_restore.WINDOWS_300_BATCHES
    assert action["required_env"] == [
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "TAMANDUA_FRESH_RESTORE_VMID",
        "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "TAMANDUA_FRESH_RESTORE_HOSTNAME",
    ]
    assert "Restore WIN-TEMPLATE" in action["action"]


def test_fresh_restore_markdown_renders_next_action(tmp_path):
    action = {
        "missing_profiles": ["windows-roadmap-300-batch-01"],
        "non_executed_profiles": ["windows-roadmap-300-batch-02"],
        "missing_metadata_profiles": ["windows-roadmap-300-batch-03"],
        "field_gaps": {"windows-roadmap-300-batch-04": ["snapshot_id"]},
        "required_env": ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"],
        "action": "Restore WIN-TEMPLATE and rerun all Windows 300 batches.",
    }
    report = {
        "run_id": "20260604T000000Z-fresh-restore-provenance-probe",
        "started_at": "2026-06-04T00:00:00Z",
        "finished_at": "2026-06-04T00:01:00Z",
        "quality_gate": {"passed": False},
        "tests": [
            {
                "id": "fresh-restore-windows-300-artifact-set-present",
                "status": "missed",
                "gap_category": "infrastructure",
                "missing_expected_fields": ["windows-roadmap-300-batch-01"],
                "evidence": {"latest_paths": {}},
            }
        ],
        "fresh_restore_provenance": {"next_action": action},
    }
    markdown_path = tmp_path / "fresh-restore.md"

    fresh_restore.write_markdown(report, markdown_path)
    markdown = markdown_path.read_text(encoding="utf-8")

    assert "## Next Action" in markdown
    assert "windows-roadmap-300-batch-01" in markdown
    assert "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID" in markdown
    assert "Restore WIN-TEMPLATE" in markdown


def test_status_consistency_collects_nested_required_env_lists():
    artifact = {
        "tests": [
            {
                "evidence": {
                    "required_env": [
                        "CALDERA_API_KEY",
                        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
                    ]
                }
            }
        ]
    }

    values = consistency.collect_nested_values(artifact, "required_env")

    assert "CALDERA_API_KEY" in values
    assert "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID" in values


def test_status_consistency_normalizes_artifact_refs():
    assert consistency.normalize_artifact_ref(r"docs\benchmarks\runs\artifact.json") == (
        "docs/benchmarks/runs/artifact.json"
    )
    assert consistency.normalize_artifact_ref(None) == ""


def test_status_consistency_requires_scorecard_indexed_minimum_checks():
    minimum = consistency.MIN_SCORECARD_CONSISTENCY_CHECKS

    assert consistency.scorecard_consistency_latest_meets_minimum({"covered": minimum, "tests": minimum})
    assert not consistency.scorecard_consistency_latest_meets_minimum(
        {"covered": minimum - 1, "tests": minimum - 1}
    )


def test_status_consistency_compares_latest_run_id_timestamps():
    consistency_run = "20260603T192452Z-validation-status-consistency-probe"
    preflight_run = "20260603T192108Z-validation-execution-preflight-probe"
    newer_dispatch_run = "20260603T193000Z-validation-dispatch-results-probe"

    assert consistency.run_id_is_at_least(consistency_run, preflight_run)
    assert not consistency.run_id_is_at_least(consistency_run, newer_dispatch_run)


def test_status_consistency_pass_run_supersedes_latest_fail_timestamp():
    pass_run = "20260603T192922Z-validation-status-consistency-probe"
    fail_run = "20260603T192900Z-validation-status-consistency-probe"
    stale_pass_run = "20260603T192800Z-validation-status-consistency-probe"

    assert consistency.run_id_is_at_least(pass_run, fail_run)
    assert not consistency.run_id_is_at_least(stale_pass_run, fail_run)


def test_status_consistency_explicit_run_id_can_be_prospective_latest(tmp_path):
    scorecard_path = tmp_path / "scorecard.json"
    scorecard_path.write_text(
        json.dumps(
            {
                "profiles": [
                    {
                        "profile_id": "validation-status-consistency-probe",
                        "latest": {
                            "run_id": "20260603T192452Z-validation-status-consistency-probe",
                            "covered": 140,
                            "tests": 140,
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    scorecard = consistency.load_json(scorecard_path)
    latest = consistency.latest_profile(scorecard, "validation-status-consistency-probe")

    assert not consistency.scorecard_consistency_latest_meets_minimum(latest)
    assert consistency.run_id_is_at_least(
        "20260603T193100Z-validation-status-consistency-probe",
        "20260603T192452Z-validation-status-consistency-probe",
    )


def test_status_consistency_prospective_run_accepts_pre_aligned_doc_checks(tmp_path):
    prospective_run = "20990101T000000Z-validation-status-consistency-probe"
    scorecard = consistency.load_json(consistency.SCORECARD_JSON)
    consistency_entry = consistency.profile_entry(scorecard, "validation-status-consistency-probe")
    latest_fail = consistency_entry.get("latest_fail", {}).get("run_id")
    status_docs = []
    for index in range(len(consistency.STATUS_DOCS)):
        doc = tmp_path / f"status-{index}.md"
        doc.write_text(
            f"latest consistency run {prospective_run}\n"
            f"latest superseded consistency fail {latest_fail}\n",
            encoding="utf-8",
        )
        status_docs.append(doc)

    payload = consistency.build_payload(
        consistency.SCORECARD_JSON,
        status_docs,
        prospective_run,
    )

    assert payload["latest"]["validation-status-consistency-probe"]["run_id"] == prospective_run
    doc_checks = [
        item
        for item in payload["checks"]
        if item["name"].endswith("references latest consistency run")
    ]
    assert len(doc_checks) == len(consistency.STATUS_DOCS)
    assert {item["status"] for item in doc_checks} == {"PASS"}
    fail_doc_checks = [
        item
        for item in payload["checks"]
        if item["name"].endswith("references latest superseded consistency fail")
    ]
    assert len(fail_doc_checks) == len(consistency.STATUS_DOCS)
    assert {item["status"] for item in fail_doc_checks} == {"PASS"}


def test_status_consistency_detects_self_indexed_latest_artifact():
    run_id = "20260603T194324Z-validation-status-consistency-probe"
    artifact = {
        "run_id": run_id,
        "latest": {
            "validation-status-consistency-probe": {
                "run_id": run_id,
                "path": f"docs/benchmarks/runs/{run_id}.json",
            }
        },
    }

    assert consistency.consistency_artifact_self_indexes_run(artifact, run_id)
    artifact["latest"]["validation-status-consistency-probe"]["run_id"] = (
        "20260603T193911Z-validation-status-consistency-probe"
    )
    assert not consistency.consistency_artifact_self_indexes_run(artifact, run_id)


def test_status_consistency_detects_self_indexed_dispatch_artifact():
    run_id = "20260604T175518Z-validation-dispatch-results-probe"
    artifact = {"run_id": run_id}

    assert consistency.dispatch_artifact_self_indexes_run(artifact, run_id)
    artifact["run_id"] = "20260604T174000Z-validation-dispatch-results-probe"
    assert not consistency.dispatch_artifact_self_indexes_run(artifact, run_id)


def test_status_consistency_validates_dispatch_timestamps():
    artifact = {
        "generated_at": "2026-06-04T21:35:41.437494Z",
        "summarized_at": "2026-06-04T21:35:41.437494Z",
    }

    assert consistency.dispatch_official_timestamps_are_parseable(artifact)
    artifact["generated_at"] = "2026-06-04T21:35:40Z"
    artifact["summarized_at"] = "2026-06-04T21:35:41Z"
    assert not consistency.dispatch_official_timestamps_are_parseable(artifact)
    artifact["generated_at"] = "2026-06-04T21:35:41.437494Z"
    artifact["summarized_at"] = "2026-06-04T21:35:41.437494Z"
    artifact["summarized_at"] = "not-a-timestamp"
    assert not consistency.dispatch_official_timestamps_are_parseable(artifact)
    artifact.pop("summarized_at")
    assert not consistency.dispatch_official_timestamps_are_parseable(artifact)


def test_status_consistency_existing_expected_run_uses_self_index_sources():
    scorecard = consistency.load_json(consistency.SCORECARD_JSON)
    latest = consistency.latest_profile(scorecard, "validation-status-consistency-probe")
    run_id = str(latest["run_id"])

    payload = consistency.build_payload(consistency.SCORECARD_JSON, consistency.STATUS_DOCS, run_id)

    source_checks = [
        item
        for item in payload["checks"]
        if item["name"] in {
            "consistency latest artifact path exists",
            "consistency latest artifact self-indexes its run_id",
        }
    ]
    expected_source = f"docs/benchmarks/runs/{run_id}.json"
    assert len(source_checks) == 2
    assert all(expected_source in item["source_files"] for item in source_checks)
    assert {item["status"] for item in source_checks} == {"PASS"}


def test_status_consistency_validates_dispatch_self_contained_paths(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    package_dir = archive_root / "packages" / "wave-1"
    package_dir.mkdir(parents=True)
    launcher_path = archive_root / "launchers" / "wave-1.ps1"
    launcher_path.parent.mkdir(parents=True)
    launcher_path.write_text(
        (
            f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1\n"
        ),
        encoding="utf-8",
    )
    prompt_path = package_dir / "prompt.md"
    prompt_path.write_text(
        "\n".join(
            [
                "# wave-1",
                "Claim ID: claim-wave-1",
                "Title: Wave 1",
                "Wave: 1",
                "Owner role: validation-agent",
                "Roadmaps: A",
                "Required env: -",
                "Next-action env: TAMANDUA_SERVER_PASSWORD",
                "Depends on waves: -",
                "Resource tags: windows-lab",
                "Blocking profiles: windows-lab-execution-readiness-probe",
                f"Source preflight: docs/benchmarks/runs/{run_id}.json",
                f"Script: docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1",
                f"Status path: docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/agent_status.json",
                f"Claim lock helper: docs/benchmarks/runs/{run_id}.package-artifacts/claim_lock_helper.ps1",
                (
                    "Claim lock command: powershell -NoProfile -ExecutionPolicy Bypass -File "
                    f"'docs/benchmarks/runs/{run_id}.package-artifacts/claim_lock_helper.ps1' "
                    "-ClaimId claim-wave-1 -AgentId <agent-id>"
                ),
                "Expected JSON profiles: windows-lab-execution-readiness-probe",
                "Status JSON required fields: package_id, claim_id, agent_id, status, artifacts, blocker_cleared, notes, exit_code, expected_profiles, missing_profiles",
                "Status JSON allowed status values: pass, fail, blocked",
                "Current status: not_run",
                "Current exit code: -",
                "Current artifacts: -",
                "Current missing profiles: -",
                "Effective env checklist: -",
                "",
                "Command:",
                (
                    "powershell -NoProfile -ExecutionPolicy Bypass -File "
                    f"'docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1'"
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    script_path = package_dir / "run.ps1"
    script_path.write_text(
        f"$Out = 'docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1'\n",
        encoding="utf-8",
    )
    claim_lock_helper_path = archive_root / "claim_lock_helper.ps1"
    claim_lock_helper_path.write_text("# Validation Claim Lock Helper\n", encoding="utf-8")
    roster_path = archive_root / "agent_roster.md"
    roster_path.write_text(
        "\n".join(
            [
                "# Validation Agent Roster",
                "",
                "| Wave | Package | Owner | Launcher | Resources | Required env | Next-action env | Depends | Script | Prompt | Status | Output contract |",
                "|---:|---|---|---|---|---|---|---|---|---|---|---|",
                (
                    f"| 1 | `wave-1` | validation-agent | auto | `windows-lab` | - | `TAMANDUA_SERVER_PASSWORD` | - | "
                    f"`docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1` | "
                    f"`docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/prompt.md` | "
                    f"`docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/agent_status.json` | "
                    "`windows-lab-execution-readiness-probe` |"
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    brief_path = archive_root / "dispatch_brief.md"
    brief_path.write_text(
        "\n".join(
            [
                "# Validation Dispatch Brief",
                "",
                "| Package | Launcher | Staged | Owner | Resources | Required env | Missing effective env | Script | Prompt | Handoff notes |",
                "|---|---|---|---|---|---|---|---|---|---|",
                (
                    f"| `wave-1` | auto | stage 1 | validation-agent | `windows-lab` | - | - | "
                    f"`docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1` | "
                    f"`docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/prompt.md` | "
                    "`parallelizable`, `parallel-launcher:auto`, `staged-launcher:stage-1` |"
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    (archive_root / "dispatch_manifest.json").write_text(
        json.dumps(
                {
                    "source_preflight": f"docs/benchmarks/runs/{run_id}.json",
                    "output_dir": f"docs/benchmarks/runs/{run_id}.package-artifacts",
                    "agent_roster_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/agent_roster.md",
                    "claim_lock_helper_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/claim_lock_helper.ps1",
                    "dispatch_brief_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_brief.md",
                "launcher_paths": [
                    f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-1.ps1"
                ],
                "packages": [
                    {
                        "package_id": "wave-1",
                        "title": "Wave 1",
                        "recommended_owner_role": "validation-agent",
                        "output_dir": (
                            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1"
                        ),
                        "prompt_path": (
                            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/prompt.md"
                        ),
                        "script_path": (
                            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1"
                        ),
                        "status_path": (
                            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/agent_status.json"
                        ),
                        "claim_output_contract": {
                            "output_dir": "package output directory",
                            "required_json_profile_ids": ["windows-lab-execution-readiness-probe"],
                            "status_file": "agent_status.json",
                            "status_required_fields": [
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
                            ],
                            "status_allowed_values": ["pass", "fail", "blocked"],
                        },
                        "wave": 1,
                        "parallelizable_in_wave": True,
                        "launcher_selected": True,
                        "manual_reason": None,
                        "staged_stage": 1,
                        "resource_tags": ["windows-lab"],
                        "required_env": [],
                        "next_action_required_env": ["TAMANDUA_SERVER_PASSWORD"],
                        "effective_required_env": [],
                        "handoff_notes": [
                            "parallelizable",
                            "parallel-launcher:auto",
                            "staged-launcher:stage-1",
                        ],
                        "roadmaps": ["A"],
                        "blocking_profiles": ["windows-lab-execution-readiness-probe"],
                        "depends_on_waves": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (package_dir / "artifact.json").write_text("{}", encoding="utf-8")
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        artifact = {
            "run_id": run_id,
            "profile_id": "validation-dispatch-results-probe",
            "profile": "validation-dispatch-results-probe",
            "benchmark_lane": "claim-boundary",
            "claim_boundary": (
                "Dispatch-results coordination artifact only. It summarizes package scripts "
                "and their latest local output artifacts; it does not promote package artifacts "
                "to official roadmap evidence or claim closure."
            ),
            "source_preflight": f"docs/benchmarks/runs/{run_id}.json",
            "dispatch_manifest": (
                f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json"
            ),
            "status_counts": {
                "pass": 1,
                "fail": 0,
                "blocked": 0,
                "missing": 0,
                "invalid": 0,
                "unknown": 0,
            },
            "summary": {"covered": 1, "tests": 1},
            "packages": [
                {
                    "package_id": "wave-1",
                    "artifact_path": (
                        f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/artifact.json"
                    ),
                    "archived_artifacts": [
                        f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/artifact.json"
                    ],
                    "output_dir": f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1",
                    "wave": 1,
                    "launcher_selected": True,
                    "manual_reason": None,
                    "staged_stage": 1,
                    "resource_tags": ["windows-lab"],
                    "required_env": [],
                    "roadmaps": ["A"],
                    "blocking_profiles": ["windows-lab-execution-readiness-probe"],
                    "depends_on_waves": [],
                }
            ],
        }

        assert consistency.dispatch_official_metadata_matches_profile(artifact)
        artifact["profile"] = "other-profile"
        assert not consistency.dispatch_official_metadata_matches_profile(artifact)
        artifact["profile"] = "validation-dispatch-results-probe"
        assert consistency.dispatch_official_paths_are_self_contained(artifact, run_id)
        assert consistency.dispatch_official_paths_exist(artifact)
        assert consistency.dispatch_official_payload_has_no_tmp(artifact)
        comparison_path = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.comparison.json"
        comparison_payload = {
            "schema_version": 1,
            "profile_id": artifact.get("profile_id"),
            "benchmark_lane": artifact.get("benchmark_lane"),
            "claim_boundary": artifact.get("claim_boundary"),
            "quality_gate": artifact.get("quality_gate"),
            "summary": {
                "passed_count": artifact.get("passed_count"),
                "failed_count": artifact.get("failed_count"),
                "status_counts": artifact.get("status_counts"),
                "blocked_count": artifact.get("blocked_count"),
                "failed_status_count": artifact.get("failed_status_count"),
                "missing_count": artifact.get("missing_count"),
                "invalid_count": artifact.get("invalid_count"),
                "dispatch_manifest": artifact.get("dispatch_manifest"),
                "source_preflight": artifact.get("source_preflight"),
                "missing_required_env": artifact.get("missing_required_env"),
                "required_env_blockers": artifact.get("required_env_blockers"),
                "owner_handoff": artifact.get("owner_handoff"),
                "covered": artifact.get("summary", {}).get("covered"),
                "tests": artifact.get("summary", {}).get("tests"),
            },
            "packages": json.loads(json.dumps(artifact["packages"])),
            "tests": artifact.get("tests"),
        }
        comparison_path.write_text(json.dumps(comparison_payload), encoding="utf-8")
        assert consistency.dispatch_official_comparison_matches_payload(artifact)
        comparison_payload["schema_version"] = 2
        comparison_path.write_text(json.dumps(comparison_payload), encoding="utf-8")
        assert not consistency.dispatch_official_comparison_matches_payload(artifact)
        comparison_payload["schema_version"] = 1
        comparison_payload["summary"]["status_counts"] = {"pass": 0}
        comparison_path.write_text(json.dumps(comparison_payload), encoding="utf-8")
        assert not consistency.dispatch_official_comparison_matches_payload(artifact)
        comparison_payload["summary"]["status_counts"] = artifact.get("status_counts")
        comparison_payload["quality_gate"] = {"passed": True, "status": "pass"}
        comparison_path.write_text(json.dumps(comparison_payload), encoding="utf-8")
        assert not consistency.dispatch_official_comparison_matches_payload(artifact)
        comparison_payload["quality_gate"] = artifact.get("quality_gate")
        comparison_payload["packages"][0]["profile_results"] = [
            {
                "profile_id": "example-probe",
                "artifact_path": (
                    f"D:/treant/tamandua/docs/benchmarks/runs/{run_id}.package-artifacts/"
                    "packages/wave-1/artifact.json"
                ),
            }
        ]
        comparison_path.write_text(json.dumps(comparison_payload), encoding="utf-8")
        assert not consistency.dispatch_official_comparison_matches_payload(artifact)
        comparison_path.write_text(
            json.dumps(
                {
                    **comparison_payload,
                    "packages": json.loads(json.dumps(artifact["packages"])),
                }
            ),
            encoding="utf-8",
        )
        archived_summary_path = archive_root / "dispatch_results.json"
        archived_summary_markdown_path = archive_root / "dispatch_results.md"
        archived_summary_path.write_text(
            json.dumps(
                {
                    "dispatch_manifest": artifact["dispatch_manifest"],
                    "source_preflight": artifact["source_preflight"],
                    "passed_count": artifact.get("passed_count"),
                    "failed_count": artifact.get("failed_count"),
                    "blocked_count": artifact.get("blocked_count"),
                    "failed_status_count": artifact.get("failed_status_count"),
                    "missing_count": artifact.get("missing_count"),
                    "invalid_count": artifact.get("invalid_count"),
                    "packages": json.loads(json.dumps(artifact["packages"])),
                }
            ),
            encoding="utf-8",
        )
        archived_summary_markdown_path.write_text(
            f"| `wave-1` | `{artifact['packages'][0]['artifact_path']}` |\n",
            encoding="utf-8",
        )
        assert consistency.dispatch_archived_summary_has_self_contained_paths(artifact)
        archived_summary_markdown_path.write_text(
            "artifact D:/treant/tamandua/docs/benchmarks/runs/run.json\n",
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_summary_has_self_contained_paths(artifact)
        archived_summary_markdown_path.write_text(
            f"| `wave-1` | `{artifact['packages'][0]['artifact_path']}` |\n",
            encoding="utf-8",
        )
        assert consistency.dispatch_archived_manifest_source_matches_artifact(artifact)
        assert consistency.dispatch_archived_manifest_has_no_tmp(artifact)
        assert consistency.dispatch_archived_manifest_handoff_paths_exist(artifact)
        assert consistency.dispatch_archived_handoff_contents_are_self_contained(artifact)
        assert consistency.dispatch_archived_manifest_packages_match_artifact(artifact)
        assert consistency.dispatch_archived_manifest_handoff_notes_are_actionable(artifact)
        assert consistency.dispatch_archived_prompts_match_manifest_metadata(artifact)
        assert consistency.dispatch_archived_agent_roster_matches_manifest(artifact)

        artifact["packages"][0]["profile_results"] = [
            {
                "profile_id": "example-probe",
                "artifact_path": (
                    f"D:/treant/tamandua/docs/benchmarks/runs/{run_id}.package-artifacts/"
                    "packages/wave-1/artifact.json"
                ),
            }
        ]
        assert not consistency.dispatch_official_paths_are_self_contained(artifact, run_id)
        assert not consistency.dispatch_official_payload_has_no_tmp(artifact)
        artifact["packages"][0]["profile_results"][0]["artifact_path"] = (
            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/artifact.json"
        )
        assert consistency.dispatch_official_paths_are_self_contained(artifact, run_id)
        assert consistency.dispatch_official_payload_has_no_tmp(artifact)

        artifact["packages"][0]["agent_artifacts"] = [
            (
                f"D:/treant/tamandua/docs/benchmarks/runs/{run_id}.package-artifacts/"
                "packages/wave-1/artifact.json"
            )
        ]
        assert not consistency.dispatch_official_paths_are_self_contained(artifact, run_id)
        assert not consistency.dispatch_official_payload_has_no_tmp(artifact)
        artifact["packages"][0]["agent_artifacts"] = [
            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/artifact.json"
        ]
        assert consistency.dispatch_official_paths_are_self_contained(artifact, run_id)
        assert consistency.dispatch_official_payload_has_no_tmp(artifact)

        roster_text = roster_path.read_text(encoding="utf-8")
        roster_path.write_text(
            roster_text.replace("Next-action env", "Next action env"),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_agent_roster_matches_manifest(artifact)
        roster_path.write_text(roster_text, encoding="utf-8")
        roster_legacy_text = roster_text.replace(
            "| Wave | Package | Owner | Launcher | Resources | Required env | Next-action env | Depends | Script | Prompt | Status | Output contract |",
            "| Wave | Package | Owner | Launcher | Resources | Required env | Depends | Script | Prompt | Status | Output contract |",
        ).replace(
            "|---:|---|---|---|---|---|---|---|---|---|---|---|",
            "|---:|---|---|---|---|---|---|---|---|---|---|",
        ).replace(
            "| - | `TAMANDUA_SERVER_PASSWORD` | - |",
            "| - | - |",
        )
        roster_path.write_text(
            roster_legacy_text,
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_agent_roster_matches_manifest(artifact)
        roster_path.write_text(roster_text, encoding="utf-8")

        (archive_root / "dispatch_manifest.json").write_text(
            json.dumps({"source_preflight": "docs/benchmarks/runs/older-preflight.json"}),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_manifest_source_matches_artifact(artifact)
        (archive_root / "dispatch_manifest.json").write_text(
            json.dumps(
                {
                    "source_preflight": f"docs/benchmarks/runs/{run_id}.json",
                    "packages": [
                        {
                            "package_id": "wave-1",
                            "wave": 1,
                            "launcher_selected": False,
                            "manual_reason": "resource overlap: windows-lab",
                            "resource_tags": ["windows-lab"],
                            "required_env": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_manifest_packages_match_artifact(artifact)
        assert not consistency.dispatch_archived_manifest_handoff_notes_are_actionable(artifact)
        (archive_root / "dispatch_manifest.json").write_text(
            json.dumps(
                {
                    "source_preflight": f"docs/benchmarks/runs/{run_id}.json",
                    "output_dir": "tmp/dispatch-181102",
                    "launcher_paths": [
                        f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-1.ps1"
                    ],
                    "packages": [
                        {
                            "package_id": "wave-1",
                            "output_dir": (
                                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1"
                            ),
                            "prompt_path": (
                                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/prompt.md"
                            ),
                            "script_path": "D:/tmp/package.ps1",
                            "wave": 1,
                            "launcher_selected": True,
                            "manual_reason": None,
                            "resource_tags": ["windows-lab"],
                            "required_env": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_manifest_has_no_tmp(artifact)
        (archive_root / "dispatch_manifest.json").write_text(
            json.dumps(
                {
                    "source_preflight": f"docs/benchmarks/runs/{run_id}.json",
                    "output_dir": f"docs/benchmarks/runs/{run_id}.package-artifacts",
                    "launcher_paths": [
                        f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/missing.ps1"
                    ],
                    "packages": [
                        {
                            "package_id": "wave-1",
                            "output_dir": (
                                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1"
                            ),
                            "prompt_path": (
                                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/missing.md"
                            ),
                            "script_path": (
                                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1"
                            ),
                            "wave": 1,
                            "launcher_selected": True,
                            "manual_reason": None,
                            "resource_tags": ["windows-lab"],
                            "required_env": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_manifest_handoff_paths_exist(artifact)
        prompt_path.write_text("Script: D:/treant/tamandua/tmp/dispatch-181102/wave-1.ps1\n", encoding="utf-8")
        (archive_root / "dispatch_manifest.json").write_text(
            json.dumps(
                {
                    "source_preflight": f"docs/benchmarks/runs/{run_id}.json",
                    "output_dir": f"docs/benchmarks/runs/{run_id}.package-artifacts",
                    "launcher_paths": [
                        f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-1.ps1"
                    ],
                    "packages": [
                        {
                            "package_id": "wave-1",
                            "output_dir": (
                                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1"
                            ),
                            "prompt_path": (
                                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/prompt.md"
                            ),
                            "script_path": (
                                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1"
                            ),
                            "wave": 1,
                            "launcher_selected": True,
                            "manual_reason": None,
                            "resource_tags": ["windows-lab"],
                            "required_env": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_handoff_contents_are_self_contained(artifact)
        prompt_path.write_text(
            "\n".join(
                [
                    "# wave-1",
                    "Title: Wave 1",
                    "Wave: 1",
                    "Owner role: validation-agent",
                    "Roadmaps: A",
                    "Required env: -",
                    "Depends on waves: -",
                    "Resource tags: windows-lab",
                    "Blocking profiles: windows-lab-execution-readiness-probe",
                    f"Source preflight: docs/benchmarks/runs/{run_id}.json",
                    f"Script: docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1",
                    "",
                    "Command:",
                    (
                        "powershell -NoProfile -ExecutionPolicy Bypass -File "
                        f"'docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/run.ps1'"
                    ),
                    "",
                ]
            ),
            encoding="utf-8",
        )
        script_path.write_text("Set-Location 'D:\\treant\\tamandua'\n", encoding="utf-8")
        assert not consistency.dispatch_archived_handoff_contents_are_self_contained(artifact)
        script_path.write_text(
            f"$Out = 'docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1'\n",
            encoding="utf-8",
        )
        prompt_path.write_text(prompt_path.read_text(encoding="utf-8").replace("Roadmaps: A", "Roadmaps: B"), encoding="utf-8")
        assert not consistency.dispatch_archived_prompts_match_manifest_metadata(artifact)
        prompt_path.write_text(prompt_path.read_text(encoding="utf-8").replace("Roadmaps: B", "Roadmaps: A"), encoding="utf-8")
        roster_path.write_text(roster_path.read_text(encoding="utf-8").replace("validation-agent", "other-owner"), encoding="utf-8")
        assert not consistency.dispatch_archived_agent_roster_matches_manifest(artifact)

        artifact["source_preflight"] = f"D:/treant/tamandua/docs/benchmarks/runs/{run_id}.json"
        assert not consistency.dispatch_official_payload_has_no_tmp(artifact)
        artifact["source_preflight"] = f"docs/benchmarks/runs/{run_id}.json"

        artifact["packages"][0]["output_dir"] = "tmp/dispatch-181102/wave-1/outputs"
        assert not consistency.dispatch_official_payload_has_no_tmp(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_dispatch_package_summaries_against_artifacts(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    package_dir = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts" / "packages" / "wave-1"
    package_dir.mkdir(parents=True)
    package_artifact_path = package_dir / "20260603T180000Z-example-probe.json"
    package_artifact_path.write_text(
        json.dumps(
            {
                "profile_id": "example-probe",
                "run_id": "20260603T180000Z-example-probe",
                "quality_gate": {
                    "status": "fail",
                    "passed": False,
                    "blocking_gaps": ["target_offline"],
                    "failures": ["example_probe_gaps"],
                },
            }
        ),
        encoding="utf-8",
    )
    (package_dir / "20260603T180000Z-example-probe.md").write_text("# example\n", encoding="utf-8")
    (package_dir / "20260603T180000Z-example-probe.comparison.json").write_text("{}", encoding="utf-8")
    dispatch_md = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.md"
    dispatch_md.write_text(
        "# Dispatch Results\n\n"
        "- Source preflight: `docs/benchmarks/runs/source-preflight.json`\n"
        "- Passed packages: `0`\n"
        "- Failed/missing packages: `1`\n"
        "- Blocked packages: `0`\n"
        "- Failed packages with artifacts: `1`\n"
        "- Missing packages: `0`\n"
        "- Invalid packages: `0`\n"
        "- Missing required env: `-`\n\n"
        "## Owner Handoff\n\n"
        "| Owner | Packages | Passed | Blocked | Failed | Missing env | Roadmaps |\n"
        "|---|---:|---:|---:|---:|---|---|\n"
        "| `unassigned` | 1 | 0 | 0 | 1 | - | - |\n\n"
        "## Owner Package Queue\n\n"
        "| Owner | Package | Wave | Status | Title | Depends on waves | Parallel in wave | Handoff notes |\n"
        "|---|---|---:|---|---|---|---|---|\n"
        "| `unassigned` | `wave-1` | 1 | `fail` | - | - | false | - |\n\n"
        "| Package | Wave | Selected | Status | Artifact | Blockers | First gap |\n"
        "|---|---:|---|---|---|---|---|\n"
        "| `wave-1` | 1 | true | `fail` | "
        f"`docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
        "20260603T180000Z-example-probe.json` | `target_offline` | `target-offline` |\n"
        "| | | | | | evidence | `required_env` |\n"
        "| | | | | | evidence | `hostname=WIN-TEMPLATE; status=offline; health=unknown` |\n"
        "| | | | | | `windows-agent-connection-stability-probe` next action | "
        "`server_log_access, telemetry_batches; Set TAMANDUA_SERVER_PASSWORD.` |\n",
        encoding="utf-8",
    )
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        artifact = {
            "packages": [
                {
                    "package_id": "wave-1",
                    "artifact_path": (
                        f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
                        "20260603T180000Z-example-probe.json"
                    ),
                    "archived_artifacts": [
                        (
                            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
                            "20260603T180000Z-example-probe.comparison.json"
                        ),
                        (
                            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
                            "20260603T180000Z-example-probe.json"
                        ),
                        (
                            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
                            "20260603T180000Z-example-probe.md"
                        ),
                    ],
                    "profile_id": "example-probe",
                    "run_id": "20260603T180000Z-example-probe",
                    "status": "fail",
                    "passed": False,
                    "agent_missing_required_env": [],
                    "effective_required_env": [],
                    "roadmaps": [],
                    "blocking_profiles": [],
                    "blocked_run_classes": [],
                    "blocking_gaps": ["target_offline"],
                    "failures": ["example_probe_gaps"],
                    "first_gap": {"test_id": "target-offline", "missing": ["required_env"]},
                    "evidence_excerpt": {
                        "missing": ["required_env"],
                        "agent": {
                            "hostname": "WIN-TEMPLATE",
                            "status": "offline",
                            "health": "unknown",
                        }
                    },
                    "profile_results": [
                        {
                            "profile_id": "windows-agent-connection-stability-probe",
                            "evidence_excerpt": {
                                "next_action": {
                                    "missing_stability": ["server_log_access", "telemetry_batches"],
                                    "action": "Set TAMANDUA_SERVER_PASSWORD.",
                                }
                            },
                        }
                    ],
                    "launcher_selected": True,
                    "wave": 1,
                }
            ],
            "tests": [
                {
                    "id": "dispatch-package-wave-1",
                    "status": "missed",
                    "gap_category": "dispatch-results",
                    "evidence": {
                        "package_id": "wave-1",
                        "artifact_path": (
                            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
                            "20260603T180000Z-example-probe.json"
                        ),
                        "profile_id": "example-probe",
                        "run_id": "20260603T180000Z-example-probe",
                        "status": "fail",
                        "first_gap": {"test_id": "target-offline", "missing": ["required_env"]},
                    },
                }
            ],
            "passed_count": 0,
            "failed_count": 1,
            "status_counts": {
                "pass": 0,
                "fail": 1,
                "blocked": 0,
                "missing": 0,
                "invalid": 0,
                "unknown": 0,
            },
            "blocked_count": 0,
            "failed_status_count": 1,
            "missing_count": 0,
            "invalid_count": 0,
            "missing_required_env": [],
            "required_env_blockers": [],
            "owner_handoff": [
                {
                    "owner": "unassigned",
                    "package_count": 1,
                    "passed_count": 0,
                    "blocked_count": 0,
                    "failed_status_count": 1,
                    "missing_count": 0,
                    "invalid_count": 0,
                    "packages": [
                        {
                            "package_id": "wave-1",
                            "wave": 1,
                            "status": "fail",
                            "title": None,
                            "parallelizable_in_wave": None,
                            "depends_on_waves": [],
                            "handoff_notes": [],
                        }
                    ],
                    "missing_required_env": [],
                    "roadmaps": [],
                }
            ],
            "summary": {
                "covered": 0,
                "missed": 1,
                "tests": 1,
                "total": 1,
                "partial": 0,
                "planned": 0,
                "skipped": 0,
                "execution_failed": 0,
                "category_coverage": {
                    "validation_dispatch_results": {
                        "covered": 0,
                        "missed": 1,
                    }
                },
            },
            "quality_gate": {
                "passed": False,
                "status": "fail",
                "blocking_gaps": ["wave-1"],
                "failures": ["dispatch_results_incomplete"],
            },
            "run_id": run_id,
            "source_preflight": "docs/benchmarks/runs/source-preflight.json",
        }

        assert consistency.dispatch_package_summaries_match_artifacts(artifact)
        assert consistency.dispatch_package_archived_artifacts_include_companions(artifact)
        assert consistency.dispatch_tests_match_package_summaries(artifact)
        assert consistency.dispatch_summary_and_gate_match_packages(artifact)
        assert consistency.dispatch_markdown_matches_package_summaries(artifact)
        original_dispatch_markdown = dispatch_md.read_text(encoding="utf-8")
        dispatch_md.write_text(original_dispatch_markdown + "\nD:/treant/tamandua/tmp/dispatch/artifact.json\n", encoding="utf-8")
        assert not consistency.dispatch_markdown_matches_package_summaries(artifact)
        dispatch_md.write_text(original_dispatch_markdown, encoding="utf-8")
        assert consistency.dispatch_package_evidence_excerpt_is_actionable(artifact)
        assert consistency.dispatch_windows_connection_next_action(artifact) == {
            "package_id": "wave-1",
            "profile_id": "windows-agent-connection-stability-probe",
            "missing_stability": ["server_log_access", "telemetry_batches"],
            "has_action": True,
        }
        artifact["packages"][0]["evidence_excerpt"]["missing"] = ["other_env"]
        assert not consistency.dispatch_package_evidence_excerpt_is_actionable(artifact)
        artifact["packages"][0]["evidence_excerpt"]["missing"] = ["required_env"]
        artifact["packages"][0]["first_gap"] = None
        artifact["packages"][0]["evidence_excerpt"] = {}
        assert not consistency.dispatch_package_evidence_excerpt_is_actionable(artifact)
        artifact["packages"][0]["first_gap"] = {"test_id": "target-offline", "missing": ["required_env"]}
        artifact["packages"][0]["evidence_excerpt"] = {
            "missing": ["required_env"],
            "agent": {
                "hostname": "WIN-TEMPLATE",
                "status": "offline",
                "health": "unknown",
            }
        }
        dispatch_md.write_text(dispatch_md.read_text(encoding="utf-8").replace("20260603T180000Z-example-probe.json", "wrong.json"), encoding="utf-8")
        assert not consistency.dispatch_markdown_matches_package_summaries(artifact)
        dispatch_md.write_text(
            dispatch_md.read_text(encoding="utf-8").replace("wrong.json", "20260603T180000Z-example-probe.json"),
            encoding="utf-8",
        )
        artifact["passed_count"] = 1
        assert not consistency.dispatch_summary_and_gate_match_packages(artifact)
        artifact["passed_count"] = 0
        artifact["failed_status_count"] = 0
        assert not consistency.dispatch_summary_and_gate_match_packages(artifact)
        artifact["failed_status_count"] = 1
        artifact["missing_required_env"] = ["TAMANDUA_SERVER_PASSWORD"]
        assert not consistency.dispatch_summary_and_gate_match_packages(artifact)
        artifact["missing_required_env"] = []
        artifact["owner_handoff"][0]["failed_status_count"] = 0
        assert not consistency.dispatch_summary_and_gate_match_packages(artifact)
        artifact["owner_handoff"][0]["failed_status_count"] = 1
        artifact["quality_gate"]["blocking_gaps"] = []
        assert not consistency.dispatch_summary_and_gate_match_packages(artifact)
        artifact["quality_gate"]["blocking_gaps"] = ["wave-1"]
        artifact["summary"]["category_coverage"]["validation_dispatch_results"]["missed"] = 0
        assert not consistency.dispatch_summary_and_gate_match_packages(artifact)
        artifact["summary"]["category_coverage"]["validation_dispatch_results"]["missed"] = 1
        artifact["tests"][0]["evidence"]["artifact_path"] = "docs/benchmarks/runs/wrong.json"
        assert not consistency.dispatch_tests_match_package_summaries(artifact)
        artifact["tests"][0]["evidence"]["artifact_path"] = (
            f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
            "20260603T180000Z-example-probe.json"
        )
        artifact["tests"][0]["status"] = "covered"
        assert not consistency.dispatch_tests_match_package_summaries(artifact)
        artifact["tests"][0]["status"] = "missed"
        artifact["packages"][0]["archived_artifacts"] = artifact["packages"][0]["archived_artifacts"][1:]
        assert not consistency.dispatch_package_archived_artifacts_include_companions(artifact)
        artifact["packages"][0]["archived_artifacts"] = [
            (
                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
                "20260603T180000Z-example-probe.comparison.json"
            ),
            (
                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
                "20260603T180000Z-example-probe.json"
            ),
            (
                f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/"
                "20260603T180000Z-example-probe.md"
            ),
        ]
        artifact["packages"][0]["blocking_gaps"] = ["different_gap"]
        assert not consistency.dispatch_package_summaries_match_artifacts(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_windows_connection_missing_package_handoff():
    artifact = {
        "packages": [
            {
                "package_id": "wave-1-restore-windows-backend-readiness",
                "expected_profile_ids": [
                    "windows-lab-execution-readiness-probe",
                    "windows-agent-connection-stability-probe",
                ],
                "evidence_excerpt": {
                    "missing_package": {
                        "missing_expected_profiles": [
                            "windows-lab-execution-readiness-probe",
                            "windows-agent-connection-stability-probe",
                        ],
                        "required_env": ["TAMANDUA_SERVER_PASSWORD"],
                    }
                },
            }
        ]
    }

    assert consistency.dispatch_windows_connection_handoff(artifact) == {
        "package_id": "wave-1-restore-windows-backend-readiness",
        "profile_id": "windows-agent-connection-stability-probe",
        "required_env": ["TAMANDUA_SERVER_PASSWORD"],
        "missing_package": True,
    }

    artifact["packages"][0]["evidence_excerpt"]["missing_package"]["required_env"] = []
    assert consistency.dispatch_windows_connection_handoff(artifact)["required_env"] == []


def test_status_consistency_validates_macos_auth_handoff_command():
    login_command = "tamandua-ctl remote login --server http://192.168.12.146:4000 --no-browser"
    token_login_command = (
        "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN"
    )
    artifact = {
        "packages": [
            {
                "package_id": "wave-1-restore-macos-backend-readiness",
                "expected_profile_ids": ["macos-backend-readiness-probe"],
                "evidence_excerpt": {
                    "next_action": {
                        "missing_readiness": ["tamandua_ctl_auth"],
                        "login_command": login_command,
                        "token_env": "TAMANDUA_TOKEN",
                        "token_login_command": token_login_command,
                        "target_server": "http://192.168.12.146:4000",
                        "action": "Refresh tamandua-ctl auth, then rerun.",
                    }
                },
            }
        ]
    }

    assert consistency.dispatch_macos_auth_handoff(artifact) == {
        "package_id": "wave-1-restore-macos-backend-readiness",
        "profile_id": "macos-backend-readiness-probe",
        "missing_readiness": ["tamandua_ctl_auth"],
        "login_command": login_command,
        "token_env": "TAMANDUA_TOKEN",
        "token_login_command": token_login_command,
        "target_server": "http://192.168.12.146:4000",
        "has_action": True,
    }

    artifact["packages"][0]["evidence_excerpt"] = {}
    artifact["packages"][0]["profile_results"] = [
        {
            "profile_id": "macos-backend-readiness-probe",
            "evidence_excerpt": {
                "next_action": {
                    "missing_readiness": ["tamandua_ctl_auth"],
                    "login_command": login_command,
                    "token_env": "TAMANDUA_TOKEN",
                    "token_login_command": token_login_command,
                    "target_server": "http://192.168.12.146:4000",
                    "action": "Refresh tamandua-ctl auth, then rerun.",
                }
            },
        }
    ]
    assert consistency.dispatch_macos_auth_handoff(artifact)["login_command"] == login_command
    assert consistency.dispatch_macos_auth_handoff(artifact)["token_login_command"] == token_login_command


def test_status_consistency_validates_dispatch_manifest_against_source_preflight(tmp_path):
    dispatch_run = "20260603T182929Z-validation-dispatch-results-probe"
    preflight_run = "20260603T180000Z-validation-execution-preflight-probe"
    runs_dir = tmp_path / "docs" / "benchmarks" / "runs"
    archive_root = runs_dir / f"{dispatch_run}.package-artifacts"
    archive_root.mkdir(parents=True)
    preflight_path = runs_dir / f"{preflight_run}.json"
    preflight_path.write_text(
        json.dumps(
            {
                "parallel_work_packages": [
                    {
                        "package_id": "wave-1-env",
                        "title": "Env",
                        "wave": 1,
                        "recommended_owner_role": "operator-or-secret-holder",
                        "parallelizable_in_wave": True,
                        "blocked_run_classes": ["windows-broad"],
                        "blocking_profiles": ["fresh-restore-provenance-probe"],
                        "depends_on_waves": [],
                        "required_env": ["TAMANDUA_FRESH_RESTORE"],
                        "roadmaps": ["B"],
                        "safe_commands": ["python tools/detection_validation/fresh_restore_provenance_probe.py --output-dir $Out"],
                    },
                    {
                        "package_id": "wave-1-macos",
                        "title": "macOS",
                        "wave": 1,
                        "recommended_owner_role": "validation-agent",
                        "parallelizable_in_wave": True,
                        "blocked_run_classes": ["macos-server-backed-smoke"],
                        "blocking_profiles": ["macos-backend-readiness-probe"],
                        "depends_on_waves": [],
                        "required_env": [],
                        "roadmaps": ["E"],
                        "safe_commands": ["python tools/detection_validation/macos_backend_readiness_probe.py --output-dir $Out"],
                    },
                    {
                        "package_id": "wave-2-caldera",
                        "title": "CALDERA",
                        "wave": 2,
                        "recommended_owner_role": "validation-agent",
                        "parallelizable_in_wave": True,
                        "blocked_run_classes": ["windows-caldera-enterprise"],
                        "blocking_profiles": ["caldera-repeatability-probe"],
                        "depends_on_waves": [1],
                        "required_env": ["CALDERA_API_KEY"],
                        "roadmaps": ["D"],
                        "safe_commands": ["python tools/detection_validation/caldera_repeatability_probe.py --output-dir $Out"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    manifest = {
        "source_preflight": f"docs/benchmarks/runs/{preflight_run}.json",
        "selection_mode": "wave",
        "selected_wave": 1,
        "expected_waves": [1],
        "expected_package_ids": ["wave-1-env", "wave-1-macos"],
        "packages": [
            {
                "package_id": "wave-1-env",
                "title": "Env",
                "wave": 1,
                "recommended_owner_role": "operator-or-secret-holder",
                "parallelizable_in_wave": True,
                "blocked_run_classes": ["windows-broad"],
                "blocking_profiles": ["fresh-restore-provenance-probe"],
                "depends_on_waves": [],
                "required_env": ["TAMANDUA_FRESH_RESTORE"],
                "roadmaps": ["B"],
                "safe_commands": ["python tools/detection_validation/fresh_restore_provenance_probe.py --output-dir $Out"],
                "script_path": f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/wave-1-env.ps1",
                "output_dir": f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/packages/wave-1-env",
                "status_path": f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/packages/wave-1-env/agent_status.json",
                "claim_output_contract": {
                    "output_dir": "package output directory",
                    "required_json_profile_ids": [],
                    "status_file": "agent_status.json",
                    "status_required_fields": [
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
                    ],
                    "status_allowed_values": ["pass", "fail", "blocked"],
                },
            },
            {
                "package_id": "wave-1-macos",
                "title": "macOS",
                "wave": 1,
                "recommended_owner_role": "validation-agent",
                "parallelizable_in_wave": True,
                "blocked_run_classes": ["macos-server-backed-smoke"],
                "blocking_profiles": ["macos-backend-readiness-probe"],
                "depends_on_waves": [],
                "required_env": [],
                "roadmaps": ["E"],
                "safe_commands": ["python tools/detection_validation/macos_backend_readiness_probe.py --output-dir $Out"],
                "script_path": f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/wave-1-macos.ps1",
                "output_dir": f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/packages/wave-1-macos",
                "status_path": f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/packages/wave-1-macos/agent_status.json",
                "claim_output_contract": {
                    "output_dir": "package output directory",
                    "required_json_profile_ids": [],
                    "status_file": "agent_status.json",
                    "status_required_fields": [
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
                    ],
                    "status_allowed_values": ["pass", "fail", "blocked"],
                },
            },
        ],
    }
    manifest_path = archive_root / "dispatch_manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "source_preflight": f"docs/benchmarks/runs/{preflight_run}.json",
        "dispatch_manifest": f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_manifest_matches_source_preflight_packages(artifact)
        manifest["selection_mode"] = "all"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        assert not consistency.dispatch_archived_manifest_matches_source_preflight_packages(artifact)
        manifest["selection_mode"] = "wave"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest["packages"][1]["required_env"] = ["UNEXPECTED_ENV"]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        assert not consistency.dispatch_archived_manifest_matches_source_preflight_packages(artifact)
        manifest["packages"] = manifest["packages"][:1]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        assert not consistency.dispatch_archived_manifest_matches_source_preflight_packages(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_dispatch_handoff_execution_guards(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    handoff_dir = archive_root / "handoffs" / "wave-1-env"
    launcher_dir = archive_root / "launchers"
    handoff_dir.mkdir(parents=True)
    launcher_dir.mkdir(parents=True)
    script_path = handoff_dir / "wave-1-env.ps1"
    launcher_path = launcher_dir / "wave-1-parallel-launcher.ps1"
    script_path.write_text(
        "$StatusPath = 'agent_status.json'\n"
        "$PackageId = 'wave-1-env'\n"
        "$ClaimId = 'claim-wave-1-env'\n"
        "$AgentId = 'agent-a'\n"
        "function Write-AgentStatus {\n"
        "  param([string]$Status, [int]$ExitCode, [string[]]$Notes)\n"
        "  $Artifacts = @()\n"
        "  $Payload = [pscustomobject]@{ profile_id = 'x'; quality_gate = [pscustomobject]@{ passed = $true } }\n"
        "  $ProfileIdProperty = $Payload.PSObject.Properties['profile_id']\n"
        "  $QualityGateProperty = $Payload.PSObject.Properties['quality_gate']\n"
        "  $PassedProperty = $QualityGateProperty.Value.PSObject.Properties['passed']\n"
        "  $BlockerCleared = ($Status -eq 'pass')\n"
        "  $Payload = [ordered]@{\n"
        "    package_id = $PackageId\n"
        "    claim_id = $ClaimId\n"
        "    agent_id = $AgentId\n"
        "    status = $Status\n"
        "    artifacts = @($Artifacts)\n"
        "    blocker_cleared = [bool]$BlockerCleared\n"
        "    notes = @($Notes)\n"
        "  }\n"
        "}\n"
        "$RequiredEnv = @('CALDERA_API_KEY')\n"
        "$MissingEnv = @($RequiredEnv | Where-Object { -not [Environment]::GetEnvironmentVariable($_) })\n"
        "if ($MissingEnv.Count -gt 0) { Write-Error 'Missing effective env for package'; Write-AgentStatus 'blocked' 2 @('missing_effective_env: CALDERA_API_KEY'); exit 2 }\n",
        encoding="utf-8",
    )
    launcher_path.write_text(
        "$WaveLauncherAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_WAVE_LAUNCHER_AGENT_ID')\n"
        "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId\n"
        "$env:TAMANDUA_AGENT_ID = $AgentId\n"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath\n"
        "if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n",
        encoding="utf-8",
    )
    manifest = {
        "launcher_paths": [
            f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-1-parallel-launcher.ps1"
        ],
        "packages": [
            {
                "package_id": "wave-1-env",
                "required_env": ["CALDERA_API_KEY"],
                "script_path": (
                    f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/wave-1-env/wave-1-env.ps1"
                ),
            }
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_handoff_execution_guards_present(artifact)
        launcher_path.write_text("powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath\n", encoding="utf-8")
        assert not consistency.dispatch_archived_handoff_execution_guards_present(artifact)
        launcher_path.write_text(
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath\n"
            "if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n",
            encoding="utf-8",
        )
        script_path.write_text("Write-Output 'missing guard'\n", encoding="utf-8")
        assert not consistency.dispatch_archived_handoff_execution_guards_present(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_dependent_launcher_evidence_guards(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    launcher_dir = archive_root / "launchers"
    launcher_dir.mkdir(parents=True)
    launcher_path = launcher_dir / "wave-2-parallel-launcher.ps1"
    good_launcher = (
        "# Wave: 2\n"
        "# DependsOnWaves: 1\n"
        "$AllowDependentWaveLaunch = [Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH')\n"
        "$LauncherDir = Split-Path -Parent $MyInvocation.MyCommand.Path\n"
        "$ManifestPath = Join-Path $LauncherDir 'dispatch_manifest.json'\n"
        "$ManifestPath = Join-Path (Split-Path -Parent $LauncherDir) 'dispatch_manifest.json'\n"
        "$DependencyPackages = @($Manifest.packages | Where-Object { [int]$_.wave -eq $WaveNumber -and ($_.launcher_selected -eq $true -or $_.staged_launcher_selected -eq $true) })\n"
        "$MissingDependencyEvidence += ('wave-' + [string]$WaveNumber + ':missing_dependency_packages')\n"
        "$MissingDependencyEvidence += ([string]$DependencyPackage.package_id + ':missing_json_output')\n"
        "foreach ($ExpectedProfile in @($DependencyPackage.expected_profile_ids)) {\n"
        "$MissingDependencyEvidence += ([string]$DependencyPackage.package_id + ':' + [string]$ExpectedProfile + ':quality_gate_not_passed')\n"
        "}\n"
        "Write-Error ('Dependent wave evidence missing: ' + ($MissingDependencyEvidence -join ', '))\n"
    )
    launcher_path.write_text(good_launcher, encoding="utf-8")
    manifest = {
        "launcher_paths": [
            f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-2-parallel-launcher.ps1"
        ],
        "packages": [
            {
                "package_id": "wave-2-dependent",
                "wave": 2,
                "parallelizable_in_wave": True,
                "depends_on_waves": [1],
                "launcher_selected": True,
            }
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_dependent_launcher_evidence_guards_present(artifact)
        launcher_path.write_text(good_launcher.replace("missing_json_output", "missing_output"), encoding="utf-8")
        assert not consistency.dispatch_archived_dependent_launcher_evidence_guards_present(artifact)
        manifest["packages"][0]["depends_on_waves"] = []
        (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        assert consistency.dispatch_archived_dependent_launcher_evidence_guards_present(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_one_shot_runner_guard(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    archive_root.mkdir(parents=True)
    status_file = archive_root / "packages" / "wave-1-caldera" / "agent_status.json"
    status_file.parent.mkdir(parents=True)
    status_file.write_text(
        json.dumps(
            {
                "package_id": "wave-1-caldera",
                "claim_id": "claim-wave-1-caldera",
                "agent_id": "agent-a",
                "status": "blocked",
                "artifacts": [],
                "blocker_cleared": False,
                "notes": ["missing_env"],
                "exit_code": 2,
                "expected_profiles": ["caldera-api-shape-probe"],
                "missing_profiles": ["caldera-api-shape-probe"],
            }
        ),
        encoding="utf-8",
    )
    runner_path = archive_root / "dispatch_one_shot_runner.ps1"
    staged_path = archive_root / "launchers" / "wave-1-staged-launcher.ps1"
    staged_path.parent.mkdir(parents=True)
    staged_path.write_text(
        "# staged\n"
        "$StagedLauncherAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_STAGED_LAUNCHER_AGENT_ID')\n"
        "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId\n"
        "$env:TAMANDUA_AGENT_ID = $AgentId\n"
        "$StageFailures = @()\n"
        "$script:StageFailures += ('stage 1: ' + ($failed -join ', '))\n"
        "Write-Error ('Failed package jobs across staged wave: ' + ($StageFailures -join '; '))\n",
        encoding="utf-8",
    )
    runner_path.write_text(
        "$AllowOneShot = [Environment]::GetEnvironmentVariable('TAMANDUA_ALLOW_ONE_SHOT_DISPATCH')\n"
        "$env:TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH = '1'\n"
        "$DispatchAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_DISPATCH_AGENT_ID')\n"
        "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId\n"
        "$env:TAMANDUA_AGENT_ID = $script:DispatchAgentId\n"
        "$DispatchFailures = @()\n"
        "$FailedWaves = @{}\n"
        "$ClaimLockHelperPath = Join-Path $DispatchRunnerDir 'claim_lock_helper.ps1'\n"
        "Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)\n"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ClaimLockHelperPath -ClaimId $ClaimId -AgentId $script:DispatchAgentId\n"
        "$script:DispatchFailures += ($Label + ' claim lock exit ' + [string]$LASTEXITCODE)\n"
        "function Write-DispatchBlockedPackageStatus { "
        "$ExpectedProfiles = @($Package.expected_profile_ids | ForEach-Object { [string]$_ }); "
        "$Status = @{ claim_id = 'claim-' + [string]$Package.package_id; agent_id = $script:DispatchAgentId; status = 'blocked'; exit_code = 2; missing_profiles = $ExpectedProfiles } }\n"
        "function Write-DispatchBlockedWaveStatuses { param([int]$Wave, [string]$Note) }\n"
        "function Test-DispatchWaveDependencies { param([int]$Wave, [int[]]$DependsOnWaves) }\n"
        "function Invoke-DispatchCommand { param([string]$Label, [string[]]$Command) }\n"
        "$script:DispatchFailures += ('wave 2 skipped because dependency wave failed: 1')\n"
        "$script:DispatchFailures += ('wave 3 skipped because dependency evidence missing: missing_json_output')\n"
        f"powershell.exe -File 'docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-1-staged-launcher.ps1'\n"
        "python tools/detection_validation/run_preflight_work_package.py --summarize-dispatch dispatch_manifest.json\n"
        "python tools/detection_validation/run_preflight_work_package.py --promote-dispatch-results dispatch_manifest.json\n"
        "python tools/detection_validation/generate_validation_scorecard.py\n"
        "python tools/detection_validation/validation_status_consistency.py\n"
        "Write-Error ('Dispatch one-shot completed with failures: ' + ($DispatchFailures -join ', '))\n",
        encoding="utf-8",
    )
    manifest = {
        "dispatch_runner_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_one_shot_runner.ps1",
        "staged_launcher_paths": [
            f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-1-staged-launcher.ps1"
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_one_shot_runner_guard_present(artifact)
        runner_path.write_text(
            runner_path.read_text(encoding="utf-8").replace("Write-DispatchBlockedWaveStatuses", "Write-DispatchSkippedWaveStatuses"),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_one_shot_runner_guard_present(artifact)
        runner_path.write_text(
            runner_path.read_text(encoding="utf-8").replace("Write-DispatchSkippedWaveStatuses", "Write-DispatchBlockedWaveStatuses"),
            encoding="utf-8",
        )
        runner_path.write_text(runner_path.read_text(encoding="utf-8").replace("--promote-dispatch-results", ""), encoding="utf-8")
        assert not consistency.dispatch_archived_one_shot_runner_guard_present(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_env_checklist_operator_input_details(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    archive_root.mkdir(parents=True)
    checklist_path = archive_root / "env_checklist.md"
    checklist_path.write_text(
        "# Validation Env Checklist\n\n"
        "| Wave | Package | Env var | Present | Class | Source | Flag | Description | Owner |\n"
        "|---:|---|---|---|---|---|---|---|---|\n"
        "| 2 | `wave-2-caldera` | `CALDERA_GROUP` | `no` | `claim-metadata` | `next-action+script` | `--caldera-group` | set to tamandua-lab | operator-or-secret-holder |\n",
        encoding="utf-8",
    )
    manifest = {
        "env_checklist_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_checklist.md",
        "packages": [
            {
                "package_id": "wave-2-caldera",
                "env_details": {
                    "CALDERA_GROUP": {
                        "name": "caldera_group",
                        "flag": "--caldera-group",
                        "description": "set to tamandua-lab",
                    }
                },
                "operator_inputs": [
                    {
                        "name": "caldera_group",
                        "env": "CALDERA_GROUP",
                        "flag": "--caldera-group",
                        "description": "set to tamandua-lab",
                    }
                ],
            }
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_env_checklist_includes_operator_input_details(artifact)
        checklist_path.write_text(
            checklist_path.read_text(encoding="utf-8").replace("--caldera-group", "--wrong-flag"),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_env_checklist_includes_operator_input_details(artifact)
        checklist_path.write_text(
            checklist_path.read_text(encoding="utf-8").replace("--wrong-flag", "--caldera-group"),
            encoding="utf-8",
        )
        manifest["packages"][0]["env_details"]["CALDERA_GROUP"]["description"] = "wrong description"
        (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        assert not consistency.dispatch_archived_env_checklist_includes_operator_input_details(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_env_template_is_redacted_and_complete(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    archive_root.mkdir(parents=True)
    template_path = archive_root / "env_template.ps1"
    template_path.write_text(
        "# Validation env handoff template\n"
        "# Fill placeholders locally before launching dispatch scripts.\n"
        "# This file is generated with redacted placeholder values only.\n\n"
        "# Class: secret; Owner: operator-or-secret-holder\n"
        "# Flag: -; Description: API key\n"
        "$env:CALDERA_API_KEY = '<set-caldera-api-key-secret>'\n\n"
        "# Class: claim-metadata; Owner: operator-or-secret-holder\n"
        "# Flag: --caldera-group; Description: group\n"
        "$env:CALDERA_GROUP = '<set-caldera-group>'\n",
        encoding="utf-8",
    )
    manifest = {
        "env_template_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_template.ps1",
        "packages": [
            {
                "package_id": "wave-2-caldera",
                "effective_required_env": ["CALDERA_API_KEY", "CALDERA_GROUP"],
            }
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_env_template_is_redacted_and_complete(artifact)
        template_path.write_text(
            template_path.read_text(encoding="utf-8").replace("<set-caldera-api-key-secret>", "real-key"),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_env_template_is_redacted_and_complete(artifact)
        template_path.write_text(
            template_path.read_text(encoding="utf-8").replace("real-key", "<set-caldera-api-key-secret>").replace(
                "$env:CALDERA_GROUP", "$env:OTHER_GROUP"
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_env_template_is_redacted_and_complete(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_current_action_env_guards(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    handoff_root = archive_root / "handoffs" / "wave-1-macos"
    handoff_root.mkdir(parents=True)
    template_path = archive_root / "env_template.ps1"
    roster_path = archive_root / "agent_roster.md"
    script_path = handoff_root / "wave-1-macos.ps1"
    token_login_command = (
        "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN"
    )
    template_path.write_text(
        "# Validation env handoff template\n"
        "# Fill placeholders locally before launching dispatch scripts.\n"
        "# This file is generated with redacted placeholder values only.\n\n"
        "# Class: secret; Owner: validation-agent\n"
        "# Flag: -; Description: -\n"
        "$env:TAMANDUA_TOKEN = '<set-tamandua-token-secret>'\n",
        encoding="utf-8",
    )
    roster_path.write_text(
        "\n".join(
            [
                "# Validation Agent Roster",
                "",
                "| Wave | Package | Owner | Launcher | Resources | Required env | Next-action env | Depends | Script | Prompt | Status | Output contract |",
                "|---:|---|---|---|---|---|---|---|---|---|---|---|",
                (
                    f"| 1 | `wave-1-macos` | validation-agent | auto | `macos-agent` | - | `TAMANDUA_TOKEN` | - | "
                    f"`docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/wave-1-macos/wave-1-macos.ps1` | "
                    f"`docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/wave-1-macos/wave-1-macos.agent.md` | "
                    f"`docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1-macos/agent_status.json` | "
                    "`macos-backend-readiness-probe` |"
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    script_path.write_text(
        "$RequiredEnv = @('TAMANDUA_TOKEN')\n"
        "$MissingEnv = @($RequiredEnv | Where-Object { -not [Environment]::GetEnvironmentVariable($_) })\n"
        "if ($MissingEnv.Count -gt 0) {\n"
        "  Write-Host ('Missing effective env for package: ' + ($MissingEnv -join ', '))\n"
        "}\n",
        encoding="utf-8",
    )
    manifest = {
        "env_template_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_template.ps1",
        "agent_roster_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/agent_roster.md",
        "packages": [
            {
                "package_id": "wave-1-macos",
                "script_path": (
                    f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/wave-1-macos/wave-1-macos.ps1"
                ),
                "current_next_action": {
                    "token_env": "TAMANDUA_TOKEN",
                    "token_login_command": token_login_command,
                },
                "current_next_action_required_env": ["TAMANDUA_TOKEN"],
            }
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_current_action_env_guards_match_manifest(artifact)
        template_path.write_text(
            template_path.read_text(encoding="utf-8").replace("$env:TAMANDUA_TOKEN", "$env:TAMANDUA_OTHER"),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_current_action_env_guards_match_manifest(artifact)
        template_path.write_text(
            template_path.read_text(encoding="utf-8").replace("$env:TAMANDUA_OTHER", "$env:TAMANDUA_TOKEN"),
            encoding="utf-8",
        )
        script_path.write_text(script_path.read_text(encoding="utf-8").replace("'TAMANDUA_TOKEN'", "'OTHER_TOKEN'"), encoding="utf-8")
        assert not consistency.dispatch_archived_current_action_env_guards_match_manifest(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_owner_launch_plan_matches_manifest(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    archive_root.mkdir(parents=True)
    plan_path = archive_root / "owner_launch_plan.md"
    script_ref = f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/wave-1-caldera/wave-1-caldera.ps1"
    prompt_ref = f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/wave-1-caldera/wave-1-caldera.agent.md"
    checklist_ref = f"docs/benchmarks/runs/{run_id}.package-artifacts/env_checklist.md"
    template_ref = f"docs/benchmarks/runs/{run_id}.package-artifacts/env_template.ps1"
    plan_path.write_text(
        "# Validation Owner Launch Plan\n\n"
        f"Env checklist: `{checklist_ref}`\n"
        f"Env template: `{template_ref}`\n\n"
        "## Owner: operator-or-secret-holder\n\n"
        "| Wave | Stage | Package | Launch mode | Depends | Missing env | Command | Prompt |\n"
        "|---:|---:|---|---|---|---|---|---|\n"
        f"| 1 | 1 | `wave-1-caldera` | parallel-auto | - | `CALDERA_API_KEY` | `powershell -NoProfile -ExecutionPolicy Bypass -File '{script_ref}'` | `{prompt_ref}` |\n",
        encoding="utf-8",
    )
    manifest = {
        "env_checklist_path": checklist_ref,
        "env_template_path": template_ref,
        "owner_launch_plan_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/owner_launch_plan.md",
        "packages": [
            {
                "package_id": "wave-1-caldera",
                "recommended_owner_role": "operator-or-secret-holder",
                "script_path": script_ref,
                "prompt_path": prompt_ref,
                "effective_required_env": ["CALDERA_API_KEY"],
            }
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_owner_launch_plan_matches_manifest(artifact)
        plan_path.write_text(plan_path.read_text(encoding="utf-8").replace(script_ref, "wrong.ps1"), encoding="utf-8")
        assert not consistency.dispatch_archived_owner_launch_plan_matches_manifest(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_owner_launch_plan_json_matches_manifest(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    archive_root.mkdir(parents=True)
    script_ref = f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/wave-1-caldera/wave-1-caldera.ps1"
    prompt_ref = f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/wave-1-caldera/wave-1-caldera.agent.md"
    status_ref = f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1-caldera/agent_status.json"
    prompt_path = archive_root / "handoffs" / "wave-1-caldera" / "wave-1-caldera.agent.md"
    prompt_path.parent.mkdir(parents=True)
    prompt_path.write_text(
        "# wave-1-caldera\n\nClaim ID: claim-wave-1-caldera\n\nCommand:\n"
        f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_ref}'\n",
        encoding="utf-8",
    )
    status_path = archive_root / "packages" / "wave-1-caldera" / "agent_status.json"
    status_path.parent.mkdir(parents=True)
    status_path.write_text(
        json.dumps(
            {
                "package_id": "wave-1-caldera",
                "claim_id": "claim-wave-1-caldera",
                "agent_id": "agent-a",
                "status": "blocked",
                "artifacts": [],
                "blocker_cleared": False,
                "notes": ["missing_env"],
                "exit_code": 2,
                "expected_profiles": ["caldera-api-shape-probe"],
                "missing_profiles": ["caldera-api-shape-probe"],
            }
        ),
        encoding="utf-8",
    )
    plan_json_path = archive_root / "owner_launch_plan.json"
    plan_json_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact": "validation-owner-launch-plan",
                "env_checklist_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_checklist.md",
                "env_template_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_template.ps1",
                "owner_count": 1,
                "package_count": 1,
                "launchable_package_count": 0,
                "blocked_package_count": 1,
                "owners": [
                    {
                        "owner": "operator-or-secret-holder",
                        "package_count": 1,
                        "launchable_package_count": 0,
                        "blocked_package_count": 1,
                        "missing_effective_env": ["CALDERA_API_KEY"],
                        "roadmaps": ["D"],
                        "packages": [
                            {
                                "package_id": "wave-1-caldera",
                                "wave": 1,
                                "stage": 1,
                                "depends_on_waves": [],
                                "script_path": script_ref,
                                "prompt_path": prompt_ref,
                                "status_path": status_ref,
                                "command": f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_ref}'",
                                "missing_effective_env": ["CALDERA_API_KEY"],
                                "ready_to_launch": False,
                                "blocked_reasons": ["missing_effective_env"],
                                "current_status": "blocked",
                                "current_exit_code": 2,
                                "current_notes": ["missing_env"],
                                "current_artifacts": [],
                                "current_missing_profiles": ["caldera-api-shape-probe"],
                                "current_blocker_cleared": False,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    plan = json.loads(plan_json_path.read_text(encoding="utf-8"))
    matrix_json_path = archive_root / "execution_matrix.json"
    matrix_path = archive_root / "execution_matrix.md"
    matrix = preflight_work_package.build_execution_matrix_json(plan)
    matrix_json_path.write_text(json.dumps(matrix), encoding="utf-8")
    matrix_path.write_text(preflight_work_package.render_execution_matrix(matrix), encoding="utf-8")
    claims_json_path = archive_root / "agent_claims.json"
    claims_path = archive_root / "agent_claims.md"
    claims = preflight_work_package.build_agent_claims_json(matrix)
    claims_json_path.write_text(json.dumps(claims), encoding="utf-8")
    claims_path.write_text(preflight_work_package.render_agent_claims(claims), encoding="utf-8")
    spawn_plan_json_path = archive_root / "agent_spawn_plan.json"
    spawn_plan_path = archive_root / "agent_spawn_plan.md"
    archive_ref = Path(f"docs/benchmarks/runs/{run_id}.package-artifacts")

    def build_spawn_plan(claims_payload):
        plan = preflight_work_package.build_agent_spawn_plan_json(claims_payload, archive_ref)
        for batch_key in ("batches", "env_bundle_ready_batches"):
            for batch in plan.get(batch_key) or []:
                for claim in batch.get("claims") or []:
                    prompt_file = tmp_path / str(claim.get("prompt_path") or "")
                    prompt_text = prompt_file.read_text(encoding="utf-8").strip() if prompt_file.exists() else ""
                    claim["prompt_text"] = prompt_text
                    templates = claim.get("agent_spawn_command_templates") or {}
                    claim["copy_paste_prompt"] = "\n".join(
                        [
                            f"Claim ID: {claim.get('claim_id')}",
                            f"Package ID: {claim.get('package_id')}",
                            f"Prompt path: {claim.get('prompt_path')}",
                            f"Working directory: {claim.get('cwd')}",
                            f"Claim env: {claim.get('claim_id_env')}",
                            f"Agent env: {claim.get('agent_id_env')}",
                            f"Claim lock command: {claim.get('lock_command')}",
                            f"Run command: {claim.get('run_command')}",
                            f"Codex spawn template: {templates.get('codex')}",
                            f"Claude spawn template: {templates.get('claude')}",
                            "",
                            prompt_text,
                        ]
                    ).strip()
        return plan

    spawn_plan = build_spawn_plan(claims)
    spawn_plan_json_path.write_text(json.dumps(spawn_plan), encoding="utf-8")
    spawn_plan_path.write_text(preflight_work_package.render_agent_spawn_plan(spawn_plan), encoding="utf-8")
    spawn_launcher_path = archive_root / "agent_spawn_launcher.ps1"
    spawn_launcher_path.write_text(
        preflight_work_package.render_agent_spawn_launcher(spawn_plan_json_path),
        encoding="utf-8",
    )
    claim_report_json_path = archive_root / "claim_status_report.json"
    claim_report_path = archive_root / "claim_status_report.md"
    claim_lock_dir = archive_root / "claim_locks"
    claim_lock_dir.mkdir()
    (claim_lock_dir / "claim-wave-1-caldera.claim-lock.json").write_text(
        json.dumps(
            {
                "claim_id": "claim-wave-1-caldera",
                "agent_id": "agent-a",
                "locked_at": "2026-06-04T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    claim_report = preflight_work_package.build_claim_status_report_json(claims, archive_root / "claim_locks")
    claim_report_json_path.write_text(json.dumps(claim_report), encoding="utf-8")
    claim_report_path.write_text(preflight_work_package.render_claim_status_report(claim_report), encoding="utf-8")
    claim_lock_helper_path = archive_root / "claim_lock_helper.ps1"
    claim_lock_helper_path.write_text(preflight_work_package.render_claim_lock_helper(claims), encoding="utf-8")
    queue_json_path = archive_root / "env_unblock_queue.json"
    queue_path = archive_root / "env_unblock_queue.md"
    queue = preflight_work_package.build_env_unblock_queue_json(
        claims,
        Path(f"docs/benchmarks/runs/{run_id}.package-artifacts/env_bundle_ready_claims_launcher.ps1"),
    )
    queue_json_path.write_text(json.dumps(queue), encoding="utf-8")
    queue_path.write_text(preflight_work_package.render_env_unblock_queue(queue), encoding="utf-8")
    ready_launcher_path = archive_root / "ready_claims_launcher.ps1"
    ready_launcher_path.write_text(preflight_work_package.render_ready_claims_launcher(claims), encoding="utf-8")
    ready_parallel_launcher_path = archive_root / "ready_claims_parallel_launcher.ps1"
    ready_parallel_launcher_path.write_text(
        preflight_work_package.render_ready_claims_parallel_launcher(claims),
        encoding="utf-8",
    )
    env_bundle_launcher_path = archive_root / "env_bundle_ready_claims_launcher.ps1"
    env_bundle_launcher_path.write_text(
        preflight_work_package.render_env_bundle_ready_claims_launcher(claims),
        encoding="utf-8",
    )
    prelaunch_validation_path = archive_root / "dispatch_prelaunch_validation.ps1"
    prelaunch_validation_path.write_text(
        preflight_work_package.render_dispatch_prelaunch_validation(
            Path(f"docs/benchmarks/runs/{run_id}.package-artifacts/agent_spawn_launcher.ps1"),
            Path(f"docs/benchmarks/runs/{run_id}.package-artifacts/ready_claims_launcher.ps1"),
            Path(f"docs/benchmarks/runs/{run_id}.package-artifacts/ready_claims_parallel_launcher.ps1"),
            Path(f"docs/benchmarks/runs/{run_id}.package-artifacts/env_bundle_ready_claims_launcher.ps1"),
            Path(f"docs/benchmarks/runs/{run_id}.package-artifacts/claim_lock_helper.ps1"),
        ),
        encoding="utf-8",
    )
    brief_path = archive_root / "dispatch_brief.md"
    brief_path.write_text(
        "\n".join(
            [
                "# Validation Dispatch Brief",
                "",
                "## Recommended Launch Sequence",
                "",
                f"1. Dispatch prelaunch validation: `powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_prelaunch_validation.ps1'`",
                "   This runs no-execution checks for spawn dry-run, ready launchers, and claim-lock listing.",
                f"   Wrapped agent spawn dry run: `powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/agent_spawn_launcher.ps1' -Provider all -Phase all -ShowBlocked`",
                "   This prints Codex/Claude spawn commands and blocked-claim context; it does not execute package scripts.",
                f"1a. Optional Codex parallel agent execution: `$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/agent_spawn_launcher.ps1' -Provider codex -Phase ready -Execute -Parallel`",
                f"1b. Optional Claude parallel agent execution: `$env:TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/agent_spawn_launcher.ps1' -Provider claude -Phase ready -Execute -Parallel`",
                f"1c. Optional env-bundle prelaunch validation after env fill: `powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_prelaunch_validation.ps1' -ValidateEnvBundle`",
                "   Use one provider per claim; this acquires claim locks inline before spawning agents.",
                "   Duplicate-provider execution requires both `-AllowDuplicateProviderPerClaim` and `TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1`; override launches emit `[duplicate-provider-override]`.",
                f"2. Ready package claims: `$env:TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/ready_claims_parallel_launcher.ps1'`",
                f"   Validate first without launching: `powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/ready_claims_parallel_launcher.ps1' -ValidateOnly`",
                "   This launcher runs package scripts directly after acquiring claim locks; use the agent spawn dry run above for Codex/Claude commands.",
                f"3. Fill env bundle: `docs/benchmarks/runs/{run_id}.package-artifacts/env_unblock_queue.md`",
                f"4. Post-env-bundle package claims: `$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'; powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/env_bundle_ready_claims_launcher.ps1'`",
                f"   Validate first without launching: `powershell -NoProfile -ExecutionPolicy Bypass -File 'docs/benchmarks/runs/{run_id}.package-artifacts/env_bundle_ready_claims_launcher.ps1' -ValidateOnly`",
                f"5. Refresh claim status: `python tools/detection_validation/run_preflight_work_package.py --refresh-claim-status-report 'docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json'`",
            ]
        ),
        encoding="utf-8",
    )
    manifest = {
        "env_checklist_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_checklist.md",
        "env_template_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_template.ps1",
        "owner_launch_plan_json_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/owner_launch_plan.json",
        "execution_matrix_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/execution_matrix.md",
        "execution_matrix_json_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/execution_matrix.json",
        "agent_claims_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/agent_claims.md",
        "agent_claims_json_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/agent_claims.json",
        "agent_spawn_plan_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/agent_spawn_plan.md",
        "agent_spawn_plan_json_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/agent_spawn_plan.json",
        "agent_spawn_launcher_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/agent_spawn_launcher.ps1",
        "claim_status_report_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/claim_status_report.md",
        "claim_status_report_json_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/claim_status_report.json",
        "claim_lock_helper_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/claim_lock_helper.ps1",
        "env_unblock_queue_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_unblock_queue.md",
        "env_unblock_queue_json_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_unblock_queue.json",
        "ready_claims_launcher_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/ready_claims_launcher.ps1",
        "ready_claims_parallel_launcher_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/ready_claims_parallel_launcher.ps1",
        "env_bundle_ready_claims_launcher_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/env_bundle_ready_claims_launcher.ps1",
        "dispatch_prelaunch_validation_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_prelaunch_validation.ps1",
        "dispatch_brief_path": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_brief.md",
        "packages": [
            {
                "package_id": "wave-1-caldera",
                "recommended_owner_role": "operator-or-secret-holder",
                "depends_on_waves": [],
                "launcher_selected": True,
                "script_path": script_ref,
                "prompt_path": prompt_ref,
                "status_path": status_ref,
                "effective_required_env": ["CALDERA_API_KEY"],
            }
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_owner_launch_plan_json_matches_manifest(artifact)
        assert consistency.dispatch_archived_execution_matrix_matches_owner_plan(artifact)
        assert consistency.dispatch_archived_agent_claims_match_execution_matrix(artifact)
        assert consistency.dispatch_archived_agent_spawn_plan_matches_agent_claims(artifact)
        assert consistency.dispatch_archived_agent_spawn_launcher_matches_spawn_plan(artifact)
        assert consistency.dispatch_archived_claim_status_report_matches_agent_claims(artifact)
        assert consistency.dispatch_archived_claim_lock_helper_matches_agent_claims(artifact)
        assert consistency.dispatch_archived_env_unblock_queue_matches_agent_claims(artifact)
        assert consistency.dispatch_archived_ready_claims_launcher_matches_agent_claims(artifact)
        assert consistency.dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(artifact)
        assert consistency.dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(artifact)
        assert consistency.dispatch_archived_prelaunch_validation_matches_manifest(artifact)
        assert consistency.dispatch_archived_brief_recommended_launch_sequence_matches_manifest(artifact)
        queue["entries"][0]["claim_count"] = 99
        queue_json_path.write_text(json.dumps(queue), encoding="utf-8")
        assert not consistency.dispatch_archived_env_unblock_queue_matches_agent_claims(artifact)
        queue = preflight_work_package.build_env_unblock_queue_json(
            claims,
            Path(f"docs/benchmarks/runs/{run_id}.package-artifacts/env_bundle_ready_claims_launcher.ps1"),
        )
        queue_json_path.write_text(json.dumps(queue), encoding="utf-8")
        queue["entries"][0]["copy_paste_unblock_prompt"] = queue["entries"][0]["copy_paste_unblock_prompt"].replace(
            "Claims still blocked after setting only this env:",
            "Claims omitted after setting only this env:",
        )
        queue_json_path.write_text(json.dumps(queue), encoding="utf-8")
        queue_path.write_text(preflight_work_package.render_env_unblock_queue(queue), encoding="utf-8")
        assert not consistency.dispatch_archived_env_unblock_queue_matches_agent_claims(artifact)
        queue = preflight_work_package.build_env_unblock_queue_json(
            claims,
            Path(f"docs/benchmarks/runs/{run_id}.package-artifacts/env_bundle_ready_claims_launcher.ps1"),
        )
        queue_json_path.write_text(json.dumps(queue), encoding="utf-8")
        queue_path.write_text(preflight_work_package.render_env_unblock_queue(queue), encoding="utf-8")
        claims["claims"][0]["claim_state"] = "ready_to_claim"
        claims_json_path.write_text(json.dumps(claims), encoding="utf-8")
        assert not consistency.dispatch_archived_agent_claims_match_execution_matrix(artifact)
        claims = preflight_work_package.build_agent_claims_json(matrix)
        claims_json_path.write_text(json.dumps(claims), encoding="utf-8")
        spawn_plan = build_spawn_plan(claims)
        spawn_plan_json_path.write_text(json.dumps(spawn_plan), encoding="utf-8")
        spawn_plan_path.write_text(preflight_work_package.render_agent_spawn_plan(spawn_plan), encoding="utf-8")
        env_bundle_copy_prompt = spawn_plan["env_bundle_ready_batches"][0]["claims"][0]["copy_paste_prompt"]
        spawn_plan["env_bundle_ready_batches"][0]["claims"][0]["copy_paste_prompt"] = env_bundle_copy_prompt.replace(
            spawn_plan["env_bundle_ready_batches"][0]["claims"][0]["run_command"],
            "powershell -NoProfile -ExecutionPolicy Bypass -File 'wrong.ps1'",
        )
        spawn_plan_json_path.write_text(json.dumps(spawn_plan), encoding="utf-8")
        spawn_plan_path.write_text(preflight_work_package.render_agent_spawn_plan(spawn_plan), encoding="utf-8")
        assert not consistency.dispatch_archived_agent_spawn_plan_matches_agent_claims(artifact)
        spawn_plan = build_spawn_plan(claims)
        spawn_plan_json_path.write_text(json.dumps(spawn_plan), encoding="utf-8")
        spawn_plan_path.write_text(preflight_work_package.render_agent_spawn_plan(spawn_plan), encoding="utf-8")
        spawn_plan["env_bundle_ready_batches"][0]["claims"][0]["cwd"] = "wrong-cwd"
        spawn_plan_json_path.write_text(json.dumps(spawn_plan), encoding="utf-8")
        spawn_plan_path.write_text(preflight_work_package.render_agent_spawn_plan(spawn_plan), encoding="utf-8")
        assert not consistency.dispatch_archived_agent_spawn_plan_matches_agent_claims(artifact)
        spawn_plan = build_spawn_plan(claims)
        spawn_plan_json_path.write_text(json.dumps(spawn_plan), encoding="utf-8")
        spawn_plan_path.write_text(preflight_work_package.render_agent_spawn_plan(spawn_plan), encoding="utf-8")
        env_bundle_copy_prompt = spawn_plan["env_bundle_ready_batches"][0]["claims"][0]["copy_paste_prompt"]
        spawn_plan["env_bundle_ready_batches"][0]["claims"][0]["copy_paste_prompt"] = env_bundle_copy_prompt.replace(
            "Working directory: .",
            "Working directory: wrong-cwd",
        )
        spawn_plan_json_path.write_text(json.dumps(spawn_plan), encoding="utf-8")
        spawn_plan_path.write_text(preflight_work_package.render_agent_spawn_plan(spawn_plan), encoding="utf-8")
        assert not consistency.dispatch_archived_agent_spawn_plan_matches_agent_claims(artifact)
        spawn_plan = build_spawn_plan(claims)
        spawn_plan_json_path.write_text(json.dumps(spawn_plan), encoding="utf-8")
        spawn_plan_path.write_text(preflight_work_package.render_agent_spawn_plan(spawn_plan), encoding="utf-8")
        spawn_launcher_path.write_text(
            preflight_work_package.render_agent_spawn_launcher(spawn_plan_json_path).replace(
                "if ($Phase -in @('env-bundle','all')) { Add-SpawnRows @($Plan.env_bundle_ready_batches) 'env-bundle' }",
                "if ($Phase -in @('env-bundle','all')) { Add-SpawnRows @($Plan.batches) 'env-bundle' }",
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_agent_spawn_launcher_matches_spawn_plan(artifact)
        spawn_launcher_path.write_text(
            preflight_work_package.render_agent_spawn_launcher(spawn_plan_json_path),
            encoding="utf-8",
        )
        claim_report = preflight_work_package.build_claim_status_report_json(claims, archive_root / "claim_locks")
        claim_report_json_path.write_text(json.dumps(claim_report), encoding="utf-8")
        claim_report_path.write_text(preflight_work_package.render_claim_status_report(claim_report), encoding="utf-8")
        claim_report["claims"][0]["claim_state"] = "ready_to_claim"
        claim_report_json_path.write_text(json.dumps(claim_report), encoding="utf-8")
        assert not consistency.dispatch_archived_claim_status_report_matches_agent_claims(artifact)
        claim_report = preflight_work_package.build_claim_status_report_json(claims, archive_root / "claim_locks")
        claim_report_json_path.write_text(json.dumps(claim_report), encoding="utf-8")
        claim_report_path.write_text(preflight_work_package.render_claim_status_report(claim_report), encoding="utf-8")
        claim_report["claims"][0]["locked_at"] = ""
        claim_report_json_path.write_text(json.dumps(claim_report), encoding="utf-8")
        assert not consistency.dispatch_archived_claim_status_report_matches_agent_claims(artifact)
        claim_report = preflight_work_package.build_claim_status_report_json(claims, archive_root / "claim_locks")
        claim_report_json_path.write_text(json.dumps(claim_report), encoding="utf-8")
        claim_report_path.write_text(
            preflight_work_package.render_claim_status_report(claim_report).replace("- Invalid locks: `0`\n", ""),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_claim_status_report_matches_agent_claims(artifact)
        claim_report_path.write_text(preflight_work_package.render_claim_status_report(claim_report), encoding="utf-8")
        ready_launcher_path.write_text(preflight_work_package.render_ready_claims_launcher(claims), encoding="utf-8")
        ready_parallel_launcher_path.write_text(
            preflight_work_package.render_ready_claims_parallel_launcher(claims),
            encoding="utf-8",
        )
        env_bundle_launcher_path.write_text(
            preflight_work_package.render_env_bundle_ready_claims_launcher(claims),
            encoding="utf-8",
        )
        ready_launcher_path.write_text(
            ready_launcher_path.read_text(encoding="utf-8") + "\n# Claim: claim-wave-1-caldera\n",
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_ready_claims_launcher_matches_agent_claims(artifact)
        ready_launcher_path.write_text(preflight_work_package.render_ready_claims_launcher(claims), encoding="utf-8")
        ready_launcher_path.write_text(
            ready_launcher_path.read_text(encoding="utf-8")
            + "\nInvoke-ReadyClaim 'claim-wave-1-caldera' 'wave-1-caldera' 'blocked.ps1'\n",
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_ready_claims_launcher_matches_agent_claims(artifact)
        ready_launcher_path.write_text(preflight_work_package.render_ready_claims_launcher(claims), encoding="utf-8")
        ready_launcher_path.write_text(
            ready_launcher_path.read_text(encoding="utf-8").replace(
                "  $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId\n",
                "",
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_ready_claims_launcher_matches_agent_claims(artifact)
        ready_launcher_path.write_text(preflight_work_package.render_ready_claims_launcher(claims), encoding="utf-8")
        ready_parallel_launcher_path.write_text(
            ready_parallel_launcher_path.read_text(encoding="utf-8") + "\n# Claim: claim-wave-1-caldera\n",
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(artifact)
        ready_parallel_launcher_path.write_text(
            preflight_work_package.render_ready_claims_parallel_launcher(claims),
            encoding="utf-8",
        )
        ready_parallel_launcher_path.write_text(
            ready_parallel_launcher_path.read_text(encoding="utf-8")
            + "\n$ReadyClaimJobs += Start-ReadyClaimJob 'claim-wave-1-caldera' 'wave-1-caldera' 'blocked.ps1'\n",
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(artifact)
        ready_parallel_launcher_path.write_text(
            preflight_work_package.render_ready_claims_parallel_launcher(claims),
            encoding="utf-8",
        )
        ready_parallel_launcher_path.write_text(
            ready_parallel_launcher_path.read_text(encoding="utf-8").replace(
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerClaimLockHelperPath -ClaimId $InnerClaimId -AgentId $InnerAgentId",
                "Write-Host 'lock omitted'",
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(artifact)
        ready_parallel_launcher_path.write_text(
            preflight_work_package.render_ready_claims_parallel_launcher(claims),
            encoding="utf-8",
        )
        ready_parallel_launcher_path.write_text(
            ready_parallel_launcher_path.read_text(encoding="utf-8").replace(
                "    $env:TAMANDUA_AGENT_ID = $InnerAgentId\n",
                "",
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_ready_claims_parallel_launcher_matches_agent_claims(artifact)
        ready_parallel_launcher_path.write_text(
            preflight_work_package.render_ready_claims_parallel_launcher(claims),
            encoding="utf-8",
        )
        env_bundle_launcher_path.write_text(
            env_bundle_launcher_path.read_text(encoding="utf-8")
            + "\n$EnvBundleClaimJobs += Start-EnvBundleClaimJob 'claim-wave-1-caldera' 'wave-1-caldera' 'blocked.ps1'\n",
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(artifact)
        env_bundle_launcher_path.write_text(
            preflight_work_package.render_env_bundle_ready_claims_launcher(claims),
            encoding="utf-8",
        )
        env_bundle_launcher_path.write_text(
            env_bundle_launcher_path.read_text(encoding="utf-8").replace("env_unblock_queue.json", "env_queue.json"),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(artifact)
        env_bundle_launcher_path.write_text(
            preflight_work_package.render_env_bundle_ready_claims_launcher(claims),
            encoding="utf-8",
        )
        env_bundle_launcher_path.write_text(
            env_bundle_launcher_path.read_text(encoding="utf-8").replace(
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InnerClaimLockHelperPath -ClaimId $InnerClaimId -AgentId $InnerAgentId",
                "Write-Host 'lock omitted'",
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(artifact)
        env_bundle_launcher_path.write_text(
            preflight_work_package.render_env_bundle_ready_claims_launcher(claims),
            encoding="utf-8",
        )
        env_bundle_launcher_path.write_text(
            env_bundle_launcher_path.read_text(encoding="utf-8").replace(
                "    $env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId\n",
                "",
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_env_bundle_ready_claims_launcher_matches_agent_claims(artifact)
        env_bundle_launcher_path.write_text(
            preflight_work_package.render_env_bundle_ready_claims_launcher(claims),
            encoding="utf-8",
        )
        brief_path.write_text(
            brief_path.read_text(encoding="utf-8").replace(
                "env_bundle_ready_claims_launcher.ps1",
                "wrong_env_bundle_launcher.ps1",
            ),
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_brief_recommended_launch_sequence_matches_manifest(artifact)
        brief_path.write_text(
            brief_path.read_text(encoding="utf-8").replace(
                "wrong_env_bundle_launcher.ps1",
                "env_bundle_ready_claims_launcher.ps1",
            ),
            encoding="utf-8",
        )
        matrix["rows"][0]["current_status"] = "pass"
        matrix_json_path.write_text(json.dumps(matrix), encoding="utf-8")
        assert not consistency.dispatch_archived_execution_matrix_matches_owner_plan(artifact)
        matrix = preflight_work_package.build_execution_matrix_json(json.loads(plan_json_path.read_text(encoding="utf-8")))
        matrix_json_path.write_text(json.dumps(matrix), encoding="utf-8")
        plan = json.loads(plan_json_path.read_text(encoding="utf-8"))
        plan["owners"][0]["packages"][0]["command"] = "powershell -File wrong.ps1"
        plan_json_path.write_text(json.dumps(plan), encoding="utf-8")
        assert not consistency.dispatch_archived_owner_launch_plan_json_matches_manifest(artifact)
        plan["owners"][0]["packages"][0]["command"] = f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_ref}'"
        plan["owners"][0]["packages"][0]["current_status"] = "pass"
        plan_json_path.write_text(json.dumps(plan), encoding="utf-8")
        assert not consistency.dispatch_archived_owner_launch_plan_json_matches_manifest(artifact)
    finally:
        consistency.ROOT = old_root


def test_preflight_ready_claim_parallel_batches_avoid_resource_overlap():
    claims_payload = {
        "claims": [
            {
                "claim_id": "claim-a",
                "package_id": "pkg-a",
                "claim_state": "ready_to_claim",
                "wave": 1,
                "stage": 1,
                "resource_tags": ["windows-lab"],
                "script_path": "pkg-a.ps1",
            },
            {
                "claim_id": "claim-b",
                "package_id": "pkg-b",
                "claim_state": "ready_to_claim",
                "wave": 1,
                "stage": 2,
                "resource_tags": ["windows-lab"],
                "script_path": "pkg-b.ps1",
            },
            {
                "claim_id": "claim-c",
                "package_id": "pkg-c",
                "claim_state": "ready_to_claim",
                "wave": 1,
                "stage": 3,
                "resource_tags": ["macos-lab"],
                "script_path": "pkg-c.ps1",
            },
            {
                "claim_id": "claim-blocked",
                "package_id": "pkg-blocked",
                "claim_state": "blocked_missing_env",
                "wave": 1,
                "stage": 1,
                "resource_tags": ["windows-lab"],
                "script_path": "blocked.ps1",
            },
        ]
    }

    batches = preflight_work_package.ready_claim_parallel_batches(claims_payload)
    launcher = preflight_work_package.render_ready_claims_parallel_launcher(claims_payload)

    assert [[claim["claim_id"] for claim in batch] for _, _, batch in batches] == [
        ["claim-a", "claim-c"],
        ["claim-b"],
    ]
    assert "# Validation Ready Claims Parallel Launcher" in launcher
    assert "Start-Job" in launcher
    assert "Invoke-ClaimStatusRefresh" in launcher
    assert "--refresh-claim-status-report" in launcher
    assert "# Resources: windows-lab" in launcher
    assert "# Claim: claim-blocked" not in launcher


def test_agent_spawn_and_parallel_launchers_surface_current_next_action(tmp_path):
    prompt_path = tmp_path / "macos.agent.md"
    prompt_path.write_text("Run macOS readiness.", encoding="utf-8")
    login_command = "tamandua-ctl remote login --server http://192.168.12.146:4000 --no-browser"
    token_login_command = (
        "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN"
    )
    next_action = {
        "missing_readiness": ["tamandua_ctl_auth"],
        "login_command": login_command,
        "token_env": "TAMANDUA_TOKEN",
        "token_login_command": token_login_command,
    }
    claims_payload = {
        "artifact": "validation-agent-claims",
        "claims": [
            {
                "claim_id": "claim-wave-1-macos",
                "package_id": "wave-1-macos",
                "owner": "validation-agent",
                "claim_state": "ready_to_claim",
                "wave": 1,
                "stage": 1,
                "resource_tags": ["macos-agent"],
                "prompt_path": str(prompt_path),
                "script_path": "wave-1-macos.ps1",
                "status_path": "agent_status.json",
                "command": "powershell -NoProfile -ExecutionPolicy Bypass -File 'wave-1-macos.ps1'",
                "current_next_action": next_action,
            },
            {
                "claim_id": "claim-wave-1-blocked",
                "package_id": "wave-1-blocked",
                "owner": "operator",
                "claim_state": "blocked_missing_env",
                "wave": 1,
                "stage": 1,
                "missing_effective_env": ["TAMANDUA_TOKEN"],
                "blocked_reasons": ["missing_effective_env"],
                "prompt_path": str(prompt_path),
                "current_next_action": next_action,
            },
        ],
    }

    plan = preflight_work_package.build_agent_spawn_plan_json(claims_payload, tmp_path)
    markdown = preflight_work_package.render_agent_spawn_plan(plan)
    launcher = preflight_work_package.render_agent_spawn_launcher(tmp_path / "agent_spawn_plan.json")
    parallel_launcher = preflight_work_package.render_ready_claims_parallel_launcher(claims_payload)
    env_queue = preflight_work_package.build_env_unblock_queue_json(claims_payload)
    env_queue_markdown = preflight_work_package.render_env_unblock_queue(env_queue)

    spawn_claim = plan["batches"][0]["claims"][0]
    blocked_claim = plan["blocked_or_manual_claims"][0]
    assert spawn_claim["current_next_action"] == next_action
    assert blocked_claim["current_next_action"] == next_action
    assert (
        "| Claim | Owner | Package | Resources | Next action | Prompt | Codex template | Claude template | Lock command | Run command | Status |"
        in markdown
    )
    assert "| Claim | Owner | Package | State | Missing env | Blockers | Depends | Next action | Prompt |" in markdown
    assert token_login_command in markdown
    assert "Format-NextAction" in launcher
    assert "next_action=" in launcher
    assert "token_login_command" in launcher
    assert (
        f"# Next action: missing=tamandua_ctl_auth; login_command={login_command}; token_login_command={token_login_command}"
        in parallel_launcher
    )
    assert env_queue["next_action_env_count"] == 1
    assert env_queue["next_action_entries"][0]["env"] == "TAMANDUA_TOKEN"
    assert env_queue["next_action_entries"][0]["claim_ids"] == [
        "claim-wave-1-blocked",
        "claim-wave-1-macos",
    ]
    assert env_queue["next_action_entries"][0]["token_login_commands"] == [token_login_command]
    assert "$env:TAMANDUA_TOKEN = '<set-tamandua-token-secret>'" in env_queue["next_action_env_powershell_set_commands"]
    assert "## Copy/Paste Next-Action Env Commands" in env_queue_markdown
    assert "## Next-Action Env Follow-Ups" in env_queue_markdown
    assert token_login_command in env_queue_markdown


def test_owner_launch_plan_blocks_current_macos_token_next_action(tmp_path, monkeypatch):
    monkeypatch.delenv("TAMANDUA_TOKEN", raising=False)
    script_path = tmp_path / "wave-1-macos.ps1"
    prompt_path = tmp_path / "wave-1-macos.agent.md"
    artifact_path = tmp_path / "20260604T000000Z-macos-backend-readiness-probe.json"
    script_path.write_text("Write-Host macos", encoding="utf-8")
    prompt_path.write_text("Run macOS readiness.", encoding="utf-8")
    status_path = preflight_work_package.package_status_path_for_script(script_path)
    status_path.parent.mkdir(parents=True)
    token_login_command = (
        "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN"
    )
    artifact_path.write_text(
        json.dumps(
            {
                "profile_id": "macos-backend-readiness-probe",
                "quality_gate": {
                    "status": "fail",
                    "passed": False,
                    "actionable_gaps": [
                        {
                            "test_id": "macos-backend-agent-row-present",
                            "missing": ["tamandua_ctl_auth"],
                            "evidence": {
                                "next_action": {
                                    "missing_readiness": ["tamandua_ctl_auth"],
                                    "required_env": [],
                                    "token_env": "TAMANDUA_TOKEN",
                                    "token_login_command": token_login_command,
                                }
                            },
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    status_path.write_text(
        json.dumps(
            {
                "package_id": "wave-1-macos",
                "status": "fail",
                "exit_code": 1,
                "artifacts": [str(artifact_path)],
                "missing_profiles": [],
                "notes": [],
            }
        ),
        encoding="utf-8",
    )
    package = {
        "package_id": "wave-1-macos",
        "title": "Restore macOS readiness",
        "wave": 1,
        "parallelizable_in_wave": True,
        "recommended_owner_role": "validation-agent",
        "resource_tags": ["macos-agent"],
        "required_env": [],
        "roadmaps": ["E"],
        "expected_profile_ids": ["macos-backend-readiness-probe"],
    }

    plan = preflight_work_package.build_owner_launch_plan_json(
        [package],
        {"wave-1-macos": script_path},
        {"wave-1-macos": prompt_path},
    )
    owner = plan["owners"][0]
    entry = owner["packages"][0]

    assert owner["missing_effective_env"] == ["TAMANDUA_TOKEN"]
    assert entry["next_action_required_env"] == ["TAMANDUA_TOKEN"]
    assert entry["current_next_action_required_env"] == ["TAMANDUA_TOKEN"]
    assert entry["effective_required_env"] == ["TAMANDUA_TOKEN"]
    assert entry["missing_effective_env"] == ["TAMANDUA_TOKEN"]
    assert entry["ready_to_launch"] is False
    assert "missing_effective_env" in entry["blocked_reasons"]
    assert "env-blocked:TAMANDUA_TOKEN" in entry["handoff_notes"]
    assert entry["current_next_action"]["token_login_command"] == token_login_command

    owner_plan_path = tmp_path / "owner_launch_plan.json"
    owner_plan_path.write_text(json.dumps(plan), encoding="utf-8")
    manifest = preflight_work_package.build_dispatch_manifest(
        [package],
        tmp_path / "20260604T000000Z-validation-execution-preflight-probe.json",
        tmp_path,
        {"wave-1-macos": script_path},
        {"wave-1-macos": prompt_path},
        owner_launch_plan_json_path=owner_plan_path,
    )
    manifest_package = manifest["packages"][0]
    assert manifest_package["next_action_required_env"] == ["TAMANDUA_TOKEN"]
    assert manifest_package["current_next_action_required_env"] == ["TAMANDUA_TOKEN"]
    assert manifest_package["effective_required_env"] == ["TAMANDUA_TOKEN"]
    assert "env-blocked:TAMANDUA_TOKEN" in manifest_package["handoff_notes"]

    prompt = preflight_work_package.render_agent_prompt(
        package,
        script_path,
        tmp_path / "20260604T000000Z-validation-execution-preflight-probe.json",
    )
    assert "Next-action env: TAMANDUA_TOKEN" in prompt
    assert "Effective env checklist: TAMANDUA_TOKEN" in prompt
    assert token_login_command in prompt


def test_current_next_action_infers_macos_token_handoff_from_auth_error(tmp_path):
    artifact_path = tmp_path / "macos-auth-old-shape.json"
    artifact_path.write_text(
        json.dumps(
            {
                "profile_id": "macos-backend-readiness-probe",
                "quality_gate": {"passed": False},
                "evidence": {
                    "inventory": {
                        "command": "tamandua-ctl remote agents list --json --server http://192.168.12.146:4000",
                        "exit_code": 1,
                        "stderr": '[ERROR] failed to list agents: HTTP 401 Unauthorized {"error":"Invalid or expired token"}',
                        "stdout": "",
                    },
                    "next_action": {
                        "action": "Enroll or reconnect a macOS lab agent.",
                        "missing_readiness": ["macos_agent_row"],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    action = preflight_work_package.current_next_action_from_artifacts([str(artifact_path)])

    assert action["missing_readiness"] == ["tamandua_ctl_auth"]
    assert action["token_env"] == "TAMANDUA_TOKEN"
    assert action["login_command"] == "tamandua-ctl remote login --server http://192.168.12.146:4000 --no-browser"
    assert (
        action["token_login_command"]
        == "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN"
    )


def test_preflight_claim_lock_helper_creates_atomic_claim_lock(tmp_path):
    claims_payload = {
        "claims": [
            {
                "claim_id": "claim-ready",
                "package_id": "pkg-ready",
                "claim_state": "ready_to_claim",
            }
        ]
    }
    helper_path = tmp_path / "claim_lock_helper.ps1"
    helper_path.write_text(preflight_work_package.render_claim_lock_helper(claims_payload), encoding="utf-8")
    repo_root = Path(__file__).resolve().parents[2]

    first = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper_path),
            "-ClaimId",
            "claim-ready",
            "-AgentId",
            "agent-a",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    second = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper_path),
            "-ClaimId",
            "claim-ready",
            "-AgentId",
            "agent-b",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    unknown = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper_path),
            "-ClaimId",
            "claim-missing",
            "-AgentId",
            "agent-c",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    list_locks = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper_path),
            "-List",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    reset_without_force = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper_path),
            "-ResetClaimId",
            "claim-ready",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    reset = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper_path),
            "-ResetClaimId",
            "claim-ready",
            "-Force",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    reacquire = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper_path),
            "-ClaimId",
            "claim-ready",
            "-AgentId",
            "agent-d",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )

    lock_path = tmp_path / "claim_locks" / "claim-ready.claim-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert first.returncode == 0
    assert second.returncode == 3
    assert unknown.returncode == 2
    assert list_locks.returncode == 0
    assert '"claim_id"' in list_locks.stdout
    assert '"claim-ready"' in list_locks.stdout
    assert reset_without_force.returncode == 4
    assert reset.returncode == 0
    assert reacquire.returncode == 0
    assert lock["claim_id"] == "claim-ready"
    assert lock["agent_id"] == "agent-d"


def test_preflight_env_bundle_launcher_validate_only_checks_env_without_launch_guard(tmp_path):
    claims_payload = {
        "claims": [
            {
                "claim_id": "claim-env",
                "package_id": "pkg-env",
                "claim_state": "blocked_or_manual",
                "wave": 1,
                "resource_tags": ["operator-env"],
                "script_path": "pkg-env.ps1",
                "missing_effective_env": ["TAMANDUA_TEST_ENV_BUNDLE_VALUE"],
                "blocked_reasons": ["missing_effective_env"],
            }
        ]
    }
    launcher_path = tmp_path / "env_bundle_ready_claims_launcher.ps1"
    launcher_path.write_text(preflight_work_package.render_env_bundle_ready_claims_launcher(claims_payload), encoding="utf-8")
    (tmp_path / "claim_lock_helper.ps1").write_text("# placeholder for validate-only path guard\n", encoding="utf-8")
    (tmp_path / "env_unblock_queue.json").write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "env": "TAMANDUA_TEST_ENV_BUNDLE_VALUE",
                        "placeholder": "<set-tamandua-test-env-bundle-value>",
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    repo_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.pop("TAMANDUA_TEST_ENV_BUNDLE_VALUE", None)
    env.pop("TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH", None)

    missing = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(launcher_path),
            "-ValidateOnly",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
    )
    env["TAMANDUA_TEST_ENV_BUNDLE_VALUE"] = "real-value"
    valid = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(launcher_path),
            "-ValidateOnly",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
    )

    assert missing.returncode != 0
    assert "Missing env bundle values: TAMANDUA_TEST_ENV_BUNDLE_VALUE" in (missing.stdout + missing.stderr)
    assert valid.returncode == 0
    assert "Env bundle validation passed. Ready claims: claim-env" in valid.stdout


def test_preflight_ready_parallel_launcher_validate_only_does_not_require_launch_guard(tmp_path):
    claims_payload = {
        "claims": [
            {
                "claim_id": "claim-ready",
                "package_id": "pkg-ready",
                "claim_state": "ready_to_claim",
                "wave": 1,
                "stage": 1,
                "resource_tags": ["windows-lab"],
                "script_path": "pkg-ready.ps1",
                "current_next_action": {},
            }
        ]
    }
    launcher_path = tmp_path / "ready_claims_parallel_launcher.ps1"
    launcher_path.write_text(preflight_work_package.render_ready_claims_parallel_launcher(claims_payload), encoding="utf-8")
    repo_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.pop("TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH", None)

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(launcher_path),
            "-ValidateOnly",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert "Ready claims validation passed. Ready claims: claim-ready" in result.stdout


def test_preflight_ready_launcher_validate_only_does_not_require_launch_guard(tmp_path):
    claims_payload = {
        "claims": [
            {
                "claim_id": "claim-ready",
                "package_id": "pkg-ready",
                "claim_state": "ready_to_claim",
                "wave": 1,
                "stage": 1,
                "script_path": "pkg-ready.ps1",
            }
        ]
    }
    launcher_path = tmp_path / "ready_claims_launcher.ps1"
    launcher_path.write_text(preflight_work_package.render_ready_claims_launcher(claims_payload), encoding="utf-8")
    repo_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.pop("TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH", None)

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(launcher_path),
            "-ValidateOnly",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert "Ready claims validation passed. Ready claims: claim-ready" in result.stdout


def test_preflight_claim_status_report_includes_claim_locks(tmp_path):
    lock_dir = tmp_path / "claim_locks"
    lock_dir.mkdir()
    status_path = tmp_path / "pkg-ready" / "agent_status.json"
    status_path.parent.mkdir()
    status_path.write_text(
        json.dumps(
            {
                "package_id": "pkg-ready",
                "claim_id": "claim-ready",
                "agent_id": "agent-status-a",
                "status": "pass",
                "artifacts": [],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 0,
                "expected_profiles": [],
                "missing_profiles": [],
            }
        ),
        encoding="utf-8",
    )
    (lock_dir / "claim-ready.claim-lock.json").write_text(
        json.dumps(
            {
                "claim_id": "claim-ready",
                "agent_id": "agent-a",
                "locked_at": "2026-06-04T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    claims_payload = {
        "claims": [
            {
                "claim_id": "claim-ready",
                "package_id": "pkg-ready",
                "claim_state": "ready_to_claim",
                "wave": 1,
                "stage": 1,
                "status_path": str(status_path),
            },
            {
                "claim_id": "claim-blocked",
                "package_id": "pkg-blocked",
                "claim_state": "blocked_missing_env",
                "wave": 1,
                "stage": 2,
            },
        ]
    }

    report = preflight_work_package.build_claim_status_report_json(claims_payload, lock_dir)
    markdown = preflight_work_package.render_claim_status_report(report)
    by_id = {claim["claim_id"]: claim for claim in report["claims"]}

    assert report["locked_claim_count"] == 1
    assert report["invalid_lock_count"] == 0
    assert by_id["claim-ready"]["lock_state"] == "locked"
    assert by_id["claim-ready"]["lock_agent_id"] == "agent-a"
    assert by_id["claim-ready"]["locked_at"] == "2026-06-04T09:00:00Z"
    assert by_id["claim-ready"]["agent_status"] == "pass"
    assert by_id["claim-ready"]["agent_claim_id"] == "claim-ready"
    assert by_id["claim-ready"]["agent_id"] == "agent-status-a"
    assert by_id["claim-blocked"]["lock_state"] == "unlocked"
    assert by_id["claim-blocked"]["lock_path"].endswith("claim-blocked.claim-lock.json")
    assert "Locked claims: `1`" in markdown
    assert "| Claim | Wave | Stage | Owner | Package | State | Agent status | Agent claim | Agent id | Lock | Lock agent | Locked at | Exit | Missing env | Missing profiles | Artifacts | Next action | Command |" in markdown


def test_preflight_work_package_refreshes_claim_status_report_from_manifest(tmp_path):
    claims_path = tmp_path / "agent_claims.json"
    manifest_path = tmp_path / "dispatch_manifest.json"
    lock_dir = tmp_path / "claim_locks"
    lock_dir.mkdir()
    claims_path.write_text(
        json.dumps(
            {
                "artifact": "validation-agent-claims",
                "claims": [
                    {
                        "claim_id": "claim-ready",
                        "package_id": "pkg-ready",
                        "claim_state": "ready_to_claim",
                        "wave": 1,
                        "stage": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (lock_dir / "claim-ready.claim-lock.json").write_text(
        json.dumps(
            {
                "claim_id": "claim-ready",
                "agent_id": "agent-refresh",
                "locked_at": "2026-06-04T10:10:00Z",
            }
        ),
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps(
            {
                "output_dir": str(tmp_path),
                "agent_claims_json_path": str(claims_path),
                "claim_status_report_path": str(tmp_path / "claim_status_report.md"),
                "claim_status_report_json_path": str(tmp_path / "claim_status_report.json"),
            }
        ),
        encoding="utf-8",
    )

    exit_code = preflight_work_package.main(
        [
            "--refresh-claim-status-report",
            str(manifest_path),
        ]
    )
    report = json.loads((tmp_path / "claim_status_report.json").read_text(encoding="utf-8"))
    markdown = (tmp_path / "claim_status_report.md").read_text(encoding="utf-8")

    assert exit_code == 0
    assert report["locked_claim_count"] == 1
    assert report["claims"][0]["lock_state"] == "locked"
    assert report["claims"][0]["lock_agent_id"] == "agent-refresh"
    assert "Locked claims: `1`" in markdown


def test_status_consistency_validates_dispatch_launcher_membership(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    archive_root = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts"
    handoff_root = archive_root / "handoffs"
    launcher_dir = archive_root / "launchers"
    (handoff_root / "selected").mkdir(parents=True)
    (handoff_root / "manual").mkdir(parents=True)
    launcher_dir.mkdir(parents=True)
    selected_script = (
        f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/selected/selected.ps1"
    )
    selected_two_script = (
        f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/selected/selected-two.ps1"
    )
    manual_script = f"docs/benchmarks/runs/{run_id}.package-artifacts/handoffs/manual/manual.ps1"
    (handoff_root / "selected" / "selected.ps1").write_text("Write-Output selected\n", encoding="utf-8")
    (handoff_root / "selected" / "selected-two.ps1").write_text("Write-Output selected two\n", encoding="utf-8")
    (handoff_root / "manual" / "manual.ps1").write_text("Write-Output manual\n", encoding="utf-8")
    launcher_path = launcher_dir / "wave-1-parallel-launcher.ps1"
    staged_launcher_path = launcher_dir / "wave-1-staged-launcher.ps1"
    good_launcher = (
        "# Wave: 1\n"
        "$WaveLauncherAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_WAVE_LAUNCHER_AGENT_ID')\n"
        "$ClaimLockHelperPath = Join-Path $WaveLauncherDir 'claim_lock_helper.ps1'\n"
        "Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)\n"
        "# Package: selected resources=windows-lab\n"
        f"$jobs += Start-Job -Name 'selected' -ArgumentList '{selected_script}', 'claim-selected', $script:ClaimLockHelperPath, $WaveLauncherAgentId -ScriptBlock {{\n"
        "  param([string]$ScriptPath, [string]$ClaimId, [string]$ClaimLockHelperPath, [string]$AgentId)\n"
        "  $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId\n"
        "  $env:TAMANDUA_AGENT_ID = $AgentId\n"
        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId\n"
        "  $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'\n"
        "  powershell.exe -File $ScriptPath\n"
        "}\n"
        "# Package: selected-two resources=macos-agent\n"
        f"$jobs += Start-Job -Name 'selected-two' -ArgumentList '{selected_two_script}', 'claim-selected-two', $script:ClaimLockHelperPath, $WaveLauncherAgentId -ScriptBlock {{\n"
        "  param([string]$ScriptPath, [string]$ClaimId, [string]$ClaimLockHelperPath, [string]$AgentId)\n"
        "  $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId\n"
        "  $env:TAMANDUA_AGENT_ID = $AgentId\n"
        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId\n"
        "  $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'\n"
        "  powershell.exe -File $ScriptPath\n"
        "}\n"
        "# Skipped due to resource overlap:\n"
        "# - manual: resource overlap: windows-lab\n"
    )
    launcher_path.write_text(good_launcher, encoding="utf-8")
    good_staged_launcher = (
        "# Generated staged launcher for validation preflight work packages.\n"
        "# Wave: 1\n"
        "$StagedLauncherAgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_STAGED_LAUNCHER_AGENT_ID')\n"
        "$ClaimLockHelperPath = Join-Path $StagedLauncherDir 'claim_lock_helper.ps1'\n"
        "Write-Error ('Missing claim lock helper: ' + $ClaimLockHelperPath)\n"
        "$StageFailures = @()\n"
        "# Stage 1\n"
        "$jobs = @()\n"
        "# Package: selected resources=windows-lab\n"
        f"$jobs += Start-Job -Name 'selected' -ArgumentList '{selected_script}', 'claim-selected', $script:ClaimLockHelperPath, $StagedLauncherAgentId -ScriptBlock {{\n"
        "  param([string]$ScriptPath, [string]$ClaimId, [string]$ClaimLockHelperPath, [string]$AgentId)\n"
        "  $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId\n"
        "  $env:TAMANDUA_AGENT_ID = $AgentId\n"
        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId\n"
        "  $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'\n"
        "  powershell.exe -File $ScriptPath\n"
        "}\n"
        "# Stage 2\n"
        "$jobs = @()\n"
        "# Package: selected-two resources=macos-agent\n"
        f"$jobs += Start-Job -Name 'selected-two' -ArgumentList '{selected_two_script}', 'claim-selected-two', $script:ClaimLockHelperPath, $StagedLauncherAgentId -ScriptBlock {{\n"
        "  param([string]$ScriptPath, [string]$ClaimId, [string]$ClaimLockHelperPath, [string]$AgentId)\n"
        "  $env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId\n"
        "  $env:TAMANDUA_AGENT_ID = $AgentId\n"
        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId\n"
        "  $env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'\n"
        "  powershell.exe -File $ScriptPath\n"
        "}\n"
        "Write-Error ('Failed package jobs across staged wave: ' + ($StageFailures -join '; '))\n"
    )
    staged_launcher_path.write_text(good_staged_launcher, encoding="utf-8")
    manifest = {
        "launcher_paths": [
            f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-1-parallel-launcher.ps1"
        ],
        "staged_launcher_paths": [
            f"docs/benchmarks/runs/{run_id}.package-artifacts/launchers/wave-1-staged-launcher.ps1"
        ],
        "packages": [
            {
                "package_id": "selected",
                "wave": 1,
                "parallelizable_in_wave": True,
                "launcher_selected": True,
                "staged_launcher_selected": True,
                "staged_stage": 1,
                "manual_reason": None,
                "impact_score": 90,
                "resource_tags": ["windows-lab"],
                "script_path": selected_script,
            },
                {
                    "package_id": "selected-two",
                    "wave": 1,
                    "parallelizable_in_wave": True,
                    "launcher_selected": True,
                    "staged_launcher_selected": True,
                    "staged_stage": 2,
                    "manual_reason": None,
                    "impact_score": 80,
                    "resource_tags": ["macos-agent"],
                    "script_path": selected_two_script,
                },
            {
                "package_id": "manual",
                "wave": 1,
                "parallelizable_in_wave": True,
                "launcher_selected": False,
                "staged_launcher_selected": False,
                "staged_stage": None,
                "manual_reason": "resource overlap: windows-lab",
                "impact_score": 10,
                "resource_tags": ["windows-lab"],
                "script_path": manual_script,
            },
        ],
    }
    (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact = {
        "dispatch_manifest": f"docs/benchmarks/runs/{run_id}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_launcher_membership_matches_manifest(artifact)
        assert consistency.dispatch_archived_staged_launcher_stage_membership_matches_manifest(artifact)
        assert consistency.dispatch_archived_manifest_launcher_decisions_are_replayable(artifact)
        assert consistency.dispatch_archived_launcher_manual_reasons_match_manifest(artifact)
        assert consistency.dispatch_archived_launcher_selected_metadata_matches_manifest(artifact)
        staged_launcher_path.write_text(good_staged_launcher.replace("# Stage 2", "# Stage 1"), encoding="utf-8")
        assert not consistency.dispatch_archived_staged_launcher_stage_membership_matches_manifest(artifact)
        staged_launcher_path.write_text(good_staged_launcher + "# Package: selected resources=windows-lab\n", encoding="utf-8")
        assert not consistency.dispatch_archived_staged_launcher_stage_membership_matches_manifest(artifact)
        staged_launcher_path.write_text(good_staged_launcher, encoding="utf-8")
        launcher_path.write_text(good_launcher.replace("resources=windows-lab", "resources=macos-agent"), encoding="utf-8")
        assert not consistency.dispatch_archived_launcher_selected_metadata_matches_manifest(artifact)
        launcher_path.write_text(good_launcher.replace("Start-Job -Name 'selected'", "Start-Job -Name 'other'"), encoding="utf-8")
        assert not consistency.dispatch_archived_launcher_selected_metadata_matches_manifest(artifact)
        launcher_path.write_text(good_launcher, encoding="utf-8")
        launcher_path.write_text(f"powershell.exe -File '{selected_script}'\n", encoding="utf-8")
        assert not consistency.dispatch_archived_launcher_manual_reasons_match_manifest(artifact)
        launcher_path.write_text(
            f"powershell.exe -File '{selected_script}'\n# - manual: resource overlap: macos-agent\n",
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_launcher_manual_reasons_match_manifest(artifact)
        launcher_path.write_text(good_launcher, encoding="utf-8")
        launcher_path.write_text("Write-Output missing-selected\n", encoding="utf-8")
        assert not consistency.dispatch_archived_launcher_membership_matches_manifest(artifact)
        launcher_path.write_text(
            f"powershell.exe -File '{selected_script}'\npowershell.exe -File '{manual_script}'\n",
            encoding="utf-8",
        )
        assert not consistency.dispatch_archived_launcher_membership_matches_manifest(artifact)
        launcher_path.write_text(good_launcher, encoding="utf-8")
        manifest["packages"][2]["manual_reason"] = None
        (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        assert not consistency.dispatch_archived_launcher_membership_matches_manifest(artifact)
        assert not consistency.dispatch_archived_manifest_launcher_decisions_are_replayable(artifact)
        manifest["packages"][1]["manual_reason"] = "resource overlap: macos-agent"
        (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        assert not consistency.dispatch_archived_manifest_launcher_decisions_are_replayable(artifact)
        manifest["packages"][1]["manual_reason"] = "resource overlap: windows-lab"
        manifest["packages"][0]["impact_score"] = 1
        manifest["packages"][1]["impact_score"] = 90
        manifest["packages"][0]["launcher_selected"] = True
        manifest["packages"][1]["launcher_selected"] = False
        (archive_root / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        assert not consistency.dispatch_archived_manifest_launcher_decisions_are_replayable(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_validates_handoff_scripts_against_source_commands(tmp_path):
    dispatch_run = "20260603T182929Z-validation-dispatch-results-probe"
    preflight_run = "20260603T180000Z-validation-execution-preflight-probe"
    runs_dir = tmp_path / "docs" / "benchmarks" / "runs"
    handoff_dir = runs_dir / f"{dispatch_run}.package-artifacts" / "handoffs" / "wave-1-env"
    handoff_dir.mkdir(parents=True)
    preflight_path = runs_dir / f"{preflight_run}.json"
    preflight_path.write_text(
        json.dumps(
            {
                "parallel_work_packages": [
                    {
                        "package_id": "wave-1-env",
                        "safe_commands": [
                            "$Out = Join-Path $env:TEMP tamandua-preflight",
                            "python tools/detection_validation/validation_execution_preflight_probe.py --output-dir $Out",
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    script_path = handoff_dir / "wave-1-env.ps1"
    script_path.write_text(
        "$Out = 'docs/benchmarks/runs/package-output'\n"
        "python tools/detection_validation/validation_execution_preflight_probe.py --output-dir $Out\n",
        encoding="utf-8",
    )
    manifest_path = runs_dir / f"{dispatch_run}.package-artifacts" / "dispatch_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "package_id": "wave-1-env",
                        "script_path": (
                            f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/"
                            "handoffs/wave-1-env/wave-1-env.ps1"
                        ),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    artifact = {
        "source_preflight": f"docs/benchmarks/runs/{preflight_run}.json",
        "dispatch_manifest": f"docs/benchmarks/runs/{dispatch_run}.package-artifacts/dispatch_manifest.json",
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_archived_handoff_scripts_match_source_commands(artifact)
        script_path.write_text("Write-Output 'wrong command'\n", encoding="utf-8")
        assert not consistency.dispatch_archived_handoff_scripts_match_source_commands(artifact)
    finally:
        consistency.ROOT = old_root


def test_status_consistency_extracts_caldera_repeatability_reset_reasons():
    artifact = {
        "quality_gate": {
            "actionable_gaps": [
                {
                    "evidence": {
                        "profile_id": "windows-caldera-smoke",
                        "latest_streak_reset": {"reason": "quality_gate_failed"},
                        "recent_history": [{"run_id": "older"}],
                    }
                },
                {
                    "evidence": {
                        "profile_id": "windows-caldera-enterprise-safe",
                        "latest_streak_reset": {
                            "reason": "quality_gate_failed:caldera_agent_stale_or_offline"
                        },
                        "recent_history": [{"run_id": "latest"}],
                    }
                },
                {"evidence": {"profile_id": "ignored", "recent_history": []}},
            ]
        }
    }

    assert consistency.caldera_repeatability_reset_reasons(artifact) == {
        "windows-caldera-smoke": "quality_gate_failed",
        "windows-caldera-enterprise-safe": "quality_gate_failed:caldera_agent_stale_or_offline",
    }
    assert consistency.caldera_repeatability_recent_history_profiles(artifact) == [
        "windows-caldera-enterprise-safe",
        "windows-caldera-smoke",
    ]
    assert consistency.caldera_repeatability_next_actions(artifact) == {}


def test_status_consistency_validates_closure_next_actions():
    artifact = {
        "roadmap_next_actions": [
            {
                "roadmap": "A",
                "blocking_profiles": ["windows-lab-execution-readiness-probe"],
                "required_env": [],
                "action": "Restore Windows readiness.",
            },
            {
                "roadmap": "B",
                "blocking_profiles": ["fresh-restore-provenance-probe"],
                "required_env": consistency.EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS["B"],
                "action": "Run fresh restore batches.",
            },
            {
                "roadmap": "D",
                "blocking_profiles": ["caldera-api-shape-probe"],
                "required_env": consistency.EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS["D"],
                "action": "Restore CALDERA readiness.",
            },
            {
                "roadmap": "E",
                "blocking_profiles": ["macos-backend-readiness-probe"],
                "required_env": [],
                "action": "Reconnect macOS.",
            },
            {
                "roadmap": "M",
                "blocking_profiles": ["windows-atomic-extended-safe"],
                "required_env": [],
                "action": "Close Atomic extended.",
            },
        ]
    }

    summary = consistency.closure_next_action_summary(artifact)

    assert summary["D"] == {
        "blocking_profiles": ["caldera-api-shape-probe"],
        "required_env": ["CALDERA_AGENT_PAW", "CALDERA_API_KEY", "CALDERA_GROUP"],
        "has_action": True,
    }
    assert consistency.closure_next_actions_valid(artifact)


def test_status_consistency_rejects_closure_next_actions_missing_required_env():
    artifact = {
        "roadmap_next_actions": [
            {
                "roadmap": roadmap,
                "blocking_profiles": [f"roadmap-{roadmap.lower()}-profile"],
                "required_env": [],
                "action": f"Close roadmap {roadmap}.",
            }
            for roadmap in consistency.EXPECTED_CLOSURE_NEXT_ACTION_ROADMAPS
        ]
    }

    assert not consistency.closure_next_actions_valid(artifact)


def test_status_consistency_validates_preflight_roadmap_next_actions():
    artifact = {
        "roadmap_next_actions": [
            {
                "roadmap": "A",
                "blocking_profiles": ["windows-lab-execution-readiness-probe"],
                "required_env": ["TAMANDUA_SERVER_PASSWORD"],
                "action": "Restore Windows readiness.",
            },
            {
                "roadmap": "B",
                "blocking_profiles": ["fresh-restore-provenance-probe"],
                "required_env": consistency.EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS["B"],
                "action": "Run fresh restore batches.",
            },
            {
                "roadmap": "D",
                "blocking_profiles": ["caldera-api-shape-probe"],
                "required_env": consistency.EXPECTED_CLOSURE_NEXT_ACTION_REQUIRED_ENVS["D"],
                "action": "Restore CALDERA readiness.",
            },
            {
                "roadmap": "E",
                "blocking_profiles": ["macos-backend-readiness-probe"],
                "required_env": [],
                "action": "Reconnect macOS.",
            },
            {
                "roadmap": "M",
                "blocking_profiles": ["windows-atomic-extended-safe"],
                "required_env": [],
                "action": "Close Atomic extended.",
            },
        ]
    }

    assert consistency.preflight_roadmap_next_actions_valid(artifact)


def test_status_consistency_extracts_caldera_repeatability_next_actions():
    artifact = {
        "quality_gate": {
            "actionable_gaps": [
                {
                    "evidence": {
                        "profile_id": "windows-caldera-smoke",
                        "next_action": {
                            "passes_needed": 2,
                            "profile_file": "tools/detection_validation/profiles/windows_caldera_smoke.json",
                            "next_command_hint": "python tools/detection_validation/tamandua_detection_validation.py --profile tools/detection_validation/profiles/windows_caldera_smoke.json",
                            "required_env": ["CALDERA_API_KEY", "CALDERA_GROUP", "CALDERA_AGENT_PAW"],
                        },
                    }
                }
            ]
        }
    }

    assert consistency.caldera_repeatability_next_actions(artifact) == {
        "windows-caldera-smoke": {
            "passes_needed": 2,
            "profile_file": "tools/detection_validation/profiles/windows_caldera_smoke.json",
            "has_command_hint": True,
            "required_env": ["CALDERA_API_KEY", "CALDERA_GROUP", "CALDERA_AGENT_PAW"],
        }
    }


def test_status_consistency_extracts_macos_backend_best_candidate_action():
    artifact = {
        "quality_gate": {
            "actionable_gaps": [
                {
                    "evidence": {
                        "best_candidate": {
                            "hostname": "Victors-MacBook-Pro.local",
                            "status": "offline",
                            "health": "unknown",
                            "missing_readiness": ["status_online", "health_healthy", "fresh_heartbeat"],
                        },
                        "next_action": {
                            "target_hostname": "Victors-MacBook-Pro.local",
                            "action": "Reconnect the selected macOS agent.",
                        },
                    }
                }
            ]
        }
    }

    assert consistency.macos_backend_best_candidate_action(artifact) == {
        "hostname": "Victors-MacBook-Pro.local",
        "status": "offline",
        "health": "unknown",
        "missing_readiness": ["status_online", "health_healthy", "fresh_heartbeat"],
        "target_hostname": "Victors-MacBook-Pro.local",
        "has_action": True,
    }


def test_status_consistency_extracts_macos_backend_auth_action_without_candidate():
    artifact = {
        "quality_gate": {
            "actionable_gaps": [
                {
                    "evidence": {
                        "best_candidate": None,
                        "next_action": {
                            "target_hostname": None,
                            "missing_readiness": ["tamandua_ctl_auth"],
                            "action": "Refresh tamandua-ctl authentication.",
                        },
                    }
                }
            ]
        }
    }

    assert consistency.macos_backend_best_candidate_action(artifact) == {
        "hostname": None,
        "status": None,
        "health": None,
        "missing_readiness": ["tamandua_ctl_auth"],
        "target_hostname": None,
        "has_action": True,
    }


def test_status_consistency_extracts_windows_lab_next_action():
    artifact = {
        "windows_lab_readiness": {
            "target": {
                "hostname": "WIN-TEMPLATE",
                "status": "offline",
                "health": "unknown",
            },
            "next_action": {
                "target_hostname": "WIN-TEMPLATE",
                "missing_readiness": ["status_online", "live_response_reported"],
                "action": "Bring WIN-TEMPLATE online.",
            },
        }
    }

    assert consistency.windows_lab_next_action(artifact) == {
        "hostname": "WIN-TEMPLATE",
        "status": "offline",
        "health": "unknown",
        "missing_readiness": ["status_online", "live_response_reported"],
        "target_hostname": "WIN-TEMPLATE",
        "has_action": True,
    }


def test_status_consistency_extracts_windows_connection_stability_next_action():
    artifact = {
        "connection_stability": {
            "next_action": {
                "agent_id": "agent-win-template",
                "missing_stability": ["server_log_access", "telemetry_batches"],
                "blockers": ["collector", "infra"],
                "min_stable_session_seconds": 300,
                "action": "Set TAMANDUA_SERVER_PASSWORD.",
            }
        }
    }

    assert consistency.windows_connection_stability_next_action(artifact) == {
        "agent_id": "agent-win-template",
        "missing_stability": ["server_log_access", "telemetry_batches"],
        "blockers": ["collector", "infra"],
        "min_stable_session_seconds": 300,
        "has_action": True,
    }


def test_status_consistency_run_artifact_accepts_explicit_run_id(tmp_path):
    payload = {
        "checks": [
            {
                "name": "sample check",
                "status": "PASS",
                "actual": True,
                "expected": True,
                "source_files": ["docs/example.md"],
            }
        ],
        "latest": {
            "validation-status-consistency-probe": {
                "run_id": "20260603T172000Z-validation-status-consistency-probe",
                "path": "docs/benchmarks/runs/20260603T172000Z-validation-status-consistency-probe.json",
            }
        },
        "claim_boundary": "local audit",
        "summary": {"passed": 1, "failed": 0, "total_checks": 1},
    }

    json_path, md_path, comparison_path = consistency.write_run_artifacts(
        payload,
        tmp_path,
        "20260603T172500Z-validation-status-consistency-probe",
    )
    report = json.loads(json_path.read_text(encoding="utf-8"))

    assert json_path.name == "20260603T172500Z-validation-status-consistency-probe.json"
    assert md_path.exists()
    assert comparison_path.exists()
    assert report["run_id"] == "20260603T172500Z-validation-status-consistency-probe"
    assert report["started_at"] == "2026-06-03T17:25:00Z"
    assert report["latest"]["validation-status-consistency-probe"]["run_id"] == report["run_id"]


def test_status_consistency_run_artifact_rejects_invalid_explicit_run_id(tmp_path):
    try:
        consistency.write_run_artifacts({"checks": []}, tmp_path, "bad-run-id")
    except ValueError as exc:
        assert "YYYYMMDDTHHMMSSZ-validation-status-consistency-probe" in str(exc)
    else:
        raise AssertionError("invalid run id should fail")


def test_status_consistency_formats_scorecard_coverage_string():
    assert consistency.scorecard_coverage_string({"covered": 4, "tests": 7}) == "4/7"
    assert consistency.scorecard_coverage_string({"covered": 28, "expected_profile_tests": 28}) == "28/28"
    assert consistency.scorecard_coverage_string({"covered": 4}) == ""


def test_status_consistency_extracts_roadmap_note():
    payload = {"roadmaps": [{"key": "B", "note": "fresh_restore=true required"}]}

    assert consistency.roadmap_note(payload, "B") == "fresh_restore=true required"
    assert consistency.roadmap_note(payload, "A") == ""


def test_status_consistency_finds_needles_on_same_line():
    text = "run-a is fail (`0/5`)\nrun-b is fail"

    assert consistency.line_contains_all(text, ["run-a", "0/5"])
    assert not consistency.line_contains_all(text, ["run-b", "0/5"])


def test_status_consistency_extracts_open_roadmaps_and_blocked_run_classes():
    closure_artifact = {"gated_roadmaps": ["B", "A", "A"]}
    preflight_artifact = {
        "run_class_readiness": [
            {
                "run_class": "windows-broad",
                "allowed": False,
                "open_roadmaps": ["B", "A"],
                "missing_env": ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"],
            },
            {
                "run_class": "macos-server-backed-smoke",
                "allowed": False,
                "open_roadmaps": ["E"],
                "missing_env": [],
            },
            {"run_class": "windows-atomic-extended", "allowed": True},
        ]
    }

    assert consistency.closure_open_roadmaps(closure_artifact) == ["A", "B"]
    assert consistency.blocked_run_classes(preflight_artifact) == [
        "macos-server-backed-smoke",
        "windows-broad",
    ]
    assert consistency.blocked_run_class_roadmaps(preflight_artifact) == {
        "macos-server-backed-smoke": ["E"],
        "windows-broad": ["A", "B"],
    }
    assert consistency.blocked_run_class_missing_envs(preflight_artifact) == {
        "macos-server-backed-smoke": [],
        "windows-broad": ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"],
    }


def test_status_consistency_extracts_unblock_sequence_ids_and_priorities():
    preflight_artifact = {
        "unblock_sequence": [
            {"priority": 10, "step_id": "provide-required-preflight-env"},
            {"priority": 90, "step_id": "rerun-preflight-and-closure-gate"},
            {"priority": 99},
        ]
    }

    assert consistency.unblock_sequence_ids(preflight_artifact) == [
        "provide-required-preflight-env",
        "rerun-preflight-and-closure-gate",
    ]
    assert consistency.unblock_sequence_priorities(preflight_artifact) == [10, 90, 99]


def test_status_consistency_extracts_parallel_unblock_wave_shape():
    preflight_artifact = {
        "parallel_unblock_waves": [
            {
                "wave": 2,
                "parallelizable": True,
                "step_ids": ["capture-fresh-restore-provenance"],
                "depends_on_waves": [1],
                "roadmaps": ["B"],
            },
            {
                "wave": 1,
                "parallelizable": True,
                "step_ids": ["provide-required-preflight-env"],
                "depends_on_waves": [],
                "roadmaps": ["B", "D"],
            },
        ]
    }

    assert consistency.parallel_unblock_wave_shape(preflight_artifact) == [
        {
            "wave": 1,
            "parallelizable": True,
            "step_ids": ["provide-required-preflight-env"],
            "depends_on_waves": [],
        },
        {
            "wave": 2,
            "parallelizable": True,
            "step_ids": ["capture-fresh-restore-provenance"],
            "depends_on_waves": [1],
        },
    ]


def test_status_consistency_reports_missing_expected_values():
    assert "TAMANDUA_FRESH_RESTORE" in consistency.EXPECTED_PREFLIGHT_REQUIRED_ENVS
    assert consistency.missing_expected_values(["A", "C"], ["A", "B", "C"]) == ["B"]
    assert consistency.missing_expected_values(["A", "B"], ["A", "B"]) == []
    assert consistency.missing_expected_values(
        consistency.EXPECTED_PREFLIGHT_REQUIRED_ENVS,
        consistency.EXPECTED_PREFLIGHT_REQUIRED_ENVS,
    ) == []


def test_status_consistency_extracts_preflight_package_required_env():
    artifact = {
        "parallel_work_packages": [
            {
                "package_id": "wave-1-restore-windows-qga-readiness",
                "required_env": ["TAMANDUA_PROXMOX_PASSWORD"],
            },
            {
                "package_id": "wave-2-capture-fresh-restore-provenance",
                "required_env": [
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
        ]
    }

    assert consistency.preflight_package_required_env(artifact) == {
        "wave-1-restore-windows-qga-readiness": ["TAMANDUA_PROXMOX_PASSWORD"],
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


def test_fresh_restore_requires_true_claim_flag_and_valid_timing():
    metadata = {
        "fresh_restore": False,
        "restore_started_at": "2026-06-03T10:00:00Z",
        "restore_finished_at": "2026-06-03T09:59:00Z",
        "snapshot_name": "pre-roadmap-b",
        "snapshot_id": "snapshot-1",
        "vmid": 1521,
        "agent_id_after_restore": "agent-1",
        "hostname_after_restore": "WIN-TEMPLATE",
    }
    report = {"started_at": "2026-06-03T09:58:00Z"}

    gaps = fresh_restore.provenance_field_gaps(metadata, report)

    assert "fresh_restore:true" in gaps
    assert "restore_started_at_before_restore_finished_at" in gaps
    assert "benchmark_started_at_after_restore_finished_at" in gaps


def test_fresh_restore_accepts_complete_true_claim_with_ordered_timing():
    metadata = {
        "fresh_restore": True,
        "restore_started_at": "2026-06-03T09:50:00Z",
        "restore_finished_at": "2026-06-03T09:59:00Z",
        "snapshot_name": "pre-roadmap-b",
        "snapshot_id": "snapshot-1",
        "vmid": 1521,
        "agent_id_after_restore": "agent-1",
        "hostname_after_restore": "WIN-TEMPLATE",
    }
    report = {"started_at": "2026-06-03T10:00:00Z"}

    assert fresh_restore.provenance_field_gaps(metadata, report) == []


def test_preflight_blocks_windows_broad_for_fresh_restore_env_gap():
    closure_gate = {
        "tests": [
            {
                "status": "missed",
                "evidence": {"roadmap_key": "B"},
            }
        ]
    }
    required_by_roadmap = {"B": ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"]}
    blockers = [
        {
            "roadmap": "B",
            "profile_id": "fresh-restore-provenance-probe",
            "required_env": ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"],
            "blocking_gaps": ["fresh_restore_provenance_missing"],
        }
    ]

    readiness = preflight.classify_run_classes(
        closure_gate,
        required_by_roadmap,
        ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"],
        blockers,
    )
    broad = next(item for item in readiness if item["run_class"] == "windows-broad")

    assert not broad["allowed"]
    assert broad["missing_env"] == ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"]

    sequence = preflight.derive_unblock_sequence(
        required_by_roadmap,
        ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"],
        blockers,
        readiness,
    )
    env_step = next(item for item in sequence if item["step_id"] == "provide-required-preflight-env")

    assert env_step["roadmaps"] == ["B"]
    assert env_step["blocked_run_classes"] == ["windows-broad"]


def test_preflight_collects_closure_roadmap_next_actions():
    closure_gate = {
        "roadmap_next_actions": [
            {
                "roadmap": "B",
                "roadmap_status": "partial",
                "blocking_profiles": ["fresh-restore-provenance-probe"],
                "required_env": ["TAMANDUA_FRESH_RESTORE"],
                "errors": [],
                "actionable_gap_ids": ["fresh-restore-provenance-metadata-present"],
                "action": "Run the restore-backed batches.",
            }
        ]
    }

    actions = preflight.collect_roadmap_next_actions(closure_gate)

    assert actions == [
        {
            "roadmap": "B",
            "roadmap_status": "partial",
            "blocking_profiles": ["fresh-restore-provenance-probe"],
            "required_env": ["TAMANDUA_FRESH_RESTORE"],
            "errors": [],
            "actionable_gap_ids": ["fresh-restore-provenance-metadata-present"],
            "action": "Run the restore-backed batches.",
        }
    ]


def test_preflight_markdown_renders_roadmap_next_actions(tmp_path):
    report = {
        "run_id": "20260604T000000Z-validation-execution-preflight-probe",
        "quality_gate": {"status": "fail"},
        "closure_gate_run_id": "20260604T000000Z-roadmap-closure-gate-probe",
        "claim_boundary": "Local read-only scheduling preflight only.",
        "roadmap_next_actions": [
            {
                "roadmap": "D",
                "blocking_profiles": ["caldera-api-shape-probe"],
                "required_env": ["CALDERA_API_KEY"],
                "action": "Provide CALDERA_API_KEY, then rerun.",
            }
        ],
        "tests": [
            {
                "id": "execution-preflight-required-env-present",
                "name": "Required preflight environment variables are present in this shell",
                "status": "missed",
                "missing_expected_fields": ["CALDERA_API_KEY"],
                "evidence": {
                    "required_env_by_roadmap": {"D": ["CALDERA_API_KEY"]},
                    "required_env_present": [],
                    "required_env_missing": ["CALDERA_API_KEY"],
                },
            },
            {
                "id": "execution-preflight-closure-gate-green",
                "name": "Roadmap closure gate is green before broad execution",
                "status": "missed",
                "missing_expected_fields": ["roadmap_closure_gate_passed"],
                "evidence": {
                    "closure_gate_passed": False,
                    "open_roadmaps": ["D"],
                    "blocking_gaps": ["roadmap-d-closure-gate"],
                },
            },
            {
                "id": "execution-preflight-broad-runs-allowed",
                "name": "Broad validation runs are allowed from this shell",
                "status": "missed",
                "missing_expected_fields": ["broad_execution_preflight_green"],
                "evidence": {"allowed": False, "blocked_run_classes": ["windows-caldera-enterprise"]},
            },
            {
                "id": "execution-preflight-roadmap-blockers-summarized",
                "name": "Roadmap blocker profiles are summarized for scheduling triage",
                "status": "covered",
                "missing_expected_fields": [],
                "evidence": {"roadmap_blockers": []},
            },
            {
                "id": "execution-preflight-run-class-readiness-summarized",
                "name": "Run class readiness is summarized before broad scheduling",
                "status": "covered",
                "missing_expected_fields": [],
                "evidence": {"run_class_readiness": []},
            },
            {
                "id": "execution-preflight-unblock-sequence-summarized",
                "name": "Unblock sequence is summarized before broad scheduling",
                "status": "covered",
                "missing_expected_fields": [],
                "evidence": {
                    "unblock_sequence": [],
                    "roadmap_next_actions": [
                        {
                            "roadmap": "D",
                            "blocking_profiles": ["caldera-api-shape-probe"],
                            "required_env": ["CALDERA_API_KEY"],
                            "action": "Provide CALDERA_API_KEY, then rerun.",
                        }
                    ],
                },
            },
            {
                "id": "execution-preflight-parallel-unblock-waves-summarized",
                "name": "Parallel unblock waves are summarized for multi-agent scheduling",
                "status": "covered",
                "missing_expected_fields": [],
                "evidence": {"parallel_unblock_waves": [], "parallel_work_packages": []},
            },
        ],
    }
    path = tmp_path / "preflight.md"

    preflight.write_markdown(path, report)
    markdown = path.read_text(encoding="utf-8")

    assert "## Roadmap Next Actions" in markdown
    assert "caldera-api-shape-probe" in markdown
    assert "Provide CALDERA_API_KEY" in markdown


def test_preflight_blocks_windows_transport_run_classes_for_readiness_gap():
    closure_gate = {
        "tests": [
            {"status": "missed", "evidence": {"roadmap_key": "A"}},
        ]
    }
    blockers = [
        {
            "roadmap": "A",
            "profile_id": "windows-lab-execution-readiness-probe",
            "required_env": [],
            "blocking_gaps": ["windows_lab_not_ready"],
        },
        {
            "roadmap": "A",
            "profile_id": "windows-agent-connection-stability-probe",
            "required_env": [],
            "blocking_gaps": ["windows_connection_unstable"],
        },
    ]

    readiness = preflight.classify_run_classes(closure_gate, {}, [], blockers)
    by_class = {item["run_class"]: item for item in readiness}

    assert not by_class["windows-broad"]["allowed"]
    assert not by_class["windows-p1-p2-rerun"]["allowed"]
    assert by_class["windows-atomic-extended"]["allowed"]
    assert by_class["windows-caldera-enterprise"]["allowed"]
    assert by_class["macos-server-backed-smoke"]["allowed"]

    sequence = preflight.derive_unblock_sequence({}, [], blockers, readiness)
    backend_step = next(item for item in sequence if item["step_id"] == "restore-windows-backend-readiness")

    assert backend_step["roadmaps"] == ["A"]
    assert backend_step["blocked_run_classes"] == ["windows-broad", "windows-p1-p2-rerun"]
    assert backend_step["required_env"] == []


def test_preflight_derives_parallel_unblock_waves():
    sequence = [
        {"priority": 10, "step_id": "provide-required-preflight-env", "roadmaps": ["B", "D"], "blocked_run_classes": ["windows-broad"]},
        {"priority": 20, "step_id": "restore-windows-backend-readiness", "roadmaps": ["A"], "blocked_run_classes": ["windows-p1-p2-rerun"]},
        {"priority": 25, "step_id": "restore-windows-qga-readiness", "roadmaps": ["A"], "blocked_run_classes": ["windows-p1-p2-rerun"]},
        {"priority": 50, "step_id": "resolve-atomic-extended-preconditions", "roadmaps": ["M"], "blocked_run_classes": ["windows-atomic-extended"]},
        {"priority": 60, "step_id": "restore-macos-backend-readiness", "roadmaps": ["E"], "blocked_run_classes": ["macos-server-backed-smoke"]},
        {"priority": 90, "step_id": "rerun-preflight-and-closure-gate", "roadmaps": ["A", "B", "D", "E", "M"], "blocked_run_classes": ["windows-broad"]},
    ]

    waves = preflight.derive_parallel_unblock_waves(sequence)

    assert waves[0]["wave"] == 1
    assert waves[0]["parallelizable"]
    assert waves[0]["step_ids"] == [
        "provide-required-preflight-env",
        "restore-windows-backend-readiness",
        "restore-windows-qga-readiness",
        "resolve-atomic-extended-preconditions",
        "restore-macos-backend-readiness",
    ]
    assert waves[-1]["wave"] == 3
    assert waves[-1]["depends_on_waves"] == [1]


def test_preflight_derives_parallel_work_packages():
    sequence = [
        {
            "priority": 10,
            "step_id": "provide-required-preflight-env",
            "title": "Provide required preflight environment inputs",
            "roadmaps": ["B", "D"],
            "blocked_run_classes": ["windows-broad", "windows-caldera-enterprise"],
            "required_env": ["CALDERA_API_KEY"],
            "blocking_profiles": ["caldera-api-shape-probe"],
            "action": "Set required env vars.",
            "runtime_effect": "operator_input_or_readiness_work",
        },
        {
            "priority": 20,
            "step_id": "restore-windows-backend-readiness",
            "title": "Restore Windows backend readiness",
            "roadmaps": ["A"],
            "blocked_run_classes": ["windows-broad"],
            "required_env": [],
            "blocking_profiles": ["windows-lab-execution-readiness-probe"],
            "action": "Prove Windows readiness.",
            "runtime_effect": "operator_input_or_readiness_work",
        },
        {
            "priority": 25,
            "step_id": "restore-windows-qga-readiness",
            "title": "Restore Windows QGA readiness",
            "roadmaps": ["A"],
            "blocked_run_classes": ["windows-broad"],
            "required_env": ["TAMANDUA_PROXMOX_PASSWORD"],
            "blocking_profiles": ["windows-proxmox-qga-readiness-probe"],
            "action": "Prove QGA readiness.",
            "runtime_effect": "operator_input_or_readiness_work",
        },
    ]
    waves = preflight.derive_parallel_unblock_waves(sequence)

    roadmap_actions = [
        {
            "roadmap": "D",
            "roadmap_status": "needs-repeatability",
            "blocking_profiles": ["caldera-api-shape-probe"],
            "required_env": ["CALDERA_API_KEY"],
            "action": "Restore CALDERA readiness.",
        }
    ]

    packages = preflight.derive_parallel_work_packages(sequence, waves, roadmap_actions)

    assert [item["package_id"] for item in packages] == [
        "wave-1-provide-required-preflight-env",
        "wave-1-restore-windows-backend-readiness",
        "wave-1-restore-windows-qga-readiness",
    ]
    assert packages[0]["recommended_owner_role"] == "operator-or-secret-holder"
    assert packages[0]["required_env"] == ["CALDERA_API_KEY"]
    assert packages[0]["roadmap_next_actions"] == roadmap_actions
    assert "validation_execution_preflight_probe.py --output-dir" in " ".join(packages[0]["safe_commands"])
    assert packages[1]["recommended_owner_role"] == "validation-agent"
    assert packages[1]["parallelizable_in_wave"]
    assert "windows_lab_execution_readiness_probe.py --server" in " ".join(packages[1]["safe_commands"])
    assert "--server http://192.168.12.146:4000" in " ".join(packages[1]["safe_commands"])
    assert packages[1]["required_env"] == []
    assert packages[1]["continue_on_failure"] is True
    assert packages[1]["expected_profile_ids"] == [
        "windows-lab-execution-readiness-probe",
        "windows-agent-connection-stability-probe",
    ]
    assert packages[2]["recommended_owner_role"] == "operator-or-secret-holder"
    assert packages[2]["required_env"] == ["TAMANDUA_PROXMOX_PASSWORD"]
    assert packages[2]["continue_on_failure"] is True
    assert packages[2]["expected_profile_ids"] == [
        "windows-proxmox-qga-readiness-probe",
        "windows-proxmox-qga-file-diagnostics-probe",
    ]


def test_preflight_safe_commands_cover_all_unblock_steps():
    expected = {
        "provide-required-preflight-env": "validation_execution_preflight_probe.py --output-dir",
        "restore-windows-backend-readiness": "windows_agent_connection_stability_probe.py --output-dir",
        "restore-windows-qga-readiness": "windows_proxmox_qga_readiness_probe.py --output-dir",
        "capture-fresh-restore-provenance": "fresh_restore_provenance_probe.py --output-dir",
        "restore-caldera-readiness-repeatability": "caldera_repeatability_probe.py --output-dir",
        "resolve-atomic-extended-preconditions": "atomic_t1047_lab_capability_probe.py --output-dir",
        "restore-macos-backend-readiness": "run-macos-p0-smoke.ps1 -OutputDir",
        "rerun-preflight-and-closure-gate": "roadmap_closure_gate_probe.py --output-dir",
    }

    for step_id, marker in expected.items():
        assert marker in " ".join(preflight.safe_commands_for_step(step_id))

    fresh_restore_commands = " ".join(preflight.safe_commands_for_step("capture-fresh-restore-provenance"))
    assert fresh_restore_commands.count("tamandua_detection_validation.py --profile") == 6
    assert "windows_roadmap_300_batch_01.json" in fresh_restore_commands
    assert "windows_roadmap_300_batch_06.json" in fresh_restore_commands
    assert "--fresh-restore-started-at $env:TAMANDUA_FRESH_RESTORE_STARTED_AT" in fresh_restore_commands
    assert "--fresh-restore-hostname $env:TAMANDUA_FRESH_RESTORE_HOSTNAME" in fresh_restore_commands
    assert "--execute --benchmark-lane enterprise-eval --output-dir $Out" in fresh_restore_commands

    endpoint_commands = " ".join(
        preflight.safe_commands_for_step("restore-windows-backend-readiness")
        + preflight.safe_commands_for_step("restore-macos-backend-readiness")
    )
    assert endpoint_commands.count("--server http://192.168.12.146:4000") == 2


def test_preflight_operator_inputs_cover_fresh_restore_and_caldera():
    fresh_inputs = preflight.operator_inputs_for_step("capture-fresh-restore-provenance")
    caldera_inputs = preflight.operator_inputs_for_step("restore-caldera-readiness-repeatability")
    backend_inputs = preflight.operator_inputs_for_step("restore-windows-backend-readiness")
    qga_inputs = preflight.operator_inputs_for_step("restore-windows-qga-readiness")
    aggregate_inputs = preflight.operator_inputs_for_step("provide-required-preflight-env")
    closure_inputs = preflight.operator_inputs_for_step("rerun-preflight-and-closure-gate")

    assert [item["env"] for item in fresh_inputs] == [
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_FRESH_RESTORE_STARTED_AT",
        "TAMANDUA_FRESH_RESTORE_FINISHED_AT",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_NAME",
        "TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID",
        "TAMANDUA_FRESH_RESTORE_VMID",
        "TAMANDUA_FRESH_RESTORE_AGENT_ID",
        "TAMANDUA_FRESH_RESTORE_HOSTNAME",
    ]
    assert "--fresh-restore-snapshot-id" in [item["flag"] for item in fresh_inputs]
    assert {item["env"] for item in caldera_inputs} == {
        "CALDERA_API_KEY",
        "CALDERA_GROUP",
        "CALDERA_AGENT_PAW",
    }
    assert any("tamandua-lab" in item["description"] for item in caldera_inputs)
    assert backend_inputs == [
        {
            "name": "server_password",
            "flag": "--server-password",
            "env": "TAMANDUA_SERVER_PASSWORD",
            "description": "Tamandua backend password used by server-backed Windows readiness and connection-stability probes",
        }
    ]
    assert {item["env"] for item in qga_inputs} == {
        "TAMANDUA_PROXMOX_PASSWORD",
        "TAMANDUA_SERVER_PASSWORD",
    }
    assert {item["env"] for item in aggregate_inputs} >= {
        "CALDERA_API_KEY",
        "CALDERA_GROUP",
        "CALDERA_AGENT_PAW",
        "TAMANDUA_FRESH_RESTORE",
        "TAMANDUA_SERVER_PASSWORD",
        "TAMANDUA_PROXMOX_PASSWORD",
    }
    assert {item["env"] for item in closure_inputs} == {item["env"] for item in aggregate_inputs}
    assert any(item["flag"] == "--server-password" for item in aggregate_inputs)
    assert "three consecutive" in " ".join(
        preflight.manual_prerequisites_for_step("restore-caldera-readiness-repeatability")
    )


def test_preflight_work_package_finds_latest_preflight_artifact(tmp_path):
    older = tmp_path / "20260603T100000Z-validation-execution-preflight-probe.json"
    newer = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    comparison = tmp_path / "20260603T120000Z-validation-execution-preflight-probe.comparison.json"
    older.write_text("{}", encoding="utf-8")
    newer.write_text("{}", encoding="utf-8")
    comparison.write_text("{}", encoding="utf-8")

    assert preflight_work_package.latest_preflight_path(tmp_path) == newer


def test_preflight_work_package_load_json_accepts_utf8_bom(tmp_path):
    path = tmp_path / "agent_status.json"
    path.write_text('{"status": "pass"}', encoding="utf-8-sig")

    assert preflight_work_package.load_json(path) == {"status": "pass"}


def test_preflight_work_package_renders_safe_command_script(tmp_path):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    package = {
        "package_id": "wave-1-restore-windows-backend-readiness",
        "title": "Restore Windows backend readiness",
        "wave": 1,
        "recommended_owner_role": "validation-agent",
        "required_env": ["CALDERA_API_KEY"],
        "roadmap_next_actions": [
            {
                "required_env": ["TAMANDUA_SERVER_PASSWORD"],
                "action": "Provide server log access before backend readiness.",
            }
        ],
        "safe_commands": [
            "$Out = Join-Path $env:TEMP 'tamandua-windows-backend-readiness'",
            "python tools/detection_validation/windows_lab_execution_readiness_probe.py --output-dir $Out",
        ],
    }

    script_path = preflight_work_package.write_package_script(package, preflight_path, tmp_path / "scripts")
    script_text = script_path.read_text(encoding="utf-8")

    assert script_path.name == "wave-1-restore-windows-backend-readiness.ps1"
    assert "# PackageId: wave-1-restore-windows-backend-readiness" in script_text
    assert "Set-Location" in script_text
    assert "TAMANDUA_REPO_ROOT" in script_text
    assert "D:\\treant\\tamandua" not in script_text
    assert "$RequiredEnv = @('CALDERA_API_KEY', 'TAMANDUA_SERVER_PASSWORD')" in script_text
    assert "(Split-Path -Leaf $Out) -ieq 'outputs'" in script_text
    assert "Join-Path (Split-Path -Parent $Out) 'agent_status.json'" in script_text
    assert "Join-Path $Out 'agent_status.json'" in script_text
    assert "Missing effective env for package" in script_text
    assert "Write-Host ('Missing effective env for package: ' + ($MissingEnv -join ', '))" in script_text
    assert "Write-AgentStatus 'blocked' 2 @('missing_effective_env: ' + ($MissingEnv -join ', '))" in script_text
    assert "$StatusPath" in script_text
    assert "$ClaimId = [Environment]::GetEnvironmentVariable('TAMANDUA_AGENT_CLAIM_ID')" in script_text
    assert "$AgentId = [Environment]::GetEnvironmentVariable('TAMANDUA_AGENT_ID')" in script_text
    assert "TAMANDUA_CLAIM_LOCK_ACQUIRED" in script_text
    assert "Missing claim lock helper for direct package execution" in script_text
    assert "-File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId" in script_text
    assert "function Write-AgentStatus" in script_text
    assert "$ProfileIdProperty = $Payload.PSObject.Properties['profile_id']" in script_text
    assert "$QualityGateProperty = $Payload.PSObject.Properties['quality_gate']" in script_text
    assert "$PassedProperty = $QualityGateProperty.Value.PSObject.Properties['passed']" in script_text
    assert "Write-AgentStatus 'blocked'" in script_text
    assert "Write-AgentStatus 'fail' $LASTEXITCODE" in script_text
    assert "Write-AgentStatus 'pass' 0 @()" in script_text
    assert "claim_id = $ClaimId" in script_text
    assert "agent_id = $AgentId" in script_text
    assert "expected_profiles = @($ExpectedProfiles)" in script_text
    assert "windows_lab_execution_readiness_probe.py --output-dir" in script_text
    assert "exit $LASTEXITCODE" in script_text


def test_preflight_work_package_prompt_and_manifest_include_roadmap_next_actions(tmp_path):
    package = {
        "package_id": "wave-2-restore-caldera-readiness-repeatability",
        "title": "Restore CALDERA readiness",
        "wave": 2,
        "step_id": "restore-caldera-readiness-repeatability",
        "recommended_owner_role": "operator-or-secret-holder",
        "parallelizable_in_wave": True,
        "continue_on_failure": False,
        "roadmaps": ["D"],
        "blocked_run_classes": ["windows-caldera-enterprise"],
        "blocking_profiles": ["caldera-api-shape-probe"],
        "required_env": ["CALDERA_API_KEY"],
        "expected_profile_ids": ["caldera-api-shape-probe"],
        "safe_commands": [
            "$Out = Join-Path $env:TEMP 'tamandua-caldera-readiness'",
            "python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out",
        ],
        "roadmap_next_actions": [
            {
                "roadmap": "D",
                "roadmap_status": "needs-repeatability",
                "blocking_profiles": ["caldera-api-shape-probe"],
                "required_env": ["CALDERA_API_KEY"],
                "action": "Provide CALDERA_API_KEY and rerun API shape.",
            }
        ],
        "action": "Restore CALDERA readiness.",
    }
    preflight_path = tmp_path / "20260604T000000Z-validation-execution-preflight-probe.json"
    script_path = tmp_path / "wave-2-restore-caldera-readiness-repeatability.ps1"
    script_path.write_text("Write-Output ok\n", encoding="utf-8")

    prompt = preflight_work_package.render_agent_prompt(package, script_path, preflight_path)

    assert "Claim ID: claim-wave-2-restore-caldera-readiness-repeatability" in prompt
    assert "Roadmap next actions:" in prompt
    assert "Provide CALDERA_API_KEY and rerun API shape" in prompt
    assert "CALDERA_API_KEY" in prompt
    assert "Status JSON required fields: package_id, claim_id, agent_id, status, artifacts, blocker_cleared, notes, exit_code, expected_profiles, missing_profiles" in prompt
    assert "Status JSON allowed status values: pass, fail, blocked" in prompt
    assert "Current status: not_run" in prompt
    assert "Current artifacts: -" in prompt
    assert "Claim lock helper:" in prompt
    assert "Claim lock command:" in prompt
    assert "-ClaimId claim-wave-2-restore-caldera-readiness-repeatability" in prompt
    assert "Acquire the claim lock" in prompt

    manifest = preflight_work_package.build_dispatch_manifest(
        [package],
        preflight_path,
        tmp_path,
        {package["package_id"]: script_path},
    )
    action = manifest["packages"][0]["roadmap_next_actions"][0]

    assert action["roadmap"] == "D"
    assert action["required_env"] == ["CALDERA_API_KEY"]
    assert action["blocking_profiles"] == ["caldera-api-shape-probe"]
    assert manifest["packages"][0]["claim_output_contract"]["status_required_fields"] == [
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
    ]
    assert manifest["packages"][0]["claim_output_contract"]["status_allowed_values"] == [
        "pass",
        "fail",
        "blocked",
    ]


def test_preflight_work_package_renders_continue_on_failure_script(tmp_path):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    package = {
        "package_id": "wave-1-restore-windows-qga-readiness",
        "title": "Restore Windows QGA readiness",
        "wave": 1,
        "recommended_owner_role": "operator-or-secret-holder",
        "required_env": ["TAMANDUA_PROXMOX_PASSWORD"],
        "continue_on_failure": True,
        "safe_commands": [
            "$Out = Join-Path $env:TEMP 'tamandua-windows-qga-readiness'",
            "python tools/detection_validation/windows_proxmox_qga_readiness_probe.py --output-dir $Out",
            "python tools/detection_validation/windows_proxmox_qga_file_diagnostics_probe.py --output-dir $Out",
        ],
    }

    script_path = preflight_work_package.write_package_script(package, preflight_path, tmp_path / "scripts")
    script_text = script_path.read_text(encoding="utf-8")

    assert "$PackageExitCode = 0" in script_text
    assert "windows_proxmox_qga_readiness_probe.py --output-dir" in script_text
    assert "windows_proxmox_qga_file_diagnostics_probe.py --output-dir" in script_text
    assert "$PackageExitCode = $LASTEXITCODE" in script_text
    assert "if ($PackageExitCode -ne 0) {" in script_text
    assert "Write-AgentStatus 'fail' $PackageExitCode @('one_or_more_commands_failed')" in script_text
    assert "exit $PackageExitCode" in script_text
    assert "Write-AgentStatus 'pass' 0 @()" in script_text
    assert "Write-AgentStatus 'fail' $LASTEXITCODE" not in script_text


def test_preflight_work_package_main_lists_packages(tmp_path, capsys):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    preflight_path.write_text(
        '{"profile_id":"validation-execution-preflight-probe",'
        '"claim_boundary":"Local read-only scheduling preflight only.",'
        '"parallel_work_packages":[{"package_id":"wave-1-example","wave":1,'
        '"recommended_owner_role":"validation-agent","parallelizable_in_wave":true,'
        '"title":"Example package","safe_commands":["Write-Host ok"]}]}',
        encoding="utf-8",
    )

    exit_code = preflight_work_package.main(["--preflight-json", str(preflight_path), "--list"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "wave-1-example" in output
    assert "owner=validation-agent" in output


def test_preflight_work_package_main_lists_package_details(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    preflight_path.write_text(
        json.dumps(
            {
                "profile_id": "validation-execution-preflight-probe",
                "claim_boundary": "Local read-only scheduling preflight only.",
                "parallel_work_packages": [
                    {
                        "package_id": "wave-2-caldera",
                        "wave": 2,
                        "recommended_owner_role": "operator-or-secret-holder",
                        "parallelizable_in_wave": True,
                        "title": "Restore CALDERA",
                        "roadmaps": ["D"],
                        "blocking_profiles": ["caldera-api-shape-probe"],
                        "required_env": ["CALDERA_API_KEY"],
                        "expected_profile_ids": ["caldera-api-shape-probe"],
                        "depends_on_waves": [1],
                        "operator_inputs": [
                            {
                                "name": "caldera_api_key",
                                "env": "CALDERA_API_KEY",
                                "flag": "",
                                "description": "CALDERA API key with read access",
                            }
                        ],
                        "safe_commands": [
                            "$Out = Join-Path $env:TEMP 'tamandua-caldera'",
                            "python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out",
                        ],
                        "roadmap_next_actions": [
                            {
                                "roadmap": "D",
                                "roadmap_status": "needs-repeatability",
                                "required_env": ["CALDERA_API_KEY"],
                                "action": "Provide CALDERA_API_KEY.",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = preflight_work_package.main(["--preflight-json", str(preflight_path), "--list-detail"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "resources: caldera" in output
    assert "depends_on_waves: 1" in output
    assert "handoff_notes: parallelizable, depends-on-waves:1, env-blocked:CALDERA_API_KEY" in output
    assert "missing_env: CALDERA_API_KEY" in output
    assert "env_details: CALDERA_API_KEY flag=-" in output
    assert "roadmap_next_actions:" in output
    assert "Provide CALDERA_API_KEY." in output


def test_preflight_work_package_main_lists_packages_as_json(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CALDERA_API_KEY", "present")
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    preflight_path.write_text(
        json.dumps(
            {
                "profile_id": "validation-execution-preflight-probe",
                "claim_boundary": "Local read-only scheduling preflight only.",
                "parallel_work_packages": [
                    {
                        "package_id": "wave-2-caldera",
                        "wave": 2,
                        "recommended_owner_role": "operator-or-secret-holder",
                        "parallelizable_in_wave": True,
                        "title": "Restore CALDERA",
                        "required_env": ["CALDERA_API_KEY"],
                        "operator_inputs": [
                            {
                                "name": "caldera_api_key",
                                "env": "CALDERA_API_KEY",
                                "flag": "",
                                "description": "CALDERA API key with read access",
                            }
                        ],
                        "safe_commands": [
                            "$Out = Join-Path $env:TEMP 'tamandua-caldera'",
                            "python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out",
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = preflight_work_package.main(["--preflight-json", str(preflight_path), "--list-json"])

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert output[0]["package_id"] == "wave-2-caldera"
    assert output[0]["required_env"] == ["CALDERA_API_KEY"]
    assert output[0]["handoff_notes"] == ["parallelizable"]
    assert output[0]["missing_env"] == []
    assert output[0]["resource_tags"] == ["caldera"]
    assert output[0]["env_details"]["CALDERA_API_KEY"]["description"] == "CALDERA API key with read access"


def test_preflight_work_package_summarizes_all_package_artifacts(tmp_path):
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    first = output_dir / "20260603T100000Z-first-probe.json"
    second = output_dir / "20260603T100100Z-second-probe.json"
    for path, profile_id, passed in (
        (first, "first-probe", False),
        (second, "second-probe", True),
    ):
        path.write_text(
            json.dumps(
                {
                    "profile_id": profile_id,
                    "run_id": path.stem,
                    "quality_gate": {"passed": passed, "status": "pass" if passed else "fail"},
                }
            ),
            encoding="utf-8",
        )

    assert preflight_work_package.primary_result_artifact(output_dir) == first
    assert preflight_work_package.latest_result_artifact(output_dir) == second
    assert preflight_work_package.result_artifact_paths(output_dir) == [str(first), str(second)]


def test_preflight_work_package_main_writes_script_without_execution(tmp_path):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    output_dir = tmp_path / "out"
    preflight_path.write_text(
        '{"profile_id":"validation-execution-preflight-probe",'
        '"claim_boundary":"Local read-only scheduling preflight only.",'
        '"parallel_work_packages":[{"package_id":"wave-1-example","wave":1,'
        '"recommended_owner_role":"validation-agent","title":"Example package",'
        '"safe_commands":["$Out = Join-Path $env:TEMP tamandua-example",'
        '"python tools/detection_validation/validation_execution_preflight_probe.py --output-dir $Out"]}]}',
        encoding="utf-8",
    )

    exit_code = preflight_work_package.main(
        [
            "--preflight-json",
            str(preflight_path),
            "--package-id",
            "wave-1-example",
            "--output-dir",
            str(output_dir),
        ]
    )

    script_path = output_dir / "wave-1-example.ps1"
    assert exit_code == 0
    assert script_path.exists()
    script_text = script_path.read_text(encoding="utf-8")
    assert "validation_execution_preflight_probe.py --output-dir" in script_text
    assert str(output_dir / "wave-1-example" / "outputs") in script_text
    assert "Join-Path $env:TEMP tamandua-example" not in script_text


def test_preflight_work_package_selects_wave_and_all_packages():
    packages = [
        {"package_id": "wave-1-a", "wave": 1},
        {"package_id": "wave-2-b", "wave": 2},
        {"package_id": "wave-1-c", "wave": 1},
    ]

    wave_packages = preflight_work_package.select_packages(packages, wave=1)
    all_packages = preflight_work_package.select_packages(packages, include_all=True)

    assert [package["package_id"] for package in wave_packages] == ["wave-1-a", "wave-1-c"]
    assert [package["package_id"] for package in all_packages] == ["wave-1-a", "wave-1-c", "wave-2-b"]


def test_preflight_work_package_main_writes_wave_prompts_and_launcher(tmp_path):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    output_dir = tmp_path / "out"
    preflight_path.write_text(
        '{"profile_id":"validation-execution-preflight-probe",'
        '"claim_boundary":"Local read-only scheduling preflight only.",'
        '"parallel_work_packages":['
        '{"package_id":"wave-1-alpha","wave":1,"parallelizable_in_wave":true,'
        '"recommended_owner_role":"validation-agent","title":"Alpha package",'
        '"roadmaps":["A"],"blocking_profiles":["alpha-probe"],'
        '"safe_commands":["$Out = Join-Path $env:TEMP tamandua-alpha",'
        '"python tools/detection_validation/windows_lab_execution_readiness_probe.py --output-dir $Out"]},'
        '{"package_id":"wave-1-beta","wave":1,"parallelizable_in_wave":true,'
        '"recommended_owner_role":"operator-or-secret-holder","title":"Beta package",'
        '"required_env":["CALDERA_API_KEY","CALDERA_AGENT_PAW"],'
        '"operator_inputs":[{"name":"caldera_group","env":"CALDERA_GROUP",'
        '"flag":"--caldera-group","description":"set to tamandua-lab"}],'
        '"manual_prerequisites":["Start a fresh sandcat/PAW in CALDERA group tamandua-lab."],'
        '"safe_commands":["$Out = Join-Path $env:TEMP tamandua-beta",'
        '"python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out"]},'
        '{"package_id":"wave-2-gamma","wave":2,"parallelizable_in_wave":true,'
        '"recommended_owner_role":"validation-agent","title":"Gamma package",'
        '"safe_commands":["Write-Host gamma"]}'
        "]}",
        encoding="utf-8",
    )

    exit_code = preflight_work_package.main(
        [
            "--preflight-json",
            str(preflight_path),
            "--wave",
            "1",
            "--output-dir",
            str(output_dir),
            "--emit-agent-prompts",
            "--emit-agent-roster",
            "--emit-env-checklist",
            "--emit-wave-launcher",
        ]
    )

    assert exit_code == 0
    assert (output_dir / "wave-1-alpha.ps1").exists()
    assert (output_dir / "wave-1-beta.ps1").exists()
    assert not (output_dir / "wave-2-gamma.ps1").exists()
    prompt_text = (output_dir / "wave-1-beta.agent.md").read_text(encoding="utf-8")
    roster_text = (output_dir / "agent_roster.md").read_text(encoding="utf-8")
    checklist_text = (output_dir / "env_checklist.md").read_text(encoding="utf-8")
    launcher_text = (output_dir / "wave-1-parallel-launcher.ps1").read_text(encoding="utf-8")
    assert "Required env: CALDERA_API_KEY" in prompt_text
    assert "Resource tags: caldera" in prompt_text
    assert "docs/benchmarks/CALDERA_PAW_RECOVERY_RUNBOOK.md" in prompt_text
    assert "Manual prerequisites:" in prompt_text
    assert "Start a fresh sandcat/PAW in CALDERA group tamandua-lab." in prompt_text
    assert "Operator inputs:" in prompt_text
    assert "caldera_group: env `CALDERA_GROUP`, flag `--caldera-group`" in prompt_text
    assert "Status path:" in prompt_text
    assert "Expected JSON profiles: -" in prompt_text
    assert "docs/benchmarks/FRESH_RESTORE_PROVENANCE_RUNBOOK.md" not in prompt_text
    assert "`wave-1-alpha`" in roster_text
    assert "`wave-1-beta`" in roster_text
    assert "`CALDERA_API_KEY`" in roster_text
    assert "agent_status.json" in roster_text
    assert "operator-or-secret-holder" in roster_text
    assert "`CALDERA_API_KEY` | `no` | `secret`" in checklist_text
    assert "`CALDERA_GROUP` | `no` | `claim-metadata` | `next-action` | `--caldera-group` | set to tamandua-lab" in checklist_text
    assert "`wave-1-alpha`" not in checklist_text
    assert "Start-Job" in launcher_text
    assert "TAMANDUA_WAVE_LAUNCHER_AGENT_ID" in launcher_text
    assert "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId" in launcher_text
    assert "$env:TAMANDUA_AGENT_ID = $AgentId" in launcher_text
    assert "claim-wave-1-alpha" in launcher_text
    assert "claim-wave-1-beta" in launcher_text
    assert "if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" in launcher_text
    assert "wave-1-alpha.ps1" in launcher_text
    assert "wave-1-beta.ps1" in launcher_text
    assert "resources=windows-lab" in launcher_text
    assert "resources=caldera" in launcher_text


def test_preflight_work_package_execute_requires_explicit_artifact_and_env(tmp_path, monkeypatch):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    output_dir = tmp_path / "out"
    preflight_path.write_text(
        '{"profile_id":"validation-execution-preflight-probe",'
        '"claim_boundary":"Local read-only scheduling preflight only.",'
        '"parallel_work_packages":[{"package_id":"wave-1-secret","wave":1,'
        '"recommended_owner_role":"operator-or-secret-holder","title":"Secret package",'
        '"required_env":["CALDERA_API_KEY"],'
        '"safe_commands":["python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out"]}]}',
        encoding="utf-8",
    )
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)

    implicit_exit = preflight_work_package.main(
        [
            "--runs-dir",
            str(tmp_path),
            "--package-id",
            "wave-1-secret",
            "--output-dir",
            str(output_dir),
            "--execute",
        ]
    )
    missing_env_exit = preflight_work_package.main(
        [
            "--preflight-json",
            str(preflight_path),
            "--package-id",
            "wave-1-secret",
            "--output-dir",
            str(output_dir),
            "--execute",
        ]
    )

    assert implicit_exit == 2
    assert missing_env_exit == 2


def test_preflight_work_package_execute_rejects_shell_chaining_in_safe_commands(tmp_path, monkeypatch):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    output_dir = tmp_path / "out"
    preflight_path.write_text(
        '{"profile_id":"validation-execution-preflight-probe",'
        '"claim_boundary":"Local read-only scheduling preflight only.",'
        '"parallel_work_packages":[{"package_id":"wave-1-injected","wave":1,'
        '"recommended_owner_role":"validation-agent","title":"Injected package",'
        '"safe_commands":["python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out; Write-Host unsafe"]}]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(preflight_work_package, "execute_script", lambda _script_path: 0)

    exit_code = preflight_work_package.main(
        [
            "--preflight-json",
            str(preflight_path),
            "--package-id",
            "wave-1-injected",
            "--output-dir",
            str(output_dir),
            "--execute",
        ]
    )

    assert exit_code == 2


def test_preflight_work_package_execute_blocks_dependent_wave_without_override(tmp_path, monkeypatch):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    output_dir = tmp_path / "out"
    preflight_path.write_text(
        '{"profile_id":"validation-execution-preflight-probe",'
        '"claim_boundary":"Local read-only scheduling preflight only.",'
        '"parallel_work_packages":[{"package_id":"wave-2-dependent","wave":2,'
        '"depends_on_waves":[1],"recommended_owner_role":"validation-agent",'
        '"title":"Dependent package",'
        '"safe_commands":["python tools/detection_validation/fresh_restore_provenance_probe.py --output-dir $Out"]}]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(preflight_work_package, "execute_script", lambda _script_path: 0)

    blocked_exit = preflight_work_package.main(
        [
            "--preflight-json",
            str(preflight_path),
            "--package-id",
            "wave-2-dependent",
            "--output-dir",
            str(output_dir),
            "--execute",
        ]
    )
    allowed_exit = preflight_work_package.main(
        [
            "--preflight-json",
            str(preflight_path),
            "--package-id",
            "wave-2-dependent",
            "--output-dir",
            str(output_dir),
            "--execute",
            "--allow-dependent-wave-execute",
        ]
    )

    assert blocked_exit == 2
    assert allowed_exit == 0


def test_preflight_work_package_launcher_prioritizes_higher_impact_resource_conflict(tmp_path):
    packages = [
        {
            "package_id": "wave-1-low-impact",
            "wave": 1,
            "parallelizable_in_wave": True,
            "blocking_profiles": ["windows-low"],
            "blocked_run_classes": ["windows-broad"],
        },
        {
            "package_id": "wave-1-high-impact",
            "wave": 1,
            "parallelizable_in_wave": True,
            "blocking_profiles": ["windows-a", "windows-b", "windows-c"],
            "blocked_run_classes": ["windows-broad", "windows-p1-p2-rerun"],
        },
        {
            "package_id": "wave-1-caldera",
            "wave": 1,
            "parallelizable_in_wave": True,
            "blocking_profiles": ["caldera-api-shape-probe"],
            "blocked_run_classes": ["windows-caldera-enterprise"],
        },
    ]
    script_paths = {
        package["package_id"]: tmp_path / f"{package['package_id']}.ps1"
        for package in packages
    }

    launcher_paths = preflight_work_package.write_wave_launchers(packages, script_paths, tmp_path)
    launcher_text = launcher_paths[0].read_text(encoding="utf-8")

    assert "# Package: wave-1-high-impact" in launcher_text
    assert "# Package: wave-1-caldera" in launcher_text
    assert str(script_paths["wave-1-high-impact"].resolve()).replace("\\", "/") in launcher_text
    assert str(script_paths["wave-1-caldera"].resolve()).replace("\\", "/") in launcher_text
    assert "# - wave-1-low-impact: resource overlap: windows-lab" in launcher_text


def test_preflight_work_package_staged_launcher_serializes_resource_conflicts(tmp_path):
    packages = [
        {
            "package_id": "wave-1-low-impact",
            "wave": 1,
            "parallelizable_in_wave": True,
            "blocking_profiles": ["windows-low"],
            "blocked_run_classes": ["windows-broad"],
        },
        {
            "package_id": "wave-1-high-impact",
            "wave": 1,
            "parallelizable_in_wave": True,
            "blocking_profiles": ["windows-a", "windows-b", "windows-c"],
            "blocked_run_classes": ["windows-broad", "windows-p1-p2-rerun"],
        },
        {
            "package_id": "wave-1-macos",
            "wave": 1,
            "parallelizable_in_wave": True,
            "blocking_profiles": ["macos-backend-readiness-probe"],
            "blocked_run_classes": ["macos-server-backed-smoke"],
        },
    ]
    script_paths = {
        package["package_id"]: tmp_path / f"{package['package_id']}.ps1"
        for package in packages
    }

    launcher_paths = preflight_work_package.write_staged_wave_launchers(packages, script_paths, tmp_path)
    launcher_text = launcher_paths[0].read_text(encoding="utf-8")
    staged = preflight_work_package.staged_launcher_membership(packages)

    stage_one = launcher_text.split("# Stage 1", 1)[1].split("# Stage 2", 1)[0]
    stage_two = launcher_text.split("# Stage 2", 1)[1]
    assert "# Package: wave-1-high-impact" in stage_one
    assert "# Package: wave-1-macos" in stage_one
    assert "# Package: wave-1-low-impact" in stage_two
    assert "Skipped due to resource overlap" not in launcher_text
    assert "$StageFailures = @()" in launcher_text
    assert "stage 1: " in launcher_text
    assert "Failed package jobs across staged wave" in launcher_text
    assert staged == {
        "wave-1-high-impact": 1,
        "wave-1-macos": 1,
        "wave-1-low-impact": 2,
    }


def test_preflight_work_package_dependent_wave_launcher_requires_explicit_ack(tmp_path):
    packages = [
        {
            "package_id": "wave-2-fresh-restore",
            "wave": 2,
            "parallelizable_in_wave": True,
            "depends_on_waves": [1],
            "blocking_profiles": ["fresh-restore-provenance-probe"],
            "blocked_run_classes": ["windows-broad"],
        },
        {
            "package_id": "wave-2-caldera",
            "wave": 2,
            "parallelizable_in_wave": True,
            "depends_on_waves": [1],
            "blocking_profiles": ["caldera-repeatability-probe"],
            "blocked_run_classes": ["windows-caldera-enterprise"],
        },
    ]
    script_paths = {
        package["package_id"]: tmp_path / f"{package['package_id']}.ps1"
        for package in packages
    }

    launcher_paths = preflight_work_package.write_wave_launchers(packages, script_paths, tmp_path)
    launcher_text = launcher_paths[0].read_text(encoding="utf-8")

    assert "# DependsOnWaves: 1" in launcher_text
    assert "TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH" in launcher_text
    assert "Wave 2 depends on completed waves: 1" in launcher_text
    assert "dispatch_manifest.json" in launcher_text
    assert "Dependent wave evidence missing" in launcher_text
    assert "missing_json_output" in launcher_text
    assert "expected_profile_ids" in launcher_text
    assert "quality_gate_not_passed" in launcher_text
    assert "staged_launcher_selected" in launcher_text
    assert "Split-Path -Parent $LauncherDir" in launcher_text
    assert "exit 2" in launcher_text


def test_preflight_work_package_main_writes_dispatch_manifest(tmp_path):
    preflight_path = tmp_path / "20260603T110000Z-validation-execution-preflight-probe.json"
    output_dir = tmp_path / "out"
    preflight_path.write_text(
        '{"profile_id":"validation-execution-preflight-probe",'
        '"claim_boundary":"Local read-only scheduling preflight only.",'
        '"parallel_work_packages":['
        '{"package_id":"wave-1-windows-high","wave":1,"parallelizable_in_wave":true,'
        '"recommended_owner_role":"validation-agent","title":"Windows high",'
        '"blocking_profiles":["windows-a","windows-b"],"blocked_run_classes":["windows-broad"],'
        '"safe_commands":["python tools/detection_validation/windows_lab_execution_readiness_probe.py --output-dir $Out"]},'
        '{"package_id":"wave-1-windows-low","wave":1,"parallelizable_in_wave":true,'
        '"recommended_owner_role":"validation-agent","title":"Windows low",'
        '"blocking_profiles":["windows-c"],'
        '"safe_commands":["python tools/detection_validation/atomic_t1047_lab_capability_probe.py --output-dir $Out"]},'
        '{"package_id":"wave-1-caldera","wave":1,"parallelizable_in_wave":true,'
        '"recommended_owner_role":"operator-or-secret-holder","title":"Caldera",'
        '"required_env":["CALDERA_API_KEY","CALDERA_AGENT_PAW"],'
        '"expected_profile_ids":["caldera-api-shape-probe"],'
        '"operator_inputs":[{"name":"caldera_agent_paw","env":"CALDERA_AGENT_PAW",'
        '"flag":"--caldera-agent-paw","description":"fresh target PAW"}],'
        '"manual_prerequisites":["Use a disposable lab VM."],'
        '"safe_commands":["python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out"]}'
        "]}",
        encoding="utf-8",
    )

    exit_code = preflight_work_package.main(
        [
            "--preflight-json",
            str(preflight_path),
            "--wave",
            "1",
            "--output-dir",
            str(output_dir),
            "--emit-agent-prompts",
            "--emit-agent-roster",
            "--emit-env-checklist",
            "--emit-wave-launcher",
            "--emit-staged-wave-launcher",
            "--emit-dispatch-runner",
            "--emit-dispatch-brief",
            "--emit-dispatch-manifest",
        ]
    )

    manifest_path = output_dir / "dispatch_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_id = {package["package_id"]: package for package in manifest["packages"]}

    assert exit_code == 0
    assert manifest["profile_id"] == "validation-execution-preflight-probe"
    assert manifest["selection_mode"] == "wave"
    assert manifest["selected_wave"] == 1
    assert manifest["expected_waves"] == [1]
    assert manifest["expected_package_ids"] == [
        "wave-1-caldera",
        "wave-1-windows-high",
        "wave-1-windows-low",
    ]
    assert manifest["launcher_paths"]
    assert manifest["staged_launcher_paths"]
    assert manifest["agent_roster_path"].endswith("agent_roster.md")
    assert manifest["env_checklist_path"].endswith("env_checklist.md")
    assert manifest["env_template_path"].endswith("env_template.ps1")
    assert manifest["owner_launch_plan_path"].endswith("owner_launch_plan.md")
    assert manifest["owner_launch_plan_json_path"].endswith("owner_launch_plan.json")
    assert manifest["execution_matrix_path"].endswith("execution_matrix.md")
    assert manifest["execution_matrix_json_path"].endswith("execution_matrix.json")
    assert manifest["agent_claims_path"].endswith("agent_claims.md")
    assert manifest["agent_claims_json_path"].endswith("agent_claims.json")
    assert manifest["agent_spawn_plan_path"].endswith("agent_spawn_plan.md")
    assert manifest["agent_spawn_plan_json_path"].endswith("agent_spawn_plan.json")
    assert manifest["agent_spawn_launcher_path"].endswith("agent_spawn_launcher.ps1")
    assert manifest["claim_status_report_path"].endswith("claim_status_report.md")
    assert manifest["claim_status_report_json_path"].endswith("claim_status_report.json")
    assert manifest["claim_lock_helper_path"].endswith("claim_lock_helper.ps1")
    assert manifest["env_unblock_queue_path"].endswith("env_unblock_queue.md")
    assert manifest["env_unblock_queue_json_path"].endswith("env_unblock_queue.json")
    assert manifest["ready_claims_launcher_path"].endswith("ready_claims_launcher.ps1")
    assert manifest["ready_claims_parallel_launcher_path"].endswith("ready_claims_parallel_launcher.ps1")
    assert manifest["env_bundle_ready_claims_launcher_path"].endswith("env_bundle_ready_claims_launcher.ps1")
    assert manifest["dispatch_prelaunch_validation_path"].endswith("dispatch_prelaunch_validation.ps1")
    assert manifest["dispatch_brief_path"].endswith("dispatch_brief.md")
    assert manifest["dispatch_runner_path"].endswith("dispatch_one_shot_runner.ps1")
    assert Path(manifest["agent_roster_path"]).is_absolute()
    assert Path(manifest["env_checklist_path"]).is_absolute()
    assert Path(manifest["env_template_path"]).is_absolute()
    assert Path(manifest["owner_launch_plan_path"]).is_absolute()
    assert Path(manifest["owner_launch_plan_json_path"]).is_absolute()
    assert Path(manifest["execution_matrix_path"]).is_absolute()
    assert Path(manifest["execution_matrix_json_path"]).is_absolute()
    assert Path(manifest["agent_claims_path"]).is_absolute()
    assert Path(manifest["agent_claims_json_path"]).is_absolute()
    assert Path(manifest["agent_spawn_plan_path"]).is_absolute()
    assert Path(manifest["agent_spawn_plan_json_path"]).is_absolute()
    assert Path(manifest["agent_spawn_launcher_path"]).is_absolute()
    assert Path(manifest["claim_status_report_path"]).is_absolute()
    assert Path(manifest["claim_status_report_json_path"]).is_absolute()
    assert Path(manifest["claim_lock_helper_path"]).is_absolute()
    assert Path(manifest["env_unblock_queue_path"]).is_absolute()
    assert Path(manifest["env_unblock_queue_json_path"]).is_absolute()
    assert Path(manifest["ready_claims_launcher_path"]).is_absolute()
    assert Path(manifest["ready_claims_parallel_launcher_path"]).is_absolute()
    assert Path(manifest["env_bundle_ready_claims_launcher_path"]).is_absolute()
    assert Path(manifest["dispatch_prelaunch_validation_path"]).is_absolute()
    assert Path(manifest["dispatch_brief_path"]).is_absolute()
    assert Path(manifest["dispatch_runner_path"]).is_absolute()
    brief_text = Path(manifest["dispatch_brief_path"]).read_text(encoding="utf-8")
    template_text = Path(manifest["env_template_path"]).read_text(encoding="utf-8")
    owner_plan_text = Path(manifest["owner_launch_plan_path"]).read_text(encoding="utf-8")
    owner_plan_json = json.loads(Path(manifest["owner_launch_plan_json_path"]).read_text(encoding="utf-8"))
    execution_matrix_text = Path(manifest["execution_matrix_path"]).read_text(encoding="utf-8")
    execution_matrix_json = json.loads(Path(manifest["execution_matrix_json_path"]).read_text(encoding="utf-8"))
    agent_claims_text = Path(manifest["agent_claims_path"]).read_text(encoding="utf-8")
    agent_claims_json = json.loads(Path(manifest["agent_claims_json_path"]).read_text(encoding="utf-8"))
    agent_spawn_plan_text = Path(manifest["agent_spawn_plan_path"]).read_text(encoding="utf-8")
    agent_spawn_plan_json = json.loads(Path(manifest["agent_spawn_plan_json_path"]).read_text(encoding="utf-8"))
    agent_spawn_launcher_text = Path(manifest["agent_spawn_launcher_path"]).read_text(encoding="utf-8")
    claim_status_report_text = Path(manifest["claim_status_report_path"]).read_text(encoding="utf-8")
    claim_status_report_json = json.loads(Path(manifest["claim_status_report_json_path"]).read_text(encoding="utf-8"))
    claim_lock_helper_text = Path(manifest["claim_lock_helper_path"]).read_text(encoding="utf-8")
    env_unblock_queue_text = Path(manifest["env_unblock_queue_path"]).read_text(encoding="utf-8")
    env_unblock_queue_json = json.loads(Path(manifest["env_unblock_queue_json_path"]).read_text(encoding="utf-8"))
    ready_claims_launcher_text = Path(manifest["ready_claims_launcher_path"]).read_text(encoding="utf-8")
    ready_claims_parallel_launcher_text = Path(manifest["ready_claims_parallel_launcher_path"]).read_text(encoding="utf-8")
    env_bundle_ready_claims_launcher_text = Path(
        manifest["env_bundle_ready_claims_launcher_path"]
    ).read_text(encoding="utf-8")
    dispatch_prelaunch_validation_text = Path(
        manifest["dispatch_prelaunch_validation_path"]
    ).read_text(encoding="utf-8")
    wave_launcher_text = Path(manifest["launcher_paths"][0]).read_text(encoding="utf-8")
    staged_launcher_text = Path(manifest["staged_launcher_paths"][0]).read_text(encoding="utf-8")
    dispatch_runner_text = Path(manifest["dispatch_runner_path"]).read_text(encoding="utf-8")
    runner_text = Path(manifest["dispatch_runner_path"]).read_text(encoding="utf-8")
    assert "# Validation Dispatch Brief" in brief_text
    assert "Launcher command:" in brief_text
    assert "Env template:" in brief_text
    assert "Owner launch plan:" in brief_text
    assert "Owner launch plan JSON:" in brief_text
    assert "Execution matrix:" in brief_text
    assert "Execution matrix JSON:" in brief_text
    assert "Agent claims:" in brief_text
    assert "Agent claims JSON:" in brief_text
    assert "Agent spawn plan:" in brief_text
    assert "Agent spawn plan JSON:" in brief_text
    assert "Agent spawn launcher:" in brief_text
    assert "Agent spawn launcher command:" in brief_text
    assert "Agent spawn launcher dry-run all command:" in brief_text
    assert "Agent spawn launcher Codex parallel execute command:" in brief_text
    assert "Agent spawn launcher Claude parallel execute command:" in brief_text
    assert "Agent spawn duplicate-provider override guard:" in brief_text
    assert "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1" in brief_text
    assert "[duplicate-provider-override]" in brief_text
    assert "-Provider all -Phase all -ShowBlocked" in brief_text
    assert "-Provider codex -Phase ready -Execute -Parallel" in brief_text
    assert "-Provider claude -Phase ready -Execute -Parallel" in brief_text
    assert "Claim status report:" in brief_text
    assert "Claim status report JSON:" in brief_text
    assert "Claim status refresh command:" in brief_text
    assert "--refresh-claim-status-report" in brief_text
    assert "Claim lock helper:" in brief_text
    assert "Claim lock command:" in brief_text
    assert "Claim lock list command:" in brief_text
    assert "Claim lock reset command:" in brief_text
    caldera_prompt_path = Path(next(package["prompt_path"] for package in manifest["packages"] if package["package_id"] == "wave-1-caldera"))
    caldera_prompt_text = caldera_prompt_path.read_text(encoding="utf-8")
    assert "Claim lock helper:" in caldera_prompt_text
    assert "Claim lock command:" in caldera_prompt_text
    assert "-ClaimId claim-wave-1-caldera" in caldera_prompt_text
    assert "Env unblock queue:" in brief_text
    assert "Env unblock queue JSON:" in brief_text
    assert "Ready claims launcher:" in brief_text
    assert "Ready claims sequential validation command:" in brief_text
    assert "Ready claims command:" in brief_text
    assert "TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH" in brief_text
    assert "Ready claims parallel launcher:" in brief_text
    assert "Ready claims validation command:" in brief_text
    assert "Ready claims parallel command:" in brief_text
    assert "Env-bundle ready claims launcher:" in brief_text
    assert "Env-bundle validation command:" in brief_text
    assert "-ValidateOnly" in brief_text
    assert "Env-bundle ready claims command:" in brief_text
    assert "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH" in brief_text
    assert "Dispatch prelaunch validation:" in brief_text
    assert "Dispatch prelaunch validation command:" in brief_text
    assert "Dispatch prelaunch env-bundle validation command:" in brief_text
    assert "## Recommended Launch Sequence" in brief_text
    assert "1. Dispatch prelaunch validation:" in brief_text
    assert "This runs no-execution checks" in brief_text
    assert "1c. Optional env-bundle prelaunch validation after env fill:" in brief_text
    assert "This prints Codex/Claude spawn commands" in brief_text
    assert "1a. Optional Codex parallel agent execution:" in brief_text
    assert "1b. Optional Claude parallel agent execution:" in brief_text
    assert "Use one provider per claim" in brief_text
    assert "Duplicate-provider execution requires both `-AllowDuplicateProviderPerClaim`" in brief_text
    assert "2. Ready package claims:" in brief_text
    assert "Validate first without launching:" in brief_text
    assert "This launcher runs package scripts directly" in brief_text
    assert "3. Fill env bundle:" in brief_text
    assert "4. Post-env-bundle package claims:" in brief_text
    assert "Validate first without launching:" in brief_text
    assert "5. Refresh claim status:" in brief_text
    assert "## Dependency-Gated Continuation" in brief_text
    assert "Run this after the recommended launch sequence and claim-status refresh" in brief_text
    assert "Wave 1 staged continuation:" in brief_text
    if "Wave 2" in brief_text:
        assert "Wave 2 staged continuation:" in brief_text
        assert "$env:TAMANDUA_ALLOW_DEPENDENT_WAVE_LAUNCH = '1'" in brief_text
        assert "Requires waves `1` evidence to be green before launch." in brief_text
    if "Wave 3" in brief_text:
        assert "Wave 3 closure handoff:" in brief_text
        assert "Requires waves `1`, `2` evidence to be green before launch." in brief_text
    assert "Staged command:" in brief_text
    assert "One-shot command:" in brief_text
    assert "Handoff notes" in brief_text
    assert "wave-1-staged-launcher.ps1" in brief_text
    assert "TAMANDUA_ALLOW_ONE_SHOT_DISPATCH" in runner_text
    assert "$DispatchFailures = @()" in runner_text
    assert "$FailedWaves = @{}" in runner_text
    assert "$DispatchManifestPath =" in runner_text
    assert "ClaimLockHelperPath" in runner_text
    assert "Missing claim lock helper" in runner_text
    assert "-File $script:ClaimLockHelperPath -ClaimId $ClaimId -AgentId $script:DispatchAgentId" in runner_text
    assert "claim lock exit" in runner_text
    assert "Test-DispatchWaveDependencies" in runner_text
    assert "skipped because dependency wave failed" in runner_text
    assert "skipped because dependency evidence missing" in runner_text
    assert "missing_dependency_packages" in runner_text
    assert "quality_gate_not_passed" in runner_text
    assert "{ continue }" not in runner_text
    assert "Invoke-DispatchCommand" in runner_text
    assert "Dispatch one-shot completed with failures" in runner_text
    assert "wave 1 staged launcher" in runner_text
    assert "refresh dispatch handoff artifacts" in runner_text
    assert "--refresh-dispatch-handoff-artifacts" in runner_text
    assert "--promote-dispatch-results" in runner_text
    assert "validation_status_consistency.py" in runner_text
    assert "# Validation env handoff template" in template_text
    assert "$env:CALDERA_API_KEY = '<set-caldera-api-key-secret>'" in template_text
    assert "$env:CALDERA_AGENT_PAW = '<set-caldera-agent-paw>'" in template_text
    assert "# Validation Owner Launch Plan" in owner_plan_text
    assert "## Owner: operator-or-secret-holder" in owner_plan_text
    assert "powershell -NoProfile -ExecutionPolicy Bypass -File" in owner_plan_text
    assert owner_plan_json["artifact"] == "validation-owner-launch-plan"
    assert owner_plan_json["package_count"] == 3
    assert owner_plan_json["launchable_package_count"] >= 1
    assert owner_plan_json["blocked_package_count"] >= 1
    assert any(owner["owner"] == "operator-or-secret-holder" for owner in owner_plan_json["owners"])
    caldera_owner = next(owner for owner in owner_plan_json["owners"] if owner["owner"] == "operator-or-secret-holder")
    caldera_package = next(package for package in caldera_owner["packages"] if package["package_id"] == "wave-1-caldera")
    assert caldera_package["ready_to_launch"] is False
    assert "missing_effective_env" in caldera_package["blocked_reasons"]
    assert caldera_package["current_status"] == "not_run"
    assert caldera_package["current_artifacts"] == []
    assert "# Validation Execution Matrix" in execution_matrix_text
    assert execution_matrix_json["artifact"] == "validation-execution-matrix"
    assert execution_matrix_json["package_count"] == 3
    assert any(row["package_id"] == "wave-1-caldera" for row in execution_matrix_json["rows"])
    assert "# Validation Agent Claims" in agent_claims_text
    assert agent_claims_json["artifact"] == "validation-agent-claims"
    assert agent_claims_json["claim_count"] == 3
    assert any(claim["claim_id"] == "claim-wave-1-caldera" for claim in agent_claims_json["claims"])
    assert "# Validation Agent Spawn Plan" in agent_spawn_plan_text
    assert agent_spawn_plan_json["artifact"] == "validation-agent-spawn-plan"
    assert agent_spawn_plan_json["ready_claim_count"] == 1
    assert agent_spawn_plan_json["env_bundle_ready_claim_count"] == 1
    assert agent_spawn_plan_json["env_bundle_still_blocked_claim_count"] == 0
    assert agent_spawn_plan_json["execute_policy"] == {
        "one_provider_per_claim": True,
        "override_env": "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM",
        "override_switch": "-AllowDuplicateProviderPerClaim",
        "parallel_switch": "-Parallel",
    }
    assert agent_spawn_plan_json["not_multi_agent_actionable_reason"] == "fewer than two ready claims"
    assert "claim-wave-1-windows-high" in agent_spawn_plan_text
    assert "Execute policy: one provider per claim" in agent_spawn_plan_text
    assert "Ready After Env Bundle" in agent_spawn_plan_text
    assert "Copy/Paste Env-Bundle Spawn Prompts" in agent_spawn_plan_text
    assert "Copy/Paste Spawn Prompts" in agent_spawn_plan_text
    assert "Codex spawn template:" in agent_spawn_plan_text
    assert "Claude spawn template:" in agent_spawn_plan_text
    assert "# Validation Agent Spawn Launcher" in agent_spawn_launcher_text
    assert "[ValidateSet('codex','claude','all')]" in agent_spawn_launcher_text
    assert "[ValidateSet('ready','env-bundle','all')]" in agent_spawn_launcher_text
    assert "[switch]$ShowBlocked" in agent_spawn_launcher_text
    assert "[switch]$AllowDuplicateProviderPerClaim" in agent_spawn_launcher_text
    assert "[switch]$Parallel" in agent_spawn_launcher_text
    assert "Group-Object claim_id" in agent_spawn_launcher_text
    assert "Refusing to execute multiple providers for the same claim" in agent_spawn_launcher_text
    assert "TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM" in agent_spawn_launcher_text
    assert "Refusing duplicate provider execution without TAMANDUA_ALLOW_DUPLICATE_PROVIDER_PER_CLAIM=1" in agent_spawn_launcher_text
    assert "[duplicate-provider-override]" in agent_spawn_launcher_text
    assert "Start-Job -Name ($Row.provider + '-' + $Row.claim_id)" in agent_spawn_launcher_text
    assert "Remove-Job -Job $Job -Force" in agent_spawn_launcher_text
    assert "Agent spawn parallel execution failed" in agent_spawn_launcher_text
    assert "AgentId may only contain letters" in agent_spawn_launcher_text
    assert "$SawResult = $false" in agent_spawn_launcher_text
    assert "produced no result" in agent_spawn_launcher_text
    assert "Agent spawn sequential execution failed" in agent_spawn_launcher_text
    assert "Show-BlockedClaims" in agent_spawn_launcher_text
    assert "$Plan.blocked_or_manual_claims" in agent_spawn_launcher_text
    assert "[blocked][" in agent_spawn_launcher_text
    assert "TAMANDUA_ALLOW_AGENT_SPAWN_LAUNCH" in agent_spawn_launcher_text
    assert "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH" in agent_spawn_launcher_text
    assert "Refusing to execute env-bundle spawn commands without TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH=1" in agent_spawn_launcher_text
    assert "Dry run only" in agent_spawn_launcher_text
    assert "Invoke-Expression $Row.command" in agent_spawn_launcher_text
    assert agent_spawn_plan_json["batches"][0]["claims"][0]["claim_id"] == "claim-wave-1-windows-high"
    assert agent_spawn_plan_json["env_bundle_ready_batches"][0]["claims"][0]["claim_id"] == "claim-wave-1-caldera"
    spawn_claim = agent_spawn_plan_json["batches"][0]["claims"][0]
    assert spawn_claim["cwd"] == "."
    assert spawn_claim["claim_id_env"] == "TAMANDUA_AGENT_CLAIM_ID=claim-wave-1-windows-high"
    assert spawn_claim["agent_id_env"] == "TAMANDUA_AGENT_ID=<agent-id>"
    assert "claim-wave-1-windows-high" in spawn_claim["agent_spawn_command_templates"]["codex"]
    assert "claim-wave-1-windows-high" in spawn_claim["agent_spawn_command_templates"]["claude"]
    assert spawn_claim["prompt_path"] in spawn_claim["agent_spawn_command_templates"]["codex"]
    assert spawn_claim["prompt_path"] in spawn_claim["agent_spawn_command_templates"]["claude"]
    assert "claim_lock_helper.ps1" in spawn_claim["agent_spawn_command_templates"]["codex"]
    assert "claim_lock_helper.ps1" in spawn_claim["agent_spawn_command_templates"]["claude"]
    assert "TAMANDUA_CLAIM_LOCK_ACQUIRED='1'" in spawn_claim["agent_spawn_command_templates"]["codex"]
    assert "TAMANDUA_CLAIM_LOCK_ACQUIRED='1'" in spawn_claim["agent_spawn_command_templates"]["claude"]
    assert spawn_claim["prompt_text"]
    assert spawn_claim["copy_paste_prompt"] in agent_spawn_plan_text
    assert any(claim["claim_id"] == "claim-wave-1-caldera" for claim in agent_spawn_plan_json["blocked_or_manual_claims"])
    assert "--refresh-claim-status-report" in agent_spawn_plan_text
    assert "# Validation Claim Status Report" in claim_status_report_text
    assert claim_status_report_json["artifact"] == "validation-claim-status-report"
    assert claim_status_report_json["claim_count"] == 3
    assert claim_status_report_json["locked_claim_count"] == 0
    assert claim_status_report_json["invalid_lock_count"] == 0
    assert "Locked claims: `0`" in claim_status_report_text
    assert "Lock agent" in claim_status_report_text
    assert "Agent claim" in claim_status_report_text
    assert "Agent id" in claim_status_report_text
    assert any(claim["claim_id"] == "claim-wave-1-caldera" for claim in claim_status_report_json["claims"])
    assert "# Validation Claim Lock Helper" in claim_lock_helper_text
    assert "CreateNew" in claim_lock_helper_text
    assert "[switch]$List" in claim_lock_helper_text
    assert "[string]$ResetClaimId" in claim_lock_helper_text
    assert "[switch]$ResetAll" in claim_lock_helper_text
    assert "Refusing to reset claim lock without -Force" in claim_lock_helper_text
    assert "claim-wave-1-caldera" in claim_lock_helper_text
    assert "# Validation Env Unblock Queue" in env_unblock_queue_text
    assert env_unblock_queue_json["artifact"] == "validation-env-unblock-queue"
    assert env_unblock_queue_json["env_count"] >= 1
    caldera_unblock_entry = next(entry for entry in env_unblock_queue_json["entries"] if entry["env"] == "CALDERA_API_KEY")
    assert caldera_unblock_entry["placeholder"] == "<set-caldera-api-key-secret>"
    assert caldera_unblock_entry["powershell_set_command"] == "$env:CALDERA_API_KEY = '<set-caldera-api-key-secret>'"
    assert caldera_unblock_entry["single_env_ready_claim_ids"] == []
    assert caldera_unblock_entry["single_env_still_blocked_claim_ids"] == ["claim-wave-1-caldera"]
    assert caldera_unblock_entry["remaining_env_after_setting"] == {"claim-wave-1-caldera": ["CALDERA_AGENT_PAW"]}
    assert "Immediate claims unlocked by this env:" in caldera_unblock_entry["copy_paste_unblock_prompt"]
    assert "Claims ready after setting only this env:" in caldera_unblock_entry["copy_paste_unblock_prompt"]
    assert env_unblock_queue_json["ready_after_all_env_claim_ids"] == ["claim-wave-1-caldera"]
    assert env_unblock_queue_json["still_blocked_after_all_env_claim_ids"] == []
    assert env_unblock_queue_json["post_env_bundle_launcher_commands"] == [
        "$env:TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH = '1'",
        f"powershell -NoProfile -ExecutionPolicy Bypass -File '{manifest['env_bundle_ready_claims_launcher_path']}'",
    ]
    assert (
        env_unblock_queue_json["env_bundle_validation_command"]
        == f"powershell -NoProfile -ExecutionPolicy Bypass -File '{manifest['env_bundle_ready_claims_launcher_path']}' -ValidateOnly"
    )
    assert "$env:CALDERA_API_KEY = '<set-caldera-api-key-secret>'" in env_unblock_queue_json[
        "all_env_powershell_set_commands"
    ]
    assert "Copy/Paste Env Unblock Commands" in env_unblock_queue_text
    assert "Copy/Paste Complete Env Bundle" in env_unblock_queue_text
    assert "Copy/Paste Env-Bundle Validation" in env_unblock_queue_text
    assert "-ValidateOnly" in env_unblock_queue_text
    assert "Copy/Paste Post-Env-Bundle Launcher" in env_unblock_queue_text
    assert "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH" in env_unblock_queue_text
    assert "env_bundle_ready_claims_launcher.ps1" in env_unblock_queue_text
    assert "Claims ready after all envs:" in env_unblock_queue_text
    assert "$env:CALDERA_API_KEY = '<set-caldera-api-key-secret>'" in env_unblock_queue_text
    assert "# Validation Ready Claims Launcher" in ready_claims_launcher_text
    assert "[switch]$ValidateOnly" in ready_claims_launcher_text
    assert "Ready claims validation passed. Ready claims:" in ready_claims_launcher_text
    assert "TAMANDUA_ALLOW_READY_CLAIMS_LAUNCH" in ready_claims_launcher_text
    assert "TAMANDUA_READY_CLAIMS_AGENT_ID" in ready_claims_launcher_text
    assert "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId" in ready_claims_launcher_text
    assert "$env:TAMANDUA_AGENT_ID = $script:ReadyClaimAgentId" in ready_claims_launcher_text
    assert "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'" in ready_claims_launcher_text
    assert "claim_lock_helper.ps1" in ready_claims_launcher_text
    assert "Invoke-ClaimStatusRefresh" in ready_claims_launcher_text
    assert "--refresh-claim-status-report" in ready_claims_launcher_text
    assert "claim-wave-1-windows-high" in ready_claims_launcher_text
    assert "claim-wave-1-caldera" not in ready_claims_launcher_text
    assert "# Validation Ready Claims Parallel Launcher" in ready_claims_parallel_launcher_text
    assert "[switch]$ValidateOnly" in ready_claims_parallel_launcher_text
    assert "Ready claims validation passed. Ready claims:" in ready_claims_parallel_launcher_text
    assert "TAMANDUA_READY_CLAIMS_AGENT_ID" in ready_claims_parallel_launcher_text
    assert "$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId" in ready_claims_parallel_launcher_text
    assert "$env:TAMANDUA_AGENT_ID = $InnerAgentId" in ready_claims_parallel_launcher_text
    assert "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'" in ready_claims_parallel_launcher_text
    assert "Phase = 'auth-env'" in ready_claims_parallel_launcher_text
    assert "Phase = 'auth-login'" in ready_claims_parallel_launcher_text
    assert "$InnerTokenLoginCommand" in ready_claims_parallel_launcher_text
    assert "claim_lock_helper.ps1" in ready_claims_parallel_launcher_text
    assert "Invoke-ClaimStatusRefresh" in ready_claims_parallel_launcher_text
    assert "--refresh-claim-status-report" in ready_claims_parallel_launcher_text
    assert "Start-Job" in ready_claims_parallel_launcher_text
    assert "Wait-ReadyClaimBatch" in ready_claims_parallel_launcher_text
    assert "claim-wave-1-windows-high" in ready_claims_parallel_launcher_text
    assert "claim-wave-1-caldera" not in ready_claims_parallel_launcher_text
    assert "# Validation Env-Bundle Ready Claims Launcher" in env_bundle_ready_claims_launcher_text
    assert "[switch]$ValidateOnly" in env_bundle_ready_claims_launcher_text
    assert "Env bundle validation passed. Ready claims:" in env_bundle_ready_claims_launcher_text
    assert "TAMANDUA_ALLOW_ENV_BUNDLE_CLAIMS_LAUNCH" in env_bundle_ready_claims_launcher_text
    assert "TAMANDUA_ENV_BUNDLE_CLAIMS_AGENT_ID" in env_bundle_ready_claims_launcher_text
    assert "$env:TAMANDUA_AGENT_CLAIM_ID = $InnerClaimId" in env_bundle_ready_claims_launcher_text
    assert "$env:TAMANDUA_AGENT_ID = $InnerAgentId" in env_bundle_ready_claims_launcher_text
    assert "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'" in env_bundle_ready_claims_launcher_text
    assert "env_unblock_queue.json" in env_bundle_ready_claims_launcher_text
    assert "Missing env bundle values" in env_bundle_ready_claims_launcher_text
    assert "Placeholder env bundle values must be replaced before launch" in env_bundle_ready_claims_launcher_text
    assert "$PlaceholderEnv" in env_bundle_ready_claims_launcher_text
    assert "^<set-.+>$" in env_bundle_ready_claims_launcher_text
    assert "claim_lock_helper.ps1" in env_bundle_ready_claims_launcher_text
    assert "Invoke-ClaimStatusRefresh" in env_bundle_ready_claims_launcher_text
    assert "--refresh-claim-status-report" in env_bundle_ready_claims_launcher_text
    assert "Start-Job" in env_bundle_ready_claims_launcher_text
    assert "Wait-EnvBundleClaimBatch" in env_bundle_ready_claims_launcher_text
    assert "Phase = 'auth-env'" in env_bundle_ready_claims_launcher_text
    assert "Phase = 'auth-login'" in env_bundle_ready_claims_launcher_text
    assert "$InnerTokenLoginCommand" in env_bundle_ready_claims_launcher_text
    assert "claim-wave-1-caldera" in env_bundle_ready_claims_launcher_text
    assert "claim-wave-1-windows-high" not in env_bundle_ready_claims_launcher_text
    assert "# Validation Dispatch Prelaunch Validation" in dispatch_prelaunch_validation_text
    assert "[switch]$ValidateEnvBundle" in dispatch_prelaunch_validation_text
    assert "Invoke-PrelaunchStep 'agent spawn dry run'" in dispatch_prelaunch_validation_text
    assert "-Provider', 'all', '-Phase', 'all', '-ShowBlocked'" in dispatch_prelaunch_validation_text
    assert "Invoke-PrelaunchStep 'ready claims sequential validate-only'" in dispatch_prelaunch_validation_text
    assert "Invoke-PrelaunchStep 'ready claims parallel validate-only'" in dispatch_prelaunch_validation_text
    assert "Invoke-PrelaunchStep 'claim lock list'" in dispatch_prelaunch_validation_text
    assert "if ($ValidateEnvBundle)" in dispatch_prelaunch_validation_text
    assert "Invoke-PrelaunchStep 'env bundle validate-only'" in dispatch_prelaunch_validation_text
    assert "env bundle validate-only skipped" in dispatch_prelaunch_validation_text
    assert "Dispatch prelaunch validation passed." in dispatch_prelaunch_validation_text
    assert "TAMANDUA_WAVE_LAUNCHER_AGENT_ID" in wave_launcher_text
    assert "ClaimLockHelperPath" in wave_launcher_text
    assert "Missing claim lock helper" in wave_launcher_text
    assert "-File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId" in wave_launcher_text
    assert "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId" in wave_launcher_text
    assert "$env:TAMANDUA_AGENT_ID = $AgentId" in wave_launcher_text
    assert "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'" in wave_launcher_text
    assert "TAMANDUA_STAGED_LAUNCHER_AGENT_ID" in staged_launcher_text
    assert "ClaimLockHelperPath" in staged_launcher_text
    assert "Missing claim lock helper" in staged_launcher_text
    assert "-File $ClaimLockHelperPath -ClaimId $ClaimId -AgentId $AgentId" in staged_launcher_text
    assert "$env:TAMANDUA_AGENT_CLAIM_ID = $ClaimId" in staged_launcher_text
    assert "$env:TAMANDUA_AGENT_ID = $AgentId" in staged_launcher_text
    assert "$env:TAMANDUA_CLAIM_LOCK_ACQUIRED = '1'" in staged_launcher_text
    assert "TAMANDUA_DISPATCH_AGENT_ID" in dispatch_runner_text
    assert "claim_id = 'claim-' + [string]$Package.package_id" in dispatch_runner_text
    assert "agent_id = $script:DispatchAgentId" in dispatch_runner_text
    assert "`wave-1-windows-low` | manual: resource overlap: windows-lab" in brief_text
    assert "`wave-1-windows-low` | manual: resource overlap: windows-lab | stage 2" in brief_text
    assert "`CALDERA_API_KEY`" in brief_text
    assert str(manifest_path).replace("\\", "/") in brief_text
    assert by_id["wave-1-windows-high"]["launcher_selected"] is True
    assert by_id["wave-1-windows-high"]["staged_launcher_selected"] is True
    assert by_id["wave-1-windows-high"]["staged_stage"] == 1
    assert by_id["wave-1-windows-low"]["launcher_selected"] is False
    assert by_id["wave-1-windows-low"]["manual_reason"] == "resource overlap: windows-lab"
    assert by_id["wave-1-windows-low"]["staged_launcher_selected"] is True
    assert by_id["wave-1-windows-low"]["staged_stage"] == 2
    assert by_id["wave-1-windows-low"]["handoff_notes"] == [
        "parallelizable",
        "parallel-launcher:manual:resource overlap: windows-lab",
        "staged-launcher:stage-2",
    ]
    assert by_id["wave-1-caldera"]["required_env"] == ["CALDERA_API_KEY", "CALDERA_AGENT_PAW"]
    assert by_id["wave-1-caldera"]["expected_profile_ids"] == ["caldera-api-shape-probe"]
    assert by_id["wave-1-caldera"]["safe_commands"] == [
        "python tools/detection_validation/caldera_api_shape_probe.py --output-dir $Out"
    ]
    assert by_id["wave-1-caldera"]["status_path"].endswith("wave-1-caldera/agent_status.json") or by_id[
        "wave-1-caldera"
    ]["status_path"].endswith("wave-1-caldera\\agent_status.json")
    assert by_id["wave-1-caldera"]["claim_output_contract"] == {
        "output_dir": "package output directory",
        "required_json_profile_ids": ["caldera-api-shape-probe"],
        "status_file": "agent_status.json",
        "status_required_fields": [
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
        ],
        "status_allowed_values": ["pass", "fail", "blocked"],
    }
    assert by_id["wave-1-caldera"]["operator_inputs"][0]["env"] == "CALDERA_AGENT_PAW"
    assert by_id["wave-1-caldera"]["env_details"]["CALDERA_AGENT_PAW"] == {
        "name": "caldera_agent_paw",
        "flag": "--caldera-agent-paw",
        "description": "fresh target PAW",
    }
    assert by_id["wave-1-caldera"]["env_details"]["CALDERA_API_KEY"] == {
        "name": "",
        "flag": "",
        "description": "",
    }
    assert by_id["wave-1-caldera"]["manual_prerequisites"] == ["Use a disposable lab VM."]
    assert by_id["wave-1-windows-high"]["continue_on_failure"] is False
    assert Path(manifest["output_dir"]).is_absolute()
    assert Path(manifest["launcher_paths"][0]).is_absolute()
    assert Path(manifest["staged_launcher_paths"][0]).is_absolute()
    assert Path(by_id["wave-1-caldera"]["script_path"]).is_absolute()
    assert Path(by_id["wave-1-caldera"]["prompt_path"]).is_absolute()
    assert Path(by_id["wave-1-caldera"]["output_dir"]).is_absolute()
    assert by_id["wave-1-caldera"]["prompt_path"].endswith("wave-1-caldera.agent.md")
    assert by_id["wave-1-caldera"]["output_dir"].endswith("wave-1-caldera\\outputs") or by_id[
        "wave-1-caldera"
    ]["output_dir"].endswith("wave-1-caldera/outputs")

    for package in manifest["packages"]:
        if package["package_id"] == "wave-1-caldera":
            package["resource_tags"] = ["operator-env"]
            break
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    preflight_work_package.refresh_dispatch_handoff_artifacts_from_manifest(manifest_path)
    refreshed_roster_text = Path(manifest["agent_roster_path"]).read_text(encoding="utf-8")
    refreshed_prompt_text = caldera_prompt_path.read_text(encoding="utf-8")
    refreshed_brief_text = Path(manifest["dispatch_brief_path"]).read_text(encoding="utf-8")
    assert "`wave-1-caldera` | operator-or-secret-holder | auto | `operator-env`" in refreshed_roster_text
    assert "Resource tags: operator-env" in refreshed_prompt_text
    assert "`wave-1-caldera` | auto | stage 1 | operator-or-secret-holder | `operator-env`" in refreshed_brief_text


def test_preflight_work_package_summarizes_dispatch_results(tmp_path):
    output_dir = tmp_path / "dispatch"
    pass_dir = output_dir / "wave-1-pass" / "outputs"
    fail_dir = output_dir / "wave-1-fail" / "outputs"
    missing_dir = output_dir / "wave-1-missing" / "outputs"
    pass_dir.mkdir(parents=True)
    fail_dir.mkdir(parents=True)
    missing_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(pass_dir),
            },
            {
                "package_id": "wave-1-fail",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["windows-lab"],
                "required_env": [],
                "expected_profile_ids": ["fail-probe"],
                "output_dir": str(fail_dir),
                "status_path": str(output_dir / "wave-1-fail" / "agent_status.json"),
            },
            {
                "package_id": "wave-1-missing",
                "wave": 1,
                "launcher_selected": False,
                "manual_reason": "resource overlap: windows-lab",
                "resource_tags": ["windows-lab"],
                "required_env": [],
                "expected_profile_ids": ["missing-probe"],
                "output_dir": str(missing_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (pass_dir / "20260603T100000Z-pass-probe.json").write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (fail_dir / "20260603T100000Z-fail-probe.json").write_text(
        '{"profile_id":"fail-probe","quality_gate":{"status":"fail","passed":false,'
        '"blocking_gaps":["target_offline"],"failures":["fail_probe_gaps"]},'
        '"tests":[{"id":"target-online","status":"missed",'
        '"missing_expected_fields":["online_agent"],"gap_category":"infrastructure",'
        '"evidence":{"target":{"hostname":"WIN-TEMPLATE","status":"offline",'
        '"last_seen":"2026-06-03T15:23:52","endpoint_telemetry":"not_observed"}}}]}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-fail" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-fail",
                "status": "blocked",
                "artifacts": [str(fail_dir / "20260603T100000Z-fail-probe.json")],
                "blocker_cleared": False,
                "notes": ["missing_effective_env: TAMANDUA_SERVER_PASSWORD"],
                "exit_code": 2,
                "expected_profiles": ["fail-probe"],
                "missing_profiles": ["fail-probe"],
            }
        ),
        encoding="utf-8",
    )

    old_repo_root = preflight_work_package.REPO_ROOT
    preflight_work_package.REPO_ROOT = tmp_path
    try:
        json_path, markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    finally:
        preflight_work_package.REPO_ROOT = old_repo_root
    results = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    by_id = {package["package_id"]: package for package in results["packages"]}

    assert markdown_path.exists()
    assert "## Required Env Blockers" in markdown
    assert "## Owner Handoff" in markdown
    assert "## Owner Package Queue" in markdown
    assert "| `unassigned` | 3 | 1 | 1 | 0 | `TAMANDUA_SERVER_PASSWORD` | - |" in markdown
    assert "| `unassigned` | `wave-1-fail` | 1 | `blocked` | - | - | false | - |" in markdown
    assert "| `wave-1-fail` | 1 | `-` | - | `TAMANDUA_SERVER_PASSWORD` | - |" in markdown
    assert results["passed_count"] == 1
    assert results["failed_count"] == 2
    assert results["status_counts"] == {
        "pass": 1,
        "fail": 0,
        "blocked": 1,
        "missing": 1,
        "invalid": 0,
        "unknown": 0,
    }
    assert results["blocked_count"] == 1
    assert results["failed_status_count"] == 0
    assert results["missing_count"] == 1
    assert results["invalid_count"] == 0
    assert results["missing_required_env"] == ["TAMANDUA_SERVER_PASSWORD"]
    assert results["owner_handoff"] == [
        {
            "owner": "unassigned",
            "package_count": 3,
            "passed_count": 1,
            "blocked_count": 1,
            "failed_status_count": 0,
            "missing_count": 1,
            "invalid_count": 0,
            "packages": [
                {
                    "package_id": "wave-1-pass",
                    "wave": 1,
                    "status": "pass",
                    "title": None,
                    "parallelizable_in_wave": None,
                    "depends_on_waves": [],
                    "handoff_notes": [],
                },
                {
                    "package_id": "wave-1-fail",
                    "wave": 1,
                    "status": "blocked",
                    "title": None,
                    "parallelizable_in_wave": None,
                    "depends_on_waves": [],
                    "handoff_notes": [],
                },
                {
                    "package_id": "wave-1-missing",
                    "wave": 1,
                    "status": "missing",
                    "title": None,
                    "parallelizable_in_wave": None,
                    "depends_on_waves": [],
                    "handoff_notes": [],
                },
            ],
            "missing_required_env": ["TAMANDUA_SERVER_PASSWORD"],
            "roadmaps": [],
        }
    ]
    assert results["required_env_blockers"] == [
        {
            "package_id": "wave-1-fail",
            "wave": 1,
            "title": None,
            "recommended_owner_role": None,
            "status": "blocked",
            "roadmaps": [],
            "blocking_profiles": [],
            "blocked_run_classes": [],
            "missing_required_env": ["TAMANDUA_SERVER_PASSWORD"],
            "declared_required_env": [],
        }
    ]
    assert by_id["wave-1-pass"]["passed"] is True
    assert not Path(by_id["wave-1-pass"]["artifact_path"]).is_absolute()
    assert by_id["wave-1-pass"]["profile_results"][0]["artifact_path"] == by_id["wave-1-pass"]["artifact_path"]
    assert str(tmp_path) not in markdown
    assert str(tmp_path).replace("\\", "/") not in markdown
    assert by_id["wave-1-fail"]["status"] == "blocked"
    assert by_id["wave-1-fail"]["agent_status"] == "blocked"
    assert by_id["wave-1-fail"]["agent_exit_code"] == 2
    assert by_id["wave-1-fail"]["agent_missing_required_env"] == ["TAMANDUA_SERVER_PASSWORD"]
    assert by_id["wave-1-fail"]["failures"] == ["fail_probe_gaps", "agent_status_blocked"]
    assert by_id["wave-1-fail"]["blocking_gaps"] == ["target_offline"]
    assert by_id["wave-1-fail"]["first_gap"]["test_id"] == "target-online"
    assert by_id["wave-1-fail"]["first_gap"]["missing"] == ["online_agent"]
    assert by_id["wave-1-fail"]["evidence_excerpt"]["agent"]["hostname"] == "WIN-TEMPLATE"
    assert by_id["wave-1-fail"]["evidence_excerpt"]["agent"]["status"] == "offline"
    assert by_id["wave-1-missing"]["failures"][0] == "missing_expected_profile_artifact"
    assert by_id["wave-1-missing"]["missing_expected_profiles"] == ["missing-probe"]


def test_preflight_work_package_rejects_mistyped_agent_status_contract(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260603T100000Z-pass-probe.json").write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(package_dir / "20260603T100000Z-pass-probe.json")],
                "blocker_cleared": "false",
                "notes": [],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["agent_status"] == "invalid"
    assert package["agent_blocker_cleared"] is False
    assert package["failures"] == ["agent_status_invalid"]
    assert package["agent_notes"] == [
        "agent_status_contract_invalid",
        "blocker_cleared_not_bool",
        "exit_code_not_int",
        "expected_profiles_not_list",
        "missing_profiles_not_list",
    ]


def test_preflight_work_package_rejects_non_string_agent_status_lists(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(artifact)],
                "blocker_cleared": True,
                "notes": [{"message": "not a string"}],
                "exit_code": 0,
                "expected_profiles": ["pass-probe", 123],
                "missing_profiles": [],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["agent_status"] == "invalid"
    assert package["failures"] == ["agent_status_invalid"]
    assert package["agent_notes"] == [
        "agent_status_contract_invalid",
        "notes_not_string_list",
        "expected_profiles_not_string_list",
    ]


def test_preflight_work_package_rejects_blank_agent_status_list_entries(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(artifact)],
                "blocker_cleared": True,
                "notes": ["  "],
                "exit_code": 0,
                "expected_profiles": ["pass-probe"],
                "missing_profiles": [""],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["agent_status"] == "invalid"
    assert package["failures"] == ["agent_status_invalid"]
    assert package["agent_notes"] == [
        "agent_status_contract_invalid",
        "notes_has_blank_entry",
        "missing_profiles_has_blank_entry",
    ]


def test_preflight_work_package_rejects_unexpected_agent_status_path(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    external_status = output_dir / "other-package" / "agent_status.json"
    external_status.parent.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(external_status),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    external_status.write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(artifact)],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 0,
                "expected_profiles": ["pass-probe"],
                "missing_profiles": [],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["agent_status"] == "invalid"
    assert package["failures"] == ["agent_status_invalid"]
    assert package["agent_notes"] == [
        "agent_status_contract_invalid",
        "agent_status_path_unexpected",
    ]


def test_preflight_work_package_rejects_missing_declared_agent_status(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["agent_status"] == "invalid"
    assert package["failures"] == ["agent_status_invalid"]
    assert package["agent_notes"] == [
        "agent_status_contract_invalid",
        "agent_status_missing",
    ]


def test_preflight_work_package_rejects_output_dir_outside_manifest_dir(tmp_path):
    output_dir = tmp_path / "dispatch"
    output_dir.mkdir()
    external_dir = tmp_path / "external-package" / "outputs"
    external_dir.mkdir(parents=True)
    artifact = external_dir / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(external_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["status"] == "fail"
    assert package["artifact_paths"] == []
    assert package["failures"] == ["dispatch_output_dir_outside_manifest"]
    assert package["first_gap"]["test_id"] == "dispatch_output_dir_outside_manifest"


def test_preflight_work_package_rejects_invalid_manifest_package_identity(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "  ",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": "pass-probe",
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-bad-profile",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe", ""],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-missing-tags",
                "wave": 1,
                "launcher_selected": True,
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-empty-tags",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": [],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-bad-tags",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent", " "],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-env",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": "TAMANDUA_SERVER_PASSWORD",
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-bad-env",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": ["TAMANDUA_SERVER_PASSWORD", ""],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-selection",
                "wave": 1,
                "launcher_selected": "true",
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-manual-no-reason",
                "wave": 1,
                "launcher_selected": False,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-auto-with-reason",
                "wave": 1,
                "launcher_selected": True,
                "manual_reason": "resource overlap: macos-agent",
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-staged",
                "wave": 1,
                "launcher_selected": True,
                "staged_launcher_selected": "true",
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-bad-stage",
                "wave": 1,
                "launcher_selected": True,
                "staged_launcher_selected": True,
                "staged_stage": 0,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-missing-wave",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-string-wave",
                "wave": "1",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-zero-wave",
                "wave": 0,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-2-mistyped-dependencies",
                "wave": 2,
                "depends_on_waves": "1",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-2-invalid-dependencies",
                "wave": 2,
                "depends_on_waves": [1, "2"],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-2-non-prior-dependencies",
                "wave": 2,
                "depends_on_waves": [2],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-safe-commands",
                "wave": 1,
                "safe_commands": "python tools/detection_validation/macos_backend_readiness_probe.py --output-dir $Out",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-safe-commands",
                "wave": 1,
                "safe_commands": [
                    "python tools/detection_validation/macos_backend_readiness_probe.py --output-dir $Out",
                    "",
                ],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-unsupported-safe-commands",
                "wave": 1,
                "safe_commands": [
                    "python tools/detection_validation/macos_backend_readiness_probe.py --output-dir $Out; Write-Host unsafe"
                ],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-claim-contract",
                "wave": 1,
                "claim_output_contract": "agent_status.json",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-claim-profiles",
                "wave": 1,
                "claim_output_contract": {
                    "required_json_profile_ids": ["pass-probe", ""],
                    "status_required_fields": preflight_work_package.AGENT_STATUS_REQUIRED_FIELDS,
                    "status_allowed_values": ["pass", "fail", "blocked"],
                },
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mismatched-claim-profiles",
                "wave": 1,
                "claim_output_contract": {
                    "required_json_profile_ids": ["other-probe"],
                    "status_required_fields": preflight_work_package.AGENT_STATUS_REQUIRED_FIELDS,
                    "status_allowed_values": ["pass", "fail", "blocked"],
                },
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-claim-status-fields",
                "wave": 1,
                "claim_output_contract": {
                    "required_json_profile_ids": ["pass-probe"],
                    "status_required_fields": ["package_id", "status"],
                    "status_allowed_values": ["pass", "fail", "blocked"],
                },
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-claim-status-values",
                "wave": 1,
                "claim_output_contract": {
                    "required_json_profile_ids": ["pass-probe"],
                    "status_required_fields": preflight_work_package.AGENT_STATUS_REQUIRED_FIELDS,
                    "status_allowed_values": ["pass"],
                },
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-manual-prerequisites",
                "wave": 1,
                "manual_prerequisites": "Use a disposable lab VM.",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-manual-prerequisites",
                "wave": 1,
                "manual_prerequisites": ["Use a disposable lab VM.", ""],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-operator-inputs",
                "wave": 1,
                "operator_inputs": "CALDERA_API_KEY",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-operator-inputs",
                "wave": 1,
                "operator_inputs": [
                    {
                        "name": "caldera_api_key",
                        "flag": "--caldera-api-key",
                        "env": "",
                        "description": "CALDERA API key",
                    }
                ],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-roadmap-next-actions",
                "wave": 1,
                "roadmap_next_actions": "Provide CALDERA_API_KEY",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-roadmap-next-actions",
                "wave": 1,
                "roadmap_next_actions": [
                    {
                        "roadmap": "D",
                        "roadmap_status": "blocked",
                        "blocking_profiles": ["caldera-api-shape-probe"],
                        "required_env": ["CALDERA_API_KEY", ""],
                        "action": "Provide CALDERA_API_KEY.",
                    }
                ],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-roadmaps",
                "wave": 1,
                "roadmaps": "D",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-roadmaps",
                "wave": 1,
                "roadmaps": ["D", ""],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-blocking-profiles",
                "wave": 1,
                "blocking_profiles": "caldera-api-shape-probe",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-blocking-profiles",
                "wave": 1,
                "blocking_profiles": ["caldera-api-shape-probe", ""],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-blocked-run-classes",
                "wave": 1,
                "blocked_run_classes": "windows-caldera-enterprise",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-blocked-run-classes",
                "wave": 1,
                "blocked_run_classes": ["windows-caldera-enterprise", ""],
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-invalid-owner-role",
                "wave": 1,
                "recommended_owner_role": "",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
            {
                "package_id": "wave-1-mistyped-continue-on-failure",
                "wave": 1,
                "continue_on_failure": "true",
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    packages = results["packages"]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 41
    assert packages[0]["failures"] == ["dispatch_package_id_missing"]
    assert packages[1]["failures"] == ["dispatch_expected_profiles_not_list"]
    assert packages[2]["failures"] == ["dispatch_expected_profiles_invalid"]
    assert packages[3]["failures"] == ["dispatch_resource_tags_not_list"]
    assert packages[4]["failures"] == ["dispatch_resource_tags_empty"]
    assert packages[5]["failures"] == ["dispatch_resource_tags_invalid"]
    assert packages[6]["failures"] == ["dispatch_required_env_not_list"]
    assert packages[7]["failures"] == ["dispatch_required_env_invalid"]
    assert packages[8]["failures"] == ["dispatch_launcher_selected_not_bool"]
    assert packages[9]["failures"] == ["dispatch_manual_reason_missing"]
    assert packages[10]["failures"] == ["dispatch_manual_reason_unexpected"]
    assert packages[11]["failures"] == ["dispatch_staged_launcher_selected_not_bool"]
    assert packages[12]["failures"] == ["dispatch_staged_stage_invalid"]
    assert packages[13]["failures"] == ["dispatch_wave_invalid"]
    assert packages[14]["failures"] == ["dispatch_wave_invalid"]
    assert packages[15]["failures"] == ["dispatch_wave_invalid"]
    assert packages[16]["failures"] == ["dispatch_depends_on_waves_not_list"]
    assert packages[17]["failures"] == ["dispatch_depends_on_waves_invalid"]
    assert packages[18]["failures"] == ["dispatch_depends_on_waves_not_prior"]
    assert packages[19]["failures"] == ["dispatch_safe_commands_not_list"]
    assert packages[20]["failures"] == ["dispatch_safe_commands_invalid"]
    assert packages[21]["failures"] == ["dispatch_safe_commands_unsupported"]
    assert packages[22]["failures"] == ["dispatch_claim_contract_not_dict"]
    assert packages[23]["failures"] == ["dispatch_claim_contract_profiles_invalid"]
    assert packages[24]["failures"] == ["dispatch_claim_contract_profiles_mismatch"]
    assert packages[25]["failures"] == ["dispatch_claim_contract_status_fields_invalid"]
    assert packages[26]["failures"] == ["dispatch_claim_contract_status_values_invalid"]
    assert packages[27]["failures"] == ["dispatch_manual_prerequisites_not_list"]
    assert packages[28]["failures"] == ["dispatch_manual_prerequisites_invalid"]
    assert packages[29]["failures"] == ["dispatch_operator_inputs_not_list"]
    assert packages[30]["failures"] == ["dispatch_operator_inputs_invalid"]
    assert packages[31]["failures"] == ["dispatch_roadmap_next_actions_not_list"]
    assert packages[32]["failures"] == ["dispatch_roadmap_next_actions_invalid"]
    assert packages[33]["failures"] == ["dispatch_roadmaps_not_list"]
    assert packages[34]["failures"] == ["dispatch_roadmaps_invalid"]
    assert packages[35]["failures"] == ["dispatch_blocking_profiles_not_list"]
    assert packages[36]["failures"] == ["dispatch_blocking_profiles_invalid"]
    assert packages[37]["failures"] == ["dispatch_blocked_run_classes_not_list"]
    assert packages[38]["failures"] == ["dispatch_blocked_run_classes_invalid"]
    assert packages[39]["failures"] == ["dispatch_recommended_owner_role_invalid"]
    assert packages[40]["failures"] == ["dispatch_continue_on_failure_not_bool"]
    assert all(package["artifact_paths"] == [] for package in packages)


def test_preflight_work_package_rejects_invalid_dispatch_manifest_metadata(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    base_package = {
        "package_id": "wave-1-pass",
        "wave": 1,
        "launcher_selected": True,
        "resource_tags": ["macos-agent"],
        "required_env": [],
        "expected_profile_ids": ["pass-probe"],
        "output_dir": str(package_dir),
    }
    cases = [
        ({"profile_id": "other-probe"}, "dispatch_manifest_profile_id_invalid"),
        ({"source_preflight": ""}, "dispatch_manifest_source_preflight_missing"),
        ({"packages": "wave-1-pass"}, "dispatch_manifest_packages_not_list"),
        ({"packages": ["wave-1-pass"]}, "dispatch_manifest_packages_invalid"),
        ({"expected_waves": "1"}, "dispatch_manifest_expected_waves_not_list"),
        ({"expected_waves": [True]}, "dispatch_manifest_expected_waves_invalid"),
        ({"expected_waves": [2]}, "dispatch_manifest_expected_waves_mismatch"),
        ({"expected_package_ids": "wave-1-pass"}, "dispatch_manifest_expected_package_ids_not_list"),
        ({"expected_package_ids": [""]}, "dispatch_manifest_expected_package_ids_invalid"),
        ({"expected_package_ids": ["wave-1-other"]}, "dispatch_manifest_expected_package_ids_mismatch"),
        ({"selected_wave": 2}, "dispatch_manifest_selected_wave_invalid"),
        ({"selection_mode": ""}, "dispatch_manifest_selection_mode_invalid"),
        ({"launcher_paths": "wave-1-launcher.ps1"}, "dispatch_manifest_launcher_paths_not_list"),
        ({"launcher_paths": [""]}, "dispatch_manifest_launcher_paths_invalid"),
        ({"launcher_paths": ["..\\outside.ps1"]}, "dispatch_manifest_launcher_paths_outside_manifest"),
        ({"staged_launcher_paths": "wave-1-staged-launcher.ps1"}, "dispatch_manifest_staged_launcher_paths_not_list"),
        ({"staged_launcher_paths": [""]}, "dispatch_manifest_staged_launcher_paths_invalid"),
        (
            {"staged_launcher_paths": ["..\\outside-staged.ps1"]},
            "dispatch_manifest_staged_launcher_paths_outside_manifest",
        ),
        ({"agent_roster_path": ""}, "dispatch_manifest_agent_roster_path_invalid"),
        ({"agent_roster_path": "..\\agent_roster.md"}, "dispatch_manifest_agent_roster_path_outside_manifest"),
        ({"env_checklist_path": ""}, "dispatch_manifest_env_checklist_path_invalid"),
        ({"env_checklist_path": "..\\env_checklist.md"}, "dispatch_manifest_env_checklist_path_outside_manifest"),
        ({"env_template_path": ""}, "dispatch_manifest_env_template_path_invalid"),
        ({"env_template_path": "..\\env_template.ps1"}, "dispatch_manifest_env_template_path_outside_manifest"),
        ({"owner_launch_plan_path": ""}, "dispatch_manifest_owner_launch_plan_path_invalid"),
        ({"owner_launch_plan_path": "..\\owner_launch_plan.md"}, "dispatch_manifest_owner_launch_plan_path_outside_manifest"),
        ({"owner_launch_plan_json_path": ""}, "dispatch_manifest_owner_launch_plan_json_path_invalid"),
        (
            {"owner_launch_plan_json_path": "..\\owner_launch_plan.json"},
            "dispatch_manifest_owner_launch_plan_json_path_outside_manifest",
        ),
        ({"agent_spawn_launcher_path": ""}, "dispatch_manifest_agent_spawn_launcher_path_invalid"),
        (
            {"agent_spawn_launcher_path": "..\\agent_spawn_launcher.ps1"},
            "dispatch_manifest_agent_spawn_launcher_path_outside_manifest",
        ),
        ({"claim_status_report_path": ""}, "dispatch_manifest_claim_status_report_path_invalid"),
        (
            {"claim_status_report_path": "..\\claim_status_report.md"},
            "dispatch_manifest_claim_status_report_path_outside_manifest",
        ),
        ({"claim_status_report_json_path": ""}, "dispatch_manifest_claim_status_report_json_path_invalid"),
        (
            {"claim_status_report_json_path": "..\\claim_status_report.json"},
            "dispatch_manifest_claim_status_report_json_path_outside_manifest",
        ),
        ({"claim_lock_helper_path": ""}, "dispatch_manifest_claim_lock_helper_path_invalid"),
        (
            {"claim_lock_helper_path": "..\\claim_lock_helper.ps1"},
            "dispatch_manifest_claim_lock_helper_path_outside_manifest",
        ),
        ({"ready_claims_launcher_path": ""}, "dispatch_manifest_ready_claims_launcher_path_invalid"),
        (
            {"ready_claims_launcher_path": "..\\ready_claims_launcher.ps1"},
            "dispatch_manifest_ready_claims_launcher_path_outside_manifest",
        ),
        ({"ready_claims_parallel_launcher_path": ""}, "dispatch_manifest_ready_claims_parallel_launcher_path_invalid"),
        (
            {"ready_claims_parallel_launcher_path": "..\\ready_claims_parallel_launcher.ps1"},
            "dispatch_manifest_ready_claims_parallel_launcher_path_outside_manifest",
        ),
        (
            {"env_bundle_ready_claims_launcher_path": ""},
            "dispatch_manifest_env_bundle_ready_claims_launcher_path_invalid",
        ),
        (
            {"env_bundle_ready_claims_launcher_path": "..\\env_bundle_ready_claims_launcher.ps1"},
            "dispatch_manifest_env_bundle_ready_claims_launcher_path_outside_manifest",
        ),
        (
            {"dispatch_prelaunch_validation_path": ""},
            "dispatch_manifest_dispatch_prelaunch_validation_path_invalid",
        ),
        (
            {"dispatch_prelaunch_validation_path": "..\\dispatch_prelaunch_validation.ps1"},
            "dispatch_manifest_dispatch_prelaunch_validation_path_outside_manifest",
        ),
        ({"dispatch_brief_path": ""}, "dispatch_manifest_dispatch_brief_path_invalid"),
        ({"dispatch_brief_path": "..\\dispatch_brief.md"}, "dispatch_manifest_dispatch_brief_path_outside_manifest"),
        ({"dispatch_runner_path": ""}, "dispatch_manifest_dispatch_runner_path_invalid"),
        (
            {"dispatch_runner_path": "..\\dispatch_one_shot_runner.ps1"},
            "dispatch_manifest_dispatch_runner_path_outside_manifest",
        ),
    ]

    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    for index, (override, failure) in enumerate(cases):
        case_dir = output_dir / f"case-{index}"
        case_package_dir = case_dir / "wave-1-pass" / "outputs"
        case_package_dir.mkdir(parents=True)
        (case_package_dir / artifact.name).write_text(artifact.read_text(encoding="utf-8"), encoding="utf-8")
        package = {**base_package, "output_dir": str(case_package_dir)}
        manifest = {
            "profile_id": "validation-execution-preflight-probe",
            "source_preflight": "preflight.json",
            "packages": [package],
            "expected_waves": [1],
            "expected_package_ids": ["wave-1-pass"],
            "selected_wave": 1,
            "selection_mode": "wave",
            **override,
        }
        (case_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        json_path, _ = preflight_work_package.summarize_dispatch(case_dir)
        results = json.loads(json_path.read_text(encoding="utf-8"))
        assert results["passed_count"] == 0, failure
        assert results["failed_count"] == 1, failure
        assert results["manifest_failures"] == [failure]
        assert results["packages"][0]["failures"] == [failure]


def test_preflight_work_package_rejects_agent_status_package_id_mismatch(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260603T100000Z-pass-probe.json").write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-other",
                "claim_id": "claim-wave-1-pass",
                "agent_id": "agent-a",
                "status": "pass",
                "artifacts": [str(package_dir / "20260603T100000Z-pass-probe.json")],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 0,
                "expected_profiles": ["pass-probe"],
                "missing_profiles": [],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["agent_package_id"] == "wave-1-other"
    assert package["agent_status"] == "pass"
    assert package["failures"] == ["agent_status_package_id_mismatch"]


def test_preflight_work_package_rejects_agent_status_claim_id_mismatch(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260603T100000Z-pass-probe.json").write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "claim_id": "claim-wave-1-other",
                "agent_id": "agent-a",
                "status": "pass",
                "artifacts": [str(package_dir / "20260603T100000Z-pass-probe.json")],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 0,
                "expected_profiles": ["pass-probe"],
                "missing_profiles": [],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["agent_package_id"] == "wave-1-pass"
    assert package["agent_claim_id"] == "claim-wave-1-other"
    assert package["agent_id"] == "agent-a"
    assert package["agent_status"] == "pass"
    assert package["failures"] == ["agent_status_claim_id_mismatch"]


def test_preflight_work_package_rejects_agent_status_expected_profiles_mismatch(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(artifact)],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 0,
                "expected_profiles": ["other-probe"],
                "missing_profiles": [],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["agent_expected_profiles"] == ["other-probe"]
    assert package["failures"] == ["agent_status_expected_profiles_mismatch"]


def test_preflight_work_package_rejects_agent_status_artifact_mismatch(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    real_artifact = package_dir / "20260603T100000Z-pass-probe.json"
    stale_artifact = output_dir / "other-package" / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    real_artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(stale_artifact)],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 0,
                "expected_profiles": ["pass-probe"],
                "missing_profiles": [],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["failures"] == ["agent_status_unknown_artifact", "agent_status_missing_artifact"]


def test_preflight_work_package_rejects_pass_status_with_nonzero_exit_code(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(artifact)],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 2,
                "expected_profiles": ["pass-probe"],
                "missing_profiles": [],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["agent_exit_code"] == 2
    assert package["failures"] == ["agent_status_pass_exit_code_nonzero"]


def test_preflight_work_package_records_fail_status_with_zero_exit_code(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-fail" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-fail-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-fail",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["windows-lab"],
                "required_env": [],
                "expected_profile_ids": ["fail-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-fail" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"fail-probe","quality_gate":{"status":"fail","passed":false,'
        '"failures":["fail_probe_gaps"]}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-fail" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-fail",
                "status": "fail",
                "artifacts": [str(artifact)],
                "blocker_cleared": False,
                "notes": ["command_failed"],
                "exit_code": 0,
                "expected_profiles": ["fail-probe"],
                "missing_profiles": ["fail-probe"],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["agent_exit_code"] == 0
    assert package["failures"] == [
        "fail_probe_gaps",
        "agent_status_fail",
        "agent_status_failure_exit_code_zero",
    ]


def test_preflight_work_package_records_failure_status_with_empty_notes(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-blocked" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-blocked-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-blocked",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["windows-lab"],
                "required_env": [],
                "expected_profile_ids": ["blocked-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-blocked" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"blocked-probe","quality_gate":{"status":"fail","passed":false,'
        '"failures":["blocked_probe_gaps"]}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-blocked" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-blocked",
                "status": "blocked",
                "artifacts": [str(artifact)],
                "blocker_cleared": False,
                "notes": [],
                "exit_code": 2,
                "expected_profiles": ["blocked-probe"],
                "missing_profiles": ["blocked-probe"],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["status"] == "blocked"
    assert package["agent_notes"] == []
    assert package["failures"] == [
        "blocked_probe_gaps",
        "agent_status_blocked",
        "agent_status_failure_notes_empty",
    ]


def test_preflight_work_package_rejects_agent_missing_profiles_as_pass(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    second_artifact = package_dir / "20260603T100100Z-second-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe", "second-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    second_artifact.write_text(
        '{"profile_id":"second-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(artifact), str(second_artifact)],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 0,
                "expected_profiles": ["pass-probe", "second-probe"],
                "missing_profiles": ["second-probe"],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["status"] == "missing"
    assert package["missing_expected_profiles"] == ["second-probe"]
    assert package["failures"] == ["agent_status_missing_profiles"]


def test_preflight_work_package_rejects_agent_unexpected_missing_profile(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-pass" / "outputs"
    package_dir.mkdir(parents=True)
    artifact = package_dir / "20260603T100000Z-pass-probe.json"
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["pass-probe"],
                "output_dir": str(package_dir),
                "status_path": str(output_dir / "wave-1-pass" / "agent_status.json"),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text(
        '{"profile_id":"pass-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (output_dir / "wave-1-pass" / "agent_status.json").write_text(
        json.dumps(
            {
                "package_id": "wave-1-pass",
                "status": "pass",
                "artifacts": [str(artifact)],
                "blocker_cleared": True,
                "notes": [],
                "exit_code": 0,
                "expected_profiles": ["pass-probe"],
                "missing_profiles": ["other-probe"],
            }
        ),
        encoding="utf-8",
    )

    json_path, _ = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["status"] == "fail"
    assert package["missing_expected_profiles"] == ["other-probe"]
    assert package["failures"] == [
        "agent_status_missing_profiles",
        "agent_status_unexpected_missing_profile",
    ]


def test_preflight_work_package_marks_missing_expected_profile_failed(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-multi" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-multi",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["windows-lab"],
                "required_env": [],
                "expected_profile_ids": ["first-probe", "second-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260603T100000Z-first-probe.json").write_text(
        '{"profile_id":"first-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )

    json_path, _markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["status"] == "missing"
    assert package["artifact_path"].endswith("first-probe.json")
    assert package["missing_expected_profiles"] == ["second-probe"]
    assert package["failures"][0] == "missing_expected_profile_artifact"


def test_preflight_work_package_marks_unexpected_profile_artifact_failed(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-isolated" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-isolated",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["windows-lab"],
                "required_env": [],
                "expected_profile_ids": ["expected-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260603T100000Z-expected-probe.json").write_text(
        '{"profile_id":"expected-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    (package_dir / "20260603T100100Z-other-probe.json").write_text(
        '{"profile_id":"other-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )

    json_path, _markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]

    assert results["passed_count"] == 0
    assert results["failed_count"] == 1
    assert package["passed"] is False
    assert package["status"] == "fail"
    assert package["missing_expected_profiles"] == []
    assert package["unexpected_profile_ids"] == ["other-probe"]
    assert package["failures"][0] == "unexpected_profile_artifact"


def test_status_consistency_validates_unexpected_profile_artifacts_are_rejected(tmp_path):
    run_id = "20260603T182929Z-validation-dispatch-results-probe"
    package_dir = tmp_path / "docs" / "benchmarks" / "runs" / f"{run_id}.package-artifacts" / "packages" / "wave-1"
    package_dir.mkdir(parents=True)
    expected_path = package_dir / "expected.json"
    unexpected_path = package_dir / "unexpected.json"
    expected_path.write_text(
        '{"profile_id":"expected-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    unexpected_path.write_text(
        '{"profile_id":"unexpected-probe","quality_gate":{"status":"pass","passed":true}}',
        encoding="utf-8",
    )
    artifact = {
        "packages": [
            {
                "package_id": "wave-1",
                "passed": False,
                "failures": ["unexpected_profile_artifact"],
                "expected_profile_ids": ["expected-probe"],
                "unexpected_profile_ids": ["unexpected-probe"],
                "artifact_paths": [
                    f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/expected.json",
                    f"docs/benchmarks/runs/{run_id}.package-artifacts/packages/wave-1/unexpected.json",
                ],
            }
        ]
    }
    old_root = consistency.ROOT
    consistency.ROOT = tmp_path
    try:
        assert consistency.dispatch_package_summaries_reject_unexpected_profile_artifacts(artifact)
        artifact["packages"][0]["unexpected_profile_ids"] = []
        assert not consistency.dispatch_package_summaries_reject_unexpected_profile_artifacts(artifact)
        artifact["packages"][0]["unexpected_profile_ids"] = ["unexpected-probe"]
        artifact["packages"][0]["failures"] = []
        assert not consistency.dispatch_package_summaries_reject_unexpected_profile_artifacts(artifact)
    finally:
        consistency.ROOT = old_root


def test_preflight_work_package_summarizes_missing_package_handoff(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-qga" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-qga",
                "wave": 1,
                "launcher_selected": False,
                "manual_reason": "resource overlap: windows-lab",
                "resource_tags": ["proxmox-qga"],
                "required_env": ["TAMANDUA_PROXMOX_PASSWORD"],
                "expected_profile_ids": [
                    "windows-proxmox-qga-readiness-probe",
                    "windows-proxmox-qga-file-diagnostics-probe",
                ],
                "manual_prerequisites": ["Verify Proxmox API is reachable before running QGA probes."],
                "operator_inputs": [
                    {
                        "name": "proxmox_password",
                        "env": "TAMANDUA_PROXMOX_PASSWORD",
                        "flag": "",
                        "description": "Proxmox password from the approved secret store",
                    }
                ],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    json_path, markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]
    missing_package = package["evidence_excerpt"]["missing_package"]
    markdown = markdown_path.read_text(encoding="utf-8")

    assert package["status"] == "missing"
    assert missing_package["required_env"] == ["TAMANDUA_PROXMOX_PASSWORD"]
    assert missing_package["missing_expected_profiles"] == [
        "windows-proxmox-qga-readiness-probe",
        "windows-proxmox-qga-file-diagnostics-probe",
    ]
    assert missing_package["manual_reason"] == "resource overlap: windows-lab"
    assert missing_package["operator_inputs"][0]["env"] == "TAMANDUA_PROXMOX_PASSWORD"
    assert "missing package" in markdown
    assert "TAMANDUA_PROXMOX_PASSWORD" in markdown
    assert "windows-proxmox-qga-readiness-probe" in markdown


def test_preflight_work_package_summarizes_connection_stability_next_action(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-windows" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-windows",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["windows-lab"],
                "required_env": [],
                "expected_profile_ids": ["windows-agent-connection-stability-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260604T010012Z-windows-agent-connection-stability-probe.json").write_text(
        json.dumps(
            {
                "profile_id": "windows-agent-connection-stability-probe",
                "run_id": "20260604T010012Z-windows-agent-connection-stability-probe",
                "quality_gate": {
                    "status": "fail",
                    "passed": False,
                    "blocking_gaps": ["windows-agent-server-log-readable"],
                    "failures": ["windows_agent_connection_stability_gaps"],
                },
                "tests": [
                    {
                        "id": "windows-agent-server-log-readable",
                        "status": "missed",
                        "missing_expected_fields": ["infra"],
                        "gap_category": "infra",
                    }
                ],
                "connection_stability": {
                    "next_action": {
                        "agent_id": "agent-win-template",
                        "missing_stability": ["server_log_access", "telemetry_batches"],
                        "blockers": ["collector", "infra"],
                        "action": "Set TAMANDUA_SERVER_PASSWORD or provide --server-password.",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    json_path, markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]
    markdown = markdown_path.read_text(encoding="utf-8")

    assert package["evidence_excerpt"]["next_action"]["missing_stability"] == [
        "server_log_access",
        "telemetry_batches",
    ]
    assert "TAMANDUA_SERVER_PASSWORD" in package["evidence_excerpt"]["next_action"]["action"]
    assert "next action" in markdown
    assert "windows-agent-connection-stability-probe" in markdown
    assert "server_log_access, telemetry_batches" in markdown


def test_preflight_work_package_promotes_dispatch_results_artifact(tmp_path):
    dispatch_dir = tmp_path / "source-workdir"
    output_dir = dispatch_dir / "wave-1-fail" / "outputs"
    runs_dir = tmp_path / "runs"
    output_dir.mkdir(parents=True)
    script_path = dispatch_dir / "wave-1-fail.ps1"
    prompt_path = dispatch_dir / "wave-1-fail.agent.md"
    status_path = dispatch_dir / "wave-1-fail" / "agent_status.json"
    launcher_path = dispatch_dir / "wave-1-parallel-launcher.ps1"
    staged_launcher_path = dispatch_dir / "wave-1-staged-launcher.ps1"
    roster_path = dispatch_dir / "agent_roster.md"
    checklist_path = dispatch_dir / "env_checklist.md"
    brief_path = dispatch_dir / "dispatch_brief.md"
    runner_path = dispatch_dir / "dispatch_one_shot_runner.ps1"
    template_path = dispatch_dir / "env_template.ps1"
    owner_plan_path = dispatch_dir / "owner_launch_plan.md"
    owner_plan_json_path = dispatch_dir / "owner_launch_plan.json"
    script_path.write_text(f"$Out = '{output_dir}'\nWrite-Output 'package'\n", encoding="utf-8")
    prompt_path.write_text(
        f"# package prompt\n"
        f"Script: {script_path}\n"
        f"Status path: {status_path}\n"
        f"Current artifacts: {output_dir / '20260603T100000Z-fail-probe.json'}\n"
        f"Command:\npowershell -File '{script_path}'\n",
        encoding="utf-8",
    )
    launcher_path.write_text(
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File '{script_path}'\n",
        encoding="utf-8",
    )
    staged_launcher_path.write_text(
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File '{script_path}'\n",
        encoding="utf-8",
    )
    roster_path.write_text(
        f"# Validation Agent Roster\n\n| 1 | `wave-1-fail` | `{script_path}` | `{prompt_path}` |\n",
        encoding="utf-8",
    )
    checklist_path.write_text(
        f"# Validation Env Checklist\n\nScript: {script_path}\n",
        encoding="utf-8",
    )
    template_path.write_text(
        "# Validation env handoff template\n"
        "# This file is generated with redacted placeholder values only.\n"
        "$env:TAMANDUA_SERVER_PASSWORD = '<set-tamandua-server-password-secret>'\n",
        encoding="utf-8",
    )
    owner_plan_path.write_text(
        "# Validation Owner Launch Plan\n\n"
        f"Env checklist: `{checklist_path}`\n"
        f"Env template: `{template_path}`\n\n"
        "## Owner: unassigned\n\n"
        "| Wave | Stage | Package | Launch mode | Depends | Missing env | Command | Prompt |\n"
        "|---:|---:|---|---|---|---|---|---|\n"
        f"| 1 | 1 | `wave-1-fail` | parallel-auto | - | `TAMANDUA_SERVER_PASSWORD` | `powershell -NoProfile -ExecutionPolicy Bypass -File '{script_path}'` | `{prompt_path}` |\n",
        encoding="utf-8",
    )
    owner_plan_json_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact": "validation-owner-launch-plan",
                "env_checklist_path": str(checklist_path),
                "env_template_path": str(template_path),
                "owner_count": 1,
                "package_count": 1,
                "launchable_package_count": 0,
                "blocked_package_count": 1,
                "owners": [
                    {
                        "owner": "unassigned",
                        "package_count": 1,
                        "launchable_package_count": 0,
                        "blocked_package_count": 1,
                        "missing_effective_env": ["TAMANDUA_SERVER_PASSWORD"],
                        "roadmaps": [],
                        "packages": [
                            {
                                "package_id": "wave-1-fail",
                                "wave": 1,
                                "stage": 1,
                                "depends_on_waves": [],
                                "script_path": str(script_path),
                                "prompt_path": str(prompt_path),
                                "status_path": str(status_path),
                                "command": f"powershell -NoProfile -ExecutionPolicy Bypass -File '{script_path}'",
                                "missing_effective_env": ["TAMANDUA_SERVER_PASSWORD"],
                                "ready_to_launch": False,
                                "blocked_reasons": ["missing_effective_env"],
                                "current_status": "fail",
                                "current_exit_code": 1,
                                "current_notes": ["one_or_more_commands_failed"],
                                "current_artifacts": [str(output_dir / "20260603T100000Z-fail-probe.json")],
                                "current_missing_profiles": ["fail-probe"],
                                "current_blocker_cleared": False,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    brief_path.write_text(
        f"# Validation Dispatch Brief\n\nScript: {script_path}\nManifest: {dispatch_dir / 'dispatch_manifest.json'}\n",
        encoding="utf-8",
    )
    runner_path.write_text(
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File '{staged_launcher_path}'\n"
        f"python tools/detection_validation/run_preflight_work_package.py --promote-dispatch-results '{dispatch_dir / 'dispatch_manifest.json'}'\n",
        encoding="utf-8",
    )
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "docs\\benchmarks\\runs\\preflight.json",
        "output_dir": str(dispatch_dir),
        "launcher_paths": [str(launcher_path)],
        "staged_launcher_paths": [str(staged_launcher_path)],
        "agent_roster_path": str(roster_path),
        "env_checklist_path": str(checklist_path),
        "env_template_path": str(template_path),
        "owner_launch_plan_path": str(owner_plan_path),
        "owner_launch_plan_json_path": str(owner_plan_json_path),
        "dispatch_brief_path": str(brief_path),
        "dispatch_runner_path": str(runner_path),
        "packages": [
            {
                "package_id": "wave-1-fail",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["windows-lab"],
                "required_env": [],
                "effective_required_env": ["TAMANDUA_SERVER_PASSWORD"],
                "output_dir": str(output_dir),
                "script_path": str(script_path),
                "prompt_path": str(prompt_path),
                "status_path": str(status_path),
                "claim_output_contract": {
                    "output_dir": "package output directory",
                    "required_json_profile_ids": ["fail-probe"],
                    "status_file": "agent_status.json",
                    "status_required_fields": [
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
                    ],
                    "status_allowed_values": ["pass", "fail", "blocked"],
                },
            }
        ],
    }
    (dispatch_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (output_dir / "20260603T100000Z-fail-probe.json").write_text(
        '{"profile_id":"fail-probe","quality_gate":{"status":"fail","passed":false,'
        '"blocking_gaps":["left|right"],"failures":["fail_probe_gaps"]}}',
        encoding="utf-8",
    )
    (output_dir / "20260603T100100Z-second-probe.json").write_text(
        '{"profile_id":"second-probe","quality_gate":{"status":"fail","passed":false,'
        '"blocking_gaps":["second"],"failures":["second_probe_gaps"]}}',
        encoding="utf-8",
    )
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.write_text(
        json.dumps(
            {
                "package_id": "wave-1-fail",
                "status": "fail",
                "artifacts": [str(output_dir / "20260603T100000Z-fail-probe.json")],
                "blocker_cleared": False,
                "notes": ["one_or_more_commands_failed"],
                "exit_code": 1,
                "expected_profiles": ["fail-probe"],
                "missing_profiles": ["fail-probe"],
            }
        ),
        encoding="utf-8",
    )

    json_path, markdown_path, comparison_path = preflight_work_package.promote_dispatch_results(dispatch_dir, runs_dir)
    report = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))

    assert json_path.name.endswith("-validation-dispatch-results-probe.json")
    assert report["profile_id"] == "validation-dispatch-results-probe"
    assert report["quality_gate"]["passed"] is False
    assert report["quality_gate"]["blocking_gaps"] == ["wave-1-fail"]
    assert report["summary"]["tests"] == 1
    assert report["summary"]["covered"] == 0
    assert report["summary"]["missed"] == 1
    assert report["status_counts"] == {
        "pass": 0,
        "fail": 1,
        "blocked": 0,
        "missing": 0,
        "invalid": 0,
        "unknown": 0,
    }
    assert report["blocked_count"] == 0
    assert report["failed_status_count"] == 1
    assert report["missing_count"] == 0
    assert report["invalid_count"] == 0
    assert report["missing_required_env"] == []
    assert report["required_env_blockers"] == []
    assert report["owner_handoff"] == [
        {
            "owner": "unassigned",
            "package_count": 1,
            "passed_count": 0,
            "blocked_count": 0,
            "failed_status_count": 1,
            "missing_count": 0,
            "invalid_count": 0,
            "packages": [
                {
                    "package_id": "wave-1-fail",
                    "wave": 1,
                    "status": "fail",
                    "title": None,
                    "parallelizable_in_wave": None,
                    "depends_on_waves": [],
                    "handoff_notes": [],
                }
            ],
            "missing_required_env": [],
            "roadmaps": [],
        }
    ]
    assert report["source_preflight"] == "docs/benchmarks/runs/preflight.json"
    assert report["tests"][0]["id"] == "dispatch-package-wave-1-fail"
    assert report["tests"][0]["status"] == "missed"
    assert ".package-artifacts" in report["dispatch_manifest"]
    assert Path(report["dispatch_manifest"]).exists()
    assert ".package-artifacts" in report["packages"][0]["artifact_path"]
    assert len(report["packages"][0]["artifact_paths"]) == 2
    assert all(".package-artifacts" in path for path in report["packages"][0]["artifact_paths"])
    assert ".package-artifacts" in report["packages"][0]["output_dir"]
    assert ".package-artifacts" in report["packages"][0]["agent_status_path"]
    assert report["packages"][0]["agent_status"] == "fail"
    assert report["packages"][0]["agent_exit_code"] == 1
    assert report["packages"][0]["agent_notes"] == ["one_or_more_commands_failed"]
    assert report["packages"][0]["agent_missing_profiles"] == ["fail-probe"]
    assert report["packages"][0]["profile_results"]
    profile_artifact_path = report["packages"][0]["profile_results"][0]["artifact_path"]
    assert ".package-artifacts" in profile_artifact_path
    assert Path(profile_artifact_path).exists()
    assert "source-workdir" not in profile_artifact_path
    assert "original_artifact_path" not in report["packages"][0]
    assert Path(report["packages"][0]["artifact_path"]).exists()
    assert Path(report["packages"][0]["agent_status_path"]).exists()
    assert report["tests"][0]["evidence"]["artifact_path"] == report["packages"][0]["artifact_path"]
    assert "source-workdir" not in json.dumps(report)
    assert comparison["summary"]["status_counts"] == report["status_counts"]
    assert comparison["summary"]["failed_status_count"] == 1
    assert comparison["summary"]["missing_required_env"] == []
    assert comparison["summary"]["required_env_blockers"] == []
    assert comparison["summary"]["owner_handoff"] == report["owner_handoff"]
    assert comparison["packages"][0]["profile_results"][0]["artifact_path"] == profile_artifact_path
    assert "source-workdir" not in json.dumps(comparison)
    archived_manifest = json.loads(Path(report["dispatch_manifest"]).read_text(encoding="utf-8"))
    archived_package = archived_manifest["packages"][0]
    assert ".package-artifacts" in archived_manifest["output_dir"]
    assert archived_manifest["source_preflight"] == "docs/benchmarks/runs/preflight.json"
    assert ".package-artifacts" in archived_manifest["launcher_paths"][0]
    assert ".package-artifacts" in archived_manifest["staged_launcher_paths"][0]
    assert ".package-artifacts" in archived_manifest["agent_roster_path"]
    assert ".package-artifacts" in archived_manifest["env_checklist_path"]
    assert ".package-artifacts" in archived_manifest["env_template_path"]
    assert ".package-artifacts" in archived_manifest["owner_launch_plan_path"]
    assert ".package-artifacts" in archived_manifest["owner_launch_plan_json_path"]
    assert ".package-artifacts" in archived_manifest["dispatch_brief_path"]
    assert ".package-artifacts" in archived_manifest["dispatch_runner_path"]
    assert ".package-artifacts" in archived_package["output_dir"]
    assert ".package-artifacts" in archived_package["script_path"]
    assert ".package-artifacts" in archived_package["prompt_path"]
    assert ".package-artifacts" in archived_package["status_path"]
    assert archived_package["status_path"].replace("\\", "/").endswith("packages/wave-1-fail/agent_status.json")
    assert "source-workdir" not in json.dumps(archived_manifest)
    assert Path(archived_manifest["launcher_paths"][0]).exists()
    assert Path(archived_manifest["staged_launcher_paths"][0]).exists()
    assert Path(archived_manifest["agent_roster_path"]).exists()
    assert Path(archived_manifest["env_checklist_path"]).exists()
    assert Path(archived_manifest["env_template_path"]).exists()
    assert Path(archived_manifest["owner_launch_plan_path"]).exists()
    assert Path(archived_manifest["owner_launch_plan_json_path"]).exists()
    assert Path(archived_manifest["dispatch_brief_path"]).exists()
    assert Path(archived_manifest["dispatch_runner_path"]).exists()
    assert Path(archived_package["script_path"]).exists()
    assert Path(archived_package["prompt_path"]).exists()
    archived_script = Path(archived_package["script_path"]).read_text(encoding="utf-8")
    archived_prompt = Path(archived_package["prompt_path"]).read_text(encoding="utf-8")
    archived_launcher = Path(archived_manifest["launcher_paths"][0]).read_text(encoding="utf-8")
    archived_staged_launcher = Path(archived_manifest["staged_launcher_paths"][0]).read_text(encoding="utf-8")
    archived_roster = Path(archived_manifest["agent_roster_path"]).read_text(encoding="utf-8")
    archived_checklist = Path(archived_manifest["env_checklist_path"]).read_text(encoding="utf-8")
    archived_template = Path(archived_manifest["env_template_path"]).read_text(encoding="utf-8")
    archived_owner_plan = Path(archived_manifest["owner_launch_plan_path"]).read_text(encoding="utf-8")
    archived_owner_plan_json = Path(archived_manifest["owner_launch_plan_json_path"]).read_text(encoding="utf-8")
    archived_brief = Path(archived_manifest["dispatch_brief_path"]).read_text(encoding="utf-8")
    archived_runner = Path(archived_manifest["dispatch_runner_path"]).read_text(encoding="utf-8")
    assert "source-workdir" not in archived_script
    assert "source-workdir" not in archived_prompt
    assert ".package-artifacts" in archived_prompt
    assert "Current artifacts:" in archived_prompt
    assert "source-workdir" not in archived_launcher
    assert "source-workdir" not in archived_staged_launcher
    assert "source-workdir" not in archived_roster
    assert "source-workdir" not in archived_checklist
    assert "source-workdir" not in archived_template
    assert "source-workdir" not in archived_owner_plan
    assert "source-workdir" not in archived_owner_plan_json
    assert "source-workdir" not in archived_brief
    assert "source-workdir" not in archived_runner
    assert archived_package["output_dir"] in archived_script
    assert archived_package["script_path"] in archived_prompt
    assert archived_package["script_path"] in archived_launcher
    assert archived_package["script_path"] in archived_staged_launcher
    assert archived_package["script_path"] in archived_roster
    assert archived_package["script_path"] in archived_checklist
    assert archived_package["script_path"] in archived_brief
    assert archived_manifest["staged_launcher_paths"][0] in archived_runner
    assert comparison["profile_id"] == "validation-dispatch-results-probe"
    assert comparison["summary"]["tests"] == 1
    assert comparison["tests"][0]["status"] == "missed"
    assert "left\\|right" in markdown
    assert "agent status" in markdown
    assert "one_or_more_commands_failed" in markdown
    assert "Dispatch-results coordination artifact only" in report["claim_boundary"]


def test_preflight_work_package_promotion_rejects_stale_source_preflight(tmp_path):
    dispatch_dir = tmp_path / "source-workdir"
    runs_dir = tmp_path / "runs"
    output_dir = dispatch_dir / "wave-1-pass" / "outputs"
    output_dir.mkdir(parents=True)
    runs_dir.mkdir()
    older = runs_dir / "20260603T100000Z-validation-execution-preflight-probe.json"
    newer = runs_dir / "20260603T110000Z-validation-execution-preflight-probe.json"
    older.write_text("{}", encoding="utf-8")
    newer.write_text("{}", encoding="utf-8")
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": str(older),
        "output_dir": str(dispatch_dir),
        "packages": [
            {
                "package_id": "wave-1-pass",
                "wave": 1,
                "output_dir": str(output_dir),
            }
        ],
    }
    (dispatch_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    try:
        preflight_work_package.promote_dispatch_results(dispatch_dir, runs_dir)
    except ValueError as exc:
        assert "source_preflight is stale" in str(exc)
    else:
        raise AssertionError("stale source_preflight was promoted")


def test_preflight_run_class_configuration_is_complete():
    run_classes = set(preflight.BROAD_RUN_CLASSES)

    assert set(preflight.RUN_CLASS_ROADMAPS) == run_classes
    assert set(preflight.RUN_CLASS_RELEVANT_PROFILES) == run_classes

    for run_class in preflight.BROAD_RUN_CLASSES:
        assert preflight.RUN_CLASS_ROADMAPS[run_class]
        relevant_profiles = preflight.RUN_CLASS_RELEVANT_PROFILES[run_class]
        if run_class != "windows-broad":
            assert relevant_profiles


def test_preflight_blocks_caldera_classes_for_api_key_gap():
    closure_gate = {
        "tests": [
            {"status": "missed", "evidence": {"roadmap_key": "D"}},
            {"status": "missed", "evidence": {"roadmap_key": "M"}},
        ]
    }
    required_by_roadmap = {"D": ["CALDERA_API_KEY"]}
    blockers = [
        {
            "roadmap": "D",
            "profile_id": "caldera-api-shape-probe",
            "required_env": ["CALDERA_API_KEY"],
            "blocking_gaps": ["caldera_api_shape_missing"],
        },
        {
            "roadmap": "M",
            "profile_id": "windows-caldera-enterprise-safe",
            "required_env": [],
            "blocking_gaps": ["quality_gate_failed"],
        },
    ]

    readiness = preflight.classify_run_classes(
        closure_gate,
        required_by_roadmap,
        ["CALDERA_API_KEY"],
        blockers,
    )
    by_class = {item["run_class"]: item for item in readiness}

    assert not by_class["windows-broad"]["allowed"]
    assert not by_class["windows-caldera-enterprise"]["allowed"]
    assert "windows-caldera-enterprise-safe" in by_class["windows-broad"]["blocking_profiles"]
    assert by_class["windows-caldera-enterprise"]["missing_env"] == ["CALDERA_API_KEY"]

    sequence = preflight.derive_unblock_sequence(
        required_by_roadmap,
        ["CALDERA_API_KEY"],
        blockers,
        readiness,
    )
    env_step = next(item for item in sequence if item["step_id"] == "provide-required-preflight-env")
    caldera_step = next(
        item for item in sequence if item["step_id"] == "restore-caldera-readiness-repeatability"
    )

    assert env_step["roadmaps"] == ["D"]
    assert env_step["blocked_run_classes"] == ["windows-caldera-enterprise"]
    assert caldera_step["roadmaps"] == ["D", "M"]
    assert caldera_step["blocked_run_classes"] == ["windows-broad", "windows-caldera-enterprise"]


def test_caldera_paw_next_action_for_missing_api_key_and_paw():
    args = Namespace(
        caldera_url="http://192.168.12.146:8888",
        caldera_agent_paw="",
        caldera_group="tamandua-lab",
        freshness_seconds=300,
    )
    tests = [
        caldera_paw.make_result(
            "caldera-api-agents-readable",
            "CALDERA /api/v2/agents is reachable through a read-only request",
            False,
            "infrastructure",
            {
                "url": "http://192.168.12.146:8888/api/v2/agents",
                "error": "missing_caldera_api_key",
                "required_env": "CALDERA_API_KEY",
            },
            ["caldera_api_key_present", "caldera_api_agents_http_200"],
        ),
    ]

    action = caldera_paw.next_action_hint(args, tests, False)

    assert action["missing_readiness"] == [
        "caldera_agent_paw_configured",
        "caldera_agents_api",
        "caldera_api_key",
    ]
    assert action["required_env"] == ["CALDERA_AGENT_PAW", "CALDERA_API_KEY", "CALDERA_GROUP"]
    assert action["requested_group"] == "tamandua-lab"
    assert "CALDERA_API_KEY" in action["action"]


def test_caldera_paw_markdown_renders_next_action(tmp_path):
    report = {
        "run_id": "20260604T000000Z-caldera-paw-readiness-probe",
        "quality_gate": {"passed": False},
        "summary": {"covered": 0, "tests": 1},
        "tests": [
            {
                "id": "caldera-api-agents-readable",
                "status": "missed",
                "gap_category": "infrastructure",
                "missing_expected_fields": ["caldera_api_key_present"],
                "evidence": {"required_env": "CALDERA_API_KEY"},
            }
        ],
        "caldera_paw_readiness": {
            "next_action": {
                "caldera_url": "http://192.168.12.146:8888",
                "requested_paw": "paw-1",
                "requested_group": "tamandua-lab",
                "missing_readiness": ["target_paw_fresh"],
                "required_env": ["CALDERA_API_KEY", "CALDERA_AGENT_PAW"],
                "action": "Start a fresh Sandcat, then rerun.",
            }
        },
    }
    path = tmp_path / "caldera-paw.md"

    caldera_paw.write_markdown(report, path)
    markdown = path.read_text(encoding="utf-8")

    assert "## Next Action" in markdown
    assert "paw-1" in markdown
    assert "target_paw_fresh" in markdown
    assert "Start a fresh Sandcat" in markdown


def test_caldera_repeatability_streak_reset_reason_distinguishes_failure_modes():
    failed = {
        "quality_gate": {"passed": False},
        "tests": [{"execution": {"error_code": "missing_caldera_api_key"}}],
        "summary": {"upstream_backed_tests": 0},
    }
    no_upstream = {
        "quality_gate": {"passed": True},
        "summary": {"upstream_backed_tests": 0, "executor_counts": {}},
    }
    upstream = {
        "quality_gate": {"passed": True},
        "summary": {"upstream_backed_tests": 1},
    }

    assert caldera_repeatability.streak_reset_reason(failed) == (
        "quality_gate_failed:missing_caldera_api_key"
    )
    assert caldera_repeatability.streak_reset_reason(no_upstream) == (
        "missing_upstream_caldera_operation_evidence"
    )
    assert caldera_repeatability.streak_reset_reason(upstream) == "none"


def test_caldera_repeatability_latest_streak_reset_reports_latest_blocker(tmp_path):
    first = tmp_path / "20260601T000000Z-windows-caldera-smoke.json"
    second = tmp_path / "20260602T000000Z-windows-caldera-smoke.json"
    reports = [
        (first, {"run_id": first.stem, "quality_gate": {"passed": True}, "summary": {"upstream_backed_tests": 1}}),
        (
            second,
            {
                "run_id": second.stem,
                "quality_gate": {"passed": False},
                "summary": {"upstream_backed_tests": 0},
                "tests": [{"execution": {"caldera_proof": {"error_code": "paw_offline"}}}],
            },
        ),
    ]
    old_root = caldera_repeatability.ROOT
    caldera_repeatability.ROOT = tmp_path
    try:
        reset = caldera_repeatability.latest_streak_reset(reports)
    finally:
        caldera_repeatability.ROOT = old_root

    assert reset["run_id"] == second.stem
    assert reset["reason"] == "quality_gate_failed:paw_offline"


def write_caldera_repeatability_artifact(
    runs_dir: Path,
    profile_id: str,
    index: int,
    *,
    passed: bool = True,
    upstream_backed: bool = True,
    error_code: str | None = None,
) -> None:
    timestamp = f"20260603T10{index:02d}00Z"
    run_id = f"{timestamp}-{profile_id}"
    summary = {
        "upstream_backed_tests": 1 if upstream_backed else 0,
        "executor_counts": {"caldera_operation": 1 if upstream_backed else 0},
    }
    report = {
        "run_id": run_id,
        "profile_id": profile_id,
        "started_at": f"2026-06-03T10:{index:02d}:00Z",
        "finished_at": f"2026-06-03T10:{index:02d}:30Z",
        "quality_gate": {"passed": passed},
        "summary": summary,
        "tests": [],
    }
    if error_code:
        report["tests"] = [{"execution": {"caldera_proof": {"error_code": error_code}}}]
    path = runs_dir / f"{run_id}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def test_caldera_repeatability_build_tests_accepts_three_consecutive_upstream_passes(
    tmp_path,
    monkeypatch,
):
    runs_dir = tmp_path / "docs" / "benchmarks" / "runs"
    runs_dir.mkdir(parents=True)
    for profile_id in caldera_repeatability.CALDERA_PROFILES:
        for index in range(1, 4):
            write_caldera_repeatability_artifact(runs_dir, profile_id, index)
    monkeypatch.setattr(caldera_repeatability, "ROOT", tmp_path)
    monkeypatch.setattr(caldera_repeatability, "RUNS_DIR", runs_dir)

    tests = caldera_repeatability.build_tests()

    assert [test["status"] for test in tests] == ["covered", "covered"]
    assert {test["evidence"]["consecutive_passing_tail"] for test in tests} == {3}
    assert all(test["evidence"]["passing_tail_run_ids"] for test in tests)


def test_caldera_repeatability_build_tests_rejects_latest_reset_after_pass_streak(
    tmp_path,
    monkeypatch,
):
    runs_dir = tmp_path / "docs" / "benchmarks" / "runs"
    runs_dir.mkdir(parents=True)
    for profile_id in caldera_repeatability.CALDERA_PROFILES:
        for index in range(1, 4):
            write_caldera_repeatability_artifact(runs_dir, profile_id, index)
    write_caldera_repeatability_artifact(
        runs_dir,
        "windows-caldera-enterprise-safe",
        4,
        passed=False,
        upstream_backed=False,
        error_code="caldera_agent_stale_or_offline",
    )
    monkeypatch.setattr(caldera_repeatability, "ROOT", tmp_path)
    monkeypatch.setattr(caldera_repeatability, "RUNS_DIR", runs_dir)

    tests = caldera_repeatability.build_tests()
    by_profile = {test["evidence"]["profile_id"]: test for test in tests}
    enterprise = by_profile["windows-caldera-enterprise-safe"]

    assert by_profile["windows-caldera-smoke"]["status"] == "covered"
    assert by_profile["windows-caldera-smoke"]["evidence"]["next_action"]["passes_needed"] == 0
    assert by_profile["windows-caldera-smoke"]["evidence"]["next_action"]["next_profile_to_run"] is None
    assert enterprise["status"] == "missed"
    assert enterprise["evidence"]["consecutive_passing_tail"] == 0
    assert enterprise["evidence"]["next_action"]["passes_needed"] == 3
    assert enterprise["evidence"]["next_action"]["next_profile_to_run"] == "windows-caldera-enterprise-safe"
    assert "windows_caldera_enterprise_safe.json" in enterprise["evidence"]["next_action"]["next_command_hint"]
    assert enterprise["evidence"]["next_action"]["required_env"] == [
        "CALDERA_API_KEY",
        "CALDERA_GROUP",
        "CALDERA_AGENT_PAW",
    ]
    assert enterprise["evidence"]["latest_streak_reset"]["reason"] == (
        "quality_gate_failed:caldera_agent_stale_or_offline"
    )
    assert enterprise["missing_expected_fields"] == ["0/3 consecutive passes"]


def test_caldera_repeatability_markdown_renders_next_actions(tmp_path):
    report = {
        "run_id": "20260604T000000Z-caldera-repeatability-probe",
        "quality_gate": {"passed": False},
        "tests": [
            {
                "id": "caldera-repeatability-windows-caldera-enterprise-safe",
                "status": "missed",
                "gap_category": "runner",
                "missing_expected_fields": ["0/3 consecutive passes"],
                "evidence": {
                    "profile_id": "windows-caldera-enterprise-safe",
                    "latest_run_id": "latest-run",
                    "consecutive_passing_tail": 0,
                    "required_consecutive_passes": 3,
                    "latest_streak_reset": {"reason": "quality_gate_failed"},
                    "recent_history": [],
                    "next_action": {
                        "next_profile_to_run": "windows-caldera-enterprise-safe",
                        "passes_needed": 3,
                        "required_env": ["CALDERA_API_KEY", "CALDERA_GROUP", "CALDERA_AGENT_PAW"],
                        "next_command_hint": "python tools/detection_validation/tamandua_detection_validation.py --profile tools/detection_validation/profiles/windows_caldera_enterprise_safe.json",
                    },
                },
            }
        ],
    }
    path = tmp_path / "repeatability.md"

    caldera_repeatability.write_markdown(report, path)
    text = path.read_text(encoding="utf-8")

    assert "## Next Actions" in text
    assert "`windows-caldera-enterprise-safe`" in text
    assert "`3`" in text
    assert "CALDERA_AGENT_PAW" in text
    assert "windows_caldera_enterprise_safe.json" in text


def test_caldera_api_shape_next_action_for_missing_api_key():
    args = Namespace(caldera_url="http://192.168.12.146:8888")
    tests = [
        caldera_api.make_result(
            "caldera-api-agents-readable",
            "CALDERA agents endpoint is readable",
            False,
            {"required_env": "CALDERA_API_KEY", "error": "missing_caldera_api_key"},
            ["caldera_api_key_present", "caldera_api_agents_http_200"],
        ),
        caldera_api.make_result(
            "caldera-api-supporting-endpoints-readable",
            "At least one supporting CALDERA inventory endpoint is readable",
            False,
            {"required_env": "CALDERA_API_KEY", "error": "missing_caldera_api_key"},
            ["caldera_api_key_present", "caldera_supporting_endpoint_http_200"],
        ),
    ]

    action = caldera_api.next_action_hint(args, tests, False)

    assert action["required_env"] == ["CALDERA_API_KEY"]
    assert action["missing_endpoints"] == [
        "/api/v2/abilities",
        "/api/v2/adversaries",
        "/api/v2/agents",
        "/api/v2/operations",
    ]
    assert "CALDERA_API_KEY" in action["action"]


def test_caldera_api_shape_markdown_renders_next_action(tmp_path):
    report = {
        "run_id": "20260604T000000Z-caldera-api-shape-probe",
        "quality_gate": {"passed": False},
        "summary": {"covered": 0, "tests": 3},
        "caldera_endpoint_shapes": {
            "/api/v2/agents": {
                "status": None,
                "count": None,
                "shape": None,
                "error": "missing_caldera_api_key",
                "required_env": "CALDERA_API_KEY",
            }
        },
        "caldera_api_shape": {
            "next_action": {
                "caldera_url": "http://192.168.12.146:8888",
                "missing_endpoints": ["/api/v2/agents"],
                "required_env": ["CALDERA_API_KEY"],
                "action": "Set CALDERA_API_KEY, then rerun.",
            }
        },
    }
    path = tmp_path / "caldera-api.md"

    caldera_api.write_markdown(report, path)
    text = path.read_text(encoding="utf-8")

    assert "## Next Action" in text
    assert "CALDERA_API_KEY" in text
    assert "/api/v2/agents" in text


def test_caldera_probes_write_to_explicit_output_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    modules = [
        ("caldera-api-shape-probe", caldera_api, "caldera-api-shape-probe"),
        ("caldera-paw-readiness-probe", caldera_paw, "caldera-paw-readiness-probe"),
        ("caldera-repeatability-probe", caldera_repeatability, "caldera-repeatability-probe"),
    ]

    for command_name, module, profile_id in modules:
        output_dir = tmp_path / profile_id
        monkeypatch.setattr(sys, "argv", [command_name, "--output-dir", str(output_dir)])

        exit_code = module.main()

        assert exit_code in (0, 1)
        assert list(output_dir.glob(f"*-{profile_id}.json"))
        assert list(output_dir.glob(f"*-{profile_id}.md"))
        assert list(output_dir.glob(f"*-{profile_id}.comparison.json"))


def test_macos_backend_probe_writes_to_explicit_output_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(
        macos_backend,
        "load_agents",
        lambda server=None: ([], {"command": ["tamandua-ctl", "remote", "agents", "list", "--json"]}),
    )
    output_dir = tmp_path / "macos-backend"
    monkeypatch.setattr(
        sys,
        "argv",
        ["macos-backend-readiness-probe", "--output-dir", str(output_dir)],
    )

    exit_code = macos_backend.main()

    assert exit_code == 1
    assert list(output_dir.glob("*-macos-backend-readiness-probe.json"))
    assert list(output_dir.glob("*-macos-backend-readiness-probe.md"))
    assert list(output_dir.glob("*-macos-backend-readiness-probe.comparison.json"))


def test_macos_backend_load_agents_passes_explicit_server(monkeypatch):
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return macos_backend.subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"data": []}),
            stderr="",
        )

    monkeypatch.setattr(macos_backend.subprocess, "run", fake_run)

    agents, evidence = macos_backend.load_agents("http://192.168.12.146:4000")

    assert agents == []
    assert calls[0][-2:] == ["--server", "http://192.168.12.146:4000"]
    assert "--server http://192.168.12.146:4000" in evidence["command"]


def test_macos_backend_load_agents_redacts_remote_config_metadata(tmp_path, monkeypatch):
    appdata = tmp_path / "AppData" / "Roaming"
    config_dir = appdata / "Tamandua" / "tamandua-ctl"
    config_dir.mkdir(parents=True)
    (config_dir / "remote.json").write_text(
        json.dumps(
            {
                "server": "https://tamandua.treantlab.org",
                "token": "secret-token-value",
                "expires_at": "server-token-ttl-7d",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setattr(macos_backend.os, "name", "nt")

    def fake_run(command, **_kwargs):
        return macos_backend.subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr='[ERROR] failed to list agents: HTTP 401 Unauthorized {"error":"Invalid or expired token"}',
        )

    monkeypatch.setattr(macos_backend.subprocess, "run", fake_run)

    _agents, evidence = macos_backend.load_agents("http://192.168.12.146:4000")

    metadata = evidence["remote_config"]
    assert metadata["exists"] is True
    assert metadata["server"] == "https://tamandua.treantlab.org"
    assert metadata["has_token"] is True
    assert metadata["expires_at"] == "server-token-ttl-7d"
    assert metadata["target_server"] == "http://192.168.12.146:4000"
    assert metadata["server_matches_target"] is False
    assert "last_modified" in metadata
    assert "secret-token-value" not in json.dumps(evidence)


def test_macos_backend_build_tests_surfaces_expired_ctl_auth(monkeypatch):
    monkeypatch.setattr(
        macos_backend,
        "load_agents",
        lambda server=None: (
            [],
            {
                "exit_code": 1,
                "stderr": '[ERROR] failed to list agents: HTTP 401 Unauthorized {"error":"Invalid or expired token"}',
                "stdout": "",
                "remote_config": {
                    "server": "https://tamandua.treantlab.org",
                    "target_server": "http://192.168.12.146:4000",
                    "server_matches_target": False,
                    "has_token": True,
                },
            },
        ),
    )

    tests = macos_backend.build_tests("http://192.168.12.146:4000")
    row = next(test for test in tests if test["id"] == "macos-backend-agent-row-present")
    evidence = row["evidence"]

    assert row["missing_expected_fields"] == ["tamandua_ctl_auth"]
    assert evidence["next_action"]["missing_readiness"] == ["tamandua_ctl_auth"]
    assert "saved remote login is for https://tamandua.treantlab.org" in evidence["next_action"]["action"]
    assert evidence["next_action"]["login_command"] == (
        "tamandua-ctl remote login --server http://192.168.12.146:4000 --no-browser"
    )
    assert evidence["next_action"]["token_env"] == "TAMANDUA_TOKEN"
    assert evidence["next_action"]["token_login_command"] == (
        "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN"
    )
    assert "secret" not in json.dumps(evidence["next_action"]).lower()


def macos_inventory_agent(
    *,
    status: str = "online",
    health: str = "healthy",
    last_seen: str = "2026-06-03T10:04:30Z",
    endpoint_status: str = "available",
) -> dict[str, object]:
    return {
        "id": "macos-agent-1",
        "hostname": "macos-lab-01",
        "os_type": "macos",
        "os_version": "14.5",
        "status": status,
        "health_status": {"status": health},
        "last_seen": last_seen,
        "platform_capabilities": [
            {
                "id": "endpoint_telemetry",
                "status": endpoint_status,
                "maturity": "runtime",
                "observed": True,
            }
        ],
    }


def test_macos_backend_build_tests_accepts_online_healthy_fresh_endpoint_agent(monkeypatch):
    now = macos_backend.datetime(2026, 6, 3, 10, 5, 0, tzinfo=macos_backend.timezone.utc)
    monkeypatch.setattr(macos_backend, "utc_now", lambda: now)
    monkeypatch.setattr(
        macos_backend,
        "load_agents",
        lambda server=None: ([macos_inventory_agent()], {"exit_code": 0, "server": server}),
    )

    tests = macos_backend.build_tests("http://192.168.12.146:4000")

    assert [test["status"] for test in tests] == ["covered"] * 4
    endpoint = next(test for test in tests if test["id"] == "macos-backend-endpoint-telemetry-capability")
    assert endpoint["evidence"]["macos_agents"][0]["last_seen_age_seconds"] == 30


def test_macos_backend_build_tests_rejects_stale_offline_agent(monkeypatch):
    now = macos_backend.datetime(2026, 6, 3, 10, 5, 0, tzinfo=macos_backend.timezone.utc)
    monkeypatch.setattr(macos_backend, "utc_now", lambda: now)
    monkeypatch.setattr(
        macos_backend,
        "load_agents",
        lambda server=None: (
            [
                macos_inventory_agent(
                    status="offline",
                    health="unknown",
                    last_seen="2026-06-03T09:00:00Z",
                    endpoint_status="unknown",
                )
            ],
            {"exit_code": 0},
        ),
    )

    tests = macos_backend.build_tests()
    by_id = {test["id"]: test for test in tests}

    assert by_id["macos-backend-agent-row-present"]["status"] == "covered"
    assert by_id["macos-backend-agent-online-healthy"]["missing_expected_fields"] == [
        "online_healthy_macos_agent"
    ]
    assert by_id["macos-backend-agent-fresh"]["missing_expected_fields"] == ["fresh_macos_heartbeat"]
    assert by_id["macos-backend-endpoint-telemetry-capability"]["missing_expected_fields"] == [
        "macos_endpoint_telemetry_capability"
    ]
    evidence = by_id["macos-backend-agent-online-healthy"]["evidence"]
    assert evidence["best_candidate"]["hostname"] == "macos-lab-01"
    assert evidence["best_candidate"]["missing_readiness"] == [
        "status_online",
        "health_healthy",
        "fresh_heartbeat",
        "endpoint_telemetry_capability",
    ]
    assert evidence["next_action"]["target_hostname"] == "macos-lab-01"
    assert "Reconnect the selected macOS agent" in evidence["next_action"]["action"]


def test_macos_backend_markdown_renders_best_candidate_and_next_action(tmp_path):
    report = {
        "run_id": "20260604T000000Z-macos-backend-readiness-probe",
        "quality_gate": {"passed": False},
        "tests": [
            {
                "id": "macos-backend-agent-online-healthy",
                "status": "missed",
                "gap_category": "infrastructure",
                "missing_expected_fields": ["online_healthy_macos_agent"],
                "evidence": {
                    "best_candidate": {
                        "hostname": "Victors-MacBook-Pro.local",
                        "id": "mac-agent-1",
                        "status": "offline",
                        "health": "unknown",
                        "last_seen_age_seconds": 440170,
                        "missing_readiness": ["status_online", "health_healthy"],
                    },
                    "next_action": {
                        "target_hostname": "Victors-MacBook-Pro.local",
                        "target_agent_id": "mac-agent-1",
                        "missing_readiness": ["status_online", "health_healthy"],
                        "action": "Reconnect the selected macOS agent, then rerun.",
                    },
                },
            }
        ],
    }
    path = tmp_path / "macos.md"

    macos_backend.write_markdown(report, path)
    text = path.read_text(encoding="utf-8")

    assert "## Best Candidate" in text
    assert "Victors-MacBook-Pro.local" in text
    assert "status_online, health_healthy" in text
    assert "## Next Action" in text
    assert "Reconnect the selected macOS agent" in text


def test_atomic_t1047_probe_writes_to_explicit_output_dir(tmp_path):
    output_dir = tmp_path / "atomic-t1047"

    exit_code = atomic_t1047.main(["--output-dir", str(output_dir)])

    assert exit_code in (0, 1)
    assert list(output_dir.glob("*-atomic-t1047-lab-capability-probe.json"))
    assert list(output_dir.glob("*-atomic-t1047-lab-capability-probe.md"))
    assert list(output_dir.glob("*-atomic-t1047-lab-capability-probe.comparison.json"))


def test_atomic_t1047_latest_source_artifact_prefers_precondition_payload(tmp_path, monkeypatch):
    runs_dir = tmp_path / "docs" / "benchmarks" / "runs"
    runs_dir.mkdir(parents=True)
    old_focused = runs_dir / "20260603T100000Z-windows-atomic-extended-safe.json"
    newer_aggregate = runs_dir / "20260603T110000Z-windows-atomic-extended-safe.json"
    old_focused.write_text(
        json.dumps(
            {
                "run_id": old_focused.stem,
                "profile_id": "windows-atomic-extended-safe",
                "tests": [
                    {
                        "id": "T1047-wmi-discovery",
                        "precondition": {
                            "command_confirmed": True,
                            "end_reason": "command_confirmed",
                            "guest_exit_code": 2,
                            "guest_stdout": "__TAMANDUA_CTL_DONE_1__:2",
                        },
                        "execution": {"error_code": "wmi_cli_unavailable_on_target"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    newer_aggregate.write_text(
        json.dumps(
            {
                "run_id": newer_aggregate.stem,
                "profile_id": "windows-atomic-extended-safe",
                "tests": [{"id": "T1047-wmi-discovery", "status": "missed"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(atomic_t1047, "ROOT", tmp_path)
    monkeypatch.setattr(atomic_t1047, "RUNS_DIR", runs_dir)

    path, report = atomic_t1047.latest_source_artifact()

    assert path == old_focused
    assert report["run_id"] == old_focused.stem
    assert atomic_t1047.artifact_test_result(report)["precondition"]["command_confirmed"] is True


def test_macos_p0_smoke_wrapper_exposes_output_dir_and_local_target():
    script = (
        Path(__file__).resolve().parents[2]
        / "deploy"
        / "scripts"
        / "proxmox"
        / "run-macos-p0-smoke.ps1"
    ).read_text(encoding="utf-8")

    assert "[string]$OutputDir" in script
    assert "--output-dir" in script
    assert "--local-target" in script
    assert "--resolve-agent-by-hostname" in script


def test_windows_qga_probes_write_to_explicit_output_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("TAMANDUA_PROXMOX_PASSWORD", raising=False)
    modules = [
        ("windows-proxmox-qga-readiness-probe", windows_qga_readiness),
        ("windows-proxmox-qga-file-diagnostics-probe", windows_qga_file_diagnostics),
    ]

    for profile_id, module in modules:
        output_dir = tmp_path / profile_id
        monkeypatch.setattr(sys, "argv", [profile_id, "--output-dir", str(output_dir)])

        exit_code = module.main()

        assert exit_code == 1
        assert list(output_dir.glob(f"*-{profile_id}.json"))
        assert list(output_dir.glob(f"*-{profile_id}.md"))
        assert list(output_dir.glob(f"*-{profile_id}.comparison.json"))


def test_windows_qga_readiness_next_action_for_missing_proxmox_password():
    args = Namespace(
        proxmox_host="192.168.12.149",
        proxmox_user="root@pam",
        proxmox_node="Default",
        vmid=1521,
    )
    tests = [
        windows_qga_readiness.make_result(
            "proxmox-api-authenticated",
            "Proxmox API accepts configured credentials",
            False,
            "infra",
            {
                "error": "missing_proxmox_password",
                "required_env": "TAMANDUA_PROXMOX_PASSWORD",
                "url": "https://192.168.12.149:8006/api2/json/access/ticket",
            },
        )
    ]

    action = windows_qga_readiness.next_action_hint(args, tests, False)

    assert action["missing_readiness"] == ["proxmox_api_auth"]
    assert action["required_env"] == ["TAMANDUA_PROXMOX_PASSWORD"]
    assert "TAMANDUA_PROXMOX_PASSWORD" in action["action"]
    assert action["api_url"] == "https://192.168.12.149:8006/api2/json/access/ticket"


def test_windows_qga_readiness_markdown_renders_next_action(tmp_path):
    report = {
        "run_id": "20260604T000000Z-windows-proxmox-qga-readiness-probe",
        "quality_gate": {"status": "fail"},
        "tests": [{"id": "proxmox-api-authenticated", "status": "missed", "gap_category": "infra"}],
        "proxmox_qga_readiness": {
            "ready_for_bounded_execution": False,
            "next_action": {
                "host": "192.168.12.149",
                "node": "Default",
                "vmid": 1521,
                "missing_readiness": ["proxmox_api_auth"],
                "required_env": ["TAMANDUA_PROXMOX_PASSWORD"],
                "action": "Set TAMANDUA_PROXMOX_PASSWORD, then rerun.",
            },
        },
    }
    path = tmp_path / "qga-readiness.md"

    windows_qga_readiness.write_markdown(report, path)
    text = path.read_text(encoding="utf-8")

    assert "## Next Action" in text
    assert "proxmox_api_auth" in text
    assert "TAMANDUA_PROXMOX_PASSWORD" in text


def test_windows_qga_file_diagnostics_next_action_for_file_open_501():
    args = Namespace(
        proxmox_host="192.168.12.149",
        proxmox_user="root@pam",
        proxmox_node="Default",
        vmid=1521,
    )
    tests = [
        windows_qga_file_diagnostics.make_result(
            "proxmox-api-authenticated",
            "Proxmox API accepts configured credentials",
            True,
            "infra",
            {"authenticated": True},
        ),
        windows_qga_file_diagnostics.make_result(
            "proxmox-agent-file-open-exposed",
            "Proxmox API exposes QGA file-open endpoint",
            False,
            "runner",
            {"observed_501_not_implemented": True},
        ),
    ]
    file_attempts = [{"path": r"C:\ProgramData\Tamandua\logs\agent.log", "status": 501, "ok": False}]

    action = windows_qga_file_diagnostics.next_action_hint(args, tests, file_attempts, False)

    assert action["missing_diagnostics"] == ["proxmox_agent_file_open_exposed"]
    assert action["observed_501_not_implemented"] is True
    assert action["file_open_endpoint"] == "/nodes/Default/qemu/1521/agent/file-open"
    assert "HTTP 501" in action["action"]


def test_preflight_work_package_summarizes_qga_next_action(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-qga" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-qga",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["proxmox-qga"],
                "required_env": ["TAMANDUA_PROXMOX_PASSWORD"],
                "expected_profile_ids": ["windows-proxmox-qga-readiness-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260604T000000Z-windows-proxmox-qga-readiness-probe.json").write_text(
        json.dumps(
            {
                "profile_id": "windows-proxmox-qga-readiness-probe",
                "run_id": "20260604T000000Z-windows-proxmox-qga-readiness-probe",
                "quality_gate": {
                    "status": "fail",
                    "passed": False,
                    "failures": ["windows_proxmox_qga_readiness_gaps"],
                },
                "tests": [
                    {
                        "id": "proxmox-api-authenticated",
                        "status": "missed",
                        "missing_expected_fields": ["infra"],
                        "gap_category": "infra",
                    }
                ],
                "proxmox_qga_readiness": {
                    "next_action": {
                        "host": "192.168.12.149",
                        "node": "Default",
                        "vmid": 1521,
                        "missing_readiness": ["proxmox_api_auth"],
                        "required_env": ["TAMANDUA_PROXMOX_PASSWORD"],
                        "blockers": ["infra"],
                        "action": "Set TAMANDUA_PROXMOX_PASSWORD, then rerun.",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    json_path, markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]
    markdown = markdown_path.read_text(encoding="utf-8")

    assert package["evidence_excerpt"]["next_action"]["missing_readiness"] == ["proxmox_api_auth"]
    assert package["evidence_excerpt"]["next_action"]["required_env"] == ["TAMANDUA_PROXMOX_PASSWORD"]
    assert "proxmox_api_auth" in markdown
    assert "Set TAMANDUA_PROXMOX_PASSWORD" in markdown


def test_preflight_work_package_summarizes_macos_auth_next_action(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-1-macos" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-1-macos",
                "wave": 1,
                "launcher_selected": True,
                "resource_tags": ["macos-agent"],
                "required_env": [],
                "expected_profile_ids": ["macos-backend-readiness-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    login_command = "tamandua-ctl remote login --server http://192.168.12.146:4000 --no-browser"
    token_login_command = (
        "tamandua-ctl remote login --server http://192.168.12.146:4000 --token $env:TAMANDUA_TOKEN"
    )
    (package_dir / "20260604T000000Z-macos-backend-readiness-probe.json").write_text(
        json.dumps(
            {
                "profile_id": "macos-backend-readiness-probe",
                "run_id": "20260604T000000Z-macos-backend-readiness-probe",
                "quality_gate": {
                    "status": "fail",
                    "passed": False,
                    "failures": ["macos_backend_readiness_gaps"],
                    "actionable_gaps": [
                        {
                            "test_id": "macos-backend-agent-row-present",
                            "missing": ["tamandua_ctl_auth"],
                            "gap_category": "infrastructure",
                            "evidence": {
                                "next_action": {
                                    "missing_readiness": ["tamandua_ctl_auth"],
                                    "required_env": [],
                                    "blockers": ["macos-backend-agent-row-present"],
                                    "action": (
                                        "Run tamandua-ctl remote login for the target server "
                                        "http://192.168.12.146:4000 because the saved remote login is for "
                                        "https://tamandua.treantlab.org; then rerun."
                                    ),
                                    "login_command": login_command,
                                    "token_env": "TAMANDUA_TOKEN",
                                    "token_login_command": token_login_command,
                                    "saved_server": "https://tamandua.treantlab.org",
                                    "target_server": "http://192.168.12.146:4000",
                                    "server_matches_target": False,
                                    "has_token": True,
                                }
                            },
                        }
                    ],
                },
                "tests": [
                    {
                        "id": "macos-backend-agent-row-present",
                        "status": "missed",
                        "missing_expected_fields": ["tamandua_ctl_auth"],
                        "gap_category": "infrastructure",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    json_path, markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]
    markdown = markdown_path.read_text(encoding="utf-8")

    action = package["evidence_excerpt"]["next_action"]
    assert action["missing_readiness"] == ["tamandua_ctl_auth"]
    assert action["login_command"] == login_command
    assert action["token_env"] == "TAMANDUA_TOKEN"
    assert action["token_login_command"] == token_login_command
    assert action["saved_server"] == "https://tamandua.treantlab.org"
    assert action["target_server"] == "http://192.168.12.146:4000"
    assert action["server_matches_target"] is False
    assert action["has_token"] is True
    assert "tamandua_ctl_auth" in markdown
    assert login_command in markdown
    assert token_login_command in markdown
    assert "secret" not in json.dumps(action).lower()


def test_preflight_work_package_summarizes_caldera_api_next_action(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-2-caldera" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-2-caldera",
                "wave": 2,
                "launcher_selected": True,
                "resource_tags": ["caldera"],
                "required_env": ["CALDERA_API_KEY"],
                "expected_profile_ids": ["caldera-api-shape-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260604T000000Z-caldera-api-shape-probe.json").write_text(
        json.dumps(
            {
                "profile_id": "caldera-api-shape-probe",
                "run_id": "20260604T000000Z-caldera-api-shape-probe",
                "quality_gate": {
                    "status": "fail",
                    "passed": False,
                    "failures": ["caldera_api_shape_gaps"],
                },
                "tests": [
                    {
                        "id": "caldera-api-agents-readable",
                        "status": "missed",
                        "missing_expected_fields": ["caldera_api_key_present"],
                        "gap_category": "infrastructure",
                    }
                ],
                "caldera_api_shape": {
                    "next_action": {
                        "caldera_url": "http://192.168.12.146:8888",
                        "missing_endpoints": ["/api/v2/agents"],
                        "required_env": ["CALDERA_API_KEY"],
                        "blockers": ["infrastructure"],
                        "action": "Set CALDERA_API_KEY, then rerun.",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    json_path, markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]
    markdown = markdown_path.read_text(encoding="utf-8")

    assert package["evidence_excerpt"]["next_action"]["missing_endpoints"] == ["/api/v2/agents"]
    assert package["evidence_excerpt"]["next_action"]["required_env"] == ["CALDERA_API_KEY"]
    assert "/api/v2/agents" in markdown
    assert "Set CALDERA_API_KEY" in markdown


def test_preflight_work_package_summarizes_caldera_paw_next_action(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-2-caldera" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-2-caldera",
                "wave": 2,
                "launcher_selected": True,
                "resource_tags": ["caldera"],
                "required_env": ["CALDERA_API_KEY", "CALDERA_AGENT_PAW"],
                "expected_profile_ids": ["caldera-paw-readiness-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260604T000000Z-caldera-paw-readiness-probe.json").write_text(
        json.dumps(
            {
                "profile_id": "caldera-paw-readiness-probe",
                "run_id": "20260604T000000Z-caldera-paw-readiness-probe",
                "quality_gate": {
                    "status": "fail",
                    "passed": False,
                    "failures": ["caldera_paw_readiness_gaps"],
                },
                "tests": [
                    {
                        "id": "caldera-target-paw-fresh",
                        "status": "missed",
                        "missing_expected_fields": ["caldera_agent_fresh"],
                        "gap_category": "infrastructure",
                    }
                ],
                "caldera_paw_readiness": {
                    "next_action": {
                        "caldera_url": "http://192.168.12.146:8888",
                        "requested_paw": "paw-1",
                        "requested_group": "tamandua-lab",
                        "freshness_seconds": 300,
                        "missing_readiness": ["target_paw_fresh"],
                        "required_env": ["CALDERA_API_KEY", "CALDERA_AGENT_PAW"],
                        "blockers": ["caldera-target-paw-fresh"],
                        "action": "Start a fresh Sandcat, then rerun.",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    json_path, markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]
    markdown = markdown_path.read_text(encoding="utf-8")

    action = package["evidence_excerpt"]["next_action"]
    assert action["missing_readiness"] == ["target_paw_fresh"]
    assert action["requested_paw"] == "paw-1"
    assert action["requested_group"] == "tamandua-lab"
    assert action["freshness_seconds"] == 300
    assert "target_paw_fresh" in markdown
    assert "Start a fresh Sandcat" in markdown


def test_preflight_work_package_summarizes_fresh_restore_next_action(tmp_path):
    output_dir = tmp_path / "dispatch"
    package_dir = output_dir / "wave-3-fresh-restore" / "outputs"
    package_dir.mkdir(parents=True)
    manifest = {
        "profile_id": "validation-execution-preflight-probe",
        "source_preflight": "preflight.json",
        "packages": [
            {
                "package_id": "wave-3-fresh-restore",
                "wave": 3,
                "launcher_selected": False,
                "manual_reason": "requires restored Windows VM",
                "resource_tags": ["windows", "fresh_restore"],
                "required_env": ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"],
                "expected_profile_ids": ["fresh-restore-provenance-probe"],
                "output_dir": str(package_dir),
            },
        ],
    }
    (output_dir / "dispatch_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package_dir / "20260604T000000Z-fresh-restore-provenance-probe.json").write_text(
        json.dumps(
            {
                "profile_id": "fresh-restore-provenance-probe",
                "run_id": "20260604T000000Z-fresh-restore-provenance-probe",
                "quality_gate": {
                    "status": "fail",
                    "passed": False,
                    "failures": ["fresh_restore_provenance_gaps"],
                },
                "tests": [
                    {
                        "id": "fresh-restore-windows-300-artifact-set-present",
                        "status": "missed",
                        "missing_expected_fields": ["windows-roadmap-300-batch-01"],
                        "gap_category": "infrastructure",
                    }
                ],
                "fresh_restore_provenance": {
                    "next_action": {
                        "missing_profiles": ["windows-roadmap-300-batch-01"],
                        "non_executed_profiles": ["windows-roadmap-300-batch-01"],
                        "missing_metadata_profiles": ["windows-roadmap-300-batch-01"],
                        "field_gaps": {"windows-roadmap-300-batch-01": ["snapshot_id"]},
                        "required_env": ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"],
                        "blockers": ["fresh-restore-windows-300-artifact-set-present"],
                        "action": "Restore WIN-TEMPLATE, run the six batches, then rerun.",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    json_path, markdown_path = preflight_work_package.summarize_dispatch(output_dir)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    package = results["packages"][0]
    markdown = markdown_path.read_text(encoding="utf-8")

    assert package["evidence_excerpt"]["next_action"]["missing_profiles"] == ["windows-roadmap-300-batch-01"]
    assert package["evidence_excerpt"]["next_action"]["non_executed_profiles"] == ["windows-roadmap-300-batch-01"]
    assert package["evidence_excerpt"]["next_action"]["required_env"] == ["TAMANDUA_FRESH_RESTORE_SNAPSHOT_ID"]
    assert "windows-roadmap-300-batch-01" in markdown
    assert "Restore WIN-TEMPLATE" in markdown


def windows_lab_agent(
    *,
    status: str = "online",
    health: str = "healthy",
    live_response: str = "reported",
    endpoint_telemetry: str = "reported",
    cpu_usage: object = 12.5,
    driver_state: str = "loaded",
) -> dict[str, object]:
    return {
        "id": "agent-win-template",
        "hostname": "WIN-TEMPLATE",
        "status": status,
        "os_type": "windows",
        "os_version": "Windows Server",
        "last_seen": "2026-06-03T10:00:00Z",
        "health_status": {
            "status": health,
            "metrics": {
                "cpu_usage": cpu_usage,
                "driver_state": driver_state,
            },
            "reasons": [],
        },
        "platform_capabilities": [
            {"id": "live_response", "observed": live_response},
            {"id": "endpoint_telemetry", "observed": endpoint_telemetry},
            {"id": "kernel_sensor", "observed": "reported"},
        ],
    }


def test_windows_lab_readiness_accepts_online_degraded_target_with_runtime_capabilities():
    ctl = {"ok": True, "payload": {"data": [windows_lab_agent(health="degraded")]}}

    tests, readiness = windows_lab_readiness.build_tests(ctl, "WIN-TEMPLATE", None, 90.0)

    assert [test["status"] for test in tests] == ["covered"] * 6
    assert readiness["ready_for_windows_broad_runs"] is True
    assert readiness["target"]["health"] == "degraded"
    assert readiness["target"]["live_response"] == "reported"
    assert readiness["target"]["endpoint_telemetry"] == "reported"
    assert readiness["next_action"]["missing_readiness"] == []
    assert "readiness is green" in readiness["next_action"]["action"]


def test_windows_lab_readiness_rejects_present_but_offline_unknown_target():
    ctl = {
        "ok": True,
        "payload": {
            "data": [
                windows_lab_agent(
                    status="offline",
                    health="unknown",
                    live_response="not_observed",
                    endpoint_telemetry="not_observed",
                )
            ]
        },
    }

    tests, readiness = windows_lab_readiness.build_tests(ctl, "WIN-TEMPLATE", None, 90.0)
    by_id = {test["id"]: test for test in tests}

    assert by_id["windows-lab-target-present"]["status"] == "covered"
    assert by_id["windows-lab-target-online"]["missing_expected_fields"] == ["infra"]
    assert by_id["windows-lab-target-health-acceptable"]["missing_expected_fields"] == ["agent-health"]
    assert by_id["windows-lab-target-live-response-ready"]["missing_expected_fields"] == ["runner"]
    assert by_id["windows-lab-target-endpoint-telemetry-ready"]["missing_expected_fields"] == ["collector"]
    assert readiness["ready_for_windows_broad_runs"] is False
    assert readiness["blockers"] == ["agent-health", "collector", "infra", "runner"]
    assert readiness["next_action"]["target_hostname"] == "WIN-TEMPLATE"
    assert readiness["next_action"]["target_agent_id"] == "agent-win-template"
    assert readiness["next_action"]["missing_readiness"] == [
        "status_online",
        "health_or_load_safe",
        "live_response_reported",
        "endpoint_telemetry_reported",
    ]
    assert "Bring WIN-TEMPLATE online" in readiness["next_action"]["action"]


def test_windows_lab_readiness_rejects_driver_not_loaded_even_with_online_target():
    ctl = {"ok": True, "payload": {"data": [windows_lab_agent(driver_state="not_loaded")]}}

    tests, readiness = windows_lab_readiness.build_tests(ctl, "WIN-TEMPLATE", None, 90.0)
    load_safe = next(test for test in tests if test["id"] == "windows-lab-target-load-safe-for-broad-runs")

    assert load_safe["status"] == "missed"
    assert load_safe["missing_expected_fields"] == ["agent-health"]
    assert load_safe["evidence"]["driver_not_loaded"] is True
    assert readiness["ready_for_windows_broad_runs"] is False


def test_windows_lab_readiness_markdown_renders_next_action(tmp_path):
    report = {
        "run_id": "20260604T000000Z-windows-lab-execution-readiness-probe",
        "quality_gate": {"status": "fail"},
        "target_hostname": "WIN-TEMPLATE",
        "tests": [{"id": "windows-lab-target-online", "status": "missed", "gap_category": "infra"}],
        "windows_lab_readiness": {
            "ready_for_windows_broad_runs": False,
            "target": {"hostname": "WIN-TEMPLATE", "status": "offline"},
            "next_action": {
                "target_hostname": "WIN-TEMPLATE",
                "target_agent_id": "agent-win-template",
                "missing_readiness": ["status_online", "live_response_reported"],
                "action": "Bring WIN-TEMPLATE online, then rerun.",
            },
        },
    }
    path = tmp_path / "windows.md"

    windows_lab_readiness.write_markdown(path, report)
    text = path.read_text(encoding="utf-8")

    assert "## Next Action" in text
    assert "WIN-TEMPLATE" in text
    assert "status_online, live_response_reported" in text
    assert "Bring WIN-TEMPLATE online" in text


def test_windows_connection_stability_accepts_active_stable_session_with_telemetry():
    sessions = [
        windows_connection_stability.Session(
            connected_at="2026-06-03T10:00:00Z",
            disconnected_at="2026-06-03T10:06:00Z",
            telemetry_batches=1,
            telemetry_events=5,
        ),
        windows_connection_stability.Session(
            connected_at="2026-06-03T10:10:00Z",
            joined_at="2026-06-03T10:10:05Z",
            first_telemetry_at="2026-06-03T10:10:15Z",
            last_telemetry_at="2026-06-03T10:12:00Z",
            telemetry_batches=2,
            telemetry_events=8,
        ),
    ]

    tests, stability = windows_connection_stability.build_tests({"ok": True}, sessions, 300)

    assert [test["status"] for test in tests] == ["covered"] * 5
    assert stability["ready_for_windows_broad_runs"] is True
    assert stability["stable_session_count"] == 1
    assert stability["active_session_count"] == 1
    assert stability["telemetry_events"] == 13
    assert stability["next_action"]["missing_stability"] == []
    assert "Connection stability is ready" in stability["next_action"]["action"]


def test_windows_connection_stability_rejects_missing_auth_logs_and_disconnected_session():
    sessions = [
        windows_connection_stability.Session(
            connected_at="2026-06-03T10:00:00Z",
            disconnected_at="2026-06-03T10:01:00Z",
            disconnect_reason="Socket disconnected",
            telemetry_batches=0,
            telemetry_events=0,
        )
    ]

    tests, stability = windows_connection_stability.build_tests(
        {"ok": True, "command": "ssh tamandua-server tail agent.log"},
        sessions,
        300,
    )
    by_id = {test["id"]: test for test in tests}

    assert by_id["windows-agent-server-log-readable"]["missing_expected_fields"] == []
    assert by_id["windows-agent-stable-session-duration"]["missing_expected_fields"] == ["agent-health"]
    assert by_id["windows-agent-not-currently-disconnected"]["missing_expected_fields"] == ["runner"]
    assert by_id["windows-agent-telemetry-flow-observed"]["missing_expected_fields"] == ["collector"]
    assert stability["next_action"]["missing_stability"] == [
        "stable_session_300s",
        "active_session",
        "telemetry_batches",
    ]
    assert "Bring WIN-TEMPLATE online" in stability["next_action"]["action"]


def test_windows_connection_stability_next_action_for_missing_server_password():
    tests, stability = windows_connection_stability.build_tests(
        {"ok": False, "error": "missing_server_password", "required_env": "TAMANDUA_SERVER_PASSWORD"},
        [],
        300,
    )

    assert tests[0]["missing_expected_fields"] == ["infra"]
    assert stability["next_action"]["missing_stability"][0] == "server_log_access"
    assert "TAMANDUA_SERVER_PASSWORD" in stability["next_action"]["action"]


def test_windows_connection_stability_markdown_renders_next_action(tmp_path):
    report = {
        "run_id": "20260604T000000Z-windows-agent-connection-stability-probe",
        "quality_gate": {"status": "fail"},
        "agent_id": "agent-win-template",
        "tests": [{"id": "windows-agent-telemetry-flow-observed", "status": "missed", "gap_category": "collector"}],
        "server_log_probe": {},
        "connection_stability": {
            "ready_for_windows_broad_runs": False,
            "next_action": {
                "missing_stability": ["telemetry_batches"],
                "action": "Bring WIN-TEMPLATE online, then rerun.",
            },
        },
    }
    path = tmp_path / "stability.md"

    windows_connection_stability.write_markdown(path, report)
    text = path.read_text(encoding="utf-8")

    assert "## Next Action" in text
    assert "telemetry_batches" in text
    assert "Bring WIN-TEMPLATE online" in text


def test_windows_readiness_probes_write_to_explicit_output_dir(tmp_path, monkeypatch):
    lab_output_dir = tmp_path / "windows-lab-readiness"
    monkeypatch.setattr(
        windows_lab_readiness,
        "run_ctl",
        lambda _ctl_path, _server: {"ok": True, "payload": {"data": []}, "command": "tamandua-ctl"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "windows-lab-execution-readiness-probe",
            "--output-dir",
            str(lab_output_dir),
        ],
    )

    lab_exit_code = windows_lab_readiness.main()

    assert lab_exit_code == 1
    assert list(lab_output_dir.glob("*-windows-lab-execution-readiness-probe.json"))
    assert list(lab_output_dir.glob("*-windows-lab-execution-readiness-probe.md"))
    assert list(lab_output_dir.glob("*-windows-lab-execution-readiness-probe.comparison.json"))

    stability_output_dir = tmp_path / "windows-connection-stability"
    monkeypatch.setattr(
        windows_connection_stability,
        "fetch_logs",
        lambda _args: {
            "ok": False,
            "error": "missing_server_password",
            "required_env": "TAMANDUA_SERVER_PASSWORD",
            "password_supplied": False,
            "stdout": "",
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "windows-agent-connection-stability-probe",
            "--output-dir",
            str(stability_output_dir),
        ],
    )

    stability_exit_code = windows_connection_stability.main()

    assert stability_exit_code == 1
    assert list(stability_output_dir.glob("*-windows-agent-connection-stability-probe.json"))
    assert list(stability_output_dir.glob("*-windows-agent-connection-stability-probe.md"))
    assert list(stability_output_dir.glob("*-windows-agent-connection-stability-probe.comparison.json"))


def test_preflight_blocks_atomic_extended_for_atomic_profile_gap():
    closure_gate = {
        "tests": [
            {"status": "missed", "evidence": {"roadmap_key": "M"}},
        ]
    }
    blockers = [
        {
            "roadmap": "M",
            "profile_id": "windows-atomic-extended-safe",
            "required_env": [],
            "blocking_gaps": ["quality_gate_failed"],
        }
    ]

    readiness = preflight.classify_run_classes(closure_gate, {}, [], blockers)
    by_class = {item["run_class"]: item for item in readiness}

    assert not by_class["windows-broad"]["allowed"]
    assert not by_class["windows-atomic-extended"]["allowed"]
    assert "windows-atomic-extended-safe" in by_class["windows-atomic-extended"]["blocking_profiles"]

    sequence = preflight.derive_unblock_sequence({}, [], blockers, readiness)
    atomic_step = next(
        item for item in sequence if item["step_id"] == "resolve-atomic-extended-preconditions"
    )

    assert atomic_step["roadmaps"] == ["M"]
    assert atomic_step["blocked_run_classes"] == ["windows-atomic-extended", "windows-broad"]


def test_preflight_blocks_macos_server_smoke_for_macos_backend_gap():
    closure_gate = {
        "tests": [
            {"status": "missed", "evidence": {"roadmap_key": "E"}},
        ]
    }
    blockers = [
        {
            "roadmap": "E",
            "profile_id": "macos-backend-readiness-probe",
            "required_env": [],
            "blocking_gaps": ["macos_backend_readiness_missing"],
        }
    ]

    readiness = preflight.classify_run_classes(closure_gate, {}, [], blockers)
    macos_class = next(item for item in readiness if item["run_class"] == "macos-server-backed-smoke")

    assert not macos_class["allowed"]
    assert macos_class["open_roadmaps"] == ["E"]
    assert macos_class["blocking_profiles"] == ["macos-backend-readiness-probe"]

    sequence = preflight.derive_unblock_sequence({}, [], blockers, readiness)
    macos_step = next(item for item in sequence if item["step_id"] == "restore-macos-backend-readiness")

    assert macos_step["roadmaps"] == ["E"]
    assert macos_step["blocked_run_classes"] == ["macos-server-backed-smoke"]


def test_windows_error_reporting_ntdll_noise_is_narrowly_benign():
    row = {
        "event_type": "defense_evasion",
        "detection_name": "ntdll_write_ntmapviewofsection",
        "process_name": "wermgr.exe",
        "process_path": r"\Device\HarddiskVolume2\Windows\SysWOW64\wermgr.exe",
        "operation": "NtMapViewOfSection",
        "mem_type_str": "MEM_IMAGE",
        "new_protection_str": "PAGE_EXECUTE_READ",
    }

    assert validation.is_benign_windows_error_reporting_ntdll_event(row)


def test_windows_error_reporting_ntdll_noise_keeps_suspicious_context():
    row = {
        "event_type": "defense_evasion",
        "detection_name": "ntdll_write_ntmapviewofsection",
        "process_name": "wermgr.exe",
        "process_path": r"C:\Windows\SysWOW64\wermgr.exe",
        "operation": "NtMapViewOfSection",
        "mem_type_str": "MEM_IMAGE",
        "new_protection_str": "PAGE_EXECUTE_READ",
        "command_line": "wermgr.exe spawned cmd.exe /c whoami",
    }

    assert not validation.is_benign_windows_error_reporting_ntdll_event(row)


def test_score_expected_fields_matches_nested_registry_key():
    samples = [
        {
            "event_type": "registry_set_value",
            "payload": {"pid": 1000},
            "enrichment": {
                "correlation_entities": {
                    "registry": {"key_path": r"\\REGISTRY\\USER\\Software\\Tamandua"}
                }
            },
        }
    ]

    score = validation.score_expected_fields(["registry_key"], samples)

    assert score["missing_expected_fields"] == []
    assert score["observed_field_counts"]["registry_key"] == 1


def test_score_expected_fields_accepts_common_remote_ip_aliases():
    samples = [
        {
            "event_type": "network_connect",
            "payload": {"dest_ip": "93.184.216.34"},
        },
        {
            "event_type": "network_connect",
            "payload": {"remote_address": "93.184.216.35"},
        },
    ]

    score = validation.score_expected_fields(["remote_ip"], samples)

    assert score["missing_expected_fields"] == []
    assert score["observed_field_counts"]["remote_ip"] == 2


def test_score_expected_fields_does_not_treat_dns_answers_as_remote_ip():
    samples = [
        {
            "event_type": "dns_query",
            "payload": {
                "domain": "example.com",
                "resolved_ips": ["93.184.216.34"],
                "answers": ["93.184.216.34"],
            },
        }
    ]

    score = validation.score_expected_fields(["remote_ip"], samples)

    assert score["missing_expected_fields"] == ["remote_ip"]
    assert score["observed_field_counts"] == {}


def test_score_test_uses_inline_event_sample_detections():
    score = validation.score_test(
        {
            "expected_telemetry": ["process_create"],
            "expected_detections": ["encoded", "powershell"],
        },
        [{"event_type": "process_create", "source_name": "endpoint_process", "count": 1}],
        [],
        [],
        [
            {
                "event_type": "process_create",
                "severity": "high",
                "detections": [
                    {
                        "rule_name": "encoded_powershell_execution",
                        "detection_type": "script_threat",
                        "description": "Encoded PowerShell command line",
                    }
                ],
            }
        ],
    )

    assert score["missing_expected_detections"] == []
    assert score["observed_expected_detections"] == ["encoded", "powershell"]


def test_score_test_accepts_explicit_alternative_telemetry_without_hiding_strict_gap():
    score = validation.score_test(
        {
            "expected_telemetry": ["process_create"],
            "expected_telemetry_any": [["process_create"], ["live_response_command"]],
            "expected_fields": ["agent_id", "hostname", "process_name", "command_line"],
        },
        [{"event_type": "live_response_command", "source_name": "live_response_audit", "count": 1}],
        [],
        [],
        [
            {
                "event_type": "live_response_command",
                "payload": {
                    "agent_id": "agent-1",
                    "hostname": "WIN-TEMPLATE",
                    "process_name": "cmd.exe",
                    "command_line": "cmd.exe /d /c whoami",
                },
            }
        ],
    )

    assert score["status"] == "covered"
    assert score["missing_expected_telemetry"] == []
    assert score["missing_strict_expected_telemetry"] == ["process_create"]
    assert score["observed_telemetry_alternative"] == ["live_response_command"]
    assert score["coverage"]["telemetry"] == "ok"


def test_transport_only_live_response_alternative_uses_audit_field_contract():
    score = validation.score_transport_only_execution(
        {
            "expected_telemetry": ["process_create"],
            "expected_telemetry_any": [["live_response_command_completed"]],
            "expected_fields_by_event_type": {
                "process_create": ["agent_id", "hostname", "process_name", "command_line"],
                "live_response_command_completed": ["agent_id", "hostname", "command", "session_id"],
            },
        },
        {
            "tamandua_ctl_payload": {
                "status": "completed",
                "agent_id": "agent-1",
                "hostname": "WIN-TEMPLATE",
                "command": "cmd.exe /d /c whoami",
                "session_id": "session-1",
            },
        },
    )

    assert score["status"] == "covered"
    assert score["missing_expected_telemetry"] == []
    assert score["missing_strict_expected_telemetry"] == ["process_create"]
    assert score["observed_telemetry_alternative"] == ["live_response_command_completed"]
    assert score["missing_expected_fields"] == []


def test_tamandua_ctl_command_requires_semantic_marker_in_output(monkeypatch):
    def fake_local_command(_invocation, cwd=None, timeout=120):
        return validation.CommandResult(
            host="local",
            command="tamandua-ctl remote command",
            exit_code=0,
            stdout=(
                '{"status":"completed","shell_ready":true,"unconfirmed_dispatch":false,'
                '"output":"\\r\\n[Tamandua shell ready]\\r\\nroot@lab:/# ",'
                '"events":[{"event":"session_started"}]}'
            ),
            stderr="",
            duration_ms=1000,
        )

    monkeypatch.setattr(validation, "local_command", fake_local_command)
    args = Namespace(
        agent_id="agent-1",
        live_response_idle_timeout_seconds=2,
        live_response_shell_start_timeout_seconds=20,
        live_response_supervisor_mode=False,
        tamandua_ctl_path="tamandua-ctl",
        tamandua_ctl_server="https://tamandua.example",
        tamandua_ctl_token=None,
    )

    result = validation.tamandua_ctl_command(
        args,
        "sh -lc 'echo tamandua-semantic-rewrite-test-case; id'",
        30,
    )

    assert result["outer_exit_code"] == 1
    assert result["error_code"] == "live_response_command_marker_missing"


def test_score_test_accepts_persisted_kernel_driver_event_as_raw_evidence():
    before = {"driver_status": {"raw_event_type_counts": {"registry_set_value": 10}}}
    after = {"driver_status": {"raw_event_type_counts": {"registry_set_value": 10}}}

    score = validation.score_test(
        {
            "expected_telemetry": ["process_create"],
            "expected_driver_raw_event_types": ["registry_set_value"],
        },
        [
            {"event_type": "process_create", "source_name": "endpoint_process", "count": 1},
            {"event_type": "registry_set_value", "source_name": "kernel_driver", "count": 1},
        ],
        [],
        [],
        [],
        before,
        after,
    )

    assert score["missing_expected_driver_raw_event_types"] == []
    assert score["coverage"]["driver_raw"] == "ok"


def test_gap_category_routes_common_failures():
    assert validation.gap_category({"score": {"status": "covered"}}) == "none"
    assert validation.gap_category({"score": {"status": "execution_failed"}}) == "runner"
    assert (
        validation.gap_category(
            {"fallback_used": True, "score": {"status": "partial", "missing_expected_detections": ["encoded"]}}
        )
        == "claim-boundary"
    )
    assert (
        validation.gap_category({"score": {"status": "partial", "missing_expected_fields": ["remote_ip"]}})
        == "normalization"
    )
    assert (
        validation.gap_category({"score": {"status": "missed", "missing_expected_telemetry": ["process_create"]}})
        == "collector"
    )
    assert (
        validation.gap_category({"score": {"status": "partial", "missing_expected_detections": ["encoded"]}})
        == "detector"
    )


def test_classify_live_response_auth_and_offline_failures_as_runner_infra():
    status, gap, code = validation.classify_execution_failure(
        {
            "transport": "tamandua_ctl_live_response",
            "stderr": '[ERROR] failed to list agents: HTTP 401 Unauthorized {"error":"Invalid or expired token"}',
        }
    )

    assert (status, gap, code) == ("infra_blocked", "runner", "cli_auth_invalid_or_expired")

    status, gap, code = validation.classify_execution_failure(
        {
            "transport": "tamandua_ctl_live_response",
            "stderr": "[ERROR] failed to connect dashboard socket\n  Caused by: HTTP error: 403 Forbidden",
        }
    )

    assert (status, gap, code) == ("infra_blocked", "runner", "cli_auth_forbidden")

    status, gap, code = validation.classify_execution_failure(
        {
            "transport": "tamandua_ctl_live_response",
            "stderr": "[ERROR] live response join failed: Agent is not online",
        }
    )

    assert (status, gap, code) == ("infra_blocked", "runner", "live_response_agent_offline")


def test_summarize_tests_exposes_actionable_gap_categories():
    summary = validation.summarize_tests(
        [
            {
                "id": "roadmap-win-test",
                "tags": ["tactic:execution", "mitre:T1059.001", "category:atomic-upstream-candidate"],
                "validation_category": "atomic-upstream-candidate",
                "execution_class": "fallback",
                "fallback_used": True,
                "score": {"status": "partial", "missing_expected_detections": ["powershell"]},
            }
        ]
    )

    assert summary["gap_category_counts"] == {"claim-boundary": 1}
    assert summary["tactic_coverage"]["execution"]["gap_category_counts"] == {"claim-boundary": 1}
    assert summary["technique_coverage"]["T1059.001"]["gap_category_counts"] == {"claim-boundary": 1}
    assert summary["category_coverage"]["atomic-upstream-candidate"]["gap_category_counts"] == {"claim-boundary": 1}
    assert summary["actionable_gaps"][0]["validation_category"] == "atomic-upstream-candidate"


def test_executed_without_server_evidence_fails_quality_gate():
    summary = validation.summarize_tests(
        [
            {
                "id": "roadmap-mac-execution-001-t1059-004",
                "tags": ["tactic:execution", "mitre:T1059.004", "category:sensor_contract"],
                "validation_category": "sensor_contract",
                "execution_class": "deterministic",
                "score": {
                    "status": "executed_without_server_evidence",
                    "missing_expected_telemetry": ["process_create"],
                },
            }
        ]
    )
    report = {"execute": True, "summary": summary}

    gate = validation.evaluate_gates(
        report,
        Namespace(
            benchmark_lane="enterprise-eval",
            fail_on_missed=True,
            fail_on_partial=True,
            max_driver_channel_drops=0,
            max_driver_kernel_drops=0,
            max_unexpected_high_critical=0,
            max_unknown_source=0,
            require_upstream=False,
        ),
    )
    report["quality_gate"] = gate
    scorecard = validation.benchmark_scorecard(report)

    assert summary["executed_without_server_evidence"] == 1
    assert summary["gap_category_counts"] == {"collector": 1}
    assert gate["passed"] is False
    assert "executed_without_server_evidence" in gate["failures"]
    assert scorecard["maturity_band"] == "prototype"
    assert "missing_server_evidence" in scorecard["blocking_gaps"]


def test_windows_roadmap_scenarios_have_traceability_by_technique_category_and_lane():
    scenarios = roadmap.build_scenarios()

    assert len(scenarios) == 300
    for scenario in scenarios:
        trace = scenario.get("traceability") or {}
        assert scenario.get("technique_id")
        assert scenario.get("validation_category")
        assert scenario.get("benchmark_lane")
        assert trace.get("technique") == scenario["technique_id"]
        assert trace.get("category") == scenario["validation_category"]
        assert trace.get("lane") == scenario["benchmark_lane"]


def test_windows_roadmap_batch_generator_declares_live_response_audit_alternative():
    scenario = {
        "id": "win-execution-999",
        "name": "Generated live response audit fallback contract",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "validation_category": "atomic-upstream-candidate",
        "benchmark_lane": "enterprise-eval",
        "executor": "atomic_or_command",
        "upstream_target_lane": "atomic-upstream",
        "existing_profile_refs": [],
        "variant": "safe",
        "status": "planned",
        "safe_level": "safe",
    }

    test = roadmap_batch.profile_test("windows", scenario)

    assert test["expected_telemetry"] == ["process_create"]
    assert test["expected_telemetry_any"] == [["live_response_command_completed"]]
    assert test["expected_fields_by_event_type"]["process_create"] == roadmap_batch.WINDOWS_REQUIRED_FIELDS
    assert test["expected_fields_by_event_type"]["live_response_command_completed"] == [
        "agent_id",
        "hostname",
        "command",
        "session_id",
    ]
    assert "expected_fields" not in test


def test_cmd_fallback_commands_get_observable_dwell():
    command = 'cmd.exe /d /c "curl.exe -I http://127.0.0.1/ 2>nul || ver"'

    normalized = validation.normalize_guest_command(command)

    assert normalized.startswith('cmd.exe /d /c "curl.exe')
    assert "ping -n 9 127.0.0.1 > nul" in normalized
    assert normalized.endswith('"')


def test_benchmark_setup_alert_filter_is_path_scoped_for_caldera_harness():
    assert validation.is_benchmark_setup_alert(
        {
            "title": "Agent detection: powershell_encoded_command",
            "evidence": {
                "process": {
                    "path": r"D:\ProgramData\Tamandua\caldera\sandcat-v1.exe",
                    "command_line": r"D:\ProgramData\Tamandua\caldera\sandcat-v1.exe -server http://127.0.0.1",
                }
            },
        }
    )

    assert not validation.is_benchmark_setup_alert(
        {
            "title": "Agent detection: caldera-enterprise-c2-beacon-safe",
            "detection_metadata": {"rule_name": "caldera-enterprise-c2-beacon-safe"},
            "evidence": {"process": {"name": "curl.exe", "command_line": "curl.exe http://10.0.0.5/beacon"}},
        }
    )


def test_benchmark_setup_alert_filter_excludes_tamandua_agent_service_starter():
    assert validation.is_benchmark_setup_alert(
        {
            "title": "Agent detection: behavioral_script_from_temp",
            "evidence": {
                "process": {
                    "name": "powershell.exe",
                    "command_line": (
                        "powershell.exe -ExecutionPolicy Bypass -Command "
                        "\"Start-Process -FilePath 'D:\\Program Files\\Tamandua\\tamandua-agent.exe' "
                        "-ArgumentList 'service' -WindowStyle Hidden -Verb RunAs\""
                    ),
                }
            },
        }
    )


def test_benchmark_setup_alert_filter_excludes_enterprise_eval_marker():
    assert validation.is_benchmark_setup_alert(
        {
            "title": "Agent detection: registry_t1547_001",
            "evidence": {
                "registry": [
                    {
                        "key": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        "value": "TamanduaEnterpriseEval",
                    }
                ]
            },
        }
    )


def test_benchmark_setup_alert_filter_excludes_safe_masquerade_marker_only():
    assert validation.is_benchmark_setup_alert(
        {
            "title": "Agent detection: process_masquerade_outside_system32",
            "evidence": {
                "process": {
                    "name": "svchost.exe",
                    "path": r"D:\Windows\Temp\svchost.exe",
                    "cmdline": r"D:\WINDOWS\TEMP\svchost.exe  /c ping -n 5 127.0.0.1 > nul ",
                }
            },
        }
    )

    assert not validation.is_benchmark_setup_alert(
        {
            "title": "Agent detection: process_masquerade_outside_system32",
            "evidence": {
                "process": {
                    "name": "svchost.exe",
                    "path": r"D:\Users\Public\svchost.exe",
                    "cmdline": r"D:\Users\Public\svchost.exe /c whoami",
                }
            },
        }
    )
