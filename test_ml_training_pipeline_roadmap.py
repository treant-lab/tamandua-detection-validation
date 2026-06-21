from __future__ import annotations

import re
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
ROADMAP = ROOT / "docs" / "benchmarks" / "ML_TRAINING_PIPELINE_ROADMAP.md"
NEXT_VALIDATION_QUEUE = ROOT / "docs" / "benchmarks" / "NEXT_VALIDATION_WORK_QUEUE.md"
PARALLEL_EXECUTION_BOARD = ROOT / "docs" / "benchmarks" / "PARALLEL_EXECUTION_BOARD.md"
DATASET_GUIDE = ROOT / "apps" / "tamandua_ml" / "docs" / "DATASET_ACQUISITION.md"
DATASET_QUICKSTART = ROOT / "apps" / "tamandua_ml" / "docs" / "DATASET_QUICKSTART.md"
RUNBOOK = ROOT / "docs" / "apps" / "tamandua_ml" / "PRODUCTION_ACQUISITION_RUNBOOK.md"
SCRIPTS_README = ROOT / "apps" / "tamandua_ml" / "scripts" / "README.md"
README = ROOT / "apps" / "tamandua_ml" / "README.md"
TRAINING_QUICKSTART = ROOT / "docs" / "apps" / "tamandua_ml" / "TRAINING_QUICKSTART.md"
ML_PLATFORM_EVOLUTION_PLAN = ROOT / "docs" / "apps" / "tamandua_ml" / "ML_PLATFORM_EVOLUTION_PLAN.md"
ML_BENCHMARK_VALIDATION_PLAN = ROOT / "docs" / "apps" / "tamandua_ml" / "ML_BENCHMARK_VALIDATION_PLAN.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_ml_training_pipeline_roadmap_preserves_goal_and_gate_boundaries() -> None:
    text = read(ROADMAP)

    required_fragments = [
        "goal_complete=false",
        "ready_for_completion_claim=false",
        "goal_missing_requirements=9",
        "wave1_governed_acquisition",
        "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH",
        "TAMANDUA_ALLOW_ML_TRAINING",
        "TAMANDUA_ALLOW_ML_PARITY",
        "TAMANDUA_ALLOW_ML_SERVICE_BENCH",
        "TAMANDUA_ALLOW_ML_PIPELINE_REPLAY",
        "TAMANDUA_ALLOW_ML_HOLDOUT",
        "standalone model detection",
        "agent-side ONNX detection",
        "Tamandua platform replay detection",
    ]

    for fragment in required_fragments:
        assert fragment in text


def test_ml_training_pipeline_roadmap_preserves_vx_metadata_only_boundary() -> None:
    text = read(ROADMAP)

    required_fragments = [
        "vx-underground InTheWild",
        "holdout_candidate",
        "metadata only",
        "archive_downloaded=false",
        "used_in_training=false",
        "raw_archives_in_repo=false",
        "archive_extraction_performed=false",
        "not part of the current train/validation/test split",
        "TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD",
        "Do not set `TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD` during Wave 1",
    ]

    for fragment in required_fragments:
        assert fragment in text

    vx_guard_positions = [match.start() for match in re.finditer("TAMANDUA_ALLOW_VX_UNDERGROUND_DOWNLOAD", text)]
    wave1_execute_position = text.index("TAMANDUA_ALLOW_ML_REAL_ACQUISITION")
    assert vx_guard_positions
    assert any(position > wave1_execute_position for position in vx_guard_positions)


def test_ml_training_pipeline_roadmap_lists_all_completion_requirements() -> None:
    text = read(ROADMAP)

    for requirement_id in [
        "wave1_governed_acquisition",
        "wave1_sanitized_manifest",
        "ml1_model_quality",
        "ml1_model_contract_and_card",
        "ml2_pytorch_onnx_parity",
        "ml3_agent_onnx_parity",
        "ml4_service_benchmark",
        "ml5_tamandua_replay",
        "ml6_cross_time_holdout",
    ]:
        assert requirement_id in text


def test_ml_training_pipeline_roadmap_uses_current_governed_next_step() -> None:
    text = read(ROADMAP)
    next_step = text.split("## Next Operator Step", 1)[1]

    assert "20260620T-ml-execution-status-virusshare-source-aware.json" in text
    assert "20260620T2310Z-ml-execution-status-after-secret-sanitization.json" in text
    assert "20260620T2310Z-ml-platform-readiness-after-secret-sanitization.json" in text
    assert "20260620T2310Z-ml-mirror-publication-after-secret-sanitization.json" in text
    assert "20260621T-ml-mirror-publication-post-governed-route-publish.json" in text
    assert "tamandua-ml` staging is clean at local snapshot `a37efe2` with 731 tracked" in text
    assert "20260620T2320Z-ml-next-action-secret-readiness.json" in text
    assert "20260621T-ml-next-gate-authorization-post-win-template-gate-threading-governed.json" in text
    assert "launch_package" in text
    assert "authorized_for_guarded_execution=true" in text
    assert "effective_source_route=malwarebazaar_governed_acquisition" in text
    assert "hold_do_not_push" in text
    assert "older secret-readiness and source-aware\n  VirusShare packets remain historical or conditional fallback evidence" in text
    assert "wave_1_real_acquisition_launcher.ps1" in next_step
    assert "download_production_dataset.py" in next_step


def test_ml_validation_queue_uses_current_governed_next_step() -> None:
    text = read(NEXT_VALIDATION_QUEUE)

    assert "20260621T-ml-next-action-post-win-template-gate-threading-governed.run.json" in text
    assert "20260621T-ml-next-gate-authorization-post-win-template-gate-threading-governed.json" in text
    assert "shell execution: none" not in text
    assert "wave_1_real_acquisition_launcher.ps1 -Execute" in text
    assert "TAMANDUA_MALWAREBAZAAR_AUTH_KEY" in text
    assert "authorized_for_guarded_execution=true" in text
    assert "malwarebazaar_governed_acquisition" in text
    assert "Direct `download_production_dataset.py`" in text
    assert "invocation is not valid production evidence for this Wave 1 route" in text

    current_intro = text.split("For the ML platform execution queue", 1)[1]
    current_intro = current_intro.split("The current pre-lab sweep also", 1)[0]
    assert "20260604T-ml-prelab-next-action-validation.run.json" not in current_intro
    assert "selected action is now\n`ml_data_virusshare_fallback`" not in current_intro


def test_parallel_execution_board_uses_current_governed_next_step() -> None:
    text = read(PARALLEL_EXECUTION_BOARD)
    active_work = text.split("## Current Active Work", 1)[1]
    active_work = active_work.split("The synthetic validation-only transition probe", 1)[0]

    assert "20260621T-ml-next-action-post-win-template-gate-threading-governed.run.json" in active_work
    assert "wave_1_real_acquisition_launcher.ps1 -Execute" in active_work
    assert "TAMANDUA_MALWAREBAZAAR_AUTH_KEY" in active_work
    assert "malwarebazaar_governed_acquisition" in active_work
    assert "not the current execute path" in active_work
    assert "20260604T-ml-prelab-next-action-validation.run.json` are historical" in active_work
    assert "Only `20260604T-ml-prelab-next-action-validation.run.json` is the current" not in active_work


def test_ml_training_pipeline_roadmap_is_linked_from_operator_docs() -> None:
    relative_link = "docs/benchmarks/ML_TRAINING_PIPELINE_ROADMAP.md"
    assert relative_link in read(DATASET_GUIDE)
    assert "../../docs/benchmarks/ML_TRAINING_PIPELINE_ROADMAP.md" in read(README)


def test_operator_docs_route_real_acquisition_through_guarded_launcher() -> None:
    guarded_fragments = [
        "wave_1_real_acquisition_launcher.ps1",
        "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
        "TAMANDUA_MALWAREBAZAAR_AUTH_KEY",
    ]
    for path in [RUNBOOK, DATASET_GUIDE, DATASET_QUICKSTART, SCRIPTS_README, TRAINING_QUICKSTART]:
        text = read(path)
        for fragment in guarded_fragments:
            assert fragment in text

    runbook = read(RUNBOOK)
    normalized_runbook = re.sub(r"\s+", " ", runbook)
    assert "safe_commands" in runbook
    assert "20260621T-ml-next-gate-authorization-post-win-template-gate-threading-governed.json" in runbook
    assert "authorized_for_guarded_execution=true" in runbook
    assert "direct `download_production_dataset.py` invocation" in runbook
    assert "dry-run command" in normalized_runbook
    assert "validation-only launchers" in normalized_runbook

    quickstart = read(DATASET_QUICKSTART)
    assert "Legacy Direct Script Path (Do Not Use For Production Claims)" in quickstart
    assert "resume through the guarded launcher" in quickstart

    scripts_readme = read(SCRIPTS_README)
    assert "Direct `download_production_dataset.py` calls are for dry-run/debugging only" in scripts_readme


def test_ml_operator_docs_do_not_present_malwarebazaar_launcher_as_current() -> None:
    stale_current_claims = [
        "first production candidate should be based on MalwareBazaar + goodware",
        "Only `20260604T-ml-prelab-next-action-validation.run.json` is the current",
        "current production path\nis the generated Wave 1 handoff",
    ]

    for path in [
        RUNBOOK,
        DATASET_GUIDE,
        DATASET_QUICKSTART,
        SCRIPTS_README,
        TRAINING_QUICKSTART,
        ML_PLATFORM_EVOLUTION_PLAN,
        ML_BENCHMARK_VALIDATION_PLAN,
    ]:
        text = read(path)
        for claim in stale_current_claims:
            assert claim not in text

    benchmark_plan = read(ML_BENCHMARK_VALIDATION_PLAN)
    platform_plan = read(ML_PLATFORM_EVOLUTION_PLAN)
    training_quickstart = read(TRAINING_QUICKSTART)

    assert "20260620T2320Z-ml-next-action-secret-readiness.json" in benchmark_plan
    assert "20260621T-ml-next-gate-authorization-post-win-template-gate-threading-governed.json" in benchmark_plan
    assert "authorized_for_guarded_execution=true" in benchmark_plan
    assert "VirusShare evidence is fallback-only" in benchmark_plan
    assert "20260620T-ml-next-action-virusshare-source-aware.json" in benchmark_plan

    assert "20260621T-ml-next-gate-authorization-post-win-template-gate-threading-governed.json" in platform_plan
    assert "authorized_for_guarded_execution=true" in platform_plan
    assert "effective_source_route=malwarebazaar_governed_acquisition" in platform_plan
    assert "It must stay\n  `authorized_for_guarded_execution=false`" not in platform_plan

    assert "no-execution env remediation" in training_quickstart
    assert "does not invoke PowerShell or a guarded launcher" in training_quickstart
    assert "To consume the first launchable `next_actions` item safely" not in training_quickstart
