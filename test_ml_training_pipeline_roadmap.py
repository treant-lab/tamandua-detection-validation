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
DATASET_GUIDE = ROOT / "apps" / "tamandua_ml" / "docs" / "DATASET_ACQUISITION.md"
DATASET_QUICKSTART = ROOT / "apps" / "tamandua_ml" / "docs" / "DATASET_QUICKSTART.md"
RUNBOOK = ROOT / "docs" / "apps" / "tamandua_ml" / "PRODUCTION_ACQUISITION_RUNBOOK.md"
SCRIPTS_README = ROOT / "apps" / "tamandua_ml" / "scripts" / "README.md"
README = ROOT / "apps" / "tamandua_ml" / "README.md"


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


def test_ml_training_pipeline_roadmap_uses_current_virusshare_next_step() -> None:
    text = read(ROADMAP)
    next_step = text.split("## Next Operator Step", 1)[1]

    assert "wave_1_virusshare_fallback_readiness_launcher.ps1" in next_step
    assert "wave_1_virusshare_fallback_acquisition_launcher.ps1 -Execute" in next_step
    assert "download_production_dataset.py" in next_step
    assert "do not invoke the direct acquisition" in next_step
    assert "wave_1_real_acquisition_launcher.ps1" not in next_step


def test_ml_training_pipeline_roadmap_is_linked_from_operator_docs() -> None:
    relative_link = "docs/benchmarks/ML_TRAINING_PIPELINE_ROADMAP.md"
    assert relative_link in read(DATASET_GUIDE)
    assert "../../docs/benchmarks/ML_TRAINING_PIPELINE_ROADMAP.md" in read(README)


def test_operator_docs_route_real_acquisition_through_guarded_launcher() -> None:
    guarded_fragments = [
        "wave_1_real_acquisition_launcher.ps1 -Execute",
        "TAMANDUA_ALLOW_ML_REAL_ACQUISITION",
    ]
    for path in [RUNBOOK, DATASET_QUICKSTART, SCRIPTS_README]:
        text = read(path)
        for fragment in guarded_fragments:
            assert fragment in text

    runbook = read(RUNBOOK)
    normalized_runbook = re.sub(r"\s+", " ", runbook)
    assert "safe_commands" in runbook
    assert "direct `download_production_dataset.py` invocation" in runbook
    assert "dry-run command" in normalized_runbook
    assert "validation-only launchers" in normalized_runbook

    quickstart = read(DATASET_QUICKSTART)
    assert "Legacy Direct Script Path (Do Not Use For Production Claims)" in quickstart
    assert "resume through the guarded launcher" in quickstart

    scripts_readme = read(SCRIPTS_README)
    assert "Direct `download_production_dataset.py` calls are for dry-run/debugging only" in scripts_readme
