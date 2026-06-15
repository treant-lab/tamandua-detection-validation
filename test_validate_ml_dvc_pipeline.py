from __future__ import annotations

from pathlib import Path
import sys

import yaml


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[2]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
ML_ROOT = ROOT / "apps" / "tamandua_ml"
DVC_PIPELINE = ML_ROOT / "dvc.yaml"
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import ContractError, validate_ml_dvc_pipeline  # noqa: E402


def load_dvc_pipeline() -> dict:
    with DVC_PIPELINE.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert isinstance(data, dict)
    return data


def test_ml_dvc_pipeline_uses_existing_scripts_and_contracts() -> None:
    validate_ml_dvc_pipeline(DVC_PIPELINE)
    data = load_dvc_pipeline()
    stages = data["stages"]

    expected_stages = {"validate_ml_contracts", "validate_dataset", "train", "evaluate", "export_onnx"}
    assert expected_stages.issubset(stages)

    allowed_missing_deps = {
        "data/production",
        "data/production/train",
        "data/production/val",
        "data/production/test",
    }
    produced_outs = {
        output
        for stage in stages.values()
        for output in stage.get("outs", [])
        if isinstance(output, str)
    }
    for stage_name, stage in stages.items():
        for dep in stage.get("deps", []):
            if dep in allowed_missing_deps or dep in produced_outs:
                continue
            dep_path = (ML_ROOT / dep).resolve()
            assert dep_path.exists(), f"{stage_name} dep does not exist: {dep}"

    contract_deps = set(stages["validate_ml_contracts"]["deps"])
    assert "../../schemas/ml_model_contract_v1.schema.json" in contract_deps
    assert "../../docs/apps/tamandua_ml/examples/ml_model_contract_malware_smell_onnx_v1.json" in contract_deps


def test_ml_dvc_pipeline_is_not_a_real_acquisition_or_publish_path() -> None:
    data = load_dvc_pipeline()
    commands = "\n".join(str(stage.get("cmd", "")) for stage in data["stages"].values())

    forbidden_snippets = [
        "download_production_dataset.py",
        "acquire_malware_bazaar.py",
        "acquire_vx_underground.py",
        "acquire_goodware.py",
        "publish_dataset_manifest.py",
        "TAMANDUA_ALLOW_ML_REAL_ACQUISITION=1",
        "TAMANDUA_ALLOW_ML_MANIFEST_PUBLISH=1",
    ]
    for snippet in forbidden_snippets:
        assert snippet not in commands


def test_ml_dvc_pipeline_validator_rejects_real_acquisition_command(tmp_path: Path) -> None:
    data = load_dvc_pipeline()
    data["stages"]["validate_dataset"]["cmd"] = "python scripts/download_production_dataset.py --output data/production"
    pipeline = tmp_path / "dvc.yaml"
    pipeline.write_text(yaml.safe_dump(data), encoding="utf-8")

    try:
        validate_ml_dvc_pipeline(pipeline)
    except ContractError as exc:
        assert "real acquisition/publication path" in str(exc)
    else:
        raise AssertionError("expected DVC pipeline acquisition path to fail")


def test_ml_dvc_pipeline_train_export_commands_match_current_cli() -> None:
    stages = load_dvc_pipeline()["stages"]

    train_cmd = stages["train"]["cmd"]
    for required_arg in (
        "--data_root_dir data/production",
        "--model_save_path models/latest/encoder.pt",
        "--markers_save_path models/latest/markers.pkl",
        "--latent_dim 256",
    ):
        assert required_arg in train_cmd

    export_cmd = stages["export_onnx"]["cmd"]
    for required_arg in (
        "--model-dir models/latest",
        "--output models/latest/malware_smell.onnx",
        "--quantized-output models/latest/malware_smell_int8.onnx",
        "--image-size 64",
        "--latent-dim 256",
    ):
        assert required_arg in export_cmd
