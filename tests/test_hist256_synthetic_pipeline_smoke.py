import importlib.util
import importlib.metadata
import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]


def test_synthetic_pipeline_reaches_freeze_but_readiness_stays_blocked():
    path = ROOT / "tools" / "detection_validation" / "scripts" / "run_hist256_synthetic_pipeline_smoke.py"
    spec = importlib.util.spec_from_file_location("hist256_synthetic_pipeline_smoke_test", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    report = module.run_smoke(ROOT)
    assert report["evidence_class"] == "synthetic_pipeline_smoke"
    assert report["stages"]["lightgbm_guard"] == "clean"
    assert report["stages"]["holdout"] == "governed_holdout_below_sample_gate"
    assert report["stages"]["holdout_sample_gate_met"] is False
    assert report["stages"]["readiness"] == "blocked"
    assert report["real_runtime"]["lightgbm_version"] == importlib.metadata.version("lightgbm")
    assert report["real_runtime"]["required_version"] == "4.5.0"
    assert report["may_promote"] is False and report["may_enforce"] is False
    schema = json.loads((ROOT / "schemas" / "hist256_synthetic_pipeline_smoke_v1.schema.json").read_text())
    jsonschema.validate(report, schema)
