"""Regression tests for generate_validation_scorecard.profile_id robustness.

Six legacy run-report JSONs under docs/benchmarks/runs/ carry a bare string
``profile`` field (e.g. ``"profile": "tamandua-corpus-training"``) instead of
the scorecard-run dict shape (``"profile": {"profile_id": ...}``). Before the
fix, ``profile_id()`` crashed with ``'str' object has no attribute 'get'``
during the scorecard refresh, taking down the whole
validation_status_consistency full-mode run.

Contract under test (fail-safe skip, not fail-open scoring):
- a non-dict ``profile`` yields an empty profile id, so ``load_reports``
  classifies the artifact as non-scorecard and skips it — it must never be
  counted as a passing run;
- well-formed reports keep producing exactly the same profile id as before.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/generate_validation_scorecard.py"
SPEC = importlib.util.spec_from_file_location(
    "generate_validation_scorecard_profile_id_for_test", SCRIPT
)
assert SPEC and SPEC.loader
scorecard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = scorecard
SPEC.loader.exec_module(scorecard)


def test_profile_id_with_string_profile_is_empty_not_crash():
    # Shape observed in the six legacy run reports that crashed the refresh.
    assert scorecard.profile_id({"profile": "tamandua-corpus-training"}) == ""


def test_profile_id_with_missing_profile_is_empty():
    assert scorecard.profile_id({}) == ""
    assert scorecard.profile_id({"summary": {"tests": 1}}) == ""


def test_profile_id_with_other_non_dict_profile_shapes_is_empty():
    assert scorecard.profile_id({"profile": None}) == ""
    assert scorecard.profile_id({"profile": ["elixir-only-current-lock-v1"]}) == ""
    assert scorecard.profile_id({"profile": 7}) == ""


def test_profile_id_well_formed_report_unchanged():
    report = {"profile": {"profile_id": "windows-baseline-v1"}}
    assert scorecard.profile_id(report) == "windows-baseline-v1"


def test_profile_id_top_level_key_still_takes_precedence():
    report = {
        "profile_id": "top-level-v1",
        "profile": {"profile_id": "nested-v1"},
    }
    assert scorecard.profile_id(report) == "top-level-v1"


def test_load_reports_skips_string_profile_artifact_keeps_well_formed(tmp_path, monkeypatch):
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    (runs_dir / "20260715T122952Z-legacy-receipt.json").write_text(
        json.dumps(
            {
                "profile": "tamandua-corpus-training",
                "summary": {"tests": 5, "covered": 5},
                "quality_gate": {"passed": True},
            }
        ),
        encoding="utf-8",
    )
    (runs_dir / "20260716T000000Z-well-formed.json").write_text(
        json.dumps(
            {
                "run_id": "well-formed-run",
                "profile": {"profile_id": "windows-baseline-v1"},
                "summary": {"tests": 3, "covered": 3},
            }
        ),
        encoding="utf-8",
    )
    # load_reports computes paths relative to the module-level ROOT.
    monkeypatch.setattr(scorecard, "ROOT", tmp_path)

    reports = scorecard.load_reports(runs_dir)

    profile_ids = [scorecard.profile_id(report) for report in reports]
    assert profile_ids == ["windows-baseline-v1"]
    assert reports[0]["_run_id"] == "well-formed-run"
