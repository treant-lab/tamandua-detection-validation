import json
from pathlib import Path

import pytest

from tools.detection_validation.scripts import alert_evidence_quality_gate as gate


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_gate_passes_direct_and_correlated_evidence(tmp_path: Path) -> None:
    artifact = write_json(
        tmp_path / "direct.json",
        {
            "tests": [
                {
                    "alert": {
                        "id": "alert-1",
                        "evidence_quality": {
                            "quality": "direct",
                            "claimable": True,
                            "benchmark_eligible": True,
                        },
                    }
                },
                {
                    "alert": {
                        "id": "alert-2",
                        "evidenceQuality": {
                            "quality": "correlated",
                            "claimable": True,
                            "benchmarkEligible": True,
                        },
                    }
                },
            ]
        },
    )

    report = gate.build_report([artifact])

    assert report["status"] == "pass"
    assert report["results"][0]["scanned_evidence_quality"] == 2


@pytest.mark.parametrize("quality", ["synthetic", "missing"])
def test_gate_rejects_non_claimable_evidence_quality(tmp_path: Path, quality: str) -> None:
    artifact = write_json(
        tmp_path / f"{quality}.json",
        {
            "alert": {
                "id": "alert-weak",
                "evidence_quality": {
                    "quality": quality,
                    "claimable": False,
                    "benchmark_eligible": False,
                    "summary": "weak alert provenance",
                },
            }
        },
    )

    report = gate.build_report([artifact])

    assert report["status"] == "fail"
    assert report["results"][0]["findings"][0]["quality"] == quality


def test_gate_rejects_non_benchmark_eligible_derived_evidence(tmp_path: Path) -> None:
    artifact = write_json(
        tmp_path / "derived.json",
        {
            "alert": {
                "id": "alert-derived",
                "evidence_quality": {
                    "quality": "derived",
                    "claimable": True,
                    "benchmark_eligible": False,
                    "summary": "no persisted source-event anchor",
                },
            }
        },
    )

    report = gate.build_report([artifact])

    assert report["status"] == "fail"
    assert report["results"][0]["findings"][0]["quality"] == "derived"


def test_gate_rejects_camel_case_non_benchmark_eligible_evidence(tmp_path: Path) -> None:
    artifact = write_json(
        tmp_path / "camel-derived.json",
        {
            "alert": {
                "id": "alert-camel-derived",
                "evidenceQuality": {
                    "quality": "derived",
                    "claimable": True,
                    "benchmarkEligible": False,
                    "summary": "no persisted source-event anchor",
                },
            }
        },
    )

    report = gate.build_report([artifact])

    assert report["status"] == "fail"
    assert report["results"][0]["findings"][0]["quality"] == "derived"


def test_gate_rejects_benchmark_flag_without_quality(tmp_path: Path) -> None:
    artifact = write_json(
        tmp_path / "missing-quality.json",
        {
            "alert": {
                "id": "alert-missing-quality",
                "evidenceQuality": {
                    "benchmarkEligible": False,
                    "summary": "malformed evidence-quality annotation",
                },
            }
        },
    )

    report = gate.build_report([artifact])

    assert report["status"] == "fail"
    assert report["results"][0]["scanned_evidence_quality"] == 1
    assert report["results"][0]["findings"][0]["quality"] == "malformed"


def test_gate_rejects_empty_explicit_evidence_quality_block(tmp_path: Path) -> None:
    artifact = write_json(
        tmp_path / "empty-quality.json",
        {
            "alert": {
                "id": "alert-empty-quality",
                "evidence_quality": {},
            }
        },
    )

    report = gate.build_report([artifact])

    assert report["status"] == "fail"
    assert report["results"][0]["findings"][0]["quality"] == "malformed"


def test_gate_rejects_malformed_benchmark_flag(tmp_path: Path) -> None:
    artifact = write_json(
        tmp_path / "string-flag.json",
        {
            "alert": {
                "id": "alert-string-flag",
                "evidenceQuality": {
                    "quality": "direct",
                    "benchmarkEligible": "false",
                },
            }
        },
    )

    report = gate.build_report([artifact])

    assert report["status"] == "fail"
    assert report["results"][0]["findings"][0]["quality"] == "malformed"


def test_gate_can_require_evidence_quality_annotations(tmp_path: Path) -> None:
    artifact = write_json(tmp_path / "legacy.json", {"tests": [{"id": "legacy"}]})

    report = gate.build_report([artifact], require_evidence_quality=True)

    assert report["status"] == "fail"
    assert report["results"][0]["missing_required_evidence_quality"] is True


def test_require_evidence_quality_ignores_aggregate_quality_blocks(tmp_path: Path) -> None:
    artifact = write_json(
        tmp_path / "aggregate-only.json",
        {"score": {"evidence_quality": {"alert_provenance": "ok", "source_attribution": "ok"}}},
    )

    report = gate.build_report([artifact], require_evidence_quality=True)

    assert report["status"] == "fail"
    assert report["results"][0]["scanned_evidence_quality"] == 0
    assert report["results"][0]["missing_required_evidence_quality"] is True


def test_gate_ignores_aggregate_score_quality_even_with_quality_flag(tmp_path: Path) -> None:
    artifact = write_json(
        tmp_path / "aggregate-quality.json",
        {
            "tests": [
                {
                    "id": "aggregate-only",
                    "score": {
                        "evidence_quality": {
                            "quality": "missing",
                            "benchmark_eligible": False,
                        }
                    },
                }
            ]
        },
    )

    report = gate.build_report([artifact], require_evidence_quality=True)

    assert report["status"] == "fail"
    assert report["results"][0]["scanned_evidence_quality"] == 0
    assert report["results"][0]["missing_required_evidence_quality"] is True
