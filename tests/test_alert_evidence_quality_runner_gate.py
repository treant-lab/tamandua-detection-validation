from tools.detection_validation.scripts import tamandua_detection_validation as tdv


def test_score_test_rejects_matched_alert_with_synthetic_evidence() -> None:
    alert = {
        "id": "alert-synthetic",
        "title": "Expected Synthetic Alert",
        "severity": "high",
        "raw_event": {"payload": {"event_type": "alert_event"}},
    }

    score = tdv.score_test(
        {"expected_alerts": ["Expected Synthetic Alert"]},
        event_rows=[],
        alert_rows=[alert],
        detection_rows=[],
    )

    assert score["status"] == "missed"
    assert score["observed_expected_alerts"] == ["Expected Synthetic Alert"]
    assert score["unclaimable_alert_evidence_quality"][0]["quality"] == "synthetic"
    assert score["evidence_quality"]["alert_provenance"] == "weak"


def test_quality_gate_fails_on_unclaimable_alert_evidence_quality() -> None:
    class Args:
        fail_on_missed = False
        fail_on_partial = False
        benchmark_lane = "stable-regression"
        max_driver_channel_drops = -1
        max_driver_kernel_drops = -1
        max_unexpected_high_critical = -1
        max_unknown_source = -1
        require_upstream = False

    gate = tdv.evaluate_gates({"summary": {"unclaimable_alert_evidence_quality": 1}}, Args())

    assert gate["passed"] is False
    assert "unclaimable_alert_evidence_quality" in gate["failures"]


def test_runner_rejects_derived_alert_when_not_benchmark_eligible() -> None:
    alert = {
        "id": "alert-derived",
        "title": "Expected Derived Alert",
        "severity": "high",
        "evidence": {"detection": {"rule_name": "ML detection"}},
        "detection_metadata": {"rule_name": "ML detection"},
    }

    score = tdv.score_test(
        {"expected_alerts": ["Expected Derived Alert"]},
        event_rows=[],
        alert_rows=[alert],
        detection_rows=[],
    )

    assert score["status"] == "missed"
    assert score["unclaimable_alert_evidence_quality"][0]["quality"] == "derived"
    assert score["unclaimable_alert_evidence_quality"][0]["benchmark_eligible"] is False


def test_runner_rejects_explicit_camel_case_non_benchmark_eligible_alert() -> None:
    alert = {
        "id": "alert-camel-derived",
        "title": "Expected Camel Derived Alert",
        "severity": "high",
        "evidenceQuality": {
            "quality": "derived",
            "claimable": True,
            "benchmarkEligible": False,
        },
    }

    score = tdv.score_test(
        {"expected_alerts": ["Expected Camel Derived Alert"]},
        event_rows=[],
        alert_rows=[alert],
        detection_rows=[],
    )

    assert score["status"] == "missed"
    assert score["unclaimable_alert_evidence_quality"][0]["quality"] == "derived"
    assert score["unclaimable_alert_evidence_quality"][0]["benchmark_eligible"] is False


def test_runner_rejects_explicit_benchmark_flag_without_quality() -> None:
    alert = {
        "id": "alert-missing-quality",
        "title": "Expected Missing Quality Alert",
        "severity": "high",
        "source_event_id": "event-1",
        "event_ids": ["event-1"],
        "evidence": {"detection": {"rule_name": "anchored alert"}},
        "raw_event": {"event_type": "process_event"},
        "evidenceQuality": {
            "benchmarkEligible": False,
        },
    }

    score = tdv.score_test(
        {"expected_alerts": ["Expected Missing Quality Alert"]},
        event_rows=[],
        alert_rows=[alert],
        detection_rows=[],
    )

    assert score["status"] == "missed"
    assert score["unclaimable_alert_evidence_quality"][0]["quality"] == "malformed"
    assert score["unclaimable_alert_evidence_quality"][0]["benchmark_eligible"] is False


def test_runner_rejects_empty_explicit_quality_even_when_alert_could_infer_direct() -> None:
    alert = {
        "id": "alert-empty-explicit-quality",
        "title": "Expected Empty Quality Alert",
        "severity": "high",
        "source_event_id": "event-1",
        "event_ids": ["event-1"],
        "evidence": {"detection": {"rule_name": "anchored alert"}},
        "raw_event": {"event_type": "process_event"},
        "evidence_quality": {},
    }

    score = tdv.score_test(
        {"expected_alerts": ["Expected Empty Quality Alert"]},
        event_rows=[],
        alert_rows=[alert],
        detection_rows=[],
    )

    assert score["status"] == "missed"
    assert score["unclaimable_alert_evidence_quality"][0]["quality"] == "malformed"
    assert score["unclaimable_alert_evidence_quality"][0]["benchmark_eligible"] is False


def test_runner_rejects_malformed_benchmark_flag() -> None:
    alert = {
        "id": "alert-string-flag",
        "title": "Expected String Flag Alert",
        "severity": "high",
        "evidenceQuality": {
            "quality": "direct",
            "benchmarkEligible": "false",
        },
    }

    score = tdv.score_test(
        {"expected_alerts": ["Expected String Flag Alert"]},
        event_rows=[],
        alert_rows=[alert],
        detection_rows=[],
    )

    assert score["status"] == "missed"
    assert score["unclaimable_alert_evidence_quality"][0]["quality"] == "malformed"
    assert score["unclaimable_alert_evidence_quality"][0]["benchmark_eligible"] is False


def test_benchmark_scorecard_lists_unclaimable_alert_evidence_gap() -> None:
    report = {
        "execute": True,
        "benchmark_lane": "stable-regression",
        "quality_gate": {"passed": False},
        "summary": {
            "tests": 1,
            "covered": 0,
            "partial": 1,
            "unclaimable_alert_evidence_quality": 1,
        },
    }

    scorecard = tdv.benchmark_scorecard(report)

    assert "unclaimable_alert_evidence_quality" in scorecard["blocking_gaps"]
    assert scorecard["context_quality"] == 0.0


def test_gap_category_routes_unclaimable_alert_evidence_to_alert_quality() -> None:
    category = tdv.gap_category(
        {
            "score": {
                "status": "missed",
                "unclaimable_alert_evidence_quality": [{"id": "alert-1"}],
            }
        }
    )

    assert category == "alert-quality"
