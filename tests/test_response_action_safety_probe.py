import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools" / "detection_validation" / "scripts" / "response_action_safety_probe.py"
SCHEMA_PATH = REPO_ROOT / "schemas" / "response_action_safety_probe_v1.schema.json"
MATRIX_PATH = REPO_ROOT / "docs" / "validation" / "RESPONSE_ACTION_VALIDATION_MATRIX.md"

SPEC = importlib.util.spec_from_file_location("response_action_safety_probe", MODULE_PATH)
response_probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = response_probe
SPEC.loader.exec_module(response_probe)


def test_response_action_safety_probe_is_non_destructive(monkeypatch):
    monkeypatch.setattr(response_probe, "git_snapshot", lambda: {"dirty": True, "status_short": []})

    report = response_probe.build_report()

    assert report["api_version"] == "tamandua.io/response-action-safety-probe/v1"
    assert report["kind"] == "ResponseActionSafetyProbe"
    assert report["execute"] is False
    assert report["profile_id"] == "response-action-safety-probe"
    assert report["quality_gate"]["passed"] is True
    assert report["safety_contract"]["destructive_actions_executed"] is False
    assert report["safety_contract"]["host_os_mutated"] is False
    assert "does not prove live" in report["claim_boundary"].lower()


def test_response_action_safety_probe_covers_required_safety_capabilities(monkeypatch):
    monkeypatch.setattr(response_probe, "git_snapshot", lambda: {"dirty": True, "status_short": []})

    report = response_probe.build_report()
    coverage = report["summary"]["category_coverage"]

    for capability in response_probe.REQUIRED_CAPABILITIES:
        assert coverage[capability]["covered"] > 0
        assert coverage[capability]["missed"] == 0


def test_response_action_safety_probe_marks_mobile_and_browser_unsupported():
    matrix = response_probe.fixture_matrix()
    unsupported_rows = [
        row for row in matrix if row["platform"] in {"android", "ios", "browser", "mobile"}
    ]

    assert unsupported_rows
    assert all(row["status"] == "unsupported_platform" for row in unsupported_rows)
    assert all(row["default_mode"] == "disabled" for row in unsupported_rows)
    assert all(row["runtime_effect"] == "none_probe_only" for row in unsupported_rows)


def test_response_action_safety_probe_schema_pins_no_mutation_contract():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["properties"]["execute"]["const"] is False
    safety = schema["properties"]["safety_contract"]["properties"]
    assert safety["destructive_actions_executed"]["const"] is False
    assert safety["host_os_mutated"]["const"] is False
    thresholds = schema["properties"]["quality_gate"]["properties"]["thresholds"]["properties"]
    assert thresholds["allow_destructive_actions"]["const"] is False
    assert thresholds["require_live_endpoint_execution"]["const"] is False


def test_response_action_validation_matrix_documents_control_plane_gates():
    matrix = MATRIX_PATH.read_text(encoding="utf-8").lower()

    for term in [
        "dry-run",
        "rbac",
        "audit event",
        "unsupported_platform",
        "mobile/app guard boundary",
        "host-only",
        "no host os mutation",
    ]:
        assert term in matrix
