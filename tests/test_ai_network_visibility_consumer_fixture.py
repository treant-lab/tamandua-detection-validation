import json
from pathlib import Path


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "ai_network_visibility_consumer_v1.json"


def test_ai_network_visibility_fixture_has_conservative_claim_boundary():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    assert data["schema_version"] == 1
    assert data["fixture_id"] == "ai-network-visibility-consumer-v1"
    assert data["evidence_class"] == "synthetic_parity"
    assert "does not demonstrate packet capture" in data["claim_boundary"]
    assert "detection performance" in data["claim_boundary"]


def test_degraded_fixture_forbids_tls_and_certificate_claims():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    fixtures = {item["id"]: item for item in data["fixtures"]}
    degraded = fixtures["passive-connection-table-degraded"]

    metadata = degraded["input"]["metadata"]
    expected = degraded["expected"]
    assert metadata["network_visibility_state"] == "degraded"
    assert metadata["tls_fingerprints_available"] is False
    assert metadata["certificate_visibility"] == "unavailable"
    assert expected["show_degraded_visibility"] is True
    assert expected["show_tls_fingerprint_claim"] is False
    assert expected["show_certificate_claim"] is False


def test_available_claims_require_explicit_metadata_and_artifact_fields_survive():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    fixtures = {item["id"]: item for item in data["fixtures"]}
    available = fixtures["packet-source-explicitly-available"]
    artifact = fixtures["artifact-redacted-evidence"]

    assert available["input"]["metadata"]["tls_fingerprints_available"] is True
    assert available["input"]["metadata"]["certificate_visibility"] == "available"
    assert available["expected"]["show_tls_fingerprint_claim"] is True
    assert artifact["input"]["payload"]["artifact_type"] == "mcp_config"
    assert artifact["input"]["payload"]["redacted_preview"] == "tools: [redacted]"
    assert artifact["input"]["payload"]["matched_patterns"] == ["approval_bypass"]
    assert artifact["input"]["payload"]["risk_indicators"] == ["unsigned_source"]
