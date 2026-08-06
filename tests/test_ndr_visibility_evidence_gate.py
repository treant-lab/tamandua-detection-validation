import json
from pathlib import Path

from tools.detection_validation.scripts import ndr_visibility_evidence_gate as gate


FIXTURE = Path("tools/detection_validation/fixtures/ndr_visibility_evidence_v1.json")


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_fixture_maps_required_ndr_visibility_scenarios() -> None:
    payload = gate.load_json(FIXTURE)
    categories = {scenario["category"] for scenario in payload["scenarios"]}

    assert categories == {
        "dns_normal",
        "doh_8_8_8_8_443",
        "connection_no_domain",
        "process_no_attribution",
        "bytes_zero",
        "tls_metadata_absent",
        "lateral_movement_smb_rdp",
    }


def test_gate_classifies_fixture_expected_outcomes() -> None:
    report = gate.build_report(FIXTURE)

    assert report["status"] == "pass"
    assert report["checked_scenarios"] == 7
    assert {
        result["event_id"]: result["classification"] for result in report["results"]
    } == {
        "dns-normal-browser-example-com": "investigable",
        "doh-google-dns-443": "partial",
        "connection-without-domain": "partial",
        "process-without-attribution": "partial",
        "zero-byte-flow": "weak",
        "tls-metadata-absent": "partial",
        "lateral-smb-rdp-internal": "investigable",
    }


def test_gate_rejects_missing_minimum_field_contract(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "missing-minimum.json",
        {
            "scenarios": [
                {
                    "id": "missing-remote",
                    "category": "contract_gap",
                    "event": {
                        "process": {"pid": 1, "name": "test.exe", "source": "endpoint_socket"},
                        "domain_source": "dns_query",
                        "bytes": {"sent": 1, "received": 1, "source": "flow_counter"},
                        "tls": {"source": "not_applicable"},
                        "dns_correlation": {"status": "direct"},
                    },
                    "expected_classification": "investigable",
                }
            ]
        },
    )

    report = gate.build_report(fixture)

    assert report["status"] == "fail"
    result = report["results"][0]
    assert result["classification"] == "weak"
    assert result["missing_minimum_fields"] == ["remote_endpoint"]


def test_gate_treats_zero_bytes_as_weak_even_with_domain_and_process(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "zero-bytes.json",
        {
            "scenarios": [
                {
                    "id": "zero",
                    "category": "bytes_zero",
                    "event": {
                        "process": {"pid": 1, "name": "test.exe", "source": "endpoint_socket"},
                        "remote_endpoint": {
                            "ip": "192.0.2.1",
                            "port": 443,
                            "protocol": "tcp",
                            "source": "flow_observed",
                        },
                        "domain": "zero.example.test",
                        "domain_source": "dns_query",
                        "bytes": {"sent": 0, "received": 0, "source": "flow_counter"},
                        "tls": {"sni": "zero.example.test", "source": "handshake_metadata"},
                        "dns_correlation": {"status": "direct"},
                    },
                    "expected_classification": "partial",
                }
            ]
        },
    )

    report = gate.build_report(fixture)

    assert report["status"] == "fail"
    assert report["results"][0]["classification"] == "weak"
