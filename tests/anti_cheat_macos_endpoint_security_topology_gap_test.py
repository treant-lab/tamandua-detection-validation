"""Historical v1 receipt regression after the selected v2 topology transition."""

import importlib.util
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/anti_cheat_macos_endpoint_security_topology_gap_gate.py"
FIXTURE = ROOT / "tools/detection_validation/fixtures/anti_cheat_macos_endpoint_security_topology_gap_degraded.json"
SCHEMA = ROOT / "schemas/anti_cheat_macos_endpoint_security_topology_gap_v1.schema.json"
EXPECTED_GATE_SHA256 = "688100b012cd7b003c64b4e8b2785775954329f144d0cd00a1817178d0e62885"
EXPECTED_FIXTURE_SHA256 = "b3812f9af2fe4615e93a689c71dc951f02ebc547acfbc4a45fec663b0eaacad0"
EXPECTED_SCHEMA_SHA256 = "b9f6d7b137c898f03edc9d4f7a5acf04ba1a87d841245d92086a6e4921045317"
assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest() == EXPECTED_GATE_SHA256
SPEC = importlib.util.spec_from_file_location("macos_topology_gap_v1_gate", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(GATE)


EXPECTED_HASH_DRIFT = [
    "apps/tamandua_agent/SystemExtension/Package.swift",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/ESClient.swift",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/Info.plist",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/TamanduaFileMonitor.swift",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/XPCServer.swift",
    "apps/tamandua_agent/SystemExtension/TamanduaFileMonitor/entitlements.plist",
    "apps/tamandua_agent/src/collectors/health.rs",
    "apps/tamandua_agent/src/collectors/sysext_bridge.rs",
    "deploy/installers/macos/create-dmg.sh",
    "deploy/installers/macos/entitlements.plist",
]


def test_historical_v1_receipt_records_expected_source_hash_drift():
    result = GATE.run_gate(ROOT)
    assert result["ok"] is False
    assert result["failures"]["hashes"] == EXPECTED_HASH_DRIFT


def test_historical_v1_detached_authorities_remain_byte_pinned():
    assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest() == EXPECTED_GATE_SHA256
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == EXPECTED_FIXTURE_SHA256
    assert hashlib.sha256(SCHEMA.read_bytes()).hexdigest() == EXPECTED_SCHEMA_SHA256


def test_historical_v1_fixture_still_names_detached_review_truthfully():
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert value["gate_authority"]["sha256"] == EXPECTED_GATE_SHA256
    assert value["gate_authority"]["cli_autonomously_authenticates"] is False
    assert value["gate_authority"]["coordinated_change_requires_external_review"] is True


def test_historical_v1_stays_degraded_and_unexecuted():
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert value["capability_state"] == "degraded_topology_unproven"
    assert value["runtime_state"] == "not_executed"
    assert set(value["lifecycle"].values()) == {False}
    assert set(value["claims"].values()) == {False}


def test_historical_v1_reports_shape_drift_in_addition_to_hash_drift():
    result = GATE.run_gate(ROOT)
    assert result["ok"] is False
    assert result["failures"]["hashes"] == EXPECTED_HASH_DRIFT
    assert result["failures"]["shapes"]
    assert "shape:swift_es:ES_EVENT_TYPE_AUTH_OPEN" in result["failures"]["shapes"]


def test_historical_v1_test_checks_hash_before_importing_gate():
    text = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert text.index("hashlib.sha256(SCRIPT.read_bytes())") < text.index("spec_from_file_location")
