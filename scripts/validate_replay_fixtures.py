#!/usr/bin/env python3
"""Validate static replay fixture structure.

This intentionally does not execute Tamandua server code. It keeps replay data
machine-checkable so future Elixir/Phoenix replay tests can consume the same
fixtures without schema drift.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    _SCRIPT_DIR = Path(__file__).resolve().parent
    ROOT = _SCRIPT_DIR.parents[2] if _SCRIPT_DIR.name == "scripts" else _SCRIPT_DIR.parents[1]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
DEFAULT_FIXTURE_DIR = ROOT / "fixtures" if is_standalone() else ROOT / "tools" / "detection_validation" / "fixtures"
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_CONTRACT_GAPS = {
    "alert-quality",
    "analyst-ux",
    "audit",
    "authentication",
    "authorization",
    "claim-boundary",
    "collector",
    "evidence-integrity",
    "identity",
    "integration",
    "normalization",
    "orchestration",
    "reliability",
    "runner",
    "scale",
    "tenant-boundary",
}
APP_GUARD_REPLAY_SCHEMA = "tamandua.detection_validation.app_guard_rasp_replay/v1"
APP_GUARD_EVENT_SCHEMA = "tamandua.app_guard.event/v1"
NON_REPLAY_FIXTURE_API_VERSIONS = {
    "tamandua.io/governed-fp-fn-corpus-gate/v1",
    "tamandua.io/benchmark-claim-maturity-matrix/v1",
    "tamandua.io/threat-benchmark-taxonomy-mapping/v1",
}
NON_REPLAY_FIXTURE_IDS = {
    "wazuh-posture-inventory-compliance-gap-v1",
}
BENCHMARK_CLAIM_MATURITY_API_VERSION = "tamandua.io/benchmark-claim-maturity-matrix/v1"
BENCHMARK_CLAIM_MATURITY_GATES = {
    "goodware_fp",
    "malware_fn",
    "mobile_shielding_synthetic_vs_physical",
    "endpoint_parity",
}
BENCHMARK_CLAIM_MATURITY_VENDORS = {"Elastic", "Wazuh", "Appdome", "Verimatrix"}
APP_GUARD_EVENT_TYPES = {
    "debugger_detected",
    "root_detected",
    "jailbreak_detected",
    "emulator_detected",
    "simulator_detected",
    "hook_framework_detected",
    "app_integrity_violation",
    "tampering_detected",
    "pinning_bypass_detected",
    "mitm_detected",
    "overlay_attack_detected",
    "browser_tamper_detected",
    "automation_detected",
    "network_exfiltration_suspected",
    "integrity_snapshot_changed",
    "behavior_anomaly_detected",
    "policy_decision",
}
APP_GUARD_DECISIONS = {"allow", "observe", "warn", "step_up", "block", "kill_session"}
APP_GUARD_FORBIDDEN_EVIDENCE_KEYS = {
    "raw_body",
    "raw_payload",
    "page_content",
    "dom_snapshot",
    "request_body",
    "response_body",
    "raw_pointer_data",
    "raw_key_data",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def validate_fixture_file(path: Path) -> list[str]:
    errors: list[str] = []
    data = load_json(path)
    fixtures = data.get("fixtures")
    lanes = data.get("lanes")

    if data.get("schema") == APP_GUARD_REPLAY_SCHEMA:
        return validate_app_guard_rasp_replay_file(path, data)

    if data.get("api_version") == BENCHMARK_CLAIM_MATURITY_API_VERSION:
        return validate_benchmark_claim_maturity_fixture(path, data)

    if data.get("api_version") in NON_REPLAY_FIXTURE_API_VERSIONS:
        return []
    if data.get("fixture_id") in NON_REPLAY_FIXTURE_IDS:
        return []

    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    if not data.get("fixture_id"):
        errors.append(f"{path}: fixture_id is required")
    if isinstance(lanes, list):
        errors.extend(validate_contract_lanes(path, lanes))
        return errors
    if not isinstance(fixtures, list) or not fixtures:
        errors.append(f"{path}: fixtures must be a non-empty list")
        return errors

    seen_ids: set[str] = set()
    for index, item in enumerate(fixtures):
        prefix = f"{path}:{index}"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: fixture must be an object")
            continue

        fixture_id = item.get("id")
        if not fixture_id:
            errors.append(f"{prefix}: id is required")
        elif fixture_id in seen_ids:
            errors.append(f"{prefix}: duplicate id {fixture_id}")
        else:
            seen_ids.add(str(fixture_id))

        if not item.get("event_type"):
            errors.append(f"{prefix}: event_type is required")
        if not isinstance(item.get("input"), dict):
            errors.append(f"{prefix}: input must be an object")
        expected = item.get("expected")
        if not isinstance(expected, dict):
            errors.append(f"{prefix}: expected must be an object")
            continue

        severity = expected.get("alert_severity")
        is_suppressed = expected.get("suppressed") is True
        if severity is None and is_suppressed:
            pass  # suppressed alerts have no surviving severity
        elif severity not in VALID_SEVERITIES:
            errors.append(f"{prefix}: expected.alert_severity must be one of {sorted(VALID_SEVERITIES)}")
        if not isinstance(expected.get("severity_adjusted"), bool):
            errors.append(f"{prefix}: expected.severity_adjusted must be boolean")
        if "fp_reason" not in expected:
            errors.append(f"{prefix}: expected.fp_reason must be present, use null when not adjusted")

    return errors


def validate_benchmark_claim_maturity_fixture(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if data.get("kind") != "BenchmarkClaimMaturityMatrix":
        errors.append(f"{path}: kind must be BenchmarkClaimMaturityMatrix")
    if set(data.get("status_labels", [])) != {"local", "synthetic", "live missing"}:
        errors.append(f"{path}: status_labels must be local/synthetic/live missing")

    gates = data.get("gates")
    if not isinstance(gates, list):
        return errors + [f"{path}: gates must be a list"]
    gate_ids = {gate.get("id") for gate in gates if isinstance(gate, dict)}
    missing_gates = sorted(BENCHMARK_CLAIM_MATURITY_GATES - gate_ids)
    if missing_gates:
        errors.append(f"{path}: benchmark maturity matrix missing gates {missing_gates}")
    for gate in gates:
        if not isinstance(gate, dict):
            errors.append(f"{path}: gate must be an object")
            continue
        gate_id = gate.get("id", "<unknown>")
        if gate.get("external_claim_allowed") is not False:
            errors.append(f"{path}: gate {gate_id} external_claim_allowed must be false")
        if gate.get("status") not in {"local", "synthetic", "live missing"}:
            errors.append(f"{path}: gate {gate_id} status must be local, synthetic, or live missing")
        if not isinstance(gate.get("metrics"), dict):
            errors.append(f"{path}: gate {gate_id} metrics must be an object")
        if not isinstance(gate.get("source_artifacts"), list) or not gate["source_artifacts"]:
            errors.append(f"{path}: gate {gate_id} source_artifacts must be non-empty")
        promotion = gate.get("promotion_evidence")
        if not isinstance(promotion, dict):
            errors.append(f"{path}: gate {gate_id} promotion_evidence must be an object")
        else:
            if promotion.get("live_proof_required") is not True:
                errors.append(f"{path}: gate {gate_id} promotion_evidence.live_proof_required must be true")
            if not isinstance(promotion.get("required_live_artifacts"), list) or not promotion["required_live_artifacts"]:
                errors.append(f"{path}: gate {gate_id} promotion_evidence.required_live_artifacts must be non-empty")
            if not isinstance(promotion.get("satisfied_live_artifacts"), list):
                errors.append(f"{path}: gate {gate_id} promotion_evidence.satisfied_live_artifacts must be a list")

    competitor_matrix = data.get("competitor_matrix")
    if not isinstance(competitor_matrix, list):
        return errors + [f"{path}: competitor_matrix must be a list"]
    vendors = {row.get("vendor") for row in competitor_matrix if isinstance(row, dict)}
    missing_vendors = sorted(BENCHMARK_CLAIM_MATURITY_VENDORS - vendors)
    if missing_vendors:
        errors.append(f"{path}: competitor_matrix missing vendors {missing_vendors}")
    for row in competitor_matrix:
        if not isinstance(row, dict):
            errors.append(f"{path}: competitor_matrix rows must be objects")
            continue
        vendor = row.get("vendor", "<unknown>")
        if row.get("external_claim_allowed") is not False:
            errors.append(f"{path}: competitor_matrix.{vendor}.external_claim_allowed must be false")
        if row.get("tamandua_status") not in {"local", "synthetic", "live missing"}:
            errors.append(f"{path}: competitor_matrix.{vendor}.tamandua_status must be local, synthetic, or live missing")
        live_parity = row.get("live_parity_evidence")
        if not isinstance(live_parity, dict):
            errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence must be an object")
        else:
            if live_parity.get("live_proof_required") is not True:
                errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.live_proof_required must be true")
            if not isinstance(live_parity.get("required_artifacts"), list) or not live_parity["required_artifacts"]:
                errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.required_artifacts must be non-empty")
            if not isinstance(live_parity.get("satisfied_artifacts"), list):
                errors.append(f"{path}: competitor_matrix.{vendor}.live_parity_evidence.satisfied_artifacts must be a list")

    return errors


def validate_app_guard_rasp_replay_file(path: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    fixtures = data.get("fixtures")
    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    if not data.get("fixture_id"):
        errors.append(f"{path}: fixture_id is required")
    if not data.get("claim_boundary"):
        errors.append(f"{path}: claim_boundary is required")
    gate = data.get("benchmark_gate")
    if isinstance(gate, dict):
        boundary = gate.get("evidence_boundary")
        if boundary is not None:
            if not isinstance(boundary, dict):
                errors.append(f"{path}: benchmark_gate.evidence_boundary must be an object")
            else:
                if boundary.get("fixture_evidence_class") != "synthetic_replay_contract":
                    errors.append(f"{path}: benchmark_gate.evidence_boundary.fixture_evidence_class must be synthetic_replay_contract")
                if boundary.get("local_fixture_claimable") is not True:
                    errors.append(f"{path}: benchmark_gate.evidence_boundary.local_fixture_claimable must be true")
                if boundary.get("live_signed_ingestion_claimable") is not False:
                    errors.append(f"{path}: benchmark_gate.evidence_boundary.live_signed_ingestion_claimable must be false")
                if boundary.get("live_anti_replay_claimable") is not False:
                    errors.append(f"{path}: benchmark_gate.evidence_boundary.live_anti_replay_claimable must be false")
                release_requires = set(boundary.get("release_claim_requires", []))
                required_release = {
                    "live_signed_app_guard_ingestion",
                    "live_duplicate_signed_request_rejection",
                    "physical_device_collection_packet",
                    "ios_native_build_evidence",
                    "ios_xcframework_binding_evidence",
                    "governed_physical_attack_lab_evidence",
                }
                if not required_release.issubset(release_requires):
                    errors.append(
                        f"{path}: benchmark_gate.evidence_boundary.release_claim_requires must include {sorted(required_release)}"
                    )
    if not isinstance(fixtures, list) or not fixtures:
        errors.append(f"{path}: fixtures must be a non-empty list")
        return errors

    seen_ids: set[str] = set()
    for index, item in enumerate(fixtures):
        prefix = f"{path}:{index}"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: fixture must be an object")
            continue
        fixture_id = item.get("id")
        if not fixture_id:
            errors.append(f"{prefix}: id is required")
        elif fixture_id in seen_ids:
            errors.append(f"{prefix}: duplicate id {fixture_id}")
        else:
            seen_ids.add(str(fixture_id))

        event = item.get("input")
        expected = item.get("expected")
        if not isinstance(event, dict):
            errors.append(f"{prefix}: input must be an App Guard event object")
            continue
        if not isinstance(expected, dict):
            errors.append(f"{prefix}: expected must be an object")
            continue
        errors.extend(validate_app_guard_event(prefix, event))
        errors.extend(validate_app_guard_expected_projection(prefix, event, expected))

    return errors


def validate_app_guard_event(prefix: str, event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {"schema", "event_id", "timestamp", "event_type", "severity", "platform", "app", "device", "risk", "evidence"}
    missing = sorted(required - set(event))
    if missing:
        errors.append(f"{prefix}: App Guard event missing required fields: {missing}")
        return errors

    if event.get("schema") != APP_GUARD_EVENT_SCHEMA:
        errors.append(f"{prefix}: input.schema must be {APP_GUARD_EVENT_SCHEMA}")
    if event.get("event_type") not in APP_GUARD_EVENT_TYPES:
        errors.append(f"{prefix}: unsupported App Guard event_type {event.get('event_type')}")
    if event.get("severity") not in VALID_SEVERITIES:
        errors.append(f"{prefix}: severity must be one of {sorted(VALID_SEVERITIES)}")
    if event.get("platform") not in {"android", "ios"}:
        errors.append(f"{prefix}: platform must be android or ios")

    risk = event.get("risk")
    if not isinstance(risk, dict):
        errors.append(f"{prefix}: risk must be an object")
    else:
        score = risk.get("score")
        decision = risk.get("decision")
        reasons = risk.get("reasons")
        if not isinstance(score, int) or not 0 <= score <= 100:
            errors.append(f"{prefix}: risk.score must be an integer from 0 to 100")
        if decision not in APP_GUARD_DECISIONS:
            errors.append(f"{prefix}: risk.decision must be one of {sorted(APP_GUARD_DECISIONS)}")
        if not isinstance(reasons, list) or not reasons:
            errors.append(f"{prefix}: risk.reasons must be a non-empty list")

    evidence = event.get("evidence")
    if not isinstance(evidence, dict):
        errors.append(f"{prefix}: evidence must be an object")
        return errors
    if evidence.get("collector") != "protected-webview":
        errors.append(f"{prefix}: evidence.collector must be protected-webview")
    if evidence.get("privacy_mode") != "metadata_only":
        errors.append(f"{prefix}: evidence.privacy_mode must be metadata_only")
    forbidden = sorted(APP_GUARD_FORBIDDEN_EVIDENCE_KEYS & set(evidence))
    if forbidden:
        errors.append(f"{prefix}: evidence contains forbidden raw/privacy-sensitive fields: {forbidden}")
    active_signals = evidence.get("active_signals")
    if not isinstance(active_signals, list) or not active_signals:
        errors.append(f"{prefix}: evidence.active_signals must be a non-empty list")
    else:
        if evidence.get("signal_count") != len(active_signals):
            errors.append(f"{prefix}: evidence.signal_count must match active_signals length")
        for signal_index, signal in enumerate(active_signals):
            signal_prefix = f"{prefix}:active_signal:{signal_index}"
            if not isinstance(signal, dict):
                errors.append(f"{signal_prefix}: signal must be an object")
                continue
            if signal.get("name") not in APP_GUARD_EVENT_TYPES:
                errors.append(f"{signal_prefix}: unsupported signal name {signal.get('name')}")
            if not isinstance(signal.get("weight"), int) or not 0 <= signal["weight"] <= 100:
                errors.append(f"{signal_prefix}: weight must be an integer from 0 to 100")
            reasons = event.get("risk", {}).get("reasons", [])
            if signal.get("name") not in reasons and signal.get("name") != event.get("event_type"):
                errors.append(f"{signal_prefix}: active signal must be represented in risk.reasons or event_type")

    network = evidence.get("network")
    if network is not None:
        if not isinstance(network, dict):
            errors.append(f"{prefix}: evidence.network must be an object")
        elif "host_hash" not in network or not str(network["host_hash"]).startswith("sha256:"):
            errors.append(f"{prefix}: evidence.network.host_hash must be a sha256 hash, not a raw host")

    tamper = evidence.get("tamper")
    if tamper is not None:
        if not isinstance(tamper, dict):
            errors.append(f"{prefix}: evidence.tamper must be an object")
        elif tamper.get("content_sampled") is not False:
            errors.append(f"{prefix}: evidence.tamper.content_sampled must be false")

    return errors


def validate_app_guard_expected_projection(prefix: str, event: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    alert = expected.get("alert")
    timeline = expected.get("timeline")
    server = expected.get("server")
    if not isinstance(alert, dict):
        errors.append(f"{prefix}: expected.alert must be an object")
    else:
        if alert.get("source") != "mobile_app_guard":
            errors.append(f"{prefix}: expected.alert.source must be mobile_app_guard")
        if alert.get("server_source") != "app_guard":
            errors.append(f"{prefix}: expected.alert.server_source must be app_guard")
        if alert.get("severity") != event.get("severity"):
            errors.append(f"{prefix}: expected.alert.severity must match input severity")
        if alert.get("detection_rule") != event.get("event_type"):
            errors.append(f"{prefix}: expected.alert.detection_rule must match input event_type")
        expected_action = alert.get("recommended_action")
        decision = event.get("risk", {}).get("decision")
        if decision == "step_up" and expected_action != "step_up_auth":
            errors.append(f"{prefix}: step_up decision must expect step_up_auth action")
        if decision == "block" and expected_action != "block_mobile_workflow":
            errors.append(f"{prefix}: block decision must expect block_mobile_workflow action")
        if decision == "kill_session" and expected_action != "kill_session":
            errors.append(f"{prefix}: kill_session decision must expect kill_session action")
        if decision in {"allow", "observe", "warn"} and expected_action is not None:
            errors.append(f"{prefix}: non-blocking decision must not expect a response action")
        metadata_fields = set(alert.get("metadata_fields", []))
        missing_metadata = sorted({"app", "device", "risk", "evidence.active_signals"} - metadata_fields)
        if missing_metadata:
            errors.append(f"{prefix}: expected.alert.metadata_fields missing {missing_metadata}")

    if not isinstance(timeline, dict):
        errors.append(f"{prefix}: expected.timeline must be an object")
    else:
        if timeline.get("type") != "app_guard_event":
            errors.append(f"{prefix}: expected.timeline.type must be app_guard_event")
        if timeline.get("source") != "mobile_app_guard":
            errors.append(f"{prefix}: expected.timeline.source must be mobile_app_guard")
        if timeline.get("must_preserve_active_signals") is not True:
            errors.append(f"{prefix}: timeline must preserve active signals")
        if timeline.get("must_preserve_privacy_mode") is not True:
            errors.append(f"{prefix}: timeline must preserve privacy_mode")

    if not isinstance(server, dict):
        errors.append(f"{prefix}: expected.server must be an object")
    else:
        required_topics = {"app_guard:event", "mobile:app_guard_event", "security:app_guard"}
        missing_topics = sorted(required_topics - set(server.get("required_pubsub_topics", [])))
        if missing_topics:
            errors.append(f"{prefix}: expected.server.required_pubsub_topics missing {missing_topics}")
        channel_events = set(server.get("required_channel_events", []))
        if not {"events:all", "events:<device_db_id>"}.issubset(channel_events):
            errors.append(f"{prefix}: expected.server.required_channel_events must include events:all and events:<device_db_id>")
        if server.get("must_not_500") is not True:
            errors.append(f"{prefix}: expected.server.must_not_500 must be true")

    return errors


def validate_contract_lanes(path: Path, lanes: list[Any]) -> list[str]:
    errors: list[str] = []
    if not lanes:
        return [f"{path}: lanes must be a non-empty list"]

    seen_ids: set[str] = set()
    for lane_index, lane in enumerate(lanes):
        prefix = f"{path}:lane:{lane_index}"
        if not isinstance(lane, dict):
            errors.append(f"{prefix}: lane must be an object")
            continue
        for field in ["roadmap", "profile_id", "owner_area"]:
            if not lane.get(field):
                errors.append(f"{prefix}: {field} is required")
        if not isinstance(lane.get("required_evidence_fields"), list) or not lane["required_evidence_fields"]:
            errors.append(f"{prefix}: required_evidence_fields must be a non-empty list")

        lane_fixtures = lane.get("fixtures")
        if not isinstance(lane_fixtures, list) or not lane_fixtures:
            errors.append(f"{prefix}: fixtures must be a non-empty list")
            continue

        for fixture_index, item in enumerate(lane_fixtures):
            item_prefix = f"{prefix}:fixture:{fixture_index}"
            if not isinstance(item, dict):
                errors.append(f"{item_prefix}: fixture must be an object")
                continue
            fixture_id = item.get("id")
            if not fixture_id:
                errors.append(f"{item_prefix}: id is required")
            elif fixture_id in seen_ids:
                errors.append(f"{item_prefix}: duplicate id {fixture_id}")
            else:
                seen_ids.add(str(fixture_id))
            for field in ["capability", "expected_artifact", "gap_classification", "remaining_gap"]:
                if not item.get(field):
                    errors.append(f"{item_prefix}: {field} is required")
            gap = item.get("gap_classification")
            if gap and gap not in VALID_CONTRACT_GAPS:
                errors.append(
                    f"{item_prefix}: gap_classification must be one of {sorted(VALID_CONTRACT_GAPS)}"
                )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    args = parser.parse_args()

    paths = sorted(args.fixture_dir.glob("*.json"))
    if not paths:
        raise SystemExit(f"no fixture files found under {args.fixture_dir}")

    errors: list[str] = []
    for path in paths:
        errors.extend(validate_fixture_file(path))

    if errors:
        for error in errors:
            print(error)
        return 1

    print(f"validated {len(paths)} replay fixture file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
