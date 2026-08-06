#!/usr/bin/env python3
"""Validate synthetic server-authoritative fixed-point movement replays."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
SOURCE_PATH = Path(__file__).resolve()
TELEMETRY_SCHEMA_PATH = ROOT / "schemas/anti_cheat_game_telemetry_envelope_v1.schema.json"
REPLAY_SCHEMA_PATH = ROOT / "schemas/anti_cheat_server_movement_replay_v1.schema.json"
REPORT_SCHEMA_PATH = ROOT / "schemas/anti_cheat_game_vertical_slice_report_v1.schema.json"
DEFAULT_FIXTURE_PATH = ROOT / "tools/detection_validation/fixtures/anti_cheat_unity_server_movement_replay_synthetic_v1.json"
MAX_JSON_BYTES = 1_048_576
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){0,3}(?:[-+][a-z0-9][a-z0-9.-]{0,31})?$")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
URL_RE = re.compile(r"(?i)(?:\b(?:https?|ftp)://|\bwww\.)")
SECRET_RE = re.compile(r"(?i)\b(?:basic|bearer)\s+[a-z0-9._~+/=-]{4,}")
ASSIGNMENT_RE = re.compile(r"(?i)(?:^|[\s;,])([a-z][a-z0-9_. -]{0,63}?)\s*[:=]")
POLICY_DOMAIN = b"tamandua.anti_cheat.server_movement_policy/v1\0"
REPLAY_DOMAIN = b"tamandua.anti_cheat.server_movement_replay/v1\0"
REPORT_DOMAIN = b"tamandua.anti_cheat.game_vertical_slice_report/v1\0"
FIXTURE_KEYS = {
    "schema", "evidence_class", "claim_boundary", "tenant_scope_digest", "build_digest",
    "policy", "policy_digest", "clean_strata", "authorized_teleport", "speed_violation",
    "gap_inconclusive",
}
POLICY_KEYS = {
    "schema", "policy_id", "policy_version", "tick_rate_hz", "max_speed_mm_per_second",
    "tolerance_mm", "max_gap_ticks", "authorized_transitions",
}
FORBIDDEN_NORMALIZED_KEYS = {
    "authorization", "api_key", "access_token", "refresh_token", "password", "secret",
    "player_email", "email", "ip", "ip_address", "tenant_id", "build_id", "session_id",
    "match_id", "player_id", "global_player_id", "device_serial", "raw_input", "raw_chat",
    "auth", "authentication", "auth_token", "cookie", "set_cookie", "session", "sessionid", "session_token",
    "proxy_authorization", "www_authenticate", "aws_access_key_id", "aws_secret_access_key",
    "aws_session_token",
}


class MovementReplayGateError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MovementReplayGateError("duplicate JSON member rejected")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if not 1 <= len(raw) <= MAX_JSON_BYTES or b"\x00" in raw:
        raise MovementReplayGateError("JSON bounds are invalid")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_closed_pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(MovementReplayGateError("floating-point JSON rejected")),
            parse_constant=lambda _value: (_ for _ in ()).throw(MovementReplayGateError("non-finite JSON rejected")),
        )
    except MovementReplayGateError:
        raise
    except Exception:
        raise MovementReplayGateError("invalid JSON") from None
    if type(value) is not dict:
        raise MovementReplayGateError("JSON root must be an object")
    return value, raw


def _contains_ip(value: str) -> bool:
    for raw in re.split(r"[\s,;(){}<>\[\]\"'=/]+", value):
        token = raw.strip(".,")
        if "%" in token:
            token = token.split("%", 1)[0]
        if token.count(":") == 1 and token.count(".") == 3:
            host, port = token.rsplit(":", 1)
            if port.isdigit():
                token = host
        if ":" not in token and token.count(".") != 3:
            continue
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        return True
    return False


def _normalized_member_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _is_secret_member_name(value: str) -> bool:
    normalized = _normalized_member_name(value)
    parts = set(normalized.split("_"))
    return (
        normalized in FORBIDDEN_NORMALIZED_KEYS
        or normalized.endswith(("_authorization", "_authentication", "_auth", "_api_key", "_auth_token"))
        or (normalized.startswith("aws_") and bool(parts & {"key", "secret", "token", "credential", "credentials"}))
        or ("cookie" in parts)
        or ("session" in parts and bool(parts & {"id", "key", "token", "cookie"}))
    )


def _contains_secret(value: str) -> bool:
    if SECRET_RE.search(value):
        return True
    return any(_is_secret_member_name(match.group(1)) for match in ASSIGNMENT_RE.finditer(value))


def privacy_errors(value: Any, path: str = "fixture") -> list[str]:
    errors: list[str] = []
    if type(value) is dict:
        for key, member in value.items():
            child = f"{path}.{key}"
            if _is_secret_member_name(key):
                errors.append(f"raw identifier or secret member rejected at {child}")
            errors.extend(privacy_errors(member, child))
    elif type(value) is list:
        for index, member in enumerate(value):
            errors.extend(privacy_errors(member, f"{path}[{index}]"))
    elif type(value) is float:
        errors.append(f"floating-point value rejected at {path}")
    elif type(value) is str:
        if EMAIL_RE.search(value):
            errors.append(f"email-shaped value rejected at {path}")
        if _contains_ip(value):
            errors.append(f"IP address value rejected at {path}")
        if URL_RE.search(value):
            errors.append(f"URL value rejected at {path}")
        if _contains_secret(value):
            errors.append(f"secret-shaped value rejected at {path}")
    return errors


def policy_digest(policy: dict[str, Any]) -> str:
    return sha256(POLICY_DOMAIN + canonical(policy))


def _validate_policy(policy: Any) -> None:
    if type(policy) is not dict or set(policy) != POLICY_KEYS:
        raise MovementReplayGateError("policy members are not closed")
    if policy["schema"] != "tamandua.anti_cheat.server_movement_policy/v1":
        raise MovementReplayGateError("policy schema is invalid")
    if re.fullmatch(r"[a-z][a-z0-9_.-]{1,127}", policy.get("policy_id", "")) is None:
        raise MovementReplayGateError("policy id is invalid")
    if VERSION_RE.fullmatch(policy.get("policy_version", "")) is None:
        raise MovementReplayGateError("policy version is invalid")
    for name, low, high in (
        ("tick_rate_hz", 1, 1000), ("max_speed_mm_per_second", 1, 1000000),
        ("tolerance_mm", 0, 100000), ("max_gap_ticks", 1, 1000),
    ):
        value = policy.get(name)
        if type(value) is not int or not low <= value <= high:
            raise MovementReplayGateError(f"policy {name} is invalid")
    transitions = policy.get("authorized_transitions")
    if type(transitions) is not list or not 1 <= len(transitions) <= 8:
        raise MovementReplayGateError("authorized transitions are invalid")
    identities = []
    for item in transitions:
        if type(item) is not dict or set(item) != {"kind", "authorization_digest", "max_displacement_mm", "max_gap_ticks"}:
            raise MovementReplayGateError("authorized transition members are not closed")
        if item["kind"] not in {"dash", "teleport"} or DIGEST_RE.fullmatch(item["authorization_digest"]) is None:
            raise MovementReplayGateError("authorized transition identity is invalid")
        if type(item["max_displacement_mm"]) is not int or not 1 <= item["max_displacement_mm"] <= 1000000000:
            raise MovementReplayGateError("authorized transition displacement is invalid")
        if type(item["max_gap_ticks"]) is not int or not 1 <= item["max_gap_ticks"] <= policy["max_gap_ticks"]:
            raise MovementReplayGateError("authorized transition gap is invalid")
        identities.append((item["kind"], item["authorization_digest"]))
    if len(identities) != len(set(identities)):
        raise MovementReplayGateError("authorized transition identities are duplicated")


def _schema_errors(value: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    return [error.message for error in Draft202012Validator(schema).iter_errors(value)]


def evaluate_replay(events: list[dict[str, Any]], policy: dict[str, Any], digest: str, telemetry_schema: dict[str, Any]) -> dict[str, Any]:
    _validate_policy(policy)
    policy_privacy_errors = privacy_errors(policy, "policy")
    if policy_privacy_errors:
        raise MovementReplayGateError(policy_privacy_errors[0])
    computed_digest = policy_digest(policy)
    if type(digest) is not str or not hmac.compare_digest(digest, computed_digest):
        raise MovementReplayGateError("policy digest is not recomputable")
    digest = computed_digest
    if type(events) is not list or not 2 <= len(events) <= 128:
        raise MovementReplayGateError("replay event count is invalid")
    telemetry_validator = Draft202012Validator(telemetry_schema)
    for event in events:
        if type(event) is not dict or list(telemetry_validator.iter_errors(event)):
            raise MovementReplayGateError("telemetry envelope schema validation failed")
        errors = privacy_errors(event, "event")
        if errors:
            raise MovementReplayGateError(errors[0])
    identity = (events[0]["tenant_scope_digest"], events[0]["build_digest"], events[0]["session_digest"])
    if any((event["tenant_scope_digest"], event["build_digest"], event["session_digest"]) != identity for event in events[1:]):
        raise MovementReplayGateError("cross tenant, build, or session replay rejected")
    seen_sequences: set[int] = set()
    seen_ticks: set[int] = set()
    classification = "within_constraints"
    start_tick = events[0]["server_tick"]
    end_tick = events[-1]["server_tick"]
    for index, event in enumerate(events):
        if event["sequence"] in seen_sequences or event["server_tick"] in seen_ticks:
            raise MovementReplayGateError("duplicate sequence or tick rejected")
        seen_sequences.add(event["sequence"])
        seen_ticks.add(event["server_tick"])
        if index == 0:
            continue
        previous = events[index - 1]
        if event["sequence"] <= previous["sequence"] or event["server_tick"] <= previous["server_tick"]:
            raise MovementReplayGateError("out-of-order sequence or tick rejected")
        gap = event["server_tick"] - previous["server_tick"]
        if event["sequence"] != previous["sequence"] + 1 or gap > policy["max_gap_ticks"]:
            if classification != "constraint_violation":
                classification = "inconclusive_gap"
            continue
        dx = event["position_mm"]["x"] - previous["position_mm"]["x"]
        dy = event["position_mm"]["y"] - previous["position_mm"]["y"]
        dz = event["position_mm"]["z"] - previous["position_mm"]["z"]
        distance_squared = dx * dx + dy * dy + dz * dz
        transition = event["transition"]
        if transition["kind"] != "none":
            matches = [item for item in policy["authorized_transitions"] if item["kind"] == transition["kind"] and item["authorization_digest"] == transition["authorization_digest"]]
            if len(matches) != 1 or gap > matches[0]["max_gap_ticks"]:
                if classification != "constraint_violation":
                    classification = "inconclusive_transition"
                continue
            if distance_squared > matches[0]["max_displacement_mm"] ** 2:
                classification = "constraint_violation"
            continue
        allowed_numerator = policy["max_speed_mm_per_second"] * gap + policy["tolerance_mm"] * policy["tick_rate_hz"]
        if distance_squared * policy["tick_rate_hz"] ** 2 > allowed_numerator ** 2:
            classification = "constraint_violation"
    if classification == "constraint_violation":
        disposition = "emit_observation"
        outcome = "corroborated"
        reason = "server_movement_constraint_violation"
    elif classification == "within_constraints":
        disposition = "observe"
        outcome = "not_corroborated"
        reason = "server_movement_within_constraints"
    else:
        disposition = "abstain"
        outcome = None
        reason = None
    evidence_digest = sha256(REPLAY_DOMAIN + canonical({"events": events, "policy_digest": digest, "classification": classification}))
    observation = None if outcome is None else {
        "observation_id_digest": sha256(b"observation\0" + bytes.fromhex(evidence_digest)),
        "detector_family": "movement", "outcome": outcome, "reason_code": reason,
        "evidence_digest": evidence_digest, "start_tick": start_tick, "end_tick": end_tick,
        "feature_schema": "tamandua.game.movement_features/v1",
    }
    basis = {
        "tenant_scope_digest": identity[0], "build_digest": identity[1], "session_digest": identity[2],
        "policy_digest": digest, "classification": classification, "disposition": disposition,
        "observation": observation, "extensions_influenced_suspicion": False,
        "evidence_class": "synthetic_contract", "external_claim_allowed": False,
    }
    replay_id = sha256(REPLAY_DOMAIN + canonical(basis))
    return {"schema": "tamandua.anti_cheat.server_movement_replay/v1", "replay_id": replay_id, **basis}


def _event(fixture: dict[str, Any], session: str, sequence: int, tick: int, x: int, transition: dict[str, Any], extension: Any) -> dict[str, Any]:
    return {
        "schema": "tamandua.anti_cheat.game_telemetry_envelope/v1", "authority": "authoritative_server",
        "tenant_scope_digest": fixture["tenant_scope_digest"], "build_digest": fixture["build_digest"],
        "session_digest": session, "sequence": sequence, "server_tick": tick,
        "position_mm": {"x": x, "y": 0, "z": 0}, "transition": transition,
        "extensions": [] if extension is None else [extension],
    }


def expand_fixture(fixture: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    expanded: list[tuple[str, list[dict[str, Any]]]] = []
    specs = [(item["name"], item["count"], item["step_mm"], 1, {"kind": "none"}, item["extension"]) for item in fixture["clean_strata"]]
    teleport = fixture["authorized_teleport"]
    specs.append((teleport["name"], teleport["count"], teleport["step_mm"], 1, {"kind": teleport["transition_kind"], "authorization_digest": teleport["authorization_digest"]}, None))
    violation = fixture["speed_violation"]
    specs.append((violation["name"], violation["count"], violation["step_mm"], 1, {"kind": "none"}, None))
    gap = fixture["gap_inconclusive"]
    specs.append((gap["name"], gap["count"], gap["step_mm"], gap["gap_ticks"], {"kind": "none"}, None))
    ordinal = 0
    for name, count, step, tick_gap, transition, extension in specs:
        for index in range(count):
            session = sha256(f"tamandua.synthetic.session/v1\0{name}\0{index}".encode())
            start = 1000 + ordinal * 16
            events = [
                _event(fixture, session, 0, start, 0, {"kind": "none"}, extension),
                _event(fixture, session, 1, start + tick_gap, step, transition, extension),
            ]
            expanded.append((name, events))
            ordinal += 1
    return expanded


def validate_fixture(fixture: dict[str, Any]) -> tuple[dict[str, Any], str]:
    errors = privacy_errors(fixture)
    if errors:
        raise MovementReplayGateError(errors[0])
    if set(fixture) != FIXTURE_KEYS or fixture["schema"] != "tamandua.anti_cheat.server_movement_replay_fixture/v1":
        raise MovementReplayGateError("fixture members or schema are invalid")
    if fixture["evidence_class"] != "synthetic_contract" or fixture["claim_boundary"] != {
        "production_fpr_claimable": False, "live_server_validated": False,
        "enforcement_authorized": False, "external_claim_allowed": False,
    }:
        raise MovementReplayGateError("fixture claim boundary is invalid")
    if DIGEST_RE.fullmatch(fixture["tenant_scope_digest"]) is None or DIGEST_RE.fullmatch(fixture["build_digest"]) is None:
        raise MovementReplayGateError("fixture scoped digest is invalid")
    _validate_policy(fixture["policy"])
    digest = policy_digest(fixture["policy"])
    if fixture["policy_digest"] != digest:
        raise MovementReplayGateError("policy digest is not recomputable")
    clean = fixture["clean_strata"]
    if type(clean) is not list or any(type(item) is not dict or set(item) != {"name", "count", "step_mm", "extension"} for item in clean):
        raise MovementReplayGateError("clean strata members are not closed")
    if [(item.get("name"), item.get("count")) for item in clean] != [("vanilla", 598), ("approved_mod", 598), ("approved_accessibility", 598)]:
        raise MovementReplayGateError("clean strata are invalid")
    if any(type(item["step_mm"]) is not int or not 0 <= item["step_mm"] <= 1000000000 for item in clean):
        raise MovementReplayGateError("clean stratum displacement is invalid")
    teleport = fixture["authorized_teleport"]
    if type(teleport) is not dict or set(teleport) != {"name", "count", "step_mm", "transition_kind", "authorization_digest"}:
        raise MovementReplayGateError("teleport stratum members are not closed")
    if (teleport.get("name"), teleport.get("count")) != ("authorized_teleport", 1):
        raise MovementReplayGateError("teleport stratum is invalid")
    violation = fixture["speed_violation"]
    if type(violation) is not dict or set(violation) != {"name", "count", "step_mm"}:
        raise MovementReplayGateError("violation stratum members are not closed")
    if (violation.get("name"), violation.get("count")) != ("speed_violation", 100):
        raise MovementReplayGateError("violation stratum is invalid")
    gap = fixture["gap_inconclusive"]
    if type(gap) is not dict or set(gap) != {"name", "count", "step_mm", "gap_ticks"}:
        raise MovementReplayGateError("gap stratum members are not closed")
    if (gap.get("name"), gap.get("count")) != ("gap_inconclusive", 1):
        raise MovementReplayGateError("gap stratum is invalid")
    for item in (teleport, violation, gap):
        if type(item["step_mm"]) is not int or not 0 <= item["step_mm"] <= 1000000000:
            raise MovementReplayGateError("synthetic displacement is invalid")
    if type(gap["gap_ticks"]) is not int or gap["gap_ticks"] <= fixture["policy"]["max_gap_ticks"]:
        raise MovementReplayGateError("synthetic gap is not conclusively excessive")
    return fixture["policy"], digest


def validate_gate(fixture_path: Path = DEFAULT_FIXTURE_PATH) -> dict[str, Any]:
    fixture, fixture_raw = load_json(fixture_path)
    telemetry_schema, telemetry_raw = load_json(TELEMETRY_SCHEMA_PATH)
    replay_schema, replay_raw = load_json(REPLAY_SCHEMA_PATH)
    report_schema, report_raw = load_json(REPORT_SCHEMA_PATH)
    for schema in (telemetry_schema, replay_schema, report_schema):
        Draft202012Validator.check_schema(schema)
    replay_validator = Draft202012Validator(replay_schema)
    report_validator = Draft202012Validator(report_schema)
    privacy_closed = not privacy_errors(fixture)
    policy, digest = validate_fixture(fixture)
    results: list[tuple[str, dict[str, Any]]] = []
    for name, events in expand_fixture(fixture):
        replay = evaluate_replay(events, policy, digest, telemetry_schema)
        if list(replay_validator.iter_errors(replay)):
            raise MovementReplayGateError("replay schema validation failed")
        results.append((name, replay))
    expected = {
        "vanilla": Counter({"within_constraints": 598}),
        "approved_mod": Counter({"within_constraints": 598}),
        "approved_accessibility": Counter({"within_constraints": 598}),
        "authorized_teleport": Counter({"within_constraints": 1}),
        "speed_violation": Counter({"constraint_violation": 100}),
        "gap_inconclusive": Counter({"inconclusive_gap": 1}),
    }
    actual = {name: Counter(replay["classification"] for stratum, replay in results if stratum == name) for name in expected}
    if actual != expected:
        raise MovementReplayGateError("synthetic replay outcomes do not match the closed expectation")
    strata = []
    for name in expected:
        counts = actual[name]
        inconclusive = counts["inconclusive_gap"] + counts["inconclusive_transition"]
        strata.append({
            "name": name, "total": sum(counts.values()), "within_constraints": counts["within_constraints"],
            "constraint_violation": counts["constraint_violation"], "inconclusive": inconclusive,
            "synthetic_one_sided_upper_bound_ppm": 4998 if name in {"vanilla", "approved_mod", "approved_accessibility"} else None,
        })
    totals = Counter(replay["classification"] for _name, replay in results)
    basis = {
        "schema": "tamandua.anti_cheat.game_vertical_slice_report/v1",
        "fixture_sha256": sha256(fixture_raw), "telemetry_schema_sha256": sha256(telemetry_raw),
        "replay_schema_sha256": sha256(replay_raw), "report_schema_sha256": sha256(report_raw),
        "gate_source_sha256": sha256(SOURCE_PATH.read_bytes()), "policy_digest": digest,
        "evidence_class": "synthetic_contract",
        "counts": {"total": len(results), "within_constraints": totals["within_constraints"], "constraint_violation": totals["constraint_violation"], "inconclusive": totals["inconclusive_gap"] + totals["inconclusive_transition"]},
        "synthetic_upper_bound_contract": {"method": "clopper_pearson_one_sided", "confidence_ppm": 950000, "zero_failure_sample_count": 598, "upper_bound_ppm": 4998, "production_fpr_claimable": False},
        "strata": strata,
        "gates": {"schemas_valid": True, "fixed_point_only": True, "server_authoritative_only": True, "identity_scope_closed": True, "privacy_closed": privacy_closed, "extensions_non_suspicious": True, "deterministic": True},
        "claims": {"production_fpr_validated": False, "live_server_validated": False, "enforcement_authorized": False, "external_claim_allowed": False},
    }
    report = {"report_id": sha256(REPORT_DOMAIN + canonical(basis)), **basis}
    if list(report_validator.iter_errors(report)):
        raise MovementReplayGateError("report schema validation failed")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE_PATH)
    args = parser.parse_args(argv)
    try:
        print(canonical(validate_gate(args.fixture)).decode())
    except (MovementReplayGateError, OSError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
