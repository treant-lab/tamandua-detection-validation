#!/usr/bin/env python3
"""Deterministic synthetic server-authoritative economy/action replay gate."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
FIXTURE_PATH = ROOT / "tools/detection_validation/fixtures/anti_cheat_server_economy_action_synthetic_v1.json"
REPLAY_SCHEMA_PATH = ROOT / "schemas/anti_cheat_server_economy_action_replay_v1.schema.json"
REPORT_SCHEMA_PATH = ROOT / "schemas/anti_cheat_server_economy_action_report_v1.schema.json"
POLICY_DOMAIN = b"tamandua.anti_cheat.server_economy_action_policy/v1\0"
REPLAY_DOMAIN = b"tamandua.anti_cheat.server_economy_action_replay/v1\0"
REPORT_DOMAIN = b"tamandua.anti_cheat.server_economy_action_report/v1\0"
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_JSON_BYTES = 1_048_576
FIXTURE_KEYS = {"schema", "evidence_class", "claim_boundary", "tenant_scope_digest", "build_digest", "policy", "policy_digest", "clean_strata", "injected"}
POLICY_KEYS = {"schema", "policy_id", "policy_version", "max_gap_ticks", "initial_currency", "initial_items", "initial_ammo", "operations"}
OP_KEYS = {"kind", "authorization_digest", "currency_delta", "item_delta", "ammo_delta", "cooldown_ticks", "ability_from", "ability_to"}
EVENT_KEYS = {"tenant_scope_digest", "build_digest", "session_digest", "ledger_scope_digest", "event_id_digest", "idempotency_of_digest", "sequence", "server_tick", "kind", "authorization_digest", "currency", "items", "ammo", "ability_state", "conflict_code", "extensions"}
FORBIDDEN_KEYS = {"tenant_id", "build_id", "session_id", "player_id", "email", "ip", "password", "secret", "token", "credential", "authorization", "raw_id"}


class EconomyActionReplayError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EconomyActionReplayError("duplicate JSON member rejected")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if not 1 <= len(raw) <= MAX_JSON_BYTES or b"\0" in raw:
        raise EconomyActionReplayError("JSON bounds invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
            parse_float=lambda _x: (_ for _ in ()).throw(EconomyActionReplayError("floating-point JSON rejected")),
            parse_constant=lambda _x: (_ for _ in ()).throw(EconomyActionReplayError("non-finite JSON rejected")))
    except EconomyActionReplayError:
        raise
    except Exception:
        raise EconomyActionReplayError("invalid JSON") from None
    if type(value) is not dict:
        raise EconomyActionReplayError("JSON root must be object")
    return value, raw


def _normalized(value: str) -> str:
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def privacy_errors(value: Any, path: str = "value") -> list[str]:
    errors: list[str] = []
    if type(value) is dict:
        for key, member in value.items():
            normalized = _normalized(key)
            parts = set(normalized.split("_"))
            if normalized in FORBIDDEN_KEYS or parts & {"password", "secret", "token", "credential", "credentials"}:
                errors.append(f"raw identifier or secret member rejected at {path}.{key}")
            errors.extend(privacy_errors(member, f"{path}.{key}"))
    elif type(value) is list:
        for index, member in enumerate(value):
            errors.extend(privacy_errors(member, f"{path}[{index}]"))
    elif type(value) is float:
        errors.append(f"floating point rejected at {path}")
    elif type(value) is str:
        if re.search(r"(?i)(?:bearer\s+|password\s*[:=]|secret\s*[:=]|[\w.+-]+@[\w.-]+\.[a-z]{2,})", value):
            errors.append(f"raw secret or email rejected at {path}")
        if re.search(r"(?:\b\d{1,3}\.){3}\d{1,3}\b", value):
            errors.append(f"raw IP rejected at {path}")
    return errors


def policy_digest(policy: dict[str, Any]) -> str:
    return sha256(POLICY_DOMAIN + canonical(policy))


def validate_policy(policy: Any, digest: Any) -> dict[str, dict[str, Any]]:
    if type(policy) is not dict or set(policy) != POLICY_KEYS:
        raise EconomyActionReplayError("policy members not closed")
    if policy["schema"] != "tamandua.anti_cheat.server_economy_action_policy/v1":
        raise EconomyActionReplayError("policy schema invalid")
    if re.fullmatch(r"[a-z][a-z0-9_.-]{1,127}", policy["policy_id"]) is None or re.fullmatch(r"\d+\.\d+\.\d+", policy["policy_version"]) is None:
        raise EconomyActionReplayError("policy identity invalid")
    for key, low, high in (("max_gap_ticks", 1, 1000), ("initial_currency", 0, 10**12), ("initial_items", 0, 10**9), ("initial_ammo", 0, 10**9)):
        if type(policy[key]) is not int or not low <= policy[key] <= high:
            raise EconomyActionReplayError("policy integer invalid")
    operations = policy["operations"]
    if type(operations) is not list or not 1 <= len(operations) <= 32:
        raise EconomyActionReplayError("policy operations invalid")
    table: dict[str, dict[str, Any]] = {}
    for operation in operations:
        if type(operation) is not dict or set(operation) != OP_KEYS or operation.get("kind") in table:
            raise EconomyActionReplayError("policy operation members or identity invalid")
        if re.fullmatch(r"[a-z][a-z0-9_]{1,31}", operation["kind"]) is None or DIGEST_RE.fullmatch(operation["authorization_digest"]) is None:
            raise EconomyActionReplayError("policy operation authorization invalid")
        for key in ("currency_delta", "item_delta", "ammo_delta", "cooldown_ticks"):
            if type(operation[key]) is not int or abs(operation[key]) > 10**12:
                raise EconomyActionReplayError("policy operation integer invalid")
        if operation["cooldown_ticks"] < 0 or operation["ability_from"] not in {"ready", "cooldown"} or operation["ability_to"] not in {"ready", "cooldown"}:
            raise EconomyActionReplayError("policy operation transition invalid")
        table[operation["kind"]] = operation
    computed = policy_digest(policy)
    if type(digest) is not str or not hmac.compare_digest(digest, computed):
        raise EconomyActionReplayError("policy digest not recomputable")
    return table


def _valid_event(event: Any) -> bool:
    if type(event) is not dict or set(event) != EVENT_KEYS:
        return False
    for key in ("tenant_scope_digest", "build_digest", "session_digest", "ledger_scope_digest", "event_id_digest", "authorization_digest"):
        if type(event[key]) is not str or DIGEST_RE.fullmatch(event[key]) is None:
            return False
    if event["idempotency_of_digest"] is not None and (type(event["idempotency_of_digest"]) is not str or DIGEST_RE.fullmatch(event["idempotency_of_digest"]) is None):
        return False
    if (event["kind"] == "idempotent_retry") != (event["idempotency_of_digest"] is not None):
        return False
    if any(type(event[key]) is not int or event[key] < 0 for key in ("sequence", "server_tick", "currency", "items", "ammo")):
        return False
    if event["ability_state"] not in {"ready", "cooldown", "active"} or event["conflict_code"] not in {"none", "ledger_snapshot_conflict"}:
        return False
    extensions = event["extensions"]
    return type(extensions) is list and len(extensions) <= 1 and all(type(item) is dict and set(item) == {"namespace_digest", "approval"} and DIGEST_RE.fullmatch(item["namespace_digest"]) and item["approval"] in {"approved_mod", "approved_accessibility", "unknown"} for item in extensions)


def evaluate_replay(events: list[dict[str, Any]], policy: dict[str, Any], digest: str) -> dict[str, Any]:
    operations = validate_policy(policy, digest)
    errors = privacy_errors(events, "events")
    if errors:
        raise EconomyActionReplayError(errors[0])
    if type(events) is not list or not 2 <= len(events) <= 64 or any(not _valid_event(event) for event in events):
        raise EconomyActionReplayError("event members invalid")
    identity = tuple(events[0][key] for key in ("tenant_scope_digest", "build_digest", "session_digest", "ledger_scope_digest"))
    if any(tuple(event[key] for key in ("tenant_scope_digest", "build_digest", "session_digest", "ledger_scope_digest")) != identity for event in events):
        raise EconomyActionReplayError("cross-scope replay rejected")
    sequences: set[int] = set()
    ticks: set[int] = set()
    ids: set[str] = set()
    for index, event in enumerate(events):
        if event["sequence"] in sequences or event["server_tick"] in ticks or event["event_id_digest"] in ids:
            raise EconomyActionReplayError("duplicate event, sequence, or tick rejected")
        sequences.add(event["sequence"]); ticks.add(event["server_tick"]); ids.add(event["event_id_digest"])
        if index and (event["sequence"] <= events[index - 1]["sequence"] or event["server_tick"] <= events[index - 1]["server_tick"]):
            raise EconomyActionReplayError("out-of-order replay rejected")
    previous = events[0]
    initial_state = (
        policy["initial_currency"], policy["initial_items"], policy["initial_ammo"], "ready"
    )
    initial_conflict = previous["kind"] != "snapshot" or (
        previous["currency"], previous["items"], previous["ammo"], previous["ability_state"]
    ) != initial_state or previous["authorization_digest"] != "0" * 64

    # Classification precedence is global, not dependent on event order:
    # conflict > gap > violation > clean.
    semantic_conflict = initial_conflict or any(
        event["conflict_code"] != "none" for event in events
    )
    processed_events = {previous["event_id_digest"]: previous}
    for event in events[1:]:
        operation = operations.get(event["kind"])
        if operation is None or not hmac.compare_digest(event["authorization_digest"], operation["authorization_digest"]):
            semantic_conflict = True
        if event["kind"] == "idempotent_retry":
            original = processed_events.get(event["idempotency_of_digest"])
            if original is None or original["kind"] in {"snapshot", "idempotent_retry"}:
                semantic_conflict = True
        processed_events[event["event_id_digest"]] = event

    has_gap = any(
        current["sequence"] != prior["sequence"] + 1
        or current["server_tick"] - prior["server_tick"] > policy["max_gap_ticks"]
        for prior, current in zip(events, events[1:])
    )

    if semantic_conflict:
        classification = "inconclusive_conflict"
    elif has_gap:
        classification = "inconclusive_gap"
    else:
        classification = "within_constraints"
        next_action_tick = 0
        previous = events[0]
        for event in events[1:]:
            operation = operations[event["kind"]]
            expected_currency = previous["currency"] + operation["currency_delta"]
            expected_items = previous["items"] + operation["item_delta"]
            expected_ammo = previous["ammo"] + operation["ammo_delta"]
            if event["currency"] != expected_currency or event["items"] != expected_items or expected_currency < 0 or expected_items < 0:
                classification = "economy_violation"; break
            if event["ammo"] != expected_ammo or expected_ammo < 0 or event["server_tick"] < next_action_tick or previous["ability_state"] != operation["ability_from"] or event["ability_state"] != operation["ability_to"]:
                classification = "action_violation"; break
            if operation["cooldown_ticks"]:
                next_action_tick = event["server_tick"] + operation["cooldown_ticks"]
            previous = event
    if classification.startswith("inconclusive"):
        disposition, observations = "abstain", []
    else:
        disposition = "emit_observation" if classification.endswith("violation") else "observe"
        families = ["economy", "action"] if classification == "within_constraints" else ["economy" if classification == "economy_violation" else "action"]
        evidence = sha256(REPLAY_DOMAIN + canonical({"events": events, "policy_digest": digest, "classification": classification}))
        observations = []
        for family in families:
            violated = classification == f"{family}_violation"
            observations.append({"observation_id_digest": sha256(f"observation:{family}:".encode() + bytes.fromhex(evidence)), "detector_family": family, "outcome": "corroborated" if violated else "not_corroborated", "reason_code": f"server_{family}_{'constraint_violation' if violated else 'within_constraints'}", "evidence_digest": evidence, "start_tick": events[0]["server_tick"], "end_tick": events[-1]["server_tick"], "feature_schema": f"tamandua.game.{family}_features/v1"})
    basis = {"tenant_scope_digest": identity[0], "build_digest": identity[1], "session_digest": identity[2], "policy_digest": digest, "classification": classification, "disposition": disposition, "observations": observations, "extensions_influenced_suspicion": False, "evidence_class": "synthetic_contract", "external_claim_allowed": False}
    replay = {"schema": "tamandua.anti_cheat.server_economy_action_replay/v1", "replay_id": sha256(REPLAY_DOMAIN + canonical(basis)), **basis}
    validate_replay_semantics(replay)
    return replay


def validate_replay_semantics(replay: dict[str, Any]) -> None:
    classification = replay.get("classification")
    disposition = replay.get("disposition")
    observations = replay.get("observations")
    if type(observations) is not list:
        raise EconomyActionReplayError("replay observations invalid")
    if classification in {"inconclusive_gap", "inconclusive_conflict"}:
        if disposition != "abstain" or observations:
            raise EconomyActionReplayError("inconclusive replay must abstain without observations")
        return
    if classification == "within_constraints":
        if disposition != "observe" or len(observations) != 2 or {item.get("detector_family") for item in observations if type(item) is dict} != {"economy", "action"} or any(item.get("outcome") != "not_corroborated" for item in observations):
            raise EconomyActionReplayError("clean replay decision relation invalid")
        return
    expected = "economy" if classification == "economy_violation" else "action" if classification == "action_violation" else None
    if expected is None or disposition != "emit_observation" or len(observations) != 1 or observations[0].get("detector_family") != expected or observations[0].get("outcome") != "corroborated":
        raise EconomyActionReplayError("violation replay decision relation invalid")


def _event(fixture: dict[str, Any], session: str, sequence: int, tick: int, kind: str, auth: str, currency: int, items: int, ammo: int, ability: str, extension: Any, idem: str | None = None) -> dict[str, Any]:
    return {"tenant_scope_digest": fixture["tenant_scope_digest"], "build_digest": fixture["build_digest"], "session_digest": session, "ledger_scope_digest": sha256(b"ledger\0" + bytes.fromhex(session)), "event_id_digest": sha256(f"event:{session}:{sequence}".encode()), "idempotency_of_digest": idem, "sequence": sequence, "server_tick": tick, "kind": kind, "authorization_digest": auth, "currency": currency, "items": items, "ammo": ammo, "ability_state": ability, "conflict_code": "none", "extensions": [] if extension is None else [extension]}


def build_events(fixture: dict[str, Any], name: str, index: int, mutation: str | None, extension: Any) -> list[dict[str, Any]]:
    session = sha256(f"tamandua.synthetic.economy_action/v1\0{name}\0{index}".encode())
    ops = {item["kind"]: item for item in fixture["policy"]["operations"]}
    zero = "0" * 64
    values = [("snapshot", zero, 1000, 2, 30, "ready", 100), ("grant", ops["grant"]["authorization_digest"], 1050, 2, 30, "ready", 101), ("purchase", ops["purchase"]["authorization_digest"], 950, 3, 30, "ready", 102), ("spend", ops["spend"]["authorization_digest"], 925, 3, 30, "ready", 103), ("fire", ops["fire"]["authorization_digest"], 925, 3, 29, "ready", 104), ("ability", ops["ability"]["authorization_digest"], 925, 3, 24, "cooldown", 114), ("recover", ops["recover"]["authorization_digest"], 925, 3, 24, "ready", 124), ("idempotent_retry", ops["idempotent_retry"]["authorization_digest"], 925, 3, 24, "ready", 125)]
    events = [_event(fixture, session, i, tick, kind, auth, currency, items, ammo, ability, extension) for i, (kind, auth, currency, items, ammo, ability, tick) in enumerate(values)]
    events[-1]["idempotency_of_digest"] = events[-2]["event_id_digest"]
    if mutation == "currency": events[2]["currency"] += 1
    elif mutation == "inventory": events[2]["items"] += 1
    elif mutation == "cadence": events[5]["server_tick"] = 105
    elif mutation == "ammo": events[4]["ammo"] += 1
    elif mutation == "ability": events[5]["ability_state"] = "active"
    elif mutation == "gap": events[-1]["sequence"] += 1
    elif mutation == "conflict": events[-1]["conflict_code"] = "ledger_snapshot_conflict"
    return events


def validate_fixture(fixture: dict[str, Any]) -> None:
    errors = privacy_errors(fixture, "fixture")
    if errors: raise EconomyActionReplayError(errors[0])
    if set(fixture) != FIXTURE_KEYS or fixture["schema"] != "tamandua.anti_cheat.server_economy_action_fixture/v1": raise EconomyActionReplayError("fixture members invalid")
    if fixture["evidence_class"] != "synthetic_contract" or fixture["claim_boundary"] != {"production_fpr_claimable": False, "live_server_validated": False, "enforcement_authorized": False, "external_claim_allowed": False}: raise EconomyActionReplayError("claim boundary invalid")
    if not all(type(fixture[key]) is str and DIGEST_RE.fullmatch(fixture[key]) for key in ("tenant_scope_digest", "build_digest")): raise EconomyActionReplayError("fixture scope invalid")
    validate_policy(fixture["policy"], fixture["policy_digest"])
    clean = fixture["clean_strata"]
    if type(clean) is not list or [(item.get("name"), item.get("count")) for item in clean] != [("vanilla", 598), ("approved_mod", 598), ("approved_accessibility", 598)] or any(type(item) is not dict or set(item) != {"name", "count", "extension"} for item in clean): raise EconomyActionReplayError("clean strata invalid")
    injected = fixture["injected"]
    expected = [("currency_violation",40,"currency"),("inventory_violation",40,"inventory"),("cadence_violation",40,"cadence"),("ammo_violation",40,"ammo"),("ability_violation",40,"ability"),("gap_inconclusive",30,"gap"),("conflict_inconclusive",30,"conflict")]
    if type(injected) is not list or [(x.get("name"),x.get("count"),x.get("mutation")) for x in injected] != expected or any(type(x) is not dict or set(x) != {"name","count","mutation"} for x in injected): raise EconomyActionReplayError("injected matrix invalid")


def cp_zero_failure_upper_ppm(samples: int) -> int:
    for ppm in range(1, 1_000_001):
        if 20 * (1_000_000 - ppm) ** samples <= 1_000_000 ** samples:
            return ppm
    raise AssertionError("unreachable")


def validate_report_semantics(report: dict[str, Any]) -> None:
    counts = report.get("counts")
    if type(counts) is not dict or counts.get("total") != sum(counts.get(key, -1) for key in ("within_constraints", "economy_violation", "action_violation", "inconclusive_gap", "inconclusive_conflict")):
        raise EconomyActionReplayError("report count conservation invalid")
    strata = report.get("clean_strata")
    expected_names = ["vanilla", "approved_mod", "approved_accessibility"]
    if type(strata) is not list or [item.get("name") for item in strata if type(item) is dict] != expected_names:
        raise EconomyActionReplayError("report clean strata identity invalid")
    for item in strata:
        if item.get("samples") != 598 or item.get("false_positives") != 0 or item.get("cp_one_sided_95_upper_ppm") != cp_zero_failure_upper_ppm(item["samples"]):
            raise EconomyActionReplayError("report CP evidence invalid")


def _build_report(path: Path) -> dict[str, Any]:
    fixture, fixture_raw = load_json(path); replay_schema, replay_raw = load_json(REPLAY_SCHEMA_PATH); report_schema, report_raw = load_json(REPORT_SCHEMA_PATH)
    Draft202012Validator.check_schema(replay_schema); Draft202012Validator.check_schema(report_schema); validate_fixture(fixture)
    validator = Draft202012Validator(replay_schema); replays: list[dict[str, Any]] = []; strata: list[dict[str, Any]] = []
    for item in fixture["clean_strata"]:
        false_positives = 0
        for index in range(item["count"]):
            replay = evaluate_replay(build_events(fixture, item["name"], index, None, item["extension"]), fixture["policy"], fixture["policy_digest"])
            if replay["classification"] != "within_constraints": false_positives += 1
            replays.append(replay)
        strata.append({"name": item["name"], "samples": item["count"], "false_positives": false_positives, "cp_one_sided_95_upper_ppm": cp_zero_failure_upper_ppm(item["count"])})
    for item in fixture["injected"]:
        for index in range(item["count"]): replays.append(evaluate_replay(build_events(fixture,item["name"],index,item["mutation"],None),fixture["policy"],fixture["policy_digest"]))
    if any(list(validator.iter_errors(item)) for item in replays): raise EconomyActionReplayError("replay schema validation failed")
    counts = Counter(item["classification"] for item in replays); counts = {key: counts[key] for key in ("within_constraints","economy_violation","action_violation","inconclusive_gap","inconclusive_conflict")}; counts = {"total": len(replays), **counts}
    basis = {"fixture_sha256": sha256(fixture_raw), "replay_schema_sha256": sha256(replay_raw), "report_schema_sha256": sha256(report_raw), "policy_digest": fixture["policy_digest"], "replay_digest": sha256(canonical(replays)), "counts": counts, "clean_strata": strata, "cp_upper_bound_contract": {"method":"clopper_pearson_zero_failures_one_sided","confidence_numerator":95,"confidence_denominator":100,"integer_exact":True}, "claims": fixture["claim_boundary"]}
    report = {"schema":"tamandua.anti_cheat.server_economy_action_report/v1","report_id":sha256(REPORT_DOMAIN+canonical(basis)),**basis}
    if list(Draft202012Validator(report_schema).iter_errors(report)): raise EconomyActionReplayError("report schema validation failed")
    validate_report_semantics(report)
    return report


@lru_cache(maxsize=8)
def _cached_report(path: str, fixture_sha: str, replay_schema_sha: str, report_schema_sha: str) -> bytes:
    del fixture_sha, replay_schema_sha, report_schema_sha
    return canonical(_build_report(Path(path)))


def validate_gate(path: Path = FIXTURE_PATH) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    encoded = _cached_report(
        str(resolved), sha256(resolved.read_bytes()), sha256(REPLAY_SCHEMA_PATH.read_bytes()),
        sha256(REPORT_SCHEMA_PATH.read_bytes()),
    )
    return json.loads(encoded)


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--fixture",type=Path,default=FIXTURE_PATH); parser.add_argument("--report",type=Path); parser.add_argument("--replay",type=Path); args=parser.parse_args()
    try:
        if args.report and args.replay: raise EconomyActionReplayError("choose one input document")
        if args.report:
            value, _ = load_json(args.report); schema, _ = load_json(REPORT_SCHEMA_PATH)
            if list(Draft202012Validator(schema).iter_errors(value)): raise EconomyActionReplayError("report schema validation failed")
            validate_report_semantics(value); print(canonical({"ok":True,"kind":"report"}).decode()); return 0
        if args.replay:
            value, _ = load_json(args.replay); schema, _ = load_json(REPLAY_SCHEMA_PATH)
            if list(Draft202012Validator(schema).iter_errors(value)): raise EconomyActionReplayError("replay schema validation failed")
            validate_replay_semantics(value); print(canonical({"ok":True,"kind":"replay"}).decode()); return 0
        print(canonical(validate_gate(args.fixture)).decode()); return 0
    except EconomyActionReplayError as error: print(canonical({"ok":False,"error":str(error)}).decode()); return 1


if __name__ == "__main__": raise SystemExit(main())
