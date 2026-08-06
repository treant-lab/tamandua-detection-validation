from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(os.environ.get("TAMANDUA_ROOT", Path(__file__).resolve().parents[3]))
SCRIPTS = ROOT / "tools" / "detection_validation" / "scripts"
FIXTURES = ROOT / "tools" / "detection_validation" / "fixtures"
sys.path.insert(0, str(SCRIPTS))

from ai_runtime_integrity_v2 import (  # noqa: E402
    CanonicalizationError,
    assemblies_hash,
    canonical_encode,
    event_digest,
    manifest_hash,
    manifest_value,
    normalized_hash,
    raw_evidence_hash,
    snapshot_digest,
    units_hash,
    validation_errors_v2,
)
from validate_ai_agent_runtime_contract import load_json, validation_errors  # noqa: E402


PROVIDERS = ("codex", "claude", "opencode")
EVENTS = [FIXTURES / f"ai_agent_runtime_{provider}_event_v2.json" for provider in PROVIDERS]
SNAPSHOTS = [FIXTURES / f"ai_agent_runtime_{provider}_snapshot_v2.json" for provider in PROVIDERS]
VECTORS = FIXTURES / "ai_agent_runtime_integrity_v2_vectors.json"


def test_v2_schemas_are_valid_and_exactly_versioned() -> None:
    for kind in ("event", "snapshot"):
        schema = json.loads((ROOT / "schemas" / f"ai_agent_runtime_{kind}_v2.schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["properties"]["api_version"]["const"] == f"tamandua.io/ai-agent-runtime-{kind}/v2"


def test_primitive_golden_vectors_match_tmnd_tree_v1() -> None:
    vectors = load_json(VECTORS)
    for vector in vectors["primitive_vectors"]:
        assert canonical_encode(vector["value"]).hex() == vector["canonical_hex"]


def test_canonicalization_rejects_floats_i64_overflow_invalid_unicode_and_duplicate_keys(tmp_path: Path) -> None:
    for value in (0.0, 1 << 63, -(1 << 63) - 1, "\ud800"):
        with pytest.raises(CanonicalizationError):
            canonical_encode(value)
    duplicate = tmp_path / "duplicate-v2.json"
    duplicate.write_text('{"api_version":"tamandua.io/ai-agent-runtime-event/v2","kind":"AiAgentRuntimeEvent","kind":"AiAgentRuntimeEvent"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate object key"):
        load_json(duplicate)


def test_all_provider_fixtures_pass_schema_and_domain_integrity() -> None:
    for path in EVENTS + SNAPSHOTS:
        payload = load_json(path)
        assert validation_errors(payload) == []
        assert payload["source"]["collector_version"] == 2
        assert payload["claims"] == {
            "maturity": "experimental",
            "evidence_class": "contract_smoke",
            "product_ready": False,
            "release_ready": False,
            "production_ready": False,
            "external_claims_allowed": False,
        }


def test_event_hashes_bind_raw_normalized_and_every_semantic_plane() -> None:
    event = load_json(EVENTS[0])
    assert raw_evidence_hash(event) == event["integrity"]["raw_evidence_sha256"]
    assert normalized_hash(event) == event["integrity"]["normalized_sha256"]
    assert event_digest(event) == event["integrity"]["event_digest"]
    original = event_digest(event)
    mutations = {
        "api_version": "tamandua.io/ai-agent-runtime-event/v9",
        "kind": "WrongKind",
        "event_id": "different-event",
        "observed_at": "2026-07-22T15:00:00Z",
        "tenant": {**event["tenant"], "tenant_id": "other-tenant"},
        "endpoint": {**event["endpoint"], "hostname": "other-host"},
        "source": {**event["source"], "collector_version": 99},
        "session": {**event["session"], "session_id": "other-session"},
        "event_type": "summary",
        "capture": {**event["capture"], "parser": "other-parser"},
        "raw_evidence": {**event["raw_evidence"], "source_locator": "/other"},
        "normalized": {**event["normalized"], "action": "other"},
        "runtime_context": {"pid": 9999},
        "governance": {**event["governance"], "retention_days": 7},
        "claims": {**event["claims"], "evidence_class": "other"},
    }
    for key, value in mutations.items():
        changed = copy.deepcopy(event)
        changed[key] = value
        assert event_digest(changed) != original, key
    for field, value in (("stream_id", "other-stream"), ("sequence", 2), ("previous_event_digest", "f" * 64)):
        changed = copy.deepcopy(event)
        changed["integrity"][field] = value
        assert event_digest(changed) != original, field
    changed = copy.deepcopy(event)
    changed["integrity"]["chunk"]["full_content_byte_length"] += 1
    assert event_digest(changed) != original


def test_multi_chunk_golden_manifest_is_ordered_complete_and_domain_separated() -> None:
    vector = load_json(VECTORS)["multi_chunk_manifest"]
    assert units_hash(vector["units"]) == vector["manifest"]["units_sha256"]
    assert assemblies_hash(vector["assemblies"]) == vector["manifest"]["assemblies_sha256"]
    assert manifest_value(vector["units"], vector["assemblies"]) == vector["manifest"]
    assert manifest_hash(vector["manifest"]) == vector["manifest_sha256"]
    assert units_hash(vector["units"]) != assemblies_hash(vector["assemblies"])


def test_snapshot_manifest_rejects_gap_reorder_duplicate_hash_and_length_tampering() -> None:
    base = load_json(SNAPSHOTS[0])
    vector = load_json(VECTORS)["multi_chunk_manifest"]
    snapshot = copy.deepcopy(base)
    integrity = snapshot["integrity"]
    integrity.update({
        "first_sequence": 1,
        "last_sequence": 2,
        "event_count": 2,
        "last_event_digest": vector["units"][-1]["event_digest"],
        "units": vector["units"],
        "assemblies": vector["assemblies"],
        "manifest": vector["manifest"],
        "manifest_sha256": vector["manifest_sha256"],
    })
    integrity["snapshot_digest"] = snapshot_digest(snapshot)
    assert validation_errors_v2(snapshot) == []

    mutations = []
    reordered = copy.deepcopy(snapshot); reordered["integrity"]["units"].reverse(); mutations.append(reordered)
    missing = copy.deepcopy(snapshot); missing["integrity"]["assemblies"][0]["sequences"] = [1]; mutations.append(missing)
    duplicate = copy.deepcopy(snapshot); duplicate["integrity"]["assemblies"][0]["sequences"] = [1, 1]; mutations.append(duplicate)
    bad_hash = copy.deepcopy(snapshot); bad_hash["integrity"]["assemblies"][0]["chunk_content_sha256s"][0] = "f" * 64; mutations.append(bad_hash)
    bad_length = copy.deepcopy(snapshot); bad_length["integrity"]["assemblies"][0]["full_content_byte_length"] += 1; mutations.append(bad_length)
    for changed in mutations:
        assert validation_errors_v2(changed), "tampered manifest must fail closed"


def test_provider_golden_full_vectors_are_stable() -> None:
    vectors = load_json(VECTORS)
    for vector in vectors["provider_vectors"]:
        event = load_json(FIXTURES / vector["event_file"])
        snapshot = load_json(FIXTURES / vector["snapshot_file"])
        assert hashlib.sha256(canonical_encode(event)).hexdigest() == vector["canonical_event_sha256"]
        assert event_digest(event) == vector["event_digest"]
        assert snapshot_digest(snapshot) == vector["snapshot_digest"]


def test_v1_v2_dispatch_is_explicit_and_unknown_or_mismatched_tuples_fail_closed() -> None:
    v2 = load_json(EVENTS[0])
    wrong_kind = copy.deepcopy(v2); wrong_kind["kind"] = "AiAgentRuntimeSnapshot"
    wrong_version = copy.deepcopy(v2); wrong_version["api_version"] = "tamandua.io/ai-agent-runtime-event/v3"
    collector_mismatch = copy.deepcopy(v2); collector_mismatch["source"]["collector_version"] = 1
    integrity_mismatch = copy.deepcopy(v2); integrity_mismatch["integrity"]["version"] = 1
    for payload in (wrong_kind, wrong_version, collector_mismatch, integrity_mismatch):
        assert validation_errors(payload)


def test_cli_accepts_v2_fixtures_as_experimental_contract_smoke() -> None:
    script = SCRIPTS / "validate_ai_agent_runtime_contract.py"
    result = subprocess.run([sys.executable, str(script), *(str(path) for path in EVENTS + SNAPSHOTS)], cwd=ROOT, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("experimental contract evidence; production/external claims false") == 6
