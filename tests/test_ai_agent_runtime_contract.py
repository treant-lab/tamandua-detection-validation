from __future__ import annotations

import copy
import json
import math
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest


LOCAL_ROOT = Path(__file__).resolve().parents[1]
if (LOCAL_ROOT / "scripts").exists() and (LOCAL_ROOT / "fixtures").exists() and (LOCAL_ROOT / "schemas").exists():
    ROOT = LOCAL_ROOT
    SCRIPTS = ROOT / "scripts"
    FIXTURES = ROOT / "fixtures"
else:
    ROOT = Path(os.environ.get("TAMANDUA_ROOT", Path(__file__).resolve().parents[3]))
    SCRIPTS = ROOT / "tools" / "detection_validation" / "scripts"
    FIXTURES = ROOT / "tools" / "detection_validation" / "fixtures"

SNAPSHOT_SCHEMA = ROOT / "schemas" / "ai_agent_runtime_snapshot_v1.schema.json"
EVENT_SCHEMA = ROOT / "schemas" / "ai_agent_runtime_event_v1.schema.json"
SNAPSHOTS = [FIXTURES / f"ai_agent_runtime_{provider}_snapshot_v1.json" for provider in ("codex", "claude", "opencode")]
EVENTS = [FIXTURES / f"ai_agent_runtime_{provider}_event_v1.json" for provider in ("codex", "claude", "opencode")]

sys.path.insert(0, str(SCRIPTS))

from validate_ai_agent_runtime_contract import (  # noqa: E402
    CONTENT_EVENT_TYPES,
    DEFAULT_FIXTURES,
    MAX_DOCUMENT_BYTES,
    event_digest,
    load_json,
    snapshot_digest,
    stream_errors,
    validation_errors,
)


@pytest.mark.parametrize("schema_path", [SNAPSHOT_SCHEMA, EVENT_SCHEMA])
def test_schema_is_valid_draft_2020_12(schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    jsonschema.Draft202012Validator.check_schema(schema)


def test_codex_claude_opencode_fixtures_pass_with_full_enterprise_governance() -> None:
    payloads = [load_json(path) for path in DEFAULT_FIXTURES]
    assert all(validation_errors(payload) == [] for payload in payloads)
    assert {payload["session"]["provider"] for payload in payloads} == {"codex", "claude", "opencode"}
    for payload in payloads:
        assert payload["tenant"]["tenant_id"] != payload["tenant"]["organization_id"]
        assert payload["governance"]["classification"] == "restricted_ai_agent_content"
        assert payload["governance"]["audit_required"] is True
        assert payload["governance"]["encryption"] == {
            "at_rest": "aes-256-gcm",
            "in_transit": "tls-1.3",
            "key_id": payload["governance"]["encryption"]["key_id"],
        }
        assert payload["claims"]["maturity"] == "experimental"
        assert not any(payload["claims"][field] for field in ("product_ready", "release_ready", "production_ready", "external_claims_allowed"))


def test_content_events_preserve_raw_and_normalized_evidence() -> None:
    for path in EVENTS:
        payload = load_json(path)
        assert payload["event_type"] in CONTENT_EVENT_TYPES
        assert payload["raw_evidence"]["content"]
        assert payload["raw_evidence"]["is_redacted"] is False
        assert payload["raw_evidence"]["is_truncated"] is False
        assert payload["normalized"]["attributes"]["content_preserved"] is True


def test_contract_covers_every_requested_content_and_runtime_channel() -> None:
    event_schema = json.loads(EVENT_SCHEMA.read_text(encoding="utf-8"))
    event_types = set(event_schema["properties"]["event_type"]["enum"])
    assert {"message", "summary", "command", "tool_input", "tool_result", "file_evidence"} <= event_types
    assert {"process", "port", "mcp", "tokens", "context", "rate_limit", "capture_degradation"} <= event_types
    snapshot = load_json(SNAPSHOTS[0])
    assert set(snapshot["session"]["content_state"]) == {"messages", "summaries", "commands", "tool_inputs", "tool_results", "file_evidence"}
    assert {channel["name"] for channel in snapshot["capture"]["channels"]} == {
        "session_metadata", "messages", "summaries", "commands", "tool_inputs", "tool_results",
        "file_evidence", "processes", "ports", "mcp", "tokens", "context", "rate_limits",
    }


def test_upstream_provenance_is_exact_and_not_claimed_as_product_evidence() -> None:
    for path in DEFAULT_FIXTURES:
        source = load_json(path)["source"]
        assert source == {
            "collector_id": "tamandua.ai_agent_runtime",
            "collector_version": 1,
            "upstream_project": "graykode/abtop",
            "upstream_commit": "a3328db20fe189887986e0147080954bc07178a1",
            "upstream_license": "MIT",
            "upstream_copyright": "Copyright (c) 2026 Tae Hwan Jung",
        }


def test_abtop_notice_and_mit_license_are_pinned() -> None:
    notice = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    license_text = (ROOT / "licenses" / "abtop-MIT.txt").read_text(encoding="utf-8")
    for text in (notice, license_text):
        assert "Copyright (c) 2026 Tae Hwan Jung" in text
    assert "a3328db20fe189887986e0147080954bc07178a1" in notice
    assert "MIT License" in license_text
    assert "THE SOFTWARE IS PROVIDED \"AS IS\"" in license_text


def test_content_tampering_breaks_content_chunk_and_event_digests() -> None:
    payload = load_json(EVENTS[0])
    payload["raw_evidence"]["content"] += " tampered"
    errors = validation_errors(payload)
    assert any("byte_length" in error for error in errors)
    assert any("content_sha256" in error for error in errors)
    assert any("chunk_sha256" in error for error in errors)


def test_silent_redaction_or_truncation_is_rejected_for_complete_capture() -> None:
    for field in ("is_redacted", "is_truncated"):
        payload = load_json(EVENTS[0])
        payload["raw_evidence"][field] = True
        assert any("redacted or truncated" in error or "False was expected" in error for error in validation_errors(payload))


def test_explicit_partial_capture_requires_reason_and_remains_valid_when_honest() -> None:
    payload = load_json(EVENTS[0])
    payload["capture"].update({"status": "partial", "reason_codes": ["source_rotated_during_read"]})
    payload["raw_evidence"]["is_truncated"] = True
    assert validation_errors(payload) == []
    payload["capture"]["reason_codes"] = []
    assert any("requires reason_codes" in error for error in validation_errors(payload))


def test_snapshot_cannot_hide_duplicate_or_missing_capture_channel() -> None:
    payload = load_json(SNAPSHOTS[0])
    payload["capture"]["channels"][-1] = copy.deepcopy(payload["capture"]["channels"][0])
    assert any("each of the 13 channels exactly once" in error for error in validation_errors(payload))


def test_overall_complete_cannot_mask_degraded_channel() -> None:
    payload = load_json(SNAPSHOTS[0])
    payload["capture"]["channels"][1].update({"status": "partial", "reason_codes": ["parse_failure"]})
    assert any("overall_status complete" in error for error in validation_errors(payload))


def test_complete_content_channel_requires_raw_and_normalized_count_parity() -> None:
    payload = load_json(SNAPSHOTS[0])
    payload["session"]["content_state"]["messages"]["raw_available_count"] = 0
    assert any("raw and normalized parity" in error for error in validation_errors(payload))


def test_context_arithmetic_and_snapshot_digest_are_fail_closed() -> None:
    payload = load_json(SNAPSHOTS[0])
    payload["session"]["usage"]["context_remaining_tokens"] -= 1
    payload["integrity"]["snapshot_digest"] = "0" * 64
    errors = validation_errors(payload)
    assert any("must equal context_window_tokens" in error for error in errors)
    assert any("snapshot_digest" in error for error in errors)


def test_snapshot_digest_helper_matches_fixture() -> None:
    for path in SNAPSHOTS:
        payload = load_json(path)
        assert snapshot_digest(payload) == payload["integrity"]["snapshot_digest"]


def test_chunk_index_and_single_chunk_assembly_digest_are_checked() -> None:
    payload = load_json(EVENTS[1])
    payload["integrity"]["chunk"].update({"index": 1, "full_content_sha256": "f" * 64})
    errors = validation_errors(payload)
    assert any("chunk.index" in error for error in errors)
    assert any("single chunk" in error for error in errors)


def test_event_digest_chain_rejects_duplicate_gap_and_wrong_predecessor() -> None:
    first = load_json(EVENTS[0])
    second = copy.deepcopy(first)
    second["event_id"] = "event-codex-002"
    second["integrity"].update({"sequence": 2, "previous_event_digest": first["integrity"]["event_digest"]})
    second["integrity"]["event_digest"] = event_digest(second)
    assert validation_errors(second) == []
    assert stream_errors([first, second]) == []

    duplicate = copy.deepcopy(second)
    duplicate["integrity"]["sequence"] = 1
    gap = copy.deepcopy(second)
    gap["integrity"]["sequence"] = 3
    wrong = copy.deepcopy(second)
    wrong["integrity"]["previous_event_digest"] = "f" * 64
    assert any("duplicate sequence" in error for error in stream_errors([first, duplicate]))
    assert any("sequence gap" in error for error in stream_errors([first, gap]))
    assert any("digest chain mismatch" in error for error in stream_errors([first, wrong]))


def test_claim_escalation_and_tenant_org_alias_are_rejected() -> None:
    payload = load_json(EVENTS[2])
    payload["claims"]["production_ready"] = True
    payload["tenant"]["organization_id"] = payload["tenant"]["tenant_id"]
    errors = validation_errors(payload)
    assert any("production_ready" in error for error in errors)
    assert any("independently bound" in error for error in errors)


def test_non_finite_and_oversized_documents_are_rejected(tmp_path: Path) -> None:
    nan_path = tmp_path / "nan.json"
    nan_path.write_text('{"value": Infinity}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite"):
        load_json(nan_path)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * MAX_DOCUMENT_BYTES + b"}")
    with pytest.raises(ValueError, match="transport it as chunks"):
        load_json(oversized)
    payload = load_json(EVENTS[0])
    payload["normalized"]["attributes"]["bad"] = math.nan
    assert any("finite" in error for error in validation_errors(payload))


def test_cli_accepts_all_fixtures_and_rejects_tampered_fixture(tmp_path: Path) -> None:
    script = SCRIPTS / "validate_ai_agent_runtime_contract.py"
    valid = subprocess.run([sys.executable, str(script)], cwd=ROOT, check=False, capture_output=True, text=True)
    assert valid.returncode == 0, valid.stdout + valid.stderr
    assert valid.stdout.count("production/external claims false") == 6

    tampered_payload = load_json(EVENTS[0])
    tampered_payload["source"]["upstream_commit"] = "f" * 40
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(tampered_payload), encoding="utf-8")
    invalid = subprocess.run([sys.executable, str(script), str(tampered)], cwd=ROOT, check=False, capture_output=True, text=True)
    assert invalid.returncode == 1
    assert "INVALID" in invalid.stdout

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"api_version":"tamandua.io/ai-agent-runtime-event/v1"}', encoding="utf-8")
    rejected = subprocess.run([sys.executable, str(script), str(malformed)], cwd=ROOT, check=False, capture_output=True, text=True)
    assert rejected.returncode == 1
    assert "INVALID" in rejected.stdout
    assert "Traceback" not in rejected.stderr
