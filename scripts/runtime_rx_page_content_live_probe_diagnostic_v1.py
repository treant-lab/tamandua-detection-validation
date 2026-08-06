#!/usr/bin/env python3
"""Validate the closed, privacy-safe runtime RX live-probe diagnostic v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCHEMA = ROOT / "schemas/runtime_rx_page_content_live_probe_diagnostic_v1.schema.json"
DEFAULT_FIXTURE = ROOT / "tools/detection_validation/fixtures/runtime_rx_page_content_live_probe_diagnostic_v1.json"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EXPECTED_MANIFEST_SHA256 = "70f0b15c6387946134946c86be6ddc557a148ba5cf2b98d952eba1469ebca5df"

FIXTURE_KEYS = {
    "schema", "evidence_class", "execution_scope", "execute",
    "external_claim_allowed", "fpr_claim_allowed", "performance_claim_allowed",
    "production_ready_claimed", "vendor_parity_claimed", "claim_boundary", "scenarios",
}
CLAIM_FIELDS = (
    "external_claim_allowed", "fpr_claim_allowed", "performance_claim_allowed",
    "production_ready_claimed", "vendor_parity_claimed",
)
FORBIDDEN_KEYS = {
    "path", "paths", "pid", "pids", "address", "addresses", "argv", "args",
    "message", "messages", "detail", "details", "reason", "reasons", "command",
    "stdout", "stderr", "raw", "content", "contents", "log", "logs", "line", "lines",
}
ALLOWED_PAYLOAD_KEYS = FIXTURE_KEYS | {
    "id", "diagnostic", "diagnostic_provenance", "run_id", "observed_at_utc",
    "prior_failure_manifest_sha256", "checkpoint", "code", "process", "output", "trace",
    "custody", "cleanup", "started", "exit_observed", "exit_code", "timed_out", "state",
    "bytes", "sha256", "network_syscall_count", "filesystem_mutation_syscall_count",
    "strace_sha256", "time_sha256", "artifact_unchanged", "config_unchanged", "attempted",
    "completed", "temporary_artifacts_remaining", "raw_logs_retained", "stage",
    "cleanup_status", "log_sha256", "cargo_metadata_stderr", "cargo_build_stderr",
}
LEAK_PATTERNS = (
    re.compile(r"(?:^|\s)[A-Za-z]:\\"),
    re.compile(r"(?:^|\s)/(?:tmp|var|opt|etc|home|proc|root|mnt)(?:/|\b)", re.I),
    re.compile(r"\b(?:pid|ppid|tgid|address|addr|argv)\s*[:=]\s*\S+", re.I),
    re.compile(r"\b0x[0-9a-f]{6,}\b", re.I),
    re.compile(r"\b[a-z][a-z0-9+.-]*://", re.I),
    re.compile(r"\\\\[^\\\s]+\\"),
    re.compile(r"(?<![0-9])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![0-9])"),
    re.compile(r"(?:^|[^0-9A-Fa-f])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:$|[^0-9A-Fa-f])"),
    re.compile(r"%[0-9a-f]{2}", re.I),
    re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b"),
)
PAIR_CODES = {
    "probe_execute": {
        "probe_timeout", "process_exit_nonzero", "output_absent", "output_empty",
        "output_invalid", "output_oversize",
    },
    "runner_trace_policy": {
        "trace_network_syscall_observed", "trace_filesystem_mutation_observed", "trace_incomplete",
    },
    "custody_validate": {"artifact_changed", "config_changed"},
    "cleanup": {"cleanup_incomplete"},
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def utc_timestamp_error(value: Any) -> str | None:
    if not isinstance(value, str):
        return "must be a string"
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        return "must use canonical UTC RFC3339 form"
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return "must be a real Gregorian UTC timestamp"
    return None


def _privacy_errors(value: Any, location: str = "diagnostic") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_location = f"{location}.{key}"
            if key not in ALLOWED_PAYLOAD_KEYS:
                errors.append("privacy: unexpected field name")
            if key.lower() in FORBIDDEN_KEYS:
                errors.append("privacy: forbidden field class")
            if any(pattern.search(key) for pattern in LEAK_PATTERNS):
                errors.append("privacy: forbidden encoded or raw field name")
            errors.extend(_privacy_errors(child, child_location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_privacy_errors(child, f"{location}[{index}]"))
    elif isinstance(value, str):
        leaf = location.rsplit(".", 1)[-1]
        structural_hex = (
            leaf == "sha256" or leaf.endswith("_sha256")
            or leaf in {"cargo_metadata_stderr", "cargo_build_stderr"}
        ) and bool(
            re.fullmatch(r"[0-9a-f]{64}", value)
        )
        structural_run_id = leaf == "run_id" and bool(re.fullmatch(
            r"(?:synthetic-(?:internal-probe-timeout|runner-trace-policy)|"
            r"[0-9]{8}T[0-9]{6}Z-runtime-rx-live-[0-9a-f]{24})", value
        ))
        structural_timestamp = leaf == "observed_at_utc"
        if not (structural_hex or structural_run_id or structural_timestamp):
            if any(pattern.search(value) for pattern in LEAK_PATTERNS):
                errors.append("privacy: forbidden encoded or raw identifier value")
    return errors


def _schema_errors(diagnostic: Any, schema: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = []
    for issue in sorted(validator.iter_errors(diagnostic), key=lambda item: list(item.absolute_schema_path)):
        schema_location = "/".join(str(part) for part in issue.absolute_schema_path) or "$"
        errors.append(f"schema:{schema_location} validator={issue.validator}")
    return errors


def validate_diagnostic(diagnostic: Any, schema: dict[str, Any], require_executed: bool) -> list[str]:
    errors = _schema_errors(diagnostic, schema)
    if not isinstance(diagnostic, dict):
        return errors
    errors.extend(_privacy_errors(diagnostic))
    if errors:
        return errors

    execute = diagnostic["execute"]
    provenance = diagnostic["diagnostic_provenance"]
    if execute != (provenance == "live_probe_runner"):
        errors.append("execute must be true iff diagnostic_provenance is live_probe_runner")
    if require_executed and not execute:
        errors.append("an executed live_probe_runner diagnostic is required")
    if diagnostic["prior_failure_manifest_sha256"] != EXPECTED_MANIFEST_SHA256:
        errors.append("prior failure manifest binding is not exact")
    timestamp_error = utc_timestamp_error(diagnostic["observed_at_utc"])
    if timestamp_error:
        errors.append(f"observed_at_utc: {timestamp_error}")
    for claim in CLAIM_FIELDS:
        if diagnostic[claim] is not False:
            errors.append(f"{claim} must remain false")

    checkpoint = diagnostic["checkpoint"]
    code = diagnostic["code"]
    if code not in PAIR_CODES[checkpoint]:
        errors.append(f"checkpoint/code pair is not allowed: {checkpoint}/{code}")

    process = diagnostic["process"]
    if process["timed_out"]:
        if code != "probe_timeout" or process["exit_observed"] or process["exit_code"] is not None:
            errors.append("probe_timeout requires timed_out=true with no observed exit or exit code")
    else:
        if not process["exit_observed"] or not isinstance(process["exit_code"], int):
            errors.append("non-timeout diagnostics require an observed integer process exit code")
    if code == "process_exit_nonzero" and (not isinstance(process["exit_code"], int) or process["exit_code"] == 0):
        errors.append("process_exit_nonzero requires a nonzero exit code")

    output = diagnostic["output"]
    if output["state"] in {"absent", "empty"}:
        if output["bytes"] != 0 or output["sha256"] != EMPTY_SHA256:
            errors.append("absent or empty output must bind zero bytes and the empty SHA-256")
    elif output["bytes"] == 0:
        errors.append("nonempty output state requires a positive byte count")
    expected_output_code = {
        "output_absent": "absent", "output_empty": "empty",
        "output_invalid": "complete_invalid", "output_oversize": "complete_invalid",
    }.get(code)
    if expected_output_code and output["state"] != expected_output_code:
        errors.append(f"{code} is inconsistent with output state")
    if code == "output_oversize" and output["bytes"] <= 2_097_152:
        errors.append("output_oversize requires a byte count above the accepted output cap")

    trace = diagnostic["trace"]
    trace_digests = (trace["strace_sha256"], trace["time_sha256"])
    counts = (trace["network_syscall_count"], trace["filesystem_mutation_syscall_count"])
    if trace["state"] == "unavailable":
        if counts != (0, 0) or any(digest not in {None, EMPTY_SHA256} for digest in trace_digests):
            errors.append("unavailable trace requires zero aggregate counts and empty or null digests")
    elif any(digest in {None, EMPTY_SHA256} for digest in trace_digests):
        errors.append("partial or complete trace requires nonempty strace and time digests")
    expected_trace_code = None
    if trace["network_syscall_count"] > 0:
        expected_trace_code = "trace_network_syscall_observed"
    elif trace["filesystem_mutation_syscall_count"] > 0:
        expected_trace_code = "trace_filesystem_mutation_observed"
    if expected_trace_code and (
        trace["state"] == "unavailable"
        or checkpoint != "runner_trace_policy"
        or code != expected_trace_code
    ):
        errors.append(
            "positive trace count requires observed trace and deterministic network-before-filesystem policy code"
        )
    if code == "trace_network_syscall_observed" and trace["network_syscall_count"] < 1:
        errors.append("trace_network_syscall_observed requires a positive aggregate count")
    if code == "trace_filesystem_mutation_observed" and trace["filesystem_mutation_syscall_count"] < 1:
        errors.append("trace_filesystem_mutation_observed requires a positive aggregate count")
    if code == "trace_incomplete" and trace["state"] == "complete":
        errors.append("trace_incomplete requires partial or unavailable trace state")

    custody = diagnostic["custody"]
    if code == "artifact_changed" and custody["artifact_unchanged"]:
        errors.append("artifact_changed requires artifact_unchanged=false")
    if code == "config_changed" and custody["config_unchanged"]:
        errors.append("config_changed requires config_unchanged=false")

    cleanup = diagnostic["cleanup"]
    cleanup_is_complete = cleanup["completed"] and cleanup["temporary_artifacts_remaining"] == 0
    if code == "cleanup_incomplete" and cleanup_is_complete:
        errors.append("cleanup_incomplete requires incomplete cleanup or remaining temporary artifacts")
    if code != "cleanup_incomplete" and not cleanup_is_complete:
        errors.append("non-cleanup failures still require completed contained cleanup")
    return errors


def validate_fixture(path: Path, schema_path: Path) -> tuple[list[str], dict[str, Any]]:
    payload = _load(path)
    schema = _load(schema_path)
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["fixture must be an object"], {}
    errors.extend(_privacy_errors(payload, "fixture"))
    extra = set(payload) - FIXTURE_KEYS
    missing = FIXTURE_KEYS - set(payload)
    if extra:
        errors.append("fixture has unexpected fields")
    if missing:
        errors.append(f"fixture is missing fields: {sorted(missing)}")
    expected = {
        "schema": "tamandua.runtime_integrity_live_probe_diagnostic_fixture/v1",
        "evidence_class": "synthetic_smoke", "execution_scope": "local_synthetic", "execute": False,
        "claim_boundary": (
            "Synthetic contract fixtures only; no live probe, efficacy, FPR, performance, "
            "production, or vendor-parity claim."
        ),
        **{claim: False for claim in CLAIM_FIELDS},
    }
    for field, value in expected.items():
        if payload.get(field) != value:
            errors.append(f"fixture: {field} must remain exact")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 2:
        errors.append("fixture must contain exactly two representative scenarios")
        scenarios = []
    expected_ids = ["internal-probe-timeout", "runner-trace-policy-network"]
    observed_ids: list[Any] = []
    for index, item in enumerate(scenarios):
        if not isinstance(item, dict) or set(item) != {"id", "diagnostic"}:
            errors.append(f"scenarios[{index}] must contain only id and diagnostic")
            continue
        observed_ids.append(item["id"])
        errors.extend(f"scenarios[{index}].{error}" for error in validate_diagnostic(item["diagnostic"], schema, False))
        if isinstance(item["diagnostic"], dict) and item["diagnostic"].get("execute") is not False:
            errors.append(f"scenarios[{index}]: synthetic diagnostics must remain execute=false")
    if observed_ids != expected_ids:
        errors.append("fixture scenario ids and order must remain exact")
    summary = {
        "schema": payload.get("schema"), "evidence_class": payload.get("evidence_class"),
        "execution_scope": payload.get("execution_scope"), "execute": payload.get("execute"),
        "scenario_count": len(scenarios), **{claim: payload.get(claim) for claim in CLAIM_FIELDS},
    }
    return errors, summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    lane = parser.add_mutually_exclusive_group()
    lane.add_argument("--fixture", type=Path, default=None)
    lane.add_argument("--diagnostic", type=Path, default=None)
    parser.add_argument("--prior-failure-manifest", type=Path, default=None)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--require-executed", action="store_true")
    return parser


def validate_prior_failure_manifest(
    path: Path, diagnostic: dict[str, Any]
) -> list[str]:
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"prior failure manifest could not be read: {type(exc).__name__}"]
    errors: list[str] = []
    if hashlib.sha256(raw).hexdigest() != diagnostic.get("prior_failure_manifest_sha256"):
        errors.append("prior failure manifest byte digest does not match diagnostic binding")
    errors.extend(_privacy_errors(manifest, "prior_failure_manifest"))
    expected_keys = {
        "schema", "run_id", "stage", "exit_code", "cleanup_status", "log_sha256", "raw_logs_retained",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        return errors + ["prior failure manifest shape is not closed"]
    if manifest["schema"] != "tamandua.runtime_integrity_live_probe_failure/v1":
        errors.append("prior failure manifest schema is not exact")
    if manifest["run_id"] != diagnostic.get("run_id"):
        errors.append("prior failure manifest run_id does not match diagnostic")
    if manifest["stage"] != "isolated_probe":
        errors.append("prior failure manifest stage must be isolated_probe")
    if not isinstance(manifest["exit_code"], int) or isinstance(manifest["exit_code"], bool):
        errors.append("prior failure manifest exit_code must be an integer")
    if manifest["cleanup_status"] != "completed":
        errors.append("prior failure manifest cleanup must be completed")
    if manifest["raw_logs_retained"] is not False:
        errors.append("prior failure manifest raw logs must not be retained")
    logs = manifest["log_sha256"]
    if not isinstance(logs, dict) or set(logs) != {"cargo_metadata_stderr", "cargo_build_stderr"}:
        errors.append("prior failure manifest log digest shape is not closed")
    else:
        for digest in logs.values():
            if digest is not None and not (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
                errors.append("prior failure manifest log digest is invalid")
    return errors


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.diagnostic:
            diagnostic = _load(args.diagnostic)
            schema = _load(args.schema)
            errors = validate_diagnostic(diagnostic, schema, True)
            if args.prior_failure_manifest is None:
                errors.append("direct diagnostic lane requires --prior-failure-manifest")
            elif isinstance(diagnostic, dict):
                errors.extend(validate_prior_failure_manifest(args.prior_failure_manifest, diagnostic))
            summary = {
                "schema": diagnostic.get("schema") if isinstance(diagnostic, dict) else None,
                "evidence_class": diagnostic.get("evidence_class") if isinstance(diagnostic, dict) else None,
                "execution_scope": diagnostic.get("execution_scope") if isinstance(diagnostic, dict) else None,
                "execute": diagnostic.get("execute") if isinstance(diagnostic, dict) else None,
                "diagnostic_provenance": diagnostic.get("diagnostic_provenance") if isinstance(diagnostic, dict) else None,
                **{claim: diagnostic.get(claim) if isinstance(diagnostic, dict) else None for claim in CLAIM_FIELDS},
            }
        else:
            if args.require_executed:
                print("--require-executed requires an explicit --diagnostic direct lane")
                return 1
            errors, summary = validate_fixture(args.fixture or DEFAULT_FIXTURE, args.schema)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"diagnostic input could not be read: {type(exc).__name__}")
        return 1
    if errors:
        bounded = errors[:20]
        if len(errors) > 20:
            bounded.append(f"... {len(errors) - 20} additional validation errors omitted")
        print("\n".join(bounded))
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
