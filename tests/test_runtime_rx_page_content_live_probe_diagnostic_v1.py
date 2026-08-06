from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/detection_validation/scripts/runtime_rx_page_content_live_probe_diagnostic_v1.py"
FIXTURE = ROOT / "tools/detection_validation/fixtures/runtime_rx_page_content_live_probe_diagnostic_v1.json"
SCHEMA = ROOT / "schemas/runtime_rx_page_content_live_probe_diagnostic_v1.schema.json"

SPEC = importlib.util.spec_from_file_location("runtime_rx_page_content_live_probe_diagnostic_v1", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

PRIOR_FAILURE_MANIFEST = (
    b'{"cleanup_status":"completed","exit_code":1,"log_sha256":'
    b'{"cargo_build_stderr":"ee4610806950184b725d870626045798976db013ab2b9d51273673129c64a5e9",'
    b'"cargo_metadata_stderr":"8942c765d32c4b6cdd91dda06e6ed40cdbac93c730dd41ab12815821e239e7e2"},'
    b'"raw_logs_retained":false,"run_id":"20260717T103431Z-runtime-rx-live-bd8f677afb36c3e9db28bc06",'
    b'"schema":"tamandua.runtime_integrity_live_probe_failure/v1","stage":"isolated_probe"}'
)


def fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def diagnostic(payload: dict, scenario_id: str = "internal-probe-timeout") -> dict:
    return next(item["diagnostic"] for item in payload["scenarios"] if item["id"] == scenario_id)


def direct_diagnostic(scenario_id: str = "internal-probe-timeout") -> dict:
    item = copy.deepcopy(diagnostic(fixture(), scenario_id))
    item["execute"] = True
    item["diagnostic_provenance"] = "live_probe_runner"
    item["run_id"] = "20260717T103431Z-runtime-rx-live-bd8f677afb36c3e9db28bc06"
    return item


def errors(item: dict) -> list[str]:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return GATE.validate_diagnostic(item, schema, False)


def run_direct(
    tmp_path: Path, item: dict, manifest_bytes: bytes = PRIOR_FAILURE_MANIFEST
) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "diagnostic.json"
    path.write_text(json.dumps(item), encoding="utf-8")
    manifest = tmp_path / "failure-manifest.json"
    manifest.write_bytes(manifest_bytes)
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--diagnostic", str(path), "--require-executed",
         "--prior-failure-manifest", str(manifest)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def test_schema_fixture_and_default_cli_are_closed_synthetic_smoke() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout) == {
        "schema": "tamandua.runtime_integrity_live_probe_diagnostic_fixture/v1",
        "evidence_class": "synthetic_smoke", "execution_scope": "local_synthetic",
        "execute": False, "scenario_count": 2, "external_claim_allowed": False,
        "fpr_claim_allowed": False, "performance_claim_allowed": False,
        "production_ready_claimed": False, "vendor_parity_claimed": False,
    }
    payload = fixture()
    assert [item["id"] for item in payload["scenarios"]] == [
        "internal-probe-timeout", "runner-trace-policy-network",
    ]
    assert all(item["diagnostic"]["execute"] is False for item in payload["scenarios"])


def test_direct_cli_accepts_only_executed_live_runner_diagnostic(tmp_path: Path) -> None:
    completed = run_direct(tmp_path, direct_diagnostic())
    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["schema"] == "tamandua.runtime_integrity_live_probe_diagnostic/v1"
    assert summary["execute"] is True
    assert summary["execution_scope"] == "wsl2_network_isolated"
    assert summary["diagnostic_provenance"] == "live_probe_runner"
    assert all(summary[field] is False for field in GATE.CLAIM_FIELDS)

    item = direct_diagnostic()
    item["execute"] = False
    completed = run_direct(tmp_path, item)
    assert completed.returncode == 1
    assert "execute must be true iff" in completed.stdout


def test_require_executed_cannot_promote_default_fixture() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--require-executed"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert "explicit --diagnostic direct lane" in completed.stdout


@pytest.mark.parametrize(
    ("checkpoint", "code"),
    [
        ("probe_execute", "trace_incomplete"),
        ("runner_trace_policy", "probe_timeout"),
        ("custody_validate", "cleanup_incomplete"),
        ("cleanup", "artifact_changed"),
    ],
)
def test_checkpoint_code_pairs_are_closed(checkpoint: str, code: str) -> None:
    item = direct_diagnostic()
    item["checkpoint"] = checkpoint
    item["code"] = code
    assert any("checkpoint/code pair is not allowed" in error for error in errors(item))


def test_timeout_process_state_is_exact() -> None:
    for field, value in [("exit_observed", True), ("exit_code", 124), ("timed_out", False)]:
        item = direct_diagnostic()
        item["process"][field] = value
        assert errors(item)


@pytest.mark.parametrize(
    ("code", "state", "byte_count"),
    [
        ("output_absent", "absent", 0),
        ("output_empty", "empty", 0),
        ("output_invalid", "complete_invalid", 10),
        ("output_oversize", "complete_invalid", 2_097_153),
    ],
)
def test_output_failure_states_bind_only_bytes_and_digest(code: str, state: str, byte_count: int) -> None:
    item = direct_diagnostic()
    item["checkpoint"] = "probe_execute"
    item["code"] = code
    item["process"] = {"started": True, "exit_observed": True, "exit_code": 1, "timed_out": False}
    item["output"] = {"state": state, "bytes": byte_count, "sha256": "8" * 64}
    if byte_count == 0:
        item["output"]["sha256"] = GATE.EMPTY_SHA256
    assert errors(item) == []


def test_trace_policy_uses_aggregate_counts_and_raw_digests_only() -> None:
    item = direct_diagnostic("runner-trace-policy-network")
    assert errors(item) == []
    item["trace"]["network_syscall_count"] = 0
    assert any("positive aggregate count" in error for error in errors(item))
    item = direct_diagnostic("runner-trace-policy-network")
    item["trace"]["raw"] = "socket(AF_INET)"
    joined = "\n".join(errors(item))
    assert "forbidden field class" in joined
    assert "validator=additionalProperties" in joined


@pytest.mark.parametrize("field", ["path", "pid", "address", "argv", "message", "raw", "content"])
def test_forbidden_privacy_fields_fail_at_any_depth(field: str) -> None:
    item = direct_diagnostic()
    item["trace"][field] = "redacted"
    assert any("forbidden field class" in error for error in errors(item))


@pytest.mark.parametrize("leak", ["/tmp/probe.out", "C:\\probe\\out", "pid=4242", "address=0x7fff123456", "argv=probe --live"])
def test_raw_path_pid_address_and_argv_values_are_rejected(leak: str) -> None:
    item = direct_diagnostic()
    item["run_id"] = leak
    joined = "\n".join(errors(item))
    assert "forbidden encoded or raw identifier value" in joined


@pytest.mark.parametrize("claim", GATE.CLAIM_FIELDS)
def test_all_claims_are_schema_fixed_false(claim: str) -> None:
    item = direct_diagnostic()
    item[claim] = True
    assert errors(item)


def test_prior_failure_manifest_binding_is_constant() -> None:
    item = direct_diagnostic()
    item["prior_failure_manifest_sha256"] = "9" * 64
    assert errors(item)


def test_direct_lane_hashes_and_validates_actual_prior_manifest_bytes(tmp_path: Path) -> None:
    assert GATE.hashlib.sha256(PRIOR_FAILURE_MANIFEST).hexdigest() == GATE.EXPECTED_MANIFEST_SHA256
    completed = run_direct(tmp_path, direct_diagnostic(), PRIOR_FAILURE_MANIFEST + b"\n")
    assert completed.returncode == 1
    assert "byte digest does not match" in completed.stdout

    mutated = json.loads(PRIOR_FAILURE_MANIFEST)
    for field, value, needle in [
        ("run_id", "20260717T103431Z-runtime-rx-live-000000000000000000000000", "run_id does not match"),
        ("stage", "build", "stage must be isolated_probe"),
        ("cleanup_status", "failed", "cleanup must be completed"),
        ("raw_logs_retained", True, "raw logs must not be retained"),
    ]:
        payload = copy.deepcopy(mutated)
        payload[field] = value
        completed = run_direct(
            tmp_path, direct_diagnostic(), json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        assert completed.returncode == 1
        assert needle in completed.stdout or "byte digest does not match" in completed.stdout


def test_direct_lane_requires_prior_failure_manifest(tmp_path: Path) -> None:
    path = tmp_path / "diagnostic.json"
    path.write_text(json.dumps(direct_diagnostic()), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--diagnostic", str(path)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 1
    assert "requires --prior-failure-manifest" in completed.stdout


@pytest.mark.parametrize(
    ("state", "network", "filesystem", "strace_digest", "time_digest", "valid"),
    [
        ("unavailable", 0, 0, None, None, True),
        ("unavailable", 0, 0, GATE.EMPTY_SHA256, GATE.EMPTY_SHA256, True),
        ("unavailable", 1, 0, None, None, False),
        ("unavailable", 0, 0, "1" * 64, None, False),
        ("partial", 0, 0, "1" * 64, "2" * 64, True),
        ("partial", 0, 0, None, "2" * 64, False),
        ("complete", 0, 0, "1" * 64, "2" * 64, True),
        ("complete", 0, 0, GATE.EMPTY_SHA256, "2" * 64, False),
    ],
)
def test_trace_state_count_digest_matrix_is_symmetric(
    state: str, network: int, filesystem: int,
    strace_digest: str | None, time_digest: str | None, valid: bool,
) -> None:
    item = direct_diagnostic()
    item["trace"] = {
        "state": state, "network_syscall_count": network,
        "filesystem_mutation_syscall_count": filesystem,
        "strace_sha256": strace_digest, "time_sha256": time_digest,
    }
    observed = errors(item)
    assert (observed == []) is valid


@pytest.mark.parametrize(
    ("network", "filesystem", "checkpoint", "code", "valid"),
    [
        (1, 0, "runner_trace_policy", "trace_network_syscall_observed", True),
        (0, 1, "runner_trace_policy", "trace_filesystem_mutation_observed", True),
        (1, 1, "runner_trace_policy", "trace_network_syscall_observed", True),
        (1, 1, "runner_trace_policy", "trace_filesystem_mutation_observed", False),
        (1, 0, "probe_execute", "probe_timeout", False),
        (0, 1, "probe_execute", "probe_timeout", False),
    ],
)
def test_positive_trace_count_has_deterministic_policy_precedence(
    network: int, filesystem: int, checkpoint: str, code: str, valid: bool,
) -> None:
    item = direct_diagnostic("runner-trace-policy-network")
    item["trace"]["network_syscall_count"] = network
    item["trace"]["filesystem_mutation_syscall_count"] = filesystem
    item["checkpoint"] = checkpoint
    item["code"] = code
    if code == "probe_timeout":
        item["process"] = {"started": True, "exit_observed": False, "exit_code": None, "timed_out": True}
    observed = errors(item)
    assert (observed == []) is valid


@pytest.mark.parametrize(
    "secret",
    [
        "https://collector.invalid/x", r"\\server\share\x", "198.51.100.42",
        "2001:db8::1", "%2fetc%2fsecret", "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "deadbeefdeadbeefdeadbeefdeadbeef",
    ],
)
def test_encoded_covert_values_are_rejected_without_echo(tmp_path: Path, secret: str) -> None:
    item = direct_diagnostic()
    item["covert"] = secret
    completed = run_direct(tmp_path, item)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert secret not in output
    assert "validator=additionalProperties" in output
    assert "forbidden encoded or raw identifier value" in output


def test_schema_errors_never_echo_instance_or_validator_message(tmp_path: Path) -> None:
    item = direct_diagnostic()
    secret = "https://secret.invalid/raw?pid=4242"
    item["process"]["message"] = secret
    completed = run_direct(tmp_path, item)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert secret not in output
    assert "Additional properties" not in output
    assert "was expected" not in output
    assert "validator=additionalProperties" in output


def test_adversarial_field_name_and_value_are_never_echoed(tmp_path: Path) -> None:
    item = direct_diagnostic()
    secret_key = "https://key.invalid/pid=9911"
    secret_value = r"\\private-host\hidden\argv"
    item[secret_key] = secret_value
    completed = run_direct(tmp_path, item)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert secret_key not in output
    assert secret_value not in output
    assert "validator=additionalProperties" in output
    assert "privacy: forbidden encoded or raw identifier value" in output


@pytest.mark.parametrize(
    "secret_key",
    [
        "private_field_name_only",
        "https://key-only.invalid/hidden", r"\\key-only-host\share",
        "pid=9911", "198.51.100.77", "2001:db8::77", "%2fhidden",
        "QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "deadbeefdeadbeefdeadbeefdeadbeef",
    ],
)
def test_direct_field_name_only_leaks_are_generic_and_never_echoed(
    tmp_path: Path, secret_key: str
) -> None:
    item = direct_diagnostic()
    item[secret_key] = False
    function_output = "\n".join(errors(item))
    assert "privacy: unexpected field name" in function_output
    if secret_key != "private_field_name_only":
        assert "privacy: forbidden encoded or raw field name" in function_output
    completed = run_direct(tmp_path, item)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert secret_key not in output
    assert "privacy: unexpected field name" in output
    if secret_key != "private_field_name_only":
        assert "privacy: forbidden encoded or raw field name" in output
    assert "validator=additionalProperties" in output


def test_privacy_scan_covers_the_full_fixture_wrapper(tmp_path: Path) -> None:
    payload = fixture()
    secret = "https://wrapper.invalid/hidden"
    payload["claim_boundary"] = secret
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    observed, _summary = GATE.validate_fixture(path, SCHEMA)
    joined = "\n".join(observed)
    assert secret not in joined
    assert "privacy: forbidden encoded or raw identifier value" in joined


def test_wrapper_field_name_only_leak_is_generic_in_function_and_cli(tmp_path: Path) -> None:
    payload = fixture()
    secret_key = "https://wrapper-key.invalid/pid=7733"
    payload[secret_key] = False
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    observed, _summary = GATE.validate_fixture(path, SCHEMA)
    joined = "\n".join(observed)
    assert secret_key not in joined
    assert "privacy: unexpected field name" in joined
    assert "privacy: forbidden encoded or raw field name" in joined
    assert "fixture has unexpected fields" in joined

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture", str(path)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert secret_key not in output
    assert "privacy: unexpected field name" in output
    assert "privacy: forbidden encoded or raw field name" in output
    assert "fixture has unexpected fields" in output


def test_prior_manifest_field_name_only_leak_is_generic_in_function_and_cli(tmp_path: Path) -> None:
    secret_key = "pid=8844:https://prior-key.invalid"
    payload = json.loads(PRIOR_FAILURE_MANIFEST)
    payload[secret_key] = False
    manifest = tmp_path / "failure-manifest.json"
    manifest.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    observed = GATE.validate_prior_failure_manifest(manifest, direct_diagnostic())
    joined = "\n".join(observed)
    assert secret_key not in joined
    assert "privacy: unexpected field name" in joined
    assert "privacy: forbidden encoded or raw field name" in joined
    assert "prior failure manifest shape is not closed" in joined

    diagnostic_path = tmp_path / "diagnostic.json"
    diagnostic_path.write_text(json.dumps(direct_diagnostic()), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--diagnostic", str(diagnostic_path),
         "--prior-failure-manifest", str(manifest)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert secret_key not in output
    assert "privacy: unexpected field name" in output
    assert "privacy: forbidden encoded or raw field name" in output
    assert "prior failure manifest shape is not closed" in output


@pytest.mark.parametrize(
    "run_id",
    [
        "runtime-rx-live-deadbeef", "20260717T103431Z-runtime-rx-live-deadbeef",
        "20260717T103431Z-runtime-rx-live-BD8F677AFB36C3E9DB28BC06",
        "20260717T103431Z-runtime-rx-live-bd8f677afb36c3e9db28bc0600",
    ],
)
def test_run_id_format_is_exact(run_id: str) -> None:
    item = direct_diagnostic()
    item["run_id"] = run_id
    assert errors(item)


def test_custody_cleanup_and_raw_log_retention_fail_closed() -> None:
    item = direct_diagnostic()
    item["custody"]["artifact_unchanged"] = False
    assert errors(item) == []

    item = direct_diagnostic()
    item["cleanup"]["completed"] = False
    assert any("completed contained cleanup" in error for error in errors(item))

    item = direct_diagnostic()
    item["cleanup"]["raw_logs_retained"] = True
    assert errors(item)


@pytest.mark.parametrize(
    "timestamp",
    ["2026-02-31T12:00:00Z", "2025-02-29T12:00:00Z", "2026-07-17T24:00:00Z", "2026-07-17T12:00:00+00:00"],
)
def test_timestamp_requires_real_canonical_utc(timestamp: str) -> None:
    item = direct_diagnostic()
    item["observed_at_utc"] = timestamp
    assert errors(item)


def test_malformed_direct_cli_is_bounded_without_traceback(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_text('{"schema": [', encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--diagnostic", str(path)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    diagnostic_text = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert "Traceback" not in diagnostic_text
    assert len(diagnostic_text) <= 320


def test_structurally_malformed_direct_cli_is_bounded_without_traceback(tmp_path: Path) -> None:
    path = tmp_path / "structurally-malformed.json"
    path.write_text('{"execute":true}', encoding="utf-8")
    manifest = tmp_path / "failure-manifest.json"
    manifest.write_bytes(PRIOR_FAILURE_MANIFEST)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--diagnostic", str(path),
         "--prior-failure-manifest", str(manifest)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    diagnostic_text = completed.stdout + completed.stderr
    assert completed.returncode == 1
    assert "Traceback" not in diagnostic_text
    assert "validator=required" in diagnostic_text
    assert len(diagnostic_text) <= 2048
