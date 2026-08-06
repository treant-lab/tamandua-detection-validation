#!/usr/bin/env python3
"""Build a privacy-preserving check-locked probe receipt from an injected adapter.

This module has no Docker or subprocess implementation.  It accepts only an
explicitly marked trusted fake for unit tests; a real adapter needs a future
separate-process boundary and serialized immutable manifest.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, Sequence

from jsonschema import Draft202012Validator


_SHA256_FACTORY = hashlib.sha256
_JSON_DUMPS = json.dumps
_JSON_LOADS = json.loads
_TOKEN_HEX = secrets.token_hex
_VALIDATOR_TYPE = Draft202012Validator
_MAPPING_PROXY = MappingProxyType

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "schemas" / "elixir_check_locked_probe_receipt_v1.schema.json"
SCHEMA_FILE_SHA256 = "692b09e70f1da3c2a15941a1f98c2882092f1fe290e5eafa16874e3fb0556789"
PROFILE = "elixir-check-locked-auditable-probe-v1"
EVIDENCE_CLASS = "local_offline_trusted_fake_unit_test_contract"
PARENT_LOOP = 137
PARENT_LOOP137_SHA256 = "47af4ad004451a6a506e022911a5b8042ebc23f50217c5b7c74c42a731cc3a4e"
LOCKED_PRECONDITION_LINE_SHA256 = "0da5a0820b791554b1d79d413168ed334a815ab35667d688fa0bcb94f27e4fe6"
SOURCE_HEAD = "ce97ccd64a686e91fbf6f613e3face7cb17843d2"
MIX_EXS_SHA256 = "68f782f5006682113827741fe3b8b16dcb1bb9f7deb99ed96fad6cbae180440b"
MIX_LOCK_SHA256 = "c2f55bbe72c17420ae1410a027ee97a7111c52427977db5e16cc3d2fc96d3f98"
CONFIG_SHA256 = "e5350e1ea1eb81007eeca2837adeef16e93731c9943637ada14afbf1889ac2da"
CONFIG_FILE_COUNT = 6
HYDRATOR_IMAGE_ID = "sha256:f31484716c92e442efbe163ff5df3456ac6dd3e0c96a2c3d1cc4fd295661e5a0"
ELIXIR_VERSION = "1.18.4"
ERLANG_VERSION = "28.5.0.2"
OTP_RELEASE = "28"
HEX_VERSION = "2.5.1"
REBAR_VERSION = "3.26.0"
TOOLCHAIN_PROFILE = "f314-hydrator-b825-final-v1"
ADAPTER_CONTRACT = "trusted_injected_fake_v1"
EVIDENCE_BOUNDARY = (
    ("adapter_trust", "trusted_injected_fake"),
    ("validation_scope", "unit_test_and_accidental_drift_only"),
    ("same_interpreter_adversarial_resistance_proven", False),
    ("schema_provenance_verified", False),
    ("invocation_entropy_verified", False),
    ("real_cleanup_verified", False),
    ("real_adapter_allowed", False),
    ("required_before_real_adapter", (
        "separate_process_boundary", "serialized_immutable_manifest",
    )),
)
LIMITATIONS = (
    "trusted_injected_fake_only", "unit_test_and_accidental_drift_only",
    "single_run_contract", "same_interpreter_not_adversarial_boundary",
    "schema_provenance_unverified", "invocation_entropy_unverified",
    "real_cleanup_unverified",
    "real_adapter_requires_separate_process_and_serialized_manifest",
    "raw_output_discarded", "no_real_probe", "no_artifact",
    "no_runtime_validation", "no_database_validation",
)
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
INVOCATION = re.compile(r"^loop144-[a-f0-9]{16}$")
CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
FORBIDDEN_PERSISTED_PATTERNS = (
    b"http://", b"https://", b"password", b"credential", b"bearer ",
    b"token=", b"env=", b"sk_test",
)
FALSE_CLAIMS = {
    "probe_executed_on_real_adapter": False,
    "artifact_verified": False,
    "runtime_validation_executed": False,
    "rls_validated": False,
    "product_ready": False,
    "production_validated": False,
    "external_claim_allowed": False,
    "vendor_parity": False,
}
TRUSTED_FAKE_EVIDENCE_MARKER = object()


def _immutable(*_args: object, **_kwargs: object) -> None:
    raise TypeError("immutable_snapshot")


class FrozenDict(dict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable


class FrozenList(list):
    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = reverse = sort = __iadd__ = __imul__ = _immutable


def _freeze_json(value: object) -> object:
    if type(value) is dict:
        return FrozenDict({key: _freeze_json(item) for key, item in value.items()})
    if type(value) is list:
        return FrozenList(_freeze_json(item) for item in value)
    return value


_FREEZE_JSON = _freeze_json


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def line_digest(line: str | bytes) -> str:
    payload = line if isinstance(line, bytes) else line.encode("utf-8", errors="replace")
    if payload.endswith(b"\r\n"):
        payload = payload[:-2]
    elif payload.endswith((b"\r", b"\n")):
        payload = payload[:-1]
    if not 1 <= len(payload) <= 4096 or b"\r" in payload or b"\n" in payload:
        raise ValueError("failure_line_invalid")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ProbeObservation:
    container_id: str
    exit_code: int
    failure_line: str | bytes


_OBSERVATION_TYPE = ProbeObservation


class ProbeAdapter(Protocol):
    evidence_marker: object
    def image_inventory(self) -> Sequence[str]: ...
    def run_once(self, argv: Sequence[str]) -> ProbeObservation: ...
    def remove_container(self, container_name: str) -> bool: ...
    def container_absent(self, container_name: str) -> bool: ...


@dataclass(frozen=True)
class AdapterSnapshot:
    image_inventory: Callable[[], Sequence[str]]
    run_once: Callable[[Sequence[str]], ProbeObservation]
    remove_container: Callable[[str], bool]
    container_absent: Callable[[str], bool]


@dataclass(frozen=True)
class RunSnapshot:
    invocation_id: str
    values: Mapping[str, object]
    schema_validator: Draft202012Validator
    schema_validate: Callable[[object], None]
    schema_sha256: str
    observation_type: type[ProbeObservation]
    container_id_pattern: re.Pattern[str]
    forbidden_patterns: tuple[bytes, ...]
    canonical_bytes: Callable[[object], bytes]
    digest: Callable[[object], str]
    line_digest: Callable[[str | bytes], str]
    failure_class: Callable[[str], str]
    canonical_inventory: Callable[[Sequence[str]], list[str]]
    inventory_evidence: Callable[[str, list[str] | None], dict[str, object]]
    validate_finalization: Callable[..., None]
    validate_primary_result: Callable[..., None]


_RUN_SNAPSHOT_TYPE = RunSnapshot


def _load_run_snapshot(invocation_id: str | None = None) -> RunSnapshot:
    """Load and seal all policy before an adapter can be inspected or called."""
    if (hashlib.sha256 is not _SHA256_FACTORY or json.dumps is not _JSON_DUMPS
            or json.loads is not _JSON_LOADS or secrets.token_hex is not _TOKEN_HEX
            or Draft202012Validator is not _VALIDATOR_TYPE or _freeze_json is not _FREEZE_JSON
            or _validate_finalization is not _ORIGINAL_VALIDATE_FINALIZATION
            or _validate_primary_result is not _ORIGINAL_VALIDATE_PRIMARY_RESULT
            or _validate_receipt_with_snapshot is not _RECEIPT_VALIDATOR):
        raise ValueError("precall_primitive_drift")
    sha256_fn = _SHA256_FACTORY
    json_dumps = _JSON_DUMPS
    json_loads = _JSON_LOADS
    validator_type = _VALIDATOR_TYPE
    schema_path = SCHEMA
    schema_hash = SCHEMA_FILE_SHA256
    invocation_pattern = INVOCATION
    image_pattern = IMAGE_ID
    sha_pattern = SHA256
    container_id_pattern = CONTAINER_ID
    observation_type = _OBSERVATION_TYPE
    forbidden_patterns = tuple(FORBIDDEN_PERSISTED_PATTERNS)
    values: dict[str, object] = {
        "profile": PROFILE,
        "evidence_class": EVIDENCE_CLASS,
        "parent_loop": PARENT_LOOP,
        "parent": PARENT_LOOP137_SHA256,
        "locked_precondition_line_sha256": LOCKED_PRECONDITION_LINE_SHA256,
        "source_head": SOURCE_HEAD,
        "mix_exs_sha256": MIX_EXS_SHA256,
        "mix_lock_sha256": MIX_LOCK_SHA256,
        "config_sha256": CONFIG_SHA256,
        "config_file_count": CONFIG_FILE_COUNT,
        "hydrator_image_id": HYDRATOR_IMAGE_ID,
        "elixir": ELIXIR_VERSION,
        "erlang": ERLANG_VERSION,
        "otp": OTP_RELEASE,
        "hex": HEX_VERSION,
        "rebar": REBAR_VERSION,
        "toolchain_profile": TOOLCHAIN_PROFILE,
        "adapter_contract": ADAPTER_CONTRACT,
        "evidence_boundary": tuple(EVIDENCE_BOUNDARY),
        "limitations": tuple(LIMITATIONS),
        "claims": tuple(FALSE_CLAIMS.items()),
    }
    if not GIT_SHA.fullmatch(SOURCE_HEAD):
        raise ValueError("closed_source_head_invalid")
    if any(not SHA256.fullmatch(value) for value in (
        PARENT_LOOP137_SHA256, MIX_EXS_SHA256, MIX_LOCK_SHA256, CONFIG_SHA256,
    )):
        raise ValueError("closed_digest_invalid")
    if not IMAGE_ID.fullmatch(HYDRATOR_IMAGE_ID):
        raise ValueError("closed_image_id_invalid")
    if type(CONFIG_FILE_COUNT) is not int or not 1 <= CONFIG_FILE_COUNT <= 64:
        raise ValueError("closed_config_file_count_invalid")
    for value in (ELIXIR_VERSION, ERLANG_VERSION, OTP_RELEASE, HEX_VERSION,
                  REBAR_VERSION, TOOLCHAIN_PROFILE):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
            raise ValueError("closed_toolchain_value_invalid")
    expected: dict[str, object] = {
        "profile": "elixir-check-locked-auditable-probe-v1",
        "evidence_class": "local_offline_trusted_fake_unit_test_contract",
        "parent_loop": 137,
        "parent": "47af4ad004451a6a506e022911a5b8042ebc23f50217c5b7c74c42a731cc3a4e",
        "locked_precondition_line_sha256": "0da5a0820b791554b1d79d413168ed334a815ab35667d688fa0bcb94f27e4fe6",
        "source_head": "ce97ccd64a686e91fbf6f613e3face7cb17843d2",
        "mix_exs_sha256": "68f782f5006682113827741fe3b8b16dcb1bb9f7deb99ed96fad6cbae180440b",
        "mix_lock_sha256": "c2f55bbe72c17420ae1410a027ee97a7111c52427977db5e16cc3d2fc96d3f98",
        "config_sha256": "e5350e1ea1eb81007eeca2837adeef16e93731c9943637ada14afbf1889ac2da",
        "config_file_count": 6,
        "hydrator_image_id": "sha256:f31484716c92e442efbe163ff5df3456ac6dd3e0c96a2c3d1cc4fd295661e5a0",
        "elixir": "1.18.4",
        "erlang": "28.5.0.2",
        "otp": "28",
        "hex": "2.5.1",
        "rebar": "3.26.0",
        "toolchain_profile": "f314-hydrator-b825-final-v1",
        "adapter_contract": "trusted_injected_fake_v1",
        "evidence_boundary": (
            ("adapter_trust", "trusted_injected_fake"),
            ("validation_scope", "unit_test_and_accidental_drift_only"),
            ("same_interpreter_adversarial_resistance_proven", False),
            ("schema_provenance_verified", False),
            ("invocation_entropy_verified", False),
            ("real_cleanup_verified", False),
            ("real_adapter_allowed", False),
            ("required_before_real_adapter", (
                "separate_process_boundary", "serialized_immutable_manifest",
            )),
        ),
        "limitations": (
            "trusted_injected_fake_only", "unit_test_and_accidental_drift_only",
            "single_run_contract", "same_interpreter_not_adversarial_boundary",
            "schema_provenance_unverified", "invocation_entropy_unverified",
            "real_cleanup_unverified",
            "real_adapter_requires_separate_process_and_serialized_manifest",
            "raw_output_discarded", "no_real_probe", "no_artifact",
            "no_runtime_validation", "no_database_validation",
        ),
        "claims": (
            ("probe_executed_on_real_adapter", False),
            ("artifact_verified", False),
            ("runtime_validation_executed", False),
            ("rls_validated", False),
            ("product_ready", False),
            ("production_validated", False),
            ("external_claim_allowed", False),
            ("vendor_parity", False),
        ),
    }
    if values != expected:
        raise ValueError("closed_binding_mismatch")
    if invocation_pattern.pattern != r"^loop144-[a-f0-9]{16}$":
        raise ValueError("closed_invocation_policy_mismatch")
    if (sha_pattern.pattern != r"^[a-f0-9]{64}$"
            or image_pattern.pattern != r"^sha256:[a-f0-9]{64}$"
            or container_id_pattern.pattern != r"^[a-f0-9]{64}$"):
        raise ValueError("closed_pattern_policy_mismatch")
    if forbidden_patterns != (
        b"http://", b"https://", b"password", b"credential", b"bearer ",
        b"token=", b"env=", b"sk_test",
    ):
        raise ValueError("closed_privacy_policy_mismatch")
    try:
        schema_bytes = schema_path.read_bytes()
    except Exception:
        raise ValueError("schema_load_error") from None
    if not 1 <= len(schema_bytes) <= 131072:
        raise ValueError("schema_size_invalid")
    try:
        schema_document = json_loads(schema_bytes.decode("utf-8"))
        if type(schema_document) is not dict:
            raise ValueError
        validator_type.check_schema(schema_document)
    except Exception:
        raise ValueError("schema_structure_invalid") from None
    observed_schema_hash = sha256_fn(schema_bytes).hexdigest()
    if observed_schema_hash != schema_hash or schema_hash != "692b09e70f1da3c2a15941a1f98c2882092f1fe290e5eafa16874e3fb0556789":
        raise ValueError("schema_hash_mismatch")
    schema_validator = validator_type(_FREEZE_JSON(schema_document))
    if invocation_id is None:
        invocation_id = f"loop144-{_TOKEN_HEX(8)}"
    if type(invocation_id) is not str or not invocation_pattern.fullmatch(invocation_id):
        raise ValueError("generated_invocation_id_invalid")
    container_name = f"tamandua-check-locked-{invocation_id}"
    argv = (
        "container-adapter", "run-once", f"name={container_name}", "pull=never",
        "network=none", "root=read-only", "workspace=tmpfs", "mounts=read-only",
        "image=sha256:f31484716c92e442efbe163ff5df3456ac6dd3e0c96a2c3d1cc4fd295661e5a0",
        "entrypoint=mix", "task=deps.get", "arg=--only", "arg=test", "arg=--check-locked",
    )
    def sealed_canonical(value: object) -> bytes:
        return json_dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    def sealed_digest(value: object) -> str:
        return sha256_fn(sealed_canonical(value)).hexdigest()
    def sealed_line_digest(line: str | bytes) -> str:
        payload = line if isinstance(line, bytes) else line.encode("utf-8", errors="replace")
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        elif payload.endswith((b"\r", b"\n")):
            payload = payload[:-1]
        if not 1 <= len(payload) <= 4096 or b"\r" in payload or b"\n" in payload:
            raise ValueError("failure_line_invalid")
        return sha256_fn(payload).hexdigest()
    def sealed_failure_class(value: str) -> str:
        if not sha_pattern.fullmatch(value):
            raise ValueError("failure_line_digest_invalid")
        return "locked_state_precondition_rejected" if value == expected["locked_precondition_line_sha256"] else "unclassified"
    def sealed_inventory(items: Sequence[str]) -> list[str]:
        inventory = sorted(items)
        if len(inventory) != len(set(inventory)) or any(not image_pattern.fullmatch(item) for item in inventory):
            raise ValueError("image_inventory_invalid")
        return inventory
    def sealed_inventory_evidence(status: str, manifest: list[str] | None = None) -> dict[str, object]:
        return {
            "status": status,
            "manifest": manifest if status == "observed" else [],
            "manifest_sha256": sealed_digest(manifest) if status == "observed" else None,
        }
    values.update({
        "container_name": container_name,
        "argv": argv,
        "argv_sha256": sealed_digest(argv),
    })
    persisted = {key: value for key, value in values.items() if key != "locked_precondition_line_sha256"}
    if any(pattern in sealed_canonical({"invocation_id": invocation_id, **persisted}).lower()
           for pattern in forbidden_patterns):
        raise ValueError("persisted_value_privacy_violation")
    return _RUN_SNAPSHOT_TYPE(
        invocation_id=invocation_id,
        values=_MAPPING_PROXY(values),
        schema_validator=schema_validator,
        schema_validate=schema_validator.validate,
        schema_sha256=observed_schema_hash,
        observation_type=observation_type,
        container_id_pattern=container_id_pattern,
        forbidden_patterns=forbidden_patterns,
        canonical_bytes=sealed_canonical,
        digest=sealed_digest,
        line_digest=sealed_line_digest,
        failure_class=sealed_failure_class,
        canonical_inventory=sealed_inventory,
        inventory_evidence=sealed_inventory_evidence,
        validate_finalization=_validate_finalization,
        validate_primary_result=_validate_primary_result,
    )


def canonical_inventory(values: Sequence[str]) -> list[str]:
    inventory = sorted(values)
    if len(inventory) != len(set(inventory)) or any(not IMAGE_ID.fullmatch(value) for value in inventory):
        raise ValueError("image_inventory_invalid")
    return inventory


def probe_argv(container_name: str) -> list[str]:
    return [
        "container-adapter", "run-once", f"name={container_name}", "pull=never",
        "network=none", "root=read-only", "workspace=tmpfs", "mounts=read-only",
        f"image={HYDRATOR_IMAGE_ID}", "entrypoint=mix",
        "task=deps.get", "arg=--only", "arg=test", "arg=--check-locked",
    ]


def failure_class_for_digest(value: str) -> str:
    if not SHA256.fullmatch(value):
        raise ValueError("failure_line_digest_invalid")
    return "locked_state_precondition_rejected" if value == LOCKED_PRECONDITION_LINE_SHA256 else "unclassified"


def _validate_adapter(
    adapter: ProbeAdapter, snapshot_type: type[AdapterSnapshot] = AdapterSnapshot,
    trusted_marker: object = TRUSTED_FAKE_EVIDENCE_MARKER,
) -> AdapterSnapshot:
    methods: dict[str, Callable[..., object]] = {}
    try:
        evidence_marker = getattr(adapter, "evidence_marker", None)
    except Exception:
        raise ValueError("adapter_contract_invalid") from None
    if evidence_marker is not trusted_marker:
        raise ValueError("adapter_not_trusted_fake")
    for name in ("image_inventory", "run_once", "remove_container", "container_absent"):
        try:
            method = getattr(adapter, name, None)
        except Exception:
            raise ValueError("adapter_contract_invalid") from None
        if not callable(method):
            raise ValueError("adapter_contract_invalid")
        methods[name] = method
    return snapshot_type(
        image_inventory=methods["image_inventory"],
        run_once=methods["run_once"],
        remove_container=methods["remove_container"],
        container_absent=methods["container_absent"],
    )


_ADAPTER_VALIDATOR = _validate_adapter


def _inventory_evidence(status: str, manifest: list[str] | None = None) -> dict[str, object]:
    return {
        "status": status,
        "manifest": manifest if status == "observed" else [],
        "manifest_sha256": digest(manifest) if status == "observed" else None,
    }


def _validate_finalization(
    *, run_count: int, remove_count: int, absence_count: int,
    removed: object, absent: object, before_status: object, after_status: object,
    unchanged: bool, errors: object,
) -> None:
    if remove_count != run_count or absence_count != run_count:
        raise ValueError("receipt_finalization_metric_mismatch")
    assert isinstance(errors, list)
    markers = set(errors)
    if run_count == 0:
        if removed is not None or absent is not None or markers & {
            "remove_result_invalid", "remove_adapter_error", "absence_result_invalid",
            "absence_adapter_error", "remove_incomplete", "container_still_present",
        }:
            raise ValueError("receipt_unattempted_finalization_mismatch")
    else:
        remove_markers = markers & {
            "remove_result_invalid", "remove_adapter_error", "remove_incomplete",
        }
        absence_markers = markers & {
            "absence_result_invalid", "absence_adapter_error", "container_still_present",
        }
        expected_remove_markers = 0 if removed is True else 1
        expected_absence_markers = 0 if absent is True else 1
        if len(remove_markers) != expected_remove_markers or len(absence_markers) != expected_absence_markers:
            raise ValueError("receipt_finalization_result_mismatch")
        if removed is False and remove_markers != {"remove_incomplete"}:
            raise ValueError("receipt_remove_result_mismatch")
        if absent is False and absence_markers != {"container_still_present"}:
            raise ValueError("receipt_absence_result_mismatch")
    if ("inventory_after_error" in markers) is not (after_status == "adapter_error"):
        raise ValueError("receipt_after_inventory_error_mismatch")
    inventory_changed = before_status == after_status == "observed" and not unchanged
    if ("inventory_changed" in markers) is not inventory_changed:
        raise ValueError("receipt_inventory_change_marker_mismatch")


def _validate_primary_result(*, error_class: object, container_id: object,
                             exit_code: object, failure_digest: object) -> None:
    observed = (container_id is not None, exit_code is not None, failure_digest is not None)
    if error_class is None:
        if observed != (True, True, True):
            raise ValueError("receipt_observed_result_incomplete")
        return
    if error_class in {"inventory_before_error", "run_adapter_error", "observation_invalid"}:
        expected = (False, False, False)
    elif error_class == "container_id_invalid":
        expected = (False, observed[1], observed[2])
    elif error_class == "exit_code_invalid":
        expected = (True, False, observed[2])
    elif error_class == "failure_line_invalid":
        expected = (True, True, False)
    else:
        raise ValueError("receipt_error_class_invalid")
    if observed != expected:
        raise ValueError("receipt_primary_result_mismatch")


_ORIGINAL_VALIDATE_FINALIZATION = _validate_finalization
_ORIGINAL_VALIDATE_PRIMARY_RESULT = _validate_primary_result


def _validate_receipt_with_snapshot(receipt: dict[str, object], snapshot: RunSnapshot) -> None:
    snapshot.schema_validate(receipt)
    invocation = receipt["invocation"]
    container = receipt["container"]
    inputs = receipt["inputs"]
    inventory = receipt["inventory"]
    result = receipt["result"]
    cleanup = receipt["cleanup"]
    metrics = receipt["metrics"]
    assert isinstance(invocation, dict) and isinstance(container, dict) and isinstance(inputs, dict)
    assert isinstance(inventory, dict) and isinstance(result, dict) and isinstance(cleanup, dict)
    assert isinstance(metrics, dict)
    if invocation["id"] != snapshot.invocation_id:
        raise ValueError("receipt_snapshot_invocation_mismatch")
    expected_name = f"tamandua-check-locked-{invocation['id']}"
    expected_argv = [
        "container-adapter", "run-once", f"name={expected_name}", "pull=never",
        "network=none", "root=read-only", "workspace=tmpfs", "mounts=read-only",
        f"image={inputs['hydrator_image_id']}", "entrypoint=mix",
        "task=deps.get", "arg=--only", "arg=test", "arg=--check-locked",
    ]
    if container["name"] != expected_name or invocation["argv"] != expected_argv:
        raise ValueError("receipt_invocation_binding_mismatch")
    if invocation["argv_sha256"] != snapshot.digest(expected_argv):
        raise ValueError("receipt_argv_digest_mismatch")
    for phase in ("before", "after"):
        evidence = inventory[phase]
        assert isinstance(evidence, dict)
        manifest = evidence["manifest"]
        if evidence["status"] == "observed":
            if manifest != sorted(manifest) or evidence["manifest_sha256"] != snapshot.digest(manifest):
                raise ValueError("receipt_inventory_binding_mismatch")
        elif manifest != [] or evidence["manifest_sha256"] is not None:
            raise ValueError("receipt_unavailable_inventory_not_empty")
    unchanged = bool(
        inventory["before"]["status"] == inventory["after"]["status"] == "observed"
        and inventory["before"]["manifest"] == inventory["after"]["manifest"]
    )
    if inventory["unchanged"] is not unchanged:
        raise ValueError("receipt_inventory_state_mismatch")
    if cleanup["image_inventory_unchanged"] is not unchanged:
        raise ValueError("receipt_cleanup_inventory_mismatch")
    if result["failure_line_sha256"] is None:
        if result["failure_class"] != "not_observed":
            raise ValueError("receipt_failure_class_mismatch")
    elif result["failure_class"] != snapshot.failure_class(result["failure_line_sha256"]):
        raise ValueError("receipt_failure_class_mismatch")
    observed_result = bool(
        result["error_class"] is None and container["id"] is not None
        and result["exit_code"] is not None and result["failure_line_sha256"] is not None
    )
    if result["status"] != ("observed" if observed_result else "blocked"):
        raise ValueError("receipt_result_status_mismatch")
    if result["outcome"] != ("fail" if observed_result else "unknown"):
        raise ValueError("receipt_result_outcome_mismatch")
    snapshot.validate_primary_result(
        error_class=result["error_class"], container_id=container["id"],
        exit_code=result["exit_code"], failure_digest=result["failure_line_sha256"],
    )
    complete = bool(
        result["status"] == "observed" and cleanup["remove_succeeded"] is True
        and cleanup["container_absent_after"] is True and unchanged
        and result["finalization_errors"] == []
    )
    if cleanup["complete"] is not complete:
        raise ValueError("receipt_cleanup_state_mismatch")
    calls = metrics["interface_calls"]
    assert isinstance(calls, dict)
    if receipt["execution"]["run_attempted"] is not (calls["run_once"] == 1):
        raise ValueError("receipt_run_metric_mismatch")
    if cleanup["remove_attempted"] is not (calls["remove_container_by_name"] == 1):
        raise ValueError("receipt_remove_metric_mismatch")
    if cleanup["absence_check_attempted"] is not (calls["container_absent_by_name"] == 1):
        raise ValueError("receipt_absence_metric_mismatch")
    snapshot.validate_finalization(
        run_count=calls["run_once"],
        remove_count=calls["remove_container_by_name"],
        absence_count=calls["container_absent_by_name"],
        removed=cleanup["remove_succeeded"],
        absent=cleanup["container_absent_after"],
        before_status=inventory["before"]["status"],
        after_status=inventory["after"]["status"],
        unchanged=unchanged,
        errors=result["finalization_errors"],
    )
    before_failed = inventory["before"]["status"] == "adapter_error"
    if before_failed is not (result["error_class"] == "inventory_before_error"):
        raise ValueError("receipt_before_inventory_error_mismatch")
    if before_failed and calls["run_once"] != 0:
        raise ValueError("receipt_run_after_inventory_error")
    serialized = snapshot.canonical_bytes(receipt).lower()
    for forbidden in snapshot.forbidden_patterns:
        if forbidden in serialized:
            raise ValueError("receipt_privacy_violation")


_RECEIPT_VALIDATOR = _validate_receipt_with_snapshot


def validate_receipt(receipt: dict[str, object]) -> None:
    try:
        invocation = receipt["invocation"]
        assert isinstance(invocation, dict)
        invocation_id = invocation["id"]
    except Exception:
        raise ValueError("receipt_invocation_invalid") from None
    snapshot = _load_run_snapshot(invocation_id if isinstance(invocation_id, str) else None)
    _validate_receipt_with_snapshot(receipt, snapshot)


def build_receipt(adapter: ProbeAdapter) -> dict[str, object]:
    snapshot = _load_run_snapshot()
    closed = snapshot.values
    receipt_validator = _RECEIPT_VALIDATOR
    adapter_snapshot = _ADAPTER_VALIDATOR(adapter)
    container_name = closed["container_name"]
    argv = closed["argv"]
    assert isinstance(container_name, str) and isinstance(argv, tuple)
    calls = {
        "image_inventory": 0, "run_once": 0,
        "remove_container_by_name": 0, "container_absent_by_name": 0,
    }
    before_evidence = snapshot.inventory_evidence("adapter_error", None)
    after_evidence = snapshot.inventory_evidence("adapter_error", None)
    observation: ProbeObservation | None = None
    container_id: str | None = None
    exit_code: int | None = None
    failure_sha256: str | None = None
    failure_class = "not_observed"
    primary_error: str | None = None
    finalization_errors: list[str] = []
    removed: bool | None = None
    absent: bool | None = None
    run_attempted = False
    try:
        calls["image_inventory"] += 1
        try:
            before_evidence = snapshot.inventory_evidence(
                "observed", snapshot.canonical_inventory(adapter_snapshot.image_inventory()),
            )
        except Exception:
            primary_error = "inventory_before_error"
        if primary_error is None:
            run_attempted = True
            calls["run_once"] += 1
            try:
                candidate = adapter_snapshot.run_once(argv)
                if not isinstance(candidate, snapshot.observation_type):
                    primary_error = "observation_invalid"
                else:
                    observation = candidate
                    if (not isinstance(candidate.container_id, str)
                            or not snapshot.container_id_pattern.fullmatch(candidate.container_id)):
                        primary_error = "container_id_invalid"
                    else:
                        container_id = candidate.container_id
                    if (not isinstance(candidate.exit_code, int) or isinstance(candidate.exit_code, bool)
                            or not 1 <= candidate.exit_code <= 125):
                        primary_error = primary_error or "exit_code_invalid"
                    else:
                        exit_code = candidate.exit_code
                    try:
                        failure_sha256 = snapshot.line_digest(candidate.failure_line)
                        failure_class = snapshot.failure_class(failure_sha256)
                    except Exception:
                        primary_error = primary_error or "failure_line_invalid"
            except Exception:
                primary_error = "run_adapter_error"
    finally:
        if run_attempted:
            calls["remove_container_by_name"] += 1
            try:
                candidate_removed = adapter_snapshot.remove_container(container_name)
                if type(candidate_removed) is bool:
                    removed = candidate_removed
                else:
                    finalization_errors.append("remove_result_invalid")
            except Exception:
                finalization_errors.append("remove_adapter_error")
            calls["container_absent_by_name"] += 1
            try:
                candidate_absent = adapter_snapshot.container_absent(container_name)
                if type(candidate_absent) is bool:
                    absent = candidate_absent
                else:
                    finalization_errors.append("absence_result_invalid")
            except Exception:
                finalization_errors.append("absence_adapter_error")
        calls["image_inventory"] += 1
        try:
            after_evidence = snapshot.inventory_evidence(
                "observed", snapshot.canonical_inventory(adapter_snapshot.image_inventory()),
            )
        except Exception:
            finalization_errors.append("inventory_after_error")
    observed = primary_error is None and observation is not None
    before_manifest = before_evidence["manifest"]
    after_manifest = after_evidence["manifest"]
    inventory_unchanged = bool(
        before_evidence["status"] == after_evidence["status"] == "observed"
        and before_manifest == after_manifest
    )
    if run_attempted and removed is False:
        finalization_errors.append("remove_incomplete")
    if run_attempted and absent is False:
        finalization_errors.append("container_still_present")
    if before_evidence["status"] == after_evidence["status"] == "observed" and not inventory_unchanged:
        finalization_errors.append("inventory_changed")
    finalization_errors = list(dict.fromkeys(finalization_errors))
    cleanup_complete = bool(observed and removed is True and absent is True and inventory_unchanged and not finalization_errors)
    receipt: dict[str, object] = {
        "schema_version": 1,
        "profile": closed["profile"],
        "evidence_class": closed["evidence_class"],
        "evidence_boundary": {
            **dict(closed["evidence_boundary"]),
            "required_before_real_adapter": list(dict(closed["evidence_boundary"])["required_before_real_adapter"]),
        },
        "parent": {"loop": closed["parent_loop"], "artifact_sha256": closed["parent"]},
        "invocation": {
            "id": snapshot.invocation_id,
            "argv": list(argv),
            "argv_sha256": closed["argv_sha256"],
        },
        "container": {"name": container_name, "id": container_id},
        "inputs": {
            "source_head": closed["source_head"],
            "mix_exs_sha256": closed["mix_exs_sha256"],
            "mix_lock_sha256": closed["mix_lock_sha256"],
            "config_sha256": closed["config_sha256"],
            "config_file_count": closed["config_file_count"],
            "hydrator_image_id": closed["hydrator_image_id"],
        },
        "toolchain": {
            "elixir": closed["elixir"],
            "erlang": closed["erlang"],
            "otp": closed["otp"],
            "hex": closed["hex"],
            "rebar": closed["rebar"],
            "profile": closed["toolchain_profile"],
        },
        "inventory": {
            "before": before_evidence,
            "after": after_evidence,
            "unchanged": inventory_unchanged,
        },
        "result": {
            "status": "observed" if observed else "blocked",
            "outcome": "fail" if observed else "unknown",
            "exit_code": exit_code,
            "failure_line_sha256": failure_sha256,
            "failure_class": failure_class,
            "error_class": primary_error,
            "finalization_errors": finalization_errors,
            "raw_output_persisted": False,
        },
        "execution": {
            "run_attempted": run_attempted,
            "retried": False,
            "build_started": False,
            "network_requested": False,
            "pull_requested": False,
            "source_mounts_read_only": True,
            "container_root_read_only": True,
            "probe_workspace_tmpfs": True,
        },
        "cleanup": {
            "remove_attempted": run_attempted,
            "remove_succeeded": removed,
            "absence_check_attempted": run_attempted,
            "container_absent_after": absent,
            "image_inventory_unchanged": inventory_unchanged,
            "complete": cleanup_complete,
        },
        "metrics": {"adapter_contract": closed["adapter_contract"], "interface_calls": calls},
        "limitations": list(closed["limitations"]),
        "claims": dict(closed["claims"]),
    }
    receipt_validator(receipt, snapshot)
    return receipt
